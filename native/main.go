// seedkernel native shell. Apps arrive as signed bundles (README §12) — nothing
// application-specific lives here, and nothing about how a node is assembled does
// either. The whole shell — verify + admit + install (§12.4/§12.5), the guest seam
// (§12.2), the confined guest's lifecycle (§12.3), protocol dispatch (§12.10) — is
// the shared host TS, compiled into the embedded host-shell.gen.js and run in
// QuickJS (README §12.9) — and so is the operator flow itself (host/cli.ts): the flag
// set, the defaults, the order a node does things in, and every line it prints.
//
// This Go layer is the bridge and only the bridge: it owns the module table (§3),
// supplies the crypto (Ed25519 via libsodium, BLAKE2b native), the fs backend, the
// sockets, the second QuickJS realm, and the process's own facilities — argv, files,
// stdout. Nothing here decides anything an operator can see. Pure Go, no cgo (QuickJS
// is quickjs-ng wasm over the in-repo qjs/wazero bridge) → one static binary.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"time"

	"seedloader/qjs"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// hostShellJS is the shared shell: the bundle format and its load order, the
// admission policy, the guest seam and guest ABI preamble, the transport + routing,
// the WebSocket codec, the protocol routing, `createShell` — and the native
// platform binding that hands `createShell` the primitives exposed below
// (host/native-shim.ts). Bundled from build/host/*.js by scripts/bundle-loader.mjs;
// it is the same compiled TS the Node shell runs, so no rule of the protocol and no
// step of the assembly is re-derived in a second language (README §12.9).
// Regenerate with `npm run build:loader-bundles`; do not hand-edit.
//
//go:embed host-shell.gen.js
var hostShellJS string

// ───────────────────────── module table (§3) ─────────────────────────

type boundModule struct {
	mod     api.Module
	cmod    wazero.CompiledModule // retained so an upgrade can release the old compiled code
	fn      api.Function
	scratch uint32 // §4.1 scratch offset, read once at instantiation
	size    uint32 // bytes reserved there: the declared scratchSize, or the default
}

var (
	ctx = context.Background()
	rt  wazero.Runtime
	qc  *qjs.Context
	qrt *qjs.Runtime
	// el is the Go-owned JS event loop driving the host realm and every confined
	// realm attached to it (loop.go). One per boot.
	el *eventLoop
	// apps is the module table (README §3), a contract rather
	// than an artifact. App key → that app's modules by logical name, so the §3.1
	// bind / unbind / resolve operations are map assignment, delete and lookup — there is
	// no id indirection, no name codec, and no second table to drift from this one. Every
	// value is an installed module: bundles are the one way code arrives (§12.4).
	apps = map[string]map[string]*boundModule{}
	// modSeq only names wazero instances (h1, h2, …) so two installs never share a
	// module name; it is not an identity anything resolves through.
	modSeq = 0
)

// The §4.1 scratch default (how much I/O space a module reserves at `scratch` when it
// declares no `scratchSize`) is the shared host's number — core/wasm-limits.ts
// DEFAULT_SCRATCH_SIZE — passed across by the shim with every bindAll, so Go's table
// never owns a copy that could drift from the JS table's. A module needing more
// exports a `scratchSize` global — seedstore's codec reserves 2 MB for whole-chunk
// shards — which instantiateWasm reads once and clamps its cross-module copies to.

// bindApp replaces `appKey`'s whole module set, releasing every instance the app held
// before — the §3.1 install, which is one assignment because an app is one value. The one
// place a displaced wasm instance is closed: Go frees neither the instance nor its
// compiled code on its own, so dropping the map value alone would leak one linear memory
// + its JITed code per re-install for the process's life.
func bindApp(appKey string, mods map[string]*boundModule) {
	for _, w := range apps[appKey] {
		closeModule(w)
	}
	apps[appKey] = mods
}

// closeModule releases a module's wasm instance and compiled code. nil-safe, so callers
// can hand it whatever a lookup returned.
func closeModule(w *boundModule) {
	if w == nil {
		return
	}
	_ = w.mod.Close(ctx)
	_ = w.cmod.Close(ctx)
}

// removeApp drops an app and releases every instance it held — the shell's uninstall
// (§12.5). An app's modules are the value under its key (§5.1), so this is one lookup.
func removeApp(appKey string) int {
	mods, ok := apps[appKey]
	if !ok {
		return 0
	}
	for _, w := range mods {
		closeModule(w)
	}
	delete(apps, appKey)
	return len(mods)
}

// callModule invokes one app's module by its logical name (README §4), returning its
// response or nil if nothing is bound there or the module produced nothing. The one way
// into an installed module: the shell uses it directly and the guest seam routes a
// guest's bare-name calls (§12.2) through it, with the app key bound when the bridge
// was built.
// Modules are pure transforms and cannot call back, so there is no re-entrancy to guard.
func callModule(appKey, module string, payload []byte) []byte {
	w := apps[appKey][module]
	if w == nil {
		return nil
	}
	// §4: write input at the scratch offset, call handle(input_len), read the response
	// back from the same offset. Both copies are clamped to what the module reserved
	// (§4.1) — writing past it would scribble whatever it keeps beyond scratch.
	if uint32(len(payload)) > w.size || !w.mod.Memory().Write(w.scratch, payload) {
		return nil
	}
	r, err := w.fn.Call(ctx, uint64(len(payload)))
	// handle returns output_len ≥ 0 (README §4): only a trap (err) or a negative
	// length is a failure. A 0-length result is a valid EMPTY response, not a
	// failure — return a non-nil slice for it so a caller can distinguish "empty OK"
	// from "no module / trap" (nil).
	if err != nil || len(r) == 0 {
		return nil
	}
	outLen := int32(r[0])
	if outLen < 0 || uint32(outLen) > w.size {
		return nil
	}
	out := make([]byte, outLen)
	if len(out) > 0 {
		// A returned length past the module's own memory is as bogus as an
		// oversized payload above — fail rather than return zero-filled bytes.
		b, ok := w.mod.Memory().Read(w.scratch, uint32(len(out)))
		if !ok {
			return nil
		}
		copy(out, b)
	}
	return out
}

// bindAll lands a bundle's modules on the module table, all or none (README §3.1) — the
// one way code arrives on this target, reached from JS as bridge.bindAll.
//
// The transaction is HERE rather than in the loader because this is the side holding the
// half-built instances: wazero frees neither a module instance nor its compiled code, so
// a bundle rejected at its third module has to close the first two, and a loader that
// forgot would leak a linear memory plus its JITed code per rejected bundle. Making it a
// two-phase seam across the bridge is what would put that duty on the caller.
func bindAll(appKey string, names []string, wasms [][]byte, scratchDefault uint32) error {
	built := make(map[string]*boundModule, len(wasms))
	for i, wasm := range wasms {
		w, err := instantiateWasm(wasm, scratchDefault)
		if err != nil {
			for _, h := range built {
				closeModule(h)
			}
			return fmt.Errorf("%s: %w", names[i], err)
		}
		built[names[i]] = w
	}
	// Nothing above touched the table and nothing below can fail.
	bindApp(appKey, built)
	return nil
}

// instantiateWasm compiles, instantiates, and validates module bytes against the §4
// ABI. No table effect: the result is an intermediate of bindAll's transaction, never
// something that crosses the bridge.
func instantiateWasm(wasm []byte, scratchDefault uint32) (*boundModule, error) {
	cm, err := rt.CompileModule(ctx, wasm)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	modSeq++
	m, err := rt.InstantiateModule(ctx, cm, wazero.NewModuleConfig().WithName(fmt.Sprintf("h%d", modSeq)))
	if err != nil {
		_ = cm.Close(ctx)
		return nil, fmt.Errorf("instantiate: %w", err)
	}
	// Every refusal below has to release the instance *and* its compiled code, or a
	// rejected instantiate leaks both for the process's life.
	ok := false
	defer func() {
		if !ok {
			_ = m.Close(ctx)
			_ = cm.Close(ctx)
		}
	}()
	g, fn := m.ExportedGlobal("scratch"), m.ExportedFunction("handle")
	if g == nil || fn == nil || m.Memory() == nil {
		return nil, fmt.Errorf("missing exports: memory=%v scratch=%v handle=%v", m.Memory() != nil, g != nil, fn != nil)
	}
	// §4.1: the module reserves [scratch, scratch+size). It MAY export `scratchSize` to
	// declare more than the default — honored only if it names real, in-bounds memory, and
	// never below the default. A negative i32 arrives as a huge uint32 the bounds refuse.
	mem, s := uint64(m.Memory().Size()), uint32(g.Get())
	if s == 0 || uint64(s)+uint64(scratchDefault) > mem {
		return nil, fmt.Errorf("scratch offset %d out of bounds (mem %d)", s, mem)
	}
	size := scratchDefault
	if sg := m.ExportedGlobal("scratchSize"); sg != nil {
		d := uint32(sg.Get())
		if d < scratchDefault {
			return nil, fmt.Errorf("scratchSize %d is below the %d default", d, scratchDefault)
		}
		if uint64(s)+uint64(d) > mem {
			return nil, fmt.Errorf("scratchSize %d overflows memory (scratch %d, mem %d)", d, s, mem)
		}
		size = d
	}
	ok = true
	return &boundModule{m, cm, fn, s, size}, nil
}

// ───────────────────────── the realm and its primitives ─────────────────────────

// boot stands up the engines and the host realm: wazero + libsodium, QuickJS and its
// event loop, the platform primitives (sodium, the fs backend, TCP sockets, the
// byte-level `bridge` below), and then the ONE shared bundle. After this the realm
// holds the shared CLI and the native platform binding over it — but no node yet, and
// not even a data directory: `--dir` is the operator's, so `host/cli.ts` reads it and
// opens the store (`__fs.open`) on its way to standing a node up.
//
// Idempotent across calls: the tests boot repeatedly in one process, and each boot
// releases the previous one's engines rather than stranding them.
func boot() error {
	shutdown()
	rt = wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler())
	sd = bootSodium(rt) // crypto primitive; the realm's bundle verification routes to it
	// ML-DSA-65 for manifest suite 0x02 (§12.4) — the same wasm the browser and Node
	// use, so this target's answer to "is this bundle authentic" cannot differ from
	// theirs (mldsa.go).
	md = bootMlDsa(rt)
	// ML-KEM-768 for the primitive catalog (§14.1) — provisioned ahead of any caller,
	// because a primitive is the one thing a bundle cannot deliver (mlkem.go).
	mk = bootMlKem(rt)
	// Every installed module is a pure transform (README §4): the only host imports it
	// takes are its language runtime's shims — for AssemblyScript the three below, which
	// are exactly the set the JS host resolves (WASM/host/module-table.ts). Resolving a
	// subset would make "does this module load" a property of which target it landed on:
	// one `trace()` or `Math.random()` anywhere in a module is the difference between
	// loading and a missing-import failure. There is no host-call / caller seam
	// and no env.invoke_module dispatch callback.
	//
	// All three are inert, which is what keeps them shims rather than a seam. `seed` is a
	// constant, not the clock: a pure transform is deterministic and reaches no clock
	// (§4.2) — a module that needs entropy takes it in its input. `trace` drops its
	// arguments rather than writing them where anything could observe them, so a module's
	// only effect stays the bytes it returns (§4.3). `abort` need not trap here: AS emits
	// `unreachable` immediately after the call, so the module traps either way.
	env := rt.NewHostModuleBuilder("env")
	env.NewFunctionBuilder().WithFunc(func(context.Context, api.Module, uint32, uint32, uint32, uint32) {}).Export("abort")
	env.NewFunctionBuilder().WithFunc(func(context.Context, api.Module) float64 { return 0 }).Export("seed")
	env.NewFunctionBuilder().WithFunc(func(context.Context, api.Module, uint32, uint32, float64, float64, float64, float64, float64) {}).Export("trace")
	if _, err := env.Instantiate(ctx); err != nil {
		return fmt.Errorf("module imports: %w", err)
	}

	var err error
	if qrt, err = qjs.New(); err != nil {
		return fmt.Errorf("qjs.New: %w", err)
	}
	qc = qrt.Context()
	el = newEventLoop(qc)
	// The shared bundle is evaluated LAST: everything below it is a primitive it
	// declares (host/native-shim.ts), and its module scope reaches for some of them
	// (the console sink, the ws codec backend) straight away. The Web globals it also
	// reaches for at load time (a TextEncoder for the DOMAIN constants) come from its
	// own first module, host/native-polyfills.ts — which is why nothing installs them
	// from here.
	exposeSodium(qc, sd)
	exposeFs(qc)
	nh := exposeNet(qc, el)
	exposeBridge(qc)
	if _, err := qc.Eval("host-shell.gen.js", qjs.Code(hostShellJS)); err != nil {
		return fmt.Errorf("shell bundle: %w", err)
	}
	// The shared shim defined the __net dispatchers at module scope of the bundle
	// (host/native-shim.ts); retain them now that it has evaluated (sock.go). Before
	// this, the shaping was a Go string evaluated here — moved out so TypeScript sees it.
	if err := nh.retain(); err != nil {
		return fmt.Errorf("net retain: %w", err)
	}
	return nil
}

// shutdown releases a previous boot's engines: every confined realm, the host realm,
// and the wazero runtime holding each module's compiled code. Without it a test run
// that boots a dozen times strands a dozen of each for the process's life.
func shutdown() {
	for _, g := range realms {
		g.discard() // guest runtime only — the host realm it borrowed values from dies below
	}
	realms = map[int64]*guestRealm{}
	if qrt != nil {
		qrt.Close()
		qrt, qc, el = nil, nil, nil
	}
	if rt != nil {
		_ = rt.Close(ctx)
		rt = nil
	}
	apps = map[string]map[string]*boundModule{}
}

// exposeBridge installs `bridge`: the byte-level host powers QuickJS genuinely cannot
// reach. Everything else the shell needs is JS. The shape is declared — and so
// typechecked — in host/native-shim.ts.
func exposeBridge(qc *qjs.Context) {
	b := qc.NewObject()

	// ── the module table (§3) ──
	// One transactional install (§3.1) of one app's whole module set. The arguments are
	// the app key and the loader's `{name, wasm}[]`, read out here rather than flattened
	// on the JS side so the bridge shape and the BundleHost interface are the same shape
	// — plus the §4.1 scratch default, which the shim passes from the shared host
	// (core/wasm-limits.ts) rather than Go owning a copy of the number the JS table
	// enforces.
	b.SetPropertyStr("bindAll", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		appKey := t.Args()[0].String()
		mods := t.Args()[1]
		lenv := mods.GetPropertyStr("length")
		n := int(lenv.Int64())
		lenv.Free()
		names := make([]string, n)
		wasms := make([][]byte, n)
		for i := 0; i < n; i++ {
			m := mods.GetPropertyStr(strconv.Itoa(i))
			nv := m.GetPropertyStr("name")
			names[i] = nv.String()
			nv.Free()
			wv := m.GetPropertyStr("wasm")
			wb, err := qjs.JsTypedArrayToGo(wv)
			wv.Free()
			m.Free()
			if err != nil {
				return nil, fmt.Errorf("bindAll: %s: %w", names[i], err)
			}
			wasms[i] = wb
		}
		if err := bindAll(appKey, names, wasms, uint32(t.Args()[2].Int64())); err != nil {
			return nil, err
		}
		return t.Context().NewNull(), nil
	}))
	b.SetPropertyStr("callModule", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		pl, err := qjs.JsTypedArrayToGo(t.Args()[2])
		if err != nil {
			return t.Context().NewNull(), nil
		}
		resp := callModule(t.Args()[0].String(), t.Args()[1].String(), pl)
		if resp == nil {
			return t.Context().NewNull(), nil
		}
		return t.Context().NewArrayBuffer(resp), nil
	}))
	b.SetPropertyStr("isBound", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		return t.Context().NewBool(apps[t.Args()[0].String()][t.Args()[1].String()] != nil), nil
	}))
	b.SetPropertyStr("removeApp", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		return t.Context().NewInt64(int64(removeApp(t.Args()[0].String()))), nil
	}))

	// ── the operator's world (host/cli.ts) ──
	// Files, arguments and stdout. Five primitives, and not one of them decides
	// anything: which files get read, what the flags are called, what gets printed and
	// in what order is the shared CLI's, which is the same module the Node shell runs.
	// These used to be a `readFreshness`/`writeFreshness` pair, narrow because the only
	// JS-driven file was the freshness store; everything else about the command line
	// was a second implementation in Go.
	b.SetPropertyStr("argv", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		// JSON rather than a joined string: an argument may contain any byte, including
		// whatever separator a join would pick.
		j, err := json.Marshal(os.Args[1:])
		if err != nil {
			return nil, err
		}
		return t.Context().NewString(string(j)), nil
	}))
	b.SetPropertyStr("readFile", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		fb, err := os.ReadFile(argString(t, 0))
		if err != nil {
			// null is "absent", a branch the CLI takes (a --key file on a first boot),
			// not a failure to report from here.
			return t.Context().NewNull(), nil
		}
		return t.Context().NewArrayBuffer(fb), nil
	}))
	b.SetPropertyStr("writeFile", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		bytes, err := qjs.JsTypedArrayToGo(t.Args()[1])
		if err != nil {
			return nil, err
		}
		// Atomic, for every caller and not just the freshness store: a truncated
		// freshness file reads back as "no marks" (dropping every downgrade guard in
		// silence), and a truncated key file is a node whose identity changed.
		if err := writeFileAtomic(argString(t, 0), bytes, ".seedkernel-", os.FileMode(t.Args()[2].Int64())); err != nil {
			return nil, err
		}
		return t.Context().NewUndefined(), nil
	}))
	b.SetPropertyStr("log", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		// The realm's own console.log writes to a WASI stdout wazero leaves
		// disconnected, so operator output has to come back out through here.
		fmt.Println(argString(t, 0))
		return t.Context().NewUndefined(), nil
	}))
	b.SetPropertyStr("logErr", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		// Diagnostics — every `console.*` in the host realm (host/native-polyfills.ts).
		// Stderr rather than stdout on purpose: stdout is the operator's channel, and
		// `--get` with no `--out` writes an app's raw response bytes there, which a
		// diagnostic line interleaved into it would corrupt.
		fmt.Fprintln(os.Stderr, argString(t, 0))
		return t.Context().NewUndefined(), nil
	}))
	b.SetPropertyStr("stdout", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		bytes, err := qjs.JsTypedArrayToGo(t.Args()[0])
		if err != nil {
			return nil, err
		}
		os.Stdout.Write(bytes)
		return t.Context().NewUndefined(), nil
	}))

	installRealmBridge(qc, b) // the confined realm (§12.3) — guest.go
	qc.Global().SetPropertyStr("bridge", b)
}

// ───────────────────────── driving the shell ─────────────────────────

// callRealm drives one of the shim's entry points (host/native-shim.ts) to completion:
// it stages the arguments as __a0…__aN in the host realm, evaluates `name(__a0, …)`,
// and pumps the loop until the returned promise settles — resolving to the bytes it
// produced, or to the realm's error message. Every Go→shell call goes through here, so
// there is one place that knows how the realm reports success and failure, and no call
// site has to splice a value into JS source.
func callRealm(name string, timeout time.Duration, args ...*qjs.Value) ([]byte, error) {
	if qc == nil {
		return nil, errors.New("seedkernel: boot has not run")
	}
	expr := name + "("
	slots := make([]string, len(args))
	for i, a := range args {
		slot := fmt.Sprintf("__a%d", i)
		slots[i] = slot
		qc.Global().SetPropertyStr(slot, a) // SetPropertyStr takes the reference
		if i > 0 {
			expr += ","
		}
		expr += slot
	}
	defer func() {
		// Release the staged arguments: SetPropertyStr took their references, and a
		// slot is only re-set by the NEXT callRealm — so a process that never calls
		// again (every one-shot --put/--get, and any op after which no other op
		// follows) would leave every payload rooted on the global object for its
		// life. Overwriting the slot with undefined drops the property's value; a
		// fresh call sets the slots again anyway.
		undef := qc.NewUndefined()
		for _, slot := range slots {
			qc.Global().SetPropertyStr(slot, undef)
		}
	}()
	kind, value, msg, err := el.awaitIn(qc, expr+")", timeout)
	if err != nil {
		return nil, err
	}
	if kind != 0 {
		return nil, errors.New(msg)
	}
	return value, nil
}

// ───────────────────────── entry ─────────────────────────

// main is the whole of this target's startup: stand the engines up, evaluate the one
// shared bundle, and run the operator flow inside it.
//
// There is no CLI here. The flags, their defaults, the order a node does things in and
// the lines it prints are `host/cli.ts` — the same module the Node shell runs — and Go
// contributes only the primitives it genuinely owns (argv, files, stdout, sockets, the
// fs directory, entropy, the engines). It used to be ~300 lines of Go saying what that
// module already said, and the two drifted: `--contact-secret` came to name a file on
// one target and the hex itself on the other, and `--guest-timeout`/`--guest-memory`
// were reachable on neither. Native is an embedding — "run this JS with these host
// functions" — so the only decision left below is Go's alone: whether to keep the event
// loop running, which is what `serving` answers.
func main() {
	// One P by default: every QuickJS/wasm instruction already runs on the single
	// event-loop goroutine, so extra Ps serve only the socket goroutines — and cost
	// idle-P wakeups and cross-CPU migrations on every message. Measured on real
	// cohorts (each process on dedicated cores): bulk PUT/GET ties the multi-P
	// default, request round-trip latency halves, and 2–3 Ps — the Go default on a
	// small VPS, the typical holder box — is the pathological setting (+30–50%,
	// erratic). An explicit GOMAXPROCS still wins: this is a default, not a cap.
	if os.Getenv("GOMAXPROCS") == "" {
		runtime.GOMAXPROCS(1)
	}
	if err := boot(); err != nil {
		fatal("boot", err)
		return
	}
	// runMain resolves once the node is up, the remedies are applied, the bundle is
	// loaded and any --put/--get has run. Anything the operator got wrong — a bad flag,
	// an unreadable file, a bundle that will not load — arrives here as an error, and is
	// fatal for the reason it always was: a script driving the loader must see it rather
	// than watch a node come up as a silent bundle-less relay.
	//
	// No watchdog (timeout 0): the steps that can genuinely hang carry their own
	// deadlines — a net request settles as unreachable, `ready()` resolves on its own
	// timer — and an outer cap would only add a way to fail a `--put` that was merely
	// slow. This is also what the Node shell does, which is the point: an operation
	// bounded on one target and unbounded on the other is a difference nobody chose.
	out, err := callRealm("runMain", 0)
	if err != nil {
		fatal("seedkernel", err)
		return
	}
	var st struct{ Serving bool }
	if err := json.Unmarshal(out, &st); err != nil {
		fatal("seedkernel", err)
		return
	}
	if !st.Serving {
		return
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() { <-sig; os.Exit(0) }()
	el.stopped = false
	el.run()
}

// fatal reports a startup failure and exits non-zero, so a script driving the loader
// sees it. Callers still `return` after for readability; that return is unreachable but
// harmless.
func fatal(stage string, err error) {
	fmt.Println("ERROR: " + stage + ": " + err.Error())
	os.Exit(1)
}
