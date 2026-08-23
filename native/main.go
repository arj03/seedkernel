// seedkernel native shell. The shell itself — verify/admit/install, the guest seam, and
// the operator flow (host/cli.ts) — is the shared host TS, embedded as host-shell.gen.js
// and run in QuickJS (README §12.9). The Go layer is only the bridge: module table (§3),
// crypto, fs, sockets, the second QuickJS realm (guest.go). Pure Go, no cgo → one static
// binary.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"time"

	"seedloader/qjs"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// hostShellJS is the shared shell plus the native platform binding (host/native-shim.ts)
// — the same TS the Node shell runs, so no rule of the protocol is re-derived in a second
// language (README §12.9). Bundled by scripts/bundle-loader.mjs, never hand-edited.
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

// defaultModuleCallDeadline bounds one module invocation (§4.3, SECURITY §14). It is the
// shared guest budget (DEFAULT_GUEST_DEADLINE_MS); arming the termination check costs
// ~1.1–1.2x on module paths (module_bound_bench_test.go). SEEDKERNEL_MODULE_DEADLINE_MS
// overrides; 0 means no bound and no arming.
const defaultModuleCallDeadline = 5 * time.Second

var (
	ctx = context.Background()
	// rt holds every installed app module and the env shims they import: the untrusted
	// code the module-call bound arms (boot).
	rt wazero.Runtime
	// rtCore is the TCB's own runtime (libsodium, ML-DSA, ML-KEM), deliberately not armed:
	// a wedged libsodium is a host bug, not a confinement breach.
	rtCore wazero.Runtime
	qc     *qjs.Context
	qrt    *qjs.Runtime
	// el drives the host realm and every confined realm attached to it (loop.go).
	el *eventLoop
	// Native module instances live behind opaque slot handles. This map is target
	// plumbing, not shell identity or routing state.
	moduleSlots = map[string]map[string]*boundModule{}
	// modSeq only names wazero instances (h1, h2, …) so two installs never share a
	// module name; it is not an identity anything resolves through.
	modSeq = 0
	// moduleCallDeadline is the settled bound, resolved once at boot because the
	// runtime's arming decision is made there.
	moduleCallDeadline time.Duration = defaultModuleCallDeadline
)

// The §4.1 scratch default arrives from the shared host (core/wasm-limits.ts
// DEFAULT_SCRATCH_SIZE) with every slot build, so Go owns no copy that could drift from
// the JS table's. A module needing more exports a `scratchSize` global.

// replaceModuleSlot replaces one opaque handle's whole module set. wazero frees neither
// instances nor compiled code, so dropping the map value alone leaks per re-install.
func replaceModuleSlot(slot string, mods map[string]*boundModule) {
	disposeModuleSlot(slot)
	moduleSlots[slot] = mods
}

// closeModule releases a module's wasm instance and compiled code. nil-safe.
func closeModule(w *boundModule) {
	if w == nil {
		return
	}
	_ = w.mod.Close(ctx)
	_ = w.cmod.Close(ctx)
}

// disposeModuleSlot releases every instance behind one opaque handle.
func disposeModuleSlot(slot string) int {
	mods := moduleSlots[slot]
	for _, w := range mods {
		closeModule(w)
	}
	delete(moduleSlots, slot)
	return len(mods)
}

// callModule invokes one app's module by logical name (README §4), returning its response
// or nil if nothing is bound there. Modules are pure transforms and cannot call back, so
// there is no re-entrancy to guard.
func callModule(slot, module string, payload []byte) []byte {
	w := moduleSlots[slot][module]
	if w == nil {
		return nil
	}
	// §4: write input at scratch, call handle(input_len), read the response back. Both
	// copies are clamped to what the module reserved (§4.1) — writing past it would
	// scribble whatever it keeps beyond scratch.
	if uint32(len(payload)) > w.size || !w.mod.Memory().Write(w.scratch, payload) {
		return nil
	}
	// The runtime is armed with WithCloseOnContextDone, which is what gives the §4.3
	// bound teeth: a module that never returns is interrupted at its next loop back-edge.
	callCtx, cancel := ctx, func() {}
	if moduleCallDeadline > 0 {
		callCtx, cancel = context.WithTimeout(ctx, moduleCallDeadline)
	}
	r, err := w.fn.Call(callCtx, uint64(len(payload)))
	cancel()
	if err != nil {
		// A trap leaves the module alive (retriable); a context-done termination closed
		// it. Evict the wedged one so a reinstall recovers it.
		if w.mod.IsClosed() {
			closeModule(w)
			delete(moduleSlots[slot], module)
		}
		return nil
	}
	// handle returns output_len ≥ 0 (README §4); a 0-length result is a valid EMPTY
	// response and returns a non-nil slice, which is how a caller distinguishes it from
	// "no module / trap" (nil).
	if len(r) == 0 {
		return nil
	}
	outLen := int32(r[0])
	if outLen < 0 || uint32(outLen) > w.size {
		return nil
	}
	out := make([]byte, outLen)
	if len(out) > 0 {
		// A length past the module's memory is as bogus as an oversized payload — fail
		// rather than return zero-filled bytes.
		b, ok := w.mod.Memory().Read(w.scratch, uint32(len(out)))
		if !ok {
			return nil
		}
		copy(out, b)
	}
	return out
}

// buildModuleSlot constructs one opaque slot's modules, all or none (README §3.1),
// reached from JS as bridge.buildModules. The transaction is here because this is the
// side holding the half-built instances, which a rejected bundle must close itself.
func buildModuleSlot(slot string, names []string, wasms [][]byte, scratchDefault uint32) error {
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
	replaceModuleSlot(slot, built)
	return nil
}

// instantiateWasm compiles, instantiates and validates module bytes against the §4 ABI.
// No slot effect: the result is an intermediate of buildModuleSlot's transaction.
func instantiateWasm(wasm []byte, scratchDefault uint32) (*boundModule, error) {
	cm, err := rt.CompileModule(ctx, wasm)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	modSeq++
	// Instantiation runs the module's start section, so a never-returning initializer
	// is bound at BIND the same way module-table.ts bounds its load, at the one place a
	// call-time deadline cannot reach. The context bounds only this invocation.
	instCtx, cancel := ctx, func() {}
	if moduleCallDeadline > 0 {
		instCtx, cancel = context.WithTimeout(ctx, moduleCallDeadline)
	}
	m, err := rt.InstantiateModule(instCtx, cm, wazero.NewModuleConfig().WithName(fmt.Sprintf("h%d", modSeq)))
	cancel()
	if err != nil {
		_ = cm.Close(ctx)
		return nil, fmt.Errorf("instantiate: %w", err)
	}
	// Every refusal below has to release the instance *and* its compiled code.
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
	// §4.1: the module reserves [scratch, scratch+size); an exported `scratchSize` is
	// honored only if in-bounds and never below the default. A negative i32 arrives as a
	// huge uint32 the bounds refuse.
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

// moduleDeadlineFromEnv resolves the module-call bound, falling back to the armed
// default; 0 means no bound and no arming. Native-only configuration: the JS targets
// reach the same bound through their own lever.
func moduleDeadlineFromEnv() (time.Duration, error) {
	v := os.Getenv("SEEDKERNEL_MODULE_DEADLINE_MS")
	if v == "" {
		return defaultModuleCallDeadline, nil
	}
	ms, err := strconv.Atoi(v)
	if err != nil || ms < 0 {
		return 0, fmt.Errorf("SEEDKERNEL_MODULE_DEADLINE_MS=%q is not a non-negative millisecond count", v)
	}
	return time.Duration(ms) * time.Millisecond, nil
}

// boot stands up the engines and the host realm: wazero + libsodium, QuickJS and its
// event loop, the platform primitives, then the ONE shared bundle. No node yet — `--dir`
// is the operator's (§12.9). Idempotent: each boot releases the previous one's engines.
func boot() error {
	shutdown()
	var err error
	if moduleCallDeadline, err = moduleDeadlineFromEnv(); err != nil {
		return err
	}
	// WithCloseOnContextDone arms the termination check compiled into every loop of every
	// module on this runtime — which is why rtCore below is left unarmed (see the vars).
	rt = wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler().
		WithCloseOnContextDone(moduleCallDeadline > 0))
	rtCore = wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler())
	sd = bootSodium(rtCore)
	md = bootMlDsa(rtCore) // manifest suite 0x02 (§12.4)
	// ML-KEM-768 for the primitive catalog (§14.1) — provisioned ahead of any caller,
	// because a primitive is the one thing a bundle cannot deliver (mlkem.go).
	mk = bootMlKem(rtCore)
	// AssemblyScript's three imports, exactly the set the JS host resolves (a subset would
	// make "does this module load" a property of the target). All inert — `seed` is a
	// constant (§4.2), `trace` drops args (§4.3), `abort` need not trap.
	env := rt.NewHostModuleBuilder("env")
	env.NewFunctionBuilder().WithFunc(func(context.Context, api.Module, uint32, uint32, uint32, uint32) {}).Export("abort")
	env.NewFunctionBuilder().WithFunc(func(context.Context, api.Module) float64 { return 0 }).Export("seed")
	env.NewFunctionBuilder().WithFunc(func(context.Context, api.Module, uint32, uint32, float64, float64, float64, float64, float64) {}).Export("trace")
	if _, err := env.Instantiate(ctx); err != nil {
		return fmt.Errorf("module imports: %w", err)
	}

	if qrt, err = qjs.New(); err != nil {
		return fmt.Errorf("qjs.New: %w", err)
	}
	qc = qrt.Context()
	el = newEventLoop(qc)
	// The shared bundle evaluates LAST: its module scope already reaches for the
	// primitives above, and its load-time Web globals come from host/native-polyfills.ts.
	exposeSodium(qc, sd)
	exposeFs(qc)
	nh := exposeNet(qc, el)
	exposeBridge(qc)
	if _, err := qc.Eval("host-shell.gen.js", qjs.Code(hostShellJS)); err != nil {
		return fmt.Errorf("shell bundle: %w", err)
	}
	// The shim defines the __net dispatchers at the bundle's module scope
	// (host/native-shim.ts); retain them now that it has evaluated (sock.go).
	if err := nh.retain(); err != nil {
		return fmt.Errorf("net retain: %w", err)
	}
	return nil
}

// shutdown releases a previous boot's engines: every confined realm, the host realm, and
// the wazero runtimes holding each module's compiled code.
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
	if rtCore != nil {
		_ = rtCore.Close(ctx)
		rtCore = nil
	}
	moduleSlots = map[string]map[string]*boundModule{}
}

// exposeBridge installs `bridge`: the byte-level host powers QuickJS genuinely cannot
// reach. The shape is declared — and so typechecked — in host/native-shim.ts.
func exposeBridge(qc *qjs.Context) {
	b := qc.NewObject()

	// ── private module slots (§3) ──
	// One transactional build of an opaque slot's module set. The §4.1 scratch default
	// arrives from the shared host rather than Go owning a copy of it.
	b.SetPropertyStr("buildModules", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		slot := t.Args()[0].String()
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
				return nil, fmt.Errorf("buildModuleSlot: %s: %w", names[i], err)
			}
			wasms[i] = wb
		}
		if err := buildModuleSlot(slot, names, wasms, uint32(t.Args()[2].Int64())); err != nil {
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
	b.SetPropertyStr("disposeModules", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		return t.Context().NewInt64(int64(disposeModuleSlot(t.Args()[0].String()))), nil
	}))

	// ── the operator's world (host/cli.ts) ──
	// Files, arguments and stdout: which files get read and what gets printed is the
	// shared CLI's, the same module the Node shell runs.
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
			// null is "absent" (a --key file on a first boot), not a failure to report.
			return t.Context().NewNull(), nil
		}
		return t.Context().NewArrayBuffer(fb), nil
	}))
	b.SetPropertyStr("writeFile", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		bytes, err := qjs.JsTypedArrayToGo(t.Args()[1])
		if err != nil {
			return nil, err
		}
		// Atomic for every caller: a truncated freshness file reads back as "no marks",
		// silently dropping every downgrade guard.
		if err := writeFileAtomic(argString(t, 0), bytes, ".seedkernel-", os.FileMode(t.Args()[2].Int64())); err != nil {
			return nil, err
		}
		return t.Context().NewUndefined(), nil
	}))
	b.SetPropertyStr("log", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		// The realm's console.log writes to a WASI stdout wazero leaves disconnected, so
		// operator output returns via stderr — stdout is `--op`'s raw data channel.
		fmt.Fprintln(os.Stderr, argString(t, 0))
		return t.Context().NewUndefined(), nil
	}))
	b.SetPropertyStr("logErr", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		// Diagnostics — every `console.*` in the host realm (host/native-polyfills.ts).
		// Stderr for the same reason as `log` above.
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
	b.SetPropertyStr("stdin", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		// `--op`'s argument, read whole; cli.ts calls this lazily, so a serving node never
		// waits on stdin. A read error answers the same as an empty pipe.
		bytes, err := io.ReadAll(os.Stdin)
		if err != nil {
			bytes = nil
		}
		return bytesAB(t, bytes), nil
	}))

	installRealmBridge(qc, b) // the confined realm (§12.3) — guest.go
	qc.Global().SetPropertyStr("bridge", b)
}

// ───────────────────────── driving the shell ─────────────────────────

// callRealm drives one of the shim's entry points (host/native-shim.ts): it stages the
// arguments as __a0…__aN, evaluates `name(__a0, …)`, and pumps the loop until the
// promise settles. Every Go→shell call goes through here.
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
		// Release the staged arguments: SetPropertyStr took their references and a slot
		// is only re-set by the next callRealm, so a one-shot --op would leak payloads.
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
// shared bundle, run the operator flow inside it. No CLI — the flags and the lines it
// prints are host/cli.ts. The only Go decision is whether to keep the loop running.
func main() {
	// One P by default: all QuickJS/wasm work already runs on the event-loop goroutine,
	// so extra Ps serve only socket goroutines and cost idle-P wakeups per message (2–3
	// Ps is the pathological setting, +30–50% on measured cohorts). Not a cap.
	if os.Getenv("GOMAXPROCS") == "" {
		runtime.GOMAXPROCS(1)
	}
	if err := boot(); err != nil {
		fatal("boot", err)
		return
	}
	// runMain resolves once the node is up and any `--op` has run; operator errors arrive
	// here as errors a driving script must see. No watchdog (timeout 0): the hanging steps
	// carry their own deadlines, and the Node shell is unbounded here too.
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
// sees it.
func fatal(stage string, err error) {
	fmt.Println("ERROR: " + stage + ": " + err.Error())
	os.Exit(1)
}
