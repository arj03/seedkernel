// seedkernel native shell. The runtime is wasm (kernel); apps arrive as signed
// bundles (README §12) — nothing application-specific lives here. Host
// orchestration (bundle verification + admission §12.4/§12.5) is JavaScript in QuickJS —
// the shared host TS, compiled and bundled to the embedded host-*.gen.js, never a
// second implementation (README §12.9); this Go layer is only the bridge: loads the
// kernel wasm, supplies the crypto primitives (Ed25519 via libsodium, BLAKE2b native) the
// realm verifies bundles with, and exposes byte primitives to the realm. Pure Go, no
// cgo (QuickJS is quickjs-ng wasm over the in-repo qjs/wazero bridge) → one static binary.
package main

import (
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"seedloader/qjs"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

//go:embed wasm/kernel.wasm
var kernelWasm []byte

// hostInstallerJS is the shared bundle loader + admission policy + bundle format,
// bundled from build/host/{util,domains,bundle,policy,native-shim}.js. It runs in
// QuickJS over the byte-level `bridge` below and is the ONLY implementation of the
// §12.5 admission rules and the §12.4 bundle load order — the same compiled TS the Node
// shell runs, so the protocol is never re-derived in a second language (README §12.9).
// Regenerate with `npm run build:loader-bundles`; do not hand-edit.
//
//go:embed host-installer.gen.js
var hostInstallerJS string

// ───────────────────────── shell core (bridge) ─────────────────────────

type wasmHandler struct {
	mod     api.Module
	cmod    wazero.CompiledModule // retained so an upgrade can release the old compiled code
	fn      api.Function
	scratch uint32 // §4.1 scratch offset, read once at instantiation
	size    uint32 // bytes reserved there: the declared scratchSize, or the default
}

// entry is what the loader tracks per installed handler, keyed by the kernel's handler id.
// The kernel owns name → id (find_handler) — the one routing decision every path resolves
// through — so keying by id here leaves no second name table to drift from it. Exactly one
// of nat (a native host service) / wasm (an installed module) is set.
type entry struct {
	nat  func([]byte) []byte
	wasm *wasmHandler
}

var (
	ctx     = context.Background()
	rt      wazero.Runtime
	kn      api.Module
	qc      *qjs.Context
	qrt     *qjs.Runtime
	entries = map[int32]*entry{} // kernel handler id → impl (the kernel owns name → id)
	nextID  = int32(10)
)

// defaultScratchSize is the I/O region a handler reserves at `scratch` when it declares
// none (README §4.1). One needing more exports a `scratchSize` global — seedstore's codec
// reserves 2 MB for whole-chunk shards — which installWasm reads once and clamps its
// cross-module copies to.
const defaultScratchSize = 0x20000 // 128 KB

// wasmCall invokes a wasm export, returning nil if it's missing or the call failed —
// so a missing ABI function degrades instead of panicking the host.
func wasmCall(m api.Module, name string, args ...uint64) []uint64 {
	if fn := m.ExportedFunction(name); fn != nil {
		if r, err := fn.Call(ctx, args...); err == nil {
			return r
		}
	}
	return nil
}

func wr(m api.Module, data []byte) uint32 {
	r := wasmCall(m, "alloc", uint64(len(data)))
	// alloc can fail two ways: the call itself faults (len(r)==0) or it returns a NULL
	// pointer (r[0]==0) when the module is out of memory. Either is a 0 return here —
	// writing at address 0 would scribble the module's low memory, and callers key off 0.
	if len(r) == 0 || r[0] == 0 {
		return 0
	}
	p := uint32(r[0])
	if !m.Memory().Write(p, data) {
		wasmCall(m, "dealloc", uint64(p)) // hand the block back rather than leak it
		return 0
	}
	return p
}

// name is a bootstrap handler name (README §5.1): the literal-ASCII
// "seedkernel.bootstrap.v1:" + canonical. Bootstrap names are plain ASCII, not
// genesis-hash-derived — swapping the genesis hash no longer re-derives the
// bootstrap namespace (only bytes_hash still depends on the genesis hash).
func name(canonical string) []byte {
	return []byte("seedkernel.bootstrap.v1:" + canonical)
}

// findHandlerID resolves the id bound to `n` through the kernel's find_handler export, or
// -1. The single name → id lookup every loader path goes through (callHandler, install,
// boot), so none can resolve a name differently (§3.1).
func findHandlerID(n []byte) int32 {
	p := wr(kn, n)
	if p == 0 {
		return -1
	}
	r := wasmCall(kn, "find_handler", uint64(p), uint64(len(n)))
	wasmCall(kn, "dealloc", uint64(p))
	if len(r) == 0 {
		return -1
	}
	return int32(r[0])
}

// bindHandler binds `n` to `id` in the kernel's table and records `e` under that id,
// dropping whatever the name was bound to before. The one place "one name ⇒ one handler id"
// is maintained, so no install path leaves a stale entry — or a leaked wasm instance —
// behind. The displaced id is resolved before the rebind, so it sees the pre-rebind table.
func bindHandler(n []byte, id int32, e *entry) bool {
	old := findHandlerID(n)
	p := wr(kn, n)
	if p == 0 {
		return false
	}
	wasmCall(kn, "set_handler", uint64(p), uint64(len(n)), uint64(uint32(id)))
	wasmCall(kn, "dealloc", uint64(p))
	if old >= 0 && old != id {
		dropEntry(old)
	}
	entries[id] = e
	return true
}

// dropEntry forgets the entry at `id`, closing its wasm instance and compiled code. Go
// frees neither on its own, so dropping the map key alone would leak one linear memory +
// its JITed code per replace/uninstall for the process's life.
func dropEntry(id int32) {
	e := entries[id]
	if e == nil {
		return
	}
	if w := e.wasm; w != nil {
		_ = w.mod.Close(ctx)
		_ = w.cmod.Close(ctx)
	}
	delete(entries, id)
}

// isRegistered answers the kernel's handler-table query for `n`: a name is bound
// exactly when find_handler resolves it, so this asks that rather than a second
// export answering the same question. The shared §12.5 admission consults it so a
// first install cannot overlay a SetHandler-seeded bootstrap slot.
func isRegistered(n []byte) bool {
	return findHandlerID(n) >= 0
}

// removeHandler unbinds `n` via the kernel's remove_handler (§12.5) and drops the entry it
// resolved to. The id is read before the removal, since afterwards the name maps to nothing.
func removeHandler(n []byte) bool {
	id := findHandlerID(n)
	p := wr(kn, n)
	if p == 0 {
		return false
	}
	r := wasmCall(kn, "remove_handler", uint64(p), uint64(len(n)))
	wasmCall(kn, "dealloc", uint64(p))
	if len(r) == 0 || r[0] != 1 {
		return false
	}
	if id >= 0 {
		dropEntry(id)
	}
	return true
}

func load(wasm []byte, modName string) api.Module {
	cm, _ := rt.CompileModule(ctx, wasm)
	m, err := rt.InstantiateModule(ctx, cm, wazero.NewModuleConfig().WithName(modName))
	if err != nil {
		panic(err)
	}
	return m
}

// invokeByID runs the handler bound to `id` (README §4 scratch ABI) and returns its
// response. Routing already happened, by id against the kernel's table, so `n` is only
// passed through to native handlers. The one invocation path, reached through callHandler.
func invokeByID(id int32, n, payload []byte) []byte {
	e := entries[id]
	if e == nil {
		return nil
	}
	if w := e.wasm; w != nil {
		// §4: write input at the scratch offset, call handle(input_len), read the response
		// back from the same offset. Both copies are clamped to what the handler reserved
		// (§4.1) — writing past it would scribble whatever it keeps beyond scratch.
		if uint32(len(payload)) > w.size || !w.mod.Memory().Write(w.scratch, payload) {
			return nil
		}
		r, err := w.fn.Call(ctx, uint64(len(payload)))
		// handle returns output_len ≥ 0 (README §4): only a trap (err) or a negative
		// length is a failure. A 0-length result is a valid EMPTY response, not a
		// failure — return a non-nil slice for it so a caller can distinguish "empty OK"
		// from "no handler / trap" (nil).
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
	if e.nat != nil {
		return e.nat(payload)
	}
	return nil
}

// callHandler invokes an installed handler by name (README §4), returning its response or
// nil if the name is unbound or the handler produced nothing. The one way into an installed
// module: the host uses it directly and the cap-bridge routes MODULE_CALL (§12.2) through
// it. Handlers are pure transforms and cannot call back, so there is no re-entrancy to guard.
func callHandler(n, payload []byte) []byte {
	id := findHandlerID(n)
	if id < 0 {
		return nil
	}
	return invokeByID(id, n, payload)
}

// installWasm instantiates handler bytes and binds them to the raw name `n`. The replace is
// unconditional — the §12.5 admission already ran, and bindHandler releases whatever the name
// displaced. Exposed to JS as bridge.installWasm (only the host can instantiate wasm, §12.4).
func installWasm(n, wasm []byte) bool {
	cm, err := rt.CompileModule(ctx, wasm)
	if err != nil {
		return false
	}
	m, err := rt.InstantiateModule(ctx, cm, wazero.NewModuleConfig().WithName(fmt.Sprintf("h%d", nextID)))
	if err != nil {
		_ = cm.Close(ctx) // instantiation failed — release the compiled code
		return false
	}
	// Every refusal below has to release the instance *and* its compiled code, or a
	// rejected install leaks both for the process's life.
	bound := false
	defer func() {
		if !bound {
			_ = m.Close(ctx)
			_ = cm.Close(ctx)
		}
	}()
	g, fn := m.ExportedGlobal("scratch"), m.ExportedFunction("handle")
	if g == nil || fn == nil || m.Memory() == nil {
		return false
	}
	// §4.1: the handler reserves [scratch, scratch+size). It MAY export `scratchSize` to
	// declare more than the default — honored only if it names real, in-bounds memory, and
	// never below the default. A negative i32 arrives as a huge uint32 the bounds refuse.
	mem, s := uint64(m.Memory().Size()), uint32(g.Get())
	if s == 0 || uint64(s)+defaultScratchSize > mem {
		return false
	}
	size := uint32(defaultScratchSize)
	if sg := m.ExportedGlobal("scratchSize"); sg != nil {
		if d := uint32(sg.Get()); d >= defaultScratchSize && uint64(s)+uint64(d) <= mem {
			size = d
		}
	}
	id := nextID
	nextID++
	bound = bindHandler(n, id, &entry{wasm: &wasmHandler{m, cm, fn, s, size}})
	return bound
}

// boot wires the wasm host imports, instantiates kernel + signature, and stands up the
// QuickJS realm running the shared bundle loader + admission policy (host-installer.gen.js).
func boot() {
	rt = wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler())
	sd = bootSodium(rt) // crypto primitive; the genesis verify routes to it below
	// The kernel and every installed handler are pure transforms (README §4): the only
	// host import they take is the AssemblyScript `env.abort` shim. There is no kernel.call
	// / kernel.caller seam and no env.invoke_handler dispatch callback any more.
	env := rt.NewHostModuleBuilder("env")
	env.NewFunctionBuilder().WithFunc(func(context.Context, api.Module, uint32, uint32, uint32, uint32) {}).Export("abort")
	env.Instantiate(ctx)
	kn = load(kernelWasm, "kernelmod")
	// The runtime above is fresh, so its kernel table is empty: drop entries a previous boot
	// left behind (the tests boot repeatedly) rather than keep ids from a dead runtime.
	entries = map[int32]*entry{}

	// QuickJS realm: expose the byte-level bridge, then run the JS orchestration.
	var err error
	if qrt, err = qjs.New(); err != nil {
		panic(fmt.Sprintf("qjs.New: %v", err))
	}
	qc = qrt.Context()
	b := qc.NewObject()
	fn := func(g func(*qjs.This) (*qjs.Value, error)) *qjs.Value { return qc.Function(g) }
	b.SetPropertyStr("installWasm", fn(func(t *qjs.This) (*qjs.Value, error) {
		nm, _ := qjs.JsTypedArrayToGo(t.Args()[0])
		wb, _ := qjs.JsTypedArrayToGo(t.Args()[1])
		return t.Context().NewBool(installWasm(nm, wb)), nil
	}))
	b.SetPropertyStr("utf8", fn(func(t *qjs.This) (*qjs.Value, error) {
		d, _ := qjs.JsTypedArrayToGo(t.Args()[0])
		return t.Context().NewString(string(d)), nil
	}))
	// The §12.5 admission refuses to overlay a SetHandler-seeded slot, so the
	// shared policy needs the kernel's handler-table query.
	b.SetPropertyStr("isRegistered", fn(func(t *qjs.This) (*qjs.Value, error) {
		n, _ := qjs.JsTypedArrayToGo(t.Args()[0])
		return t.Context().NewBool(isRegistered(n)), nil
	}))
	b.SetPropertyStr("removeHandler", fn(func(t *qjs.This) (*qjs.Value, error) {
		n, _ := qjs.JsTypedArrayToGo(t.Args()[0])
		return t.Context().NewBool(removeHandler(n)), nil
	}))
	// Bundle-freshness persistence (§12.4): the arithmetic is shared JS, the durable
	// write is ours — a truncated store reads back as "no marks", silently dropping
	// every downgrade guard, so the write must be atomic.
	b.SetPropertyStr("readFreshness", fn(func(t *qjs.This) (*qjs.Value, error) {
		if freshnessStorePath == "" {
			return t.Context().NewNull(), nil
		}
		fb, err := os.ReadFile(freshnessStorePath)
		if err != nil {
			return t.Context().NewNull(), nil // absent ⇒ first boot
		}
		return t.Context().NewString(string(fb)), nil
	}))
	b.SetPropertyStr("writeFreshness", fn(func(t *qjs.This) (*qjs.Value, error) {
		if freshnessStorePath == "" {
			return t.Context().NewNull(), nil // no store configured (tests) ⇒ in-memory only
		}
		// Logged, not fatal: the in-memory mark still guards the running process; only
		// the next boot would be unprotected, which the operator must see.
		if err := writeFileAtomic(freshnessStorePath, []byte(t.Args()[0].String())); err != nil {
			fmt.Fprintf(os.Stderr, "seedkernel: could not persist freshness mark to %s: %v\n", freshnessStorePath, err)
		}
		return t.Context().NewNull(), nil
	}))
	qc.Global().SetPropertyStr("bridge", b)
	exposeSodium(qc, sd) // installs `sodium` (libsodium-wrappers shape) into the realm
	// bundle.ts builds its manifest domain prefix with TextEncoder at module scope, so
	// the polyfills must be in place before the bundle is evaluated.
	installPolyfills(qc)
	if _, err := qc.Eval("host-installer.gen.js", qjs.Code(hostInstallerJS)); err != nil {
		panic(err)
	}

	// No `install` wire handler: code arrives only as a signed bundle (§12.4), and
	// loadBundleFiles admits each verified module directly via installWasm. There is
	// no message-driven install path (§12.4).
}

// registerNativeAt binds a native host service (a Go closure) at the raw kernel name `n`,
// reachable by name through callHandler exactly like an installed module — the native
// counterpart of the JS host's `register`. Returns the id the kernel now has it under.
func registerNativeAt(n []byte, fn func([]byte) []byte) int32 {
	id := nextID
	nextID++
	bindHandler(n, id, &entry{nat: fn})
	return id
}

func registerNative(canonical string, fn func([]byte) []byte) int32 {
	return registerNativeAt(name(canonical), fn)
}

// invokeFree calls the named global function as global.name(args...), then frees the
// resolved function value and every arg — QJS_Call only borrows them — and returns the
// result for the caller to consume and Free. It centralizes the loader's one-shot host
// calls so none leaks a QuickJS handle. The cached Global() is the `this` and is never
// freed; on error the returned value is nil (normalize already freed it).
func invokeFree(fnName string, args ...*qjs.Value) (*qjs.Value, error) {
	fn := qc.Global().GetPropertyStr(fnName)
	res, err := qc.Invoke(fn, qc.Global(), args...)
	fn.Free()
	for _, a := range args {
		a.Free()
	}
	return res, err
}

// loadedBundle is the slim descriptor of a verified bundle the node needs to run
// its guest: the declared cap domains, the manifest config (author-signed
// structural constants), and the verified guest source. `author` (hex) + `app` key
// bundle freshness and derive the guest-signing scope (README §12.2, §12.4).
type loadedBundle struct {
	app, author string
	version     int
	caps        []string
	config      json.RawMessage // manifest `config` object (merged under operator config)
	guestSource string
}

// loaded is the bundle the node is running (set by loadBundle), nil until one loads.
var loaded *loadedBundle

// loadBundle loads a signed app bundle directory (README §12.4). Reading the directory
// is all this does: the whole load — manifest signature, policy governance, freshness,
// per-module and guest integrity, and the order they run in — is the shared JS loader
// (bundle.ts, via host-installer.gen.js), which admits each verified module through
// the shared §12.5 policy. On success it records the verified guest
// source + caps + config in `loaded` for the node.
func loadBundle(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "ERROR: " + err.Error()
	}
	goFiles := map[string][]byte{}
	jsFiles := qc.NewObject()
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		fb, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue // unreadable file ⇒ absent; the loader fails it on the hash it can't match
		}
		goFiles[e.Name()] = fb
		jsFiles.SetPropertyStr(e.Name(), qc.NewArrayBuffer(fb))
	}
	res, err := invokeFree("loadBundleFiles", jsFiles)
	if err != nil {
		return "ERROR(invoke): " + err.Error()
	}
	out := res.String()
	res.Free()
	if strings.HasPrefix(out, "ERROR") {
		return out
	}
	var m struct {
		App, Author string
		Version     int
		Caps        []string
		Guest       string
		Config      json.RawMessage
		Installed   []string
	}
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		return "ERROR(json): " + err.Error()
	}
	loaded = &loadedBundle{
		app: m.App, author: m.Author, version: m.Version, caps: m.Caps,
		config: m.Config, guestSource: string(goFiles[m.Guest]),
	}
	return fmt.Sprintf("%s v%d  installed=%v", m.App, m.Version, m.Installed)
}

// freshnessStorePath is where the shared loader's bundle-freshness marks are persisted
// (README §12.4). The marks and the monotonic rule live in JS (bundle.ts FreshnessMarks);
// Go owns only the path and the atomic write. Empty (tests) ⇒ purely in-memory, so a
// fresh process starts with −∞ for every key.
var freshnessStorePath string

// writeFileAtomic writes b to path via a sibling temp file + rename, so a reader (or a
// crash) only ever sees the old or the complete new contents — never a truncated write.
func writeFileAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".freshness-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// applyPolicy installs the shell's install policy (host/policy.ts shape) into the JS
// realm. "" is not "no policy" but the deny-all default — an empty author set, so the
// node boots and serves and every install is refused (README §14) — resolved by the
// shared policyFromJson, the same function the Node shell resolves it through. A
// provided config is parsed strictly: parsePolicy throws on malformed input, which
// surfaces here as an error, so a typo'd allowed-keys.json fails the boot loudly
// rather than silently widening trust.
func applyPolicy(json string) error {
	arg := qc.NewString(json)
	if strings.TrimSpace(json) == "" {
		arg.Free()
		arg = qc.NewNull()
	}
	res, err := invokeFree("setPolicy", arg)
	if res != nil {
		res.Free()
	}
	return err
}

// wireModuleCall exposes __moduleCall(name, payload) to the realm: the cap-bridge's
// MODULE_CALL backend, routing an installed handler call through callHandler (the wasm app
// modules: codec, reputation). null when the handler is absent or returns nothing.
func wireModuleCall() {
	qc.Global().SetPropertyStr("__moduleCall", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		nm, err := qjs.JsTypedArrayToGo(t.Args()[0])
		if err != nil {
			return t.Context().NewNull(), nil
		}
		pl, err := qjs.JsTypedArrayToGo(t.Args()[1])
		if err != nil {
			return t.Context().NewNull(), nil
		}
		resp := callHandler(nm, pl)
		if resp == nil {
			return t.Context().NewNull(), nil
		}
		return t.Context().NewArrayBuffer(resp), nil
	}))
}

// ───────────────────────── entry ─────────────────────────

// cliArgs is the loader's CLI surface (mirrors host/main.ts). The bundle dir is a
// positional arg (default: the seedstore bundle) or --bundle.
type cliArgs struct {
	bundleDir, dataDir, policyPath, keyPath string
	listen, wsListen, peers                 string
	put, get, out, appConfig                string
	timeoutMs                               int
}

func parseCLI() cliArgs {
	var a cliArgs
	flag.StringVar(&a.bundleDir, "bundle", "../../seedstore/WASM/bundle", "bundle directory (also accepted as a positional argument)")
	flag.StringVar(&a.dataDir, "dir", "./data", "data directory")
	flag.StringVar(&a.keyPath, "key", "./seedkernel.key", "identity key file")
	flag.StringVar(&a.policyPath, "policy", "", "policy JSON file: authors allowed to install (default: deny-all — no install lands)")
	flag.StringVar(&a.listen, "listen", "", "TCP listen address (host:port)")
	flag.StringVar(&a.wsListen, "ws-listen", "", "WebSocket listen address (host:port)")
	flag.StringVar(&a.peers, "peers", "", "cohort peers to dial (pk@host:port,…)")
	flag.StringVar(&a.put, "put", "", "put a file, print its hash, and exit")
	flag.StringVar(&a.get, "get", "", "get a hash and exit")
	flag.StringVar(&a.out, "out", "", "output path for --get")
	flag.StringVar(&a.appConfig, "app-config", "", "app config JSON")
	flag.IntVar(&a.timeoutMs, "timeout", 2000, "network start timeout (ms)")
	flag.Parse()
	if flag.NArg() > 0 {
		a.bundleDir = flag.Arg(0)
	}
	return a
}

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
	a := parseCLI()
	boot()

	// Install policy. Omitting --policy is not "no policy" but deny-all: the realm boots
	// with an empty author set, so the node serves and nothing installs — including the
	// bundle below, whose manifest author must be listed too (README §14).
	if a.policyPath != "" {
		pj, err := os.ReadFile(a.policyPath)
		if err != nil {
			fatal("policy", err)
			return
		}
		if err := applyPolicy(string(pj)); err != nil {
			fatal("policy", err)
			return
		}
	}

	// The engine host realm over the booted kernel: fs backend + __net + the shared route
	// bundle + cap-bridge + node-setup glue, all driven by one loop. Same installEngineHost
	// the net/holder tests assemble, so main and the tests share one wiring path. boot()
	// already exposed sodium + the kernel bridge; installEngineHost re-runs them idempotently.
	el := newEventLoop(qc)
	if err := installEngineHost(qc, el, sd, a.dataDir); err != nil {
		fatal("host", err)
		return
	}
	wireModuleCall()

	// Identity (load --key or mint + persist) → the network + transport over it.
	skHex, err := loadOrMintKey(a.keyPath)
	if err != nil {
		fatal("key", err)
		return
	}
	pkVal, err := qc.Eval("<identity>", qjs.Code(fmt.Sprintf(`__setIdentity(%q)`, skHex)))
	if err != nil {
		fatal("identity", err)
		return
	}
	pkHex := pkVal.String()
	pkVal.Free()

	listenJS, err := jsAddr(a.listen)
	if err != nil {
		fatal("listen", err)
		return
	}
	wsListenJS, err := jsAddr(a.wsListen)
	if err != nil {
		fatal("ws-listen", err)
		return
	}
	if _, _, _, err := el.await(fmt.Sprintf(`__startNode(%s, %s, %d)`, listenJS, wsListenJS, a.timeoutMs), 8*time.Second); err != nil {
		fatal("network start", err)
		return
	}
	portsVal := mustEval(`__nodePorts()`)
	portBytes, err := qjs.JsTypedArrayToGo(portsVal)
	portsVal.Free()
	if err != nil {
		fatal("ports", err)
		return
	}
	tcpPort := int(portBytes[0])<<8 | int(portBytes[1])
	wsPort := int(portBytes[2])<<8 | int(portBytes[3])

	// Cohort peers (--peers: pk@host:port,…) the guest may reach via net.peers.
	peerSpecs := splitList(a.peers)
	for _, spec := range peerSpecs {
		if _, err := qc.Eval("<peer>", qjs.Code(fmt.Sprintf(`__addPeer(%q)`, spec))); err != nil {
			fatal("peer "+spec, err)
			return
		}
	}
	if len(peerSpecs) > 0 {
		if _, _, _, err := el.await(`__nodeReady()`, 8*time.Second); err != nil {
			fatal("cohort ready", err)
			return
		}
	}

	fmt.Printf("seedkernel-loader %s\n", pkHex)
	fmt.Printf("  policy %s\n", orNone(a.policyPath))
	fmt.Printf("  store  %s (fs.* backend)\n", a.dataDir)
	fmt.Printf("  cohort %d peer(s)\n", len(peerSpecs))
	if tcpPort != 0 {
		fmt.Printf("  tcp    listening on :%d\n", tcpPort)
	}
	if wsPort != 0 {
		fmt.Printf("  ws     listening on :%d\n", wsPort)
	}

	// The signed bundle: verify + install its modules, capture its guest. Every invocation
	// targets a bundle (there is always a --bundle / default dir), so a load error is fatal:
	// the node has no app to run or serve. Exit non-zero rather than keep serving as a silent
	// bundle-less relay, which would hide the failure from a driving script (§12.4).
	// Persist the freshness high-water mark in a sibling of the data dir, so a
	// fs-capable guest (whose keys are files *inside* the dir) can never tamper with it.
	freshnessStorePath = filepath.Clean(a.dataDir) + ".freshness.json"
	bundleResult := loadBundle(a.bundleDir)
	fmt.Println("  bundle " + bundleResult)
	if strings.HasPrefix(bundleResult, "ERROR") {
		os.Exit(1)
	}

	var g *guestRealm
	// A handler-only bundle (app modules, no zero-authority realm) declares no guest —
	// guestSource is empty, so there is nothing to run and `g` stays nil. The seedstore
	// bundle always ships a guest, so this guard is defensive, not a second posture.
	if loaded != nil && loaded.guestSource != "" {
		// Build the cap funnel for the bundle's declared domains, then the confined
		// guest from its verified source + the merged APP config (manifest ∪ operator).
		if _, err := qc.Eval("<bridge>", qjs.Code(fmt.Sprintf(`__buildNodeBridge(%s, %q, %q)`, jsStrArray(loaded.caps), loaded.author, loaded.app))); err != nil {
			fatal("cap-bridge", err)
			return
		}
		appJSON, err := mergeConfig(loaded.config, a.appConfig)
		if err != nil {
			fatal("app-config", err)
			return
		}
		if g, err = newGuestRealm(el, appJSON, loaded.guestSource); err != nil {
			fatal("guest", err)
			return
		}
		defer g.close()

		// One-shot client ops through the loaded guest — "the shell runs the app" as
		// the initiator (README §12.8). Arguments/results cross as raw bytes.
		if a.put != "" {
			data, err := os.ReadFile(a.put)
			if err != nil {
				fatal("put", err)
				return
			}
			r, err := g.runGuest("put", data)
			if err != nil {
				fatal("put", err)
				return
			}
			fmt.Printf("  PUT ok: %d B response\n    %s\n", len(r), hex.EncodeToString(r))
		}
		if a.get != "" {
			arg, err := decodeGetArg(a.get)
			if err != nil {
				fatal("get", err)
				return
			}
			data, err := g.runGuest("get", arg)
			if err != nil {
				fatal("get", err)
				return
			}
			if a.out != "" {
				if err := os.WriteFile(a.out, data, 0o644); err != nil {
					fatal("out", err)
					return
				}
				fmt.Printf("  GET ok: %d B → %s\n", len(data), a.out)
			} else {
				os.Stdout.Write(data)
			}
		}
	}

	serving := tcpPort != 0 || wsPort != 0
	if !serving {
		return
	}
	// A serving node with an app loaded also answers for the cohort: route incoming
	// requests to the guest's confined `handle` — no app-specific host code (§12.8).
	if g != nil {
		wireServe(qc, g)
		fmt.Println("  serving the app's request side from the confined guest")
	}
	fmt.Println("serving — Ctrl-C to stop")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() { <-sig; os.Exit(0) }()
	el.stopped = false
	el.run()
}

// ── CLI helpers ──────────────────────────────────────────────────────────────

// fatal reports a startup / one-shot failure and exits non-zero, so a script driving the
// loader (--put/--get, policy load, identity, network start) sees it. Callers still `return`
// after for readability; that return is unreachable but harmless.
func fatal(stage string, err error) {
	fmt.Println("ERROR: " + stage + ": " + err.Error())
	os.Exit(1)
}

func orNone(s string) string {
	if s == "" {
		return "(none — installs disabled)"
	}
	return s
}

// mustEval evaluates a side-effect-free JS expression that cannot fail in practice
// (a glue function the loader itself installed); a failure is a loader bug, so panic.
func mustEval(code string) *qjs.Value {
	v, err := qc.Eval("<eval>", qjs.Code(code))
	if err != nil {
		panic(fmt.Sprintf("eval %q: %v", code, err))
	}
	return v
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// jsAddr renders a host:port flag as the `{ host, port }` JS literal makeNetwork
// wants (empty ⇒ `undefined`, i.e. not listening on that transport).
func jsAddr(s string) (string, error) {
	if strings.TrimSpace(s) == "" {
		return "undefined", nil
	}
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", fmt.Errorf("expected host:port, got %q", s)
	}
	host := s[:i]
	if host == "" {
		host = "0.0.0.0"
	}
	port, err := strconv.Atoi(s[i+1:])
	if err != nil || port < 0 {
		return "", fmt.Errorf("bad port in %q", s)
	}
	return fmt.Sprintf(`{ host: %q, port: %d }`, host, port), nil
}

// jsStrArray renders a string slice as a JS array literal (`[]` when empty, so an
// undeclared-caps bundle grants no ops rather than `null`).
func jsStrArray(ss []string) string {
	if len(ss) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(ss)
	return string(b)
}

// loadOrMintKey returns the node's 64-byte ed25519 secret key as hex: read from
// keyPath if present, else minted via libsodium (byte-identical to a browser/Bun
// node's keypair) and persisted. The public key is its 32-byte tail.
func loadOrMintKey(keyPath string) (string, error) {
	if b, err := os.ReadFile(keyPath); err == nil {
		skHex := strings.TrimSpace(string(b))
		if len(skHex) != 128 {
			return "", fmt.Errorf("--key must hold a 64-byte secret key (hex), got %d chars", len(skHex))
		}
		// Validate here: the JS fromHex maps non-hex pairs to 0, so a corrupt key
		// file would silently boot the node under a different identity.
		if _, err := hex.DecodeString(skHex); err != nil {
			return "", fmt.Errorf("--key %s: %w", keyPath, err)
		}
		return skHex, nil
	}
	v, err := qc.Eval("<mint>", qjs.Code(
		`(function(){ const kp = sodium.crypto_sign_keypair(); return Array.from(kp.privateKey, b => b.toString(16).padStart(2,"0")).join(""); })()`,
	))
	if err != nil {
		return "", err
	}
	skHex := v.String()
	v.Free()
	if err := os.WriteFile(keyPath, []byte(skHex), 0o600); err != nil {
		return "", err
	}
	return skHex, nil
}

// mergeConfig builds the guest's APP JSON: the manifest's author-signed config with
// the operator's --app-config (a JSON file) merged over it (operator wins).
func mergeConfig(manifest json.RawMessage, appConfigPath string) (string, error) {
	merged := map[string]any{}
	if len(manifest) > 0 {
		if err := json.Unmarshal(manifest, &merged); err != nil {
			return "", fmt.Errorf("manifest config: %w", err)
		}
	}
	if appConfigPath != "" {
		b, err := os.ReadFile(appConfigPath)
		if err != nil {
			return "", err
		}
		op := map[string]any{}
		if err := json.Unmarshal(b, &op); err != nil {
			return "", fmt.Errorf("app-config: %w", err)
		}
		for k, v := range op {
			merged[k] = v
		}
	}
	out, err := json.Marshal(merged)
	return string(out), err
}

// decodeGetArg parses a --get argument: colon-joined hex tokens, concatenated into
// the raw bytes the guest's get entrypoint expects (the shell never decodes meaning).
func decodeGetArg(s string) ([]byte, error) {
	var out []byte
	for _, tok := range strings.Split(s, ":") {
		b, err := hex.DecodeString(tok)
		if err != nil {
			return nil, fmt.Errorf("--get token %q: %w", tok, err)
		}
		out = append(out, b...)
	}
	return out, nil
}
