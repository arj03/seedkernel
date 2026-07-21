// seedkernel native shell. Apps arrive as signed bundles (README §12) — nothing
// application-specific lives here. Host orchestration (bundle verification + admission
// §12.4/§12.5) is JavaScript in QuickJS — the shared host TS, compiled and bundled to the
// embedded host-*.gen.js, never a second implementation (README §12.9); this Go layer is
// only the bridge: it owns the handler table (§3), supplies the crypto primitives
// (Ed25519 via libsodium, BLAKE2b native) the realm verifies bundles with, and exposes
// byte primitives to the realm. Pure Go, no cgo (QuickJS is quickjs-ng wasm over the
// in-repo qjs/wazero bridge) → one static binary.
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

var (
	ctx = context.Background()
	rt  wazero.Runtime
	qc  *qjs.Context
	qrt *qjs.Runtime
	// handlers is the handler table (README §3): the whole kernel, which is a contract
	// rather than an artifact. A name is bound exactly when it is a key here, so the §3.1
	// SetHandler / remove / resolve operations are map assignment, delete and lookup —
	// there is no id indirection and no second table to drift from this one. Every value
	// is an installed module: bundles are the one way code arrives (§12.4).
	handlers = map[string]*wasmHandler{}
	// modSeq only names wazero instances (h1, h2, …) so two installs never share a
	// module name; it is not an identity anything resolves through.
	modSeq = 0
)

// defaultScratchSize is the I/O region a handler reserves at `scratch` when it declares
// none (README §4.1). One needing more exports a `scratchSize` global — seedstore's codec
// reserves 2 MB for whole-chunk shards — which installWasm reads once and clamps its
// cross-module copies to.
const defaultScratchSize = 0x20000 // 128 KB

// bind binds `n` to `w`, releasing whatever the name held before — SetHandler's
// replace-in-place (§3.1). The one place a displaced wasm instance is closed: Go frees
// neither the instance nor its compiled code on its own, so dropping the map value alone
// would leak one linear memory + its JITed code per replace for the process's life.
func bind(n string, w *wasmHandler) {
	closeHandler(handlers[n])
	handlers[n] = w
}

// closeHandler releases a handler's wasm instance and compiled code. nil-safe, so callers
// can hand it whatever a lookup returned.
func closeHandler(w *wasmHandler) {
	if w == nil {
		return
	}
	_ = w.mod.Close(ctx)
	_ = w.cmod.Close(ctx)
}

// removeHandler unbinds `n` (§12.5) and releases what it held.
func removeHandler(n string) bool {
	w := handlers[n]
	if w == nil {
		return false
	}
	closeHandler(w)
	delete(handlers, n)
	return true
}

// callHandler invokes an installed handler by name (README §4), returning its response or
// nil if the name is unbound or the handler produced nothing. The one way into an installed
// module: the host uses it directly and the cap-bridge routes MODULE_CALL (§12.2) through
// it. Handlers are pure transforms and cannot call back, so there is no re-entrancy to guard.
func callHandler(n string, payload []byte) []byte {
	w := handlers[n]
	if w == nil {
		return nil
	}
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

// installWasm instantiates handler bytes and binds them at the name `n`. The replace is
// unconditional — the §12.5 admission already ran, and bind releases whatever the name
// displaced. Exposed to JS as bridge.installWasm (only the host can instantiate wasm, §12.4).
func installWasm(n string, wasm []byte) bool {
	cm, err := rt.CompileModule(ctx, wasm)
	if err != nil {
		return false
	}
	modSeq++
	m, err := rt.InstantiateModule(ctx, cm, wazero.NewModuleConfig().WithName(fmt.Sprintf("h%d", modSeq)))
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
	bind(n, &wasmHandler{m, cm, fn, s, size})
	bound = true
	return true
}

// boot wires the wasm host imports and stands up the QuickJS realm running the shared
// bundle loader + admission policy (host-installer.gen.js).
func boot() {
	rt = wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler())
	sd = bootSodium(rt) // crypto primitive; the genesis verify routes to it below
	// Every installed handler is a pure transform (README §4): the only host import it
	// takes is the AssemblyScript `env.abort` shim. There is no kernel.call / kernel.caller
	// seam and no env.invoke_handler dispatch callback.
	env := rt.NewHostModuleBuilder("env")
	env.NewFunctionBuilder().WithFunc(func(context.Context, api.Module, uint32, uint32, uint32, uint32) {}).Export("abort")
	env.Instantiate(ctx)
	// The runtime above is fresh, so every handler from a previous boot points into a dead
	// one (the tests boot repeatedly): start from an empty table rather than keep them.
	handlers = map[string]*wasmHandler{}

	// QuickJS realm: expose the byte-level bridge, then run the JS orchestration.
	var err error
	if qrt, err = qjs.New(); err != nil {
		panic(fmt.Sprintf("qjs.New: %v", err))
	}
	qc = qrt.Context()
	b := qc.NewObject()
	fn := func(g func(*qjs.This) (*qjs.Value, error)) *qjs.Value { return qc.Function(g) }
	b.SetPropertyStr("installWasm", fn(func(t *qjs.This) (*qjs.Value, error) {
		wb, _ := qjs.JsTypedArrayToGo(t.Args()[1])
		return t.Context().NewBool(installWasm(t.Args()[0].String(), wb)), nil
	}))
	b.SetPropertyStr("utf8", fn(func(t *qjs.This) (*qjs.Value, error) {
		d, _ := qjs.JsTypedArrayToGo(t.Args()[0])
		return t.Context().NewString(string(d)), nil
	}))
	b.SetPropertyStr("removeHandler", fn(func(t *qjs.This) (*qjs.Value, error) {
		return t.Context().NewBool(removeHandler(t.Args()[0].String())), nil
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
// its guest: the guest's declared cap domains, its config (author-signed structural
// constants), the kernel names its modules landed at, and the verified guest source.
// `author` (hex) + `app` key bundle freshness and derive the guest-signing scope
// (README §12.2, §12.4).
type loadedBundle struct {
	app, author string
	version     int
	caps        []string
	config      json.RawMessage   // guest `config` object (merged under operator config)
	modules     map[string]string // logical name → kernel name, for the guest's BUNDLE
	guestSource string
}

// loaded is the bundle the node is running (set by loadBundle), nil until one loads.
var loaded *loadedBundle

// loadBundle loads a signed app bundle file (README §12.4). Reading the one file is all
// this does: the whole load — manifest signature, policy governance, freshness,
// per-module and guest integrity, and the order they run in — is the shared JS loader
// (bundle.ts, via host-installer.gen.js), which admits each verified module through
// the shared §12.5 policy. On success it records the verified guest source + caps +
// config + module names in `loaded` for the node.
//
// The guest source comes back ACROSS the bridge rather than being re-read here: the
// shared loader hashed those exact bytes against the manifest, so running them is
// running what was verified. Go holding its own copy to look up by name would be a
// second path to the same bytes, which is the drift this seam exists to prevent.
func loadBundle(path string) string {
	blob, err := os.ReadFile(path)
	if err != nil {
		return "ERROR: " + err.Error()
	}
	res, err := invokeFree("loadBundleBlob", qc.NewArrayBuffer(blob))
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
		Config      json.RawMessage
		Modules     map[string]string
		GuestSource string
		Installed   []string
	}
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		return "ERROR(json): " + err.Error()
	}
	loaded = &loadedBundle{
		app: m.App, author: m.Author, version: m.Version, caps: m.Caps,
		config: m.Config, modules: m.Modules, guestSource: m.GuestSource,
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
		pl, err := qjs.JsTypedArrayToGo(t.Args()[1])
		if err != nil {
			return t.Context().NewNull(), nil
		}
		resp := callHandler(t.Args()[0].String(), pl)
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
		// `const BUNDLE` — the facts the runtime derived from the admitted manifest
		// (author, app, signing prefix, module kernel names). Built in the host realm
		// from the one derivation (cap-bridge bundlePreamble), never restated here.
		factsJSON, err := json.Marshal(struct {
			App     string            `json:"app"`
			Author  string            `json:"author"`
			Modules map[string]string `json:"modules"`
		}{loaded.app, loaded.author, loaded.modules})
		if err != nil {
			fatal("bundle-facts", err)
			return
		}
		if g, err = newGuestRealm(el, string(factsJSON), appJSON, loaded.guestSource); err != nil {
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
