// seedkernel native shell. Apps arrive as signed bundles (README §12) — nothing
// application-specific lives here, and nothing about how a node is assembled does
// either. The whole shell — verify + admit + install (§12.4/§12.5), the cap-bridge
// (§12.2), the confined guest's lifecycle (§12.3), protocol dispatch (§12.10) — is
// the shared host TS, compiled into the embedded host-shell.gen.js and run in
// QuickJS (README §12.9). This Go layer is the bridge and only the bridge: it owns
// the handler table (§3), supplies the crypto (Ed25519 via libsodium, BLAKE2b
// native), the fs directory, the sockets and the second QuickJS realm, and forwards
// the CLI. Pure Go, no cgo (QuickJS is quickjs-ng wasm over the in-repo qjs/wazero
// bridge) → one static binary.
package main

import (
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
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

// hostShellJS is the shared shell: the bundle format and its load order, the
// admission policy, the cap-bridge and guest ABI preamble, the transport + routing,
// the WebSocket codec, the protocol bindings, `createShell` — and the native
// platform binding that hands `createShell` the primitives exposed below
// (host/native-shim.ts). Bundled from build/host/*.js by scripts/bundle-loader.mjs;
// it is the same compiled TS the Node shell runs, so no rule of the protocol and no
// step of the assembly is re-derived in a second language (README §12.9).
// Regenerate with `npm run build:loader-bundles`; do not hand-edit.
//
//go:embed host-shell.gen.js
var hostShellJS string

// ───────────────────────── handler table (§3) ─────────────────────────

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
	// el is the Go-owned JS event loop driving the host realm and every confined
	// realm attached to it (loop.go). One per boot.
	el *eventLoop
	// handlers is the handler table (README §3): the whole kernel, which is a contract
	// rather than an artifact. A name is bound exactly when it is a key here, so the §3.1
	// SetHandler / remove / resolve operations are map assignment, delete and lookup —
	// there is no id indirection and no second table to drift from this one. Every value
	// is an installed module: bundles are the one way code arrives (§12.4).
	handlers = map[string]*wasmHandler{}
	// unbound holds handlers that instantiateWasm created but bindWasm has not yet placed
	// on the handler table. Keyed by an integer token the JS bridge carries across.
	unbound    = map[int64]*wasmHandler{}
	unboundSeq int64
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

// removePrefix unbinds every name starting with `prefix` and releases what each held —
// the shell's uninstall (§12.5). Every kernel name of an app shares its app key as a
// prefix (§5.1), so one pass frees exactly that app.
func removePrefix(prefix string) int {
	removed := 0
	for n, w := range handlers {
		if strings.HasPrefix(n, prefix) {
			closeHandler(w)
			delete(handlers, n)
			removed++
		}
	}
	return removed
}

// callHandler invokes an installed handler by name (README §4), returning its response or
// nil if the name is unbound or the handler produced nothing. The one way into an installed
// module: the shell uses it directly and the cap-bridge routes MODULE_CALL (§12.2) through
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

// instantiateWasm compiles, instantiates, and validates handler bytes against the §4
// ABI. No table effect — returns an opaque token the caller must later pass to bindWasm.
// Exposed to JS as bridge.instantiateWasm (only the host can instantiate wasm, §12.4).
func instantiateWasm(wasm []byte) (*wasmHandler, error) {
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
	// §4.1: the handler reserves [scratch, scratch+size). It MAY export `scratchSize` to
	// declare more than the default — honored only if it names real, in-bounds memory, and
	// never below the default. A negative i32 arrives as a huge uint32 the bounds refuse.
	mem, s := uint64(m.Memory().Size()), uint32(g.Get())
	if s == 0 || uint64(s)+defaultScratchSize > mem {
		return nil, fmt.Errorf("scratch offset %d out of bounds (mem %d)", s, mem)
	}
	size := uint32(defaultScratchSize)
	if sg := m.ExportedGlobal("scratchSize"); sg != nil {
		d := uint32(sg.Get())
		if d < defaultScratchSize {
			return nil, fmt.Errorf("scratchSize %d is below the %d default", d, defaultScratchSize)
		}
		if uint64(s)+uint64(d) > mem {
			return nil, fmt.Errorf("scratchSize %d overflows memory (scratch %d, mem %d)", d, s, mem)
		}
		size = d
	}
	ok = true
	return &wasmHandler{m, cm, fn, s, size}, nil
}

// installWasm compiles, instantiates, validates, and binds in one call. Kept as a
// convenience for the direct tests; the two-phase path is instantiateWasm + bindWasm.
func installWasm(n string, wasm []byte) error {
	w, err := instantiateWasm(wasm)
	if err != nil {
		return err
	}
	bind(n, w)
	return nil
}

// ───────────────────────── the realm and its primitives ─────────────────────────

// boot stands up the engines and the host realm: wazero + libsodium, QuickJS and its
// event loop, the platform primitives (sodium, fs on dataDir, TCP sockets, ws.wasm,
// the byte-level `bridge` below), and then the ONE shared bundle. After this the realm
// holds `createShell` and the native platform binding over it — but no node yet; that
// is bootNode, which needs an identity and listen addresses.
//
// Idempotent across calls: the tests boot repeatedly in one process, and each boot
// releases the previous one's engines rather than stranding them.
func boot(dataDir string) error {
	shutdown()
	rt = wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler())
	sd = bootSodium(rt) // crypto primitive; the realm's bundle verification routes to it
	// Every installed handler is a pure transform (README §4): the only host import it
	// takes is the AssemblyScript `env.abort` shim. There is no kernel.call / kernel.caller
	// seam and no env.invoke_handler dispatch callback.
	env := rt.NewHostModuleBuilder("env")
	env.NewFunctionBuilder().WithFunc(func(context.Context, api.Module, uint32, uint32, uint32, uint32) {}).Export("abort")
	if _, err := env.Instantiate(ctx); err != nil {
		return fmt.Errorf("handler imports: %w", err)
	}

	var err error
	if qrt, err = qjs.New(); err != nil {
		return fmt.Errorf("qjs.New: %w", err)
	}
	qc = qrt.Context()
	el = newEventLoop(qc)
	// The shared bundle is evaluated LAST: everything below it is a primitive it
	// declares (host/native-shim.ts), and its module scope reaches for some of them
	// (TextEncoder at load time, the ws codec backend) straight away.
	installPolyfills(qc)
	exposeSodium(qc, sd)
	if err := exposeFs(qc, dataDir); err != nil {
		return fmt.Errorf("fs: %w", err)
	}
	exposeNet(qc, el)
	exposeWs(qc)
	exposeBridge(qc)
	// The freshness high-water marks live in a SIBLING of the data dir, so a fs-capable
	// guest — whose keys are files inside the dir — can never tamper with its own mark.
	freshnessStorePath = filepath.Clean(dataDir) + ".freshness.json"
	if _, err := qc.Eval("host-shell.gen.js", qjs.Code(hostShellJS)); err != nil {
		return fmt.Errorf("shell bundle: %w", err)
	}
	return nil
}

// shutdown releases a previous boot's engines: every confined realm, the host realm,
// and the wazero runtime holding each handler's compiled code. Without it a test run
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
	handlers = map[string]*wasmHandler{}
	unbound = map[int64]*wasmHandler{}
}

// exposeBridge installs `bridge`: the byte-level host powers QuickJS genuinely cannot
// reach. Everything else the shell needs is JS. The shape is declared — and so
// typechecked — in host/native-shim.ts.
func exposeBridge(qc *qjs.Context) {
	b := qc.NewObject()
	fn := func(g func(*qjs.This) (*qjs.Value, error)) *qjs.Value { return qc.Function(g) }

	// ── the handler table (§3) ──
	b.SetPropertyStr("instantiateWasm", fn(func(t *qjs.This) (*qjs.Value, error) {
		wb, _ := qjs.JsTypedArrayToGo(t.Args()[0])
		w, err := instantiateWasm(wb)
		if err != nil {
			return nil, fmt.Errorf("instantiateWasm: %w", err)
		}
		unboundSeq++
		unbound[unboundSeq] = w
		return t.Context().NewInt64(unboundSeq), nil
	}))
	b.SetPropertyStr("bindWasm", fn(func(t *qjs.This) (*qjs.Value, error) {
		tok := t.Args()[1].Int64()
		w := unbound[tok]
		if w == nil {
			return nil, fmt.Errorf("bindWasm: token %d not found", tok)
		}
		delete(unbound, tok)
		bind(t.Args()[0].String(), w)
		return t.Context().NewNull(), nil
	}))
	b.SetPropertyStr("discardWasm", fn(func(t *qjs.This) (*qjs.Value, error) {
		tok := t.Args()[0].Int64()
		w := unbound[tok]
		if w == nil {
			return t.Context().NewNull(), nil // token already consumed (bind or double discard) — harmless
		}
		delete(unbound, tok)
		closeHandler(w)
		return t.Context().NewNull(), nil
	}))
	b.SetPropertyStr("callHandler", fn(func(t *qjs.This) (*qjs.Value, error) {
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
	b.SetPropertyStr("isBound", fn(func(t *qjs.This) (*qjs.Value, error) {
		return t.Context().NewBool(handlers[t.Args()[0].String()] != nil), nil
	}))
	b.SetPropertyStr("removePrefix", fn(func(t *qjs.This) (*qjs.Value, error) {
		return t.Context().NewInt64(int64(removePrefix(t.Args()[0].String()))), nil
	}))

	// ── bundle-freshness persistence (§12.4) ──
	// The arithmetic is shared JS, the durable write is ours: a truncated store reads
	// back as "no marks", silently dropping every downgrade guard, so it must be atomic.
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

	installRealmBridge(qc, b) // the confined realm (§12.3) — guest.go
	qc.Global().SetPropertyStr("bridge", b)
}

// ───────────────────────── driving the shell ─────────────────────────

// callShell drives one of the shim's entry points (host/native-shim.ts) to completion:
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
	for i, a := range args {
		slot := fmt.Sprintf("__a%d", i)
		qc.Global().SetPropertyStr(slot, a) // SetPropertyStr takes the reference
		if i > 0 {
			expr += ","
		}
		expr += slot
	}
	kind, value, msg, err := el.awaitIn(qc, expr+")", timeout)
	if err != nil {
		return nil, err
	}
	if kind != 0 {
		return nil, errors.New(msg)
	}
	return value, nil
}

// nodeConfig is everything the operator chose, handed to the realm as one JSON object
// (host/native-shim.ts BootConfig). Parsing the flags is Go's job; acting on them is
// the shell's, so they cross as data rather than as spliced-together JS.
type nodeConfig struct {
	PolicyJSON *string           `json:"policyJson"`
	KeyHex     string            `json:"keyHex"`
	Listen     *hostPort         `json:"listen,omitempty"`
	WsListen   *hostPort         `json:"wsListen,omitempty"`
	Peers      []string          `json:"peers,omitempty"`
	TimeoutMs  int               `json:"timeoutMs,omitempty"`
	Config     map[string]any    `json:"config,omitempty"`
}

type hostPort struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// nodeStatus is what the realm reports once the node is up: who we are, and the ports
// actually bound (0 where not listening).
type nodeStatus struct {
	PeerID string `json:"peerId"`
	Port   int    `json:"port"`
	WsPort int    `json:"wsPort"`
}

// startNode builds the node inside the realm — identity, network, and the shared shell
// over this platform — and waits for the listeners to bind and any cohort peers to be
// dialled. The whole assembly order lives in createShell (README §12.9); this hands it
// the operator's choices and reads back the result.
func startNode(cfg nodeConfig) (nodeStatus, error) {
	var st nodeStatus
	j, err := json.Marshal(cfg)
	if err != nil {
		return st, err
	}
	out, err := callRealm("bootNode", 30*time.Second, qc.NewString(string(j)))
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(out, &st)
}

// loadBundle loads a signed app bundle file (README §12.4). Reading the one file is all
// this does: the whole load — manifest signature, policy governance, freshness, per-module
// and guest integrity, binding the modules and auto-binding the app's protocols — is the
// shared shell. Returns the operator's console line, or an `ERROR: …` string.
func loadBundle(path string) string {
	blob, err := os.ReadFile(path)
	if err != nil {
		return "ERROR: " + err.Error()
	}
	out, err := callRealm("loadBundleBlob", 30*time.Second, qc.NewArrayBuffer(blob))
	if err != nil {
		return "ERROR: " + err.Error()
	}
	var m struct {
		App     string
		Version int
		Handles []string
	}
	if err := json.Unmarshal(out, &m); err != nil {
		return "ERROR(json): " + err.Error()
	}
	return fmt.Sprintf("%s v%d  handles=%v", m.App, m.Version, m.Handles)
}

// runGuest runs one of the loaded bundle's guest entrypoints as the *initiator* —
// "the shell runs the app" (README §12.8). Arguments and results cross as raw bytes;
// the shell owns the realm, the cap-bridge and the confinement.
func runGuest(entry string, payload []byte) ([]byte, error) {
	return callRealm("runGuest", 60*time.Second, qc.NewString(entry), qc.NewArrayBuffer(payload))
}

// freshnessStorePath is where the shared loader's bundle-freshness marks are persisted
// (README §12.4). The marks and the monotonic rule live in JS (bundle.ts FreshnessMarks);
// Go owns only the path and the atomic write. Empty ⇒ purely in-memory, so a fresh
// process starts with −∞ for every key.
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
	if err := boot(a.dataDir); err != nil {
		fatal("boot", err)
		return
	}

	cfg, err := configFromCLI(a)
	if err != nil {
		fatal("config", err)
		return
	}
	st, err := startNode(cfg)
	if err != nil {
		fatal("node", err)
		return
	}

	fmt.Printf("seedkernel-loader %s\n", st.PeerID)
	fmt.Printf("  policy %s\n", orNone(a.policyPath))
	fmt.Printf("  store  %s (fs.* backend)\n", a.dataDir)
	fmt.Printf("  cohort %d peer(s)\n", len(cfg.Peers))
	if st.Port != 0 {
		fmt.Printf("  tcp    listening on :%d\n", st.Port)
	}
	if st.WsPort != 0 {
		fmt.Printf("  ws     listening on :%d\n", st.WsPort)
	}

	// The signed bundle: verify + install its modules, stand up its guest, bind its
	// protocols. Every invocation targets a bundle (there is always a --bundle / default
	// dir), so a load error is fatal: the node has no app to run or serve. Exit non-zero
	// rather than keep serving as a silent bundle-less relay, which would hide the
	// failure from a driving script (§12.4).
	bundleResult := loadBundle(a.bundleDir)
	fmt.Println("  bundle " + bundleResult)
	if strings.HasPrefix(bundleResult, "ERROR") {
		os.Exit(1)
	}

	// One-shot client ops through the loaded guest — "the shell runs the app" as the
	// initiator (README §12.8). Arguments/results cross as raw bytes; a handler-only
	// bundle has no guest, and the shell says so rather than silently doing nothing.
	if a.put != "" {
		data, err := os.ReadFile(a.put)
		if err != nil {
			fatal("put", err)
			return
		}
		r, err := runGuest("put", data)
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
		data, err := runGuest("get", arg)
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

	if st.Port == 0 && st.WsPort == 0 {
		return
	}
	// A serving node answers for the cohort: inbound requests are routed by protocol id
	// to whichever installed app is bound to it, and a guest app answers from its own
	// confined realm — no app-specific host code, and no second dispatch (§12.8, §12.10).
	if _, err := callRealm("serve", 30*time.Second); err != nil {
		fatal("serve", err)
		return
	}
	fmt.Println("  serving the app's request side from the confined guest")
	fmt.Println("serving — Ctrl-C to stop")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() { <-sig; os.Exit(0) }()
	el.stopped = false
	el.run()
}

// ── CLI helpers ──────────────────────────────────────────────────────────────

// configFromCLI turns the parsed flags into the node config the realm boots from,
// reading the two operator files (the policy and the app config) along the way.
// Omitting --policy is not "no policy" but deny-all: the shell resolves a null policy
// to an empty author set, so the node serves and nothing installs — including the
// bundle below, whose manifest author must be listed too (README §14).
func configFromCLI(a cliArgs) (nodeConfig, error) {
	cfg := nodeConfig{Peers: splitList(a.peers), TimeoutMs: a.timeoutMs}
	if a.policyPath != "" {
		pj, err := os.ReadFile(a.policyPath)
		if err != nil {
			return cfg, fmt.Errorf("policy: %w", err)
		}
		s := string(pj)
		cfg.PolicyJSON = &s
	}
	var err error
	if cfg.Listen, err = parseHostPort(a.listen); err != nil {
		return cfg, fmt.Errorf("listen: %w", err)
	}
	if cfg.WsListen, err = parseHostPort(a.wsListen); err != nil {
		return cfg, fmt.Errorf("ws-listen: %w", err)
	}
	if a.appConfig != "" {
		b, err := os.ReadFile(a.appConfig)
		if err != nil {
			return cfg, fmt.Errorf("app-config: %w", err)
		}
		if err := json.Unmarshal(b, &cfg.Config); err != nil {
			return cfg, fmt.Errorf("app-config: %w", err)
		}
	}
	if cfg.KeyHex, err = loadOrMintKey(a.keyPath); err != nil {
		return cfg, fmt.Errorf("key: %w", err)
	}
	return cfg, nil
}

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

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseHostPort parses a host:port flag; empty ⇒ nil (not listening on that transport).
func parseHostPort(s string) (*hostPort, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return nil, fmt.Errorf("expected host:port, got %q", s)
	}
	host := s[:i]
	if host == "" {
		host = "0.0.0.0"
	}
	port, err := strconv.Atoi(s[i+1:])
	if err != nil || port < 0 {
		return nil, fmt.Errorf("bad port in %q", s)
	}
	return &hostPort{Host: host, Port: port}, nil
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
