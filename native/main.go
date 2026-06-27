// seedkernel native shell. The runtime is wasm (kernel + signature); apps arrive as
// signed bundles (README §13) — nothing application-specific lives here. Host
// orchestration (installer §7, bundle verification §13) is JavaScript in QuickJS
// (host.js); this Go layer is only the bridge: loads the genesis wasm, supplies the
// genesis crypto (Ed25519 + SHA-3), runs the signature shuttle (the one piece needing
// raw wasm-memory access), and exposes byte primitives to the realm. Pure Go, no cgo
// (QuickJS is quickjs-ng wasm over the in-repo qjs/wazero bridge) → one static binary.
package main

import (
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"seedloader/qjs"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

//go:embed wasm/kernel.wasm
var kernelWasm []byte

//go:embed wasm/bootstrap.wasm
var bootWasm []byte

//go:embed host.js
var hostJS string

// ───────────────────────── shell core (bridge) ─────────────────────────

type handler struct {
	mod     api.Module
	cmod    wazero.CompiledModule // retained so an upgrade can release the old compiled code
	fn      api.Function
	scratch uint32
}

type signer struct {
	algo int
	pk   []byte
}

var (
	ctx     = context.Background()
	rt      wazero.Runtime
	kn, bs  api.Module
	qc      *qjs.Context
	qrt     *qjs.Runtime
	wasmH   = map[string]handler{}             // name → wasm app handler
	natH    = map[string]func([]byte) []byte{} // name → native host service
	scrOf   = map[api.Module]uint32{}          // wasm handler module → scratch offset
	blocked = map[string]bool{}                // names refused via kernel.call (§4.4)
	nextID  = int32(10)
)

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

func rd(m api.Memory, p, n uint32) []byte { x, _ := m.Read(p, n); return append([]byte(nil), x...) }

func wr(m api.Module, data []byte) uint32 {
	r := wasmCall(m, "alloc", uint64(len(data)))
	if len(r) == 0 {
		return 0
	}
	m.Memory().Write(uint32(r[0]), data)
	return uint32(r[0])
}

func name(canonical string) []byte {
	return sd.hashSha3256([]byte("seedkernel.bootstrap.v1:" + canonical))
}

func setHandler(n []byte, id int32) {
	if p := wr(kn, n); p != 0 {
		wasmCall(kn, "set_handler", uint64(p), uint64(len(n)), uint64(uint32(id)))
		wasmCall(kn, "dealloc", uint64(p))
	}
}

func load(wasm []byte, modName string) api.Module {
	cm, _ := rt.CompileModule(ctx, wasm)
	m, err := rt.InstantiateModule(ctx, cm, wazero.NewModuleConfig().WithName(modName))
	if err != nil {
		panic(err)
	}
	return m
}

// run invokes an installed handler (wasm or native) by name (README §4 scratch ABI).
func run(n, payload []byte) []byte {
	if h, ok := wasmH[string(n)]; ok {
		h.mod.Memory().Write(h.scratch, payload)
		r, err := h.fn.Call(ctx, uint64(len(payload)))
		// handle returns output_len ≥ 0 (README §4): only a trap (err) or a negative
		// length is a failure. A 0-length result is a valid EMPTY response, not a
		// failure — return a non-nil slice for it so a caller can distinguish "empty OK"
		// from "no handler / trap" (nil). rd() collapses 0 bytes back to nil, so read here.
		if err != nil || len(r) == 0 || int32(r[0]) < 0 {
			return nil
		}
		out := make([]byte, int32(r[0]))
		if len(out) > 0 {
			b, _ := h.mod.Memory().Read(h.scratch, uint32(len(out)))
			copy(out, b)
		}
		return out
	}
	if fn, ok := natH[string(n)]; ok {
		return fn(payload)
	}
	return nil
}

// env.invoke_handler — kernel matched a name (README §3). id -1 = signature wrapper.
func invoke(_ context.Context, km api.Module, hid, nP, nL, pP, pL uint32) {
	if int32(hid) == -1 { // verify → re-dispatch inner envelope → pop signer (§6.5)
		payload := rd(km.Memory(), pP, pL)
		bp := wr(bs, payload)
		ok := wasmCall(bs, "handle_signature", uint64(bp), uint64(len(payload)))
		wasmCall(bs, "dealloc", uint64(bp))
		if len(ok) == 0 || uint32(ok[0]) == 0 {
			return
		}
		ip := wasmCall(bs, "get_inner_ptr")
		il := wasmCall(bs, "get_inner_len")
		if len(ip) == 0 || len(il) == 0 {
			return
		}
		inner := rd(bs.Memory(), uint32(ip[0]), uint32(il[0]))
		kp := wr(kn, inner)
		wasmCall(kn, "dispatch", uint64(kp), uint64(len(inner)))
		wasmCall(kn, "dealloc", uint64(kp))
		wasmCall(bs, "pop_signer")
		return
	}
	run(rd(km.Memory(), nP, nL), rd(km.Memory(), pP, pL)) // inbound: response dropped
}

// kernel.call — one handler reaches another (README §4.4).
func kcall(_ context.Context, caller api.Module, nP, nL, pP, pL uint32) uint32 {
	n := rd(caller.Memory(), nP, nL)
	if blocked[string(n)] {
		return ^uint32(0)
	}
	// scrOf is set only for modules installed as handlers (installWasm). A module that
	// reaches kernel.call without one (kn/bs) has the zero-value offset, so writing the
	// response would clobber its low memory — refuse rather than corrupt.
	s, ok := scrOf[caller]
	if !ok {
		return 0
	}
	resp := run(n, rd(caller.Memory(), pP, pL))
	if resp == nil {
		return 0
	}
	caller.Memory().Write(s, resp)
	return uint32(len(resp))
}

// env.ed25519_verify — the genesis suite primitive (README §6.2). Routed to
// libsodium so the genesis verify is the same binary as the browser.
func edVerify(_ context.Context, m api.Module, pubP, sigP, dataP, dataL uint32) uint32 {
	if sd.verifyDetached(rd(m.Memory(), sigP, 64), rd(m.Memory(), dataP, dataL), rd(m.Memory(), pubP, 32)) {
		return 1
	}
	return 0
}

// topSigner reads the innermost verified signer from bootstrap.wasm (§6.5).
func topSigner() (signer, bool) {
	c := wasmCall(bs, "get_signer_count")
	if len(c) == 0 || uint32(c[0]) == 0 {
		return signer{}, false
	}
	idx := uint64(uint32(c[0]) - 1)
	pl := wasmCall(bs, "signer_pubkey_len", idx)
	if len(pl) == 0 || int32(pl[0]) <= 0 {
		return signer{}, false
	}
	ab := wasmCall(bs, "alloc", 2)
	pb := wasmCall(bs, "alloc", pl[0])
	if len(ab) == 0 || len(pb) == 0 {
		return signer{}, false
	}
	defer wasmCall(bs, "dealloc", ab[0]) // free the scratch allocs read below
	defer wasmCall(bs, "dealloc", pb[0])

	wasmCall(bs, "read_signer", idx, ab[0], pb[0], pl[0])
	a := rd(bs.Memory(), uint32(ab[0]), 2)
	return signer{int(a[0])<<8 | int(a[1]), rd(bs.Memory(), uint32(pb[0]), uint32(pl[0]))}, true
}

// installWasm instantiates handler bytes and binds them to the raw name `n`.
// Exposed to JS as bridge.installWasm (only the host can instantiate wasm, §7).
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
	g, fn := m.ExportedGlobal("scratch"), m.ExportedFunction("handle")
	if g == nil || fn == nil {
		_ = m.Close(ctx)  // not a handler module — don't leak the instance…
		_ = cm.Close(ctx) // …or its compiled code
		return false
	}
	s := uint32(g.Get())
	// approve() permits a same-author/parent re-install (host.js), so this name may
	// already hold a live handler. Close the previous instance + its compiled code and
	// drop its scrOf key before replacing, or every upgrade leaks one wasm instance
	// (linear memory + JITed code) and a stale scrOf entry for the process's life.
	if old, ok := wasmH[string(n)]; ok {
		_ = old.mod.Close(ctx)
		_ = old.cmod.Close(ctx)
		delete(scrOf, old.mod)
	}
	wasmH[string(n)] = handler{m, cm, fn, s}
	scrOf[m] = s
	setHandler(n, nextID)
	nextID++
	return true
}

// boot wires the wasm host imports, instantiates kernel + signature, and stands
// up the QuickJS realm running host.js (installer + bundle verification).
func boot() {
	rt = wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler())
	sd = bootSodium(rt) // crypto primitive; env.ed25519_verify routes to it below
	env := rt.NewHostModuleBuilder("env")
	env.NewFunctionBuilder().WithFunc(func(context.Context, api.Module, uint32, uint32, uint32, uint32) {}).Export("abort")
	env.NewFunctionBuilder().WithFunc(invoke).Export("invoke_handler")
	env.NewFunctionBuilder().WithFunc(edVerify).Export("ed25519_verify")
	env.NewFunctionBuilder().WithFunc(func(context.Context, api.Module, uint32, uint32, uint32, uint32, uint32, uint32, uint32) uint32 {
		return 0
	}).Export("suite_verify")
	env.Instantiate(ctx)
	k := rt.NewHostModuleBuilder("kernel")
	k.NewFunctionBuilder().WithFunc(kcall).Export("call")
	k.NewFunctionBuilder().WithFunc(func(context.Context, api.Module, uint32) uint32 { return 0 }).Export("caller")
	k.Instantiate(ctx)
	kn = load(kernelWasm, "kernelmod")
	bs = load(bootWasm, "bootstrap")
	setHandler(name("signature"), -1)

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
	b.SetPropertyStr("topSigner", fn(func(t *qjs.This) (*qjs.Value, error) {
		s, ok := topSigner()
		if !ok {
			return t.Context().NewArrayBuffer(nil), nil
		}
		return t.Context().NewArrayBuffer(append([]byte{byte(s.algo >> 8), byte(s.algo)}, s.pk...)), nil
	}))
	b.SetPropertyStr("utf8", fn(func(t *qjs.This) (*qjs.Value, error) {
		d, _ := qjs.JsTypedArrayToGo(t.Args()[0])
		return t.Context().NewString(string(d)), nil
	}))
	qc.Global().SetPropertyStr("bridge", b)
	exposeSodium(qc, sd) // installs `sodium` (libsodium-wrappers shape) into the realm
	if _, err := qc.Eval("host.js", qjs.Code(hostJS)); err != nil {
		panic(err)
	}

	// The install handler (§7.2) delegates to JS onInstall; blocked from kernel.call.
	registerNative("install", func(payload []byte) []byte {
		if res, _ := invokeFree("onInstall", qc.NewArrayBuffer(payload)); res != nil {
			res.Free()
		}
		return nil
	})
	blocked[string(name("install"))] = true
}

// dispatch feeds raw envelope bytes into the pipeline (README §3).
func dispatch(b []byte) {
	p := wr(kn, b)
	wasmCall(kn, "dispatch", uint64(p), uint64(len(b)))
	wasmCall(kn, "dealloc", uint64(p))
}

func registerNative(canonical string, fn func([]byte) []byte) {
	n := name(canonical)
	natH[string(n)] = fn
	setHandler(n, nextID)
	nextID++
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
// structural constants), and the verified guest source.
type loadedBundle struct {
	app, version string
	caps         []string
	config       json.RawMessage // manifest `config` object (merged under operator config)
	guestSource  string
}

// loaded is the bundle the node is running (set by loadBundle), nil until one loads.
var loaded *loadedBundle

// loadBundle loads a signed app bundle directory (README §13.4): JS verifies the
// manifest signature + module/guest content hashes, then Go dispatches each
// pre-signed install envelope (the installer re-checks author + replay). On success
// it records the verified guest source + caps + config in `loaded` for the node.
func loadBundle(dir string) string {
	menv, err := os.ReadFile(filepath.Join(dir, "manifest.bundle"))
	if err != nil {
		return "ERROR: " + err.Error()
	}
	goFiles := map[string][]byte{}
	jsFiles := qc.NewObject()
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		fb, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		goFiles[e.Name()] = fb
		jsFiles.SetPropertyStr(e.Name(), qc.NewArrayBuffer(fb))
	}
	res, err := invokeFree("verifyBundle", qc.NewArrayBuffer(menv), jsFiles)
	if err != nil {
		return "ERROR(invoke): " + err.Error()
	}
	out := res.String()
	res.Free()
	if strings.HasPrefix(out, "ERROR") {
		return out
	}
	var m struct {
		App, Version string
		Caps         []string
		Guest        string
		Config       json.RawMessage
		Modules      []struct{ Name, Install, KernelName string }
	}
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		return "ERROR(json): " + err.Error()
	}
	var installed []string
	for _, mod := range m.Modules {
		dispatch(goFiles[mod.Install]) // → installer (JS onInstall) → installWasm
		kName, _ := hex.DecodeString(mod.KernelName)
		if _, ok := wasmH[string(kName)]; ok {
			installed = append(installed, mod.Name)
		}
	}
	loaded = &loadedBundle{
		app: m.App, version: m.Version, caps: m.Caps,
		config: m.Config, guestSource: string(goFiles[m.Guest]),
	}
	return fmt.Sprintf("%s v%s  installed=%v", m.App, m.Version, installed)
}

// applyPolicy installs the shell's install policy (host/policy.ts shape) into the
// JS realm; "" leaves the permissive default. parsePolicy throws on malformed input,
// which surfaces here as an error (a typo fails the boot loudly, not silently).
func applyPolicy(json string) error {
	if strings.TrimSpace(json) == "" {
		return nil
	}
	res, err := invokeFree("setPolicy", qc.NewString(json))
	if res != nil {
		res.Free()
	}
	return err
}

// wireModuleCall exposes __moduleCall(name, payload) to the realm: the cap-bridge's
// MODULE_CALL backend, routing an installed handler call to Go's run() (the wasm app
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
		resp := run(nm, pl)
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
	a := cliArgs{bundleDir: "../../seedstore/WASM/bundle", dataDir: "./data", keyPath: "./seedkernel.key", timeoutMs: 2000}
	f := os.Args[1:]
	val := func(i *int) string {
		*i++
		if *i < len(f) {
			return f[*i]
		}
		return ""
	}
	for i := 0; i < len(f); i++ {
		switch f[i] {
		case "--policy":
			a.policyPath = val(&i)
		case "--dir":
			a.dataDir = val(&i)
		case "--key":
			a.keyPath = val(&i)
		case "--listen":
			a.listen = val(&i)
		case "--ws-listen":
			a.wsListen = val(&i)
		case "--peers":
			a.peers = val(&i)
		case "--put":
			a.put = val(&i)
		case "--get":
			a.get = val(&i)
		case "--out":
			a.out = val(&i)
		case "--app-config":
			a.appConfig = val(&i)
		case "--bundle":
			a.bundleDir = val(&i)
		case "--timeout":
			if n, err := strconv.Atoi(val(&i)); err == nil {
				a.timeoutMs = n
			}
		default:
			if !strings.HasPrefix(f[i], "--") {
				a.bundleDir = f[i]
			}
		}
	}
	return a
}

func main() {
	a := parseCLI()
	boot()

	// Install policy (optional; absent ⇒ the permissive caps-free default).
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
	portBytes, err := qjs.JsTypedArrayToGo(mustEval(`__nodePorts()`))
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

	// The signed bundle: verify + install its modules, capture its guest.
	fmt.Println("  bundle " + loadBundle(a.bundleDir))

	var g *guestRealm
	if loaded != nil {
		// Build the cap funnel for the bundle's declared domains, then the confined
		// guest from its verified source + the merged APP config (manifest ∪ operator).
		if _, err := qc.Eval("<bridge>", qjs.Code(fmt.Sprintf(`__buildNodeBridge(%s)`, jsStrArray(loaded.caps)))); err != nil {
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
		// the initiator (README §13.7). Arguments/results cross as raw bytes.
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
	// A serving node with an app loaded also holds for the cohort: route incoming
	// requests to the guest's confined `handle` — no app-specific host code (§13.7).
	if g != nil {
		wireHolder(qc, g)
		fmt.Println("  holder serving the app's request side from the confined guest")
	}
	fmt.Println("serving — Ctrl-C to stop")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() { <-sig; os.Exit(0) }()
	el.stopped = false
	el.run()
}

// ── CLI helpers ──────────────────────────────────────────────────────────────

func fatal(stage string, err error) { fmt.Println("ERROR: " + stage + ": " + err.Error()) }

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
		return skHex, nil
	}
	v, err := qc.Eval("<mint>", qjs.Code(
		`(function(){ const kp = sodium.crypto_sign_keypair(); return Array.from(kp.privateKey, b => b.toString(16).padStart(2,"0")).join(""); })()`,
	))
	if err != nil {
		return "", err
	}
	skHex := v.String()
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
