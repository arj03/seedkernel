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
	"time"

	"seedloader/qjs"

	"github.com/tetratelabs/wazero"
)

// hostShellJS is the shared shell plus the native platform binding (host/native-shim.ts)
// — the same TS the Node shell runs, so no rule of the protocol is re-derived in a second
// language (README §12.9). Bundled by scripts/bundle-loader.mjs, never hand-edited.
//
//go:embed host-shell.gen.js
var hostShellJS string

var (
	ctx = context.Background()
	// rtCore is the TCB's own runtime (libsodium, ML-DSA, ML-KEM), deliberately not armed:
	// a wedged libsodium is a host bug, not a confinement breach.
	rtCore wazero.Runtime
	qc     *qjs.Context
	qrt    *qjs.Runtime
	// el drives the host realm and every confined realm attached to it (loop.go).
	el *eventLoop
)

// ───────────────────────── the realm and its primitives ─────────────────────────

// boot stands up the engines and the host realm: wazero + libsodium, QuickJS and its
// event loop, the platform primitives, then the ONE shared bundle. No node yet — `--dir`
// is the operator's (§12.9). Idempotent: each boot releases the previous one's engines.
func boot() error {
	shutdown()
	var err error
	if err = bootModuleTable(); err != nil {
		return err
	}
	rtCore = wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler())
	sd = bootSodium(rtCore)
	md = bootMlDsa(rtCore) // manifest suite 0x02 (§12.4)

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
	realmSeq = 0
	if qrt != nil {
		qrt.Close()
		qrt, qc, el = nil, nil, nil
	}
	closeModuleTable()
	if rtCore != nil {
		_ = rtCore.Close(ctx)
		rtCore = nil
	}
}

// exposeBridge installs `bridge`: the byte-level host powers QuickJS genuinely cannot
// reach. The shape is declared — and so typechecked — in host/native-shim.ts.
func exposeBridge(qc *qjs.Context) {
	b := qc.NewObject()

	installModuleBridge(qc, b) // the private module table (§3) — module.go

	// ── the operator's world (host/cli.ts) ──
	// Files, arguments and stdout: which files get read and what gets printed is the
	// shared CLI's, the same module the Node shell runs.
	b.SetPropertyStr("argv", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		// JSON rather than a joined string: an argument may contain any byte, including
		// whatever separator a join would pick.
		j, err := json.Marshal(os.Args[1:])
		if err != nil {
			return nil, err
		}
		return t.Context().NewString(string(j)), nil
	}))
	b.SetPropertyStr("readFile", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		fb, err := os.ReadFile(t.Args()[0].String())
		if err != nil {
			// Only absence maps to null. Permission errors, directories and I/O failures
			// must remain visible to guard-bearing callers such as the freshness store.
			if errors.Is(err, os.ErrNotExist) {
				return t.Context().NewNull(), nil
			}
			return nil, err
		}
		return t.Context().NewArrayBuffer(fb), nil
	}))
	b.SetPropertyStr("writeFile", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		bytes, err := qjs.JsTypedArrayToGo(t.Args()[1])
		if err != nil {
			return nil, err
		}
		// Atomic for every caller: a truncated freshness file must never replace the last
		// readable guard state (and is refused on read if one exists out of band).
		if err := writeFileAtomic(t.Args()[0].String(), bytes, ".seedkernel-", os.FileMode(t.Args()[2].Int64())); err != nil {
			return nil, err
		}
		return t.Context().NewUndefined(), nil
	}))
	b.SetPropertyStr("log", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		// The realm's console.log writes to a WASI stdout wazero leaves disconnected, so
		// operator output returns via stderr — stdout is `--op`'s raw data channel.
		fmt.Fprintln(os.Stderr, t.Args()[0].String())
		return t.Context().NewUndefined(), nil
	}))
	b.SetPropertyStr("logErr", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		// Diagnostics — every `console.*` in the host realm (host/native-polyfills.ts).
		// Stderr for the same reason as `log` above.
		fmt.Fprintln(os.Stderr, t.Args()[0].String())
		return t.Context().NewUndefined(), nil
	}))
	b.SetPropertyStr("stdout", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		bytes, err := qjs.JsTypedArrayToGo(t.Args()[0])
		if err != nil {
			return nil, err
		}
		os.Stdout.Write(bytes)
		return t.Context().NewUndefined(), nil
	}))
	b.SetPropertyStr("stdin", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
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
	fmt.Fprintln(os.Stderr, "ERROR: "+stage+": "+err.Error())
	os.Exit(1)
}
