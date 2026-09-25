// seedkernel native shell (§12.9). The shell is the shared host TS, embedded as
// host-shell.gen.js and run in QuickJS; Go is only the bridge: module table (§3), crypto,
// fs, sockets, and the confined guest realms (guest.go). Pure Go, one static binary.
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
	"strings"
	"time"

	"seedkernel/qjs"

	"github.com/tetratelabs/wazero"
)

// hostShellJS is the shared shell plus host/native-shim.ts, bundled by
// scripts/bundle-native-host.mjs.
//
//go:embed host-shell.gen.js
var hostShellJS string

var (
	ctx = context.Background()
	// rtCore is the TCB's own runtime (libsodium, ML-DSA), not budget-armed.
	rtCore wazero.Runtime
	qc     *qjs.Context
	qrt    *qjs.Runtime
	el     *eventLoop
	nh     *netHost
)

// ───────────────────────── the realm and its primitives ─────────────────────────

// boot stands up the engines, the host realm and its primitives, then the shared bundle.
// Each boot releases the previous one's engines.
func boot() error {
	shutdown()
	var err error
	if err = bootModuleTable(); err != nil {
		return err
	}
	rtCore = wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler())
	sd = bootSodium(rtCore)
	md = bootMlDsa(rtCore) // manifest suite 0x02 (§12.4)

	// An unhandled rejection ends the process, as on Node.
	if qrt, err = qjs.New(qjs.TrackRejections()); err != nil {
		return fmt.Errorf("qjs.New: %w", err)
	}
	qc = qrt.Context()
	el = newEventLoop(qc)
	// The bundle's module scope reaches for these primitives, so it evaluates last.
	exposeSodium(qc, sd)
	exposeFs(qc)
	nh = exposeNet(qc, el)
	exposeBridge(qc)
	done, err := qc.Eval("host-shell.gen.js", hostShellJS)
	if err != nil {
		return fmt.Errorf("shell bundle: %w", err)
	}
	done.Free()
	// The shim defined the __net dispatchers; retain them.
	if err := nh.retain(); err != nil {
		return fmt.Errorf("net retain: %w", err)
	}
	return nil
}

// shutdown releases a previous boot: the network, every realm, and the wazero runtimes.
func shutdown() {
	// The network first, so its readers stop posting into the realm freed below.
	if nh != nil {
		nh.close()
		nh = nil
	}
	for _, g := range realms {
		g.discard()
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

// exposeBridge installs `bridge`, typed in host/native-shim.ts.
func exposeBridge(qc *qjs.Context) {
	b := qc.NewObject()

	installModuleBridge(qc, b) // module.go

	// The operator's world (host/cli.ts): arguments, files, stdio.
	b.SetPropertyStr("argv", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		// JSON, since an argument may contain any separator.
		j, err := json.Marshal(os.Args[1:])
		if err != nil {
			return nil, err
		}
		return qc.NewString(string(j)), nil
	}))
	b.SetPropertyStr("readFile", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		fb, err := os.ReadFile(args[0].String())
		if err != nil {
			// Only absence maps to null; every other failure surfaces.
			if errors.Is(err, os.ErrNotExist) {
				return qc.NewNull(), nil
			}
			return nil, err
		}
		return qc.NewArrayBuffer(fb), nil
	}))
	b.SetPropertyStr("writeFile", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		// Bytes borrowed last (qjs.Value.View).
		path, mode := args[0].String(), os.FileMode(args[2].Int64())
		bytes, err := args[1].View()
		if err != nil {
			return nil, err
		}
		// Atomic, so a torn write never replaces the freshness state.
		if err := writeFileAtomic(path, bytes, ".seedkernel-", mode); err != nil {
			return nil, err
		}
		return qc.NewUndefined(), nil
	}))
	b.SetPropertyStr("log", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		// The realm's console; stderr, since stdout is `--op`'s data channel.
		fmt.Fprintln(os.Stderr, args[0].String())
		return qc.NewUndefined(), nil
	}))
	b.SetPropertyStr("stdout", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		bytes, err := args[0].View()
		if err != nil {
			return nil, err
		}
		if _, err := os.Stdout.Write(bytes); err != nil {
			return nil, err
		}
		return qc.NewUndefined(), nil
	}))
	b.SetPropertyStr("stdin", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		// `--op`'s argument, read whole and only on demand.
		bytes, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		return qc.NewArrayBuffer(bytes), nil
	}))

	installRealmBridge(qc, b) // guest.go
	qc.Global().SetPropertyStr("bridge", b)
}

// ───────────────────────── driving the shell ─────────────────────────

// callRealm calls one of the shim's entry points with args staged as __a0…__aN, and pumps
// the loop until its promise settles.
func callRealm(name string, timeout time.Duration, args ...*qjs.Value) ([]byte, error) {
	if qc == nil {
		return nil, errors.New("seedkernel: boot has not run")
	}
	slots := make([]string, len(args))
	for i, a := range args {
		slots[i] = "__a" + strconv.Itoa(i)
		qc.Global().SetPropertyStr(slots[i], a) // takes the reference
	}
	defer func() {
		undef := qc.NewUndefined()
		for _, slot := range slots {
			qc.Global().SetPropertyStr(slot, undef)
		}
	}()
	kind, value, msg, err := el.await(name+"("+strings.Join(slots, ",")+")", timeout)
	if err != nil {
		return nil, err
	}
	if kind != 0 {
		return nil, errors.New(msg)
	}
	return value, nil
}

// ───────────────────────── entry ─────────────────────────

// main boots and runs the operator flow (host/cli.ts); Go only decides whether to keep
// the loop running.
func main() {
	// One P by default: all engine work is on the loop goroutine, and extra Ps only add
	// wakeups per message. GOMAXPROCS overrides.
	if os.Getenv("GOMAXPROCS") == "" {
		runtime.GOMAXPROCS(1)
	}
	if err := boot(); err != nil {
		fatal("boot", err)
		return
	}
	// No watchdog: the steps that can hang carry their own deadlines.
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
	if el.err != nil {
		fatal("seedkernel", el.err)
	}
}

// fatal reports a failure and exits non-zero.
func fatal(stage string, err error) {
	fmt.Fprintln(os.Stderr, "ERROR: "+stage+": "+err.Error())
	os.Exit(1)
}
