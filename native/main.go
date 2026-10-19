// seedkernel native loader (§12.9). It runs the host script in a host blob (hostblob.go)
// on QuickJS, over the platform ABI (WASM/host/abi.ts): the module table (§3), files,
// sockets, entropy, and the engine table realms and the host's crypto run on (engine.go).
// Everything a node does is in the blob, the checks on its successor included; the loader
// keeps the slots it is staged in (hostslots.go). Pure Go, one static binary.
package main

import (
	"context"
	crand "crypto/rand"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"

	"seedkernel/qjs"
)

// platformABI is the version of the platform ABI (host/abi.ts) this binary implements.
const platformABI = 1

// genesisHost is the host blob this binary was built with (scripts/build-host-blob.mjs),
// the one it runs unless told otherwise.
//
//go:embed host.skb
var genesisHost []byte

var (
	ctx = context.Background()
	qc  *qjs.Context
	qrt *qjs.Runtime
	el  *eventLoop
	nh  *netHost
	uh  *udpHost

	// bootBlob is the host blob boot runs: genesisHost, or the loader's choice.
	bootBlob = genesisHost
	// host is the running host blob and the parts boot runs of it.
	host struct {
		env    []byte
		script string
		qjs    []byte
	}
	// ldr is the loader script's realm (hostslots.go); nil in tests that boot directly.
	ldr *loader
	// serving is set while the loop runs for a serving node, after its operator flow.
	serving bool
	// rebootWaiting is set when a host staged under "now" waits for the operator flow to end.
	rebootWaiting bool
)

// ───────────────────────── the realm and its primitives ─────────────────────────

// boot reads bootBlob, then stands up the engines, the host realm and its primitives, and
// runs the host script. Each boot releases the previous one's engines.
func boot() error {
	shutdown()
	var err error
	host.env = bootBlob
	if host.script, host.qjs, err = hostParts(bootBlob); err != nil {
		return err
	}

	// An unhandled rejection ends the process, as on Node.
	if qrt, err = qjs.New(host.qjs, qjs.TrackRejections()); err != nil {
		return fmt.Errorf("qjs.New: %w", err)
	}
	qc = qrt.Context()
	el = newEventLoop(qc)
	// The bundle's module scope reaches for these primitives, so it evaluates last.
	exposeFs(qc)
	nh = exposeNet(qc, el)
	uh = exposeUdp(qc, el)
	exposeBridge(qc)
	done, err := qc.Eval("host.js", host.script)
	if err != nil {
		return fmt.Errorf("host script: %w", err)
	}
	done.Free()
	return nil
}

// shutdown releases a previous boot: the network, every realm, and the wazero runtimes.
func shutdown() {
	// The network first, so its readers stop posting into the realm freed below.
	if nh != nil {
		nh.close()
		nh = nil
	}
	if uh != nil {
		uh.close()
		uh = nil
	}
	for _, e := range engines {
		e.close()
	}
	engines = map[int64]*engineInstance{}
	if qrt != nil {
		qrt.Close()
		qrt, qc, el = nil, nil, nil
	}
}

// exposeBridge installs `bridge`, typed in host/platform.ts.
func exposeBridge(qc *qjs.Context) {
	b := qc.NewObject()

	// The platform ABI this loader implements, which the host script checks first.
	b.SetPropertyStr("abi", qc.NewInt32(platformABI))
	b.SetPropertyStr("banner", qc.NewString("seedkernel-native"))
	// The operator's world (host/cli.ts): arguments, files, stdio.
	b.SetPropertyStr("argv", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		// JSON, since an argument may contain any separator.
		j, _, err := ldr.call(`JSON.stringify(__loader.hostArgs)`)
		return qc.NewString(j), err
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
		if err := writeFileAtomic(path, bytes, mode); err != nil {
			return nil, err
		}
		return qc.NewUndefined(), nil
	}))
	// The running host blob, which carries the realm engine and the host's crypto.
	b.SetPropertyStr("hostBlob", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		return qc.NewArrayBuffer(host.env), nil
	}))
	// Keep a host blob, which the running host checked, as the pending host (hostslots.go).
	// Under --host-updates now, the loop stops after this turn and the loader boots it.
	b.SetPropertyStr("stageHost", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		env, err := args[0].Bytes()
		if err != nil {
			return nil, err
		}
		now, err := ldr.stage(env)
		// While the operator flow runs, the loop is driving its await, so runHost checks once
		// that ends instead.
		if now && serving {
			el.stopped = true
		} else if now {
			rebootWaiting = true
		}
		return nil, err
	}))
	b.SetPropertyStr("random", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		out := make([]byte, args[0].Int32())
		crand.Read(out)
		return qc.NewArrayBuffer(out), nil
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

	installEngineBridge(qc, b) // engine.go
	qc.Global().SetPropertyStr("bridge", b)
}

// ───────────────────────── entry ─────────────────────────

// main boots the loader's choice and runs its operator flow (host/cli.ts); Go only decides
// whether to keep the loop running.
func main() {
	// One P by default: all engine work is on the loop goroutine, and extra Ps only add
	// wakeups per message. GOMAXPROCS overrides.
	if os.Getenv("GOMAXPROCS") == "" {
		runtime.GOMAXPROCS(1)
	}
	// The loader script runs on the genesis blob's engine, which the host's realm then
	// shares from the compile cache.
	_, engine, err := hostParts(genesisHost)
	if err == nil {
		ldr, err = newLoader(engine, os.Args[1:], genesisHost)
	}
	if err != nil {
		fatal("seedkernel", err)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() { <-sig; os.Exit(0) }()
	for {
		if bootBlob, err = ldr.choose(genesisHost); err != nil {
			fatal("host slots", err)
		}
		again, err := runHost()
		if err != nil {
			// A pending host that fails is dropped, and the committed one boots instead.
			if ldr.failed(err) {
				continue
			}
			fatal("seedkernel", err)
		}
		if !again {
			return
		}
	}
}

// runHost boots bootBlob and runs its operator flow, and while it serves, its loop. It
// returns when the flow ends without serving, when a staged host asks to boot now (again),
// or on a failure.
func runHost() (again bool, err error) {
	if err := boot(); err != nil {
		return false, fmt.Errorf("boot: %w", err)
	}
	// No watchdog: the steps that can hang carry their own deadlines.
	kind, out, msg, err := el.await("runMain()")
	if err != nil {
		return false, err
	}
	if kind != 0 {
		return false, errors.New(msg)
	}
	var st struct{ Serving bool }
	if err := json.Unmarshal(out, &st); err != nil {
		return false, err
	}
	if _, _, err := ldr.call(`__loader.ended(__a0)`, st.Serving); err != nil {
		return false, err
	}
	if !st.Serving || rebootWaiting {
		rebootWaiting = false
		return st.Serving, nil
	}
	serving = true
	defer func() { serving = false }()
	el.stopped = false
	el.run()
	// The loop stops for a failure, or for a host staged under "now".
	return el.err == nil, el.err
}

// fatal reports a failure and exits non-zero.
func fatal(stage string, err error) {
	fmt.Fprintln(os.Stderr, "ERROR: "+stage+": "+err.Error())
	os.Exit(1)
}
