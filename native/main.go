// seedkernel native loader (§12.9). It verifies a signed host blob (hostblob.go) and runs
// the host script in it on QuickJS, over the platform ABI (WASM/host/abi.ts): the module
// table (§3), files, sockets, entropy, and the engine table realms and the host's crypto
// run on (engine.go). Everything a node does is in the blob. Pure Go, one static binary.
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
	"strconv"
	"strings"
	"time"

	"seedkernel/qjs"

	"github.com/tetratelabs/wazero"
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
	// rtCore is the loader's own crypto runtime (libsodium, ML-DSA), not budget-armed.
	rtCore wazero.Runtime
	qc     *qjs.Context
	qrt    *qjs.Runtime
	el     *eventLoop
	nh     *netHost
	uh     *udpHost

	// bootBlob is the host blob boot runs: genesisHost, or the operator's --host.
	bootBlob = genesisHost
	// host is the running host blob, verified.
	host *hostBlob
	// hostArgs are the arguments the host sees: the command line less the loader's own.
	hostArgs []string
	// updates are the host slots (hostslots.go); nil when --host chose the blob.
	updates *hostUpdates
	// serving is set while the loop runs for a serving node, after its operator flow.
	serving bool
)

// ───────────────────────── the realm and its primitives ─────────────────────────

// boot checks bootBlob, then stands up the engines, the host realm and its primitives, and
// runs the host script. Each boot releases the previous one's engines.
func boot() error {
	shutdown()
	var err error
	if err = bootModuleTable(); err != nil {
		return err
	}
	loaderCrypto()
	if host, err = verifyHostBlob(bootBlob); err != nil {
		return err
	}
	if host.abi != platformABI {
		return fmt.Errorf("host: the blob needs platform ABI %d, this loader implements %d", host.abi, platformABI)
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
	// The shim defined the __net and __udp dispatchers; retain them.
	if err := nh.retain(); err != nil {
		return fmt.Errorf("net retain: %w", err)
	}
	if err := uh.retain(); err != nil {
		return fmt.Errorf("udp retain: %w", err)
	}
	return nil
}

// loaderCrypto stands up the loader's own crypto once: it checks host blobs before any
// boot, and outlives every host it checks.
func loaderCrypto() {
	if rtCore == nil {
		rtCore = wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler())
		sd = bootSodium(rtCore)
		md = bootMlDsa(rtCore) // manifest suite 0x02 (§12.4)
	}
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
	closeModuleTable()
}

// exposeBridge installs `bridge`, typed in host/platform.ts.
func exposeBridge(qc *qjs.Context) {
	b := qc.NewObject()

	// The platform ABI this loader implements, which the host script checks first.
	b.SetPropertyStr("abi", qc.NewInt32(platformABI))
	b.SetPropertyStr("banner", qc.NewString("seedkernel-native"))
	// A module call runs on the loop inside the guest's segment, which counts it.
	b.SetPropertyStr("modulesInSegment", qc.NewBool(true))

	installModuleBridge(qc, b) // module.go

	// The operator's world (host/cli.ts): arguments, files, stdio.
	b.SetPropertyStr("argv", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		// JSON, since an argument may contain any separator.
		j, err := json.Marshal(hostArgs)
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
	// Keep a host blob as the pending host (hostslots.go). Under --host-updates now, the
	// loop stops after this turn and the loader boots it.
	b.SetPropertyStr("stageHost", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		env, err := args[0].Bytes()
		if err != nil {
			return nil, err
		}
		now, err := updates.stage(env, host)
		if err != nil {
			return nil, err
		}
		// While the operator flow runs, the loop is driving its await, so runHost checks once
		// that ends instead.
		if now && serving {
			el.stopped = true
		}
		return nil, nil
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
	flags, err := loaderFlags(os.Args[1:])
	if err != nil {
		fatal("seedkernel", err)
		return
	}
	hostArgs = flags.rest
	loaderCrypto()
	if flags.hostFile != "" {
		if bootBlob, err = os.ReadFile(flags.hostFile); err != nil {
			fatal("--host", err)
			return
		}
	} else {
		genesis, err := verifyHostBlob(genesisHost)
		if err != nil {
			fatal("genesis host", err)
			return
		}
		if updates, err = newHostUpdates(dataDirOf(hostArgs), flags.updates, genesis); err != nil {
			fatal("seedkernel", err)
			return
		}
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() { <-sig; os.Exit(0) }()
	for {
		if updates != nil {
			bootBlob = updates.choose()
		}
		up, err := runHost()
		if err != nil {
			// A pending host that fails is dropped, and the committed one boots instead.
			if updates.failed(err) {
				continue
			}
			fatal("seedkernel", err)
			return
		}
		if !up || !updates.takeReboot() {
			return
		}
	}
}

// runHost boots bootBlob and runs its operator flow, and while it serves, its loop. It
// returns when the flow ends without serving, when a staged host asks to boot now, or on
// a failure.
func runHost() (serving bool, err error) {
	if err := boot(); err != nil {
		return false, fmt.Errorf("boot: %w", err)
	}
	// No watchdog: the steps that can hang carry their own deadlines.
	out, err := callRealm("runMain", 0)
	if err != nil {
		return false, err
	}
	// A host booted after this one, in this process, does not repeat the one-shot op.
	hostArgs = withoutOp(hostArgs)
	var st struct{ Serving bool }
	if err := json.Unmarshal(out, &st); err != nil {
		return false, err
	}
	updates.started(st.Serving)
	if !st.Serving || updates.rebootWaiting() {
		return st.Serving, nil
	}
	serving = true
	defer func() { serving = false }()
	el.stopped = false
	el.run()
	return true, el.err
}

// The loader's own flags (loaderFlags), and the host's arguments without them.
type loaderOptions struct {
	rest     []string
	hostFile string
	updates  string
}

// loaderFlags takes the loader's own flags out of the command line, as `--name value` or
// `--name=value`. The rest is the host's.
//
//   - `--host <file>` boots that host blob instead of the slots' choice, by the operator's
//     explicit choice and from any author.
//   - `--host-updates off|next|now` is whether a running host may stage a new one, and
//     when it runs: refused (the default), at the next start, or at once.
func loaderFlags(argv []string) (loaderOptions, error) {
	o := loaderOptions{rest: []string{}, updates: updatesOff}
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		name, value, inline := strings.Cut(strings.TrimPrefix(a, "--"), "=")
		if !strings.HasPrefix(a, "--") || (name != "host" && name != "host-updates") {
			o.rest = append(o.rest, a)
			continue
		}
		if !inline {
			if i+1 >= len(argv) {
				return o, fmt.Errorf("--%s needs a value", name)
			}
			i++
			value = argv[i]
		}
		if name == "host" {
			o.hostFile = value
		} else {
			o.updates = value
		}
	}
	return o, nil
}

// withoutOp is args less --op and its value.
func withoutOp(args []string) []string {
	out := []string{}
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--op":
			i++
		case strings.HasPrefix(args[i], "--op="):
		default:
			out = append(out, args[i])
		}
	}
	return out
}

// dataDirOf is the host's --dir, which the slots sit beside, or the CLI's default
// (host/cli.ts DEFAULT_DIR).
func dataDirOf(args []string) string {
	for i, a := range args {
		if a == "--dir" && i+1 < len(args) {
			return args[i+1]
		}
		if v, ok := strings.CutPrefix(a, "--dir="); ok {
			return v
		}
	}
	return "./data"
}

// fatal reports a failure and exits non-zero.
func fatal(stage string, err error) {
	fmt.Fprintln(os.Stderr, "ERROR: "+stage+": "+err.Error())
	os.Exit(1)
}
