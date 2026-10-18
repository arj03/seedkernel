// Host updates (§12.9): the slots a host blob is staged into and committed from. The rules
// are the shared loader script (WASM/host/slots.ts, embedded as loader.js), which this file
// runs in a QuickJS realm of the loader's own: never the host's, so a broken host cannot
// break its own rollback, and only ever the script built into this binary. Go keeps the
// clock: it arms the health window and reports how each boot ended.
package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"seedkernel/qjs"
)

// loaderScript is the shared loader script (scripts/bundle-host.mjs build/loader.js).
//
//go:embed loader.js
var loaderScript string

// loader is the loader script's realm. Calls come from main, from the host's loop (a
// staging) and from the health timer, so they take turns.
type loader struct {
	mu sync.Mutex
	rt *qjs.Runtime
	qc *qjs.Context
	// slots is set once the slots are open: not under --host.
	slots bool
	// reboot is set when a host staged under "now" is waiting to boot.
	reboot bool
}

// newLoader stands the realm up on engine, the genesis blob's.
func newLoader(engine []byte) (*loader, error) {
	rt, err := qjs.New(engine)
	if err != nil {
		return nil, fmt.Errorf("loader: %w", err)
	}
	qc := rt.Context()
	exposeFs(qc)
	b := qc.NewObject()
	b.SetPropertyStr("log", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		fmt.Fprintln(os.Stderr, "  host   "+args[0].String())
		return nil, nil
	}))
	qc.Global().SetPropertyStr("bridge", b)
	v, err := qc.Eval("loader.js", loaderScript)
	if err != nil {
		rt.Close()
		return nil, fmt.Errorf("loader script: %w", err)
	}
	v.Free()
	return &loader{rt: rt, qc: qc}, nil
}

// call evaluates expr with args staged as __a0…__aN.
func (l *loader) call(expr string, args ...*qjs.Value) (*qjs.Value, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	g := l.qc.Global()
	for i, a := range args {
		g.SetPropertyStr("__a"+strconv.Itoa(i), a) // takes the reference
	}
	defer func() {
		for i := range args {
			g.SetPropertyStr("__a"+strconv.Itoa(i), l.qc.NewUndefined())
		}
	}()
	return l.qc.Eval("loader-call.js", expr)
}

// callJSON passes in and out as JSON, for the calls whose values are plain data.
func (l *loader) callJSON(fn string, in, out any) error {
	j, err := json.Marshal(in)
	if err != nil {
		return err
	}
	v, err := l.call("JSON.stringify("+fn+"(JSON.parse(__a0)))", l.qc.NewString(string(j)))
	if err != nil {
		return err
	}
	defer v.Free()
	return json.Unmarshal([]byte(v.String()), out)
}

// The loader's own flags (loaderFlags in slots.ts), and the host's arguments without them.
type loaderOptions struct {
	Rest     []string
	HostFile string
	Updates  string
}

func (l *loader) flags(argv []string) (o loaderOptions, err error) {
	err = l.callJSON("loaderFlags", argv, &o)
	return o, err
}

func (l *loader) withoutOp(args []string) (out []string, err error) {
	err = l.callJSON("withoutOp", args, &out)
	return out, err
}

// open opens the slots beside the host's --dir, under mode, falling back on genesis.
func (l *loader) open(hostArgs []string, mode string, genesis []byte) error {
	j, err := json.Marshal(hostArgs)
	if err != nil {
		return err
	}
	v, err := l.call(`globalThis.__slots = new HostSlots(__fs, dataDirOf(JSON.parse(__a0)), __a1,
		new Uint8Array(__a2), __a3 || undefined, (line) => bridge.log(line)), 0`,
		l.qc.NewString(string(j)), l.qc.NewString(mode), l.qc.NewArrayBuffer(genesis),
		l.qc.NewString(os.Getenv("SEEDKERNEL_HOST_HEALTH_MS")))
	if err != nil {
		return err
	}
	v.Free()
	l.slots = true
	return nil
}

// choose picks the blob the next boot runs: genesis unless the slots name another.
func (l *loader) choose(genesis []byte) ([]byte, error) {
	if l == nil || !l.slots {
		return genesis, nil
	}
	v, err := l.call(`__slots.choose()`)
	if err != nil {
		return nil, err
	}
	defer v.Free()
	if v.IsNull() {
		return genesis, nil
	}
	return v.Bytes()
}

// failed reports whether a failure belongs to a pending host, which the slots then drop:
// the caller boots the committed host instead of giving up.
func (l *loader) failed(err error) bool {
	if l == nil || !l.slots {
		return false
	}
	v, cerr := l.call(`__slots.failed(__a0)`, l.qc.NewString(err.Error()))
	if cerr != nil {
		return false
	}
	defer v.Free()
	return v.String() == "true"
}

// started is told how the booted host's operator flow ended, and arms the health window
// when the slots ask for one.
func (l *loader) started(serving bool) {
	if l == nil || !l.slots {
		return
	}
	v, err := l.call(`(() => { const g = __slots.started(__a0); return g === null ? -1 : g; })()`, l.qc.NewBool(serving))
	if err != nil {
		hostLog("cannot arm the health window: %v", err)
		return
	}
	gen := v.Int64()
	v.Free()
	if gen < 0 {
		return
	}
	w, err := l.call(`__slots.windowMs`)
	if err != nil {
		return
	}
	window := time.Duration(w.Int64()) * time.Millisecond
	w.Free()
	time.AfterFunc(window, func() {
		if v, err := l.call(`__slots.commit(__a0)`, l.qc.NewInt64(gen)); err == nil {
			v.Free()
		}
	})
}

// stage keeps a host blob the running host checked as pending. Answers whether it should
// boot now.
func (l *loader) stage(env []byte) (bool, error) {
	if l == nil || !l.slots {
		return false, fmt.Errorf("host: updates are off on this node (--host-updates next|now)")
	}
	v, err := l.call(`__slots.stage(new Uint8Array(__a0))`, l.qc.NewArrayBuffer(env))
	if err != nil {
		return false, err
	}
	defer v.Free()
	if v.String() == "true" {
		l.mu.Lock()
		l.reboot = true
		l.mu.Unlock()
	}
	return v.String() == "true", nil
}

// rebootWaiting reports a pending reboot without clearing it.
func (l *loader) rebootWaiting() bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.reboot
}

// takeReboot reports and clears a pending reboot.
func (l *loader) takeReboot() bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	r := l.reboot
	l.reboot = false
	return r
}

func hostLog(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "  host   "+format+"\n", args...)
}
