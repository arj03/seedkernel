// Host updates (§12.9): which host blob each boot runs, and the trial that commits a staged
// one. The rules are the shared loader script (WASM/host/slots.ts, embedded as loader.js),
// which this file runs in a QuickJS realm of the loader's own: never the host's, so a
// broken host cannot break its own rollback, and only ever the script built into this
// binary. Go keeps the clock the health window runs on.
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
	// abi is the platform ABI this binary implements: the loader script's PLATFORM_ABI
	// (host/abi.ts), built with it, so the number is written down once.
	abi int
}

// newLoader stands the realm up on engine, the genesis blob's, with the script's `Loader`
// over the command line.
func newLoader(engine []byte, argv []string, genesis []byte) (*loader, error) {
	rt, err := qjs.New(engine)
	if err != nil {
		return nil, fmt.Errorf("loader: %w", err)
	}
	l := &loader{rt: rt, qc: rt.Context()}
	exposeFs(l.qc)
	b := l.qc.NewObject()
	b.SetPropertyStr("log", l.qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		fmt.Fprintln(os.Stderr, "  host   "+args[0].String())
		return nil, nil
	}))
	// The clock: fn runs after ms, in turn with the other callers.
	b.SetPropertyStr("after", l.qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		fn := args[1].Dup()
		time.AfterFunc(time.Duration(args[0].Int64())*time.Millisecond, func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			dispatch(l.qc, "loader", fn)
			fn.Free()
		})
		return nil, nil
	}))
	l.qc.Global().SetPropertyStr("bridge", b)
	j, err := json.Marshal(argv)
	if err == nil {
		_, _, err = l.call(loaderScript)
	}
	if err == nil {
		_, _, err = l.call(`globalThis.__loader = new Loader(__fs, JSON.parse(__a0), new Uint8Array(__a1), __a2 || undefined,
			bridge.log, bridge.after), 0`, string(j), genesis, os.Getenv("SEEDKERNEL_HOST_HEALTH_MS"))
	}
	if err == nil {
		var abi string
		if abi, _, err = l.call(`PLATFORM_ABI`); err == nil {
			l.abi, err = strconv.Atoi(abi)
		}
	}
	if err != nil {
		rt.Close()
		return nil, err
	}
	return l, nil
}

// call evaluates expr in turn with the other callers, with args (strings, bytes, bools)
// as __a0…__aN, and answers its value as bytes when it is bytes, else as a string.
func (l *loader) call(expr string, args ...any) (string, []byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	g := l.qc.Global()
	for i, a := range args {
		var v *qjs.Value
		switch a := a.(type) {
		case string:
			v = l.qc.NewString(a)
		case []byte:
			v = l.qc.NewArrayBuffer(a)
		case bool:
			v = l.qc.NewBool(a)
		}
		g.SetPropertyStr("__a"+strconv.Itoa(i), v) // takes the reference
	}
	defer func() {
		for i := range args {
			g.SetPropertyStr("__a"+strconv.Itoa(i), l.qc.NewUndefined())
		}
	}()
	v, err := l.qc.Eval("loader.js", expr)
	if err != nil {
		return "", nil, err
	}
	defer v.Free()
	if b, err := v.Bytes(); err == nil {
		return "", b, nil
	}
	return v.String(), nil, nil
}

// failed reports whether a failure belongs to a pending host, which is then dropped: the
// caller boots the committed host instead of giving up.
func (l *loader) failed(err error) bool {
	s, _, cerr := l.call(`__loader.failed(__a0)`, err.Error())
	return cerr == nil && s == "true"
}

// stage keeps a host blob the running host checked as pending. Answers whether it should
// boot now.
func (l *loader) stage(env []byte) (bool, error) {
	s, _, err := l.call(`__loader.stage(new Uint8Array(__a0))`, env)
	return s == "true", err
}
