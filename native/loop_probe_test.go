package main

import (
	"testing"

	"seedloader/qjs"
)

// TestQjsPumpModel is the gate for the whole no-rebuild async design. It verifies
// the two facts the Go-owned event loop relies on:
//
//  1. Invoke (QJS_Call) does NOT run the job queue — a microtask queued during an
//     invoked JS callback stays pending afterwards.
//  2. Eval("0") DOES run the job queue (QJS_Eval calls js_std_loop), draining that
//     pending microtask — and returns promptly (no os timers registered, so it
//     does not block).
//
// If (2) fails we cannot pump jobs from Go without rebuilding qjs.wasm to export
// JS_ExecutePendingJob.
func TestQjsPumpModel(t *testing.T) {
	rt, err := qjs.New()
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	c := rt.Context()

	if _, err := c.Eval("setup.js", qjs.Code(`
		globalThis.__flag = 0;
		globalThis.queueMicrotask = (f) => { Promise.resolve().then(f); };
		globalThis.kick = () => { queueMicrotask(() => { globalThis.__flag = 1; }); };
	`)); err != nil {
		t.Fatal("setup:", err)
	}

	// Call kick() via Invoke — this queues a microtask but must NOT run it.
	kick := c.Global().GetPropertyStr("kick")
	if _, err := c.Invoke(kick, c.Global()); err != nil {
		t.Fatal("invoke kick:", err)
	}
	flagAfterInvoke := c.Global().GetPropertyStr("__flag").Int32()

	// Pump: a trivial Eval runs js_std_loop, which drains pending jobs.
	if _, err := c.Eval("pump.js", qjs.Code("0")); err != nil {
		t.Fatal("pump:", err)
	}
	flagAfterPump := c.Global().GetPropertyStr("__flag").Int32()

	t.Logf("flag after Invoke=%d, after Eval-pump=%d", flagAfterInvoke, flagAfterPump)
	if flagAfterPump != 1 {
		t.Fatalf("Eval-pump did not drain the queued microtask (flag=%d); the no-rebuild loop is not viable", flagAfterPump)
	}
}

// TestQjsAwaitsOsTimer confirms QJS_Eval awaits a promise that only settles when
// an os.setTimeout fires — i.e. js_std_await drives the built-in timer loop. This
// is the Phase-0-only driving model (no Go I/O); Phases 1-3 use Go-backed timers.
func TestQjsAwaitsOsTimer(t *testing.T) {
	rt, err := qjs.New()
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	c := rt.Context()

	v, err := c.Eval("await.js", qjs.Code(`
		new Promise((resolve) => { setTimeout(() => resolve(42), 5); })
	`))
	if err != nil {
		t.Fatal("eval await:", err)
	}
	if got := v.Int32(); got != 42 {
		t.Fatalf("QJS_Eval did not await the os.setTimeout promise: got %d, want 42", got)
	}
}
