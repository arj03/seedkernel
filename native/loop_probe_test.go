package main

import (
	"testing"

	"seedloader/qjs"
)

// TestQjsPumpModel is the gate for the whole Go-owned async design. It verifies the two
// facts the event loop relies on:
//
//  1. Invoke (QJS_Call) does NOT run the job queue — a microtask queued during an
//     invoked JS callback stays pending afterwards.
//  2. Pump DOES run it, draining that pending microtask, and returns promptly: the
//     loader registers no os timers, so js_std_loop has nothing to wait on.
//
// Pump reached the queue through QJS_Eval's trailing js_std_loop back when the engine
// blob was vendored and its exports were not ours to choose. It calls js_std_loop
// directly now (csrc/qjswasm.cmake), which is the same drain without compiling and
// running an expression first — a cost every pump paid, and the loop pumps after every
// re-entry into JS.
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

	if err := c.Pump(); err != nil {
		t.Fatal("pump:", err)
	}
	flagAfterPump := c.Global().GetPropertyStr("__flag").Int32()

	t.Logf("flag after Invoke=%d, after Pump=%d", flagAfterInvoke, flagAfterPump)
	if flagAfterPump != 1 {
		t.Fatalf("Pump did not drain the queued microtask (flag=%d); the Go-driven loop is not viable", flagAfterPump)
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

// The host realm's monotonic clock must answer FRACTIONAL milliseconds, as Node and the
// browsers do. The guest seam meters host compute by the distance across one synchronous
// handler (host/guest-seam.ts), and an ed25519 verify does not last a whole millisecond:
// a truncating clock would read every one of them as free, and with it a timer re-arm
// loop built out of them (§12.3). Nothing else fails if this regresses, so it is asserted
// here rather than left to a pacing test that would still pass at zero.
func TestHostClockIsSubMillisecond(t *testing.T) {
	bootRealm(t)
	// Two readings around a busy wait far shorter than a millisecond. Whole-ms truncation
	// answers "0" for the difference on all but the unlucky reading that straddles a tick,
	// so the loop retries: one fractional reading is proof, many zeroes are not.
	got := evalString(t, `(() => {
	  for (let attempt = 0; attempt < 100; attempt++) {
	    const started = performance.now();
	    while (performance.now() === started) { /* wait for the clock to move at all */ }
	    const step = performance.now() - started;
	    if (step > 0 && step < 1) return "fractional";
	  }
	  return "whole milliseconds";
	})()`)
	if got != "fractional" {
		t.Fatalf("performance.now() moves in %s; host-service compute would meter as zero", got)
	}
}
