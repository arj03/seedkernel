package qjs

import "testing"

// TestConfinedWASIStubsAreUnreachable pins the confined realm's WASI surface: the engine's
// imports are unchanged, but a confined runtime links stubs for every one of them except
// the clock, and neither construction nor any JS path in a bare quickjs-ng context
// reaches a stub. The clock is the positive control — it is the one import the realm
// keeps, so a probe that records it proves the witness is wired; anything else recorded
// fails the test.
func TestConfinedWASIStubsAreUnreachable(t *testing.T) {
	var reached []string
	probe := func(name string) { reached = append(reached, name) }
	// clockOnly fails on any import but the clock reached since the last reset, then resets.
	clockOnly := func(phase string) {
		t.Helper()
		for _, name := range reached {
			if name != "clock_time_get" {
				t.Fatalf("confined %s reached WASI import %q (all reached: %v)", phase, name, reached)
			}
		}
		reached = nil
	}

	rt, err := New(WithoutHostObjects(), func(c *config) { c.wasiProbe = probe })
	if err != nil {
		t.Fatal("New(WithoutHostObjects):", err)
	}
	defer rt.Close()
	c := rt.Context()
	// Construction itself reads the clock (JS_AddPerformance) and nothing else.
	clockOnly("construction")

	// Prove a JS call reaches the witness before trusting a quiet one.
	if _, err := c.Eval("clock.js", Code("Date.now()")); err != nil {
		t.Fatal("Date.now:", err)
	}
	if len(reached) == 0 {
		t.Fatal("Date.now did not reach the confined clock: the WASI witness is not wired")
	}
	clockOnly("Date.now")

	// Every builtin that could plausibly touch the host: time, entropy, serialization,
	// regexp, eval, microtasks and async resumption. A throw or a rejection is an expected
	// result here, not the subject.
	for _, src := range []string{
		"Date.now()",
		"new Date()",
		"performance.now()",
		"Math.random()",
		`JSON.stringify({ a: [1, 2, 3], b: "x" })`,
		`/a+/.test("aaa")`,
		`eval("1 + 1")`,
		`new Function("return 1")()`,
		`Promise.resolve(1).then((v) => v + 1)`,
		`(async () => 1)()`,
		`(() => { throw new Error("boom"); })()`,
		`Object.defineProperty({}, "x", { get() { throw new Error("get"); } }).x`,
	} {
		if v, err := c.Eval("confined-wasi-probe.js", Code(src)); err == nil && v != nil {
			v.Free()
		}
		_ = c.Pump()
	}

	clockOnly("JS")
}
