package qjs

import (
	"strings"
	"testing"
)

// TestWASIStubsAreUnreachable pins a runtime's WASI surface: every import but the clock is
// a refusing stub (instantiateWASI), and nothing in a bare quickjs-ng context reaches one —
// but for wasi-libc's allocator setup, which asks for entropy once at construction and
// settles for a fixed value when refused. The clock is the positive control: it is the one
// import a realm keeps, so a probe that records it proves the witness is wired; anything
// else recorded fails the test.
func TestWASIStubsAreUnreachable(t *testing.T) {
	var reached []string
	probe := func(name string) { reached = append(reached, name) }
	// only fails on an import outside allowed reached since the last reset, then resets.
	only := func(phase string, allowed ...string) {
		t.Helper()
	next:
		for _, name := range reached {
			for _, a := range allowed {
				if name == a {
					continue next
				}
			}
			t.Fatalf("%s reached WASI import %q (all reached: %v)", phase, name, reached)
		}
		reached = nil
	}

	// Capped like a guest realm, so the out-of-memory probe below fails fast.
	rt, err := New(WithMemoryLimit(64<<20), func(c *config) { c.wasiProbe = probe })
	if err != nil {
		t.Fatal("New:", err)
	}
	defer rt.Close()
	c := rt.Context()
	// Construction reads the clock (the context's random seed, JS_AddPerformance), and
	// wasi-libc's _initialize asks for entropy.
	only("construction", "clock_time_get", "random_get")

	// Prove a JS call reaches the witness before trusting a quiet one.
	if _, err := c.Eval("clock.js", Code("Date.now()")); err != nil {
		t.Fatal("Date.now:", err)
	}
	if len(reached) == 0 {
		t.Fatal("Date.now did not reach the clock: the WASI witness is not wired")
	}
	only("Date.now", "clock_time_get")

	// Every builtin that could plausibly touch the host: time, entropy, serialization,
	// regexp, eval, microtasks, async resumption, and the engine's own failure paths. A throw
	// or a rejection is an expected result here, not the subject.
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
		`Promise.reject(new Error("unhandled"))`,
		`(() => { throw new Error("boom"); })()`,
		`Object.defineProperty({}, "x", { get() { throw new Error("get"); } }).x`,
		`(function f() { return f(); })()`,
		`JSON.parse("[".repeat(100000) + "]".repeat(100000))`,
		`new Array(2e7).fill(0)`,
	} {
		if v, err := c.Eval("wasi-probe.js", Code(src)); err == nil && v != nil {
			v.Free()
		}
		_ = c.Pump()
	}

	only("JS", "clock_time_get")
}

// Deep recursion — in JS, or in the engine's own recursive native code such as JSON.parse —
// ends in a catchable RangeError and leaves the runtime usable. quickjs-ng switches its
// stack limit off for WASI (csrc/0001-wasi-stack-limit.patch turns it back on), and without
// the limit the recursion runs off the shadow stack into a trap that breaks every later call.
func TestStackOverflowThrows(t *testing.T) {
	for _, tc := range []struct{ name, src string }{
		{"recursion", `(function f(n) { return f(n + 1) + 1; })(0)`},
		{"JSON.parse", `JSON.parse("[".repeat(1000000) + "]".repeat(1000000))`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, err := New()
			if err != nil {
				t.Fatal("New:", err)
			}
			defer rt.Close()
			c := rt.Context()
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("the engine trapped instead of throwing: %v", r)
				}
			}()
			if _, err := c.Eval("overflow.js", Code(tc.src)); err == nil ||
				!strings.Contains(err.Error(), "RangeError: Maximum call stack size exceeded") {
				t.Fatalf("got %v, want the engine's stack overflow RangeError", err)
			}
			v, err := c.Eval("after.js", Code(`1 + 1`))
			if err != nil {
				t.Fatalf("the runtime is unusable after the overflow: %v", err)
			}
			defer v.Free()
			if got := v.String(); got != "2" {
				t.Fatalf("1 + 1 = %s", got)
			}
		})
	}
}
