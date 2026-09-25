package qjs

import "testing"

// TestImmediatesMatchEngine pins the Go-side IsUndefined/IsNull, which compare tags
// against the engine's own JS_UNDEFINED and JS_NULL, to the engine's predicates over a
// value of every kind — doubles included, since a NaN-boxed double spreads over the high
// word a tag occupies.
func TestImmediatesMatchEngine(t *testing.T) {
	rt, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	c := rt.Context()
	for _, src := range []string{
		"undefined", "null", "true", "false", "0", "1", "-1", "2147483647", "-2147483648",
		"1.5", "-1.5", "-0", "NaN", "Infinity", "-Infinity", "1e300", "-1e300", "5e-324",
		"''", "'x'", "Symbol()", "10n", "({})", "[]", "(function(){})",
	} {
		v, err := c.Eval("immediates.js", src)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		if got, want := v.IsUndefined(), v.boolCall("QJS_IsUndefined", v.raw); got != want {
			t.Errorf("%s: IsUndefined %v, engine says %v", src, got, want)
		}
		if got, want := v.IsNull(), v.boolCall("QJS_IsNull", v.raw); got != want {
			t.Errorf("%s: IsNull %v, engine says %v", src, got, want)
		}
		v.Free()
	}
}
