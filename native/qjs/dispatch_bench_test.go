package qjs

import "testing"

// BenchmarkCallDispatch measures the per-call floor of the call() path — wazero's
// ExportedFunction resolution plus the invocation, which lazily allocates a fresh
// re-entrancy-safe execution stack (~11 KB/op). QJS_NewInt32 makes an immediate
// (non-refcounted, no-GC) JSValue, so the benchmark isolates dispatch from engine work.
//
// This documents why the bridge resolves the export per call rather than caching the
// api.Function: caching reuses a single instance's execution stack, which corrupts under
// the bridge's re-entrancy (a host import calling back into JS→wasm) — the cheap-looking
// cache produced a fatal stack overflow in the re-entrant net path.
func BenchmarkCallDispatch(b *testing.B) {
	rt, err := New()
	if err != nil {
		b.Fatal(err)
	}
	defer rt.Close()
	h := rt.ctxt.handle
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rt.call("QJS_NewInt32", h, uint64(uint32(i)))
	}
}
