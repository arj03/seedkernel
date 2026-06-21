package qjs

import "testing"

// BenchmarkInvoke3Args isolates the Invoke marshaling path (marshalArgs + QJS_Call):
// args are built once outside the loop, so each iteration measures only the per-call
// arg staging into wasm and the dispatch — the hot path every host.call / holder
// Invoke runs through. Used to check marshalArgs writing the JSValue words straight
// into the malloc'd region (vs building a Go staging slice and copying it in).
func BenchmarkInvoke3Args(b *testing.B) {
	rt, err := New()
	if err != nil {
		b.Fatal(err)
	}
	defer rt.Close()
	c := rt.Context()
	if _, err := c.Eval("f.js", Code("globalThis.f = (a, b, c) => a;")); err != nil {
		b.Fatal(err)
	}
	fn := c.Global().GetPropertyStr("f")
	defer fn.Free()
	undef := c.NewUndefined()
	a1, a2, a3 := c.NewInt32(1), c.NewInt32(2), c.NewInt32(3) // immediates: no Free needed
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, err := c.Invoke(fn, undef, a1, a2, a3)
		if err != nil {
			b.Fatal(err)
		}
		r.Free()
	}
}

const abPayload = 64 << 10 // 64 KiB, a storage block

// BenchmarkABParts_Fold builds a JS ArrayBuffer for [type][payload] by staging the
// parts directly into one wasm buffer (the serveHandle path after the change).
func BenchmarkABParts_Fold(b *testing.B) {
	rt, err := New()
	if err != nil {
		b.Fatal(err)
	}
	defer rt.Close()
	c := rt.Context()
	payload := make([]byte, abPayload)
	hdr := []byte{1}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v := c.NewArrayBufferParts(hdr, payload)
		v.Free()
	}
}

// BenchmarkABParts_Concat builds the same buffer the old way: a concatenated Go slice
// (make+copy of the whole payload) handed to NewArrayBuffer, which copies it again.
func BenchmarkABParts_Concat(b *testing.B) {
	rt, err := New()
	if err != nil {
		b.Fatal(err)
	}
	defer rt.Close()
	c := rt.Context()
	payload := make([]byte, abPayload)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		arg := make([]byte, 1+len(payload))
		arg[0] = 1
		copy(arg[1:], payload)
		v := c.NewArrayBuffer(arg)
		v.Free()
	}
}
