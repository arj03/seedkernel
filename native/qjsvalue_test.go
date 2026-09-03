package main

// JsTypedArrayToGo is the JS→Go byte seam every subsystem crosses (fs.put, __net.send,
// sodium args, guest-seam payloads). The view path must copy exactly the view's window —
// O(view), not O(backing buffer) — and leave the source intact for re-reads.

import (
	"bytes"
	"testing"

	"seedloader/qjs"
)

func TestJsTypedArrayToGoViews(t *testing.T) {
	bootRealm(t)
	v, err := qc.Eval("typedarray-view-test.js", qjs.Code(`
		(() => {
			const buf = new ArrayBuffer(64);
			const full = new Uint8Array(buf);
			for (let i = 0; i < 64; i++) full[i] = i;
			return {
				buf,
				full,
				mid: full.subarray(8, 12),
				empty: full.subarray(5, 5),
				dv: new DataView(buf, 60, 4),
				// A forged "view" whose window runs past the real buffer end: the range
				// check must run against the buffer size QuickJS reports, not these numbers.
				fake: { buffer: buf, byteOffset: 60, byteLength: 8 },
			};
		})();
	`))
	if err != nil {
		t.Fatal(err)
	}
	defer v.Free()

	read := func(name string) ([]byte, error) {
		p := v.GetPropertyStr(name)
		defer p.Free()
		return qjs.JsTypedArrayToGo(p)
	}
	want := func(name string, exp []byte) {
		t.Helper()
		got, err := read(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(got, exp) {
			t.Fatalf("%s = %v, want %v", name, got, exp)
		}
	}

	seq := make([]byte, 64)
	for i := range seq {
		seq[i] = byte(i)
	}
	want("buf", seq)                   // bare ArrayBuffer: the whole store
	want("full", seq)                  // whole-buffer view
	want("mid", []byte{8, 9, 10, 11})  // interior window only
	want("mid", []byte{8, 9, 10, 11})  // re-read: the source must be left intact
	want("empty", []byte{})            // zero-length view
	want("dv", []byte{60, 61, 62, 63}) // DataView is a view too

	if _, err := read("fake"); err == nil {
		t.Fatal("out-of-range window accepted")
	}
}

// A view's byteOffset/byteLength/buffer are ordinary properties of an object the CALLER
// supplies — untrusted code on the guest seam. One that is not a number, or a getter that
// throws, must be refused without leaving the exception for the next call to inherit.
func TestJsTypedArrayToGoHostileProperties(t *testing.T) {
	bootRealm(t)
	for _, tc := range []struct{ name, src string }{
		{"symbol offset", `({ buffer: new ArrayBuffer(8), byteOffset: Symbol("x"), byteLength: 4 })`},
		{"throwing length", `({ buffer: new ArrayBuffer(8), byteOffset: 0, get byteLength() { throw new Error("boom"); } })`},
		{"throwing buffer", `({ get buffer() { throw new Error("nope"); } })`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := qc.Eval("hostile-view-test.js", qjs.Code("("+tc.src+")"))
			if err != nil {
				t.Fatal(err)
			}
			defer v.Free()
			if b, err := qjs.JsTypedArrayToGo(v); err == nil {
				t.Fatalf("JsTypedArrayToGo accepted it, returning %v", b)
			}
			if n, err := qjs.JsTypedArrayByteLength(v); err == nil {
				t.Fatalf("JsTypedArrayByteLength accepted it, returning %d", n)
			}
			// The realm is still usable: the refusal took the exception with it.
			r, err := qc.Eval("after-hostile-view.js", qjs.Code(`1 + 1`))
			if err != nil {
				t.Fatalf("the refusal poisoned the next call: %v", err)
			}
			defer r.Free()
			if got := r.String(); got != "2" {
				t.Fatalf("1 + 1 = %s", got)
			}
		})
	}
}
