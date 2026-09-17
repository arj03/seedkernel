package main

// Value.Bytes is the JS→Go byte seam every subsystem crosses (fs.put, __net.send,
// sodium args, guest-seam payloads). The view path must copy exactly the view's window —
// O(view), not O(backing buffer) — and leave the source intact for re-reads.

import (
	"bytes"
	"testing"
)

func TestValueBytesViews(t *testing.T) {
	bootRealm(t)
	v, err := qc.Eval("typedarray-view-test.js", `
		(() => {
			const buf = new ArrayBuffer(64);
			const full = new Uint8Array(buf);
			for (let i = 0; i < 64; i++) full[i] = i;
			return {
				buf,
				full,
				mid: full.subarray(8, 12),
				empty: full.subarray(5, 5),
				words: new Uint16Array(buf, 16, 2),
				dv: new DataView(buf, 60, 4),
				// Shaped like a view, with an honest window: still not one.
				fake: { buffer: buf, byteOffset: 0, byteLength: 4 },
			};
		})();
	`)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Free()

	read := func(name string) ([]byte, error) {
		p := v.GetPropertyStr(name)
		defer p.Free()
		return p.Bytes()
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
	want("buf", seq)                      // bare ArrayBuffer: the whole store
	want("full", seq)                     // whole-buffer view
	want("mid", []byte{8, 9, 10, 11})     // interior window only
	want("mid", []byte{8, 9, 10, 11})     // re-read: the source must be left intact
	want("empty", []byte{})               // zero-length view
	want("words", []byte{16, 17, 18, 19}) // a wider element type: its bytes, not its length

	// Only ArrayBuffers and TypedArrays have the slots the bridge reads.
	for _, name := range []string{"dv", "fake"} {
		if b, err := read(name); err == nil {
			t.Fatalf("%s accepted as bytes: %v", name, b)
		}
	}
}

// A view's window is the engine's own: its accessors are not consulted, so redefining them
// neither changes what is copied nor runs any JS.
func TestValueBytesIgnoresAccessors(t *testing.T) {
	bootRealm(t)
	v, err := qc.Eval("accessor-test.js", `
		(() => {
			globalThis.__touched = 0;
			const view = new Uint8Array([1, 2, 3, 4]).subarray(1, 3);
			for (const name of ["buffer", "byteOffset", "byteLength", "length"]) {
				Object.defineProperty(view, name, { get() { globalThis.__touched++; return 0; } });
			}
			return view;
		})()
	`)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Free()
	if n, err := v.ByteLength(); err != nil || n != 2 {
		t.Fatalf("ByteLength = %d, %v; want 2", n, err)
	}
	if b, err := v.Bytes(); err != nil || !bytes.Equal(b, []byte{2, 3}) {
		t.Fatalf("Bytes = %v, %v; want [2 3]", b, err)
	}
	if got := evalString(t, `String(globalThis.__touched)`); got != "0" {
		t.Fatalf("the bridge ran %s accessor(s) while reading the view", got)
	}
}

// The bytes arrive from untrusted code on the guest seam, and an object that merely carries
// view-shaped properties — odd values, throwing getters — is refused without leaving the
// engine's error for the next call to inherit.
func TestValueBytesHostileProperties(t *testing.T) {
	bootRealm(t)
	for _, tc := range []struct{ name, src string }{
		{"symbol offset", `({ buffer: new ArrayBuffer(8), byteOffset: Symbol("x"), byteLength: 4 })`},
		{"throwing length", `({ buffer: new ArrayBuffer(8), byteOffset: 0, get byteLength() { throw new Error("boom"); } })`},
		{"throwing buffer", `({ get buffer() { throw new Error("nope"); } })`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := qc.Eval("hostile-view-test.js", "("+tc.src+")")
			if err != nil {
				t.Fatal(err)
			}
			defer v.Free()
			if b, err := v.Bytes(); err == nil {
				t.Fatalf("Bytes accepted it, returning %v", b)
			}
			if n, err := v.ByteLength(); err == nil {
				t.Fatalf("ByteLength accepted it, returning %d", n)
			}
			// The realm is still usable: the refusal took the exception with it.
			r, err := qc.Eval("after-hostile-view.js", `1 + 1`)
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

// A conversion that cannot succeed must take its own exception. Every entry point on a
// context assumes a clean one, and all three conversions are reached with arguments a
// guest chose (guest.go's __host_call), so one left pending fails the NEXT call there —
// rejecting an invocation that had already produced its answer.
func TestFailedConversionsTakeTheirException(t *testing.T) {
	bootRealm(t)
	for _, tc := range []struct {
		name  string
		expr  string
		asInt bool
	}{
		{"symbol to string", `Symbol("x")`, false},
		{"throwing toString", `({ toString() { throw new Error("no") } })`, false},
		{"throwing valueOf", `({ valueOf() { throw new Error("no") } })`, true},
	} {
		v, err := qc.Eval("conversion-test.js", tc.expr)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if tc.asInt {
			if n := v.Int64(); n != 0 {
				t.Fatalf("%s: Int64 = %d, want 0", tc.name, n)
			}
		} else if s := v.String(); s != "" {
			t.Fatalf("%s: String = %q, want the empty string", tc.name, s)
		}
		v.Free()
		next, err := qc.Eval("conversion-next.js", `1 + 1`)
		if err != nil {
			t.Fatalf("%s: left its exception pending, failing an unrelated call: %v", tc.name, err)
		}
		if got := next.Int32(); got != 2 {
			t.Fatalf("%s: the next call answered %d, want 2", tc.name, got)
		}
		next.Free()
	}
}
