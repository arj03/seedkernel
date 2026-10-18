package main

import (
	"strings"
	"testing"
)

// abortingWasm is a minimal module whose `handle` calls `env.abort` and would then return
// 0. Hand-assembled instead of built with AssemblyScript because only one import and one
// call matter, and a toolchain build would need to exist on every machine that runs the
// suite. It exports a memory, which the engine table needs, and no scratch, so the module
// ABI refuses it.
//
//	(module
//	  (import "env" "abort" (func $abort (param i32 i32 i32 i32)))
//	  (memory (export "memory") 1)
//	  (func (export "handle") (param i32) (result i32)
//	    i32.const 0  i32.const 0  i32.const 12  i32.const 34  call $abort
//	    i32.const 0))
var abortingWasm = func() []byte {
	typ := sec(1, 2, 0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x00, 0x60, 0x01, 0x7f, 0x01, 0x7f)
	imp := sec(2, 1, 0x03, 'e', 'n', 'v', 0x05, 'a', 'b', 'o', 'r', 't', 0x00, 0x00)
	fn := sec(3, 1, 0x01)
	mem := sec(5, 1, 0x00, 0x01)
	exp := sec(7, 2, 0x06, 'h', 'a', 'n', 'd', 'l', 'e', 0x00, 0x01, 0x06, 'm', 'e', 'm', 'o', 'r', 'y', 0x02, 0x00)
	body := []byte{0x00, 0x41, 0x00, 0x41, 0x00, 0x41, 0x0c, 0x41, 0x22, 0x10, 0x00, 0x41, 0x00, 0x0b}
	code := sec(10, append([]byte{0x01, byte(len(body))}, body...)...)
	out := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	for _, s := range [][]byte{typ, imp, fn, mem, exp, code} {
		out = append(out, s...)
	}
	return out
}()

// AssemblyScript calls `env.abort` where a module has detected it is broken (a failed
// assertion, an out-of-bounds access). The shim (host/pure-module.ts moduleShims) must trap,
// not return: a returning abort would let the module run past that point, failing on the
// JS targets while silently continuing here (§4.2). A trapped call answers null, which the
// guest seam rejects (§12.2).
func TestAbortShimTraps(t *testing.T) {
	bootRealm(t)
	qc.Global().SetPropertyStr("__aborting", qc.NewArrayBuffer(abortingWasm))
	got := evalString(t, `(() => {
		const id = bridge.engineInstantiate(new Uint8Array(__aborting), moduleShims(), -1);
		const fn = bridge.engineExport(id, "handle");
		try { bridge.engineCallBounded(id, fn, -1, 0); return "returned"; }
		catch (e) { return String(e.message); } finally { bridge.engineDispose(id); }
	})()`)
	if got == "returned" {
		t.Fatal("a module calling env.abort returned instead of trapping")
	}
	// The location is the only thing that makes an abort diagnosable, since the instance
	// is gone by the time anyone reads the error.
	if !strings.Contains(got, "12:34") {
		t.Fatalf("abort trap lost its line:column: %v", got)
	}
}
