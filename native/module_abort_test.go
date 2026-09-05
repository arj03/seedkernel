package main

import (
	"strings"
	"testing"
)

// abortingWasm is a minimal §4-shaped module whose `handle` calls `env.abort` and would
// then return 0. Hand-assembled rather than built from AssemblyScript because the point is
// one import and one call: a toolchain fixture would bury that under a runtime, and the
// build step would have to exist on every machine that runs the suite.
//
//	(module
//	  (import "env" "abort" (func $abort (param i32 i32 i32 i32)))
//	  (func (export "handle") (param i32) (result i32)
//	    i32.const 0  i32.const 0  i32.const 12  i32.const 34  call $abort
//	    i32.const 0))
var abortingWasm = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic, version
	// Type section: (i32,i32,i32,i32)->() for abort, (i32)->(i32) for handle.
	0x01, 0x0d, 0x02,
	0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x00,
	0x60, 0x01, 0x7f, 0x01, 0x7f,
	// Import section: env.abort, type 0.
	0x02, 0x0d, 0x01,
	0x03, 'e', 'n', 'v', 0x05, 'a', 'b', 'o', 'r', 't', 0x00, 0x00,
	// Function section: one local function of type 1.
	0x03, 0x02, 0x01, 0x01,
	// Export section: "handle" = func 1 (func 0 is the imported abort).
	0x07, 0x0a, 0x01, 0x06, 'h', 'a', 'n', 'd', 'l', 'e', 0x00, 0x01,
	// Code section: abort(0, 0, 12, 34) then i32.const 0.
	0x0a, 0x10, 0x01, 0x0e, 0x00,
	0x41, 0x00, 0x41, 0x00, 0x41, 0x0c, 0x41, 0x22, 0x10, 0x00,
	0x41, 0x00, 0x0b,
}

// AssemblyScript calls `env.abort` at the point a module has declared itself broken — a
// failed assertion, an out-of-bounds access. The shim must TRAP rather than return: a
// returning abort lets the module run on past that point, and would make one module fail
// its call on the JS targets while silently continuing here (PROTOCOL §4.2). callModule
// reads the resulting call error as a failure, which the guest seam rejects (§12.2).
func TestAbortShimTraps(t *testing.T) {
	ensureBooted(t)
	m, err := rt.Instantiate(ctx, abortingWasm)
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	defer m.Close(ctx)

	_, err = m.ExportedFunction("handle").Call(ctx, 0)
	if err == nil {
		t.Fatal("a module calling env.abort returned instead of trapping")
	}
	// The site is the only thing that makes an abort diagnosable — the instance is spent
	// by the time anyone reads the error.
	if !strings.Contains(err.Error(), "12:34") {
		t.Fatalf("abort trap lost its line:column: %v", err)
	}
}
