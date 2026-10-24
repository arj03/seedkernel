package main

// The §4.3 bound in practice: a module that never returns holds the thread it runs on,
// and only the deadline ends it (§14.1). These tests check the bound fires, and that the
// killed module's next call runs on a fresh instance.
//
// Two wedges, because a module can fail to return in two places: its `handle` (the call,
// below) and its start section, which instantiation runs; TestModuleBindBound checks the
// deadline covers that too. A third wedges `handle` without a loop, through calls alone.
//
// The wedge is a minimal hand-assembled module whose handle is an infinite loop when the
// request's first byte is nonzero and an echo otherwise, so the module that was killed can
// show its next call answered (the JS suite's SPIN_OR_ECHO_WASM). It declares the §4.1
// exports like any installed module. WAT:
//
//	(module
//	  (memory (export "memory") 3)
//	  (global (export "scratch") i32 (i32.const 16))
//	  (global (export "scratchSize") i32 (i32.const 131072))
//	  (func (export "handle") (param i32) (result i32)
//	    (if (i32.load8_u (i32.const 16)) (then (loop (br 0))))
//	    local.get 0))

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// sec size-prefixes one wasm section. Sizes are computed, not hand-counted, so the bytes
// cannot drift from the WAT they are transcribed from.
func sec(id byte, content ...byte) []byte {
	out := []byte{id, byte(len(content))}
	return append(out, content...)
}

// wedgeWasmBytes assembles the module above, byte by byte (no wabt in the toolchain).
func wedgeWasmBytes() []byte {
	// type (i32)->i32
	typ := sec(1, 1, 0x60, 0x01, 0x7f, 0x01, 0x7f)
	fn := sec(3, 1, 0x00)                          // func 0 has type 0
	mem := sec(5, 1, 0x00, 0x03)                   // memory: one, min 3 pages
	gbl := sec(6, 2, 0x7f, 0x00, 0x41, 0x10, 0x0b, // globals: scratch = 16,
		0x7f, 0x00, 0x41, 0x80, 0x80, 0x08, 0x0b) // scratchSize = 131072, the host default
	exp := sec(7,
		4,                                              // exports:
		0x06, 'm', 'e', 'm', 'o', 'r', 'y', 0x02, 0x00, //   memory
		0x07, 's', 'c', 'r', 'a', 't', 'c', 'h', 0x03, 0x00, //   scratch
		0x0b, 's', 'c', 'r', 'a', 't', 'c', 'h', 'S', 'i', 'z', 'e', 0x03, 0x01, //   scratchSize
		0x06, 'h', 'a', 'n', 'd', 'l', 'e', 0x00, 0x00) //   handle
	body := []byte{
		// no locals
		0x00,
		// i32.load8_u (i32.const 16): the request's first byte
		0x41, 0x10, 0x2d, 0x00, 0x00,
		// if (void), loop (void), br 0 back to the loop header forever, end loop, end if
		0x04, 0x40, 0x03, 0x40, 0x0c, 0x00, 0x0b, 0x0b,
		// local.get 0: echo the request
		0x20, 0x00,
		// end func
		0x0b,
	}
	codeContent := append([]byte{1, byte(len(body))}, body...) // count + size-prefixed body
	code := sec(10, codeContent...)
	out := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00} // magic + version
	out = append(out, typ...)
	out = append(out, fn...)
	out = append(out, mem...)
	out = append(out, gbl...)
	out = append(out, exp...)
	out = append(out, code...)
	return out
}

// wedgeStartWasmBytes is the same module with the loop moved into a start section: its
// `handle` returns immediately, and instantiation never finishes. WAT:
//
//	(module
//	  (memory (export "memory") 3)
//	  (global (export "scratch") i32 (i32.const 16))
//	  (global (export "scratchSize") i32 (i32.const 131072))
//	  (func (export "handle") (param i32) (result i32) i32.const 0)
//	  (func $init (loop (br 0)))   ;; never returns
//	  (start $init))
//
// A call-time deadline cannot reach this wedge, since the module never becomes callable,
// so it checks that the bound also covers instantiation (engine.go newEngineInstance).
func wedgeStartWasmBytes() []byte {
	typ := sec(1, 2,
		0x60, 0x01, 0x7f, 0x01, 0x7f, // type 0: (i32) -> i32   (handle)
		0x60, 0x00, 0x00) //             type 1: () -> ()       (the start function)
	fn := sec(3, 2, 0x00, 0x01)                    // func 0: type 0, func 1: type 1
	mem := sec(5, 1, 0x00, 0x03)                   // memory: one, min 3 pages
	gbl := sec(6, 2, 0x7f, 0x00, 0x41, 0x10, 0x0b, // globals: scratch = 16,
		0x7f, 0x00, 0x41, 0x80, 0x80, 0x08, 0x0b) // scratchSize = 131072, the host default
	exp := sec(7,
		4,                                              // exports:
		0x06, 'm', 'e', 'm', 'o', 'r', 'y', 0x02, 0x00, //   memory
		0x07, 's', 'c', 'r', 'a', 't', 'c', 'h', 0x03, 0x00, //   scratch
		0x0b, 's', 'c', 'r', 'a', 't', 'c', 'h', 'S', 'i', 'z', 'e', 0x03, 0x01, //   scratchSize
		0x06, 'h', 'a', 'n', 'd', 'l', 'e', 0x00, 0x00) //   handle
	start := sec(8, 0x01) // start = func 1
	handleBody := []byte{
		0x00,       // no locals
		0x41, 0x00, // i32.const 0: the callable half is trivial
		0x0b, // end func
	}
	initBody := []byte{
		0x00,       // no locals
		0x03, 0x40, // loop (void)
		0x0c, 0x00, // br 0: forever, during instantiation
		0x0b, // end loop
		0x0b, // end func
	}
	codeContent := []byte{2}
	codeContent = append(codeContent, byte(len(handleBody)))
	codeContent = append(codeContent, handleBody...)
	codeContent = append(codeContent, byte(len(initBody)))
	codeContent = append(codeContent, initBody...)
	code := sec(10, codeContent...)
	out := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00} // magic + version
	out = append(out, typ...)
	out = append(out, fn...)
	out = append(out, mem...)
	out = append(out, gbl...)
	out = append(out, exp...)
	out = append(out, start...)
	out = append(out, code...)
	return out
}

// wedgeTreeWasmBytes is a wedge with no loop in it: `handle` starts a call tree in which
// every level calls the next twice, so it makes 2^depth calls at a stack depth of only
// `depth`. WAT:
//
//	(module
//	  (memory (export "memory") 3)
//	  (global (export "scratch") i32 (i32.const 16))
//	  (global (export "scratchSize") i32 (i32.const 131072))
//	  (func (export "handle") (param i32) (result i32)
//	    (call $tree (i32.const 30))
//	    i32.const 0)
//	  (func $tree (param i32)
//	    (if (i32.eqz (local.get 0)) (then return))
//	    (call $tree (i32.sub (local.get 0) (i32.const 1)))
//	    (call $tree (i32.sub (local.get 0) (i32.const 1)))))
//
// A check on loop back-edges alone never runs here, so this pins that the bound also
// covers function entry. The depth is finite on purpose: a host that misses the deadline
// runs the tree out in seconds and fails the test, where a deeper one would hang it.
func wedgeTreeWasmBytes() []byte {
	typ := sec(1, 2,
		0x60, 0x01, 0x7f, 0x01, 0x7f, // type 0: (i32) -> i32   (handle)
		0x60, 0x01, 0x7f, 0x00) //       type 1: (i32) -> ()    (tree)
	fn := sec(3, 2, 0x00, 0x01)                    // func 0: type 0, func 1: type 1
	mem := sec(5, 1, 0x00, 0x03)                   // memory: one, min 3 pages
	gbl := sec(6, 2, 0x7f, 0x00, 0x41, 0x10, 0x0b, // globals: scratch = 16,
		0x7f, 0x00, 0x41, 0x80, 0x80, 0x08, 0x0b) // scratchSize = 131072, the host default
	exp := sec(7,
		4,                                              // exports:
		0x06, 'm', 'e', 'm', 'o', 'r', 'y', 0x02, 0x00, //   memory
		0x07, 's', 'c', 'r', 'a', 't', 'c', 'h', 0x03, 0x00, //   scratch
		0x0b, 's', 'c', 'r', 'a', 't', 'c', 'h', 'S', 'i', 'z', 'e', 0x03, 0x01, //   scratchSize
		0x06, 'h', 'a', 'n', 'd', 'l', 'e', 0x00, 0x00) //   handle
	handleBody := []byte{
		0x00,       // no locals
		0x41, 0x1e, // i32.const 30: the tree depth
		0x10, 0x01, // call $tree
		0x41, 0x00, // i32.const 0
		0x0b, // end func
	}
	treeBody := []byte{
		0x00,       // no locals
		0x20, 0x00, // local.get 0
		0x45,       // i32.eqz
		0x04, 0x40, // if (void)
		0x0f, //         return
		0x0b, //       end if
		0x20, 0x00, 0x41, 0x01, 0x6b, // local.get 0, i32.const 1, i32.sub
		0x10, 0x01, // call $tree
		0x20, 0x00, 0x41, 0x01, 0x6b, // and again
		0x10, 0x01, // call $tree
		0x0b, // end func
	}
	codeContent := []byte{2}
	codeContent = append(codeContent, byte(len(handleBody)))
	codeContent = append(codeContent, handleBody...)
	codeContent = append(codeContent, byte(len(treeBody)))
	codeContent = append(codeContent, treeBody...)
	code := sec(10, codeContent...)
	out := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00} // magic + version
	out = append(out, typ...)
	out = append(out, fn...)
	out = append(out, mem...)
	out = append(out, gbl...)
	out = append(out, exp...)
	out = append(out, code...)
	return out
}

func TestModuleCallBound(t *testing.T) {
	bootRealm(t)
	key := "wedgeapp"
	if err := buildModules(t, key, []string{"wedge", "fwd"}, wedgeWasmBytes(), forwarderWasm); err != nil {
		t.Fatalf("the wedge was refused: %v", err)
	}
	// The healthy module on the same app works before and after the kill: the bound
	// takes the wedged module, not the app.
	msg := []byte("still alive")
	echo := func() {
		t.Helper()
		if r := callMod(t, key, "fwd", msg, time.Second); !bytes.Equal(r, msg) {
			t.Fatalf("healthy module echo = %q, want %q", r, msg)
		}
	}
	echo()

	// The wedge must be interrupted at the deadline, not return early and not wedge the
	// test. This is the host's own path, so dropping the deadline anywhere along it would
	// hang the process.
	wedged := func() {
		t.Helper()
		start := time.Now()
		if r := callMod(t, key, "wedge", []byte{1}, 50*time.Millisecond); r != nil {
			t.Fatalf("wedge returned %d B, want a bounded failure", len(r))
		}
		if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
			t.Fatalf("wedge returned after %s, want ~50 ms: the bound did not fire", elapsed)
		}
	}
	wedged()

	// The kill closed the instance, and the next call runs on a fresh one, as the JS
	// target's next call loads a fresh worker (§4.3): one overrun must not cost the app its
	// module until someone reinstalls it.
	if r := callMod(t, key, "wedge", []byte{0, 9}, time.Second); !bytes.Equal(r, []byte{0, 9}) {
		t.Fatalf("the killed module answered %v on its next call, want [0 9] from a fresh instance", r)
	}
	echo()
	// The bound fires on the fresh instance too.
	wedged()

	// A reinstall over a killed instance replaces it like any other.
	if err := buildModules(t, key, []string{"wedge", "fwd"}, wedgeWasmBytes(), forwarderWasm); err != nil {
		t.Fatalf("reinstall refused: %v", err)
	}
	echo()
	wedged()
}

// TestModuleCallBoundLoopFree: the bound reaches a module that never loops. A call tree
// burns unbounded time through calls alone, so the deadline has to be checked on function
// entry as well as on back-edges.
func TestModuleCallBoundLoopFree(t *testing.T) {
	bootRealm(t)
	if err := buildModules(t, "treewedge", []string{"wedge"}, wedgeTreeWasmBytes()); err != nil {
		t.Fatalf("the tree wedge was refused: %v", err)
	}
	start := time.Now()
	if r := callMod(t, "treewedge", "wedge", nil, 50*time.Millisecond); r != nil {
		t.Fatalf("call tree returned %d B, want nil", len(r))
	}
	// Unbounded, the tree takes seconds to run out, so anything near the deadline is the
	// bound firing and anything far past it is the tree finishing on its own.
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("call tree returned after %s, want ~50 ms: the bound did not fire", elapsed)
	}
}

// TestModuleBindBound: instantiation is bounded too. A module whose start section never
// returns is wedged before it is callable, so the call-time deadline has nothing to fire
// on; a bounded instance's instantiation must run under the bind deadline, or install would
// bypass it. The JS table bounds its worker load for the same reason (module-table.ts).
func TestModuleBindBound(t *testing.T) {
	bootRealm(t)
	qc.Global().SetPropertyStr("__startWedge", qc.NewArrayBuffer(wedgeStartWasmBytes()))
	start := time.Now()
	got := evalString(t, `(() => {
		try { bridge.engineInstantiate(new Uint8Array(__startWedge), moduleShims(), 50); return "accepted"; }
		catch (e) { return String(e.message); }
	})()`)
	elapsed := time.Since(start)
	// It must be the deadline that refused it, not validation: a compile-time refusal would
	// pass this test while leaving the wedge open. The error comes from instantiation, and
	// it took about as long as the bound.
	if !strings.Contains(got, "instantiate") {
		t.Fatalf("bind refused with %q, want an instantiate failure (the bound, not a validation error)", got)
	}
	if elapsed < 40*time.Millisecond || elapsed > 5*time.Second {
		t.Fatalf("the bind was refused after %s, want ~50 ms: that is not the bound firing", elapsed)
	}
	// The host is unharmed: it still loads and runs an ordinary module.
	if err := buildModules(t, "startwedge", []string{"fwd"}, forwarderWasm); err != nil {
		t.Fatalf("a healthy module was refused after the wedge: %v", err)
	}
	if r := callMod(t, "startwedge", "fwd", []byte("still alive"), time.Second); !bytes.Equal(r, []byte("still alive")) {
		t.Fatalf("healthy module echo = %q", r)
	}
}

// TestModuleBuildAllOrNone (§3.1): a set with one module the ABI refuses is refused whole,
// and leaves what the key held before.
func TestModuleBuildAllOrNone(t *testing.T) {
	bootRealm(t)
	if err := buildModules(t, "halfapp", []string{"fwd", "bad"}, forwarderWasm, abortingWasm); err == nil {
		t.Fatal("a set with a module missing its exports was built")
	} else if !strings.Contains(err.Error(), "bad:") {
		t.Fatalf("the refusal does not name the module: %v", err)
	}
	if hasModules(t, "halfapp") {
		t.Fatal("a refused set was kept")
	}
}

// wasiClockWasm is a module of the §4 shape whose handle calls WASI's clock_time_get.
var wasiClockWasm, _ = hex.DecodeString("0061736d01000000010d0260037f7e7f017f60017f017f02290116776173695f736e617073686f745f70726576696577310e636c6f636b5f74696d655f6765740000030201010504010104040607017f004180080b071d03066d656d6f72790200077363726174636803000668616e646c6500010a0f010d0041004201410010001a41000b")

// TestModuleGetsNoWasi (§4.2): the engine table answers WASI for the realm engine alone, so
// a module importing it binds on no target. Install refuses it before that
// (host/wasm-limits.ts, tests/verify-hardening.mjs); this is the bridge behind it.
func TestModuleGetsNoWasi(t *testing.T) {
	bootRealm(t)
	err := buildModules(t, "wasiapp", []string{"clock"}, wasiClockWasm)
	if err == nil {
		t.Fatal("a module importing WASI's clock was built, so it can read the clock")
	}
	if !strings.Contains(err.Error(), "wasi_snapshot_preview1") {
		t.Fatalf("the refusal does not name the WASI import: %v", err)
	}
}
