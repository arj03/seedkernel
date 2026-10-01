package main

// The §4.3 bound in practice: a module that never returns holds the thread it runs on,
// and only the deadline ends it (§14.1). These tests check the bound fires, that the
// closed module is evicted, and that a reinstall recovers the app.
//
// Two wedges, because a module can fail to return in two places: its `handle` (the call,
// below) and its start section, which instantiation runs; TestModuleBindBound checks the
// deadline covers that too. A third wedges `handle` without a loop, through calls alone.
//
// The wedge is a minimal hand-assembled module whose handle is an infinite loop; it
// declares the §4.1 exports like any installed module. WAT:
//
//	(module
//	  (memory (export "memory") 2)
//	  (global (export "scratch") i32 (i32.const 16))
//	  (global (export "scratchSize") i32 (i32.const 4096))
//	  (func (export "handle") (param i32) (result i32)
//	    (block (loop (br 0)))
//	    i32.const 0))

import (
	"bytes"
	"context"
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

// wedgeWasmBytes assembles the infinite-loop module above, byte by byte (no wabt in
// the toolchain).
func wedgeWasmBytes() []byte {
	// type (i32)->i32
	typ := sec(1, 1, 0x60, 0x01, 0x7f, 0x01, 0x7f)
	fn := sec(3, 1, 0x00)                          // func 0 has type 0
	mem := sec(5, 1, 0x00, 0x02)                   // memory: one, min 2 pages
	gbl := sec(6, 2, 0x7f, 0x00, 0x41, 0x10, 0x0b, // globals: scratch = 16,
		0x7f, 0x00, 0x41, 0x80, 0x20, 0x0b) //          scratchSize = 4096
	exp := sec(7,
		4,                                              // exports:
		0x06, 'm', 'e', 'm', 'o', 'r', 'y', 0x02, 0x00, //   memory
		0x07, 's', 'c', 'r', 'a', 't', 'c', 'h', 0x03, 0x00, //   scratch
		0x0b, 's', 'c', 'r', 'a', 't', 'c', 'h', 'S', 'i', 'z', 'e', 0x03, 0x01, //   scratchSize
		0x06, 'h', 'a', 'n', 'd', 'l', 'e', 0x00, 0x00) //   handle
	body := []byte{
		0x00,       // no locals
		0x02, 0x40, // block (void)
		0x03, 0x40, // loop (void)
		0x0c, 0x00, // br 0: back to the loop header, forever
		0x0b, 0x0b, // end loop, end block
		0x41, 0x00, // i32.const 0
		0x0b, // end func
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
//	  (memory (export "memory") 2)
//	  (global (export "scratch") i32 (i32.const 16))
//	  (global (export "scratchSize") i32 (i32.const 4096))
//	  (func (export "handle") (param i32) (result i32) i32.const 0)
//	  (func $init (loop (br 0)))   ;; never returns
//	  (start $init))
//
// A call-time deadline cannot reach this wedge, since the module never becomes callable,
// so it checks that the bound also covers instantiation (module.go instantiateWasm).
func wedgeStartWasmBytes() []byte {
	typ := sec(1, 2,
		0x60, 0x01, 0x7f, 0x01, 0x7f, // type 0: (i32) -> i32   (handle)
		0x60, 0x00, 0x00) //             type 1: () -> ()       (the start function)
	fn := sec(3, 2, 0x00, 0x01)                    // func 0: type 0, func 1: type 1
	mem := sec(5, 1, 0x00, 0x02)                   // memory: one, min 2 pages
	gbl := sec(6, 2, 0x7f, 0x00, 0x41, 0x10, 0x0b, // globals: scratch = 16,
		0x7f, 0x00, 0x41, 0x80, 0x20, 0x0b) //          scratchSize = 4096
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
//	  (memory (export "memory") 2)
//	  (global (export "scratch") i32 (i32.const 16))
//	  (global (export "scratchSize") i32 (i32.const 4096))
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
	mem := sec(5, 1, 0x00, 0x02)                   // memory: one, min 2 pages
	gbl := sec(6, 2, 0x7f, 0x00, 0x41, 0x10, 0x0b, // globals: scratch = 16,
		0x7f, 0x00, 0x41, 0x80, 0x20, 0x0b) //          scratchSize = 4096
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
	if err := buildModuleSlot(key, []string{"wedge", "fwd"}, [][]byte{wedgeWasmBytes(), forwarderWasm}, 0x1000, time.Second); err != nil {
		t.Fatalf("buildModuleSlot refused: %v", err)
	}
	if _, err := qc.Eval("module-deadline-bridge.js", `
		globalThis.__callBoundModule = (slot, name, deadlineMs) => {
		  const out = bridge.callModule(slot, name, new Uint8Array(0), deadlineMs);
		  return out === null ? new Uint8Array(0) : new Uint8Array(out);
		};
	`); err != nil {
		t.Fatal("bridge harness:", err)
	}
	// The healthy module on the same app works before and after the kill: the bound
	// takes the wedged module, not the app.
	msg := []byte("still alive")
	echo := func() {
		t.Helper()
		if r := callModule(key, "fwd", msg, time.Second); !bytes.Equal(r, msg) {
			t.Fatalf("healthy module echo = %q, want %q", r, msg)
		}
	}
	echo()

	// The wedge must be interrupted at the deadline, not return early and not wedge
	// the test. Drive the real JS→Go bridge so dropping its deadline argument would hang
	// the process forever.
	start := time.Now()
	if r, err := callRealm("__callBoundModule", time.Second,
		qc.NewString(key), qc.NewString("wedge"), qc.NewInt64(50)); err != nil || len(r) != 0 {
		t.Fatalf("wedged module returned %d B, err=%v; want an empty bounded failure", len(r), err)
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Fatalf("wedge returned after %s, want ~50 ms: the bound did not fire", elapsed)
	}

	// The kill closed the module, so it is evicted from the table; a closed instance left
	// in place would silently fail every later call, and the app would answer empty
	// forever. The slot still holds the healthy module.
	if moduleSlots[key]["wedge"] != nil {
		t.Fatal("the wedged module must be evicted from the table, not left as a closed instance")
	}
	if r := callModule(key, "wedge", nil, 50*time.Millisecond); r != nil {
		t.Fatalf("evicted wedge still answered %d B", len(r))
	}
	echo()

	// A reinstall creates a fresh instance and the bound fires again on it: recovery is
	// the ordinary reinstall path, not a host restart.
	if err := buildModuleSlot(key, []string{"wedge", "fwd"}, [][]byte{wedgeWasmBytes(), forwarderWasm}, 0x1000, time.Second); err != nil {
		t.Fatalf("reinstall refused: %v", err)
	}
	echo()
	start = time.Now()
	if r := callModule(key, "wedge", nil, 50*time.Millisecond); r != nil {
		t.Fatalf("reinstalled wedge returned %d B, want nil", len(r))
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Fatalf("reinstalled wedge returned after %s, want ~50 ms", elapsed)
	}
}

// TestModuleCallBoundLoopFree: the bound reaches a module that never loops. A call tree
// burns unbounded time through calls alone, so the deadline has to be checked on function
// entry as well as on back-edges.
func TestModuleCallBoundLoopFree(t *testing.T) {
	bootRealm(t)
	key := "treewedge"
	if err := buildModuleSlot(key, []string{"wedge"}, [][]byte{wedgeTreeWasmBytes()}, 0x1000, time.Second); err != nil {
		t.Fatalf("buildModuleSlot refused: %v", err)
	}
	start := time.Now()
	if r := callModule(key, "wedge", nil, 50*time.Millisecond); r != nil {
		t.Fatalf("call tree returned %d B, want nil", len(r))
	}
	// Unbounded, the tree takes seconds to run out, so anything near the deadline is the
	// bound firing and anything far past it is the tree finishing on its own.
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("call tree returned after %s, want ~50 ms: the bound did not fire", elapsed)
	}
}

// TestModuleRuntimeArmed checks the app-module runtime honors the per-call context it is
// given. Every call supplies its calling guest's remainder, and the runtime is armed so
// that context is enforced.
func TestModuleRuntimeArmed(t *testing.T) {
	probe := func(t *testing.T) (called bool, closed bool) {
		t.Helper()
		key := "probeapp"
		if err := buildModuleSlot(key, []string{"fwd"}, [][]byte{forwarderWasm}, 0x20000, time.Second); err != nil {
			t.Fatalf("buildModuleSlot refused: %v", err)
		}
		w := moduleSlots[key]["fwd"]
		done, cancel := context.WithCancel(ctx)
		cancel() // done before the call: armed runtimes refuse at entry
		defer cancel()
		_, err := w.fn.Call(done, 0)
		return err == nil, w.mod.IsClosed()
	}

	bootRealm(t)
	if called, closed := probe(t); called || !closed {
		t.Fatalf("armed runtime: call ok=%v closed=%v, want ok=false closed=true (the done ctx must end the call)", called, closed)
	}
}

// TestModuleBindBound: instantiation is bounded too. A module whose start section never
// returns is wedged before it is callable, so the call-time deadline has nothing to fire
// on; instantiation itself must run under the bound (module.go instantiateWasm), or
// install would bypass it. The JS table bounds its worker load for the same reason
// (module-table.ts).
func TestModuleBindBound(t *testing.T) {
	bootRealm(t)
	key := "startwedge"

	start := time.Now()
	err := buildModuleSlot(key, []string{"wedge"}, [][]byte{wedgeStartWasmBytes()}, 0x1000, 50*time.Millisecond)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("buildModuleSlot accepted a module whose start section never returns")
	}
	// It must be the deadline that refused it, not validation: a compile-time refusal
	// would pass this test while leaving the wedge open. The error comes from
	// instantiation, and it took about as long as the bound.
	if !strings.Contains(err.Error(), "instantiate") {
		t.Fatalf("bind refused with %v, want an instantiate failure (the bound, not a validation error)", err)
	}
	if elapsed < 40*time.Millisecond || elapsed > 5*time.Second {
		t.Fatalf("the bind was refused after %s, want ~50 ms: that is not the bound firing", elapsed)
	}
	// All-or-none (§3.1): a refused bind leaves the table exactly as it was.
	if moduleSlots[key] != nil {
		t.Fatal("a refused bind left the app on the table")
	}

	// The host is unharmed: the runtime that killed the wedge still loads and runs an
	// ordinary module.
	if err := buildModuleSlot(key, []string{"fwd"}, [][]byte{forwarderWasm}, 0x20000, time.Second); err != nil {
		t.Fatalf("buildModuleSlot refused a healthy module after the wedge: %v", err)
	}
	msg := []byte("still alive")
	if r := callModule(key, "fwd", msg, time.Second); !bytes.Equal(r, msg) {
		t.Fatalf("healthy module echo = %q, want %q", r, msg)
	}
}
