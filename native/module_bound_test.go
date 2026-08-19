package main

// module_bound_test.go — the §4.3 lever, functionally: a module that never returns holds
// the thread it runs on, and only the deadline ends it (SECURITY §14.1). These tests prove
// the bound fires, that the closed module is evicted, and that a reinstall recovers the app.
//
// Two wedges, because there are two places a module can refuse to return: its `handle`
// (the call, below) and its START section, which instantiation runs — TestModuleBindBound
// is what says the deadline covers that too.
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

// sec size-prefixes one wasm section. Sizes are computed rather than hand-counted so a
// layout cannot drift from the WAT it is transcribed from.
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
		0x0c, 0x00, // br 0 — back to the loop header, forever
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

// wedgeStartWasmBytes is the same module with the loop moved into a START section: its
// `handle` returns immediately, and it is INSTANTIATION that never finishes. WAT:
//
//	(module
//	  (memory (export "memory") 2)
//	  (global (export "scratch") i32 (i32.const 16))
//	  (global (export "scratchSize") i32 (i32.const 4096))
//	  (func (export "handle") (param i32) (result i32) i32.const 0)
//	  (func $init (loop (br 0)))   ;; never returns
//	  (start $init))
//
// This is the one wedge a call-time deadline cannot reach — the module never becomes
// callable — so it is what says the bound also covers the bind (main.go
// instantiateWasm).
func wedgeStartWasmBytes() []byte {
	typ := sec(1, 2,
		0x60, 0x01, 0x7f, 0x01, 0x7f, // type 0: (i32) -> i32   — handle
		0x60, 0x00, 0x00) //             type 1: () -> ()       — the start function
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
		0x41, 0x00, // i32.const 0 — the callable half is trivial
		0x0b, // end func
	}
	initBody := []byte{
		0x00,       // no locals
		0x03, 0x40, // loop (void)
		0x0c, 0x00, // br 0 — forever, during instantiation
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

func TestModuleCallBound(t *testing.T) {
	// The bound is armed by default at the guest budget; tighten it to 50 ms here so
	// the wedge is caught in test time rather than in five seconds. Still generous
	// headroom over a real transform.
	t.Setenv("SEEDKERNEL_MODULE_DEADLINE_MS", "50")
	bootRealm(t)
	key := appKeyFor(bytes.Repeat([]byte{0x5e}, 32), "wedgeapp")
	if err := buildModuleSlot(key, []string{"wedge", "fwd"}, [][]byte{wedgeWasmBytes(), forwarderWasm}, 0x1000); err != nil {
		t.Fatalf("buildModuleSlot refused: %v", err)
	}
	// The healthy module on the same app works before and after the kill: the bound
	// takes the wedged module, not the app.
	msg := []byte("still alive")
	echo := func() {
		t.Helper()
		if r := callModule(key, "fwd", msg); !bytes.Equal(r, msg) {
			t.Fatalf("healthy module echo = %q, want %q", r, msg)
		}
	}
	echo()

	// The wedge must be interrupted at the deadline, not return early and not wedge
	// the test: without the bound this call would hang the process forever.
	start := time.Now()
	if r := callModule(key, "wedge", nil); r != nil {
		t.Fatalf("wedged module returned %d B, want nil (the bound must interrupt it)", len(r))
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Fatalf("wedge returned after %s, want ~50 ms: the bound did not fire", elapsed)
	}

	// The kill CLOSED the module, so it is evicted from the table — a closed instance
	// left in place would fail every later call silently, which is the app answering
	// empty on a protocol forever. The app key still holds the healthy module.
	if moduleSlots[key]["wedge"] != nil {
		t.Fatal("the wedged module must be evicted from the table, not left as a closed instance")
	}
	if r := callModule(key, "wedge", nil); r != nil {
		t.Fatalf("evicted wedge still answered %d B", len(r))
	}
	echo()

	// A reinstall binds a fresh instance and the bound fires again on it — recovery
	// is the ordinary reload path, not a restart of the host.
	if err := buildModuleSlot(key, []string{"wedge", "fwd"}, [][]byte{wedgeWasmBytes(), forwarderWasm}, 0x1000); err != nil {
		t.Fatalf("reinstall refused: %v", err)
	}
	echo()
	start = time.Now()
	if r := callModule(key, "wedge", nil); r != nil {
		t.Fatalf("reinstalled wedge returned %d B, want nil", len(r))
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Fatalf("reinstalled wedge returned after %s, want ~50 ms", elapsed)
	}
}

// TestModuleCallBoundArmedByDefault proves the bound is ON with no configuration, and that
// SEEDKERNEL_MODULE_DEADLINE_MS=0 is a real off switch. Both are asked of wazero
// behaviorally, with an already-canceled context — which an armed runtime honors at call
// entry by closing the module, and an unarmed one ignores entirely:
//
//   - default boot: the call fails and the module is closed;
//   - deadline 0: the same call runs normally and the module stays open — the escape
//     hatch, and the "no bound, no checks" baseline, since an unbound runtime is left
//     unarmed rather than paying for a disabled lever.
//
// A wedge would prove it too, but a goroutine stuck in wasm forever poisons the test
// process (closing the runtime under an executing call hangs the next boot), so the
// infinite-loop module stays in the armed test, where the bound ends it.
func TestModuleCallBoundArmedByDefault(t *testing.T) {
	probe := func(t *testing.T) (called bool, closed bool) {
		t.Helper()
		key := appKeyFor(bytes.Repeat([]byte{0x5c}, 32), "probeapp")
		if err := buildModuleSlot(key, []string{"fwd"}, [][]byte{forwarderWasm}, 0x20000); err != nil {
			t.Fatalf("buildModuleSlot refused: %v", err)
		}
		w := moduleSlots[key]["fwd"]
		done, cancel := context.WithCancel(ctx)
		cancel() // done before the call: armed runtimes refuse at entry
		defer cancel()
		_, err := w.fn.Call(done, 0)
		return err == nil, w.mod.IsClosed()
	}

	bootRealm(t) // no env: the bound is armed by default
	if moduleCallDeadline != defaultModuleCallDeadline || moduleCallDeadline <= 0 {
		t.Fatalf("default boot resolved a deadline of %s, want %s (armed by default)", moduleCallDeadline, defaultModuleCallDeadline)
	}
	if called, closed := probe(t); called || !closed {
		t.Fatalf("armed runtime: call ok=%v closed=%v, want ok=false closed=true (the done ctx must end the call)", called, closed)
	}

	t.Setenv("SEEDKERNEL_MODULE_DEADLINE_MS", "0")
	bootRealm(t) // re-boot reads the env: the runtime unarms
	if moduleCallDeadline != 0 {
		t.Fatalf("deadline 0 resolved %s, want 0 (the off switch)", moduleCallDeadline)
	}
	if called, closed := probe(t); !called || closed {
		t.Fatalf("unarmed runtime: call ok=%v closed=%v, want ok=true closed=false (the ctx must be ignored)", called, closed)
	}
}

// TestModuleBindBound: the bind is bounded too. A module whose START section never
// returns is wedged before it is ever callable, so the call-time deadline has nothing
// to fire on — instantiation itself must run under the bound (main.go
// instantiateWasm), or an install is the hole the whole lever was closing. The JS
// table bounds its worker load for the same reason (module-table.ts).
func TestModuleBindBound(t *testing.T) {
	t.Setenv("SEEDKERNEL_MODULE_DEADLINE_MS", "50")
	bootRealm(t)
	key := appKeyFor(bytes.Repeat([]byte{0x5d}, 32), "startwedge")

	start := time.Now()
	err := buildModuleSlot(key, []string{"wedge"}, [][]byte{wedgeStartWasmBytes()}, 0x1000)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("buildModuleSlot accepted a module whose start section never returns")
	}
	// It must be the DEADLINE that refused it, not validation: a compile-time refusal
	// would pass this test while leaving the wedge wide open. The error comes from
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

	// The host is unharmed — the runtime that killed the wedge still binds and runs an
	// ordinary module.
	if err := buildModuleSlot(key, []string{"fwd"}, [][]byte{forwarderWasm}, 0x20000); err != nil {
		t.Fatalf("buildModuleSlot refused a healthy module after the wedge: %v", err)
	}
	msg := []byte("still alive")
	if r := callModule(key, "fwd", msg); !bytes.Equal(r, msg) {
		t.Fatalf("healthy module echo = %q, want %q", r, msg)
	}
}
