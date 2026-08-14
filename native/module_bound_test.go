package main

// module_bound_test.go — the §4.3 lever, functionally: the module table's runtime is
// armed with wazero's WithCloseOnContextDone when SEEDKERNEL_MODULE_DEADLINE_MS is set,
// and callModule runs under that deadline (main.go). A module that never returns is the
// one case the bound exists for (SECURITY §14.1) — the call is synchronous, so without
// the bound a wedged module holds the thread forever. This test proves the bound
// actually fires, that the closed module is evicted (the guest realm's markDead, per
// module), and that a reinstall recovers the app.
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
	"testing"
	"time"
)

// wedgeWasmBytes()Bytes assembles the infinite-loop module above, byte by byte (no wabt in
// the toolchain). Section sizes are computed here rather than hand-counted so the
// layout cannot drift from the WAT.
func wedgeWasmBytes() []byte {
	sec := func(id byte, content ...byte) []byte {
		out := []byte{id, byte(len(content))}
		return append(out, content...)
	}
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

func TestModuleCallBound(t *testing.T) {
	// The bound is behind a flag (off by default — SECURITY §14.1 records why); arm
	// it for this test. 50 ms is generous headroom over a real transform and tiny
	// next to the guest budget the bound mirrors.
	t.Setenv("SEEDKERNEL_MODULE_DEADLINE_MS", "50")
	bootRealm(t)
	key := appKeyFor(bytes.Repeat([]byte{0x5e}, 32), "wedgeapp")
	if err := bindAll(key, []string{"wedge", "fwd"}, [][]byte{wedgeWasmBytes(), forwarderWasm}, 0x1000); err != nil {
		t.Fatalf("bindAll refused: %v", err)
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
	if apps[key]["wedge"] != nil {
		t.Fatal("the wedged module must be evicted from the table, not left as a closed instance")
	}
	if r := callModule(key, "wedge", nil); r != nil {
		t.Fatalf("evicted wedge still answered %d B", len(r))
	}
	echo()

	// A reinstall binds a fresh instance and the bound fires again on it — recovery
	// is the ordinary reload path, not a restart of the host.
	if err := bindAll(key, []string{"wedge", "fwd"}, [][]byte{wedgeWasmBytes(), forwarderWasm}, 0x1000); err != nil {
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

// TestModuleCallBoundArmsOnlyWhenConfigured proves the bound is off by default and
// that arming it changes the CALL, not just the config. Both are asked of wazero
// behaviorally, with an already-canceled context — which an armed runtime honors at
// call entry by closing the module (call_engine.go's ctx.Done select), and an
// unarmed one ignores entirely:
//
//   - default boot (no env): the call runs normally and the module stays open — the
//     "no bound, no checks" baseline the flag decision preserves;
//   - after SEEDKERNEL_MODULE_DEADLINE_MS: the same call fails and the module is
//     closed — the lever, at its cheapest (entry check, no wedge needed).
//
// A wedge would also prove it, but a goroutine stuck in wasm forever poisons the
// test process (the runtime's close under an executing call hangs the next boot), so
// the infinite-loop module stays in the armed test, where the bound ends it.
func TestModuleCallBoundArmsOnlyWhenConfigured(t *testing.T) {
	probe := func(t *testing.T) (called bool, closed bool) {
		t.Helper()
		key := appKeyFor(bytes.Repeat([]byte{0x5c}, 32), "probeapp")
		if err := bindAll(key, []string{"fwd"}, [][]byte{forwarderWasm}, 0x20000); err != nil {
			t.Fatalf("bindAll refused: %v", err)
		}
		w := apps[key]["fwd"]
		done, cancel := context.WithCancel(ctx)
		cancel() // done before the call: armed runtimes refuse at entry
		defer cancel()
		_, err := w.fn.Call(done, 0)
		return err == nil, w.mod.IsClosed()
	}

	bootRealm(t) // no env: the flag is off by default
	if moduleCallDeadline != 0 {
		t.Fatalf("default boot resolved a deadline of %s, want 0 (off by default)", moduleCallDeadline)
	}
	if called, closed := probe(t); !called || closed {
		t.Fatalf("unarmed runtime: call ok=%v closed=%v, want ok=true closed=false (the ctx must be ignored)", called, closed)
	}

	t.Setenv("SEEDKERNEL_MODULE_DEADLINE_MS", "5000")
	bootRealm(t) // re-boot reads the env: the runtime arms
	if moduleCallDeadline <= 0 {
		t.Fatal("armed boot resolved no deadline")
	}
	if called, closed := probe(t); called || !closed {
		t.Fatalf("armed runtime: call ok=%v closed=%v, want ok=false closed=true (the done ctx must end the call)", called, closed)
	}
}
