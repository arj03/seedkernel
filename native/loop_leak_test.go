package main

import (
	"testing"
	"time"

	"seedloader/qjs"
)

// TestAwaitNoCallbackLeak guards the persistent-__settle fix: each el.await must reuse
// one registered callback, not register a fresh one per call. The callback registry is
// a Go map with no unregister, so a regression here leaks a closure — and the result
// payload it captures — on every await for the runtime's whole life. Pre-fix the count
// climbs by one per await; post-fix it is flat.
func TestAwaitNoCallbackLeak(t *testing.T) {
	rt, err := qjs.New()
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	el := newEventLoop(rt.Context())

	await := func() {
		kind, _, msg, err := el.await(`Promise.resolve(new Uint8Array(8))`, 2*time.Second)
		if err != nil || kind != 0 {
			t.Fatalf("await: kind=%d msg=%q err=%v", kind, msg, err)
		}
	}
	// Warm: first await installs the persistent __settle; setTimeout/clearTimeout/__signal
	// were installed once by newEventLoop. After this the registry is at steady state.
	for i := 0; i < 20; i++ {
		await()
	}
	base := rt.CallbackCount()

	const n = 2000
	for i := 0; i < n; i++ {
		await()
	}
	if got := rt.CallbackCount(); got != base {
		t.Fatalf("callback registry grew %d → %d over %d awaits — per-await callback leak?", base, got, n)
	}
	t.Logf("callback registry steady at %d across %d awaits", base, n)
}
