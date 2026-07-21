package main

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// boundToWasm reports whether `n` resolves — through the handler table, the way every call
// path resolves it — to an installed wasm handler.
func boundToWasm(n string) bool {
	return handlers[n] != nil
}

// TestScratchRegion covers the §4.1 reservation on this target: a handler that declares no
// `scratchSize` gets the 128 KB default, and the host clamps its I/O to what it reserved
// rather than to whatever its linear memory happens to allow. The forwarder reserves a
// second buffer past `scratch`, so an over-default payload would physically fit its memory —
// only the clamp refuses it. (The declared-scratchSize branch belongs to handlers like
// seedstore's RS codec, which reserves 2 MB; no in-repo fixture declares one.)
func TestScratchRegion(t *testing.T) {
	boot()
	n := kernelNameFor("scratchapp", "fwd")
	if !installWasm(n, forwarderWasm) {
		t.Fatal("installWasm(forwarder) refused")
	}
	w := handlers[n]
	if w.size != defaultScratchSize {
		t.Fatalf("a handler exporting no scratchSize should get the %d B default, got %d",
			defaultScratchSize, w.size)
	}
	// The installed module actually runs: an in-bounds payload echoes back unchanged,
	// proving the host stages input at `scratch`, calls handle, and reads the response
	// from the same region (README §4).
	msg := []byte("hello handler")
	if r := callHandler(n, msg); !bytes.Equal(r, msg) {
		t.Fatalf("echo handler returned %q, want %q", r, msg)
	}
	// A payload past the reserved region is refused by the clamp, not by memory bounds.
	if r := callHandler(n, make([]byte, w.size+1)); r != nil {
		t.Fatalf("a payload past the reserved region must be refused, got %d B", len(r))
	}
}

// TestBundleModuleRuns is the end-to-end shape: build a minimal signed bundle right here
// (no seedstore / sibling-repo dependency), load it, then reach its installed module by
// name and confirm the pure-transform executes. The host reaches installed modules only by
// name now (README §4, §12.4) — there is no kernel.call/dispatch seam to drive one through —
// so echoing a payload back is the whole "the bundle-installed wasm runs" proof.
func TestBundleModuleRuns(t *testing.T) {
	boot()
	author, authorPub := testAuthor(t)
	if err := applyPolicy(`{"authors":["` + hex.EncodeToString(authorPub) + `"]}`); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	bundlePath, kernelName := writeTestBundle(t, author, authorPub, "runapp", 1)
	if status := loadBundle(bundlePath); !strings.HasPrefix(status, "runapp v1  installed=[fwd]") {
		t.Fatalf("bundle load: %s", status)
	}
	msg := []byte("relayed")
	if r := callHandler(kernelName, msg); !bytes.Equal(r, msg) {
		t.Fatalf("bundle module echo = %q, want %q (module ran + host read its response)", r, msg)
	}
}
