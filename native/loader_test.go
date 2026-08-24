package main

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// TestScratchRegion covers the §4.1 reservation on this target: a module that declares no
// `scratchSize` gets the 128 KB default, and the host clamps its I/O to what it reserved
// rather than to whatever its linear memory happens to allow. The forwarder reserves a
// second buffer past `scratch`, so an over-default payload would physically fit its memory —
// only the clamp refuses it. (The declared-scratchSize branch belongs to modules like
// seedstore's RS codec, which reserves 2 MB; no in-repo fixture declares one.)
//
// The default itself is the shared host's number (core/wasm-limits.ts
// DEFAULT_SCRATCH_SIZE), passed by the shim at every slot build; the test mirrors it,
// since Go no longer owns a copy.
func TestScratchRegion(t *testing.T) {
	bootRealm(t)
	key := appKeyFor(bytes.Repeat([]byte{0xab}, 32), "scratchapp")
	if err := buildModuleSlot(key, []string{"fwd"}, [][]byte{forwarderWasm}, 0x20000); err != nil {
		t.Fatalf("buildModuleSlot(forwarder) refused: %v", err)
	}
	w := moduleSlots[key]["fwd"]
	if w.size != 0x20000 {
		t.Fatalf("a module exporting no scratchSize should get the 128 KB default, got %d",
			w.size)
	}
	// The installed module actually runs: an in-bounds payload echoes back unchanged,
	// proving the host stages input at `scratch`, calls handle, and reads the response
	// from the same region (README §4).
	msg := []byte("hello module")
	if r := callModule(key, "fwd", msg); !bytes.Equal(r, msg) {
		t.Fatalf("echo module returned %q, want %q", r, msg)
	}
	residue, ok := w.mod.Memory().Read(w.scratch, uint32(len(msg)))
	if !ok || !bytes.Equal(residue, make([]byte, len(msg))) {
		t.Fatalf("module scratch retained the staged request after return: %x", residue)
	}
	// A payload past the reserved region is refused by the clamp, not by memory bounds.
	if r := callModule(key, "fwd", make([]byte, w.size+1)); r != nil {
		t.Fatalf("a payload past the reserved region must be refused, got %d B", len(r))
	}
}

// TestBundleModuleRuns is the end-to-end shape: build a minimal signed bundle here, load
// it, then reach its installed module by name and confirm the pure-transform executes.
// Modules are reached only by name (README §4, §12.4) — there is no dispatch seam to drive
// one through — so echoing a payload back is the whole proof.
func TestBundleModuleRuns(t *testing.T) {
	bootShell(t, t.TempDir(), "", nil)
	author := testAuthor(t)
	if err := applyPolicy(`{"authors":["` + hex.EncodeToString(author.id()) + `"]}`); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	bundlePath, appKey := writeTestBundle(t, author, "runapp", 1)
	if status := loadBundle(bundlePath); !strings.HasPrefix(status, "runapp v1  key "+appKey) {
		t.Fatalf("bundle load: %s", status)
	}
	msg := []byte("relayed")
	r, err := invokeBundle(appKey, msg)
	if err != nil || !bytes.Equal(r, msg) {
		t.Fatalf("bundle module echo = %q, want %q (module ran + host read its response)", r, msg)
	}
}

// TestManifestClaimIsTheRouting covers the load-time claim (§12.10): the manifest names
// the protocol ids the app serves and the load that admits the code claims them, so there
// is no operator step between installing an app and it answering — and no app key to
// mistype into a node that boots clean and answers an empty body forever. The id's format
// is checked at the load, so an unroutable claim is refused where it can be named.
func TestManifestClaimIsTheRouting(t *testing.T) {
	bootShell(t, t.TempDir(), "", nil)
	author := testAuthor(t)
	if err := applyPolicy(`{"authors":["` + hex.EncodeToString(author.id()) + `"]}`); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	bundlePath, appKey := writeTestBundle(t, author, "claimapp", 1)
	if status := loadBundle(bundlePath); status != loadedLine("claimapp", 1, appKey, "claimapp") {
		t.Fatalf("the load must claim what the manifest declares: %s", status)
	}
	// A space is not in the protocol charset (§12.10), so this bundle is refused whole —
	// an id nothing could route is a manifest its author got wrong, not an entry to drop.
	badPath, _ := signBundleJSON(t, author, "badclaim", claimManifest(t, "badclaim", "bad id"), stubGuestSrc)
	if status := loadBundle(badPath); !strings.Contains(status, "malformed manifest") {
		t.Fatalf("a malformed protocol id must be refused at the load: %s", status)
	}

	// Legacy transport spellings are ordinary local claims; no claim name carries authority.
	netPath, _ := signBundleJSON(t, author, "netsquat", claimManifest(t, "netsquat", "_net"), stubGuestSrc)
	if status := loadBundle(netPath); !strings.Contains(status, "claim '_net' is already held") {
		t.Fatalf("_net must reach ordinary claim-conflict handling: %s", status)
	}
	hostPath, _ := signBundleJSON(t, author, "hostsquat", claimManifest(t, "hostsquat", "_host"), stubGuestSrc)
	if status := loadBundle(hostPath); !strings.Contains(status, "serves _host") {
		t.Fatalf("_host must load as an ordinary claim: %s", status)
	}
	// An ordinary `_`-led id is a LOCAL service name no peer can reach, so it claims like
	// any other id: the reservation is about routing, not about authority.
	localPath, appKey2 := signBundleJSON(t, author, "offerapp", claimManifest(t, "offerapp", "_offer"), stubGuestSrc)
	if status := loadBundle(localPath); status != loadedLine("offerapp", 1, appKey2, "_offer") {
		t.Fatalf("an ordinary reserved id claims like any other: %s", status)
	}
}

// --contact-secret validation moved with the flag itself: it names a FILE of 64 hex
// characters now (matching the JS shell, and keeping the secret out of `ps` output), and
// `parseHex32` in the shared CLI refuses a corrupt or wrong-length one loudly — which is
// the only place an operator can be told, since a gated node refuses callers in silence
// (§12.6.2). Covered in WASM/tests/cli.test.mjs.
