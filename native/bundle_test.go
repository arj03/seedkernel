package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// TestScratchRegion covers the §4.1 scratch size on this target: a module that declares
// no `scratchSize` gets the 128 KB default, and the host clamps its I/O to that, not to
// whatever its linear memory allows. The forwarder reserves a second buffer past
// `scratch`, so an over-default payload would fit its memory and only the clamp refuses
// it. (The declared-scratchSize case covers modules like seedstore's RS codec, which
// reserves 2 MB; no in-repo fixture declares one.)
//
// The default is the shared host's number (host/wasm-limits.ts DEFAULT_SCRATCH_SIZE),
// passed by the shim at every slot build; Go has no constant of its own.
func TestScratchRegion(t *testing.T) {
	bootRealm(t)
	key := "scratchapp"
	if err := buildModuleSlot(key, []string{"fwd"}, [][]byte{forwarderWasm}, 0x20000, time.Second); err != nil {
		t.Fatalf("buildModuleSlot(forwarder) refused: %v", err)
	}
	w := moduleSlots[key]["fwd"]
	if w.size != 0x20000 {
		t.Fatalf("a module exporting no scratchSize should get the 128 KB default, got %d",
			w.size)
	}
	// The installed module runs: an in-bounds payload echoes back unchanged, showing the
	// host writes input at `scratch`, calls handle, and reads the response from the same
	// region (§4).
	msg := []byte("hello module")
	if r := callModule(key, "fwd", msg, time.Second); !bytes.Equal(r, msg) {
		t.Fatalf("echo module returned %q, want %q", r, msg)
	}
	residue, ok := w.mod.Memory().Read(w.scratch, uint32(len(msg)))
	if !ok || !bytes.Equal(residue, make([]byte, len(msg))) {
		t.Fatalf("module scratch retained the staged request after return: %x", residue)
	}
	// A payload past the reserved region is refused by the clamp, not by memory bounds.
	if r := callModule(key, "fwd", make([]byte, w.size+1), time.Second); r != nil {
		t.Fatalf("a payload past the reserved region must be refused, got %d B", len(r))
	}
}

// TestBundleModuleRuns is the end-to-end case: build a minimal signed bundle here, install
// it, then call its module by name and confirm the pure transform runs. Modules are only
// reached by name (§4, §12.4), so echoing a payload back is enough.
func TestBundleModuleRuns(t *testing.T) {
	bootRealmIn(t, t.TempDir())
	author := testAuthor(t)
	startShell(t, authorsPolicy(author.id()), nil)
	bundlePath, app := writeTestBundle(t, author, "runapp", 1)
	if status := loadBundle(bundlePath); status != loadedLine("runapp", 1, author.id(), "runapp") {
		t.Fatalf("bundle load: %s", status)
	}
	msg := []byte("relayed")
	r, err := invokeBundle(app, msg)
	if err != nil || !bytes.Equal(r, msg) {
		t.Fatalf("bundle module echo = %q, want %q (module ran + host read its response)", r, msg)
	}
}

// TestManifestClaimIsTheRouting covers claims at install (§12.10): the manifest names the
// protocol ids the app serves and the install claims them, so there is no operator step
// between installing an app and it answering, and no route to mistype. The id's format is
// checked at install, so an unroutable claim is refused there with a clear error.
func TestManifestClaimIsTheRouting(t *testing.T) {
	bootRealmIn(t, t.TempDir())
	author := testAuthor(t)
	startShell(t, authorsPolicy(author.id()), nil)
	bundlePath, _ := writeTestBundle(t, author, "claimapp", 1)
	if status := loadBundle(bundlePath); status != loadedLine("claimapp", 1, author.id(), "claimapp") {
		t.Fatalf("the load must claim what the manifest declares: %s", status)
	}
	// A space is not in the protocol charset (§12.10), so this bundle is refused whole, not
	// installed with the bad id dropped.
	badPath, _ := signBundleJSON(t, author, "badclaim", claimManifest(t, "badclaim", "bad id"), stubGuestSrc)
	if status := loadBundle(badPath); !strings.Contains(status, "malformed manifest") {
		t.Fatalf("a malformed protocol id must be refused at the load: %s", status)
	}

	// Two claim lists are two maps: the shipped transport holds "_net" under `services`, so
	// the same name under `protocols` has its own owner and does not conflict. No claim
	// name carries authority either way.
	netPath, _ := signBundleJSON(t, author, "netsquat", claimManifest(t, "netsquat", "_net"), stubGuestSrc)
	if status := loadBundle(netPath); status != loadedLine("netsquat", 1, author.id(), "_net") {
		t.Fatalf("a protocols claim spelled _net is a peer-side name of its own: %s", status)
	}
	// Within one map there is still one owner.
	dupPath, _ := signBundleJSON(t, author, "netsquat2", claimManifest(t, "netsquat2", "_net"), stubGuestSrc)
	if status := loadBundle(dupPath); !strings.Contains(status, "claim '_net' is already held") {
		t.Fatalf("a contested protocols claim must be refused: %s", status)
	}
	hostPath, _ := signBundleJSON(t, author, "hostsquat", claimManifest(t, "hostsquat", "_host"), stubGuestSrc)
	if status := loadBundle(hostPath); !strings.Contains(status, "serves _host") {
		t.Fatalf("_host must load as an ordinary claim: %s", status)
	}
	// An id starting with `_` claims like any other id; the prefix carries no special
	// meaning.
	localPath, _ := signBundleJSON(t, author, "offerapp", claimManifest(t, "offerapp", "_offer"), stubGuestSrc)
	if status := loadBundle(localPath); status != loadedLine("offerapp", 1, author.id(), "_offer") {
		t.Fatalf("an ordinary reserved id claims like any other: %s", status)
	}
}

// --contact-secret names a file (keeping the secret out of `ps` output) whose contents the
// shared CLI passes to the transport unread; the transport refuses a malformed one at
// install, the only place an operator can be told, since a gated node refuses callers
// silently (§12.6.3). Covered in WASM/tests/cli.test.mjs and transport-bundle.test.mjs.
