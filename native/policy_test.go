package main

import (
	"encoding/hex"
	"strings"
	"testing"
)

// With the bundle author allow-listed, the closed policy still loads the bundle.
func TestPolicyAllowsBundleAuthor(t *testing.T) {
	boot()
	author, authorPub := testAuthor(t)
	if err := applyPolicy(`{"authors":["` + hex.EncodeToString(authorPub) + `"]}`); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	dir, _ := writeTestBundle(t, author, authorPub, "testapp", 1)
	if status := loadBundle(dir); !strings.HasPrefix(status, "testapp v1  installed=[fwd]") {
		t.Fatalf("policy-allowed bundle: %s", status)
	}
}

// A policy that omits the bundle author rejects it at the manifest-governance gate.
func TestPolicyRejectsForeignAuthor(t *testing.T) {
	boot()
	if err := applyPolicy(`{"authors":["` + strings.Repeat("ab", 32) + `"]}`); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	author, authorPub := testAuthor(t)
	dir, _ := writeTestBundle(t, author, authorPub, "testapp", 1)
	if status := loadBundle(dir); !strings.Contains(status, "manifest author is not in the policy's allowed set") {
		t.Fatalf("expected foreign-author rejection, got: %s", status)
	}
}

// parsePolicy fails loudly on malformed config rather than silently widening trust.
func TestPolicyMalformed(t *testing.T) {
	boot()
	for _, bad := range []string{`{}`, `{"authors":[]}`, `[]`, `not json`, `{"authors":[123]}`, `{"authors":"x"}`} {
		if err := applyPolicy(bad); err == nil {
			t.Fatalf("applyPolicy(%q) = nil, want an error", bad)
		}
	}
	// A rejected policy must not leave the realm wider than it started: the boot default
	// is deny-all, so nothing installs (README §14). Before, a realm whose policy failed
	// to parse kept a permissive default and loaded any signed bundle.
	author, authorPub := testAuthor(t)
	dir, _ := writeTestBundle(t, author, authorPub, "testapp", 1)
	if status := loadBundle(dir); !strings.Contains(status, "not in the policy") {
		t.Fatalf("after rejected policies the realm must stay deny-all: %s", status)
	}
}

// The whole point of the omitted-policy default: a node that was never given a policy
// refuses every install rather than trusting any signed author (README §14). The JS
// shell has always done this (main.ts) — the native loader used to do the opposite.
func TestNoPolicyDeniesInstalls(t *testing.T) {
	boot()
	author, authorPub := testAuthor(t)

	// A signed bundle from an otherwise-valid author does not load.
	dir, _ := writeTestBundle(t, author, authorPub, "testapp", 1)
	if status := loadBundle(dir); !strings.Contains(status, "not in the policy") {
		t.Fatalf("no --policy must deny a bundle install, got: %s", status)
	}

	// Nor does a signed §7.2 wire install.
	target := name("nopolicy.mod")
	dispatch(buildInstall(author, authorPub, target, forwarderWasm, 1))
	if boundToWasm(target) {
		t.Fatal("no --policy must deny a wire install, but the module bound")
	}
}

// A first install must not overlay a SetHandler-seeded bootstrap slot (README §7.4) —
// the reference policy's rule, enforced via the kernel's handler table. The native
// approve() had no such check, so a signed install could rebind a seeded slot.
func TestFirstInstallCannotOverlaySeededSlot(t *testing.T) {
	boot()
	author, authorPub := testAuthor(t)
	if err := applyPolicy(`{"authors":["` + hex.EncodeToString(authorPub) + `"]}`); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	// `install` is seeded by boot() and has no install record, so it is a bootstrap slot.
	// It is seeded as a native handler, so the slot still holding a non-wasm impl
	// afterwards is exactly "the install did not overlay it".
	seeded := name("install")
	dispatch(buildInstall(author, authorPub, seeded, forwarderWasm, 1))
	if boundToWasm(seeded) {
		t.Fatal("a first install overlaid the SetHandler-seeded `install` slot")
	}
	if id := findHandlerID(seeded); id < 0 || entries[id].nat == nil {
		t.Fatal("the seeded `install` handler is gone from its slot")
	}
}
