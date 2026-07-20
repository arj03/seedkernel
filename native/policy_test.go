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
	bundlePath, _ := writeTestBundle(t, author, authorPub, "testapp", 1)
	if status := loadBundle(bundlePath); !strings.HasPrefix(status, "testapp v1  installed=[fwd]") {
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
	bundlePath, _ := writeTestBundle(t, author, authorPub, "testapp", 1)
	if status := loadBundle(bundlePath); !strings.Contains(status, "manifest author is not in the policy's allowed set") {
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
	bundlePath, _ := writeTestBundle(t, author, authorPub, "testapp", 1)
	if status := loadBundle(bundlePath); !strings.Contains(status, "not in the policy") {
		t.Fatalf("after rejected policies the realm must stay deny-all: %s", status)
	}
}

// The whole point of the omitted-policy default: a node that was never given a policy
// refuses every install rather than trusting any signed author (README §14). The JS
// shell has always done this (main.ts) — the native loader used to do the opposite.
func TestNoPolicyDeniesInstalls(t *testing.T) {
	boot()
	author, authorPub := testAuthor(t)

	// A signed bundle from an otherwise-valid author does not load. Bundles are the only
	// way code arrives (§12.4), so the manifest-author gate is the whole install surface.
	bundlePath, _ := writeTestBundle(t, author, authorPub, "testapp", 1)
	if status := loadBundle(bundlePath); !strings.Contains(status, "not in the policy") {
		t.Fatalf("no --policy must deny a bundle install, got: %s", status)
	}
}

// A bundle module must not overlay a SetHandler-seeded bootstrap slot (README §12.5) —
// the loader's structural admission rule, enforced via the kernel's handler table on the
// shared admission path. A native host handler seeded straight into the table has no install
// record, so aiming a bundle module at its slot must leave the native handler in place.
func TestBundleCannotOverlaySeededSlot(t *testing.T) {
	boot()
	author, authorPub := testAuthor(t)
	if err := applyPolicy(`{"authors":["` + hex.EncodeToString(authorPub) + `"]}`); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	// Seed a native host handler the way boot()-time services are seeded — bound into the
	// handler table via SetHandler, with no install record for the policy to key on.
	seeded := name("host.seeded")
	registerNativeAt(seeded, func(p []byte) []byte { return p })
	bundlePath, _ := writeTestBundle(t, author, authorPub, "overlayapp", 1, seeded)
	if status := loadBundle(bundlePath); strings.Contains(status, "installed=[fwd]") {
		t.Fatalf("a bundle module overlaid the seeded `host.seeded` slot: %s", status)
	}
	if boundToWasm(seeded) {
		t.Fatal("the seeded `host.seeded` slot was overlaid by a bundle module")
	}
	if e := handlers[seeded]; e == nil || e.nat == nil {
		t.Fatal("the seeded `host.seeded` handler is gone from its slot")
	}
}
