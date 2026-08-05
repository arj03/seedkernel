package main

import (
	"encoding/hex"
	"strings"
	"testing"
)

// With the bundle author allow-listed, the closed policy still loads the bundle.
func TestPolicyAllowsBundleAuthor(t *testing.T) {
	bootShell(t, t.TempDir(), "", nil)
	author, authorPub := testAuthor(t)
	if err := applyPolicy(`{"authors":["` + hex.EncodeToString(authorPub) + `"]}`); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	bundlePath, _ := writeTestBundle(t, author, authorPub, "testapp", 1)
	if status := loadBundle(bundlePath); !strings.HasPrefix(status, "testapp v1  handles=[testapp]") {
		t.Fatalf("policy-allowed bundle: %s", status)
	}
}

// A policy that omits the bundle author rejects it at the manifest-governance gate.
func TestPolicyRejectsForeignAuthor(t *testing.T) {
	bootShell(t, t.TempDir(), "", nil)
	if err := applyPolicy(`{"authors":["` + strings.Repeat("ab", 32) + `"]}`); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	author, authorPub := testAuthor(t)
	bundlePath, _ := writeTestBundle(t, author, authorPub, "testapp", 1)
	if status := loadBundle(bundlePath); !strings.Contains(status, "rejected by admission") {
		t.Fatalf("expected foreign-author rejection, got: %s", status)
	}
}

// A slot occupant is a SECOND admission class (§12.5): the transport sees all plaintext
// and holds the session keys, so "I trust this author's apps" must not answer "may this
// author be my transport". The author allowlist refuses a `role` claim; only a `roles`
// entry admits one. Driven through the native loader because the policy file is an
// operator-facing surface on this target — `--policy` is parsed by the shared JS, and
// this is what proves the loader reaches that decision and not a permissive default.
func TestPolicySlotNeedsItsOwnGrant(t *testing.T) {
	bootShell(t, t.TempDir(), "", nil)
	author, authorPub := testAuthor(t)
	authorHex := hex.EncodeToString(authorPub)

	if err := applyPolicy(`{"authors":["` + authorHex + `"]}`); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	slotBundle := writeSlotBundle(t, author, authorPub, "linkapp", 1, "transport")
	if status := loadBundle(slotBundle); !strings.Contains(status, "rejected by admission") {
		t.Fatalf("an app-allowlisted author must not thereby occupy a slot: %s", status)
	}

	// The deliberate second entry admits it — and the app grant still works alongside.
	if err := applyPolicy(`{"authors":["` + authorHex + `"],"roles":{"transport":["` + authorHex + `"]}}`); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	if status := loadBundle(slotBundle); strings.Contains(status, "rejected") {
		t.Fatalf("a roles entry must admit the slot it names: %s", status)
	}
	appBundle, _ := writeTestBundle(t, author, authorPub, "ordinary", 1)
	if status := loadBundle(appBundle); !strings.Contains(status, "ordinary") {
		t.Fatalf("adding a slot entry must not disturb app admission: %s", status)
	}

	// A typo'd slot name fails the boot rather than parsing into a list that admits
	// nothing and looks like it should.
	if err := applyPolicy(`{"authors":["` + authorHex + `"],"roles":{"transprot":["` + authorHex + `"]}}`); err == nil {
		t.Fatal("an unknown slot name in the policy must fail loudly")
	}
}

// parsePolicy fails loudly on malformed config rather than silently widening trust.
func TestPolicyMalformed(t *testing.T) {
	bootShell(t, t.TempDir(), "", nil)
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
	if status := loadBundle(bundlePath); !strings.Contains(status, "rejected by admission") {
		t.Fatalf("after rejected policies the realm must stay deny-all: %s", status)
	}
}

// The whole point of the omitted-policy default: a node that was never given a policy
// refuses every install rather than trusting any signed author (README §14). The JS
// shell has always done this (main.ts) — the native loader used to do the opposite.
func TestNoPolicyDeniesInstalls(t *testing.T) {
	bootShell(t, t.TempDir(), "", nil)
	author, authorPub := testAuthor(t)

	// A signed bundle from an otherwise-valid author does not load. Bundles are the only
	// way code arrives (§12.4), so the manifest-author gate is the whole install surface.
	bundlePath, _ := writeTestBundle(t, author, authorPub, "testapp", 1)
	if status := loadBundle(bundlePath); !strings.Contains(status, "rejected by admission") {
		t.Fatalf("no --policy must deny a bundle install, got: %s", status)
	}
}

// Two authors shipping an app under the SAME name coexist (README §5.1): a kernel name
// is derived from its author's key, so B never aims at A's slot in the first place. There
// is no ownership register and no same-author clause — the collision the old register
// existed to refuse is unrepresentable, and both modules land.
func TestSameAppNameFromTwoAuthorsCoexists(t *testing.T) {
	bootShell(t, t.TempDir(), "", nil)
	authorA, authorAPub := testAuthor(t)
	authorB, authorBPub := testAuthor(t)
	// Both authors are allowed to install: this test is about the namespace, not the
	// closed author set. A permissive policy is exactly the interesting case — even with
	// nothing refusing anyone, neither author can reach the other's names.
	if err := applyPolicy(`{"authors":["` + hex.EncodeToString(authorAPub) + `","` + hex.EncodeToString(authorBPub) + `"]}`); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	keyA := appKeyFor(authorAPub, "ownedapp")
	keyB := appKeyFor(authorBPub, "ownedapp")
	if keyA == keyB {
		t.Fatal("the same app name under two authors must derive distinct app keys")
	}
	bundleA, _ := writeTestBundle(t, authorA, authorAPub, "ownedapp", 1)
	if status := loadBundle(bundleA); !strings.Contains(status, "ownedapp") {
		t.Fatalf("author A's install should be admitted: %s", status)
	}
	if !boundToWasm(keyA, "fwd") {
		t.Fatalf("author A's module is not bound under `%s`", keyA)
	}
	// B's bundle declares the same app name and installs too — beside A, never over it.
	bundleB, _ := writeTestBundle(t, authorB, authorBPub, "ownedapp", 2)
	if status := loadBundle(bundleB); !strings.Contains(status, "ownedapp") {
		t.Fatalf("author B's install should be admitted under its own name: %s", status)
	}
	if !boundToWasm(keyB, "fwd") {
		t.Fatalf("author B's module is not bound under `%s`", keyB)
	}
	// The decisive assertion: A's slot is untouched by B's install.
	if !boundToWasm(keyA, "fwd") {
		t.Fatalf("author B's install displaced author A under `%s`", keyA)
	}
}
