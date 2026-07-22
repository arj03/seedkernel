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

// Two authors shipping an app under the SAME name coexist (README §5.1): a kernel name
// is derived from its author's key, so B never aims at A's slot in the first place. There
// is no ownership register and no same-author clause — the collision the old register
// existed to refuse is unrepresentable, and both modules land.
func TestSameAppNameFromTwoAuthorsCoexists(t *testing.T) {
	boot()
	authorA, authorAPub := testAuthor(t)
	authorB, authorBPub := testAuthor(t)
	// Both authors are allowed to install: this test is about the namespace, not the
	// closed author set. A permissive policy is exactly the interesting case — even with
	// nothing refusing anyone, neither author can reach the other's names.
	if err := applyPolicy(`{"authors":["` + hex.EncodeToString(authorAPub) + `","` + hex.EncodeToString(authorBPub) + `"]}`); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	nameA := kernelNameFor(authorAPub, "ownedapp", "fwd")
	nameB := kernelNameFor(authorBPub, "ownedapp", "fwd")
	if nameA == nameB {
		t.Fatal("the same app name under two authors must derive distinct kernel names")
	}
	bundleA, _ := writeTestBundle(t, authorA, authorAPub, "ownedapp", 1)
	if status := loadBundle(bundleA); !strings.Contains(status, "installed=[fwd]") {
		t.Fatalf("author A's install should be admitted: %s", status)
	}
	if !boundToWasm(nameA) {
		t.Fatalf("author A's module is not bound at `%s`", nameA)
	}
	// B's bundle declares the same app name and installs too — beside A, never over it.
	bundleB, _ := writeTestBundle(t, authorB, authorBPub, "ownedapp", 2)
	if status := loadBundle(bundleB); !strings.Contains(status, "installed=[fwd]") {
		t.Fatalf("author B's install should be admitted under its own name: %s", status)
	}
	if !boundToWasm(nameB) {
		t.Fatalf("author B's module is not bound at `%s`", nameB)
	}
	// The decisive assertion: A's slot is untouched by B's install.
	if !boundToWasm(nameA) {
		t.Fatalf("author B's install displaced author A at `%s`", nameA)
	}
}
