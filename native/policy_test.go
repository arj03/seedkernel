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

// A different author cannot take over a name another author's bundle already owns
// (README §12.5): the policy's same-author rule keys on the install record the first
// bundle left behind, so the second bundle's module must not land.
func TestBundleCannotHijackAnotherAuthorsName(t *testing.T) {
	boot()
	authorA, authorAPub := testAuthor(t)
	authorB, authorBPub := testAuthor(t)
	// Both authors are allowed to install — this test is about the per-name ownership
	// rule, not the closed author set.
	if err := applyPolicy(`{"authors":["` + hex.EncodeToString(authorAPub) + `","` + hex.EncodeToString(authorBPub) + `"]}`); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	// A module's name is derived from the manifest `app` (§5.1), so two bundles declaring
	// the same app aim at the same slot: `<app>:fwd`.
	name := kernelNameFor("ownedapp", "fwd")
	bundleA, _ := writeTestBundle(t, authorA, authorAPub, "ownedapp", 1)
	if status := loadBundle(bundleA); !strings.Contains(status, "installed=[fwd]") {
		t.Fatalf("author A's first install should be admitted: %s", status)
	}
	if !boundToWasm(name) {
		t.Fatalf("author A's module is not bound at `%s`", name)
	}
	// B's bundle is well-formed and its author is allowed, so it verifies and loads — the
	// refusal is the per-module admission, leaving an empty installed set rather than an
	// error. A's handler must still be the one bound at the name.
	bundleB, _ := writeTestBundle(t, authorB, authorBPub, "ownedapp", 2)
	if status := loadBundle(bundleB); !strings.Contains(status, "installed=[]") {
		t.Fatalf("author B hijacked author A's `%s` slot: %s", name, status)
	}
	if !boundToWasm(name) {
		t.Fatalf("the refused install unbound `%s`", name)
	}
}
