package main

import (
	"encoding/hex"
	"strings"
	"testing"
)

// With the bundle author allow-listed, the closed policy still loads the bundle.
func TestPolicyAllowsBundleAuthor(t *testing.T) {
	bootShell(t, t.TempDir(), "", nil)
	author := testAuthor(t)
	if err := applyPolicy(`{"authors":["` + hex.EncodeToString(author.id()) + `"]}`); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	bundlePath, appKey := writeTestBundle(t, author, "testapp", 1)
	if status := loadBundle(bundlePath); !strings.HasPrefix(status, "testapp v1  key "+appKey) {
		t.Fatalf("policy-allowed bundle: %s", status)
	}
}

// A policy that omits the bundle author rejects it at the manifest-governance gate.
func TestPolicyRejectsForeignAuthor(t *testing.T) {
	bootShell(t, t.TempDir(), "", nil)
	if err := applyPolicy(`{"authors":["` + strings.Repeat("ab", 32) + `"]}`); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	author := testAuthor(t)
	bundlePath, _ := writeTestBundle(t, author, "testapp", 1)
	if status := loadBundle(bundlePath); !strings.Contains(status, "rejected by admission") {
		t.Fatalf("expected foreign-author rejection, got: %s", status)
	}
}

// The `link/*` names carry a PRIVILEGE an operator grants separately (§12.5): the transport
// sees all plaintext and holds the session keys, so "I trust this author's apps" must not
// answer "may this author be my transport". There is no self-description in the manifest
// — the bundle format has no role field — so `guest.requires` alone decides which
// privileges are in play, and the derivation only ever runs the strict way: naming
// any `link/*` name puts `link` in the set, never takes it out.
//
// Driven through the native loader because the policy file is an operator-facing surface
// on this target — `--policy` is parsed by the shared JS, and this is what proves the
// loader reaches that decision and not a permissive default.
func TestPolicyLinkIsASeparatelyGrantedPrivilege(t *testing.T) {
	bootShell(t, t.TempDir(), "", nil)
	author := testAuthor(t)
	authorHex := hex.EncodeToString(author.id())

	// On the plain author list and nothing else. The same load that lands this author's
	// apps refuses their transport, and the refusal is admission — not a parse error, not
	// a missing entrypoint: the requires named a privilege nobody was granted.
	if err := applyPolicy(`{"authors":["` + authorHex + `"]}`); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	linkBundle, _ := writeBundle(t, author, "linkapp", 1, "", []string{"link/open"})
	if status := loadBundle(linkBundle); !strings.Contains(status, "rejected by admission") {
		t.Fatalf("an app-allowlisted author must not thereby become the transport: %s", status)
	}

	// A privilege is ONE thing, so there is no partial claim to refuse and nothing that
	// could fall through to the unprivileged base: a single `link/*` name is the whole
	// claim, which is what the one-name bundle above already proves.

	// Granting the privilege gets the same blob PAST admission, where it then fails on its
	// own merits — this fixture's stub guest is not a transport. A different failure, from
	// a policy edit and nothing else.
	if err := applyPolicy(`{"authors":["` + authorHex + `"],"grants":{"link":["` + authorHex + `"]}}`); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	if status := loadBundle(linkBundle); strings.Contains(status, "rejected by admission") {
		t.Fatalf("a grants.link entry must admit its author to the transport: %s", status)
	}
	appBundle, _ := writeTestBundle(t, author, "ordinary", 1)
	if status := loadBundle(appBundle); !strings.Contains(status, "ordinary") {
		t.Fatalf("adding a grant must not disturb app admission: %s", status)
	}

	// The superseded policy vocabularies are gone and say so at the boot: a file carrying
	// either fails loudly rather than parsing into an app-only policy that silently leaves
	// the node without a network. A grant naming no privilege this host has fails the same
	// way, which is what naming grants from the catalog buys.
	for _, bad := range []string{
		`{"authors":["` + authorHex + `"],"roles":{"transport":["` + authorHex + `"]}}`,
		`{"authors":["` + authorHex + `"],"transportAuthors":["` + authorHex + `"]}`,
		`{"authors":["` + authorHex + `"],"grants":{"mount":["` + authorHex + `"]}}`,
		`{"authors":["` + authorHex + `"],"grants":{"links":["` + authorHex + `"]}}`,
	} {
		if err := applyPolicy(bad); err == nil {
			t.Fatalf("applyPolicy(%s) must fail loudly", bad)
		}
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
	author := testAuthor(t)
	bundlePath, _ := writeTestBundle(t, author, "testapp", 1)
	if status := loadBundle(bundlePath); !strings.Contains(status, "rejected by admission") {
		t.Fatalf("after rejected policies the realm must stay deny-all: %s", status)
	}
}

// The whole point of the omitted-policy default: a node that was never given a policy
// refuses every install rather than trusting any signed author (README §14). The JS
// shell has always done this (main.ts) — the native loader used to do the opposite.
func TestNoPolicyDeniesInstalls(t *testing.T) {
	bootShell(t, t.TempDir(), "", nil)
	author := testAuthor(t)

	// A signed bundle from an otherwise-valid author does not load. Bundles are the only
	// way code arrives (§12.4), so the manifest-author gate is the whole install surface.
	bundlePath, _ := writeTestBundle(t, author, "testapp", 1)
	if status := loadBundle(bundlePath); !strings.Contains(status, "rejected by admission") {
		t.Fatalf("no --policy must deny a bundle install, got: %s", status)
	}
}

// Two authors shipping an app under the SAME name coexist (README §5.1): a table name
// is derived from its author's key, so B never aims at A's slot in the first place. There
// is no ownership register and no same-author clause — the collision the old register
// existed to refuse is unrepresentable, and both modules land.
func TestSameAppNameFromTwoAuthorsCoexists(t *testing.T) {
	bootShell(t, t.TempDir(), "", nil)
	authorA := testAuthor(t)
	authorB := testAuthor(t)
	// Both authors are allowed to install: this test is about the namespace, not the
	// closed author set. A permissive policy is exactly the interesting case — even with
	// nothing refusing anyone, neither author can reach the other's names.
	if err := applyPolicy(`{"authors":["` + hex.EncodeToString(authorA.id()) + `","` + hex.EncodeToString(authorB.id()) + `"]}`); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	keyA := appKeyFor(authorA.id(), "ownedapp")
	keyB := appKeyFor(authorB.id(), "ownedapp")
	if keyA == keyB {
		t.Fatal("the same app name under two authors must derive distinct app keys")
	}
	bundleA, _ := writeTestBundle(t, authorA, "ownedapp", 1)
	if status := loadBundle(bundleA); !strings.Contains(status, "ownedapp") {
		t.Fatalf("author A's install should be admitted: %s", status)
	}
	if !boundToWasm(keyA, "fwd") {
		t.Fatalf("author A's module is not bound under `%s`", keyA)
	}
	// B's bundle declares the same app name and installs too — beside A, never over it.
	bundleB, _ := writeTestBundle(t, authorB, "ownedapp", 2)
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
