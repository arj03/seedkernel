package main

import (
	"strings"
	"testing"
	"time"
)

// With the bundle author allow-listed, the closed policy still loads the bundle.
func TestPolicyAllowsBundleAuthor(t *testing.T) {
	bootRealmIn(t, t.TempDir())
	author := testAuthor(t)
	startShell(t, authorsPolicy(author.id()), nil)
	bundlePath, appKey := writeTestBundle(t, author, "testapp", 1)
	if status := loadBundle(bundlePath); !strings.HasPrefix(status, "testapp v1  key "+appKey) {
		t.Fatalf("policy-allowed bundle: %s", status)
	}
}

// A policy that omits the bundle author rejects it at the manifest-governance gate.
func TestPolicyRejectsForeignAuthor(t *testing.T) {
	bootShell(t, t.TempDir(), `{"authors":["`+strings.Repeat("ab", 32)+`"]}`, nil)
	author := testAuthor(t)
	bundlePath, _ := writeTestBundle(t, author, "testapp", 1)
	if status := loadBundle(bundlePath); !strings.Contains(status, "rejected by admission") {
		t.Fatalf("expected foreign-author rejection, got: %s", status)
	}
}

// Trusting an app author cannot appoint that author as the transport.
func TestAppPolicyCannotInstallTransport(t *testing.T) {
	bootRealmIn(t, t.TempDir())
	author := testAuthor(t)
	startShell(t, authorsPolicy(author.id()), nil)
	linkBundle, _ := writeBundle(t, author, "linkapp", 1, "", []string{"link"})
	if status := loadBundle(linkBundle); !strings.Contains(status, "explicit replacement") {
		t.Fatalf("app policy must not appoint a transport: %s", status)
	}
	appBundle, _ := writeTestBundle(t, author, "ordinary", 1)
	if status := loadBundle(appBundle); !strings.HasPrefix(status, "ordinary v1") {
		t.Fatalf("app policy must still admit ordinary apps: %s", status)
	}
}

func TestTransportNetworkOptional(t *testing.T) {
	bootRealmIn(t, t.TempDir())
	got := awaitOK(t, "transport without app policy", `(async () => {
	  const identity = deriveNodeKey(sodium, sodium.randombytes_buf(32));
	  for (const network of [false, true]) {
	    const node = await standUp({ dir: __dir, identity, transport: network ? {} : false });
	    try {
	      if ((node.transport !== null) !== network) throw new Error("network adapter mismatch");
	      if ((node.shell.resolve("_net") !== null) !== network) throw new Error("transport slot mismatch");
	    } finally { node.shell.close(); }
	  }
	  return new Uint8Array([1]);
	})()`, 10*time.Second)
	if len(got) != 1 || got[0] != 1 {
		t.Fatalf("network opt-in: %v", got)
	}
}

// parsePolicy fails loudly on malformed config rather than silently widening trust: a
// node handed one does not stand up at all.
func TestPolicyMalformed(t *testing.T) {
	bootRealmIn(t, t.TempDir())
	for _, bad := range []string{`{}`, `[]`, `not json`, `{"authors":[123]}`, `{"authors":"x"}`, `{"authors":["zz"]}`, `{"authors":[],"grants":{"link":[]}}`} {
		if _, err := startNode(nodeConfig{KeyHex: testKeyHex(t), PolicyJSON: &bad}); err == nil {
			t.Fatalf("a node stood up under policy %q, want an error", bad)
		}
	}
}

// The whole point of the omitted-policy default: a node that was never given a policy
// refuses every ordinary app install (README §14). The JS
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

// Two authors shipping an app under the SAME name coexist (README §5.1): a slot's
// identity is derived from its author's key, so B never aims at A's slot in the first
// place. There is no ownership register and no same-author clause — the collision the old
// register existed to refuse is unrepresentable, and both slots land.
//
// The app name and the wire claim are separate facts, which is what the middle of this
// test pins down: identity coexists, a claim does not. A claim has ONE active owner
// (§12.10), so B contesting the id A serves is refused by name — B's own identity is what
// it may install under, never A's route.
func TestSameAppNameFromTwoAuthorsCoexists(t *testing.T) {
	bootRealmIn(t, t.TempDir())
	authorA := testAuthor(t)
	authorB := testAuthor(t)
	// Both authors are allowed to install: this test is about the namespace, not the
	// closed author set. A permissive policy is exactly the interesting case — even with
	// nothing refusing anyone, neither author can reach the other's names.
	startShell(t, authorsPolicy(authorA.id(), authorB.id()), nil)
	keyA := appKeyFor(authorA.id(), "ownedapp")
	keyB := appKeyFor(authorB.id(), "ownedapp")
	if keyA == keyB {
		t.Fatal("the same app name under two authors must derive distinct app keys")
	}
	// A installs and claims the id its manifest declares. Asserted on the whole operator
	// line rather than on a substring: every rejection below also names the app, so a
	// `Contains` would read a refused load as a successful one.
	bundleA, _ := writeTestBundle(t, authorA, "ownedapp", 1)
	if status := loadBundle(bundleA); status != loadedLine("ownedapp", 1, keyA, "ownedapp") {
		t.Fatalf("author A's install should be admitted: %s", status)
	}
	if out, err := invokeBundle(keyA, []byte("A")); err != nil || string(out) != "A" {
		t.Fatalf("author A's slot did not run through `%s`: %q, %v", keyA, out, err)
	}
	// B contesting A's claim is refused by name — and refused WHOLE, so nothing of B is
	// left behind for the install below to collide with.
	contested, _ := writeTestBundle(t, authorB, "ownedapp", 1)
	if status := loadBundle(contested); !strings.Contains(status, "is already held by '"+keyA+"'") {
		t.Fatalf("a second identity contesting an active claim must be refused by name: %s", status)
	}
	// B's bundle declares the same app name under a claim of its own, and installs too —
	// beside A, never over it.
	bundleB := writeBundleFile(t, "ownedapp",
		manifestEnvelope(t, authorB, claimManifest(t, "ownedapp", "ownedapp-b")), stubGuestSrc)
	if status := loadBundle(bundleB); status != loadedLine("ownedapp", 1, keyB, "ownedapp-b") {
		t.Fatalf("author B's install should be admitted under its own name: %s", status)
	}
	if out, err := invokeBundle(keyB, []byte("B")); err != nil || string(out) != "B" {
		t.Fatalf("author B's slot did not run through `%s`: %q, %v", keyB, out, err)
	}
	// The decisive assertion: A's slot, and the id it serves, are untouched by B's install.
	if out, err := invokeBundle(keyA, []byte("A2")); err != nil || string(out) != "A2" {
		t.Fatalf("author B's install displaced author A's slot `%s`: %q, %v", keyA, out, err)
	}
}
