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
	bundlePath, _ := writeTestBundle(t, author, "testapp", 1)
	if status := loadBundle(bundlePath); status != loadedLine("testapp", 1, author.id(), "testapp") {
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
	if status := loadBundle(linkBundle); !strings.Contains(status, "claim 'link' is already held") {
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
// shell has always done this (main.ts) — the native binary used to do the opposite.
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

// One slot per app label on a node, whoever authored it (§5): the label names the
// slot's fs and signing namespaces, so a second author's bundle under a label already
// standing is refused by name, even one claiming nothing the first serves. Taking a label
// over means naming the slot being replaced, which this operator flow never does.
//
// The label and the wire claim are separate facts, and both have ONE owner: B under a
// label of its own still cannot contest the id A serves (§12.10).
func TestOneSlotPerLabel(t *testing.T) {
	bootRealmIn(t, t.TempDir())
	authorA := testAuthor(t)
	authorB := testAuthor(t)
	// Both authors are allowed to install: this test is about the namespace, not the
	// closed author set. A permissive policy is exactly the interesting case — even with
	// nothing refusing anyone, neither author can take the other's label or claim.
	startShell(t, authorsPolicy(authorA.id(), authorB.id()), nil)
	// A installs and claims the id its manifest declares. Asserted on the whole operator
	// line rather than on a substring: every rejection below also names the app, so a
	// `Contains` would read a refused load as a successful one.
	bundleA, keyA := writeTestBundle(t, authorA, "ownedapp", 1)
	if status := loadBundle(bundleA); status != loadedLine("ownedapp", 1, authorA.id(), "ownedapp") {
		t.Fatalf("author A's install should be admitted: %s", status)
	}
	if out, err := invokeBundle(keyA, []byte("A")); err != nil || string(out) != "A" {
		t.Fatalf("author A's slot did not run through `%s`: %q, %v", keyA, out, err)
	}
	// B under A's label is refused by name, even claiming an id of its own.
	sameLabel := writeBundleFile(t, "ownedapp",
		bundleEnvelope(t, authorB, claimManifest(t, "ownedapp", "ownedapp-b"), stubGuestSrc, forwarderWasm))
	if status := loadBundle(sameLabel); !strings.Contains(status, "'ownedapp' is already installed") {
		t.Fatalf("a second author under a standing label must be refused by name: %s", status)
	}
	// B under a label of its own, contesting A's claim, is refused by name too.
	contested := writeBundleFile(t, "otherapp",
		bundleEnvelope(t, authorB, claimManifest(t, "otherapp", "ownedapp"), stubGuestSrc, forwarderWasm))
	if status := loadBundle(contested); !strings.Contains(status, "is already held by '"+keyA+"'") {
		t.Fatalf("a second app contesting an active claim must be refused by name: %s", status)
	}
	// The decisive assertion: A's slot, and the id it serves, are untouched by both.
	if out, err := invokeBundle(keyA, []byte("A2")); err != nil || string(out) != "A2" {
		t.Fatalf("author B's installs displaced author A's slot `%s`: %q, %v", keyA, out, err)
	}
}
