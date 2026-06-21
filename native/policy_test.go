package main

import (
	"os"
	"strings"
	"testing"
)

// The Ed25519 author key that signs the seedstore bundle's manifest and both module
// installs (read from manifest.bundle / *.install).
const seedstoreAuthor = "56216c9c9077f177454008cc5600f817d96009c1625b2e0fe5fbd9ea0928f470"

func bundleDir() string {
	if d := os.Getenv("SEEDSTORE_BUNDLE"); d != "" {
		return d
	}
	return "../../../seedstore/WASM/bundle"
}

// With the bundle author allow-listed, the closed policy still loads the bundle.
func TestPolicyAllowsBundleAuthor(t *testing.T) {
	boot()
	if err := applyPolicy(`{"authors":["` + seedstoreAuthor + `"]}`); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	if status := loadBundle(bundleDir()); !strings.HasPrefix(status, "seedstore v1  installed=[codec reputation]") {
		t.Fatalf("policy-allowed bundle: %s", status)
	}
}

// A policy that omits the bundle author rejects it at the manifest-governance gate.
func TestPolicyRejectsForeignAuthor(t *testing.T) {
	boot()
	if err := applyPolicy(`{"authors":["` + strings.Repeat("ab", 32) + `"]}`); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	if status := loadBundle(bundleDir()); !strings.Contains(status, "manifest author not in policy") {
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
	// A still-permissive realm (policy never took) loads the bundle.
	if status := loadBundle(bundleDir()); !strings.HasPrefix(status, "seedstore v1  installed=[codec reputation]") {
		t.Fatalf("after rejected policies the realm should stay permissive: %s", status)
	}
}
