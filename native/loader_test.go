package main

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// boundToWasm reports whether an app's module resolves — through the module table, the way
// every call path resolves it — to an installed wasm module.
func boundToWasm(appKey, module string) bool {
	return apps[appKey][module] != nil
}

// TestScratchRegion covers the §4.1 reservation on this target: a module that declares no
// `scratchSize` gets the 128 KB default, and the host clamps its I/O to what it reserved
// rather than to whatever its linear memory happens to allow. The forwarder reserves a
// second buffer past `scratch`, so an over-default payload would physically fit its memory —
// only the clamp refuses it. (The declared-scratchSize branch belongs to modules like
// seedstore's RS codec, which reserves 2 MB; no in-repo fixture declares one.)
//
// The default itself is the shared host's number (core/wasm-limits.ts
// DEFAULT_SCRATCH_SIZE), passed by the shim at every bindAll; the test mirrors it,
// since Go no longer owns a copy.
func TestScratchRegion(t *testing.T) {
	bootRealm(t)
	key := appKeyFor(bytes.Repeat([]byte{0xab}, 32), "scratchapp")
	if err := bindAll(key, []string{"fwd"}, [][]byte{forwarderWasm}, 0x20000); err != nil {
		t.Fatalf("bindAll(forwarder) refused: %v", err)
	}
	w := apps[key]["fwd"]
	if w.size != 0x20000 {
		t.Fatalf("a module exporting no scratchSize should get the 128 KB default, got %d",
			w.size)
	}
	// The installed module actually runs: an in-bounds payload echoes back unchanged,
	// proving the host stages input at `scratch`, calls handle, and reads the response
	// from the same region (README §4).
	msg := []byte("hello module")
	if r := callModule(key, "fwd", msg); !bytes.Equal(r, msg) {
		t.Fatalf("echo module returned %q, want %q", r, msg)
	}
	// A payload past the reserved region is refused by the clamp, not by memory bounds.
	if r := callModule(key, "fwd", make([]byte, w.size+1)); r != nil {
		t.Fatalf("a payload past the reserved region must be refused, got %d B", len(r))
	}
}

// TestBundleModuleRuns is the end-to-end shape: build a minimal signed bundle right here
// (no seedstore / sibling-repo dependency), load it, then reach its installed module by
// name and confirm the pure-transform executes. The host reaches installed modules only by
// name now (README §4, §12.4) — there is no host-call/dispatch seam to drive one through —
// so echoing a payload back is the whole "the bundle-installed wasm runs" proof.
func TestBundleModuleRuns(t *testing.T) {
	bootShell(t, t.TempDir(), "", nil)
	author, authorPub := testAuthor(t)
	if err := applyPolicy(`{"authors":["` + hex.EncodeToString(authorPub) + `"]}`); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	bundlePath, appKey := writeTestBundle(t, author, authorPub, "runapp", 1)
	if status := loadBundle(bundlePath); !strings.HasPrefix(status, "runapp v1  key "+appKey) {
		t.Fatalf("bundle load: %s", status)
	}
	msg := []byte("relayed")
	if r := callModule(appKey, "fwd", msg); !bytes.Equal(r, msg) {
		t.Fatalf("bundle module echo = %q, want %q (module ran + host read its response)", r, msg)
	}
}

// TestBindNamesAnInstalledApp covers --bind's one check (§12.10). Which app answers a
// protocol is entirely the operator's, but an app key nothing is installed under is a
// mistake rather than a choice: install is inert, so nothing else would ever catch it,
// and its only runtime symptom is a node that boots clean and answers an empty body on
// that protocol forever. The bind is refused, and main() exits on the error.
func TestBindNamesAnInstalledApp(t *testing.T) {
	bootShell(t, t.TempDir(), "", nil)
	author, authorPub := testAuthor(t)
	if err := applyPolicy(`{"authors":["` + hex.EncodeToString(authorPub) + `"]}`); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	bundlePath, appKey := writeTestBundle(t, author, authorPub, "bindapp", 1)
	if status := loadBundle(bundlePath); !strings.HasPrefix(status, "bindapp v1  key "+appKey) {
		t.Fatalf("bundle load: %s", status)
	}
	if line, err := bindProtocol("bindapp/v1", appKey); err != nil {
		t.Fatalf("bind to the installed app: %v", err)
	} else if line != "bindapp/v1 → "+appKey {
		t.Fatalf("bind line = %q", line)
	}
	_, err := bindProtocol("bindapp/v1", appKey+"-typo")
	if err == nil {
		t.Fatal("a bind naming an app key nothing is installed under must be refused")
	}
	if !strings.Contains(err.Error(), "no app") {
		t.Fatalf("the refusal must name the rule, got %v", err)
	}
}

// TestContactSecretFlag covers -contact-secret validation (parseContactSecret).
//
// Validation belongs at STARTUP because a wrong contact secret has no runtime symptom:
// a gated node refuses callers in silence (§12.6.2), so a typo'd secret produces a node
// that looks healthy and answers nobody. Failing at parse is the only place an operator
// gets told. Empty stays empty — absent means "open", not "gate on the empty string".
func TestContactSecretFlag(t *testing.T) {
	const good = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

	for _, tc := range []struct {
		name, in, want string
		ok             bool
	}{
		{name: "absent leaves the node open", in: "", want: "", ok: true},
		{name: "32-byte hex is accepted", in: good, want: good, ok: true},
		{name: "non-hex is refused", in: "nothexatall", ok: false},
		{name: "31 bytes is refused", in: good[:62], ok: false},
		{name: "33 bytes is refused", in: good + "ab", ok: false},
		{name: "odd-length hex is refused", in: good[:63], ok: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseContactSecret(tc.in)
			if tc.ok {
				if err != nil {
					t.Fatalf("want accepted, got error: %v", err)
				}
				if got != tc.want {
					t.Fatalf("ContactSecretHex = %q, want %q", got, tc.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("want error for %q, got none (got=%q)", tc.in, got)
			}
			if !strings.Contains(err.Error(), "contact-secret") {
				t.Fatalf("error should name the flag, got: %v", err)
			}
		})
	}
}
