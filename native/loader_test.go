package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

// End-to-end: boot the shell, exercise the signature pipeline, load a minimal signed
// bundle built right here (no seedstore / sibling-repo dependency), and confirm its
// installed module runs and can reach another handler through kernel.call.
func TestShellRunsBundle(t *testing.T) {
	boot()

	// Signature pipeline: a signed envelope routed to a native handler dispatches once.
	echo := 0
	registerNative("test.echo", func(p []byte) []byte { echo++; return p })
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dispatch(sign(priv, pub, name("test.echo"), []byte("hi")))
	if echo != 1 {
		t.Fatalf("signed dispatch → echo = %d, want 1", echo)
	}

	// A minimal signed bundle: verify the manifest, govern it, install its module. The
	// author must be in the policy — an unconfigured node is deny-all (README §14).
	author, authorPub := testAuthor(t)
	if err := applyPolicy(`{"authors":["` + hex.EncodeToString(authorPub) + `"]}`); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	dir, kernelName := writeTestBundle(t, author, authorPub, "testapp", 1)
	if status := loadBundle(dir); !strings.HasPrefix(status, "testapp v1  installed=[fwd]") {
		t.Fatalf("bundle load: %s", status)
	}

	// The installed module actually runs: drive the forwarder to relay a payload to the
	// echo handler via kernel.call — reaching it proves the bundle-installed wasm executes.
	en := name("test.echo")
	fwdReq := append(append([]byte{byte(len(en))}, en...), []byte("relayed")...)
	callHandler(kernelName, fwdReq)
	if echo != 2 {
		t.Fatalf("bundle module forward → echo = %d, want 2 (module ran + reached echo)", echo)
	}
}

// boundToWasm reports whether `n` resolves — through the kernel's own table, the way every
// call path resolves it — to an installed wasm handler.
func boundToWasm(n []byte) bool {
	id := findHandlerID(n)
	return id >= 0 && entries[id] != nil && entries[id].wasm != nil
}

// TestScratchRegion covers the §4.1 reservation on this target: a handler that declares no
// `scratchSize` gets the 128 KB default, and the host clamps its I/O to what it reserved
// rather than to whatever its linear memory happens to allow. The forwarder's memory is
// 512 KB against a ~35 KB scratch offset, so an over-default payload would physically fit —
// only the clamp refuses it. (The declared-scratchSize branch belongs to handlers like
// seedstore's RS codec, which reserves 2 MB; no in-repo fixture declares one.)
func TestScratchRegion(t *testing.T) {
	boot()
	n := name("scratch.fwd")
	if !installWasm(n, forwarderWasm) {
		t.Fatal("installWasm(forwarder) refused")
	}
	w := entries[findHandlerID(n)].wasm
	if w.size != defaultScratchSize {
		t.Fatalf("a handler exporting no scratchSize should get the %d B default, got %d",
			defaultScratchSize, w.size)
	}
	if r := callHandler(n, make([]byte, w.size+1)); r != nil {
		t.Fatalf("a payload past the reserved region must be refused, got %d B", len(r))
	}
}

// TestCallerStack covers the §4.2 call chain on this target: a handler reached through
// kernel.call sees its immediate caller's name, one reached by top-level dispatch sees the
// no-caller marker, and the stack is balanced afterwards. §8.1 bridge pinning is a decision
// on exactly this name, so it has to be live here and not only on the JS host — same ground
// as testCallerStackFormat in WASM/tests/run.mjs, whose shape this mirrors.
func TestCallerStack(t *testing.T) {
	boot()
	author, authorPub := testAuthor(t)
	if err := applyPolicy(`{"authors":["` + hex.EncodeToString(authorPub) + `"]}`); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	dir, fwdName := writeTestBundle(t, author, authorPub, "callerapp", 1)
	if status := loadBundle(dir); !strings.HasPrefix(status, "callerapp v1") {
		t.Fatalf("bundle load: %s", status)
	}

	// A probe records its immediate caller on every call. A native handler reads the same
	// host-owned stack that the kernel.caller import serves to wasm handlers.
	var seen []byte
	probe := name("probe.caller")
	registerNativeAt(probe, func([]byte) []byte {
		seen = append([]byte(nil), immediateCaller()...)
		return []byte{0xff}
	})

	// forwarder → probe via kernel.call: the probe's immediate caller is the forwarder.
	// (The forwarder fixture's payload is [target_len u8][target][forward_payload].)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dispatch(sign(priv, pub, fwdName, append([]byte{byte(len(probe))}, probe...)))
	want := append([]byte{byte(len(fwdName))}, fwdName...)
	if !bytes.Equal(seen, want) {
		t.Fatalf("immediate caller = %q, want the forwarder %q", seen, want)
	}

	// Top-level dispatch straight into the probe: no caller — the single byte [0x00].
	seen = nil
	dispatch(sign(priv, pub, probe, nil))
	if !bytes.Equal(seen, []byte{0}) {
		t.Fatalf("top-level dispatch caller = %v, want the no-caller marker [0]", seen)
	}

	// Every frame pushed around a kernel.call was popped again.
	if len(callerStack) != 0 {
		t.Fatalf("callerStack not balanced: %d frame(s) left", len(callerStack))
	}
}

func envelope(n, payload []byte) []byte {
	return append(append([]byte{0x53, 0x44, 1, byte(len(n))}, n...), payload...)
}

func sign(priv ed25519.PrivateKey, pub, innerName, payload []byte) []byte {
	inner := envelope(innerName, payload)
	// README §6.3: sign over DOMAIN_env ‖ algo_id ‖ signer_len ‖ signer ‖ inner_envelope,
	// not the bare inner bytes. The domain prefix and outer fields are reconstructed by
	// the verifier, never transmitted; the signer is length-prefixed (2-byte BE, 32 here)
	// so the preimage is self-delimiting.
	var pre []byte
	pre = append(pre, "seedkernel-envelope-sig-v1\x00"...)
	pre = append(pre, 0, 0)  // algo_id 0x0000 (genesis)
	pre = append(pre, 0, 32) // signer_len = 32 (u16 BE)
	pre = append(pre, pub...)
	pre = append(pre, inner...)
	wp := append([]byte{0, 0, 0, 32}, pub...)
	wp = append(append(wp, 0, 64), ed25519.Sign(priv, pre)...)
	return envelope(name("signature"), append(wp, inner...))
}
