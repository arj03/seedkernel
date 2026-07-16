package main

import (
	"crypto/ed25519"
	"crypto/rand"
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

	// A minimal signed bundle: verify the manifest, govern it, install its module.
	author, authorPub := testAuthor(t)
	dir, kernelName := writeTestBundle(t, author, authorPub, "testapp", 1)
	if status := loadBundle(dir); !strings.HasPrefix(status, "testapp v1  installed=[fwd]") {
		t.Fatalf("bundle load: %s", status)
	}

	// The installed module actually runs: drive the forwarder to relay a payload to the
	// echo handler via kernel.call — reaching it proves the bundle-installed wasm executes.
	en := name("test.echo")
	fwdReq := append(append([]byte{byte(len(en))}, en...), []byte("relayed")...)
	run(kernelName, fwdReq)
	if echo != 2 {
		t.Fatalf("bundle module forward → echo = %d, want 2 (module ran + reached echo)", echo)
	}
}

// TestWireInstall drives the live-update wire path (README §7.2): a signed install
// envelope dispatched through the pipeline reaches onInstall, clears the permissive
// default policy, and binds the module. This path stays after bundles moved to direct
// installs (§13.4), so it keeps its own coverage here.
func TestWireInstall(t *testing.T) {
	boot()
	author, authorPub := testAuthor(t)
	target := name("wire.mod")
	dispatch(buildInstall(author, authorPub, target, forwarderWasm, 1))
	if _, ok := wasmH[string(target)]; !ok {
		t.Fatal("wire install did not register the module")
	}
	// A replay of the same seq is dropped; the module stays bound to the same bytes.
	dispatch(buildInstall(author, authorPub, target, forwarderWasm, 1))
	if _, ok := wasmH[string(target)]; !ok {
		t.Fatal("module unbound after a replayed install")
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
