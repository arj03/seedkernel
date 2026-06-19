package main

import (
	"bytes"
	"testing"
)

// Unit tests for the WS wire codec primitive (ws.go). The routing/handshake/
// transport that used to live in net.go is now shared JS, exercised end-to-end over
// the real socket primitive in peerlink_test.go (PeerLink) and transport_test.go
// (NodeNetworkCore + Transport, TCP and WS).

// The RFC 6455 §1.3 worked example pins the accept-key transform byte-for-byte, so a
// Go node's 101 reply is identical to what a browser (and a Bun node) expect.
func TestWSAcceptKey(t *testing.T) {
	if got := wsAcceptKey("dGhlIHNhbXBsZSBub25jZQ=="); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("wsAcceptKey = %q, want s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", got)
	}
}

// encodeWSFrame ↔ wsParser round-trip, both directions of masking. A client masks,
// so the parser feeding client bytes must expect masked; the server's replies are
// unmasked.
func TestWSFrameRoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte("seedkernel "), 30) // > 125, exercises the 126 path
	// client → server: masked
	enc := encodeWSFrame(opBinary, payload, randBytes(4))
	frames, err := newWSParser(true).push(enc)
	if err != nil || len(frames) != 1 || !bytes.Equal(frames[0].payload, payload) {
		t.Fatalf("masked round trip: err=%v frames=%d", err, len(frames))
	}
	// server → client: unmasked
	enc = encodeWSFrame(opBinary, payload, nil)
	frames, err = newWSParser(false).push(enc)
	if err != nil || len(frames) != 1 || !bytes.Equal(frames[0].payload, payload) {
		t.Fatalf("unmasked round trip: err=%v frames=%d", err, len(frames))
	}
	// wrong mask direction is a protocol error (an unmasked frame fed to a server)
	if _, err := newWSParser(true).push(encodeWSFrame(opBinary, payload, nil)); err == nil {
		t.Fatal("expected a mask-direction protocol error")
	}
}

// A frame split across two pushes must still parse once whole — the framing wait
// (frameLength) is what guarantees we copy a big frame once, not per chunk.
func TestWSPartialFrame(t *testing.T) {
	enc := encodeWSFrame(opBinary, []byte("hello world"), randBytes(4))
	p := newWSParser(true)
	if f, err := p.push(enc[:3]); err != nil || len(f) != 0 {
		t.Fatalf("partial push: err=%v frames=%d", err, len(f))
	}
	if f, err := p.push(enc[3:]); err != nil || len(f) != 1 || string(f[0].payload) != "hello world" {
		t.Fatalf("completing push: err=%v frames=%d", err, len(f))
	}
}
