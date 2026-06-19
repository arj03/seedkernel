package main

import (
	"bytes"
	"testing"
)

// Unit tests for the WS wire codec primitive — the embedded ws.wasm driven over
// wazero (__ws). The RFC 6455 handshake/framing on top is the shared host JS
// (net-frame.ts + ws-codec.ts), exercised end-to-end over a real socket in
// peerlink_test.go (PeerLink) and transport_test.go (NodeNetworkCore + Transport).

// The RFC 6455 §1.3 worked example pins the accept-key transform byte-for-byte, so
// a Go node's 101 reply is identical to what a browser (and a Bun node) expect.
// This drives ws.wasm's OP_ACCEPT (sha1 + base64) directly.
func TestWsWasmAcceptKey(t *testing.T) {
	c := bootWsCodec()
	req := append([]byte{3 /*OP_ACCEPT*/}, []byte("dGhlIHNhbXBsZSBub25jZQ==")...)
	if got := string(c.call(req)); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("ws.wasm accept = %q, want s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", got)
	}
}

// OP_ENCODE → OP_DECODE_ONE round-trip, masked (client→server). Exercises the
// 126-length path (payload > 125) and the mask XOR both ways through the module.
func TestWsWasmFrameRoundTrip(t *testing.T) {
	c := bootWsCodec()
	payload := bytes.Repeat([]byte("seedkernel "), 30) // > 125 bytes
	mask := randBytes(4)

	enc := append([]byte{1 /*OP_ENCODE*/, 0x2 /*binary*/, 1 /*masked*/}, mask...)
	enc = append(enc, payload...)
	frame := c.call(enc)
	if frame == nil {
		t.Fatal("OP_ENCODE returned nil")
	}

	dec := append([]byte{2 /*OP_DECODE_ONE*/, 1 /*expect masked*/}, frame...)
	r := c.call(dec)
	if len(r) < 10 || r[0] != 1 {
		t.Fatalf("OP_DECODE_ONE status = %v", r)
	}
	plen := int(getU32BE(r, 6))
	if got := r[10 : 10+plen]; !bytes.Equal(got, payload) {
		t.Fatalf("decoded payload mismatch (%d bytes)", len(got))
	}
}
