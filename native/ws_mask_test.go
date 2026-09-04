package main

// ws_mask_test.go — the RFC 6455 masking transform, at every length that lands differently
// in ws.wasm's vectorized loop (assembly/ws/index.ts `maskRun`).
//
// The loop masks eight bytes at a time, then four, then the last 0..3 one at a time, so a
// payload's length mod 8 chooses which of the three paths runs and how they hand over. A
// byte-at-a-time loop had no such seams; this one does, and the fuzzer reaches them only by
// chance. So the lengths below are walked exhaustively across the boundaries rather than
// sampled, in both directions, against the spec-written oracle in fuzz_ws_test.go
// (`refDecodeOne`) — which masks one byte at a time and is the second implementation this
// asserts against.

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// wsMaskKey is deliberately four DIFFERENT non-zero octets: a key with a repeat, or a zero
// byte, would let a loop that mixes up its lane order still pass.
var wsMaskKey = [4]byte{0x37, 0xfa, 0x21, 0x3d}

// wsMaskLengths are the payload widths worth walking: every residue class of the eight- and
// four-byte steps (0..40 covers each of them several times), the 7-bit/16-bit/64-bit length
// form boundaries, and two megabyte-scale payloads — one a multiple of 8 and one not, so the
// bulk path is exercised with and without a tail.
func wsMaskLengths() []int {
	lens := make([]int, 0, 64)
	for n := 0; n <= 40; n++ {
		lens = append(lens, n)
	}
	return append(lens, 125, 126, 127, 128, 65535, 65536, 65537, 1<<20, 1<<20+5)
}

// wsMaskPayload is position-dependent, so a mask applied at the wrong offset — or a lane
// swapped inside the word — changes the bytes rather than cancelling out.
func wsMaskPayload(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i*7 + 3)
	}
	return p
}

// wsMaskedFrame builds one masked binary frame by hand, in the minimal length encoding the
// oracle insists on. Hand-built rather than produced by the module, so a decode test is not
// checking the encoder against itself.
func wsMaskedFrame(payload []byte) []byte {
	var f []byte
	n := len(payload)
	switch {
	case n < 126:
		f = append(f, 0x82, byte(0x80|n))
	case n < 65536:
		f = append(f, 0x82, 0x80|126, byte(n>>8), byte(n))
	default:
		f = append(f, 0x82, 0x80|127, 0, 0, 0, 0)
		f = binary.BigEndian.AppendUint32(f, uint32(n))
	}
	f = append(f, wsMaskKey[:]...)
	for i, b := range payload {
		f = append(f, b^wsMaskKey[i&3])
	}
	return f
}

// TestWsMaskDecodeEveryTail decodes a masked frame at each length and checks the unmasked
// payload against the oracle's. This is the SERVER side: every frame a browser edge sends is
// masked, so it is the whole inbound data path.
func TestWsMaskDecodeEveryTail(t *testing.T) {
	w := wsModule(t)
	for _, n := range wsMaskLengths() {
		payload := wsMaskPayload(n)
		frame := wsMaskedFrame(payload)
		req := append([]byte{wsOpDecodeOne, 1}, frame...)
		got, out := wsCall(t, w, req)
		want := refDecodeOne(true, frame)

		if want.status != wsFrame {
			t.Fatalf("len %d: the oracle refused a frame this test built (status %d)", n, want.status)
		}
		if got < 10 || out[0] != wsFrame {
			t.Fatalf("len %d: module answered %d bytes, status %d; want a frame", n, got, out[0])
		}
		if consumed := binary.BigEndian.Uint32(out[2:6]); int(consumed) != want.consumed {
			t.Fatalf("len %d: consumed %d, oracle says %d", n, consumed, want.consumed)
		}
		gotLen := binary.BigEndian.Uint32(out[6:10])
		if int(gotLen) != n {
			t.Fatalf("len %d: module reports payloadLen %d", n, gotLen)
		}
		if !bytes.Equal(out[10:10+gotLen], want.payload) {
			t.Fatalf("len %d: unmasked payload differs from the oracle's at byte %d",
				n, firstByteDiff(out[10:10+gotLen], want.payload))
		}
		// Against the ORIGINAL too, not only the oracle: the two agreeing on a wrong answer
		// is the one thing a second implementation cannot rule out by itself.
		if !bytes.Equal(out[10:10+gotLen], payload) {
			t.Fatalf("len %d: unmasked payload is not what was masked", n)
		}
	}
}

// TestWsMaskEncodeEveryTail masks on the way OUT — the client side — and reads the frame
// back with the oracle. Same lengths, so both directions cross the same loop seams.
func TestWsMaskEncodeEveryTail(t *testing.T) {
	w := wsModule(t)
	for _, n := range wsMaskLengths() {
		payload := wsMaskPayload(n)
		req := append([]byte{wsOpEncode, 0x2, 1}, wsMaskKey[:]...)
		req = append(req, payload...)
		got, out := wsCall(t, w, req)
		if got <= 0 {
			t.Fatalf("len %d: encode answered %d bytes", n, got)
		}
		// The oracle reads what a server would: a masked frame it must unmask itself.
		dec := refDecodeOne(true, out[:got])
		if dec.status != wsFrame {
			t.Fatalf("len %d: the oracle would not read the module's own frame (status %d)", n, dec.status)
		}
		if dec.consumed != int(got) {
			t.Fatalf("len %d: frame is %d bytes, oracle consumed %d", n, got, dec.consumed)
		}
		if !bytes.Equal(dec.payload, payload) {
			t.Fatalf("len %d: round-tripped payload differs at byte %d",
				n, firstByteDiff(dec.payload, payload))
		}
		// A masked frame whose payload survived unchanged would mean the mask never ran.
		// Only worth asserting where there is a byte the key cannot leave alone.
		if n > 0 && bytes.Equal(out[len(out)-n:got], payload) {
			t.Fatalf("len %d: the wire bytes are the plaintext — nothing was masked", n)
		}
	}
}

func firstByteDiff(a, b []byte) int {
	for i := range a {
		if i >= len(b) || a[i] != b[i] {
			return i
		}
	}
	return len(a)
}
