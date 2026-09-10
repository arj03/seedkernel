package main

// ws_mask_test.go — the RFC 6455 masking transform, at every length that lands differently
// in ws.wasm's vectorized loop (assembly/ws/index.ts `maskRun`).
//
// The loop masks eight bytes at a time, then four, then the last 0..3 one at a time, so a
// payload's length mod 8 chooses which of the three paths runs and how they hand over. So
// the lengths below are walked exhaustively across the boundaries, in both directions,
// against a frame masked one byte at a time by hand.

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"seedloader/qjs"
)

const (
	// assembly/ws/abi.ts
	wsOpEncode    = 1
	wsOpDecodeOne = 2
	wsFrame       = 1 // decodeOne's status for a whole frame
)

// wsModuleJS lifts ws.wasm out of the transport bundle the host already embeds, so the
// module under test is always the one that ships in the signed bundle.
const wsModuleJS = `
globalThis.__wsModuleBytes = () => unpackBundle(transportBundleBytes())["ws.wasm"];
`

// wsModule stands the codec up on the module table's runtime. The scratch floor mirrors
// core/wasm-limits.ts DEFAULT_SCRATCH_SIZE; ws.wasm exports its own larger `scratchSize`,
// so this only has to be a floor it clears.
func wsModule(t *testing.T) *boundModule {
	t.Helper()
	bootRealm(t)
	if _, err := qc.Eval("ws-module.js", qjs.Code(wsModuleJS)); err != nil {
		t.Fatal("ws module probe:", err)
	}
	wasm, err := callRealm("__wsModuleBytes", 20*time.Second)
	if err != nil {
		t.Fatal("ws.wasm out of the transport bundle:", err)
	}
	w, err := instantiateWasm(wasm, 128*1024, -1)
	if err != nil {
		t.Fatal("instantiate ws.wasm:", err)
	}
	t.Cleanup(func() { closeModule(w) })
	return w
}

// wsCall stages one request and returns handle()'s answer, unclamped: a length past the
// scratch is a finding here, not something to trim the way the host's callModule does.
func wsCall(t *testing.T, w *boundModule, req []byte) []byte {
	t.Helper()
	mem := w.mod.Memory()
	if uint32(len(req)) > w.size || !mem.Write(w.scratch, req) {
		t.Fatalf("could not stage a %d-byte request in a %d-byte scratch", len(req), w.size)
	}
	// Zero what lies past the request, so an answer the module never wrote cannot be read
	// back as the previous length's.
	if tail, ok := mem.Read(w.scratch+uint32(len(req)), 64); ok {
		clear(tail)
	}
	r, err := w.fn.Call(ctx, uint64(len(req)))
	if err != nil {
		t.Fatalf("ws.wasm trapped on a %d-byte request: %v", len(req), err)
	}
	n := int32(r[0])
	if n < 0 || uint32(n) > w.size {
		t.Fatalf("ws.wasm answered %d bytes from a %d-byte scratch", n, w.size)
	}
	out, _ := mem.Read(w.scratch, uint32(n))
	return bytes.Clone(out)
}

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

// wsMaskedFrame builds one masked binary frame by hand, one byte at a time, in the minimal
// length encoding RFC 6455 §5.2 requires — so neither test checks the module against itself.
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

// TestWsMaskDecodeEveryTail decodes a masked frame at each length. This is the SERVER side:
// every frame a browser edge sends is masked, so it is the whole inbound data path.
func TestWsMaskDecodeEveryTail(t *testing.T) {
	w := wsModule(t)
	for _, n := range wsMaskLengths() {
		payload := wsMaskPayload(n)
		frame := wsMaskedFrame(payload)
		// [status][fin|opcode][consumed u32][payloadLen u32][payload]
		out := wsCall(t, w, append([]byte{wsOpDecodeOne, 1}, frame...))
		if len(out) < 10 || out[0] != wsFrame {
			t.Fatalf("len %d: module answered %d bytes, want a frame", n, len(out))
		}
		if consumed := binary.BigEndian.Uint32(out[2:6]); int(consumed) != len(frame) {
			t.Fatalf("len %d: consumed %d of a %d-byte frame", n, consumed, len(frame))
		}
		if gotLen := binary.BigEndian.Uint32(out[6:10]); int(gotLen) != n {
			t.Fatalf("len %d: module reports payloadLen %d", n, gotLen)
		}
		if !bytes.Equal(out[10:], payload) {
			t.Fatalf("len %d: unmasked payload differs at byte %d", n, firstByteDiff(out[10:], payload))
		}
	}
}

// TestWsMaskEncodeEveryTail masks on the way OUT — the client side — and checks the frame
// byte for byte against the hand-masked one. Same lengths, so both directions cross the
// same loop seams.
func TestWsMaskEncodeEveryTail(t *testing.T) {
	w := wsModule(t)
	for _, n := range wsMaskLengths() {
		payload := wsMaskPayload(n)
		req := append([]byte{wsOpEncode, 0x2, 1}, wsMaskKey[:]...)
		got := wsCall(t, w, append(req, payload...))
		if want := wsMaskedFrame(payload); !bytes.Equal(got, want) {
			t.Fatalf("len %d: %d-byte frame differs from the hand-masked %d-byte one at byte %d",
				n, len(got), len(want), firstByteDiff(got, want))
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
