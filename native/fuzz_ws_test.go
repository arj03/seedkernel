//go:build fuzz

package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"testing"
	"time"

	"seedloader/qjs"
)

// ── fuzzing the RFC 6455 codec (assembly/ws) ─────────────────────────────────
//
// ws.wasm decodes frames a browser edge sends before the AKE has authenticated anyone, so
// every byte it reads is a stranger's. It is also the one pre-auth parser written against
// raw memory: AssemblyScript's `load`/`store`/`memory.copy` are unchecked, so a length the
// module mis-measures is a read or write past the region it reserved, not an exception.
//
// The module is driven through the §4 ABI directly rather than through the transport
// guest, so `handle()`'s RAW answer is visible: the host clamps an over-long response to
// the reserved scratch (callModule), which would hide exactly the bug worth finding.
//
// The oracle is a second decoder written from RFC 6455 in Go. Two implementations of one
// format disagreeing is the finding; one implementation asserting about itself is not.

const (
	wsOpEncode    = 1
	wsOpDecodeOne = 2
	wsOpAccept    = 3
	wsOpBase64    = 4
	// assembly/ws/abi.ts. Restated because the fuzzer's job is to disagree with the
	// module: reading them out of the module would make every bound it checks its own.
	wsScratchSize      = (2 << 20) + (1 << 12)
	wsMaxFramePayload  = wsScratchSize - 16
	wsHandshakeGUID    = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	wsDecodeHeaderSize = 10 // [status][fin|opcode][consumed u32][payloadLen u32]
)

// wsModuleJS lifts ws.wasm out of the transport bundle the host already embeds, so the
// fuzzer needs no path into a sibling build directory and always tests the module that
// actually ships in the signed bundle.
const wsModuleJS = `
globalThis.__wsModuleBytes = () => unpackBundle(transportBundleBytes())["ws.wasm"];
`

// wsModule stands the codec up on the module table's runtime. Instantiated once per fuzz
// process: compiling it per iteration would cost more than the parse under test.
func wsModule(f *testing.F) *boundModule {
	f.Helper()
	bootRealm(f)
	if _, err := qc.Eval("fuzz-ws.js", qjs.Code(wsModuleJS)); err != nil {
		f.Fatal("ws module probe:", err)
	}
	wasm, err := callRealm("__wsModuleBytes", 20*time.Second)
	if err != nil {
		f.Fatal("ws.wasm out of the transport bundle:", err)
	}
	w, err := instantiateWasm(wasm, fuzzScratchFloor, -1)
	if err != nil {
		f.Fatal("instantiate ws.wasm:", err)
	}
	f.Cleanup(func() { closeModule(w) })
	return w
}

// fuzzScratchFloor mirrors core/wasm-limits.ts DEFAULT_SCRATCH_SIZE; ws.wasm exports
// its own larger `scratchSize`, so this only has to be a floor it clears.
const fuzzScratchFloor = 128 * 1024

// wsCall stages one request and returns handle()'s raw length plus the module's memory,
// UNCLAMPED — the length is the assertion's subject, so it must not be trimmed first.
func wsCall(t *testing.T, w *boundModule, req []byte) (int64, []byte) {
	t.Helper()
	if uint32(len(req)) > w.size {
		t.Fatalf("harness: %d-byte request past the module's %d-byte scratch", len(req), w.size)
	}
	mem := w.mod.Memory()
	if !mem.Write(w.scratch, req) {
		t.Fatalf("harness: could not stage %d bytes at scratch", len(req))
	}
	// Zero the tail so a stale answer from the previous iteration cannot be mistaken for
	// this one's, which would make a failure unreproducible from its input alone.
	if tail, ok := mem.Read(w.scratch+uint32(len(req)), 64); ok {
		clear(tail)
	}
	r, err := w.fn.Call(ctx, uint64(len(req)))
	if err != nil {
		t.Fatalf("ws.wasm trapped on a %d-byte request: %v\nreq: %x", len(req), err, head(req))
	}
	if len(r) != 1 {
		t.Fatalf("ws.wasm returned %d values, want 1", len(r))
	}
	n := int64(int32(r[0]))
	if n < 0 || n > int64(w.size) {
		// The host clamps this away in production, which is exactly why it is asserted
		// here: a JS host that trusted the length would read past the reserved region.
		t.Fatalf("ws.wasm answered %d bytes from a %d-byte scratch — req %d bytes: %x",
			n, w.size, len(req), head(req))
	}
	out, ok := mem.Read(w.scratch, uint32(n))
	if !ok {
		t.Fatalf("ws.wasm answered %d bytes that are not in its memory", n)
	}
	return n, bytes.Clone(out)
}

// ── the oracle: RFC 6455 single-frame decode, written from the spec ───────────

const (
	wsNeedMore = 0
	wsFrame    = 1
	wsProtoErr = 2
)

type wsDecoded struct {
	status   int
	fin      bool
	opcode   byte
	consumed int
	payload  []byte
}

// refDecodeOne is the second implementation. It mirrors the module's contract — status,
// consumed, unmasked payload — and nothing else, so a disagreement is about the format
// rather than about a shared assumption.
func refDecodeOne(expectMasked bool, buf []byte) wsDecoded {
	if len(buf) < 2 {
		return wsDecoded{status: wsNeedMore}
	}
	b0, b1 := buf[0], buf[1]
	fin := b0&0x80 != 0
	opcode := b0 & 0x0f
	if !fin && opcode >= 8 {
		return wsDecoded{status: wsProtoErr} // fragmented control frame (§5.5)
	}
	masked := b1&0x80 != 0
	if masked != expectMasked {
		return wsDecoded{status: wsProtoErr}
	}
	payloadLen, headerLen := int64(b1&0x7f), 2
	switch payloadLen {
	case 126:
		if len(buf) < 4 {
			return wsDecoded{status: wsNeedMore}
		}
		payloadLen = int64(binary.BigEndian.Uint16(buf[2:4]))
		headerLen = 4
	case 127:
		if len(buf) < 10 {
			return wsDecoded{status: wsNeedMore}
		}
		// The module reads the low half into an i32, so a length with bit 31 set is
		// negative there; both halves are refused, and the oracle refuses them the same
		// way rather than by size alone.
		high := binary.BigEndian.Uint32(buf[2:6])
		low := int32(binary.BigEndian.Uint32(buf[6:10]))
		if high != 0 || low < 0 || int64(low) > wsMaxFramePayload {
			return wsDecoded{status: wsProtoErr}
		}
		payloadLen = int64(low)
		headerLen = 10
	}
	if payloadLen > wsMaxFramePayload {
		return wsDecoded{status: wsProtoErr}
	}
	maskLen := 0
	if masked {
		maskLen = 4
	}
	total := int64(headerLen+maskLen) + payloadLen
	if int64(len(buf)) < total {
		return wsDecoded{status: wsNeedMore}
	}
	payload := bytes.Clone(buf[headerLen+maskLen : total])
	if masked {
		mask := buf[headerLen : headerLen+4]
		for i := range payload {
			payload[i] ^= mask[i&3]
		}
	}
	return wsDecoded{status: wsFrame, fin: fin, opcode: opcode, consumed: int(total), payload: payload}
}

// FuzzWsDecodeOne is the pre-auth frame decoder. Everything a browser edge sends before
// the handshake completes lands here first.
func FuzzWsDecodeOne(f *testing.F) {
	w := wsModule(f)
	f.Add(byte(0), []byte{0x82, 0x03, 1, 2, 3})                            // unmasked binary
	f.Add(byte(1), []byte{0x82, 0x83, 9, 9, 9, 9, 1, 2, 3})                // masked binary
	f.Add(byte(0), []byte{0x82, 0x7e, 0x00, 0x02, 1, 2})                   // 16-bit length
	f.Add(byte(0), []byte{0x82, 0x7f, 0, 0, 0, 0, 0, 0, 0, 2, 1, 2})       // 64-bit length
	f.Add(byte(0), []byte{0x82, 0x7f, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}) // 4 GiB claim
	f.Add(byte(0), []byte{0x02, 0x00})                                     // fragmented data
	f.Add(byte(0), []byte{0x08, 0x00})                                     // fragmented control
	f.Add(byte(0), []byte{0x82})
	f.Add(byte(0), []byte{})

	f.Fuzz(func(t *testing.T, expect byte, buf []byte) {
		// The request is [op][expectMasked][buf], so the biggest buffer the ABI can carry
		// is the scratch minus that lead.
		if len(buf) > wsScratchSize-2 {
			t.Skip()
		}
		expectMasked := expect != 0
		req := append([]byte{wsOpDecodeOne, expect}, buf...)
		n, out := wsCall(t, w, req)
		if n < 1 {
			t.Fatalf("decodeOne answered nothing for a %d-byte buffer: %x", len(buf), head(buf))
		}
		want := refDecodeOne(expectMasked, buf)
		got := int(out[0])
		if got != want.status {
			t.Fatalf("decodeOne(masked=%v): status %d, RFC 6455 says %d — buf %d bytes: %x",
				expectMasked, got, want.status, len(buf), head(buf))
		}
		if got != wsFrame {
			// Nothing but the status byte is defined for the other two answers.
			return
		}
		if n != int64(wsDecodeHeaderSize)+int64(len(want.payload)) {
			t.Fatalf("decodeOne: answered %d bytes for a %d-byte payload — buf %d bytes: %x",
				n, len(want.payload), len(buf), head(buf))
		}
		fin := out[1]&0x80 != 0
		opcode := out[1] & 0x0f
		consumed := int(binary.BigEndian.Uint32(out[2:6]))
		payloadLen := int(binary.BigEndian.Uint32(out[6:10]))
		if fin != want.fin || opcode != want.opcode {
			t.Fatalf("decodeOne: fin=%v opcode=%d, want fin=%v opcode=%d — buf: %x",
				fin, opcode, want.fin, want.opcode, head(buf))
		}
		// `consumed` is what the caller advances its stream by. A value over the buffer
		// would skip bytes nobody parsed; one under it would replay them as a new frame.
		if consumed != want.consumed {
			t.Fatalf("decodeOne: consumed %d, RFC 6455 says %d (buffer is %d) — buf: %x",
				consumed, want.consumed, len(buf), head(buf))
		}
		if consumed > len(buf) {
			t.Fatalf("decodeOne: consumed %d of a %d-byte buffer — buf: %x",
				consumed, len(buf), head(buf))
		}
		if payloadLen != len(want.payload) {
			t.Fatalf("decodeOne: payloadLen %d, want %d — buf: %x",
				payloadLen, len(want.payload), head(buf))
		}
		if !bytes.Equal(out[wsDecodeHeaderSize:], want.payload) {
			t.Fatalf("decodeOne: unmasked payload differs — buf %d bytes: %x", len(buf), head(buf))
		}
	})
}

// FuzzWsEncodeDecode closes the loop: whatever the encoder writes, the decoder must read
// back as the same message. A round trip catches the length-boundary cases (125/126/65535/
// 65536) that a decoder-only oracle can only reach if the fuzzer guesses the header.
func FuzzWsEncodeDecode(f *testing.F) {
	w := wsModule(f)
	f.Add(byte(2), byte(0), []byte("hello"))
	f.Add(byte(2), byte(1), []byte("hello"))
	f.Add(byte(9), byte(1), []byte{})
	f.Add(byte(2), byte(0), bytes.Repeat([]byte("x"), 125))
	f.Add(byte(2), byte(0), bytes.Repeat([]byte("x"), 126))
	f.Add(byte(2), byte(0), bytes.Repeat([]byte("x"), 65535))
	f.Add(byte(2), byte(0), bytes.Repeat([]byte("x"), 65536))

	f.Fuzz(func(t *testing.T, opcode, maskFlag byte, payload []byte) {
		// [op][opcode][maskFlag][mask 4?][payload] in, at most a full frame out.
		if len(payload) > wsScratchSize/2 {
			t.Skip()
		}
		masked := maskFlag != 0
		req := []byte{wsOpEncode, opcode, maskFlag}
		if masked {
			req = append(req, 0xde, 0xad, 0xbe, 0xef)
		}
		req = append(req, payload...)
		n, frame := wsCall(t, w, req)
		// The encoder's ONE refusal is a frame past the scratch it writes into (opEncode:
		// `outTotal > SCRATCH_SIZE`). Anything that fits must come back — without this, an
		// encoder that answered 0 for "hello" would satisfy every assertion below by
		// never reaching them.
		outHeader := 2
		if len(payload) >= 65536 {
			outHeader = 10
		} else if len(payload) >= 126 {
			outHeader = 4
		}
		outMask := 0
		if masked {
			outMask = 4
		}
		fits := outHeader+outMask+len(payload) <= wsScratchSize
		if n == 0 {
			if fits {
				t.Fatalf("encode: refused a %d-byte %s payload whose frame is %d bytes, inside the %d-byte scratch",
					len(payload), map[bool]string{true: "masked", false: "unmasked"}[masked],
					outHeader+outMask+len(payload), wsScratchSize)
			}
			return
		}
		if !fits {
			t.Fatalf("encode: answered %d bytes for a frame of %d, past the %d-byte scratch",
				n, outHeader+outMask+len(payload), wsScratchSize)
		}
		if int(n) != outHeader+outMask+len(payload) {
			t.Fatalf("encode: %d bytes for a %d-byte payload; RFC 6455 frames it in %d",
				n, len(payload), outHeader+outMask+len(payload))
		}
		// The encoder always sets FIN, so the decoder must see one whole message back.
		want := refDecodeOne(masked, frame)
		if want.status != wsFrame {
			t.Fatalf("encode produced %d bytes RFC 6455 will not read back (status %d): %x",
				n, want.status, head(frame))
		}
		if !want.fin || want.opcode != opcode&0x0f {
			t.Fatalf("encode: round trip gave fin=%v opcode=%d, want fin=true opcode=%d",
				want.fin, want.opcode, opcode&0x0f)
		}
		if !bytes.Equal(want.payload, payload) {
			t.Fatalf("encode: round trip changed a %d-byte payload", len(payload))
		}
		if want.consumed != len(frame) {
			t.Fatalf("encode: frame is %d bytes, its own header declares %d", len(frame), want.consumed)
		}
	})
}

// FuzzWsAccept is the opening handshake's one computed value. It runs on the SERVER side
// against a header field a stranger chose, so the input is as attacker-controlled as a
// frame, and its output goes straight back on the wire.
func FuzzWsAccept(f *testing.F) {
	w := wsModule(f)
	f.Add([]byte("dGhlIHNhbXBsZSBub25jZQ==")) // RFC 6455 §1.3
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte("A"), 4096-len(wsHandshakeGUID)))
	f.Add(bytes.Repeat([]byte("A"), 4096-len(wsHandshakeGUID)+1))
	f.Add([]byte{0, 0xff, 0x80})

	f.Fuzz(func(t *testing.T, key []byte) {
		if len(key) > wsScratchSize-1 {
			t.Skip()
		}
		n, out := wsCall(t, w, append([]byte{wsOpAccept}, key...))
		// The module refuses a key it has no room for; its cap is its own, so the only
		// property asserted is that a refusal is a refusal.
		if len(key)+len(wsHandshakeGUID) > 4096 {
			if n != 0 {
				t.Fatalf("accept: answered %d bytes for a %d-byte key past its own cap", n, len(key))
			}
			return
		}
		sum := sha1.Sum(append(bytes.Clone(key), []byte(wsHandshakeGUID)...))
		want := base64.StdEncoding.EncodeToString(sum[:])
		if string(out) != want {
			t.Fatalf("accept(%d-byte key): %q, want %q — key: %x", len(key), out, want, head(key))
		}
	})
}

// FuzzWsBase64 is the client's Sec-WebSocket-Key. Same shape, other direction.
func FuzzWsBase64(f *testing.F) {
	w := wsModule(f)
	f.Add([]byte{})
	f.Add([]byte("a"))
	f.Add([]byte("ab"))
	f.Add([]byte("abc"))
	f.Add(bytes.Repeat([]byte{0xff}, 16))
	f.Add(bytes.Repeat([]byte("z"), 4096))
	f.Add(bytes.Repeat([]byte("z"), 4097))

	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) > wsScratchSize-1 {
			t.Skip()
		}
		n, out := wsCall(t, w, append([]byte{wsOpBase64}, in...))
		if len(in) > 4096 {
			if n != 0 {
				t.Fatalf("base64: answered %d bytes for a %d-byte input past its own cap", n, len(in))
			}
			return
		}
		if want := base64.StdEncoding.EncodeToString(in); string(out) != want {
			t.Fatalf("base64(%d bytes): %q, want %q — in: %x", len(in), out, want, head(in))
		}
	})
}
