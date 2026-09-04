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
	// RFC 6455 §5.5: a control frame's payload is at most 125 bytes, so it always uses the
	// 7-bit length field.
	wsMaxControlPayload = 125
)

// wsEncodeOpcodes is the encoder's caller contract, which is narrower than the ABI: the
// framer asks for a binary frame to carry a message, a pong to answer a ping, and a close
// to say goodbye (framing.js `enqueue`). Nothing asks for a reserved opcode or a text
// frame, so a round-trip target that produced one would be measuring the codec against a
// frame the transport cannot send — and, since the decoder refuses those, would fail.
var wsEncodeOpcodes = []byte{0x2, 0x8, 0xa}

// wsModuleJS lifts ws.wasm out of the transport bundle the host already embeds, so the
// fuzzer needs no path into a sibling build directory and always tests the module that
// actually ships in the signed bundle.
const wsModuleJS = `
globalThis.__wsModuleBytes = () => unpackBundle(transportBundleBytes())["ws.wasm"];
`

// wsModule stands the codec up on the module table's runtime. Instantiated once per fuzz
// process: compiling it per iteration would cost more than the parse under test.
func wsModule(f testing.TB) *boundModule {
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
func wsCall(t testing.TB, w *boundModule, req []byte) (int64, []byte) {
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
//
// Where a refusal and "need more bytes" both apply, the refusal wins: every check below
// reads bytes RFC 6455 puts in the first two, so a frame whose opcode is reserved is
// reserved whether or not its extended length has arrived. That ordering is the format's,
// not the module's — a decoder that waited for the rest of a frame it has already decided
// to refuse would let a peer hold a pre-auth link open on bytes it never has to send.
func refDecodeOne(expectMasked bool, buf []byte) wsDecoded {
	if len(buf) < 2 {
		return wsDecoded{status: wsNeedMore}
	}
	b0, b1 := buf[0], buf[1]
	fin := b0&0x80 != 0
	opcode := b0 & 0x0f
	// RSV1/2/3 (§5.2) mean an extension, and this endpoint negotiates none — so a frame
	// setting one is a frame whose payload this decoder would be misreading.
	if b0&0x70 != 0 {
		return wsDecoded{status: wsProtoErr}
	}
	// Six opcodes are defined (§5.2: continuation, text, binary, close, ping, pong); the
	// other ten are reserved, and a receiver must fail the connection on one rather than
	// guess whether it frames a payload.
	switch opcode {
	case 0x0, 0x1, 0x2, 0x8, 0x9, 0xa:
	default:
		return wsDecoded{status: wsProtoErr}
	}
	if !fin && opcode >= 8 {
		return wsDecoded{status: wsProtoErr} // fragmented control frame (§5.5)
	}
	masked := b1&0x80 != 0
	if masked != expectMasked {
		return wsDecoded{status: wsProtoErr}
	}
	payloadLen, headerLen := int64(b1&0x7f), 2
	if opcode >= 8 {
		// A control frame carries at most 125 bytes (§5.5), so its length is always the
		// 7-bit field — 126 and 127 there are already too long, and settling that here is
		// what keeps a two-byte ping from being a reason to buffer eight more.
		if payloadLen > wsMaxControlPayload {
			return wsDecoded{status: wsProtoErr}
		}
		// A close body is a two-byte status code and then an optional reason (§5.5.1); one
		// byte is half a status code and nothing else.
		if opcode == 0x8 && payloadLen == 1 {
			return wsDecoded{status: wsProtoErr}
		}
	}
	switch payloadLen {
	case 126:
		if len(buf) < 4 {
			return wsDecoded{status: wsNeedMore}
		}
		payloadLen = int64(binary.BigEndian.Uint16(buf[2:4]))
		// "The minimal number of bytes MUST be used to encode the length" (§5.2). Without
		// this one frame has three spellings, and two parsers of one stream — this decoder
		// and whatever else reads the same bytes — can be made to disagree about where the
		// next frame starts.
		if payloadLen < 126 {
			return wsDecoded{status: wsProtoErr}
		}
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
		if payloadLen < 65536 { // minimal encoding again: this form starts at 64 KiB
			return wsDecoded{status: wsProtoErr}
		}
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

// wsCovName is what one decode DID, in the terms the mutator should be steered by
// (fuzz_cov_test.go): the length form it took, the verdict it reached, and what class of
// frame it read — never a length or a payload.
func covMarkWsDecode(expectMasked bool, buf, out []byte, n int64) {
	if len(buf) >= 1 {
		// The opcode by CLASS. Sixteen of them would be sixteen milestones for one decode
		// path, which is the fuzzer spending its corpus on a nibble it already reaches.
		// Read off the INPUT rather than the answer, so a refusal is marked by what it
		// refused — a reserved opcode and a set RSV bit both answer "protocol error" and
		// have no other state of their own to be seen by.
		switch op := buf[0] & 0x0f; {
		case op <= 2:
			covMark(covWsOpData)
		case op >= 8 && op <= 10:
			covMark(covWsOpControl)
		default:
			covMark(covWsOpReserved)
		}
		covMarkIf(buf[0]&0x70 != 0, covWsRsvSet)
		covMarkIf(buf[0]&0x80 == 0, covWsFragment)
	}
	if len(buf) >= 2 {
		switch buf[1] & 0x7f {
		case 126:
			covMark(covWsLenU16)
		case 127:
			covMark(covWsLenU64)
		default:
			covMark(covWsLen7)
		}
		// Only a frame whose mask direction is the one this end expects reaches the unmask
		// loop; the other is refused on the header.
		masked := buf[1]&0x80 != 0
		covMarkIf(masked && masked == expectMasked, covWsMasked)
	}
	switch int(out[0]) {
	case wsNeedMore:
		covMark(covWsNeedMore)
	case wsFrame:
		covMark(covWsFrame)
	case wsProtoErr:
		covMark(covWsProtoErr)
	}
	covMarkIf(n > int64(wsDecodeHeaderSize), covWsPayload)
}

// FuzzWsDecodeOne is the pre-auth frame decoder. Everything a browser edge sends before
// the handshake completes lands here first.
func FuzzWsDecodeOne(f *testing.F) {
	w := wsModule(f)
	f.Add(byte(0), []byte{0x82, 0x03, 1, 2, 3})                            // unmasked binary
	f.Add(byte(1), []byte{0x82, 0x83, 9, 9, 9, 9, 1, 2, 3})                // masked binary
	f.Add(byte(0), []byte{0x82, 0x7f, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}) // 4 GiB claim
	f.Add(byte(0), []byte{0x02, 0x00})                                     // fragmented data
	f.Add(byte(0), []byte{0x08, 0x00})                                     // fragmented control
	f.Add(byte(0), []byte{0x82})
	f.Add(byte(0), []byte{})
	// The two extended length forms at the smallest value each is allowed to spell, which
	// is the only way to reach them at all now that a shorter form that fits is a refusal.
	f.Add(byte(0), append([]byte{0x82, 0x7e, 0x00, 0x7e}, make([]byte, 126)...))
	f.Add(byte(0), append([]byte{0x82, 0x7f, 0, 0, 0, 0, 0, 1, 0, 0}, make([]byte, 65536)...))
	// …and the same two spelled one form too wide: a length RFC 6455 §5.2 says must have
	// been written in fewer bytes, which is one frame with two encodings.
	f.Add(byte(0), []byte{0x82, 0x7e, 0x00, 0x02, 1, 2})
	f.Add(byte(0), []byte{0x82, 0x7f, 0, 0, 0, 0, 0, 0, 0, 2, 1, 2})
	// An extension bit set with no extension negotiated, and an opcode that names nothing:
	// two frames whose payload a decoder that read on would be inventing.
	f.Add(byte(0), []byte{0x92, 0x00})
	f.Add(byte(0), []byte{0x83, 0x00})
	// A control frame too big to be one, and a close carrying half a status code — the two
	// §5.5 refusals that are settled from the first two bytes.
	f.Add(byte(0), []byte{0x89, 0x7e, 0x00, 0x7e})
	f.Add(byte(0), []byte{0x88, 0x01, 0x03})

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
		covMarkWsDecode(expectMasked, buf, out, n)
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
	f.Add(byte(0), byte(0), []byte("hello"))
	f.Add(byte(0), byte(1), []byte("hello"))
	f.Add(byte(2), byte(1), []byte{})                       // an empty pong
	f.Add(byte(1), byte(0), []byte{0x03, 0xe8})             // the close the framer sends
	f.Add(byte(0), byte(0), bytes.Repeat([]byte("x"), 125)) // the length-form boundaries
	f.Add(byte(0), byte(0), bytes.Repeat([]byte("x"), 126))
	f.Add(byte(0), byte(0), bytes.Repeat([]byte("x"), 65535))
	f.Add(byte(0), byte(0), bytes.Repeat([]byte("x"), 65536))

	f.Fuzz(func(t *testing.T, opChoice, maskFlag byte, payload []byte) {
		// [op][opcode][maskFlag][mask 4?][payload] in, at most a full frame out.
		if len(payload) > wsScratchSize/2 {
			t.Skip()
		}
		// The encoder writes whatever nibble it is handed, so the constraint here is the
		// CALLER's, not the module's: framing.js asks for these three opcodes and, on the
		// two control ones, for a payload RFC 6455 §5.5 lets a control frame carry. A round
		// trip over anything else asserts that the decoder reads back a frame the transport
		// has no way to send — and the decoder, correctly, refuses it instead.
		opcode := wsEncodeOpcodes[int(opChoice)%len(wsEncodeOpcodes)]
		if opcode >= 0x8 && len(payload) > wsMaxControlPayload {
			payload = payload[:wsMaxControlPayload]
		}
		if opcode == 0x8 && len(payload) == 1 {
			payload = payload[:0] // half a close status code is not a close body (§5.5.1)
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
		switch outHeader {
		case 2:
			covMark(covWsEncHead2)
		case 4:
			covMark(covWsEncHead4)
		default:
			covMark(covWsEncHead10)
		}
		covMarkIf(masked, covWsEncMasked)
		covMarkIf(opcode >= 0x8, covWsEncControl)
		covMarkIf(n == 0, covWsEncRefused)
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
		if !want.fin || want.opcode != opcode {
			t.Fatalf("encode: round trip gave fin=%v opcode=%d, want fin=true opcode=%d",
				want.fin, want.opcode, opcode)
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
