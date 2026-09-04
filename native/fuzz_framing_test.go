//go:build fuzz

package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"seedloader/qjs"
)

// ── fuzzing the transport's own inbound framing (§12.1, §12.6) ───────────────
//
// Everything below runs on an ACCEPTING link before the AKE knows who is on it, and a
// node holds up to `maxHalfOpenUnverified` of these at once — so this is the widest
// pre-auth surface the kernel has. What arrives is not messages but arbitrary slices of a
// byte stream, and the sender chooses the split: `ByteParts` reassembles them behind a
// growable accumulator with its own head/tail arithmetic, and both framers read their
// lengths out of the result.
//
// The property under test is CHUNK-BOUNDARY INDEPENDENCE: one byte stream must decode to
// the same messages however the sender cuts it up. It is the right property because it
// needs no second implementation of the codecs, and because every reassembly bug — a
// dropped accumulator, a mis-compacted head, a length read across a slice edge — breaks
// it by construction. `LengthFramer` additionally gets a Go oracle, since its format is
// four bytes and a body.
//
// The framers are the SIGNED transport bundle's own, lifted out of the blob the host
// embeds and evaluated in a function scope with the config it really ships under. Nothing
// here is a copy of them.

// framingFuzzJS stands the transport guest's framing layer up on its own.
//
// The guest source is one concatenated program: wrapping it in a function gives the
// framers their module scope (`maxFrameBytes`, `MAX_HANDSHAKE_FRAME_BYTES`, the ws ABI
// numbers) without evaluating it as this realm's globals, and `start()` is lazy, so
// nothing reaches for a host until an op is dispatched — which these targets never do.
const framingFuzzJS = `
"use strict";
{
  const enc0 = new TextEncoder(), dec0 = new TextDecoder();
  const fz = (o) => enc0.encode(JSON.stringify(o));
  const hex = (b) => Array.prototype.map.call(b, (x) => x.toString(16).padStart(2, "0")).join("");
  // The harness's own two numbers, published through __framingCaps below so the probe and
  // the oracle cannot drift apart on them: the authority a dialled link puts in its Host
  // header, and the ceiling on how much one ByteParts program may push.
  const FUZZ_AUTHORITY = "fuzz.example:443";
  const BYTEPARTS_BUDGET = 1 << 20;

  const blob = transportBundleBytes();
  const src = dec0.decode(unpackBundle(blob)["guest.js"]);
  // The author's own signed configuration, so the caps these framers apply are the caps a
  // deployment runs under rather than numbers this test picked.
  const APP = verifyBundle(sodium, blob).manifest.guest.config;
  const LOCAL = { networkKey: "00".repeat(32), peers: [], admitPeers: [] };
  // The one host name the framers reach: their own ws.wasm, run by Go over the §4 ABI.
  const host = { call: async (name, bytes) => {
    if (name === "ws") return new Uint8Array(__wsRun(bytes));
    // The dialling half draws its Sec-WebSocket-Key and every outbound mask from here.
    // Fixed, and a function of the offset alone, so the head a client writes and the masks
    // it applies are values the oracle COMPUTES rather than reads back off the framer.
    if (name === "node/random") {
      const n = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
      const out = new Uint8Array(n);
      for (let i = 0; i < n; i++) out[i] = i & 0xff;
      return out;
    }
    throw new Error("fuzz: transport framing called " + name);
  } };
  const F = new Function("APP", "LOCAL", "host", src +
    "\nreturn { ByteParts, LengthFramer, WsFramer, MAX_HANDSHAKE_FRAME_BYTES, maxFrameBytes, MAX_WS_HANDSHAKE };"
  )(APP, LOCAL, host);

  // Cut a stream at the sizes the fuzzer chose, each a big-endian uint16. A byte apiece
  // could not ask for a chunk over 255, which put the 8 KiB accumulator boundary — the one
  // size at which ByteParts changes strategy — out of a split's reach. A zero-length piece
  // is dropped by ByteParts.push, so the splits only ever describe real slices.
  const cut = (stream, splits) => {
    const out = [];
    let off = 0;
    for (let i = 0; i + 1 < splits.length; i += 2) {
      const take = Math.min((splits[i] << 8) | splits[i + 1], stream.length - off);
      if (take > 0) out.push(stream.subarray(off, off + take));
      off += take;
      if (off >= stream.length) break;
    }
    if (off < stream.length) out.push(stream.subarray(off));
    return out;
  };

  // Feed one chunking to a LengthFramer and report what came out. Synchronous: this
  // framer neither calls the host nor writes.
  globalThis.__fuzzLengthFramer = (streamAB, splitsAB) => {
    const stream = new Uint8Array(streamAB);
    const framer = new F.LengthFramer(() => Promise.resolve());
    const msgs = [];
    let ok = true;
    for (const chunk of cut(stream, new Uint8Array(splitsAB))) {
      ok = framer.push(chunk, (m) => msgs.push(hex(m)));
      if (!ok) break;
    }
    return fz({ ok, msgs, cap: framer.cap });
  };

  // The same for the server side of the WebSocket framer: the HTTP upgrade head, then
  // RFC 6455 frames, all of it before anyone is authenticated. Async because every frame
  // is a module call.
  globalThis.__fuzzWsFramer = async (streamAB, splitsAB) => {
    const stream = new Uint8Array(streamAB);
    const wrote = [];
    const framer = new F.WsFramer((b) => { wrote.push(hex(b)); return Promise.resolve(); }, false, "");
    framer.opened.catch(() => {});
    const msgs = [];
    let ok = true;
    for (const chunk of cut(stream, new Uint8Array(splitsAB))) {
      try { ok = await framer.push(chunk, (m) => msgs.push(hex(m))); }
      catch (e) { return fz({ threw: true, msg: String(e && e.message || e) }); }
      if (!ok) break;
    }
    return fz({ ok, msgs, wrote, open: framer.open, held: framer.parts.length });
  };

  // The dialling half of the same class, which nothing reached before: it writes the GET,
  // then holds every byte the SERVER sends against an accept value it computed itself.
  globalThis.__fuzzWsClient = async (streamAB, splitsAB) => {
    const stream = new Uint8Array(streamAB);
    const wrote = [];
    const framer = new F.WsFramer((b) => { wrote.push(hex(b)); return Promise.resolve(); }, true, FUZZ_AUTHORITY);
    framer.opened.catch(() => {});
    // The GET is put on a later turn. Awaiting it here only makes that turn happen before
    // the first chunk rather than during it, so an empty stream still shows the write.
    await framer.prepared;
    const msgs = [];
    let ok = true;
    for (const chunk of cut(stream, new Uint8Array(splitsAB))) {
      try { ok = await framer.push(chunk, (m) => msgs.push(hex(m))); }
      catch (e) { return fz({ threw: true, msg: String(e && e.message || e) }); }
      if (!ok) break;
    }
    return fz({ ok, msgs, wrote, open: framer.open, held: framer.parts.length });
  };

  // ByteParts on its own, as a state machine. The framers reach it only through the shapes
  // their two formats happen to ask for; this asks directly, so accumulator replacement,
  // partial consumption, head compaction and scan invalidation are reached deliberately
  // rather than by luck. What is reported is exactly what a caller can see — length, what
  // peek and take hand back, where findHeadEnd points — so agreement is agreement
  // about the contract, and the arithmetic behind it stays free to change.
  globalThis.__fuzzByteParts = (dataAB, progAB) => {
    const data = new Uint8Array(dataAB), prog = new Uint8Array(progAB);
    const bp = new F.ByteParts();
    const log = [];
    let off = 0, pushed = 0;
    for (let i = 0; i + 2 < prog.length; i += 3) {
      const arg = (prog[i + 1] << 8) | prog[i + 2];
      switch (prog[i] & 3) {
        case 0: {
          // A chunk of arg bytes cycled out of data, so every SIZE is reachable however
          // short the fuzzer's data is — 8191, 8192 and 8193 included.
          if (data.length === 0 || pushed + arg > BYTEPARTS_BUDGET) break;
          const chunk = new Uint8Array(arg);
          for (let k = 0; k < arg; k++) chunk[k] = data[(off + k) % data.length];
          off = (off + arg) % data.length;
          pushed += arg;
          bp.push(chunk);
          log.push("push " + arg + " len=" + bp.length);
          break;
        }
        case 1:
          log.push("peek " + arg + " " + hex(bp.peek(arg)) + " len=" + bp.length);
          break;
        case 2: {
          // Clamped: take past what is buffered reads a slice that is not there, and no
          // caller asks for more than a length it has already checked.
          const n = Math.min(arg, bp.length);
          log.push("take " + n + " " + hex(bp.take(n)) + " len=" + bp.length);
          break;
        }
        default:
          log.push("find " + bp.findHeadEnd() + " len=" + bp.length);
          break;
      }
    }
    return fz({ log, rest: hex(bp.peek(bp.length)), len: bp.length });
  };

  // The caps as the module scope DECLARES them — never as a framer instance reports its
  // own. An oracle handed the instance's number would let a wrong cap validate itself. The
  // last two are the HARNESS's own choices, published through the same call so the probe
  // and the oracle cannot drift apart on them.
  globalThis.__framingCaps = () => fz({
    handshake: F.MAX_HANDSHAKE_FRAME_BYTES, frame: F.maxFrameBytes, head: F.MAX_WS_HANDSHAKE,
    authority: FUZZ_AUTHORITY, budget: BYTEPARTS_BUDGET,
  });

  // One accepting link fed a fixed slice size, whose upgrade head never completes —
  // what a stranger costs this realm before it has said who it is. Separate from the fuzz
  // probe because the subject is the chunk SIZE, which byte splits cannot express past 255.
  globalThis.__benchWsHead = async (streamAB, chunk) => {
    const stream = new Uint8Array(streamAB);
    const framer = new F.WsFramer(() => Promise.resolve(), false, "");
    framer.opened.catch(() => {});
    let ok = true;
    for (let off = 0; off < stream.length && ok; off += chunk) {
      ok = await framer.push(stream.subarray(off, Math.min(off + chunk, stream.length)), () => {});
    }
    return fz({ ok });
  };
}
`

// framingResult is one run of one framer over one chunking.
type framingResult struct {
	Ok    bool     `json:"ok"`
	Threw bool     `json:"threw"`
	Msg   string   `json:"msg"`
	Msgs  []string `json:"msgs"`
	Wrote []string `json:"wrote"`
	Open  bool     `json:"open"`
	Held  int      `json:"held"`
	Cap   int      `json:"cap"`
	Log   []string `json:"log"`  // ByteParts: one line per operation
	Rest  string   `json:"rest"` // ByteParts: whatever is still buffered, in hex
	Len   int      `json:"len"`
}

// framingFuzzRealm boots the realm, hangs ws.wasm off it as the framers' one host name,
// and evaluates the transport guest's framing layer in its own scope.
func framingFuzzRealm(f testing.TB) {
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
	// The framers' `host.call("ws", …)` — the real module over the real §4 ABI, so the
	// pair under test is the pair that ships.
	qc.Global().SetPropertyStr("__wsRun", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		req, err := qjs.JsTypedArrayToGo(t.Args()[0])
		if err != nil {
			return nil, err
		}
		return bytesAB(t, callModuleRaw(w, req)), nil
	}))
	if _, err := qc.Eval("fuzz-framing.js", qjs.Code(framingFuzzJS)); err != nil {
		f.Fatal("transport framing scope:", err)
	}
	out, err := callRealm("__framingCaps", 20*time.Second)
	if err != nil {
		f.Fatal("framing caps:", err)
	}
	if err := json.Unmarshal(out, &framingCaps); err != nil {
		f.Fatal("framing caps:", err)
	}
}

// framingCaps is the two-stage inbound ceiling as the transport's own module scope
// declares it: the pre-authentication cap every accepting link starts at, and the raised
// one an authenticated link gets. Read ONCE, from the scope rather than from a framer, so
// the oracle's number and the framer's are independent.
var framingCaps struct {
	Handshake int    `json:"handshake"`
	Frame     int    `json:"frame"`
	Head      int    `json:"head"`
	Authority string `json:"authority"`
	Budget    int    `json:"budget"`
}

// ── the browser edge, as a second implementation ─────────────────────────────
//
// refWsPeer is framing.js's WsFramer, written from RFC 6455 and the two rules the transport
// adds on top of it — the head ceiling, and one cap on every frame — rather than from that
// class. Split-versus-unsplit agreement, which is all a target asserts on its own, is
// satisfied by a framer that consistently does the WRONG thing; this says what the right
// thing is. The frame decode itself is refDecodeOne, already the oracle FuzzWsDecodeOne
// holds ws.wasm to.
//
// Both halves are one type because the class is one class: only the handshake differs —
// answer a key, or check the answer to one — and the mask direction with it. The cap, the
// continuation rules and the pong are shared code on both sides, so they are modelled once.
type refWsPeer struct {
	client bool   // the dialling half: it reads the 101 rather than writing one
	accept string // client: the Sec-WebSocket-Accept its own key demands back
	buf    []byte
	open   bool
	wrote  []string // hex of each write this end put on the wire
	msgs   []string // hex of each message delivered up
	frag   int      // opcode of an in-flight fragmented message, or -1
	frags  []byte
}

func newRefWsServer() *refWsPeer { return &refWsPeer{frag: -1} }

// newRefWsClient starts where the constructor does. The key is the probe's deterministic
// randomness, so the GET this end has already written and the accept value it will demand
// are both computed here rather than read back off the framer.
func newRefWsClient() *refWsPeer {
	key := base64.StdEncoding.EncodeToString(fuzzRandomBytes(16))
	sum := sha1.Sum([]byte(key + wsHandshakeGUID))
	c := &refWsPeer{client: true, accept: base64.StdEncoding.EncodeToString(sum[:]), frag: -1}
	c.wrote = append(c.wrote, hexOf([]byte("GET / HTTP/1.1\r\nHost: "+framingCaps.Authority+"\r\n"+
		"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: "+key+"\r\nSec-WebSocket-Version: 13\r\n\r\n")))
	return c
}

// fuzzRandomBytes is the probe's `node/random`: byte i is i.
func fuzzRandomBytes(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

// push feeds one chunk and answers what `read` answers: false is a protocol refusal the
// link owner turns into a teardown.
func (s *refWsPeer) push(chunk []byte) bool {
	s.buf = append(s.buf, chunk...)
	if !s.open {
		sep := bytes.Index(s.buf, []byte("\r\n\r\n"))
		if sep < 0 {
			// Not a head yet. A peer may make this link hold only so much while it says
			// nothing — the one thing an unauthenticated stranger can spend here.
			return len(s.buf) <= framingCaps.Head
		}
		// A head that IS terminated is held to the same ceiling, so what the bound measures
		// is the head rather than where the sender happened to cut it.
		if sep+4 > framingCaps.Head {
			return false
		}
		if !s.upgrade(s.buf[:sep]) {
			return false
		}
		s.buf = s.buf[sep+4:]
		s.open = true
	}
	for {
		total := refFrameLength(s.buf)
		if total < 0 {
			return true
		}
		// Measured on the DECLARED length, before the frame has arrived: a peer that
		// announces an over-cap frame is refused on the header, never after buffering it.
		if total > framingCaps.Handshake {
			return false
		}
		if len(s.buf) < total {
			return true
		}
		whole := s.buf[:total]
		s.buf = s.buf[total:]
		// A server reads masked frames and a client unmasked ones, and nothing else
		// (RFC 6455 §5.3).
		d := refDecodeOne(!s.client, whole)
		if d.status != wsFrame {
			return false
		}
		if !s.step(d) {
			return false
		}
	}
}

// upgrade is the one half that differs: a server answers the key it was sent, a client
// checks the answer to the key it sent.
func (s *refWsPeer) upgrade(head []byte) bool {
	if s.client {
		// `HTTP/1.1 101` ANYWHERE in the head — the status line is matched, not parsed —
		// and then the accept value byte for byte.
		return bytes.Contains(head, []byte("HTTP/1.1 101")) &&
			refHeaderValue(head, "sec-websocket-accept") == s.accept
	}
	key := refHeaderValue(head, "sec-websocket-key")
	if key == "" {
		return false
	}
	sum := sha1.Sum(append([]byte(key), []byte(wsHandshakeGUID)...))
	s.wrote = append(s.wrote, hexOf([]byte("HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: "+base64.StdEncoding.EncodeToString(sum[:])+"\r\n\r\n")))
	return true
}

// step applies RFC 6455 §5.4's continuation rules and then delivers.
func (s *refWsPeer) step(d wsDecoded) bool {
	switch {
	case d.opcode == 0x0: // continuation
		if s.frag < 0 {
			return false
		}
		if len(s.frags)+len(d.payload) > framingCaps.Handshake {
			return false
		}
		s.frags = append(s.frags, d.payload...)
		if !d.fin {
			return true
		}
		first, msg := s.frag, s.frags
		s.frag, s.frags = -1, nil
		return s.deliver(first, msg)
	case !d.fin: // the first fragment of a data message
		if s.frag >= 0 {
			return false
		}
		s.frag, s.frags = int(d.opcode), append([]byte(nil), d.payload...)
		return true
	default:
		// A data frame may not preempt an in-flight fragmented message; control frames
		// interleave freely.
		if d.opcode < 0x8 && s.frag >= 0 {
			return false
		}
		return s.deliver(int(d.opcode), d.payload)
	}
}

func (s *refWsPeer) deliver(opcode int, payload []byte) bool {
	switch opcode {
	case 0x2: // binary — the only opcode that carries a message up
		s.msgs = append(s.msgs, hexOf(payload))
	case 0x9: // ping — answered with a pong of the same payload, framed as this end frames
		s.wrote = append(s.wrote, hexOf(refWsEncode(s.client, 0xa, payload)))
	case 0x8: // close
		return false
	}
	return true
}

// refWsEncode frames one message the way this end writes it: FIN set, the shortest length
// form RFC 6455 allows, masked client→server and not server→client.
func refWsEncode(masked bool, opcode byte, payload []byte) []byte {
	flag := byte(0)
	if masked {
		flag = 0x80
	}
	out := []byte{0x80 | (opcode & 0x0f)}
	switch n := len(payload); {
	case n < 126:
		out = append(out, flag|byte(n))
	case n < 65536:
		out = binary.BigEndian.AppendUint16(append(out, flag|126), uint16(n))
	default:
		out = binary.BigEndian.AppendUint64(append(out, flag|127), uint64(n))
	}
	if !masked {
		return append(out, payload...)
	}
	mask := fuzzRandomBytes(4)
	out = append(out, mask...)
	for i, c := range payload {
		out = append(out, c^mask[i&3])
	}
	return out
}

// refHeaderValue is `headerValue` in framing.js — the first line of the head whose name
// matches case-insensitively and whose value is not empty once the spaces and tabs around
// it are gone, under its regex `^name:[ \t]*(?![ \t])(.+?)[ \t]*$`. Lines break at any JS
// line terminator, because that regex runs on a decoded string and `.` does not cross one:
// a head split by a bare CR is two lines to it, not one — which is also why a line's
// remainder here can never contain one, and why trimming is all this has to do.
func refHeaderValue(head []byte, name string) string {
	for _, line := range splitJSLines(string(head)) {
		if len(line) < len(name)+1 || !strings.EqualFold(line[:len(name)], name) || line[len(name)] != ':' {
			continue
		}
		// A field with no value is not a field: the line does not match, and the scan goes
		// on to the next exactly as it does for a name that never matched at all.
		if v := strings.Trim(line[len(name)+1:], " \t"); v != "" {
			return v
		}
	}
	return ""
}

// splitJSLines cuts at the four terminators a JS regex's `^`/`$` recognise in multiline
// mode: LF, CR, and the two Unicode separators.
func splitJSLines(s string) []string {
	out := []string{}
	start := 0
	for i, r := range s {
		if r == '\n' || r == '\r' || r == ' ' || r == ' ' {
			out = append(out, s[start:i])
			start = i + utf8.RuneLen(r)
		}
	}
	return append(out, s[start:])
}

// refFrameLength sizes the wait exactly as `frameLength` does — from the unvalidated
// header, with all real validation left to the decode. -1 means "not enough to know yet".
func refFrameLength(buf []byte) int {
	if len(buf) < 2 {
		return -1
	}
	masked := buf[1]&0x80 != 0
	len7 := int(buf[1] & 0x7f)
	headerLen, payloadLen := 2, len7
	switch len7 {
	case 126:
		if len(buf) < 4 {
			return -1
		}
		headerLen, payloadLen = 4, int(binary.BigEndian.Uint16(buf[2:4]))
	case 127:
		if len(buf) < 10 {
			return -1
		}
		if binary.BigEndian.Uint32(buf[2:6]) != 0 {
			return 0x7fffffff // over 4 GiB: over any cap
		}
		headerLen, payloadLen = 10, int(binary.BigEndian.Uint32(buf[6:10]))
	}
	if masked {
		headerLen += 4
	}
	return headerLen + payloadLen
}

// callModuleRaw is callModule's body without the table lookup: stage, call, read back,
// clamped to the reserved scratch exactly as the production host clamps it.
func callModuleRaw(w *boundModule, req []byte) []byte {
	mem := w.mod.Memory()
	if uint32(len(req)) > w.size || !mem.Write(w.scratch, req) {
		return nil
	}
	r, err := w.fn.Call(ctx, uint64(len(req)))
	if err != nil || len(r) == 0 {
		return nil
	}
	n := int32(r[0])
	if n < 0 || uint32(n) > w.size {
		return nil
	}
	b, ok := mem.Read(w.scratch, uint32(n))
	if !ok {
		return nil
	}
	return bytes.Clone(b)
}

// framingRun drives one probe over one chunking of one stream.
func framingRun(t *testing.T, probe string, stream, splits []byte) framingResult {
	t.Helper()
	out, err := callRealm(probe, 30*time.Second,
		qc.NewArrayBuffer(stream), qc.NewArrayBuffer(splits))
	if err != nil {
		t.Fatalf("%s: the realm itself failed on a %d-byte stream: %v\nstream: %x",
			probe, len(stream), err, head(stream))
	}
	var r framingResult
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("%s: undecodable answer %q: %v", probe, out, err)
	}
	return r
}

// refLengthFrames is the oracle for the length-prefixed codec: [len u32][body], repeated,
// refused when a declared length is over the cap. Written from the wire format, not from
// the framer.
func refLengthFrames(stream []byte, cap int) (msgs []string, ok bool) {
	off := 0
	for {
		if len(stream)-off < 4 {
			return msgs, true
		}
		n := int64(binary.BigEndian.Uint32(stream[off:]))
		if n > int64(cap) {
			return msgs, false
		}
		if int64(len(stream)-off-4) < n {
			return msgs, true
		}
		msgs = append(msgs, hexOf(stream[off+4:off+4+int(n)]))
		off += 4 + int(n)
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

// FuzzLengthFramer is the codec every raw TCP link and every RTC data channel uses. The
// stream and the split are both the sender's, so both are fuzzed.
func FuzzLengthFramer(f *testing.F) {
	framingFuzzRealm(f)
	f.Add([]byte{0, 0, 0, 3, 1, 2, 3}, splitsOf())
	f.Add([]byte{0, 0, 0, 3, 1, 2, 3}, splitsOf(1, 1, 1, 1, 1, 1, 1))
	f.Add([]byte{0, 0, 0, 0}, splitsOf(2))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}, splitsOf())
	f.Add(append([]byte{0, 0, 0x20, 0x01}, make([]byte, 8193)...), splitsOf(4))
	f.Add(bytes.Repeat([]byte{0, 0, 0, 1, 0x41}, 200), splitsOf(3, 7, 1, 9))
	f.Add([]byte{}, splitsOf())
	// A message that spans the accumulator boundary, cut on it — a size no byte-wide
	// split could ask for.
	f.Add(append([]byte{0, 0, 0x20, 0x00}, make([]byte, 8192)...), splitsOf(8191, 1, 4, 8192))

	f.Fuzz(func(t *testing.T, stream, splits []byte) {
		if len(stream) > 1<<20 {
			t.Skip()
		}
		got := framingRun(t, "__fuzzLengthFramer", stream, splits)
		// The framer's own cap, held against the scope's. Feeding `got.Cap` into the oracle
		// instead would let a framer that started life with the WRONG ceiling — the raised
		// one, say, on a link nobody has authenticated — agree with itself all the way.
		if got.Cap != framingCaps.Handshake {
			t.Fatalf("LengthFramer: a fresh framer's cap is %d, but a pre-authentication link's is %d",
				got.Cap, framingCaps.Handshake)
		}
		wantMsgs, wantOk := refLengthFrames(stream, framingCaps.Handshake)
		if got.Ok != wantOk {
			t.Fatalf("LengthFramer: returned ok=%v, the wire format says %v — stream %d bytes: %x",
				got.Ok, wantOk, len(stream), head(stream))
		}
		if !sameStrings(got.Msgs, wantMsgs) {
			t.Fatalf("LengthFramer: delivered %v, the wire format says %v — stream %d bytes, splits %v: %x",
				got.Msgs, wantMsgs, len(stream), head(splits), head(stream))
		}
		// One stream, one message sequence — however the sender cut it. This is the
		// assertion that reaches ByteParts' accumulator and head-compaction arithmetic,
		// which no single chunking exercises on its own.
		whole := framingRun(t, "__fuzzLengthFramer", stream, nil)
		if whole.Ok != got.Ok || !sameStrings(whole.Msgs, got.Msgs) {
			t.Fatalf("LengthFramer: the split changed the parse — split %v gave ok=%v %v, one chunk gave ok=%v %v; stream %d bytes: %x",
				head(splits), got.Ok, got.Msgs, whole.Ok, whole.Msgs, len(stream), head(stream))
		}
	})
}

// FuzzWsFramer is the browser edge: an HTTP upgrade head this node answers, then RFC 6455
// frames, all before the AKE has authenticated anyone. Server side, since that is the one
// a stranger reaches.
func FuzzWsFramer(f *testing.F) {
	framingFuzzRealm(f)
	upgrade := []byte("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	f.Add(upgrade, splitsOf())
	f.Add(upgrade, splitsOf(1, 1, 1, 1, 1, 1, 1, 1))
	f.Add(append(bytes.Clone(upgrade), 0x82, 0x83, 9, 9, 9, 9, 1, 2, 3), splitsOf())
	f.Add(append(bytes.Clone(upgrade), 0x82, 0x83, 9, 9, 9, 9, 1, 2, 3), splitsOf(70, 3, 2, 1))
	f.Add(append(bytes.Clone(upgrade), 0x89, 0x80, 1, 2, 3, 4), splitsOf()) // ping
	f.Add(append(bytes.Clone(upgrade), 0x88, 0x80, 1, 2, 3, 4), splitsOf()) // close
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"), splitsOf())
	f.Add([]byte("\r\n\r\n"), splitsOf())
	f.Add([]byte{}, splitsOf())
	// A key that is only whitespace, spelled in mixed case. The header regex used to
	// backtrack far enough to yield one of those spaces, so this COMPLETED an upgrade; a
	// value with no character in it is no value now, and this is the refusal it always
	// should have been. Found by the fuzzer.
	f.Add([]byte("Sec-WeBSoCket-KeY:  \r\n\r\n"), splitsOf())
	// The name with nothing after the colon at all, which does not match — and a real key
	// on a later line, which the scan must still reach.
	f.Add([]byte("Sec-WebSocket-Key:\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"), splitsOf())
	// A value that is only spaces is the same thing said differently: the line does not
	// match, and the real key below it is what the upgrade uses.
	f.Add([]byte("Sec-WebSocket-Key:   \r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"), splitsOf())
	// A head whose lines break on a bare CR rather than CRLF.
	f.Add([]byte("GET / HTTP/1.1\rSec-WebSocket-Key: abc\r\n\r\n"), splitsOf())
	// A complete, otherwise valid head past the ceiling. The bound used to be measured only
	// while the terminator was ABSENT, so a head of any size at all was taken whole — and
	// the same bytes were refused as soon as a chunk boundary fell before the terminator,
	// which made the ceiling the sender's to choose.
	big := append([]byte("GET / HTTP/1.1\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nX: "),
		bytes.Repeat([]byte("A"), framingCaps.Head)...)
	big = append(big, "\r\n\r\n"...)
	f.Add(big, splitsOf())
	f.Add(big, splitsOf(framingCaps.Head, 64))
	// The accumulator boundary, which a byte-wide split could not ask for.
	f.Add(append(bytes.Clone(upgrade), bytes.Repeat([]byte{0x82, 0x80, 1, 2, 3, 4}, 64)...),
		splitsOf(8191, 1, 8192, 8193))

	f.Fuzz(func(t *testing.T, stream, splits []byte) {
		if len(stream) > 1<<18 {
			t.Skip()
		}
		wsFramerProperties(t, "server", "__fuzzWsFramer", newRefWsServer, stream, splits)
	})
}

// FuzzWsClientFramer is the half a node runs when it DIALS. Having dialled an address is
// not evidence about who answers it — the AKE above is what settles that — so these bytes
// are a stranger's too, and this end holds a value of its own against them: the accept its
// key demands back, which nothing else checks.
func FuzzWsClientFramer(f *testing.F) {
	framingFuzzRealm(f)
	accept := newRefWsClient().accept
	ok101 := []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n")
	f.Add(ok101, splitsOf())
	f.Add(ok101, splitsOf(1, 1, 1, 1, 1, 1, 1, 1))
	// A server writes UNMASKED frames; a masked one is a violation this end refuses rather
	// than unmasks.
	f.Add(append(bytes.Clone(ok101), 0x82, 0x03, 1, 2, 3), splitsOf())
	f.Add(append(bytes.Clone(ok101), 0x82, 0x83, 9, 9, 9, 9, 1, 2, 3), splitsOf())
	f.Add(append(bytes.Clone(ok101), 0x89, 0x02, 7, 7), splitsOf()) // ping, answered masked
	f.Add(append(bytes.Clone(ok101), 0x88, 0x00), splitsOf())       // close
	f.Add([]byte("HTTP/1.1 101 Switching Protocols\r\n\r\n"), splitsOf())
	f.Add([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"), splitsOf())
	// The status line is matched anywhere in the head, so a header VALUE carrying it does
	// as well as a status line — the accept value is what this end really checks.
	f.Add([]byte("X: HTTP/1.1 101\r\nSec-WebSocket-Accept: "+accept+"\r\n\r\n"), splitsOf())
	f.Add([]byte{}, splitsOf())

	f.Fuzz(func(t *testing.T, stream, splits []byte) {
		if len(stream) > 1<<18 {
			t.Skip()
		}
		wsFramerProperties(t, "client", "__fuzzWsClient", newRefWsClient, stream, splits)
	})
}

// wsFramerProperties holds one probe to three separate things: that no refusal escaped as a
// throw, that the sender's chunking changed nothing, and that what came out is what RFC
// 6455 plus the transport's ceilings say. Both halves of the class are held to all three,
// so it is written once.
func wsFramerProperties(t *testing.T, side, probe string, newRef func() *refWsPeer, stream, splits []byte) {
	t.Helper()
	got := framingRun(t, probe, stream, splits)
	if got.Threw {
		// `read` catches the upgrade's and the frame loop's refusals itself and answers
		// false; anything escaping is a refusal the link owner never sees as a refusal.
		t.Fatalf("ws %s: threw out of push (%q) — stream %d bytes, splits %v: %x",
			side, got.Msg, len(stream), head(splits), head(stream))
	}
	whole := framingRun(t, probe, stream, nil)
	if whole.Threw {
		t.Fatalf("ws %s: threw out of push on one chunk (%q) — stream %d bytes: %x",
			side, whole.Msg, len(stream), head(stream))
	}
	if got.Ok != whole.Ok || got.Open != whole.Open {
		t.Fatalf("ws %s: the split changed the verdict — split %v gave ok=%v open=%v, one chunk gave ok=%v open=%v; stream %d bytes: %x",
			side, head(splits), got.Ok, got.Open, whole.Ok, whole.Open, len(stream), head(stream))
	}
	if !sameStrings(got.Msgs, whole.Msgs) {
		t.Fatalf("ws %s: the split changed the messages — split %v gave %v, one chunk gave %v; stream %d bytes: %x",
			side, head(splits), got.Msgs, whole.Msgs, len(stream), head(stream))
	}
	if !sameStrings(got.Wrote, whole.Wrote) {
		t.Fatalf("ws %s: the split changed what went back on the wire — split %v gave %v, one chunk gave %v; stream %d bytes: %x",
			side, head(splits), got.Wrote, whole.Wrote, len(stream), head(stream))
	}
	// Everything above is the framer agreeing with itself, which a framer that consistently
	// did the wrong thing would also satisfy. This is what the right answer IS: RFC 6455
	// plus the transport's two ceilings, written independently.
	//
	// The upgrade head is DECODED before it is read, so a head that is not valid UTF-8
	// reaches those regexes as replacement characters — a lossy step this oracle does not
	// invert. Frames are never decoded, so everything after the head is exact either way,
	// and the invariants above still cover the heads skipped here.
	if sep := bytes.Index(stream, []byte("\r\n\r\n")); sep >= 0 && !utf8.Valid(stream[:sep]) {
		return
	}
	ref := newRef()
	refOk := true
	for _, chunk := range cutStream(stream, splits) {
		if refOk = ref.push(chunk); !refOk {
			break
		}
	}
	if got.Ok != refOk {
		t.Fatalf("ws %s: answered ok=%v, RFC 6455 says %v — stream %d bytes, splits %v: %x",
			side, got.Ok, refOk, len(stream), head(splits), head(stream))
	}
	if !sameStrings(got.Msgs, ref.msgs) {
		t.Fatalf("ws %s: delivered %v, RFC 6455 says %v — stream %d bytes, splits %v: %x",
			side, got.Msgs, ref.msgs, len(stream), head(splits), head(stream))
	}
	// The handshake and every pong, byte for byte: this is what the node says back to a
	// stranger, so a divergence here is a divergence on the wire.
	if !sameStrings(got.Wrote, ref.wrote) {
		t.Fatalf("ws %s: wrote %v, RFC 6455 says %v — stream %d bytes, splits %v: %x",
			side, got.Wrote, ref.wrote, len(stream), head(splits), head(stream))
	}
}

// splitsOf encodes chunk sizes the way the probes read them: one big-endian uint16 each.
// The fuzzer mutates these bytes freely; this is for the seeds, which want to NAME a size —
// 8191, 8192, 8193 — rather than spell it.
func splitsOf(ns ...int) []byte {
	out := make([]byte, 0, len(ns)*2)
	for _, n := range ns {
		out = binary.BigEndian.AppendUint16(out, uint16(n))
	}
	return out
}

// cutStream is the JS probe's `cut`, so the oracle sees exactly the chunking the framer
// saw. A zero-length piece is dropped, as ByteParts.push drops it.
func cutStream(stream, splits []byte) [][]byte {
	out := [][]byte{}
	off := 0
	for i := 0; i+1 < len(splits); i += 2 {
		n := int(binary.BigEndian.Uint16(splits[i:]))
		if n > len(stream)-off {
			n = len(stream) - off
		}
		if n > 0 {
			out = append(out, stream[off:off+n])
		}
		off += n
		if off >= len(stream) {
			break
		}
	}
	if off < len(stream) {
		out = append(out, stream[off:])
	}
	return out
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ── the accumulator on its own ───────────────────────────────────────────────
//
// ByteParts is where every inbound byte of every link lands, and the only part of the
// transport that keeps a data structure rather than a parse: a list of slices, a head index
// into it, a growable tail, and a head-end scan that resumes across calls. The two framers
// reach it only through the shapes their formats ask for, which is not the same as reaching
// it — a length-prefixed stream never calls findHeadEnd at all, and neither format asks for
// a chunk sized to land on the accumulator boundary. This drives it directly.
//
// The oracle is a flat byte slice. It keeps ONE piece of state beyond the bytes — how far
// the head scan has read — because that is contract, not arithmetic: the scan resumes where
// it stopped, and `take` is what restarts it.

const (
	bpPush = 0
	bpPeek = 1
	bpTake = 2
	bpFind = 3
)

// bytePartsProg spells one program the way the probe reads it: an op byte and a big-endian
// uint16 argument, three bytes each, given here as alternating op and argument.
func bytePartsProg(opArg ...int) []byte {
	out := make([]byte, 0, len(opArg)/2*3)
	for i := 0; i+1 < len(opArg); i += 2 {
		out = binary.BigEndian.AppendUint16(append(out, byte(opArg[i])), uint16(opArg[i+1]))
	}
	return out
}

type refByteParts struct {
	buf     []byte
	scanned int // bytes the head scan has already read
}

func (b *refByteParts) push(chunk []byte) { b.buf = append(b.buf, chunk...) }

func (b *refByteParts) peek(n int) []byte { return b.buf[:min(n, len(b.buf))] }

func (b *refByteParts) take(n int) []byte {
	out := b.buf[:n]
	b.buf = b.buf[n:]
	// The scan's cursor indexed the bytes that just moved, so it starts over — for n=0 as
	// much as for any other n, which is what makes a no-op take observable at all.
	b.scanned = 0
	return out
}

// findHeadEnd resumes: a terminator is found by the byte that COMPLETES it, and only bytes
// the scan has not read yet can complete one. So a second call with no take in between
// answers about the rest of the buffer rather than about all of it.
func (b *refByteParts) findHeadEnd() int {
	for i := b.scanned; i < len(b.buf); i++ {
		b.scanned = i + 1
		if i >= 3 && b.buf[i-3] == 13 && b.buf[i-2] == 10 && b.buf[i-1] == 13 && b.buf[i] == 10 {
			return i - 3
		}
	}
	return -1
}

// refBytePartsRun is the probe's loop, op for op. The two must agree on which ops they SKIP
// as much as on what the rest answer, so the budget and the empty-data case are spelled the
// same way on both sides.
func refBytePartsRun(data, prog []byte) (log []string, rest string, length int) {
	b := &refByteParts{}
	log = []string{}
	off, pushed := 0, 0
	for i := 0; i+2 < len(prog); i += 3 {
		arg := int(binary.BigEndian.Uint16(prog[i+1:]))
		switch prog[i] & 3 {
		case bpPush:
			if len(data) == 0 || pushed+arg > framingCaps.Budget {
				break
			}
			chunk := make([]byte, arg)
			for k := range chunk {
				chunk[k] = data[(off+k)%len(data)]
			}
			off = (off + arg) % len(data)
			pushed += arg
			b.push(chunk)
			log = append(log, fmt.Sprintf("push %d len=%d", arg, len(b.buf)))
		case bpPeek:
			log = append(log, fmt.Sprintf("peek %d %s len=%d", arg, hexOf(b.peek(arg)), len(b.buf)))
		case bpTake:
			n := min(arg, len(b.buf))
			log = append(log, fmt.Sprintf("take %d %s len=%d", n, hexOf(b.take(n)), len(b.buf)))
		default:
			log = append(log, fmt.Sprintf("find %d len=%d", b.findHeadEnd(), len(b.buf)))
		}
	}
	return log, hexOf(b.buf), len(b.buf)
}

// FuzzByteParts is the reassembly buffer as a state machine.
func FuzzByteParts(f *testing.F) {
	framingFuzzRealm(f)
	f.Add([]byte("hello"), bytePartsProg(bpPush, 5, bpPeek, 5, bpTake, 5, bpPeek, 1))
	f.Add([]byte("\r\n\r\n"), bytePartsProg(bpFind, 0, bpPush, 4, bpFind, 0, bpFind, 0))
	// The head-end scan resuming across arrivals, with the terminator straddling several of
	// them: the four-byte window is the only thing that carries it over.
	f.Add([]byte("a\r\n\r\nb"), bytePartsProg(bpPush, 2, bpFind, 0, bpPush, 1, bpFind, 0,
		bpPush, 1, bpFind, 0, bpPush, 1, bpFind, 0, bpPush, 1, bpFind, 0))
	// The accumulator boundary from both sides, and the merge that follows it.
	f.Add([]byte("ab"), bytePartsProg(bpPush, 8191, bpPush, 1, bpPush, 1, bpPeek, 8193))
	f.Add([]byte("ab"), bytePartsProg(bpPush, 8192, bpPush, 8192, bpTake, 4, bpPeek, 16380))
	f.Add([]byte("ab"), bytePartsProg(bpPush, 8193, bpTake, 1, bpPush, 100, bpPeek, 8292))
	// A partial take out of the accumulator, then more pushes: the capacity behind a slice
	// that has been consumed from is no longer this buffer's to append into.
	f.Add([]byte("abcdef"), bytePartsProg(bpPush, 10, bpTake, 3, bpPush, 10, bpTake, 1, bpPush, 10, bpPeek, 26))
	// Enough takes to trip the head compaction, which moves every index at once.
	f.Add([]byte("xyz"), bytePartsProg(
		bpPush, 9000, bpPush, 2, bpPush, 2, bpPush, 2, bpPush, 2, bpPush, 2, bpPush, 2, bpPush, 2,
		bpTake, 9000, bpTake, 2, bpTake, 2, bpTake, 2, bpTake, 2, bpTake, 2, bpTake, 2, bpPeek, 4))
	f.Add([]byte{}, bytePartsProg(bpPush, 100, bpTake, 100, bpFind, 0))
	f.Add([]byte("q"), bytePartsProg(bpTake, 0, bpPeek, 9, bpFind, 0))

	f.Fuzz(func(t *testing.T, data, prog []byte) {
		// The probe reports the whole buffer after every peek and take, so a program costs
		// the square of what it holds; these bounds keep one iteration cheap enough that the
		// fuzzer spends its time on shapes rather than on bytes.
		if len(data) > 4096 || len(prog) > 3*64 {
			t.Skip()
		}
		out, err := callRealm("__fuzzByteParts", 60*time.Second,
			qc.NewArrayBuffer(data), qc.NewArrayBuffer(prog))
		if err != nil {
			t.Fatalf("__fuzzByteParts: the realm itself failed: %v\nprog: %x", err, head(prog))
		}
		var got framingResult
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatalf("__fuzzByteParts: undecodable answer %q: %v", out, err)
		}
		wantLog, wantRest, wantLen := refBytePartsRun(data, prog)
		if !sameStrings(got.Log, wantLog) {
			t.Fatalf("ByteParts: %s\nprog: %x\ndata %d bytes: %x",
				firstDiff(got.Log, wantLog), head(prog), len(data), head(data))
		}
		if got.Rest != wantRest || got.Len != wantLen {
			t.Fatalf("ByteParts: %d bytes left (%s), want %d (%s) — prog: %x",
				got.Len, got.Rest, wantLen, wantRest, head(prog))
		}
	})
}

// firstDiff names the operation the two disagree on, which is the only one worth printing:
// a program's log is as long as the program.
func firstDiff(got, want []string) string {
	for i := range max(len(got), len(want)) {
		g, w := "<end>", "<end>"
		if i < len(got) {
			g = got[i]
		}
		if i < len(want) {
			w = want[i]
		}
		if g != w {
			return fmt.Sprintf("op %d gave %q, the contract says %q", i, g, w)
		}
	}
	return "logs agree"
}

// wsHeadAmplificationBound is how much more a 16 KiB head may cost dribbled one byte at a
// time than delivered whole. A scan that restarts at the front costs n²/2 byte steps and
// measured ~6800× (25 s against 3.7 ms); a scan that resumes leaves only per-push overhead,
// which is linear in the number of pushes and measures ~40× for 16384 of them against one.
// The bound sits an order of magnitude above what a resumed scan costs and more than an
// order below what a restarted one does.
const wsHeadAmplificationBound = 500

// TestWsHandshakeHeadScansOnce is BenchmarkWsHandshakeHead's finding, as something that
// fails. A benchmark measures the amplification but nothing about it goes red when the scan
// stops resuming, so on its own the discovery would survive as a number nobody reads.
//
// The assertion is a RATIO — the same head, both ways, in the same realm on the same
// machine — so machine speed cancels out of both sides and what is left is the shape of the
// scan. This is the property findHeadEnd's comment claims: the head is scanned once,
// however it arrives.
func TestWsHandshakeHeadScansOnce(t *testing.T) {
	framingFuzzRealm(t)
	// A head one byte under the ceiling with no CRLFCRLF in it: the most an accepting link
	// will hold for a peer that has not said who it is.
	stream := bytes.Repeat([]byte("A"), framingCaps.Head-1)
	// Best of three. The realm is shared and this machine moves work between cores, so the
	// fastest run is the one least contaminated by that — and a floor is the right summary
	// when the assertion is an upper bound.
	feed := func(chunk int) time.Duration {
		t.Helper()
		best := time.Duration(0)
		for i := 0; i < 3; i++ {
			start := time.Now()
			if _, err := callRealm("__benchWsHead", 120*time.Second,
				qc.NewArrayBuffer(stream), qc.NewInt64(int64(chunk))); err != nil {
				t.Fatal(err)
			}
			if d := time.Since(start); best == 0 || d < best {
				best = d
			}
		}
		return best
	}
	whole := feed(len(stream))
	dribbled := feed(1)
	if ratio := float64(dribbled) / float64(whole); ratio > wsHeadAmplificationBound {
		t.Fatalf("a %d-byte upgrade head costs %v whole and %v one byte at a time — %.0f×, past the %d× a scan that resumes allows. The head-end scan is being restarted per slice, which is n²/2 byte steps of the one realm every link shares, bought by a stranger for %d bytes.",
			len(stream), whole, dribbled, ratio, wsHeadAmplificationBound, len(stream))
	}
}

// ── what a stranger's upgrade head costs this realm ──────────────────────────
//
// An accepting WebSocket link buffers bytes until it sees `\r\n\r\n`, and re-runs
// `ByteParts.findHeadEnd` over EVERYTHING buffered on every arriving slice. The sender
// picks the slice size, so the same 16 KiB of head is one scan or sixteen thousand of
// them — and the difference is work this node does for a peer it has not authenticated,
// on the one realm every other link shares. The benchmark holds the bytes fixed and
// varies only the chunking, so the number it prints IS the amplification.
func BenchmarkWsHandshakeHead(b *testing.B) {
	framingFuzzRealm(b)
	// A head one byte under the 16 KiB ceiling, with no CRLFCRLF anywhere in it: the
	// most a peer may make this link hold before `read` gives up on it.
	stream := bytes.Repeat([]byte("A"), 16*1024-1)
	for _, chunk := range []int{16384, 1024, 64, 8, 1} {
		b.Run("chunk="+itoa(chunk), func(b *testing.B) {
			for b.Loop() {
				if _, err := callRealm("__benchWsHead", 120*time.Second,
					qc.NewArrayBuffer(stream), qc.NewInt64(int64(chunk))); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
