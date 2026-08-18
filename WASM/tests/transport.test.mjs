// The ws.wasm module's RFC 6455 conformance, plus peer-address parsing.
//
// The framing STATE MACHINE — the residual buffer, the two-stage cap, fragment
// reassembly — is the transport guest's (transport/src/framing.js `WsFramer`), covered
// end to end by transport-tcp.test.mjs. What is tested here is the module those framers
// call: one whole frame in, one decoded frame out, and the refusals it owes its callers.

import { encodeFrame, decodeOne, wsAcceptKey, wsBase64, WS_OP, SCRATCH_SIZE } from "./ws-module.mjs";
import { MAX_FRAME_BYTES } from "../build/core/net-limits.js";
import { parseWsPeer } from "../build/host/net-ws.js";
import { parsePeerSpec } from "../build/host/net-node.js";
import { testkit } from "./testkit.mjs";

const { test, assert, summary } = testkit();

console.log("\nRFC 6455 module conformance (ws.wasm, a module of the transport bundle)\n");

const MASK = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
const body = (n) => {
  const p = new Uint8Array(n);
  for (let i = 0; i < n; i++) p[i] = (i * 31 + 28) & 255;
  return p;
};

test("RFC 6455 §1.3 accept vector — the runtime's only SHA-1, and its base64", () => {
  assert(wsAcceptKey("dGhlIHNhbXBsZSBub25jZQ==") === "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "known vector");
  assert(wsBase64(new Uint8Array([0, 1, 2, 3])) === "AAECAw==", "base64 with padding");
});

test("a masked client frame round-trips through a server decode", () => {
  const payload = body(300);
  const got = decodeOne(encodeFrame(WS_OP.BINARY, payload, MASK), true);
  assert(got !== null, "decode refused a well-formed masked frame");
  assert(got.fin && got.opcode === WS_OP.BINARY, "fin/opcode");
  assert(Buffer.compare(Buffer.from(got.payload), Buffer.from(payload)) === 0, "payload survived demasking");
});

test("each length encoding decodes to the length it declares", () => {
  // 125 / 126 / 65535 / 65536 straddle the 7-bit, 16-bit and 64-bit header forms.
  for (const n of [0, 125, 126, 65535, 65536]) {
    const got = decodeOne(encodeFrame(WS_OP.BINARY, body(n), null), false);
    assert(got !== null && got.payload.length === n, `length ${n}`);
  }
});

test("the mask direction is enforced in BOTH directions", () => {
  // The RFC is not asymmetric by accident: an unmasked client frame is the one an
  // off-path attacker can smuggle through a cache, which is what masking exists to stop.
  assert(decodeOne(encodeFrame(WS_OP.BINARY, body(8), null), true) === null,
    "a server must refuse an UNmasked client frame");
  assert(decodeOne(encodeFrame(WS_OP.BINARY, body(8), MASK), false) === null,
    "a client must refuse a MASKED server frame");
});

test("a fragmented control frame is refused (RFC 6455 §5.5)", () => {
  const f = encodeFrame(WS_OP.PING, body(4), null);
  f[0] &= 0x7f; // clear FIN — a control frame may never be fragmented
  assert(decodeOne(f, false) === null, "a FIN-less control frame must be a protocol error");
});

test("a truncated frame decodes to nothing rather than reading past its end", () => {
  const f = encodeFrame(WS_OP.BINARY, body(200), null);
  assert(decodeOne(f.subarray(0, f.length - 10), false) === null, "short frame");
});

// The one cross-artifact coupling in the frame path, checked rather than documented.
// `MAX_FRAME_BYTES` is the host's number (core/net-limits.ts), but this module must STAGE
// a whole frame in the scratch it allocates at instantiation, so its compiled-in capacity
// is a floor under the cap. Raising the cap past it fails nothing at build time: TCP keeps
// carrying the frame while WS tears the link down on the first big one, reading as a WS
// bug. Red here instead, naming the rebuild.
test("ws.wasm's compiled scratch still fits a whole MAX_FRAME_BYTES frame", () => {
  // The encoder's own ceiling: header (10) + mask (4) ≤ the 16 bytes abi.ts holds back.
  assert(MAX_FRAME_BYTES + 16 <= SCRATCH_SIZE,
    `MAX_FRAME_BYTES ${MAX_FRAME_BYTES} needs ${MAX_FRAME_BYTES + 16} B of scratch, `
    + `ws.wasm allocates ${SCRATCH_SIZE} — raise SCRATCH_SIZE in assembly/ws/abi.ts and `
    + `rebuild (npm run build:ws)`);
  // Not vacuous: the largest frame really does encode and decode through the module.
  const got = decodeOne(encodeFrame(WS_OP.BINARY, body(MAX_FRAME_BYTES), MASK), true);
  assert(got !== null && got.payload.length === MAX_FRAME_BYTES, "a full-size frame round-trips");
});

// ── peer specs ───────────────────────────────────────────────────────────────
// Both transports carry the same address shape, `pk[.secret]@where`, and the secret is
// the PEER's. Getting this wrong is silent: a dial sealed under the wrong secret simply
// draws no response, which is indistinguishable from the peer being down.
const PK = "aa".repeat(32), SEC = "bb".repeat(32);

test("peer specs: the optional contact secret parses on both transports", () => {
  const tcp = parsePeerSpec(`${PK}.${SEC}@1.2.3.4:9`, "tcp");
  assert(tcp.peerId === PK, "tcp peerId");
  assert(Buffer.from(tcp.addr.contactSecret).toString("hex") === SEC, "tcp contact secret");
  const ws = parseWsPeer(`${PK}.${SEC}@host:1`);
  assert(ws.peerId === PK, "ws peerId");
  assert(Buffer.from(ws.contactSecret).toString("hex") === SEC, "ws contact secret");
});

test("peer specs: omitting the secret means an open peer, not a parse error", () => {
  assert(parsePeerSpec(`${PK}@1.2.3.4:9`, "tcp").addr.contactSecret === undefined, "tcp");
  assert(parseWsPeer(`${PK}@host:1`).contactSecret === undefined, "ws");
});

test("peer specs: a malformed secret is rejected, not silently ignored", () => {
  for (const [name, fn] of [["tcp", (x) => parsePeerSpec(x, "tcp")], ["ws", parseWsPeer]]) {
    let threw = false;
    try { fn(`${PK}.${"cc".repeat(20)}@host:1`); } catch { threw = true; }
    assert(threw, `${name} must reject a short contact secret`);
  }
});

summary("RFC 6455 module conformance");
