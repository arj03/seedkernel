// The ws.wasm module's RFC 6455 conformance, plus peer-address parsing. The framing STATE
// MACHINE (residual buffer, two-stage cap, fragment reassembly) is the transport guest's
// (transport/src/framing.js `WsFramer`), covered end to end by transport-tcp.test.mjs; what
// is tested here is the module those framers call — one frame in, one decoded frame out,
// and the refusals it owes its callers.

import { encodeFrame, decodeOne, wsAcceptKey, wsBase64, WS_OP, SCRATCH_SIZE } from "./ws-module.mjs";
import { MAX_FRAME_BYTES } from "../build/core/net-limits.js";
import { parsePeerRef, parseDest, peersConfig } from "../build/host/peer-addr.js";
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

// The one cross-artifact coupling in the frame path, checked rather than documented:
// `MAX_FRAME_BYTES` (host, core/net-limits.ts) is a floor under the module's compiled
// scratch, and raising the cap past it fails nothing at build time — TCP keeps carrying
// the frame while WS tears the link down on the first big one. Red here, naming the rebuild.
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

// ── peer references ──────────────────────────────────────────────────────────
// One shape, `pk[.secret]@dest`, whatever the destination turns out to be, and the secret
// is the PEER's — getting that wrong is silent: a dial sealed under the wrong secret draws
// no response, indistinguishable from the peer being down. What comes out is what the
// transport's own address book stores and hands back down through `link/open` (§12.10).
const PK = "aa".repeat(32), SEC = "bb".repeat(32);

test("peer refs: the optional contact secret parses under either default scheme", () => {
  const tcp = parsePeerRef(`${PK}.${SEC}@1.2.3.4:9`, "tcp");
  assert(tcp.peerId === PK, "tcp peerId");
  assert(Buffer.from(tcp.contactSecret).toString("hex") === SEC, "tcp contact secret");
  const ws = parsePeerRef(`${PK}.${SEC}@host:1`, "ws");
  assert(ws.peerId === PK, "ws peerId");
  assert(Buffer.from(ws.contactSecret).toString("hex") === SEC, "ws contact secret");
});

test("peer refs: omitting the secret means an open peer, not a parse error", () => {
  assert(parsePeerRef(`${PK}@1.2.3.4:9`, "tcp").contactSecret === undefined, "tcp");
  assert(parsePeerRef(`${PK}@host:1`, "ws").contactSecret === undefined, "ws");
});

test("peer refs: a destination carries its own scheme, and the default fills one in", () => {
  // The scheme is what a socket factory branches on, so it must be IN the string a
  // reference produces — `link/open` carries nothing else, the driver having no address
  // book left to consult. A reference that states one keeps it; one that does not takes
  // the default the flag it was typed under implies.
  assert(parsePeerRef(`${PK}@1.2.3.4:9`, "tcp").dest === "tcp://1.2.3.4:9", "the tcp default");
  assert(parsePeerRef(`${PK}@example.com:8080`, "ws").dest === "ws://example.com:8080", "the ws default");
  assert(parsePeerRef(`${PK}@wss://relay.example.com:443`, "tcp").dest === "wss://relay.example.com:443",
    "a stated scheme beats the default, whatever the default was");
});

test("peer refs: a scheme and a path survive whole, and neither disturbs the port", () => {
  // The whole URL a browser's `WebSocket` needs has to survive the grammar, because the
  // reference is the only thing that knows it: `wss://` is how a deployment asks for TLS,
  // and a path is how it is reached behind a reverse proxy. The port still parses out of
  // the middle of both — a naive last-colon split would read `8080/chat` as the port.
  const bare = parseDest(parsePeerRef(`${PK}@example.com:8080`, "ws").dest);
  assert(bare.scheme === "ws" && bare.host === "example.com" && bare.port === 8080 && bare.path === undefined,
    `a bare host:port must carry no path, got ${JSON.stringify(bare)}`);
  const tls = parseDest(parsePeerRef(`${PK}@wss://relay.example.com:443`, "ws").dest);
  assert(tls.scheme === "wss" && tls.host === "relay.example.com" && tls.port === 443 && tls.path === undefined,
    `the scheme must come off the host, got ${JSON.stringify(tls)}`);
  const proxied = parsePeerRef(`${PK}.${SEC}@wss://relay.example.com:443/chat/v1`, "ws");
  const proxiedDest = parseDest(proxied.dest);
  assert(proxiedDest.host === "relay.example.com" && proxiedDest.port === 443,
    `a path must not disturb host:port, got ${JSON.stringify(proxiedDest)}`);
  assert(proxiedDest.path === "/chat/v1", `the path must survive whole, got ${proxiedDest.path}`);
  assert(Buffer.from(proxied.contactSecret).toString("hex") === SEC,
    "the credential half still parses alongside a path");
  // The scheme's own `//` is not a path, and a root path is kept as one.
  assert(parseDest(parsePeerRef(`${PK}@ws://h:1/`, "ws").dest).path === "/", "a bare root path is still a path");
});

test("peer refs: a malformed secret is rejected, not silently ignored", () => {
  for (const scheme of ["tcp", "ws"]) {
    let threw = false;
    try { parsePeerRef(`${PK}.${"cc".repeat(20)}@host:1`, scheme); } catch { threw = true; }
    assert(threw, `${scheme} must reject a short contact secret`);
  }
});

test("peer refs: a malformed destination fails at the reference, not at the dial", () => {
  // Both dispositions of the ONE parser: a human's reference throws where the typo is,
  // while a socket factory handed something it cannot route answers `null`, which the
  // driver reads as "no route" (core/socket-seam.ts).
  for (const bad of [`${PK}@host`, `${PK}@host:0`, `${PK}@host:70000`, `${PK}@:9`]) {
    let threw = false;
    try { parsePeerRef(bad, "tcp"); } catch { threw = true; }
    assert(threw, `a reference must reject ${bad}`);
  }
  assert(parseDest("host:9") === null, "a destination with no scheme is unroutable");
  assert(parseDest("quic://host:9") === null, "a scheme no factory speaks is unroutable");
  assert(parseDest("tcp://host:abc") === null, "a destination with no usable port is unroutable");
});

test("peer refs: the config form spells the same reference in hex", () => {
  // What an embedder puts in `transportConfig.peers` — the boot-time half of the address
  // book, since the book itself is the transport guest's and dies with its realm (§12.10).
  const [withSecret, open] = peersConfig([`${PK}.${SEC}@1.2.3.4:9`, `${PK}@ws://h:1/p`]);
  assert(withSecret.peerId === PK && withSecret.dest === "tcp://1.2.3.4:9" && withSecret.contactSecret === SEC,
    `the credential half must survive the JSON form, got ${JSON.stringify(withSecret)}`);
  assert(open.dest === "ws://h:1/p" && !("contactSecret" in open),
    `an open peer must state no secret at all, got ${JSON.stringify(open)}`);
});

summary("RFC 6455 module conformance");
