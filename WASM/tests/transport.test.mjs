// Transport-level behaviour: WebSocket frame-cap ordering and peer-address parsing.
//
// Transports reassemble inbound frames under MAX_HANDSHAKE_FRAME_BYTES until a link
// authenticates, then raise the cap. On the WS path the cap lives in WsParser and is
// raised by the channel from inside frame delivery — so the parser MUST deliver each
// frame as it is parsed rather than parsing a whole chunk and delivering afterwards.
//
// The distinction is not theoretical. A responder authenticates at msg3 and may send
// application data alongside msg4, and TCP will happily deliver both in one segment. A
// batch-then-deliver parser measures that application frame against the cap that was in
// force before msg4 was seen — the pre-auth cap — and fails the connection. Every
// browser-to-node link would drop on its first sizeable frame.

import { WsParser } from "../build/host/ws/ws-codec.js";
import { installWasmWsBackend } from "../build/host/ws/ws-wasm-backend.js";
import { parseWsPeer } from "../build/host/net-ws.js";
import { parsePeerSpec } from "../build/core/socket-seam.js";

installWasmWsBackend();

let pass = 0, fail = 0;
function test(name, fn) {
  try { fn(); pass++; console.log(`  OK   ${name}`); }
  catch (e) { fail++; console.log(`  FAIL ${name}\n       ${e.message}`); }
}
const assert = (c, m) => { if (!c) throw new Error(m); };

/** One unmasked binary frame, built by hand — servers read masked frames, clients
 *  unmasked, and this exercises the client direction. */
function binaryFrame(n) {
  const payload = new Uint8Array(n);
  for (let i = 0; i < n; i++) payload[i] = i & 255;
  if (n < 126) return Uint8Array.from([0x82, n, ...payload]);
  return Uint8Array.from([0x82, 126, (n >> 8) & 255, n & 255, ...payload]);
}

console.log("\nWebSocket frame cap ordering (§12.6.2)\n");

test("a cap raised during delivery applies to the next frame in the SAME chunk", () => {
  const small = binaryFrame(100), big = binaryFrame(2000);
  const chunk = new Uint8Array(small.length + big.length);
  chunk.set(small, 0); chunk.set(big, small.length);

  const parser = new WsParser(false, 512); // pre-auth cap
  const got = [];
  parser.push(chunk, (f) => {
    got.push(f.payload.length);
    if (got.length === 1) parser.setCap(1 << 20); // what authentication does
  });
  assert(got.length === 2, `expected 2 frames, got ${got.length}`);
  assert(got[1] === 2000, `expected the second frame at full size, got ${got[1]}`);
});

test("the cap still rejects an oversize frame that arrives before any raise", () => {
  const parser = new WsParser(false, 512);
  let threw = false;
  try { parser.push(binaryFrame(2000), () => {}); } catch { threw = true; }
  assert(threw, "an oversize pre-auth frame must be rejected");
});

test("the callback form and the array form agree", () => {
  const chunk = binaryFrame(50);
  const viaArray = new WsParser(false, 512).push(chunk);
  const viaCb = [];
  new WsParser(false, 512).push(chunk, (f) => viaCb.push(f));
  assert(viaArray.length === 1 && viaCb.length === 1, "both forms should yield one frame");
  assert(viaArray[0].payload.length === viaCb[0].payload.length, "payloads should match");
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

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
