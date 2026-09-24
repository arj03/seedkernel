// The ws.wasm module's RFC 6455 conformance, plus destination parsing. The framing STATE
// MACHINE (residual buffer, two-stage cap, fragment reassembly) is the transport guest's
// (transport/src/framing.js `WsFramer`), covered end to end by transport-tcp.test.mjs; what
// is tested here is the module those framers call — one frame in, one decoded frame out,
// and the refusals it owes its callers.

import { encodeFrame, decodeOne, wsAcceptKey, wsBase64, WS_OP, SCRATCH_SIZE } from "./ws-module.mjs";
import { MAX_LINK_READ_BYTES } from "../build/services/net-limits.js";
import { MAX_FRAME_BYTES } from "../scripts/transport-config.mjs";
import { parseDest } from "../build/services/peer-addr.js";
import { testkit } from "./testkit.mjs";
import { readFileSync } from "node:fs";
import { toHex } from "../build/services/util.js";
import { createSafeRealm } from "../build/host/safe-js.js";

const { test, assert, summary } = testkit();

await test("host and confined transport hex preserve unsigned words, padding, tails and views", async () => {
  const source = readFileSync(new URL("../transport/src/util.js", import.meta.url), "utf8");
  const realm = await createSafeRealm({
    source: source + '\nfunction handle(b) { return Uint8Array.from(toHex(b), c => c.charCodeAt(0)); }',
    hostCall: async () => new Uint8Array(),
  });
  try {
    const data = Uint8Array.from({ length: 272 }, (_, i) => i & 255);
    const cases = [new Uint8Array(33), new Uint8Array(35).fill(255), data];
    for (let n = 0; n <= 67; n++) cases.push(data.subarray(n % 8, n % 8 + n));
    for (const bytes of cases) {
      const expected = Buffer.from(bytes).toString("hex");
      assert(toHex(bytes) === expected, `host hex (${bytes.length} bytes, offset ${bytes.byteOffset})`);
      const actual = new TextDecoder().decode(await realm.call(bytes));
      assert(actual === expected, `guest hex (${bytes.length} bytes, offset ${bytes.byteOffset})`);
    }
  } finally { realm.dispose(); }
});

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

// The cross-artifact couplings in the frame path, checked rather than documented. The
// transport's `MAX_FRAME_BYTES` (scripts/transport-config.mjs) is a floor under the module's
// compiled scratch, and raising the cap past it fails nothing at build time — TCP keeps
// carrying the frame while WS tears the link down on the first big one. Red here, naming
// the rebuild. It must also fit the host's read cap, or a platform-framed link (a browser
// WebSocket, a data channel) is failed by the driver on its first full-size frame.
test("ws.wasm's compiled scratch still fits a whole MAX_FRAME_BYTES frame", () => {
  // The encoder's own ceiling: header (10) + mask (4) ≤ the 16 bytes abi.ts holds back.
  assert(MAX_FRAME_BYTES + 16 <= SCRATCH_SIZE,
    `MAX_FRAME_BYTES ${MAX_FRAME_BYTES} needs ${MAX_FRAME_BYTES + 16} B of scratch, `
    + `ws.wasm allocates ${SCRATCH_SIZE} — raise SCRATCH_SIZE in assembly/ws/abi.ts and `
    + `rebuild (npm run build:ws)`);
  assert(MAX_FRAME_BYTES <= MAX_LINK_READ_BYTES,
    `MAX_FRAME_BYTES ${MAX_FRAME_BYTES} exceeds the host's MAX_LINK_READ_BYTES ${MAX_LINK_READ_BYTES}`);
  // Not vacuous: the largest frame really does encode and decode through the module.
  const got = decodeOne(encodeFrame(WS_OP.BINARY, body(MAX_FRAME_BYTES), MASK), true);
  assert(got !== null && got.payload.length === MAX_FRAME_BYTES, "a full-size frame round-trips");
});

// ── destinations ─────────────────────────────────────────────────────────────
// The string `link/open` carries is the only thing a socket factory reads, so a scheme and
// a path have to survive the one parser the socket edges share (services/peer-addr.ts).
// How a PEER is spelled is the transport's grammar, tested with its config (transport-link).

test("destinations: a scheme and a path survive whole, and neither disturbs the port", () => {
  // `wss://` is how a deployment asks for TLS, and a path is how it is reached behind a
  // reverse proxy. The port still parses out of the middle of both — a naive last-colon
  // split would read `8080/chat` as the port.
  const bare = parseDest("ws://example.com:8080");
  assert(bare.scheme === "ws" && bare.host === "example.com" && bare.port === 8080 && bare.path === undefined,
    `a bare host:port must carry no path, got ${JSON.stringify(bare)}`);
  const tls = parseDest("wss://relay.example.com:443");
  assert(tls.scheme === "wss" && tls.host === "relay.example.com" && tls.port === 443 && tls.path === undefined,
    `the scheme must come off the host, got ${JSON.stringify(tls)}`);
  const proxied = parseDest("wss://relay.example.com:443/chat/v1");
  assert(proxied.host === "relay.example.com" && proxied.port === 443,
    `a path must not disturb host:port, got ${JSON.stringify(proxied)}`);
  assert(proxied.path === "/chat/v1", `the path must survive whole, got ${proxied.path}`);
  // The scheme's own `//` is not a path, and a root path is kept as one.
  assert(parseDest("ws://h:1/").path === "/", "a bare root path is still a path");
});

test("destinations: anything malformed is no route, not a throw", () => {
  // A socket factory handed something it cannot route answers `null`, which the driver
  // reads as "no route" (services/socket-seam.ts).
  assert(parseDest("host:9") === null, "a destination with no scheme is unroutable");
  assert(parseDest("quic://host:9") === null, "a scheme no factory speaks is unroutable");
  assert(parseDest("tcp://host:abc") === null, "a destination with no usable port is unroutable");
});

summary("RFC 6455 module conformance");
