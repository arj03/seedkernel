// Minimal WebSocket broadcast hub for the browser/chat.html demo.
//
// Used only as a WebRTC signaling rendezvous: clients exchange JSON SDP
// offers / answers and ICE candidates here, then open RTCDataChannels to
// each other and route kernel envelopes peer-to-peer. Once every pair of
// active tabs has an open DataChannel, this process can be killed without
// disrupting the chat — it only matters for adding new peers.
//
// The relay is intentionally dumb: every frame from one client is forwarded
// verbatim to every other connected client. Signaling messages carry `from`
// / `to` peer-id fields so clients can filter; the relay itself does not
// inspect them. SeedKernel signatures and trust are still verified end-to-end
// inside each peer's kernel pipeline.
//
// No third-party dependencies: hand-rolled RFC 6455 framing in ~150 lines.
//
// Run: node scripts/relay.mjs [port] [--host HOST] [--allow-origin ORIGIN]

import { createServer } from "node:http";
import { createHash } from "node:crypto";

// ─── CLI parsing ─────────────────────────────────────────────────────────

const args = process.argv.slice(2);
let PORT = 8080;
let HOST = "127.0.0.1";
const ALLOWED_ORIGINS = new Set();
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === "--host") { HOST = args[++i] ?? HOST; }
  else if (a === "--allow-origin") { ALLOWED_ORIGINS.add(args[++i] ?? ""); }
  else if (a === "--port") { PORT = Number(args[++i]) || PORT; }
  else if (/^\d+$/.test(a)) { PORT = Number(a); }
}
// Defaults: localhost over http/https on common dev ports. file:// pages
// send Origin: null, which is also permitted by default so that opening
// the bundled chat-shell.html directly off disk still works.
if (ALLOWED_ORIGINS.size === 0) {
  ALLOWED_ORIGINS.add("null");
  for (const scheme of ["http", "https"]) {
    for (const host of ["localhost", "127.0.0.1", "[::1]"]) {
      ALLOWED_ORIGINS.add(`${scheme}://${host}`);
      for (const port of [80, 443, 3000, 5173, 8000, 8080, 8443]) {
        ALLOWED_ORIGINS.add(`${scheme}://${host}:${port}`);
      }
    }
  }
}

const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// ─── safety limits ───────────────────────────────────────────────────────
//
// Picked for signaling traffic — SDPs are a few KB, ICE candidates are a
// few hundred bytes. 64 KB is room for an unusually fat SDP; anything
// larger is almost certainly garbage or an attacker probing limits.
const MAX_FRAME_PAYLOAD = 64 * 1024;
// If a single client's outbound buffer grows past this, we drop broadcasts
// to them until they catch up. They're still alive and may receive future
// frames; we just stop piling up their backlog. 256 KB ≈ ~4 worst-case
// frames.
const MAX_SOCKET_BACKLOG = 256 * 1024;

// ─── server ──────────────────────────────────────────────────────────────

const clients = new Set();

const server = createServer((_req, res) => {
  res.writeHead(426, { "Content-Type": "text/plain" });
  res.end("WebSocket relay — connect with ws://\n");
});

server.on("upgrade", (req, sock) => {
  const key = req.headers["sec-websocket-key"];
  if (!key) { sock.destroy(); return; }

  // CSWSH defence: only accept upgrades whose Origin is on the allowlist.
  // The browser fills Origin from the page that initiated the WS, so a
  // drive-by from evil.example.com cannot impersonate the local shell.
  const origin = req.headers["origin"];
  // No origin header at all is suspicious from a browser but expected from
  // hand-rolled clients (`websocat`, `wscat`); we accept those as a
  // convenience. Comment out the next two lines if you want strict mode.
  const originStr = typeof origin === "string" ? origin : "";
  if (originStr && !ALLOWED_ORIGINS.has(originStr)) {
    sock.write("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
    sock.destroy();
    console.log(`! rejected upgrade from origin=${originStr}`);
    return;
  }

  const accept = createHash("sha1").update(key + GUID).digest("base64");
  sock.write(
    "HTTP/1.1 101 Switching Protocols\r\n" +
    "Upgrade: websocket\r\n" +
    "Connection: Upgrade\r\n" +
    `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
  );

  clients.add(sock);
  console.log(`+ client (${clients.size} connected)`);

  // Chunk buffer: a list of incoming Buffers + the total bytes pending.
  // We only Buffer.concat when we have at least enough bytes to parse the
  // next frame header, and we slice the head off in one operation per
  // consumed frame. v1's per-chunk concat was O(n²) for any large frame.
  const chunks = [];
  let chunkTotal = 0;

  function consumeBytes(n) {
    // Drop the leading `n` bytes from the chunk list. If n == chunkTotal
    // we just empty the list; otherwise we walk forward until we've
    // accounted for `n` bytes and keep the tail of the current chunk.
    let remaining = n;
    while (remaining > 0 && chunks.length > 0) {
      const c = chunks[0];
      if (c.length <= remaining) {
        remaining -= c.length;
        chunks.shift();
      } else {
        chunks[0] = c.subarray(remaining);
        remaining = 0;
      }
    }
    chunkTotal -= n;
  }

  function peek(n) {
    // Return a contiguous view over the first `n` bytes, or null if we
    // don't have that many yet. Avoids the full concat in the common case
    // where the first chunk already covers `n` bytes.
    if (chunkTotal < n) return null;
    if (chunks[0].length >= n) return chunks[0].subarray(0, n);
    // Concat just enough to satisfy the read.
    const collected = [];
    let have = 0;
    for (const c of chunks) {
      collected.push(c);
      have += c.length;
      if (have >= n) break;
    }
    return Buffer.concat(collected).subarray(0, n);
  }

  sock.on("data", (chunk) => {
    chunks.push(chunk);
    chunkTotal += chunk.length;

    // Drain as many complete frames as we have.
    while (true) {
      const header = peek(2);
      if (!header) break;

      // Enforce FIN=1 (no fragmented frames). The relay is for short
      // signaling JSON; legitimate clients never need fragmentation.
      // A FIN=0 frame would be repacked as FIN=1 by encodeFrame below,
      // changing the semantics on the wire — better to refuse outright.
      const fin = (header[0] & 0x80) !== 0;
      if (!fin) {
        console.log("! dropped: fragmented frame (FIN=0)");
        sock.destroy();
        return;
      }

      const opcode = header[0] & 0x0f;
      const masked = (header[1] & 0x80) !== 0;
      // Per RFC 6455 client→server frames MUST be masked.
      if (!masked) {
        console.log("! dropped: unmasked client frame");
        sock.destroy();
        return;
      }

      let payloadLen = header[1] & 0x7f;
      let headerLen = 2;
      if (payloadLen === 126) {
        const ext = peek(4);
        if (!ext) break;
        payloadLen = ext.readUInt16BE(2);
        headerLen = 4;
      } else if (payloadLen === 127) {
        const ext = peek(10);
        if (!ext) break;
        const big = ext.readBigUInt64BE(2);
        // Bound the announced length BEFORE we ever try to allocate.
        if (big > BigInt(MAX_FRAME_PAYLOAD)) {
          console.log(`! dropped: oversize frame announced (${big})`);
          sock.destroy();
          return;
        }
        payloadLen = Number(big);
        headerLen = 10;
      }
      if (payloadLen > MAX_FRAME_PAYLOAD) {
        console.log(`! dropped: oversize frame (${payloadLen})`);
        sock.destroy();
        return;
      }

      const totalFrame = headerLen + 4 + payloadLen; // +4 mask
      const full = peek(totalFrame);
      if (!full) break;                              // wait for more bytes

      const mask = full.subarray(headerLen, headerLen + 4);
      const masked_payload = full.subarray(headerLen + 4, totalFrame);
      const payload = Buffer.alloc(payloadLen);
      for (let i = 0; i < payloadLen; i++) {
        payload[i] = masked_payload[i] ^ mask[i % 4];
      }
      consumeBytes(totalFrame);

      handleFrame(opcode, payload);
    }
  });

  function handleFrame(opcode, payload) {
    if (opcode === 0x8) { sock.end(); return; }              // close
    if (opcode === 0x9) {                                     // ping → pong
      try { sock.write(encodeFrame(0xA, payload)); } catch {}
      return;
    }
    if (opcode === 0x1 || opcode === 0x2) {                   // text/binary
      const out = encodeFrame(opcode, payload);
      for (const other of clients) {
        if (other === sock) continue;
        if (!other.writable) continue;
        // V2 backpressure: skip clients with a fat outbound queue rather
        // than letting it grow without limit. They'll catch up on their
        // own writes; missing one broadcast is benign (signaling is
        // best-effort, peers retry).
        if (other.writableLength > MAX_SOCKET_BACKLOG) continue;
        try { other.write(out); } catch { /* swallow */ }
      }
      return;
    }
    // Continuation (0x0) and reserved opcodes (3-7, B-F) are not valid
    // here given FIN=1 was already enforced. Drop the connection.
    console.log(`! dropped: invalid opcode 0x${opcode.toString(16)}`);
    sock.destroy();
  }

  const drop = () => {
    if (clients.delete(sock)) {
      console.log(`- client (${clients.size} connected)`);
    }
  };
  sock.on("close", drop);
  sock.on("error", drop);
});

// Encode a server→client frame (unmasked per RFC 6455).
function encodeFrame(opcode, payload) {
  const len = payload.length;
  let header;
  if (len < 126) {
    header = Buffer.alloc(2);
    header[1] = len;
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  header[0] = 0x80 | opcode;
  return Buffer.concat([header, payload]);
}

server.listen(PORT, HOST, () => {
  console.log(`SeedKernel chat relay listening on ws://${HOST}:${PORT}`);
  console.log(`  origin allowlist: ${[...ALLOWED_ORIGINS].slice(0, 4).join(", ")}…`);
  console.log(`  frame cap: ${MAX_FRAME_PAYLOAD} B  socket backlog cap: ${MAX_SOCKET_BACKLOG} B`);
  if (HOST !== "127.0.0.1" && HOST !== "localhost" && HOST !== "::1") {
    console.log(`  ⚠  bound to ${HOST} — exposed to the network`);
  }
  console.log(`Open browser/chat-shell.html in two tabs to chat.`);
});
