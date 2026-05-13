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
// No third-party dependencies: hand-rolled RFC 6455 framing in ~100 lines.
//
// Run: node scripts/relay.mjs [port]   (default 8080)

import { createServer } from "node:http";
import { createHash } from "node:crypto";

const PORT = Number(process.argv[2]) || 8080;
const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const clients = new Set();

const server = createServer((_req, res) => {
  res.writeHead(426, { "Content-Type": "text/plain" });
  res.end("WebSocket relay — connect with ws://\n");
});

server.on("upgrade", (req, sock) => {
  const key = req.headers["sec-websocket-key"];
  if (!key) { sock.destroy(); return; }
  const accept = createHash("sha1").update(key + GUID).digest("base64");
  sock.write(
    "HTTP/1.1 101 Switching Protocols\r\n" +
    "Upgrade: websocket\r\n" +
    "Connection: Upgrade\r\n" +
    `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
  );

  clients.add(sock);
  console.log(`+ client (${clients.size} connected)`);

  let buf = Buffer.alloc(0);
  sock.on("data", (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    while (true) {
      const frame = parseFrame(buf);
      if (!frame) break;
      buf = buf.subarray(frame.consumed);
      if (frame.opcode === 0x8) { sock.end(); return; }       // close
      if (frame.opcode === 0x9) {                              // ping → pong
        sock.write(encodeFrame(0xA, frame.payload));
        continue;
      }
      if (frame.opcode === 0x1 || frame.opcode === 0x2) {      // text/binary
        const out = encodeFrame(frame.opcode, frame.payload);
        for (const other of clients) {
          if (other !== sock && other.writable) other.write(out);
        }
      }
    }
  });

  const drop = () => {
    if (clients.delete(sock)) {
      console.log(`- client (${clients.size} connected)`);
    }
  };
  sock.on("close", drop);
  sock.on("error", drop);
});

// Parse one client→server frame. Clients MUST mask per RFC 6455.
function parseFrame(buf) {
  if (buf.length < 2) return null;
  const opcode = buf[0] & 0x0f;
  const masked = (buf[1] & 0x80) !== 0;
  let len = buf[1] & 0x7f;
  let offset = 2;
  if (len === 126) {
    if (buf.length < 4) return null;
    len = buf.readUInt16BE(2);
    offset = 4;
  } else if (len === 127) {
    if (buf.length < 10) return null;
    const big = buf.readBigUInt64BE(2);
    if (big > BigInt(0x7fffffff)) return null;
    len = Number(big);
    offset = 10;
  }
  if (!masked) return null;
  if (buf.length < offset + 4 + len) return null;
  const mask = buf.subarray(offset, offset + 4);
  const payload = Buffer.alloc(len);
  for (let i = 0; i < len; i++) payload[i] = buf[offset + 4 + i] ^ mask[i % 4];
  return { opcode, payload, consumed: offset + 4 + len };
}

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

server.listen(PORT, () => {
  console.log(`SeedKernel chat relay listening on ws://localhost:${PORT}`);
  console.log(`Open browser/chat.html in two tabs to chat.`);
});
