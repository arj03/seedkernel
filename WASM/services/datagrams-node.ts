// Node's datagram sockets (datagrams.ts `RawDatagrams`): a `node:dgram` socket per bind,
// dual-stack where the machine has IPv6. The Node platform hands them to the host
// (host/platform-node.ts), which lends them to the UDP bundle (§12.7).
import { createSocket, type Socket } from "node:dgram";
import { lookup } from "node:dns";
import { isIPv4 } from "node:net";
import { networkInterfaces } from "node:os";
import { forEachDatagram, ipv6Bytes, type RawDatagrams } from "./datagrams.js";

/** IPv4 as a dual-stack socket sends to and hears from it. */
const MAPPED = "::ffff:";

/** A socket on a port the OS picks: `udp6` taking IPv4 too, or `udp4` on a machine
 *  without IPv6. */
function bound(type: "udp4" | "udp6", bufferBytes: number): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const s = createSocket({ type, ipv6Only: false, recvBufferSize: bufferBytes, sendBufferSize: bufferBytes });
    s.once("error", reject);
    s.bind(0, () => { s.off("error", reject); resolve(s); });
  });
}

let dualStack = true;

/** Node's raw datagram sockets, and the release of every one still open. */
export function nodeRawDatagrams(): RawDatagrams & { closeAll(): void } {
  const sockets = new Map<number, { send(bytes: Uint8Array, port: number, host: string): void; close(): void }>();
  let seq = 0;
  return {
    async bind(deliver, bufferBytes) {
      let s: Socket;
      try {
        s = await bound(dualStack ? "udp6" : "udp4", bufferBytes);
      } catch (err) {
        if (!dualStack) throw err;
        dualStack = false;
        s = await bound("udp4", bufferBytes);
      }
      const six = dualStack;
      // A send that fails is a lost datagram, which the stream already expects.
      s.on("error", () => {});
      s.on("message", (msg, from) => {
        // IPv4 as itself, though a dual-stack socket hears it IPv4-mapped.
        const a = from.address.startsWith(MAPPED) ? from.address.slice(MAPPED.length) : from.address;
        const ip = a.includes(":") ? ipv6Bytes(a) : Uint8Array.from(a.split("."), Number);
        const batch = new Uint8Array(5 + ip.length + msg.length);
        batch[0] = ip.length;
        batch.set(ip, 1);
        const at = 1 + ip.length;
        batch[at] = from.port >> 8;
        batch[at + 1] = from.port & 255;
        batch[at + 2] = msg.length >> 8;
        batch[at + 3] = msg.length & 255;
        batch.set(msg, at + 4);
        deliver(batch);
      });
      let sending = 0, closing = false;
      const shut = () => { try { s.close(); } catch { /* already closed */ } };
      const sent = () => { if (--sending === 0 && closing) shut(); };
      const to = (bytes: Uint8Array, port: number, host: string) => {
        sending++;
        // A port or address the OS refuses (port 0 throws synchronously) is a lost datagram,
        // as the contract says, not an exception out of the socket callback.
        try { s.send(bytes, port, host, sent); } catch { sent(); }
      };
      const id = ++seq;
      sockets.set(id, {
        send(bytes, port, host) {
          if (closing) return;
          if (!six || host.includes(":")) to(bytes, port, host);
          else if (isIPv4(host)) to(bytes, port, MAPPED + host);
          else {
            // A name, as a STUN server's: its IPv4 address, as on an IPv4 socket.
            sending++;
            lookup(host, { family: 4 }, (err, address) => {
              if (err || closing) sent();
              else try { s.send(bytes, port, MAPPED + address, sent); } catch { sent(); }
            });
          }
        },
        // Behind what is still being sent, a stream's CLOSE among it.
        close() {
          if (closing) return;
          closing = true;
          if (sending === 0) shut();
        },
      });
      return { id, port: s.address().port };
    },
    send: (batch) => forEachDatagram(batch, (id, host, port, bytes) => sockets.get(id)?.send(bytes, port, host)),
    close: (id) => { sockets.get(id)?.close(); sockets.delete(id); },
    // IPv6 only while sockets are dual-stack.
    addresses: () => Object.values(networkInterfaces()).flat()
      .filter((a) => a !== undefined && (dualStack || a.family === "IPv4")).map((a) => a!.address).join("\n"),
    closeAll() {
      for (const s of sockets.values()) s.close();
      sockets.clear();
    },
  };
}
