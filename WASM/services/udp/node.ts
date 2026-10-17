// Node's datagrams for the UDP seam (net-udp.ts): a `node:dgram` socket per path, dual-stack
// where the machine has IPv6, and this machine's addresses for its candidates.
import { createSocket, type Socket } from "node:dgram";
import { lookup } from "node:dns";
import { isIPv4 } from "node:net";
import { networkInterfaces } from "node:os";
import { type DatagramPlatform } from "./net-udp.js";
import { SOCKET_BUFFER_BYTES } from "./stream.js";

/** IPv4 as a dual-stack socket sends to and hears from it. */
const MAPPED = "::ffff:";

/** A socket on a port the OS picks: `udp6` taking IPv4 too, or `udp4` on a machine
 *  without IPv6. */
function bound(type: "udp4" | "udp6"): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const s = createSocket({ type, ipv6Only: false, recvBufferSize: SOCKET_BUFFER_BYTES, sendBufferSize: SOCKET_BUFFER_BYTES });
    s.once("error", reject);
    s.bind(0, () => { s.off("error", reject); resolve(s); });
  });
}

let dualStack = true;

export const nodeDatagrams: DatagramPlatform = {
  async bind() {
    let s: Socket;
    try {
      s = await bound(dualStack ? "udp6" : "udp4");
    } catch (err) {
      if (!dualStack) throw err;
      dualStack = false;
      s = await bound("udp4");
    }
    const six = dualStack;
    // A send that fails is a lost datagram, which the stream already expects.
    s.on("error", () => {});
    let sending = 0, closing = false;
    const shut = () => { try { s.close(); } catch { /* already closed */ } };
    const sent = () => { if (--sending === 0 && closing) shut(); };
    const to = (bytes: Uint8Array, port: number, host: string) => {
      sending++;
      // A port or address the OS refuses (port 0 throws synchronously) is a lost datagram,
      // as the contract says, not an exception out of the socket callback.
      try { s.send(bytes, port, host, sent); } catch { sent(); }
    };
    return {
      port: s.address().port,
      socket: {
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
        onMessage(cb) {
          s.on("message", (msg, from) => {
            const host = from.address.startsWith(MAPPED) ? from.address.slice(MAPPED.length) : from.address;
            cb(new Uint8Array(msg.buffer, msg.byteOffset, msg.length), host, from.port);
          });
        },
        // Behind what is still being sent, a stream's CLOSE among it.
        close() {
          if (closing) return;
          closing = true;
          if (sending === 0) shut();
        },
      },
    };
  },
  /** Every outward IPv4 address, or loopback on a machine with none, then every IPv6 one
   *  but loopback and link-local, while sockets are dual-stack. */
  addresses() {
    const all = Object.values(networkInterfaces()).flat();
    const v4 = all.filter((a) => a?.family === "IPv4");
    const outward = v4.filter((a) => !a!.internal);
    const v6 = dualStack ? all.filter((a) => a?.family === "IPv6" && !a.internal && !/^fe[89ab]/i.test(a.address)) : [];
    return [...(outward.length > 0 ? outward : v4), ...v6].map((a) => a!.address.toLowerCase());
  },
};
