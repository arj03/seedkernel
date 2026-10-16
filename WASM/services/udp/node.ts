// Node's datagrams for the UDP seam (net-udp.ts): a `node:dgram` socket per path, and this
// machine's IPv4 addresses for its candidates.
import { createSocket } from "node:dgram";
import { networkInterfaces } from "node:os";
import { type DatagramPlatform } from "./net-udp.js";
import { SOCKET_BUFFER_BYTES } from "./stream.js";

export const nodeDatagrams: DatagramPlatform = {
  bind() {
    return new Promise((resolve, reject) => {
      const s = createSocket({ type: "udp4", recvBufferSize: SOCKET_BUFFER_BYTES, sendBufferSize: SOCKET_BUFFER_BYTES });
      s.once("error", reject);
      s.bind(0, () => {
        s.off("error", reject);
        // A send that fails is a lost datagram, which the stream already expects.
        s.on("error", () => {});
        let sending = 0, closing = false;
        const shut = () => { try { s.close(); } catch { /* already closed */ } };
        resolve({
          port: s.address().port,
          socket: {
            send(bytes, port, host) {
              if (closing) return;
              sending++;
              s.send(bytes, port, host, () => { if (--sending === 0 && closing) shut(); });
            },
            onMessage(cb) {
              s.on("message", (msg, from) => cb(new Uint8Array(msg.buffer, msg.byteOffset, msg.length), from.address, from.port));
            },
            // Behind what is still being sent, a stream's CLOSE among it.
            close() {
              if (closing) return;
              closing = true;
              if (sending === 0) shut();
            },
          },
        });
      });
    });
  },
  /** Every outward IPv4 address, or loopback on a machine with none. */
  addresses() {
    const all = Object.values(networkInterfaces()).flat().filter((a) => a?.family === "IPv4");
    const outward = all.filter((a) => !a!.internal);
    return (outward.length > 0 ? outward : all).map((a) => a!.address);
  },
};
