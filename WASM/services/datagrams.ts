// A platform's raw datagram sockets (host/abi.ts `PlatformUdp`), which the host lends the
// link occupant (§12.7, host/transport-host.ts). Raw primitives only: what a path is, which
// addresses are candidates and how a stream gets across are the transport's (udp.js).
import { dec, readU32BE } from "./util.js";

/** A platform's datagram sockets. */
export interface RawDatagrams {
  /** A socket on a port the OS picks, dual-stack where the machine has IPv6, asking for
   *  kernel receive and send buffers of `bufferBytes`; a kernel that grants less is no
   *  failure. What it reads arrives at `deliver` in batches of
   *  `[n u8][ip n][port u16][len u16][bytes]`, n 4 for IPv4 and 16 for IPv6. A platform that
   *  reads off its event loop holds what it has read for `deliver` within `heldBytes`, for
   *  all its sockets together, dropping a datagram past it; one that reads on the loop
   *  delivers at once and holds nothing. */
  bind(deliver: (batch: Uint8Array | ArrayBuffer) => void, bufferBytes: number, heldBytes: number):
    { id: number; port: number } | Promise<{ id: number; port: number }>;
  /** A turn's datagrams, as `link/udpSend` carries them (`forEachDatagram`), whole and from
   *  sockets the sender holds. A failure is a lost one. A name rather than an address
   *  resolves to IPv4. */
  send(batch: Uint8Array): void;
  close(id: number): void;
  /** Every address this machine's sockets are reached at, `\n`-separated. */
  addresses(): string;
}

/** Where the send-batch datagram at `at` ends, `[socket u32][hostLen u8][host utf8]
 *  [port u16][len u16][bytes]`: past the batch when it runs off its end. */
export function datagramEnd(batch: Uint8Array, at: number): number {
  const p = at + 5 + (batch[at + 4] ?? 0);
  return p + 4 > batch.length ? Infinity : p + 4 + ((batch[p + 2] << 8) | batch[p + 3]);
}

/** Each datagram of a send batch, in order; the host has already checked its bounds. */
export function forEachDatagram(batch: Uint8Array, fn: (id: number, host: string, port: number, bytes: Uint8Array) => void): void {
  for (let at = 0; at < batch.length;) {
    const p = at + 5 + batch[at + 4], end = datagramEnd(batch, at);
    fn(readU32BE(batch, at), dec.decode(batch.subarray(at + 5, p)), (batch[p] << 8) | batch[p + 1], batch.subarray(p + 4, end));
    at = end;
  }
}

/** The 16 bytes of an IPv6 address's text, as an OS spells one: any zone dropped. */
export function ipv6Bytes(text: string): Uint8Array {
  const [head, tail] = text.split("%")[0].split("::");
  const groups = (part?: string) => (part ? part.split(":").map((g) => parseInt(g, 16)) : []);
  const front = groups(head), back = groups(tail);
  const all = tail === undefined ? front : [...front, ...new Array<number>(8 - front.length - back.length).fill(0), ...back];
  const out = new Uint8Array(16);
  all.forEach((w, i) => { out[2 * i] = w >> 8; out[2 * i + 1] = w & 255; });
  return out;
}
