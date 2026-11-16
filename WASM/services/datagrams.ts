// A platform's raw datagram sockets (host/abi.ts `PlatformUdp`), which the host lends the
// link occupant (§12.7, services/link.ts). Raw primitives only: what a path is, which
// addresses are candidates and how a stream gets across are the transport's (udp.js).
import { dec, readU32BE } from "../host/util.js";

/** A platform's datagram sockets. */
export interface RawDatagrams {
  /** A socket on `port`, or on one the OS picks for 0, dual-stack where the machine has
   *  IPv6, asking for kernel receive and send buffers of `bufferBytes`; a kernel that grants
   *  less is no failure. What it reads arrives at `deliver` in batches of
   *  `[n u8][ip n][port u16][len u16][bytes]`, n 4 for IPv4 and 16 for IPv6. A platform that
   *  reads off its event loop holds what it has read for `deliver` within `heldBytes`, for
   *  all its sockets together, dropping a datagram past it; one that reads on the loop
   *  delivers at once and holds nothing. */
  bind(deliver: (batch: Uint8Array | ArrayBuffer) => void, bufferBytes: number, heldBytes: number, port: number):
    { id: number; port: number } | Promise<{ id: number; port: number }>;
  /** A turn's datagrams, as `link/udpSend` carries them (`forEachDatagram`): each socket's
   *  group within the batch and from a socket the sender holds, the datagrams inside it for
   *  the platform to check. A failure is a lost one. A name rather than an address resolves
   *  to IPv4. */
  send(batch: Uint8Array): void;
  close(id: number): void;
  /** Every address this machine's sockets are reached at, `\n`-separated. */
  addresses(): string;
}

/** Where the host of the send-batch datagram at `at` ends. A datagram is `[host][port u16]
 *  [len u16][bytes]`, the host `[4][ip 4]` or `[16][ip 16]` as the read batches spell it, or
 *  a name as `[0][len u8][name utf8]`; another first byte is no host. */
function hostEnd(batch: Uint8Array, at: number): number {
  const n = batch[at];
  return n === 4 || n === 16 ? at + 1 + n : n === 0 ? at + 2 + (batch[at + 1] ?? 0) : Infinity;
}

/** Where each socket's group of a send batch, `([socket u32][len u32][datagrams])*`, ends:
 *  past the batch when it runs off its end. */
export function groupEnd(batch: Uint8Array, at: number): number {
  return at + 8 > batch.length ? Infinity : at + 8 + readU32BE(batch, at + 4);
}

/** Where the read batch's datagrams from `at` end, taking as many whole ones as fit in
 *  `max` bytes and at least one. A read datagram is `[n u8][ip n][port u16][len u16][bytes]`. */
export function readsWithin(batch: Uint8Array, at: number, max: number): number {
  // The platform's batch is whole datagrams, so a rest that fits is all of them, unwalked.
  if (batch.length - at <= max) return batch.length;
  let end = at;
  while (end < batch.length) {
    const n = batch[end] + 5;
    const next = end + n + ((batch[end + n - 2] << 8) | batch[end + n - 1]);
    if (next > batch.length) return batch.length;
    if (end > at && next - at > max) break;
    end = next;
  }
  return end;
}

/** Each datagram of a send batch, in order, its host as text. The host has checked each
 *  socket's group lies within the batch; a datagram that names no host or runs past its
 *  group throws, the batch's later ones unvisited. */
export function forEachDatagram(batch: Uint8Array, fn: (id: number, host: string, port: number, bytes: Uint8Array) => void): void {
  // A batch is mostly one path's, so a host spelled as the one before is that one's text.
  let last = -1, lastEnd = -1, host = "";
  for (let at = 0; at < batch.length;) {
    const id = readU32BE(batch, at), end = groupEnd(batch, at);
    for (let d = at + 8; d < end;) {
      const p = hostEnd(batch, d), n = batch[d];
      const next = p + 4 > end ? Infinity : p + 4 + ((batch[p + 2] << 8) | batch[p + 3]);
      if (next > end) throw new Error("datagrams: a malformed datagram");
      if (last < 0 || !sameSpan(batch, last, lastEnd, d, p)) {
        host = n === 4 ? batch.subarray(d + 1, p).join(".")
          : n === 16 ? Array.from({ length: 8 }, (_, i) => ((batch[d + 1 + 2 * i] << 8) | batch[d + 2 + 2 * i]).toString(16)).join(":")
            : dec.decode(batch.subarray(d + 2, p));
      }
      last = d;
      lastEnd = p;
      fn(id, host, (batch[p] << 8) | batch[p + 1], batch.subarray(p + 4, next));
      d = next;
    }
    at = end;
  }
}

/** Whether the bytes from `a` to `aEnd` spell those from `b` to `bEnd`. */
function sameSpan(batch: Uint8Array, a: number, aEnd: number, b: number, bEnd: number): boolean {
  if (aEnd - a !== bEnd - b) return false;
  for (let i = 0; a + i < aEnd; i++) {
    if (batch[a + i] !== batch[b + i]) return false;
  }
  return true;
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
