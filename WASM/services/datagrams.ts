// A platform's raw datagram sockets (host/abi.ts `PlatformUdp`), which the host lends the
// link occupant (§12.7, host/transport-host.ts). Raw primitives only: what a path is, which
// addresses are candidates and how a stream gets across are the transport's (udp.js).

/** A platform's datagram sockets. */
export interface RawDatagrams {
  /** A socket on a port the OS picks, dual-stack where the machine has IPv6, asking for
   *  kernel receive and send buffers of `bufferBytes`; a kernel that grants less is no
   *  failure. What it reads arrives at `deliver` in batches of
   *  `[n u8][ip n][port u16][len u16][bytes]`, n 4 for IPv4 and 16 for IPv6. */
  bind(deliver: (batch: Uint8Array | ArrayBuffer) => void, bufferBytes: number):
    { id: number; port: number } | Promise<{ id: number; port: number }>;
  /** One datagram; a failure is a lost one. A name rather than an address resolves to
   *  IPv4. */
  send(id: number, host: string, port: number, bytes: Uint8Array): void;
  close(id: number): void;
  /** Every address this machine's sockets are reached at, `\n`-separated. */
  addresses(): string;
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
