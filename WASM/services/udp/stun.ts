// STUN Binding (RFC 8489), the one request a UDP path makes of a server: what address the
// internet sees this socket at. The request carries no attributes and only
// XOR-MAPPED-ADDRESS is read from the answer, which is all a server must send, and all
// seedrelay's `--stun` does. IPv4 only, as the path's sockets are.

const COOKIE = 0x2112a442;
const BINDING_REQUEST = 0x0001, BINDING_SUCCESS = 0x0101, XOR_MAPPED_ADDRESS = 0x0020;
const IPV4 = 1;

/** A Binding request under transaction id `txn` (12 bytes). */
export function bindingRequest(txn: Uint8Array): Uint8Array {
  const out = new Uint8Array(20);
  const v = new DataView(out.buffer);
  v.setUint16(0, BINDING_REQUEST);
  v.setUint32(4, COOKIE);
  out.set(txn, 8);
  return out;
}

/** Whether a datagram is STUN at all, which a path's own packets never are: STUN's first
 *  two bits are zero, and its cookie follows the length. */
export function isStun(msg: Uint8Array): boolean {
  return msg.length >= 20 && msg[0] < 2 && new DataView(msg.buffer, msg.byteOffset).getUint32(4) === COOKIE;
}

/** The `host:port` a Binding success for `txn` names, or null for anything else. */
export function mappedAddress(msg: Uint8Array, txn: Uint8Array): string | null {
  if (!isStun(msg)) return null;
  const v = new DataView(msg.buffer, msg.byteOffset, msg.byteLength);
  if (v.getUint16(0) !== BINDING_SUCCESS || v.getUint16(2) !== msg.length - 20) return null;
  for (let i = 0; i < 12; i++) if (msg[8 + i] !== txn[i]) return null;
  for (let at = 20; at + 4 <= msg.length; at += 4 + ((v.getUint16(at + 2) + 3) & ~3)) {
    const len = v.getUint16(at + 2);
    if (at + 4 + len > msg.length) return null;
    if (v.getUint16(at) !== XOR_MAPPED_ADDRESS || len !== 8 || msg[at + 5] !== IPV4) continue;
    // The port XORed with the cookie's top half, the address with the cookie.
    const port = v.getUint16(at + 6) ^ (COOKIE >>> 16);
    const host = [0, 1, 2, 3].map((i) => msg[at + 8 + i] ^ msg[4 + i]).join(".");
    return `${host}:${port}`;
  }
  return null;
}
