// Envelope codec wire format (README §2):
//   magic(2) + version(1) + name_len(1) + name + payload
//
// `decode` / `Envelope` are the readable reference codec for the format and the
// "Envelope.Decode" step in the README §3 flowchart. The kernel's hot path
// (`dispatch` in index.ts) re-implements the same parse inline and zero-copy
// for speed and does NOT call `decode` (so it is tree-shaken from the kernel
// binary); the two are kept in lockstep so this stays a faithful spec reference.

export const MAGIC: u16 = 0x5344; // "SD"
export const CURRENT_VERSION: u8 = 0x01;
// Hard upper bound on the total envelope (README §2.2). Both encode and
// dispatch enforce this so an oversize buffer is rejected at its source.
export const MAX_ENVELOPE_BYTES: i32 = 65536;

export class Envelope {
  version: u8;
  name: Uint8Array;
  payload: Uint8Array;

  constructor(version: u8, name: Uint8Array, payload: Uint8Array) {
    this.version = version;
    this.name = name;
    this.payload = payload;
  }
}

export function decode(bytes: Uint8Array): Envelope | null {
  if (bytes.length < 4) return null;

  const magic: u16 = ((bytes[0] as u16) << 8) | (bytes[1] as u16);
  if (magic != MAGIC) return null;

  const version = bytes[2];
  if (version != CURRENT_VERSION) return null;

  const nameLen = bytes[3] as i32;
  if (nameLen == 0) return null; // zero-length name is reserved/invalid (§2)
  if (4 + nameLen > bytes.length) return null;

  const name = bytes.subarray(4, 4 + nameLen);
  const payload = bytes.subarray(4 + nameLen);
  return new Envelope(version, name, payload);
}
