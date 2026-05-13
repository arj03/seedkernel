// Envelope codec wire format (README §2):
//   magic(2) + version(1) + schema_id_len(1) + schema_id + payload

export const MAGIC: u16 = 0x5344; // "SD"
export const CURRENT_VERSION: u8 = 0x01;
// Hard upper bound on the total envelope (README §2.2). Both encode and
// dispatch enforce this so an oversize buffer is rejected at its source.
export const MAX_ENVELOPE_BYTES: i32 = 65536;

export class Envelope {
  version: u8;
  schemaId: Uint8Array;
  payload: Uint8Array;

  constructor(version: u8, schemaId: Uint8Array, payload: Uint8Array) {
    this.version = version;
    this.schemaId = schemaId;
    this.payload = payload;
  }
}

export function decode(bytes: Uint8Array): Envelope | null {
  if (bytes.length < 4) return null;

  const magic: u16 = ((bytes[0] as u16) << 8) | (bytes[1] as u16);
  if (magic != MAGIC) return null;

  const version = bytes[2];
  if (version != CURRENT_VERSION) return null;

  const schemaLen = bytes[3] as i32;
  if (schemaLen == 0) return null; // zero-length schema_id is reserved/invalid (§2)
  if (4 + schemaLen > bytes.length) return null;

  const schemaId = bytes.slice(4, 4 + schemaLen);
  const payload = bytes.slice(4 + schemaLen);
  return new Envelope(version, schemaId, payload);
}
