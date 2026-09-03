// Small byte helpers shared across the runtime host. No dependencies.

const HEX_BYTE = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));

/** One TextEncoder/TextDecoder for the whole host. Both are stateless and present on every
 *  target (the native shell polyfills them, host/native-polyfills.ts). */
export const enc = new TextEncoder();
export const dec = new TextDecoder();

export function toHex(b: Uint8Array): string {
  const out = new Array<string>(b.length);
  for (let i = 0; i < b.length; i++) out[i] = HEX_BYTE[b[i]];
  return out.join("");
}

export function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

/** 32 bytes as lowercase hex — the shape of every key and secret an operator types.
 *  `fromHex` maps a non-hex pair to 0, so an unvalidated decode turns a typo into a
 *  different-but-plausible 32 bytes. */
const HEX64 = /^[0-9a-f]{64}$/;
export function isHex64(s: string): boolean {
  return HEX64.test(s);
}

export function concatBytes(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function writeU32BE(out: Uint8Array, offset: number, value: number): void {
  out[offset] = (value >>> 24) & 0xff;
  out[offset + 1] = (value >>> 16) & 0xff;
  out[offset + 2] = (value >>> 8) & 0xff;
  out[offset + 3] = value & 0xff;
}

export function readU32BE(buf: Uint8Array, offset: number): number {
  return ((buf[offset] << 24) | (buf[offset + 1] << 16) |
          (buf[offset + 2] << 8) | buf[offset + 3]) >>> 0;
}

/** Base64 → bytes via the platform's `atob` (a browser global; also in Node ≥16 and in
 *  the native shell's QuickJS). */
export function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function errMessage(e: unknown): string {
  const m = (e as Error | null)?.message;
  return m == null ? String(e) : String(m);
}
