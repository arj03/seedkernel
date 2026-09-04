// Small helpers shared across the runtime host. No dependencies.

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

/** A queue whose pop is O(1): a head index into a plain array, with the consumed prefix
 *  dropped once it outnumbers what is still live.
 *
 *  `Array.prototype.shift` moves every remaining element, so draining a full queue costs
 *  O(n²) — and every queue here is BOUNDED, which means the quadratic term is paid exactly
 *  when the bound is doing its job and the queue is full. The same shape as the framer's
 *  `ByteParts`, which is where the amortization constants come from. */
export class Fifo<T> {
  private items: T[] = [];
  private head = 0;

  /** Live entries — never `items.length`, which counts the consumed prefix too. */
  get size(): number { return this.items.length - this.head; }

  push(v: T): void { this.items.push(v); }

  /** The front, still queued. Undefined only when empty. */
  peek(): T | undefined { return this.head < this.items.length ? this.items[this.head] : undefined; }

  /** The i-th live entry, oldest first. Callers bound `i` by `size`; past it reads
   *  undefined, which is a bug rather than a case. */
  at(i: number): T { return this.items[this.head + i]; }

  shift(): T | undefined {
    if (this.head >= this.items.length) return undefined;
    const v = this.items[this.head];
    this.drop(1);
    return v;
  }

  /** Discard the oldest `n`, for the caller that scanned a prefix before deciding. The
   *  slots are cleared as they go: a consumed entry the array still points at would stay
   *  reachable until the next compaction. */
  drop(n: number): void {
    const end = Math.min(this.head + n, this.items.length);
    while (this.head < end) this.items[this.head++] = undefined as unknown as T;
    if (this.head >= 8 && this.head * 2 >= this.items.length) {
      this.items = this.items.slice(this.head);
      this.head = 0;
    }
  }

  clear(): void { this.items = []; this.head = 0; }
}
