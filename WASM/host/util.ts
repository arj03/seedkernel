// Small byte helpers shared across the runtime host. No dependencies.

const HEX_BYTE = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));

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

/** Map a raw handler name to the string key the host's name-keyed tables use.
 *  Lives here rather than in kernel-host.ts so the installer can key its records
 *  without importing the kernel host — the installer, the policy and the bundle
 *  loader are the portable core the native loader bundles (README §12.9), and the
 *  kernel host is a target-specific implementation of the seam they run over. */
export function nameKey(name: Uint8Array): string {
  return toHex(name);
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
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

/** A FIFO of bytes fed in arbitrary chunks. Receive paths use it so that
 *  accumulating a large message stays O(n): chunks are appended by reference and
 *  bytes are copied exactly once, when a complete record is taken out — instead
 *  of re-copying the whole buffer on every incoming chunk. */
export class ByteQueue {
  private chunks: Uint8Array[] = [];
  private head = 0; // read offset into chunks[0]
  private size = 0;

  get length(): number { return this.size; }

  push(chunk: Uint8Array): void {
    if (chunk.length === 0) return;
    this.chunks.push(chunk);
    this.size += chunk.length;
  }

  /** Copy of the first n bytes without consuming them; null if fewer buffered. */
  peek(n: number): Uint8Array | null {
    if (n > this.size) return null;
    const out = new Uint8Array(n);
    let o = 0, head = this.head;
    for (let i = 0; o < n; i++) {
      const c = this.chunks[i];
      const take = Math.min(c.length - head, n - o);
      out.set(c.subarray(head, head + take), o);
      o += take;
      head = 0;
    }
    return out;
  }

  /** Remove and return the first n bytes; null if fewer buffered. */
  take(n: number): Uint8Array | null {
    const out = this.peek(n);
    if (out !== null) this.drop(n);
    return out;
  }

  /** Discard the first n bytes (caps at what is buffered). */
  drop(n: number): void {
    let left = Math.min(n, this.size);
    this.size -= left;
    while (left > 0) {
      const avail = this.chunks[0].length - this.head;
      if (left < avail) { this.head += left; return; }
      left -= avail;
      this.chunks.shift();
      this.head = 0;
    }
  }
}
