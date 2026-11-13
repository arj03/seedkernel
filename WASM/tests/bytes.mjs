// Byte comparison for assertions only, not a runtime helper: every comparison the runtime
// makes is cryptographic and goes through libsodium (`crypto_sign_verify_detached`, the
// AEAD tag check), which compares in constant time. An early-return loop like this leaks
// its answer through timing, so it stays out of the runtime tree.

/** A realm call's payload, which the host may hand over as parts, as one buffer. */
export function joined(parts) {
  if (parts instanceof Uint8Array) return parts;
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

/** True when `a` and `b` hold the same bytes. Not constant-time; assertions only. */
export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
