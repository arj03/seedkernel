// Byte comparison for assertions, and deliberately not a runtime helper: every
// comparison the runtime makes is a cryptographic one and goes through libsodium
// (`crypto_sign_verify_detached`, the AEAD tag check), which compares in constant time.
// An early-return loop like this leaks its answer through timing, so keeping it out of
// the runtime tree is what stops it being reached for where that matters.

/** True when `a` and `b` hold the same bytes. NOT constant-time — assertions only. */
export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
