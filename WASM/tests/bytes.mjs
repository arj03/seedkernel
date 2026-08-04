// Byte comparison for assertions. A test helper, not a runtime one: nothing in
// core/ or host/ compares two byte arrays for equality — every comparison the
// runtime actually makes is a *cryptographic* one, and those go through libsodium
// (`crypto_sign_verify_detached`, the AEAD tag check), which compares in constant
// time. A plain early-return loop like this one leaks its answer through timing,
// so keeping it out of the runtime tree is what stops it from being reached for on
// a path where that matters.

/** True when `a` and `b` hold the same bytes. NOT constant-time — assertions only. */
export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
