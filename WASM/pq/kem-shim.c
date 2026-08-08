/*
 * kem-shim.c — the entire seedkernel-specific surface of mlkem768.wasm.
 *
 * Three exports over mlkem-native's derandomized core API, in the shape the
 * runtime's crypto seam already speaks: raw byte pointers into linear memory, no
 * key objects, no formats, no allocation. Every buffer is caller-owned and its
 * length is a format constant of the parameter set, so there is nothing here to get
 * wrong at runtime.
 *
 * Randomness is an *argument*, never a syscall — the same rule shim.c states for
 * ML-DSA, and here it does double duty. It keeps the module import-free, so one
 * artifact instantiates identically under Node, under a browser, and under wazero
 * in the Go host with no per-target glue to disagree about (§12.9). And it is what
 * lets the KEM enter the primitive catalog at all: a catalog entry is a pure
 * function of its argument bytes (guest-seam.ts), so the coins come from `RANDOM`
 * — an authority the guest already holds — rather than from inside the primitive.
 *
 * There is no `check_pk` / `check_sk` export. FIPS 203's modulus and hash checks
 * are not optional extras a caller might skip: enc_derand and dec run them
 * themselves and return failure, which is what the `ok` byte in the catalog's
 * output carries. Exporting them separately would offer a second, weaker way to
 * ask the same question.
 */

#include <stddef.h>
#include <stdint.h>

#include "mlkem_native.h"

/* memcpy/memset for the freestanding target: mlkem-native itself routes through
 * mlk_memcpy/mlk_memset (kem-config.h), but clang may still emit calls to these
 * for struct copies and loop idioms, and there is no libc linked to satisfy them. */
void *memcpy(void *dest, const void *src, size_t n)
{
  unsigned char *d = (unsigned char *)dest;
  const unsigned char *s = (const unsigned char *)src;
  size_t i;
  for (i = 0; i < n; i++)
  {
    d[i] = s[i];
  }
  return dest;
}

void *memset(void *s, int c, size_t n)
{
  unsigned char *p = (unsigned char *)s;
  size_t i;
  for (i = 0; i < n; i++)
  {
    p[i] = (unsigned char)c;
  }
  return s;
}

#define EXPORT __attribute__((visibility("default")))

/* KeyGen_Internal (FIPS 203 Algorithm 16). `coins` is 2*32 bytes: (d ‖ z). */
EXPORT int mlkem768_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *coins)
{
  return crypto_kem_keypair_derand(pk, sk, coins) == 0;
}

/* Encaps_Internal (FIPS 203 Algorithm 17). `coins` is 32 bytes (m). Returns 0 when
 * the public key fails the modulus check of FIPS 203 §7.2 — a malformed peer key,
 * which the caller must be able to tell from a good one. */
EXPORT int mlkem768_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                           const uint8_t *coins)
{
  return crypto_kem_enc_derand(ct, ss, pk, coins) == 0;
}

/* Decaps (FIPS 203 Algorithm 21). Returns 0 only when the secret key fails the hash
 * check of FIPS 203 §7.3 — a corrupt key, not a bad ciphertext. A ciphertext that
 * does not decrypt is NOT an error: ML-KEM's implicit rejection returns a shared
 * secret derived from the key's z instead, in constant time, and reporting that
 * apart from success is exactly the oracle implicit rejection exists to deny. */
EXPORT int mlkem768_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
  return crypto_kem_dec(ss, ct, sk) == 0;
}

/* Field widths, exported so the JS and Go sides read them out of the artifact
 * instead of repeating them — a build against the wrong parameter set should fail
 * loudly at load, not silently produce a KEM for a different one. */
EXPORT int mlkem768_publickeybytes(void) { return MLKEM768_PUBLICKEYBYTES; }
EXPORT int mlkem768_secretkeybytes(void) { return MLKEM768_SECRETKEYBYTES; }
EXPORT int mlkem768_ciphertextbytes(void) { return MLKEM768_CIPHERTEXTBYTES; }
EXPORT int mlkem768_bytes(void) { return MLKEM768_BYTES; }
EXPORT int mlkem768_symbytes(void) { return MLKEM768_SYMBYTES; }
