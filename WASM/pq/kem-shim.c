/*
 * The seedkernel-specific part of mlkem768.wasm.
 *
 * Three low-level exports over mlkem-native's derandomized core API, plus the
 * pure-module `scratch`/`handle` ABI (§4), so a signed bundle can carry this as one of
 * its own modules instead of the host exposing a KEM to guests.
 *
 * Randomness is an argument, never a syscall, as in shim.c. The module has no imports,
 * so one artifact instantiates identically under Node, a browser and wazero in the Go
 * host (§12.9), and the KEM stays a pure module: the guest gets coins from
 * `crypto/random` and passes them in.
 *
 * There is no `check_pk` / `check_sk` export. FIPS 203's modulus and hash checks are
 * not optional: enc_derand and dec run them and return failure, which the `ok` byte in
 * the module's output carries. Separate exports would only add a second way to ask
 * the same question.
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
 * the public key fails the modulus check of FIPS 203 §7.2: a malformed peer key,
 * which the caller must be able to tell from a good one. */
EXPORT int mlkem768_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                           const uint8_t *coins)
{
  return crypto_kem_enc_derand(ct, ss, pk, coins) == 0;
}

/* Decaps (FIPS 203 Algorithm 21). Returns 0 only when the secret key fails the hash
 * check of FIPS 203 §7.3: a corrupt key, not a bad ciphertext. A ciphertext that does
 * not decrypt is not an error: ML-KEM's implicit rejection returns a shared secret
 * derived from the key's z instead, in constant time, and reporting it separately
 * would create the oracle implicit rejection is there to prevent. */
EXPORT int mlkem768_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
  return crypto_kem_dec(ss, ct, sk) == 0;
}

/* Field widths, exported so callers can check them at load: a build against the
 * wrong parameter set should fail there, not act as a KEM for a different one. */
EXPORT int mlkem768_publickeybytes(void) { return MLKEM768_PUBLICKEYBYTES; }
EXPORT int mlkem768_secretkeybytes(void) { return MLKEM768_SECRETKEYBYTES; }
EXPORT int mlkem768_ciphertextbytes(void) { return MLKEM768_CIPHERTEXTBYTES; }
EXPORT int mlkem768_bytes(void) { return MLKEM768_BYTES; }
EXPORT int mlkem768_symbytes(void) { return MLKEM768_SYMBYTES; }

/* Bundle-module ABI -------------------------------------------------------
 *
 * Request/response formats (the first byte is an operation tag):
 *   0 [seed 64]              -> [pk 1184][sk 2400]
 *   1 [pk 1184][coins 32]    -> [ok 1][ct 1088][ss 32]
 *   2 [sk 2400][ct 1088]     -> [ok 1][ss 32]
 *
 * Inputs are copied out of scratch before the primitive runs, so output can replace
 * the request even though the upstream implementation does not allow overlap.
 * The largest request is 3489 bytes. No `scratchSize` is exported, so the host assumes
 * its 128 KB default (§4.1), which is larger than this array; only the transport guest
 * calls this module, always with the exact widths above. */
#define MODULE_SCRATCH_BYTES 65536
#define OP_KEYPAIR 0
#define OP_ENCAPS 1
#define OP_DECAPS 2

EXPORT uint8_t scratch[MODULE_SCRATCH_BYTES];

static uint8_t kem_pk[MLKEM768_PUBLICKEYBYTES];
static uint8_t kem_sk[MLKEM768_SECRETKEYBYTES];
static uint8_t kem_ct[MLKEM768_CIPHERTEXTBYTES];
static uint8_t kem_ss[MLKEM768_BYTES];
static uint8_t kem_coins[2 * MLKEM768_SYMBYTES];

/* Keep secret-bearing temporaries from surviving the call or being optimized away. */
static void wipe(void *ptr, size_t n)
{
  volatile uint8_t *p = (volatile uint8_t *)ptr;
  while (n--) *p++ = 0;
}

EXPORT int handle(int input_len)
{
  if (input_len == 1 + 2 * MLKEM768_SYMBYTES && scratch[0] == OP_KEYPAIR)
  {
    memcpy(kem_coins, scratch + 1, 2 * MLKEM768_SYMBYTES);
    if (!mlkem768_keypair(kem_pk, kem_sk, kem_coins))
    {
      wipe(kem_coins, sizeof(kem_coins));
      wipe(kem_sk, sizeof(kem_sk));
      wipe(scratch, input_len);
      return 0;
    }
    memcpy(scratch, kem_pk, MLKEM768_PUBLICKEYBYTES);
    memcpy(scratch + MLKEM768_PUBLICKEYBYTES, kem_sk, MLKEM768_SECRETKEYBYTES);
    wipe(kem_coins, sizeof(kem_coins));
    wipe(kem_sk, sizeof(kem_sk));
    return MLKEM768_PUBLICKEYBYTES + MLKEM768_SECRETKEYBYTES;
  }

  if (input_len == 1 + MLKEM768_PUBLICKEYBYTES + MLKEM768_SYMBYTES && scratch[0] == OP_ENCAPS)
  {
    memcpy(kem_pk, scratch + 1, MLKEM768_PUBLICKEYBYTES);
    memcpy(kem_coins, scratch + 1 + MLKEM768_PUBLICKEYBYTES, MLKEM768_SYMBYTES);
    if (!mlkem768_encaps(kem_ct, kem_ss, kem_pk, kem_coins))
    {
      scratch[0] = 0;
      wipe(kem_coins, sizeof(kem_coins));
      wipe(kem_ss, sizeof(kem_ss));
      wipe(scratch + 1, input_len - 1);
      return 1;
    }
    scratch[0] = 1;
    memcpy(scratch + 1, kem_ct, MLKEM768_CIPHERTEXTBYTES);
    memcpy(scratch + 1 + MLKEM768_CIPHERTEXTBYTES, kem_ss, MLKEM768_BYTES);
    wipe(kem_coins, sizeof(kem_coins));
    wipe(kem_ss, sizeof(kem_ss));
    wipe(scratch + 1 + MLKEM768_CIPHERTEXTBYTES + MLKEM768_BYTES,
         input_len - (1 + MLKEM768_CIPHERTEXTBYTES + MLKEM768_BYTES));
    return 1 + MLKEM768_CIPHERTEXTBYTES + MLKEM768_BYTES;
  }

  if (input_len == 1 + MLKEM768_SECRETKEYBYTES + MLKEM768_CIPHERTEXTBYTES && scratch[0] == OP_DECAPS)
  {
    memcpy(kem_sk, scratch + 1, MLKEM768_SECRETKEYBYTES);
    memcpy(kem_ct, scratch + 1 + MLKEM768_SECRETKEYBYTES, MLKEM768_CIPHERTEXTBYTES);
    if (!mlkem768_decaps(kem_ss, kem_ct, kem_sk))
    {
      scratch[0] = 0;
      wipe(kem_sk, sizeof(kem_sk));
      wipe(kem_ss, sizeof(kem_ss));
      wipe(scratch + 1, input_len - 1);
      return 1;
    }
    scratch[0] = 1;
    memcpy(scratch + 1, kem_ss, MLKEM768_BYTES);
    wipe(kem_sk, sizeof(kem_sk));
    wipe(kem_ss, sizeof(kem_ss));
    wipe(scratch + 1 + MLKEM768_BYTES, input_len - (1 + MLKEM768_BYTES));
    return 1 + MLKEM768_BYTES;
  }

  /* A wrong tag or width may still carry secret bytes, so wipe it. The host passes a
   * non-negative length, but bound it here anyway. */
  if (input_len > 0 && input_len <= MODULE_SCRATCH_BYTES)
  {
    wipe(scratch, (size_t)input_len);
  }
  return 0;
}
