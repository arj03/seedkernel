/*
 * The seedkernel-specific part of mldsa65.wasm.
 *
 * Three exports over mldsa-native's core API, matching the runtime's crypto seam:
 * raw byte pointers into linear memory, no key objects, no formats, no allocation.
 * Every buffer is caller-owned and its length is a format constant (§12.4).
 *
 * FIPS 204 pure mode prefixes the message with `0x00 ‖ ctxlen ‖ ctx`. The context
 * is passed through the ABI even though the runtime always passes an empty one: its
 * domain separation is the DOMAIN_manifest prefix inside the signed preimage
 * (§16.1), and it should not use two mechanisms. Keeping the parameter costs two
 * arguments and lets the published ACVP vectors, most of which use a context, run
 * unmodified.
 *
 * Randomness is an argument, never a syscall, so the module has no imports and
 * instantiates identically under Node, a browser and wazero in the Go host, with no
 * per-target glue (§12.9).
 */

#include <stddef.h>
#include <stdint.h>

#include "mldsa_native.h"

/* memcpy/memset for the freestanding target: mldsa-native itself routes through
 * mld_memcpy/mld_memset (config.h), but clang may still emit calls to these for
 * struct copies and loop idioms, and there is no libc linked to satisfy them. */
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

/* FIPS 204 pure-mode prefix: 0x00 ‖ ctxlen ‖ ctx, at most 2 + 255 bytes. Static
 * because the module is single-threaded and cannot be re-entered: each call runs to
 * completion. */
static uint8_t mld_pre[257];

static size_t mld_build_pre(const uint8_t *ctx, size_t ctxlen)
{
  size_t i;
  mld_pre[0] = 0x00;
  mld_pre[1] = (uint8_t)ctxlen;
  for (i = 0; i < ctxlen; i++)
  {
    mld_pre[2 + i] = ctx[i];
  }
  return 2 + ctxlen;
}

#define EXPORT __attribute__((visibility("default")))

/* Verify. Returns 1 for a good signature, 0 for anything else, since the runtime's
 * verifiers are booleans (`crypto_sign_verify_detached`). Collapsing here instead of
 * in JS keeps both halves of the suite failing the same way. */
EXPORT int mldsa65_verify(const uint8_t *sig, const uint8_t *m, size_t mlen,
                          const uint8_t *ctx, size_t ctxlen, const uint8_t *pk)
{
  size_t prelen;
  if (ctxlen > 255)
  {
    return 0;
  }
  prelen = mld_build_pre(ctx, ctxlen);
  return mld65_verify_internal(sig, m, mlen, mld_pre, prelen, pk, 0) == 0;
}

/* Sign. `rnd` is the 32 bytes of FIPS 204 hedging randomness, supplied by the
 * caller from the host's own CSPRNG. Returns 1 on success. */
EXPORT int mldsa65_sign(uint8_t *sig, const uint8_t *m, size_t mlen,
                        const uint8_t *ctx, size_t ctxlen, const uint8_t *rnd,
                        const uint8_t *sk)
{
  size_t prelen;
  if (ctxlen > 255)
  {
    return 0;
  }
  prelen = mld_build_pre(ctx, ctxlen);
  return mld65_signature_internal(sig, m, mlen, mld_pre, prelen, rnd, sk, 0) == 0;
}

/* Key generation from a caller-supplied 32-byte seed. */
EXPORT int mldsa65_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed)
{
  return mld65_keypair_internal(pk, sk, seed) == 0;
}

/* Field widths, exported so the JS and Go sides can check them against the
 * envelope format's constants at load: a build against the wrong parameter set
 * fails there instead of verifying a different algorithm. */
EXPORT int mldsa65_publickeybytes(void) { return MLDSA65_PUBLICKEYBYTES; }
EXPORT int mldsa65_secretkeybytes(void) { return MLDSA65_SECRETKEYBYTES; }
EXPORT int mldsa65_signaturebytes(void) { return MLDSA65_BYTES; }
EXPORT int mldsa65_seedbytes(void) { return MLDSA_SEEDBYTES; }
EXPORT int mldsa65_rndbytes(void) { return MLDSA_RNDBYTES; }
