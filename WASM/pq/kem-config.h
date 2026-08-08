/*
 * mlkem-native configuration for seedkernel's freestanding wasm32 build.
 *
 * The sibling of pq/config.h, and the same four choices for the same reasons —
 * each one removes something from the artifact rather than adding to it:
 *
 *  - PARAMETER_SET 768      the only set the primitive catalog names
 *                           (the `ml-kem-768` catalog names, README §14.1)
 *  - NO_RANDOMIZED_API      leaves only keypair_derand / enc_derand / dec — the
 *                           variants that take their randomness as an argument. The
 *                           randomized wrappers are what would pull randombytes()
 *                           in, and an import the host must satisfy is an import
 *                           the Go host must satisfy identically. The module has
 *                           none: no imports at all, only exports. It is also what
 *                           keeps the catalog PURELY FUNCTIONAL — a bundle draws
 *                           its coins from `RANDOM`, an authority, and hands them
 *                           in, exactly as an ephemeral X25519 pair is `RANDOM(32)`
 *                           plus `x25519/dh` (guest-seam.ts).
 *  - CUSTOM_MEMCPY/SET      mlkem-native's whole libc dependency is memcpy and
 *                           memset (STDLIB.md). Supplying both here means the build
 *                           needs no sysroot, no wasi-libc, no emscripten — just
 *                           clang's own freestanding headers.
 *  - CUSTOM_ZEROIZE         the default reaches for SecureZeroMemory or a memset
 *                           plus a compiler barrier. The replacement writes through
 *                           a volatile pointer, which is the portable way to keep
 *                           the compiler from eliding a wipe of memory that is
 *                           never read again.
 */

#define MLK_CONFIG_PARAMETER_SET 768

/* Symbol prefix. Set explicitly because this file REPLACES mlkem_native_config.h
 * (that is what MLK_CONFIG_FILE means), and the upstream default is defined in the
 * file being replaced. */
#define MLK_CONFIG_NAMESPACE_PREFIX mlk768
#define MLK_CONFIG_NO_RANDOMIZED_API

#define MLK_CONFIG_CUSTOM_ZEROIZE
#define MLK_CONFIG_CUSTOM_MEMCPY
#define MLK_CONFIG_CUSTOM_MEMSET
#if !defined(__ASSEMBLER__)
#include <stddef.h>
#include <stdint.h>
static __attribute__((unused)) void *mlk_memcpy(void *dest, const void *src, size_t n)
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
static __attribute__((unused)) void mlk_zeroize(void *ptr, size_t len)
{
  volatile unsigned char *p = (volatile unsigned char *)ptr;
  size_t i;
  for (i = 0; i < len; i++)
  {
    p[i] = 0;
  }
}
static __attribute__((unused)) void *mlk_memset(void *s, int c, size_t n)
{
  unsigned char *p = (unsigned char *)s;
  size_t i;
  for (i = 0; i < n; i++)
  {
    p[i] = (unsigned char)c;
  }
  return s;
}
#endif
