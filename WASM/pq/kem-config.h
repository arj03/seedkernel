/*
 * mlkem-native configuration for seedkernel's freestanding wasm32 build.
 *
 * The counterpart of pq/config.h, with the same four choices for the same reasons,
 * each removing something from the artifact:
 *
 *  - PARAMETER_SET 768      the parameter set the transport bundle's `mlkem` module uses
 *  - NO_RANDOMIZED_API      leaves only keypair_derand / enc_derand / dec, the
 *                           variants that take their randomness as an argument. The
 *                           randomized wrappers would pull in randombytes(), an
 *                           import every host (Go included) would have to provide
 *                           identically. The module has no imports, only exports,
 *                           and stays a pure function: the guest gets its coins from
 *                           `crypto/random` and passes them in, just as an ephemeral
 *                           X25519 pair is `crypto/random` plus `crypto/x25519/dh`.
 *  - CUSTOM_MEMCPY/SET      mlkem-native's only libc dependency is memcpy and memset
 *                           (STDLIB.md). Supplying both here means the build needs no
 *                           sysroot, wasi-libc or emscripten, only clang's own
 *                           freestanding headers.
 *  - CUSTOM_ZEROIZE         the default uses SecureZeroMemory or a memset plus a
 *                           compiler barrier. The replacement writes through a
 *                           volatile pointer, the portable way to keep the compiler
 *                           from eliding a wipe of memory that is never read again.
 */

#define MLK_CONFIG_PARAMETER_SET 768

/* Symbol prefix. Set explicitly because this file replaces mlkem_native_config.h
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
