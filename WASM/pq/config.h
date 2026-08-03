/*
 * mldsa-native configuration for seedkernel's freestanding wasm32 build.
 *
 * Three choices, each of which removes something from the artifact rather than
 * adding to it:
 *
 *  - PARAMETER_SET 65   the only set the manifest suite uses (§12.4)
 *  - CORE_API_ONLY      leaves only keypair_internal / signature_internal /
 *                       verify_internal — the variants that take their randomness
 *                       as an argument. The randomized wrappers are what would pull
 *                       randombytes() in, and an import the host must satisfy is an
 *                       import the Go host must satisfy identically. The module has
 *                       none: no imports at all, only exports.
 *  - CUSTOM_MEMCPY/SET  mldsa-native's whole libc dependency is memcpy and memset
 *                       (STDLIB.md). Supplying both here means the build needs no
 *                       sysroot, no wasi-libc, no emscripten — just clang's own
 *                       freestanding headers.
 *  - CUSTOM_ZEROIZE     the default zeroize reaches for <string.h> too. The
 *                       replacement writes through a volatile pointer, which is the
 *                       portable way to keep the compiler from eliding a wipe of
 *                       memory that is never read again.
 */

#define MLD_CONFIG_PARAMETER_SET 65

/* Symbol prefix. Set explicitly because this file REPLACES mldsa_native_config.h
 * (that is what MLD_CONFIG_FILE means), and the upstream default is defined at the
 * bottom of the file being replaced. */
#define MLD_CONFIG_NAMESPACE_PREFIX mld65
#define MLD_CONFIG_CORE_API_ONLY

#define MLD_CONFIG_CUSTOM_ZEROIZE
#define MLD_CONFIG_CUSTOM_MEMCPY
#define MLD_CONFIG_CUSTOM_MEMSET
#if !defined(__ASSEMBLER__)
#include <stddef.h>
#include <stdint.h>
static __attribute__((unused)) void *mld_memcpy(void *dest, const void *src, size_t n)
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
static __attribute__((unused)) void mld_zeroize(void *ptr, size_t len)
{
  volatile unsigned char *p = (volatile unsigned char *)ptr;
  size_t i;
  for (i = 0; i < len; i++)
  {
    p[i] = 0;
  }
}
static __attribute__((unused)) void *mld_memset(void *s, int c, size_t n)
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
