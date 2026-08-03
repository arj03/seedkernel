/*
 * Freestanding <assert.h> for the wasm32 build.
 *
 * mldsa-native's FIPS 202 core carries a handful of NDEBUG-guarded asserts. This
 * build defines NDEBUG (a release artifact, and there is no stderr to report to in
 * a wasm module with no imports), so `assert` compiles to nothing — the same thing
 * a real <assert.h> does under NDEBUG. The header exists only so the include
 * resolves without a sysroot.
 */
#ifndef SEEDKERNEL_FREESTANDING_ASSERT_H
#define SEEDKERNEL_FREESTANDING_ASSERT_H

#define assert(cond) ((void)0)

#endif
