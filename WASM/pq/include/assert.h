/*
 * Freestanding <assert.h> for the wasm32 build.
 *
 * mldsa-native's FIPS 202 core has a few NDEBUG-guarded asserts. This build defines
 * NDEBUG (a release artifact, and a wasm module with no imports has no stderr), so
 * `assert` compiles to nothing, as a real <assert.h> does under NDEBUG. The header
 * exists only so the include resolves without a sysroot.
 */
#ifndef SEEDKERNEL_FREESTANDING_ASSERT_H
#define SEEDKERNEL_FREESTANDING_ASSERT_H

#define assert(cond) ((void)0)

#endif
