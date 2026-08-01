/*
 * Freestanding <string.h> for the wasm32 build.
 *
 * mldsa-native's whole libc surface is memcpy and memset (its STDLIB.md), and
 * pq/config.h already redirects both to local definitions — but a few of its .c
 * files include <string.h> unconditionally, and a freestanding clang has no libc
 * headers to find. Declaring the two functions here is enough, and it keeps the
 * build free of a sysroot: no wasi-libc, no emscripten, no toolchain to install
 * beyond clang itself. The definitions live in pq/shim.c.
 */
#ifndef SEEDKERNEL_FREESTANDING_STRING_H
#define SEEDKERNEL_FREESTANDING_STRING_H

#include <stddef.h>

void *memcpy(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);

#endif
