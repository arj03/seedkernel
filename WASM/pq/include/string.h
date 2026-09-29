/*
 * Freestanding <string.h> for the wasm32 build.
 *
 * mldsa-native only uses memcpy and memset from libc (its STDLIB.md), and pq/config.h
 * redirects both to local definitions, but a few of its .c files include <string.h>
 * unconditionally and a freestanding clang has no libc headers. Declaring the two
 * functions here is enough and keeps the build free of a sysroot. The definitions
 * are in pq/shim.c.
 */
#ifndef SEEDKERNEL_FREESTANDING_STRING_H
#define SEEDKERNEL_FREESTANDING_STRING_H

#include <stddef.h>

void *memcpy(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);

#endif
