/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#pragma once

#include "prng_types.h"
#include <string.h>

PRNG_STRUCT_PACK_START
typedef struct chacha_ctx_t {
    uint32_t input[16];
} PRNG_STRUCT_PACKED chacha_ctx_t;
PRNG_STRUCT_PACK_END

void chacha_keysetup(chacha_ctx_t *ctx, const UINT8 *k, UINT32 kbits);
void chacha_ivsetup(chacha_ctx_t *ctx, const UINT8 *iv, const UINT8* counter);
void chacha_ietf_ivsetup(chacha_ctx_t *ctx, const UINT8 *iv, const UINT8* counter);
void chacha_encrypt_bytes(chacha_ctx_t *ctx, const UINT8 *m, UINT8 *c, size_t bytes);
void chacha_decrypt_bytes(chacha_ctx_t *ctx, const UINT8 *c, UINT8 *m, size_t bytes);
void chacha_keystream_bytes(chacha_ctx_t *ctx, UINT8 *stream, size_t bytes);
