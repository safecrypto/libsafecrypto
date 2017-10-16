/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#pragma once

#include "prng_types.h"
#include <string.h>

typedef struct salsa_ctx_t {
    uint32_t input[16];
} salsa_ctx_t;

void salsa20_core(const UINT32 *input, UINT8 *output);

void salsa_keysetup(salsa_ctx_t *ctx, const UINT8 *k, UINT32 kbits);
void salsa_ivsetup(salsa_ctx_t *ctx, const UINT8 *iv, const UINT8* counter);
void salsa_ietf_ivsetup(salsa_ctx_t *ctx, const UINT8 *iv, const UINT8* counter);
void salsa_encrypt_bytes(salsa_ctx_t *ctx, const UINT8 *m, UINT8 *c, size_t bytes);
void salsa_decrypt_bytes(salsa_ctx_t *ctx, const UINT8 *c, UINT8 *m, size_t bytes);
void salsa_keystream_bytes(salsa_ctx_t *ctx, UINT8 *stream, size_t bytes);
