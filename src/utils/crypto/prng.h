/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

/*
 * Git commit information:
 *   Author: $SC_AUTHOR$
 *   Date:   $SC_DATE$
 *   Branch: $SC_BRANCH$
 *   Id:     $SC_IDENT$
 */

#pragma once

#include "safecrypto_types.h"
#include "prng_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// A bucket of random bits
#ifdef CONSTRAINED_RAM
#define RANDOM_POOL_SIZE        16
#else
#define RANDOM_POOL_SIZE        4096
#endif

#if RANDOM_POOL_SIZE < 4
#error RANDOM_POOL_SIZE must be 4 bytes or greater
#endif

/// Create and initialise the PRNG for the specified type
prng_ctx_t * prng_create(safecrypto_entropy_e entropy,
    safecrypto_prng_e type, safecrypto_prng_threading_e mt,
    size_t seed_period);

/// Set an external entropy source to be used when SC_ENTROPY_USER_PROVIDED is
/// selected as the entropy source
SINT32 prng_set_entropy(prng_ctx_t *ctx, const UINT8 *entropy, size_t len);

/// Set a callback function as the entropy source when SC_ENTROPY_CALLBACK is
/// selected as the entropy source
SINT32 prng_set_entropy_callback(prng_entropy_callback cb);

/// Once configured, initialise the PRNG
SINT32 prng_init(prng_ctx_t *ctx, const UINT8 *nonce, size_t len_nonce);

/// Return the type of PRNG that has been configured
safecrypto_prng_e prng_get_type(prng_ctx_t *ctx);

/// Destroy the specified PRNG instance
SINT32 prng_destroy(prng_ctx_t *ctx);

/// Reset the PRNG buffers
void prng_reset(prng_ctx_t *ctx);

/// Return the number of CSPRNG bytes that have thus far been generated
UINT64 prng_get_csprng_bytes(prng_ctx_t *ctx);

/// Return the number of bytes output by the PRNG
UINT64 prng_get_out_bytes(prng_ctx_t *ctx);

/// Extract a bit from the PRNG
SINT32 prng_bit(prng_ctx_t *ctx);

#if defined(HAVE_128BIT) && defined(__x86_64__)
/// Extract a 128-bit unsigned integer from the PRNG
UINT128 prng_128(prng_ctx_t *ctx);
#endif

#ifdef HAVE_64BIT
/// Extract a 64-bit unsigned integer from the PRNG
UINT64 prng_64(prng_ctx_t *ctx);
#endif

/// Extract a 32-bit unsigned integer from the PRNG
UINT32 prng_32(prng_ctx_t *ctx);

/// Extract a 16-bit unsigned integer from the PRNG
UINT16 prng_16(prng_ctx_t *ctx);

/// Extract an 8-bit unsigned integer from the PRNG
UINT8 prng_8(prng_ctx_t *ctx);

/// Extract a float from the PRNG
FLOAT prng_float(prng_ctx_t *ctx);

/// Extract a double unsigned integer from the PRNG
DOUBLE prng_double(prng_ctx_t *ctx);

/// Extract 1 to 32 bits from the PRNG
UINT32 prng_var(prng_ctx_t *ctx, size_t n);

/// Use the PRNG to obtain an array of random bytes
SINT32 prng_mem(prng_ctx_t *ctx, UINT8 *mem, SINT32 length);

#ifdef _ENABLE_CSPRNG_FILE
SINT32 prng_set_debug_file(prng_ctx_t *ctx, const char *filename);
#endif

#ifdef __cplusplus
}
#endif
