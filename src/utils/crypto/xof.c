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

#include "xof.h"
#include "sha3/tinysha3.h"
#include "sha3/fips202.h"


PRNG_STRUCT_PACK_START
typedef struct fips202_sha3_ctx_t {
    uint64_t state[25];
    uint8_t outbuf[SHAKE128_RATE];
    size_t len;
} PRNG_STRUCT_PACKED fips202_sha3_ctx_t;
PRNG_STRUCT_PACK_END


static int fips202_shake128_init(void *c, int mdlen)
{
    fips202_sha3_ctx_t *ctx = (fips202_sha3_ctx_t *) c;
    ctx->len = SHAKE128_RATE;
    return 1;
}

static int fips202_shake128_absorb(void *c, const void *data, size_t len)
{
    fips202_sha3_ctx_t *ctx = (fips202_sha3_ctx_t*) c;
    const uint8_t *in = (const uint8_t *) data;
    shake128_absorb(ctx->state, in, len);
    return 1;
}

static int fips202_shake128_squeeze(void *c, void *out, size_t len)
{
    fips202_sha3_ctx_t *ctx = (fips202_sha3_ctx_t*) c;

    size_t n = 0;
    while (n < len) {
        if (SHAKE128_RATE == ctx->len) {
            shake128_squeezeblocks(ctx->outbuf, 1, ctx->state);
            ctx->len = 0;
        }

        size_t l = ((SHAKE128_RATE - ctx->len) > len)? (SHAKE128_RATE - ctx->len) : SHAKE128_RATE;
        PRNG_MEMCOPY(out + n, ctx->outbuf + ctx->len, l);
        ctx->len += l;
        n += l;
    }

    return 1;
}

utils_crypto_xof_t * utils_crypto_xof_create(safecrypto_xof_e type)
{
    utils_crypto_xof_t *crypto_xof = PRNG_MALLOC(sizeof(utils_crypto_xof_t));

    switch (type)
    {
#ifdef ENABLE_SHA3
        case SC_XOF_SHAKE256:
        {
            crypto_xof->type    = SC_XOF_SHAKE256;
            crypto_xof->length  = 32;
            crypto_xof->init    = tinysha3_init;
            crypto_xof->absorb  = tinysha3_update;
            crypto_xof->final   = tinysha3_xof_final;
            crypto_xof->squeeze = tinysha3_xof;
            crypto_xof->ctx     = PRNG_MALLOC(sizeof(sha3_ctx_t));
        } break;

        case SC_XOF_SHAKE128:
        {
            crypto_xof->type    = SC_XOF_SHAKE128;
            crypto_xof->length  = 16;
            crypto_xof->init    = tinysha3_init;//fips202_shake128_init;
            crypto_xof->absorb  = tinysha3_update;//fips202_shake128_absorb;
            crypto_xof->final   = tinysha3_xof_final;
            crypto_xof->squeeze = tinysha3_xof;//fips202_shake128_squeeze;
            crypto_xof->ctx     = PRNG_MALLOC(sizeof(sha3_ctx_t));//PRNG_MALLOC(sizeof(fips202_sha3_ctx_t));
        } break;
#endif

        default:
        {
            PRNG_FREE(crypto_xof, sizeof(utils_crypto_xof_t));
            crypto_xof = NULL;
        };
    }

    return crypto_xof;
}

SINT32 utils_crypto_xof_destroy(utils_crypto_xof_t *xof)
{
    if (NULL == xof) {
        return PRNG_FUNC_FAILURE;
    }

    switch (xof->type)
    {
#ifdef ENABLE_SHA3
        case SC_XOF_SHAKE256:
        case SC_XOF_SHAKE128:
        {
            PRNG_FREE(xof->ctx, sizeof(sha3_ctx_t));
        } break;
#endif

        default:
        {
            return PRNG_FUNC_FAILURE;
        };
    }

    PRNG_FREE(xof, sizeof(utils_crypto_xof_t));

    return PRNG_FUNC_SUCCESS;
}

SINT32 xof_init(utils_crypto_xof_t *c)
{
    if (NULL == c) {
        return PRNG_FUNC_FAILURE;
    }
    return c->init(c->ctx, c->length);
}

SINT32 xof_absorb(utils_crypto_xof_t *c, const void *data, size_t len)
{
    if (NULL == c || NULL == data) {
        return PRNG_FUNC_FAILURE;
    }
    if (0 == len) {
        return PRNG_FUNC_SUCCESS;
    }
    return c->absorb(c->ctx, data, len);
}

SINT32 xof_final(utils_crypto_xof_t *c)
{
    if (NULL == c) {
        return PRNG_FUNC_FAILURE;
    }
    return c->final(c->ctx);
}

SINT32 xof_squeeze(utils_crypto_xof_t *c, void *output, size_t len)
{
    if (NULL == c || NULL == output) {
        return PRNG_FUNC_FAILURE;
    }
    return c->squeeze(c->ctx, output, len);
}

