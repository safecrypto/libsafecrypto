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

#include "safecrypto_private.h"


utils_crypto_xof_t * utils_crypto_xof_create(crypto_xof_e type)
{
    utils_crypto_xof_t *crypto_xof = SC_MALLOC(sizeof(utils_crypto_xof_t));

    switch (type)
    {
#ifdef ENABLE_SHA3
        case CRYPTO_XOF_SHAKE256:
        {
            crypto_xof->type    = CRYPTO_XOF_SHAKE256;
            crypto_xof->length  = 32;
            crypto_xof->init    = tinysha3_init;
            crypto_xof->absorb  = tinysha3_update;
            crypto_xof->final   = tinysha3_xof_final;
            crypto_xof->squeeze = tinysha3_xof;
            crypto_xof->ctx     = SC_MALLOC(sizeof(sha3_ctx_t));
        } break;

        case CRYPTO_XOF_SHAKE128:
        {
            crypto_xof->type    = CRYPTO_XOF_SHAKE128;
            crypto_xof->length  = 16;
            crypto_xof->init    = tinysha3_init;
            crypto_xof->absorb  = tinysha3_update;
            crypto_xof->final   = tinysha3_xof_final;
            crypto_xof->squeeze = tinysha3_xof;
            crypto_xof->ctx     = SC_MALLOC(sizeof(sha3_ctx_t));
        } break;

#ifdef HAVE_AVX2
        case CRYPTO_XOF_SHAKE256_4X:
        {
            crypto_xof->type    = CRYPTO_XOF_SHAKE256_4X;
            crypto_xof->length  = 128;
            crypto_xof->init    = tinysha3_init_4x;
            crypto_xof->absorb  = tinysha3_update_4x;
            crypto_xof->final   = tinysha3_xof_final_4x;
            crypto_xof->squeeze = tinysha3_xof_4x;
            crypto_xof->ctx     = SC_MALLOC(sizeof(sha3_4x_ctx_t));
        } break;

        case CRYPTO_XOF_SHAKE128_4X:
        {
            crypto_xof->type    = CRYPTO_XOF_SHAKE128_4X;
            crypto_xof->length  = 64;
            crypto_xof->init    = tinysha3_init_4x;
            crypto_xof->absorb  = tinysha3_update_4x;
            crypto_xof->final   = tinysha3_xof_final_4x;
            crypto_xof->squeeze = tinysha3_xof_4x;
            crypto_xof->ctx     = SC_MALLOC(sizeof(sha3_4x_ctx_t));
        } break;
#endif
#endif

        default:
        {
            SC_FREE(crypto_xof, sizeof(utils_crypto_xof_t));
            crypto_xof = NULL;
        };
    }

    return crypto_xof;
}

SINT32 utils_crypto_xof_destroy(utils_crypto_xof_t *xof)
{
    if (NULL == xof) {
        return SC_FUNC_FAILURE;
    }

    switch (xof->type)
    {
#ifdef ENABLE_SHA3
        case CRYPTO_XOF_SHAKE256:
        case CRYPTO_XOF_SHAKE128:
#ifdef HAVE_AVX2
        case CRYPTO_XOF_SHAKE256_4X:
        case CRYPTO_XOF_SHAKE128_4X:
#endif
        {
            SC_FREE(xof->ctx, sizeof(sha3_ctx_t));
        } break;
#endif

        default:
        {
            return SC_FUNC_FAILURE;
        };
    }

    SC_FREE(xof, sizeof(utils_crypto_xof_t));

    return SC_FUNC_SUCCESS;
}

SINT32 xof_init(utils_crypto_xof_t *c)
{
    if (NULL == c) {
        return SC_FUNC_FAILURE;
    }
    return c->init(c->ctx, c->length);
}

SINT32 xof_absorb(utils_crypto_xof_t *c, const void *data, size_t len)
{
    if (NULL == c || NULL == data) {
        return SC_FUNC_FAILURE;
    }
    if (0 == len) {
        return SC_FUNC_SUCCESS;
    }
    return c->absorb(c->ctx, data, len);
}

SINT32 xof_final(utils_crypto_xof_t *c)
{
    if (NULL == c) {
        return SC_FUNC_FAILURE;
    }
    return c->final(c->ctx);
}

SINT32 xof_squeeze(utils_crypto_xof_t *c, void *output, size_t len)
{
    if (NULL == c || NULL == output) {
        return SC_FUNC_FAILURE;
    }
    return c->squeeze(c->ctx, output, len);
}

