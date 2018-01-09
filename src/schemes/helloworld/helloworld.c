/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "helloworld.h"
#include "safecrypto.h"
#include "safecrypto_debug.h"
#include "safecrypto_error.h"

#include <stdio.h>
#include <string.h>


int32_t helloworld_create(safecrypto_t *sc, SINT32 set, const UINT32 *flags)
{
    SC_PRINT_DEBUG(sc, "Entry: %s, %s, %d\n", __FUNCTION__, __FILE__, __LINE__);
    SC_PRINT_DEBUG(sc, "Exit: %s, %s, %d\n", __FUNCTION__, __FILE__, __LINE__);

    SC_PRINT_DEBUG(sc, "I appear at DEBUG level or lower\n");
    SC_PRINT_INFO(sc, "I appear at INFO level or lower\n");
    SC_PRINT_WARNING(sc, "I appear at WARNING level or lower\n");
    SC_PRINT_ERROR(sc, "I appear at ERROR level or lower\n");

    (void) set;
    (void) flags;
    sc->temp_size = 0;
    return SC_FUNC_SUCCESS;
}

int32_t helloworld_destroy(safecrypto_t *sc)
{
    SC_PRINT_DEBUG(sc, "Entry: %s, %s, %d\n", __FUNCTION__, __FILE__, __LINE__);
    SC_PRINT_DEBUG(sc, "Exit: %s, %s, %d\n", __FUNCTION__, __FILE__, __LINE__);

    (void) sc;
    return SC_FUNC_SUCCESS;
}

int32_t helloworld_sign(safecrypto_t *sc, const uint8_t *m, size_t m_len,
    uint8_t **sigret, size_t *siglen)
{
    SC_PRINT_DEBUG(sc, "Entry: %s, %s, %d\n", __FUNCTION__, __FILE__, __LINE__);

    if (m == NULL) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    if (*sigret == NULL) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    *siglen = 0;

    SC_PRINT_DEBUG(sc, "Exit: %s, %s, %d\n", __FUNCTION__, __FILE__, __LINE__);

    (void) m_len;
    return SC_FUNC_SUCCESS;
}

int32_t helloworld_verify(safecrypto_t *sc, const uint8_t *m, size_t m_len,
    const uint8_t *sigbuf, size_t siglen)
{
    SC_PRINT_DEBUG(sc, "Entry: %s, %s, %d\n", __FUNCTION__, __FILE__, __LINE__);

    if (m == NULL) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }
    if (sigbuf == NULL) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    SC_PRINT_DEBUG(sc, "Exit: %s, %s, %d\n", __FUNCTION__, __FILE__, __LINE__);

    (void) m_len;
    (void) siglen;
    return SC_FUNC_SUCCESS;
}

