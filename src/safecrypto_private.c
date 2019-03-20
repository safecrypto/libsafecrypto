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

#include "safecrypto_private.h"

#include <stdlib.h>
#include <string.h>


//------------------ ENDIAN CONVERSION HELPER FUNCTIONS ---------------------//

#ifdef HAVE_64BIT
void sc_swap_copy_64(void* to, size_t index, const void* from, size_t length)
{
    // If all pointers, offset and length are 64-bits aligned
    if ( 0 == (( (size_t)((UINT8*)to) | (size_t)((UINT8*)from) | index | length ) & 7) ) {
        // Efficiently copy aligned memory block as 64-bit integers
        const UINT64 *src = (const UINT64*)from;
        const UINT64 *end = (const UINT64*)((const UINT8*)src + length);
        UINT64 *dst = (UINT64*)((UINT8*)to + index);
        while (src < end) {
            *(dst++) = SC_BIG_ENDIAN_64(*(src));
            src++;
        }
    }
    else {
        // No alignment so copy is performed byte-per-byte
        const UINT8* src = (const UINT8*)from;
        for (length += index; index < length; index++) {
            ((UINT8*)to)[index ^ 7] = *(src++);
        }
    }
}
#endif

void sc_swap_copy_32(void* to, size_t index, const void* from, size_t length)
{
    // If all pointers, offset and length are 32-bits aligned
    if ( 0 == (( (size_t)((UINT8*)to) | (size_t)((UINT8*)from) | index | length ) & 3) ) {
        // Efficiently copy aligned memory block as 32-bit integers
        const UINT32 *src = (const UINT32*)from;
        const UINT32 *end = (const UINT32*)((const UINT8*)src + length);
        UINT32 *dst = (UINT32*)((UINT8*)to + index);
        while (src < end) {
            *(dst++) = SC_BIG_ENDIAN_32(*(src));
            src++;
        }
    }
    else {
        // No alignment so copy is performed byte-per-byte
        const UINT8* src = (const UINT8*)from;
        for (length += index; index < length; index++) {
            ((UINT8*)to)[index ^ 3] = *(src++);
        }
    }
}


//----------------- MEMORY ALLOCATION HELPER FUNCTIONS --------------------//

__attribute__((weak))
void dummy_symbol_to_prevent_lto(void * const ptr, const size_t len)
{
    (void) ptr;
    (void) len;
}

void *sc_malloc(size_t len)
{
#if defined(__linux__) && !defined(ENABLE_BAREMETAL)
    void *ptr = NULL;
    if (0 != posix_memalign(&ptr, 32, len)) {
        return NULL;
    }
    memset(ptr, 0, len);
#else
    void *ptr = malloc(len);
    memset(ptr, 0, len);
#endif
    return ptr;
}

void *sc_realloc(void *ptr, size_t size)
{
    return realloc(ptr, size);
}

void sc_free(void *pptr, size_t len)
{
    memset(pptr, 0, len);
    free(pptr);
}

SINT32 sc_mem_is_zero(volatile const UINT8 *a, size_t n)
{
    volatile SINT32 is_zero = 0;
    for (;n--;) {
        is_zero |= a[n];
    }
    // Will return 0 if the array a contains all zeros, non-zero otherwise
    return is_zero;
}

void sc_explicit_memzero(void * const ptr, const size_t len)
{
    memset(ptr, 0, len);
    dummy_symbol_to_prevent_lto(ptr, len);
}

void * sc_memcpy(void *dest, const void *src, size_t size)
{
    return memcpy(dest, src, size);
}

char* sc_strcpy(char *dest, const char *src, size_t dest_len)
{
    if (dest_len > 0)
    {
        dest[0] = '\0';
        strncat(dest, src, dest_len - 1);
    }

    return dest;
}

/// Free memory associated with statistics gathering
void sc_free_stats(safecrypto_t *sc)
{
#if 0
    size_t i;
    for (i=0; i<6; i++) {
        size_t num_components = sc->stats.num_components[i];
        if (num_components) {
            SC_FREE(sc->stats.components[i], (1 + num_components) * sizeof(sc_stat_coding_t));
        }
    }
#endif
}

/// Dynamically allocate memory depending upon what is required for
/// statistics gathering
SINT32 sc_init_stats(safecrypto_t *sc, size_t pub_key, size_t priv_key,
    size_t signature, size_t extract, size_t encrypt, size_t encapsulate)
{
    SC_MEMZERO(&sc->stats, sizeof(sc_statistics_t));

    sc->stats.scheme = sc->scheme;

    sc->stats.num_components[SC_STAT_PUB_KEY]     = pub_key;
    sc->stats.num_components[SC_STAT_PRIV_KEY]    = priv_key;
    sc->stats.num_components[SC_STAT_SIGNATURE]   = signature;
    sc->stats.num_components[SC_STAT_EXTRACT]     = extract;
    sc->stats.num_components[SC_STAT_ENCRYPT]     = encrypt;
    sc->stats.num_components[SC_STAT_ENCAPSULATE] = encapsulate;
#if 0
    size_t i;

    for (i=0; i<6; i++) {
        sc->stats.components[i] = NULL;
        if (sc->stats.num_components[i]) {
            sc->stats.components[i] = SC_MALLOC((1 + sc->stats.num_components[i]) * sizeof(sc_stat_coding_t));
            if (NULL == sc->stats.components[i]) {
                goto error_return;
            }
        }
    }
#endif

    return SC_FUNC_SUCCESS;

#if 0
error_return:
    sc_free_stats(sc);
    return SC_FUNC_FAILURE;
#endif
}

