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

#include "prng_types.h"
#include "safecrypto_private.h"

#include <stdlib.h>
#include <string.h>

const char *safecrypto_prng_names [16] = {
    "SC_PRNG_SYSTEM",
    "SC_PRNG_AES_CTR_DRBG",
    "SC_PRNG_AES_CTR",
    "SC_PRNG_CHACHA",
    "SC_PRNG_SALSA",
    "SC_PRNG_ISAAC",
    "SC_PRNG_KISS",
    "SC_PRNG_HASH_DRBG_SHA2_256",
    "SC_PRNG_HASH_DRBG_SHA2_512",
    "SC_PRNG_HASH_DRBG_SHA3_256",
    "SC_PRNG_HASH_DRBG_SHA3_512",
    "SC_PRNG_HASH_DRBG_BLAKE2_256",
    "SC_PRNG_HASH_DRBG_BLAKE2_512",
    "SC_PRNG_HASH_DRBG_WHIRLPOOL_512",
    "SC_PRNG_FILE",
    "SC_PRNG_HIGH_ENTROPY",
};


//------------------ ENDIAN CONVERSION HELPER FUNCTIONS ---------------------//

void *prng_malloc(size_t len)
{
#if defined(__linux__)
    void *ptr;
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

void prng_free(void *pptr, size_t len)
{
    memset(pptr, 0, len);
    free(pptr);
}

void prng_explicit_memzero(void * const ptr, const size_t len)
{
    memset(ptr, 0, len);
}

void * prng_memcpy(void *dest, const void *src, size_t size)
{
    return memcpy(dest, src, size);
}

char* prng_strcpy(char *dest, const char *src, size_t dest_len)
{
    if (dest_len > 0)
    {
        dest[0] = '\0';
        strncat(dest, src, dest_len - 1);
    }

    return dest;
}


//------------------ ENDIAN CONVERSION HELPER FUNCTIONS ---------------------//

#ifdef HAVE_64BIT
UINT64 prng_bswap_64(UINT64 x)
{
    union {
        UINT64 ll;
        UINT32 l[2];
    } w, r;
    w.ll = x;
    r.l[0] = SC_BIG_ENDIAN_32(w.l[1]);
    r.l[1] = SC_BIG_ENDIAN_32(w.l[0]);
    return r.ll;
}

void prng_swap_copy_64(void* to, SINT32 index, const void* from, size_t length)
{
    // If all pointers and length are 64-bits aligned
    if ( 0 == (( (SINT32)((UINT8*)to - (UINT8*)0) | ((UINT8*)from - (UINT8*)0) | index | length ) & 7) ) {
        // Copy aligned memory block as 64-bit integers
        const UINT64 *src = (const UINT64*)from;
        const UINT64 *end = (const UINT64*)((const UINT8*)src + length);
        UINT64 *dst = (UINT64*)((UINT8*)to + index);
        while (src < end) {
            *(dst++) = prng_bswap_64(*(src++));
        }
    }
    else {
        const UINT8* src = (const UINT8*)from;
        for (length += index; (size_t)index < length; index++) {
            ((UINT8*)to)[index ^ 7] = *(src++);
        }
    }
}
#endif

void prng_swap_copy_32(void* to, SINT32 index, const void* from, size_t length)
{
    // If all pointers and length are 32-bits aligned
    if ( 0 == (( (SINT32)((UINT8*)to - (UINT8*)0) | ((UINT8*)from - (UINT8*)0) | index | length ) & 3) ) {
        // Copy aligned memory block as 32-bit integers
        const UINT32 *src = (const UINT32*)from;
        const UINT32 *end = (const UINT32*)((const UINT8*)src + length);
        UINT32 *dst = (UINT32*)((UINT8*)to + index);
        while (src < end) {
            *(dst++) = SC_BIG_ENDIAN_32(*(src));
            src++;
        }
    }
    else {
        const UINT8* src = (const UINT8*)from;
        for (length += index; (size_t)index < length; index++) {
            ((UINT8*)to)[index ^ 3] = *(src++);
        }
    }
}
