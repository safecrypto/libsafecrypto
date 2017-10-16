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

#include "prng_types.h"
#include <stdio.h>

#define WHIRLPOOL_BLOCK_SIZE 64

/* algorithm context */
typedef struct whirlpool_ctx
{
	uint64_t hash[8];    /* 512-bit algorithm internal hashing state */

	unsigned char message[WHIRLPOOL_BLOCK_SIZE]; /* 512-bit buffer to hash */

	/* Note: original algorith uses 256-bit counter, allowing to hash up to
	   2^256 bits sized message. For optimization we use here 64-bit counter,
	   thus reducing maximal message size to 2^64 bits = 2 Exbibytes = 2^21 TiB) */
	uint64_t length;     /* number of processed bytes */
} whirlpool_ctx;


/* hash functions */

SINT32 whirlpool_init(void* ctx, SINT32 mdlen);
SINT32 whirlpool_update(void* ctx, const void* msg, size_t size);
SINT32 whirlpool_final(void* ctx, void* result);

