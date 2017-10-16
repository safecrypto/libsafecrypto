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

#include "safecrypto_private.h"
#include <string.h>

typedef struct sc_entropy sc_entropy_t;

typedef struct sc_packer sc_packer_t;

typedef SINT32 (*packer_write)(sc_packer_t *, UINT32, size_t);
typedef SINT32 (*packer_read)(sc_packer_t *, UINT32 *, size_t);

typedef SINT32 (*sig_encode)(sc_packer_t *, SINT32, SINT32 *, SINT32, SINT32 *, SINT32);
typedef SINT32 (*sig_decode)(sc_packer_t *, SINT32, SINT32 *, SINT32, SINT32 *, SINT32);
typedef SINT32 (*pub_key_encode)(sc_packer_t *, SINT32, SINT16 *, SINT32);
typedef SINT32 (*pub_key_decode)(sc_packer_t *, SINT32, SINT16 *, SINT32);
typedef SINT32 (*priv_key_encode)(sc_packer_t *, SINT32, SINT16 *, SINT16 *, SINT32);
typedef SINT32 (*priv_key_decode)(sc_packer_t *, SINT32, SINT16 *, SINT16 *, SINT32);

SC_STRUCT_PACK_START
typedef struct sc_packer {
	safecrypto_t *sc;
    SINT32 use_internal_buffer;
    size_t bits;
    size_t bits_left;
    UINT32 scratch;
    UINT8 *buffer;
    size_t buffer_alloc;
    size_t head;
    size_t tail;
    size_t bits_in;
    size_t bits_out;
    sc_entropy_t *coder;
    packer_read peek;
    packer_read read;
    packer_write write;
    sig_encode data_encode;
    sig_decode data_decode;
    pub_key_encode pub_encode;
    pub_key_decode pub_decode;
    priv_key_encode priv_encode;
    priv_key_decode priv_decode;
} SC_STRUCT_PACKED sc_packer_t;
SC_STRUCT_PACK_END


typedef sc_packer_t * (*entropy_create)(safecrypto_t *, sc_entropy_t *,
	size_t, const UINT8 *, size_t, UINT8 **, size_t *);
typedef SINT32 (*entropy_destroy)(sc_packer_t **);
typedef SINT32 (*entropy_decode)(sc_packer_t *, UINT32 *, size_t);
typedef SINT32 (*entropy_encode)(sc_packer_t *, UINT32, size_t);
typedef SINT32 (*entropy_remove)(sc_packer_t *, UINT32 *, size_t);
typedef SINT32 (*entropy_insert)(sc_packer_t *, UINT32, size_t);
typedef SINT32 (*entropy_flush)(sc_packer_t *);
typedef size_t (*entropy_get_bits)(sc_packer_t *);
typedef SINT32 (*entropy_get_buffer)(sc_packer_t *, UINT8 **, size_t *);
typedef UINT8* (*entropy_get_head)(sc_packer_t *);
typedef SINT32 (*entropy_reset_io_count)(sc_packer_t *);
typedef SINT32 (*entropy_get_io_count)(sc_packer_t *);

SC_STRUCT_PACK_START
typedef struct _utils_entropy {
    entropy_create         pack_create;
    entropy_destroy        pack_destroy;
    entropy_encode         pack_encode;
    entropy_decode         pack_decode;
    entropy_insert         pack_insert;
    entropy_remove         pack_remove;
    entropy_flush          pack_flush;
    entropy_get_bits       pack_is_data_avail;
    entropy_get_bits       pack_get_bits;
    entropy_get_buffer     pack_get_buffer;
    entropy_get_head       pack_get_write_ptr;
    entropy_reset_io_count pack_reset_io_count;
    entropy_get_io_count   pack_get_bits_in;
    entropy_get_io_count   pack_get_bits_out;
} SC_STRUCT_PACKED utils_entropy_t;
SC_STRUCT_PACK_END

extern utils_entropy_t utils_entropy;
