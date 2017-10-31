/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2017                      *
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

#include <string.h>


/// Function pointers for a common XOF interface
///@{
typedef SINT32 (*xof_func_init)(void *, SINT32);
typedef SINT32 (*xof_func_absorb)(void *, const void *, size_t);
typedef SINT32 (*xof_func_final)(void *);
typedef SINT32 (*xof_func_squeeze)(void *, void *, size_t);
///@}

/// A struct used to store an instantiated hash
SC_STRUCT_PACK_START
typedef struct _utils_crypto_xof {
    sc_xof_e          type;
    size_t            length;
    xof_func_init     init;
    xof_func_absorb   absorb;
    xof_func_final    final;
    xof_func_squeeze  squeeze;
    void             *ctx;
} SC_STRUCT_PACKED utils_crypto_xof_t;
SC_STRUCT_PACK_END

/// Create an instance of the selected hash function
extern utils_crypto_xof_t * utils_crypto_xof_create(sc_xof_e type);

/// Destroy an instance of a hash and release all memory resources
extern SINT32 utils_crypto_xof_destroy(utils_crypto_xof_t* xof);

/// The common XOF API function used to obtain the XOF type
extern sc_xof_e xof_get_type(utils_crypto_xof_t *c);

/// The common XOF API function used to initialise a XOF instance
extern SINT32 xof_init(utils_crypto_xof_t *c);

/// The common XOF API function used to seed a XOF
extern SINT32 xof_absorb(utils_crypto_xof_t *c, const void *data, size_t len);

/// The common XOF API function used to finalize the XOF input
extern SINT32 xof_final(utils_crypto_xof_t *c);

/// The common XOF API function used to generate output data
extern SINT32 xof_squeeze(utils_crypto_xof_t *c, void *output, size_t len);


