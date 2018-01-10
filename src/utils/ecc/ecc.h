/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2017                      *
 *                                                                           *
 * This file is part of tachyon.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include "safecrypto_private.h"
#include "utils/arith/sc_mp.h"

#define MAX_ECC_BITS      521
#define MAX_ECC_LIMBS     ((MAX_ECC_BITS + SC_LIMB_BITS - 1) / SC_LIMB_BITS)
#define MAX_ECC_BYTES     ((MAX_ECC_BITS + 7) >> 3)


typedef struct _ecdh_set_t {
	size_t      num_bits;
	size_t      num_bytes;
	size_t      num_limbs;
	const char *a;
	const char *g_x;
	const char *g_y;
	const char *p;
} ecdh_set_t;

SC_STRUCT_PACK_START
typedef struct _ecdh_cfg_t {
    ecdh_set_t *params;
} SC_STRUCT_PACKED ecdh_cfg_t;
SC_STRUCT_PACK_END

typedef struct ecc_point ecc_point_t;


extern const ecdh_set_t param_ecdh_secp256r1;

extern SINT32 ecc_diffie_hellman(safecrypto_t *sc, const ecc_point_t *p_base,
	const sc_ulimb_t *secret, size_t *tlen, UINT8 **to);

extern SINT32 ecc_sign(safecrypto_t *sc, const UINT8 *m, size_t mlen,
    UINT8 **sigret, size_t *siglen);

extern SINT32 ecc_verify(safecrypto_t *sc, const UINT8 *m, size_t mlen,
    const UINT8 *sigbuf, size_t siglen);



//
// end of file
//
