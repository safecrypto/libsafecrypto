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
#define MAX_ECC_LIMBS     ((MAX_ECC_BITS + SC_LIMB_BITS - 1) >> SC_LIMB_BITS_SHIFT)
#define MAX_ECC_BYTES     ((MAX_ECC_BITS + 7) >> 3)


/// AN elliptic curve affine coordinate
typedef struct _ecc_point_t {
	sc_mpz_t x;
	sc_mpz_t y;
	size_t   n;
} ecc_point_t;

/// The parameters associated with an elliptic curve
typedef struct _ec_set_t {
	size_t      num_bits;
	size_t      num_bytes;
	size_t      num_limbs;
	const char *a;
	const char *b;
	const char *g_x;
	const char *g_y;
	const char *p;
	const char *p_inv;
	const char *order_m;
} ec_set_t;

/// A set of predefined curves
/// @{
extern const ec_set_t param_ec_secp192r1;
extern const ec_set_t param_ec_secp224r1;
extern const ec_set_t param_ec_secp256r1;
extern const ec_set_t param_ec_secp384r1;
extern const ec_set_t param_ec_secp521r1;
/// @}

/// A struct used to define the parameters of the selected curve
SC_STRUCT_PACK_START
typedef struct _ec_cfg_t {
    const ec_set_t *params;
	ecc_point_t     base;
} SC_STRUCT_PACKED ec_cfg_t;
SC_STRUCT_PACK_END


extern SINT32 ecc_diffie_hellman(safecrypto_t *sc, const ecc_point_t *p_base,
	const sc_ulimb_t *secret, size_t *tlen, UINT8 **to, SINT32 final_flag);

extern SINT32 ecc_diffie_hellman_encapsulate(safecrypto_t *sc, const sc_ulimb_t *secret,
	size_t *tlen, UINT8 **to);
extern SINT32 ecc_diffie_hellman_decapsulate(safecrypto_t *sc, const sc_ulimb_t *secret,
	size_t flen, const UINT8 *from, size_t *tlen, UINT8 **to);

extern SINT32 ecc_keygen(safecrypto_t *sc);
extern SINT32 ecc_sign(safecrypto_t *sc, const UINT8 *m, size_t mlen,
    UINT8 **sigret, size_t *siglen);

extern SINT32 ecc_verify(safecrypto_t *sc, const UINT8 *m, size_t mlen,
    const UINT8 *sigbuf, size_t siglen);



//
// end of file
//
