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


//#define USE_OPT_ECC

#ifdef USE_OPT_ECC
typedef struct ecc_point {
	sc_ulimb_t x[MAX_ECC_LIMBS];
	sc_ulimb_t y[MAX_ECC_LIMBS];
	size_t     n;
	size_t     x_len;
	size_t     y_len;
} ecc_point_t;
#else
typedef struct ecc_point {
	sc_mpz_t x;
	sc_mpz_t y;
	size_t   n;
} ecc_point_t;
#endif

typedef struct _ec_set_t {
	size_t      num_bits;
	size_t      num_bytes;
	size_t      num_limbs;
#ifdef USE_OPT_ECC
	const sc_ulimb_t a[MAX_ECC_LIMBS];
	const sc_ulimb_t b[MAX_ECC_LIMBS];
	const sc_ulimb_t g_x[MAX_ECC_LIMBS];
	const sc_ulimb_t g_y[MAX_ECC_LIMBS];
	const sc_ulimb_t p[MAX_ECC_LIMBS];
	const sc_ulimb_t p_mu[MAX_ECC_LIMBS];
	const sc_ulimb_t order[MAX_ECC_LIMBS];
#else
	const char *a;
	const char *b;
	const char *g_x;
	const char *g_y;
	const char *p;
	const char *p_inv;
	const char *order_m;
#endif
} ec_set_t;

extern const ec_set_t param_ec_secp256r1;
extern const ec_set_t param_ec_secp384r1;
extern const ec_set_t param_ec_secp521r1;

SC_STRUCT_PACK_START
typedef struct _ecdh_cfg_t {
    const ec_set_t *params;
	ecc_point_t     base;
} SC_STRUCT_PACKED ecdh_cfg_t;
SC_STRUCT_PACK_END

SC_STRUCT_PACK_START
typedef struct _ecdsa_cfg_t {
    const ec_set_t *params;
	ecc_point_t     base;
} SC_STRUCT_PACKED ecdsa_cfg_t;
SC_STRUCT_PACK_END


extern SINT32 ecc_diffie_hellman(safecrypto_t *sc, const ecc_point_t *p_base,
	const sc_ulimb_t *secret, size_t *tlen, UINT8 **to);

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
