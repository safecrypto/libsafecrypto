/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2017                      *
 *                                                                           *
 * This file is part of tachyon.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "ecc.h"

/// Bit coding format
/// @{
#define ECC_K_IS_HIGH        0
#define ECC_K_IS_SCA_DUMMY   1
#define ECC_K_IS_LOW         2
#define ECC_K_IS_MINUS_ONE   3
/// @}

#define ECC_K_CODING_NAF_BIT         0x08
#define ECC_K_CODING_NAF_BIT_SHIFT   3

/// An enumerated type used to define the coding format of the secret
typedef enum ecc_k_coding {
	ECC_K_BINARY = 0,
	ECC_K_NAF_2  = ECC_K_CODING_NAF_BIT,
	ECC_K_NAF_3  = ECC_K_CODING_NAF_BIT + 1,
	ECC_K_NAF_4  = ECC_K_CODING_NAF_BIT + 2,
	ECC_K_NAF_5  = ECC_K_CODING_NAF_BIT + 3,
	ECC_K_NAF_6  = ECC_K_CODING_NAF_BIT + 4,
} ecc_k_coding_e;

/// A struct defining the context of the secret recoder
typedef struct point_secret {
	const sc_ulimb_t *secret;
	sc_ulimb_t recoded[2*MAX_ECC_LIMBS+1];
	size_t max;
	size_t shift;
	SINT32 index;
	ecc_k_coding_e coding;
} point_secret_t;


/// Initialise the given secret context using the selected coding format and value
size_t secret_bits_init(ecc_k_coding_e coding, point_secret_t *bit_ctx,
	const sc_ulimb_t *secret, size_t num_bits);

/// Pull a coded bit from the secret value
UINT32 secret_bits_pull(point_secret_t *bit_ctx);


