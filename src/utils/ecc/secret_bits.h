/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2017                      *
 *                                                                           *
 * This file is part of tachyon.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "ecc.h"

#define ECC_K_IS_HIGH        0
#define ECC_K_IS_SCA_DUMMY   1
#define ECC_K_IS_LOW         2

typedef enum ecc_direction {
	ECC_DIR_LEFT = 0,
	ECC_DIR_RIGHT,
} ecc_direction_e;

typedef enum ecc_k_coding {
	ECC_K_BINARY = 0,
	ECC_K_NAF_4,
} ecc_k_coding_e;

typedef struct point_secret {
	const sc_ulimb_t *secret;
	sc_ulimb_t recoded[2*MAX_ECC_LIMBS+1];
	size_t max;
	size_t shift;
	SINT32 index;
	ecc_direction_e dir;
	ecc_k_coding_e coding;
} point_secret_t;


UINT32 secret_bits_pull(point_secret_t *bit_ctx);
size_t secret_bits_init(ecc_k_coding_e coding, point_secret_t *bit_ctx, const sc_ulimb_t *secret, size_t num_bits);


