/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2017                      *
 *                                                                           *
 * This file is part of tachyon.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "utils/ecc/secret_bits.h"

#include "utils/arith/sc_mpz.h"


static SINT32 naf(const sc_ulimb_t *secret, size_t num_bits, sc_ulimb_t *recoded)
{
	UINT32 bit, bits;
	size_t i, j = 0;
	size_t total = 0;
	size_t num_ones = 0;
	size_t hamming  = 0;
	sc_mpz_t e;

	// Convert the input secret array containing the scalar value to an MP integer
	sc_mpz_init2(&e, MAX_ECC_BITS);
	size_t max_limbs = (num_bits + SC_LIMB_BITS - 1) >> SC_LIMB_BITS_SHIFT;
	sc_ulimb_t mask = (0 == (num_bits & SC_LIMB_BITS_MASK))? SC_LIMB_MASK : (1UL << (num_bits & SC_LIMB_BITS_MASK)) - 1;
	sc_mpz_add_ui(&e, &e, secret[max_limbs - 1] & mask);
	for (i=1; i<max_limbs; i++) {
		sc_mpz_mul_2exp(&e, &e, SC_LIMB_BITS);
		sc_mpz_add_ui(&e, &e, secret[max_limbs - i - 1]);
	}

	// Retrive a pointer to the limbs of the scalar value
	sc_ulimb_t *limbs = sc_mpz_get_limbs(&e);

	// Initialise the recoded scalar value to 0
	for (i=2*MAX_ECC_LIMBS+1; i--;) {
		recoded[i] = 0;
	}

	// Calculate the number of asserted bits in the NAF coded scalar
	for (size_t k=0; k<sc_mpz_get_size(&e); k++) {
		sc_ulimb_t limb = limbs[k];
		while (limb) {
			num_ones += (limb & 0x1);
			limb >>= 1;
		}
	}

	// The NAF encoding routine
	i = 0;
	while (!sc_mpz_is_zero(&e)) {
		sc_ulimb_t limb = sc_mpz_get_limbs(&e)[0] & 0x3;
		total++;
		if (limb & 0x1) {
			hamming++;
			sc_ulimb_t zi = (2 - (int) limb) & 0x3;
			if (3 == zi) {
				sc_mpz_add_ui(&e, &e, 1);
			}
			else {
				sc_mpz_sub_ui(&e, &e, 1);
			}
			recoded[j] |= zi << i;
		}
		sc_mpz_divquo_2exp(&e, &e, 1);

		i += 2;
		if (i >= SC_LIMB_BITS) {
			i = 0;
			j++;
		}
	}

	// Release memory resources associated with the MP scalar
	sc_mpz_clear(&e);

	// If the NAF coded scalar is larger return a 1, 0 otherwise
	return total > num_bits;
}

static UINT32 secret_bits_peek(point_secret_t *bit_ctx)
{
	UINT32 bit;
	sc_ulimb_t word1, word2, shift;

	// Peek ahead at the bit(s) to be pulled depending upon the coding mode
	if (ECC_K_BINARY == bit_ctx->coding) {
		word1 = bit_ctx->secret1[bit_ctx->index];
		shift = bit_ctx->shift;
		bit   = (word1 >> shift) & 0x1;
	}
	else if (ECC_K_BINARY_DUAL == bit_ctx->coding) {
		word1 = bit_ctx->secret1[bit_ctx->index];
		word2 = bit_ctx->secret2[bit_ctx->index];
		shift = bit_ctx->shift;
		bit   = (word1 >> shift) & 0x1;
		bit  |= ((word2 >> shift) & 0x1) << 1;
	}
	else {
		word1 = bit_ctx->recoded[bit_ctx->index];
		shift = bit_ctx->shift;
		bit   = (word1 >> shift) & 0x3;
	}

	return bit;
}

size_t secret_bits_init(ecc_k_coding_e coding, point_secret_t *bit_ctx,
	const sc_ulimb_t *secret1, const sc_ulimb_t *secret2, size_t num_bits)
{
	sc_ulimb_t is_naf    = (coding & ECC_K_CODING_NAF_BIT) >> ECC_K_CODING_NAF_BIT_SHIFT;
	size_t     max_scale = is_naf + 1;
	if (NULL == bit_ctx || 0 == num_bits) {
		return 0;
	}

	// Recoding of the secret value to non-adjacent form
	if (ECC_K_NAF_2 == coding) {
		num_bits += naf(secret1, num_bits, bit_ctx->recoded);
	}

	// Initialise the scalar variables
	bit_ctx->secret1 = secret1;
	bit_ctx->secret2 = secret2;
	bit_ctx->max     = num_bits;
	bit_ctx->index   = (max_scale*bit_ctx->max - 1) >> SC_LIMB_BITS_SHIFT;
	bit_ctx->shift   = ((max_scale*bit_ctx->max & SC_LIMB_BITS_MASK) - 1) & (SC_LIMB_BITS_MASK ^ is_naf);
	bit_ctx->coding  = coding;

	// Skim through the scalar value until the first bit/window to be pulled by the user will be non-zero
	while (num_bits && bit_ctx->index >= 0 && 0 == secret_bits_peek(bit_ctx)) {
		num_bits--;
		secret_bits_pull(bit_ctx);
	}

	// Return the number fo bits in the encoded scalar
	return num_bits;
}

static UINT32 secret_bits_pull_binary(point_secret_t *bit_ctx)
{
	UINT32 bit;
	sc_ulimb_t word, shift;

	// Obtain the bit from the secret
	word  = bit_ctx->secret1[bit_ctx->index];
	shift = bit_ctx->shift;
	bit   = (word >> shift) & 0x1;

	// Decrement the index if shift reaches 0
	bit_ctx->index -= !(((shift | (~shift + 1)) >> (SC_LIMB_BITS - 1)) & 1);

	// Decrement the shift and reset to SC_LIMB_BITS_MASK when it wraps around
	shift--;
	bit_ctx->shift = shift & SC_LIMB_BITS_MASK;

	return bit;
}

static UINT32 secret_bits_pull_binary_dual(point_secret_t *bit_ctx)
{
	UINT32 bit;
	sc_ulimb_t word1, word2, shift;

	// Obtain the bit from the secret
	word1 = bit_ctx->secret1[bit_ctx->index];
	word2 = bit_ctx->secret2[bit_ctx->index];
	shift = bit_ctx->shift;
	bit   = (word1 >> shift) & 0x1;
	bit  |= ((word2 >> shift) & 0x1) << 1;

	// Decrement the index if shift reaches 0
	bit_ctx->index -= !(((shift | (~shift + 1)) >> (SC_LIMB_BITS - 1)) & 1);

	// Decrement the shift and reset to SC_LIMB_BITS_MASK when it wraps around
	shift--;
	bit_ctx->shift = shift & SC_LIMB_BITS_MASK;

	return bit;
}

static UINT32 secret_bits_pull_naf(point_secret_t *bit_ctx)
{
	UINT32 bit;
	sc_ulimb_t word, shift;

	// Obtain the bit from the secret
	word  = bit_ctx->recoded[bit_ctx->index];
	shift = bit_ctx->shift;
	bit   = (word >> shift) & 0x3;

	// Decrement the index if shift reaches 0
	bit_ctx->index -= !(((shift | (~shift + 1)) >> (SC_LIMB_BITS - 1)) & 1);

	// Decrement the shift and reset to SC_LIMB_BITS_MASK when it wraps around
	shift -= 2;
	bit_ctx->shift = shift & SC_LIMB_BITS_MASK;

	return bit;
}

UINT32 secret_bits_pull(point_secret_t *bit_ctx)
{
	static const UINT32 code[4] = {ECC_K_IS_LOW, ECC_K_IS_HIGH, ECC_K_IS_SCA_DUMMY, ECC_K_IS_MINUS_ONE};
	UINT32 bit;
	sc_ulimb_t word, shift;

	// Obtain the bit depending upon the coding mode
	if (ECC_K_BINARY == bit_ctx->coding) {
		bit = secret_bits_pull_binary(bit_ctx);
	}
	else if (ECC_K_BINARY_DUAL == bit_ctx->coding) {
		bit = secret_bits_pull_binary_dual(bit_ctx);
	}
	else {
		bit = secret_bits_pull_naf(bit_ctx);;
	}

	// Return the coded bit
	return code[bit];
}

