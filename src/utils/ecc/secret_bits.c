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
	sc_mpz_t e;

	sc_mpz_init2(&e, MAX_ECC_BITS);

	size_t max_limbs = (num_bits + SC_LIMB_BITS - 1) >> SC_LIMB_BITS_SHIFT;
	for (i=0; i<max_limbs; i++) {
		sc_mpz_mul_2exp(&e, &e, SC_LIMB_BITS);
		if (0 == i) {
			sc_ulimb_t mask = (0 == (num_bits & SC_LIMB_BITS_MASK))? SC_LIMB_MASK : (1UL << (num_bits & SC_LIMB_BITS_MASK)) - 1;
			sc_mpz_add_ui(&e, &e, secret[max_limbs - i - 1] & mask);
		}
		else {
			sc_mpz_add_ui(&e, &e, secret[max_limbs - i - 1]);
		}
	}

	sc_ulimb_t *limbs = sc_mpz_get_limbs(&e);
	/*sc_mpz_set_limbs(&e, secret, (num_bits + SC_LIMB_BITS - 1) >> SC_LIMB_BITS_SHIFT);
	sc_ulimb_t *limbs = sc_mpz_get_limbs(&e);
	sc_ulimb_t  mask  = (1 << (num_bits & SC_LIMB_BITS_MASK)) - 1;
	limbs[(num_bits - 1) >> SC_LIMB_BITS_SHIFT] &= mask;*/

	/*fprintf(stderr, "NAF E = ");
	sc_mpz_out_str(stderr, 16, &e);
	fprintf(stderr, "\n");

	fprintf(stderr, "E = %016lX %016lX %016lX %016lX\n", secret[3], secret[2], secret[1], secret[0]);*/

	for (i=2*MAX_ECC_LIMBS+1; i--;) {
		recoded[i] = 0;
	}

	size_t total = 0;
	size_t num_ones = 0;
	size_t hamming  = 0;

	for (size_t k=0; k<sc_mpz_get_size(&e); k++) {
		sc_ulimb_t limb = limbs[k];
		while (limb) {
			num_ones += (limb & 0x1);
			limb >>= 1;
		}
	}

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

	/*fprintf(stderr, "bits=%zu, ones=%zu, hamming=%zu, recoded = ", total, num_ones, hamming);
	for (i=(2*total + SC_LIMB_BITS - 1) >> SC_LIMB_BITS_SHIFT; i--;) {
		fprintf(stderr, "%016lX ", recoded[i]);
	}
	fprintf(stderr, "\n");*/

	sc_mpz_clear(&e);

	return total > num_bits;
}

static UINT32 secret_bits_peek(point_secret_t *bit_ctx);

size_t secret_bits_init(ecc_k_coding_e coding, point_secret_t *bit_ctx, const sc_ulimb_t *secret, size_t num_bits)
{
	if (NULL == bit_ctx || 0 == num_bits) {
		return 0;
	}

	// Recoding of the secret value to non-adjacent form
	if (ECC_K_NAF_4 == coding) {
		num_bits += naf(secret, num_bits, bit_ctx->recoded);
	}

	bit_ctx->secret = secret;
	bit_ctx->max    = num_bits;
	bit_ctx->index  = (((ECC_K_NAF_4 == coding)? 2:1)*bit_ctx->max - 1) >> SC_LIMB_BITS_SHIFT;
	bit_ctx->shift  = (ECC_K_NAF_4 == coding)? ((2*bit_ctx->max & SC_LIMB_BITS_MASK) - 1) & (SC_LIMB_BITS_MASK ^ 1) :
	                                           ((bit_ctx->max & SC_LIMB_BITS_MASK) - 1) & SC_LIMB_BITS_MASK;
	bit_ctx->dir    = ECC_DIR_LEFT;
	bit_ctx->coding = coding;

	//fprintf(stderr, "max = %d, index = %d, shift = %d\n", bit_ctx->max, bit_ctx->index, bit_ctx->shift);

	while (num_bits && bit_ctx->index >= 0 && 0 == secret_bits_peek(bit_ctx)) {
		num_bits--;
		secret_bits_pull(bit_ctx);
	}

	return num_bits;
}

static UINT32 secret_bits_pull_binary(point_secret_t *bit_ctx)
{
	UINT32 bit;
	sc_ulimb_t word, shift;

	word  = bit_ctx->secret[bit_ctx->index];
	shift = bit_ctx->shift;
	bit   = (word >> shift) & 0x1;

	if (ECC_DIR_LEFT == bit_ctx->dir) {
		bit_ctx->index -= !(((shift | (~shift + 1)) >> (SC_LIMB_BITS - 1)) & 1);
		shift--;
	}
	else {
		bit_ctx->index += (sc_ulimb_t)((((SC_LIMB_BITS - 1 - shift) ^ SC_LIMB_MASK) - SC_LIMB_MASK)) >> SC_LIMB_BITS_MASK;
		shift++;
	}

	bit_ctx->shift = shift & SC_LIMB_BITS_MASK;

	//fprintf(stderr, "bit = %d, max = %d, index = %d, shift = %d\n", bit, bit_ctx->max, bit_ctx->index, bit_ctx->shift);
	//bit += 2;

	return bit;
}

static UINT32 secret_bits_peek(point_secret_t *bit_ctx)
{
	UINT32 bit;
	sc_ulimb_t word, shift;

	if (ECC_K_BINARY == bit_ctx->coding) {
		word  = bit_ctx->secret[bit_ctx->index];
	}
	else {
		word  = bit_ctx->recoded[bit_ctx->index];
	}
	shift = bit_ctx->shift;
	if (ECC_K_BINARY == bit_ctx->coding) {
		bit   = (word >> shift) & 0x1;
	}
	else {
		bit   = (word >> shift) & 0x3;
	}

	return bit;
}

static UINT32 secret_bits_pull_naf(point_secret_t *bit_ctx)
{
	UINT32 bit;
	sc_ulimb_t word, shift;

	word  = bit_ctx->recoded[bit_ctx->index];
	shift = bit_ctx->shift;
	bit   = (word >> shift) & 0x3;

	if (ECC_DIR_LEFT == bit_ctx->dir) {
		bit_ctx->index -= !(((shift | (~shift + 1)) >> (SC_LIMB_BITS - 1)) & 1);
		shift -= 2;
	}
	else {
		bit_ctx->index += (sc_ulimb_t)((((SC_LIMB_BITS - 1 - shift) ^ SC_LIMB_MASK) - SC_LIMB_MASK)) >> SC_LIMB_BITS_MASK;
		shift += 2;
	}

	bit_ctx->shift = shift & SC_LIMB_BITS_MASK;

	return bit;
}

UINT32 secret_bits_pull(point_secret_t *bit_ctx)
{
	static const UINT32 code[4] = {ECC_K_IS_LOW, ECC_K_IS_HIGH, ECC_K_IS_SCA_DUMMY, ECC_K_IS_MINUS_ONE};
	UINT32 bit;
	sc_ulimb_t word, shift;

	if (ECC_K_BINARY == bit_ctx->coding) {
		bit = secret_bits_pull_binary(bit_ctx);
	}
	else {
		bit = secret_bits_pull_naf(bit_ctx);;
	}

	return code[bit];
}

