/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2017                      *
 *                                                                           *
 * This file is part of tachyon.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "utils/ecc/ecc.h"
#include "utils/ecc/secret_bits.h"
#include "utils/arith/sc_mpz.h"
#include "utils/crypto/prng.h"
#include "safecrypto_debug.h"
#include "safecrypto_error.h"


typedef struct ecc_metadata {
	sc_mpz_t lambda;
	sc_mpz_t temp;
	sc_mpz_t x;
	sc_mpz_t y;
	sc_mpz_t m;
	sc_mpz_t m_inv;
	sc_mpz_t order_m;
	sc_mpz_t a;
	size_t   k;
} ecc_metadata_t;

const ec_set_t param_ec_secp192r1 = {
	192,
	24,
	192 >> SC_LIMB_BITS_SHIFT,
	"-3",//"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
	"64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1",
	"188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
	"07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
	"",
	"FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831",
};

const ec_set_t param_ec_secp224r1 = {
	224,
	28,
	(224 + SC_LIMB_BITS - 1) >> SC_LIMB_BITS_SHIFT,
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
	"B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
	"B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
	"BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
	"",
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
};

const ec_set_t param_ec_secp256r1 = {
	256,
	32,
	256 >> SC_LIMB_BITS_SHIFT,
	"-3",//"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
	"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
	"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
	"4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
	"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
	"100000000fffffffffffffffefffffffefffffffeffffffff0000000000000003",
	"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
};

const ec_set_t param_ec_secp384r1 = {
	384,
	48,
	384 >> SC_LIMB_BITS_SHIFT,
	"-3", // "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
	"B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF"
	"AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
	"3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
	"",
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
};

const ec_set_t param_ec_secp521r1 = {
	521,
	66,
	(521 + SC_LIMB_BITS - 1) >> SC_LIMB_BITS_SHIFT,
	"-3", // "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
	"0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
	"00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
	"011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
	"",
	"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
};


static void point_reset(ecc_point_t *p)
{
	sc_mpz_set_ui(&p->x, 0);
	sc_mpz_set_ui(&p->y, 0);
}

static void point_init(ecc_point_t *p, size_t n)
{
	sc_mpz_init2(&p->x, MAX_ECC_BITS);
	sc_mpz_init2(&p->y, MAX_ECC_BITS);
	p->n = n;
}

static void point_clear(ecc_point_t *p)
{
	sc_mpz_clear(&p->x);
	sc_mpz_clear(&p->y);
}

static void point_copy(ecc_point_t *p_out, const ecc_point_t *p_in)
{
	sc_mpz_copy(&p_out->x, &p_in->x);
	sc_mpz_copy(&p_out->y, &p_in->y);
	p_out->n = p_in->n;
}

static void point_negate(ecc_point_t *p_inout)
{
	sc_mpz_negate(&p_inout->y, &p_inout->y);
}

static SINT32 point_is_zero(const ecc_point_t *p)
{
	return sc_mpz_is_zero(&p->x) && sc_mpz_is_zero(&p->y);
}

static void point_double_affine(ecc_metadata_t *metadata, ecc_point_t *point)
{
	sc_mpz_t *lambda, *temp, *x, *y, *m, *a, *m_inv, *order_m;
	lambda        = &metadata->lambda;
	temp          = &metadata->temp;
	x             = &metadata->x;
	y             = &metadata->y;
	m             = &metadata->m;
	m_inv         = &metadata->m_inv;
	order_m       = &metadata->order_m;
	a             = &metadata->a;

	// lambda = (3*x^2 + a)/(2*y)
	sc_mpz_mul(temp, &point->x, &point->x);
	sc_mpz_mod(lambda, temp, m);
	sc_mpz_mul_ui(temp, lambda, 3);
	sc_mpz_mod(lambda, temp, m);
	sc_mpz_add(temp, lambda, a);
	sc_mpz_mod(lambda, temp, m);
	sc_mpz_add(temp, &point->y, &point->y);
	sc_mpz_mod(x, temp, m);
	sc_mpz_invmod(y, x, m);
	sc_mpz_mul(temp, lambda, y);
	sc_mpz_mod(lambda, temp, m);

	// xr = lambda^2 - 2*xp
	sc_mpz_mul(temp, lambda, lambda);
	sc_mpz_mod(x, temp, m);
	sc_mpz_sub(temp, x, &point->x);
    sc_mpz_sub(temp, temp, &point->x);
	sc_mpz_mod(x, temp, m);

	// yr = lambda*(xp - xr) - yp
    sc_mpz_sub(y, x, &point->x);
	sc_mpz_mod(y, y, m);
	sc_mpz_mul(temp, lambda, y);
	sc_mpz_mod(y, temp, m);
    sc_mpz_add(y, y, &point->y);
    sc_mpz_negate(y, y);
    sc_mpz_mod(&point->y, y, m);

    // Overwrite the input point X coordinate with it's new value
    sc_mpz_copy(&point->x, x);
}

static void point_add_affine(ecc_metadata_t *metadata, ecc_point_t *p_a, const ecc_point_t *p_b)
{
	sc_mpz_t *lambda, *temp, *x, *y, *m;
	lambda = &metadata->lambda;
	temp   = &metadata->temp;
	x      = &metadata->x;
	y      = &metadata->y;
	m      = &metadata->m;

	// lambda = (yb - ya) / (xb - xa)
	sc_mpz_sub(y, &p_b->y, &p_a->y);
	sc_mpz_mod(y, y, m);
	sc_mpz_sub(x, &p_b->x, &p_a->x);
	sc_mpz_mod(x, x, m);
	sc_mpz_invmod(lambda, x, m);
	sc_mpz_mul(temp, lambda, y);
	sc_mpz_mod(lambda, temp, m);

	// xr = lambda^2 - xp - xq
	sc_mpz_mul(temp, lambda, lambda);
	sc_mpz_mod(x, temp, m);
    sc_mpz_sub(x, x, &p_a->x);
    sc_mpz_sub(x, x, &p_b->x);
    sc_mpz_mod(&p_a->x, x, m);

	// yr = lambda*(xp - xq) - a
    sc_mpz_sub(y, &p_a->x, &p_b->x);
    sc_mpz_mod(y, y, m);
	sc_mpz_mul(temp, lambda, y);
	sc_mpz_mod(y, temp, m);
    sc_mpz_add(y, y, &p_b->y);
    sc_mpz_negate(y, y);
    sc_mpz_mod(&p_a->y, y, m);
}

static void point_double(ecc_metadata_t *metadata, ecc_point_t *point)
{
	// If x and y are zero the result is zero
	if (point_is_zero(point)) {
		return;
	}

	point_double_affine(metadata, point);
}

static void point_add(ecc_metadata_t *metadata, ecc_point_t *p_a, const ecc_point_t *p_b)
{
	point_add_affine(metadata, p_a, p_b);
}

static void scalar_point_mult_binary(size_t num_bits, ecc_metadata_t *metadata,
	const ecc_point_t *p_in, const sc_ulimb_t *secret, ecc_point_t *p_out)
{
	size_t i;
	point_secret_t bit_ctx;
	ecc_point_t p_dummy;

	point_init(&p_dummy, MAX_ECC_LIMBS);
	point_reset(&p_dummy);
	point_reset(p_out);
	point_copy(p_out, p_in);

	/*fprintf(stderr, "in   x: "); sc_mpz_out_str(stderr, 16, &p_in->x); fprintf(stderr, "\n");
	fprintf(stderr, "     y: "); sc_mpz_out_str(stderr, 16, &p_in->y); fprintf(stderr, "\n");
	fprintf(stderr, "out  x: "); sc_mpz_out_str(stderr, 16, &p_out->x); fprintf(stderr, "\n");
	fprintf(stderr, "     y: "); sc_mpz_out_str(stderr, 16, &p_out->y); fprintf(stderr, "\n");
	fprintf(stderr, "secret: %016llX %016llX %016llX %016llX\n", secret[3], secret[2], secret[1], secret[0]);*/

	// Windowing
	size_t w = 4;
	ecc_point_t *p_window = SC_MALLOC(sizeof(ecc_point_t) * (1 << w));
	point_init(&p_window[0], MAX_ECC_LIMBS);
	point_copy(&p_window[0], p_in);
	for (i=1; i<(1 << w); i++) {
		point_init(&p_window[i], MAX_ECC_LIMBS);
		point_copy(&p_window[i], &p_window[i-1]);
		point_add(metadata, &p_window[i], p_in);
	}

	num_bits = secret_bits_init(ECC_K_BINARY, &bit_ctx, secret, num_bits);
	secret_bits_pull(&bit_ctx);
	num_bits--;

	for (i=num_bits; i--;) {
		sc_ulimb_t bit;

		// Point doubling
		point_double(metadata, p_out);

		// Determine if an asserted bit requires a point addition (or a dummy point addition as an SCA countermeasure)
		bit = secret_bits_pull(&bit_ctx);
		//fprintf(stderr, "index = %zu, bit = %d\n", i, bit);
		if (ECC_K_IS_LOW != bit) {
			// Create a mask of all zeros if ECC_K_IS_HIGH or all ones if an ECC_K_IS_SCA_DUMMY operation
			intptr_t temp   = (intptr_t) (bit << (SC_LIMB_BITS - 1));
			intptr_t mask   = (bit ^ temp) - temp;

			// Branch-free pointer selection in constant time
			intptr_t p_temp = (intptr_t) p_out ^ (((intptr_t) p_out ^ (intptr_t) &p_dummy) & mask);
			//fprintf(stderr, "%zu %zu %zu\n", p_temp, (intptr_t) p_out, (intptr_t) &p_dummy);

			// Point addition
			point_add(metadata, (ecc_point_t *) p_temp, p_in);
		}
	}

	point_clear(&p_dummy);

	for (i=0; i<(1 << w); i++) {
		point_clear(&p_window[i]);
	}
	SC_FREE(p_window, sizeof(ecc_point_t) * (1 << w));

	//fprintf(stderr, "result x: "); sc_mpz_out_str(stderr, 16, &p_out->x); fprintf(stderr, "\n");
	//fprintf(stderr, "       y: "); sc_mpz_out_str(stderr, 16, &p_out->y); fprintf(stderr, "\n");
}

static void scalar_point_mult_naf(size_t num_bits, ecc_metadata_t *metadata,
	const ecc_point_t *p_in, const sc_ulimb_t *secret, ecc_point_t *p_out)
{
	size_t i;
	UINT32 bit;
	point_secret_t bit_ctx;
	ecc_point_t p_dummy, p_in_minus;

	point_init(&p_dummy, MAX_ECC_LIMBS);
	point_reset(&p_dummy);
	point_reset(p_out);
	point_copy(p_out, p_in);
	point_init(&p_in_minus, MAX_ECC_LIMBS);
	point_copy(&p_in_minus, p_in);
	point_negate(&p_in_minus);

	/*fprintf(stderr, "in   x: "); sc_mpz_out_str(stderr, 16, &p_in->x); fprintf(stderr, "\n");
	fprintf(stderr, "     y: "); sc_mpz_out_str(stderr, 16, &p_in->y); fprintf(stderr, "\n");
	fprintf(stderr, "out  x: "); sc_mpz_out_str(stderr, 16, &p_out->x); fprintf(stderr, "\n");
	fprintf(stderr, "     y: "); sc_mpz_out_str(stderr, 16, &p_out->y); fprintf(stderr, "\n");
	fprintf(stderr, "secret: %016llX %016llX %016llX %016llX\n", secret[3], secret[2], secret[1], secret[0]);*/

	// Windowing
	/*size_t w = 4;
	ecc_point_t *p_window = SC_MALLOC(sizeof(ecc_point_t) * (1 << w));
	point_init(&p_window[0], MAX_ECC_LIMBS);
	point_copy(&p_window[0], p_in);
	for (i=1; i<(1 << w); i++) {
		point_init(&p_window[i], MAX_ECC_LIMBS);
		point_copy(&p_window[i], &p_window[i-1]);
		point_add(metadata, &p_window[i], p_in);
	}*/

	num_bits = secret_bits_init(ECC_K_NAF_2, &bit_ctx, secret, num_bits);
	bit = secret_bits_pull(&bit_ctx);
	num_bits--;

	for (i=num_bits; i--;) {
		// Point doubling
		point_double(metadata, p_out);

		// Determine if an asserted bit requires a point addition (or a dummy point addition as an SCA countermeasure)
		bit = secret_bits_pull(&bit_ctx);
		//fprintf(stderr, "index = %zu, bit = %d\n", i, bit);
		if (ECC_K_IS_LOW != bit) {
			// Branch-free pointer selection in constant time where we create a mask of all zeros
			// if ECC_K_IS_HIGH or all ones if an ECC_K_IS_SCA_DUMMY operation
			intptr_t mask, p_temp, p_temp2;
			sc_ulimb_t hide     = (bit & 0x1) - ((bit & 0x2) >> 1);
			sc_ulimb_t subtract = (bit >> 1);
			mask   = (intptr_t) 0 - (intptr_t) hide;
			p_temp = (intptr_t) p_out ^ (((intptr_t) p_out ^ (intptr_t) &p_dummy) & mask);
			mask   = (intptr_t) 0 - (intptr_t) subtract;
			p_temp2 = (intptr_t) p_in ^ (((intptr_t) p_in ^ (intptr_t) &p_in_minus) & mask);

			// Point addition
			point_add(metadata, (ecc_point_t *) p_temp, (ecc_point_t *) p_temp2);
		}
	}

	point_clear(&p_dummy);
	point_clear(&p_in_minus);

	/*for (i=0; i<(1 << w); i++) {
		point_clear(&p_window[i]);
	}
	SC_FREE(p_window, sizeof(ecc_point_t) * (1 << w));*/

	//fprintf(stderr, "result x: "); sc_mpz_out_str(stderr, 16, &p_out->x); fprintf(stderr, "\n");
	//fprintf(stderr, "       y: "); sc_mpz_out_str(stderr, 16, &p_out->y); fprintf(stderr, "\n");
}

static void scalar_point_mult(size_t num_bits, ecc_metadata_t *metadata,
	const ecc_point_t *p_in, const sc_ulimb_t *secret, ecc_point_t *p_out)
{
#if 0
	scalar_point_mult_binary(num_bits, metadata, p_in, secret, p_out);
#else
	scalar_point_mult_naf(num_bits, metadata, p_in, secret, p_out);
#endif
}

SINT32 ecc_diffie_hellman(safecrypto_t *sc, const ecc_point_t *p_base, const sc_ulimb_t *secret, size_t *tlen, UINT8 **to, SINT32 final_flag)
{
	size_t i;
	ecc_point_t p_result;
	size_t num_bits, num_bytes, num_limbs;
	ecc_metadata_t metadata;

	// If the sc pointer is NULL then return with a failure
	if (NULL == sc) {
		return SC_FUNC_FAILURE;
	}

	// Obtain common array lengths
	num_bits  = sc->ec->params->num_bits;
	num_bytes = sc->ec->params->num_bytes;
	num_limbs = sc->ec->params->num_limbs;

	// Initialise the MP variables
	metadata.k = num_limbs;
	sc_mpz_init2(&metadata.lambda, MAX_ECC_BITS);
	sc_mpz_init2(&metadata.x, MAX_ECC_BITS);
	sc_mpz_init2(&metadata.y, MAX_ECC_BITS);
	sc_mpz_init2(&metadata.temp, 2*MAX_ECC_BITS);
	sc_mpz_init2(&metadata.a, MAX_ECC_BITS);
	sc_mpz_init2(&metadata.m, MAX_ECC_BITS);
	sc_mpz_init2(&metadata.m_inv, MAX_ECC_BITS+1);
	sc_mpz_init2(&metadata.order_m, MAX_ECC_BITS);
	sc_mpz_init2(&p_result.x, MAX_ECC_BITS);
	sc_mpz_init2(&p_result.y, MAX_ECC_BITS);
	sc_mpz_set_str(&metadata.a, 16, sc->ec->params->a);
	sc_mpz_set_str(&metadata.m, 16, sc->ec->params->p);
	sc_mpz_set_str(&metadata.m_inv, 16, sc->ec->params->p_inv);
	sc_mpz_set_str(&metadata.order_m, 16, sc->ec->params->order_m);

	// Perform a scalar point multiplication from the base point using the random secret
	scalar_point_mult(num_bits, &metadata, p_base, secret, &p_result);

	// Translate the output point (coordinates are MP variables) to the output byte stream
	*to = SC_MALLOC((2-final_flag)*num_bytes);
	*tlen = (2-final_flag) * num_bytes;
	sc_mpz_get_bytes(*to, &p_result.x);
	if (0 == final_flag) {
		sc_mpz_get_bytes(*to + num_bytes, &p_result.y);
	}

	// Free resources associated with the MP variables
	sc_mpz_clear(&metadata.lambda);
	sc_mpz_clear(&metadata.x);
	sc_mpz_clear(&metadata.y);
	sc_mpz_clear(&metadata.temp);
	sc_mpz_clear(&metadata.a);
	sc_mpz_clear(&metadata.m);
	sc_mpz_clear(&metadata.m_inv);
	sc_mpz_clear(&metadata.order_m);
	sc_mpz_clear(&p_result.x);
	sc_mpz_clear(&p_result.y);

	return SC_FUNC_SUCCESS;
}

SINT32 ecc_diffie_hellman_encapsulate(safecrypto_t *sc, const sc_ulimb_t *secret,
	size_t *tlen, UINT8 **to)
{
	// Use an ECC scalar point multiplication to geometrically transform the base point
	// to the intermediate point (i.e. the public key)
	ecc_diffie_hellman(sc, &sc->ec->base, secret, tlen, to, 0);

	return SC_FUNC_SUCCESS;
}

SINT32 ecc_diffie_hellman_decapsulate(safecrypto_t *sc, const sc_ulimb_t *secret,
	size_t flen, const UINT8 *from, size_t *tlen, UINT8 **to)
{
	size_t num_bytes = sc->ec->params->num_bytes;
	size_t num_limbs = sc->ec->params->num_limbs;

	// Convert the input byte stream (public key) to the intermediate coordinate
	ecc_point_t p_base;
	p_base.n = num_limbs;
	sc_mpz_init2(&p_base.x, MAX_ECC_BITS);
	sc_mpz_init2(&p_base.y, MAX_ECC_BITS);
	sc_mpz_set_bytes(&p_base.x, from, num_bytes);
	sc_mpz_set_bytes(&p_base.y, from + num_bytes, num_bytes);

	// Use an ECC scalar point multiplication to geometrically transform the intermediate point
	// to the final point (shared secret)
	ecc_diffie_hellman(sc, &p_base, secret, tlen, to, 1);

	sc_mpz_clear(&p_base.x);
	sc_mpz_clear(&p_base.y);

	return SC_FUNC_SUCCESS;
}

SINT32 ecc_keygen(safecrypto_t *sc)
{
	SINT32 retval = SC_FUNC_FAILURE;
	size_t num_bits, num_bytes, num_limbs;
	sc_ulimb_t *secret;
	ecc_point_t p_public;
	ecc_metadata_t metadata;

	num_bits  = sc->ec->params->num_bits;
	num_bytes = sc->ec->params->num_bytes;
	num_limbs = sc->ec->params->num_limbs;

	metadata.k = num_limbs;
	sc_mpz_init2(&metadata.lambda, MAX_ECC_BITS);
	sc_mpz_init2(&metadata.x, MAX_ECC_BITS);
	sc_mpz_init2(&metadata.y, MAX_ECC_BITS);
	sc_mpz_init2(&metadata.temp, 2*MAX_ECC_BITS);
	sc_mpz_init2(&metadata.a, MAX_ECC_BITS);
	sc_mpz_init2(&metadata.m, MAX_ECC_BITS);
	sc_mpz_init2(&metadata.m_inv, MAX_ECC_BITS+1);
	sc_mpz_init2(&metadata.order_m, MAX_ECC_BITS);
	sc_mpz_set_str(&metadata.a, 16, sc->ec->params->a);
	sc_mpz_set_str(&metadata.m, 16, sc->ec->params->p);
	sc_mpz_set_str(&metadata.m_inv, 16, sc->ec->params->p_inv);
	sc_mpz_set_str(&metadata.order_m, 16, sc->ec->params->order_m);

	// Allocate memory for the private key
    if (NULL == sc->privkey->key) {
        sc->privkey->key = SC_MALLOC(sizeof(sc_ulimb_t) * num_limbs);
        if (NULL == sc->privkey->key) {
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            goto finish_free;
        }
    }
	secret = sc->privkey->key;

	// Generate a secret key as a random number
	/*fprintf(stderr, "private key = ");
	for (size_t q=0; q<32; q++) {
		fprintf(stderr, "%02X", ((UINT8*)sc->privkey->key)[q]);
		if (7 == (q & 0x7)) {
			fprintf(stderr, " ");
		}
	}
	fprintf(stderr, "\n");*/
	prng_mem(sc->prng_ctx[0], (UINT8*)secret, num_bytes);
	//fprintf(stderr, "private key = %016lX %016lX %016lX %016lX\n", secret[3], secret[2], secret[1], secret[0]);

	// Generate the public key as the product of a scalar multiplication
	// of the base point with k
	point_init(&p_public, MAX_ECC_LIMBS);
	scalar_point_mult(num_bits, &metadata, &sc->ec->base, secret, &p_public);
	sc_mpz_mod(&p_public.x, &p_public.x, &metadata.order_m);
	sc_mpz_mod(&p_public.y, &p_public.y, &metadata.order_m);
	/*fprintf(stderr, "public x = "); sc_mpz_out_str(stderr, 16, &p_public.x); fprintf(stderr, "\n");
	fprintf(stderr, "public y = "); sc_mpz_out_str(stderr, 16, &p_public.y); fprintf(stderr, "\n");*/

	// Allocate memory for the public key
    if (NULL == sc->pubkey->key) {
        sc->pubkey->key = SC_MALLOC(sizeof(sc_ulimb_t) * 2 * num_limbs);
        if (NULL == sc->pubkey->key) {
            SC_LOG_ERROR(sc, SC_NULL_POINTER);
            goto finish_free;
        }
    }

    // Copy the public key to storage
	sc_mpz_get_bytes(sc->pubkey->key, &p_public.x);
	sc_mpz_get_bytes(sc->pubkey->key + num_bytes, &p_public.y);

	retval = SC_FUNC_SUCCESS;

finish_free:
	// Free resources
	point_clear(&p_public);
	sc_mpz_clear(&metadata.lambda);
	sc_mpz_clear(&metadata.x);
	sc_mpz_clear(&metadata.y);
	sc_mpz_clear(&metadata.temp);
	sc_mpz_clear(&metadata.a);
	sc_mpz_clear(&metadata.m);
	sc_mpz_clear(&metadata.m_inv);
	sc_mpz_clear(&metadata.order_m);

	return retval;
}

SINT32 ecc_sign(safecrypto_t *sc, const UINT8 *m, size_t mlen,
    UINT8 **sigret, size_t *siglen)
{
	size_t i, num_bits, num_bytes, num_limbs;
	ecc_point_t p_base, p_result;
	sc_ulimb_t secret[MAX_ECC_LIMBS];
	sc_mpz_t d, e, k, temp1, temp2;
	SINT32 mem_is_zero;
	ecc_metadata_t metadata;

	// Obtain common array lengths
	num_bits  = sc->ec->params->num_bits;
	num_bytes = sc->ec->params->num_bytes;
	num_limbs = sc->ec->params->num_limbs;

	if (0 != *siglen && *siglen < 2*num_bytes) {
		return SC_FUNC_FAILURE;
	}

	sc_mpz_init2(&metadata.lambda, MAX_ECC_BITS);
	sc_mpz_init2(&metadata.x, MAX_ECC_BITS);
	sc_mpz_init2(&metadata.y, MAX_ECC_BITS);
	sc_mpz_init2(&metadata.temp, 2*MAX_ECC_BITS);
	sc_mpz_init2(&metadata.a, MAX_ECC_BITS);
	sc_mpz_init2(&metadata.m, MAX_ECC_BITS);
	sc_mpz_init2(&metadata.m_inv, MAX_ECC_BITS+1);
	sc_mpz_init2(&metadata.order_m, MAX_ECC_BITS);
	sc_mpz_set_str(&metadata.a, 16, sc->ec->params->a);
	sc_mpz_set_str(&metadata.m, 16, sc->ec->params->p);
	sc_mpz_set_str(&metadata.m_inv, 16, sc->ec->params->p_inv);
	sc_mpz_set_str(&metadata.order_m, 16, sc->ec->params->order_m);

	sc_mpz_init2(&d, MAX_ECC_BITS);
	sc_mpz_init2(&e, MAX_ECC_BITS);
	sc_mpz_init2(&k, MAX_ECC_BITS);
	sc_mpz_init2(&temp1, 2*MAX_ECC_BITS);
	sc_mpz_init2(&temp2, MAX_ECC_BITS);
	point_init(&p_base, MAX_ECC_LIMBS);
	point_init(&p_result, MAX_ECC_LIMBS);

	p_base.n = (num_bits + SC_LIMB_BITS - 1) >> SC_LIMB_BITS_SHIFT;
	sc_mpz_set_str(&p_base.x, 16, sc->ec->params->g_x);
	sc_mpz_set_str(&p_base.y, 16, sc->ec->params->g_y);

	sc_mpz_set_limbs(&d, (sc_ulimb_t*) sc->privkey->key, num_limbs);
	sc_mpz_set_bytes(&e, m, mlen);

	/*fprintf(stderr, "base x      = "); sc_mpz_out_str(stderr, 16, &p_base.x); fprintf(stderr, "\n");
	fprintf(stderr, "base y      = "); sc_mpz_out_str(stderr, 16, &p_base.y); fprintf(stderr, "\n");
	fprintf(stderr, "private key = "); sc_mpz_out_str(stderr, 16, &d); fprintf(stderr, "\n");
	fprintf(stderr, "message     = "); sc_mpz_out_str(stderr, 16, &e); fprintf(stderr, "\n");*/

restart:
	// Generate a random secret k
	prng_mem(sc->prng_ctx[0], (UINT8*)secret, num_bytes);
	sc_mpz_set_limbs(&k, secret, num_limbs);
	//fprintf(stderr, "k           = "); sc_mpz_out_str(stderr, 16, &k); fprintf(stderr, "\n");

	// Perform a scalar point multiplication from the base point using the random secret k
	scalar_point_mult(num_bits, &metadata, &p_base, secret, &p_result);
	sc_mpz_mod(&p_result.x, &p_result.x, &metadata.order_m);
	if (sc_mpz_is_zero(&p_result.x)) {
		goto restart;
	}

	// s = k^(-1)*(z + r*d) mod n
	sc_mpz_mul(&temp1, &p_result.x, &d);
	sc_mpz_mod(&temp2, &temp1, &metadata.order_m);
	//fprintf(stderr, "r*d = "); sc_mpz_out_str(stderr, 16, &temp2); fprintf(stderr, "\n");
	sc_mpz_add(&temp1, &temp2, &e);
	sc_mpz_mod(&temp1, &temp1, &metadata.order_m);
	//fprintf(stderr, "z + r*d = "); sc_mpz_out_str(stderr, 16, &temp1); fprintf(stderr, "\n");
	sc_mpz_invmod(&temp2, &k, &metadata.order_m);
	//fprintf(stderr, "k^{-1} = "); sc_mpz_out_str(stderr, 16, &temp2); fprintf(stderr, "\n");
	sc_mpz_mul(&temp1, &temp2, &temp1);
	sc_mpz_mod(&temp2, &temp1, &metadata.order_m);
	if (sc_mpz_is_zero(&temp2)) {
		goto restart;
	}

	/*fprintf(stderr, "r = "); sc_mpz_out_str(stderr, 16, &p_result.x); fprintf(stderr, "\n");
	fprintf(stderr, "s = "); sc_mpz_out_str(stderr, 16, &temp2); fprintf(stderr, "\n");*/

	// Pack r and s into the output signature
	if (0 == *siglen || 0 == *sigret) {
		*sigret = SC_MALLOC(2*num_bytes);
	}
	*siglen = 2*num_bytes;
	sc_mpz_get_bytes(*sigret, &p_result.x);
	sc_mpz_get_bytes(*sigret + num_bytes, &temp2);

	sc_mpz_clear(&metadata.lambda);
	sc_mpz_clear(&metadata.x);
	sc_mpz_clear(&metadata.y);
	sc_mpz_clear(&metadata.temp);
	sc_mpz_clear(&metadata.a);
	sc_mpz_clear(&metadata.m);
	sc_mpz_clear(&metadata.m_inv);
	sc_mpz_clear(&metadata.order_m);

	sc_mpz_clear(&d);
	sc_mpz_clear(&e);
	sc_mpz_clear(&k);
	sc_mpz_clear(&temp1);
	sc_mpz_clear(&temp2);
	point_clear(&p_base);
	point_clear(&p_result);

	return SC_FUNC_SUCCESS;
}

SINT32 ecc_verify(safecrypto_t *sc, const UINT8 *m, size_t mlen,
    const UINT8 *sigbuf, size_t siglen)
{
	SINT32 retval;
	size_t i, num_bits, num_bytes, num_limbs;
	sc_mpz_t r, s, w, temp, z;
	sc_ulimb_t *secret;
	ecc_point_t p_base, p_public, p_u1, p_u2;
	ecc_metadata_t metadata;

	// Obtain common array lengths
	num_bits  = sc->ec->params->num_bits;
	num_bytes = sc->ec->params->num_bytes;
	num_limbs = sc->ec->params->num_limbs;

	// VErify that the signature length is valid and accomodates the r and s components
	if (siglen != 2*num_bytes) {
		return SC_FUNC_FAILURE;
	}

	// Configure the curve parameters
	sc_mpz_init2(&metadata.lambda, MAX_ECC_BITS);
	sc_mpz_init2(&metadata.x, MAX_ECC_BITS);
	sc_mpz_init2(&metadata.y, MAX_ECC_BITS);
	sc_mpz_init2(&metadata.temp, 2*MAX_ECC_BITS);
	sc_mpz_init2(&metadata.a, MAX_ECC_BITS);
	sc_mpz_init2(&metadata.m, MAX_ECC_BITS);
	sc_mpz_init2(&metadata.m_inv, MAX_ECC_BITS+1);
	sc_mpz_init2(&metadata.order_m, MAX_ECC_BITS);
	sc_mpz_set_str(&metadata.a, 16, sc->ec->params->a);
	sc_mpz_set_str(&metadata.m, 16, sc->ec->params->p);
	sc_mpz_set_str(&metadata.m_inv, 16, sc->ec->params->p_inv);
	sc_mpz_set_str(&metadata.order_m, 16, sc->ec->params->order_m);
	sc_mpz_init2(&temp, 2*MAX_ECC_BITS);
	sc_mpz_init2(&r, MAX_ECC_BITS);
	sc_mpz_init2(&s, MAX_ECC_BITS);
	sc_mpz_init2(&w, MAX_ECC_BITS);
	sc_mpz_init2(&z, MAX_ECC_BITS);
	point_init(&p_base, MAX_ECC_LIMBS);
	point_init(&p_public, MAX_ECC_LIMBS);
	point_init(&p_u1, MAX_ECC_LIMBS);
	point_init(&p_u2, MAX_ECC_LIMBS);

	sc_mpz_set_bytes(&r, sigbuf, num_bytes);
	sc_mpz_set_bytes(&s, sigbuf + num_bytes, num_bytes);
	/*fprintf(stderr, "r = "); sc_mpz_out_str(stderr, 16, &r); fprintf(stderr, "\n");*/
	/*fprintf(stderr, "s = "); sc_mpz_out_str(stderr, 16, &s); fprintf(stderr, "\n");*/

	sc_mpz_set_bytes(&z, m, mlen);

	// w = s^{-1}
	sc_mpz_invmod(&w, &s, &metadata.order_m);

	// Obtain the public key Q in the form of an elliptic curve point
	p_public.n = sc->ec->params->num_limbs;
	sc_mpz_set_bytes(&p_public.x, sc->pubkey->key, num_bytes);
	sc_mpz_set_bytes(&p_public.y, sc->pubkey->key + num_bytes, num_bytes);
	/*fprintf(stderr, "public x = "); sc_mpz_out_str(stderr, 16, &p_public.x); fprintf(stderr, "\n");
	fprintf(stderr, "public y = "); sc_mpz_out_str(stderr, 16, &p_public.y); fprintf(stderr, "\n");*/

	// Obtain the base point G
	p_base.n = sc->ec->params->num_limbs;
	sc_mpz_set_str(&p_base.x, 16, sc->ec->params->g_x);
	sc_mpz_set_str(&p_base.y, 16, sc->ec->params->g_y);

	// u1 = w * z * G
	sc_mpz_mul(&temp, &w, &z);
	sc_mpz_mod(&temp, &temp, &metadata.order_m);
	secret = sc_mpz_get_limbs(&temp);
	scalar_point_mult(num_bits, &metadata, &p_base, secret, &p_u1);

	// u2 = w * r * Q
	sc_mpz_mul(&temp, &w, &r);
	sc_mpz_mod(&temp, &temp, &metadata.order_m);
	secret = sc_mpz_get_limbs(&temp);
	scalar_point_mult(num_bits, &metadata, &p_public, secret, &p_u2);

	// Point addition to obtain the signature point on the curve
	/*fprintf(stderr, "u1 x = "); sc_mpz_out_str(stderr, 16, &p_u1.x); fprintf(stderr, "\n");
	fprintf(stderr, "u1 y = "); sc_mpz_out_str(stderr, 16, &p_u1.y); fprintf(stderr, "\n");
	fprintf(stderr, "u2 x = "); sc_mpz_out_str(stderr, 16, &p_u2.x); fprintf(stderr, "\n");
	fprintf(stderr, "u2 y = "); sc_mpz_out_str(stderr, 16, &p_u2.y); fprintf(stderr, "\n");*/
	point_add(&metadata, &p_u1, &p_u2);
	/*fprintf(stderr, "u1 x = "); sc_mpz_out_str(stderr, 16, &p_u1.x); fprintf(stderr, "\n");
	fprintf(stderr, "u1 y = "); sc_mpz_out_str(stderr, 16, &p_u1.y); fprintf(stderr, "\n");*/

	// Validate the signature
	if (0 == sc_mpz_cmp(&p_u1.x, &r)) {
		retval = SC_FUNC_SUCCESS;
	}
	else {
		retval = SC_FUNC_FAILURE;
	}

	// Free memory resources
	sc_mpz_clear(&metadata.lambda);
	sc_mpz_clear(&metadata.x);
	sc_mpz_clear(&metadata.y);
	sc_mpz_clear(&metadata.temp);
	sc_mpz_clear(&metadata.a);
	sc_mpz_clear(&metadata.m);
	sc_mpz_clear(&metadata.m_inv);
	sc_mpz_clear(&metadata.order_m);
	sc_mpz_clear(&temp);
	sc_mpz_clear(&r);
	sc_mpz_clear(&s);
	sc_mpz_clear(&w);
	sc_mpz_clear(&z);
	point_clear(&p_base);
	point_clear(&p_public);
	point_clear(&p_u1);
	point_clear(&p_u2);

	return retval;
}



//
// end of file
//
