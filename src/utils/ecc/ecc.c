/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2017                      *
 *                                                                           *
 * This file is part of tachyon.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "ecc.h"

#include "utils/arith/sc_mpz.h"
#include "utils/crypto/prng.h"


#define ECC_K_IS_HIGH        0
#define ECC_K_IS_SCA_DUMMY   1
#define ECC_K_IS_LOW         2

typedef enum ecc_direction {
	ECC_DIR_LEFT = 0,
	ECC_DIR_RIGHT,
} ecc_direction_e;

typedef struct point_secret {
	const sc_ulimb_t *secret;
	size_t max;
	size_t index;
	size_t shift;
	ecc_direction_e dir;
} point_secret_t;

typedef struct ecc_point {
	sc_mpz_t x;
	sc_mpz_t y;
	size_t   n;
} ecc_point_t;


const ecdh_set_t param_ecdh_secp256r1 = {
	256,
	256 >> 3,
	256 >> SC_LIMB_BITS_SHIFT,
	"-3", // "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
	"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
	"4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
	"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
};

const ecdh_set_t param_ecdh_secp384r1 = {
	384,
	384 >> 3,
	384 >> SC_LIMB_BITS_SHIFT,
	"-3", // "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
	"AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
	"3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000FFFFFFFF",
};

const ecdh_set_t param_ecdh_secp521r1 = {
	521,
	521 >> 3,
	521 >> SC_LIMB_BITS_SHIFT,
	"-3", // "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
	"00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
	"011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
	"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
};


static void secret_bits_init(point_secret_t *bit_ctx, const sc_ulimb_t *secret, size_t num_bits)
{
	bit_ctx->secret = secret;
	bit_ctx->max    = num_bits;
	bit_ctx->index  = (bit_ctx->max - 1) >> SC_LIMB_BITS_SHIFT;
	bit_ctx->shift  = (bit_ctx->max & SC_LIMB_BITS_MASK) - 1;
	bit_ctx->dir    = ECC_DIR_LEFT;
}

static UINT32 secret_bits_pull(point_secret_t *bit_ctx)
{
	static const UINT32 code[4] = {ECC_K_IS_LOW, ECC_K_IS_HIGH, ECC_K_IS_SCA_DUMMY, ECC_K_IS_SCA_DUMMY};
	UINT32 bit;
	sc_ulimb_t word = bit_ctx->secret[bit_ctx->index];
	sc_slimb_t shift = bit_ctx->shift;

	bit = (word >> shift) & 0x1;

	if (ECC_DIR_LEFT == bit_ctx->dir) {
		shift--;
		bit_ctx->index -= (sc_ulimb_t)(((shift ^ SC_LIMB_MASK) - SC_LIMB_MASK)) >> SC_LIMB_BITS_MASK;
	}
	else {
		shift++;
		bit_ctx->index += (sc_ulimb_t)((((SC_LIMB_BITS - 1 - shift) ^ SC_LIMB_MASK) - SC_LIMB_MASK)) >> SC_LIMB_BITS_MASK;
	}

	bit_ctx->shift = shift & SC_LIMB_BITS_MASK;

	return code[bit];
}

static void point_clear(ecc_point_t *p)
{
	sc_mpz_set_ui(&p->x, 0);
	sc_mpz_set_ui(&p->y, 0);
}

static SINT32 point_is_zero(const ecc_point_t *p)
{
	return sc_mpz_is_zero(&p->x) && sc_mpz_is_zero(&p->y);
}

static void point_cartesian(const sc_mpz_t *m, const sc_mpz_t *lambda, ecc_point_t *p_a, const ecc_point_t *p_b)
{
	sc_mpz_t x, y, temp;
	sc_mpz_init2(&x, MAX_ECC_BITS);
	sc_mpz_init2(&y, MAX_ECC_BITS);
	sc_mpz_init2(&temp, 2*MAX_ECC_BITS);

	// xr = lambda^2 - xa - xb
	sc_mpz_mul(&temp, lambda, lambda);
	sc_mpz_mod(&x, &temp, m);
    sc_mpz_sub(&x, &x, &p_a->x);
    sc_mpz_sub(&x, &x, &p_b->x);
    sc_mpz_mod(&p_a->x, &x, m);

	// yr = lambda*(xa - xr) - ya
    sc_mpz_sub(&y, &p_a->x, &x);
    sc_mpz_mod(&y, &y, m);
	sc_mpz_mul(&temp, lambda, &y);
	sc_mpz_mod(&temp, &temp, m);
    sc_mpz_sub(&y, &y, &p_a->y);
    sc_mpz_mod(&p_a->y, &y, m);

	sc_mpz_clear(&x);
	sc_mpz_clear(&y);
	sc_mpz_clear(&temp);
}

static void point_double_cartesian(const sc_mpz_t *m, const sc_mpz_t *a, const sc_mpz_t *p, ecc_point_t *point)
{
	size_t i;
	sc_mpz_t lambda, temp, x, y;
	sc_mpz_init2(&lambda, MAX_ECC_BITS);
	sc_mpz_init2(&x, MAX_ECC_BITS);
	sc_mpz_init2(&y, MAX_ECC_BITS);
	sc_mpz_init2(&temp, 2*MAX_ECC_BITS);

	// lambda = (3*x^2 + a)/(2*y)
	sc_mpz_mul(&temp, &point->x, &point->x);
	sc_mpz_mod(&lambda, &temp, m);
	sc_mpz_sub(&lambda, &lambda, a);
	sc_mpz_mul_ui(&temp, &lambda, 3);
	sc_mpz_mod(&lambda, &temp, m);
	sc_mpz_add(&temp, &point->y, &point->y);
	sc_mpz_mod(&x, &temp, m);
	sc_mpz_invmod(&y, &x, m);
	sc_mpz_mul(&temp, &lambda, &y);
	sc_mpz_mod(&lambda, &temp, m);

    // Given lambda, calculate the resulting point p
	point_cartesian(m, &lambda, point, point);

	sc_mpz_clear(&lambda);
	sc_mpz_clear(&x);
	sc_mpz_clear(&y);
	sc_mpz_clear(&temp);
}

static void point_add_cartesian(const sc_mpz_t *m, const sc_mpz_t *p, ecc_point_t *p_a, const ecc_point_t *p_b)
{
	size_t i;
	sc_mpz_t lambda, temp, x, y;
	sc_mpz_init2(&lambda, MAX_ECC_BITS);
	sc_mpz_init2(&x, MAX_ECC_BITS);
	sc_mpz_init2(&y, MAX_ECC_BITS);
	sc_mpz_init2(&temp, 2*MAX_ECC_BITS);

	// lambda = (yb - ya) / (xb - xa)
	sc_mpz_sub(&y, &p_b->y, &p_a->y);
	sc_mpz_mod(&y, &y, m);
	sc_mpz_sub(&x, &p_b->x, &p_a->x);
	sc_mpz_mod(&x, &x, m);
	sc_mpz_invmod(&lambda, &x, m);
	sc_mpz_mul(&temp, &lambda, &y);
	sc_mpz_mod(&lambda, &temp, m);

    // Given lambda, calculate the resulting point p
	point_cartesian(m, &lambda, p_a, p_b);

	sc_mpz_clear(&lambda);
	sc_mpz_clear(&x);
	sc_mpz_clear(&y);
	sc_mpz_clear(&temp);
}

static void point_double(const sc_mpz_t *m, const sc_mpz_t *a, const sc_mpz_t *p, ecc_point_t *point)
{
	// If x and y are zero the result is zero
	if (point_is_zero(point)) {
		return;
	}

	point_double_cartesian(m, a, p, point);
}

static void point_add(const sc_mpz_t *m, const sc_mpz_t *p, ecc_point_t *p_a, const ecc_point_t *p_b)
{
	point_add_cartesian(m, p, p_a, p_b);
}


static void scalar_point_mult(size_t num_bits, const sc_mpz_t *a, const sc_mpz_t *m, const sc_mpz_t *p,
	const ecc_point_t *p_in, const sc_ulimb_t *secret, ecc_point_t *p_out)
{
	size_t i;
	point_secret_t bit_ctx;
	ecc_point_t p_dummy;

	point_clear(p_out);
	point_clear(&p_dummy);

	secret_bits_init(&bit_ctx, secret, num_bits);

	for (i=num_bits; i--;) {
		UINT32 bit;

		// Point doubling
		point_double(m, a, p, p_out);

		// Determine if an asserted bit requires a point addition (or a dummy point addition as an SCA countermeasure)
		bit = secret_bits_pull(&bit_ctx);
		if (ECC_K_IS_LOW != bit) {
			// Create a mask of all zeros if ECC_K_IS_HIGH or all ones if a ECC_K_IS_SCA_DUMMY operation
			intptr_t mask   = (intptr_t) bit - 1;

			// Branch-free pointer selection in constant time
			intptr_t p_temp = (intptr_t) p_out ^ (((intptr_t) p_out ^ (intptr_t) &p_dummy) & mask);

			// Point addition
			point_add(m, p, (ecc_point_t *) p_temp, p_in);
		}
	}
}

SINT32 ecc_diffie_hellman(safecrypto_t *sc, const ecc_point_t *p_base, const sc_ulimb_t *secret, size_t *tlen, UINT8 **to)
{
	size_t i;
	ecc_point_t p_result;
	size_t num_bits, num_bytes, num_limbs;
	sc_mpz_t m, p, a;

	// If the sc pointer is NULL then return with a failure
	if (NULL == sc) {
		return SC_FUNC_FAILURE;
	}

	// Obtain common array lengths
	num_bits  = sc->ecdh->params->num_bits;
	num_bytes = sc->ecdh->params->num_bytes;
	num_limbs = sc->ecdh->params->num_limbs;

	// Initialise the MP variables
	sc_mpz_init2(&a, MAX_ECC_BITS);
	sc_mpz_init2(&m, MAX_ECC_BITS);
	sc_mpz_init2(&p, MAX_ECC_BITS+1);
	sc_mpz_set_str(&a, 16, sc->ecdh->params->a);
	sc_mpz_set_str(&p, 16, sc->ecdh->params->p);

	// Perform a scalar point multiplication from the base point using the random secret
	scalar_point_mult(num_bits, &a, &m, &p, p_base, secret, &p_result);

	// Translate the output point (coordinates are MP variables) to the output byte stream
	*to = SC_MALLOC((num_bits + 7) >> 3);
	*tlen = 2 * num_bytes;
	sc_mpz_get_bytes(*to, &p_result.x);
	sc_mpz_get_bytes(*to + num_bytes, &p_result.y);

	// Free resources associated with the MP variables
	sc_mpz_clear(&a);
	sc_mpz_clear(&m);
	sc_mpz_clear(&p);

	return SC_FUNC_SUCCESS;
}

SINT32 ecc_diffie_hellman_encapsulate(safecrypto_t *sc, const sc_ulimb_t *secret, size_t *tlen, UINT8 **to)
{
	size_t num_bits  = sc->ecdh->params->num_bits;
	size_t num_bytes = sc->ecdh->params->num_bytes;

	// Obtain the base point from the ECC parameters
	ecc_point_t p_base;
	p_base.n = sc->ecdh->params->num_limbs;
	sc_mpz_set_str(&p_base.x, 16, sc->ecdh->params->g_x);
	sc_mpz_set_str(&p_base.y, 16, sc->ecdh->params->g_y);

	// Use an ECC scalar point multiplication to geometrically transform the base point
	// to the intermediate point (i.e. the public key)
	ecc_diffie_hellman(sc, &p_base, secret, tlen, to);

	return SC_FUNC_SUCCESS;
}

SINT32 ecc_diffie_hellman_decapsulate(safecrypto_t *sc, const sc_ulimb_t *secret, size_t flen, const UINT8 *from, size_t *tlen, UINT8 **to)
{
	size_t num_bits  = sc->ecdh->params->num_bits;
	size_t num_bytes = sc->ecdh->params->num_bytes;
	size_t num_limbs = sc->ecdh->params->num_limbs;

	// Convert the input byte stream (public key) to the intermediate coordinate
	ecc_point_t p_base;
	p_base.n = num_limbs;
	sc_mpz_set_bytes(&p_base.x, from, num_bytes);
	sc_mpz_set_bytes(&p_base.y, from + num_bytes, num_bytes);

	// Use an ECC scalar point multiplication to geometrically transform the intermediate point
	// to the final point (shared secret)
	ecc_diffie_hellman(sc, &p_base, secret, tlen, to);

	return SC_FUNC_SUCCESS;
}

SINT32 ecc_sign(safecrypto_t *sc, const UINT8 *m, size_t mlen,
    UINT8 **sigret, size_t *siglen)
{
	size_t i, num_bits, num_bytes, num_limbs;
	ecc_point_t p_base, p_result;
	sc_ulimb_t secret[MAX_ECC_LIMBS];
	sc_mpz_t mod, d, e, k, temp1, temp2, p, a;
	SINT32 mem_is_zero;

	// Obtain common array lengths
	num_bits  = sc->ecdh->params->num_bits;
	num_bytes = sc->ecdh->params->num_bytes;
	num_limbs = sc->ecdh->params->num_limbs;

	p_base.n = (num_bits + SC_LIMB_BITS - 1) >> SC_LIMB_BITS_SHIFT;
	sc_mpz_set_str(&p_base.x, 16, sc->ecdh->params->g_x);
	sc_mpz_set_str(&p_base.y, 16, sc->ecdh->params->g_y);

	sc_mpz_init2(&a, MAX_ECC_BITS);
	sc_mpz_init2(&mod, MAX_ECC_BITS);
	sc_mpz_init2(&d, MAX_ECC_BITS);
	sc_mpz_init2(&e, MAX_ECC_BITS);
	sc_mpz_init2(&k, MAX_ECC_BITS);
	sc_mpz_init2(&temp1, 2*MAX_ECC_BITS);
	sc_mpz_init2(&temp2, MAX_ECC_BITS);
	sc_mpz_init2(&p, MAX_ECC_BITS+1);
	sc_mpz_set_str(&a, 16, sc->ecdh->params->a);
	sc_mpz_set_str(&p, 16, sc->ecdh->params->p);

restart:
	// Generate a random secret k and ensure it is not zero
	prng_mem(sc->prng_ctx[0], (UINT8*)secret, num_bytes);
	mem_is_zero = sc_mem_is_zero((void*) secret, num_bytes);
	if (mem_is_zero) {
		goto restart;
	}

	// Perform a scalar point multiplication from the base point using the random secret
	scalar_point_mult(num_bits, &a, &mod, &p, &p_base, secret, &p_result);
	sc_mpz_mod(&p_result.x, &p_result.x, &mod);
	if (sc_mpz_is_zero(&p_result.x)) {
		goto restart;
	}

	// s = k^(-1)*(z + r*d) mod n
	sc_mpz_mul(&temp1, &p_result.x, &d);
	sc_mpz_mod(&temp2, &temp1, &mod);
	sc_mpz_add(&temp1, &temp2, &e);
	sc_mpz_mod(&temp1, &temp1, &mod);
	sc_mpz_invmod(&temp2, &k, &mod);
	sc_mpz_mul(&temp1, &temp2, &temp1);
	sc_mpz_mod(&temp2, &temp1, &mod);
	if (sc_mpz_is_zero(&temp2)) {
		goto restart;
	}

	// Pack r and s into the output signature
	SINT32 r_len = (sc_mpz_get_size(&p_result.x) + 7) >> 3;
	SINT32 s_len = (sc_mpz_get_size(&temp2) + 7) >> 3;
	sc_ulimb_t *r = sc_mpz_get_limbs(&p_result.x);
	sc_ulimb_t *s = sc_mpz_get_limbs(&temp2);
	*siglen = r_len + s_len;
	*sigret = SC_MALLOC(*siglen);
#if SC_LIMB_BITS == 64
	SC_BIG_ENDIAN_64_COPY(*sigret, 0, r, r_len);
	SC_BIG_ENDIAN_64_COPY(*sigret, r_len, s, s_len);
#else
	SC_BIG_ENDIAN_32_COPY(*sigret, 0, r, r_len);
	SC_BIG_ENDIAN_32_COPY(*sigret, r_len, s, s_len);
#endif

	sc_mpz_clear(&a);
	sc_mpz_clear(&mod);
	sc_mpz_clear(&d);
	sc_mpz_clear(&e);
	sc_mpz_clear(&k);
	sc_mpz_clear(&temp1);
	sc_mpz_clear(&temp2);
	sc_mpz_clear(&p);
}

SINT32 ecc_verify(safecrypto_t *sc, const UINT8 *m, size_t mlen,
    const UINT8 *sigbuf, size_t siglen)
{
	size_t i, num_bits, num_bytes, num_limbs;
	sc_mpz_t p, mod, a, r, s, w, temp, z;
	sc_ulimb_t *secret;
	ecc_point_t p_base, p_public, p_u1, p_u2;

	// Obtain common array lengths
	num_bits  = sc->ecdh->params->num_bits;
	num_bytes = sc->ecdh->params->num_bytes;
	num_limbs = sc->ecdh->params->num_limbs;

	sc_mpz_init2(&temp, 2*MAX_ECC_BITS);
	sc_mpz_init2(&a, MAX_ECC_BITS);
	sc_mpz_init2(&mod, MAX_ECC_BITS);
	sc_mpz_init2(&p, MAX_ECC_BITS+1);
	sc_mpz_init2(&w, MAX_ECC_BITS);
	sc_mpz_set_str(&p, 16, sc->ecdh->params->p);
	sc_mpz_set_str(&a, 16, sc->ecdh->params->a);

	sc_mpz_invmod(&w, &s, &mod);

	p_base.n = sc->ecdh->params->num_limbs;
	sc_mpz_set_str(&p_base.x, 16, sc->ecdh->params->g_x);
	sc_mpz_set_str(&p_base.y, 16, sc->ecdh->params->g_y);

	sc_mpz_mul(&temp, &w, &z);
	sc_mpz_mod(&temp, &temp, &mod);
	secret = sc_mpz_get_limbs(&temp);
	scalar_point_mult(num_bits, sc->ecdh->params->a, &mod, &p, &p_base, secret, &p_u1);

	sc_mpz_mul(&temp, &w, &r);
	sc_mpz_mod(&temp, &temp, m);
	secret = sc_mpz_get_limbs(&temp);
	scalar_point_mult(num_bits, sc->ecdh->params->a, &mod, &p, &p_public, secret, &p_u2);

	point_add(&m, &p, &p_u1, &p_u2);

	sc_mpz_clear(&a);
	sc_mpz_clear(&mod);
	sc_mpz_clear(&p);
	sc_mpz_clear(&temp);

	if (0 == sc_mpz_cmp(&p_u1.x, &r)) {
		return SC_FUNC_SUCCESS;
	}
	else {
		return SC_FUNC_FAILURE;
	}
}




//
// end of file
//
