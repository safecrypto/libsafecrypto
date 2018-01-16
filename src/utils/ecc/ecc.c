/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2017                      *
 *                                                                           *
 * This file is part of tachyon.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "ecc.h"

#include "utils/ecc/secret_bits.h"


#ifdef USE_OPT_ECC
#include "utils/crypto/prng.h"
#include "utils/arith/sc_mpn.h"

typedef struct ecc_metadata {
	sc_ulimb_t lambda[MAX_ECC_LIMBS];
	sc_ulimb_t temp[MAX_ECC_LIMBS];
	sc_ulimb_t x[MAX_ECC_LIMBS];
	sc_ulimb_t y[MAX_ECC_LIMBS];
	const sc_ulimb_t *m;
	const sc_ulimb_t *mu;
	const sc_ulimb_t *order;
	const sc_ulimb_t *a;
	size_t     k;
	size_t     n;
} ecc_metadata_t;

const ecdh_set_t param_ecdh_secp256r1 = {
	256,
	32,
	256 >> SC_LIMB_BITS_SHIFT,
#if 64 == SC_LIMB_BITS
	{0xFFFFFFFFFFFFFFFC, 0x00000000FFFFFFFF, 0x0000000000000000, 0xFFFFFFFF00000001},
	{0x3BCE3C3E27D2604B, 0x651D06B0CC53B0F6, 0xB3EBBD55769886BC, 0x5AC635D8AA3A93E7},
	{0xF4A13945D898C296, 0x77037D812DEB33A0, 0xF8BCE6E563A440F2, 0x6B17D1F2E12C4247},
	{0xCBB6406837BF51F5, 0x2BCE33576B315ECE, 0x8EE7EB4A7C0F9E16, 0x4FE342E2FE1A7F9B},
	{0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF, 0x0000000000000000, 0xFFFFFFFF00000001},
	{0x0000000000000001, 0xffffffff00000000, 0xffffffffffffffff, 0x00000000fffffffe},
	{0xF3B9CAC2FC632551, 0xBCE6FAADA7179E84, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF00000000},
	{0x0000000000000001, 0xFFFFFFFEFFFFFFFF, 0xFFFFFFFEFFFFFFFE, 0x00000000FFFFFFFF, 0x0000000000000003},
#else
	{0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF},
	{0x27D2604B, 0x3BCE3C3E, 0xCC53B0F6, 0x651D06B0, 0x769886BC, 0xB3EBBD55, 0xAA3A93E7, 0x5AC635D8},
	{0xD898C296, 0xF4A13945, 0x2DEB33A0, 0x77037D81, 0x63A440F2, 0xF8BCE6E5, 0xE12C4247, 0x6B17D1F2},
	{0x37BF51F5, 0xCBB64068, 0x6B315ECE, 0x2BCE3357, 0x7C0F9E16, 0x8EE7EB4A, 0xFE1A7F9B, 0x4FE342E2},
	{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF},
	{0x00000001, 0x00000000, 0x00000000, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0x00000000},
	{0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF},
	{0x00000001, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFE, 0xFFFFFFFE, 0xFFFFFFFF, 0x00000000, 0x00000003},
#endif
};


static void point_reset(ecc_point_t *p)
{
	size_t i;
	for (i=0; i<p->n; i++) {
		p->x[i] = 0;
		p->y[i] = 0;
	}
	p->x_len = p->n;
	p->y_len = p->n;
}

static void point_init(ecc_point_t *p, size_t n)
{
	p->n = n;
	point_reset(p);
}

static void point_clear(ecc_point_t *p)
{
}

static void point_copy(ecc_point_t *p_out, const ecc_point_t *p_in)
{
	size_t i;
	for (i=0; i<p_in->n; i++) {
		p_out->x[i] = p_in->x[i];
		p_out->y[i] = p_in->y[i];
	}
	p_out->n = p_in->n;
	p_out->x_len = p_in->x_len;
	p_out->y_len = p_in->y_len;
}

static SINT32 point_is_zero(const ecc_point_t *p)
{
	volatile SINT32 flag = 0;
	size_t i;
	for (i=0; i<p->n; i++) {
		flag |= p->x[i] | p->y[i];
	}
	return 0 == flag;
}

void ec_zero(sc_ulimb_t* inout, size_t n)
{
    while (n--) {
        inout[n] = 0;
    }
}

void ec_copy(sc_ulimb_t* out, const sc_ulimb_t* in, size_t n)
{
    while (n--) {
        out[n] = in[n];
    }
}

static sc_ulimb_t add(sc_ulimb_t *out, const sc_ulimb_t *x, const sc_ulimb_t *y, size_t n){
	sc_ulimb_big_t d = 0; //carry
	size_t v;
	for (v=0; v<n; v++) {
		d += (sc_ulimb_big_t) x[v] + (sc_ulimb_big_t) y[v];
		out[v] = d;
		d = d >> SC_LIMB_BITS; //save carry
	}
	
	return (sc_ulimb_t) d;
}

static sc_ulimb_t sub(sc_ulimb_t *out, const sc_ulimb_t *x, const sc_ulimb_t *y, size_t n){
	sc_ulimb_big_t d = 0;
	size_t v;
	for(v=0; v<n; v++){
		d = (sc_ulimb_big_t) x[v] - (sc_ulimb_big_t) y[v] - d;
		out[v] = d & SC_LIMB_MASK;
		d = d >> SC_LIMB_BITS;
		d &= 0x1;
	}	
	return (sc_ulimb_t) d;
}

static void ec_field_add(sc_ulimb_t *out, const sc_ulimb_t *in1, const sc_ulimb_t *in2, size_t n, const sc_ulimb_t *mu)
{
	if (add(out, in1, in2, n)) {
		sc_ulimb_t temp[MAX_ECC_LIMBS] = {0};
		add(temp, out, mu, n);
		ec_copy(out, temp, n);
	}
}

static void ec_field_sub(sc_ulimb_t *out, const sc_ulimb_t *in1, const sc_ulimb_t *in2, size_t n, const sc_ulimb_t *mu)
{
	if (sub(out, in1, in2, n)) {
		sc_ulimb_t temp[MAX_ECC_LIMBS] = {0};
		add(temp, out, mu, n);
		ec_copy(out, temp, n);
	}
}

static SINT32 is_one(const sc_ulimb_t *in, size_t n)
{
	size_t i;
	volatile sc_ulimb_t flag = 0;
	for (i=1; i<n; i++) {
		flag |= in[i];
	}
	flag ^= in[0] ^ 1;
	return 0 == flag;
}

SINT32 ec_cmp(const sc_ulimb_t *in1, const sc_ulimb_t *in2, size_t n)
{
    while (n--) {
        if (in1[n] != in2[n]) {
            return (in1[n] > in2[n])? 1 : -1;
        }
    }
    return 0;
}

static sc_ulimb_t ec_rshift(sc_ulimb_t *inout, size_t n)
{
    size_t i;
	sc_ulimb_t c, old = 0;
	for (i=2*n; i--;) {
		c = inout[i] & 0x1;
		inout[i] = (inout[i] >> 1) | (old << (SC_LIMB_BITS - 1));
		old = c;
	}
}

static void ec_field_add_div(sc_ulimb_t* out, const sc_ulimb_t *in, size_t n, const sc_ulimb_t *m, const sc_ulimb_t *mu){
	sc_ulimb_t c = add(out, in, m, n);
	ec_rshift(out, n);
	if (c) { //add prime if carry is still set!
#if 64 == SC_LIMB_BITS
		out[3] |= SC_LIMB_HIGHBIT; // add the carry
#else
		out[7] |= SC_LIMB_HIGHBIT; // add the carry
#endif
		if (ec_cmp(out, m, n) > 0) {
			sc_ulimb_t tempas[2*MAX_ECC_LIMBS] = {0};
			add(tempas, out, mu, 2*n);
			ec_copy(out, tempas, n);
		}
		
	}
}


static void ec_field_inv(sc_ulimb_t *out, const sc_ulimb_t *in, size_t n, const sc_ulimb_t *m, const sc_ulimb_t *mu)
{
	sc_ulimb_t u[MAX_ECC_LIMBS] = {0}, v[MAX_ECC_LIMBS] = {0}, x1[MAX_ECC_LIMBS] = {0}, x2[MAX_ECC_LIMBS] = {0};
	sc_ulimb_t tempm[MAX_ECC_LIMBS] = {0};
	sc_ulimb_t tempm2[MAX_ECC_LIMBS] = {0};

	sc_ulimb_t t;
	ec_copy(u, in, n); 
	ec_copy(v, m, n); 
	x1[0] = 1; 
	// While u !=1 and v !=1
	while (0 == (is_one(u, 2*n) || is_one(v, 2*n))) {
		while(!(u[0]&1)) { 					/* While u is even */
			ec_rshift(u, n); 				/* divide by 2 */
			if (!(x1[0]&1)) {				/*if x1 is even*/
				ec_rshift(x1, n);				/* Divide by 2 */
			}
			else {
				ec_field_add_div(tempm, x1, n, m, mu);	/* tempm = x1 + p */
				ec_copy(x1, tempm, n);					/* x1 = tempm */
			}
		} 
		while(!(v[0]&1)) {					/* While v is even */
			ec_rshift(v, n);				/* divide by 2 */ 
			if (!(x2[0]&1)) {				/*if x2 is even*/
				ec_rshift(x2, n);	 			/* Divide by 2 */
			}
			else {
				ec_field_add_div(tempm, x2, n, m, mu);	/* tempm = x2 + p */
				ec_copy(x2, tempm, n); 				/* x2 = tempm */ 
			}
		}
		t = sub(tempm, u, v, n); 			/* tempm=u-v */
		if (0 == t) {							/* If u > 0 */
			ec_copy(u, tempm, n); 					/* u=u-v */
			ec_field_sub(tempm, x1, x2, n, m);		/* tempm=x1-x2 */
			ec_copy(x1, tempm, n);					/* x1=x1-x2 */
		}
		else {
			sub(tempm, v, u, n); 				/* tempm=v-u */
			ec_copy(v, tempm, n); 					/* v=v-u */
			ec_field_sub(tempm, x2, x1, n, m); 		/* tempm=x2-x1 */
			ec_copy(x2, tempm, n);					/* x2=x2-x1 */
		}
	} 
	if (is_one(u, n)) {
		ec_copy(out, x1, n); 
	}
	else {
		ec_copy(out, x2, n);
	}
}

static void ec_field_mod(sc_ulimb_t *a, const sc_ulimb_t *b, size_t n, const sc_ulimb_t *m, const sc_ulimb_t *mu)
{
}

static void ec_field_mod_secp256r1(sc_ulimb_t *a, const sc_ulimb_t *b, size_t n, const sc_ulimb_t *m, const sc_ulimb_t *mu)
{
	size_t i;
	sc_ulimb_t tempm[4] = {0};
	sc_ulimb_t tempm2[4] = {0};

	/* A = T */ 
	ec_copy(a, b, 4);

#if 64 == SC_LIMB_BITS
	/* Form S1 */ 
	tempm[0] = 0;
	tempm[1] = b[5] & 0xFFFFFFFF00000000ULL;
	tempm[2] = b[6];
	tempm[3] = b[7];

	/* tempm2=T+S1 */
	ec_field_add(tempm2, a, tempm, 4, mu);
	/* A=T+S1+S1 */ 
	ec_field_add(a, tempm2, tempm, 4, mu);
	/* Form S2 */
	tempm[0] = 0;
	tempm[1] = b[6] << 32;
	tempm[2] = (b[6] >> 32) | (b[7] << 32);
	tempm[3] = b[7] >> 32;
	/* tempm2=T+S1+S1+S2 */ 
	ec_field_add(tempm2, a, tempm, 4, mu);
	/* A=T+S1+S1+S2+S2 */ 
	ec_field_add(a, tempm2, tempm, 4, mu);
	/* Form S3 */ 
	tempm[0] = b[4];
	tempm[1] = b[5] & 0xFFFFFFFF;
	tempm[2] = 0;
	tempm[3] = b[7];
	/* tempm2=T+S1+S1+S2+S2+S3 */ 
	ec_field_add(tempm2, a, tempm, 4, mu);
	/* Form S4 */ 
	tempm[0] = (b[5] << 32) | (b[4] >> 32);
	tempm[1] = (b[6] & 0xFFFFFFFF00000000ULL) | (b[5] >> 32);;
	tempm[2] = b[7];
	tempm[3] = (b[6] >> 32) | (b[4] << 32);
	/* A=T+S1+S1+S2+S2+S3+S4 */ 
	ec_field_add(a, tempm2, tempm, 4, mu);
	/* Form D1 */ 
	tempm[0] = (b[6] << 32) | (b[5] >> 32);
	tempm[1] = b[6] >> 32;
	tempm[2] = 0;
	tempm[3] = (b[5] << 32) | (b[4] & 0xFFFFFFFF);
	/* tempm2=T+S1+S1+S2+S2+S3+S4-D1 */ 
	ec_field_sub(tempm2, a, tempm, 4, m);
	/* Form D2 */ 
	tempm[0] = b[6];
	tempm[1] = b[7];
	tempm[2] = 0;
	tempm[3] = (b[5] & 0xFFFFFFFF00000000ULL) | (b[4] >> 32);
	/* A=T+S1+S1+S2+S2+S3+S4-D1-D2 */ 
	ec_field_sub(a, tempm2, tempm, 4, m);
	/* Form D3 */ 
	tempm[0] = (b[7] << 32) | (b[6] >> 32);
	tempm[1] = (b[7] >> 32) | (b[4] << 32);
	tempm[2] = (b[5] << 32) | (b[4] >> 32);
	tempm[3] = b[6] << 32;
	/* tempm2=T+S1+S1+S2+S2+S3+S4-D1-D2-D3 */ 
	ec_field_sub(tempm2, a, tempm, 4, m);
	/* Form D4 */ 
	tempm[0] = b[7];
	tempm[1] = b[4] & 0xFFFFFFFF00000000ULL;
	tempm[2] = b[5];
	tempm[3] = b[6] & 0xFFFFFFFF00000000ULL;
#else
	/* Form S1 */ 
	for (i=0; i<3; i++) tempm[i] = 0; 
	for (i=3; i<8; i++) tempm[i] = b[i+8];

	/* tempm2=T+S1 */ 
	ec_field_add(tempm2, a, tempm, n, mu);
	/* A=T+S1+S1 */ 
	ec_field_add(a, tempm2, tempm, n, mu);
	/* Form S2 */ 
	for (i=0; i<3; i++) tempm[i] = 0; 
	for (i=3; i<7; i++) tempm[i] = b[i+9]; 
	for (i=7; i<8; i++) tempm[i] = 0;
	/* tempm2=T+S1+S1+S2 */ 
	ec_field_add(tempm2, a, tempm, n, mu);
	/* A=T+S1+S1+S2+S2 */ 
	ec_field_add(a, tempm2, tempm, n, mu);
	/* Form S3 */ 
	for (i=0; i<3; i++) tempm[i] = b[i+8]; 
	for (i=3; i<6; i++) tempm[i] = 0; 
	for (i=6; i<8; i++) tempm[i] = b[i+8];
	/* tempm2=T+S1+S1+S2+S2+S3 */ 
	ec_field_add(tempm2, a, tempm, n, mu);
	/* Form S4 */ 
	for (i=0; i<3; i++) tempm[i] = b[i+9]; 
	for (i=3; i<6; i++) tempm[i] = b[i+10]; 
	for (i=6; i<7; i++) tempm[i] = b[i+7]; 
	for (i=7; i<8; i++) tempm[i] = b[i+1];
	/* A=T+S1+S1+S2+S2+S3+S4 */ 
	ec_field_add(a, tempm2, tempm, n, mu);
	/* Form D1 */ 
	for (i=0; i<3; i++) tempm[i] = b[i+11]; 
	for (i=3; i<6; i++) tempm[i] = 0; 
	for (i=6; i<7; i++) tempm[i] = b[i+2]; 
	for (i=7; i<8; i++) tempm[i] = b[i+3];
	/* tempm2=T+S1+S1+S2+S2+S3+S4-D1 */ 
	ec_field_sub(tempm2, a, tempm, n, m);
	/* Form D2 */ 
	for (i=0; i<4; i++) tempm[i] = b[i+12]; 
	for (i=4; i<6; i++) tempm[i] = 0; 
	for (i=6; i<7; i++) tempm[i] = b[i+3]; 
	for (i=7; i<8; i++) tempm[i] = b[i+4];
	/* A=T+S1+S1+S2+S2+S3+S4-D1-D2 */ 
	ec_field_sub(a, tempm2, tempm, n, m);
	/* Form D3 */ 
	for (i=0; i<3; i++) tempm[i] = b[i+13]; 
	for (i=3; i<6; i++) tempm[i] = b[i+5]; 
	for (i=6; i<7; i++) tempm[i] = 0; 
	for (i=7; i<8; i++) tempm[i] = b[i+5];
	/* tempm2=T+S1+S1+S2+S2+S3+S4-D1-D2-D3 */ 
	ec_field_sub(tempm2, a, tempm, n, m);
	/* Form D4 */ 
	for (i=0; i<2; i++) tempm[i] = b[i+14]; 
	for (i=2; i<3; i++) tempm[i] = 0; 
	for (i=3; i<6; i++) tempm[i] = b[i+6]; 
	for (i=6; i<7; i++) tempm[i] = 0; 
	for (i=7; i<8; i++) tempm[i] = b[i+6];
#endif
	/* A=T+S1+S1+S2+S2+S3+S4-D1-D2-D3-D4 */ 
	ec_field_sub(a, tempm2, tempm, n, m);
	if(ec_cmp(a, m, n) >= 0){
		ec_field_sub(tempm, a, m, n, m);
		ec_copy(a, tempm, n);
	}
}

static void ec_mul(sc_ulimb_t *out, const sc_ulimb_t *in1, const sc_ulimb_t *in2, size_t n)
{
#if 0
	mpn_mul_n(out, in1, in2, n);
#else
	sc_ulimb_t temp[n * 2];
	ec_zero(temp, n * 2);
	ec_zero(out, n * 2);
	size_t k, i;
	for (k = 0; k < n; k++) {
		for (i = 0; i < n; i++) { 
			sc_ulimb_big_t l;
			l = (sc_ulimb_big_t) in1[i] * (sc_ulimb_big_t) in2[k];
			temp[i+k] = l & SC_LIMB_MASK;
			temp[i+k+1] = l >> SC_LIMB_BITS;
			add(&out[i+k], &temp[i+k], &out[i+k], (n * 2) - (i + k));

			ec_zero(temp, n * 2);
		}
	}
#endif
}

static void point_double_affine(ecc_metadata_t *metadata, ecc_point_t *point)
{
	size_t n;
	sc_ulimb_t *lambda, *temp, *x, *y;
	const sc_ulimb_t *m, *a, *mu, *order;
	lambda = metadata->lambda;
	temp   = metadata->temp;
	x      = metadata->x;
	y      = metadata->y;
	m      = metadata->m;
	mu     = metadata->mu;
	order  = metadata->order;
	a      = metadata->a;
	n      = metadata->n;

	// lambda = (3*x^2 + a)/(2*y)
	ec_mul(temp, point->x, point->x, n);
	ec_field_mod_secp256r1(lambda, temp, n, m, mu);
	ec_zero(x, n);
	x[0] = 3;
	ec_mul(temp, lambda, x, n);
	ec_field_mod_secp256r1(lambda, temp, n, m, mu);
	ec_field_add(lambda, lambda, a, n, mu);
	ec_field_add(temp, point->y, point->y, n, mu);
	ec_field_inv(y, temp, n, m, mu);
	ec_mul(temp, lambda, y, n);
	ec_field_mod_secp256r1(lambda, temp, n, m, mu);

	// xr = lambda^2 - 2*xp
	ec_mul(temp, lambda, lambda, n);
	ec_field_mod_secp256r1(x, temp, n, m, mu);
	ec_field_sub(temp, x, point->x, n, m);
	ec_field_sub(x, temp, point->x, n, m);

	// yr = lambda*(xp - xr) - yp
	ec_field_sub(y, point->x, x, n, m);
	ec_mul(temp, lambda, y, n);
    ec_field_mod_secp256r1(y, temp, n, m, mu);
	ec_field_sub(point->y, y, point->y, n, m);

    // Overwrite the input point X coordinate with it's new value
    ec_copy(point->x, x, n);
}

static void point_add_affine(ecc_metadata_t *metadata, ecc_point_t *p_a, const ecc_point_t *p_b)
{
	size_t n;
	sc_ulimb_t *lambda, *temp, *x, *y;
	const sc_ulimb_t *m, *mu;
	lambda = metadata->lambda;
	temp   = metadata->temp;
	x      = metadata->x;
	y      = metadata->y;
	m      = metadata->m;
	mu     = metadata->mu;
	n      = metadata->n;

	// lambda = (yb - ya) / (xb - xa)
	ec_field_sub(y, p_b->y, p_a->y, n, m);
	ec_field_sub(x, p_b->x, p_a->x, n, m);
	ec_field_inv(lambda, x, n, m, mu);
	ec_mul(temp, lambda, y, n);
	ec_field_mod_secp256r1(lambda, temp, n, m, mu);

	// xr = lambda^2 - xp - xq
	ec_mul(temp, lambda, lambda, n);
	ec_field_mod_secp256r1(x, temp, n, m, mu);
    ec_field_sub(x, x, p_a->x, n, m);
    ec_field_sub(p_a->x, x, p_b->x, n, m);

	// yr = lambda*(xp - xq) - a
    ec_field_sub(y, p_b->x, p_a->x, n, m);
	ec_mul(temp, lambda, y, n);
	ec_field_mod_secp256r1(y, temp, n, m, mu);
    ec_field_sub(p_a->y, y, p_b->y, n, m);
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


static void scalar_point_mult(size_t num_bits, ecc_metadata_t *metadata,
	const ecc_point_t *p_in, const sc_ulimb_t *secret, ecc_point_t *p_out)
{
	size_t i;
	point_secret_t bit_ctx;
	ecc_point_t p_dummy;

	point_init(&p_dummy, metadata->k);
	point_reset(&p_dummy);
	point_reset(p_out);
	point_copy(p_out, p_in);

	/*fprintf(stderr, "in   x: "); sc_mpz_out_str(stderr, 16, &p_in->x); fprintf(stderr, "\n");
	fprintf(stderr, "     y: "); sc_mpz_out_str(stderr, 16, &p_in->y); fprintf(stderr, "\n");
	fprintf(stderr, "out  x: "); sc_mpz_out_str(stderr, 16, &p_out->x); fprintf(stderr, "\n");
	fprintf(stderr, "     y: "); sc_mpz_out_str(stderr, 16, &p_out->y); fprintf(stderr, "\n");
	fprintf(stderr, "secret: %016llX %016llX %016llX %016llX\n", secret[3], secret[2], secret[1], secret[0]);*/

	num_bits = secret_bits_init(ECC_K_BINARY, &bit_ctx, secret, num_bits);
	secret_bits_pull(&bit_ctx);
	num_bits--;

	for (i=num_bits; i--;) {
		UINT32 bit;

		// Point doubling
		point_double(metadata, p_out);

		// Determine if an asserted bit requires a point addition (or a dummy point addition as an SCA countermeasure)
		bit = secret_bits_pull(&bit_ctx);
		//fprintf(stderr, "index = %zu, bit = %d\n", i, bit);
		if (ECC_K_IS_LOW != bit) {
			// Create a mask of all zeros if ECC_K_IS_HIGH or all ones if an ECC_K_IS_SCA_DUMMY operation
			intptr_t temp   = (intptr_t) ((sc_ulimb_t)bit << (SC_LIMB_BITS - 1));
			intptr_t mask   = (bit ^ temp) - temp;

			// Branch-free pointer selection in constant time
			intptr_t p_temp = (intptr_t) p_out ^ (((intptr_t) p_out ^ (intptr_t) &p_dummy) & mask);
			//fprintf(stderr, "%zu %zu %zu\n", p_temp, (intptr_t) p_out, (intptr_t) &p_dummy);

			// Point addition
			point_add(metadata, (ecc_point_t *) p_temp, p_in);
		}
	}

	point_clear(&p_dummy);

	//fprintf(stderr, "result x: "); sc_mpz_out_str(stderr, 16, &p_out->x); fprintf(stderr, "\n");
	//fprintf(stderr, "       y: "); sc_mpz_out_str(stderr, 16, &p_out->y); fprintf(stderr, "\n");
}

SINT32 ecc_diffie_hellman(safecrypto_t *sc, const ecc_point_t *p_base, const sc_ulimb_t *secret, size_t *tlen, UINT8 **to)
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
	num_bits  = sc->ecdh->params->num_bits;
	num_bytes = sc->ecdh->params->num_bytes;
	num_limbs = sc->ecdh->params->num_limbs;

	// Initialise the MP variables
	metadata.k = num_limbs;
	metadata.n = num_limbs;
	metadata.a = sc->ecdh->params->a;
	metadata.m = sc->ecdh->params->p;
	metadata.mu = sc->ecdh->params->p_mu;
	metadata.order = sc->ecdh->params->order;
	point_init(&p_result, num_limbs);

	// Perform a scalar point multiplication from the base point using the random secret
	scalar_point_mult(num_bits, &metadata, p_base, secret, &p_result);

	// Translate the output point (coordinates are MP variables) to the output byte stream
	*to = SC_MALLOC(3*num_bytes);   // FIXME
	*tlen = 2 * num_bytes;

#if SC_LIMB_BITS == 64
	SC_BIG_ENDIAN_64_COPY(*to, 0, p_result.x, num_bytes);
	SC_BIG_ENDIAN_64_COPY(*to + num_bytes, 0, p_result.y + num_bytes, num_bytes);
#else
	SC_BIG_ENDIAN_32_COPY(*to, 0, p_result.x, num_bytes);
	SC_BIG_ENDIAN_32_COPY(*to + num_bytes, 0, p_result.y + num_bytes, num_bytes);
#endif

	return SC_FUNC_SUCCESS;
}

SINT32 ecc_diffie_hellman_encapsulate(safecrypto_t *sc, const sc_ulimb_t *secret,
	size_t *tlen, UINT8 **to)
{
	size_t num_bits  = sc->ecdh->params->num_bits;
	size_t num_bytes = sc->ecdh->params->num_bytes;

	// Use an ECC scalar point multiplication to geometrically transform the base point
	// to the intermediate point (i.e. the public key)
	ecc_diffie_hellman(sc, &sc->ecdh->base, secret, tlen, to);

	return SC_FUNC_SUCCESS;
}

SINT32 ecc_diffie_hellman_decapsulate(safecrypto_t *sc, const sc_ulimb_t *secret,
	size_t flen, const UINT8 *from, size_t *tlen, UINT8 **to)
{
	size_t num_bits  = sc->ecdh->params->num_bits;
	size_t num_bytes = sc->ecdh->params->num_bytes;
	size_t num_limbs = sc->ecdh->params->num_limbs;

	// Convert the input byte stream (public key) to the intermediate coordinate
	ecc_point_t p_base;
	p_base.n = num_limbs;

#if SC_LIMB_BITS == 64
	SC_BIG_ENDIAN_64_COPY(p_base.x, 0, from, num_bytes);
	SC_BIG_ENDIAN_64_COPY(p_base.y, 0, from + num_bytes, num_bytes);
#else
	SC_BIG_ENDIAN_32_COPY(p_base.x, 0, from, num_bytes);
	SC_BIG_ENDIAN_32_COPY(p_base.y, 0, from + num_bytes, num_bytes);
#endif

	// Use an ECC scalar point multiplication to geometrically transform the intermediate point
	// to the final point (shared secret)
	ecc_diffie_hellman(sc, &p_base, secret, tlen, to);

	return SC_FUNC_SUCCESS;
}

SINT32 ecc_sign(safecrypto_t *sc, const UINT8 *m, size_t mlen,
    UINT8 **sigret, size_t *siglen)
{
	return SC_FUNC_FAILURE;
}

SINT32 ecc_verify(safecrypto_t *sc, const UINT8 *m, size_t mlen,
    const UINT8 *sigbuf, size_t siglen)
{
	return SC_FUNC_FAILURE;
}
#else
#include "utils/arith/sc_mpz.h"
#include "utils/crypto/prng.h"


typedef struct ecc_metadata {
	sc_mpz_t lambda;
	sc_mpz_t temp;
	sc_mpz_t x;
	sc_mpz_t y;
	sc_mpz_t m;
	sc_mpz_t mu;
	sc_mpz_t order;
	sc_mpz_t a;
	size_t   k;
} ecc_metadata_t;

const ecdh_set_t param_ecdh_secp256r1 = {
	256,
	32,
	256 >> SC_LIMB_BITS_SHIFT,
	"-3",//"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
	"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
	"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
	"4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
	"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
	"100000000fffffffffffffffefffffffefffffffeffffffff0000000000000003",//"100000000FFFFFFFFFFFFFFFEFFFFFFFF43190552DF1A6C21012FFD85EEDF9BFE",
	"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
};

const ecdh_set_t param_ecdh_secp384r1 = {
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

const ecdh_set_t param_ecdh_secp521r1 = {
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

static SINT32 point_is_zero(const ecc_point_t *p)
{
	return sc_mpz_is_zero(&p->x) && sc_mpz_is_zero(&p->y);
}

static void point_double_affine(ecc_metadata_t *metadata, ecc_point_t *point)
{
	sc_mpz_t *lambda, *temp, *x, *y, *m, *a, *mu, *order;
	lambda = &metadata->lambda;
	temp   = &metadata->temp;
	x      = &metadata->x;
	y      = &metadata->y;
	m      = &metadata->m;
	mu     = &metadata->mu;
	order  = &metadata->order;
	a      = &metadata->a;

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

static void point_add_affine(ecc_metadata_t *metadata, ecc_point_t *p_a, const ecc_point_t *p_b, SINT32 sub)
{
	sc_mpz_t *lambda, *temp, *x, *y, *m;
	lambda = &metadata->lambda;
	temp   = &metadata->temp;
	x      = &metadata->x;
	y      = &metadata->y;
	m      = &metadata->m;

	if (sub) {
		sc_mpz_negate(&p_b->y, &p_b->y);
	}

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

	if (sub) {
		sc_mpz_negate(&p_b->y, &p_b->y);
	}
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
	point_add_affine(metadata, p_a, p_b, 0);
}

static void point_sub(ecc_metadata_t *metadata, ecc_point_t *p_a, const ecc_point_t *p_b)
{
	point_add_affine(metadata, p_a, p_b, 1);
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
		UINT32 bit;

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
	/*size_t w = 4;
	ecc_point_t *p_window = SC_MALLOC(sizeof(ecc_point_t) * (1 << w));
	point_init(&p_window[0], MAX_ECC_LIMBS);
	point_copy(&p_window[0], p_in);
	for (i=1; i<(1 << w); i++) {
		point_init(&p_window[i], MAX_ECC_LIMBS);
		point_copy(&p_window[i], &p_window[i-1]);
		point_add(metadata, &p_window[i], p_in);
	}*/

	num_bits = secret_bits_init(ECC_K_NAF_4, &bit_ctx, secret, num_bits);
	bit = secret_bits_pull(&bit_ctx);
	num_bits--;

	for (i=num_bits; i--;) {
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
			if (ECC_K_IS_MINUS_ONE == bit)
				point_sub(metadata, (ecc_point_t *) p_temp, p_in);
			else
				point_add(metadata, (ecc_point_t *) p_temp, p_in);
		}
	}

	point_clear(&p_dummy);

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
	//scalar_point_mult_binary(num_bits, metadata, p_in, secret, p_out);
	scalar_point_mult_naf(num_bits, metadata, p_in, secret, p_out);
}

SINT32 ecc_diffie_hellman(safecrypto_t *sc, const ecc_point_t *p_base, const sc_ulimb_t *secret, size_t *tlen, UINT8 **to)
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
	num_bits  = sc->ecdh->params->num_bits;
	num_bytes = sc->ecdh->params->num_bytes;
	num_limbs = sc->ecdh->params->num_limbs;

	// Initialise the MP variables
	metadata.k = num_limbs;
	sc_mpz_init2(&metadata.lambda, MAX_ECC_BITS);
	sc_mpz_init2(&metadata.x, MAX_ECC_BITS);
	sc_mpz_init2(&metadata.y, MAX_ECC_BITS);
	sc_mpz_init2(&metadata.temp, 2*MAX_ECC_BITS);
	sc_mpz_init2(&metadata.a, MAX_ECC_BITS);
	sc_mpz_init2(&metadata.m, MAX_ECC_BITS);
	sc_mpz_init2(&metadata.mu, MAX_ECC_BITS+1);
	sc_mpz_init2(&metadata.order, MAX_ECC_BITS);
	sc_mpz_init2(&p_result.x, MAX_ECC_BITS);
	sc_mpz_init2(&p_result.y, MAX_ECC_BITS);
	sc_mpz_set_str(&metadata.a, 16, sc->ecdh->params->a);
	sc_mpz_set_str(&metadata.m, 16, sc->ecdh->params->p);
	sc_mpz_set_str(&metadata.mu, 16, sc->ecdh->params->mu);
	sc_mpz_set_str(&metadata.order, 16, sc->ecdh->params->order);

	// Perform a scalar point multiplication from the base point using the random secret
	scalar_point_mult(num_bits, &metadata, p_base, secret, &p_result);

	// Translate the output point (coordinates are MP variables) to the output byte stream
	*to = SC_MALLOC(2*num_bytes);   // FIXME
	*tlen = 2 * num_bytes;
	sc_mpz_get_bytes(*to, &p_result.x);
	sc_mpz_get_bytes(*to + num_bytes, &p_result.y);

	// Free resources associated with the MP variables
	sc_mpz_clear(&metadata.lambda);
	sc_mpz_clear(&metadata.x);
	sc_mpz_clear(&metadata.y);
	sc_mpz_clear(&metadata.temp);
	sc_mpz_clear(&metadata.a);
	sc_mpz_clear(&metadata.m);
	sc_mpz_clear(&metadata.mu);
	sc_mpz_clear(&metadata.order);
	sc_mpz_clear(&p_result.x);
	sc_mpz_clear(&p_result.y);

	return SC_FUNC_SUCCESS;
}

SINT32 ecc_diffie_hellman_encapsulate(safecrypto_t *sc, const sc_ulimb_t *secret,
	size_t *tlen, UINT8 **to)
{
	// Use an ECC scalar point multiplication to geometrically transform the base point
	// to the intermediate point (i.e. the public key)
	ecc_diffie_hellman(sc, &sc->ecdh->base, secret, tlen, to);

	return SC_FUNC_SUCCESS;
}

SINT32 ecc_diffie_hellman_decapsulate(safecrypto_t *sc, const sc_ulimb_t *secret,
	size_t flen, const UINT8 *from, size_t *tlen, UINT8 **to)
{
	size_t num_bytes = sc->ecdh->params->num_bytes;
	size_t num_limbs = sc->ecdh->params->num_limbs;

	// Convert the input byte stream (public key) to the intermediate coordinate
	ecc_point_t p_base;
	p_base.n = num_limbs;
	sc_mpz_init2(&p_base.x, MAX_ECC_BITS);
	sc_mpz_init2(&p_base.y, MAX_ECC_BITS);
	sc_mpz_set_bytes(&p_base.x, from, num_bytes);
	sc_mpz_set_bytes(&p_base.y, from + num_bytes, num_bytes);

	// Use an ECC scalar point multiplication to geometrically transform the intermediate point
	// to the final point (shared secret)
	ecc_diffie_hellman(sc, &p_base, secret, tlen, to);

	sc_mpz_clear(&p_base.x);
	sc_mpz_clear(&p_base.y);

	return SC_FUNC_SUCCESS;
}

SINT32 ecc_sign(safecrypto_t *sc, const UINT8 *m, size_t mlen,
    UINT8 **sigret, size_t *siglen)
{
	size_t i, num_bits, num_bytes, num_limbs;
	ecc_point_t p_base, p_result;
	sc_ulimb_t secret[MAX_ECC_LIMBS];
	sc_mpz_t d, e, k, temp1, temp2, p, a;
	SINT32 mem_is_zero;
	ecc_metadata_t metadata;

	// Obtain common array lengths
	num_bits  = sc->ecdh->params->num_bits;
	num_bytes = sc->ecdh->params->num_bytes;
	num_limbs = sc->ecdh->params->num_limbs;

	p_base.n = (num_bits + SC_LIMB_BITS - 1) >> SC_LIMB_BITS_SHIFT;
	sc_mpz_set_str(&p_base.x, 16, sc->ecdh->params->g_x);
	sc_mpz_set_str(&p_base.y, 16, sc->ecdh->params->g_y);

	sc_mpz_init2(&metadata.a, MAX_ECC_BITS);
	sc_mpz_init2(&d, MAX_ECC_BITS);
	sc_mpz_init2(&e, MAX_ECC_BITS);
	sc_mpz_init2(&k, MAX_ECC_BITS);
	sc_mpz_init2(&temp1, 2*MAX_ECC_BITS);
	sc_mpz_init2(&temp2, MAX_ECC_BITS);
	sc_mpz_init2(&metadata.m, MAX_ECC_BITS);
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
	scalar_point_mult(num_bits, &metadata, &p_base, secret, &p_result);
	sc_mpz_mod(&p_result.x, &p_result.x, &p);
	if (sc_mpz_is_zero(&p_result.x)) {
		goto restart;
	}

	// s = k^(-1)*(z + r*d) mod n
	sc_mpz_mul(&temp1, &p_result.x, &d);
	sc_mpz_mod(&temp2, &temp1, &p);
	sc_mpz_add(&temp1, &temp2, &e);
	sc_mpz_mod(&temp1, &temp1, &p);
	sc_mpz_invmod(&temp2, &k, &p);
	sc_mpz_mul(&temp1, &temp2, &temp1);
	sc_mpz_mod(&temp2, &temp1, &p);
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

	sc_mpz_clear(&metadata.a);
	sc_mpz_clear(&d);
	sc_mpz_clear(&e);
	sc_mpz_clear(&k);
	sc_mpz_clear(&temp1);
	sc_mpz_clear(&temp2);
	sc_mpz_clear(&metadata.m);
}

SINT32 ecc_verify(safecrypto_t *sc, const UINT8 *m, size_t mlen,
    const UINT8 *sigbuf, size_t siglen)
{
	size_t i, num_bits, num_bytes, num_limbs;
	sc_mpz_t p, a, r, s, w, temp, z;
	sc_ulimb_t *secret;
	ecc_point_t p_base, p_public, p_u1, p_u2;
	ecc_metadata_t metadata;

	// Obtain common array lengths
	num_bits  = sc->ecdh->params->num_bits;
	num_bytes = sc->ecdh->params->num_bytes;
	num_limbs = sc->ecdh->params->num_limbs;

	sc_mpz_init2(&temp, 2*MAX_ECC_BITS);
	sc_mpz_init2(&metadata.a, MAX_ECC_BITS);
	sc_mpz_init2(&metadata.m, MAX_ECC_BITS);
	sc_mpz_init2(&w, MAX_ECC_BITS);
	sc_mpz_set_str(&metadata.m, 16, sc->ecdh->params->p);
	sc_mpz_set_str(&metadata.a, 16, sc->ecdh->params->a);

	sc_mpz_invmod(&w, &s, &p);

	p_base.n = sc->ecdh->params->num_limbs;
	sc_mpz_set_str(&p_base.x, 16, sc->ecdh->params->g_x);
	sc_mpz_set_str(&p_base.y, 16, sc->ecdh->params->g_y);

	sc_mpz_mul(&temp, &w, &z);
	sc_mpz_mod(&temp, &temp, &p);
	secret = sc_mpz_get_limbs(&temp);
	scalar_point_mult(num_bits, &metadata, &p_base, secret, &p_u1);

	sc_mpz_mul(&temp, &w, &r);
	sc_mpz_mod(&temp, &temp, m);
	secret = sc_mpz_get_limbs(&temp);
	scalar_point_mult(num_bits, &metadata, &p_public, secret, &p_u2);

	point_add(&metadata, &p_u1, &p_u2);

	sc_mpz_clear(&a);
	sc_mpz_clear(&p);
	sc_mpz_clear(&temp);

	if (0 == sc_mpz_cmp(&p_u1.x, &r)) {
		return SC_FUNC_SUCCESS;
	}
	else {
		return SC_FUNC_FAILURE;
	}
}

#endif



//
// end of file
//
