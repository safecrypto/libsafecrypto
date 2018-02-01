/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2017                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

/*
 * Git commit information:
 *   Author: $SC_AUTHOR$
 *   Date:   $SC_DATE$
 *   Branch: $SC_BRANCH$
 *   Id:     $SC_IDENT$
 */

#pragma once

#include "safecrypto_types.h"

#if defined(USE_SAFECRYPTO_INTEGER_MP) || defined(USE_SAFECRYPTO_FLOAT_MP)
#define USE_SAFECRYPTO_MULTIPLE_PRECISION
#endif


#include <limits.h>
#ifndef NATIVE_WORD_SIZE
#define NATIVE_WORD_SIZE   __WORDSIZE
#endif

#if !defined(USE_SAFECRYPTO_MULTIPLE_PRECISION)
#include <gmp.h>
#endif


// Depending on the system we're building on, GMP will utilise
// the machine wordlength, therefore we create a type used to store
// the GMP limbs
#if NATIVE_WORD_SIZE == 64

#define SC_LIMB_BITS       64
#define SC_LIMB_BITS2      32
#define SC_LIMB_BITS4      16
#define SC_LIMB_BITS_MASK  0x003F
#define SC_LIMB_BITS_SHIFT 6
#define SC_LIMB_HIGH(x)    ((x) >> 32)
#define SC_LIMB_LOW(x)     ((x) & 0xFFFFFFFF)
#define SC_LIMB_B2(x)      ((x) << 32)
#define SC_LIMB_B4(x)      ((x) << 16)
typedef UINT128 sc_ulimb_big_t;
typedef SINT128 sc_slimb_big_t;
typedef unsigned long sc_ulimb_t;
typedef signed long sc_slimb_t;
typedef UINT32 sc_ulimb_half_t;
typedef SINT32 sc_slimb_half_t;

#else

#define SC_LIMB_BITS       32
#define SC_LIMB_BITS2      16
#define SC_LIMB_BITS4      8
#define SC_LIMB_BITS_MASK  0x001F
#define SC_LIMB_BITS_SHIFT 5
#define SC_LIMB_HIGH(x)    ((x) >> 16)
#define SC_LIMB_LOW(x)     ((x) & 0xFFFF)
#define SC_LIMB_B2(x)      ((x) << 16)
#define SC_LIMB_B4(x)      ((x) << 8)
typedef UINT64 sc_ulimb_big_t;
typedef SINT64 sc_slimb_big_t;
typedef unsigned long sc_ulimb_t;
typedef signed long sc_slimb_t;
typedef UINT16 sc_ulimb_half_t;
typedef SINT16 sc_slimb_half_t;

#endif

#define SC_LIMB_MASK            (~(sc_ulimb_t)0)
#define SC_LIMB_MASK_LOW        (((sc_ulimb_t) 1 << SC_LIMB_BITS2) - 1)
#define SC_LIMB_SMIN            (LONG_MIN)
#define SC_LIMB_SMAX            (LONG_MAX)
#define SC_LIMB_UMIN            (0)
#define SC_LIMB_UMAX            (ULONG_MAX)
#define SC_LIMB_BYTES           (SC_LIMB_BITS >> 3)
#define SC_LIMB_WORD(x)         ((sc_ulimb_t)(x))
#define SC_LIMB_RSHIFT(x,bits)  (((bits) != SC_LIMB_BITS) * ((sc_ulimb_t)(x) >> (sc_ulimb_t)(bits)))
#define SC_LIMB_LSHIFT(x,bits)  (((bits) != SC_LIMB_BITS) * ((sc_ulimb_t)(x) << (sc_ulimb_t)(bits)))
#define SC_LIMB_HIGHBIT         ((sc_ulimb_t) 1 << (SC_LIMB_BITS - 1))
#define SC_LIMB_HIGHBIT2        ((sc_ulimb_t) 1 << (SC_LIMB_BITS2 - 1))
#define SC_LIMB_FROM_NEG(x)     (-((sc_ulimb_t)((x) + 1) - 1))
#define SC_LIMB_TO_NEG(x)       (-1 - (sc_slimb_t) (((x) - 1) & ~SC_LIMB_HIGHBIT))


typedef enum _round_mode_e {
    SC_ROUND_ZERO = 0,
    SC_ROUND_FLOOR,
    SC_ROUND_CEIL,
    SC_ROUND_TRUNC,
} round_mode_e;


#ifdef USE_SAFECRYPTO_MULTIPLE_PRECISION
/// A struct used to store a signed multiple-precision integer variable
typedef struct _sc_mpz_t
{
   SINT32 alloc;       ///< Number of limbs allocated
   SINT32 used;        ///< Number of limbs used, if negative it's a negative number
   sc_ulimb_t *limbs;  ///< Pointer to the limbs
} sc_mpz_t;
#else
typedef __mpz_struct sc_mpz_t;
#endif


#ifdef USE_SAFECRYPTO_INTEGER_MP

sc_ulimb_t * mpz_realloc(sc_mpz_t *inout, size_t size);
void mpz_init(sc_mpz_t *inout);
void mpz_init2(sc_mpz_t *inout, size_t bits);
void mpz_init_set_ui(sc_mpz_t *out, sc_ulimb_t in);
void mpz_clear(sc_mpz_t *inout);
size_t mpz_sizeinbase (const sc_mpz_t *in, SINT32 base);
void mpz_swap(sc_mpz_t *a, sc_mpz_t *b);
void mpz_set(sc_mpz_t *out, const sc_mpz_t *in);
void mpz_set_d(sc_mpz_t *out, DOUBLE in);
void mpz_set_ui(sc_mpz_t *out, sc_ulimb_t in);
void mpz_set_si(sc_mpz_t *out, sc_slimb_t in);
void mpz_abs(sc_mpz_t *out, const sc_mpz_t *in);
SINT32 mpz_tstbit(const sc_mpz_t *in, sc_ulimb_t bit_index);
void mpz_setbit(sc_mpz_t *inout, sc_ulimb_t bit_index);
DOUBLE mpz_get_d(const sc_mpz_t *in);
sc_ulimb_t mpz_get_ui(const sc_mpz_t *in);
sc_ulimb_t* mpz_get_limbs(const sc_mpz_t *in);
sc_slimb_t mpz_get_si(const sc_mpz_t *in);

SINT32 mpz_cmpabs_d(const sc_mpz_t *in1, DOUBLE in2);
SINT32 mpz_cmpabs_ui(const sc_mpz_t *in1, sc_ulimb_t in2);
SINT32 mpz_cmpabs(const sc_mpz_t *in1, const sc_mpz_t *in2);
SINT32 mpz_cmp_d(const sc_mpz_t *in1, DOUBLE in2);
SINT32 mpz_cmp_ui(const sc_mpz_t *in1, sc_ulimb_t in2);
SINT32 mpz_cmp_si(const sc_mpz_t *in1, sc_slimb_t in2);
SINT32 mpz_cmp(const sc_mpz_t *in1, const sc_mpz_t *in2);
void mpz_gcd(sc_mpz_t *g, const sc_mpz_t *u, const sc_mpz_t *v);
void mpz_gcdext(sc_mpz_t *out, sc_mpz_t *s, sc_mpz_t *t, const sc_mpz_t *u, const sc_mpz_t *v);
SINT32 mpz_sgn(const sc_mpz_t *in);
SINT32 mpz_fits_slong_p(const sc_mpz_t *in);
void mpz_neg(sc_mpz_t *out, const sc_mpz_t *in);
SINT32 mpz_invert(sc_mpz_t *out, const sc_mpz_t *in, const sc_mpz_t *mod);

void mpz_add(sc_mpz_t *out, const sc_mpz_t *in1, const sc_mpz_t *in2);
void mpz_sub(sc_mpz_t *out, const sc_mpz_t *in1, const sc_mpz_t *in2);
void mpz_add_ui(sc_mpz_t *out, const sc_mpz_t *in1, sc_ulimb_t in2);
void mpz_sub_ui(sc_mpz_t *out, const sc_mpz_t *in1, sc_ulimb_t in2);

sc_ulimb_t mpz_tdiv_qr(sc_mpz_t *q, sc_mpz_t *r,
    const sc_mpz_t *n, const sc_mpz_t *d);
sc_ulimb_t mpz_tdiv_q(sc_mpz_t *q,
    const sc_mpz_t *n, const sc_mpz_t *d);
sc_ulimb_t mpz_tdiv_r(sc_mpz_t *r,
    const sc_mpz_t *n, const sc_mpz_t *d);
sc_ulimb_t mpz_fdiv_qr(sc_mpz_t *q, sc_mpz_t *r,
    const sc_mpz_t *n, const sc_mpz_t *d);
sc_ulimb_t mpz_fdiv_q(sc_mpz_t *q,
    const sc_mpz_t *n, const sc_mpz_t *d);
sc_ulimb_t mpz_fdiv_r(sc_mpz_t *r,
    const sc_mpz_t *n, const sc_mpz_t *d);
sc_ulimb_t mpz_fdiv_qr_ui(sc_mpz_t *q, sc_mpz_t *r,
    const sc_mpz_t *n, sc_ulimb_t d);
sc_ulimb_t mpz_fdiv_q_ui(sc_mpz_t *q,
    const sc_mpz_t *n, sc_ulimb_t d);
sc_ulimb_t mpz_fdiv_r_ui(sc_mpz_t *r, const sc_mpz_t *in, sc_ulimb_t d);
sc_ulimb_t mpz_tdiv_q_2exp(sc_mpz_t *q,
    const sc_mpz_t *n, sc_ulimb_t b);
sc_ulimb_t mpz_cdiv_ui (const sc_mpz_t *n, sc_ulimb_t d);
sc_ulimb_t mpz_fdiv_ui (const sc_mpz_t *n, sc_ulimb_t d);
sc_ulimb_t mpz_tdiv_ui(const sc_mpz_t *n, sc_ulimb_t d);
void mpz_divexact(sc_mpz_t *q, const sc_mpz_t *n, const sc_mpz_t *d);
void mpz_divexact_ui(sc_mpz_t *q, const sc_mpz_t *n, sc_ulimb_t d);

void mpz_addmul_ui(sc_mpz_t *out, const sc_mpz_t *in1, sc_ulimb_t in2);
void mpz_submul_ui(sc_mpz_t *out, const sc_mpz_t *in1, sc_ulimb_t in2);
void mpz_addmul(sc_mpz_t *out, const sc_mpz_t *in1, const sc_mpz_t *in2);
void mpz_submul(sc_mpz_t *out, const sc_mpz_t *in1, const sc_mpz_t *in2);
void mpz_mul_ui(sc_mpz_t *out, const sc_mpz_t *in1, sc_ulimb_t in2);
void mpz_mul_si(sc_mpz_t *out, const sc_mpz_t *in1, sc_slimb_t in2);
void mpz_mul_2exp(sc_mpz_t *out, const sc_mpz_t *in, size_t bits);
void mpz_mul(sc_mpz_t *out, const sc_mpz_t *in1, const sc_mpz_t *in2);

void mpz_pow_ui(sc_mpz_t *r, const sc_mpz_t *b, sc_ulimb_t e);
void mpz_sqrt(sc_mpz_t *out, const sc_mpz_t *in);
sc_ulimb_t mpz_mod_ui(sc_mpz_t *out, const sc_mpz_t *in, sc_ulimb_t m);
void mpz_mod(sc_mpz_t *r, const sc_mpz_t *n, const sc_mpz_t *d);

size_t mpz_out_str(FILE *stream, int base, const sc_mpz_t *in);
SINT32 mpz_set_str(sc_mpz_t *out, const char *str, SINT32 base);

#endif
