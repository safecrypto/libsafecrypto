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

#include "utils/arith/sc_mpf.h"
#include "utils/arith/sc_mpn.h"
#include "utils/arith/sc_math.h"
#include "utils/arith/sc_math.h"
#include "utils/arith/poly_limb.h"
#include "safecrypto_private.h"
#include "safecrypto_debug.h"

#include <math.h>


#ifdef USE_SAFECRYPTO_FLOAT_MP

#define SC_MPF_EXP_ZERO        (SC_LIMB_SMIN + 1)
#define SC_MPF_EXP_NAN         (SC_LIMB_SMIN + 2)
#define SC_MPF_EXP_INF         (SC_LIMB_SMIN + 3)
#define SC_MPF_IS_SINGULAR(x)  (x->exponent <= SC_MPF_EXP_INF)

static size_t g_mpf_precision = SC_MPF_DEFAULT_PRECISION;

#else
#define MPFR_DEFAULT_ROUNDING  MPFR_RNDZ
#endif


static SINT32 sc_mpf_negative_mod_limb(const sc_mpf_t *inout, SINT32 x)
{
	// Calculate (-x) mod SC_LIMB_BITS
	SINT32 pos_mod;
	if (x & (x - 1)) {
		pos_mod = x & SC_LIMB_BITS_MASK;
		if (pos_mod) {
			pos_mod = SC_LIMB_BITS - pos_mod;
		}
	}
	else {
		pos_mod = (-(sc_ulimb_t)x) & SC_LIMB_BITS_MASK;
	}
	return pos_mod;
}

SINT32 sc_mpf_set_precision(size_t precision)
{
	/*if (precision < SC_LIMB_BITS) {
		return SC_FUNC_FAILURE;
	}*/
#ifdef USE_SAFECRYPTO_FLOAT_MP
	g_mpf_precision = precision;
#else
	mpfr_set_default_prec(precision);
#endif

	return SC_FUNC_SUCCESS;
}

size_t sc_mpf_get_precision(void)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	return g_mpf_precision;
#else
	return mpfr_get_default_prec();
#endif
}

static void sc_mpf_init2(sc_mpf_t *inout, size_t precision)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	// Initialise to the default precision and set to NaN
	size_t num_limbs = 1 + (precision - 1) / SC_LIMB_BITS;
    inout->sign      = 0;
    inout->precision = precision;
    inout->alloc     = num_limbs;
    inout->mantissa  = SC_MALLOC(num_limbs * SC_LIMB_BYTES);
    inout->exponent  = SC_MPF_EXP_NAN;
#else
	mpfr_init2(inout, precision);
#endif
}

void sc_mpf_init(sc_mpf_t *inout)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	sc_mpf_init2(inout, g_mpf_precision);
#else
	mpfr_init(inout);
#endif
}

void sc_mpf_clear(sc_mpf_t *inout)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	size_t num_limbs = 1 + (inout->precision - 1) / SC_LIMB_BITS;
	SC_FREE(inout->mantissa, num_limbs * SC_LIMB_BYTES);
#else
	mpfr_clear(inout);
#endif
}

void sc_mpf_get_pi(sc_mpf_t *out)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	sc_mpf_t *retval;
	mpfr_const_pi(out, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_clear_constants(void)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	mpfr_free_cache();
#endif
}

#ifdef USE_SAFECRYPTO_FLOAT_MP
static void sc_mpf_set_with_negate(sc_mpf_t *out, const sc_mpf_t *in, SINT32 negate)
{
	out->sign     = (negate)? (0 == in->sign)? 0 : -in->sign : in->sign;
	out->exponent = in->exponent;
	if (SC_MPF_IS_SINGULAR(in)) {
		// Only the exponent and sign are relevant
		return;
	}
	else if (in->precision == out->precision) {
		// Duplicate the mantissa if the precision is identical
		mpn_copy(out->mantissa, in->mantissa, in->alloc);
		return;
	}
	else if (in->precision < out->precision) {
		// Duplicate the mantissa if the input precision is smaller,
		// then zero the unused output limbs
		/// @todo Merge with above?
		mpn_copy(out->mantissa, in->mantissa, in->alloc);
		mpn_zero(out->mantissa, out->alloc - in->alloc);
	}
	else {
		SINT32 shift;
		size_t offset;
		sc_ulimb_t *mantissa, guard, rounding, sticky, mask;

		// Determine how many bits shifting are required
		shift = out->precision & SC_LIMB_BITS_MASK;
		if (shift) {
			shift = SC_LIMB_BITS - shift;
		}

		// Determine a pointer to the least significant limb of the input mantissa
		mantissa = in->mantissa + in->alloc - out->alloc;

		// Calculate the rounding parameters
		if (shift) {
			mask   = (sc_ulimb_t)1 << (shift - 1);
			offset = 1;
			guard  = mask << 1;
		}
		else {
			mask   = SC_LIMB_HIGHBIT;
			offset = 0;
			guard  = (sc_ulimb_t) 1;
		}

		rounding = mantissa[-1+offset] & mask;
		sticky   = mantissa[-1+offset] & (mask - 1);
		if (0 == sticky && 0 == rounding) {
			// Search towards the least significant word for sticky bits
			sc_ulimb_t *l;
			size_t i;
			for (l=mantissa-2+offset, i=in->alloc - out->alloc - 1; i!=0 && 0==sticky; i--) {
				sticky = *l--;
			}
		}

		// Perform the rounding towards zero
		mpn_copy(out->mantissa, in->mantissa + offset, out->alloc);
		out->mantissa[0] &= ~(guard - 1);
	}
}
#endif

void sc_mpf_set(sc_mpf_t *out, const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	sc_mpf_set_with_negate(out, in, 0);
#else
	(void)mpfr_set(out, in, MPFR_DEFAULT_ROUNDING);
#endif
}

size_t sc_mpf_out_str(FILE *stream, SINT32 base, size_t digits, const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
    return mpfr_out_str(stream, base, digits, in, MPFR_DEFAULT_ROUNDING);
#endif
}

#ifdef USE_SAFECRYPTO_FLOAT_MP
// Determine if |in| is a power of 2
static SINT32 abs_power_of_2(const sc_mpf_t *in)
{
	SINT32 n = in->alloc;
	if (in->mantissa[--n] != SC_LIMB_HIGHBIT) {
		return 0;
	}
	while (n) {
    	if (in->mantissa[--n]) {
		    return 0;
    	}
    }
	return 1;
}

// Round 
static void iround(sc_mpf_t *out, const sc_mpf_t *in)
{
	size_t n_words;
	SINT32 n_bits, flags = 0, shift;

	// Deal with a singluar input
	if (SC_MPF_IS_SINGULAR(in)) {
		if (SC_MPF_EXP_NAN == in->exponent) {
			out->exponent = SC_MPF_EXP_NAN;
			return;
		}

		// Ensure that a signed zero and INF is accounted for
		out->sign     = in->sign;
		out->exponent = in->exponent;
		return;
	}

	out->sign = in->sign;

	// Check for 0 < |in| < 1, 
	if (in->exponent <= 0) {
		// We always round towards zero so we always output 0 if the absolute
		// exponent is less than 1
		out->sign     = 0;
		out->exponent = SC_MPF_EXP_ZERO;
		return;
	}

	// Otherwise, the exponent is greater than or equal to 1
	out->exponent = in->exponent;

	// Determine how many bits shifting are required
	shift = out->precision & SC_LIMB_BITS_MASK;
	if (shift) {
		shift = SC_LIMB_BITS - shift;
	}

	// Determine if |in| can be represented by the mantissa without truncation
	n_words = in->alloc;
	n_bits  = 0;
	if (((in->exponent - 1) >> SC_LIMB_BITS_SHIFT) < in->alloc) {
		size_t lsw;
		n_words = ((in->exponent - 1) >> SC_LIMB_BITS_SHIFT) + 1;
		lsw     = in->alloc - n_words;
		n_bits  = in->exponent & SC_LIMB_BITS_MASK;

		// Set flags to 1 if any of the LSBs are asserted
		flags = 1;
		if ((0 == n_bits || 0 == (in->mantissa[lsw] << n_bits))) {
			flags = 0;
			while (lsw) {
				if (in->mantissa[--lsw]) {
					flags = 1;
					break;
				}
			}
		}
	}

	// If the number of words required to represent 'in' is larger than that allocated to 'out'
	// we simply output 'in' to the designated precision
	if (n_words > out->alloc) {
		// Copy the 'in' mantissa to 'out'
		mpn_copy(out->mantissa, in->mantissa + in->alloc - out->alloc, out->alloc * SC_LIMB_BYTES);

		// If none of the LSBs are asserted
		if (0 == flags) {
			// Check the least significant limb of the output mantissa which must be left shifted by 'shift'
			// to ensure no data is being lost
			if (shift && (out->mantissa[0] << shift)) {
				flags = 2;
			}
			else {
				// Check those limbs of 'in' that are not used in 'out' to determine if they would be lost
				size_t i;
				for (i=n_words - out->alloc - 1; i>=0; i--) {
					if (in->mantissa[i]) {
						flags = 2;
						break;
					}
				}
			}
		}

		if (shift) {
			out->mantissa[0] &= SC_LIMB_MASK << shift;
		}
	}
	else {
		// Otherwise rounding is required when the input mantissa is smaller
		SINT32 frac_bits;
		size_t i_words, o_words;
		i_words = in->alloc - n_words;
		o_words = out->alloc - n_words;

		// Copy the input mantissa limbs to the output
		mpn_copy(out->mantissa + o_words, in->mantissa + i_words, n_words);

		// Determine the number of fractional bits in the least significant limb of 'out'
		frac_bits = (0 == n_bits)? 0 : SC_LIMB_BITS - n_bits;
		if (0 == o_words && frac_bits < shift) {
			// Check if the bits netween shift and frac_bits are non-zero, i.e. not representable
			if (0 == flags && (out->mantissa[o_words] & (((sc_ulimb_t)1 << shift) - ((sc_ulimb_t)1 << frac_bits)))) {
				flags = 2;
			}
		}
		else {
			shift = frac_bits;
		}

		// Clear the least significant words and bits of 'out' are set to zero
		mpn_zero(out->mantissa, o_words);
		if (shift) {
			out->mantissa[o_words] &= SC_LIMB_MASK << shift;
		}
	}

	return;
}
#endif

sc_ulimb_t sc_mpf_get_ui(const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	if (SC_MPF_EXP_ZERO == in->exponent) {
		return 0;
	}
	else if (!sc_mpf_fits_ulimb(in)) {
		return (SC_MPF_EXP_NAN == in->exponent || (in->sign < 0))? 0 : SC_LIMB_UMAX;
	}
	else {
		sc_mpf_t temp;
		sc_ulimb_t retval;

		sc_mpf_init2(&temp, SC_LIMB_BITS);
		iround(&temp, in);
		if (SC_MPF_EXP_ZERO == temp.exponent) {
			retval = 0;
		}
		else {
			retval = temp.mantissa[temp.alloc-1] >> (SC_LIMB_BITS - temp.exponent);
		}
		sc_mpf_clear(&temp);

		return retval;
	}
#else
    return mpfr_get_ui(in, MPFR_DEFAULT_ROUNDING);
#endif
}

sc_slimb_t sc_mpf_get_si(const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	if (SC_MPF_EXP_ZERO == in->exponent) {
		return 0;
	}
	else if (!sc_mpf_fits_slimb(in)) {
		return (SC_MPF_EXP_NAN == in->exponent || in->sign < 0)? SC_LIMB_SMIN : SC_LIMB_SMAX;
	}
	else {
		sc_mpf_t temp;
		sc_ulimb_t retval;

		sc_mpf_init2(&temp, SC_LIMB_BITS);
		iround(&temp, in);
		if (SC_MPF_EXP_ZERO == temp.exponent) {
			retval = 0;
		}
		else {
			retval = temp.mantissa[temp.alloc-1] >> (SC_LIMB_BITS - temp.exponent);
			retval = (in->sign < 0)? (retval <= SC_LIMB_SMAX)? -(sc_slimb_t)retval : SC_LIMB_SMIN : retval;
		}
		sc_mpf_clear(&temp);

		return retval;
	}
#else
    return mpfr_get_si(in, MPFR_DEFAULT_ROUNDING);
#endif
}

DOUBLE sc_mpf_get_d(const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
    return mpfr_get_d(in, MPFR_DEFAULT_ROUNDING);
#endif
}

sc_ulimb_t * sc_mpf_get_limbs(const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
    return in->mantissa;
#else
    __mpfr_struct *f = (__mpfr_struct *) in;
    return f->_mpfr_d;
#endif
}

sc_slimb_t sc_mpf_get_exp(const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	return mpfr_get_exp(in);
#endif
}

void sc_mpf_set_ui(sc_mpf_t *inout, sc_ulimb_t value)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	if (0 == value) {
		inout->exponent = SC_MPF_EXP_ZERO;
		inout->sign     = 0;
	}
	else {
		// Set the most significant limb of the mantissa to the normalised integer,
		// zeroing all low significance limbs. Set the exponent to SC_LIMB_BITS minus
		// the normalisation bits.
		// Therefore the float is represented as: (-1)^s . c . b^q
		// Where b is the base (2), q is the exponent, c is the mantissa and s the sign bit
		// such that 32 with 32-bit limbs would be encoded as s=0, c=0x80000000, q=5.
		SINT32 clz;
		clz             = limb_clz(value);
		inout->mantissa[inout->alloc - 1] = value << clz;
		mpn_zero(inout->mantissa, inout->alloc - 1);
		inout->exponent = SC_LIMB_BITS - clz;
		inout->sign     = 1;
	}
#else
	mpfr_set_ui(inout, value, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_set_si(sc_mpf_t *inout, sc_slimb_t value)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	if (0 == value) {
		inout->exponent = SC_MPF_EXP_ZERO;
		inout->sign     = 0;
	}
	else {
		// Set the most significant limb of the mantissa to the normalised integer,
		// zeroing all low significance limbs. Set the exponent to SC_LIMB_BITS minus
		// the normalisation bits.
		// i.e. -32 with 32-bit limbs would be encoded as s=1, c=0x80000000, q=5.
		SINT32 clz;
		sc_ulimb_t abs_value;
		abs_value       = (value >= 0)? value : -(sc_ulimb_t) value;
		clz             = limb_clz(abs_value);
		inout->mantissa[inout->alloc - 1] = abs_value << clz;
		mpn_zero(inout->mantissa, inout->alloc - 1);
		inout->exponent = SC_LIMB_BITS - clz;
		inout->sign     = (value < 0)? -1 : 1;
	}
#else
	mpfr_set_si(inout, value, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_set_d(sc_mpf_t *inout, DOUBLE value)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	mpfr_set_d(inout, value, MPFR_DEFAULT_ROUNDING);
#endif
}

SINT32 sc_mpf_cmp(const sc_mpf_t *a, const sc_mpf_t *b)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	SINT32 na, nb;

	// Deal with singluar inputs
	if (SC_MPF_IS_SINGULAR(a) || SC_MPF_IS_SINGULAR(b)) {
		if (SC_MPF_EXP_NAN == a->exponent || SC_MPF_EXP_NAN == b->exponent) {
			return 0;  // If a or b is NaN then result is 0
		}
		else if (SC_MPF_EXP_INF == a->exponent) {
			// Return 0 if both infinite and same sign, otherwise a->sign is
			// the comparison result
			if (SC_MPF_EXP_INF == b->exponent) {
				return (a->sign == b->sign)? 0 : a->sign;
			}
			// If only a is infinite then simply return it's sign as the result
			return a->sign;
		}
		else if (SC_MPF_EXP_INF == b->exponent) {
			// Return the inverted sign of b if only it is infinite (it is on RHS of comparison)
			return -b->sign;
		}
		else if (SC_MPF_EXP_ZERO == a->exponent) {
			return (SC_MPF_EXP_ZERO == b->exponent)? 0 : -b->sign;
		}
		else {
			return a->sign;
		}
	}

	// Not singular and the signs are different
	if (a->sign != b->sign) {
		return a->sign;
	}

	// Check the exponents to quickly compare the magnitude (both signs are identical)
	if (a->exponent > b->exponent) {
		return a->sign; // e.g. a=-2^10, b=-2^9 => a<b = sign(a), a=2^10, b=2^9 => a>b = sign(a)
	}
	else if (a->exponent < b->exponent) {
		return -a->sign; // e.g. a=-2^9, b=-2^10 => a>b = -sign(a), a=2^9, b=2^10 => a<b = -sign(a), 
	}

	// All is equal except the mantissa so iteratively compare them until one or both
	// are exhausted of limbs
	na = a->alloc - 1;
	nb = b->alloc - 1;
	for (; na>=0, nb>=0; na--, nb--) {
		if (a->mantissa[na] != b->mantissa[nb]) {
			return (a->mantissa[na] > b->mantissa[nb])? a->sign : -a->sign;
		}
	}

	// na and/or nb are now negative so iterate over them until a non-zero limb is discovered
	for (; na>=0; na--) {
		if (a->mantissa[na]) {
			return a->sign;
		}
	}
	for (; nb>=0; nb--) {
		if (b->mantissa[nb]) {
			return -b->sign;
		}
	}

	// If the sign, exponent and mantissa are equal then both values are identical
	return 0;
#else
	return mpfr_cmp(a, b);
#endif
}

SINT32 sc_mpf_cmp_d(const sc_mpf_t *a, DOUBLE b)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	return mpfr_cmp_d(a, b);
#endif
}

SINT32 sc_mpf_cmp_ui(const sc_mpf_t *a, sc_ulimb_t b)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	SINT32 na, nb;
	SINT32 i;
	SINT32 bits;

	// Deal with singluar inputs - ZERO, INF and NaN
	if (SC_MPF_IS_SINGULAR(a)) {
		if (SC_MPF_EXP_NAN == a->exponent) {
			// If a is NaN then result is 0
			return 0;
		}
		else if (SC_MPF_EXP_INF == a->exponent) {
			// If a is infinite then simply return it's sign as the result
			return a->sign;
		}
		else {
			// If a is zero then a<=b as b is unsigned
			return (b)? -1 : 0;
		}
	}

	// As b is unsigned then negative a will always be smaller
	if (a->sign < 0) {
		return -1;
	}

	// If a>0 (non-singular and sign is NOT negative) then quickly check if b is zero
	if (0 == b) {
		return 1;
	}

	// At this stage both the MP float and the unisgned integer are greater than 0, so
	// if the exponent is negative then the 'a' is less than 1, so b must be larger
	if (a->exponent < 0) {
		return -1;
	}

	// If the exponent is larger than SC_LIMB_BITS then b is smaller
	if (a->exponent > SC_LIMB_BITS) {
		return 1;
	}

	// If the bitsize of b is smaller/larger than the exponent then a is correspondingly larger/smaller
	bits = limb_clz(b);
	if ((SC_LIMB_BITS - bits) < a->exponent) {
		return 1;
	}
	if ((SC_LIMB_BITS - bits) > a->exponent) {
		return -1;
	}

	// At this stage both numbers are greater than zero with the same exponent, so 'b' is
	// normalised to the MSB and directly compared to the most significant limb of the mantissa
	b <<= bits;
	if (b < a->mantissa[a->alloc-1]) {
		return 1;
	}
	if (b > a->mantissa[a->alloc-1]) {
		return -1;
	}

	// The lower order limbs of a's mantissa must now be compared to determine if it is larger than b
	for (i=a->alloc-2; i>=0; i--) {
		if (a->mantissa[i]) {
			return 1;
		}
	}

	// The values are identical
	return 0;
#else
	return mpfr_cmp_ui(a, b);
#endif
}

SINT32 sc_mpf_cmp_si(const sc_mpf_t *a, sc_slimb_t b)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	return mpfr_cmp_si(a, b);
#endif
}

SINT32 sc_mpf_fits_slimb(const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	sc_ulimb_t abs_max;
	SINT32 bits;

	if (SC_MPF_IS_SINGULAR(in)) {
		return in->exponent == SC_MPF_EXP_ZERO;
	}
	else if (in->exponent < 1) {
		return 1;
	}
	
	abs_max = (in->sign >= 0)? SC_LIMB_SMAX : -(sc_ulimb_t)SC_LIMB_SMIN;
	bits    = SC_LIMB_BITS - limb_clz(abs_max);

	if (in->exponent <= (bits - 1)) {
		return 1;
	}
	else if (in->exponent >= (bits + 1)) {
		return 0;
	}

	// Check with rounding if the exponent is equal to SC_LIMB_BITS - 1
	SINT32 retval;
	sc_mpf_t temp;
	sc_mpf_init2(&temp, SC_LIMB_BITS-1);
	sc_mpf_set(&temp, in);
	retval = temp.exponent == in->exponent;
	sc_mpf_clear(&temp);
	return retval;
#else
	return mpfr_fits_slong_p(in, MPFR_DEFAULT_ROUNDING);
#endif
}

SINT32 sc_mpf_fits_ulimb(const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	if (SC_MPF_IS_SINGULAR(in)) {
		return in->exponent == SC_MPF_EXP_ZERO;
	}
	else if (in->sign < 0) {
		return 0;
	}
	else if (in->exponent <= (SC_LIMB_BITS - 1)) {
		return 1;
	}
	else if (in->exponent >= (SC_LIMB_BITS + 1)) {
		return 0;
	}

	// Check with rounding if the exponent is equal to SC_LIMB_BITS
	SINT32 retval;
	sc_mpf_t temp;
	sc_mpf_init2(&temp, SC_LIMB_BITS);
	sc_mpf_set(&temp, in);
	retval = temp.exponent == in->exponent;
	sc_mpf_clear(&temp);
	return retval;
#else
	return mpfr_fits_ulong_p(in, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_abs(sc_mpf_t *out, const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	sc_mpf_set_with_negate(out, in, (in->sign < 0)? 1 : 0);
#else
	mpfr_abs(out, in, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_negate(sc_mpf_t *out, const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	if (out == in) {
		out->sign = (0 == out->sign)? 0 : -out->sign;
	}
	else {
		sc_mpf_set_with_negate(out, in, 1);
	}
#else
	mpfr_neg(out, in, MPFR_DEFAULT_ROUNDING);
#endif
}

SINT32 sc_mpf_is_zero(const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	return SC_MPF_EXP_ZERO == in->exponent;
#else
	return mpfr_zero_p(in);
#endif
}

SINT32 sc_mpf_is_nan(const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	return SC_MPF_EXP_NAN == in->exponent;
#else
	return mpfr_nan_p(in);
#endif
}

SINT32 sc_mpf_is_inf(const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	return SC_MPF_EXP_INF == in->exponent;
#else
	return mpfr_inf_p(in);
#endif
}

SINT32 sc_mpf_is_neg(const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	return in->sign < 0;
#else
	return mpfr_signbit(in);
#endif
}

SINT32 sc_mpf_sign(const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	return in->sign;
#else
	return mpfr_sgn(in);
#endif
}

#ifdef USE_SAFECRYPTO_FLOAT_MP

static void sc_mpf_add_normal(sc_mpf_t *out, const sc_mpf_t *in1, const sc_mpf_t *in2)
{
	// There are no special cases to be considered here, addition must be performed with
	// two non-zero real numbers, i.e. out = sign(in1) * (|in1| + |in2|)

	SINT32 negative_flag, lsb_sh, dist, exponent;

	// Ensure that the exponent of in1 is greater than or equal to in2's exponent
	if (in1->exponent < in2->exponent) {
		return sc_mpf_add_normal(out, in2, in1);
	}

	// Determine how many bits of the least significant input are not contained in a whole limb
	lsb_sh        = sc_mpf_negative_mod_limb(in1, in1->precision);

	// Determine how much larger the exponent of in1 is than in2
	dist          = in1->exponent - in2->exponent;

	// Maintain a variable for the output exponent
	exponent      = in1->exponent;

	// Record if the inputs are both negative or both positive
	negative_flag = in1->sign < 0;

	// The output sign is equivalent to in1 or in2's sign (they are both gauranteed to be the same sign)
	out->sign     = in1->sign;

	if (dist >= in1->precision) {
		// in1 is much larger than in2 and addition with rounding towards zero is simply a copy
		mpn_copy(out->mantissa, in1->mantissa, in1->alloc);
		out->exponent = exponent;
	}
	else if (0 == dist) {
		// mpn_add_n of the two mantissa's will always produce a carry bit due to normalisation.
		// We ignore the returned carry bit, right shift by 1 and assert the MSB of the most significant limb.
		mpn_add_n(out->mantissa, in1->mantissa, in2->mantissa, in1->alloc);
		mpn_rshift(out->mantissa, out->mantissa, in1->alloc, 1);
		out->mantissa[in1->alloc - 1] |= SC_LIMB_HIGHBIT;

		// The least significant bits outside of the precision range are masked off
		out->mantissa[0] &= ~(((sc_ulimb_t)1 << lsb_sh) - 1);

		// The output exponent is incremented by one to account for the carry bit and right shift
		exponent++;
		out->exponent = exponent;
	}
	else {
		// Addition occurs between two operands with different exponents but the distance between their exponents
		// is greater than 0 and less than the precision, i.e. in2 needs to be right shifted
		// by dist bits to align with in1
		SINT32 carry, sh_limb, sh_bits;
		sc_ulimb_t rnd_msb, rnd_bits;
		sh_limb = dist >> SC_LIMB_BITS_SHIFT;
		sh_bits = dist & SC_LIMB_BITS_MASK;

		/// @todo If small enough the memory allocation can be to the stack
		sc_ulimb_t *temp = SC_MALLOC(sizeof(sc_ulimb_t) * in1->alloc);

		// NOTE: As dist is non-zero sh_limb and sh_bits can't both be zero
		if (0 == sh_limb) {
			// We are aligned to the same limb so a right-shift by sh_bits will suffice
			mpn_rshift(temp, in2->mantissa, in1->alloc, sh_bits);
		}
		else {
			if (0 == sh_bits) {
				// We are bit aligned so we can do a copy and zero to acheive a right shift
				mpn_copy(temp, in2->mantissa + sh_limb, in1->alloc - sh_limb);
			}
			else {
				// We are neither word or bit aligned so a shift and zero is required
				mpn_rshift(temp, in2->mantissa + sh_limb, in1->alloc - sh_limb, sh_bits);
			}
			mpn_zero(temp + in1->alloc - sh_limb, sh_limb);
		}

		// Find the rounding bits from the shifted in2
		rnd_msb = temp[0] & ((sc_ulimb_t)1 << (lsb_sh-1));
		if (lsb_sh && temp[0] & ((((sc_ulimb_t)1 << (lsb_sh-1))) - 1)) {
			// The lower significance discarded bits are non-zero
			rnd_bits = 1;
		}
		else {
			// We can't quickly detect rounding bits in in2 so we must look at the
			// discarded limbs as well
			SINT32 discarded = in1->precision - dist;
			if (lsb_sh) {
				discarded += lsb_sh - 1;
			}
			if (discarded > in1->precision) {
				rnd_bits = 0;
			}
			else {
				SINT32 i    = in1->alloc - 1 - (discarded >> SC_LIMB_BITS_SHIFT);
				SINT32 mask = SC_LIMB_WORD(1) << (SC_LIMB_BITS - 1 - (discarded & SC_LIMB_BITS_MASK));
				if (in2->mantissa[i] & mask) {
					rnd_bits = 1;
				}
				else {
					do {
						i--;
					} while (i >= 0 && 0 == in2->mantissa[i]);
					rnd_bits = i >= 0;
				}
			}
		}

		// Remove unused precision bits in the aligned copy of in2
		temp[0] &= ~((SC_LIMB_WORD(1) << lsb_sh) - 1);

		// Add in1 and the aligned in2
		carry = mpn_add_n(out->mantissa, in1->mantissa, temp, in1->alloc);

		// If the addition produced a carry bit we must compensate
		if (carry) {
			carry = out->mantissa[0] & (SC_LIMB_WORD(1) << lsb_sh);
			mpn_rshift(out->mantissa, out->mantissa, in1->alloc, 1);
			out->mantissa[in1->alloc - 1] |= SC_LIMB_HIGHBIT;
			out->mantissa[0] &= ~((SC_LIMB_WORD(1) << lsb_sh) - 1);
			rnd_bits |= rnd_msb;
			rnd_msb   = carry;

			exponent++;
		}

		// Set the output exponent
		out->exponent = exponent;

		SC_FREE(temp, sizeof(sc_ulimb_t) * in1->alloc);
	}
}

static void sc_mpf_sub_normal(sc_mpf_t *out, const sc_mpf_t *in1, const sc_mpf_t *in2, SINT32 swap_sign)
{
	// There are no special cases to be considered here, subtraction must be performed with
	// two non-zero real numbers, i.e. out = (|in1|>|in2|)? sign(in1) * (|in1| - |in2|) : -sign(in1) * (|in2| - |in1|)

	SINT32 lsb_sh, exponent, dist;
	sc_ulimb_t rnd_msb, rnd_bits, maybe_rnd_msb, maybe_rnd_bits;
	sc_ulimb_t *temp = NULL;

	// Ensure that the exponent of in1 is greater than or equal to in2's exponent
	if (!swap_sign) {
		if (in1->exponent < in2->exponent) {
			return sc_mpf_sub_normal(out, in2, in1, 1);
		}
		else if (in1->exponent == in2->exponent) {
			// Scan through the mantissa to determine which input is larger
			size_t i = in1->alloc;
			while (i--) {
				if (in1->mantissa[i] == in2->mantissa[i]) {
					if (0 == i) {
						// The exponent and mantissa's are identical so set the result to zero
						out->sign = 1;
						out->exponent = SC_MPF_EXP_ZERO;
						return;
					}
				}
				else if (in1->mantissa[i] < in2->mantissa[i]) {
					return sc_mpf_sub_normal(out, in2, in1, 1);
				}
				else {
					break;
				}
			}
		}
		out->sign = in1->sign;
	}
	else {
		// If we re-enter with swap_sign asserted then |in1| > |in2| as the inputs have been swapped,
		// therefore the sign of the output must be swapped
		out->sign = -in2->sign;
	}
	
	// Determine the distance between the input exponents
	dist = in1->exponent - in2->exponent;

	// Initialise the output exponent equal to the larger in1 input exponent
	exponent = in1->exponent;

	// Determine how many bits of the least significant input are not contained in a whole limb
	lsb_sh = sc_mpf_negative_mod_limb(in1, in1->precision);

	if (dist == in1->precision) {
		// The exponent distance is equivalent to the precision of the input, so in2
		// can potentially require rounding so look at its most significant bits
		rnd_msb  = 1;
		rnd_bits = 1;
		maybe_rnd_msb = in2->mantissa[in1->alloc - 1] & (SC_LIMB_HIGHBIT >> 1);
		if (!maybe_rnd_msb) {
			if (in2->mantissa[in1->alloc - 1] & SC_LIMB_HIGHBIT) {
				SINT32 i = in1->alloc - 1;
				do {
					i--;
				} while (i >= 0 && 0 == in2->mantissa[i]);
				rnd_bits = i >= 0;
			}
		}

		mpn_copy(out->mantissa, in1->mantissa, in1->alloc);

		goto apply_sub_1;
	}
	else if (dist > in1->precision) {
		// The exponent distance is larger than the precision of the input
		mpn_copy(out->mantissa, in1->mantissa, in1->alloc);
		rnd_msb = 0;
		rnd_bits = dist == (in1->precision + 1);
		goto apply_sub_1;
	}
	else if (0 == dist) {
		// Both of the inputs are aligned
		SINT32 bits, words;
		size_t limb;
		size_t k = in1->alloc;

		// mpn_sub_n of the two mantissa's where |in1| > |in2|
		mpn_sub_n(out->mantissa, in1->mantissa, in2->mantissa, in1->alloc);

		// We need to normalise the result. Knowing that |in1| > |in2| we can scan until a non-zero limb is found.
		// Then we left shift by the appropriate number of bits to normalise and zero the least significant limbs.
		do {
			limb = out->mantissa[--k];
		} while (0 == limb);
		k++;
		bits = limb_clz(limb);
		words = in1->alloc - k;
		if (bits) {
			mpn_lshift(out->mantissa + words, out->mantissa, k, bits);
		}
		else {
			mpn_copy(out->mantissa + words, out->mantissa, k);
		}
		mpn_zero(out->mantissa, words);
		
		// The least significant bits outside of the precision range are masked off
		out->mantissa[0] &= ~(((sc_ulimb_t)1 << lsb_sh) - 1);

		// The output exponent is incremented to account for normalistion
		exponent -= bits + SC_LIMB_BITS * words;
		out->exponent = exponent;
	}
	else {
		// The distance between exponents is greater than 0 and less than the input precision
		SINT32 sh_limb, sh_bits;
		sc_ulimb_t carry;
		sh_limb = dist >> SC_LIMB_BITS_SHIFT;
		sh_bits = dist & SC_LIMB_BITS_MASK;

		/// @todo If small enough the memory allocation can be to the stack
		temp = SC_MALLOC(sizeof(sc_ulimb_t) * in1->alloc);

		// NOTE: As dist is non-zero sh_limb and sh_bits can't both be zero
		if (0 == sh_limb) {
			// We are aligned to the same limb so a right-shift by sh_bits will suffice
			mpn_rshift(temp, in2->mantissa, in1->alloc, sh_bits);
		}
		else {
			if (0 == sh_bits) {
				// We are bit aligned so we can do a copy and zero to acheive a right shift
				mpn_copy(temp, in2->mantissa + sh_limb, in1->alloc - sh_limb);
			}
			else {
				// We are neither word or bit aligned so a shift and zero is required
				mpn_rshift(temp, in2->mantissa + sh_limb, in1->alloc - sh_limb, sh_bits);
			}
			mpn_zero(temp + in1->alloc - sh_limb, sh_limb);
		}

		// Find the rounding bits from the shifted in2
		rnd_msb = temp[0] & ((sc_ulimb_t)1 << (lsb_sh-1));
		if (lsb_sh && temp[0] & ((((sc_ulimb_t)1 << (lsb_sh-1))) - 1)) {
			// The lower significance discarded bits are non-zero
			rnd_bits = 1;
		}
		else {
			// We can't quickly detect rounding bits in in2 so we must look at the
			// discarded limbs as well
			SINT32 discarded = in1->precision - dist;
			if (lsb_sh) {
				discarded += lsb_sh - 1;
			}
			if (discarded > in1->precision) {
				rnd_bits = 0;
			}
			else {
				SINT32 i    = in1->alloc - 1 - (discarded >> SC_LIMB_BITS_SHIFT);
				SINT32 mask = SC_LIMB_WORD(1) << (SC_LIMB_BITS - 1 - (discarded & SC_LIMB_BITS_MASK));
				if (in2->mantissa[i] & mask) {
					rnd_bits = 1;
				}
				else {
					do {
						i--;
					} while (i >= 0 && 0 == in2->mantissa[i]);
					rnd_bits = i >= 0;
				}
			}
		}

		// Check for rounding conditions where we can lose a bit, i.e. the highest bit is set and
		// the following subtraction could result in a leading 0 bit.
		if ((in1->mantissa[in1->alloc] - temp[in1->alloc]) <= SC_LIMB_HIGHBIT) {
			if (0 == rnd_bits) {
				maybe_rnd_msb  = 0;
				maybe_rnd_bits = 0;
			}
			else {
				SINT32 discarded = in1->precision + 1 - dist;
				SINT32 shift     = SC_LIMB_BITS - 1 - (discarded & SC_LIMB_BITS_MASK);
				SINT32 mask      = SC_LIMB_WORD(1) << shift;
				SINT32 i         = in1->alloc - 1 - (discarded >> SC_LIMB_BITS_SHIFT);

				maybe_rnd_msb = in2->mantissa[i] & mask;

				if (0 == maybe_rnd_msb || (in2->mantissa[in1->alloc-1] & (mask - 1))) {
					maybe_rnd_bits = 1;
				}
				else {
					do {
						i--;
					} while (i >= 0 && 0 == in2->mantissa[i]);
					maybe_rnd_bits = i >= 0;
				}
			}
		}

		// Remove unused precision bits in the aligned copy of in2
		temp[0] &= ~((SC_LIMB_WORD(1) << lsb_sh) - 1);

		// Subtract the aligned in2 from in1
		mpn_sub_n(out->mantissa, in1->mantissa, temp, in1->alloc);

		// If the subtraction results in the most significant bit being zero we must normalize
		if (!(SC_LIMB_HIGHBIT & out->mantissa[in1->alloc - 1])) {
			mpn_lshift(out->mantissa, out->mantissa, in1->alloc, 1);

			if (rnd_msb) {
				mpn_sub_1(out->mantissa, out->mantissa, in1->alloc, SC_LIMB_WORD(1) << lsb_sh);
			}
			out->mantissa[0] &= ~((SC_LIMB_WORD(1) << lsb_sh) - 1);
			exponent--;
			rnd_msb  = maybe_rnd_msb;
			rnd_bits = maybe_rnd_bits;
		}

		// Apply rounding to the result
		if (rnd_msb || rnd_bits) {
apply_sub_1:
			// 
			mpn_sub_1(out->mantissa, out->mantissa, in1->alloc, SC_LIMB_WORD(1) << lsb_sh);

			if (out->mantissa[in1->alloc-1] <= SC_LIMB_HIGHBIT) {
				// The result was a power of 2 and we lost a bit, therefore left-shifting by 1 bit
				// must occur to normalize the result
				out->mantissa[in1->alloc-1] |= SC_LIMB_HIGHBIT;
				out->mantissa[0] <<= 1;
				exponent--;

				if ((0 != rnd_msb && 0 == rnd_bits) || 0 == rnd_msb) {
					out->mantissa[0] |= SC_LIMB_WORD(1) << lsb_sh;
				}
			}
		}

		// Remove unused precision bits
		out->mantissa[0] &= ~((SC_LIMB_WORD(1) << lsb_sh) - 1);

		out->exponent = exponent;

		if (temp) {
			SC_FREE(temp, sizeof(sc_ulimb_t) * in1->alloc);
		}
	}
}

#endif

void sc_mpf_add(sc_mpf_t *out, const sc_mpf_t *in1, const sc_mpf_t *in2)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	if (SC_MPF_IS_SINGULAR(in1) || SC_MPF_IS_SINGULAR(in2)) {
		if (SC_MPF_EXP_NAN == in1->exponent || SC_MPF_EXP_NAN == in2->exponent) {
			// If either input is NaN then the result is NaN
			out->exponent = SC_MPF_EXP_NAN;
		}
		else if (SC_MPF_EXP_INF == in1->exponent) {
			if (SC_MPF_EXP_INF != in2->exponent || in1->sign == in2->sign) {
				// If both are infinite with the same sign (inf+inf, -inf-inf) OR in2 is a finite number
				// then the result is infinite with the same sign is in1
				out->exponent = SC_MPF_EXP_INF;
				out->sign     = in1->sign;
			}
			else {
				// inf - inf is indeterminate so return a NaN
				out->exponent = SC_MPF_EXP_NAN;
			}
		}
		else if (SC_MPF_EXP_INF == in2->exponent) {
			// in1 is a finite number so the result is the same as in2
			out->exponent = SC_MPF_EXP_INF;
			out->sign     = in2->sign;
		}
		else if (SC_MPF_EXP_ZERO == in1->exponent && SC_MPF_EXP_ZERO == in2->exponent) {
			// We need to ensure that -0 + -0 results in -0 if both inputs are zero
			out->sign     = (in1->sign < 0 && in2->sign < 0)? -1 : 1;
			out->exponent = SC_MPF_EXP_ZERO;
		}
		else if (SC_MPF_EXP_ZERO == in1->exponent) {
			sc_mpf_set(out, in2);
		}
		else if (SC_MPF_EXP_ZERO == in2->exponent) {
			sc_mpf_set(out, in1);
		}
		return;
	}

	// Now simply add or subtract based on the difference in signs of the finite numbers
	if (in1->sign != in2->sign) {
		sc_mpf_sub_normal(out, in1, in2, 0);
	}
	else {
		sc_mpf_add_normal(out, in1, in2);
	}

#else
	mpfr_add(out, in1, in2, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_add_ui(sc_mpf_t *out, const sc_mpf_t *in1, sc_ulimb_t in2)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	sc_mpf_t mpf_in2;

	if (0 == in2) {
		return sc_mpf_set(out, in1);
	}
	else if (SC_MPF_IS_SINGULAR(in1)) {
		if (SC_MPF_EXP_NAN == in1->exponent) {
			out->exponent = SC_MPF_EXP_NAN;
		}
		else if(SC_MPF_EXP_INF == in1->exponent) {
			out->exponent = SC_MPF_EXP_INF;
			out->sign     = in1->sign;
		}
		else {
			sc_mpf_set_ui(out, in2);
		}
		return;
	}

	// Manufacture an SC_LIMB_BITS precision floating point number using in2
	sc_mpf_init2(&mpf_in2, g_mpf_precision);
	sc_mpf_set_ui(&mpf_in2, in2);
	sc_mpf_add(out, in1, &mpf_in2);
	sc_mpf_clear(&mpf_in2);
#else
	mpfr_add_ui(out, in1, in2, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_add_si(sc_mpf_t *out, const sc_mpf_t *in1, sc_slimb_t in2)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	sc_mpf_t mpf_in2;

	if (0 == in2) {
		return sc_mpf_set(out, in1);
	}
	else if (SC_MPF_IS_SINGULAR(in1)) {
		if (SC_MPF_EXP_NAN == in1->exponent) {
			out->exponent = SC_MPF_EXP_NAN;
		}
		else if(SC_MPF_EXP_INF == in1->exponent) {
			out->exponent = SC_MPF_EXP_INF;
			out->sign     = in1->sign;
		}
		else {
			sc_mpf_set_si(out, in2);
		}
		return;
	}

	// Manufacture an SC_LIMB_BITS precision floating point number using in2
	sc_mpf_init2(&mpf_in2, g_mpf_precision);
	sc_mpf_set_si(&mpf_in2, in2);
	sc_mpf_add(out, in1, &mpf_in2);
	sc_mpf_clear(&mpf_in2);
#else
	mpfr_add_si(out, in1, in2, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_sub(sc_mpf_t *out, const sc_mpf_t *in1, const sc_mpf_t *in2)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	if (SC_MPF_IS_SINGULAR(in1) || SC_MPF_IS_SINGULAR(in2)) {
		if (SC_MPF_EXP_NAN == in1->exponent || SC_MPF_EXP_NAN == in2->exponent) {
			// If either input is NaN then the result is NaN
			out->exponent = SC_MPF_EXP_NAN;
		}
		else if (SC_MPF_EXP_INF == in1->exponent) {
			if (SC_MPF_EXP_INF != in2->exponent || in1->sign != in2->sign) {
				// If both are infinite with different sign ((inf)-(-inf), (-inf)-(inf) OR in2 is a finite number
				// then the result is infinite with the same sign is in1
				out->exponent = SC_MPF_EXP_INF;
				out->sign     = in1->sign;
			}
			else {
				// inf - inf is indeterminate so return a NaN
				out->exponent = SC_MPF_EXP_NAN;
			}
		}
		else if (SC_MPF_EXP_INF == in2->exponent) {
			// in1 is a finite number so the result is the same as in2 negated
			out->exponent = SC_MPF_EXP_INF;
			out->sign     = -in2->sign;
		}
		else if (SC_MPF_EXP_ZERO == in1->exponent && SC_MPF_EXP_ZERO == in2->exponent) {
			// We need to ensure that -0 - +0 results in -0 if both inputs are zero
			out->sign     = (in1->sign < 0 && in2->sign > 0)? -1 : 1;
			out->exponent = SC_MPF_EXP_ZERO;
		}
		else if (SC_MPF_EXP_ZERO == in1->exponent) {
			sc_mpf_negate(out, in2);
		}
		else if (SC_MPF_EXP_ZERO == in2->exponent) {
			sc_mpf_set(out, in1);
		}
		return;
	}

	if (in1->sign == in2->sign) {
		sc_mpf_sub_normal(out, in1, in2, 0);
	}
	else {
		// If the sign's are different we must perform an addition instead.
		if (in1->exponent < in2->exponent) {
			// We must ensure that |in1|>|in2| in sc_mpf_add_normal() and that 
			// the sign is appropriately negated to compensate for the operand swap.
			sc_mpf_add_normal(out, in2, in1);
			out->sign = -out->sign;
		}
		else {
			sc_mpf_add_normal(out, in1, in2);
		}
	}
#else
	mpfr_sub(out, in1, in2, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_sub_ui(sc_mpf_t *out, const sc_mpf_t *in1, sc_ulimb_t in2)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	sc_mpf_t mpf_in2;

	if (0 == in2) {
		return sc_mpf_set(out, in1);
	}
	else if (SC_MPF_IS_SINGULAR(in1)) {
		if (SC_MPF_EXP_NAN == in1->exponent) {
			out->exponent = SC_MPF_EXP_NAN;
		}
		else if(SC_MPF_EXP_INF == in1->exponent) {
			out->exponent = SC_MPF_EXP_INF;
			out->sign     = in1->sign;
		}
		else {
			sc_mpf_set_ui(out, in2);
			out->sign = -out->sign;
		}
		return;
	}

	// Manufacture an SC_LIMB_BITS precision floating point number using in2
	sc_mpf_init2(&mpf_in2, g_mpf_precision);
	sc_mpf_set_ui(&mpf_in2, in2);
	sc_mpf_sub(out, in1, &mpf_in2);
	sc_mpf_clear(&mpf_in2);
#else
	mpfr_sub_ui(out, in1, in2, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_sub_si(sc_mpf_t *out, const sc_mpf_t *in1, sc_slimb_t in2)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	sc_mpf_t mpf_in2;

	if (0 == in2) {
		return sc_mpf_set(out, in1);
	}
	else if (SC_MPF_IS_SINGULAR(in1)) {
		if (SC_MPF_EXP_NAN == in1->exponent) {
			out->exponent = SC_MPF_EXP_NAN;
		}
		else if(SC_MPF_EXP_INF == in1->exponent) {
			out->exponent = SC_MPF_EXP_INF;
			out->sign     = in1->sign;
		}
		else {
			sc_mpf_set_si(out, in2);
			out->sign = -out->sign;
		}
		return;
	}

	// Manufacture an SC_LIMB_BITS precision floating point number using in2
	sc_mpf_init2(&mpf_in2, g_mpf_precision);
	sc_mpf_set_si(&mpf_in2, in2);
	sc_mpf_sub(out, in1, &mpf_in2);
	sc_mpf_clear(&mpf_in2);
#else
	mpfr_sub_si(out, in1, in2, MPFR_DEFAULT_ROUNDING);
#endif
}

#ifdef USE_SAFECRYPTO_FLOAT_MP

static void sc_mpf_mul_1(sc_mpf_t *out, const sc_mpf_t *in1, const sc_mpf_t *in2)
{
	// NOTE: All IO must have precision less than or equal to SC_LIMB_BITS
	sc_ulimb_t hi, lo;
	SINT32 exponent;

	// Set the output exponent
	exponent = in1->exponent + in2->exponent;

	// Perform a word-oriented multiply of in1 and in2
	limb_mul_hi_lo(&hi, &lo, in1->mantissa[0], in2->mantissa[0]);

	// If necessary, normalise the result
	//if (!(hi & SC_LIMB_HIGHBIT)) {
	if (hi < SC_LIMB_HIGHBIT) {
		hi   = (hi << 1) | (lo >> (SC_LIMB_BITS - 1));
		lo <<= 1;
		exponent--;
	}

	// Set the exponent
	out->exponent = exponent;

	// Set the sign as appropriate
	out->sign = in1->sign * in2->sign;

	// Round towards zero so simply truncate when setting the output mantissa
	out->mantissa[0] = hi;
}

static void sc_mpf_mul_2(sc_mpf_t *out, const sc_mpf_t *in1, const sc_mpf_t *in2)
{
	sc_ulimb_t msb, *limbs = NULL;
	sc_ulimb_t p[4], hi, lo;
	SINT32 exponent, used, out_used, smaller;

	used     = in1->alloc;
	smaller  = (2 * used) > ((in1->precision + in2->precision) >> SC_LIMB_BITS_SHIFT);
	out_used = 2 * used - smaller;

	// Set the output exponent
	exponent = in1->exponent + in2->exponent;

	// Set the output sign
	out->sign = in1->sign * in2->sign;
	
	limbs = p;
		
	// The first partial product {A1B0, 0} + {A0B0}
	limb_mul_hi_lo(&hi, &lo, in1->mantissa[0], in2->mantissa[0]);
	limb_mul_hi_lo(&limbs[1], &limbs[0], in1->mantissa[1], in2->mantissa[0]);
	limb_add_hi_lo(&limbs[1], &limbs[0], limbs[1], limbs[0], 0, hi);

	// The second partial product {A0B1} + {A1B1, 0}
	limb_mul_hi_lo(&hi, &lo, in1->mantissa[0], in2->mantissa[1]);
	limb_mul_hi_lo(&limbs[3], &limbs[2], in1->mantissa[1], in2->mantissa[1]);
	limb_add_hi_lo(&limbs[3], &hi, limbs[3], limbs[2], 0, hi);

	// Sum of the partial products to for {p3, p2, p1, p0}
	limb_add_hi_lo(&limbs[2], &limbs[1], limbs[2], limbs[1], hi, lo);
	limbs[3] += limbs[2] < hi;
	msb = limbs[3] >> (SC_LIMB_BITS - 1);

	// Compensate for smaller precisions that result in 2*used-1 product limbs
	limbs += smaller;

	// Normalise the product
	if (!msb) {
		mpn_lshift(limbs, limbs, out_used, 1);
		exponent--;
	}

	// Copy the product to the output
	mpn_copy(out->mantissa, limbs + out_used - used, used);

	// Set the exponent
	out->exponent = exponent;
}

static void sc_mpf_mul_general(sc_mpf_t *out, const sc_mpf_t *in1, const sc_mpf_t *in2)
{
	sc_ulimb_t msb, *limbs = NULL;
	SINT32 exponent, used, out_used, smaller;

	used     = in1->alloc;
	smaller  = (2 * used) > ((in1->precision + in2->precision) >> SC_LIMB_BITS_SHIFT);
	out_used = 2 * used - smaller;

	// Set the output exponent
	exponent = in1->exponent + in2->exponent;

	// Set the output sign
	out->sign = in1->sign * in2->sign;

	limbs = SC_MALLOC(sizeof(sc_ulimb_t) * 2 * used);

	mpn_mul(limbs, in1->mantissa, used, in2->mantissa, used);

	msb = limbs[2*used - 1] >> (SC_LIMB_BITS - 1);

	// Compensate for smaller precisions that result in 2*used-1 product limbs
	limbs += smaller;

	// Normalise the product
	if (!msb) {
		mpn_lshift(limbs, limbs, out_used, 1);
		exponent--;
	}

	// Copy the product to the output
	mpn_copy(out->mantissa, limbs + out_used - used, used);

	// Set the exponent
	out->exponent = exponent;

	SC_FREE(limbs, sizeof(sc_ulimb_t) * 2 * used);
}

#endif

void sc_mpf_mul(sc_mpf_t *out, const sc_mpf_t *in1, const sc_mpf_t *in2)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	if (SC_MPF_IS_SINGULAR(in1) || SC_MPF_IS_SINGULAR(in2)) {
		SINT32 sign = in1->sign * in2->sign;
		if (SC_MPF_EXP_NAN == in1->exponent || SC_MPF_EXP_NAN == in2->exponent) {
			// If in1 or in2 is NaN then result is NaN
			out->exponent = SC_MPF_EXP_NAN;
		}
		else if (SC_MPF_EXP_INF == in1->exponent || SC_MPF_EXP_INF == in2->exponent) {
			if (SC_MPF_EXP_ZERO == in1->exponent || SC_MPF_EXP_ZERO == in2->exponent) {
				out->exponent = SC_MPF_EXP_NAN;
			}
			else {
				out->exponent = SC_MPF_EXP_INF;
				out->sign     = sign;
			}
		}
		else {
			out->exponent = SC_MPF_EXP_ZERO;
			out->sign     = sign;
		}
		return;
	}

	// Precision is identical for all operands, so we should take care of those cases
	// we're likely to encounter, such as 64 to 256-bit precision for Gaussian sampling.
	// At a minimum on a 64-bit machine we'll use a single limb to store the mantissa.
	if (SC_LIMB_BITS >= in1->precision) {
		sc_mpf_mul_1(out, in1, in2);
	}
	else if (2*SC_LIMB_BITS >= in1->precision) {
		sc_mpf_mul_2(out, in1, in2);
	}
	else {
		sc_mpf_mul_general(out, in1, in2);
	}
#else
	mpfr_mul(out, in1, in2, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_mul_2exp(sc_mpf_t *out, const sc_mpf_t *in, sc_ulimb_t exp)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	sc_mpf_set(out, in);

	// If in is NaN, INF or ZERO the result should be the same, otherwise multiplication
	// is performed by simply increasing the exponent by exp
	if (!SC_MPF_IS_SINGULAR(in)) {
		out->exponent += exp;
	}
#else
	mpfr_mul_2exp(out, in, exp, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_mul_ui(sc_mpf_t *out, const sc_mpf_t *in1, const sc_ulimb_t in2)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	sc_mpf_t mpf_in2;

	if (SC_MPF_IS_SINGULAR(in1)) {
		if (SC_MPF_EXP_NAN == in1->exponent) {
			out->exponent = SC_MPF_EXP_NAN;
		}
		else if(SC_MPF_EXP_INF == in1->exponent) {
			if (0 == in2) {
				out->exponent = SC_MPF_EXP_NAN;
			}
			else {
				out->exponent = SC_MPF_EXP_INF;
				out->sign     = in1->sign;
			}
		}
		else {
			out->exponent = SC_MPF_EXP_ZERO;
			out->sign     = in1->sign;
		}
		return;
	}
	else if (0 == in2) {
		return sc_mpf_set_ui(out, in2);
	}
	else if (1 == in2) {
		return sc_mpf_set(out, in1);
	}
	else {
		sc_ulimb_t msb, *limbs = NULL, v;
		SINT32 exponent, used, out_used, smaller, clz;
	
		used     = in1->alloc;
		smaller  = (used + 1) > ((in1->precision + SC_LIMB_BITS) >> SC_LIMB_BITS_SHIFT);
		out_used = used + 1 - smaller;
	
		// Set the output exponent
		clz      = limb_clz(in2);
		exponent = in1->exponent + SC_LIMB_BITS - clz;

		// Normalise the input
		v        = in2 << clz;
	
		// Set the output sign
		out->sign = in1->sign;
	
		// Allocate memory for the intermediate result
		limbs = SC_MALLOC(sizeof(sc_ulimb_t) * (used + 1));
	
		// Multiply the MP limbs with the single precision (normalised) value
		limbs[used] = mpn_mul_1(limbs, in1->mantissa, used, v);
	
		msb = limbs[used] >> (SC_LIMB_BITS - 1);
	
		// Compensate for smaller precisions that result in 2*used-1 product limbs
		limbs += smaller;
	
		// Normalise the product
		if (!msb) {
			mpn_lshift(limbs, limbs, out_used, 1);
			exponent--;
		}
	
		// Copy the product to the output
		mpn_copy(out->mantissa, limbs + out_used - used, used);

		// Set the exponent
		out->exponent = exponent;
	
		// Free resources associated with the intermediate result
		SC_FREE(limbs, sizeof(sc_ulimb_t) * (used + 1));
	}
#else
	mpfr_mul_ui(out, in1, in2, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_mul_si(sc_mpf_t *out, const sc_mpf_t *in1, const sc_slimb_t in2)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	sc_mpf_t mpf_in2;

	if (SC_MPF_IS_SINGULAR(in1)) {
		if (SC_MPF_EXP_NAN == in1->exponent) {
			out->exponent = SC_MPF_EXP_NAN;
		}
		else if(SC_MPF_EXP_INF == in1->exponent) {
			if (0 == in2) {
				out->exponent = SC_MPF_EXP_NAN;
			}
			else {
				out->exponent = SC_MPF_EXP_INF;
				out->sign     = in1->sign* ((in2 < 0)? -1 : 1);
			}
		}
		else {
			out->exponent = SC_MPF_EXP_ZERO;
			out->sign     = in1->sign;
		}
		return;
	}
	else if (0 == in2) {
		return sc_mpf_set_ui(out, in2);
	}
	else if (1 == in2) {
		return sc_mpf_set(out, in1);
	}
	else {
		sc_ulimb_t msb, *limbs = NULL, v;
		SINT32 exponent, used, out_used, smaller, clz;
	
		used     = in1->alloc;
		smaller  = (used + 1) > ((in1->precision + SC_LIMB_BITS) >> SC_LIMB_BITS_SHIFT);
		out_used = used + 1 - smaller;
	
		// Set the output exponent
		v        = (in2 >= 0)? in2 : -(sc_ulimb_t) in2;
		clz      = limb_clz(v);
		exponent = in1->exponent + SC_LIMB_BITS - clz;

		// Normalise the input
		v        = v << clz;
	
		// Set the output sign
		out->sign = in1->sign * ((in2 < 0)? -1 : 1);
	
		// Allocate memory for the intermediate result
		limbs = SC_MALLOC(sizeof(sc_ulimb_t) * (used + 1));
	
		// Multiply the MP limbs with the single precision (normalised) value
		limbs[used] = mpn_mul_1(limbs, in1->mantissa, used, v);
	
		msb = limbs[used] >> (SC_LIMB_BITS - 1);
	
		// Compensate for smaller precisions that result in 2*used-1 product limbs
		limbs += smaller;
	
		// Normalise the product
		if (!msb) {
			mpn_lshift(limbs, limbs, out_used, 1);
			exponent--;
		}
	
		// Copy the product to the output
		mpn_copy(out->mantissa, limbs + out_used - used, used);

		// Set the exponent
		out->exponent = exponent;
	
		// Free resources associated with the intermediate result
		SC_FREE(limbs, sizeof(sc_ulimb_t) * (used + 1));
	}
#else
    mpfr_mul_si(out, in1, (sc_ulimb_t) in2, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_div(sc_mpf_t *out, const sc_mpf_t *n, const sc_mpf_t *d)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	mpfr_div(out, n, d, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_div_2exp(sc_mpf_t *out, const sc_mpf_t *n, sc_ulimb_t exp)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	sc_mpf_set(out, n);
	if (!SC_MPF_IS_SINGULAR(n) && exp) {
		out->exponent = n->exponent - exp;
	}
#else
	mpfr_div_2exp(out, n, exp, MPFR_DEFAULT_ROUNDING);
#endif
}

#ifdef USE_SAFECRYPTO_FLOAT_MP
static void sc_mpf_div_ui_normal(sc_mpf_t *out, const sc_mpf_t *n, sc_ulimb_t d)
{
	// All special cases and singular values are exhausted, we must perform a division
	size_t len_n = n->alloc;
	size_t len_q = out->alloc;
	SINT32 dist  = (SINT32)len_q - (SINT32)len_n + 1;
	SINT32 exact = 0;
	SINT32 lsb_sh, lsb;
	sc_slimb_t exponent = n->exponent;
	sc_ulimb_t temp[dist + len_n];
	sc_ulimb_t est_carry;

	// First estimate the quotient before we try to correct
	if (dist < 0) {
		est_carry = mpn_divrem_1(temp, 0, n->mantissa - dist, len_q + 1, d);
		exact     = 0 == est_carry;

		// Verify that the estimated remainder is not dependent on the unused lower limbs
		// of the mantissa
		if (exact) {
			size_t i;
			for (i=0; i < -dist; i++) {
				if (n->mantissa[i]) {
					exact = 0;
					break;
				}
			}
		}
	}
	else {
		est_carry = mpn_divrem_1(temp, dist, n->mantissa, len_n, d);
		exact     = 0 == est_carry;
	}

	// Transfer the temporary quotient to the output quotient with normalization.
	if (!temp[len_q]) {
		// If the leading limb is zero then simply copy to the output and reduce the exponent.
		mpn_copy(out->mantissa, temp, len_q);
		exponent -= SC_LIMB_BITS;
	}
	else {
		// Normalize by left shifting by the number of leading zeros in the significant word
		SINT32 clz;
		clz = limb_clz(temp[len_q]);
		if (clz) {
			sc_ulimb_t lost_bits = temp[0] << clz;
			mpn_lshift(out->mantissa, temp + 1, len_q, clz);
			out->mantissa[0] |= temp[0] >> (SC_LIMB_BITS - clz);
			exact  |= 0 == lost_bits;
			exponent -= clz;
		}
		else {
			mpn_copy(out->mantissa, temp + 1, len_q);
		}
	}

	// Determine how many remaining bits of the quotient must be calculated
	lsb_sh = sc_mpf_negative_mod_limb(out, out->precision);

	// Mask off the least significant bits from the quotient but save them for analysis
	out->mantissa[0] &= ~(((sc_ulimb_t)1 << lsb_sh) - 1);

	out->exponent = exponent;
	out->sign     = n->sign;
}
#endif

void sc_mpf_div_ui(sc_mpf_t *out, const sc_mpf_t *n, sc_ulimb_t d)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	// Deal with singluar inputs - ZERO, INF and NaN
	if (SC_MPF_IS_SINGULAR(n)) {
		if (SC_MPF_EXP_NAN == n->exponent) {
			// If the numerator is NaN then quotient is also a NaN
    		out->exponent  = SC_MPF_EXP_NAN;
		}
		else if (SC_MPF_EXP_INF == n->exponent) {
			// If numerator is infinite then the quotient is infinite with the same sign
			out->sign      = n->sign;
    		out->exponent  = SC_MPF_EXP_INF;
    	}
		else if (0 == d) {
			// If numerator and denominator are zero then quotient is NaN
			out->exponent  = SC_MPF_EXP_NAN;
		}
		else {
			// 0/d is zero
			out->sign      = n->sign;
			out->exponent  = SC_MPF_EXP_ZERO;
		}
		return;
	}
	else if (0 == d) {
		// If numerator is non-zero and denominator is zero then quotient is infinite
		// with the same sign as the numerator
		out->sign      = n->sign;
		out->exponent  = SC_MPF_EXP_INF;
		return;
	}
	else if (1 == d) {
		sc_mpf_set(out, n);
		return;
	}
	else if (!(d & (d-1))) {
		return sc_mpf_div_2exp(out, n, limb_ctz(d));
	}

	return sc_mpf_div_ui_normal(out, n, d);
#else
	mpfr_div_ui(out, n, d, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_div_si(sc_mpf_t *out, const sc_mpf_t *n, sc_slimb_t d)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	// Deal with singluar inputs - ZERO, INF and NaN
	if (SC_MPF_IS_SINGULAR(n)) {
		if (SC_MPF_EXP_NAN == n->exponent) {
			// If the numerator is NaN then quotient is also a NaN
    		out->exponent  = SC_MPF_EXP_NAN;
		}
		else if (SC_MPF_EXP_INF == n->exponent) {
			// If numerator is infinite then the quotient is infinite with the same sign
			out->sign      = n->sign * ((d < 0)? -1 : 1);
    		out->exponent  = SC_MPF_EXP_INF;
    	}
		else if (0 == d) {
			// If numerator and denominator are zero then quotient is NaN
			out->exponent  = SC_MPF_EXP_NAN;
		}
		else {
			// 0/d is zero
			out->sign      = n->sign * ((d < 0)? -1 : 1);
			out->exponent  = SC_MPF_EXP_ZERO;
		}
		return;
	}
	else if (0 == d) {
		// If numerator is non-zero and denominator is zero then quotient is infinite
		// with the same sign as the numerator
		out->sign      = n->sign * ((d < 0)? -1 : 1);
		out->exponent  = SC_MPF_EXP_INF;
		return;
	}
	else {
		sc_ulimb_t abs_d = (d >= 0)? d : -(sc_ulimb_t) d;
		if (1 == abs_d) {
			sc_mpf_set(out, n);
			if (d < 0) {
				out->sign = -out->sign;
			}
			return;
		}
		else if (!(abs_d & (abs_d-1))) {
			sc_mpf_div_2exp(out, n, limb_ctz(abs_d));
			if (d < 0) {
				out->sign = -out->sign;
			}
			return;
		}

		sc_mpf_div_ui_normal(out, n, abs_d);
	}
#else
    mpfr_div_si(out, n, (sc_ulimb_t) d, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_sqrt(sc_mpf_t *out, const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	mpfr_sqrt(out, in, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_sqrt_ui(sc_mpf_t *out, sc_ulimb_t in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	mpfr_sqrt_ui(out, in, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_pow_ui(sc_mpf_t *out, const sc_mpf_t *in, sc_ulimb_t exp)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	mpfr_pow_ui(out, in, exp, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_pow_si(sc_mpf_t *out, const sc_mpf_t *in, sc_slimb_t exp)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	mpfr_pow_si(out, in, exp, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_ceil(sc_mpf_t *out, const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	mpfr_ceil(out, in);
#endif
}

void sc_mpf_floor(sc_mpf_t *out, const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	mpfr_floor(out, in);
#endif
}

void sc_mpf_trunc(sc_mpf_t *out, const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	mpfr_trunc(out, in);
#endif
}

SINT32 sc_mpf_exp(sc_mpf_t *out, const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	return mpfr_exp(out, in, MPFR_DEFAULT_ROUNDING);
#endif
}

SINT32 sc_mpf_log(sc_mpf_t *out, const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	return mpfr_log(out, in, MPFR_DEFAULT_ROUNDING);
#endif
}
