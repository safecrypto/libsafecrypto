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
#include "safecrypto_types.h"
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


SINT32 sc_mpf_set_precision(size_t precision)
{
	if (precision < SC_LIMB_BITS) {
		return SC_FUNC_FAILURE;
	}
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
		fprintf(stderr, "a->sign is %d, b->sign is %d\n", a->sign, b->sign);
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

static void sc_mpf_add_normal(sc_mpf_t *out, const sc_mpf_t *in1, const sc_mpf_t *in2)
{
}

static void sc_mpf_sub_normal(sc_mpf_t *out, const sc_mpf_t *in1, const sc_mpf_t *in2)
{
}

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
			out->sign     = in1->sign;
		}
		else if (SC_MPF_EXP_ZERO == in1->exponent && SC_MPF_EXP_ZERO == in2->exponent) {
			// We need to ensure that -0 + -0 results in -0 if both inputs are zero
			out->sign     = (in1->sign < 0 && in2->sign < 0)? -1 : 1;
			out->exponent = SC_MPF_EXP_ZERO;
		}
		else if (SC_MPF_EXP_ZERO == in1->exponent) {
			sc_mpf_set(out, in1);
		}
		else if (SC_MPF_EXP_ZERO == in2->exponent) {
			sc_mpf_set(out, in2);
		}
		return;
	}

	// Now simply add or subtract based on the difference in signs of the finite numbers
	if (in1->sign != in2->sign) {
		sc_mpf_sub_normal(out, in1, in2);
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
#else
	mpfr_add_ui(out, in1, in2, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_add_si(sc_mpf_t *out, const sc_mpf_t *in1, sc_slimb_t in2)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	mpfr_add_si(out, in1, in2, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_sub(sc_mpf_t *out, const sc_mpf_t *in1, const sc_mpf_t *in2)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	mpfr_sub(out, in1, in2, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_sub_ui(sc_mpf_t *out, const sc_mpf_t *in1, sc_ulimb_t in2)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	mpfr_sub_ui(out, in1, in2, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_sub_si(sc_mpf_t *out, const sc_mpf_t *in1, sc_slimb_t in2)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	mpfr_sub_si(out, in1, in2, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_mul(sc_mpf_t *out, const sc_mpf_t *in1, const sc_mpf_t *in2)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	mpfr_mul(out, in1, in2, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_mul_2exp(sc_mpf_t *out, const sc_mpf_t *in, sc_ulimb_t exp)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	mpfr_mul_2exp(out, in, exp, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_mul_ui(sc_mpf_t *out, const sc_mpf_t *in1, const sc_ulimb_t in2)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	mpfr_mul_ui(out, in1, in2, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_mul_si(sc_mpf_t *out, const sc_mpf_t *in1, const sc_slimb_t in2)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
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
	if (temp[len_q]) {
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
	if (out->precision & (out->precision - 1)) {
		lsb_sh = out->precision & SC_LIMB_BITS_MASK;
		if (lsb_sh) {
			lsb_sh = SC_LIMB_BITS - lsb_sh;
		}
	}
	else {
		lsb_sh = (-(sc_ulimb_t)out->precision) & SC_LIMB_BITS_MASK;
	}

	// Mask off the least significant bits from the quotient but save them for analysis
	out->mantissa[0] &= ~(((sc_ulimb_t)1 << lsb_sh) - 1);

	out->exponent = exponent;
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
	else if (!(d & (d-1))) {
		return sc_mpf_div_2exp(out, n, limb_ctz(d));
	}
	else if (1 == d) {
		sc_mpf_set(out, n);
		return;
	}

	return sc_mpf_div_ui_normal(out, n, d);
#else
	mpfr_div_ui(out, n, d, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_div_si(sc_mpf_t *out, const sc_mpf_t *n, sc_slimb_t d)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
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
