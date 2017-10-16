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

void sc_mpf_set(sc_mpf_t *out, const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	out->sign     = in->sign;
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
	if (((in->exponent - 1) / SC_LIMB_BITS) < in->alloc) {
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
	else if (!sc_mpf_fits_ulong(in)) {
		return (SC_MPF_EXP_NAN == in->exponent || in->sign)? 0 : SC_LIMB_UMAX;
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
	else if (!sc_mpf_fits_slong(in)) {
		return (SC_MPF_EXP_NAN == in->exponent || in->sign)? SC_LIMB_SMIN : SC_LIMB_SMAX;
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
			retval = (in->sign)? (retval <= SC_LIMB_SMAX)? -(sc_slimb_t)retval : SC_LIMB_SMIN : retval;
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
	inout->sign = 0;
	if (0 == value) {
		inout->exponent = SC_MPF_EXP_ZERO;
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
	}
#else
	mpfr_set_ui(inout, value, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_set_si(sc_mpf_t *inout, sc_slimb_t value)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	if (0 == value) {
		inout->sign     = 0;
		inout->exponent = SC_MPF_EXP_ZERO;
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
		inout->sign     = value < 0;
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

SINT32 sc_mpf_fits_slong(const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	if (SC_MPF_IS_SINGULAR(in)) {
		return in->exponent == SC_MPF_EXP_ZERO;
	}
	else if (in->sign) {
		return 0;
	}
	else if (in->exponent <= (SC_LIMB_BITS - 2)) {
		return 1;
	}
	else if (in->exponent >= (SC_LIMB_BITS)) {
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

SINT32 sc_mpf_fits_sint(const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	return mpfr_fits_sint_p(in, MPFR_DEFAULT_ROUNDING);
#endif
}

SINT32 sc_mpf_fits_sshort(const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	return mpfr_fits_sshort_p(in, MPFR_DEFAULT_ROUNDING);
#endif
}

SINT32 sc_mpf_fits_ulong(const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
	if (SC_MPF_IS_SINGULAR(in)) {
		return in->exponent == SC_MPF_EXP_ZERO;
	}
	else if (in->sign) {
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

SINT32 sc_mpf_fits_uint(const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	return mpfr_fits_uint_p(in, MPFR_DEFAULT_ROUNDING);
#endif
}

SINT32 sc_mpf_fits_ushort(const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	return mpfr_fits_ushort_p(in, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_abs(sc_mpf_t *out, const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	mpfr_abs(out, in, MPFR_DEFAULT_ROUNDING);
#endif
}

void sc_mpf_negate(sc_mpf_t *out, const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	mpfr_neg(out, in, MPFR_DEFAULT_ROUNDING);
#endif
}

SINT32 sc_mpf_is_zero(const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	return mpfr_zero_p(in);
#endif
}

SINT32 sc_mpf_is_nan(const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	return mpfr_nan_p(in);
#endif
}

SINT32 sc_mpf_is_inf(const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	return mpfr_inf_p(in);
#endif
}

SINT32 sc_mpf_is_neg(const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	return mpfr_signbit(in);
#endif
}

SINT32 sc_mpf_sign(const sc_mpf_t *in)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
#else
	return mpfr_sgn(in);
#endif
}

void sc_mpf_add(sc_mpf_t *out, const sc_mpf_t *in1, const sc_mpf_t *in2)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
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

void sc_mpf_div_ui(sc_mpf_t *out, const sc_mpf_t *n, sc_ulimb_t d)
{
#ifdef USE_SAFECRYPTO_FLOAT_MP
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
