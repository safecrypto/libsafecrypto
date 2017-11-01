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

#include "sc_mp.h"
#include "sc_mpn.h"
#include "sc_math.h"
#include "safecrypto_private.h"
#include "safecrypto_debug.h"
#include "limb.h"


#ifdef USE_SAFECRYPTO_INTEGER_MP

sc_ulimb_t * mpz_realloc(sc_mpz_t *inout, size_t size)
{
    // Ensure that the allocated size is 1 or more
    size = SC_MAX(size, 1);

    // If memory is NOT already allocated then alloc rather than realloc
    // and set the allocated memory size accordingly
    if (inout->alloc) {
        inout->limbs = SC_REALLOC(inout->limbs, size * sizeof(sc_ulimb_t));
    }
    else {
        inout->limbs = SC_MALLOC(size * sizeof(sc_ulimb_t));
    }
    inout->alloc = size;

    // Clear the memory contents (they are now invalid) IF the used
    // memory size is greater than that allocated
    if (SC_ABS(inout->used) > size) {
        inout->used = 0;
    }

    // Return a pointer to the allocated array of limbs
    return inout->limbs;
}

void mpz_init(sc_mpz_t *inout)
{
    // No memory allocation, simply initialise to zero
    inout->alloc = 0;
    inout->used  = 0;
    inout->limbs = NULL;
}

void mpz_init_set_ui(sc_mpz_t *out, sc_ulimb_t in)
{
    // Initialise and set equal to the specific unsigned integer
    mpz_init(out);
    mpz_set_ui(out, in);
}

void mpz_init2(sc_mpz_t *inout, size_t bits)
{
    // Initialise to zero, but preallocate memory for 'bits' worth of limbs
    size_t len;
    len   = (bits + SC_LIMB_BITS - 1) >> SC_LIMB_BITS_SHIFT;

    inout->alloc = len;
    inout->used  = 0;
    inout->limbs = SC_MALLOC(len * sizeof(sc_ulimb_t));
}

void mpz_clear(sc_mpz_t *inout)
{
    // If alloc is NON-NULL then free memory resources
    if (inout->alloc) {
        free(inout->limbs);
    }
}

void mpz_swap(sc_mpz_t *a, sc_mpz_t *b)
{
    // Swap the limb pointers, used length and allocated length
    sc_ulimb_t *limbs;
    limbs    = a->limbs;
    a->limbs = b->limbs;
    b->limbs = limbs;

    b->used ^= a->used;
    a->used ^= b->used;
    b->used ^= a->used;

    b->alloc ^= a->alloc;
    a->alloc ^= b->alloc;
    b->alloc ^= a->alloc;
}

void mpz_set(sc_mpz_t *out, const sc_mpz_t *in)
{
    // If pointers are the same skip this operation
    if (out != in) {
        // Copy the limbs from in to out and set the length accordingly
        SINT32 used = SC_ABS(in->used);
        sc_ulimb_t *limbs = mpz_realloc(out, used);
        mpn_copy(limbs, in->limbs, used);
        out->used = in->used;
    }
}

void mpz_set_d(sc_mpz_t *out, DOUBLE in)
{
	SINT32 sign;
	static const DOUBLE b     = 2.0 * (DOUBLE) SC_LIMB_HIGHBIT;
	static const DOUBLE b_inv = 1.0 / (2.0 * (DOUBLE) SC_LIMB_HIGHBIT);
	sc_ulimb_t fix;
	size_t used, i;

	// Check for x is NaN, zero or infinity, set the value to zero if so
	if (in != in || in == in * 0.5) {
		out->used = 0;
		return;
	}

	// Determine the sign and obtain the absolute value of the input floating point value,
	// if less than 1 then the result is zero.
	sign = in < 0.0;
	in   = (sign)? -in : in;
	if (in < 1.0) {
		out->used = 0;
		return;
	}

	// Determine the required number of limb words required to store the result
	// and scale the input floating point value.
	for (used=1; in>=b; used++) {
		in *= b_inv;
	}

	// Resize the output MP integer
	sc_ulimb_t *limbs = mpz_realloc(out, used);

	// Iteratively expand the fractional component from most to least significant word
	i        = used - 1;
	fix      = (sc_ulimb_t) in;
	in      -= (DOUBLE) fix;
	limbs[i] = fix;
	while (i--) {
		in      *= b;
		fix      = (sc_ulimb_t) in;
		in      -= (DOUBLE) fix;
		limbs[i] = fix;
	}

	// Ensure that the output sign is correct
	out->used = (sign)? -used : used;
}

void mpz_set_ui(sc_mpz_t *out, sc_ulimb_t in)
{
    if (0 == in) {
        // If zero then simply assign a used length of zero
        out->used = 0;
    }
    else {
        // Modify the limb length to single precision and set the value
        sc_ulimb_t *limbs = mpz_realloc(out, 1);
        out->used = 1;
        limbs[0]  = in;
    }
}

void mpz_set_si(sc_mpz_t *out, sc_slimb_t in)
{
    if (in >= 0) {
        // If positive simply use the mpz_set_ui() function
        mpz_set_ui(out, in);
    }
    else {
        // If negative modify the limb length to single precision, ensure that
        // 'used' is set to -1 and cast the signed integer to unsigned
        sc_ulimb_t *limbs = mpz_realloc(out, 1);
        out->used = -1;
        limbs[0]  = SC_LIMB_FROM_NEG(in);
    }
}

void mpz_abs(sc_mpz_t *out, const sc_mpz_t *in)
{
    mpz_set(out, in);
    out->used = SC_ABS(out->used);
}

SINT32 mpz_tstbit(const sc_mpz_t *in, sc_ulimb_t bit_index)
{
    size_t idx;
    SINT32 used, abs_used;

    used     = in->used;
    abs_used = SC_ABS(used);
    idx      = bit_index >> SC_LIMB_BITS_SHIFT; // Divie the bit_index by SC_LIMB_BITS

    if (abs_used <= idx) {
        // If the bit index exceeds the number of used limb words the output
        // is the sign extended to infinity
        return used < 0;
    }
    else {
        // Determine the number of bits to shift in the word containing the bit
        // are testing to obtain the bit in the LSB position
        size_t shift = bit_index & SC_LIMB_BITS_MASK;
        size_t word  = in->limbs[idx];
        SINT32 bit   = (word >> shift) & 0x1;

        // Determine if the number is negative and the result must be modified
        // as the two's complement
        if (used < 0) {
            // There are non-zero lower order bits present in the word
            if (shift > 0 && (word << (SC_LIMB_BITS - shift)) > 0) {
                return bit ^ 1;
            }

            // There are non-zero low order bits present in lower order words
            while (idx--) {
                if (in->limbs[idx]) {
                    return bit ^ 1;
                }
            }
        }

        return bit;
    }
}

void mpz_setbit(sc_mpz_t *inout, sc_ulimb_t bit_index)
{
    // Only if the bit is currently unset then add the bit and perform
    // any carry operations
    if (0 == mpz_tstbit(inout, bit_index)) {
        sc_ulimb_t *limbs;
        size_t used, word;
        sc_ulimb_t bit;
        SINT32 sign;

        limbs = inout->limbs;
        used  = SC_ABS(inout->used);
        sign  = inout->used < 0;
        word  = bit_index >> SC_LIMB_BITS_SHIFT; // Divide the bit_index by SC_LIMB_BITS;
        bit   = (sc_ulimb_t) 1 << (bit_index & SC_LIMB_BITS_MASK);


        if (inout->used < 0) {
            // The number is negative, so subtract and recalculate the used words
            mpn_sub_1(limbs + word, limbs + word, used - word, bit);
            used = mpn_normalized_size(limbs, used);
        }
        else if (word < used) {
            // The number is zero or positive and the bit index is within range then
            // add the bit at the appropriate position and carry any bits
            sc_ulimb_t carry;
            carry = mpn_add_1(limbs + word, limbs + word, used - word, bit);
            if (carry) {
                limbs = mpz_realloc(inout, used + 1);
                limbs[used++] = carry;
            }
        }
        else {
            // The number is zero or positive and out of range so allocate more storage
            // and set the bit and zero any new bits
            size_t i;
            limbs = mpz_realloc(inout, word + 1);
            limbs[word] = bit;
            for (i=used; i<word; i++) {
                limbs[i] = 0;
            }
            used  = word + 1;
        }

        inout->used = sign? -used : used;
    }
}

DOUBLE mpz_get_d(const sc_mpz_t *in)
{
	static const DOUBLE b = 2.0 * (DOUBLE) SC_LIMB_HIGHBIT;
	SINT32 sign;
	DOUBLE res;
	SINT32 used;

	// Determine the number of limbs, if zero then terminate early
	sign  = in->used < 0;
	used  = SC_ABS(in->used);
	if (0 == used) {
		return 0.0;
	}

	// Iteratively generate the floating point equivalent
	res = in->limbs[--used];
	while (used > 0) {
		res *= b;
		res += in->limbs[--used];
	}

	// Apply the correct sign
	res = (sign)? -res : res;

	return res;
}

sc_ulimb_t mpz_get_ui(const sc_mpz_t *in)
{
    // Simply return the least significant limb, or zero for the special
    // case of a zero value as indicated bu 'used'
    return (0 == in->used)? 0 : in->limbs[0];
}

sc_ulimb_t* mpz_get_limbs(const sc_mpz_t *in)
{
    // Return a pointer to the limbs array
    return in->limbs;
}

sc_slimb_t mpz_get_si(const sc_mpz_t *in)
{
    if (in->used >= 0) {
        // If non-negative use the mpz_get_ui() function
        return (sc_slimb_t) mpz_get_ui(in);
    }
    else {
        // If negative cast back to a positive value
        sc_ulimb_t limb = in->limbs[0];
        return SC_LIMB_TO_NEG(limb);
    }
}

SINT32 mpz_cmpabs_d(const sc_mpz_t *in1, DOUBLE in2)
{
	in2 = SC_ABS(in2);

    // If in1 is non-zero 
	if (in1->used) {
		size_t i;
		SINT32 used = SC_ABS(in1->used);
		DOUBLE b = 2.0 * SC_LIMB_HIGHBIT;
		DOUBLE b_inv = 1.0 / b;

		// Scale the floating-point number using the reciprocal of the maximum value
		for (i=0; i<used; i++) {
			in2 *= b_inv;
		}

		// If the scaled double is greater than or equal to the largest integer value then
        // the result is less than
		if (in2 >= b) {
			return -1;
		}

		// From the most significant limb compare to the floor(in2) until a comparison decision
        // has been reached or we run out of MP limbs (i.e. the two values are equal)
		while (used--) {
			sc_ulimb_t floor_in2, limb;
			floor_in2 = (sc_ulimb_t) in2;
			limb = in1->limbs[used];
			if (limb > floor_in2) {
				return 1;
			}
			else if (limb < floor_in2) {
				return -1;
			}
			
			in2 = b * (in2 - floor_in2);
		}
	}

	// in1 is zero and floor(in2) is zero  -- OR --  in1 is zero
	return -(in2 > 0.0);
}

SINT32 mpz_cmpabs_ui(const sc_mpz_t *in1, sc_ulimb_t in2)
{
	if (SC_ABS(in1->used) > 1) {
		// If the multiple-precision input is larger than 1 limb in length then the comparison result is quickly output
		return 1;
	}
	else {
		// Otherwise, compare words and output 0, 1 or -1 accordingly
		sc_ulimb_t temp1 = mpz_get_ui(in1);
		return (temp1 > in2) - (temp1 < in2);
	}
}

SINT32 mpz_cmp_d(const sc_mpz_t *in1, DOUBLE in2)
{
	if (in1->used < 0) {
		if (in2 >= 0.0) {
			return -1;
		}
		else {
			// in1 and in2 are negative, so compare their absolute values and invert the sign
			// as the negative value indicates it must be less than
			return -mpz_cmpabs_d(in1, in2);
		}
	}
	else {
		if (in2 < 0.0) {
			return 1;
		}
		else {
			// Both values are greater than or equal to zero compare them directly
			return mpz_cmpabs_d(in1, in2);
		}
	}
}

SINT32 mpz_cmp_ui(const sc_mpz_t *in1, sc_ulimb_t in2)
{
    if (0 == in1->used) {
        // 'in1' is zero, so do a simple comparison of zero to 'in2'
        return (0 == in2)? 0 : (in2 < 0)? 1 : -1;
    }
	else if (in1->used > 1) {
        // 'in1' is a multiple precision positive integer, so it is larger than
		return 1;
	}
	else if (in1->used < 0) {
        // We are comparing to an unsigned number, so any negative 'in1' will be less than
		return -1;
	}
	else {
        // i.e. Both 'in1' and 'in2' are non-zero single precision positive integers
		return (in1->limbs[0] > in2) - (in1->limbs[0] < in2);
	}
}

SINT32 mpz_cmp_si(const sc_mpz_t *in1, sc_slimb_t in2)
{
	if (in1->used < -1) {
		// If in1 is a multiple-precision negative number it must be less than in2
		return -1;
	}
	else if (in2 >= 0) {
		// Use the routine to compare an unsigned integer
		return mpz_cmp_ui(in1, in2);
	}
	else if (in1->used >= 0) {
		// in2 is negative and in1 is positive or zero then the result must be greater than
		return 1;
	}
	else {
		// in1 has length of -1 and in2 is negative so compare their single precision magnitudes
		sc_ulimb_t temp1 = in1->limbs[0];
		sc_ulimb_t temp2 = SC_LIMB_FROM_NEG(in2);
		return (temp1 > temp2) - (temp1 < temp2);
	}
}

SINT32 mpz_cmpabs(const sc_mpz_t *in1, const sc_mpz_t *in2)
{
    // Compare the two limb arrays which are stored in an absolute format
	return mpn_cmp_n(in1->limbs, SC_ABS(in1->used), in2->limbs, SC_ABS(in2->used));
}

SINT32 mpz_cmp(const sc_mpz_t *in1, const sc_mpz_t *in2)
{
    // Use the 'used' parameter to quickly compare multiple precision integers of
    // different lengths, otherwise if they are both positive numbers of equal length they are
    // simply compared. If both numbers are negative and equal length then they are compared as
    // asbsolute values with the result inverted to account for the sign change.
	if (in1->used < in2->used) {
		return -1;
	}
	else if (in1->used > in2->used) {
		return 1;
	}
	else if (in1->used >= 0) {
		return mpn_cmp(in1->limbs, in2->limbs, in1->used);
	}
	else {
		return mpn_cmp(in2->limbs, in1->limbs, -in1->used);
	}
}

static size_t mpz_make_odd(sc_mpz_t *r)
{
    size_t i, shift;
    SINT32 count;
    sc_ulimb_t limb = r->limbs[0];

    // Obtain the number of trailing zeros in the MP integer
    i = 0;
    while (0 == limb) {
        i++;
        limb = r->limbs[i];
    }
    count = limb_ctz(limb);

    // Now normalise the input by right shifting the zeros away
    // making it an odd number
    shift = (size_t) i * SC_LIMB_BITS + count;
    mpz_tdiv_q_2exp(r, r, shift);

    // Return the number of normalised bits
    return shift;
}

void mpz_gcd(sc_mpz_t *g, const sc_mpz_t *u, const sc_mpz_t *v)
{
    sc_mpz_t tu, tv;
    size_t uz, vz, gz;

    // If either input is zero then the GCD is the absolute value of the other input
    if (0 == u->used) {
        mpz_abs(g, v);
        return;
    }
    if (0 == v->used) {
        mpz_abs(g, u);
        return;
    }

    // Initialise the two temporary MP variables and 
    mpz_init(&tu);
    mpz_init(&tv);

    // Normalise the absolute input variables and store in temporary storage
    mpz_abs(&tu, u);
    uz = mpz_make_odd(&tu);
    mpz_abs(&tv, v);
    vz = mpz_make_odd(&tv);

    // Obtain the minimum normalisation bit shift
    gz = SC_MIN(uz, vz);

    // Ensure that normalised u is the largest input for the following
    // division to return a non-zero result
    if (tu.used < tv.used) {
        mpz_swap(&tu, &tv);
    }

    // Obtain the remainder of N(|u|)/N(|v))
    mpz_tdiv_r(&tu, &tu, &tv);
    if (0 == tu.used){
        // If the remainder is zero then the GCD is N(|v|), pre-scaled by gz
        mpz_swap(g, &tv);
    }
    else {
        // Iteratively update the remainder until it is zero or
        // the denominator is single-precision
        while (1) {
            SINT32 c;

            mpz_make_odd(&tu);
            c = mpz_cmp(&tu, &tv);
            if (0 == c) {
                mpz_swap(g, &tu);
                break;
            }
            if (c < 0) {
                mpz_swap(&tu, &tv);
            }

            if (1 == tv.used) {
                sc_ulimb_t vl = tv.limbs[0];
                sc_ulimb_t ul = mpz_tdiv_ui(&tu, vl);
                mpz_set_ui(g, limb_gcd(ul, vl));
                break;
            }
            mpz_sub(&tu, &tu, &tv);
        }
    }

    // Free memory resources
    mpz_clear(&tu);
    mpz_clear(&tv);

    // Scale the GCD result by gz bits
    mpz_mul_2exp(g, g, gz);
}

void mpz_gcdext(sc_mpz_t *out, sc_mpz_t *s, sc_mpz_t *t, const sc_mpz_t *u, const sc_mpz_t *v)
{
    sc_mpz_t tu, tv, s0, s1, t0, t1;
    size_t uz, vz, gz;
    size_t power;

    if (0 == u->used) {
        // GCD = 0.u + sgn(v).v
        SINT32 sign = mpz_sgn(v);
        mpz_abs (out, v);
        if (s) {
            mpz_set_ui(s, 0);
        }
        if (t) {
            mpz_set_si(t, sign);
        }
        return;
    }

    if (0 == v->used) {
        // GCD = sgn(u).u + 0.v
        SINT32 sign = mpz_sgn(u);
        mpz_abs (out, u);
        if (s) {
            mpz_set_si(s, sign);
        }
        if (t) {
            mpz_set_ui(t, 0);
        }
        return;
    }

    // Initialise the temporary MP variables and 
    mpz_init(&tu);
    mpz_init(&tv);
    mpz_init(&s0);
    mpz_init(&s1);
    mpz_init(&t0);
    mpz_init(&t1);

    // Normalise the absolute input variables and store in temporary storage
    mpz_abs(&tu, u);
    uz = mpz_make_odd(&tu);
    mpz_abs(&tv, v);
    vz = mpz_make_odd(&tv);
    gz = SC_MIN(uz, vz);
    uz -= gz;
    vz -= gz;

    // Cofactors corresponding to odd gcd
    if (tu.used < tv.used) {
        mpz_swap(&tu, &tv);

        const sc_mpz_t *temp1 = u;
        u = v;
        v = temp1;
        sc_mpz_t *temp2 = s;
        s = t;
        t = temp2;
        size_t temp3 = uz;
        uz = vz;
        vz = temp3;
    }
  
    // u = t0.tu + t1.tv, v = s0.tu + s1.tv
    //
    // tu = q.tv + tu', tu and tv are scaled by uz and vz bits respectively.
    //   => u = 2^uz (tu' + q.tv) and v = 2^vz tv
    //
    // So we must initialise the variables as follows:
    //   t0 = 2^uz, t1 = 2^uz.q, s0 = 0, s1 = 2^vz
    mpz_setbit(&t0, uz);
    mpz_tdiv_qr(&t1, &tu, &tu, &tv);
    mpz_mul_2exp(&t1, &t1, uz);
    mpz_setbit(&s1, vz);
    power = uz + vz;

    if (tu.used > 0) {
        size_t shift;
        shift = mpz_make_odd(&tu);
        mpz_mul_2exp(&t0, &t0, shift);
        mpz_mul_2exp(&s0, &s0, shift);
        power += shift;
  
        while (1) {
            SINT32 c;
            sc_mpz_t *ip0, *ip1, *sp0, *sp1, *tp0, *tp1;

            c = mpz_cmp(&tu, &tv);
            if (c == 0)
                break;
  
            if (c < 0) {
                ip0 = &tv;
                ip1 = &tu;
                sp0 = &s1;
                sp1 = &s0;
                tp0 = &t1;
                tp1 = &t0;
            }
            else {
                ip0 = &tu;
                ip1 = &tv;
                sp0 = &s0;
                sp1 = &s1;
                tp0 = &t0;
                tp1 = &t1;
            }

            mpz_sub(ip0, ip0, ip1);
            mpz_add(tp1, tp0, tp1);
            mpz_add(sp1, sp0, sp1);
  
            shift = mpz_make_odd(ip0);
            mpz_mul_2exp(tp0, tp0, shift);
            mpz_mul_2exp(sp0, sp0, shift);

            power += shift;
        }
    }

    // Now tv = odd part of gcd, and -s0 and t0 are corresponding
    // cofactors
    mpz_mul_2exp(&tv, &tv, gz);
    mpz_neg(&s0, &s0);
  
    // 2^p g = s0 u + t0 v. Eliminate one factor of two at a time. To
    // adjust cofactors, we need u / g and v / g
    mpz_divexact(&s1, v, &tv);
    mpz_abs(&s1, &s1);
    mpz_divexact(&t1, u, &tv);
    mpz_abs(&t1, &t1);

    while (power-- > 0) {
        // s0 u + t0 v = (s0 - v/g) u - (t0 + u/g) v
        if ((s0.used? 1 & s0.limbs[0] : 0) || (t0.used? 1 & t0.limbs[0] : 0)) {
            mpz_sub(&s0, &s0, &s1);
            mpz_add(&t0, &t0, &t1);
        }
        mpz_divexact_ui(&s0, &s0, 2);
        mpz_divexact_ui(&t0, &t0, 2);
    }

    // Arrange so that |s| < |u| / 2g
    mpz_add(&s1, &s0, &s1);
    if (mpz_cmpabs(&s0, &s1) > 0) {
        mpz_swap(&s0, &s1);
        mpz_sub(&t0, &t0, &t1);
    }
    if (u->used < 0) {
        mpz_neg(&s0, &s0);
    }
    if (v->used < 0) {
        mpz_neg(&t0, &t0);
    }
  
    mpz_swap(out, &tv);
    if (s) {
        mpz_swap(s, &s0);
    }
    if (t) {
        mpz_swap(t, &t0);
    }

    mpz_clear(&tu);
    mpz_clear(&tv);
    mpz_clear(&s0);
    mpz_clear(&s1);
    mpz_clear(&t0);
    mpz_clear(&t1);
}

SINT32 mpz_sgn (const sc_mpz_t *in)
{
    // Return -1 less than zero, +1 if greater than zero and zero otherwise
    return (in->used > 0) - (in->used < 0);
}

SINT32 mpz_fits_slong_p (const sc_mpz_t *in)
{
    /// Return 1 if the MP integer is single precision
    if (in->used == 1) {
        // If positive it must be less than 1 << (SC_LIMB_BITS - 1)
        return in->limbs[0] < SC_LIMB_HIGHBIT;
    }
    else if (in->used == -1) {
        // If negative it must be less than or equal to 1 << SC_LIMB_BITS (the
        // maximum negative magnitude)
        return in->limbs[0] <= SC_LIMB_HIGHBIT;
    }

    // We only need to check if used indicates a 0 value and return a 1
    return 0 == in->used;
}

void mpz_neg(sc_mpz_t *out, const sc_mpz_t *in)
{
    if (in != out) {
	   mpz_set(out, in);
    }
	out->used = -out->used;
}

SINT32 mpz_invert(sc_mpz_t *out, const sc_mpz_t *in, const sc_mpz_t *mod)
{
    // Calculate the modular multiplicative inverse using the Extended Euclidean algorithm
	SINT32 inverse_exists;
	sc_mpz_t gcd, x;

    // If we try to invert zero or the modulus is 0 the result is indeterminate
	if (0 == in->used || 0 == mod->used) {
		return 0;
	}

	mpz_init(&gcd);
	mpz_init(&x);

    // Calculate XGCD(in, mod), the GCD must be 1 for an inverse to exist
	mpz_gcdext(&gcd, &x, NULL, in, mod);
	inverse_exists = 1 == mpz_get_ui(&gcd);

    // If an inverse exists we use the Bezout coefficient to calculate it
	if (inverse_exists) {
        // i.e. ax + my = gcd(a,m) = 1
        //   => ax + my = 1
        //      ax - 1 = (-y)m
        //      ax = 1 mod m, where x is the modular multiplicative inverse of a

        // If the inverse is negative the absolute value of the modulus is added
		if (x.used < 0) {
			if (mod->used >= 0) {
				mpz_add(&x, &x, mod);
			}
			else {
				mpz_sub(&x, &x, mod);
			}
		}
        mpz_swap(out, &x);
	}

	mpz_clear(&gcd);
	mpz_clear(&x);
	return inverse_exists;
}

// NOTE: This function only modifies the limbs of 'out'
static SINT32 mpz_abs_add(sc_mpz_t *out, const sc_mpz_t *in1, const sc_mpz_t *in2)
{
	SINT32 in1_used = SC_ABS(in1->used);
	SINT32 in2_used = SC_ABS(in2->used);

    // 'in1' must be greater than 'in2' for the mpn_add() function, so swap if appropriate
	if (in1_used < in2_used) {
		const sc_mpz_t *temp = in1;
		in1 = in2;
		in2 = temp;
		in1_used ^= in2_used;
		in2_used ^= in1_used;
		in1_used ^= in2_used;
	}

    // Ensure that 'out' has sufficient limbs and calculate the result accounting for the carry
    // returned by mpn_add().
	sc_ulimb_t *limbs = mpz_realloc(out, in1_used + 1);
	sc_ulimb_t  carry = mpn_add(limbs, in1->limbs, in1_used, in2->limbs, in2_used);
	limbs[in1_used] = carry;

    // Return the length of the result
	return in1_used + carry;
}

// NOTE: This function only modifies the limbs of 'out'
static SINT32 mpz_abs_sub(sc_mpz_t *out, const sc_mpz_t *in1, const sc_mpz_t *in2)
{
    // Determine relative absolute sizes of the inputs
	SINT32 in1_used = SC_ABS(in1->used);
	SINT32 in2_used = SC_ABS(in2->used);
	SINT32 cmp = mpn_cmp_n(in1->limbs, in1_used, in2->limbs, in2_used);

    if (0 == cmp) {
        // If identical the result is zero and a length of 0 is returned
        return 0;
    }
	else if (cmp > 0) {
        // If 'in1' is larger than 'in2' resize the output and subtract 'in2' from 'in1'
		sc_ulimb_t *limbs = mpz_realloc(out, in1_used);
        mpn_sub(limbs, in1->limbs, in1_used, in2->limbs, in2_used);
		return mpn_normalized_size(limbs, in1_used);
	}
	else if (cmp < 0) {
        // If 'in2' is larger than 'in1' resize the output and subtract 'in1' from 'in2'
		sc_ulimb_t *limbs = mpz_realloc(out, in2_used);
        mpn_sub(limbs, in2->limbs, in2_used, in1->limbs, in1_used);
		return -mpn_normalized_size(limbs, in2_used);
	}
}

// NOTE: This function only modifies the limbs of 'out'
static SINT32 mpz_abs_add_ui(sc_mpz_t *out, const sc_mpz_t *in1, sc_ulimb_t in2)
{
    sc_ulimb_t carry;
    sc_ulimb_t *limbs;

    // If 'in1' is zero the output is set to 'in2' and the length is returned
    SINT32 used = SC_ABS(in1->used);
    if (0 == used) {
        limbs = mpz_realloc(out, 1);
        limbs[0] = in2;
        return in2 > 0;
    }

    // The output is extended by one limb and an addition with carry is performed
    limbs = mpz_realloc(out, used + 1);
    carry = mpn_add_1(limbs, in1->limbs, used, in2);
    limbs[used] = carry;
    return used + carry;
}

// NOTE: This function only modifies the limbs of 'out'
static SINT32 mpz_abs_sub_ui(sc_mpz_t *out, const sc_mpz_t *in1, sc_ulimb_t in2)
{
    sc_ulimb_t *limbs;
    SINT32 used = SC_ABS(in1->used);

    // If 'in1' is zero the output is set to 'in2' and the length is returned
    if (0 == used) {
        limbs = mpz_realloc(out, 1);
        limbs[0] = in2;
        return -(in2 > 0);
    }

    // If 'in1' is single precision and less than in2 we calculate in2 - in1,
    // otherwise we resort to using mpn_sub_1()
    limbs = mpz_realloc(out, used);
    if (1 == used && in1->limbs[0] < in2) {
        limbs[0] = in2 - in1->limbs[0];
        return -1;
    }
    else {
        mpn_sub_1(limbs, in1->limbs, used, in2);
        return mpn_normalized_size(limbs, used);;
    }
}

void mpz_add(sc_mpz_t *out, const sc_mpz_t *in1, const sc_mpz_t *in2)
{
    SINT32 used;
	if (0 <= (in1->used ^ in2->used)) {
		used = mpz_abs_add(out, in1, in2);
	}
	else {
		used = mpz_abs_sub(out, in1, in2);
	}
    out->used = (in1->used >= 0)? used : -used;
}

void mpz_sub(sc_mpz_t *out, const sc_mpz_t *in1, const sc_mpz_t *in2)
{
    SINT32 used;
	if (0 <= (in1->used ^ in2->used)) {
		used = mpz_abs_sub(out, in1, in2);
	}
	else {
		used = mpz_abs_add(out, in1, in2);
	}
    out->used = (in1->used >= 0)? used : -used;
}

void mpz_add_ui(sc_mpz_t *out, const sc_mpz_t *in1, sc_ulimb_t in2)
{
    if (in1->used >= 0) {
        out->used = mpz_abs_add_ui(out, in1, in2);
    }
    else {
        out->used = -mpz_abs_sub_ui(out, in1, in2);
    }
}

void mpz_sub_ui(sc_mpz_t *out, const sc_mpz_t *in1, sc_ulimb_t in2)
{
    if (in1->used >= 0) {
        out->used = mpz_abs_sub_ui(out, in1, in2);
    }
    else {
        out->used = -mpz_abs_add_ui(out, in1, in2);
    }
}

static sc_ulimb_t mpz_div_q_2exp(sc_mpz_t *q, const sc_mpz_t *n,
    sc_ulimb_t b, round_mode_e mode)
{
    SINT32 q_used, n_used, used;
    SINT32 rounding = 0;

    // If the numerator is 0 then we terminate early
    n_used = n->used;
    if (0 == n_used) {
        q->used = 0;
        return 0;
    }

    used    = b >> SC_LIMB_BITS_SHIFT;
    q_used  = SC_ABS(n_used) - used;
    b      &= SC_LIMB_BITS_MASK;

    if (mode == ((n_used > 0)? SC_ROUND_CEIL : SC_ROUND_FLOOR)) {
        rounding  = q_used <= 0;                              // Divisor is larger than numerator
        rounding |= 0 != mpn_normalized_size(n->limbs, used); // Normalised numerator is larger than 0 in length
        rounding |= n->limbs[used] & ((1 << b) - 1);          // most significant word of numerator is non-zero
    }

    // If q_used less than or equal to zero then the quotient is zero,
    // otherwise we resize the 'out' limbs and shift the numerator by
    // "used*SC_LIMB_BITS + b" bits
    if (q_used <= 0) {
        q_used = 0;
    }
    else {
        sc_ulimb_t *q_limbs = mpz_realloc(q, q_used);
        if (0 != b) {
            // Shifting of bits within words is necessary, so use mpn_rshift()
            // and decrement the quotient length if the most significant limb is zero
            mpn_rshift(q_limbs, n->limbs + used, q_used, b);
            q_used -= 0 == q_limbs[q_used - 1];
        }
        else {
            // SHifting by an exact number of limbs so simply copy
            mpn_copy(q_limbs, n->limbs + used, q_used);
        }
    }

    // Set the final quotient result by rounding and negating as necessary
    q->used = q_used;
    if (rounding) {
        mpz_add_ui(q, q, 1);
    }
    if (n_used < 0) {
        mpz_neg(q, q);
    }

    return (q_used > 1) || (q_used == 1 && q->limbs[0]);
}

static void mpz_div_r_2exp(sc_mpz_t *r, const sc_mpz_t *n,
    sc_ulimb_t b, round_mode_e mode)
{
    SINT32 r_used, n_used, used;
    SINT32 adjust = 0;
    sc_ulimb_t mask;
    sc_ulimb_t *r_limbs;

    // If the numerator is 0 then we terminate early
    n_used = n->used;
    if (0 == n_used || 0 == b) {
        r->used = 0;
        return;
    }

    r_used  = (b + SC_LIMB_BITS - 1) >> SC_LIMB_BITS_SHIFT;
    r_limbs = mpz_realloc(r, r_used);
    n_used  = SC_ABS(n_used);
    mask    = SC_LIMB_UMAX >> (r_used * SC_LIMB_BITS - b);

    if (r_used > n_used) {
        // Negate the numerator if it is non-zero, otherwise copy it
        if (mode == ((n->used > 0)? SC_ROUND_CEIL : SC_ROUND_FLOOR)) {
            size_t i;
            sc_ulimb_t carry = 1;
            for (i=0; i<n_used; i++) {
                sc_ulimb_t temp = ~n->limbs[i] + carry;
                r->limbs[i] = temp;
                carry = temp < carry;
            }

            // Sign extend the most significant limbs
            for (;i<r_used - 1; i++) {
                r->limbs[i] = SC_LIMB_MASK;
            }
            r->limbs[r_used - 1] = mask;
            n_used = -n->used;
        }
        else {
            // The remainder is equal to the numberator with the 
            if (r != n) {
                mpn_copy(r->limbs, n->limbs, n_used);
                r_used = n_used;
            }
        }
    }
    else {
        // The remainder is equal to the numberator with the 
        if (r != n) {
            mpn_copy(r->limbs, n->limbs, r_used - 1);
        }

        // Zero the most significant bits of the most significant limb of the remainder
        r->limbs[r_used - 1] = n->limbs[r_used - 1] & mask;

        if (mode == ((n->used > 0)? SC_ROUND_CEIL : SC_ROUND_FLOOR)) {
            size_t i;
            for (i=0; i<r_used && 0 == r->limbs[i]; i++) {
            }

            if (i < r_used) {
                r->limbs[i] = ~r->limbs[i] + 1;
                while (++i < r_used) {
                    r->limbs[i] = ~r->limbs[i];
                }
                r->limbs[r_used-1] &= mask;
                n_used = -n->used;
            }

        }
    }

    r_used  = mpn_normalized_size(r->limbs, r_used);
    r->used = (n_used > 0)? r_used : -r_used;

    return;
}

static sc_ulimb_t mpz_div_qr(sc_mpz_t *q, sc_mpz_t *r, const sc_mpz_t *n,
    const sc_mpz_t *d, round_mode_e mode)
{
    SINT32 n_used = n->used;
    SINT32 d_used = d->used;
    SINT32 q_sign, r_used;
    sc_ulimb_t r_lsw;

    // Check for divide by zero
    if (0 == d_used) {
        return 0;
    }

    // Check for a single precision divisor that is a power of 2
    if (1 == d_used && !(d->limbs[0] & (d->limbs[0] - 1))) {
        sc_mpz_t temp;
        sc_ulimb_t retval = 0;
        SINT32 ctz;
        ctz    = limb_ctz(d->limbs[0]);
        if (q) {
            retval = mpz_div_q_2exp(q, n, ctz, mode);
        }
        if (r) {
            mpz_div_r_2exp(r, n, ctz, mode);
        }
        return retval;
    }

    // If the numerator is zero set the output quotient and remainder to zero
    // and return 0 to indicate a zero remainder
    if (0 == n_used) {
        if (q) {
            q->used = 0;
        }
        if (r) {
            r->used = 0;
        }
        return 0;
    }

    // Allocate memory for the quotient if necessary
    q_sign = d_used ^ n_used;
    d_used = SC_ABS(d_used);
    n_used = SC_ABS(n_used);

    // If the numerator used length is less than the denominator then quickly
    // compute the quotient and remainder
    if (n_used < d_used) {
        if (SC_ROUND_FLOOR == mode && q_sign < 0) {
            // Round down required
            if (r) {
                mpz_add(r, n, d);   // r = n + d, where n and d have opposing signs
            }
            if (q) {
                mpz_set_si(q, -1);
            }
        }
        else if (SC_ROUND_CEIL == mode && q_sign >= 0) {
            // Round up required
            if (r) {
                mpz_sub(r, n, d);   // r = n - d, where n and d have the same sign
            }
            if (q) {
                mpz_set_si(q, 1);
            }
        }
        else {
            // Normal truncation
            if (r) {
                mpz_set(r, n);
            }
            if (q) {
                mpz_set_si(q, 0);
            }
        }

        // Return a non-zero remainder
        return 1;
    }
    else {
        SINT32 q_used, r_used;
        sc_ulimb_t *q_limbs, *n_limbs, *d_limbs;
        sc_mpz_t temp_r, temp_q;

        // Initialise the temporary remainder and commonly used variables
        mpz_init(&temp_r);
        mpz_set(&temp_r, n);
        n_limbs = temp_r.limbs;
        d_limbs = d->limbs;
        q_used  = n_used - d_used + 1;

        // Create a pointer to the quotient data
        if (q) {
            mpz_init2(&temp_q, q_used * SC_LIMB_BITS);
            q_limbs = temp_q.limbs;
        }
        else {
            q_limbs = NULL;
        }

        // Obtain the quotient
        mpn_div_qr(q_limbs, n_limbs, n_used, d_limbs, d_used);

        // Compensate for the most significant limb being zero and set the size
        // of the output quotient and the remainder
        if (q_limbs) {
            q_used -= q_limbs[q_used - 1] == 0;
            temp_q.used = (q_sign < 0)? -q_used : q_used;
        }
        r_used = mpn_normalized_size(n_limbs, d_used);
        temp_r.used = (n->used < 0)? -r_used : r_used;

        // Rounding
        if (0 != r_used) {
            if (SC_ROUND_FLOOR == mode && q_sign < 0) {
                // Round down required
                if (r) {
                    mpz_add(&temp_r, &temp_r, d);
                }
                if (q) {
                    mpz_sub_ui(&temp_q, &temp_q, 1);
                }
            }
            else if (SC_ROUND_CEIL == mode && q_sign >= 0) {
                // Round up required
                if (r) {
                    mpz_sub(&temp_r, &temp_r, d);
                }
                if (q) {
                    mpz_add_ui(&temp_q, &temp_q, 1);
                }
            }
        }

        if (q) {
            mpz_swap(&temp_q, q);
            mpz_clear(&temp_q);
        }
        if (r) {
            mpz_swap(&temp_r, r);
        }
        mpz_clear(&temp_r);

        return 0 != r_used;
    }
}

static sc_ulimb_t mpz_div_qr_ui(sc_mpz_t *q, sc_mpz_t *r, const sc_mpz_t *n,
    sc_ulimb_t d, round_mode_e mode)
{
    SINT32 n_used = n->used;
    SINT32 q_used, r_used;
    sc_ulimb_t *q_limbs;
    sc_ulimb_t *n_limbs;
    sc_ulimb_t r_lsw;

    // If the numerator is zero set the output quotient and remainder to zero
    // and return 0
    if (0 == n_used) {
        if (q) {
            q->used = 0;
        }
        if (r) {
            r->used = 0;
        }
        return 0;
    }

    // Allocate memory for the quotient if necessary
    q_used = SC_ABS(n_used);
    if (q) {
        q_limbs = mpz_realloc(q, q_used);
    }
    else {
        q_limbs = NULL;
    }

    // Obtain the result of q / d
    n_limbs = n->limbs;
    r_lsw   = mpn_div_qr_1(q_limbs, n_limbs, q_used, d);
    r_used  = r_lsw > 0;
    r_used  = (n_used < 0)? -r_used : r_used;

    // If q/d is non-zero then apply rounding
    if (r_lsw > 0) {
        if ((SC_ROUND_FLOOR == mode && n_used  < 0) ||
            (SC_ROUND_CEIL  == mode && n_used >= 0)) {
            if (q) {
                mpn_add_1(q_limbs, q_limbs, q_used, 1);
            }
            r_lsw = d - r_lsw;
            r_used = -r_used;
        }
    }

    // If a remainder is to be output then (re)allocate memory and configure
    // the LSW and length for a single output word
    if (r) {
        mpz_realloc(r, 1);
        r->limbs[0] = r_lsw;
        r->used     = r_used;
    }

    // a quotient is to be output then update the used length
    if (q) {
        q_used  -= (0 == q_limbs[q_used-1]);
        q->used  = (n_used < 0)? -q_used : q_used;
    }

    return r_lsw;
}

sc_ulimb_t mpz_fdiv_qr(sc_mpz_t *q, sc_mpz_t *r,
    const sc_mpz_t *n, const sc_mpz_t *d)
{
    return mpz_div_qr(q, r, n, d, SC_ROUND_FLOOR);
}

sc_ulimb_t mpz_tdiv_qr(sc_mpz_t *q, sc_mpz_t *r,
    const sc_mpz_t *n, const sc_mpz_t *d)
{
    return mpz_div_qr(q, r, n, d, SC_ROUND_TRUNC);
}

sc_ulimb_t mpz_fdiv_q(sc_mpz_t *q,
    const sc_mpz_t *n, const sc_mpz_t *d)
{
    return mpz_div_qr(q, NULL, n, d, SC_ROUND_FLOOR);
}

sc_ulimb_t mpz_tdiv_q(sc_mpz_t *q,
    const sc_mpz_t *n, const sc_mpz_t *d)
{
    return mpz_div_qr(q, NULL, n, d, SC_ROUND_TRUNC);
}

sc_ulimb_t mpz_fdiv_r(sc_mpz_t *r,
    const sc_mpz_t *n, const sc_mpz_t *d)
{
    return mpz_div_qr(NULL, r, n, d, SC_ROUND_FLOOR);
}

sc_ulimb_t mpz_tdiv_r(sc_mpz_t *r,
    const sc_mpz_t *n, const sc_mpz_t *d)
{
    return mpz_div_qr(NULL, r, n, d, SC_ROUND_TRUNC);
}

sc_ulimb_t mpz_fdiv_qr_ui(sc_mpz_t *q, sc_mpz_t *r,
    const sc_mpz_t *n, sc_ulimb_t d)
{
    return mpz_div_qr_ui(q, r, n, d, SC_ROUND_FLOOR);
}

sc_ulimb_t mpz_fdiv_q_ui(sc_mpz_t *q,
    const sc_mpz_t *n, sc_ulimb_t d)
{
    return mpz_div_qr_ui(q, NULL, n, d, SC_ROUND_FLOOR);
}

sc_ulimb_t mpz_fdiv_r_ui(sc_mpz_t *r,
    const sc_mpz_t *n, sc_ulimb_t d)
{
    return mpz_div_qr_ui(NULL, r, n, d, SC_ROUND_FLOOR);
}

sc_ulimb_t mpz_tdiv_q_2exp(sc_mpz_t *q, const sc_mpz_t *n, sc_ulimb_t b)
{
    mpz_div_q_2exp(q, n, b, SC_ROUND_TRUNC);   // TRUNC(n/(2^b))
}

sc_ulimb_t mpz_cdiv_ui(const sc_mpz_t *n, sc_ulimb_t d)
{
    return mpz_div_qr_ui(NULL, NULL, n, d, SC_ROUND_CEIL);
}

sc_ulimb_t mpz_fdiv_ui(const sc_mpz_t *n, sc_ulimb_t d)
{
    return mpz_div_qr_ui(NULL, NULL, n, d, SC_ROUND_FLOOR);
}

sc_ulimb_t mpz_tdiv_ui(const sc_mpz_t *n, sc_ulimb_t d)
{
    return mpz_div_qr_ui(NULL, NULL, n, d, SC_ROUND_TRUNC);
}

void mpz_divexact(sc_mpz_t *q, const sc_mpz_t *n, const sc_mpz_t *d)
{
    mpz_div_qr(q, NULL, n, d, SC_ROUND_TRUNC);
}

void mpz_divexact_ui(sc_mpz_t *q, const sc_mpz_t *n, sc_ulimb_t d)
{
    mpz_div_qr_ui(q, NULL, n, d, SC_ROUND_TRUNC);
}

void mpz_addmul_ui(sc_mpz_t *out, const sc_mpz_t *in1, sc_ulimb_t in2)
{
	sc_mpz_t temp;
	mpz_init(&temp);
	mpz_mul_ui(&temp, in1, in2);
	mpz_add(out, out, &temp);
	mpz_clear(&temp);
}

void mpz_submul_ui(sc_mpz_t *out, const sc_mpz_t *in1, sc_ulimb_t in2)
{
	sc_mpz_t temp;
	mpz_init(&temp);
	mpz_mul_ui(&temp, in1, in2);
	mpz_sub(out, out, &temp);
	mpz_clear(&temp);
}

void mpz_addmul(sc_mpz_t *out, const sc_mpz_t *in1, const sc_mpz_t *in2)
{
	sc_mpz_t temp;
	mpz_init(&temp);
	mpz_mul(&temp, in1, in2);
	mpz_add(out, out, &temp);
	mpz_clear(&temp);
}

void mpz_submul(sc_mpz_t *out, const sc_mpz_t *in1, const sc_mpz_t *in2)
{
	sc_mpz_t temp;
	mpz_init(&temp);
	mpz_mul(&temp, in1, in2);
	mpz_sub(out, out, &temp);
	mpz_clear(&temp);
}

void mpz_mul_ui(sc_mpz_t *out, const sc_mpz_t *in1, sc_ulimb_t in2)
{
	SINT32 in1_used;
	sc_mpz_t temp;
	sc_ulimb_t carry;
    sc_ulimb_t *limbs;

    // If either operand is zero the result is zero
	in1_used = in1->used;
	if (0 == in1_used || 0 == in2) {
		out->used = 0;
		return;
	}

	in1_used = SC_ABS(in1_used);

    // Resize the 'out' limbs, perform a multiply using mpn_mul_1() and
    // remember to assign the carry to the most significant limb
	limbs    = mpz_realloc(out, in1_used + 1);
	carry    = mpn_mul_1(limbs, in1->limbs, in1_used, in2);
	limbs[in1_used] = carry;

    // Increment the output length if the carry is non-zero and set the
    // appropriate sign
	in1_used += (carry > 0);
	out->used = (in1->used < 0)? -in1_used : in1_used;
}

void mpz_mul_si(sc_mpz_t *out, const sc_mpz_t *in1, sc_slimb_t in2)
{
	if (in2 < 0) {
		mpz_mul_ui(out, in1, SC_LIMB_FROM_NEG(in2));
		mpz_neg(out, out);
	}
	else {
		mpz_mul_ui(out, in1, in2);
	}
}

void mpz_mul_2exp(sc_mpz_t *out, const sc_mpz_t *in, size_t bits)
{
    size_t in_used, out_used;
    size_t sh_words;
    UINT32 sh_bits;
    sc_ulimb_t *limbs;
  
    in_used = SC_ABS(in->used);
    if (0 == in_used) {
        out->used = 0;
        return;
    }
    
    // This multiply corresponds to a left shift by 'bits', so determine the number of
    // words and bits to shift
    sh_words = bits >> SC_LIMB_BITS_SHIFT; // Divide by SC_LIMB_BITS;
    sh_bits = bits & SC_LIMB_BITS_MASK;    // Modulo SC_LIMB)BITS
  
    // The output length will be incremented by (bits + SC_LIMB_BITS - 1) / SC_LIMB_BITS,
    // so resize the limbs array appropriately
    out_used = in_used + sh_words + (sh_bits > 0);
    limbs = mpz_realloc(out, out_used);

    if (sh_bits > 0) {
        // If sh_bits is non-zero bits must be shifted between limbs
        sc_ulimb_t carry;
        carry             = mpn_lshift(limbs + sh_words, in->limbs, in_used, sh_bits);
        limbs[out_used-1] = carry;
        out_used         -= (0 == carry);
    }
    else {
        // sh_bits is zero therefore a copy is sufficient to perform the shift
        mpn_copy(limbs + sh_words, in->limbs, in_used);
    }
    
    // The least significant words of the output must be zeroed
    mpn_zero(limbs, sh_words);

    // Set the output length with the same sign as the input
    out->used = (in->used < 0) ? -out_used : out_used;
}

void mpz_mul(sc_mpz_t *out, const sc_mpz_t *in1, const sc_mpz_t *in2)
{
	SINT32 in1_used, in2_used, sign;
	sc_mpz_t temp;

    // If either operand is zero the result is zero
	in1_used = in1->used;
	in2_used = in2->used;
	if (0 == in1_used || 0 == in2_used) {
		out->used = 0;
		return;
	}
	sign = (in1_used ^ in2_used) < 0;

	in1_used = SC_ABS(in1_used);
	in2_used = SC_ABS(in2_used);

    // Preallocate an intermediate output with appropriate bit length for the product.
    // Ensure that the first operand is larger than the second for mpn_mul() to
    // operate correctly.
	mpz_init2(&temp, (in1_used + in2_used) * SC_LIMB_BITS);
	if (in1_used >= in2_used) {
		mpn_mul(temp.limbs, in1->limbs, in1_used, in2->limbs, in2_used);
	}
	else {
		mpn_mul(temp.limbs, in2->limbs, in2_used, in1->limbs, in1_used);
	}

    // Set the output length and sign as appropriate, swapping the output sc_mpz_t struct
    // for the intermediate value and discarding it.
	temp.used = in1_used + in2_used	- (0 == temp.limbs[in1_used + in2_used - 1]);
	if (sign) {
		temp.used = -temp.used;
	}
	mpz_swap(out, &temp);
	mpz_clear(&temp);
}

void mpz_pow_ui(sc_mpz_t *r, const sc_mpz_t *b, sc_ulimb_t e)
{
    sc_ulimb_t bit = SC_LIMB_HIGHBIT >> limb_clz(e);
    sc_mpz_t tr;
    mpz_init_set_ui(&tr, 1);
 
    // Square-and-multiply exponentiation by scanning the exponent
    // from right to left
    do {
        mpz_mul(&tr, &tr, &tr);
        if (e & bit) {
            mpz_mul(&tr, &tr, b);
        }
        bit >>= 1;
    } while (bit > 0);
  
    mpz_swap(r, &tr);
    mpz_clear(&tr);
}

size_t mpz_sizeinbase(const sc_mpz_t *in, SINT32 base)
{
    size_t bits;
    SINT32 used;

    used = SC_ABS(in->used);

    // Terminte early with a 1-bit zero value
    if (0 == used) {
        return 1;
    }

    bits  = (used - 1) * SC_LIMB_BITS + (SC_LIMB_BITS - limb_clz(in->limbs[used - 1]));

    switch (base)
    {
    case  2: return bits;            // break not needed
    case  4: return (bits + 1) >> 1; // break not needed
#if 1
    case  8: return ((bits + 2) * 0x55555556) >> 32; // break not needed
    case 16: return (bits + 3) >> 2; // break not needed
    case 32: return ((bits + 4) * 0x33333333) >> 32; // break not needed
#else
    case  8: return (bits + 2) / 3; // break not needed
    case 16: return (bits + 3) / 4; // break not needed
    case 32: return (bits + 4) / 5; // break not needed
#endif
    }

    return 0;
}

// NOTE: the square root of a negative number is indeterminate and a zero is returned
void mpz_sqrt(sc_mpz_t *out, const sc_mpz_t *in)
{
    sc_mpz_t a, b;

    // If 'in' <= 1 then return the input, this is incorrect for negative inputs
    // which are indeterminate
    if (mpz_cmp_ui(in, 1) <= 0) {
        mpz_set(out, in);
        return;
    }

    // Set a=0 and b=2^ceil(log2(in))
    mpz_init(&a);
    mpz_init(&b);
    mpz_setbit(&b, (mpz_sizeinbase(in, 2) >> 1) + 1);

    // Iteratively compute a=b, b=(a + (in/a))/2 until |b| >= |a|
    do {
        mpz_swap(&a, &b);
        mpz_tdiv_q(&b, in, &a);
        mpz_add(&b, &b, &a);
        mpz_tdiv_q_2exp(&b, &b, 1);
    } while (mpz_cmpabs(&b, &a) < 0);

    mpz_swap(out, &a);
    mpz_clear(&a);
    mpz_clear(&b);
}

sc_ulimb_t mpz_mod_ui(sc_mpz_t *out, const sc_mpz_t *in, sc_ulimb_t m)
{
    return mpz_div_qr_ui(NULL, out, in, m, SC_ROUND_FLOOR);
}

void mpz_mod(sc_mpz_t *r, const sc_mpz_t *n, const sc_mpz_t *d)
{
    mpz_div_qr(NULL, r, n, d, (d->used >= 0)? SC_ROUND_FLOOR : SC_ROUND_CEIL);
}


size_t mpz_out_str (FILE *stream, int base, const sc_mpz_t *in)
{
    char *str;
    size_t len, str_len;
    SINT32 used;
    const char ascii[] = "0123456789abcdefghijklmnopqrstuvwxyz";

    if (base < 0) {
        base = -base;
    }
    if (0 == base) {
        base = 10;
    }
    if (base > 36) {
        return 0;
    }

    len = 2 + mpz_sizeinbase(in, base);
    str = SC_MALLOC(len);

    used = SC_ABS(in->used);
    if (0 == used) {
        str[0] = '0';
        str[1] = '\0';
        str_len = 1;
    }
    else {
        size_t i = 0;
        SINT32 shift;

        // Prepend a sign character as required
        if (in->used < 0) {
            str[i++] = '-';
        }

        if (2 == base || 8 == base || 16 == base || 32 == base) {
            size_t j, k;
            size_t bitsize = (2 == base)? 1 : (8 == base)? 3 : (16 == base)? 4 : 5;
            uint8_t mask = (1 << bitsize) - 1;

            // Calculate the number of digits rounded up
            str_len = (used * SC_LIMB_BITS + bitsize - 1 - limb_clz(in->limbs[used-1])) / bitsize;

            // Iterate through all the digits from the least significant, writing to the most
            // significant characters of the output
            for (j=0, k=str_len, shift=0; k-->0;) {
                uint8_t c = in->limbs[j] >> shift;
                shift += bitsize;
                if (shift >= SC_LIMB_BITS && ++j < used) {
                    shift -= SC_LIMB_BITS;
                    c     |= in->limbs[j] << (bitsize - shift);
                }
                str[k+i] = mask & c;
            }
        }

        for (; i<str_len; i++) {
            str[i] = ascii[(uint8_t) str[i]];
        }
        str[str_len] = '\0';
    }

    fwrite(str, 1, str_len, stream);
    SC_FREE(str, str_len);
    return len;
}

#endif // USE_SAFECRYPTO_INTEGER_MP

