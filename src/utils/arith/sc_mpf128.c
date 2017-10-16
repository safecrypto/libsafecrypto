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

#include "sc_mpf128.h"


#if defined(SC_USE_GNU_MPF)

FLOAT128 sc_mpf128_mul(FLOAT128 a, FLOAT128 b)
{
	return a * b;
}

FLOAT128 sc_mpf128_div(FLOAT128 a, FLOAT128 b)
{
	return a / b;
}

FLOAT128 sc_mpf128_add(FLOAT128 a, FLOAT128 b)
{
	return a + b;
}

FLOAT128 sc_mpf128_sub(FLOAT128 a, FLOAT128 b)
{
	return a - b;
}

FLOAT128 sc_mpf128_exp(FLOAT128 x)
{
	return expq(x);
}

FLOAT128 sc_mpf128_floor(FLOAT128 x)
{
	return floorq(x);
}

FLOAT128 sc_mpf128_neg(FLOAT128 x)
{
	return -x;
}

FLOAT128 sc_mpf128_abs(FLOAT128 x)
{
	return fabsq(x);
}

FLOAT128 sc_mpf128_pow(FLOAT128 x, FLOAT128 y)
{
	return powq(x, y);
}

FLOAT128 sc_mpf128_log(FLOAT128 x)
{
	return logq(x);
}

FLOAT128 sc_mpf128_sqrt(FLOAT128 x)
{
	return sqrtq(x);
}

SINT32 sc_mpf128_cmp(FLOAT128 a, FLOAT128 b)
{
	if (a < b) {
		return -1;
	}
	else if (a > b) {
		return 1;
	}
	else {
		return 0;
	}
}

#else

sc_mpf128_t sc_2_sqrtpi_quad;
sc_mpf128_t sc_sqrt1_2_quad;

FLOAT128 sc_mpf128_mul(FLOAT128 a, FLOAT128 b)
{
	FLOAT128 flt;
	return flt;
}

FLOAT128 sc_mpf128_div(FLOAT128 a, FLOAT128 b)
{
	FLOAT128 flt;
	return flt;
}

FLOAT128 sc_mpf128_add(FLOAT128 a, FLOAT128 b)
{
	FLOAT128 flt;
	return flt;
}

FLOAT128 sc_mpf128_sub(FLOAT128 a, FLOAT128 b)
{
	FLOAT128 flt;
	return flt;
}

FLOAT128 sc_mpf128_exp(FLOAT128 x)
{
	FLOAT128 flt;
	return flt;
}

FLOAT128 sc_mpf128_floor(FLOAT128 x)
{
	FLOAT128 flt;
	return flt;
}

FLOAT128 sc_mpf128_neg(FLOAT128 x)
{
	FLOAT128 flt;
	return flt;
}

FLOAT128 sc_mpf128_abs(FLOAT128 x)
{
	FLOAT128 flt;
	return flt;
}

FLOAT128 sc_mpf128_pow(FLOAT128 x, FLOAT128 y)
{
	FLOAT128 flt;
	return flt;
}

FLOAT128 sc_mpf128_log(FLOAT128 x)
{
	FLOAT128 flt;
	return flt;
}

FLOAT128 sc_mpf128_sqrt(FLOAT128 x)
{
	FLOAT128 flt;
	return flt;
}

SINT32 sc_mpf128_cmp(FLOAT128 a, FLOAT128 b)
{
	return 0;
}

FLOAT128 sc_mpf128_convert_f32_to_f128(FLOAT x)
{
	FLOAT128 flt;
	return flt;
}

#if defined (HAVE_128BIT)
UINT128 sc_mpf128_convert_f128_to_ui128(FLOAT128 x)
{
	UINT128 res = 0;
	return res;
}
#endif

FLOAT128 sc_mpf128_convert_ui32_to_f128(UINT32 x)
{
	FLOAT128 flt;
	return flt;
}

#endif

