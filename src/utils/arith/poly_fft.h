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
#include <complex.h>
#include <string.h>


typedef DOUBLE complex sc_complex_t;

SC_STRUCT_PACK_START
typedef struct sc_fft_t {
    sc_complex_t ii;
    sc_complex_t omega;
    sc_complex_t omega_1;
    size_t n;
} SC_STRUCT_PACKED sc_fft_t;
SC_STRUCT_PACK_END

sc_fft_t * create_fft(size_t n);
SINT32 destroy_fft(sc_fft_t *ctx);

SINT32 fwd_fft_int(sc_fft_t *ctx, sc_complex_t * f_fft,
    const SINT32 * const f);
SINT32 inv_fft_int(sc_fft_t *ctx, SINT32 * const f,
    sc_complex_t const * const f_fft);

SINT32 fwd_fft_flt(sc_fft_t *ctx, sc_complex_t * f_fft,
    const FLOAT * const f);
SINT32 inv_fft_flt(sc_fft_t *ctx, FLOAT * const f,
    sc_complex_t const * const f_fft);

SINT32 fwd_fft_dbl(sc_fft_t *ctx, sc_complex_t * f_fft,
    const DOUBLE * const f);
SINT32 inv_fft_dbl(sc_fft_t *ctx, DOUBLE * const f,
    sc_complex_t const * const f_fft);

SINT32 fwd_fft_long_dbl(sc_fft_t *ctx, sc_complex_t * f_fft,
    const LONGDOUBLE * const f);
SINT32 inv_fft_long_dbl(sc_fft_t *ctx, LONGDOUBLE * const f,
    sc_complex_t const * const f_fft);

