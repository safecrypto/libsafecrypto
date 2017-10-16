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
#include "sc_mp.h"


#ifdef USE_SAFECRYPTO_MULTIPLE_PRECISION

SINT32 mpn_cmp(const sc_ulimb_t *in1, const sc_ulimb_t *in2, size_t n);
SINT32 mpn_cmp_n(const sc_ulimb_t *in1, size_t in1_n, const sc_ulimb_t *in2, size_t in2_n);
void mpn_copy(sc_ulimb_t *out, const sc_ulimb_t *in, size_t n);
void mpn_zero(sc_ulimb_t* inout, size_t n);
void mpn_com(sc_ulimb_t* out, const sc_ulimb_t *in, size_t n);
size_t mpn_normalized_size(const sc_ulimb_t *inout, size_t n);
sc_ulimb_t mpn_lshift(sc_ulimb_t *out, const sc_ulimb_t *in, size_t n, size_t count);
sc_ulimb_t mpn_rshift(sc_ulimb_t *out, const sc_ulimb_t *in, size_t n, size_t count);
sc_ulimb_t mpn_add_1(sc_ulimb_t *out, const sc_ulimb_t *in1, size_t n, sc_ulimb_t in2);
sc_ulimb_t mpn_add_n(sc_ulimb_t *out, const sc_ulimb_t *in1, const sc_ulimb_t *in2, size_t n);
sc_ulimb_t mpn_add(sc_ulimb_t *out, const sc_ulimb_t *in1, size_t n1, const sc_ulimb_t *in2, size_t n2);
sc_ulimb_t mpn_addmul_1(sc_ulimb_t *out, const sc_ulimb_t *in1, size_t n, sc_ulimb_t in2);
sc_ulimb_t mpn_sub_1(sc_ulimb_t *out, const sc_ulimb_t *in1, size_t n, sc_ulimb_t in2);
sc_ulimb_t mpn_sub_n(sc_ulimb_t *out, const sc_ulimb_t *in1, const sc_ulimb_t *in2, size_t n);
sc_ulimb_t mpn_sub(sc_ulimb_t *out, const sc_ulimb_t *in1, size_t n1, const sc_ulimb_t *in2, size_t n2);
sc_ulimb_t mpn_submul_1(sc_ulimb_t *out, const sc_ulimb_t *in1, size_t n, sc_ulimb_t in2);
sc_ulimb_t mpn_mul_1(sc_ulimb_t *out, const sc_ulimb_t *in1, size_t n, sc_ulimb_t in2);
void mpn_mul_n(sc_ulimb_t *out, const sc_ulimb_t *in1, const sc_ulimb_t *in2, size_t n);
sc_ulimb_t mpn_mul(sc_ulimb_t *out, const sc_ulimb_t *in1, size_t in1_n, const sc_ulimb_t *in2, size_t in2_n);
sc_ulimb_t mpn_sqr(sc_ulimb_t *out, const sc_ulimb_t *in, size_t n);
void mpn_div_qr(sc_ulimb_t *q_limbs, sc_ulimb_t *n_limbs,
    size_t n, const sc_ulimb_t *d_limbs, size_t dn);
sc_ulimb_t mpn_div_qr_1(sc_ulimb_t *q_limbs, const sc_ulimb_t *n_limbs,
    size_t n, sc_ulimb_t d);
#endif

