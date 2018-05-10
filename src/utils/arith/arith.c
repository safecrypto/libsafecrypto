/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
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

#include "utils/arith/arith.h"
#include "utils/crypto/prng.h"


static const utils_arith_poly_t utils_arith_poly_table = {
    poly_8_cmp_not_equal,
    poly_16_copy, poly_16_reset,
    poly_16_add_scalar, poly_16_sub_scalar, poly_16_mul_scalar,
    poly_16_add, poly_16_sub,
    poly_16_add_single, poly_16_sub_single, 
    poly_16_mul,
    poly_16_mod_negate,
    poly_16_cmp_not_equal,
    poly_16_uniform_rand,
    poly_16_degree,
    poly_32_copy, poly_32_reset,
    poly_32_add_scalar, poly_32_sub_scalar, poly_32_mul_scalar,
    poly_32_add, poly_32_sub,
    poly_32_add_single, poly_32_sub_single, 
    poly_32_mul,
    poly_32_mod_negate,
    poly_32_cmp_not_equal,
    poly_32_uniform_rand,
    poly_32_degree,
    z2_inv,
    z2_mul,
    z2_div,
    z2_mul_mod2,
    z2_conv_mod2,
    z2_uniform
};

const utils_arith_poly_t *utils_arith_poly(void)
{
    return &utils_arith_poly_table;
}


static const utils_arith_vec_t utils_arith_vec_table = {
    vecabsmax_32, vecscalar_32, vecabsmax_16, vecscalar_16
};

const utils_arith_vec_t *utils_arith_vectors(void)
{
    return &utils_arith_vec_table;
}


static const utils_arith_ntt_t utils_arith_ntt_barrett = {
    ntt32_modn_barrett, ntt32_muln_barrett, ntt32_sqrn_barrett,
    ntt32_mult_sparse_32_generic, ntt32_mult_sparse_16_generic,
    ntt32_mult_pointwise_barrett, ntt32_mult_pointwise_16_barrett, ntt32_mult_scalar_generic,
    ntt32_fft_32_barrett, ntt32_large_fft_32_barrett,
    ntt32_fft_16_barrett, ntt32_large_fft_16_barrett,
    ntt32_pwr_barrett, ntt32_invert_barrett, ntt32_div_barrett, ntt32_flip_generic,
    ntt32_center_32_barrett, ntt32_normalize_32_barrett, ntt32_center_16_barrett, ntt32_normalize_16_barrett,
    ntt32_fwd_ntt_32_barrett, ntt32_inv_ntt_32_barrett, ntt32_large_fwd_ntt_32_barrett, ntt32_large_inv_ntt_32_barrett,
    ntt32_fwd_ntt_16_barrett, ntt32_inv_ntt_16_barrett, ntt32_large_fwd_ntt_16_barrett, ntt32_large_inv_ntt_16_barrett,

    ntt_modn_barrett, ntt_muln_barrett, ntt_sqrn_barrett,
    ntt_mult_sparse_32_generic, ntt_mult_sparse_16_generic,
    ntt_mult_pointwise_barrett, ntt_mult_pointwise_32_barrett, ntt_mult_pointwise_16_barrett,
    ntt_mult_scalar_generic,
    ntt_fft_barrett, ntt_large_fft_barrett,
    ntt_fft_32_barrett, ntt_large_fft_32_barrett,
    ntt_fft_16_barrett, ntt_large_fft_16_barrett,
    ntt_pwr_barrett, ntt_invert_barrett, ntt_div_barrett, ntt_flip_generic,
    ntt_center_barrett, ntt_normalize_barrett,
    ntt_fwd_ntt_barrett,  ntt_inv_ntt_barrett,ntt_large_fwd_ntt_barrett, ntt_large_inv_ntt_barrett,
    ntt_fwd_ntt_32_barrett, ntt_inv_ntt_32_barrett, ntt_large_fwd_ntt_32_barrett, ntt_large_inv_ntt_32_barrett,
    ntt_fwd_ntt_16_barrett, ntt_inv_ntt_16_barrett, ntt_large_fwd_ntt_16_barrett, ntt_large_inv_ntt_16_barrett
};

/*static const utils_arith_ntt_t utils_arith_ntt_barrett_rev = {
    ntt32_modn_barrett_rev, ntt32_muln_barrett_rev, ntt32_sqrn_barrett_rev,
    ntt32_mult_sparse_32_generic, ntt32_mult_sparse_16_generic,
    ntt32_mult_pointwise_barrett_rev, ntt32_mult_pointwise_16_barrett_rev, ntt32_mult_scalar_generic,
    ntt32_fft_32_barrett_rev, ntt32_large_fft_32_barrett_rev,
    ntt32_fft_16_barrett_rev, ntt32_large_fft_16_barrett_rev,
    ntt32_pwr_barrett_rev, ntt32_invert_barrett_rev, ntt32_flip_generic,
    ntt32_center_32_barrett_rev, ntt32_normalize_32_barrett_rev, ntt32_center_16_barrett_rev, ntt32_normalize_16_barrett_rev,
    ntt32_fwd_ntt_32_barrett_rev, ntt32_inv_ntt_32_barrett_rev, ntt32_large_fwd_ntt_32_barrett_rev, ntt32_large_inv_ntt_32_barrett_rev,
    ntt32_fwd_ntt_16_barrett_rev, ntt32_inv_ntt_16_barrett_rev, ntt32_large_fwd_ntt_16_barrett_rev, ntt32_large_inv_ntt_16_barrett_rev,

    ntt_modn_barrett_rev, ntt_muln_barrett_rev, ntt_sqrn_barrett_rev,
    ntt_mult_sparse_32_generic, ntt_mult_sparse_16_generic,
    ntt_mult_pointwise_barrett_rev, ntt_mult_pointwise_32_barrett_rev, ntt_mult_pointwise_16_barrett_rev,
    ntt_mult_scalar_generic,
    ntt_fft_barrett_rev, ntt_large_fft_barrett_rev,
    ntt_fft_32_barrett_rev, ntt_large_fft_32_barrett_rev,
    ntt_fft_16_barrett_rev, ntt_large_fft_16_barrett_rev,
    ntt_pwr_barrett_rev, ntt_invert_barrett_rev, ntt_flip_generic,
    ntt_center_barrett_rev, ntt_normalize_barrett_rev,
    ntt_fwd_ntt_barrett_rev,  ntt_inv_ntt_barrett_rev, ntt_large_fwd_ntt_barrett_rev, ntt_large_inv_ntt_barrett_rev,
    ntt_fwd_ntt_32_barrett_rev, ntt_inv_ntt_32_barrett_rev, ntt_large_fwd_ntt_32_barrett_rev, ntt_large_inv_ntt_32_barrett_rev,
    ntt_fwd_ntt_16_barrett_rev, ntt_inv_ntt_16_barrett_rev, ntt_large_fwd_ntt_16_barrett_rev, ntt_large_inv_ntt_16_barrett_rev
};*/

static const utils_arith_ntt_t utils_arith_ntt_fp = {
    ntt32_modn_fp, ntt32_muln_fp, ntt32_sqrn_fp,
    ntt32_mult_sparse_32_generic, ntt32_mult_sparse_16_generic,
    ntt32_mult_pointwise_fp, ntt32_mult_pointwise_16_fp, ntt32_mult_scalar_generic,
    ntt32_fft_32_fp, ntt32_large_fft_32_fp,
    ntt32_fft_16_fp, ntt32_large_fft_16_fp,
    ntt32_pwr_fp, ntt32_invert_fp, ntt32_div_fp, ntt32_flip_generic,
    ntt32_center_32_fp, ntt32_normalize_32_fp, ntt32_center_16_fp, ntt32_normalize_16_fp,
    ntt32_fwd_ntt_32_fp, ntt32_inv_ntt_32_fp, ntt32_large_fwd_ntt_32_fp, ntt32_large_inv_ntt_32_fp,
    ntt32_fwd_ntt_16_fp, ntt32_inv_ntt_16_fp, ntt32_large_fwd_ntt_16_fp, ntt32_large_inv_ntt_16_fp,

    ntt_modn_fp, ntt_muln_fp, ntt_sqrn_fp,
    ntt_mult_sparse_32_generic, ntt_mult_sparse_16_generic,
    ntt_mult_pointwise_fp, ntt_mult_pointwise_32_fp, ntt_mult_pointwise_16_fp,
    ntt_mult_scalar_generic,
    ntt_fft_fp, ntt_large_fft_fp,
    ntt_fft_32_fp, ntt_large_fft_32_fp,
    ntt_fft_16_fp, ntt_large_fft_16_fp,
    ntt_pwr_fp, ntt_invert_fp, ntt_div_fp, ntt_flip_generic,
    ntt_center_fp, ntt_normalize_fp,
    ntt_fwd_ntt_fp, ntt_inv_ntt_fp, ntt_large_fwd_ntt_fp, ntt_large_inv_ntt_fp,
    ntt_fwd_ntt_32_fp, ntt_inv_ntt_32_fp, ntt_large_fwd_ntt_32_fp, ntt_large_inv_ntt_32_fp,
    ntt_fwd_ntt_16_fp, ntt_inv_ntt_16_fp, ntt_large_fwd_ntt_16_fp, ntt_large_inv_ntt_16_fp,
};

static const utils_arith_ntt_t utils_arith_ntt_reference = {
    ntt32_modn_reference, ntt32_muln_reference, ntt32_sqrn_reference,
    ntt32_mult_sparse_32_generic, ntt32_mult_sparse_16_generic,
    ntt32_mult_pointwise_reference, ntt32_mult_pointwise_16_reference, ntt32_mult_scalar_generic,
    ntt32_fft_32_reference, ntt32_large_fft_32_reference,
    ntt32_fft_16_reference, ntt32_large_fft_16_reference,
    ntt32_pwr_reference, ntt32_invert_reference, ntt32_div_reference, ntt32_flip_generic,
    ntt32_center_32_reference, ntt32_normalize_32_reference, ntt32_center_16_reference, ntt32_normalize_16_reference,
    ntt32_fwd_ntt_32_reference, ntt32_inv_ntt_32_reference, ntt32_large_fwd_ntt_32_reference, ntt32_large_inv_ntt_32_reference,
    ntt32_fwd_ntt_16_reference, ntt32_inv_ntt_16_reference, ntt32_large_fwd_ntt_16_reference, ntt32_large_inv_ntt_16_reference,

    ntt_modn_reference, ntt_muln_reference, ntt_sqrn_reference,
    ntt_mult_sparse_32_generic, ntt_mult_sparse_16_generic,
    ntt_mult_pointwise_reference, ntt_mult_pointwise_32_reference, ntt_mult_pointwise_16_reference,
    ntt_mult_scalar_generic,
    ntt_fft_reference, ntt_large_fft_reference,
    ntt_fft_32_reference, ntt_large_fft_32_reference,
    ntt_fft_16_reference, ntt_large_fft_16_reference,
    ntt_pwr_reference, ntt_invert_reference, ntt_div_reference, ntt_flip_generic,
    ntt_center_reference, ntt_normalize_reference,
    ntt_fwd_ntt_reference, ntt_inv_ntt_reference, ntt_large_fwd_ntt_reference, ntt_large_inv_ntt_reference,
    ntt_fwd_ntt_32_reference, ntt_inv_ntt_32_reference, ntt_large_fwd_ntt_32_reference, ntt_large_inv_ntt_32_reference,
    ntt_fwd_ntt_16_reference, ntt_inv_ntt_16_reference, ntt_large_fwd_ntt_16_reference, ntt_large_inv_ntt_16_reference,
};

#ifdef HAVE_AVX2
static const utils_arith_ntt_t utils_arith_ntt_avx = {
    ntt32_modn_avx, ntt32_muln_avx, ntt32_sqrn_avx,
    ntt32_mult_sparse_32_generic, ntt32_mult_sparse_16_generic,
    ntt32_mult_pointwise_avx, ntt32_mult_pointwise_16_avx, ntt32_mult_scalar_generic,
    ntt32_fft_32_avx, ntt32_large_fft_32_avx,
    ntt32_fft_16_avx, ntt32_large_fft_16_avx,
    ntt32_pwr_avx, ntt32_invert_avx, ntt32_div_avx, ntt32_flip_generic,
    ntt32_center_32_avx, ntt32_normalize_32_avx, ntt32_center_16_avx, ntt32_normalize_16_avx,
    ntt32_fwd_ntt_32_avx, ntt32_inv_ntt_32_avx, ntt32_large_fwd_ntt_32_avx, ntt32_large_inv_ntt_32_avx,
    ntt32_fwd_ntt_16_avx, ntt32_inv_ntt_16_avx, ntt32_large_fwd_ntt_16_avx, ntt32_large_inv_ntt_16_avx,

    ntt_modn_avx, ntt_muln_avx, ntt_sqrn_avx,
    ntt_mult_sparse_32_generic, ntt_mult_sparse_16_generic,
    ntt_mult_pointwise_avx, ntt_mult_pointwise_32_avx, ntt_mult_pointwise_16_avx,
    ntt_mult_scalar_generic,
    ntt_fft_avx, ntt_large_fft_avx,
    ntt_fft_32_avx, ntt_large_fft_32_avx,
    ntt_fft_16_avx, ntt_large_fft_16_avx,
    ntt_pwr_avx, ntt_invert_avx, ntt_div_avx, ntt_flip_generic,
    ntt_center_avx, ntt_normalize_avx,
    ntt_fwd_ntt_avx, ntt_inv_ntt_avx, ntt_large_fwd_ntt_avx, ntt_large_inv_ntt_avx,
    ntt_fwd_ntt_32_avx, ntt_inv_ntt_32_avx, ntt_large_fwd_ntt_32_avx, ntt_large_inv_ntt_32_avx,
    ntt_fwd_ntt_16_avx, ntt_inv_ntt_16_avx, ntt_large_fwd_ntt_16_avx, ntt_large_inv_ntt_16_avx,
};

/*static const utils_arith_ntt_t utils_arith_ntt_avx_rev = {
    ntt32_modn_avx_rev, ntt32_muln_avx_rev, ntt32_sqrn_avx_rev,
    ntt32_mult_sparse_32_generic, ntt32_mult_sparse_16_generic,
    ntt32_mult_pointwise_avx_rev, ntt32_mult_pointwise_16_avx_rev, ntt32_mult_scalar_generic,
    ntt32_fft_32_avx_rev, ntt32_large_fft_32_avx_rev,
    ntt32_fft_16_avx_rev, ntt32_large_fft_16_avx_rev,
    ntt32_pwr_avx_rev, ntt32_invert_avx_rev, ntt32_flip_generic,
    ntt32_center_32_avx_rev, ntt32_normalize_32_avx_rev, ntt32_center_16_avx_rev, ntt32_normalize_16_avx_rev,
    ntt32_fwd_ntt_32_avx_rev, ntt32_inv_ntt_32_avx_rev, ntt32_large_fwd_ntt_32_avx_rev, ntt32_large_inv_ntt_32_avx_rev,
    ntt32_fwd_ntt_16_avx_rev, ntt32_inv_ntt_16_avx_rev, ntt32_large_fwd_ntt_16_avx_rev, ntt32_large_inv_ntt_16_avx_rev,

    ntt_modn_avx_rev, ntt_muln_avx_rev, ntt_sqrn_avx_rev,
    ntt_mult_sparse_32_generic, ntt_mult_sparse_16_generic,
    ntt_mult_pointwise_avx_rev, ntt_mult_pointwise_32_avx_rev, ntt_mult_pointwise_16_avx_rev,
    ntt_mult_scalar_generic,
    ntt_fft_avx_rev, ntt_large_fft_avx_rev,
    ntt_fft_32_avx_rev, ntt_large_fft_32_avx_rev,
    ntt_fft_16_avx_rev, ntt_large_fft_16_avx_rev,
    ntt_pwr_avx_rev, ntt_invert_avx_rev, ntt_flip_generic,
    ntt_center_avx_rev, ntt_normalize_avx_rev,
    ntt_fwd_ntt_avx_rev, ntt_inv_ntt_avx_rev, ntt_large_fwd_ntt_avx_rev, ntt_large_inv_ntt_avx_rev,
    ntt_fwd_ntt_32_avx_rev, ntt_inv_ntt_32_avx_rev, ntt_large_fwd_ntt_32_avx_rev, ntt_large_inv_ntt_32_avx_rev,
    ntt_fwd_ntt_16_avx_rev, ntt_inv_ntt_16_avx_rev, ntt_large_fwd_ntt_16_avx_rev, ntt_large_inv_ntt_16_avx_rev,
};*/
#endif

static const utils_arith_ntt_t utils_arith_ntt_7681 = {
    ntt32_modn_7681, ntt32_muln_7681, ntt32_sqrn_7681,
    ntt32_mult_sparse_32_generic, ntt32_mult_sparse_16_generic,
    ntt32_mult_pointwise_7681, ntt32_mult_pointwise_16_7681, ntt32_mult_scalar_generic,
    ntt32_fft_32_7681, ntt32_large_fft_32_7681,
    ntt32_fft_16_7681, ntt32_large_fft_16_7681,
    ntt32_pwr_7681, ntt32_invert_7681, ntt32_div_7681, ntt32_flip_generic,
    ntt32_center_32_7681, ntt32_normalize_32_7681, ntt32_center_16_7681, ntt32_normalize_16_7681,
    ntt32_fwd_ntt_32_7681, ntt32_inv_ntt_32_7681, ntt32_large_fwd_ntt_32_7681, ntt32_large_inv_ntt_32_7681,
    ntt32_fwd_ntt_16_7681, ntt32_inv_ntt_16_7681, ntt32_large_fwd_ntt_16_7681, ntt32_large_inv_ntt_16_7681,

    ntt_modn_7681, ntt_muln_7681, ntt_sqrn_7681,
    ntt_mult_sparse_32_generic, ntt_mult_sparse_16_generic,
    ntt_mult_pointwise_7681, ntt_mult_pointwise_32_7681, ntt_mult_pointwise_16_7681,
    ntt_mult_scalar_generic,
    ntt_fft_7681, ntt_large_fft_7681,
    ntt_fft_32_7681, ntt_large_fft_32_7681,
    ntt_fft_16_7681, ntt_large_fft_16_7681,
    ntt_pwr_7681, ntt_invert_7681, ntt_div_7681, ntt_flip_generic,
    ntt_center_7681, ntt_normalize_7681,
    ntt_fwd_ntt_7681, ntt_inv_ntt_7681, ntt_large_fwd_ntt_7681, ntt_large_inv_ntt_7681,
    ntt_fwd_ntt_32_7681, ntt_inv_ntt_32_7681, ntt_large_fwd_ntt_32_7681, ntt_large_inv_ntt_32_7681,
    ntt_fwd_ntt_16_7681, ntt_inv_ntt_16_7681, ntt_large_fwd_ntt_16_7681, ntt_large_inv_ntt_16_7681,
};

static const utils_arith_ntt_t utils_arith_ntt_8380417 = {
    ntt32_modn_8380417, ntt32_muln_8380417, ntt32_sqrn_8380417,
    ntt32_mult_sparse_32_generic, ntt32_mult_sparse_16_generic,
    ntt32_mult_pointwise_8380417, ntt32_mult_pointwise_16_8380417, ntt32_mult_scalar_generic,
    ntt32_fft_32_8380417, ntt32_large_fft_32_8380417,
    ntt32_fft_16_8380417, ntt32_large_fft_16_8380417,
    ntt32_pwr_8380417, ntt32_invert_8380417, ntt32_div_8380417, ntt32_flip_generic,
    ntt32_center_32_8380417, ntt32_normalize_32_8380417, ntt32_center_16_8380417, ntt32_normalize_16_8380417,
    ntt32_fwd_ntt_32_8380417, ntt32_inv_ntt_32_8380417, ntt32_large_fwd_ntt_32_8380417, ntt32_large_inv_ntt_32_8380417,
    ntt32_fwd_ntt_16_8380417, ntt32_inv_ntt_16_8380417, ntt32_large_fwd_ntt_16_8380417, ntt32_large_inv_ntt_16_8380417,

    ntt_modn_8380417, ntt_muln_8380417, ntt_sqrn_8380417,
    ntt_mult_sparse_32_generic, ntt_mult_sparse_16_generic,
    ntt_mult_pointwise_8380417, ntt_mult_pointwise_32_8380417, ntt_mult_pointwise_16_8380417,
    ntt_mult_scalar_generic,
    ntt_fft_8380417, ntt_large_fft_8380417,
    ntt_fft_32_8380417, ntt_large_fft_32_8380417,
    ntt_fft_16_8380417, ntt_large_fft_16_8380417,
    ntt_pwr_8380417, ntt_invert_8380417, ntt_div_8380417, ntt_flip_generic,
    ntt_center_8380417, ntt_normalize_8380417,
    ntt_fwd_ntt_8380417, ntt_inv_ntt_8380417, ntt_large_fwd_ntt_8380417, ntt_large_inv_ntt_8380417,
    ntt_fwd_ntt_32_8380417, ntt_inv_ntt_32_8380417, ntt_large_fwd_ntt_32_8380417, ntt_large_inv_ntt_32_8380417,
    ntt_fwd_ntt_16_8380417, ntt_inv_ntt_16_8380417, ntt_large_fwd_ntt_16_8380417, ntt_large_inv_ntt_16_8380417,
};

/*static const utils_arith_ntt_t utils_arith_ntt_16813057 = {
    ntt32_modn_16813057, ntt32_muln_16813057, ntt32_sqrn_16813057,
    ntt32_mult_sparse_32_generic, ntt32_mult_sparse_16_generic,
    ntt32_mult_pointwise_16813057, ntt32_mult_pointwise_16_16813057, ntt32_mult_scalar_generic,
    ntt32_fft_32_16813057, ntt32_large_fft_32_16813057,
    ntt32_fft_16_16813057, ntt32_large_fft_16_16813057,
    ntt32_pwr_16813057, ntt32_invert_16813057, ntt32_flip_generic,
    ntt32_center_32_16813057, ntt32_normalize_32_16813057, ntt32_center_16_16813057, ntt32_normalize_16_16813057,
    ntt32_fwd_ntt_32_16813057, ntt32_inv_ntt_32_16813057, ntt32_large_fwd_ntt_32_16813057, ntt32_large_inv_ntt_32_16813057,
    ntt32_fwd_ntt_16_16813057, ntt32_inv_ntt_16_16813057, ntt32_large_fwd_ntt_16_16813057, ntt32_large_inv_ntt_16_16813057,

    ntt_modn_16813057, ntt_muln_16813057, ntt_sqrn_16813057,
    ntt_mult_sparse_32_generic, ntt_mult_sparse_16_generic,
    ntt_mult_pointwise_16813057, ntt_mult_pointwise_32_16813057, ntt_mult_pointwise_16_16813057,
    ntt_mult_scalar_generic,
    ntt_fft_16813057, ntt_large_fft_16813057,
    ntt_fft_32_16813057, ntt_large_fft_32_16813057,
    ntt_fft_16_16813057, ntt_large_fft_16_16813057,
    ntt_pwr_16813057, ntt_invert_16813057, ntt_flip_generic,
    ntt_center_16813057, ntt_normalize_16813057,
    ntt_fwd_ntt_16813057, ntt_inv_ntt_16813057, ntt_large_fwd_ntt_16813057, ntt_large_inv_ntt_16813057,
    ntt_fwd_ntt_32_16813057, ntt_inv_ntt_32_16813057, ntt_large_fwd_ntt_32_16813057, ntt_large_inv_ntt_32_16813057,
    ntt_fwd_ntt_16_16813057, ntt_inv_ntt_16_16813057, ntt_large_fwd_ntt_16_16813057, ntt_large_inv_ntt_16_16813057,
};

static const utils_arith_ntt_t utils_arith_ntt_134348801 = {
    ntt32_modn_134348801, ntt32_muln_134348801, ntt32_sqrn_134348801,
    ntt32_mult_sparse_32_generic, ntt32_mult_sparse_16_generic,
    ntt32_mult_pointwise_134348801, ntt32_mult_pointwise_16_134348801, ntt32_mult_scalar_generic,
    ntt32_fft_32_134348801, ntt32_large_fft_32_134348801,
    ntt32_fft_16_134348801, ntt32_large_fft_16_134348801,
    ntt32_pwr_134348801, ntt32_invert_134348801, ntt32_flip_generic,
    ntt32_center_32_134348801, ntt32_normalize_32_134348801, ntt32_center_16_134348801, ntt32_normalize_16_134348801,
    ntt32_fwd_ntt_32_134348801, ntt32_inv_ntt_32_134348801, ntt32_large_fwd_ntt_32_134348801, ntt32_large_inv_ntt_32_134348801,
    ntt32_fwd_ntt_16_134348801, ntt32_inv_ntt_16_134348801, ntt32_large_fwd_ntt_16_134348801, ntt32_large_inv_ntt_16_134348801,

    ntt_modn_134348801, ntt_muln_134348801, ntt_sqrn_134348801,
    ntt_mult_sparse_32_generic, ntt_mult_sparse_16_generic,
    ntt_mult_pointwise_134348801, ntt_mult_pointwise_32_134348801, ntt_mult_pointwise_16_134348801,
    ntt_mult_scalar_generic,
    ntt_fft_134348801, ntt_large_fft_134348801,
    ntt_fft_32_134348801, ntt_large_fft_32_134348801,
    ntt_fft_16_134348801, ntt_large_fft_16_134348801,
    ntt_pwr_134348801, ntt_invert_134348801, ntt_flip_generic,
    ntt_center_134348801, ntt_normalize_134348801,
    ntt_fwd_ntt_134348801, ntt_inv_ntt_134348801, ntt_large_fwd_ntt_134348801, ntt_large_inv_ntt_134348801,
    ntt_fwd_ntt_32_134348801, ntt_inv_ntt_32_134348801, ntt_large_fwd_ntt_32_134348801, ntt_large_inv_ntt_32_134348801,
    ntt_fwd_ntt_16_134348801, ntt_inv_ntt_16_134348801, ntt_large_fwd_ntt_16_134348801, ntt_large_inv_ntt_16_134348801,
};*/

const utils_arith_ntt_t *utils_arith_ntt(safecrypto_ntt_e type)
{
    if (SC_NTT_BARRETT == type) {
        ntt_table = &utils_arith_ntt_barrett;
    }
    /*else if (SC_NTT_BARRETT_REV == type) {
        ntt_table = &utils_arith_ntt_barrett_rev;
    }*/
    else if (SC_NTT_FLOATING_POINT == type) {
        ntt_table = &utils_arith_ntt_fp;
    }
#ifdef HAVE_AVX2
    else if (SC_NTT_AVX == type) {
        ntt_table = &utils_arith_ntt_avx;
    }
    /*else if (SC_NTT_AVX_REV == type) {
        ntt_table = &utils_arith_ntt_avx_rev;
    }*/
#endif
    else if (SC_NTT_SOLINAS_7681 == type) {
        ntt_table = &utils_arith_ntt_7681;
    }
    else if (SC_NTT_SOLINAS_8380417 == type) {
        ntt_table = &utils_arith_ntt_8380417;
    }
    /*else if (SC_NTT_SOLINAS_16813057 == type) {
        ntt_table = &utils_arith_ntt_16813057;
    }
    else if (SC_NTT_SOLINAS_134348801 == type) {
        ntt_table = &utils_arith_ntt_134348801;
    }*/
    else {
        ntt_table = &utils_arith_ntt_reference;
    }

    return ntt_table;
}

SINT32 poly_8_cmp_not_equal(volatile const SINT8 *in1, volatile const SINT8 *in2, size_t n)
{
    size_t i;
    volatile SINT32 not_equal = 0;
    for (i=n; i--;) {
        not_equal |= in1[i] ^ in2[i];
    }
    return not_equal;
}
