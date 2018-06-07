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


#include "roots_of_unity.h"


// Euler's Phi function
// NOTE: We only operate with positive numbers
static sc_ulimb_t euler_phi(sc_ulimb_t k)
{
    size_t i;
    sc_ulimb_t sum = SC_LIMB_WORD(0);
    if (k > 1 && 1 == (k & 1)) {
        for (i=1; i<k; i++) {
            if (1 == limb_gcd(i, k)) {
                sum++;
            }
        }
        return sum;
    }
    return 0;
}

/// Find a primitive root of the given integer modulo mod->m
static sc_ulimb_t find_primitive_root(const sc_mod_t *mod)
{
    size_t l, m;
    sc_ulimb_t phi = euler_phi(mod->m);

    for (m=1; m<mod->m-1; m++) {
        sc_ulimb_t sum = m == 1;
        sc_ulimb_t p   = m;

        for (l=1; l<phi; l++) {
            sc_ulimb_t hi, lo;
            limb_mul_hi_lo(&hi, &lo, m, p);
            p = limb_mod_reduction_norm(hi, lo, mod->m, mod->m_inv, mod->norm);
            sum += (p == 1);
        }

        if (1 != sum) {
            continue;
        }

        return m;
    }

    return 0;
}

/// Find a primitive root of the given integer modulo mod->m
static sc_ulimb_t find_primitive_root_of_unity(const sc_mod_t *mod, size_t n)
{
    size_t l, m;

    for (m=2; m<mod->m-1; m++) {
        sc_ulimb_t p = 1;

        for (l=1; l<=n; l++) {
            sc_ulimb_t hi, lo;
            limb_mul_hi_lo(&hi, &lo, m, p);
            p = limb_mod_reduction_norm(hi, lo, mod->m, mod->m_inv, mod->norm);
        }

        if ((mod->m-1) != p) {
            continue;
        }

        return m;
    }

    return 0;
}

static sc_ulimb_t find_inverse_primitive_root(sc_mod_t *mod, size_t n)
{
    sc_ulimb_t g, x, y;
    g = limb_xgcd(n, mod->m, &x, &y);
    if (1 != g) {
        return 0;
    }

    if (x & (SC_LIMB_WORD(1) << (SC_LIMB_BITS - 1))) {
        x = ~x + 1;
    }

    return x;
}

/// Generate the n roots of unity for prime number p
SINT32 roots_of_unity_slimb(sc_slimb_t *fwd, sc_slimb_t *inv,
    size_t n, sc_ulimb_t p, sc_ulimb_t prim)
{
    size_t i;
    sc_ulimb_t inv_p;
    sc_mod_t mod;

    limb_mod_init(&mod, p);
    if (0 == prim) {
        prim  = find_primitive_root_of_unity(&mod, n);
    }
    if (0 == prim) {
        return SC_FUNC_FAILURE;
    }
    inv_p = find_inverse_primitive_root(&mod, n);

    fwd[0] = 1;
    fwd[1] = prim;
    for (i=2; i<n; i++) {
        sc_ulimb_t hi, lo;
        limb_mul_hi_lo(&hi, &lo, fwd[i-1], prim);
        fwd[i] = limb_mod_reduction_norm(hi, lo, mod.m, mod.m_inv, mod.norm);
    }

    inv[0] = inv_p;
    for (i=1; i<n; i++) {
        sc_ulimb_t hi, lo;
        limb_mul_hi_lo(&hi, &lo, inv[i-1], prim);
        inv[i] = limb_mod_reduction_norm(hi, lo, mod.m, mod.m_inv, mod.norm);
    }

    return SC_FUNC_SUCCESS;
}


SINT32 roots_of_unity_s32(SINT32 *fwd, SINT32 *inv, size_t n, sc_ulimb_t p, sc_ulimb_t prim)
{
    size_t i;
    sc_ulimb_t inv_p;
    sc_mod_t mod;

    limb_mod_init(&mod, p);
    if (0 == prim) {
        prim  = find_primitive_root_of_unity(&mod, n);
        fprintf(stderr, "root of unity for %d is %d\n", p, prim);
    }
    if (0 == prim) {
        return SC_FUNC_FAILURE;
    }
    inv_p = find_inverse_primitive_root(&mod, n);

    fwd[0] = 1;
    fwd[1] = prim;
    for (i=2; i<n; i++) {
        sc_ulimb_t hi, lo;
        limb_mul_hi_lo(&hi, &lo, fwd[i-1], prim);
        fwd[i] = (SINT32)limb_mod_reduction_norm(hi, lo, mod.m, mod.m_inv, mod.norm);
    }

    inv[0] = inv_p;
    for (i=1; i<n; i++) {
        sc_ulimb_t hi, lo;
        limb_mul_hi_lo(&hi, &lo, inv[i-1], prim);
        inv[i] = (SINT32)limb_mod_reduction_norm(hi, lo, mod.m, mod.m_inv, mod.norm);
    }

    return SC_FUNC_SUCCESS;
}

SINT32 roots_of_unity_s16(SINT16 *fwd, SINT16 *inv, size_t n, sc_ulimb_t p, sc_ulimb_t prim)
{
    size_t i;
    sc_ulimb_t inv_p;
    sc_mod_t mod;

    limb_mod_init(&mod, p);
    if (0 == prim) {
        prim  = find_primitive_root_of_unity(&mod, n);
    }
    if (0 == prim) {
        return SC_FUNC_FAILURE;
    }
    inv_p = find_inverse_primitive_root(&mod, n);

    fwd[0] = 1;
    fwd[1] = prim;
    for (i=2; i<n; i++) {
        sc_ulimb_t hi, lo;
        limb_mul_hi_lo(&hi, &lo, fwd[i-1], prim);
        fwd[i] = (SINT16)limb_mod_reduction_norm(hi, lo, mod.m, mod.m_inv, mod.norm);
    }

    inv[0] = inv_p;
    for (i=1; i<n; i++) {
        sc_ulimb_t hi, lo;
        limb_mul_hi_lo(&hi, &lo, inv[i-1], prim);
        inv[i] = (SINT16)limb_mod_reduction_norm(hi, lo, mod.m, mod.m_inv, mod.norm);
    }

    return SC_FUNC_SUCCESS;
}

SINT32 inv_root_square_s32(SINT32 *fwd, size_t n, sc_ulimb_t p, sc_ulimb_t prim)
{
    size_t i;
    sc_ulimb_t g2, inv_g2;//, inv_g2_2;
    sc_mod_t mod;

    limb_mod_init(&mod, p);
    if (0 == prim) {
        prim  = find_primitive_root_of_unity(&mod, n);
    }
    if (0 == prim) {
        return SC_FUNC_FAILURE;
    }
    sc_ulimb_t hi, lo;
    limb_sqr_hi_lo(&hi, &lo, prim);
    g2 = (SINT32)limb_mod_reduction_norm(hi, lo, mod.m, mod.m_inv, mod.norm);
    inv_g2 = limb_inv_mod(g2, mod.m);

    fwd[0] = 1;
    fwd[1] = inv_g2;
    for (i=2; i<n; i++) {
        sc_ulimb_t hi, lo;
        limb_mul_hi_lo(&hi, &lo, fwd[i-1], inv_g2);
        fwd[i] = (SINT32)limb_mod_reduction_norm(hi, lo, mod.m, mod.m_inv, mod.norm);
    }
}

SINT32 inv_root_square_s16(SINT16 *fwd, size_t n, sc_ulimb_t p, sc_ulimb_t prim)
{
    size_t i;
    sc_ulimb_t g2, inv_g2;//, inv_g2_2;
    sc_mod_t mod;

    limb_mod_init(&mod, p);
    if (0 == prim) {
        prim  = find_primitive_root_of_unity(&mod, n);
    }
    if (0 == prim) {
        return SC_FUNC_FAILURE;
    }
    sc_ulimb_t hi, lo;
    limb_sqr_hi_lo(&hi, &lo, prim);
    g2 = (SINT16)limb_mod_reduction_norm(hi, lo, mod.m, mod.m_inv, mod.norm);
    inv_g2 = limb_inv_mod(g2, mod.m);

    fwd[0] = 1;
    fwd[1] = inv_g2;
    for (i=2; i<n; i++) {
        sc_ulimb_t hi, lo;
        limb_mul_hi_lo(&hi, &lo, fwd[i-1], inv_g2);
        fwd[i] = (SINT16)limb_mod_reduction_norm(hi, lo, mod.m, mod.m_inv, mod.norm);
    }
}
