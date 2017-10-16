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

#include "poly_z2.h"
#include "utils/crypto/prng.h"
#include "utils/arith/sc_math.h"


void z2_mul(SINT32 *out, SINT32 n, const SINT32 *in1, const SINT32 *in2)
{
    SINT32 i, j;

    // out = in1 * in2
    for (i=2*n; i--;)
        out[i] = 0;

    for (i=0; i<n; i++) {
        for (j=0; j<n; j++) {
            out[i+j] ^= in1[i] & in2[j];
        }
    }
}

SINT32 z2_div(SINT32 *q, SINT32 *r, SINT32 n, const SINT32 *num, const SINT32 *den)
{
    SINT32 i, j, k;
    SINT32 deg_num = n - 1, deg_den = n - 1;

    while (deg_num >= 0 && 0 == num[deg_num]) {
        deg_num--;
    }
    
    while (deg_den >= 0 && 0 == den[deg_den]) {
        deg_den--;
    }
    
    if (deg_num < 0) {
        return SC_FUNC_FAILURE;
    }

    if (deg_den < 0) {
        return SC_FUNC_FAILURE;
    }

    // r = num, q = 0
    for (i=n; i--;) {
        r[i] = num[i];
        q[i] = 0;
    }

    for (k=deg_num - deg_den; k>=0; k--) {
        q[k] = r[deg_den+k]; // Divide by den[deg_den] is irrelevant as it is 1
        for (j=deg_den+k-1; j>=k; j--) {
            r[j] ^= q[k] & den[j-k];
        }
    }
    for (j=deg_den; j<=n; j++) {
        r[j] = 0;
    }

    return SC_FUNC_SUCCESS;
}

static void field2n_8_mul(UINT8 *out, SINT32 n, const UINT8 *in1, const UINT8 *in2)
{
    SINT32 i, j;

    // out = in1 * in2
    for (i=2*n; i--;)
        out[i] = 0;

    for (i=0; i<n; i++) {
        for (j=0; j<n; j++) {
            out[i+j] ^= in1[i] & in2[j];
        }
    }
}

static SINT32 field2n_8_div(UINT8 *q, UINT8 *r, SINT32 n, const UINT8 *num, const UINT8 *den)
{
    SINT32 i, j, k;
    SINT32 deg_num = n - 1, deg_den = n - 1;

    while (deg_num >= 0 && 0 == num[deg_num]) {
        deg_num--;
    }
    
    while (deg_den >= 0 && 0 == den[deg_den]) {
        deg_den--;
    }
    
    if (deg_num < 0) {
        return SC_FUNC_FAILURE;
    }

    if (deg_den < 0) {
        return SC_FUNC_FAILURE;
    }

    // r = num, q = 0
    for (i=n; i--;) {
        r[i] = num[i];
        q[i] = 0;
    }

    for (k=deg_num - deg_den; k>=0; k--) {
        q[k] = r[deg_den+k]; // Divide by den[deg_den] is irrelevant as it is 1
        for (j=deg_den+k-1; j>=k; j--) {
            r[j] ^= q[k] & den[j-k];
        }
    }
    for (j=deg_den; j<=n; j++) {
        r[j] = 0;
    }

    return SC_FUNC_SUCCESS;
}

SINT32 z2_ext_euclidean(SINT32 *inv, SINT32 *f, SINT32 *scratch, size_t n)
{
    size_t i;
    UINT32 deg_r1;
    UINT8 *r0   = (UINT8 *)scratch;
    UINT8 *r1   = r0 +      n + 1;
    UINT8 *r2   = r0 + 2 * (n + 1);
    UINT8 *s0   = r0 + 3 * (n + 1);
    UINT8 *s1   = r0 + 4 * (n + 1);
    UINT8 *s2   = r0 + 5 * (n + 1);
    UINT8 *quo  = r0 + 6 * (n + 1);
    UINT8 *temp = (UINT8 *)inv;

    SC_MEMZERO(scratch, 7 * (n + 1) * sizeof(UINT8));
    r1[0] = 1;
    r1[n] = 1;
    deg_r1 = n;

    for (i=0; i<n; i++) {
        r0[i] = f[i];
    }

    s0[0] = 1;

    while (0 != deg_r1 || 0 != r1[0]) {
        field2n_8_div(quo, temp, n+1, r0, r1);

        field2n_8_mul(temp, n+1, quo, r1);
        for (i=n+1; i--;) {
            r2[i] = r0[i] ^ temp[i];
        }

        field2n_8_mul(temp, n+1, quo, s1);
        for (i=n+1; i--;) {
            s2[i] = s0[i] ^ temp[i];
        }

        UINT8 *swap;
        swap = r0;
        r0 = r1;
        r1 = r2;
        r2 = swap;
        swap = s0;
        s0 = s1;
        s1 = s2;
        s2 = swap;

        deg_r1 = 0;
        for (i=0; i<n+1; i++) {
            if (r1[i]) deg_r1 = i;
        }
    }

    for (i=0; i<n; i++) {
        inv[i] = s0[i];
    }

    return SC_FUNC_SUCCESS;
}

SINT32 z2_inv(SINT32 *inv, SINT32 *f, SINT32 *scratch, size_t n)
{
    // Almost Inverse Algorithm - NTRU Cryptosystems Technical Report
    // Requires gcd(f(X),g(X)) == 1 and m[0] = 1

    size_t i, j;
    SINT32 k = 0;
    UINT32 deg_b, deg_c, deg_f, deg_g;
    UINT8  *b = (UINT8 *) scratch;
    UINT8  *c = b + n;
    SINT32 *g = inv;

    // Verify that parity is even otherwise it is NOT invertible,
    // also obtain the degree of the polynomial
    deg_f = 0;
    j = 0;
    for (i=0; i<n; i++) {
        j ^= f[i];
        //if (f[i]) deg_f = i;
        deg_f = (f[i] != 0)? i : deg_f;
    }

    /// @todo This does NOT work for the ENS NTRU KEM scheme as parity
    /// is always even for parameter sets 0, 1 and 2.
    if (0 == j) {
        return SC_FUNC_FAILURE;
    }

    // Clear b and c
    for (i=n; i--;) {
        scratch[i] = 0;
    }

    // Clear g
    for (i=(n + 1); i--;) {
        g[i] = 0;
    }

    // b(X) = 1
    b[0] = 1;
    deg_b = 0;

    // c(X) = 0
    deg_c = 0;

    // Create an irreducible polynomial g(x) = X^n - 1
    g[0] = 1;
    g[n] = 1;
    deg_g = n;

    // Now search for f(X) = 1
    while (1) {

        // "while f[0] = 0, f(X) /= X, c(X) *= X, k++"

        // Calculate how many low order 0 coefficients are present
        for (i=0; (i <= deg_f) && (0 == f[i]); i++) {
            // Intentionally empty
        }

        // If the number of low order zero coefficients is greater than
        // the degree of f(X) then exit
        if (i > deg_f) {
            return SC_FUNC_FAILURE;
        }

        // If the number of low order zero coefficients is greater than 0
        // adjust the pointer f to effect f(X) /= X, move the c coefficients
        // by i elements to effect C(X) *= X, and increment k by i.
        if (i) {
            f += i;
            deg_f -= i;

#pragma GCC ivdep
            for (j=deg_c+1; j--;) {
                c[j+i] = c[j];
            }
            for (j=i; j--;) {
                c[j] = 0;
            }
            deg_c += i;

            k += i;
        }

        // "if f(X) = 1, DONE"
        if (deg_f == 0) {
            break;
        }

        // "if deg_f < deg_g, f <-> g, b <-> c"
        if (deg_f < deg_g) {
            // Swap f and g pointers
            SINT32 *temp = f; f = g; g = temp;

            // Swap the degree variables
            deg_f ^= deg_g; deg_g ^= deg_f; deg_f ^= deg_g;

            // Swap b and c pointers
            UINT8 *temp8 = b; b = c; c = temp8;

            // Swap the degree variables
            deg_b ^= deg_c; deg_c ^= deg_b; deg_b ^= deg_c;
        }

        // "f(X) += g(X)"
        for (j=deg_g+1; j--;) {
            f[j] ^= g[j];
        }
        if (deg_g == deg_f) {
            while (deg_f > 0 && 0 == f[deg_f]) {
                deg_f--;
            }
        }

        // "b(X) += c(X)"
        for (j=deg_c+1; j--;) {
            b[j] ^= c[j];
        }
        if (deg_c >= deg_b) {
            deg_b = deg_c;
            while (deg_b > 0 && 0 == b[deg_b]) {
                deg_b--;
            }
        }
    }

    // a^-1 in (Z/2Z)[X]/(X^N - 1) = b(X) shifted left k coefficients
    // i.e. a(x) = x^(N-k) * b(x)
    j = 0;
    if ((size_t)k >= n) {
        k -= n;
    }

    for (i=(size_t)k; i<n; i++) {
        inv[j++] = (SINT32) b[i];
    }
#pragma GCC ivdep
    for (i=0; i<(size_t)k; i++) {
        inv[j++] = (SINT32) b[i];
    }

    return SC_FUNC_SUCCESS;
}

SINT32 z2_mul_mod2(const SINT32 *in1, const SINT32 *in2, SINT32 n, SINT32 *out)
{
    SINT32 i, j;
    SINT32 mod_n = n - 1;

    for (i=0; i<n; i++) {
        SINT32 temp = 0;
        for (j=0; j<n; j++) {
            temp ^= in1[j] & in2[(n+i-j) & mod_n];
        }
        out[i] = temp;
    }

    return SC_FUNC_SUCCESS;
}

SINT32 z2_conv_mod2(const UINT32 *a, UINT32 *b_rev, size_t n, UINT32 *out)
{
    size_t i, j;

    for (i=0; i<n; i++) {
        UINT32 temp = 0;
        sc_arr_rotl_32(b_rev, n>>5, -1);
        for (j=0; j<n>>5; j++) {
            temp ^= a[j] & b_rev[j];
        }
        temp ^= temp >> 16;
        temp ^= temp >> 8;
        temp ^= temp >> 4;
        temp &= 0xF;
        temp = (0x6996 >> temp) & 0x1;
        if ((i & 0x1F) == 0)
            out[i>>5] = temp << 31;
        else
            out[i>>5] |= temp << (31 - (i & 0x1F));
    }

    return SC_FUNC_SUCCESS;
}

void z2_uniform(prng_ctx_t *ctx, SINT32 *v, size_t n, size_t num_ones)
{
    size_t i;

    // Reset the output polynomial to all zeros
    for (i=n; i--;)
        v[i] = 0;

    for (i=num_ones; i--;) {
        UINT32 rand = prng_32(ctx);
        SINT32 idx = (rand >> 1) & (n-1);
        v[idx] = rand & 0x1;
    }
}
