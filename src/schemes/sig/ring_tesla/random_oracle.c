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

#include "random_oracle.h"
#include "ring_tesla_params.h"

#include "utils/arith/sc_math.h"
#include "utils/crypto/salsa/salsa20.h"


static const UINT8 sigma[16] = "expand 32-byte k";


void poly_rounding(safecrypto_t *sc, UINT16 n, SINT32 *p, SINT32 *r)
{
    size_t i;
    SINT32 d = sc->ring_tesla->params->d;
    const utils_arith_ntt_t *sc_ntt = sc->sc_ntt;
    ntt_params_t *ntt = &sc->ring_tesla->ntt;

    for (i=n; i--;) {
        SINT32 temp = sc_ntt->modn_32(p[i], ntt);
        r[i] = (p[i] - temp) >> d;
    }
}

void oracle(safecrypto_t *sc, SINT32 *v1, SINT32 *v2,
    SINT32 *temp, UINT16 n,
    const UINT8 *m, size_t m_len, UINT8 *md)
{
    size_t i;
    typedef union {
        UINT8 t[4];
        UINT32 word;
    } be_union;
    be_union data;

    hash_init(sc->hash);

    poly_rounding(sc, n, v1, temp);
    for (i = 0; i < n; i++) {
        data.word = SC_BIG_ENDIAN_32(temp[i]);
        hash_update(sc->hash, data.t, 4);
    }

    poly_rounding(sc, n, v2, temp);
    for (i = 0; i < n; i++) {
        data.word = SC_BIG_ENDIAN_32(temp[i]);
        hash_update(sc->hash, data.t, 4);
    }

    hash_update(sc->hash, m, m_len);
    hash_final(sc->hash, md);
}

void random_stream(UINT8 *md, UINT8 *nonce, UINT8 *r)
{
    size_t i;
    UINT8 in[16];
    UINT8 block[64];
    UINT32 salsa[16];
    size_t r_len = RANDOM_STREAM_LENGTH;

    // Initialise the input array with the nonce
    for (i=8; i--;) {
        in[i] = nonce[i];
    }
    for (i=8; i<16; i++) {
        in[i] = 0;
    }

    // Process all 64 byte long blocks
    while (r_len >= 64) {
        SC_LITTLE_ENDIAN_32_COPY(salsa, 0, (UINT32*)sigma, 4);
        SC_LITTLE_ENDIAN_32_COPY(salsa, 1, (UINT32*)md, 16);
        SC_LITTLE_ENDIAN_32_COPY(salsa, 5, (UINT32*)(sigma + 4), 4);
        SC_LITTLE_ENDIAN_32_COPY(salsa, 6, (UINT32*)in, 16);
        SC_LITTLE_ENDIAN_32_COPY(salsa, 10, (UINT32*)(sigma + 8), 4);
        SC_LITTLE_ENDIAN_32_COPY(salsa, 11, (UINT32*)(md + 16), 16);
        SC_LITTLE_ENDIAN_32_COPY(salsa, 15, (UINT32*)(sigma + 12), 4);
        salsa20_core(salsa, r);

        UINT32 u = 1;
        for (i=8; i<16; i++) {
            u += (UINT32) in[i];
            in[i] = u;
            u >>= 8;
        }

        r_len -= 64;
        r += 64;
    }

    if (r_len) {
        SC_LITTLE_ENDIAN_32_COPY(salsa, 0, (UINT32*)sigma, 4);
        SC_LITTLE_ENDIAN_32_COPY(salsa, 1, (UINT32*)md, 16);
        SC_LITTLE_ENDIAN_32_COPY(salsa, 5, (UINT32*)(sigma + 4), 4);
        SC_LITTLE_ENDIAN_32_COPY(salsa, 6, (UINT32*)in, 16);
        SC_LITTLE_ENDIAN_32_COPY(salsa, 10, (UINT32*)(sigma + 8), 4);
        SC_LITTLE_ENDIAN_32_COPY(salsa, 11, (UINT32*)(md + 16), 16);
        SC_LITTLE_ENDIAN_32_COPY(salsa, 15, (UINT32*)(sigma + 12), 4);
        salsa20_core(salsa, block);

        for (i=r_len; i--;) {
            r[i] = block[i];
        }
    }
}

void populate_c(safecrypto_t *sc, UINT8 *r, UINT8 *s, SINT32 *c)
{
    size_t i;
    SINT32 pos, cnt = 0;
    UINT16 omega = sc->ring_tesla->params->omega;
    UINT16 n = sc->ring_tesla->params->n;

    // Reset the "used" array, s
    for (i=n; i--;) {
        s[i] = 0;
    }

    // Use rejection sampling to generate the random vector c
    i = 0;
    while (i < omega) {
        pos  = r[cnt++] << 8;
        pos |= r[cnt++];
        pos &= n - 1;

        if (0 == s[pos]) {
            s[pos] = 1;
            c[i] = pos;
            i++;
        }
    }
}

void f_function(safecrypto_t *sc, UINT8 *md, SINT32 *temp, SINT32 *c)
{
    UINT8 nonce[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    UINT16 n = sc->ring_tesla->params->n;
    UINT8 *r = (UINT8*) temp; // 2*n bytes of storage
    UINT8 *s = r + 2*n;       // 2*n bytes of storage

    // Use a stream cipher with the hash as a key to generate
    // a random stream (that can be regenerated with the same key).
    random_stream(md, nonce, r);

    // Use the random stream to populate c
    populate_c(sc, r, s, c);
}

