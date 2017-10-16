/*
 * Git commit information:
 *   Author: $SC_AUTHOR$
 *   Date:   $SC_DATE$
 *   Branch: $SC_BRANCH$
 *   Id:     $SC_IDENT$
 */

// sha3.c
// 19-Nov-11  Markku-Juhani O. Saarinen <mjos@iki.fi>

// Revised 07-Aug-15 to match with official release of FIPS PUB 202 "SHA3"
// Revised 03-Sep-15 for portability + OpenSSL - style API

#include "tinysha3.h"

// update the state with given number of rounds

static void sha3_keccakf(uint64_t st[25], int rounds)
{
    // constants
    const uint64_t keccakf_rndc[24] = {
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    };
    const int keccakf_rotc[24] = {
        1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
        27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };
    const int keccakf_piln[24] = {
        10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    };

    // variables
    int i, j, r;
#ifndef SHA3_UNROLLED
    int i4mod5[5] = {4, 0, 1, 2, 3};
    int i2mod5[5] = {2, 3, 4, 0, 1};
    int i1mod5[5] = {1, 2, 3, 4, 0};
#endif
    uint64_t t, bc[5];

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    uint8_t *v;

    // endianess conversion. this is redundant on little-endian targets
    for (i = 0; i < 25; i++) {
        st[i] = ((st[i] & 0xFF00000000000000L) >> 56) |
                ((st[i] & 0x00FF000000000000L) >> 40) |
                ((st[i] & 0x0000FF0000000000L) >> 24) |
                ((st[i] & 0x000000FF00000000L) >>  8) |
                ((st[i] & 0x00000000FF000000L) <<  8) |
                ((st[i] & 0x0000000000FF0000L) << 24) |
                ((st[i] & 0x000000000000FF00L) << 40) |
                ((st[i] & 0x00000000000000FFL) << 56);
    }
#endif

    // actual iteration
    for (r = 0; r < rounds; r++) {

#ifdef SHA3_UNROLLED
        // Theta
        bc[0] = st[0] ^ st[0 + 5] ^ st[0 + 10] ^ st[0 + 15] ^ st[0 + 20];
        bc[1] = st[1] ^ st[1 + 5] ^ st[1 + 10] ^ st[1 + 15] ^ st[1 + 20];
        bc[2] = st[2] ^ st[2 + 5] ^ st[2 + 10] ^ st[2 + 15] ^ st[2 + 20];
        bc[3] = st[3] ^ st[3 + 5] ^ st[3 + 10] ^ st[3 + 15] ^ st[3 + 20];
        bc[4] = st[4] ^ st[4 + 5] ^ st[4 + 10] ^ st[4 + 15] ^ st[4 + 20];

        t = bc[4] ^ ROTL64(bc[1], 1);
        st[0     ] ^= t;
        st[0 +  5] ^= t;
        st[0 + 10] ^= t;
        st[0 + 15] ^= t;
        st[0 + 20] ^= t;
        t = bc[0] ^ ROTL64(bc[2], 1);
        st[1     ] ^= t;
        st[1 +  5] ^= t;
        st[1 + 10] ^= t;
        st[1 + 15] ^= t;
        st[1 + 20] ^= t;
        t = bc[1] ^ ROTL64(bc[3], 1);
        st[2     ] ^= t;
        st[2 +  5] ^= t;
        st[2 + 10] ^= t;
        st[2 + 15] ^= t;
        st[2 + 20] ^= t;
        t = bc[2] ^ ROTL64(bc[4], 1);
        st[3     ] ^= t;
        st[3 +  5] ^= t;
        st[3 + 10] ^= t;
        st[3 + 15] ^= t;
        st[3 + 20] ^= t;
        t = bc[3] ^ ROTL64(bc[0], 1);
        st[4     ] ^= t;
        st[4 +  5] ^= t;
        st[4 + 10] ^= t;
        st[4 + 15] ^= t;
        st[4 + 20] ^= t;

        // Rho Pi
        t = st[1];
        bc[0] = st[10];
        st[10] = ROTL64(t, 1);
        t = bc[0];
        bc[0] = st[7];
        st[7] = ROTL64(t, 3);
        t = bc[0];
        bc[0] = st[11];
        st[11] = ROTL64(t, 6);
        t = bc[0];
        bc[0] = st[17];
        st[17] = ROTL64(t, 10);
        t = bc[0];
        bc[0] = st[18];
        st[18] = ROTL64(t, 15);
        t = bc[0];
        bc[0] = st[3];
        st[3] = ROTL64(t, 21);
        t = bc[0];
        bc[0] = st[5];
        st[5] = ROTL64(t, 28);
        t = bc[0];
        bc[0] = st[16];
        st[16] = ROTL64(t, 36);
        t = bc[0];
        bc[0] = st[8];
        st[8] = ROTL64(t, 45);
        t = bc[0];
        bc[0] = st[21];
        st[21] = ROTL64(t, 55);
        t = bc[0];
        bc[0] = st[24];
        st[24] = ROTL64(t, 2);
        t = bc[0];
        bc[0] = st[4];
        st[4] = ROTL64(t, 14);
        t = bc[0];
        bc[0] = st[15];
        st[15] = ROTL64(t, 27);
        t = bc[0];
        bc[0] = st[23];
        st[23] = ROTL64(t, 41);
        t = bc[0];
        bc[0] = st[19];
        st[19] = ROTL64(t, 56);
        t = bc[0];
        bc[0] = st[13];
        st[13] = ROTL64(t, 8);
        t = bc[0];
        bc[0] = st[12];
        st[12] = ROTL64(t, 25);
        t = bc[0];
        bc[0] = st[2];
        st[2] = ROTL64(t, 43);
        t = bc[0];
        bc[0] = st[20];
        st[20] = ROTL64(t, 62);
        t = bc[0];
        bc[0] = st[14];
        st[14] = ROTL64(t, 18);
        t = bc[0];
        bc[0] = st[22];
        st[22] = ROTL64(t, 39);
        t = bc[0];
        bc[0] = st[9];
        st[9] = ROTL64(t, 61);
        t = bc[0];
        bc[0] = st[6];
        st[6] = ROTL64(t, 20);
        t = bc[0];
        bc[0] = st[1];
        st[1] = ROTL64(t, 44);
        t = bc[0];
        
        //  Chi
        bc[0] = st[0    ];
        bc[1] = st[0 + 1];
        bc[2] = st[0 + 2];
        bc[3] = st[0 + 3];
        bc[4] = st[0 + 4];
        st[0    ] ^= (~bc[1]) & bc[2];
        st[0 + 1] ^= (~bc[2]) & bc[3];
        st[0 + 2] ^= (~bc[3]) & bc[4];
        st[0 + 3] ^= (~bc[4]) & bc[0];
        st[0 + 4] ^= (~bc[0]) & bc[1];
        bc[0] = st[1    ];
        bc[1] = st[1 + 1];
        bc[2] = st[1 + 2];
        bc[3] = st[1 + 3];
        bc[4] = st[1 + 4];
        st[1    ] ^= (~bc[1]) & bc[2];
        st[1 + 1] ^= (~bc[2]) & bc[3];
        st[1 + 2] ^= (~bc[3]) & bc[4];
        st[1 + 3] ^= (~bc[4]) & bc[0];
        st[1 + 4] ^= (~bc[0]) & bc[1];
        bc[0] = st[2    ];
        bc[1] = st[2 + 1];
        bc[2] = st[2 + 2];
        bc[3] = st[2 + 3];
        bc[4] = st[2 + 4];
        st[2    ] ^= (~bc[1]) & bc[2];
        st[2 + 1] ^= (~bc[2]) & bc[3];
        st[2 + 2] ^= (~bc[3]) & bc[4];
        st[2 + 3] ^= (~bc[4]) & bc[0];
        st[2 + 4] ^= (~bc[0]) & bc[1];
        bc[0] = st[3    ];
        bc[1] = st[3 + 1];
        bc[2] = st[3 + 2];
        bc[3] = st[3 + 3];
        bc[4] = st[3 + 4];
        st[3    ] ^= (~bc[1]) & bc[2];
        st[3 + 1] ^= (~bc[2]) & bc[3];
        st[3 + 2] ^= (~bc[3]) & bc[4];
        st[3 + 3] ^= (~bc[4]) & bc[0];
        st[3 + 4] ^= (~bc[0]) & bc[1];
        bc[0] = st[4    ];
        bc[1] = st[4 + 1];
        bc[2] = st[4 + 2];
        bc[3] = st[4 + 3];
        bc[4] = st[4 + 4];
        st[4    ] ^= (~bc[1]) & bc[2];
        st[4 + 1] ^= (~bc[2]) & bc[3];
        st[4 + 2] ^= (~bc[3]) & bc[4];
        st[4 + 3] ^= (~bc[4]) & bc[0];
        st[4 + 4] ^= (~bc[0]) & bc[1];
#else
        // Theta
        for (i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

        for (i = 0; i < 5; i++) {
            t = bc[i4mod5[i]] ^ ROTL64(bc[i1mod5[i]], 1);
            for (j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }

        // Rho Pi
        t = st[1];
        for (i = 0; i < 24; i++) {
            j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = ROTL64(t, keccakf_rotc[i]);
            t = bc[0];
        }

        //  Chi
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++)
                bc[i] = st[j + i];
            for (i = 0; i < 5; i++)
                st[j + i] ^= (~bc[i1mod5[i]]) & bc[i2mod5[i]];
        }
#endif

        //  Iota
        st[0] ^= keccakf_rndc[r];
    }

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    // endianess conversion. this is redundant on little-endian targets
    for (i = 0; i < 25; i++) {
        st[i] = ((st[i] & 0xFF00000000000000L) >> 56) |
                ((st[i] & 0x00FF000000000000L) >> 40) |
                ((st[i] & 0x0000FF0000000000L) >> 24) |
                ((st[i] & 0x000000FF00000000L) >>  8) |
                ((st[i] & 0x00000000FF000000L) <<  8) |
                ((st[i] & 0x0000000000FF0000L) << 24) |
                ((st[i] & 0x000000000000FF00L) << 40) |
                ((st[i] & 0x00000000000000FFL) << 56);
    }
#endif
}

// Initialize the context for SHA3

int tinysha3_init(void *c, int mdlen)
{
    int i;
    sha3_ctx_t *ctx = (sha3_ctx_t *) c;

    for (i = 25; i--;)
        ctx->st.q[i] = 0;
    ctx->mdlen = mdlen;
    ctx->rsiz = 200 - 2 * mdlen;
    ctx->pt = 0;

    return 1;
}

// update state with more data

int tinysha3_update(void *c, const void *data, size_t len)
{
    size_t i;
    int j;
    const uint8_t *in = (const uint8_t *) data;
    sha3_ctx_t *ctx = (sha3_ctx_t *) c;

    j = ctx->pt;
    for (i = len; i--;) {
        ctx->st.b[j++] ^= *in++;
        if (j >= ctx->rsiz) {
            sha3_keccakf(ctx->st.q, KECCAKF_ROUNDS);
            j = 0;
        }
    }
    ctx->pt = j;

    return 1;
}

// finalize and output a hash

int tinysha3_final(void *c, void *md)
{
    int i;
    sha3_ctx_t *ctx = (sha3_ctx_t *) c;

    ctx->st.b[ctx->pt] ^= 0x06;
    ctx->st.b[ctx->rsiz - 1] ^= 0x80;
    sha3_keccakf(ctx->st.q, KECCAKF_ROUNDS);

    for (i = ctx->mdlen; i--;) {
        ((uint8_t *) md)[i] = ctx->st.b[i];
    }

    return 1;
}

int tinysha3_xof_final(void *c)
{
    sha3_ctx_t *ctx = (sha3_ctx_t *) c;

    shake_xof(ctx);

    return 1;
}

int tinysha3_xof(void *c, void *out, size_t len)
{
    sha3_ctx_t *ctx = (sha3_ctx_t *) c;

    shake_out(ctx, out, len);

    return 1;
}

// compute a SHA-3 hash (md) of given byte length from "in"

void *sha3(const void *in, size_t inlen, void *md, int mdlen)
{
    sha3_ctx_t sha3;

    tinysha3_init(&sha3, mdlen);
    tinysha3_update(&sha3, in, inlen);
    tinysha3_final(md, &sha3);

    return md;
}

// SHAKE128 and SHAKE256 extensible-output functionality

void shake_xof(sha3_ctx_t *c)
{
    c->st.b[c->pt] ^= 0x1F;
    c->st.b[c->rsiz - 1] ^= 0x80;
    sha3_keccakf(c->st.q, KECCAKF_ROUNDS);
    c->pt = 0;
}

void shake_out(sha3_ctx_t *c, void *out, size_t len)
{
    size_t i;
    int j;

    j = c->pt;
    for (i = 0; i < len; i++) {
        if (j >= c->rsiz) {
            sha3_keccakf(c->st.q, KECCAKF_ROUNDS);
            j = 0;
        }
        ((uint8_t *) out)[i] = c->st.b[j++];
    }
    c->pt = j;
}

