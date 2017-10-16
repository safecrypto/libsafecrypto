/*
 * Git commit information:
 *   Author: $SC_AUTHOR$
 *   Date:   $SC_DATE$
 *   Branch: $SC_BRANCH$
 *   Id:     $SC_IDENT$
 */

// sha3.h
// 19-Nov-11  Markku-Juhani O. Saarinen <mjos@iki.fi>

#ifndef SHA3_H
#define SHA3_H

#include <stddef.h>
#include <stdint.h>
#include "prng_types.h"


#ifndef KECCAKF_ROUNDS
#define KECCAKF_ROUNDS 24
#endif

#ifndef ROTL64
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))
#endif

// state context
PRNG_STRUCT_PACK_START
typedef struct {
    union {                                 // state:
        uint8_t b[200];                     // 8-bit bytes
        uint64_t q[25];                     // 64-bit words
    } st;
    int pt, rsiz, mdlen;                    // these don't overflow
} PRNG_STRUCT_PACKED sha3_ctx_t;
PRNG_STRUCT_PACK_END

// OpenSSL - like interfece
int tinysha3_init(void *c, int mdlen);    // mdlen = hash output in bytes
int tinysha3_update(void *c, const void *data, size_t len);
int tinysha3_final(void *c, void *md);    // digest goes to md
int tinysha3_xof_final(void *c);
int tinysha3_xof(void *c, void *out, size_t len);

// compute a sha3 hash (md) of given byte length from "in"
void *sha3(const void *in, size_t inlen, void *md, int mdlen);

// SHAKE128 and SHAKE256 extensible-output functions
#define shake128_init(c) sha3_init(c, 16)
#define shake256_init(c) sha3_init(c, 32)
#define shake_update sha3_update

void shake_xof(sha3_ctx_t *c);
void shake_out(sha3_ctx_t *c, void *out, size_t len);

#endif

