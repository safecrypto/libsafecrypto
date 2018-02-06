/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2018                      *
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

#include <stdlib.h>
#include "safecrypto.h"
#include "safecrypto_debug.h"
#include "utils/crypto/hash.h"
#include "utils/crypto/prng.h"
#include "utils/threading/threading.h"

#include <string.h>


#define MAX_ITER    1024

#define USE_FIXED_BUFFERS     0
#if USE_FIXED_BUFFERS == 1
#define FIXED_BUFFER_SIZE     8192
#else
#define FIXED_BUFFER_SIZE     0
#endif


void show_progress(int32_t count, int32_t max)
{
    int i;
    int barWidth = 70;
    double progress = (double) count / max;

    printf("[");
    int pos = barWidth * progress;
    for (i = 0; i < barWidth; ++i) {
        if (i < pos) printf("=");
        else if (i == pos) printf(">");
        else printf(" ");
    }
    printf("] %4d/%4d (%3d %%)\r", count, max, (int)(progress * 100.0f));
    if (count == max) printf("\n");
    fflush(stdout);
}

SINT32 compare_secrets(UINT8 *a, UINT8 *b, size_t length)
{
    size_t i;

    for (i=0; i<length; i++) {
        if (a[i] != b[i]) {
            fprintf(stderr, "ERROR! Secrets do NOT match at index %d: %08X vs %08X\n",
                (SINT32)i, a[i], b[i]);
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

int main(void)
{
    safecrypto_t *sc = NULL;

#ifdef DISABLE_ECDH
    UINT32 flags[1] = {SC_FLAG_NONE};
    sc = safecrypto_create(SC_SCHEME_SIG_ENS, 0, flags);
    if (NULL != sc) {
        fprintf(stderr, "ERROR! safecrypto_create() succeeded but the scheme has been disabled\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
#else
    int32_t i, j;
#if USE_FIXED_BUFFERS
    UINT8 *fixed_buffer = malloc(FIXED_BUFFER_SIZE);
    UINT8 *msg = fixed_buffer;
    UINT8 *res = fixed_buffer + 2048;
#else
    UINT8 *msg = NULL;
    UINT8 *res = NULL;
#endif
    size_t msglen = 0, reslen = 0;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    printf("Elliptic Curve Diffie-Hellman\n");

    for (i=2; i<3; i++) {

        printf("Parameter Set: %d\n", i);

        UINT32 flags[2] = {SC_FLAG_NONE, SC_FLAG_NONE};
        sc_entropy_type_e coding = SC_ENTROPY_NONE;
        flags[0] |= SC_FLAG_MORE;
        flags[1] |= SC_FLAG_1_CSPRNG_AES_CTR_DRBG;

        // Create a SAFEcrypto object
        sc = safecrypto_create(SC_SCHEME_DH_ECDH, i, flags);

        show_progress(0, MAX_ITER);

        // Load the private key
#if 0
        uint8_t tv1_secret[] = {0x7d, 0x7d, 0xc5, 0xf7, 0x1e, 0xb2, 0x9d, 0xda, 0xf8, 0x0d, 0x62, 0x14, 0x63, 0x2e, 0xea, 0xe0,
                                0x3d, 0x90, 0x58, 0xaf, 0x1f, 0xb6, 0xd2, 0x2e, 0xd8, 0x0b, 0xad, 0xb6, 0x2b, 0xc1, 0xa5, 0x34};
        uint8_t tv1_pubkey[] = {0x70, 0x0c, 0x48, 0xf7, 0x7f, 0x56, 0x58, 0x4c, 0x5c, 0xc6, 0x32, 0xca, 0x65, 0x64, 0x0d, 0xb9,
                                0x1b, 0x6b, 0xac, 0xce, 0x3a, 0x4d, 0xf6, 0xb4, 0x2c, 0xe7, 0xcc, 0x83, 0x88, 0x33, 0xd2, 0x87,
                                0xdb, 0x71, 0xe5, 0x09, 0xe3, 0xfd, 0x9b, 0x06, 0x0d, 0xdb, 0x20, 0xba, 0x5c, 0x51, 0xdc, 0xc5,
                                0x94, 0x8d, 0x46, 0xfb, 0xf6, 0x40, 0xdf, 0xe0, 0x44, 0x17, 0x82, 0xca, 0xb8, 0x5f, 0xa4, 0xac};
        uint8_t tv1_shared[] = {0x46, 0xfc, 0x62, 0x10, 0x64, 0x20, 0xff, 0x01, 0x2e, 0x54, 0xa4, 0x34, 0xfb, 0xdd, 0x2d, 0x25,
                                0xcc, 0xc5, 0x85, 0x20, 0x60, 0x56, 0x1e, 0x68, 0x04, 0x0d, 0xd7, 0x77, 0x89, 0x97, 0xbd, 0x7b};
#else
        uint8_t tv1_secret[] = {0xBC, 0x24, 0x21, 0x99, 0x00, 0x3C, 0x9E, 0xCC, 0xAB, 0xC3, 0x77, 0xB1, 0x7A, 0x40, 0x56, 0x40, 0x1E, 0x09, 0xC2, 0x70, 0x06, 0xA0, 0xD2, 0xFD, 0xB9, 0x2A, 0xB4, 0xE9, 0xFF, 0x80, 0x16, 0x22};
        uint8_t tv1_pubkey[] = {0x60, 0x7B, 0x3B, 0x31, 0x4E, 0x52, 0x9D, 0x2B, 0x90, 0x6C, 0xCC, 0xBD, 0x34, 0xBF, 0xF8, 0x4D, 0x14, 0xC3, 0x5B, 0x3B, 0xD6, 0x10, 0xCD, 0xAD, 0x5B, 0xA3, 0x63, 0xB4, 0x9F, 0x12, 0x4C, 0xC9,
                                0x65, 0xE0, 0xB9, 0xB2, 0x12, 0x1C, 0xDB, 0x61, 0xC8, 0xC0, 0x9E, 0xB3, 0x86, 0xCC, 0x69, 0x8C, 0xBA, 0xA1, 0x8D, 0x1A, 0x10, 0xAB, 0x3B, 0xDB, 0x17, 0x08, 0x0C, 0x1F, 0xDA, 0x7E, 0x00, 0x53};
        uint8_t tv1_shared[] = {0xE4, 0xB4, 0xE0, 0xE8, 0xE0, 0xE5, 0xE0, 0xEA, 0x78, 0xB3, 0xDA, 0xD1, 0x68, 0xD9, 0x2F, 0x86, 0x80, 0x10, 0xF3, 0x62, 0x5F, 0x7F, 0xCC, 0x3E, 0x9A, 0x9B, 0xC1, 0xAE, 0x7B, 0x8B, 0xAB, 0xB2};
#endif

        for (size_t i=0; i<16; i++) {
            uint8_t temp = tv1_secret[i];
            tv1_secret[i] = tv1_secret[31-i];
            tv1_secret[31-i] = temp;
        }
#if 0
        for (size_t i=0; i<32; i++) {
            uint8_t temp = tv1_pubkey[i];
            tv1_pubkey[i] = tv1_secret[63-i];
            tv1_pubkey[63-i] = temp;
        }
#else
        for (size_t i=0; i<16; i++) {
            uint8_t temp = tv1_pubkey[32+i];
            tv1_pubkey[32+i] = tv1_pubkey[32+31-i];
            tv1_pubkey[32+31-i] = temp;
        }
        for (size_t i=0; i<16; i++) {
            uint8_t temp = tv1_pubkey[i];
            tv1_pubkey[i] = tv1_pubkey[31-i];
            tv1_pubkey[31-i] = temp;
        }
#endif
        for (size_t i=0; i<16; i++) {
            uint8_t temp = tv1_shared[i];
            tv1_shared[i] = tv1_shared[31-i];
            tv1_shared[31-i] = temp;
        }

        //tv1_secret[0] = 20;
        safecrypto_private_key_load(sc, tv1_secret, 32);

        // Generate the shared secret
        reslen = FIXED_BUFFER_SIZE;
        if (SC_FUNC_SUCCESS != safecrypto_diffie_hellman_final(sc, 64, tv1_pubkey, &reslen, &res)) {
            fprintf(stderr, "ERROR! safecrypto_diffie_hellman_final() failed\n");
            goto error_return;
        }

        fprintf(stderr, "output:\n");
        for (size_t i=0; i<64; i++) {
            fprintf(stderr, "%02X ", res[i]);
        }
        fprintf(stderr, "\n");
        fprintf(stderr, "tv:\n");
        for (size_t i=0; i<32; i++) {
            fprintf(stderr, "%02X ", tv1_shared[i]);
        }
        fprintf(stderr, "\n");

        // Verify that Alice and Bob have the same shared secret
        if (32 != reslen) {
            fprintf(stderr, "ERROR! ECDH secret's are not of same length\n");
            goto error_return;
        }
        if (SC_FUNC_SUCCESS != compare_secrets(res, tv1_shared, 32)) {
            goto error_return;
        }

#if USE_FIXED_BUFFERS
#else
        free(msg);
        msg = NULL;
        free(res);
        res = NULL;
#endif

        show_progress(MAX_ITER, MAX_ITER);

        const char *stats = safecrypto_processing_stats(sc);
        printf("%s", stats);

        // Free all resources for the given SAFEcrypto object
        if (SC_FUNC_SUCCESS != safecrypto_destroy(sc)) {
            return EXIT_FAILURE;
        }
    }

#if USE_FIXED_BUFFERS
    if (fixed_buffer) free(fixed_buffer);
#else
    if (msg) free(msg);
#endif

    prng_destroy(prng_ctx);
    return EXIT_SUCCESS;

error_return:
    if (sc) {
        UINT32 error;
        const char *file;
        SINT32 line;
        while (SC_OK != (error = safecrypto_err_get_error_line(sc, &file, &line))) {
            printf("ERROR: %08X, %s, line %d\n", error, file, line);
        }
    }
#if USE_FIXED_BUFFERS
    if (fixed_buffer) free(fixed_buffer);
#else
    if (msg) free(msg);
#endif
    prng_destroy(prng_ctx);
    safecrypto_destroy(sc);
    return EXIT_FAILURE;
#endif
}


