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

#include <stdlib.h>
#include "safecrypto.h"
#include "safecrypto_debug.h"
#include "utils/crypto/hash.h"
#include "utils/crypto/prng.h"
#include "utils/threading/threading.h"

#include <string.h>


#define MAX_ITER    16384

#define USE_FIXED_BUFFERS     0
#if USE_FIXED_BUFFERS == 1
#define FIXED_BUFFER_SIZE     4096
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

SINT32 compare_messages(UINT8 *a, UINT8 *b, size_t length)
{
    size_t i;

    for (i=0; i<length; i++) {
        if (a[i] != b[i]) {
            fprintf(stderr, "ERROR! Messages do NOT match at index %d: %08X vs %08X\n",
                (SINT32)i, a[i], b[i]);
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

int main(void)
{
    safecrypto_t *sc = NULL;
 
#ifdef DISABLE_KEM
    UINT32 flags[2] = {SC_FLAG_MORE, SC_FLAG_NONE};
    sc = safecrypto_create(SC_SCHEME_KEM_ENS, 0, flags);
    if (NULL != sc) {
        fprintf(stderr, "ERROR! safecrypto_create() succeeded but the scheme has been disabled\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
#else
    int32_t i, j;
    uint8_t message[8192];
    size_t length = 32;
#if USE_FIXED_BUFFERS
    UINT8 *fixed_buffer = malloc(FIXED_BUFFER_SIZE);
    UINT8 *c = fixed_buffer, *p = fixed_buffer, *k = fixed_buffer;
#else
    UINT8 *c = NULL, *p = NULL, *k = NULL;
#endif
    UINT8 *pubkey, *privkey;
    size_t pubkeylen = 0, privkeylen = 0;
    size_t c_len, p_len, k_len;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_AES_CTR_DRBG,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    printf("THE WHOLE IS ... - NTRU KEM\n");

    SC_TIMER_INSTANCE(keygen_timer);
    SC_TIMER_INSTANCE(enc_timer);
    SC_TIMER_INSTANCE(dec_timer);
    SC_TIMER_CREATE(keygen_timer);
    SC_TIMER_CREATE(enc_timer);
    SC_TIMER_CREATE(dec_timer);

    for (i=0; i<4; i++) {
        SC_TIMER_RESET(keygen_timer);

        printf("Parameter Set: %d\n", i);

#ifdef USE_HUFFMAN_STATIC_ENTROPY
        UINT32 flags[2] = {SC_FLAG_0_ENTROPY_HUFFMAN, SC_FLAG_NONE};
        sc_entropy_type_e coding = SC_ENTROPY_HUFFMAN_STATIC;
#else
#ifdef USE_BAC_ENTROPY
        UINT32 flags[2] = {SC_FLAG_0_ENTROPY_BAC, SC_FLAG_NONE};
        sc_entropy_type_e coding = SC_ENTROPY_BAC;
#else
        UINT32 flags[2] = {SC_FLAG_NONE, SC_FLAG_NONE};
        sc_entropy_type_e coding = SC_ENTROPY_NONE;
#endif
#endif
        flags[0] |= SC_FLAG_MORE;
        flags[1] |= SC_FLAG_1_CSPRNG_AES_CTR_DRBG;

        // Create a SAFEcrypto object
        sc = safecrypto_create(SC_SCHEME_KEM_ENS, i, flags);

        for (j=0; j<MAX_ITER; j++) {

            // Create a key pair
            SC_TIMER_START(keygen_timer);
            if (SC_FUNC_SUCCESS != safecrypto_keygen(sc)) {
                fprintf(stderr, "ERROR! Key generation failed\n");
                goto error_return;
            }
            SC_TIMER_STOP(keygen_timer);

            safecrypto_set_key_coding(sc, coding, coding);
            pubkeylen = FIXED_BUFFER_SIZE;
            if (SC_FUNC_SUCCESS != safecrypto_public_key_encode(sc, &pubkey, &pubkeylen)) {
                fprintf(stderr, "ERROR! safecrypto_public_key_encode() failed\n");
                goto error_return;
            }
            privkeylen = FIXED_BUFFER_SIZE;
#if USE_FIXED_BUFFERS
#else
            free(pubkey);
#endif
            if (SC_FUNC_SUCCESS != safecrypto_private_key_encode(sc, &privkey, &privkeylen)) {
               fprintf(stderr, "ERROR! safecrypto_private_key_encode() failed\n");
                goto error_return;
            }
#if USE_FIXED_BUFFERS
#else
            free(privkey);
#endif

            // Generate a random message
            prng_mem(prng_ctx, message, length);

            SC_TIMER_START(enc_timer);
            c_len = FIXED_BUFFER_SIZE;
            k_len = FIXED_BUFFER_SIZE;
            safecrypto_encapsulation(sc, &c, &c_len, &k, &k_len);
            SC_TIMER_STOP(enc_timer);

            SC_TIMER_START(dec_timer);
            p_len = FIXED_BUFFER_SIZE;
            safecrypto_decapsulation(sc, c, c_len, &p, &p_len);
            SC_TIMER_STOP(dec_timer);

            if (EXIT_FAILURE == compare_messages(k, p, k_len)) {
                fprintf(stderr, "ERROR! Messages do NOT match\n");
                goto error_return;
            }

#if USE_FIXED_BUFFERS
#else
            free(c);
            c = NULL;
            free(p);
            p = NULL;
            free(k);
            k = NULL;
#endif

            if ((j & 0x1F) == 0x1F) show_progress(j, MAX_ITER);
        }

        show_progress(MAX_ITER, MAX_ITER);

        const char *stats = safecrypto_processing_stats(sc);
        printf("%s", stats);

        // Free all resources for the given SAFEcrypto object
        if (SC_FUNC_SUCCESS != safecrypto_destroy(sc)) {
            return EXIT_FAILURE;
        }

        double elapsed = SC_TIMER_GET_ELAPSED(keygen_timer);
        printf("KeyGen time:        %f (%f per sec)\n", elapsed, (double)MAX_ITER / elapsed);
        elapsed = SC_TIMER_GET_ELAPSED(enc_timer);
        printf("Encapsulation time: %f (%f per sec)\n", elapsed, (double)MAX_ITER / elapsed);
        elapsed = SC_TIMER_GET_ELAPSED(dec_timer);
        printf("Decapsulation time: %f (%f per sec)\n\n", elapsed, (double)MAX_ITER / elapsed);

        length <<= 1;
    }

#if USE_FIXED_BUFFERS
    if (fixed_buffer) free(fixed_buffer);
#else
    if (c) free(c);
    if (p) free(p);
    if (k) free(k);
#endif
    SC_TIMER_DESTROY(keygen_timer);
    SC_TIMER_DESTROY(enc_timer);
    SC_TIMER_DESTROY(dec_timer);
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
    if (c) free(c);
    if (p) free(p);
    if (k) free(k);
#endif
    SC_TIMER_DESTROY(keygen_timer);
    SC_TIMER_DESTROY(enc_timer);
    SC_TIMER_DESTROY(dec_timer);
    prng_destroy(prng_ctx);
    safecrypto_destroy(sc);
    return EXIT_FAILURE;
#endif
}


