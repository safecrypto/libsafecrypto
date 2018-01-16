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


#define MAX_ITER    1

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
    safecrypto_t *sc_a = NULL, *sc_b = NULL;

#ifdef DISABLE_SIGNATURES
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
    UINT8 *msg   = fixed_buffer;
    UINT8 *msg_b = fixed_buffer + 2048;
    UINT8 *res_a = fixed_buffer + 4096;
    UINT8 *res_b = fixed_buffer + 6144;
#else
    UINT8 *msg   = NULL;
    UINT8 *msg_b = NULL;
    UINT8 *res_a = NULL;
    UINT8 *res_b = NULL;
#endif
    size_t msglen = 0, msglen_b = 0, reslen_a = 0, reslen_b = 0;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    printf("Elliptic Curve Diffie-Hellman\n");

    SC_TIMER_INSTANCE(init_timer);
    SC_TIMER_INSTANCE(final_timer);
    SC_TIMER_CREATE(init_timer);
    SC_TIMER_CREATE(final_timer);

    for (i=0; i<1; i++) {
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
        sc_a = safecrypto_create(SC_SCHEME_DH_ECDH, i, flags);
        sc_b = safecrypto_create(SC_SCHEME_DH_ECDH, i, flags);

        for (j=0; j<MAX_ITER; j++) {

            // Generate Alice's message
            SC_TIMER_START(init_timer);
            msglen = FIXED_BUFFER_SIZE;
            if (SC_FUNC_SUCCESS != safecrypto_diffie_hellman_init(sc_a, &msglen, &msg)) {
                fprintf(stderr, "ERROR! safecrypto_diffie_hellman_init() failed\n");
                goto error_return;
            }
            SC_TIMER_STOP(init_timer);

            // Generate Bob's message
            SC_TIMER_START(init_timer);
            msglen_b = FIXED_BUFFER_SIZE;
            if (SC_FUNC_SUCCESS != safecrypto_diffie_hellman_init(sc_b, &msglen_b, &msg_b)) {
                fprintf(stderr, "ERROR! safecrypto_diffie_hellman_init() failed\n");
                goto error_return;
            }
            SC_TIMER_STOP(init_timer);

            // Generate Alice's shared secret
            SC_TIMER_START(final_timer);
            msglen = FIXED_BUFFER_SIZE;
            if (SC_FUNC_SUCCESS != safecrypto_diffie_hellman_final(sc_a, msglen_b, msg_b, &reslen_a, &res_a)) {
                fprintf(stderr, "ERROR! safecrypto_diffie_hellman_final() failed\n");
                goto error_return;
            }
            SC_TIMER_STOP(final_timer);

            // Generate Bob's shared secret
            SC_TIMER_START(final_timer);
            msglen = FIXED_BUFFER_SIZE;
            if (SC_FUNC_SUCCESS != safecrypto_diffie_hellman_final(sc_b, msglen, msg, &reslen_b, &res_b)) {
                fprintf(stderr, "ERROR! safecrypto_diffie_hellman_final() failed\n");
                goto error_return;
            }
            SC_TIMER_STOP(final_timer);

            // Verify that Alice and Boc have the same shared secret
            if (reslen_a != reslen_b) {
                fprintf(stderr, "ERROR! ECDH secret's are not of same length\n");
                goto error_return;
            }
            if (SC_FUNC_SUCCESS != compare_secrets(res_a, res_b, reslen_a)) {
                goto error_return;
            }

#if USE_FIXED_BUFFERS
#else
            free(msg);
            msg = NULL;
            free(msg_b);
            msg_b = NULL;
            free(res_a);
            res_a = NULL;
            free(res_b);
            res_b = NULL;
#endif

            if ((j & 0x1F) == 0x1F) show_progress(j, MAX_ITER);
        }

        show_progress(MAX_ITER, MAX_ITER);

        const char *stats = safecrypto_processing_stats(sc_a);
        printf("%s", stats);

        // Free all resources for the given SAFEcrypto object
        if (SC_FUNC_SUCCESS != safecrypto_destroy(sc_a)) {
            return EXIT_FAILURE;
        }
        if (SC_FUNC_SUCCESS != safecrypto_destroy(sc_b)) {
            return EXIT_FAILURE;
        }

        double elapsed = SC_TIMER_GET_ELAPSED(init_timer);
        printf("Init time:   %f (%f per sec)\n", elapsed, (double)MAX_ITER / elapsed);
        elapsed = SC_TIMER_GET_ELAPSED(final_timer);
        printf("Final time:  %f (%f per sec)\n\n", elapsed, (double)MAX_ITER / elapsed);
    }

#if USE_FIXED_BUFFERS
    if (fixed_buffer) free(fixed_buffer);
#else
    if (msg) free(msg);
#endif

    SC_TIMER_DESTROY(init_timer);
    SC_TIMER_DESTROY(final_timer);
    prng_destroy(prng_ctx);
    return EXIT_SUCCESS;

error_return:
    if (sc_a) {
        UINT32 error;
        const char *file;
        SINT32 line;
        while (SC_OK != (error = safecrypto_err_get_error_line(sc_a, &file, &line))) {
            printf("ERROR: %08X, %s, line %d\n", error, file, line);
        }
    }
#if USE_FIXED_BUFFERS
    if (fixed_buffer) free(fixed_buffer);
#else
    if (msg) free(msg);
#endif
    SC_TIMER_DESTROY(init_timer);
    SC_TIMER_DESTROY(final_timer);
    prng_destroy(prng_ctx);
    safecrypto_destroy(sc_a);
    safecrypto_destroy(sc_b);
    return EXIT_FAILURE;
#endif
}


