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
#include "safecrypto_private.h"
#include "utils/crypto/hash.h"
#include "utils/crypto/prng.h"
#include "utils/threading/threading.h"

#include <string.h>


#define MAX_EXTRACT_ITER   1024
#define MAX_ITER           4096
#define MIN_MSG_LEN        128

#define SC_IBE_MESSAGE_LENGTH_N

void show_progress(char *msg, int32_t count, int32_t max)
{
    int i;
    int barWidth = 50;
    double progress = (double) count / max;

    printf("%-20s [", msg);
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

static void prng_entropy_source(size_t n, UINT8 *data)
{
    size_t i;
    for (i=0; i<n; i++) {
        data[i] = i;
    }
}

int main(void)
{
    safecrypto_t *sc = NULL;
    UINT32 flags[2] = {SC_FLAG_NONE, SC_FLAG_NONE};
    flags[0] = SC_FLAG_MORE | SC_FLAG_0_SAMPLE_CDF;// | SC_FLAG_0_ENTROPY_HUFFMAN | SC_FLAG_MORE;
    flags[1] = SC_FLAG_1_CSPRNG_USE_CALLBACK_RANDOM | SC_FLAG_1_CSPRNG_AES_CTR_DRBG;

#ifdef DISABLE_IBE
    sc = safecrypto_create(SC_SCHEME_IBE_DLP, 0, flags);
    if (NULL != sc) {
        fprintf(stderr, "ERROR! safecrypto_create() succeeded but the scheme has been disabled\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
#else
    int32_t i, j, k, l;
    uint8_t message[32768];
    size_t length;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);
    SINT32 retval;

    printf("SAFEcrypto IBE\n");

    char disp_msg[128];

    SC_TIMER_INSTANCE(keygen_timer);
    SC_TIMER_INSTANCE(extract_timer);
    SC_TIMER_INSTANCE(enc_timer);
    SC_TIMER_INSTANCE(dec_timer);
    SC_TIMER_CREATE(keygen_timer);
    SC_TIMER_CREATE(extract_timer);
    SC_TIMER_CREATE(enc_timer);
    SC_TIMER_CREATE(dec_timer);

    for (i=0; i<6; i++) {
        SC_TIMER_RESET(keygen_timer);
        SC_TIMER_RESET(extract_timer);
        SC_TIMER_RESET(enc_timer);
        SC_TIMER_RESET(dec_timer);

        printf("Parameter Set: %d\n", i);

        // Create a SAFEcrypto object
#if 1
        safecrypto_entropy_callback(prng_entropy_source);
#endif
        sc = safecrypto_create(SC_SCHEME_IBE_DLP, i, flags);
        if (NULL == sc) {
            fprintf(stderr, "ERROR! Failed to create a SAFEcrypto instance\n");
            return EXIT_FAILURE;
        }

        // Generate a master key
        SC_TIMER_START(keygen_timer);
        if (SC_FUNC_SUCCESS != safecrypto_keygen(sc)) {
            fprintf(stderr, "ERROR! Key generation failed\n");
            goto error_return;
        }
        SC_TIMER_STOP(keygen_timer);

        // Allocate memory for the master key
        UINT8 *masterkey[2];

        // Retrieve the master key pair
        size_t masterkey_pub_len = 0, masterkey_priv_len = 0;
        if (SC_FUNC_SUCCESS != safecrypto_public_key_encode(sc, &masterkey[0], &masterkey_pub_len)) {
            fprintf(stderr, "ERROR! Could not retrieve public master key\n");
            goto error_return;
        }
        if (SC_FUNC_SUCCESS != safecrypto_private_key_encode(sc, &masterkey[1], &masterkey_priv_len)) {
            fprintf(stderr, "ERROR! Could not retrieve private master key\n");
            goto error_return;
        }
        if (SC_FUNC_SUCCESS != safecrypto_private_key_load(sc, masterkey[1], masterkey_priv_len)) {
            fprintf(stderr, "ERROR! Could not retrieve private master key\n");
            goto error_return;
        }

        snprintf(disp_msg, 128, "%-20s", "Extract");

        // Extract user keys for Alice and Bob
        static const UINT8 alice[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0xFF};
        static const UINT8 bob[6]   = {0x01, 0x02, 0x03, 0x04, 0x05, 0xFE};
        UINT8 *sk[2] = {NULL, NULL};
        size_t len_sk[2] = {0, 0};
        SC_TIMER_START(extract_timer);
        retval = safecrypto_ibe_extract(sc, 6, alice, &len_sk[0], &sk[0]);
        if (SC_FUNC_FAILURE == retval) {
            fprintf(stderr, "ERROR! Failed to extract a user secret key\n");
            return EXIT_FAILURE;
        }
        for (j=1; j<MAX_EXTRACT_ITER; j++) {
            retval = safecrypto_ibe_extract(sc, 6, alice, &len_sk[1], &sk[1]);
            if (SC_FUNC_FAILURE == retval) {
               fprintf(stderr, "ERROR! Failed to extract a user secret key\n");
                return EXIT_FAILURE;
            }
            if (sk[1]) SC_FREE(sk[1], sizeof(UINT8) * len_sk[1]);
            len_sk[1] = 0;

            if ((j & 0x1F) == 0x1F) show_progress(disp_msg, j, MAX_EXTRACT_ITER);
        }
        SC_TIMER_STOP(extract_timer);

        show_progress(disp_msg, MAX_EXTRACT_ITER, MAX_EXTRACT_ITER);

        // Configure Alice and Bob with their respecitve id, user secret key
        // and public master key
        /*retval = safecrypto_public_key_load(sc, masterkey[0], masterkey_pub_len);
        if (SC_FUNC_FAILURE == retval) {
            fprintf(stderr, "ERROR! Failed to load a public key\n");
            return EXIT_FAILURE;
        }*/
        retval = safecrypto_secret_key(sc, len_sk[0], sk[0]);
        if (SC_FUNC_FAILURE == retval) {
            fprintf(stderr, "ERROR! Failed to load a user key for Alice\n");
            return EXIT_FAILURE;
        }

        SC_FREE(masterkey[0], masterkey_pub_len);
        SC_FREE(masterkey[1], masterkey_priv_len);

#ifdef SC_IBE_MESSAGE_LENGTH_N
        length = (i < 3)? 64 : 128;
#else
        length = MIN_MSG_LEN;
#endif

        double elapsed_enc[4], elapsed_dec[4];
#ifdef SC_IBE_MESSAGE_LENGTH_N
        for (k=0; k<1; k++) {
#else
        for (k=0; k<4; k++) {
#endif

            snprintf(disp_msg, 128, "%-10s %-6zu", "Enc/Dec", length);

            for (j=0; j<MAX_ITER; j++) {

                // Generate a random message
                prng_mem(prng_ctx, message, length);

                // Encrypt a message from Alice to Bob
                UINT8 *msg_to_bob = NULL, *msg_from_alice = NULL;
                size_t msg_to_bob_len = 0, msg_from_alice_len = 0;
                SC_TIMER_START(enc_timer);
                safecrypto_ibe_public_encrypt(sc, 6, alice,
                    length, message, &msg_to_bob_len, &msg_to_bob);
                SC_TIMER_STOP(enc_timer);

                // Decrypt a message from Alice to Bob
                SC_TIMER_START(dec_timer);
                safecrypto_private_decrypt(sc, msg_to_bob_len, msg_to_bob,
                    &msg_from_alice_len, &msg_from_alice);
                SC_TIMER_STOP(dec_timer);

                if (length != msg_from_alice_len) {
                    fprintf(stderr, "Decrypted message length is incorrect (%zu vs %zu)",
                        msg_from_alice_len, length);
                    SC_FREE(msg_to_bob, msg_to_bob_len);
                    SC_FREE(msg_from_alice, msg_from_alice_len);
                    goto error_return;
                }

                for (l=0; l<length; l++) {
                    if (message[l] != msg_from_alice[l]) {
                        fprintf(stderr, "Decrypted message mismatch (iter: %d, %d: %02X vs %02X)",
                            j, l, (int)message[l], (int)msg_from_alice[l]);
                        SC_FREE(msg_to_bob, msg_to_bob_len);
                        SC_FREE(msg_from_alice, msg_from_alice_len);
                        goto error_return;
                    }
                }

                SC_FREE(msg_to_bob, msg_to_bob_len);
                SC_FREE(msg_from_alice, msg_from_alice_len);

                if ((j & 0x1F) == 0x1F) show_progress(disp_msg, j, MAX_ITER);
            }

            show_progress(disp_msg, MAX_ITER, MAX_ITER);

#ifdef SC_IBE_MESSAGE_LENGTH_N
            length = (i < 3)? 64 : 128;
#else
            length <<= 2;
#endif
            elapsed_enc[k] = SC_TIMER_GET_ELAPSED(enc_timer);
            elapsed_dec[k] = SC_TIMER_GET_ELAPSED(dec_timer);
            SC_TIMER_RESET(enc_timer);
            SC_TIMER_RESET(dec_timer);
        }

        const char *stats = safecrypto_processing_stats(sc);
        printf("%s", stats);

        // Free all resources for the given SAFEcrypto object
        if (SC_FUNC_SUCCESS != safecrypto_destroy(sc)) {
            return EXIT_FAILURE;
        }

        // Destroy the secret keys
        if (sk[0]) SC_FREE(sk[0], sizeof(UINT8) * len_sk[0]);
        if (sk[1]) SC_FREE(sk[1], sizeof(UINT8) * len_sk[1]);

        double elapsed;
        elapsed = SC_TIMER_GET_ELAPSED(keygen_timer);
        printf("KeyGen time:   %2.3f\n", elapsed);
        elapsed = SC_TIMER_GET_ELAPSED(extract_timer);
        printf("Extract time:  %2.3f (%5.3f per sec)\n", elapsed, (double)1024 / elapsed);
#ifdef SC_IBE_MESSAGE_LENGTH_N
        printf("Encrypt time: %2.3f (%5.3f per sec, %5.0f bytes per sec)\n", elapsed_enc[0], (double)MAX_ITER / elapsed_enc[0], MAX_ITER * MIN_MSG_LEN / elapsed_enc[0]);
        printf("Decrypt time: %2.3f (%5.3f per sec, %5.0f bytes per sec)\n", elapsed_dec[0], (double)MAX_ITER / elapsed_dec[0], MAX_ITER * MIN_MSG_LEN / elapsed_dec[0]);
#else
        printf("Encrypt time %-5d: %2.3f (%5.3f per sec, %5.0f bytes per sec)\n", MIN_MSG_LEN, elapsed_enc[0], (double)MAX_ITER / elapsed_enc[0], MAX_ITER * MIN_MSG_LEN / elapsed_enc[0]);
        printf("Encrypt time %-5d: %2.3f (%5.3f per sec, %5.0f bytes per sec)\n", 4 * MIN_MSG_LEN, elapsed_enc[1], (double)MAX_ITER / elapsed_enc[1], MAX_ITER * 4 * MIN_MSG_LEN / elapsed_enc[1]);
        printf("Encrypt time %-5d: %2.3f (%5.3f per sec, %5.0f bytes per sec)\n", 16 * MIN_MSG_LEN, elapsed_enc[2], (double)MAX_ITER / elapsed_enc[2], MAX_ITER * 16 * MIN_MSG_LEN / elapsed_enc[2]);
        printf("Encrypt time %-5d: %2.3f (%5.3f per sec, %5.0f bytes per sec)\n", 64 * MIN_MSG_LEN, elapsed_enc[3], (double)MAX_ITER / elapsed_enc[3], MAX_ITER * 64 * MIN_MSG_LEN / elapsed_enc[3]);
        printf("Decrypt time %-5d: %2.3f (%5.3f per sec, %5.0f bytes per sec)\n", MIN_MSG_LEN, elapsed_dec[0], (double)MAX_ITER / elapsed_dec[0], MAX_ITER * MIN_MSG_LEN / elapsed_dec[0]);
        printf("Decrypt time %-5d: %2.3f (%5.3f per sec, %5.0f bytes per sec)\n", 4 * MIN_MSG_LEN, elapsed_dec[1], (double)MAX_ITER / elapsed_dec[1], MAX_ITER * 4 * MIN_MSG_LEN / elapsed_dec[1]);
        printf("Decrypt time %-5d: %2.3f (%5.3f per sec, %5.0f bytes per sec)\n", 16 * MIN_MSG_LEN, elapsed_dec[2], (double)MAX_ITER / elapsed_dec[2], MAX_ITER * 16 * MIN_MSG_LEN / elapsed_dec[2]);
        printf("Decrypt time %-5d: %2.3f (%5.3f per sec, %5.0f bytes per sec)\n", 64 * MIN_MSG_LEN, elapsed_dec[3], (double)MAX_ITER / elapsed_dec[3], MAX_ITER * 64 * MIN_MSG_LEN / elapsed_dec[3]);
#endif
    }

    SC_TIMER_DESTROY(keygen_timer);
    SC_TIMER_DESTROY(extract_timer);
    SC_TIMER_DESTROY(enc_timer);
    SC_TIMER_DESTROY(dec_timer);
    prng_destroy(prng_ctx);
    return EXIT_SUCCESS;

error_return:
    SC_TIMER_DESTROY(keygen_timer);
    SC_TIMER_DESTROY(extract_timer);
    SC_TIMER_DESTROY(enc_timer);
    SC_TIMER_DESTROY(dec_timer);
    prng_destroy(prng_ctx);
    if (sc) safecrypto_destroy(sc);
    return EXIT_FAILURE;
#endif
}


