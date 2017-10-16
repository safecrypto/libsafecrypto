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

#include <stdlib.h>
#include "safecrypto.h"
#include "safecrypto_debug.h"
#include "utils/crypto/hash.h"
#include "utils/crypto/prng.h"
#include "utils/threading/threading.h"

#include <string.h>


#define MAX_ITER    1024


void show_progress(char *msg, int32_t count, int32_t max)
{
    int i;
    int barWidth = 50;
    double progress = (double) count / max;

    printf("%-24s [", msg);
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
#ifdef DISABLE_SIGNATURES
    return EXIT_SUCCESS;
#else
    safecrypto_t *sc_sig_1 = NULL;
    safecrypto_t *sc_kem_1 = NULL;
    safecrypto_t *sc_sig_2 = NULL;
    safecrypto_t *sc_kem_2 = NULL;
    UINT32 flags[2] = {SC_FLAG_MORE, SC_FLAG_1_CSPRNG_AES_CTR_DRBG};

    int32_t i, j, l;
    UINT8 md[64], md2[64];
    UINT8 *c = NULL, *k = NULL;
    size_t c_len, k_len;
    utils_crypto_hash_t *hash = NULL;
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_SYSTEM,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    hash = utils_crypto_hash_create(SC_HASH_SHA2_512);

#ifdef USE_HUFFMAN_STATIC_ENTROPY
    flags[0] |= SC_FLAG_0_ENTROPY_HUFFMAN_STATIC;
#endif
    printf("2-Round Forward-Secure AKE\n");

    for (l=0; l<12; l++) {

        sc_scheme_e sig_scheme;
        SINT32 sig_set;
        char disp_msg[128];

        switch (l % 6) {
            case 0:
            {
#if defined(DISABLE_SIG_ENS) || defined(DISABLE_KEM_ENS)
                continue;
#else
                snprintf(disp_msg, 128, "%-11s", "ENS SIG");
                sig_scheme = SC_SCHEME_SIG_ENS;
                sig_set    = 0;
#endif
            } break;
            case 1:
            {
#if defined(DISABLE_SIG_RING_TESLA) || defined(DISABLE_KEM_ENS)
                continue;
#else
                snprintf(disp_msg, 128, "%-11s", "RING-TESLA");
                sig_scheme = SC_SCHEME_SIG_RING_TESLA;
                sig_set    = 0;
#endif
            } break;
            case 2:
            {
#if defined(DISABLE_SIG_BLISS_B) || defined(DISABLE_KEM_ENS)
                continue;
#else
                snprintf(disp_msg, 128, "%-11s", "BLISS-B");
                sig_scheme = SC_SCHEME_SIG_BLISS;
                sig_set    = 1;
#endif
            } break;
            case 3:
            {
#if defined(DISABLE_SIG_DLP) || defined(DISABLE_KEM_ENS)
                continue;
#else
                snprintf(disp_msg, 128, "%-11s", "DLP SIG");
                sig_scheme = SC_SCHEME_SIG_DLP;
                sig_set    = 0;
#endif
            } break;
            case 4:
            {
#if defined(DISABLE_SIG_DILITHIUM) || defined(DISABLE_KEM_ENS)
                continue;
#else
                snprintf(disp_msg, 128, "%-11s", "DILITHIUM");
                sig_scheme = SC_SCHEME_SIG_DILITHIUM;
                sig_set    = 0;
#endif
            } break;
            case 5:
            {
#if defined(DISABLE_SIG_DILITHIUM_G) || defined(DISABLE_KEM_ENS)
                continue;
#else
                snprintf(disp_msg, 128, "%-11s", "DILITHIUM-G");
                sig_scheme = SC_SCHEME_SIG_DILITHIUM_G;
                sig_set    = 0;
#endif
            } break;
        }

        sc_sig_1 = safecrypto_create(sig_scheme, sig_set, flags);
        if (NULL == sc_sig_1) {
            fprintf(stderr, "ERROR! safecrypto_create() failed\n");
            return EXIT_FAILURE;
        }
        sc_sig_2 = safecrypto_create(sig_scheme, sig_set, flags);
        if (NULL == sc_sig_2) {
            fprintf(stderr, "ERROR! safecrypto_create() failed\n");
            return EXIT_FAILURE;
        }

        if (6 <= l) {
            snprintf(disp_msg + strlen(disp_msg), 128 - strlen(disp_msg), "%-13s", " / KYBER KEM");

            sc_kem_1 = safecrypto_create(SC_SCHEME_KEM_KYBER, 0, flags);
            if (NULL == sc_kem_1) {
                fprintf(stderr, "ERROR! safecrypto_create() failed\n");
                return EXIT_FAILURE;
            }
            sc_kem_2 = safecrypto_create(SC_SCHEME_KEM_KYBER, 0, flags);
            if (NULL == sc_kem_2) {
                fprintf(stderr, "ERROR! safecrypto_create() failed\n");
                return EXIT_FAILURE;
            }
        }
        else {
            snprintf(disp_msg + strlen(disp_msg), 128 - strlen(disp_msg), "%-13s", " / ENS KEM");

            sc_kem_1 = safecrypto_create(SC_SCHEME_KEM_ENS, 0, flags);
            if (NULL == sc_kem_1) {
                fprintf(stderr, "ERROR! safecrypto_create() failed\n");
                return EXIT_FAILURE;
            }
            sc_kem_2 = safecrypto_create(SC_SCHEME_KEM_ENS, 0, flags);
            if (NULL == sc_kem_2) {
                fprintf(stderr, "ERROR! safecrypto_create() failed\n");
                return EXIT_FAILURE;
            }
        }

        // Generate Signature Keys for both parties
        if (SC_FUNC_SUCCESS != safecrypto_keygen(sc_sig_1)) {
            fprintf(stderr, "ERROR! safecrypto_keygen() failed\n");
            goto error_return;
        }
        if (SC_FUNC_SUCCESS != safecrypto_keygen(sc_sig_2)) {
            fprintf(stderr, "ERROR! safecrypto_keygen() failed\n");
            goto error_return;
        }
        UINT8 *sig_v_1, *sig_v_2;
        size_t sig_v_1_len = 0, sig_v_2_len = 0;
        if (SC_FUNC_SUCCESS != safecrypto_public_key_encode(sc_sig_1, &sig_v_1, &sig_v_1_len)) {
            fprintf(stderr, "ERROR! safecrypto_public_key_encode() failed\n");
            goto error_return;
        }
        if (SC_FUNC_SUCCESS != safecrypto_public_key_encode(sc_sig_2, &sig_v_2, &sig_v_2_len)) {
            fprintf(stderr, "ERROR! safecrypto_public_key_encode() failed\n");
            goto error_return;
        }


        if (SC_FUNC_SUCCESS != safecrypto_public_key_load(sc_sig_1, sig_v_2, sig_v_2_len)) {
            fprintf(stderr, "ERROR! safecrypto_public_key_load() failed\n");
            goto error_return;
        }
        if (SC_FUNC_SUCCESS != safecrypto_public_key_load(sc_sig_2, sig_v_1, sig_v_1_len)) {
            fprintf(stderr, "ERROR! safecrypto_public_key_load() failed\n");
            goto error_return;
        }

        for (i=0; i<MAX_ITER; i++) {

            // Party 1 - Generate KEM Encapsulation and Decapsulation keys
            if (SC_FUNC_SUCCESS != safecrypto_keygen(sc_kem_1)) {
                fprintf(stderr, "ERROR! safecrypto_keygen() failed\n");
                goto error_return;
            }
            UINT8 *kem_e;
            size_t kem_e_len = 0;
            if (SC_FUNC_SUCCESS != safecrypto_public_key_encode(sc_kem_1, &kem_e, &kem_e_len)) {
                fprintf(stderr, "ERROR! safecrypto_public_key_encode() failed\n");
                goto error_return;
            }

            // Party 1 - Sign the Encapsulation key
            UINT8 *msg_1;
            size_t msg_1_len = 0;
            if (SC_FUNC_SUCCESS != safecrypto_sign(sc_sig_1, kem_e, kem_e_len, &msg_1, &msg_1_len)) {
                fprintf(stderr, "ERROR! safecrypto_sign() failed\n");
                goto error_return;
            }

            // Party 2 - Verify the signed Encapsulation Key using Party 1's verification key
            if (SC_FUNC_SUCCESS != safecrypto_verify(sc_sig_2, kem_e, kem_e_len, msg_1, msg_1_len)) {
                fprintf(stderr, "ERROR! 1 safecrypto_verify() failed\n");
                goto error_return;
            }

            // Party 2 - Use the verified Encapsulation Key to encapsulate a random secret key
            if (SC_FUNC_SUCCESS != safecrypto_public_key_load(sc_kem_2, kem_e, kem_e_len)) {
                fprintf(stderr, "ERROR! safecrypto_public_key_load() failed\n");
                goto error_return;
            }
            c_len = 0, k_len = 0;
            if (SC_FUNC_SUCCESS != safecrypto_encapsulation(sc_kem_2, &c, &c_len, &k, &k_len)) {
                fprintf(stderr, "ERROR! safecrypto_sign() failed\n");
                goto error_return;
            }

            // Party 2 - Hash the Original Signed message with the Encapsulation output and Sign it
            hash_init(hash);
            hash_update(hash, msg_1, msg_1_len);
            hash_update(hash, c, c_len);
            hash_update(hash, k, k_len);
            hash_final(hash, md);

            UINT8 *msg_2;
            size_t msg_2_len = 0;
            if (SC_FUNC_SUCCESS != safecrypto_sign(sc_sig_2, md, 64, &msg_2, &msg_2_len)) {
                fprintf(stderr, "ERROR! safecrypto_sign() failed\n");
                goto error_return;
            }

            // Party 1 - Verify the message from Party 2 and obtain (c,Auth)
            if (SC_FUNC_SUCCESS != safecrypto_verify(sc_sig_1, md, 64, msg_2, msg_2_len)) {
                fprintf(stderr, "ERROR! 2 safecrypto_verify() failed\n");
                goto error_return;
            }

            // Party 1 - Decapsulate the KEM ciphertext to obtain the shared secret
            UINT8 *k_2;
            size_t k_2_len = 0;
            if (SC_FUNC_SUCCESS != safecrypto_decapsulation(sc_kem_1, c, c_len, &k_2, &k_2_len)) {
                fprintf(stderr, "ERROR! safecrypto_sign() failed\n");
                goto error_return;
            }

            // Party 1 - Check that Auth is correct
            hash_init(hash);
            hash_update(hash, msg_1, msg_1_len);
            hash_update(hash, c, c_len);
            hash_update(hash, k_2, k_2_len);
            hash_final(hash, md2);
            for (j=0; j<64; j++) {
                if (md[j] != md2[j]) {
                    fprintf(stderr, "ERROR! Auth mismatch\n");
                    goto error_return;
                }
            }

            // Party 1/2 - Form the secret key as the hash of the messages and shared secret
            hash_init(hash);
            hash_update(hash, msg_1, msg_1_len);
            hash_update(hash, msg_2, msg_2_len);
            hash_update(hash, k, k_len);
            hash_final(hash, md);

            free(c);
            free(k);
            free(kem_e);
            free(msg_1);
            free(msg_2);
            free(k_2);

            if ((i & 0x1F) == 0x1F) show_progress(disp_msg, i, MAX_ITER);
        }

        show_progress(disp_msg, MAX_ITER, MAX_ITER);
    }

error_return:
    for (i = 0; i<4; i++) {
        safecrypto_t *sc = (i==0)? sc_sig_1 :
                           (i==1)? sc_sig_2 :
                           (i==2)? sc_kem_1 :
                                   sc_kem_2;
        if (sc) {
            UINT32 error;
            const char *file;
            SINT32 line;
            while (SC_OK != (error = safecrypto_err_get_error_line(sc, &file, &line))) {
                printf("ERROR: %08X, %s, line %d\n", error, file, line);
            }
        }
    }
    utils_crypto_hash_destroy(hash);
    prng_destroy(prng_ctx);
    safecrypto_destroy(sc_sig_1);
    safecrypto_destroy(sc_sig_2);
    safecrypto_destroy(sc_kem_1);
    safecrypto_destroy(sc_kem_2);
    return EXIT_SUCCESS;
#endif
}


