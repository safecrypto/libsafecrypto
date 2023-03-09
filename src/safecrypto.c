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

#include "safecrypto.h"
#include "safecrypto_debug.h"
#include "safecrypto_error.h"
#include "safecrypto_version.h"

#include "utils/crypto/xof.h"
#include "utils/crypto/prng.h"
#include "utils/crypto/aes/aes.h"
#ifdef HAVE_MULTITHREADING
#include "utils/threading/threading.h"
#endif

#include "schemes/helloworld/helloworld.h"
#ifndef DISABLE_SIG_BLISS_B
#include "schemes/sig/bliss_b/bliss_b.h"
#endif
#if !defined(DISABLE_SIG_DILITHIUM) || !defined(DISABLE_SIG_DILITHIUM_G)
#include "schemes/sig/dilithium/dilithium.h"
#endif
#ifndef DISABLE_SIG_RING_TESLA
#include "schemes/sig/ring_tesla/ring_tesla.h"
#endif
#if !defined(DISABLE_SIG_DLP) || !defined(DISABLE_SIG_ENS)
#include "schemes/sig/ens_dlp/ens_dlp_sig.h"
#endif
#ifndef DISABLE_ENC_RLWE
#include "schemes/enc/rlwe_enc/rlwe_enc.h"
#endif
#ifndef DISABLE_ENC_KYBER
#include "schemes/enc/kyber/kyber_enc.h"
#endif
#ifndef DISABLE_KEM_ENS
#include "schemes/kem/ens/ens_kem.h"
#endif
#ifndef DISABLE_KEM_KYBER
#include "schemes/kem/kyber/kyber_kem.h"
#endif
#ifndef DISABLE_IBE_DLP
#include "schemes/ibe/dlp/dlp_ibe.h"
#endif
#ifndef DISABLE_ECDH
#include "schemes/dh/ecdh/ecdh.h"
#endif
#ifndef DISABLE_ECDSA
#include "schemes/sig/ecdsa/ecdsa.h"
#endif
#ifndef DISABLE_SIG_FALCON
#include "schemes/sig/falcon/falcon.h"
#endif

#include <string.h>


// The number of PRNG instances maintained by an instance of the library
#if !defined(ENABLE_BAREMETAL)
#define NUM_PRNG_INSTANCES  4
#else
#define NUM_PRNG_INSTANCES  1
#endif

// A table into which every algorithm is encoded
static safecrypto_alg_t safecrypto_algorithms[] = {
    { SC_SCHEME_SIG_HELLO_WORLD, helloworld_create, helloworld_destroy, NULL, NULL, NULL,
      NULL, NULL, NULL,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, helloworld_sign, helloworld_verify, NULL, NULL, NULL, NULL, NULL },
#if defined(DISABLE_SIGNATURES) || defined(DISABLE_SIG_BLISS_B)
    { SC_SCHEME_SIG_BLISS, NULL, NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
#else
    { SC_SCHEME_SIG_BLISS, bliss_b_create, bliss_b_destroy, bliss_b_keygen,
      bliss_b_set_key_coding, bliss_b_get_key_coding,
      bliss_b_pubkey_load, bliss_b_privkey_load, bliss_b_pubkey_encode, bliss_b_privkey_encode,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, bliss_b_sign, bliss_b_verify, NULL, NULL, NULL, NULL, bliss_b_stats },
#endif
#if defined(DISABLE_SIGNATURES) || defined(DISABLE_SIG_DILITHIUM)
    { SC_SCHEME_SIG_DILITHIUM, NULL, NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
#else
    { SC_SCHEME_SIG_DILITHIUM, dilithium_create, dilithium_destroy, dilithium_keygen,
      dilithium_set_key_coding, dilithium_get_key_coding,
      dilithium_pubkey_load, dilithium_privkey_load, dilithium_pubkey_encode, dilithium_privkey_encode,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, dilithium_sign, dilithium_verify, NULL, NULL, NULL, NULL, dilithium_stats },
#endif
#if defined(DISABLE_SIGNATURES) || defined(DISABLE_SIG_DILITHIUM_G)
    { SC_SCHEME_SIG_DILITHIUM_G, NULL, NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
#else
    { SC_SCHEME_SIG_DILITHIUM_G, dilithium_create, dilithium_destroy, dilithium_keygen,
      dilithium_set_key_coding, dilithium_get_key_coding,
      dilithium_pubkey_load, dilithium_privkey_load, dilithium_pubkey_encode, dilithium_privkey_encode,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, dilithium_sign, dilithium_verify, NULL, NULL, NULL, NULL, dilithium_stats },
#endif
#if defined(DISABLE_SIGNATURES) || defined(DISABLE_SIG_RING_TESLA)
    { SC_SCHEME_SIG_RING_TESLA, NULL, NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
#else
    { SC_SCHEME_SIG_RING_TESLA, ring_tesla_create, ring_tesla_destroy, ring_tesla_keygen,
      ring_tesla_set_key_coding, ring_tesla_get_key_coding,
      ring_tesla_pubkey_load, ring_tesla_privkey_load, ring_tesla_pubkey_encode, ring_tesla_privkey_encode,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, ring_tesla_sign, ring_tesla_verify, NULL, NULL, NULL, NULL, ring_tesla_stats },
#endif
#if defined(DISABLE_SIGNATURES) || defined(DISABLE_SIG_ENS)
    { SC_SCHEME_SIG_ENS, NULL, NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
#else
    { SC_SCHEME_SIG_ENS, ens_dlp_sig_create, ens_dlp_sig_destroy, ens_dlp_sig_keygen,
      ens_dlp_set_key_coding, ens_dlp_get_key_coding,
      ens_dlp_sig_pubkey_load, ens_dlp_sig_privkey_load, ens_dlp_sig_pubkey_encode, ens_dlp_sig_privkey_encode,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, ens_dlp_sig_sign, ens_dlp_sig_verify, NULL, NULL, NULL, NULL, ens_dlp_sig_stats },
#endif
#if defined(DISABLE_SIGNATURES) || defined(DISABLE_SIG_ENS)
    { SC_SCHEME_SIG_ENS_WITH_RECOVERY, NULL, NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
#else
    { SC_SCHEME_SIG_ENS_WITH_RECOVERY, ens_dlp_sig_create, ens_dlp_sig_destroy, ens_dlp_sig_keygen,
      ens_dlp_set_key_coding, ens_dlp_get_key_coding,
      ens_dlp_sig_pubkey_load, ens_dlp_sig_privkey_load, ens_dlp_sig_pubkey_encode, ens_dlp_sig_privkey_encode,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, ens_dlp_sig_sign_recovery, ens_dlp_sig_verify_recovery, NULL, NULL, ens_dlp_sig_stats },
#endif
#if defined(DISABLE_SIGNATURES) || defined(DISABLE_SIG_DLP)
    { SC_SCHEME_SIG_DLP, NULL, NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
#else
    { SC_SCHEME_SIG_DLP, ens_dlp_sig_create, ens_dlp_sig_destroy, ens_dlp_sig_keygen,
      ens_dlp_set_key_coding, ens_dlp_get_key_coding,
      ens_dlp_sig_pubkey_load, ens_dlp_sig_privkey_load, ens_dlp_sig_pubkey_encode, ens_dlp_sig_privkey_encode,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, ens_dlp_sig_sign, ens_dlp_sig_verify, NULL, NULL, NULL, NULL, ens_dlp_sig_stats },
#endif
#if defined(DISABLE_SIGNATURES) || defined(DISABLE_SIG_DLP)
    { SC_SCHEME_SIG_DLP_WITH_RECOVERY, NULL, NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
#else
    { SC_SCHEME_SIG_DLP_WITH_RECOVERY, ens_dlp_sig_create, ens_dlp_sig_destroy, ens_dlp_sig_keygen,
      ens_dlp_set_key_coding, ens_dlp_get_key_coding,
      ens_dlp_sig_pubkey_load, ens_dlp_sig_privkey_load, ens_dlp_sig_pubkey_encode, ens_dlp_sig_privkey_encode,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, ens_dlp_sig_sign_recovery, ens_dlp_sig_verify_recovery, NULL, NULL, ens_dlp_sig_stats },
#endif
#if defined(DISABLE_SIGNATURES) || defined(DISABLE_SIG_FALCON)
    { SC_SCHEME_SIG_FALCON, NULL, NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
#else
    { SC_SCHEME_SIG_FALCON, falcon_sig_create, falcon_sig_destroy, falcon_sig_keygen,
      falcon_sig_set_key_coding, falcon_sig_get_key_coding,
      falcon_sig_pubkey_load, falcon_sig_privkey_load, falcon_sig_pubkey_encode, falcon_sig_privkey_encode,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, falcon_sig_sign, falcon_sig_verify, NULL, NULL, NULL, NULL, falcon_sig_stats },
#endif
#if defined(DISABLE_ENCRYPTION) || defined(DISABLE_ENC_RLWE)
    { SC_SCHEME_ENC_RLWE, NULL, NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
#else
    { SC_SCHEME_ENC_RLWE, rlwe_enc_create, rlwe_enc_destroy, rlwe_enc_keygen,
      rlwe_enc_set_key_coding, rlwe_enc_get_key_coding,
      rlwe_enc_pubkey_load, rlwe_enc_privkey_load, rlwe_enc_pubkey_encode, rlwe_enc_privkey_encode,
      NULL, NULL, NULL, NULL, NULL, rlwe_enc_encrypt, rlwe_enc_decrypt, NULL, NULL, NULL, NULL, NULL, NULL, rlwe_enc_stats },
#endif
#if defined(DISABLE_ENCRYPTION) || defined(DISABLE_ENC_KYBER)
    { SC_SCHEME_ENC_KYBER_CPA, NULL, NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
#else
    { SC_SCHEME_ENC_KYBER_CPA, kyber_enc_create, kyber_enc_destroy, kyber_enc_keygen,
      kyber_enc_set_key_coding, kyber_enc_get_key_coding,
      kyber_enc_pubkey_load, kyber_enc_privkey_load, kyber_enc_pubkey_encode, kyber_enc_privkey_encode,
      NULL, NULL, NULL, NULL, NULL, kyber_enc_encrypt, kyber_enc_decrypt, NULL, NULL, NULL, NULL, NULL, NULL, kyber_enc_stats },
#endif
#if defined(DISABLE_KEM) || defined(DISABLE_KEM_ENS)
    { SC_SCHEME_KEM_ENS, NULL, NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
#else
    { SC_SCHEME_KEM_ENS, ens_kem_create, ens_kem_destroy, ens_kem_keygen,
      ens_kem_set_key_coding, ens_kem_get_key_coding,
      ens_kem_pubkey_load, ens_kem_privkey_load, ens_kem_pubkey_encode, ens_kem_privkey_encode,
      ens_kem_encapsulation, ens_kem_decapsulation, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, ens_kem_stats },
#endif
#if defined(DISABLE_KEM) || defined(DISABLE_KEM_KYBER)
    { SC_SCHEME_KEM_KYBER, NULL, NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
#else
    { SC_SCHEME_KEM_KYBER, kyber_kem_create, kyber_kem_destroy, kyber_kem_keygen,
      kyber_kem_set_key_coding, kyber_kem_get_key_coding,
      kyber_kem_pubkey_load, kyber_kem_privkey_load, kyber_kem_pubkey_encode, kyber_kem_privkey_encode,
      kyber_kem_encapsulation, kyber_kem_decapsulation, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, kyber_kem_stats },
#endif
#if defined(DISABLE_IBE) || defined(DISABLE_IBE_DLP)
    { SC_SCHEME_IBE_DLP, NULL, NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
#else
    { SC_SCHEME_IBE_DLP, dlp_ibe_create, dlp_ibe_destroy, dlp_ibe_keygen,
      dlp_ibe_set_key_coding, dlp_ibe_get_key_coding,
      dlp_ibe_pubkey_load, dlp_ibe_privkey_load, dlp_ibe_pubkey_encode, dlp_ibe_privkey_encode,
      NULL, NULL, dlp_ibe_secret_key, dlp_ibe_extract, dlp_ibe_encrypt, NULL, dlp_ibe_decrypt, NULL, NULL, NULL, NULL, NULL, NULL, dlp_ibe_stats },
#endif
#if defined(DISABLE_KEM) || defined(DISABLE_ECDH)
    { SC_SCHEME_DH_ECDH, NULL, NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
#else
    { SC_SCHEME_DH_ECDH, ecdh_create, ecdh_destroy, NULL,
      NULL, NULL,
      NULL, ecdh_privkey_load, NULL, ecdh_privkey_encode,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, ecdh_diffie_hellman_init, ecdh_diffie_hellman_final, ecdh_stats },
#endif
#if defined(DISABLE_SIG) || defined(DISABLE_SIG_ECDSA)
    { SC_SCHEME_SIG_ECDSA, NULL, NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
#else
    { SC_SCHEME_SIG_ECDSA, ecdsa_create, ecdsa_destroy, ecdsa_keygen,
      NULL, NULL,
      ecdsa_pubkey_load, ecdsa_privkey_load, ecdsa_pubkey_encode, ecdsa_privkey_encode,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, ecdsa_sign, ecdsa_verify, NULL, NULL, NULL, NULL, ecdsa_stats },
#endif
};

// A function pointer used as a callback function for an extenral entropy source
extern prng_entropy_callback entropy_callback;

// A linked list that lists all supported PKC signature schemes
static sc_pkc_scheme_t g_pkc_signature_schemes[SC_SCHEME_MAX];

// A linked list that lists all supported PKC encryption schemes
static sc_pkc_scheme_t g_pkc_encryption_schemes[SC_SCHEME_MAX];

// A linked list that lists all supported PKC KEM schemes
static sc_pkc_scheme_t g_pkc_kem_schemes[SC_SCHEME_MAX];

// A linked list that lists all supported PKC IBE schemes
static sc_pkc_scheme_t g_pkc_ibe_schemes[SC_SCHEME_MAX];

// A linked list that lists all supported hash schemes
static sc_hash_t g_hash_schemes[SC_HASH_MAX];

// A linked list that lists all supported XOF schemes
static sc_xof_t g_xof_schemes[SC_XOF_MAX];

// A linked list that lists all supported PRNG schemes
static sc_prng_t g_prng_schemes[SC_PRNG_MAX];


/****************************************************************************
 * PRIVATE FUNCTIONS
 ****************************************************************************/


/// Determine if the algorithm is supported
/// @param scheme The scheme to be used
/// @return SC_OK if the algorithm is supported, SC_OUT_OF_BOUNDS otherwise
static SINT32 is_alg_avail(sc_scheme_e scheme)
{
    SINT32 i = 0;
    while (i<ALG_TABLE_MAX) {
        sc_scheme_e alg_name = safecrypto_algorithms[i].scheme;
        if (scheme == alg_name && NULL != safecrypto_algorithms[i].create) {
            return SC_OK;
        }
        i++;
    }

    return SC_OUT_OF_BOUNDS;
}

/// Get the index of the named algorithm
/// @param name The human readable name of the algorithm
/// @return The index of the algorithm
static size_t get_alg_index(sc_scheme_e scheme)
{
    size_t i = 0;
    while (i < ALG_TABLE_MAX) {
        sc_scheme_e alg_name = safecrypto_algorithms[i].scheme;
        if (scheme == alg_name) {
            return i;
        }
        i++;
    }

    return 0;
}

/// Free memory resources associated with the given SAFEcrypto object
static SINT32 free_memory(safecrypto_t **sc_ptr)
{
    SINT32 retcode = SC_FUNC_SUCCESS;
    safecrypto_t *sc = *sc_ptr;

    if (sc) {
        size_t i;

        // Release memory associated with the private and public keys
        if (sc->privkey) {
            if (sc->privkey->key) {
                SC_FREE(sc->privkey->key, sc->privkey->len);
            }
            SC_FREE(sc->privkey, sizeof(sc_privkey_t));
        }
        if (sc->pubkey) {
            if (sc->pubkey->key) {
                SC_FREE(sc->pubkey->key, sc->pubkey->len);
            }
            SC_FREE(sc->pubkey, sizeof(sc_pubkey_t));
        }

        // Release memory resources associated with the error queue
        if (err_destroy(&sc->error_queue) != SC_FUNC_SUCCESS) {
            SC_LOG_ERROR(sc, SC_ERROR);
            retcode = SC_FUNC_FAILURE;
        }

        // Release memory resources associated with the debug interface
        if (sc_debug_destroy(sc) != SC_FUNC_SUCCESS) {
            SC_LOG_ERROR(sc, SC_ERROR);
            retcode = SC_FUNC_FAILURE;
        }

        // Release memory resources associated with the PRNG
        for (i=0; i<NUM_PRNG_INSTANCES; i++) {
          prng_destroy(sc->prng_ctx[i]);
        }
        SC_FREE(sc->prng_ctx, NUM_PRNG_INSTANCES * sizeof(prng_ctx_t*));

        // Release memory associated with statistics
        sc_free_stats(sc);

        // Finally, free resources associated with the SAFEcrypto struct
        SC_FREE(sc, sizeof(safecrypto_t));
        *sc_ptr = NULL;
    }

    return retcode;
}

/// Allocate memory for the SAFEcrypto object and initialise
static safecrypto_t * init_safecrypto(sc_scheme_e scheme, const UINT32 *flags)
{
    size_t i, num_flag_words = 0;
    SINT32 success = 1;
    safecrypto_t *sc = SC_MALLOC(sizeof(safecrypto_t));
    if (sc == NULL) {
        return NULL;
    }

    // Initialise with the selected scheme
    sc->scheme = scheme;

    // Determine the number of flag words
    while (flags[num_flag_words++] & SC_FLAG_MORE) {
    }

    // Initialise the (CS)PRNG
    sc->prng_ctx = SC_MALLOC(NUM_PRNG_INSTANCES * sizeof(prng_ctx_t*));
    safecrypto_prng_threading_e prng_mt_enabled = SC_PRNG_THREADING_NONE;
    size_t seed_period = 0x00100000;

    safecrypto_prng_e type = SC_PRNG_AES_CTR_DRBG;
    if (num_flag_words > 1) {
        if (flags[1] & SC_FLAG_1_CSPRNG_AES_CTR_DRBG) {
            type = SC_PRNG_AES_CTR_DRBG;
        }
        else if (flags[1] & SC_FLAG_1_CSPRNG_AES_CTR) {
            type = SC_PRNG_AES_CTR;
        }
        else if (flags[1] & SC_FLAG_1_CSPRNG_ISAAC) {
            type = SC_PRNG_ISAAC;
        }
        else if (flags[1] & SC_FLAG_1_CSPRNG_SALSA) {
            type = SC_PRNG_SALSA;
        }
        else if (flags[1] & SC_FLAG_1_CSPRNG_CHACHA) {
            type = SC_PRNG_CHACHA;
        }
        else if (flags[1] & SC_FLAG_1_CSPRNG_KISS) {
            type = SC_PRNG_KISS;
        }
        else if (flags[1] & SC_FLAG_1_CSPRNG_SHA3_512_DRBG) {
            type = SC_PRNG_HASH_DRBG_SHA3_512;
        }
        else if (flags[1] & SC_FLAG_1_CSPRNG_SHA3_256_DRBG) {
            type = SC_PRNG_HASH_DRBG_SHA3_256;
        }
        else if (flags[1] & SC_FLAG_1_CSPRNG_SHA2_512_DRBG) {
            type = SC_PRNG_HASH_DRBG_SHA2_512;
        }
        else if (flags[1] & SC_FLAG_1_CSPRNG_SHA2_256_DRBG) {
            type = SC_PRNG_HASH_DRBG_SHA2_256;
        }
        else if (flags[1] & SC_FLAG_1_CSPRNG_BLAKE2_512_DRBG) {
            type = SC_PRNG_HASH_DRBG_BLAKE2_512;
        }
        else if (flags[1] & SC_FLAG_1_CSPRNG_BLAKE2_256_DRBG) {
            type = SC_PRNG_HASH_DRBG_BLAKE2_256;
        }
        else if (flags[1] & SC_FLAG_1_CSPRNG_WHIRLPOOL_DRBG) {
            type = SC_PRNG_HASH_DRBG_WHIRLPOOL_512;
        }
    }

    // Set the (CS)PRNG entropy source
    static const UINT8 nonce[16] = "SAFEcrypto nonce";
    for (i=0; i<NUM_PRNG_INSTANCES; i++) {
        safecrypto_entropy_e entropy = SC_ENTROPY_RANDOM;
        if (num_flag_words > 1) {
            if (flags[1] & SC_FLAG_1_CSPRNG_USE_DEV_RANDOM) {
                entropy = SC_ENTROPY_DEV_RANDOM;
            }
            else if (flags[1] & SC_FLAG_1_CSPRNG_USE_DEV_URANDOM) {
                entropy = SC_ENTROPY_DEV_URANDOM;
            }
            else if (flags[1] & SC_FLAG_1_CSPRNG_USE_OS_RANDOM) {
                entropy = SC_ENTROPY_RANDOM;
            }
            else if (flags[1] & SC_FLAG_1_CSPRNG_USE_CALLBACK_RANDOM) {
                entropy = SC_ENTROPY_CALLBACK;
            }
        }

        sc->prng_ctx[i] = prng_create(entropy, type, prng_mt_enabled, seed_period);
        if (NULL == sc->prng_ctx[i]) {
            size_t j;
            for (j=0; j<i; j++) {
                prng_destroy(sc->prng_ctx[j]);
            }
            SC_FREE(sc->prng_ctx, NUM_PRNG_INSTANCES * sizeof(prng_ctx_t*));
            SC_FREE(sc, sizeof(safecrypto_t));
            return NULL;
        }
        prng_init(sc->prng_ctx[i], nonce, 16);
    }

    // Set a flag indicating if the "temp" intermediate buffer should be
    // created on the heap or is externally defined. Also reset the flag indicating
    // that API functions are disabled if the external intermediate memory has not
    // been configured with a call to safecrypto_memory_external().
    sc->temp_external_flag = 0;
    sc->temp_ready         = 1;
    if (num_flag_words > 2 && (flags[2] & SC_FLAG_2_MEMORY_TEMP_EXTERNAL)) {
        sc->temp_external_flag  = 1;
        sc->temp_ready          = 0;
    }

    // Configure the debug level
#ifdef DEBUG
    sc->debug_level = SC_LEVEL_DEBUG;
#else
    sc->debug_level = SC_LEVEL_NONE;
#endif

    // Configure the entropy coding techniques to be applied within
    // the specified algorithm
    sc->coding_pub_key.type             = SC_ENTROPY_NONE;
    sc->coding_priv_key.type            = SC_ENTROPY_NONE;
    sc->coding_signature.type           = SC_ENTROPY_NONE;
    for (i=0; i<ENTROPY_MAX_DIST; i++) {
        sc->dist[i] = NULL;
    }

    // Disable sample blinding by default
    sc->blinding = NORMAL_SAMPLES;

    // Disable pattern masking by default
    sc->pattern  = SCA_PATTERN_DISABLE;

    if (flags[0] & SC_FLAG_MORE) {
        if (flags[1] & SC_FLAG_MORE) {
            // Enable blinding (mixing together with randomized order) or
            // shuffling (on-the-fly) of the Gaussian samples
            sc->blinding =
                (flags[2] & SC_FLAG_2_SAMPLE_SCA_BLINDING)? BLINDING_SAMPLES :
                (flags[2] & SC_FLAG_2_SAMPLE_SCA_SHUFFLE)?  SHUFFLE_SAMPLES :
                                                            NORMAL_SAMPLES;

            // Enable the random discarding of a proportion of the samples at a specified rate
            sc->pattern |=
                (SC_FLAG_2_SAMPLE_SCA_DISCARD_HI == (flags[2] & SC_FLAG_2_SAMPLE_SCA_DISCARD_HI))? SCA_PATTERN_SAMPLE_DISCARD_HI :
                (SC_FLAG_2_SAMPLE_SCA_DISCARD_MD == (flags[2] & SC_FLAG_2_SAMPLE_SCA_DISCARD_MD))? SCA_PATTERN_SAMPLE_DISCARD_MD :
                (SC_FLAG_2_SAMPLE_SCA_DISCARD_LO == (flags[2] & SC_FLAG_2_SAMPLE_SCA_DISCARD_LO))? SCA_PATTERN_SAMPLE_DISCARD_LO :
                                                                                                   SCA_PATTERN_DISABLE;

            // Perform random read access of LUTs associated with Gaussian sampling
            if (flags[2] & SC_FLAG_2_SAMPLE_CACHE_ACCESS) {
                sc->pattern |= SCA_PATTERN_SAMPLE_CACHE_ACCESS;
            }

            // Mask the operations of non-constant-time algorithms
            if (flags[2] & SC_FLAG_2_SAMPLE_NON_CT_MASK) {
                sc->pattern |= SCA_PATTERN_SAMPLE_NON_CT_MASK;
            }
        }
    }

    // Initialise the error buffer
    sc->error_queue = err_create();

    // Define the algorithm selected using the create function
    sc->alg_index = get_alg_index(scheme);

    // Allocate memory for the key-pair
    sc->privkey = SC_MALLOC(sizeof(sc_privkey_t));
    if (sc->privkey) {
        sc->privkey->key = NULL;
        sc->privkey->len = 0;
    }
    else {
        success = 0;
    }
    sc->pubkey = SC_MALLOC(sizeof(sc_pubkey_t));
    if (sc->pubkey) {
        sc->pubkey->key = NULL;
        sc->pubkey->len = 0;
    }
    else {
        success = 0;
    }

    // If initialised successfully, finally configure the debug logging
    if (success == 1) {
        if (sc_debug_init(sc) == SC_FUNC_SUCCESS)
            return sc;
    }

    free_memory(&sc);
    return NULL;
}

static void add_scheme_node(sc_pkc_scheme_t *list, sc_scheme_e scheme)
{
    size_t i = 0;
    while (NULL != list[i].next) {
        i++;
    }

    if (0 == i && SC_SCHEME_NONE == list[0].scheme) {
        list[0].scheme   = scheme;
        list[0].next     = NULL;
    }
    else {
        list[i+1].scheme = scheme;
        list[i+1].next   = NULL;
        list[i].next     = &list[i+1];
    }
}

static void add_hash_node(sc_hash_t *list, sc_hash_e scheme)
{
    size_t i = 0;
    while (NULL != list[i].next) {
        i++;
    }

    if (0 == i && SC_HASH_MAX == list[0].scheme) {
        list[0].scheme   = scheme;
        list[0].next     = NULL;
    }
    else {
        list[i+1].scheme = scheme;
        list[i+1].next   = NULL;
        list[i].next     = &list[i+1];
    }
}

static void add_xof_node(sc_xof_t *list, sc_xof_e scheme)
{
    size_t i = 0;
    while (NULL != list[i].next) {
        i++;
    }

    if (0 == i && SC_XOF_MAX == list[0].scheme) {
        list[0].scheme   = scheme;
        list[0].next     = NULL;
    }
    else {
        list[i+1].scheme = scheme;
        list[i+1].next   = NULL;
        list[i].next     = &list[i+1];
    }
}

static void add_prng_node(sc_prng_t *list, safecrypto_prng_e scheme)
{
    size_t i = 0;
    while (NULL != list[i].next) {
        i++;
    }

    if (0 == i && SC_PRNG_MAX == list[0].scheme) {
        list[0].scheme   = scheme;
        list[0].next     = NULL;
    }
    else {
        list[i+1].scheme = scheme;
        list[i+1].next   = NULL;
        list[i].next     = &list[i+1];
    }
}


/*****************************************************************************
 * PUBLIC FUNCTIONS
 *****************************************************************************/

UINT32 safecrypto_get_version(void)
{
    return (UINT32)((MAJOR_VERSION << 24) |
                    (MINOR_VERSION << 16) |
                    (BUILD_VERSION <<  8) |
                    (PATCH_VERSION      ));
}

const char* safecrypto_get_version_string(void)
{
    return BUILD_STRING;
}

const char *safecrypto_get_configure_invocation(void)
{
    return CONFIGURE_INVOCATION;
}

const sc_pkc_scheme_t *safecrypto_get_signature_schemes(void)
{
    g_pkc_signature_schemes[0].scheme = SC_SCHEME_NONE;
    g_pkc_signature_schemes[0].next   = NULL;

#if !defined(DISABLE_SIGNATURES)
#if !defined(DISABLE_SIG_BLISS_B)
    add_scheme_node(g_pkc_signature_schemes, SC_SCHEME_SIG_BLISS);
#endif
#if !defined(DISABLE_SIG_DILITHIUM)
    add_scheme_node(g_pkc_signature_schemes, SC_SCHEME_SIG_DILITHIUM);
#endif
#if !defined(DISABLE_SIG_DILITHIUM_G)
    add_scheme_node(g_pkc_signature_schemes, SC_SCHEME_SIG_DILITHIUM_G);
#endif
#if !defined(DISABLE_SIG_RING_TESLA)
    add_scheme_node(g_pkc_signature_schemes, SC_SCHEME_SIG_RING_TESLA);
#endif
#if !defined(DISABLE_SIG_ENS)
    add_scheme_node(g_pkc_signature_schemes, SC_SCHEME_SIG_ENS);
    add_scheme_node(g_pkc_signature_schemes, SC_SCHEME_SIG_ENS_WITH_RECOVERY);
#endif
#if !defined(DISABLE_SIG_DLP)
    add_scheme_node(g_pkc_signature_schemes, SC_SCHEME_SIG_DLP);
    add_scheme_node(g_pkc_signature_schemes, SC_SCHEME_SIG_DLP_WITH_RECOVERY);
#endif
#endif

    return (SC_SCHEME_NONE == g_pkc_signature_schemes[0].scheme)? NULL : g_pkc_signature_schemes;
}

const sc_pkc_scheme_t *safecrypto_get_encryption_schemes(void)
{
    g_pkc_encryption_schemes[0].scheme = SC_SCHEME_NONE;
    g_pkc_encryption_schemes[0].next   = NULL;

#if !defined(DISABLE_ENCRYPTION)
#if !defined(DISABLE_ENC_RLWE)
    add_scheme_node(g_pkc_encryption_schemes, SC_SCHEME_ENC_RLWE);
#endif
#if !defined(DISABLE_ENC_KYBER)
    add_scheme_node(g_pkc_encryption_schemes, SC_SCHEME_ENC_KYBER_CPA);
#endif
#endif

    return (SC_SCHEME_NONE == g_pkc_encryption_schemes[0].scheme)? NULL : g_pkc_encryption_schemes;
}

const sc_pkc_scheme_t *safecrypto_get_kem_schemes(void)
{
    g_pkc_kem_schemes[0].scheme = SC_SCHEME_NONE;
    g_pkc_kem_schemes[0].next   = NULL;

#if !defined(DISABLE_KEM)
#if !defined(DISABLE_KEM_ENS)
    add_scheme_node(g_pkc_kem_schemes, SC_SCHEME_KEM_ENS);
#endif
#if !defined(DISABLE_KEM_KYBER)
    add_scheme_node(g_pkc_kem_schemes, SC_SCHEME_KEM_KYBER);
#endif
#endif

    return (SC_SCHEME_NONE == g_pkc_kem_schemes[0].scheme)? NULL : g_pkc_kem_schemes;
}

const sc_pkc_scheme_t *safecrypto_get_ibe_schemes(void)
{
    g_pkc_ibe_schemes[0].scheme = SC_SCHEME_NONE;
    g_pkc_ibe_schemes[0].next   = NULL;

#if !defined(DISABLE_IBE)
#if !defined(DISABLE_IBE_DLP)
    add_scheme_node(g_pkc_ibe_schemes, SC_SCHEME_IBE_DLP);
#endif
#endif

    return (SC_SCHEME_NONE == g_pkc_ibe_schemes[0].scheme)? NULL : g_pkc_ibe_schemes;
}

SINT32 safecrypto_set_debug_level(safecrypto_t *sc, sc_debug_level_e level)
{
    return sc_set_verbosity(sc, level);
}

sc_debug_level_e safecrypto_get_debug_level(safecrypto_t *sc)
{
    return sc_get_verbosity(sc);
}

UINT32 safecrypto_err_get_error(safecrypto_t *sc)
{
    if (sc == NULL)
        return SC_GETERR_NULL_POINTER;

    return err_get_error(sc->error_queue);
}

UINT32 safecrypto_err_peek_error(safecrypto_t *sc)
{
    if (sc == NULL)
        return SC_GETERR_NULL_POINTER;

    return err_peek_error(sc->error_queue);
}

UINT32 safecrypto_err_get_error_line(safecrypto_t *sc, const char **file, SINT32 *line)
{
    if (sc == NULL)
        return SC_GETERR_NULL_POINTER;

    return err_get_error_line(sc->error_queue, file, line);
}

UINT32 safecrypto_err_peek_error_line(safecrypto_t *sc, const char **file, SINT32 *line)
{
    if (sc == NULL)
        return SC_GETERR_NULL_POINTER;

    return err_peek_error_line(sc->error_queue, file, line);
}

void safecrypto_err_clear_error(safecrypto_t *sc)
{
    if (sc == NULL)
        return;

    err_clear_error(sc->error_queue);
}

safecrypto_t * safecrypto_create(sc_scheme_e scheme, SINT32 set, const UINT32 *flags)
{
    safecrypto_t *sc = NULL;

    // Check if the named algorithm is available
    if (SC_OK != is_alg_avail(scheme)) {
        return NULL;
    }

    // Allocate memory for the SAFEcrypto object and set the algorithm
    sc = init_safecrypto(scheme, flags);
    if (sc == NULL) {
        return NULL;
    }

    // Initialise the selected algorithm in order to dynamically configure it
    if (safecrypto_algorithms[sc->alg_index].create(sc, set, flags) != SC_FUNC_SUCCESS) {
        (void)free_memory(&sc);
        sc = NULL;
    }

    return sc;
}

SINT32 safecrypto_destroy(safecrypto_t *sc)
{
    if (NULL == sc) {
        return SC_FUNC_FAILURE;
    }

    if (safecrypto_algorithms[sc->alg_index].destroy == NULL) {
        SC_LOG_ERROR(sc, SC_INVALID_FUNCTION_CALL);
        return SC_FUNC_FAILURE;
    }

    // Free any resources associated with the selected algorithm
    (void)safecrypto_algorithms[sc->alg_index].destroy( sc );

    // Free memory associated with the SAFEcrypto object
    if (free_memory(&sc) != SC_FUNC_SUCCESS)
        return SC_FUNC_FAILURE;

    return SC_FUNC_SUCCESS;
}

SINT32 safecrypto_scratch_external(safecrypto_t *sc, void *mem, size_t len)
{
    if (NULL == sc || NULL == mem) {
        return SC_FUNC_FAILURE;
    }

    // If temp_external_flag is set then set the temp pointer and
    // assert the temp_ready flag, otherwise return with failure
    if (sc->temp_external_flag) {
        if (len >= sc->temp_size) {
            sc->temp       = mem;
            sc->temp_ready = 1;
            return SC_FUNC_SUCCESS;
        }
    }

    return SC_FUNC_FAILURE;
}

SINT32 safecrypto_scratch_size(safecrypto_t *sc, size_t *len)
{
    if (NULL == sc || NULL == len) {
        return SC_FUNC_FAILURE;
    }

    // Assign the length of the required intermediate memory
    *len = sc->temp_size;

    return SC_FUNC_SUCCESS;
}

SINT32 safecrypto_entropy_callback(safecrypto_entropy_cb_func fn_entropy)
{
    return prng_set_entropy_callback((prng_entropy_callback) fn_entropy);
}

SINT32 safecrypto_keygen(safecrypto_t *sc)
{
    if (check_safecrypto(sc) != SC_FUNC_SUCCESS)
        return SC_FUNC_FAILURE;

    if (safecrypto_algorithms[sc->alg_index].keygen == NULL) {
        SC_LOG_ERROR(sc, SC_INVALID_FUNCTION_CALL);
        return SC_FUNC_FAILURE;
    }

    // Generate the keys as appropriate
    return safecrypto_algorithms[sc->alg_index].keygen( sc );
}

SINT32 safecrypto_set_key_coding(safecrypto_t *sc, sc_entropy_type_e pub,
    sc_entropy_type_e priv)
{
    if (check_safecrypto(sc) != SC_FUNC_SUCCESS)
        return SC_FUNC_FAILURE;

    if (pub < SC_ENTROPY_NONE || pub >= SC_ENTROPY_SCHEME_MAX)
        return SC_FUNC_FAILURE;
    if (priv < SC_ENTROPY_NONE || priv >= SC_ENTROPY_SCHEME_MAX)
        return SC_FUNC_FAILURE;

    // Set the key compression uniquely for each scheme
    if (safecrypto_algorithms[sc->alg_index].set_key_coding == NULL) {
        SC_LOG_ERROR(sc, SC_INVALID_FUNCTION_CALL);
        return SC_FUNC_FAILURE;
    }

    return safecrypto_algorithms[sc->alg_index].set_key_coding(sc, pub, priv);
}

SINT32 safecrypto_get_key_coding(safecrypto_t *sc, sc_entropy_type_e *pub,
    sc_entropy_type_e *priv)
{
    if (check_safecrypto(sc) != SC_FUNC_SUCCESS)
        return SC_FUNC_FAILURE;

    if (NULL == pub || NULL == priv) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    // Get the key compression uniquely for each scheme
    if (safecrypto_algorithms[sc->alg_index].get_key_coding == NULL) {
        SC_LOG_ERROR(sc, SC_INVALID_FUNCTION_CALL);
        return SC_FUNC_FAILURE;
    }

    return safecrypto_algorithms[sc->alg_index].get_key_coding(sc, pub, priv);
}

SINT32 safecrypto_public_key_load(safecrypto_t *sc, const UINT8 *key, size_t keylen)
{
    if (check_safecrypto(sc) != SC_FUNC_SUCCESS)
        return SC_FUNC_FAILURE;

    if (safecrypto_algorithms[sc->alg_index].pubkey_load == NULL) {
        SC_LOG_ERROR(sc, SC_INVALID_FUNCTION_CALL);
        return SC_FUNC_FAILURE;
    }

    // Generate the keys as appropriate
    return safecrypto_algorithms[sc->alg_index].pubkey_load(sc, key, keylen);
}

SINT32 safecrypto_private_key_load(safecrypto_t *sc, const UINT8 *key, size_t keylen)
{
    if (check_safecrypto(sc) != SC_FUNC_SUCCESS)
        return SC_FUNC_FAILURE;

    if (safecrypto_algorithms[sc->alg_index].privkey_load == NULL) {
        SC_LOG_ERROR(sc, SC_INVALID_FUNCTION_CALL);
        return SC_FUNC_FAILURE;
    }

    // Generate the keys as appropriate
    return safecrypto_algorithms[sc->alg_index].privkey_load(sc, key, keylen);
}

SINT32 safecrypto_public_key_encode(safecrypto_t *sc, UINT8 **key, size_t *keylen)
{
    if (check_safecrypto(sc) != SC_FUNC_SUCCESS)
        return SC_FUNC_FAILURE;

    if (NULL == key || NULL == keylen) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    if (safecrypto_algorithms[sc->alg_index].pubkey_encode == NULL) {
        SC_LOG_ERROR(sc, SC_INVALID_FUNCTION_CALL);
        return SC_FUNC_FAILURE;
    }

    // Generate the keys as appropriate
    return safecrypto_algorithms[sc->alg_index].pubkey_encode(sc, key, keylen);
}

SINT32 safecrypto_private_key_encode(safecrypto_t *sc, UINT8 **key, size_t *keylen)
{
    if (check_safecrypto(sc) != SC_FUNC_SUCCESS)
        return SC_FUNC_FAILURE;

    if (NULL == key || NULL == keylen) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    if (safecrypto_algorithms[sc->alg_index].privkey_encode == NULL) {
        SC_LOG_ERROR(sc, SC_INVALID_FUNCTION_CALL);
        return SC_FUNC_FAILURE;
    }

    // Generate the keys as appropriate
    return safecrypto_algorithms[sc->alg_index].privkey_encode(sc, key, keylen);
}

SINT32 safecrypto_encapsulation(safecrypto_t *sc, UINT8 **c, size_t *c_len,
    UINT8 **k, size_t *k_len)
{
    if (check_safecrypto(sc) != SC_FUNC_SUCCESS)
        return SC_FUNC_FAILURE;

    if (NULL == c || NULL == c_len || NULL == k || NULL == k_len) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    if (safecrypto_algorithms[sc->alg_index].encapsulation == NULL) {
        SC_LOG_ERROR(sc, SC_INVALID_FUNCTION_CALL);
        return SC_FUNC_FAILURE;
    }

    return safecrypto_algorithms[sc->alg_index].encapsulation(sc, c, c_len, k, k_len);
}

SINT32 safecrypto_decapsulation(safecrypto_t *sc, const UINT8 *c, size_t c_len,
    UINT8 **k, size_t *k_len)
{
    if (check_safecrypto(sc) != SC_FUNC_SUCCESS)
        return SC_FUNC_FAILURE;

    if (NULL == k || NULL == k_len) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    if (safecrypto_algorithms[sc->alg_index].decapsulation == NULL) {
        SC_LOG_ERROR(sc, SC_INVALID_FUNCTION_CALL);
        return SC_FUNC_FAILURE;
    }

    return safecrypto_algorithms[sc->alg_index].decapsulation(sc, c, c_len, k, k_len);
}

SINT32 safecrypto_secret_key(safecrypto_t *sc, size_t sklen, const UINT8 *sk)
{
    if (check_safecrypto(sc) != SC_FUNC_SUCCESS)
        return SC_FUNC_FAILURE;

    if (safecrypto_algorithms[sc->alg_index].secret_key == NULL) {
        SC_LOG_ERROR(sc, SC_INVALID_FUNCTION_CALL);
        return SC_FUNC_FAILURE;
    }

    return safecrypto_algorithms[sc->alg_index].secret_key(sc, sklen, sk);
}

SINT32 safecrypto_ibe_extract(safecrypto_t *sc, size_t idlen, const UINT8 *id,
    size_t *sklen, UINT8 **sk)
{
    if (check_safecrypto(sc) != SC_FUNC_SUCCESS)
        return SC_FUNC_FAILURE;

    if (NULL == sk || NULL == sklen) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    if (safecrypto_algorithms[sc->alg_index].extract == NULL) {
        SC_LOG_ERROR(sc, SC_INVALID_FUNCTION_CALL);
        return SC_FUNC_FAILURE;
    }

    return safecrypto_algorithms[sc->alg_index].extract(sc, idlen, id, sklen, sk);
}

SINT32 safecrypto_ibe_public_encrypt(safecrypto_t *sc,
    size_t idlen, const UINT8 *id,
    size_t flen, const UINT8 *from,
    size_t *tlen, UINT8 **to)
{
    if (check_safecrypto(sc) != SC_FUNC_SUCCESS)
        return SC_FUNC_FAILURE;

    if (NULL == to || NULL == tlen) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    if (safecrypto_algorithms[sc->alg_index].ibe_encrypt == NULL) {
        SC_LOG_ERROR(sc, SC_INVALID_FUNCTION_CALL);
        return SC_FUNC_FAILURE;
    }

    return safecrypto_algorithms[sc->alg_index].ibe_encrypt(sc, idlen, id,
        flen, from, tlen, to);
}

SINT32 safecrypto_public_encrypt(safecrypto_t *sc,
    size_t flen, const UINT8 *from, size_t *tlen, UINT8 **to)
{
    if (check_safecrypto(sc) != SC_FUNC_SUCCESS)
        return SC_FUNC_FAILURE;

    if (NULL == to || NULL == tlen) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    if (safecrypto_algorithms[sc->alg_index].encrypt == NULL) {
        SC_LOG_ERROR(sc, SC_INVALID_FUNCTION_CALL);
        return SC_FUNC_FAILURE;
    }

    return safecrypto_algorithms[sc->alg_index].encrypt(sc, flen, from, tlen, to);
}

SINT32 safecrypto_private_decrypt(safecrypto_t *sc,
    size_t flen, const UINT8 *from, size_t *tlen, UINT8 **to)
{
    if (check_safecrypto(sc) != SC_FUNC_SUCCESS)
        return SC_FUNC_FAILURE;

    if (NULL == to || NULL == tlen) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    if (safecrypto_algorithms[sc->alg_index].decrypt == NULL) {
        SC_LOG_ERROR(sc, SC_INVALID_FUNCTION_CALL);
        return SC_FUNC_FAILURE;
    }

    return safecrypto_algorithms[sc->alg_index].decrypt(sc, flen, from, tlen, to);
}

SINT32 safecrypto_sign(safecrypto_t *sc, const UINT8 *m, size_t mlen,
    UINT8 **sigret, size_t *siglen)
{
    if (check_safecrypto(sc) != SC_FUNC_SUCCESS)
        return SC_FUNC_FAILURE;

    if (NULL == sigret || NULL == siglen) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    if (safecrypto_algorithms[sc->alg_index].signing == NULL) {
        SC_LOG_ERROR(sc, SC_INVALID_FUNCTION_CALL);
        return SC_FUNC_FAILURE;
    }

    return safecrypto_algorithms[sc->alg_index].signing(sc, m, mlen, sigret, siglen);
}

SINT32 safecrypto_verify(safecrypto_t *sc, const UINT8 *m, size_t mlen,
    const UINT8 *sigbuf, size_t siglen)
{
    if (check_safecrypto(sc) != SC_FUNC_SUCCESS)
        return SC_FUNC_FAILURE;

    if (safecrypto_algorithms[sc->alg_index].verification == NULL) {
        SC_LOG_ERROR(sc, SC_INVALID_FUNCTION_CALL);
        return SC_FUNC_FAILURE;
    }

    return safecrypto_algorithms[sc->alg_index].verification(sc, m, mlen, sigbuf, siglen);
}

SINT32 safecrypto_sign_with_recovery(safecrypto_t *sc, UINT8 **m, size_t *mlen,
    UINT8 **sigret, size_t *siglen)
{
    if (check_safecrypto(sc) != SC_FUNC_SUCCESS)
        return SC_FUNC_FAILURE;

    if (NULL == sigret || NULL == siglen) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    if (safecrypto_algorithms[sc->alg_index].signing_recovery == NULL) {
        SC_LOG_ERROR(sc, SC_INVALID_FUNCTION_CALL);
        return SC_FUNC_FAILURE;
    }

    return safecrypto_algorithms[sc->alg_index].signing_recovery(sc, m, mlen, sigret, siglen);
}

SINT32 safecrypto_verify_with_recovery(safecrypto_t *sc, UINT8 **m, size_t *mlen,
    const UINT8 *sigbuf, size_t siglen)
{
    if (check_safecrypto(sc) != SC_FUNC_SUCCESS)
        return SC_FUNC_FAILURE;

    if (NULL == m || NULL == mlen) {
        SC_LOG_ERROR(sc, SC_NULL_POINTER);
        return SC_FUNC_FAILURE;
    }

    if (safecrypto_algorithms[sc->alg_index].verification_recovery == NULL) {
        SC_LOG_ERROR(sc, SC_INVALID_FUNCTION_CALL);
        return SC_FUNC_FAILURE;
    }

    return safecrypto_algorithms[sc->alg_index].verification_recovery(sc, m, mlen, sigbuf, siglen);
}

SINT32 safecrypto_diffie_hellman_init(safecrypto_t *sc, size_t *tlen, UINT8 **to)
{
    if (check_safecrypto(sc) != SC_FUNC_SUCCESS)
        return SC_FUNC_FAILURE;

    if (safecrypto_algorithms[sc->alg_index].dh_init == NULL) {
        SC_LOG_ERROR(sc, SC_INVALID_FUNCTION_CALL);
        return SC_FUNC_FAILURE;
    }

    return safecrypto_algorithms[sc->alg_index].dh_init(sc, tlen, to);
}

SINT32 safecrypto_diffie_hellman_final(safecrypto_t *sc, size_t flen, const UINT8 *from,
    size_t *tlen, UINT8 **to)
{
    if (check_safecrypto(sc) != SC_FUNC_SUCCESS)
        return SC_FUNC_FAILURE;

    if (safecrypto_algorithms[sc->alg_index].dh_final == NULL) {
        SC_LOG_ERROR(sc, SC_INVALID_FUNCTION_CALL);
        return SC_FUNC_FAILURE;
    }

    return safecrypto_algorithms[sc->alg_index].dh_final(sc, flen, from, tlen, to);
}


const char * safecrypto_processing_stats(safecrypto_t *sc)
{
    if (check_safecrypto(sc) != SC_FUNC_SUCCESS)
        return NULL;

    if (safecrypto_algorithms[sc->alg_index].processing_stats == NULL) {
        SC_LOG_ERROR(sc, SC_INVALID_FUNCTION_CALL);
        return NULL;
    }

    return safecrypto_algorithms[sc->alg_index].processing_stats(sc);
}

const sc_statistics_t * safecrypto_get_stats(safecrypto_t *sc)
{
    if (check_safecrypto(sc) != SC_FUNC_SUCCESS)
        return NULL;

    return &sc->stats;
}


const sc_hash_t *safecrypto_get_hash_schemes(void)
{
    g_hash_schemes[0].scheme = SC_HASH_MAX;
    g_hash_schemes[0].next   = NULL;

#if defined(ENABLE_SHA2)
    add_hash_node(g_hash_schemes, SC_HASH_SHA2_512);
    add_hash_node(g_hash_schemes, SC_HASH_SHA2_384);
    add_hash_node(g_hash_schemes, SC_HASH_SHA2_256);
    add_hash_node(g_hash_schemes, SC_HASH_SHA2_224);
#endif
#if defined(ENABLE_SHA3)
    add_hash_node(g_hash_schemes, SC_HASH_SHA3_512);
    add_hash_node(g_hash_schemes, SC_HASH_SHA3_384);
    add_hash_node(g_hash_schemes, SC_HASH_SHA3_256);
    add_hash_node(g_hash_schemes, SC_HASH_SHA3_224);
#endif
#if defined(ENABLE_BLAKE2)
    add_hash_node(g_hash_schemes, SC_HASH_BLAKE2_512);
    add_hash_node(g_hash_schemes, SC_HASH_BLAKE2_384);
    add_hash_node(g_hash_schemes, SC_HASH_BLAKE2_256);
    add_hash_node(g_hash_schemes, SC_HASH_BLAKE2_224);
#endif
#if defined(ENABLE_WHIRLPOOL)
    add_hash_node(g_hash_schemes, SC_HASH_WHIRLPOOL_512);
#endif

    return (SC_HASH_MAX == g_hash_schemes[0].scheme)? NULL : g_hash_schemes;
}

safecrypto_hash_t * safecrypto_hash_create(sc_hash_e type)
{
    return utils_crypto_hash_create(type);
}

SINT32 safecrypto_hash_destroy(safecrypto_hash_t *hash)
{
    return utils_crypto_hash_destroy(hash);
}

sc_hash_e safecrypto_hash_type(safecrypto_hash_t *hash)
{
    return hash_get_type(hash);
}

size_t safecrypto_hash_length(safecrypto_hash_t *hash)
{
    return hash_length(hash);
}

safecrypto_hash_t * safecrypto_hash_make_copy(safecrypto_hash_t *hash)
{
    return hash_make_copy(hash);
}

SINT32 safecrypto_hash_init(safecrypto_hash_t *hash)
{
    return hash_init(hash);
}

SINT32 safecrypto_hash_update(safecrypto_hash_t *hash, const UINT8 *data, size_t len)
{
    return hash_update(hash, data, len);
}

SINT32 safecrypto_hash_final(safecrypto_hash_t *hash, UINT8 *md)
{
    return hash_final(hash, md);
}


const sc_xof_t *safecrypto_get_xof_schemes(void)
{
    g_xof_schemes[0].scheme = SC_XOF_MAX;
    g_xof_schemes[0].next   = NULL;

#if defined(ENABLE_SHA3)
    add_xof_node(g_xof_schemes, SC_XOF_SHAKE256);
    add_xof_node(g_xof_schemes, SC_XOF_SHAKE128);
#endif

    return (SC_XOF_MAX == g_xof_schemes[0].scheme)? NULL : g_xof_schemes;
}

safecrypto_xof_t * safecrypto_xof_create(sc_xof_e type)
{
    return utils_crypto_xof_create(type);
}

SINT32 safecrypto_xof_destroy(safecrypto_xof_t* xof)
{
    return utils_crypto_xof_destroy(xof);
}

sc_xof_e safecrypto_xof_type(safecrypto_xof_t *xof)
{
    return xof_get_type(xof);
}

SINT32 safecrypto_xof_init(safecrypto_xof_t *xof)
{
    return xof_init(xof);
}

SINT32 safecrypto_xof_absorb(safecrypto_xof_t *xof, const UINT8 *data, size_t len)
{
    return xof_absorb(xof, data, len);
}

SINT32 safecrypto_xof_final(safecrypto_xof_t *xof)
{
    return xof_final(xof);
}

SINT32 safecrypto_xof_squeeze(safecrypto_xof_t *xof, UINT8 *output, size_t len)
{
    return xof_squeeze(xof, output, len);
}


const sc_prng_t *safecrypto_get_prng_schemes(void)
{
    g_prng_schemes[0].scheme = SC_PRNG_MAX;
    g_prng_schemes[0].next   = NULL;

#if defined(SC_PRNG_SYSTEM)
    add_prng_node(g_prng_schemes, SC_PRNG_SYSTEM);
#endif
#if defined(SC_PRNG_AES_CTR_DRBG)
    add_prng_node(g_prng_schemes, SC_PRNG_AES_CTR_DRBG);
#endif
#if defined(SC_PRNG_AES_CTR)
    add_prng_node(g_prng_schemes, SC_PRNG_AES_CTR);
#endif
#if defined(SC_PRNG_CHACHA)
    add_prng_node(g_prng_schemes, SC_PRNG_CHACHA);
#endif
#if defined(SC_PRNG_SALSA)
    add_prng_node(g_prng_schemes, SC_PRNG_SALSA);
#endif
#if defined(SC_PRNG_ISAAC)
    add_prng_node(g_prng_schemes, SC_PRNG_ISAAC);
#endif
#if defined(SC_PRNG_KISS)
    add_prng_node(g_prng_schemes, SC_PRNG_KISS);
#endif
#if defined(SC_PRNG_HASH_DRBG_SHA2_256)
    add_prng_node(g_prng_schemes, SC_PRNG_HASH_DRBG_SHA2_256);
#endif
#if defined(SC_PRNG_HASH_DRBG_SHA2_512)
    add_prng_node(g_prng_schemes, SC_PRNG_HASH_DRBG_SHA2_512);
#endif
#if defined(SC_PRNG_HASH_DRBG_SHA3_256)
    add_prng_node(g_prng_schemes, SC_PRNG_HASH_DRBG_SHA3_256);
#endif
#if defined(SC_PRNG_HASH_DRBG_SHA3_512)
    add_prng_node(g_prng_schemes, SC_PRNG_HASH_DRBG_SHA3_512);
#endif
#if defined(SC_PRNG_HASH_DRBG_BLAKE2_256)
    add_prng_node(g_prng_schemes, SC_PRNG_HASH_DRBG_BLAKE2_256);
#endif
#if defined(SC_PRNG_HASH_DRBG_BLAKE2_512)
    add_prng_node(g_prng_schemes, SC_PRNG_HASH_DRBG_BLAKE2_512);
#endif
#if defined(SC_PRNG_HASH_DRBG_WHIRLPOOL_512)
    add_prng_node(g_prng_schemes, SC_PRNG_HASH_DRBG_WHIRLPOOL_512);
#endif
#if defined(SC_PRNG_FILE)
    add_prng_node(g_prng_schemes, SC_PRNG_FILE);
#endif
#if defined(SC_PRNG_HIGH_ENTROPY)
    add_prng_node(g_prng_schemes, SC_PRNG_HIGH_ENTROPY);
#endif

    return (SC_PRNG_MAX == g_prng_schemes[0].scheme)? NULL : g_prng_schemes;
}

void safecrypto_internal_rng_reset(safecrypto_t *sc){
  safecrypto_prng_reset(sc -> prng_ctx[0]);
}

safecrypto_prng_t * safecrypto_prng_create(safecrypto_prng_e type, size_t seed_period,
    safecrypto_prng_entropy_callback cb)
{
    prng_ctx_t *ctx = prng_create(SC_ENTROPY_CALLBACK, type, SC_PRNG_THREADING_NONE, seed_period);
    if (NULL == ctx) {
        return NULL;
    }

    prng_set_entropy_callback(cb);
    prng_init(ctx, NULL, 0);
    return (safecrypto_prng_t*)ctx;
}

SINT32 safecrypto_prng_destroy(safecrypto_prng_t *ctx)
{
    return prng_destroy((prng_ctx_t *)ctx);
}

safecrypto_prng_e safecrypto_prng_get_type(safecrypto_prng_t *ctx)
{
    return prng_get_type((prng_ctx_t *)ctx);
}

void safecrypto_prng_reset(safecrypto_prng_t *ctx)
{
    prng_reset((prng_ctx_t *)ctx);
}

#ifdef HAVE_64BIT
UINT64 safecrypto_prng_64(safecrypto_prng_t *ctx)
{
    return prng_64((prng_ctx_t *)ctx);
}
#endif

UINT32 safecrypto_prng_32(safecrypto_prng_t *ctx)
{
    return prng_32((prng_ctx_t *)ctx);
}

UINT16 safecrypto_prng_16(safecrypto_prng_t *ctx)
{
    return prng_16((prng_ctx_t *)ctx);
}

UINT8 safecrypto_prng_8(safecrypto_prng_t *ctx)
{
    return prng_8((prng_ctx_t *)ctx);
}

SINT32 safecrypto_prng_bit(safecrypto_prng_t *ctx)
{
    return prng_bit((prng_ctx_t *)ctx);
}

FLOAT safecrypto_prng_float(safecrypto_prng_t *ctx)
{
    return prng_float((prng_ctx_t *)ctx);
}

DOUBLE safecrypto_prng_double(safecrypto_prng_t *ctx)
{
    return prng_double((prng_ctx_t *)ctx);
}

UINT32 safecrypto_prng_var(safecrypto_prng_t *ctx, size_t n)
{
    return prng_var((prng_ctx_t *)ctx, n);
}

SINT32 safecrypto_prng_mem(safecrypto_prng_t *ctx, UINT8 *mem, SINT32 length)
{
    return prng_mem((prng_ctx_t *)ctx, mem, length);
}


safecrypto_aes_t * safecrypto_aes_create(safecrypto_aes_type_e type, const UINT8 *key)
{
    if (NULL == key) {
        return NULL;
    }

    if (type >= SC_AES_MAX) {
        return NULL;
    }

    switch (type)
    {
        case SC_AES_ENCRYPT_128:
            {
                aes_encrypt_ctx *ctx = SC_MALLOC(sizeof(aes_encrypt_ctx));
                aes_encrypt_key128(key, ctx);
                return (safecrypto_aes_t*)ctx;
            }
        case SC_AES_ENCRYPT_192:
            {
                aes_encrypt_ctx *ctx = SC_MALLOC(sizeof(aes_encrypt_ctx));
                aes_encrypt_key192(key, ctx);
                return (safecrypto_aes_t*)ctx;
            }
        case SC_AES_ENCRYPT_256:
            {
                aes_encrypt_ctx *ctx = SC_MALLOC(sizeof(aes_encrypt_ctx));
                aes_encrypt_key256(key, ctx);
                return (safecrypto_aes_t*)ctx;
            }
        case SC_AES_DECRYPT_128:
            {
                aes_decrypt_ctx *ctx = SC_MALLOC(sizeof(aes_decrypt_ctx));
                aes_decrypt_key128(key, ctx);
                return (safecrypto_aes_t*)ctx;
            }
        case SC_AES_DECRYPT_192:
            {
                aes_decrypt_ctx *ctx = SC_MALLOC(sizeof(aes_decrypt_ctx));
                aes_decrypt_key192(key, ctx);
                return (safecrypto_aes_t*)ctx;
            }
        case SC_AES_DECRYPT_256:
            {
                aes_decrypt_ctx *ctx = SC_MALLOC(sizeof(aes_decrypt_ctx));
                aes_decrypt_key256(key, ctx);
                return (safecrypto_aes_t*)ctx;
            }
        default:;
    }

    return NULL;
}

SINT32 safecrypto_aes_destroy(safecrypto_aes_t *ctx)
{
    if (NULL == ctx) {
        return SC_FUNC_FAILURE;
    }
    SC_FREE(ctx, sizeof(aes_encrypt_ctx));
    return SC_FUNC_SUCCESS;
}

SINT32 safecrypto_aes_encrypt(safecrypto_aes_t *ctx, const UINT8 *in, UINT8 *out)
{
    if (NULL == ctx) {
        return SC_FUNC_FAILURE;
    }
    return aes_encrypt(in, out, (aes_encrypt_ctx*)ctx);
}

SINT32 safecrypto_aes_decrypt(safecrypto_aes_t *ctx, const UINT8 *in, UINT8 *out)
{
    if (NULL == ctx) {
        return SC_FUNC_FAILURE;
    }
    return aes_decrypt(in, out, (aes_decrypt_ctx*)ctx);
}

