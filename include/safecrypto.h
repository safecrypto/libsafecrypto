/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

/**
 * @file safecrypto.h
 * @author n.smyth@qub.ac.uk
 * @date 10 Aug 2016
 * @brief Header file for the SAFEcrypto library.
 *
 * This header file and safecrypto_types.h are the only header files
 * that must be distributed with a pre-built library.
 *
 * Git commit information:
 *   Author: $SC_AUTHOR$
 *   Date:   $SC_DATE$
 *   Branch: $SC_BRANCH$
 *   Id:     $SC_IDENT$
 */

#pragma once

#include "safecrypto_types.h"


#ifdef __cplusplus
extern "C" {
#endif

/// Definitions for the maximum permited length of a string
#define SC_MAX_NAME_LEN       64

/// The maximum permitted length of an IBE user ID byte array
#define SC_IBE_MAX_ID_LENGTH  128


/// @todo Add error checking for incompatible flags, e.g. Ziggurat
/// and Bernoulli are selected

/// A flag bit used to indicate that a further 32-bit word of
/// configuration flags will follow
#define SC_FLAG_MORE                    0x80000000

#define SC_FLAG_NONE                    0x00000000  ///< Disable all flags

/// A list of the flags associated with optional features
/// Word 0:
/// @{
#define SC_FLAG_0_ENTROPY_BAC                0x00000001  ///< BAC compression
#define SC_FLAG_0_ENTROPY_HUFFMAN            0x00000002  ///< Huffman compression
#define SC_FLAG_0_SAMPLE_PREC_MASK           0x00000070  ///< A mask used to isloate the Gaussian sample precision bits
#define SC_FLAG_0_SAMPLE_DEFAULT             0x00000000  ///< Use default Gaussian sampling precision
#define SC_FLAG_0_SAMPLE_32BIT               0x00000010  ///< Use 32-bit Gaussian sampling precision
#define SC_FLAG_0_SAMPLE_64BIT               0x00000020  ///< Use 64-bit Gaussian sampling precision
#define SC_FLAG_0_SAMPLE_128BIT              0x00000030  ///< Use 128-bit Gaussian sampling precision
#define SC_FLAG_0_SAMPLE_192BIT              0x00000040  ///< Use 192-bit Gaussian sampling precision
#define SC_FLAG_0_SAMPLE_256BIT              0x00000050  ///< Use 256-bit Gaussian sampling precision
#define SC_FLAG_0_SAMPLE_CDF                 0x00000200  ///< CDF Gaussian sampler
#define SC_FLAG_0_SAMPLE_KNUTH_YAO           0x00000400  ///< Knuth Yao Gaussian sampler
#define SC_FLAG_0_SAMPLE_ZIGGURAT            0x00000800  ///< Ziggurat gaussian sampler
#define SC_FLAG_0_SAMPLE_BAC                 0x00001000  ///< BAC Gaussian sampler
#define SC_FLAG_0_SAMPLE_HUFFMAN             0x00002000  ///< Huffman decoder Gaussian sampler
#define SC_FLAG_0_SAMPLE_BERNOULLI           0x00004000  ///< Bernoulli Gaussian sampler
#define SC_FLAG_0_HASH_LENGTH_MASK           0x00030000  ///< Mask used to isolate hash length selection
#define SC_FLAG_0_HASH_LENGTH_512            0x00000000  ///< Enable 512-bit hash
#define SC_FLAG_0_HASH_LENGTH_384            0x00010000  ///< Enable 384-bit hash
#define SC_FLAG_0_HASH_LENGTH_256            0x00020000  ///< Enable 256-bit hash
#define SC_FLAG_0_HASH_LENGTH_224            0x00030000  ///< Enable 224-bit hash
#define SC_FLAG_0_HASH_FUNCTION_MASK         0x001C0000  ///< Mask used to isloate hash algorithm
#define SC_FLAG_0_HASH_FUNCTION_DEFAULT      0x00000000  ///< Enable scheme default hash
#define SC_FLAG_0_HASH_BLAKE2                0x00040000  ///< Enable BLAKE2-B hash
#define SC_FLAG_0_HASH_SHA2                  0x00080000  ///< Enable SHA-2 hash
#define SC_FLAG_0_HASH_SHA3                  0x000C0000  ///< Enable SHA-3 hash
#define SC_FLAG_0_HASH_WHIRLPOOL             0x00100000  ///< Enable Whirlpool hash
#define SC_FLAG_0_REDUCTION_MASK             0x00E00000  ///< Mask used to isolate reduction selection
#define SC_FLAG_0_REDUCTION_REFERENCE        0x00200000  ///< Use reference arithmetic for reduction
#define SC_FLAG_0_REDUCTION_BARRETT          0x00400000  ///< Use Barrett reduction
#define SC_FLAG_0_REDUCTION_FP               0x00600000  ///< Use Floating Point reduction
#define SC_FLAG_0_THREADING_MASK             0x7C000000  ///< Mask used to identify the multithreading selection
#define SC_FLAG_0_THREADING_KEYGEN           0x04000000  ///< Enable multithreading support for key generation
#define SC_FLAG_0_THREADING_ENC_SIGN         0x08000000  ///< Enable multithreading support for encryption, signing, etc.
#define SC_FLAG_0_THREADING_DEC_VERIFY       0x10000000  ///< Enable multithreading support for decryption, verification, etc.
/// @}

/// Word 1:
/// @{
#define SC_FLAG_1_CSPRNG_AES_CTR_DRBG        0x00000001  ///< Enable AES CTR-DRBG
#define SC_FLAG_1_CSPRNG_CHACHA              0x00000002  ///< Enable CHACHA20-CSPRNG
#define SC_FLAG_1_CSPRNG_SALSA               0x00000004  ///< Enable SALSA20-CSPRNG
#define SC_FLAG_1_CSPRNG_ISAAC               0x00000008  ///< Enable ISAAC CSPRNG
#define SC_FLAG_1_CSPRNG_KISS                0x00000010  ///< Enable Keep It Simple Stupid PRNG
#define SC_FLAG_1_CSPRNG_AES_CTR             0x00000020  ///< Enable AES CTR mode
#define SC_FLAG_1_CSPRNG_SHA3_512_DRBG       0x00000100  ///< Enable SHA3-512 HASH-DRBG
#define SC_FLAG_1_CSPRNG_SHA3_256_DRBG       0x00000400  ///< Enable SHA3-256 HASH-DRBG
#define SC_FLAG_1_CSPRNG_SHA2_512_DRBG       0x00001000  ///< Enable SHA2-512 HASH-DRBG
#define SC_FLAG_1_CSPRNG_SHA2_256_DRBG       0x00004000  ///< Enable SHA2-256 HASH-DRBG
#define SC_FLAG_1_CSPRNG_BLAKE2_512_DRBG     0x00010000  ///< Enable BLAKE2-512 HASH-DRBG
#define SC_FLAG_1_CSPRNG_BLAKE2_256_DRBG     0x00040000  ///< Enable BLAKE2-256 HASH-DRBG
#define SC_FLAG_1_CSPRNG_WHIRLPOOL_DRBG      0x00100000  ///< Enable Whirlpool-512 HASH-DRBG
#define SC_FLAG_1_CSPRNG_USE_DEV_RANDOM      0x01000000  ///< Use /dev/random as an entropy source
#define SC_FLAG_1_CSPRNG_USE_DEV_URANDOM     0x02000000  ///< Use /dev/urandom as an entropy source
#define SC_FLAG_1_CSPRNG_USE_OS_RANDOM       0x04000000  ///< Use the OS random function as an entropy source
#define SC_FLAG_1_CSPRNG_USE_CALLBACK_RANDOM 0x08000000  ///< Use a callback function as an entropy source
/// @}

/// Word 2:
/// @{
#define SC_FLAG_2_SAMPLE_SCA_DISCARD_LO      0x00000001  ///< Enable discarding Gaussian samples at a low rate (6.25%)
#define SC_FLAG_2_SAMPLE_SCA_DISCARD_MD      0x00000002  ///< Enable discarding Gaussian samples at a low rate (12.5%)
#define SC_FLAG_2_SAMPLE_SCA_DISCARD_HI      0x00000003  ///< Enable discarding Gaussian samples at a low rate (25%)
#define SC_FLAG_2_SAMPLE_CACHE_ACCESS        0x00000004  ///< Enable random cache access of any Gaussian sample LUT
#define SC_FLAG_2_SAMPLE_NON_CT_MASK         0x00000008  ///< Enable the masking of non-constant time Gaussian sampling
#define SC_FLAG_2_SAMPLE_SCA_SHUFFLE         0x00000010  ///< Enable Gaussian shuffling countermeasures
#define SC_FLAG_2_SAMPLE_SCA_BLINDING        0x00000020  ///< Enable Gaussian blinding countermeasures
#define SC_FLAG_2_MEMORY_TEMP_EXTERNAL       0x10000000  ///< Use an external memory array to store intermediate data
/// @}


/// The entropy coder configuration
typedef struct sc_entropy {
    sc_entropy_type_e type;
} sc_entropy_t;


/// Forward declaration of the SAFEcrypto struct (user does not require a definition)
typedef struct _safecrypto safecrypto_t;

/// Forward declaration of the Hash struct (user does not require a definition)
typedef struct _utils_crypto_hash safecrypto_hash_t;

/// Forward declaration of the XOF struct (user does not require a definition)
typedef struct _utils_crypto_xof safecrypto_xof_t;

/// A struct used to parse a linked list of supported public key signature schemes
struct sc_pkc_scheme {
    sc_scheme_e           scheme;
    struct sc_pkc_scheme *next;
};
typedef struct sc_pkc_scheme sc_pkc_scheme_t;

/// A struct used to parse a linked list of supported hash schemes
struct sc_hash {
    sc_hash_e       scheme;
    struct sc_hash *next;
};
typedef struct sc_hash sc_hash_t;

/// A struct used to parse a linked list of supported XOF schemes
struct sc_xof {
    sc_xof_e       scheme;
    struct sc_xof *next;
};
typedef struct sc_xof sc_xof_t;


/** @name Library version
 *  Functions used to provide the library version.
 */
/**@{*/
/** @brief Retrieve the version number of the SAFEcrypto library.
 *
 *  @return A 32-bit version number
 */
extern UINT32 safecrypto_get_version(void);

/** @brief Retrieve the version number of the SAFEcrypto library s a human readable string.
 * 
 *  @return A string representing the SAFEcrypto version number
 */
extern const char *safecrypto_get_version_string(void);
/**@}*/


/** @name Library capabilities
 *  Functions used to determine the library capabilities.
 */
/**@{*/
/** @brief Retrieve the configure invocation command used when building the library
 *
 *  @return A C-string pointer
 */
extern const char *safecrypto_get_configure_invocation(void);

/** @brief Obtain a linked list containing the signature schemes supported by SAFEcrypto
 *
 *  @return A pointer to the first sc_pkc_scheme_t node in the linked list
 */
extern const sc_pkc_scheme_t *safecrypto_get_signature_schemes(void);

/** @brief Obtain a linked list containing the encryption schemes supported by SAFEcrypto
 *
 *  @return A pointer to the first sc_pkc_scheme_t node in the linked list
 */
extern const sc_pkc_scheme_t *safecrypto_get_encryption_schemes(void);

/** @brief Obtain a linked list containing the KEM schemes supported by SAFEcrypto
 *
 *  @return A pointer to the first sc_pkc_scheme_t node in the linked list
 */
extern const sc_pkc_scheme_t *safecrypto_get_kem_schemes(void);

/** @brief Obtain a linked list containing the IBE schemes supported by SAFEcrypto
 *
 *  @return A pointer to the first sc_pkc_scheme_t node in the linked list
 */
extern const sc_pkc_scheme_t *safecrypto_get_ibe_schemes(void);
/**@}*/


/** @name Creation
 *  Functions used to create and destroy instances of the SAFEcrypto library.
 */
/**@{*/
/** @brief Create a SAFEcrypto object.
 *
 *  @param scheme The algorithm to be instantiated
 *  @param set The parameter set id
 *  @param flags An array of configuration options for the selected algorithm
 *  @return A pointer to a safecrypto object
 */
extern safecrypto_t *safecrypto_create(sc_scheme_e scheme, SINT32 set,
    const UINT32 *flags);

/** @brief Destroy a SAFEcrypto object
 *  @param sc A pointer to a safecrypto object
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_destroy(safecrypto_t *sc);
/**@}*/

/** @name Define external memory used for intermediate storage
 *  A function used to set a pointer to memory used for intermediate
 *  memory that is zeroed and discarded after any calls to the API.
 */
/**@{*/
/** @brief Set an intermediate memory pointer
 *  @param sc A pointer to a safecrypto object
 *  @param mem A pointer to a memory array
 *  @param len The size (in bytes) of the memory array (aligned to SC_DEFAULT_ALIGNED)
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_scratch_external(safecrypto_t *sc, void *mem, size_t len);

/** @name Obtain the size of the intermediate memory
 *  Returns the required size of the intermediate memory buffer.
 */
/**@{*/
/** @brief Set an intermediate memory pointer
 *  @param sc A pointer to a safecrypto object
 *  @param len A pointer to the size (in bytes) of the memory array
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_scratch_size(safecrypto_t *sc, size_t *len);

/** @name External entropy callback
 *  A function used to set an external function as an entropy source.
 */
/**@{*/
/** @brief Set a callback function pointer
 *  @param sc A pointer to a func_get_random_entropy function
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_entropy_callback(safecrypto_entropy_cb_func fn_entropy);
/**@}*/

/** @name Debug level
 *  Functions used to control the debug level of the SAFEcrypto library.
 */
/**@{*/
/** @brief Set the debug verbosity.
 *
 *  @param level The debug verboseness
 *  @param sc A pointer to a safecrypto object
 *  @param level The user specified debug verbosity
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_set_debug_level(safecrypto_t *sc, sc_debug_level_e level);

/** @brief Get the debug verbosity.
 *
 *  @param sc A pointer to a safecrypto object
 *  @return The enumerated debug level currently in operation
 */
extern sc_debug_level_e safecrypto_get_debug_level(safecrypto_t *sc);
/**@}*/

/** @name Error handling
 *  Functions associated with accessing and manipulating the error queue.
 */
/**@{*/
/// Obtain the error code from the error queue and erase it from the queue.
extern UINT32 safecrypto_err_get_error(safecrypto_t *sc);

/// Obtain the error code from the error queue, doesn't modify the queue.
extern UINT32 safecrypto_err_peek_error(safecrypto_t *sc);

/// Same as safecrypto_err_get_error(), but retrieves the file name and line number.
extern UINT32 safecrypto_err_get_error_line(safecrypto_t *sc,
    const char **file, SINT32 *line);

/// Same as safecrypto_err_peek_error(), but retrieves the file name and line number.
extern UINT32 safecrypto_err_peek_error_line(safecrypto_t *sc,
    const char **file, SINT32 *line);

/// Removes all error messages from the queue.
extern void safecrypto_err_clear_error(safecrypto_t *sc);
/**@}*/

/** @name Key Generation
 *  Functions used to populate the key pair.
 */
/**@{*/
/** @brief Create a SAFEcrypto key-pair and store it in the SAFEcrypto struct.
 *
 *  @param sc A pointer to a safecrypto object
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_keygen(safecrypto_t *sc);

/** @brief Configure the entropy coding tools to be used to compress the key-pair.
 *
 *  @param sc A pointer to a safecrypto object
 *  @param pub Entropy coding to be applied to the public key
 *  @param priv Entropy coding to be applied to the private key
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_set_key_coding(safecrypto_t *sc, sc_entropy_type_e pub,
    sc_entropy_type_e priv);

/** @brief Get the entropy coding tools to be used to compress the key-pair.
 *
 *  @param sc A pointer to a safecrypto object
 *  @param pub Entropy coding to be applied to the public key
 *  @param priv Entropy coding to be applied to the private key polynomial
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_get_key_coding(safecrypto_t *sc, sc_entropy_type_e *pub,
    sc_entropy_type_e *priv);

/** @brief Store a public key in the SAFEcrypto struct.
 *
 *  @param sc A pointer to a safecrypto object
 *  @param key A serialized public key
 *  @param key_len The length of the key array
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_public_key_load(safecrypto_t *sc, const UINT8 *key, size_t keylen);

/** @brief Store a private key in the SAFEcrypto struct.
 *
 *  @param sc A pointer to a safecrypto object
 *  @param key A serialized private key
 *  @param key_len The length of the key array
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_private_key_load(safecrypto_t *sc, const UINT8 *key, size_t keylen);

/** @brief Return the SAFEcrypto public key in a packed byte array.
 *
 *  @param sc A pointer to a safecrypto object
 *  @param key A serialized public key
 *  @param keylen The size of the returned public key
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_public_key_encode(safecrypto_t *sc, UINT8 **key, size_t *keylen);

/** @brief Return the SAFEcrypto private key in a packed byte array.
 *
 *  @param sc A pointer to a safecrypto object
 *  @param key A serialized private key
 *  @param keylen The size of the returned private key
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_private_key_encode(safecrypto_t *sc, UINT8 **key, size_t *keylen);

/**@}*/

/** @name Cryptographic Processing
 *  Functions associated with performing cryptographic processing.
 */
/**@{*/
/** @brief Use public-key to generate ciphertext and a master key.
 *
 *  @param safecrypto Object containing key pair and lattice parameters
 *  @param c Output ciphertext
 *  @param c_len Ciphertext length
 *  @param k Output master key
 *  @param k_len Master key length
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_encapsulation(safecrypto_t *sc,
	  UINT8 **c, size_t *c_len,
	  UINT8 **k, size_t *k_len);

/** @brief Use private-key and ciphertext to generate the master key.
 *
 *  @param sc Object containing key pair and lattice parameters
 *  @param c Input ciphertext
 *  @param c_len Ciphertext length
 *  @param k Output master key
 *  @param k_len Master key length
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_decapsulation(safecrypto_t *sc,
	  const UINT8 *c, size_t c_len,
	  UINT8 **k, size_t *k_len);

/** @brief IBE Set User Secret Key.
 *
 *  @param sc Object containing key pair and lattice parameters
 *  @param sklen The size of the user secret key in bytes
 *  @param sk The user secret key obtained from the Private Key Generator
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_secret_key(safecrypto_t *sc, size_t sklen, const UINT8 *sk);

/** @brief IBE Extract.
 *
 *  @param sc Object containing key pair and lattice parameters
 *  @param idlen The size of the User ID in bytes
 *  @param id The User ID
 *  @param sklen The size of the user secret key in bytes
 *  @param sk The output user secret key
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_ibe_extract(safecrypto_t *sc, size_t idlen, const UINT8 *id,
    size_t *sklen, UINT8 **sk);

/** @brief IBE public key encryption.
 *
 *  @param sc Object containing key pair and lattice parameters
 *  @param idlen The size of the receipient User ID in bytes
 *  @param id The receipient's User ID
 *  @param flen The size of the from array in bytes
 *  @param from The input message
 *  @param tlen The size of the ciphertext array in bytes
 *  @param to The output ciphertext
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_ibe_public_encrypt(safecrypto_t *sc,
    size_t idlen, const UINT8 *id,
    size_t flen, const UINT8 *from,
    size_t *tlen, UINT8 **to);

/** @brief PKE encryption.
 *
 *  @param sc Object containing key pair and lattice parameters
 *  @param flen The size of the from array in bytes
 *  @param from The input message
 *  @param tlen The size of the ciphertext array in bytes
 *  @param to The output ciphertext
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_public_encrypt(safecrypto_t *sc,
    size_t flen, const UINT8 *from, size_t *tlen, UINT8 **to);

/** @brief PKE decryption.
 *
 *  @param sc Object containing key pair and lattice parameters
 *  @param flen The size of the from array in bytes
 *  @param from The input ciphertext
 *  @param tlen The size of the output message in bytes
 *  @param to The output message
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_private_decrypt(safecrypto_t *sc,
    size_t flen, const UINT8 *from, size_t *tlen, UINT8 **to);

/** @brief Signature.
 *
 *  @param sc Object containing key pair and lattice parameters
 *  @param m The input message
 *  @param mlen The size of the message array in bytes
 *  @param sigret The output signature
 *  @param siglen The size of the signature array in bytes
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_sign(safecrypto_t *sc, const UINT8 *m, size_t mlen,
    UINT8 **sigret, size_t *siglen);

/** @brief Signature Verification.
 *
 *  @param sc Object containing key pair and lattice parameters
 *  @param m The input message
 *  @param mlen The size of the message array in bytes
 *  @param sigbuf The input signature
 *  @param siglen The size of the signature array in bytes
 *  @return Returns 1 on successful validation
 */
extern SINT32 safecrypto_verify(safecrypto_t *sc, const UINT8 *m, size_t mlen,
    const UINT8 *sigbuf, size_t siglen);
/**@}*/

/** @brief Signature with Message Recovery.
 *
 *  @param sc Object containing key pair and lattice parameters
 *  @param m The input message, modified upon return
 *  @param mlen The size of the message array in bytes when called, modified upon return
 *  @param sigret The output signature
 *  @param siglen The size of the signature array in bytes
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_sign_with_recovery(safecrypto_t *sc, UINT8 **m, size_t *mlen,
    UINT8 **sigret, size_t *siglen);

/** @brief Signature Verification with Message Recovery.
 *
 *  @param sc Object containing key pair and lattice parameters
 *  @param m The input message, modified upon return
 *  @param mlen The size of the message array in bytes, modified upon return
 *  @param sigbuf The input signature
 *  @param siglen The size of the signature array in bytes
 *  @return Returns 1 on successful validation
 */
extern SINT32 safecrypto_verify_with_recovery(safecrypto_t *sc, UINT8 **m, size_t *mlen,
    const UINT8 *sigbuf, size_t siglen);
/**@}*/


/** @name Statistics
 *  Functions used to obtain statistical information about cryptographic processing.
 */
/**@{*/
/** @brief Processing statistics in string form.
 *
 *  @param sc Object containing key pair and lattice parameters
 *  @return Returns a C string describing the previous crypto processing
 *          operation.
 */
extern const char * safecrypto_processing_stats(safecrypto_t *sc);

/** @brief Processing statistics.
 *
 *  @param sc Object containing key pair and lattice parameters
 *  @return Returns a pointer to an sc_statistics_t struct.
 */
extern const sc_statistics_t * safecrypto_get_stats(safecrypto_t *sc);
/**@}*/


/** @name Authenticated Key Exchange
 *  An interface used to generate and authenticate messages for AKE. This interface
 *  requires SAFEcrypto instances of the necessary type to be provided as inputs
 *  and messages to be transmitted/received as necessary.
 */
/**@{*/
/** @brief Generate KEM encapsulation and decapsulation keys, sign the encapsulation key
 *  and create a message for the "B" composed of the encapsulation key and signature.
 *
 *  @param sc_sig The SAFEcrypto signature scheme
 *  @param sc_kem The SAFEcrypto KEM scheme
 *  @param kem The output KEM encapsulation key
 *  @param kem_len The length of the output KEM encapsulation key
 *  @param sig A signature of the output KEM encapsulation key
 *  @param sig_len The length of the signature
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_ake_2way_init(safecrypto_t *sc_sig, safecrypto_t *sc_kem,
    UINT8 **kem, size_t *kem_len, UINT8 **sig, size_t *sig_len);

/** @brief Verify the encapsulation key to authenticate "A" and use it to encapsulate a random
 *  secret key, sign the original message and the public/private key encapsulation fields using the
 *  specified hash. Finally create the public component of the key encapsulation, the hash and the
 *  signature to be sent to "A".
 *
 *  @param sc_sig The SAFEcrypto signature scheme
 *  @param sc_kem The SAFEcrypto KEM scheme
 *  @param hash_type The hash to be used
 *  @param kem The input KEM encapsulation key
 *  @param kem_len The length of the input KEM encapsulation key
 *  @param sig A signature of the input KEM encapsulation key
 *  @param sig_len The length of the signature
 *  @param md The output message digest associated with the hash of the random secret key, original message and KEM key
 *  @param md_len The length of the output message digest
 *  @param c The output public KEM key
 *  @param c_len The length of the output public KEM key
 *  @param resp_sig The output response signature of the hash
 *  @param resp_sig_len The length of the output response signature
 *  @param secret The shared random secret key
 *  @param secret_len The length of the shared random secret key
 *  @param secret The shared random secret key
 *  @param secret_len The length of the shared random secret key
 *  @return Returns 1 on successful authentication
 */
extern SINT32 safecrypto_ake_2way_response(safecrypto_t *sc_sig, safecrypto_t *sc_kem,
    sc_ake_e ake_type, sc_hash_e hash_type,
    const UINT8 *kem, size_t kem_len, const UINT8 *sig, size_t sig_len,
    UINT8 **md, size_t *md_len, UINT8 **c, size_t *c_len, UINT8 **resp_sig, size_t *resp_sig_len,
    UINT8 **secret, size_t *secret_len);

/** @brief Authenticate "B" and retrieve the random secret key. The response signature is first
 *  authenticated, then the encapsulation key is used to retrieve the random secret key. The hash
 *  is then re-created and compared to the received hash to authenticate "B".
 *
 *  @param sc_sig The SAFEcrypto signature scheme
 *  @param sc_kem The SAFEcrypto KEM scheme
 *  @param hash_type The hash to be used
 *  @param md The input message digest associated with the hash of the random secret key, original message and KEM key
 *  @param md_len The length of the input message digest
 *  @param c The output public KEM key
 *  @param c_len The length of the output public KEM key
 *  @param resp_sig The input response signature of the hash
 *  @param resp_sig_len The length of the input response signature
 *  @param sig A signature of the input KEM encapsulation key
 *  @param sig_len The length of the signature
 *  @param secret The shared random secret key
 *  @param secret_len The length of the shared random secret key
 *  @return Returns 1 on successful authentication
 */
extern SINT32 safecrypto_ake_2way_final(safecrypto_t *sc_sig, safecrypto_t *sc_kem,
    sc_ake_e ake_type, sc_hash_e hash_type,
    const UINT8 *md, size_t md_len, const UINT8 *c, size_t c_len, const UINT8 *resp_sig, size_t resp_sig_len,
    const UINT8 *sig, size_t sig_len,
    UINT8 **secret, size_t *secret_len);
/**@}*/


/** @name Hash
 *  Functions used to provide message hashing functionality.
 */
/**@{*/

/** @brief Obtain a linked list containing the hash schemes supported by SAFEcrypto
 *
 *  @return A pointer to the first sc_hash_t node in the linked list
 */
extern const sc_hash_t *safecrypto_get_hash_schemes(void);

/** @brief Create an instance of the selected hash function
 *
 *  @param type The type of hash function
 *  @return Returns a pointer to the hash struct
 */
extern safecrypto_hash_t * safecrypto_hash_create(sc_hash_e type);

/** @brief Destroy an instance of a hash and release all memory resources
 *
 *  @param hash A pointer to the hash struct
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_hash_destroy(safecrypto_hash_t *hash);

/** @brief Return the type of hash function
 *
 *  @param hash A pointer to the hash struct
 *  @return Returns the SC_HASH_MAX upon failure
 */
extern sc_hash_e safecrypto_hash_type(safecrypto_hash_t *hash);

/** @brief Get the length of the message digest produced by the hash function
 *
 *  @param hash A pointer to the hash struct
 *  @return Returns the length of the message digest (in bytes), or 0 if failure
 */
extern size_t safecrypto_hash_length(safecrypto_hash_t *hash);

/** @brief The common hash API function used to initialise
 *
 *  @param hash A pointer to the hash struct
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_hash_init(safecrypto_hash_t *hash);

/** @brief The common hash API function used to update using a specified byte array
 *
 *  @param hash A pointer to the hash struct
 *  @param data A pointer to the memory array containing message bytes
 *  @param len The length of the message data array
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_hash_update(safecrypto_hash_t *hash, const UINT8 *data, size_t len);

/** @brief The common hash API function used to finalize the hash output
 *
 *  @param hash A pointer to the hash struct
 *  @param md A pointer to the message digest
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_hash_final(safecrypto_hash_t *hash, UINT8 *md);
/**@}*/

#ifdef __cplusplus
}
#endif


/** @name Extendible Output Function
 *  Functions used to provide XOF functionality.
 */
/**@{*/

/** @brief Obtain a linked list containing the XOF schemes supported by SAFEcrypto
 *
 *  @return A pointer to the first sc_xof_t node in the linked list
 */
extern const sc_xof_t *safecrypto_get_xof_schemes(void);

/** @brief Create an instance of the selected XOF function
 *
 *  @param type The type of XOF function
 *  @return Returns a pointer to the XOF struct
 */
extern safecrypto_xof_t * safecrypto_xof_create(sc_xof_e type);

/** @brief Destroy an instance of a XOF and release all memory resources
 *
 *  @param xof A pointer to the XOF struct
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_xof_destroy(safecrypto_xof_t* xof);

/** @brief Determine the type of XOF
 *
 *  @param xof A pointer to the XOF struct
 *  @return Returns SC_XOF_MAX on failure
 */
extern sc_xof_e safecrypto_xof_type(safecrypto_xof_t *xof);

/** @brief Initialise a XOF instance
 *
 *  @param xof A pointer to the XOF struct
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_xof_init(safecrypto_xof_t *xof);

/** @brief The XOF API function used to seed a XOF
 *
 *  @param xof A pointer to the XOF struct
 *  @param data A pointer to the memory array containing message bytes
 *  @param len The length of the message data array
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_xof_absorb(safecrypto_xof_t *xof, const UINT8 *data, size_t len);

/** @brief XOF API function used to finalize the XOF input
 *
 *  @param xof A pointer to the XOF struct
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_xof_final(safecrypto_xof_t *xof);

/** @brief Generate output data
 *
 *  @param xof A pointer to the XOF struct
 *  @param output A pointer to the memory array containing 
 *  @param len The length of the output data array
 *  @return Returns 1 on success
 */
extern SINT32 safecrypto_xof_squeeze(safecrypto_xof_t *xof, UINT8 *output, size_t len);
/**@}*/
