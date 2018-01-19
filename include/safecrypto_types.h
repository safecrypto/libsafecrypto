/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

/**
 * @file safecrypto_types.h
 * @author n.smyth@qub.ac.uk
 * @date 10 Aug 2016
 * @brief Standard types definitions for the SAFEcrypto library.
 *
 * Git commit information:
 *   Author: $SC_AUTHOR$
 *   Date:   $SC_DATE$
 *   Branch: $SC_BRANCH$
 *   Id:     $SC_IDENT$
 */

#pragma once

#include <stdint.h>
#include <stdio.h>


#ifdef __cplusplus
extern "C" {
#endif


/** @name Standard types
 *  Standard data types to be used throughout the library.
 */
/**@{*/

#define SINT8      int8_t
#define UINT8      uint8_t

#define SINT16     int16_t
#define UINT16     uint16_t

#define SINT32     int32_t
#define UINT32     uint32_t

#ifdef HAVE_64BIT
#define SINT64     int64_t
#define UINT64     uint64_t
#endif

#if defined(HAVE_128BIT) && defined(__x86_64__)
typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;
#define SINT128    int128_t
#define UINT128    uint128_t
#endif

#define BOOLEAN    int32_t

#define FLOAT      float
#define DOUBLE     double
#define LONGDOUBLE long double

/**@}*/


/// @name Function return codes (Chosen to be OpenSSL-like)
/**@{*/
#define SC_FUNC_SUCCESS   0
#define SC_FUNC_FAILURE   1
/**@}*/


/// @name Standard Error Codes for the error queue
/**@{*/
#define SC_OK                     0   ///< Function call was successfull
#define SC_OUT_OF_BOUNDS          1   ///< An out-of-bounds error occured
#define SC_CREATE_ERROR           2   ///< A resource allocation function failed
#define SC_NULL_POINTER           3   ///< Indicates an attempt to dereference a null pointer
#define SC_ERROR                  4   ///< A general error occured
#define SC_INVALID_FUNCTION_CALL  5   ///< A function call through a function pointer was invalid
#define SC_GETERR_NULL_POINTER    6   ///< Indicates the SAFEcrypto pointer is invalid
#define SC_INVALID_FILE_PTR       7   ///< Indicates the use of an invalid file pointer
#define SC_QUEUE_FULL             8   ///< A queue is full
#define SC_QUEUE_EMPTY            9   ///< A queue is empty
#define SC_FAILED_LOCK            10  ///< Failed to lock a guard
#define SC_THREAD_ERROR           11  ///< A thread error occurred
#define SC_THREAD_EXITING         12  ///< A thread is in the process of exiting
#define SC_DISABLED_AT_COMPILE    13  ///< Functionality has been disabled at compile-time
#define SC_NUM_ERROR_CODES        14  ///< NOT AN ERROR CODE, used to indicate the number of error codes
/**@}*/


/** @name Enumerated type construction
 *  Macros to be used when generating enumerated types and associated string tables.
 */
/**@{*/

/// A macro that converts a value to an enumerated type appended with a comma
#define GENERATE_ENUM_VALUE(VALUE) VALUE,

/// A macro that converts a value to a string appended with a comma
#define GENERATE_ENUM_STRING(VALUE) #VALUE,

/// A macro that declares an enumeration
#define GENERATE_ENUM(NAME,VALUES,MAXNAME) \
    typedef enum NAME { VALUES(GENERATE_ENUM_VALUE) MAXNAME } NAME

/// A macro that declares an array of strings associated with an enumeration
#define GENERATE_ENUM_NAMES(NAME,VALUES,MAXNAME) \
    static const char *NAME [MAXNAME] = { VALUES(GENERATE_ENUM_STRING) }

/**@}*/


/// Macro's used for function inlining
/**@{*/
#define SC_INLINE              inline
#ifdef _MSC_VER
#define SC_FORCE_INLINE        __forceinline
#else
#define SC_FORCE_INLINE        __attribute__((always_inline)) inline
#endif
/**@}*/

/// Macro's used for structure packing and alignment
/**@{*/
#if 0
#define SC_STRUCT_PACK_START
#define SC_STRUCT_PACKED
#define SC_STRUCT_PACK_END
#else
#ifdef _MSC_VER
#define SC_STRUCT_PACK_START   _Pragma("pack(push, 1)")
#define SC_STRUCT_PACKED
#define SC_STRUCT_PACK_END     _Pragma("pack(pop)")
#else
#define SC_STRUCT_PACK_START
#define SC_STRUCT_PACKED       __attribute__((__packed__))
#define SC_STRUCT_PACK_END
#endif
#endif
/**@}*/

/// Macro's used for alignment
/**@{*/
#if defined(_MSC_VER)
#define SC_ALIGNED(n)      __declspec(align(n))
#define SC_DEFAULT_ALIGNED __declspec(align(32))
#else
#define SC_ALIGNED(n)      __attribute__((aligned(n)))
#define SC_DEFAULT_ALIGNED __attribute__((aligned(32)))
#endif

#define SC_RESTRICT        __restrict__

#define SC_STRCPY(d,s,l)   sc_strcpy((d), (s), (l))

#define SC_IS_ALIGNED_64(p) (0 == (7 & ((const char*)(p) - (const char*)0)))
#define SC_IS_ALIGNED_32(p) (0 == (3 & ((const char*)(p) - (const char*)0)))
/**@}*/

/// A typedef for the entropy function pointers
typedef void (safecrypto_entropy_cb_func)(size_t, UINT8 *);



/// An enumerated type for print debug levels
typedef enum sc_debug_level {
    SC_LEVEL_NONE = 0,
    SC_LEVEL_ERROR,
    SC_LEVEL_WARNING,
    SC_LEVEL_INFO,
    SC_LEVEL_DEBUG,
} sc_debug_level_e;


/// A list of the lossless compression coding types to be used
#define ENTROPY_LIST(m) \
    m(SC_ENTROPY_NONE) \
    m(SC_ENTROPY_BAC) \
    m(SC_ENTROPY_BAC_RLE) \
    m(SC_ENTROPY_HUFFMAN_STATIC) \
    m(SC_ENTROPY_STRONGSWAN)

/// An enumerated type for the choice of entropy coding scheme
GENERATE_ENUM(sc_entropy_type_e, ENTROPY_LIST, SC_ENTROPY_SCHEME_MAX);

/// A list of the enumerated types in the form of human readable strings
__attribute__((unused))
GENERATE_ENUM_NAMES(sc_entropy_names, ENTROPY_LIST, SC_ENTROPY_SCHEME_MAX);


/// A list of the available hash functions
#define HASH_LIST(m) \
    m(SC_HASH_SHA3_512) \
    m(SC_HASH_SHA3_384) \
    m(SC_HASH_SHA3_256) \
    m(SC_HASH_SHA3_224) \
    m(SC_HASH_SHA2_512) \
    m(SC_HASH_SHA2_384) \
    m(SC_HASH_SHA2_256) \
    m(SC_HASH_SHA2_224) \
    m(SC_HASH_BLAKE2_512) \
    m(SC_HASH_BLAKE2_384) \
    m(SC_HASH_BLAKE2_256) \
    m(SC_HASH_BLAKE2_224) \
    m(SC_HASH_WHIRLPOOL_512) \
    m(SC_HASH_SHAKE128_256) \
    m(SC_HASH_SHAKE256_512)

/// An enumerated type for the choice of hash algorithm
GENERATE_ENUM(sc_hash_e, HASH_LIST, SC_HASH_MAX);

/// A list of the hash algorithms in the form of human readable strings
__attribute__((unused))
GENERATE_ENUM_NAMES(sc_hash_names, HASH_LIST, SC_HASH_MAX);


/// A list of the available schemes
#define XOF_LIST(m) \
   m(SC_XOF_SHAKE256) \
   m(SC_XOF_SHAKE128) \
   m(SC_XOF_SHAKE256_4X) \
   m(SC_XOF_SHAKE128_4X)

/// An enumerated type for the choice of XOF algorithm
GENERATE_ENUM(sc_xof_e, XOF_LIST, SC_XOF_MAX);

/// A list of the XOF algorithms in the form of human readable strings
__attribute__((unused))
GENERATE_ENUM_NAMES(sc_xof_names, XOF_LIST, SC_XOF_MAX);


/// An enum defining the various types of CSPRNG
typedef enum safecrypto_prng {
    SC_PRNG_SYSTEM = 0,
    SC_PRNG_AES_CTR_DRBG,
    SC_PRNG_AES_CTR,
    SC_PRNG_CHACHA,
    SC_PRNG_SALSA,
    SC_PRNG_ISAAC,
    SC_PRNG_KISS,
    SC_PRNG_HASH_DRBG_SHA2_256,
    SC_PRNG_HASH_DRBG_SHA2_512,
    SC_PRNG_HASH_DRBG_SHA3_256,
    SC_PRNG_HASH_DRBG_SHA3_512,
    SC_PRNG_HASH_DRBG_BLAKE2_256,
    SC_PRNG_HASH_DRBG_BLAKE2_512,
    SC_PRNG_HASH_DRBG_WHIRLPOOL_512,
    SC_PRNG_FILE,
    SC_PRNG_HIGH_ENTROPY,
    SC_PRNG_MAX,
} safecrypto_prng_e;

/// An enum defining the various types of CSPRNG
extern const char *safecrypto_prng_names [16];

/// A function pointer used to provide PRNG entropy using a callback function
typedef void (*safecrypto_prng_entropy_callback)(size_t, UINT8 *);


/// A list of the available AES mechanisms
#define AES_LIST(m) \
   m(SC_AES_ENCRYPT_128) \
   m(SC_AES_ENCRYPT_192) \
   m(SC_AES_ENCRYPT_256) \
   m(SC_AES_DECRYPT_128) \
   m(SC_AES_DECRYPT_192) \
   m(SC_AES_DECRYPT_256)

/// An enumerated type for the choice of XOF algorithm
GENERATE_ENUM(safecrypto_aes_type_e, AES_LIST, SC_AES_MAX);


/// A list of the available AKE types
#define AKE_LIST(m) \
    m(SC_AKE_FORWARD_SECURE)

/// An enumerated type for the choice of hash algorithm
GENERATE_ENUM(sc_ake_e, AKE_LIST, SC_AKE_MAX);


/// A list of the available schemes
#define SCHEME_LIST(m) \
    m(SC_SCHEME_NONE) \
    m(SC_SCHEME_SIG_HELLO_WORLD) \
    m(SC_SCHEME_SIG_BLISS) \
    m(SC_SCHEME_SIG_RING_TESLA) \
    m(SC_SCHEME_ENC_RLWE) \
    m(SC_SCHEME_KEM_ENS) \
    m(SC_SCHEME_SIG_ENS) \
    m(SC_SCHEME_SIG_ENS_WITH_RECOVERY) \
    m(SC_SCHEME_IBE_DLP) \
    m(SC_SCHEME_SIG_DLP) \
    m(SC_SCHEME_SIG_DLP_WITH_RECOVERY) \
    m(SC_SCHEME_SIG_DILITHIUM) \
    m(SC_SCHEME_SIG_DILITHIUM_G) \
    m(SC_SCHEME_KEM_KYBER) \
    m(SC_SCHEME_ENC_KYBER_CPA) \
    m(SC_SCHEME_ENC_KYBER_HYBRID) \
    m(SC_SCHEME_DH_ECDH) \
    m(SC_SCHEME_SIG_ECDSA)

/// An enumerated type for the choice of scheme
GENERATE_ENUM(sc_scheme_e, SCHEME_LIST, SC_SCHEME_MAX);

/// A list of the enumerated types in the form of human readable strings
__attribute__((unused))
GENERATE_ENUM_NAMES(sc_scheme_names, SCHEME_LIST, SC_SCHEME_MAX);

/// A struct used to store the coding details for produced data
SC_STRUCT_PACK_START
typedef struct _sc_stat_coding {
    size_t bits;
    size_t bits_coded;
    char   name[32];
} SC_STRUCT_PACKED sc_stat_coding_t;
SC_STRUCT_PACK_END

/// The types of data produced by the SAFEcrypto library
typedef enum _sc_stat_component {
    SC_STAT_PUB_KEY = 0,
    SC_STAT_PRIV_KEY,
    SC_STAT_SIGNATURE,
    SC_STAT_EXTRACT,
    SC_STAT_ENCRYPT,
    SC_STAT_ENCAPSULATE,
} sc_stat_component_e;

/// A struct used to store statistics for the algorithms
SC_STRUCT_PACK_START
typedef struct _sc_statistics {
    sc_scheme_e scheme;
    size_t param_set;
    size_t keygen_num;
    size_t keygen_num_trials;
    size_t pub_keys_encoded;
    size_t pub_keys_loaded;
    size_t priv_keys_encoded;
    size_t priv_keys_loaded;
    size_t sig_num;
    size_t sig_num_trials;
    size_t sig_num_verified;
    size_t sig_num_unverified;
    size_t encrypt_num;
    size_t decrypt_num;
    size_t encapsulate_num;
    size_t decapsulate_num;
    size_t extract_num;
    size_t extract_keys_loaded;
    size_t num_components[6];
#if 0
    sc_stat_coding_t *components[6];
#else
    sc_stat_coding_t components[6][5];
#endif
} SC_STRUCT_PACKED sc_statistics_t;
SC_STRUCT_PACK_END


#ifdef __cplusplus
}
#endif
