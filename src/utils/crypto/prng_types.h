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
 * This header file is the only header file that must be distributed with a
 * pre-built library.
 *
 * Git commit information:
 *   Author: $SC_AUTHOR$
 *   Date:   $SC_DATE$
 *   Branch: $SC_BRANCH$
 *   Id:     $SC_IDENT$
 */


#pragma once

#include <stdint.h>
#include <string.h>
#include "safecrypto_types.h"

#ifdef __cplusplus
extern "C" {
#endif


#if defined(CONSTRAINED_RAM) || defined(CONSTRAINED_ROM) || defined(CONSTRAINED_CPU)
#define CONSTRAINED_SYSTEM
#define ENABLE_SHA3
#define ENABLE_AES
#else
#define ENABLE_SHA2
#define ENABLE_SHA3
#define ENABLE_SHAKE
#define ENABLE_BLAKE2
#define ENABLE_WHIRLPOOL
#define ENABLE_ISAAC
#define ENABLE_KISS
#define ENABLE_SALSA20
#define ENABLE_CHACHA20
#define ENABLE_AES
#define ENABLE_HASH_DRBG
#endif

/// The size of the (CS)PRNG transfer buffer (MUST BE a factor of 64 and at least 64)
#ifdef CONSTRAINED_RAM
#define CSPRNG_BUFFER_SIZE          64
#else
#define CSPRNG_BUFFER_SIZE          1024
#endif

#if CSPRNG_BUFFER_SIZE < 64
#error CSPRNG_BUFFER_SIZE must be 64 bytes or greater and a multiple of 16
#endif

///** @name Standard types
// *  Standard data types to be used throughout the library.
// */
///**@{*/
//
//#define SINT8      int8_t
//#define UINT8      uint8_t
//
//#define SINT16     int16_t
//#define UINT16     uint16_t
//
//#define SINT32     int32_t
//#define UINT32     uint32_t
//
//#ifdef HAVE_64BIT
//#define SINT64     int64_t
//#define UINT64     uint64_t
//#endif
//
//#if defined(HAVE_128BIT) && defined(__x86_64__)
//typedef __int128 int128_t;
//typedef unsigned __int128 uint128_t;
//#define SINT128    int128_t
//#define UINT128    uint128_t
//#endif
//
//#define BOOLEAN    int32_t
//
//#define FLOAT      float
//#define DOUBLE     double
//#define LONGDOUBLE long double
//
///**@}*/
//
///// The size of the (CS)PRNG transfer buffer (MUST BE a factor of 64 and at least 64)
//#ifdef CONSTRAINED_RAM
//#define CSPRNG_BUFFER_SIZE          64
//#else
//#define CSPRNG_BUFFER_SIZE          1024
//#endif
//
//#if CSPRNG_BUFFER_SIZE < 64
//#error CSPRNG_BUFFER_SIZE must be 64 bytes or greater and a multiple of 16
//#endif
//
///// @name Function return codes
///**@{*/
//#define PRNG_FUNC_SUCCESS           1
//#define PRNG_FUNC_FAILURE           0
///**@}*/
//
//
///// @name Standard Error Codes
///**@{*/
//#define PRNG_OK                     0   ///< Function call was successfull
//#define PRNG_OUT_OF_BOUNDS          1   ///< An out-of-bounds error occured
//#define PRNG_CREATE_ERROR           2   ///< A resource allocation function failed
//#define PRNG_NULL_POINTER           3   ///< Indicates an attempt to dereference a null pointer
//#define PRNG_ERROR                  4   ///< A general error occured
//#define PRNG_INVALID_FUNCTION_CALL  5   ///< A function call through a function pointer was invalid
//#define PRNG_GETERR_NULL_POINTER    6   ///< Indicates the PRNG pointer is invalid
//#define PRNG_INVALID_FILE_PTR       7   ///< Indicates the use of an invalid file pointer
//#define PRNG_QUEUE_FULL             8   ///< A queue is full
//#define PRNG_QUEUE_EMPTY            9   ///< A queue is empty
//#define PRNG_FAILED_LOCK            10  ///< Failed to lock a guard
//#define PRNG_THREAD_ERROR           11  ///< A thread error occurred
//#define PRNG_THREAD_EXITING         12  ///< A thread is in the process of exiting
//#define PRNG_NUM_ERROR_CODES        13  ///< NOT AN ERROR CODE, used to indicate the number of error codes
///**@}*/
//
//
///// Macro's used for structure packing and alignment
///**@{*/
//#if 0
//#define SC_STRUCT_PACK_START
//#define SC_STRUCT_PACKED
//#define SC_STRUCT_PACK_END
//#else
//#ifdef _MSC_VER
//#define PRNG_STRUCT_PACK_START   _Pragma("pack(push, 1)")
//#define PRNG_STRUCT_PACKED
//#define PRNG_STRUCT_PACK_END     _Pragma("pack(pop)")
//#else
//#define PRNG_STRUCT_PACK_START
//#define PRNG_STRUCT_PACKED       __attribute__((__packed__))
//#define PRNG_STRUCT_PACK_END
//#endif
//#endif
///**@}*/
//
///// Macro's used for alignment
///**@{*/
//#if defined(_MSC_VER)
//#define PRNG_ALIGNED(n)       __declspec(align(n))
//#define PRNG_DEFAULT_ALIGNED  __declspec(align(32))
//#else
//#define PRNG_ALIGNED(n)       __attribute__((aligned(n)))
//#define PRNG_DEFAULT_ALIGNED  __attribute__((aligned(32)))
//#endif
//
//#define PRNG_RESTRICT         restrict
//
//#define PRNG_IS_ALIGNED_64(p) (0 == (7 & ((const char*)(p) - (const char*)0)))
//#define PRNG_IS_ALIGNED_32(p) (0 == (3 & ((const char*)(p) - (const char*)0)))
///**@}*/
//
//#ifdef HAVE_64BIT
//UINT64 prng_bswap_64(UINT64 x);
//void prng_swap_copy_64(void* to, SINT32 index, const void* from, size_t length);
//#endif
//void prng_swap_copy_32(void* to, SINT32 index, const void* from, size_t length);
//
//#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
//// We are big-endian
//#define PRNG_LITTLE_ENDIAN_32(x) ((((x) & 0xFF000000) >> 24) | \
//                                  (((x) & 0x00FF0000) >>  8) | \
//                                  (((x) & 0x0000FF00) <<  8) | \
//                                  (((x) & 0x000000FF) << 24))
//#define PRNG_BIG_ENDIAN_32(x)    (x)
//#define PRNG_LITTLE_ENDIAN_32_COPY(to, index, from, length) \
//            prng_swap_copy_32((to), (index), (from), (length))
//#define PRNG_BIG_ENDIAN_32_COPY(to, index, from, length) \
//            PRNG_MEMCOPY((to) + (index), (from), (length))
//#ifdef HAVE_64BIT
//#define PRNG_LITTLE_ENDIAN_64(x) ((((x) & 0xFF00000000000000) >> 56) | \
//                                  (((x) & 0x00FF000000000000) >> 40) | \
//                                  (((x) & 0x0000FF0000000000) >> 24) | \
//                                  (((x) & 0x000000FF00000000) >>  8) | \
//                                  (((x) & 0x00000000FF000000) <<  8) | \
//                                  (((x) & 0x0000000000FF0000) << 24) | \
//                                  (((x) & 0x000000000000FF00) << 40) | \
//                                  (((x) & 0x00000000000000FF) << 56))
//#define PRNG_BIG_ENDIAN_64(x)    (x)
//#define PRNG_LITTLE_ENDIAN_64_COPY(to, index, from, length) \
//            prng_swap_copy_64((to), (index), (from), (length))
//#define PRNG_BIG_ENDIAN_64_COPY(to, index, from, length) \
//            PRNG_MEMCOPY((to) + (index), (from), (length))
//#endif
//#else
//// We are little-endian
//#define PRNG_LITTLE_ENDIAN_32(x) (x)
//#define PRNG_BIG_ENDIAN_32(x)    ((((x) & 0xFF000000) >> 24) | \
//                                  (((x) & 0x00FF0000) >>  8) | \
//                                  (((x) & 0x0000FF00) <<  8) | \
//                                  (((x) & 0x000000FF) << 24))
//#define PRNG_LITTLE_ENDIAN_32_COPY(to, index, from, length) \
//            PRNG_MEMCOPY((to) + (index), (from), (length))
//#define PRNG_BIG_ENDIAN_32_COPY(to, index, from, length) \
//            prng_swap_copy_32((to), (index), (from), (length))
//#ifdef HAVE_64BIT
//#define PRNG_LITTLE_ENDIAN_64(x) (x)
//#define PRNG_BIG_ENDIAN_64(x)    ((((x) & 0xFF00000000000000) >> 56) | \
//                                  (((x) & 0x00FF000000000000) >> 40) | \
//                                  (((x) & 0x0000FF0000000000) >> 24) | \
//                                  (((x) & 0x000000FF00000000) >>  8) | \
//                                  (((x) & 0x00000000FF000000) <<  8) | \
//                                  (((x) & 0x0000000000FF0000) << 24) | \
//                                  (((x) & 0x000000000000FF00) << 40) | \
//                                  (((x) & 0x00000000000000FF) << 56))
//#define PRNG_LITTLE_ENDIAN_64_COPY(to, index, from, length) \
//            PRNG_MEMCOPY((to) + (index), (from), (length))
//#define PRNG_BIG_ENDIAN_64_COPY(to, index, from, length) \
//            prng_swap_copy_64((to), (index), (from), (length))
//#endif
//#endif
//
//
///// @name Helper functions for memory allocation and string manipulation
///**@{*/
//extern void * prng_malloc(size_t size);
//extern void prng_free(void *ptr, size_t size);
//extern void prng_explicit_memzero(void * const ptr, const size_t size);
//extern void * prng_memcpy(void *dest, const void *src, size_t size);
//extern char * prng_strcpy(char *dest, const char *src, size_t dest_size);
//
//
//#define PRNG_MALLOC(s)      prng_malloc(s)
//#define PRNG_FREE(s,l)      prng_free((s), (l)); (s) = NULL;
//#define PRNG_MEMZERO(s,l)   prng_explicit_memzero((s), (l))
//#define PRNG_MEMCOPY(d,s,l) prng_memcpy((d), (s), (l))
//#define PRNG_STRCPY(d,s,l)  prng_strcpy((d), (s), (l))
//
///**@}*/



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
} safecrypto_prng_e;

/// An enum defining the various types of CSPRNG
extern const char *safecrypto_prng_names [16];

/// An enum defining the random seeding type
typedef enum safecrypto_entropy {
    SC_ENTROPY_RANDOM = 0,
    SC_ENTROPY_DEV_RANDOM,
    SC_ENTROPY_DEV_URANDOM,
    SC_ENTROPY_DEV_HWRNG,
    SC_ENTROPY_CALLBACK,
    SC_ENTROPY_USER_PROVIDED,
} safecrypto_entropy_e;


/// An enum defining the use of multithreading in the PRNG
typedef enum safecrypto_prng_threading {
    SC_PRNG_THREADING_NONE = 0,
} safecrypto_prng_threading_e;

/// A struct used to store user supplied entropy
SC_STRUCT_PACK_START
typedef struct user_entropy {
    const UINT8 *data;
    size_t len;
    size_t idx;
} SC_STRUCT_PACKED user_entropy_t;
SC_STRUCT_PACK_END

// Forward declaration of the prng_ctx_t struct
typedef struct prng_ctx_t prng_ctx_t;


/// A typedef for the entropy function pointers
typedef void (*prng_entropy_callback)(size_t, UINT8 *);

/// A typedef for the entropy function pointers
typedef void (*func_get_random_entropy)(size_t, UINT8 *, user_entropy_t *);

/// A typedef for the function pointer used to obtain 32-bit random numbers
typedef UINT32 (*func_get_random_32)(prng_ctx_t *);

/// A typedef for the function pointer used to obtain 64-bit random numbers
typedef UINT64 (*func_get_random_64)(prng_ctx_t *);



typedef struct ctx_ctr_drbg_t ctx_ctr_drbg_t;
typedef struct ctx_aes_ctr_t ctx_aes_ctr_t;
typedef struct kiss_state_t kiss_state_t;
typedef struct isaac_state_t isaac_state_t;
typedef struct chacha20_state_t chacha20_state_t;
typedef struct salsa20_state_t salsa20_state_t;
typedef struct hash_drbg_t hash_drbg_t;
typedef struct randctx randctx;

union u_byte {
   UINT8 b[CSPRNG_BUFFER_SIZE];
   UINT32 w[CSPRNG_BUFFER_SIZE/sizeof(UINT32)];
   UINT64 w64[CSPRNG_BUFFER_SIZE/sizeof(UINT64)];
};


/// The PRNG context struct used to store the parameters for each instance
SC_STRUCT_PACK_START
typedef struct prng_ctx_t
{
    safecrypto_prng_e type;
    safecrypto_entropy_e entropy;

    /// Storage of the user supplied entropy
    user_entropy_t *user_entropy;

    /// AES CTR-DRBG context
    ctx_ctr_drbg_t *ctr_drbg_ctx;

#ifdef ENABLE_AES_CTR_STREAM
    /// AES-CTR context
    ctx_aes_ctr_t *aes_ctr_ctx;
#endif

#ifdef ENABLE_KISS
    /// KISS context
    kiss_state_t *kiss_ctx;
#endif

#ifdef ENABLE_ISAAC
    /// ISAAC context
    isaac_state_t *isaac_ctx;
#endif

#ifdef ENABLE_CHACHA20
    // ChaCha20 context
    chacha20_state_t *chacha20_ctx;
#endif

#ifdef ENABLE_SALSA20
    // ChaCha20 context
    salsa20_state_t *salsa20_ctx;
#endif

#ifdef ENABLE_HASH_DRBG
    // Hash-DRBG context
    hash_drbg_t *hash_drbg_ctx;
#endif

    /// ISAAC context
#ifndef HAVE_64BIT
    randctx rand_ctx;
#endif

#if !defined( __linux__ ) && !defined( __GNUC__ ) && !defined( __GNU_LIBRARY__ )
    HCRYPTPROV hCryptProv;
#endif

    // A buffer used to maintain random bits for output
    UINT32 *random_pool;
    SINT32 bits;
    SINT32 wr_idx;
    SINT32 rd_idx;

    // A buffer used to store bits for the prng_var function
    UINT32 var_buf;
    size_t var_bits;

    // The number of random bytes to be produced before the CSPRNG
    // is reseeded
    size_t seed_period;

    /// A function pointer for the platform specific 32-bit CSPRNG
    func_get_random_32 get_random_32;

#ifdef HAVE_64BIT
    /// A function pointer for the platform specific 64-bit CSPRNG
    func_get_random_64 get_random_64;
#endif

    /// Statistics information
    UINT64 stats_csprng_bytes;
    UINT64 stats_out_bytes;

#if 0
    /// Multithreaded support parameters
    pipe_t *pipe_u32;
    pipe_t *pipe_u16;
    pipe_t *pipe_u8;
    pipe_t *pipe_flt;
    pipe_t *pipe_dbl;
    pipe_consumer_t *pipe_u32_consumer;
    pipe_consumer_t *pipe_u16_consumer;
    pipe_consumer_t *pipe_u8_consumer;
    pipe_consumer_t *pipe_flt_consumer;
    pipe_consumer_t *pipe_dbl_consumer;
    SINT32 mt_enabled;
    sc_threadpool_t *pool;
#endif

    /// A buffer used in the transfer of data from the various (CS)PRNGs
    /**@{*/
    union u_byte rng_buffer;
    SINT32 rng_cnt;
    /**@}*/

#ifdef _ENABLE_CSPRNG_FILE
    char debug_filename[256];
    UINT8 *debug_data;
    size_t debug_ptr;
    size_t debug_length;
#endif

} SC_STRUCT_PACKED prng_ctx_t;
SC_STRUCT_PACK_END


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




#ifdef __cplusplus
}
#endif

