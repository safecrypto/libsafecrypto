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
#define SC_FUNC_SUCCESS   1
#define SC_FUNC_FAILURE   0
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

#ifdef __cplusplus
}
#endif

