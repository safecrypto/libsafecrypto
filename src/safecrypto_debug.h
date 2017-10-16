/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

/**
 * @file
 * The following macros provide a multilevel debug printing facility for users.
 * The use of these debug macros allows a user to place helpful debugging
 * information within their code that can be dynamically modified at runtime to
 * allow the level of verbosity in debug statements to be adjusted, or for all
 * debug print statements to be completely disabled.
 * Additionally the debug statements are entirely removed from the compiled
 * library when a normal Release build (the default build target) is enabled.
 * When the user defines the DEBUG preprocessor statement when building the
 * debug print macros are enabled.
 * 
 * @author n.smyth@qub.ac.uk
 * @date 10 Aug 2016
 * @brief A multilevel debug facility for users.
 *
 * Git commit information:
 *   Author: $SC_AUTHOR$
 *   Date:   $SC_DATE$
 *   Branch: $SC_BRANCH$
 *   Id:     $SC_IDENT$
 */


#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#include "safecrypto.h"
#ifndef ENABLE_BAREMETAL
#include "safecrypto_timer.h"
#endif

/// An initialisation function that must be called when a SAFEcrypto structure is created
extern SINT32 sc_debug_init(safecrypto_t *sc);

extern SINT32 sc_debug_destroy(safecrypto_t *sc);

/// @name Functions used by the API to get/set the debug level
/**@{*/
extern SINT32 sc_set_verbosity(safecrypto_t *sc, sc_debug_level_e level);
extern sc_debug_level_e sc_get_verbosity(safecrypto_t *sc);
/**@}*/

/// @name Macro functions for basic profiling of code
/**@{*/
#define SC_TIMER_INSTANCE(t)         void *t = NULL
#define SC_TIMER_CREATE(t)           t = sc_timer_create()
#define SC_TIMER_DESTROY(t)          sc_timer_delete(&t)
#define SC_TIMER_RESET(t)            sc_timer_reset(t)
#define SC_TIMER_START(t)            sc_timer_start(t)
#define SC_TIMER_STOP(t)             sc_timer_stop(t)
#define SC_TIMER_CONTINUE(t)         sc_timer_stop(t)
#define SC_TIMER_GET_ELAPSED(t)      sc_timer_get_elapsed(t)
#define SC_TIMER_GET_SECS(t)         sc_timer_diff_secs(t)
#define SC_TIMER_GET_NSEC(t)         sc_timer_diff_nsec(t)
#define SC_TIMER_PRINT_STRING(t,m)   sc_timer_print_diff_string(t, m)
/**@}*/

#ifdef DEBUG

/// @name Helper functions for printing debug statements and error information
/**@{*/
extern void sc_printf(safecrypto_t *sc, sc_debug_level_e level, const char *fmt, ...);
extern void sc_print_privkey(safecrypto_t *sc, sc_debug_level_e level, SINT32 bits);
extern void sc_print_1d_uint8(safecrypto_t *sc, sc_debug_level_e level, const char *label,
    const UINT8 *array, SINT32 len, SINT32 hex);
extern void sc_print_1d_uint16(safecrypto_t *sc, sc_debug_level_e level, const char *label,
    const UINT16 *array, SINT32 len, SINT32 hex);
extern void sc_print_1d_uint32(safecrypto_t *sc, sc_debug_level_e level, const char *label,
    const UINT32 *array, SINT32 len, SINT32 hex);
extern void sc_print_1d_uint64(safecrypto_t *sc, sc_debug_level_e level, const char *label,
    const UINT64 *array, SINT32 len, SINT32 hex);
extern void sc_print_1d_int8(safecrypto_t *sc, sc_debug_level_e level, const char *label,
    const SINT8 *array, SINT32 len, SINT32 hex);
extern void sc_print_1d_int16(safecrypto_t *sc, sc_debug_level_e level, const char *label,
    const SINT16 *array, SINT32 len, SINT32 hex);
extern void sc_print_1d_int32(safecrypto_t *sc, sc_debug_level_e level, const char *label,
    const SINT32 *array, SINT32 len, SINT32 hex);
extern void sc_print_1d_int64(safecrypto_t *sc, sc_debug_level_e level, const char *label,
    const SINT64 *array, SINT32 len, SINT32 hex);
extern void sc_print_1d_float(safecrypto_t *sc, sc_debug_level_e level, const char *label,
    const FLOAT *array, SINT32 len);
extern void sc_print_1d_double(safecrypto_t *sc, sc_debug_level_e level, const char *label,
    const DOUBLE *array, SINT32 len);
extern void sc_print_1d_long_double(safecrypto_t *sc, sc_debug_level_e level, const char *label,
    const LONGDOUBLE *array, SINT32 len);
/**@}*/

/// @name Macro functions for printing debug information
/**@{*/
#define SC_PRINT_DEBUG(sc,...)                 sc_printf((sc), SC_LEVEL_DEBUG,   __VA_ARGS__)
#define SC_PRINT_INFO(sc,...)                  sc_printf((sc), SC_LEVEL_INFO,    __VA_ARGS__)
#define SC_PRINT_WARNING(sc,...)               sc_printf((sc), SC_LEVEL_WARNING, __VA_ARGS__)
#define SC_PRINT_ERROR(sc,...)                 sc_printf((sc), SC_LEVEL_ERROR,   __VA_ARGS__)
#define SC_PRINT_KEYS(sc,l,b)                  sc_print_privkey((sc), (l), (b))
#define SC_PRINT_1D_UINT8(sc,l,n,arr,len)      sc_print_1d_uint8((sc), (l), (n), (arr), (len), 0)
#define SC_PRINT_1D_UINT16(sc,l,n,arr,len)     sc_print_1d_uint16((sc), (l), (n), (arr), (len), 0)
#define SC_PRINT_1D_UINT32(sc,l,n,arr,len)     sc_print_1d_uint32((sc), (l), (n), (arr), (len), 0)
#define SC_PRINT_1D_UINT64(sc,l,n,arr,len)     sc_print_1d_uint64((sc), (l), (n), (arr), (len), 0)
#define SC_PRINT_1D_INT8(sc,l,n,arr,len)       sc_print_1d_int8((sc), (l), (n), (arr), (len), 0)
#define SC_PRINT_1D_INT16(sc,l,n,arr,len)      sc_print_1d_int16((sc), (l), (n), (arr), (len), 0)
#define SC_PRINT_1D_INT32(sc,l,n,arr,len)      sc_print_1d_int32((sc), (l), (n), (arr), (len), 0)
#define SC_PRINT_1D_INT64(sc,l,n,arr,len)      sc_print_1d_int64((sc), (l), (n), (arr), (len), 0)
#define SC_PRINT_1D_FLOAT(sc,l,n,arr,len)      sc_print_1d_float((sc), (l), (n), (arr), (len))
#define SC_PRINT_1D_DOUBLE(sc,l,n,arr,len)     sc_print_1d_double((sc), (l), (n), (arr), (len))
#define SC_PRINT_1D_LONGDOUBLE(sc,l,n,arr,len) sc_print_1d_long_double((sc), (l), (n), (arr), (len))
#define SC_PRINT_1D_UINT8_HEX(sc,l,n,arr,len)  sc_print_1d_uint8((sc), (l), (n), (arr), (len), 1)
#define SC_PRINT_1D_UINT16_HEX(sc,l,n,arr,len) sc_print_1d_uint16((sc), (l), (n), (arr), (len), 1)
#define SC_PRINT_1D_UINT32_HEX(sc,l,n,arr,len) sc_print_1d_uint32((sc), (l), (n), (arr), (len), 1)
#define SC_PRINT_1D_UINT64_HEX(sc,l,n,arr,len) sc_print_1d_uint64((sc), (l), (n), (arr), (len), 1)
#define SC_PRINT_1D_INT8_HEX(sc,l,n,arr,len)   sc_print_1d_int8((sc), (l), (n), (arr), (len), 1)
#define SC_PRINT_1D_INT16_HEX(sc,l,n,arr,len)  sc_print_1d_int16((sc), (l), (n), (arr), (len), 1)
#define SC_PRINT_1D_INT32_HEX(sc,l,n,arr,len)  sc_print_1d_int32((sc), (l), (n), (arr), (len), 1)
#define SC_PRINT_1D_INT64_HEX(sc,l,n,arr,len)  sc_print_1d_int64((sc), (l), (n), (arr), (len), 1)
/**@}*/
#else
/// @name Macro functions for printing debug information
/**@{*/
#define SC_PRINT_DEBUG(sc,...)
#define SC_PRINT_INFO(sc,...)
#define SC_PRINT_WARNING(sc,...)
#define SC_PRINT_ERROR(sc,...)
#define SC_PRINT_KEYS(sc,l,b)
#define SC_PRINT_UINT8(l,n,arr,len)
#define SC_PRINT_1D_UINT8(sc,l,n,arr,len)
#define SC_PRINT_1D_UINT16(sc,l,n,arr,len)
#define SC_PRINT_1D_UINT32(sc,l,n,arr,len)
#define SC_PRINT_1D_UINT64(sc,l,n,arr,len)
#define SC_PRINT_1D_INT8(sc,l,n,arr,len)
#define SC_PRINT_1D_INT16(sc,l,n,arr,len)
#define SC_PRINT_1D_INT32(sc,l,n,arr,len)
#define SC_PRINT_1D_INT64(sc,l,n,arr,len)
#define SC_PRINT_1D_FLOAT(sc,l,n,arr,len)
#define SC_PRINT_1D_DOUBLE(sc,l,n,arr,len)
#define SC_PRINT_1D_LONGDOUBLE(sc,l,n,arr,len)
#define SC_PRINT_1D_UINT8_HEX(sc,l,n,arr,len)
#define SC_PRINT_1D_UINT16_HEX(sc,l,n,arr,len)
#define SC_PRINT_1D_UINT32_HEX(sc,l,n,arr,len)
#define SC_PRINT_1D_UINT64_HEX(sc,l,n,arr,len)
#define SC_PRINT_1D_INT8_HEX(sc,l,n,arr,len)
#define SC_PRINT_1D_INT16_HEX(sc,l,n,arr,len)
#define SC_PRINT_1D_INT32_HEX(sc,l,n,arr,len)
#define SC_PRINT_1D_INT64_HEX(sc,l,n,arr,len)
#endif
/**@}*/
