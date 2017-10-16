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

#include "safecrypto_debug.h"
#include "safecrypto.h"
#include "safecrypto_private.h"
#include "safecrypto_error.h"

#ifdef DEBUG
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#endif

/// @todo Modify the safecrypto_debug facility to be thread safe


#define MAX_PRINT_LOG_LINES    100000

#define DEBUG_FILENAME         "sc_debug.log"
#define DEBUG_FILENAME_OLD     "sc_debug.log.old"

#ifdef DEBUG
static FILE *fp = NULL;  ///< A file stream used to store beug messages
static char filename[SC_MAX_FILENAME_LEN];
static SINT32 num_lines = 0;
#endif

SINT32 sc_debug_init(safecrypto_t *sc)
{
#ifdef DEBUG
    num_lines = 0;
    if (NULL == fp) {
        fp = fopen(DEBUG_FILENAME, "r");
        if (fp) {
            int ch;
            do 
            {
                ch = fgetc(fp);
                if ('\n' == ch)
                    num_lines++;
            } while (ch != EOF);

            fclose(fp);
        }

        fp = fopen(DEBUG_FILENAME, "a+");
        if (NULL == fp) {
            SC_LOG_ERROR(sc, SC_INVALID_FILE_PTR);
            return SC_FUNC_FAILURE;
        }
    }
#else
    (void) sc;
#endif
    return SC_FUNC_SUCCESS;
}

extern SINT32 sc_debug_destroy(safecrypto_t *sc)
{
#ifdef DEBUG
    if (NULL != fp) {
        fflush(fp);
        fclose(fp);
        fp = NULL;
    }
#else
    (void) sc;
#endif
    return SC_FUNC_SUCCESS;
}

SINT32 sc_set_verbosity(safecrypto_t *sc, sc_debug_level_e level)
{
#ifdef DEBUG
    // Out of bounds checking and error return code
    if (sc == NULL) return SC_FUNC_FAILURE;
    if (level > SC_LEVEL_DEBUG) return SC_FUNC_FAILURE;
    if (level < SC_LEVEL_NONE) return SC_FUNC_FAILURE;

    sc->debug_level = level;

    switch (level)
    {
    case SC_LEVEL_NONE: sc_printf(sc, level, "Debug printing set to: SC_LEVEL_NONE\n");       break;
    case SC_LEVEL_ERROR: sc_printf(sc, level, "Debug printing set to: SC_LEVEL_ERROR\n");     break;
    case SC_LEVEL_WARNING: sc_printf(sc, level, "Debug printing set to: SC_LEVEL_WARNING\n"); break;
    case SC_LEVEL_INFO: sc_printf(sc, level, "Debug printing set to: SC_LEVEL_INFO\n");       break;
    case SC_LEVEL_DEBUG: sc_printf(sc, level, "Debug printing set to: SC_LEVEL_DEBUG\n");     break;
    default:;
    }

    return SC_FUNC_SUCCESS;
#else
    (void) sc;
    (void) level;
    return SC_FUNC_FAILURE;
#endif
}

sc_debug_level_e sc_get_verbosity(safecrypto_t *sc)
{
#ifdef DEBUG
    if (sc == NULL) {
        return SC_LEVEL_NONE;
    }
    return sc->debug_level;
#else
    (void) sc;
    return SC_LEVEL_NONE;
#endif
}

#ifdef DEBUG

void sc_printf(safecrypto_t *sc, sc_debug_level_e level, const char *fmt, ...)
{
    if (sc == NULL || fp == NULL) {
        return;
    }

    if (level <= sc->debug_level) {
        va_list args;
        va_start(args, fmt);
        vfprintf(fp, fmt, args);
        va_end(args);

        // Periodically flush to file (NOTE: File access is write only)
        if ((num_lines & 31) == 31 || level == SC_LEVEL_ERROR)
            fflush(fp);
        
        // Increment the number of debug lines and check for an end
        // of log file condition
        num_lines++;
        if (num_lines >= MAX_PRINT_LOG_LINES) {
            int retcode;

            num_lines = 0;
            fclose(fp);

            // Remove the old log file
            remove(DEBUG_FILENAME_OLD);

            // Rename the current log file to be the old log file
            retcode = rename(DEBUG_FILENAME, DEBUG_FILENAME_OLD);
            if (retcode) {
                SC_LOG_ERROR(sc, SC_INVALID_FILE_PTR);
                return;
            }

            // Open a new log file
            fp = fopen(DEBUG_FILENAME, "a+");
            if (fp == NULL) {
                SC_LOG_ERROR(sc, SC_INVALID_FILE_PTR);
                return;
            }
        }
    }
}

void sc_print_privkey(safecrypto_t *sc, sc_debug_level_e level, SINT32 bits)
{
    SINT32 i = 0;
    if (sc == NULL) {
        return;
    }
    if (sc->privkey == NULL ||
        sc->privkey->key == NULL) return;
    if (sc->pubkey == NULL ||
        sc->pubkey->key == NULL) return;
    if (sc->privkey->len < 0 ||
        sc->pubkey->len < 0) return;

    if (16 == bits) {
        SINT16 *p = NULL;
        p = sc->privkey->key;
        sc_printf(sc, level, "\nPrivate key");
        for (i=0; i<sc->privkey->len; i++) {
            if ((i&0x7) == 0) sc_printf(sc, level, "\n  ");
            sc_printf(sc, level, "%8d ", *p++);
        }

        p = sc->pubkey->key;
        sc_printf(sc, level, "\nPublic key");
        for (i=0; i<sc->pubkey->len; i++) {
            if ((i&0x7) == 0) sc_printf(sc, level, "\n  ");
            sc_printf(sc, level, "%8d ", *p++);
        }
    }
    else {
        SINT32 *p = NULL;
        p = (SINT32 *) sc->privkey->key;
        sc_printf(sc, level, "\nPrivate key");
        for (i=0; i<sc->privkey->len; i++) {
            if ((i&0x7) == 0) sc_printf(sc, level, "\n  ");
            sc_printf(sc, level, "%9d ", *p++);
        }

        p = (SINT32 *) sc->pubkey->key;
        sc_printf(sc, level, "\nPublic key");
        for (i=0; i<sc->pubkey->len; i++) {
            if ((i&0x7) == 0) sc_printf(sc, level, "\n  ");
            sc_printf(sc, level, "%9d ", *p++);
        }
    }

    sc_printf(sc, level, "\n");
}


void sc_print_1d_uint8(safecrypto_t *sc, sc_debug_level_e level, const char *label,
    const UINT8 *array, SINT32 len, SINT32 hex)
{
    SINT32 i = 0;
    if (NULL == sc || NULL == array) {
        return;
    }
    sc_printf(sc, level, "\n%s", label);
    for (i=0; i<len; i++) {
        if ((i&0x0F) == 0) sc_printf(sc, level, "\n  ");
        if (hex)
            sc_printf(sc, level, "%02X ", *array++);
        else
            sc_printf(sc, level, "%4d ", *array++);
    }
    sc_printf(sc, level, "\n");
}

void sc_print_1d_uint16(safecrypto_t *sc, sc_debug_level_e level, const char *label,
    const UINT16 *array, SINT32 len, SINT32 hex)
{
    SINT32 i = 0;
    if (NULL == sc || NULL == array) {
        return;
    }
    sc_printf(sc, level, "\n%s", label);
    for (i=0; i<len; i++) {
        if ((i&0x07) == 0) sc_printf(sc, level, "\n  ");
        if (hex)
            sc_printf(sc, level, "%04X ", *array++);
        else
            sc_printf(sc, level, "%6d ", *array++);
    }
    sc_printf(sc, level, "\n");
}

void sc_print_1d_uint32(safecrypto_t *sc, sc_debug_level_e level, const char *label,
    const UINT32 *array, SINT32 len, SINT32 hex)
{
    SINT32 i = 0;
    if (NULL == sc || NULL == array) {
        return;
    }
    sc_printf(sc, level, "\n%s", label);
    for (i=0; i<len; i++) {
        if ((i&0x07) == 0) sc_printf(sc, level, "\n  ");
        if (hex)
            sc_printf(sc, level, "%08lX ", *array++);
        else
            sc_printf(sc, level, "%8d ", *array++);
    }
    sc_printf(sc, level, "\n");
}

void sc_print_1d_uint64(safecrypto_t *sc, sc_debug_level_e level, const char *label,
    const UINT64 *array, SINT32 len, SINT32 hex)
{
    SINT32 i = 0;
    if (NULL == sc || NULL == array) {
        return;
    }
    sc_printf(sc, level, "\n%s", label);
    for (i=0; i<len; i++) {
        if ((i&0x03) == 0) sc_printf(sc, level, "\n  ");
        if (hex)
            sc_printf(sc, level, "%016llX ", *array++);
        else
            sc_printf(sc, level, "%12d ", *array++);
    }
    sc_printf(sc, level, "\n");
}

void sc_print_1d_int8(safecrypto_t *sc, sc_debug_level_e level, const char *label,
    const SINT8 *array, SINT32 len, SINT32 hex)
{
    SINT32 i = 0;
    if (NULL == sc || NULL == array) {
        return;
    }
    sc_printf(sc, level, "\n%s", label);
    for (i=0; i<len; i++) {
        if ((i&0x0F) == 0) sc_printf(sc, level, "\n  ");
        if (hex)
            sc_printf(sc, level, "%02X ", *array++);
        else
            sc_printf(sc, level, "%4d ", *array++);
    }
    sc_printf(sc, level, "\n");
}

void sc_print_1d_int16(safecrypto_t *sc, sc_debug_level_e level, const char *label,
    const SINT16 *array, SINT32 len, SINT32 hex)
{
    SINT32 i = 0;
    if (NULL == sc || NULL == array) {
        return;
    }
    sc_printf(sc, level, "\n%s", label);
    for (i=0; i<len; i++) {
        if ((i&0x07) == 0) sc_printf(sc, level, "\n  ");
        if (hex)
            sc_printf(sc, level, "%04X ", *array++);
        else
            sc_printf(sc, level, "%6d ", *array++);
    }
    sc_printf(sc, level, "\n");
}

void sc_print_1d_int32(safecrypto_t *sc, sc_debug_level_e level, const char *label,
    const SINT32 *array, SINT32 len, SINT32 hex)
{
    SINT32 i = 0;
    if (NULL == sc || NULL == array) {
        return;
    }
    sc_printf(sc, level, "\n%s", label);
    for (i=0; i<len; i++) {
        if ((i&0x07) == 0) sc_printf(sc, level, "\n  ");
        if (hex)
            sc_printf(sc, level, "%08lX ", *array++);
        else
            sc_printf(sc, level, "%8d ", *array++);
    }
    sc_printf(sc, level, "\n");
}

void sc_print_1d_int64(safecrypto_t *sc, sc_debug_level_e level, const char *label,
    const SINT64 *array, SINT32 len, SINT32 hex)
{
    SINT32 i = 0;
    if (NULL == sc || NULL == array) {
        return;
    }
    sc_printf(sc, level, "\n%s", label);
    for (i=0; i<len; i++) {
        if ((i&0x03) == 0) sc_printf(sc, level, "\n  ");
        if (hex)
            sc_printf(sc, level, "%016llX ", *array++);
        else
            sc_printf(sc, level, "%12d ", *array++);
    }
    sc_printf(sc, level, "\n");
}

void sc_print_1d_float(safecrypto_t *sc, sc_debug_level_e level, const char *label,
    const FLOAT *array, SINT32 len)
{
    SINT32 i = 0;
    if (NULL == sc || NULL == array) {
        return;
    }
    sc_printf(sc, level, "\n%s", label);
    for (i=0; i<len; i++) {
        if ((i&0x07) == 0) sc_printf(sc, level, "\n  ");
        sc_printf(sc, level, "%7.2f ", *array++);
    }
    sc_printf(sc, level, "\n");
}

void sc_print_1d_double(safecrypto_t *sc, sc_debug_level_e level, const char *label,
    const DOUBLE *array, SINT32 len)
{
    SINT32 i = 0;
    if (NULL == sc || NULL == array) {
        return;
    }
    sc_printf(sc, level, "\n%s", label);
    for (i=0; i<len; i++) {
        if ((i&0x03) == 0) sc_printf(sc, level, "\n  ");
        sc_printf(sc, level, "%7.10f ", *array++);
    }
    sc_printf(sc, level, "\n");
}

void sc_print_1d_long_double(safecrypto_t *sc, sc_debug_level_e level, const char *label,
    const LONGDOUBLE *array, SINT32 len)
{
    SINT32 i = 0;
    if (NULL == sc || NULL == array) {
        return;
    }
    sc_printf(sc, level, "\n%s", label);
    for (i=0; i<len; i++) {
        if ((i&0x03) == 0) sc_printf(sc, level, "\n  ");
        sc_printf(sc, level, "%7.10Le ", *array++);
    }
    sc_printf(sc, level, "\n");
}

#endif

