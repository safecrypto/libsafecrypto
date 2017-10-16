/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2017                      *
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

#ifndef ENABLE_BAREMETAL

#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#include "safecrypto.h"


/// @name Helper functions for basic profiling of code
/**@{*/
extern void* sc_timer_create(void);
extern void sc_timer_delete(void **t);
extern void sc_timer_reset(void *t);
extern void sc_timer_start(void *t);
extern void sc_timer_stop(void *t);
extern double sc_timer_get_elapsed(void *t);
extern time_t sc_timer_diff_secs(void *t);
extern long sc_timer_diff_nsec(void *t);
extern void sc_timer_print_diff_string(void *t, const char *m);
/**@}*/

#endif
