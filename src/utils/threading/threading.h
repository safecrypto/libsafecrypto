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

#pragma once

#if !defined(_WIN32) && (defined(__unix__) || defined(__unix) || (defined(__APPLE__) && defined(__MACH__)))
#include <sched.h>
#include <unistd.h>
#if defined(_POSIX_VERSION)
#include <pthread.h>
#include <semaphore.h>
#define SAFECRYPTO_POSIX
#endif
#else
#include <windows.h>
#define SAFECRYPTO_WINDOWS
#endif


/// A type definition for a cross-platform mutex
SC_STRUCT_PACK_START
typedef struct _sc_mutex {
#ifdef SAFECRYPTO_POSIX
    pthread_mutex_t m;
#else // SAFECRYPTO_WINDOWS
    HANDLE m;
#endif
} SC_STRUCT_PACKED sc_mutex_t;
SC_STRUCT_PACK_END

/// A type definition for a cross-platform mutex
SC_STRUCT_PACK_START
typedef struct _sc_sem {
#ifdef SAFECRYPTO_POSIX
    sem_t s;
#else // SAFECRYPTO_WINDOWS
#endif
} SC_STRUCT_PACKED sc_sem_t;
SC_STRUCT_PACK_END

/// A type definition for a cross-platform condition variable
SC_STRUCT_PACK_START
typedef struct sc_cond_t {
#ifdef SAFECRYPTO_POSIX
    pthread_cond_t c;
#else
#endif
} SC_STRUCT_PACKED sc_cond_t;
SC_STRUCT_PACK_END

/// An enumerated type for threadpool commands
typedef enum {
    THREAD_EXIT_NONE = 0,
    THREAD_EXIT_FORCEFULLY,
    THREAD_EXIT_GRACEFULLY,
} sc_thread_exit_e;

/// A type definition for cross-platform threads
SC_STRUCT_PACK_START
typedef struct sc_thread_t {
    sc_cond_t *notify;
#ifdef SAFECRYPTO_POSIX
    pthread_t *thread;
#else
#endif
    sc_thread_exit_e shutdown;
} SC_STRUCT_PACKED sc_thread_t;
SC_STRUCT_PACK_END


/** @name A cross-platform mutex
 *  Functions used to provide mutex guards.
 */
/**@{*/
typedef sc_mutex_t * (*utils_mutex_create)(void);
typedef void (*utils_mutex_destroy)(sc_mutex_t **);
typedef SINT32 (*utils_mutex_trylock)(sc_mutex_t *);
typedef SINT32 (*utils_mutex_lock)(sc_mutex_t *);
typedef SINT32 (*utils_mutex_unlock)(sc_mutex_t *);
/**@}*/

/** @name A cross-platform semaphore
 *  Functions used to provide mutex guards.
 */
/**@{*/
typedef sc_sem_t * (*utils_sem_create)(UINT32);
typedef void (*utils_sem_destroy)(sc_sem_t **);
typedef SINT32 (*utils_sem_trywait)(sc_sem_t *);
typedef SINT32 (*utils_sem_wait)(sc_sem_t *);
typedef SINT32 (*utils_sem_post)(sc_sem_t *);
/**@}*/

/** @name A cross-platform condition variable
 *  Functions used to provide condition variables.
 */
/**@{*/
typedef sc_cond_t * (*utils_cond_create)(void);
typedef void (*utils_cond_destroy)(sc_cond_t **);
typedef SINT32 (*utils_cond_signal)(sc_cond_t *);
typedef SINT32 (*utils_cond_broadcast)(sc_cond_t *);
typedef SINT32 (*utils_cond_wait)(sc_cond_t *, sc_mutex_t *);
/**@}*/

/** @name Cross-platform threading functions
 *  Functions used to provide threads.
 */
/**@{*/
typedef sc_thread_t * (*utils_thread_create)(void * (*)(void *),
    void *, SINT32);
typedef void (*utils_thread_destroy)(sc_thread_t **);
typedef SINT32 (*utils_thread_join)(sc_thread_t *);
typedef SINT32 (*utils_thread_exit)(void);
/**@}*/

/// A structure used to store function pointers for cross-platform
/// threading functionality.
typedef struct _utils_threading {
    utils_mutex_create       mtx_create;
    utils_mutex_destroy      mtx_destroy;
    utils_mutex_trylock      mtx_trylock;
    utils_mutex_lock         mtx_lock;
    utils_mutex_unlock       mtx_unlock;

    utils_sem_create         sem_create;
    utils_sem_destroy        sem_destroy;
    utils_sem_trywait        sem_trywait;
    utils_sem_wait           sem_wait;
    utils_sem_post           sem_post;

    utils_cond_create        cond_create;
    utils_cond_destroy       cond_destroy;
    utils_cond_signal        cond_signal;
    utils_cond_broadcast     cond_broadcast;
    utils_cond_wait          cond_wait;

    utils_thread_create      thread_create;
    utils_thread_destroy     thread_destroy;
    utils_thread_join        thread_join;
    utils_thread_exit        thread_exit;
} utils_threading_t;


extern const utils_threading_t * utils_threading(void);

