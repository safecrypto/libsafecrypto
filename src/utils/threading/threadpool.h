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

#include "safecrypto_types.h"
#include "threading.h"

#if !defined(_WIN32) && (defined(__unix__) || defined(__unix) || (defined(__APPLE__) && defined(__MACH__)))
/* UNIX-style OS. ------------------------------------------- */
#include <unistd.h>
#if defined(_POSIX_VERSION)
/* POSIX compliant */
#include <pthread.h>
#define SAFECRYPTO_POSIX
#endif
#else
#include <windows.h>
#define SAFECRYPTO_WINDOWS
#endif


/// The maximum number of threads permitted in a threadpool
#define MAX_THREADS 32

/// The maximum number of tasks queued for execution by the threadpool
#define MAX_QUEUE 128

/// The command used to instruct the threadpool to shut down gracefully
#define THREADPOOL_GRACEFUL_EXIT   0x00000001

/// The command used to instruct the threadpool to shut down forcefully
#define THREADPOOL_FORCEFUL_EXIT   0x00000002

/// A function pointer for a task routine
typedef void * (*task)(void *);

/// A type definition a threadpool task
SC_STRUCT_PACK_START
typedef struct sc_threadpool_task_t {
    task routine;
    void *argument;
} SC_STRUCT_PACKED sc_threadpool_task_t;
SC_STRUCT_PACK_END

/// A type definition for a struct containing all of the
/// threadpool parameters
SC_STRUCT_PACK_START
typedef struct sc_threadpool_t {
	sc_mutex_t *lock;
    sc_cond_t *notify;
    sc_mutex_t *wait_lock;
    sc_cond_t *wait;
    sc_thread_t **threads;
    sc_threadpool_task_t *queue;
    SINT32 thread_count;
    SINT32 task_count;
    SINT32 queue_size;
    SINT32 queue_count;
    SINT32 head;
    SINT32 tail;
    sc_thread_exit_e shutdown;
    SINT32 started;
} SC_STRUCT_PACKED sc_threadpool_t;
SC_STRUCT_PACK_END


/** @name A threadpool
 *  Functions used to provide a threadpool for worker threads to execute tasks.
 */
/**@{*/
sc_threadpool_t * threadpool_create(SINT32 thread_count,  SINT32 queue_size);
SINT32 threadpool_destroy(sc_threadpool_t *pool, UINT32 flags);
SINT32 threadpool_wait(sc_threadpool_t *pool);
SINT32 threadpool_add(sc_threadpool_t *pool, task routine, void *argument);
/**@}*/

