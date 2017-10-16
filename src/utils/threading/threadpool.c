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

#include "safecrypto_private.h"
#include "threadpool.h"


//--------------------------- PRIVATE FUNCTIONS -----------------------------//

static void * threadpool_thread(void *threadpool)
{
    sc_threadpool_t *pool = (sc_threadpool_t *) threadpool;
    sc_threadpool_task_t task;
    SINT32 task_complete = 0;

    while (1) {
    	/*struct sched_param param;
    	int policy;
    	pthread_t tid = pthread_self();
    	pthread_getschedparam(tid, &policy, &param);
    	policy = SCHED_OTHER;
    	pthread_setschedparam(tid, policy, &param);*/

    	utils_threading()->mtx_lock(pool->lock);

    	if (task_complete) {
    		task_complete = 0;
    		pool->task_count--;
    		utils_threading()->cond_signal(pool->wait);
    	}

        // Check for spurious wakeups
        while ((0 == pool->queue_count) && !pool->shutdown) {
            utils_threading()->cond_wait(pool->notify, pool->lock);
        }

        // Check for a forced or graceful exit command
        if ((pool->shutdown == THREAD_EXIT_FORCEFULLY) ||
            ((pool->shutdown == THREAD_EXIT_GRACEFULLY) && (pool->queue_count == 0))) {
            break;
        }

    	/*policy = SCHED_RR;
    	pthread_setschedparam(tid, policy, &param);*/

        // Grab our task, advance the head pointer and decrement the number
        // of buffered tasks for the worker threads
        task.routine  = pool->queue[pool->head].routine;
        task.argument = pool->queue[pool->head].argument;
        pool->head    = (pool->head + 1) % pool->queue_size;
        pool->queue_count--;

        utils_threading()->mtx_unlock(pool->lock);
        utils_threading()->cond_signal(pool->notify);

        // Execute the given task
        (*(task.routine))(task.argument);
        task_complete = 1;
    }

    pool->started--;

    utils_threading()->mtx_unlock(pool->lock);
    utils_threading()->cond_signal(pool->wait);
    utils_threading()->thread_exit();
    return(NULL);
}


//---------------------------- PUBLIC FUNCTIONS -----------------------------//

SINT32 threadpool_free(sc_threadpool_t *pool)
{
    size_t i;

    if (pool == NULL || pool->started > 0) {
        return SC_FUNC_FAILURE;
    }

    if (pool->threads) {
        for (i=0; i<(size_t)pool->thread_count; i++) {
            utils_threading()->thread_destroy(&pool->threads[i]);
        }
        SC_FREE(pool->threads, sizeof(sc_thread_t*) * pool->thread_count);
        SC_FREE(pool->queue, sizeof(sc_threadpool_task_t) * pool->queue_size);
 
 		utils_threading()->mtx_lock(pool->lock);
 		utils_threading()->mtx_destroy(&pool->lock);
        utils_threading()->cond_destroy(&pool->notify);
        utils_threading()->mtx_lock(pool->wait_lock);
        utils_threading()->mtx_destroy(&pool->wait_lock);
        utils_threading()->cond_destroy(&pool->wait);
    }
    SC_FREE(pool, sizeof(sc_threadpool_t));    
    return SC_FUNC_SUCCESS;
}

sc_threadpool_t *threadpool_create(SINT32 thread_count, SINT32 queue_size)
{
	if (thread_count <= 0          ||
        thread_count > MAX_THREADS ||
		queue_size <= 0            ||
        queue_size > MAX_QUEUE) {
        return NULL;
    }
    
    SINT32 i, j;

    sc_threadpool_t *pool = SC_MALLOC(sizeof(sc_threadpool_t));
    if (NULL == pool) {
        goto creation_error;
    }
    pool->threads = SC_MALLOC(sizeof(sc_thread_t*) * thread_count);
    if (NULL == pool->threads) {
        goto creation_error;
    }
    pool->queue = SC_MALLOC(sizeof(sc_threadpool_task_t) * queue_size);
    if (NULL == pool->queue) {
        goto creation_error;
    }

    pool->thread_count = 0;
    pool->task_count   = 0;
    pool->queue_size   = queue_size;
    pool->head         = 0;
    pool->tail         = 0;
    pool->queue_count  = 0;
    pool->shutdown     = THREAD_EXIT_NONE;
    pool->started      = 0;

    // Initialize mutex and conditional variable
    pool->lock      = utils_threading()->mtx_create();
    pool->notify    = utils_threading()->cond_create();
    pool->wait_lock = utils_threading()->mtx_create();
    pool->wait      = utils_threading()->cond_create();
    if ((NULL == pool->lock)      ||
        (NULL == pool->notify)    ||
        (NULL == pool->wait_lock) ||
        (NULL == pool->wait)      ||
        (NULL == pool->threads)   ||
        (NULL == pool->queue)) {
        goto creation_error;
    }

    // Start worker threads, pinning them to the available processors
    // in a wrapped round-robin fashion
    SINT32 num_cpu = sysconf(_SC_NPROCESSORS_ONLN);
    for (i = 0, j=thread_count>>1; i < thread_count; i++, j++) {
        pool->threads[i] = utils_threading()->thread_create(
            threadpool_thread, (void*) pool, j % num_cpu);
        if (NULL == pool->threads[i]) {
        	// If any worker thread cannot be created then exit gracefully
            threadpool_destroy(pool, THREADPOOL_GRACEFUL_EXIT);
            return NULL;
        }
        pool->thread_count++;
        pool->started++;
    }

    return pool;

 creation_error:
    if (pool) {
        threadpool_free(pool);
    }
    return NULL;
}

SINT32 threadpool_destroy(sc_threadpool_t *pool, UINT32 flags)
{
	SINT32 i;
	SINT32 err = SC_OK;

    if (pool == NULL) {
        return SC_NULL_POINTER;
    }

    if (SC_OK != utils_threading()->mtx_lock(pool->lock)) {
        return SC_FAILED_LOCK;
    }

    // Already shutting down so return with an error
    if (pool->shutdown) {
        err = SC_THREAD_EXITING;
        goto destroy_error;
    }

    pool->shutdown = (flags & THREADPOOL_GRACEFUL_EXIT) ?
        THREAD_EXIT_GRACEFULLY : THREAD_EXIT_FORCEFULLY;

    // Wake up all worker threads
    if (SC_OK != (utils_threading()->cond_broadcast(pool->notify)) ||
        SC_OK != utils_threading()->mtx_unlock(pool->lock)) {
        err = SC_FAILED_LOCK;
        goto destroy_error;
    }

    // Join all worker thread
    for (i = 0; i < pool->thread_count; i++) {
        if (SC_OK != utils_threading()->thread_join(pool->threads[i])) {
            err = SC_THREAD_ERROR;
        }
    }

destroy_error:
    // Only if everything went well do we deallocate the pool
    if (!err) {
        threadpool_free(pool);
    }
    return err;
}

SINT32 threadpool_wait(sc_threadpool_t *pool)
{
	if (pool == NULL) {
        return SC_NULL_POINTER;
    }

    if (SC_OK != utils_threading()->mtx_lock(pool->wait_lock)) {
        return SC_FAILED_LOCK;
    }

    // If the worker threads are operating wait until no tasks are running
    // and the queue is empty
    if (0 != pool->started) {
        while (0 != pool->task_count || 0 != pool->queue_count) {
            utils_threading()->cond_wait(pool->wait, pool->wait_lock);
        }
    }

    if (SC_OK != utils_threading()->mtx_unlock(pool->wait_lock)) {
        return SC_FAILED_LOCK;
    }

    return SC_OK;
}

SINT32 threadpool_add(sc_threadpool_t *pool, task routine, void *argument)
{
	SINT32 err = SC_OK;
    SINT32 next;

    if (pool == NULL || routine == NULL) {
        return SC_NULL_POINTER;
    }

    if (SC_OK != utils_threading()->mtx_lock(pool->lock)) {
        return SC_FAILED_LOCK;
    }

    // The next queue element to be buffered is indexed by the tail
    // plus 1 and wraps around the defined queue size
    next = (pool->tail + 1) % pool->queue_size;

    // If we have no available buffers then return from this function
    if (pool->queue_count == pool->queue_size) {
        err = SC_QUEUE_FULL;
        goto add_error;
    }

    // If we're in the process of shutting down then return from this function
    if (pool->shutdown) {
        err = SC_THREAD_EXITING;
        goto add_error;
    }

    // Add task to queue, set the tail end of the queue and increment the number
    // of queued tasks for the worker threads
    pool->queue[pool->tail].routine = routine;
    pool->queue[pool->tail].argument = argument;
    pool->tail = next;
    pool->queue_count++;
    pool->task_count++;

    // Signal the condition change to at least one blocked thread
    if (SC_OK != utils_threading()->cond_signal(pool->notify)) {
        err = SC_FAILED_LOCK;
    }

add_error:
    if (SC_OK != utils_threading()->mtx_unlock(pool->lock)) {
        return SC_FAILED_LOCK;
    }

    return err;
}

