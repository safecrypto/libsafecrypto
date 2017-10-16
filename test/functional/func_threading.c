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

#include <stdlib.h>
#include "safecrypto.h"
#include "safecrypto_debug.h"
#include "utils/threading/pipe.h"
#ifdef HAVE_MULTITHREADING
#include "utils/threading/threading.h"
#include "utils/threading/threadpool.h"
#endif

#include <string.h>
#include <math.h>


#define NUM_ITER      1073741824


void show_progress(char *msg, int32_t count, int32_t max)
{
    int i;
    int barWidth = 42;
    double progress = (double) count / max;

    printf("%-40s [", msg);
    int pos = barWidth * progress;
    for (i = 0; i < barWidth; ++i) {
        if (i < pos) printf("=");
        else if (i == pos) printf(">");
        else printf(" ");
    }
    printf("] %4d/%4d (%3d %%)\r", count, max, (int)(progress * 100.0f));
    if (count == max) printf("\n");
    fflush(stdout);
}

typedef struct producer_thd_t {
    UINT32 b;
    UINT32 s;
    pipe_producer_t *p;
} producer_thd_t;

typedef struct consumer_thd_t {
    UINT32 b;
    UINT32 s;
    pipe_consumer_t *c;
} consumer_thd_t;

void * producer_func(void *p)
{
    size_t i;
    const utils_threading_t *threading = utils_threading();
    producer_thd_t *t = (producer_thd_t*) p;
    pipe_producer_t *pipe = t->p;

    UINT32 elems[1024];
    for (i=0; i<t->b; i++) {
        elems[i] = i;
    }

    for (i=0; i<NUM_ITER/t->b; i++) {
        if (SC_FUNC_FAILURE == pipe_push(pipe, elems, t->b)) {
            break;
        }
    }

    threading->thread_exit();

    return NULL;
}

void * producer_worker(void *p)
{
    size_t i;
    producer_thd_t *t = (producer_thd_t*) p;
    pipe_producer_t *pipe = t->p;

    UINT32 elems[1024];
    for (i=0; i<t->b; i++) {
        elems[i] = i;
    }

    for (i=0; i<t->s/t->b; i++) {
        if (SC_FUNC_FAILURE == pipe_push(pipe, elems, t->b)) {
            break;
        }
    }

    return NULL;
}

void * consumer_worker(void *p)
{
    size_t i;
    consumer_thd_t *t = (consumer_thd_t*) p;
    pipe_consumer_t *pipe = t->c;

    UINT32 elems[1024];

    for (i=0; i<t->s/t->b; i++) {
        if (SC_FUNC_FAILURE == pipe_pull(pipe, elems, t->b)) {
            break;
        }
    }

    return NULL;
}

int main(void)
{
#ifdef HAVE_MULTITHREADING
    SC_TIMER_INSTANCE(thread_timer);
    SC_TIMER_CREATE(thread_timer);

    char msg[40];
    size_t i, k;
    pipe_t *pipe = NULL;

    //-----------------------------------------------------------------------//
    SC_TIMER_RESET(thread_timer);
    strcpy(msg, "Test 1 - Pipe Only");

    {
        size_t b = 256;

        // Create a pipe
        pipe = pipe_create(sizeof(UINT32), 0);
        if (NULL == pipe) {
            return EXIT_FAILURE;
        }
        pipe_producer_t *p = pipe_producer_create(pipe);
        pipe_consumer_t *c = pipe_consumer_create(pipe);
        if (NULL == p || NULL == c) {
            return EXIT_FAILURE;
        }
    
        UINT32 elems[1024], out[1024];
        for (i=0; i<b; i++) {
            elems[i] = i;
        }
    
        SC_TIMER_START(thread_timer);
        for (k=0; k<NUM_ITER/b; k++) {
            if (SC_FUNC_FAILURE == pipe_push(p, elems, b)) {
                return EXIT_FAILURE;
            }
            if (SC_FUNC_FAILURE == pipe_pull(c, out, b)) {
                return EXIT_FAILURE;
            }
            if ((k & 0x1FFF) == 0x1FFF) show_progress(msg, b*k, NUM_ITER);
        }
        SC_TIMER_STOP(thread_timer);
    
        // Destroy the pipe
        pipe_destroy(pipe);
        pipe_producer_destroy(p);
        pipe_consumer_destroy(c);
    
        show_progress(msg, NUM_ITER, NUM_ITER);
        double elapsed = SC_TIMER_GET_ELAPSED(thread_timer);
        printf("Elapsed time: %f\n", elapsed);
    }


    //-----------------------------------------------------------------------//
    SC_TIMER_RESET(thread_timer);
    strcpy(msg, "Test 2 - Pipe from a Thread");

    {
        size_t b = 256;

        // Create a pipe
        pipe = pipe_create(sizeof(UINT32), 8192);
        if (NULL == pipe) {
            return EXIT_FAILURE;
        }
        pipe_producer_t *p = pipe_producer_create(pipe);
        pipe_consumer_t *c = pipe_consumer_create(pipe);
        if (NULL == p || NULL == c) {
            return EXIT_FAILURE;
        }

        SINT32 num_cpu = sysconf(_SC_NPROCESSORS_ONLN);
    
        // Create a thread used to produce data
        const utils_threading_t *threading = utils_threading();
        producer_thd_t p_thd;
        p_thd.b = b;
        p_thd.p = p;
        sc_thread_t *thd = threading->thread_create(
            producer_func, (void*)&p_thd, num_cpu-1);
    
        UINT32 out[1024];
    
        SC_TIMER_START(thread_timer);
        for (k=0; k<NUM_ITER/b; k++) {
            if (SC_FUNC_FAILURE == pipe_pull(c, out, b)) {
                return EXIT_FAILURE;
            }
            if ((k & 0x1FFF) == 0x1FFF) show_progress(msg, b*k, NUM_ITER);
        }
        SC_TIMER_STOP(thread_timer);
    
        threading->thread_join(thd);
        threading->thread_destroy(&thd);
    
        // Destroy the pipe
        pipe_destroy(pipe);
        pipe_producer_destroy(p);
        pipe_consumer_destroy(c);
    
        show_progress(msg, NUM_ITER, NUM_ITER);
        double elapsed = SC_TIMER_GET_ELAPSED(thread_timer);
        printf("Elapsed time: %f\n", elapsed);
    }


    //-----------------------------------------------------------------------//
    SC_TIMER_RESET(thread_timer);
    strcpy(msg, "Test 3 - Pipe from pool, 1 producer");

    {
        size_t b = 256;

        // Create a pipe
        pipe = pipe_create(sizeof(UINT32), 8192);
        if (NULL == pipe) {
            return EXIT_FAILURE;
        }
        pipe_producer_t *p = pipe_producer_create(pipe);
        pipe_consumer_t *c = pipe_consumer_create(pipe);
        if (NULL == p || NULL == c) {
            return EXIT_FAILURE;
        }
    
        // Create a thread used to produce data
        producer_thd_t p_thd;
        p_thd.b = b;
        p_thd.s = NUM_ITER;
        p_thd.p = p;
        //sc_thread_t *thd = threading->thread_create(producer_func, (void*)&p_thd);
        sc_threadpool_t *pool = threadpool_create(1, 8);
        threadpool_add(pool, producer_worker, (void*)&p_thd);
    
        UINT32 out[1024];
    
        SC_TIMER_START(thread_timer);
        for (k=0; k<NUM_ITER/b; k++) {
            if (SC_FUNC_FAILURE == pipe_pull(c, out, b)) {
                return EXIT_FAILURE;
            }
            if ((k & 0x1FFF) == 0x1FFF) show_progress(msg, b*k, NUM_ITER);
        }
        SC_TIMER_STOP(thread_timer);
    
        threadpool_wait(pool);
        threadpool_destroy(pool, THREADPOOL_GRACEFUL_EXIT);
    
        // Destroy the pipe
        pipe_destroy(pipe);
        pipe_producer_destroy(p);
        pipe_consumer_destroy(c);
    
        show_progress(msg, NUM_ITER, NUM_ITER);
        double elapsed = SC_TIMER_GET_ELAPSED(thread_timer);
        printf("Elapsed time: %f\n", elapsed);
    }


    //-----------------------------------------------------------------------//
    SC_TIMER_RESET(thread_timer);
    strcpy(msg, "Test 4 - Pipe from pool, 4 producers");

    {
        size_t b = 256;

        // Create a pipe
        pipe = pipe_create(sizeof(UINT32), 8192);
        if (NULL == pipe) {
            return EXIT_FAILURE;
        }
        pipe_producer_t *p1 = pipe_producer_create(pipe);
        pipe_producer_t *p2 = pipe_producer_create(pipe);
        pipe_producer_t *p3 = pipe_producer_create(pipe);
        pipe_producer_t *p4 = pipe_producer_create(pipe);
        pipe_consumer_t *c = pipe_consumer_create(pipe);
        if (NULL == p1 || NULL == p2 || NULL == p3 || NULL == p4 || NULL == c) {
            return EXIT_FAILURE;
        }
    
        // Create a thread used to produce data
        producer_thd_t p_thd[4];
        p_thd[0].b = b;
        p_thd[0].s = NUM_ITER/4;
        p_thd[0].p = p1;
        p_thd[1].b = b;
        p_thd[1].s = NUM_ITER/4;
        p_thd[1].p = p2;
        p_thd[2].b = b;
        p_thd[2].s = NUM_ITER/4;
        p_thd[2].p = p3;
        p_thd[3].b = b;
        p_thd[3].s = NUM_ITER/4;
        p_thd[3].p = p4;
        //sc_thread_t *thd = threading->thread_create(producer_func, (void*)&p_thd);
        sc_threadpool_t *pool = threadpool_create(4, 8);
        threadpool_add(pool, producer_worker, (void*)&p_thd[0]);
        threadpool_add(pool, producer_worker, (void*)&p_thd[1]);
        threadpool_add(pool, producer_worker, (void*)&p_thd[2]);
        threadpool_add(pool, producer_worker, (void*)&p_thd[3]);
    
        UINT32 out[1024];
    
        SC_TIMER_START(thread_timer);
        for (k=0; k<NUM_ITER/b; k++) {
            if (SC_FUNC_FAILURE == pipe_pull(c, out, b)) {
                return EXIT_FAILURE;
            }
            if ((k & 0x1FFF) == 0x1FFF) show_progress(msg, b*k, NUM_ITER);
        }
        SC_TIMER_STOP(thread_timer);
    
        threadpool_wait(pool);
        threadpool_destroy(pool, THREADPOOL_GRACEFUL_EXIT);
    
        // Destroy the pipe
        pipe_destroy(pipe);
        pipe_producer_destroy(p1);
        pipe_producer_destroy(p2);
        pipe_producer_destroy(p3);
        pipe_producer_destroy(p4);
        pipe_consumer_destroy(c);
    
        show_progress(msg, NUM_ITER, NUM_ITER);
        double elapsed = SC_TIMER_GET_ELAPSED(thread_timer);
        printf("Elapsed time: %f\n", elapsed);
    }


    //-----------------------------------------------------------------------//
    SC_TIMER_RESET(thread_timer);
    strcpy(msg, "Test 5 - Pipe to/from pool, 1 to 1");

    {
        size_t b = 256;

        // Create a pipe
        pipe = pipe_create(sizeof(UINT32), 8192);
        if (NULL == pipe) {
            return EXIT_FAILURE;
        }
        pipe_producer_t *p = pipe_producer_create(pipe);
        pipe_consumer_t *c = pipe_consumer_create(pipe);
        if (NULL == p || NULL == c) {
            return EXIT_FAILURE;
        }
    
        // Create a thread used to produce data
        producer_thd_t p_thd;
        p_thd.b = 4*b;
        p_thd.s = NUM_ITER;
        p_thd.p = p;
        consumer_thd_t c_thd;
        c_thd.b = b;
        c_thd.s = NUM_ITER;
        c_thd.c = c;
        sc_threadpool_t *pool = threadpool_create(2, 8);
        SC_TIMER_START(thread_timer);
        threadpool_add(pool, consumer_worker, (void*)&c_thd);
        threadpool_add(pool, producer_worker, (void*)&p_thd);
        threadpool_wait(pool);
        threadpool_destroy(pool, THREADPOOL_GRACEFUL_EXIT);
        SC_TIMER_STOP(thread_timer);
    
        // Destroy the pipe
        pipe_destroy(pipe);
        pipe_producer_destroy(p);
        pipe_consumer_destroy(c);
    
        show_progress(msg, NUM_ITER, NUM_ITER);
        double elapsed = SC_TIMER_GET_ELAPSED(thread_timer);
        printf("Elapsed time: %f\n", elapsed);
    }


    //-----------------------------------------------------------------------//
    SC_TIMER_RESET(thread_timer);
    strcpy(msg, "Test 6 - Pipe to/from pool, 1 to 2");

    {
        size_t b = 256;

        // Create a pipe
        pipe = pipe_create(sizeof(UINT32), 16384);
        if (NULL == pipe) {
            return EXIT_FAILURE;
        }
        pipe_producer_t *p = pipe_producer_create(pipe);
        pipe_consumer_t *c0 = pipe_consumer_create(pipe);
        pipe_consumer_t *c1 = pipe_consumer_create(pipe);
        if (NULL == p || NULL == c0 || NULL == c1) {
            return EXIT_FAILURE;
        }
    
        // Create a thread used to produce data
        producer_thd_t p_thd;
        p_thd.b = 2*b;
        p_thd.s = NUM_ITER;
        p_thd.p = p;
        consumer_thd_t c_thd[2];
        c_thd[0].b = 4*b;
        c_thd[0].s = NUM_ITER/2;
        c_thd[0].c = c0;
        c_thd[1].b = b;
        c_thd[1].s = NUM_ITER/2;
        c_thd[1].c = c1;
        sc_threadpool_t *pool = threadpool_create(3, 8);
        SC_TIMER_START(thread_timer);
        threadpool_add(pool, consumer_worker, (void*)&c_thd[0]);
        threadpool_add(pool, consumer_worker, (void*)&c_thd[1]);
        threadpool_add(pool, producer_worker, (void*)&p_thd);
        threadpool_wait(pool);
        threadpool_destroy(pool, THREADPOOL_GRACEFUL_EXIT);
        SC_TIMER_STOP(thread_timer);
    
        // Destroy the pipe
        pipe_destroy(pipe);
        pipe_producer_destroy(p);
        pipe_consumer_destroy(c0);
        pipe_consumer_destroy(c1);
    
        show_progress(msg, NUM_ITER, NUM_ITER);
        double elapsed = SC_TIMER_GET_ELAPSED(thread_timer);
        printf("Elapsed time: %f\n", elapsed);
    }


    //-----------------------------------------------------------------------//
    SC_TIMER_RESET(thread_timer);
    strcpy(msg, "Test 7 - Pipe to/from pool, 2 to 2");

    {
        size_t b = 256;

        // Create a pipe
        pipe = pipe_create(sizeof(UINT32), 16384);
        if (NULL == pipe) {
            return EXIT_FAILURE;
        }
        pipe_producer_t *p0 = pipe_producer_create(pipe);
        pipe_producer_t *p1 = pipe_producer_create(pipe);
        pipe_consumer_t *c0 = pipe_consumer_create(pipe);
        pipe_consumer_t *c1 = pipe_consumer_create(pipe);
        if (NULL == p0 || NULL == p1 || NULL == c0 || NULL == c1) {
            return EXIT_FAILURE;
        }
    
        // Create a thread used to produce data
        producer_thd_t p_thd[2];
        p_thd[0].b = 4*b;
        p_thd[0].s = NUM_ITER/2;
        p_thd[0].p = p0;
        p_thd[1].b = b;
        p_thd[1].s = NUM_ITER/2;
        p_thd[1].p = p1;
        consumer_thd_t c_thd[2];
        c_thd[0].b = b;
        c_thd[0].s = NUM_ITER/2;
        c_thd[0].c = c0;
        c_thd[1].b = 3*b;
        c_thd[1].s = NUM_ITER/2;
        c_thd[1].c = c1;
        sc_threadpool_t *pool = threadpool_create(4, 8);
        SC_TIMER_START(thread_timer);
        threadpool_add(pool, consumer_worker, (void*)&c_thd[0]);
        threadpool_add(pool, consumer_worker, (void*)&c_thd[1]);
        threadpool_add(pool, producer_worker, (void*)&p_thd[0]);
        threadpool_add(pool, producer_worker, (void*)&p_thd[1]);
        threadpool_wait(pool);
        threadpool_destroy(pool, THREADPOOL_GRACEFUL_EXIT);
        SC_TIMER_STOP(thread_timer);
    
        // Destroy the pipe
        pipe_destroy(pipe);
        pipe_producer_destroy(p0);
        pipe_producer_destroy(p1);
        pipe_consumer_destroy(c0);
        pipe_consumer_destroy(c1);
    
        show_progress(msg, NUM_ITER, NUM_ITER);
        double elapsed = SC_TIMER_GET_ELAPSED(thread_timer);
        printf("Elapsed time: %f\n", elapsed);
    }


    SC_TIMER_DESTROY(thread_timer);
#endif
    return EXIT_SUCCESS;
}

