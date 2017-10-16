/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2017                      *
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

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#ifndef ENABLE_BAREMETAL

typedef struct _sc_timer {
    struct timespec start;
    struct timespec stop;
    double elapsed;
} sc_timer_t;


struct timespec diff(struct timespec start, struct timespec end)
{
    struct timespec temp;
    if ((end.tv_nsec-start.tv_nsec)<0) {
        temp.tv_sec = end.tv_sec-start.tv_sec-1;
        temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
    }
    else {
        temp.tv_sec = end.tv_sec-start.tv_sec;
        temp.tv_nsec = end.tv_nsec-start.tv_nsec;
    }
    return temp;
}

void* sc_timer_create(void)
{
    sc_timer_t *timer = SC_MALLOC(sizeof(sc_timer_t));
    return (void *) timer;
}

void sc_timer_delete(void **t)
{
    SC_FREE(*t, sizeof(sc_timer_t));
}

void sc_timer_reset(void *t)
{
    sc_timer_t *timer = (sc_timer_t *) t;
    timer->elapsed = 0;
}

void sc_timer_start(void *t)
{
    sc_timer_t *timer = (sc_timer_t *) t;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &timer->start);
}

void sc_timer_stop(void *t)
{
    sc_timer_t *timer = (sc_timer_t *) t;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &timer->stop);
    timer->elapsed += (double)(timer->stop.tv_sec - timer->start.tv_sec) * 1.0e9 +
              (double)(timer->stop.tv_nsec - timer->start.tv_nsec);
}

double sc_timer_get_elapsed(void *t)
{
    sc_timer_t *timer = (sc_timer_t *) t;
    return timer->elapsed / 1.0e9;
}

time_t sc_timer_diff_secs(void *t)
{
    sc_timer_t *timer = (sc_timer_t *) t;
    return diff(timer->start, timer->stop).tv_sec;
}

long sc_timer_diff_nsec(void *t)
{
    sc_timer_t *timer = (sc_timer_t *) t;
    return diff(timer->start, timer->stop).tv_nsec;
}

void sc_timer_print_diff_string(void *t, const char *m)
{
    time_t secs = sc_timer_diff_secs(t);
    long nsec = sc_timer_diff_nsec(t);
    printf("%s %ld.%09ld\n", m, secs, nsec);
}

#endif
