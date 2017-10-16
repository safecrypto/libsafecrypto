/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include <stdlib.h>
#include <check.h>
#include "safecrypto.h"
#include "safecrypto_private.h"
#include "safecrypto_version.h"
//#include "utils/threading/threading.c"
#include "utils/threading/threadpool.c"

START_TEST(test_threadpool_create_min)
{
    sc_threadpool_t* sc_threadpool = NULL;

    sc_threadpool = threadpool_create(0, 0);
    ck_assert_ptr_eq(sc_threadpool, NULL);

    sc_threadpool = threadpool_create(1, 0);
    ck_assert_ptr_eq(sc_threadpool, NULL);

    sc_threadpool = threadpool_create(0, 1);
    ck_assert_ptr_eq(sc_threadpool, NULL);
}
END_TEST

START_TEST(test_threadpool_create_max)
{
    sc_threadpool_t* sc_threadpool = NULL;

    sc_threadpool = threadpool_create(MAX_THREADS+1, MAX_QUEUE+1);
    ck_assert_ptr_eq(sc_threadpool, NULL);

    sc_threadpool = threadpool_create(MAX_THREADS+1, MAX_QUEUE);
    ck_assert_ptr_eq(sc_threadpool, NULL);

    sc_threadpool = threadpool_create(MAX_THREADS, MAX_QUEUE+1);
    ck_assert_ptr_eq(sc_threadpool, NULL);
}
END_TEST

START_TEST(test_threadpool_create)
{
    int32_t retcode;
    sc_threadpool_t* sc_threadpool = NULL;

    sc_threadpool = threadpool_create(MAX_THREADS, MAX_QUEUE);
    ck_assert_ptr_ne(sc_threadpool, NULL);

    retcode = threadpool_destroy(sc_threadpool, THREADPOOL_GRACEFUL_EXIT);
    ck_assert_int_eq(retcode, SC_OK);
}
END_TEST

START_TEST(test_threadpool_destroy)
{
    int32_t retcode;
    sc_threadpool_t* sc_threadpool = NULL;

    retcode = threadpool_destroy(sc_threadpool, THREADPOOL_GRACEFUL_EXIT);
    ck_assert_int_eq(retcode, SC_NULL_POINTER);

    sc_threadpool = threadpool_create(MAX_THREADS, MAX_QUEUE);
    ck_assert_ptr_ne(sc_threadpool, NULL);

    retcode = threadpool_destroy(sc_threadpool, THREADPOOL_GRACEFUL_EXIT);
    ck_assert_int_eq(retcode, SC_OK);
}
END_TEST

#define ARRAY_TEST_SIZE     16384
static int32_t array[ARRAY_TEST_SIZE] = {0};

typedef struct _add_args
{
    sc_mutex_t *lock;
    int32_t *data;
    int32_t start;
    int32_t end;
} add_args_t;

void * add_function(void *args)
{
    int32_t i;
    add_args_t *add_args = (add_args_t *) args;

    utils_threading()->mtx_lock(add_args->lock);

    for (i=add_args->start; i<add_args->end; i++) {
        add_args->data[i] = i;
    }

    utils_threading()->mtx_unlock(add_args->lock);

    struct timespec delay = {0, 100000000};
    nanosleep(&delay, NULL);

    return NULL;
}

START_TEST(test_threadpool_sum)
{
    int32_t i;
    sc_threadpool_t* sc_threadpool = NULL;

    sc_threadpool = threadpool_create(MAX_THREADS, MAX_QUEUE);
    ck_assert_ptr_ne(sc_threadpool, NULL);

    sc_mutex_t *func_lock = utils_threading()->mtx_create();

    add_args_t args[MAX_THREADS];
    for (i=0; i<MAX_THREADS; i++) {
        args[i].lock  = func_lock;
        args[i].data  = array;
        args[i].start = i * (ARRAY_TEST_SIZE / MAX_THREADS);
        args[i].end   = (i + 1) * (ARRAY_TEST_SIZE / MAX_THREADS);

        int32_t retcode = threadpool_add(sc_threadpool, add_function, &args[i]);
        ck_assert_int_eq(retcode, SC_OK);
    }

    struct timespec delay = {1, 0};
    while (SC_OK != threadpool_destroy(sc_threadpool, THREADPOOL_GRACEFUL_EXIT)) {
        // Wait for 1 second before destroying
        nanosleep(&delay, NULL);
    }

    utils_threading()->mtx_lock(func_lock);
    utils_threading()->mtx_destroy(&func_lock);

    // Check the contents of the array to ensure that the worker threads have executed correctly
    for (i=0; i<ARRAY_TEST_SIZE; i++) {
        ck_assert_int_eq(array[i], i);
    }

}
END_TEST

Suite *threadpool_suite(void)
{
    Suite *s;
    TCase *tc_core, *tc_operate;

    s = suite_create("threadpool");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_threadpool_create_min);
    tcase_add_test(tc_core, test_threadpool_create_max);
    tcase_add_test(tc_core, test_threadpool_create);
    tcase_add_test(tc_core, test_threadpool_destroy);
    suite_add_tcase(s, tc_core);

    tc_operate = tcase_create("OPERATION");
    tcase_add_test(tc_operate, test_threadpool_sum);
    suite_add_tcase(s, tc_operate);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = threadpool_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


