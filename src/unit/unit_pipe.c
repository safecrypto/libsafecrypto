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
#include "utils/threading/pipe.c"
#include <math.h>


START_TEST(test_pipe_creation)
{
	pipe_t *pipe = NULL;
	SINT32 retcode;

	retcode = pipe_destroy(pipe);
	ck_assert_int_eq(retcode, SC_FUNC_FAILURE);

	pipe = pipe_create(0, 0);
	ck_assert_ptr_eq(pipe, NULL);

	pipe = pipe_create(sizeof(UINT32), 128);
	ck_assert_ptr_ne(pipe, NULL);

	retcode = pipe_destroy(pipe);
	ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_pipe_creation_producer)
{
	pipe_t *pipe = NULL;
	SINT32 retcode;

	pipe = pipe_create(sizeof(UINT32), 128);
	ck_assert_ptr_ne(pipe, NULL);

	pipe_producer_t *producer = pipe_producer_create(pipe);
	ck_assert_ptr_ne(producer, NULL);

	retcode = pipe_destroy(pipe);
	ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

	retcode = pipe_producer_destroy(producer);
	ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_pipe_creation_consumer)
{
	pipe_t *pipe = NULL;
	SINT32 retcode;

	pipe = pipe_create(sizeof(UINT32), 128);
	ck_assert_ptr_ne(pipe, NULL);

	pipe_consumer_t *consumer = pipe_consumer_create(pipe);
	ck_assert_ptr_ne(consumer, NULL);

	retcode = pipe_destroy(pipe);
	ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

	retcode = pipe_consumer_destroy(consumer);
	ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_pipe_creation_producer_consumer)
{
	pipe_t *pipe = NULL;
	SINT32 retcode;

	pipe = pipe_create(sizeof(UINT32), 128);
	ck_assert_ptr_ne(pipe, NULL);

	pipe_producer_t *producer = pipe_producer_create(pipe);
	ck_assert_ptr_ne(producer, NULL);
	pipe_consumer_t *consumer = pipe_consumer_create(pipe);
	ck_assert_ptr_ne(consumer, NULL);

	retcode = pipe_destroy(pipe);
	ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

	retcode = pipe_consumer_destroy(consumer);
	ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
	retcode = pipe_producer_destroy(producer);
	ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_pipe_transfer)
{
	size_t i;
	pipe_t *pipe = NULL;
	SINT32 retcode;
	size_t retval;

	pipe = pipe_create(sizeof(UINT32), 0);
	ck_assert_ptr_ne(pipe, NULL);

	pipe_producer_t *producer = pipe_producer_create(pipe);
	ck_assert_ptr_ne(producer, NULL);
	pipe_consumer_t *consumer = pipe_consumer_create(pipe);
	ck_assert_ptr_ne(consumer, NULL);

	retcode = pipe_destroy(pipe);
	ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

	// Transfer data between the producer and consumer
	UINT32 elems[32];
	for (i=0; i<32; i++) {
		elems[i] = i;
	}
	retcode = pipe_push(producer, NULL, 0);
	ck_assert_int_eq(retcode, SC_FUNC_FAILURE);
	retcode = pipe_push(producer, elems, 0);
	ck_assert_int_eq(retcode, SC_FUNC_FAILURE);
	retcode = pipe_push(producer, elems, 32);
	ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);

	UINT32 out[32];
	retval = pipe_pull(consumer, out, 32);
	ck_assert_uint_eq(retval, 32);
	for (i=0; i<32; i++) {
		ck_assert_uint_eq(elems[i], out[i]);
	}

	retcode = pipe_producer_destroy(producer);
	ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
	retcode = pipe_consumer_destroy(consumer);
	ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_pipe_transfer_2)
{
	size_t i;
	pipe_t *pipe = NULL;
	SINT32 retcode;
	size_t retval;
	struct TestStruct {
		SINT32 a;
		UINT16 b;
		SINT8  c;
	};

	pipe = pipe_create(sizeof(struct TestStruct), 0);
	ck_assert_ptr_ne(pipe, NULL);

	pipe_producer_t *producer = pipe_producer_create(pipe);
	ck_assert_ptr_ne(producer, NULL);
	pipe_consumer_t *consumer = pipe_consumer_create(pipe);
	ck_assert_ptr_ne(consumer, NULL);

	// Transfer data between the producer and consumer
	for (i=0; i<32; i++) {
		struct TestStruct s;
		s.a = i; s.b = i; s.c = i;
		retcode = pipe_push(producer, &s, 1);
		ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
	}

	for (i=0; i<32; i++) {
		struct TestStruct s;
		retval = pipe_pull(consumer, &s, 1);
		ck_assert_uint_eq(retval, 1);
		ck_assert_int_eq(s.a, i);
		ck_assert_uint_eq(s.b, i);
		ck_assert_int_eq(s.c, i);
	}

	for (i=0; i<32; i++) {
		struct TestStruct s;
		s.a = i; s.b = i; s.c = i;
		retcode = pipe_push(producer, &s, 1);
		ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
		s.a = 64; s.b = 64; s.c = 64;
		retval = pipe_pull(consumer, &s, 1);
		ck_assert_uint_eq(retval, 1);
		ck_assert_int_eq(s.a, i);
		ck_assert_uint_eq(s.b, i);
		ck_assert_int_eq(s.c, i);
	}

	retcode = pipe_producer_destroy(producer);
	ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
	retcode = pipe_consumer_destroy(consumer);
	ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
	retcode = pipe_destroy(pipe);
	ck_assert_int_eq(retcode, SC_FUNC_SUCCESS);
}
END_TEST

Suite *ipc_suite(void)
{
    Suite *s;
    TCase *tc_pipe;

    s = suite_create("IPC");

    /* Test cases */
    tc_pipe = tcase_create("PIPE");
    tcase_add_test(tc_pipe, test_pipe_creation);
    tcase_add_test(tc_pipe, test_pipe_creation_producer);
    tcase_add_test(tc_pipe, test_pipe_creation_consumer);
    tcase_add_test(tc_pipe, test_pipe_creation_producer_consumer);
    tcase_add_test(tc_pipe, test_pipe_transfer);
    tcase_add_test(tc_pipe, test_pipe_transfer_2);
    suite_add_tcase(s, tc_pipe);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = ipc_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}



