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
#include "prng_types.h"
#include "ctr_drbg.h"


#if defined( __linux__ ) || defined( __GNUC__ ) || defined( __GNU_LIBRARY__ )
static void get_entropy(size_t n, UINT8 *data, user_entropy_t *p)
{
    UINT32 word;
    size_t i = 0;
    while (i < n) {
        if (0 == (i&3)) {
            word = random() ^ (random() << 1);
        }
        data[i] = word >> (8*(i&3));
        n--;
    }
}
#else // WINDOWS
#endif

START_TEST(test_ctr_drbg_0)
{
    SINT32 retval;

    retval = ctr_drbg_destroy(NULL);
    ck_assert_int_eq(retval, SC_FUNC_FAILURE);

    ctx_ctr_drbg_t *ctx = ctr_drbg_create(get_entropy, NULL, 0);
    ck_assert_ptr_ne(ctx, NULL);

    retval = ctr_drbg_destroy(ctx);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_ctr_drbg_1)
{
    size_t i;
    SINT32 retval;
    UINT8 data[CSPRNG_BUFFER_SIZE];

    ctx_ctr_drbg_t *ctx = ctr_drbg_create(get_entropy, NULL, 0xFFFFFFFF);
    ck_assert_ptr_ne(ctx, NULL);

    retval = ctr_drbg_update(NULL, data);
    ck_assert_int_eq(retval, SC_FUNC_FAILURE);

    retval = ctr_drbg_update(ctx, NULL);
    ck_assert_int_eq(retval, SC_FUNC_FAILURE);

    retval = ctr_drbg_update(ctx, data);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
    UINT8 OR = 0;
    for (i=0; i<CSPRNG_BUFFER_SIZE; i++) {
        OR |= data[i];
    }
    ck_assert_uint_ne(OR, 0);

    retval = ctr_drbg_destroy(ctx);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
}
END_TEST

START_TEST(test_ctr_drbg_2)
{
    size_t i;
    SINT32 retval;
    UINT8 data[CSPRNG_BUFFER_SIZE];

    ctx_ctr_drbg_t *ctx = ctr_drbg_create(get_entropy, NULL, 0x00010000);
    ck_assert_ptr_ne(ctx, NULL);

    for (i=0; i<4096; i++) {
        retval = ctr_drbg_update(ctx, data);
        ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
    }

    retval = ctr_drbg_destroy(ctx);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
}
END_TEST

Suite *ctr_drbg_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("ctr_drbg");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_ctr_drbg_0);
    tcase_add_test(tc_core, test_ctr_drbg_1);
    tcase_add_test(tc_core, test_ctr_drbg_2);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = ctr_drbg_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


