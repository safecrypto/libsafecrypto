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
#ifdef HAVE_64BIT
#include "isaac/isaac64.c"
#define ISAAC_WORD UINT64
#else
#include "isaac/rand.c"
#define ISAAC_WORD UINT32
#endif


START_TEST(test_init)
{
    size_t i;
    randctx ctx;
    for (i=0; i<RANDSIZ; i++) {
        ctx.randrsl[i] = i;
    }
    randinit(&ctx, 1);
    for (i=0; i<RANDSIZ; i++) {
        ck_assert_uint_ne(ctx.randrsl[i], i);
    }
}
END_TEST

START_TEST(test_repeat)
{
    size_t i;
    ISAAC_WORD state[RANDSIZ];
    randctx ctx;

    // Initialuse using a full word with the MSB set
    for (i=0; i<RANDSIZ; i++) {
        ctx.randrsl[i] = ((ISAAC_WORD)1 << 63) | i;
    }
    randinit(&ctx, 1);

    // Copy the state and reinitialise in an indetical manner
    for (i=0; i<RANDSIZ; i++) {
        state[i] = ctx.randrsl[i];
        ctx.randrsl[i] = ((ISAAC_WORD)1 << 63) | i;
    }
    randinit(&ctx, 1);

    // Verify that the state is repeatable
    for (i=0; i<RANDSIZ; i++) {
        ck_assert_uint_eq(ctx.randrsl[i], state[i]);
    }
}
END_TEST

Suite *isaac_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("ISAAC");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_add_test(tc_core, test_init);
    tcase_add_test(tc_core, test_repeat);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = isaac_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


