/*
 * pcep_timers_test.c
 *
 *  Created on: Oct 7, 2019
 *      Author: brady
 */

#include <stdbool.h>
#include <CUnit/CUnit.h>

#include "pcep_timers.h"

/* Test case teardown called after each test.
 * Declared in pcep_timers_tests.c */
void pcep_timers_test_teardown()
{
    teardown_timers();
}

static void test_timer_expire_handler(void *data, int timerId)
{
}


void test_double_initialization(void)
{
    CU_ASSERT_EQUAL(initialize_timers(test_timer_expire_handler), true);
    CU_ASSERT_EQUAL(initialize_timers(test_timer_expire_handler), false);
}


void test_initialization_null_callback(void)
{
    CU_ASSERT_EQUAL(initialize_timers(NULL), false);
}


void test_not_initialized(void)
{
    /* All of these should fail if initialize_timers() hasnt been called */
    CU_ASSERT_EQUAL(create_timer(5, NULL), -1);
    CU_ASSERT_EQUAL(cancel_timer(7), false);
    CU_ASSERT_EQUAL(reset_timer(7), false);
    CU_ASSERT_EQUAL(teardown_timers(), false);
}


void test_create_timer(void)
{
    CU_ASSERT_EQUAL(initialize_timers(test_timer_expire_handler), true);

    int timer_id = create_timer(0, NULL);
    CU_ASSERT_TRUE(timer_id > -1);
}


void test_cancel_timer(void)
{
    CU_ASSERT_EQUAL(initialize_timers(test_timer_expire_handler), true);

    int timer_id = create_timer(10, NULL);
    CU_ASSERT_TRUE(timer_id > -1);

    CU_ASSERT_EQUAL(cancel_timer(timer_id), true);
}


void test_cancel_timer_invalid(void)
{
    CU_ASSERT_EQUAL(initialize_timers(test_timer_expire_handler), true);
    CU_ASSERT_EQUAL(cancel_timer(1), false);
}


void test_reset_timer(void)
{
    CU_ASSERT_EQUAL(initialize_timers(test_timer_expire_handler), true);

    int timer_id = create_timer(10, NULL);
    CU_ASSERT_TRUE(timer_id > -1);

    CU_ASSERT_EQUAL(reset_timer(timer_id), true);
}


void test_reset_timer_invalid(void)
{
    CU_ASSERT_EQUAL(initialize_timers(test_timer_expire_handler), true);
    CU_ASSERT_EQUAL(reset_timer(1), false);
}
