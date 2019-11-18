/*
 * pcep_session_logic_test.c
 *
 *  Created on: Oct 9, 2019
 *      Author: brady
 */


#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <CUnit/CUnit.h>

#include "pcep_session_logic.h"

/*
 * Test case setup and teardown called before AND after each test.
 */

void pcep_session_logic_test_setup()
{
}


void pcep_session_logic_test_teardown()
{
    stop_session_logic();
}


/*
 * Test cases
 */

void test_run_stop_session_logic()
{
    CU_ASSERT_TRUE(run_session_logic());
    CU_ASSERT_TRUE(stop_session_logic());
}


void test_run_session_logic_twice()
{
    CU_ASSERT_TRUE(run_session_logic());
    CU_ASSERT_FALSE(run_session_logic());
}


void test_session_logic_without_run()
{
    /* Verify the functions that depend on run_session_logic() being called */
    CU_ASSERT_FALSE(stop_session_logic());
}


void test_create_pcep_session_null_params()
{
    pcep_configuration config;
    struct in_addr pce_ip;
    short port = 4789;

    CU_ASSERT_PTR_NULL(create_pcep_session(NULL, NULL, port));
    CU_ASSERT_PTR_NULL(create_pcep_session(NULL, &pce_ip, port));
    CU_ASSERT_PTR_NULL(create_pcep_session(&config, NULL, port));
}


void test_create_destroy_pcep_session()
{
    pcep_session *session;
    pcep_configuration config;
    struct in_addr pce_ip;
    short port = 4789;

    bzero(&config, sizeof(pcep_configuration));
    config.keep_alive_seconds = 5;
    config.dead_timer_seconds = 5;
    config.request_time_seconds = 5;
    config.max_unknown_messages = 5;
    config.max_unknown_requests = 5;
    inet_pton(AF_INET, "127.0.0.1", &(pce_ip));

    session = create_pcep_session(&config, &pce_ip, port);
    CU_ASSERT_PTR_NOT_NULL(session);
    destroy_pcep_session(session);
}


void test_destroy_pcep_session_null_session()
{
    /* Just testing that it does not core dump */
    destroy_pcep_session(NULL);
}
