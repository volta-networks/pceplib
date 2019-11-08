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
    pcep_message_response rsp_message;
    pcep_session session;

    /* Verify the functions that depend on run_session_logic() being called */
    CU_ASSERT_PTR_NULL(register_response_message(&session, 1, 5));
    CU_ASSERT_FALSE(stop_session_logic());
    destroy_response_message(&rsp_message);
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


void test_register_message_null_params()
{
    /* Just testing that it returns NULL and does not core dump */
    CU_ASSERT_PTR_NULL(register_response_message(NULL, 1, 5));
}


void test_register_destroy_response_message()
{
    pcep_message_response *rsp_message;
    pcep_session session;
    bzero(&session, sizeof(pcep_session));

    CU_ASSERT_TRUE(run_session_logic());
    rsp_message = register_response_message(&session, 1, 5);
    CU_ASSERT_PTR_NOT_NULL(rsp_message);
    destroy_response_message(rsp_message);
}


void test_destroy_message_null_params()
{
    /* Just testing that it does not core dump */
    destroy_response_message(NULL);
}


void test_query_message_null_params()
{
    /* Just testing that it does not core dump */
    query_response_message(NULL);
}


void test_query_message()
{
    pcep_message_response rsp_message;
    bzero(&rsp_message, sizeof(pcep_message_response));

    /* If the status is READY, just return true */
    rsp_message.response_status = RESPONSE_STATE_READY;
    CU_ASSERT_TRUE(query_response_message(&rsp_message));

    /* Different status, to represent a state change */
    rsp_message.response_status = RESPONSE_STATE_TIMED_OUT;
    rsp_message.prev_response_status = RESPONSE_STATE_WAITING;
    CU_ASSERT_TRUE(query_response_message(&rsp_message));

    /* Message timeout */
    rsp_message.response_status = RESPONSE_STATE_WAITING;
    rsp_message.prev_response_status = RESPONSE_STATE_WAITING;
    rsp_message.max_wait_time_milli_seconds = 1500;
    struct timespec time_now;
    clock_gettime(CLOCK_REALTIME, &time_now);
    rsp_message.time_request_registered.tv_sec = time_now.tv_sec - 2;
    rsp_message.time_request_registered.tv_nsec = time_now.tv_nsec;
    CU_ASSERT_TRUE(query_response_message(&rsp_message));
    CU_ASSERT_EQUAL(rsp_message.response_status, RESPONSE_STATE_TIMED_OUT);

    /* Still waiting for the response */
    rsp_message.response_status = RESPONSE_STATE_WAITING;
    rsp_message.prev_response_status = RESPONSE_STATE_WAITING;
    rsp_message.max_wait_time_milli_seconds = 1500;
    clock_gettime(CLOCK_REALTIME, &rsp_message.time_request_registered);
    CU_ASSERT_FALSE(query_response_message(&rsp_message));
    CU_ASSERT_EQUAL(rsp_message.prev_response_status, RESPONSE_STATE_WAITING);
    CU_ASSERT_EQUAL(rsp_message.response_status, RESPONSE_STATE_WAITING);
}


void test_wait_for_response_null_params()
{
    /* Just testing that it does not core dump */
    CU_ASSERT_FALSE(wait_for_response_message(NULL));
}


void test_wait_for_response()
{
    CU_ASSERT_TRUE(run_session_logic());

    pcep_session session;
    bzero(&session, sizeof(pcep_session));
    pcep_message_response *rsp_message = register_response_message(&session, 1, 1);

    /* If the status is READY, just return true */
    rsp_message->response_status = RESPONSE_STATE_READY;
    CU_ASSERT_TRUE(wait_for_response_message(rsp_message));

    /* Message timeout */
    rsp_message->response_status = RESPONSE_STATE_WAITING;
    rsp_message->prev_response_status = RESPONSE_STATE_WAITING;
    clock_gettime(CLOCK_REALTIME, &rsp_message->time_request_registered);
    CU_ASSERT_FALSE(wait_for_response_message(rsp_message));
    CU_ASSERT_EQUAL(rsp_message->prev_response_status, RESPONSE_STATE_WAITING);
    CU_ASSERT_EQUAL(rsp_message->response_status, RESPONSE_STATE_TIMED_OUT);

    destroy_response_message(rsp_message);
}
