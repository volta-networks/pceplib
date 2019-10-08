/*
 * pcep_socket_comm_test.c
 *
 *  Created on: Oct 8, 2019
 *      Author: brady
 */


#include <netinet/in.h>

#include <CUnit/CUnit.h>

#include "pcep_socket_comm.h"
#include "pcep_socket_comm_internals.h"

extern pcep_socket_comm_handle *socket_comm_handle_;

static pcep_socket_comm_session *test_session = NULL;
static struct in_addr test_host_ip;
static short test_port = 4789;

/*
 * Unit Test Basic pcep_socket_comm API usage.
 * Testing sending messages, etc via sockets should be done
 * with integration tests, not unit tests.
 */

/*
 * Different socket_comm handler test implementations
 */
static void test_message_received_handler(void *session_data, char *message_data, unsigned int message_length)
{
}

static int test_message_ready_to_read_handler(void *session_data, int socket_fd)
{
    return 1;
}

static void test_connection_except_notifier(void *session_data, int socket_fd)
{
}


/*
 * Test case setup and teardown called before AND after each test.
 */
void pcep_socket_comm_test_setup()
{
    inet_pton(AF_INET, "127.0.0.1", &(test_host_ip));
}

void pcep_socket_comm_test_teardown()
{
    socket_comm_session_teardown(test_session);
    test_session = NULL;
}


/*
 * Test cases
 */

void test_pcep_socket_comm_initialize()
{
    test_session = socket_comm_session_initialize(
            test_message_received_handler,
            NULL,
            test_connection_except_notifier,
            &test_host_ip, test_port, NULL);
    CU_ASSERT_PTR_NOT_NULL(test_session);
}


void test_pcep_socket_comm_initialize_handlers()
{
    /* Verify incorrect handler usage is correctly handled */

    /* Both receive handlers cannot be NULL */
    test_session = socket_comm_session_initialize(
            NULL,
            NULL,
            test_connection_except_notifier,
            &test_host_ip, test_port, NULL);
    CU_ASSERT_PTR_NULL(test_session);

    /* Both receive handlers cannot be set */
    test_session = socket_comm_session_initialize(
            test_message_received_handler,
            test_message_ready_to_read_handler,
            test_connection_except_notifier,
            &test_host_ip, test_port, NULL);
    CU_ASSERT_PTR_NULL(test_session);

    /* Only one receive handler can be set */
    test_session = socket_comm_session_initialize(
            NULL,
            test_message_ready_to_read_handler,
            test_connection_except_notifier,
            &test_host_ip, test_port, NULL);
    CU_ASSERT_PTR_NOT_NULL(test_session);
}


void test_pcep_socket_comm_session_not_initialized()
{
    CU_ASSERT_FALSE(socket_comm_session_connect_tcp(NULL));
    CU_ASSERT_FALSE(socket_comm_session_close_tcp(NULL));
    CU_ASSERT_FALSE(socket_comm_session_close_tcp_after_write(NULL));
    socket_comm_session_send_message(NULL, NULL, 0);
    CU_ASSERT_FALSE(socket_comm_session_teardown(NULL));
}

void test_pcep_socket_comm_session_destroy()
{
    test_session = socket_comm_session_initialize(
            test_message_received_handler,
            NULL,
            test_connection_except_notifier,
            &test_host_ip, test_port, NULL);
    CU_ASSERT_PTR_NOT_NULL(test_session);
    CU_ASSERT_PTR_NOT_NULL(socket_comm_handle_);
    CU_ASSERT_EQUAL(socket_comm_handle_->num_active_sessions, 1);

    CU_ASSERT_TRUE(socket_comm_session_teardown(test_session));
    CU_ASSERT_PTR_NULL(socket_comm_handle_);
}
