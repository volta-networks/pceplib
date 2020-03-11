/*
 * pcep_socket_comm_loop_test.c
 *
 *  Created on: Oct 8, 2019
 *      Author: brady
 */

#include <pthread.h>
#include <stdlib.h>

#include <CUnit/CUnit.h>

#include "pcep_socket_comm_internals.h"

/*
 * Functions to be tested, implemented in pcep_socket_comm_loop.c
 */
extern void handle_reads(pcep_socket_comm_handle *socket_comm_handle);
extern int socket_fd_node_compare(void *list_entry, void *new_entry);

typedef struct ready_to_read_handler_info_
{
    bool handler_called;
    bool except_handler_called;
    void *data;
    int socket_fd;
    int bytes_read;

} ready_to_read_handler_info;

static ready_to_read_handler_info read_handler_info;
static pcep_socket_comm_session *test_comm_session;
static pcep_socket_comm_handle *test_socket_comm_handle = NULL;

static int test_loop_message_ready_to_read_handler(void *session_data, int socket_fd)
{
    read_handler_info.handler_called = true;
    read_handler_info.data = session_data;
    read_handler_info.socket_fd = socket_fd;

    return read_handler_info.bytes_read;
}


void test_loop_conn_except_notifier(void *session_data, int socket_fd)
{
    read_handler_info.except_handler_called = true;
}


/*
 * Test case setup and teardown called before AND after each test.
 */
void pcep_socket_comm_loop_test_setup()
{
    test_socket_comm_handle = malloc(sizeof(pcep_socket_comm_handle));
    bzero(test_socket_comm_handle, sizeof(pcep_socket_comm_handle));
    test_socket_comm_handle->active = false;
    test_socket_comm_handle->read_list = ordered_list_initialize(socket_fd_node_compare);
    test_socket_comm_handle->write_list = ordered_list_initialize(socket_fd_node_compare);
    test_socket_comm_handle->session_list = ordered_list_initialize(pointer_compare_function);
    pthread_mutex_init(&test_socket_comm_handle->socket_comm_mutex, NULL);
    test_socket_comm_handle->num_active_sessions = 0;

    test_comm_session = malloc(sizeof(pcep_socket_comm_session));
    bzero(test_comm_session, sizeof(pcep_socket_comm_session));
    test_comm_session->message_ready_to_read_handler = test_loop_message_ready_to_read_handler;
    ordered_list_add_node(test_socket_comm_handle->session_list, test_comm_session);

    read_handler_info.handler_called = false;
    read_handler_info.except_handler_called = false;
    read_handler_info.data = NULL;
    read_handler_info.socket_fd = -1;
    read_handler_info.bytes_read = 0;
}


void pcep_socket_comm_loop_test_teardown()
{
    pthread_mutex_destroy(&test_socket_comm_handle->socket_comm_mutex);
    ordered_list_destroy(test_socket_comm_handle->read_list);
    ordered_list_destroy(test_socket_comm_handle->write_list);
    ordered_list_destroy(test_socket_comm_handle->session_list);
    free(test_socket_comm_handle);
    test_socket_comm_handle = NULL;

    if (test_comm_session != NULL)
    {
        free(test_comm_session);
        test_comm_session = NULL;
    }
}


/*
 * Test cases
 */

void test_socket_comm_loop_null_handle()
{
    /* Verify that socket_comm_loop() correctly handles a NULL timers_context */
    socket_comm_loop(NULL);
}


void test_socket_comm_loop_not_active()
{
    /* Verify that event_loop() correctly handles an inactive flag */
    pcep_socket_comm_handle handle;
    handle.active = false;
    socket_comm_loop(&handle);
}


void test_handle_reads_no_read()
{
    CU_ASSERT_PTR_NULL(test_socket_comm_handle->read_list->head);

    handle_reads(test_socket_comm_handle);

    CU_ASSERT_FALSE(read_handler_info.handler_called);
    CU_ASSERT_FALSE(read_handler_info.except_handler_called);
    CU_ASSERT_PTR_NULL(test_socket_comm_handle->read_list->head);
}


void test_handle_reads_read_message()
{
    /* Setup the comm session so that it can read.
     * It should read 100 bytes, which simulates a successful read */
    test_comm_session->socket_fd = 10;
    read_handler_info.bytes_read = 100;
    FD_SET(test_comm_session->socket_fd, &test_socket_comm_handle->read_master_set);
    ordered_list_add_node(test_socket_comm_handle->read_list, test_comm_session);

    handle_reads(test_socket_comm_handle);

    CU_ASSERT_TRUE(read_handler_info.handler_called);
    CU_ASSERT_FALSE(read_handler_info.except_handler_called);
    CU_ASSERT_EQUAL(test_comm_session->received_bytes, read_handler_info.bytes_read);
}


void test_handle_reads_read_message_close()
{
    /* Setup the comm session so that it can read.
     * It should read 0 bytes, which simulates that the socket closed */
    test_comm_session->socket_fd = 11;
    read_handler_info.bytes_read = 0;
    FD_SET(test_comm_session->socket_fd, &test_socket_comm_handle->read_master_set);
    ordered_list_add_node(test_socket_comm_handle->read_list, test_comm_session);

    handle_reads(test_socket_comm_handle);

    CU_ASSERT_TRUE(read_handler_info.handler_called);
    CU_ASSERT_FALSE(read_handler_info.except_handler_called);
    CU_ASSERT_EQUAL(test_comm_session->received_bytes, read_handler_info.bytes_read);
    CU_ASSERT_PTR_NULL(test_socket_comm_handle->read_list->head);
}
