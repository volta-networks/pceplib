/*
 * mock_socket_comm.c
 *
 *  Created on: Oct 9, 2019
 *      Author: brady
 */

#include <netinet/in.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <CUnit/CUnit.h>

#include "pcep_socket_comm.h"
#include "pcep_socket_comm_mock.h"
#include "pcep_utils_queue.h"

/* reset_mock_socket_comm_info() should be used before each test */
mock_socket_comm_info mock_socket_metadata;

void setup_mock_socket_comm_info()
{
    mock_socket_metadata.socket_comm_session_initialize_times_called = 0;
    mock_socket_metadata.socket_comm_session_initialize_src_times_called = 0;
    mock_socket_metadata.socket_comm_session_teardown_times_called = 0;
    mock_socket_metadata.socket_comm_session_connect_tcp_times_called = 0;
    mock_socket_metadata.socket_comm_session_send_message_times_called = 0;
    mock_socket_metadata.socket_comm_session_close_tcp_after_write_times_called = 0;
    mock_socket_metadata.socket_comm_session_close_tcp_times_called = 0;
    mock_socket_metadata.destroy_socket_comm_loop_times_called = 0;
    mock_socket_metadata.send_message_save_message = false;
    mock_socket_metadata.sent_message_list = dll_initialize();
}

void teardown_mock_socket_comm_info()
{
    dll_destroy(mock_socket_metadata.sent_message_list);
}

void reset_mock_socket_comm_info()
{
    teardown_mock_socket_comm_info();
    setup_mock_socket_comm_info();
}

mock_socket_comm_info *get_mock_socket_comm_info()
{
    return &mock_socket_metadata;
}

void verify_socket_comm_times_called(int initialized, int teardown, int connect, int send_message, int close_tcp_after_write, int close_tcp, int destroy)
{
    CU_ASSERT_EQUAL(initialized,
                    mock_socket_metadata.socket_comm_session_initialize_times_called);
    CU_ASSERT_EQUAL(teardown,
                    mock_socket_metadata.socket_comm_session_teardown_times_called);
    CU_ASSERT_EQUAL(connect,
                    mock_socket_metadata.socket_comm_session_connect_tcp_times_called);
    CU_ASSERT_EQUAL(send_message,
                    mock_socket_metadata.socket_comm_session_send_message_times_called);
    CU_ASSERT_EQUAL(close_tcp_after_write,
                    mock_socket_metadata.socket_comm_session_close_tcp_after_write_times_called);
    CU_ASSERT_EQUAL(close_tcp,
                    mock_socket_metadata.socket_comm_session_close_tcp_times_called);
    CU_ASSERT_EQUAL(destroy,
                    mock_socket_metadata.destroy_socket_comm_loop_times_called);
}


/*
 * Mock the socket_comm functions used by session_logic for Unit Testing
 */

bool destroy_socket_comm_loop()
{
    mock_socket_metadata.destroy_socket_comm_loop_times_called++;

    return false;
}

pcep_socket_comm_session *
socket_comm_session_initialize(message_received_handler msg_rcv_handler,
                            message_ready_to_read_handler msg_ready_handler,
                            message_sent_notifier msg_sent_notifier,
                            connection_except_notifier notifier,
                            struct in_addr *dst_ip,
                            short dst_port,
                            uint32_t connect_timeout_millis,
                            void *session_data)
{
    mock_socket_metadata.socket_comm_session_initialize_times_called++;

    pcep_socket_comm_session *comm_session = malloc(sizeof(pcep_socket_comm_session));
    bzero(comm_session, sizeof(pcep_socket_comm_session));

    comm_session->message_handler = msg_rcv_handler;
    comm_session->message_ready_to_read_handler = msg_ready_handler;
    comm_session->conn_except_notifier = notifier;
    comm_session->message_queue = queue_initialize();
    comm_session->session_data = session_data;
    comm_session->close_after_write = false;
    comm_session->connect_timeout_millis = connect_timeout_millis;
    comm_session->dest_sock_addr.sin_family = AF_INET;
    comm_session->dest_sock_addr.sin_port = htons(dst_port);
    comm_session->dest_sock_addr.sin_addr.s_addr = dst_ip->s_addr;

    return comm_session;
}

pcep_socket_comm_session *
socket_comm_session_initialize_with_src(message_received_handler msg_rcv_handler,
                            message_ready_to_read_handler msg_ready_handler,
                            message_sent_notifier msg_sent_notifier,
                            connection_except_notifier notifier,
                            struct in_addr *src_ip,
                            short src_port,
                            struct in_addr *dst_ip,
                            short dst_port,
                            uint32_t connect_timeout_millis,
                            void *session_data)
{
    mock_socket_metadata.socket_comm_session_initialize_src_times_called++;

    pcep_socket_comm_session *comm_session = malloc(sizeof(pcep_socket_comm_session));
    bzero(comm_session, sizeof(pcep_socket_comm_session));

    comm_session->message_handler = msg_rcv_handler;
    comm_session->message_ready_to_read_handler = msg_ready_handler;
    comm_session->conn_except_notifier = notifier;
    comm_session->message_queue = queue_initialize();
    comm_session->session_data = session_data;
    comm_session->close_after_write = false;
    comm_session->connect_timeout_millis = connect_timeout_millis;
    comm_session->src_sock_addr.sin_family = AF_INET;
    comm_session->src_sock_addr.sin_port = htons(src_port);
    comm_session->src_sock_addr.sin_addr.s_addr = ((src_ip == NULL) ? INADDR_ANY : src_ip->s_addr);
    comm_session->dest_sock_addr.sin_family = AF_INET;
    comm_session->dest_sock_addr.sin_port = htons(dst_port);
    comm_session->dest_sock_addr.sin_addr.s_addr = dst_ip->s_addr;

    return comm_session;
}

bool socket_comm_session_teardown(pcep_socket_comm_session *socket_comm_session)
{
    mock_socket_metadata.socket_comm_session_teardown_times_called++;

    if (socket_comm_session != NULL)
    {
        queue_destroy(socket_comm_session->message_queue);
        free(socket_comm_session);
    }

    return true;
}


bool socket_comm_session_connect_tcp(pcep_socket_comm_session *socket_comm_session)
{
    mock_socket_metadata.socket_comm_session_connect_tcp_times_called++;

    return true;
}


void socket_comm_session_send_message(pcep_socket_comm_session *socket_comm_session,
                                  char *unmarshalled_message,
                                  unsigned int msg_length,
                                  bool delete_after_send)
{
    mock_socket_metadata.socket_comm_session_send_message_times_called++;

    if (mock_socket_metadata.send_message_save_message == true)
    {
        /* the caller/test case is responsible for freeing the message */
        dll_append(mock_socket_metadata.sent_message_list, unmarshalled_message);
    }
    else
    {
        if (delete_after_send == true)
        {
            free(unmarshalled_message);
        }
    }

    return;
}


bool socket_comm_session_close_tcp_after_write(pcep_socket_comm_session *socket_comm_session)
{
    mock_socket_metadata.socket_comm_session_close_tcp_after_write_times_called++;

    return true;
}


bool socket_comm_session_close_tcp(pcep_socket_comm_session *socket_comm_session)
{
    mock_socket_metadata.socket_comm_session_close_tcp_times_called++;

    return true;
}
