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

#include "pcep_utils_queue.h"
#include "pcep_socket_comm.h"
#include "mock_socket_comm.h"

/* reset_mock_socket_comm_info() should be used before each test */
mock_socket_comm_info mock_socket_metadata;

void reset_mock_socket_comm_info()
{
    mock_socket_metadata.socket_comm_session_initialize_times_called = 0;
    mock_socket_metadata.socket_comm_session_teardown_times_called = 0;
    mock_socket_metadata.socket_comm_session_connect_tcp_times_called = 0;
    mock_socket_metadata.socket_comm_session_send_message_times_called = 0;
    mock_socket_metadata.socket_comm_session_close_tcp_after_write_times_called = 0;
    mock_socket_metadata.socket_comm_session_close_tcp_times_called = 0;
}

mock_socket_comm_info *get_mock_socket_comm_info()
{
    return &mock_socket_metadata;
}

void verify_socket_comm_times_called(int initialized, int teardown, int connect, int send_message, int close_tcp_after_write, int close_tcp)
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
}


/*
 * Mock the socket_comm functions used by session_logic for Unit Testing
 */

pcep_socket_comm_session *
socket_comm_session_initialize(message_received_handler msg_rcv_handler,
                            message_ready_to_read_handler msg_ready_handler,
                            connection_except_notifier notifier,
                            struct in_addr *host_ip,
                            short port,
                            void *session_data)
{
    mock_socket_metadata.socket_comm_session_initialize_times_called++;

    pcep_socket_comm_session *comm_session = malloc(sizeof(pcep_socket_comm_session));
    bzero(comm_session, sizeof(pcep_socket_comm_session));

    comm_session->message_handler = msg_rcv_handler;
    comm_session->message_ready_toRead_handler = msg_ready_handler;
    comm_session->conn_except_notifier = notifier;
    comm_session->message_queue = queue_initialize();
    comm_session->session_data = session_data;
    comm_session->close_after_write = false;
    comm_session->dest_sock_addr.sin_family = AF_INET;
    comm_session->dest_sock_addr.sin_port = htons(port);
    memcpy(&(comm_session->dest_sock_addr.sin_addr), host_ip, sizeof(struct in_addr));

    return comm_session;
}


bool socket_comm_session_teardown(pcep_socket_comm_session *socket_comm_session)
{
    mock_socket_metadata.socket_comm_session_teardown_times_called++;

    queue_destroy(socket_comm_session->message_queue);
    free(socket_comm_session);

    return true;
}


bool socket_comm_session_connect_tcp(pcep_socket_comm_session *socket_comm_session)
{
    mock_socket_metadata.socket_comm_session_connect_tcp_times_called++;

    return true;
}


void socket_comm_session_send_message(pcep_socket_comm_session *socket_comm_session,
                                  const char *unmarshalled_message,
                                  unsigned int msg_length)
{
    mock_socket_metadata.socket_comm_session_send_message_times_called++;

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