/*
 * pcep_socket_comm_mock.h
 *
 * This module is built into a separate library, and is used by several
 * other modules for unit testing, so that real sockets dont have to be
 * created.
 *
 *  Created on: Oct 10, 2019
 *      Author: brady
 */

#ifndef PCEP_SOCKET_COMM_MOCK_SOCKET_COMM_H_
#define PCEP_SOCKET_COMM_MOCK_SOCKET_COMM_H_

#include <stdbool.h>

#include "pcep_utils_double_linked_list.h"

typedef struct mock_socket_comm_info_
{
    int socket_comm_initialize_external_infra_times_called;
    int socket_comm_session_initialize_times_called;
    int socket_comm_session_initialize_src_times_called;
    int socket_comm_session_teardown_times_called;
    int socket_comm_session_connect_tcp_times_called;
    int socket_comm_session_send_message_times_called;
    int socket_comm_session_close_tcp_after_write_times_called;
    int socket_comm_session_close_tcp_times_called;
    int destroy_socket_comm_loop_times_called;

    /* TODO later if necessary, we can add return values for
     *      those functions that return something */

    /* Used to access messages sent with socket_comm_session_send_message() */
    bool send_message_save_message;
    double_linked_list *sent_message_list;

} mock_socket_comm_info;

void setup_mock_socket_comm_info();
void teardown_mock_socket_comm_info();
void reset_mock_socket_comm_info();

mock_socket_comm_info *get_mock_socket_comm_info();
void verify_socket_comm_times_called(int initialized,
                                     int teardown,
                                     int connect,
                                     int send_message,
                                     int close_after_write,
                                     int close,
                                     int destroy);

#endif /* PCEP_SOCKET_COMM_MOCK_SOCKET_COMM_H_ */
