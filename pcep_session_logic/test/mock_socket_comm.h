/*
 * mock_socket_comm.h
 *
 *  Created on: Oct 10, 2019
 *      Author: brady
 */

#ifndef PCEP_SESSION_LOGIC_TEST_MOCK_SOCKET_COMM_H_
#define PCEP_SESSION_LOGIC_TEST_MOCK_SOCKET_COMM_H_

typedef struct mock_socket_comm_info_
{
    int socket_comm_session_initialize_times_called;
    int socket_comm_session_teardown_times_called;
    int socket_comm_session_connect_tcp_times_called;
    int socket_comm_session_send_message_times_called;
    int socket_comm_session_close_tcp_after_write_times_called;
    int socket_comm_session_close_tcp_times_called;

    /* TODO later if necessary, we can add return values for
     *      those functions that return something */

} mock_socket_comm_info;

void reset_mock_socket_comm_info();
mock_socket_comm_info *get_mock_socket_comm_info();
void verify_socket_comm_times_called(int initialized, int teardown, int connect, int send_message, int close_after_write, int close);

#endif /* PCEP_SESSION_LOGIC_TEST_MOCK_SOCKET_COMM_H_ */
