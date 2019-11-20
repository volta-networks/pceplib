/*
 * pcep_socket_comm.h
 *
 *  Created on: sep 17, 2019
 *      Author: brady
 */

#ifndef INCLUDE_PCEPSOCKETCOMM_H_
#define INCLUDE_PCEPSOCKETCOMM_H_

#include <arpa/inet.h>  // sockaddr_in
#include <stdbool.h>

#include "pcep_utils_queue.h"

#define MAX_RECVD_MSG_SIZE 2048

/*
 * A socket_comm_session can be initialized with 1 of 2 types of mutually exclusive
 * message callbacks:
 * - message_received_handler : the socket_comm library reads the message and calls
 *                            the callback with the message_data and message_length.
 *                            this callback should be used for smaller/simpler messages.
 * - message_ready_to_read_handler : the socket_comm library will call this callback
 *                               when a message is ready to be read on a socket_fd.
 *                               this callback should be used if the
 */

/* message received handler that receives the message data and message length */
typedef void (*message_received_handler)(void *session_data, char *message_data, unsigned int message_length);
/* message ready received handler that should read the message on socket_fd
 * and return the number of bytes read */
typedef int (*message_ready_to_read_handler)(void *session_data, int socket_fd);
/* callback handler called when a messages is sent */
typedef void (*message_sent_notifier)(void *session_data, int socket_fd);
/* callback handler called when the socket is closed */
typedef void (*connection_except_notifier)(void *session_data, int socket_fd);

typedef struct pcep_socket_comm_session_
{
    message_received_handler message_handler;
    message_ready_to_read_handler message_ready_to_read_handler;
    message_sent_notifier message_sent_handler;
    connection_except_notifier conn_except_notifier;
    struct sockaddr_in dest_sock_addr;
    uint32_t connect_timeout_millis;
    int socket_fd;
    void *session_data;
    queue_handle *message_queue;
    char received_message[MAX_RECVD_MSG_SIZE];
    int received_bytes;
    bool close_after_write;

} pcep_socket_comm_session;


/* Need to document that when the msg_rcv_handler is called, the data needs
 * to be handled in the same function call, else it may be overwritten by
 * the next read from this socket */

/* The msg_rcv_handler and msg_ready_handler are mutually exclusive, and only
 * one can be set (as explained above), else NULL will be returned. */
pcep_socket_comm_session *
socket_comm_session_initialize(message_received_handler msg_rcv_handler,
                            message_ready_to_read_handler msg_ready_handler,
                            message_sent_notifier msg_sent_notifier,
                            connection_except_notifier notifier,
                            struct in_addr *host_ip,
                            short port,
                            uint32_t connect_timeout_millis,
                            void *session_data);

bool socket_comm_session_teardown(pcep_socket_comm_session *socket_comm_session);

bool socket_comm_session_connect_tcp(pcep_socket_comm_session *socket_comm_session);

/* Immediately close the TCP connection, irregardless if there are pending
 * messages to be sent. */
bool socket_comm_session_close_tcp(pcep_socket_comm_session *socket_comm_session);

/* Sets a flag to close the TCP connection either after all the pending messages
 * are written, or if there are no pending messages, the next time the socket is
 * checked to be writeable. */
bool socket_comm_session_close_tcp_after_write(pcep_socket_comm_session *socket_comm_session);

void socket_comm_session_send_message(pcep_socket_comm_session *socket_comm_session,
                                  char *unmarshalled_message,
                                  unsigned int msg_length,
                                  bool free_after_send);

/* the socket comm loop is started internally by socket_comm_session_initialize()
 * but needs to be explicitly stopped with this call. */
bool destroy_socket_comm_loop();

#endif /* INCLUDE_PCEPSOCKETCOMM_H_ */
