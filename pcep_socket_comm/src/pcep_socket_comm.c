/*
 * pcep_socket_comm.c
 *
 *  Created on: sep 17, 2019
 *      Author: brady
 *
 *  Implementation of public API functions.
 */


#include <fcntl.h>
#include <malloc.h>
#include <netdb.h> // gethostbyname
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>  // close

#include <arpa/inet.h>  // sockets etc.
#include <sys/types.h>  // sockets etc.
#include <sys/socket.h> // sockets etc.

#include "pcep_socket_comm.h"
#include "pcep_utils_ordered_list.h"
#include "pcep_utils_queue.h"
#include "pcep_socket_comm_internals.h"


pcep_socket_comm_handle *socket_comm_handle_ = NULL;


/* simple compare method callback used by pcep_utils_ordered_list
 * for ordered list insertion. */
int socket_fd_node_compare(void *list_entry, void *new_entry)
{
    return ((pcep_socket_comm_session *) new_entry)->socket_fd - ((pcep_socket_comm_session *) list_entry)->socket_fd;
}


bool initialize_socket_comm_loop()
{
    if (socket_comm_handle_ != NULL)
    {
        /* already initialized */
        return true;
    }

    socket_comm_handle_ = malloc(sizeof(pcep_socket_comm_handle));
    bzero(socket_comm_handle_, sizeof(pcep_socket_comm_handle));

    socket_comm_handle_->active = true;
    socket_comm_handle_->num_active_sessions = 0;
    socket_comm_handle_->read_list = ordered_list_initialize(socket_fd_node_compare);
    socket_comm_handle_->write_list = ordered_list_initialize(socket_fd_node_compare);

    if (pthread_mutex_init(&(socket_comm_handle_->socket_comm_mutex), NULL) != 0)
    {
        fprintf(stderr, "ERROR: cannot initialize socket_comm mutex.\n");
        return false;
    }

    if(pthread_create(&(socket_comm_handle_->socket_comm_thread), NULL, socket_comm_loop, socket_comm_handle_))
    {
        fprintf(stderr, "ERROR: cannot initialize socket_comm thread.\n");
        return false;
    }

    return true;
}


bool destroy_socket_comm_loop()
{
    socket_comm_handle_->active = false;

    pthread_join(socket_comm_handle_->socket_comm_thread, NULL);
    ordered_list_destroy(socket_comm_handle_->read_list);
    ordered_list_destroy(socket_comm_handle_->write_list);
    pthread_mutex_destroy(&(socket_comm_handle_->socket_comm_mutex));

    free(socket_comm_handle_);
    socket_comm_handle_ = NULL;

    return true;
}


pcep_socket_comm_session *
socket_comm_session_initialize(message_received_handler message_handler,
                            message_ready_to_read_handler message_ready_handler,
                            message_sent_notifier msg_sent_notifier,
                            connection_except_notifier notifier,
                            struct in_addr *host_ip,
                            short port,
                            uint32_t connect_timeout_millis,
                            void *session_data)
{
    /* check that not both message handlers were set */
    if (message_handler != NULL && message_ready_handler != NULL)
    {
        fprintf(stderr, "Only one of <message_received_handler | message_ready_to_read_handler> can be set.\n");
        return NULL;
    }

    /* check that at least one message handler was set */
    if (message_handler == NULL && message_ready_handler == NULL)
    {
        fprintf(stderr, "At least one of <message_received_handler | message_ready_to_read_handler> must be set.\n");
        return NULL;
    }

    if (!initialize_socket_comm_loop())
    {
        fprintf(stderr, "ERROR: cannot initialize socket_comm_loop.\n");

        return NULL;
    }

    /* initialize everything for a pcep_session socket_comm */

    pcep_socket_comm_session *socket_comm_session = malloc(sizeof(pcep_socket_comm_session));
    bzero(socket_comm_session, sizeof(pcep_socket_comm_session));

    socket_comm_session->socket_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_comm_session->socket_fd == -1) {
        fprintf(stderr, "ERROR: cannot create socket.\n");
        socket_comm_session_teardown(socket_comm_session);

        return NULL;
    }

    socket_comm_handle_->num_active_sessions++;
    socket_comm_session->close_after_write = false;
    socket_comm_session->session_data = session_data;
    socket_comm_session->message_handler = message_handler;
    socket_comm_session->message_ready_to_read_handler = message_ready_handler;
    socket_comm_session->message_sent_handler = msg_sent_notifier;
    socket_comm_session->conn_except_notifier = notifier;
    socket_comm_session->message_queue = queue_initialize();
    socket_comm_session->dest_sock_addr.sin_family = AF_INET;
    socket_comm_session->dest_sock_addr.sin_port = htons(port);
    socket_comm_session->connect_timeout_millis = connect_timeout_millis;
    memcpy(&(socket_comm_session->dest_sock_addr.sin_addr), host_ip, sizeof(struct in_addr));

    /* dont connect to the destination yet, since the PCE will have a timer
     * for max time between TCP connect and PCEP open. we'll connect later
     * when we send the PCEP open. */

    return socket_comm_session;
}


bool socket_comm_session_connect_tcp(pcep_socket_comm_session *socket_comm_session)
{
    if (socket_comm_session == NULL)
    {
        printf("WARN socket_comm_session_connect_tcp NULL socket_comm_session.\n");
        return NULL;
    }

    /* Set the socket to non-blocking, so connect() does not block */
    fcntl(socket_comm_session->socket_fd, F_SETFL, O_NONBLOCK);
    connect(socket_comm_session->socket_fd,
            (struct sockaddr *) &(socket_comm_session->dest_sock_addr),
            sizeof(struct sockaddr));

    /* Calculate the configured timeout in seconds and microseconds */
    struct timeval tv;
    if (socket_comm_session->connect_timeout_millis > 1000)
    {
        tv.tv_sec = socket_comm_session->connect_timeout_millis / 1000;
        tv.tv_usec = (socket_comm_session->connect_timeout_millis - (tv.tv_sec * 1000)) * 1000;
    }
    else
    {
        tv.tv_sec = 0;
        tv.tv_usec = socket_comm_session->connect_timeout_millis * 1000;
    }

    /* Use select to wait a max timeout for connect */
    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(socket_comm_session->socket_fd, &fdset);
    if (select(socket_comm_session->socket_fd + 1, NULL, &fdset, NULL, &tv) == 1)
    {
        int so_error;
        socklen_t len = sizeof(so_error);
        getsockopt(socket_comm_session->socket_fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error != 0)
        {
            fprintf(stderr, "ERROR: TCP connect failed on socket_fd [%d].\n",
                    socket_comm_session->socket_fd);
            return false;
        }
    }
    else
    {
        fprintf(stderr, "ERROR: TCP connect timed-out on socket_fd [%d].\n",
                socket_comm_session->socket_fd);
        return false;
    }

    pthread_mutex_lock(&(socket_comm_handle_->socket_comm_mutex));
    /* once the TCP connection is open, we should be ready to read at any time */
    ordered_list_add_node(socket_comm_handle_->read_list, socket_comm_session);
    pthread_mutex_unlock(&(socket_comm_handle_->socket_comm_mutex));

    return true;
}


bool socket_comm_session_close_tcp(pcep_socket_comm_session *socket_comm_session)
{
    if (socket_comm_session == NULL)
    {
        printf("WARN socket_comm_session_close_tcp NULL socket_comm_session.\n");
        return false;
    }

    pthread_mutex_lock(&(socket_comm_handle_->socket_comm_mutex));
    ordered_list_remove_first_node_equals(socket_comm_handle_->read_list, socket_comm_session);
    ordered_list_remove_first_node_equals(socket_comm_handle_->write_list, socket_comm_session);
    // TODO should it be close() or shutdown()??
    close(socket_comm_session->socket_fd);
    pthread_mutex_unlock(&(socket_comm_handle_->socket_comm_mutex));

    return true;
}


bool socket_comm_session_close_tcp_after_write(pcep_socket_comm_session *socket_comm_session)
{
    if (socket_comm_session == NULL)
    {
        printf("WARN socket_comm_session_close_tcp_after_write NULL socket_comm_session.\n");
        return false;
    }

    pthread_mutex_lock(&(socket_comm_handle_->socket_comm_mutex));
    socket_comm_session->close_after_write = true;
    pthread_mutex_unlock(&(socket_comm_handle_->socket_comm_mutex));

    return true;
}


bool socket_comm_session_teardown(pcep_socket_comm_session *socket_comm_session)
{
    if (socket_comm_handle_ == NULL)
    {
        printf("WARN: cannot teardown NULL socket_comm_handle\n");
        return false;
    }

    if (socket_comm_session == NULL)
    {
        printf("WARN: cannot teardown NULL session\n");
        return false;
    }

    if (socket_comm_session->socket_fd > 0)
    {
        shutdown(socket_comm_session->socket_fd, SHUT_RDWR);
        close(socket_comm_session->socket_fd);
    }

    pthread_mutex_lock(&(socket_comm_handle_->socket_comm_mutex));
    queue_destroy(socket_comm_session->message_queue);
    ordered_list_remove_first_node_equals(socket_comm_handle_->read_list, socket_comm_session);
    ordered_list_remove_first_node_equals(socket_comm_handle_->write_list, socket_comm_session);
    socket_comm_handle_->num_active_sessions--;
    pthread_mutex_unlock(&(socket_comm_handle_->socket_comm_mutex));

    printf("[%ld-%ld] socket_comm_session [%d] destroyed, [%d] sessions remaining\n",
            time(NULL), pthread_self(),
            socket_comm_session->socket_fd,
            socket_comm_handle_->num_active_sessions);

    free(socket_comm_session);

    /* It would be nice to call destroy_socket_comm_loop() here if
     * socket_comm_handle_->num_active_sessions == 0, but this function
     * will usually be called from the message_sent_notifier callback,
     * which gets called in the middle of the socket_comm_loop, and that
     * is dangerous, so destroy_socket_comm_loop() must be called upon
     * application exit. */

    return true;
}


void socket_comm_session_send_message(pcep_socket_comm_session *socket_comm_session,
                                      char *message,
                                      unsigned int msg_length,
                                      bool free_after_send)
{
    if (socket_comm_session == NULL)
    {
        printf("WARN socket_comm_session_send_message NULL socket_comm_session.\n");
        return;
    }

    pcep_socket_comm_queued_message *queued_message = malloc(sizeof(pcep_socket_comm_queued_message));
    queued_message->unmarshalled_message = message;
    queued_message->msg_length = msg_length;
    queued_message->free_after_send = free_after_send;

    pthread_mutex_lock(&(socket_comm_handle_->socket_comm_mutex));
    queue_enqueue(socket_comm_session->message_queue, queued_message);
    ordered_list_add_node(socket_comm_handle_->write_list, socket_comm_session);
    pthread_mutex_unlock(&(socket_comm_handle_->socket_comm_mutex));
}
