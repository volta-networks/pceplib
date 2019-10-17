/*
 * pcep_socket_comm_loop.c
 *
 *  Created on: sep 17, 2019
 *      Author: brady
 */

#include <errno.h>
#include <malloc.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "pcep_socket_comm_internals.h"
#include "pcep_utils_ordered_list.h"


void write_message(int socket_fd, const char *message, unsigned int msg_length)
{
    int bytes_sent = 0;
    unsigned int total_bytes_sent = 0;

    while (bytes_sent < msg_length)
    {
        bytes_sent = write(socket_fd, message + total_bytes_sent, msg_length);

        printf("[%ld-%ld] socket_comm writing on socket [%d] msg_lenth [%u] bytes sent [%d]\n",
                time(NULL), pthread_self(), socket_fd, msg_length, bytes_sent);

        if (bytes_sent < 0)
        {
              if (errno != EAGAIN && errno != EWOULDBLOCK)
              {
                perror("send() failure");

                return;
              }
        }
        else
        {
            total_bytes_sent += bytes_sent;
        }
    }
}


unsigned int read_message(int socket_fd, char *received_message, unsigned int max_message_size)
{
    /* TODO what if bytes_read == max_message_size? there could be more to read */
    unsigned int bytes_read = read(socket_fd, received_message, max_message_size);
    printf("[%ld-%ld] socket_comm read message bytes_read [%u] on socket [%d]\n",
            time(NULL), pthread_self(), bytes_read, socket_fd);

    return bytes_read;
}


int build_fd_sets(pcep_socket_comm_handle *socket_comm_handle)
{
    int max_fd = 0;

    pthread_mutex_lock(&(socket_comm_handle->socket_comm_mutex));

    FD_ZERO(&socket_comm_handle->except_master_set);
    FD_ZERO(&socket_comm_handle->read_master_set);
    ordered_list_node *node = socket_comm_handle->read_list->head;
    pcep_socket_comm_session *comm_session;
    while (node != NULL)
    {
        comm_session = (pcep_socket_comm_session *) node->data;
        if (comm_session->socket_fd > max_fd)
        {
            max_fd = comm_session->socket_fd;
        }

        /*printf("[%ld] socket_comm::build_fdSets set ready_toRead [%d]\n",
                time(NULL), comm_session->socket_fd);*/
        FD_SET(comm_session->socket_fd, &socket_comm_handle->read_master_set);
        FD_SET(comm_session->socket_fd, &socket_comm_handle->except_master_set);
        node = node->next_node;
    }

    FD_ZERO(&socket_comm_handle->write_master_set);
    node = socket_comm_handle->write_list->head;
    while (node != NULL)
    {
        comm_session = (pcep_socket_comm_session *) node->data;
        if (comm_session->socket_fd > max_fd)
        {
            max_fd = comm_session->socket_fd;
        }

        /*printf("[%ld] socket_comm::build_fdSets set ready_toWrite [%d]\n",
                time(NULL), comm_session->socket_fd);*/
        FD_SET(comm_session->socket_fd, &socket_comm_handle->write_master_set);
        FD_SET(comm_session->socket_fd, &socket_comm_handle->except_master_set);
        node = node->next_node;
    }

    pthread_mutex_unlock(&(socket_comm_handle->socket_comm_mutex));

    return max_fd + 1;
}


void handle_reads(pcep_socket_comm_handle *socket_comm_handle)
{
    pthread_mutex_lock(&(socket_comm_handle->socket_comm_mutex));

    /*
     * iterate all the socket_fd's in the read_list. it may be that not
     * all of them have something to read. dont remove the socket_fd
     * from the read_list since messages could come at any time.
     */

    ordered_list_node *node = socket_comm_handle->read_list->head;
    pcep_socket_comm_session *comm_session;
    while (node != NULL)
    {
        comm_session = (pcep_socket_comm_session *) node->data;
        node = node->next_node;
        if (FD_ISSET(comm_session->socket_fd, &(socket_comm_handle->read_master_set)))
        {
            /* either read the message locally, or call the message_ready_handler to read it */
            if (comm_session->message_handler != NULL)
            {
                comm_session->received_bytes =
                        read_message(
                                comm_session->socket_fd,
                                comm_session->received_message,
                                MAX_RECVD_MSG_SIZE);
                if (comm_session->received_bytes > 0)
                {
                    /* send the received message to the handler */
                    comm_session->message_handler(
                            comm_session->session_data,
                            comm_session->received_message,
                            comm_session->received_bytes);
                }
            }
            else
            {
                /* tell the handler a message is ready to be read */
                comm_session->received_bytes =
                        comm_session->message_ready_to_read_handler(
                                comm_session->session_data,
                                comm_session->socket_fd);
            }

            /* handle the read results */
            if (comm_session->received_bytes == 0)
            {
                /* the socket was closed */
                /* TODO should we define a socket except enum? or will the only
                 *      time we call this is when the socket is closed?? */
                if (comm_session->conn_except_notifier != NULL)
                {
                    comm_session->conn_except_notifier(
                            comm_session->session_data,
                            comm_session->socket_fd);
                }

                /* stop reading from the socket if its closed */
                ordered_list_remove_first_node_equals(socket_comm_handle->read_list, comm_session);
            }
            else if (comm_session->received_bytes < 0)
            {
                /* TODO should we call conn_except_notifier() here ? */
                fprintf(stderr, "Error on socket [%d] : [%d][%s]\n",
                        comm_session->socket_fd, errno, strerror(errno));
            }
        }
    }

    pthread_mutex_unlock(&(socket_comm_handle->socket_comm_mutex));
}


void handle_writes(pcep_socket_comm_handle *socket_comm_handle)
{
    pthread_mutex_lock(&(socket_comm_handle->socket_comm_mutex));

    /*
     * iterate all the socket_fd's in the write_list. it may be that not
     * all of them are ready to be written to. only remove the socket_fd
     * from the list if it is ready to be written to.
     */

    ordered_list_node *node = socket_comm_handle->write_list->head;
    pcep_socket_comm_session *comm_session;
    while (node != NULL)
    {
        comm_session = (pcep_socket_comm_session *) node->data;
        node = node->next_node;

        if (FD_ISSET(comm_session->socket_fd, &(socket_comm_handle->write_master_set))) {
            /* only remove the entry from the list, if it is written to */
            ordered_list_remove_first_node_equals(socket_comm_handle->write_list, comm_session);

            /* dequeue all the comm_session messages and send them */
            pcep_socket_comm_queued_message *queued_message = queue_dequeue(comm_session->message_queue);
            while (queued_message != NULL)
            {
                write_message(
                        comm_session->socket_fd,
                        queued_message->unmarshalled_message,
                        queued_message->msg_length);
                if (queued_message->delete_after_send)
                {
                    free(queued_message->unmarshalled_message);
                }
                free(queued_message);
                queued_message = queue_dequeue(comm_session->message_queue);
            }
        }

        /* check if the socket should be closed after writing */
        if (comm_session->close_after_write == true)
        {
            if (comm_session->message_queue->num_entries == 0)
            {
                /* TODO check to make sure modifying the write_list while
                 *      iterating it doesnt cause problems. */
                ordered_list_remove_first_node_equals(socket_comm_handle->read_list, comm_session);
                ordered_list_remove_first_node_equals(socket_comm_handle->write_list, comm_session);
                close(comm_session->socket_fd);
            }
        }

        if (comm_session->message_sent_handler != NULL)
        {
            /* Unlocking to allow the message_sent_handler to
             * make calls like destroy_socket_comm_session */
            pthread_mutex_unlock(&(socket_comm_handle->socket_comm_mutex));
            comm_session->message_sent_handler(
                    comm_session->session_data, comm_session->socket_fd);
            pthread_mutex_lock(&(socket_comm_handle->socket_comm_mutex));
        }

    }

    pthread_mutex_unlock(&(socket_comm_handle->socket_comm_mutex));
}


void handle_excepts(pcep_socket_comm_handle *socket_comm_handle)
{
    /* TODO finish this */
}


/* pcep_socket_comm::initialize_socket_comm_loop() will create a thread and invoke this method */
void *socket_comm_loop(void *data)
{
    if (data == NULL)
    {
        fprintf(stderr, "Cannot start socket_comm_loop with NULL pcep_socketcomm_handle\n");
        return NULL;
    }

    printf("[%ld-%ld] Starting socket_comm_loop thread\n", time(NULL), pthread_self());

    pcep_socket_comm_handle *socket_comm_handle = (pcep_socket_comm_handle *) data;
    struct timeval timer;
    int max_fd;

    while (socket_comm_handle->active)
    {
        /* check the FD's every 1/4 sec, 250 milliseconds */
        timer.tv_sec = 0;
        timer.tv_usec = 250000;
        max_fd = build_fd_sets(socket_comm_handle);

        if (select(max_fd,
                &(socket_comm_handle->read_master_set),
                &(socket_comm_handle->write_master_set),
                &(socket_comm_handle->except_master_set),
                &timer) < 0)
        {
            /* TODO handle the error */
            fprintf(stderr, "ERROR socket_comm_loop on select\n");
        }

        handle_reads(socket_comm_handle);
        handle_writes(socket_comm_handle);
        handle_excepts(socket_comm_handle);
    }

    printf("[%ld-%ld] Finished socket_comm_loop thread\n", time(NULL), pthread_self());

    return NULL;
}
