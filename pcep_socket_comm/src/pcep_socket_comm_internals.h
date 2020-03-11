/*
 * pcep_socket_comm_internals.h
 *
 *  Created on: sep 17, 2019
 *      Author: brady
 */

#ifndef SRC_PCEPSOCKETCOMMINTERNALS_H_
#define SRC_PCEPSOCKETCOMMINTERNALS_H_

#include <pthread.h>
#include <stdbool.h>

#include "pcep_utils_ordered_list.h"
#include "pcep_socket_comm.h"


typedef struct pcep_socket_comm_handle_
{
    bool active;
    pthread_t socket_comm_thread;
    pthread_mutex_t socket_comm_mutex;
    fd_set read_master_set;
    fd_set write_master_set;
    fd_set except_master_set;
    /* ordered_list of socket_descriptors to read from */
    ordered_list_handle *read_list;
    /* ordered_list of socket_descriptors to write to */
    ordered_list_handle *write_list;
    ordered_list_handle *session_list;
    int num_active_sessions;

} pcep_socket_comm_handle;


typedef struct pcep_socket_comm_queued_message_
{
    char *unmarshalled_message;
    int msg_length;
    bool free_after_send;

} pcep_socket_comm_queued_message;


/* Functions implemented in pcep_socket_comm_loop.c */
void *socket_comm_loop(void *data);

#endif /* SRC_PCEPSOCKETCOMMINTERNALS_H_ */
