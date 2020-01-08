/*
 * pcep_session_logic_internals.h
 *
 *  Created on: sep 20, 2019
 *      Author: brady
 */

#ifndef SRC_PCEPSESSIONLOGICINTERNALS_H_
#define SRC_PCEPSESSIONLOGICINTERNALS_H_


#include <pthread.h>
#include <stdbool.h>

#include "pcep-tools.h"

#include "pcep_utils_double_linked_list.h"
#include "pcep_utils_ordered_list.h"
#include "pcep_utils_queue.h"


typedef struct pcep_session_logic_handle_
{
    pthread_t session_logic_thread;
    pthread_mutex_t session_logic_mutex;
    pthread_cond_t session_logic_cond_var;
    bool session_logic_condition;
    bool active;

    ordered_list_handle *session_list;
    /* Internal timers and socket events */
    queue_handle *session_event_queue;

} pcep_session_logic_handle;


/* Used internally for Session events: message received, timer expired,
 * or socket closed */
typedef struct pcep_session_event_
{
    pcep_session *session;
    int expired_timer_id;
    double_linked_list *received_msg_list;
    bool socket_closed;

} pcep_session_event;


/* functions implemented in pcep_session_logic_loop.c */
void *session_logic_loop(void *data);
int session_logic_msg_ready_handler(void *data, int socket_fd);
void session_logic_message_sent_handler(void *data, int socket_fd);
void session_logic_conn_except_notifier(void *data, int socket_fd);
void session_logic_timer_expire_handler(void *data, int timer_id);

void handle_timer_event(pcep_session_event *event);
void handle_socket_comm_event(pcep_session_event *event);
void session_send_message(pcep_session *session, struct pcep_message *message);
/* defined in pcep_session_logic_states.c */
void send_pcep_error(pcep_session *session,
                     enum pcep_error_type error_type,
                     enum pcep_error_value error_value);


#endif /* SRC_PCEPSESSIONLOGICINTERNALS_H_ */
