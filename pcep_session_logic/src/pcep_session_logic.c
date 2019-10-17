/*
 * pcep_session_logic.c
 *
 *  Created on: sep 20, 2019
 *      Author: brady
 */

#include <errno.h>
#include <limits.h>
#include <malloc.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "pcep_session_logic.h"
#include "pcep_timers.h"
#include "pcep_utils_ordered_list.h"
#include "pcep_session_logic_internals.h"

/*
 * public API function implementations for the session_logic
 */

pcep_session_logic_handle *session_logic_handle_ = NULL;
int session_id_ = 0;


int session_id_compare_function(void *list_entry, void *new_entry)
{
    /* return:
     *   < 0  if new_entry  < list_entry
     *   == 0 if new_entry == list_entry (new_entry will be inserted after list_entry)
     *   > 0  if new_entry  > list_entry
     */

    return ((pcep_session *) new_entry)->session_id - ((pcep_session *) list_entry)->session_id;
}


int request_id_compare_function(void *list_entry, void *new_entry)
{
    return ((pcep_message_response *) new_entry)->request_id - ((pcep_message_response *) list_entry)->request_id;
}


bool run_session_logic()
{
    if (session_logic_handle_ != NULL)
    {
        printf("WARN Session Logic is already initialized.\n");
        return false;
    }

    session_logic_handle_ = malloc(sizeof(pcep_session_logic_handle));

    session_logic_handle_->active = true;
    session_logic_handle_->session_logic_condition = false;
    session_logic_handle_->session_list = ordered_list_initialize(session_id_compare_function);
    session_logic_handle_->response_msg_list = ordered_list_initialize(request_id_compare_function);
    session_logic_handle_->session_event_queue = queue_initialize();

    if (!initialize_timers(session_logic_timer_expire_handler))
    {
        fprintf(stderr, "Cannot initialize session_logic timers.\n");
        return false;
    }

    pthread_cond_init(&(session_logic_handle_->session_logic_cond_var), NULL);

    if (pthread_mutex_init(&(session_logic_handle_->session_logic_mutex), NULL) != 0)
    {
        fprintf(stderr, "Cannot initialize session_logic mutex.\n");
        return false;
    }

    if(pthread_create(&(session_logic_handle_->session_logic_thread), NULL, session_logic_loop, session_logic_handle_))
    {
        fprintf(stderr, "Cannot initialize session_logic thread.\n");
        return false;
    }

    return true;
}


bool run_session_logic_wait_for_completion()
{
    if (!run_session_logic())
    {
        return false;
    }

    /* Blocking call, waits for session logic thread to complete */
    pthread_join(session_logic_handle_->session_logic_thread, NULL);

    return true;
}


bool stop_session_logic()
{
    if (session_logic_handle_ == NULL)
    {
        printf("WARN Session logic already stopped\n");
        return false;
    }

    session_logic_handle_->active = false;
    teardown_timers();

    pthread_mutex_lock(&(session_logic_handle_->session_logic_mutex));
    session_logic_handle_->session_logic_condition = true;
    pthread_cond_signal(&(session_logic_handle_->session_logic_cond_var));
    pthread_mutex_unlock(&(session_logic_handle_->session_logic_mutex));
    pthread_join(session_logic_handle_->session_logic_thread, NULL);

    pthread_mutex_destroy(&(session_logic_handle_->session_logic_mutex));
    ordered_list_destroy(session_logic_handle_->session_list);
    ordered_list_destroy(session_logic_handle_->response_msg_list);
    queue_destroy(session_logic_handle_->session_event_queue);

    /* Explicitly stop the socket comm loop started by the pcep_sessions */
    destroy_socket_comm_loop();

    free(session_logic_handle_);
    session_logic_handle_ = NULL;

    return true;
}


void close_pcep_session(pcep_session *session)
{
    close_pcep_session_with_reason(session, PCEP_CLOSE_REASON_NO);
}

void close_pcep_session_with_reason(pcep_session *session, enum pcep_close_reasons reason)
{
    struct pcep_header* close_msg = pcep_msg_create_close(0, reason);
    socket_comm_session_send_message(
            session->socket_comm_session,
            (char *) close_msg,
            ntohs(close_msg->length),
            true);

    printf("[%ld-%ld] pcep_session_logic send pcep_close message len [%d] for session_id [%d]\n",
           time(NULL), pthread_self(), ntohs(close_msg->length), session->session_id);

    socket_comm_session_close_tcp_after_write(session->socket_comm_session);
    session->session_state = SESSION_STATE_INITIALIZED;
}


void destroy_pcep_session(pcep_session *session)
{
    if (session == NULL)
    {
        printf("WARN cannot destroy NULL session\n");
        return;
    }

    if (session->timer_id_dead_timer != TIMER_ID_NOT_SET)
    {
        cancel_timer(session->timer_id_dead_timer);
    }

    if (session->timer_id_keep_alive != TIMER_ID_NOT_SET)
    {
        cancel_timer(session->timer_id_keep_alive);
    }

    if (session->timer_id_open_keep_wait != TIMER_ID_NOT_SET)
    {
        cancel_timer(session->timer_id_open_keep_wait);
    }

    if (session->timer_id_pc_req_wait != TIMER_ID_NOT_SET)
    {
        cancel_timer(session->timer_id_pc_req_wait);
    }

    printf("[%ld-%ld] pcep_session [%d] destroyed\n", time(NULL), pthread_self(), session->session_id);

    socket_comm_session_teardown(session->socket_comm_session);

    free(session);
}


/* Internal util function */
static int get_next_session_id()
{
    if (session_id_ == INT_MAX)
    {
        session_id_ = 0;
    }

    return session_id_++;
}


pcep_session *create_pcep_session(pcep_configuration *config, struct in_addr *pce_ip, short port)
{
    if (config == NULL)
    {
        printf("WARN cannot create pcep session with NULL config\n");
        return NULL;
    }

    if (pce_ip == NULL)
    {
        printf("WARN cannot create pcep session with NULL pce_ip\n");
        return NULL;
    }

    pcep_session *session = malloc(sizeof(pcep_session));
    session->session_id = get_next_session_id();
    session->session_state = SESSION_STATE_INITIALIZED;
    session->timer_id_open_keep_wait = TIMER_ID_NOT_SET;
    session->timer_id_pc_req_wait = TIMER_ID_NOT_SET;
    session->timer_id_dead_timer = TIMER_ID_NOT_SET;
    session->timer_id_keep_alive = TIMER_ID_NOT_SET;
    session->num_erroneous_messages = 0;
    session->pcep_open_received = false;
    session->destroy_session_after_write = false;
    memcpy(&(session->pcc_config), config, sizeof(pcep_configuration));
    /* copy the pcc_config to the pce_config until we receive the open keep_alive response */
    memcpy(&(session->pce_config), config, sizeof(pcep_configuration));

    session->socket_comm_session = socket_comm_session_initialize(
            NULL,
            session_logic_msg_ready_handler,
            session_logic_message_sent_handler,
            session_logic_conn_except_notifier,
            pce_ip,
            port,
            session);
    if (session->socket_comm_session == NULL)
    {
        fprintf(stderr, "Cannot establish socket_comm_session.\n");
        destroy_pcep_session(session);

        return NULL;
    }

    if (!socket_comm_session_connect_tcp(session->socket_comm_session))
    {
        fprintf(stderr, "Cannot establish TCP socket.\n");
        destroy_pcep_session(session);

        return NULL;
    }
    session->session_state = SESSION_STATE_TCP_CONNECTED;

    /* create and send PCEP open
     * with PCEP, the PCC sends the config the PCE should use in the open message,
     * and the PCE will send an open with the config the PCC should use. */
    struct pcep_header* open_msg =
            pcep_msg_create_open(session->pcc_config.keep_alive_seconds,
                                 session->pcc_config.dead_timer_seconds,
                                 session->session_id);
    socket_comm_session_send_message(session->socket_comm_session,
                                     (char *) open_msg,
                                     ntohs(open_msg->length),
                                     true);

    session->timer_id_open_keep_wait = create_timer(config->keep_alive_seconds, session);
    //session->session_state = SESSION_STATE_OPENED;

    return session;
}


pcep_message_response *register_response_message(
        pcep_session *session, int request_id, unsigned int max_wait_time_milli_seconds)
{
    /* the response will be updated in pcep_session_logic_states.c */

    if (session == NULL)
    {
        printf("WARN cannot register with a NULL session\n");
        return NULL;
    }

    if (session_logic_handle_ == NULL)
    {
        printf("WARN cannot register without first running the session logic\n");
        return NULL;
    }

    printf("[%ld-%ld] register_response_message session [%d] request_id [%d] max_wait [%u]\n",
            time(NULL), pthread_self(), session->session_id, request_id, max_wait_time_milli_seconds);

    pcep_message_response *msg_response = malloc(sizeof(pcep_message_response));
    msg_response->session = session;
    msg_response->request_id = request_id;
    msg_response->max_wait_time_milli_seconds = max_wait_time_milli_seconds;
    msg_response->response_msg_list = NULL;
    msg_response->prev_response_status = RESPONSE_STATE_WAITING;
    msg_response->response_status = RESPONSE_STATE_WAITING;
    clock_gettime(CLOCK_REALTIME, &msg_response->time_request_registered);
    msg_response->time_response_received.tv_nsec =
            msg_response->time_response_received.tv_sec = 0;
    msg_response->response_condition = false;
    pthread_mutex_init(&(msg_response->response_mutex), NULL);
    pthread_cond_init(&(msg_response->response_cond_var), NULL);

    /* TODO we should periodically check purge the list of timed-out responses */
    pthread_mutex_lock(&(session_logic_handle_->session_logic_mutex));
    session->session_state = SESSION_STATE_WAIT_PCREQ;
    session->timer_id_pc_req_wait = create_timer(session->pce_config.request_time_seconds, session);
    ordered_list_add_node(session_logic_handle_->response_msg_list, msg_response);
    pthread_mutex_unlock(&(session_logic_handle_->session_logic_mutex));

    return msg_response;
}


void destroy_response_message(pcep_message_response *msg_response)
{
    if (msg_response == NULL)
    {
        printf("WARN cannot destroy a NULL message response\n");
        return;
    }

    if (session_logic_handle_ == NULL)
    {
        printf("WARN cannot destroy a message response without first running the session logic\n");
        return;
    }

    pthread_mutex_destroy(&msg_response->response_mutex);
    pthread_cond_destroy(&msg_response->response_cond_var);
    ordered_list_remove_first_node_equals(session_logic_handle_->response_msg_list, msg_response);

    free(msg_response);
}

/* internal util method to calculate time diffs */
int timespec_diff(struct timespec *start, struct timespec *stop)
{
    int diff_millis;
    if ((stop->tv_nsec - start->tv_nsec) < 0) {
        diff_millis  = (stop->tv_sec  - start->tv_sec - 1) * 1000;
        diff_millis += (stop->tv_nsec - start->tv_nsec + 1000000000) / 1000000;
    } else {
        diff_millis  = (stop->tv_sec  - start->tv_sec) * 1000;
        diff_millis += (stop->tv_nsec - start->tv_nsec) / 1000000;
    }

    return diff_millis;
}


/* internal util method to add times */
void add_millis_toTimespec(struct timespec *ts, int milli_seconds)
{
    static const int SEC_IN_NANOS   = 1000000000;
    static const int MAX_NANO       =  999999999;
    static const int MILLI_IN_NANOS =    1000000;
    static const int SEC_IN_MILLIS  =       1000;
    int seconds1 = 0, seconds2 = 0;
    int nano_seconds = 0;

    if (milli_seconds >= SEC_IN_MILLIS)
    {
        seconds1 = milli_seconds / SEC_IN_MILLIS;
        nano_seconds = (milli_seconds - (seconds1 * SEC_IN_MILLIS)) * MILLI_IN_NANOS;
    }
    else
    {
        nano_seconds = milli_seconds * MILLI_IN_NANOS;
    }

    if ((ts->tv_nsec + nano_seconds) > MAX_NANO)
    {
        seconds2 = (ts->tv_nsec + nano_seconds) / SEC_IN_NANOS;
        nano_seconds = (ts->tv_nsec + nano_seconds) - (seconds2 * SEC_IN_NANOS);
    }
    else
    {
        nano_seconds = ts->tv_nsec + nano_seconds;
    }

    ts->tv_sec += seconds1 + seconds2;
    ts->tv_nsec = nano_seconds;
}


bool query_response_message(pcep_message_response *msg_response)
{
    if (msg_response == NULL)
    {
        printf("WARN query_response_message cannot query with NULL pcep_message_response\n");
        return false;
    }

    pthread_mutex_lock(&msg_response->response_mutex);

    /* if the message is already available, nothing else to do */
    if (msg_response->response_status == RESPONSE_STATE_READY)
    {
        pthread_mutex_unlock(&msg_response->response_mutex);
        return true;
    }

    /* if the status changed, then return true, nothing else to do */
    if (msg_response->response_status != msg_response->prev_response_status)
    {
        pthread_mutex_unlock(&msg_response->response_mutex);

        /* return true that the state changed */
        return true;
    }

    /* check if it timed out */
    struct timespec time_now;
    clock_gettime(CLOCK_REALTIME, &time_now);
    int time_diff_milli_seconds = timespec_diff(&msg_response->time_request_registered, &time_now);
    if (time_diff_milli_seconds >= msg_response->max_wait_time_milli_seconds)
    {
        msg_response->prev_response_status = msg_response->response_status;
        msg_response->response_status = RESPONSE_STATE_TIMED_OUT;
        pthread_mutex_unlock(&msg_response->response_mutex);

        /* return true that the state changed */
        return true;
    }

    pthread_mutex_unlock(&msg_response->response_mutex);

    return false;
}


bool wait_for_response_message(pcep_message_response *msg_response)
{
    if (msg_response == NULL)
    {
        printf("ERROR wait_for_response_message cannot query with NULL pcep_message_response\n");
        return false;
    }

    pthread_mutex_lock(&msg_response->response_mutex);

    /* if the message is already available, nothing else to do */
    if (msg_response->response_status == RESPONSE_STATE_READY)
    {
        pthread_mutex_unlock(&msg_response->response_mutex);
        return true;
    }

    int wait_retval = 0;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    add_millis_toTimespec(&ts, msg_response->max_wait_time_milli_seconds);

    while (!msg_response->response_condition && wait_retval == 0)
    {
        wait_retval = pthread_cond_timedwait(
                &msg_response->response_cond_var, &msg_response->response_mutex, &ts);
    }

    /* if the message is ready, just return now */
    if (msg_response->response_status == RESPONSE_STATE_READY)
    {
        pthread_mutex_unlock(&msg_response->response_mutex);
        return true;
    }

    if (wait_retval != 0)
    {
        if (wait_retval == ETIMEDOUT)
        {
            printf("WARN wait_for_response_message timed_out session [%d] request_id [%d]\n",
                    msg_response->session->session_id, msg_response->request_id);
            msg_response->prev_response_status = msg_response->response_status;
            msg_response->response_status = RESPONSE_STATE_TIMED_OUT;
        }
        else
        {
            printf("WARN wait_for_response_message pthread_cond_timedwait returned error [%d] wait_time [%ld.%09ld] max_wait [%d]\n",
                    wait_retval, ts.tv_sec, ts.tv_nsec, msg_response->max_wait_time_milli_seconds);
        }
    }

    pthread_mutex_unlock(&msg_response->response_mutex);

    return false;
}
