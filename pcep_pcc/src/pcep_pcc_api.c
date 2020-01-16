/*
 * pcep_pcc_api.c
 *
 *  Created on: sep 27, 2019
 *      Author: brady
 */

#include <malloc.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "pcep-messages.h"
#include "pcep_pcc_api.h"
#include "pcep_utils_logging.h"

/* Not using an array here since the enum pcep_event_type indeces go into the 100's */
const char MESSAGE_RECEIVED_STR[] = "MESSAGE_RECEIVED";
const char PCE_CLOSED_SOCKET_STR[] = "PCE_CLOSED_SOCKET";
const char PCE_SENT_PCEP_CLOSE_STR[] = "PCE_SENT_PCEP_CLOSE";
const char PCE_DEAD_TIMER_EXPIRED_STR[] = "PCE_DEAD_TIMER_EXPIRED";
const char PCE_OPEN_KEEP_WAIT_TIMER_EXPIRED_STR[] = "PCE_OPEN_KEEP_WAIT_TIMER_EXPIRED";
const char PCC_CONNECTED_TO_PCE_STR[] = "PCC_CONNECTED_TO_PCE";
const char PCC_PCEP_SESSION_CLOSED_STR[] = "PCC_PCEP_SESSION_CLOSED";
const char PCC_RCVD_INVALID_OPEN_STR[] = "PCC_RCVD_INVALID_OPEN";
const char PCC_RCVD_MAX_INVALID_MSGS_STR[] = "PCC_RCVD_MAX_INVALID_MSGS";
const char PCC_RCVD_MAX_UNKOWN_MSGS_STR[] = "PCC_RCVD_MAX_UNKOWN_MSGS";
const char UNKNOWN_EVENT_STR[] = "UNKNOWN Event Type";

/* Session Logic Handle managed in pcep_session_logic.c */
extern pcep_event_queue *session_logic_event_queue_;

bool initialize_pcc()
{
    if (!run_session_logic())
    {
        pcep_log(LOG_ERR, "Error initializing PCC session logic.\n");
        return false;
    }

    return true;
}


/* this function is blocking */
bool initialize_pcc_wait_for_completion()
{
    return run_session_logic_wait_for_completion();
}


bool destroy_pcc()
{
    if (!stop_session_logic())
    {
        pcep_log(LOG_WARNING, "Error stopping PCC session logic.\n");
        return false;
    }

    return true;
}


pcep_configuration *create_default_pcep_configuration()
{
    pcep_configuration *config = malloc(sizeof(pcep_configuration));
    config->keep_alive_seconds = DEFAULT_CONFIG_KEEP_ALIVE;
    config->min_keep_alive_seconds = DEFAULT_MIN_CONFIG_KEEP_ALIVE;
    config->max_keep_alive_seconds = DEFAULT_MAX_CONFIG_KEEP_ALIVE;

    config->dead_timer_seconds = DEFAULT_CONFIG_DEAD_TIMER;
    config->min_dead_timer_seconds = DEFAULT_MIN_CONFIG_DEAD_TIMER;
    config->max_dead_timer_seconds = DEFAULT_MAX_CONFIG_DEAD_TIMER;

    config->request_time_seconds = DEFAULT_CONFIG_REQUEST_TIME;
    config->max_unknown_messages = DEFAULT_CONFIG_MAX_UNKNOWN_MESSAGES;
    config->max_unknown_requests = DEFAULT_CONFIG_MAX_UNKNOWN_REQUESTS;

    config->socket_connect_timeout_millis = DEFAULT_TCP_CONNECT_TIMEOUT_MILLIS;
    config->support_stateful_pce_lsp_update = true;
    config->support_pce_lsp_instantiation = true;
    config->support_include_db_version = true;
    config->lsp_db_version = 0;
    config->support_lsp_triggered_resync = true;
    config->support_lsp_delta_sync = true;
    config->support_pce_triggered_initial_sync = true;
    config->support_sr_te_pst = true;
    config->pcc_can_resolve_nai_to_sid = true;
    config->max_sid_depth = 0;
    config->use_pcep_sr_draft07 = false;
    config->dst_pcep_port = 0;
    config->src_pcep_port = 0;
    config->src_ip.s_addr = INADDR_ANY;

    return config;
}

void destroy_pcep_configuration(pcep_configuration *config)
{
    free(config);
}

pcep_session *connect_pce(pcep_configuration *config, struct in_addr *pce_ip)
{
    return create_pcep_session(config, pce_ip);
}

void disconnect_pce(pcep_session *session)
{
    /* This will cause the session to be destroyed AFTER the close message is sent */
    session->destroy_session_after_write = true;

    /* Send a PCEP close message */
    close_pcep_session(session);
}

void send_message(pcep_session *session, struct pcep_message *msg, bool free_after_send)
{
    pcep_msg_encode(msg);
    socket_comm_session_send_message(session->socket_comm_session,
            (char *) msg->header, ntohs(msg->header->length), free_after_send);

    if (free_after_send == true)
    {
        dll_destroy(msg->obj_list);
        free(msg);
    }
}

/* Returns true if the queue is empty, false otherwise */
bool event_queue_is_empty()
{
    if (session_logic_event_queue_ == NULL)
    {
        pcep_log(LOG_WARNING, "event_queue_is_empty Session Logic is not initialized yet\n");
        return false;
    }

    pthread_mutex_lock(&session_logic_event_queue_->event_queue_mutex);
    bool is_empty = (session_logic_event_queue_->event_queue->num_entries == 0);
    pthread_mutex_unlock(&session_logic_event_queue_->event_queue_mutex);

    return is_empty;
}


/* Return the number of events on the queue, 0 if empty */
uint32_t event_queue_num_events_available()
{
    if (session_logic_event_queue_ == NULL)
    {
        pcep_log(LOG_WARNING, "event_queue_num_events_available Session Logic is not initialized yet\n");
        return 0;
    }

    pthread_mutex_lock(&session_logic_event_queue_->event_queue_mutex);
    uint32_t num_events =  session_logic_event_queue_->event_queue->num_entries;
    pthread_mutex_unlock(&session_logic_event_queue_->event_queue_mutex);

    return num_events;
}


/* Return the next event on the queue, NULL if empty */
struct pcep_event *event_queue_get_event()
{
    if (session_logic_event_queue_ == NULL)
    {
        pcep_log(LOG_WARNING, "event_queue_get_event Session Logic is not initialized yet\n");
        return NULL;
    }

    pthread_mutex_lock(&session_logic_event_queue_->event_queue_mutex);
    struct pcep_event *event =
            (struct pcep_event *) queue_dequeue(session_logic_event_queue_->event_queue);
    pthread_mutex_unlock(&session_logic_event_queue_->event_queue_mutex);

    return event;
}


/* Free the PCEP Event resources, including the PCEP message */
void destroy_pcep_event(struct pcep_event *event)
{
    if (event == NULL)
    {
        pcep_log(LOG_WARNING, "destroy_pcep_event cannot destroy NULL event\n");
        return;
    }

    if (event->event_type == MESSAGE_RECEIVED && event->message != NULL)
    {
        pcep_msg_free_message(event->message);
    }

    free(event);
}

const char *get_event_type_str(int event_type)
{
    switch(event_type)
    {
    case MESSAGE_RECEIVED:
        return MESSAGE_RECEIVED_STR;
        break;
    case PCE_CLOSED_SOCKET:
        return PCE_CLOSED_SOCKET_STR;
        break;
    case PCE_SENT_PCEP_CLOSE:
        return PCE_SENT_PCEP_CLOSE_STR;
        break;
    case PCE_DEAD_TIMER_EXPIRED:
        return PCE_DEAD_TIMER_EXPIRED_STR;
        break;
    case PCE_OPEN_KEEP_WAIT_TIMER_EXPIRED:
        return PCE_OPEN_KEEP_WAIT_TIMER_EXPIRED_STR;
        break;
    case PCC_CONNECTED_TO_PCE:
        return PCC_CONNECTED_TO_PCE_STR;
        break;
    case PCC_PCEP_SESSION_CLOSED:
        return PCC_PCEP_SESSION_CLOSED_STR;
        break;
    case PCC_RCVD_INVALID_OPEN:
        return PCC_RCVD_INVALID_OPEN_STR;
        break;
    case PCC_RCVD_MAX_INVALID_MSGS:
        return PCC_RCVD_MAX_INVALID_MSGS_STR;
        break;
    case PCC_RCVD_MAX_UNKOWN_MSGS:
        return PCC_RCVD_MAX_UNKOWN_MSGS_STR;
        break;
    default:
        return UNKNOWN_EVENT_STR;
        break;
    }
}
