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

/* Session Logic Handle managed in pcep_session_logic.c */
extern pcep_event_queue *session_logic_event_queue_;

bool initialize_pcc()
{
    if (!run_session_logic())
    {
        fprintf(stderr, "Error initializing PCC session logic.\n");
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
        fprintf(stderr, "Error stopping PCC session logic.\n");
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

    return config;
}


pcep_session *connect_pce(pcep_configuration *config, struct in_addr *host)
{
    return connect_pce_with_port(config, host, PCEP_TCP_PORT);
}


pcep_session *connect_pce_with_port(pcep_configuration *config, struct in_addr *host, short port)
{
    return create_pcep_session(config, host, port);
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
        fprintf(stderr, "ERROR: event_queue_is_empty Session Logic is not initialized yet\n");
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
        fprintf(stderr, "ERROR: event_queue_num_events_available Session Logic is not initialized yet\n");
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
        fprintf(stderr, "ERROR: event_queue_get_event Session Logic is not initialized yet\n");
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
        fprintf(stderr, "ERROR: destroy_pcep_event cannot destroy NULL event\n");
        return;
    }

    if (event->event_type == MESSAGE_RECEIVED && event->message != NULL)
    {
        pcep_msg_free_message(event->message);
    }

    free(event);
}

