/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */


#include <errno.h>
#include <limits.h>
#include <malloc.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "pcep-encoding.h"
#include "pcep_session_logic.h"
#include "pcep_session_logic_internals.h"
#include "pcep_timers.h"
#include "pcep_utils_counters.h"
#include "pcep_utils_ordered_list.h"
#include "pcep_utils_logging.h"

/*
 * public API function implementations for the session_logic
 */

pcep_session_logic_handle *session_logic_handle_ = NULL;
pcep_event_queue *session_logic_event_queue_ = NULL;
int session_id_ = 0;

void send_pcep_open(pcep_session *session); /* forward decl */

int session_id_compare_function(void *list_entry, void *new_entry)
{
    /* return:
     *   < 0  if new_entry  < list_entry
     *   == 0 if new_entry == list_entry (new_entry will be inserted after list_entry)
     *   > 0  if new_entry  > list_entry
     */

    return ((pcep_session *) new_entry)->session_id - ((pcep_session *) list_entry)->session_id;
}


bool run_session_logic()
{
    if (session_logic_handle_ != NULL)
    {
        pcep_log(LOG_WARNING, "Session Logic is already initialized.");
        return false;
    }

    session_logic_handle_ = malloc(sizeof(pcep_session_logic_handle));
    bzero(session_logic_handle_, sizeof(pcep_session_logic_handle));

    session_logic_handle_->active = true;
    session_logic_handle_->session_logic_condition = false;
    session_logic_handle_->session_list = ordered_list_initialize(session_id_compare_function);
    session_logic_handle_->session_event_queue = queue_initialize();

    /* Initialize the event queue */
    session_logic_event_queue_ = malloc(sizeof(pcep_event_queue));
    session_logic_event_queue_->event_queue = queue_initialize();
    if (pthread_mutex_init(&(session_logic_event_queue_->event_queue_mutex), NULL) != 0)
    {
        pcep_log(LOG_ERR, "Cannot initialize session_logic event queue mutex.");
        return false;
    }

    if (!initialize_timers(session_logic_timer_expire_handler))
    {
        pcep_log(LOG_ERR, "Cannot initialize session_logic timers.");
        return false;
    }

    pthread_cond_init(&(session_logic_handle_->session_logic_cond_var), NULL);

    if (pthread_mutex_init(&(session_logic_handle_->session_logic_mutex), NULL) != 0)
    {
        pcep_log(LOG_ERR, "Cannot initialize session_logic mutex.");
        return false;
    }

    if(pthread_create(&(session_logic_handle_->session_logic_thread), NULL, session_logic_loop, session_logic_handle_))
    {
        pcep_log(LOG_ERR, "Cannot initialize session_logic thread.");
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
        pcep_log(LOG_WARNING, "Session logic already stopped");
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
    queue_destroy(session_logic_handle_->session_event_queue);

    /* destroy the event_queue */
    pthread_mutex_destroy(&(session_logic_event_queue_->event_queue_mutex));
    queue_destroy(session_logic_event_queue_->event_queue);
    free(session_logic_event_queue_);

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

void close_pcep_session_with_reason(pcep_session *session, enum pcep_close_reason reason)
{
    struct pcep_message* close_msg = pcep_msg_create_close(reason);

    pcep_log(LOG_INFO, "[%ld-%ld] pcep_session_logic send pcep_close message for session_id [%d]",
           time(NULL), pthread_self(), session->session_id);

    session_send_message(session, close_msg);
    socket_comm_session_close_tcp_after_write(session->socket_comm_session);
    session->session_state = SESSION_STATE_INITIALIZED;
}


void destroy_pcep_session(pcep_session *session)
{
    if (session == NULL)
    {
        pcep_log(LOG_WARNING, "Cannot destroy NULL session");
        return;
    }

    pcep_session_cancel_timers(session);

    delete_counters_group(session->pcep_session_counters);

    queue_destroy_with_data(session->num_unknown_messages_time_queue);

    pcep_log(LOG_INFO, "[%ld-%ld] pcep_session [%d] destroyed", time(NULL), pthread_self(), session->session_id);

    socket_comm_session_teardown(session->socket_comm_session);

    if (session->pcc_config.pcep_msg_versioning != NULL)
    {
        free(session->pcc_config.pcep_msg_versioning);
    }

    if (session->pce_config.pcep_msg_versioning != NULL)
    {
        free(session->pce_config.pcep_msg_versioning);
    }

    free(session);
}

void pcep_session_cancel_timers(pcep_session *session)
{
    if (session == NULL)
    {
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

/* Internal util function */
static pcep_session *create_pcep_session_pre_setup(pcep_configuration *config)
{
    if (config == NULL)
    {
        pcep_log(LOG_WARNING, "Cannot create pcep session with NULL config");
        return NULL;
    }

    pcep_session *session = malloc(sizeof(pcep_session));
    memset(session, 0, sizeof(pcep_session));
    session->session_id = get_next_session_id();
    session->session_state = SESSION_STATE_INITIALIZED;
    session->timer_id_open_keep_wait = TIMER_ID_NOT_SET;
    session->timer_id_pc_req_wait = TIMER_ID_NOT_SET;
    session->timer_id_dead_timer = TIMER_ID_NOT_SET;
    session->timer_id_keep_alive = TIMER_ID_NOT_SET;
    session->stateful_pce = false;
    session->num_unknown_messages_time_queue = queue_initialize();
    session->pce_open_received = false;
    session->pce_open_rejected = false;
    session->pcc_open_rejected = false;
    session->pce_open_accepted = false;
    session->pcc_open_accepted = false;
    session->destroy_session_after_write = false;
    session->lsp_db_version = config->lsp_db_version;
    memcpy(&(session->pcc_config), config, sizeof(pcep_configuration));
    /* copy the pcc_config to the pce_config until we receive the open keep_alive response */
    memcpy(&(session->pce_config), config, sizeof(pcep_configuration));
    if (config->pcep_msg_versioning != NULL)
    {
        session->pcc_config.pcep_msg_versioning = malloc(sizeof(struct pcep_versioning));
        memcpy(session->pcc_config.pcep_msg_versioning, config->pcep_msg_versioning, sizeof(struct pcep_versioning));
        session->pce_config.pcep_msg_versioning = malloc(sizeof(struct pcep_versioning));
        memcpy(session->pce_config.pcep_msg_versioning, config->pcep_msg_versioning, sizeof(struct pcep_versioning));
    }

    return session;
}

/* Internal util function */
static bool create_pcep_session_post_setup(pcep_session *session)
{
    if (!socket_comm_session_connect_tcp(session->socket_comm_session))
    {
        pcep_log(LOG_WARNING, "Cannot establish TCP socket.");
        destroy_pcep_session(session);

        return false;
    }

    session->time_connected = time(NULL);
    create_session_counters(session);

    send_pcep_open(session);

    session->session_state = SESSION_STATE_PCEP_CONNECTING;
    session->timer_id_open_keep_wait = create_timer(session->pcc_config.keep_alive_seconds, session);
    //session->session_state = SESSION_STATE_OPENED;

    return true;
}

pcep_session *create_pcep_session(pcep_configuration *config, struct in_addr *pce_ip)
{
    if (pce_ip == NULL)
    {
        pcep_log(LOG_WARNING, "Cannot create pcep session with NULL pce_ip");
        return NULL;
    }

    pcep_session *session = create_pcep_session_pre_setup(config);
    if (session == NULL)
    {
        return NULL;
    }

    session->socket_comm_session = socket_comm_session_initialize_with_src(
            NULL,
            session_logic_msg_ready_handler,
            session_logic_message_sent_handler,
            session_logic_conn_except_notifier,
            &(config->src_ip.src_ipv4),
            ((config->src_pcep_port == 0) ? PCEP_TCP_PORT : config->src_pcep_port),
            pce_ip,
            ((config->dst_pcep_port == 0) ? PCEP_TCP_PORT : config->dst_pcep_port),
            config->socket_connect_timeout_millis,
            session);
    if (session->socket_comm_session == NULL)
    {
        pcep_log(LOG_WARNING, "Cannot establish socket_comm_session.");
        destroy_pcep_session(session);

        return NULL;
    }

    if (create_pcep_session_post_setup(session) == false)
    {
        return NULL;
    }

    return session;
}

pcep_session *create_pcep_session_ipv6(pcep_configuration *config, struct in6_addr *pce_ip)
{
    if (pce_ip == NULL)
    {
        pcep_log(LOG_WARNING, "Cannot create pcep session with NULL pce_ip");
        return NULL;
    }

    pcep_session *session = create_pcep_session_pre_setup(config);
    if (session == NULL)
    {
        return NULL;
    }

    session->socket_comm_session = socket_comm_session_initialize_with_src_ipv6(
            NULL,
            session_logic_msg_ready_handler,
            session_logic_message_sent_handler,
            session_logic_conn_except_notifier,
            &(config->src_ip.src_ipv6),
            ((config->src_pcep_port == 0) ? PCEP_TCP_PORT : config->src_pcep_port),
            pce_ip,
            ((config->dst_pcep_port == 0) ? PCEP_TCP_PORT : config->dst_pcep_port),
            config->socket_connect_timeout_millis,
            session);
    if (session->socket_comm_session == NULL)
    {
        pcep_log(LOG_WARNING, "Cannot establish ipv6 socket_comm_session.");
        destroy_pcep_session(session);

        return NULL;
    }

    if (create_pcep_session_post_setup(session) == false)
    {
        return NULL;
    }

    return session;
}


void session_send_message(pcep_session *session, struct pcep_message *message)
{
    pcep_encode_message(message, session->pcc_config.pcep_msg_versioning);
    socket_comm_session_send_message(
            session->socket_comm_session,
            (char *) message->encoded_message,
            message->encoded_message_length,
            true);

    increment_message_tx_counters(session, message);

    /* The message->encoded_message will be freed in
     * socket_comm_session_send_message() once sent.
     * Setting to NULL here so pcep_msg_free_message() does not free it */
    message->encoded_message = NULL;
    pcep_msg_free_message(message);
}


/* This function is also used in pcep_session_logic_states.c */
struct pcep_message *create_pcep_open(pcep_session *session)
{
    /* create and send PCEP open
     * with PCEP, the PCC sends the config the PCE should use in the open message,
     * and the PCE will send an open with the config the PCC should use. */
    double_linked_list *tlv_list = dll_initialize();
    if (session->pcc_config.support_stateful_pce_lsp_update ||
        session->pcc_config.support_pce_lsp_instantiation ||
        session->pcc_config.support_include_db_version ||
        session->pcc_config.support_lsp_triggered_resync ||
        session->pcc_config.support_lsp_delta_sync ||
        session->pcc_config.support_pce_triggered_initial_sync)
    {
        /* Prepend this TLV as the first in the list */
        dll_append(tlv_list,
            pcep_tlv_create_stateful_pce_capability(
                    session->pcc_config.support_stateful_pce_lsp_update,     /* U flag */
                    session->pcc_config.support_include_db_version,          /* S flag */
                    session->pcc_config.support_lsp_triggered_resync,        /* T flag */
                    session->pcc_config.support_lsp_delta_sync,              /* D flag */
                    session->pcc_config.support_pce_triggered_initial_sync,  /* F flag */
                    session->pcc_config.support_pce_lsp_instantiation));     /* I flag */
    }

    if (session->pcc_config.support_include_db_version)
    {
        if (session->pcc_config.lsp_db_version != 0)
        {
            dll_append(tlv_list,
                    pcep_tlv_create_lsp_db_version(session->pcc_config.lsp_db_version));
        }
    }

    if (session->pcc_config.support_sr_te_pst)
    {
        bool flag_n = false;
        bool flag_x = false;
        if (session->pcc_config.pcep_msg_versioning->draft_ietf_pce_segment_routing_07 == false)
        {
            flag_n = session->pcc_config.pcc_can_resolve_nai_to_sid;
            flag_x = (session->pcc_config.max_sid_depth == 0);
        }

        struct pcep_object_tlv_sr_pce_capability *sr_pce_cap_tlv =
                pcep_tlv_create_sr_pce_capability(
                        flag_n, flag_x, session->pcc_config.max_sid_depth);

        double_linked_list *sub_tlv_list = NULL;
        if (session->pcc_config.pcep_msg_versioning->draft_ietf_pce_segment_routing_07 == true)
        {
            /* With draft07, send the sr_pce_cap_tlv as a normal TLV */
            dll_append(tlv_list, sr_pce_cap_tlv);
        }
        else
        {
            /* With draft16, send the sr_pce_cap_tlv as a sub-TLV in the
             * path_setup_type_capability TLV */
            sub_tlv_list = dll_initialize();
            dll_append(sub_tlv_list, sr_pce_cap_tlv);
        }

        uint8_t *pst = malloc(sizeof(uint8_t));
        *pst = SR_TE_PST;
        double_linked_list *pst_list = dll_initialize();
        dll_append(pst_list, pst);
        dll_append(tlv_list, pcep_tlv_create_path_setup_type_capability(pst_list, sub_tlv_list));
    }

    struct pcep_message *open_msg = pcep_msg_create_open_with_tlvs(
            session->pcc_config.keep_alive_seconds,
            session->pcc_config.dead_timer_seconds,
            session->session_id,
            tlv_list);

    pcep_log(LOG_INFO, "[%ld-%ld] pcep_session_logic send open message: TLVs [%d] for session_id [%d]",
            time(NULL), pthread_self(), tlv_list->num_entries, session->session_id);

    return(open_msg);
}


void send_pcep_open(pcep_session *session)
{
    session_send_message(session, create_pcep_open(session));
}
