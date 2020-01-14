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
#include "pcep_session_logic_internals.h"
#include "pcep_timers.h"
#include "pcep_utils_ordered_list.h"
#include "pcep_utils_logging.h"

/*
 * public API function implementations for the session_logic
 */

pcep_session_logic_handle *session_logic_handle_ = NULL;
pcep_event_queue *session_logic_event_queue_ = NULL;
int session_id_ = 0;

void create_and_send_open(pcep_session *session); /* forward decl */

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
        pcep_log(LOG_WARNING, "Session Logic is already initialized.\n");
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
        pcep_log(LOG_ERR, "Cannot initialize session_logic event queue mutex.\n");
        return false;
    }

    if (!initialize_timers(session_logic_timer_expire_handler))
    {
        pcep_log(LOG_ERR, "Cannot initialize session_logic timers.\n");
        return false;
    }

    pthread_cond_init(&(session_logic_handle_->session_logic_cond_var), NULL);

    if (pthread_mutex_init(&(session_logic_handle_->session_logic_mutex), NULL) != 0)
    {
        pcep_log(LOG_ERR, "Cannot initialize session_logic mutex.\n");
        return false;
    }

    if(pthread_create(&(session_logic_handle_->session_logic_thread), NULL, session_logic_loop, session_logic_handle_))
    {
        pcep_log(LOG_ERR, "Cannot initialize session_logic thread.\n");
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
        pcep_log(LOG_WARNING, "Session logic already stopped\n");
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

void close_pcep_session_with_reason(pcep_session *session, enum pcep_close_reasons reason)
{
    struct pcep_message* close_msg = pcep_msg_create_close(0, reason);

    pcep_log(LOG_INFO, "[%ld-%ld] pcep_session_logic send pcep_close message len [%d] for session_id [%d]\n",
           time(NULL), pthread_self(), close_msg->header->length, session->session_id);

    session_send_message(session, close_msg);
    socket_comm_session_close_tcp_after_write(session->socket_comm_session);
    session->session_state = SESSION_STATE_INITIALIZED;
}


void destroy_pcep_session(pcep_session *session)
{
    if (session == NULL)
    {
        pcep_log(LOG_WARNING, "Cannot destroy NULL session\n");
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

    queue_destroy_with_data(session->num_unknown_messages_time_queue);

    pcep_log(LOG_INFO, "[%ld-%ld] pcep_session [%d] destroyed\n", time(NULL), pthread_self(), session->session_id);

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


pcep_session *create_pcep_session(pcep_configuration *config, struct in_addr *pce_ip)
{
    if (config == NULL)
    {
        pcep_log(LOG_WARNING, "Cannot create pcep session with NULL config\n");
        return NULL;
    }

    if (pce_ip == NULL)
    {
        pcep_log(LOG_WARNING, "Cannot create pcep session with NULL pce_ip\n");
        return NULL;
    }

    pcep_session *session = malloc(sizeof(pcep_session));
    session->session_id = get_next_session_id();
    session->session_state = SESSION_STATE_INITIALIZED;
    session->timer_id_open_keep_wait = TIMER_ID_NOT_SET;
    session->timer_id_pc_req_wait = TIMER_ID_NOT_SET;
    session->timer_id_dead_timer = TIMER_ID_NOT_SET;
    session->timer_id_keep_alive = TIMER_ID_NOT_SET;
    session->stateful_pce = false;
    session->num_unknown_messages_time_queue = queue_initialize();
    session->pcep_open_received = false;
    session->pcep_open_rejected = false;
    session->destroy_session_after_write = false;
    session->lsp_db_version = config->lsp_db_version;
    memcpy(&(session->pcc_config), config, sizeof(pcep_configuration));
    /* copy the pcc_config to the pce_config until we receive the open keep_alive response */
    memcpy(&(session->pce_config), config, sizeof(pcep_configuration));

    session->socket_comm_session = socket_comm_session_initialize_with_src(
            NULL,
            session_logic_msg_ready_handler,
            session_logic_message_sent_handler,
            session_logic_conn_except_notifier,
            config->src_ip,
            ((config->src_pcep_port == 0) ? PCEP_TCP_PORT : config->src_pcep_port),
            pce_ip,
            ((config->dst_pcep_port == 0) ? PCEP_TCP_PORT : config->dst_pcep_port),
            config->socket_connect_timeout_millis,
            session);
    if (session->socket_comm_session == NULL)
    {
        pcep_log(LOG_WARNING, "Cannot establish socket_comm_session.\n");
        destroy_pcep_session(session);

        return NULL;
    }

    if (!socket_comm_session_connect_tcp(session->socket_comm_session))
    {
        pcep_log(LOG_WARNING, "Cannot establish TCP socket.\n");
        destroy_pcep_session(session);

        return NULL;
    }
    session->session_state = SESSION_STATE_TCP_CONNECTED;

    create_and_send_open(session);

    session->timer_id_open_keep_wait = create_timer(config->keep_alive_seconds, session);
    //session->session_state = SESSION_STATE_OPENED;

    return session;
}


void session_send_message(pcep_session *session, struct pcep_message *message)
{
    pcep_msg_encode(message);
    socket_comm_session_send_message(
            session->socket_comm_session,
            (char *) message->header,
            ntohs(message->header->length),
            true);

    /* The message->header will be freed in
     * socket_comm_session_send_message() once sent */
    dll_destroy(message->obj_list);
    free(message);
}


void create_and_send_open(pcep_session *session)
{
    /* create and send PCEP open
     * with PCEP, the PCC sends the config the PCE should use in the open message,
     * and the PCE will send an open with the config the PCC should use. */
    double_linked_list *tlv_list = dll_initialize();
    uint8_t stateful_tlv_flags = 0;
    if (session->pcc_config.support_stateful_pce_lsp_update)
    {
        stateful_tlv_flags |= PCEP_TLV_FLAG_LSP_UPDATE_CAPABILITY;
    }
    if (session->pcc_config.support_pce_lsp_instantiation)
    {
        stateful_tlv_flags |= PCEP_TLV_FLAG_LSP_INSTANTIATION;
    }
    if (session->pcc_config.support_include_db_version)
    {
        stateful_tlv_flags |= PCEP_TLV_FLAG_INCLUDE_DB_VERSION;
        if (session->pcc_config.lsp_db_version != 0)
        {
            dll_append(tlv_list,
                    pcep_tlv_create_lsp_db_version(session->pcc_config.lsp_db_version));
        }
    }
    if (session->pcc_config.support_lsp_triggered_resync)
    {
        stateful_tlv_flags |= PCEP_TLV_FLAG_TRIGGERED_RESYNC;
    }
    if (session->pcc_config.support_lsp_delta_sync)
    {
        stateful_tlv_flags |= PCEP_TLV_FLAG_DELTA_LSP_SYNC;
    }
    if (session->pcc_config.support_pce_triggered_initial_sync)
    {
        stateful_tlv_flags |= PCEP_TLV_FLAG_TRIGGERED_INITIAL_SYNC;
    }

    if (stateful_tlv_flags != 0)
    {
        /* Prepend this TLV as the first in the list */
        dll_prepend(tlv_list,
            pcep_tlv_create_stateful_pce_capability(stateful_tlv_flags));
    }

    if (session->pcc_config.support_sr_te_pst)
    {
        uint8_t flags = 0;
        if (session->pcc_config.use_pcep_sr_draft07 == false)
        {
            flags = (session->pcc_config.pcc_can_resolve_nai_to_sid == true ?
                    PCEP_TLV_FLAG_SR_PCE_CAPABILITY_NAI : 0);
            flags |= (session->pcc_config.max_sid_depth == 0 ?
                    PCEP_TLV_FLAG_NO_MSD_LIMITS : 0);
        }

        struct pcep_object_tlv *sr_pce_cap_tlv =
                pcep_tlv_create_sr_pce_capability(flags, session->pcc_config.max_sid_depth);
        double_linked_list *sub_tlv_list = NULL;

        if (session->pcc_config.use_pcep_sr_draft07)
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

        uint8_t pst = SR_TE_PST;
        double_linked_list *pst_list = dll_initialize();
        dll_append(pst_list, &pst);
        dll_append(tlv_list, pcep_tlv_create_path_setup_type_capability(pst_list, sub_tlv_list));
        dll_destroy(pst_list);
        dll_destroy_with_data(sub_tlv_list);
    }

    struct pcep_message *open_msg;
    if (tlv_list->num_entries > 0)
    {
        open_msg = pcep_msg_create_open_with_tlvs(
                session->pcc_config.keep_alive_seconds,
                session->pcc_config.dead_timer_seconds,
                session->session_id,
                tlv_list);
    }
    else
    {
        open_msg = pcep_msg_create_open(session->pcc_config.keep_alive_seconds,
                                        session->pcc_config.dead_timer_seconds,
                                        session->session_id);
    }

    pcep_log(LOG_INFO, "[%ld-%ld] pcep_session_logic send open message: TLVs [%d] len [%d] for session_id [%d]\n",
            time(NULL), pthread_self(), tlv_list->num_entries, open_msg->header->length, session->session_id);

    dll_destroy_with_data(tlv_list);

    session_send_message(session, open_msg);
}
