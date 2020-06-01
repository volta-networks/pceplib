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


#include <malloc.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "pcep-encoding.h"
#include "pcep_session_logic.h"
#include "pcep_session_logic_internals.h"
#include "pcep_timers.h"
#include "pcep_utils_logging.h"


/* Session Logic Handle managed in pcep_session_logic.c */
extern pcep_event_queue *session_logic_event_queue_;

/*
 * util functions called by the state handling below
 */

void send_keep_alive(pcep_session *session)
{
    struct pcep_message *keep_alive_msg = pcep_msg_create_keepalive();

    pcep_log(LOG_INFO, "[%ld-%ld] pcep_session_logic send keep_alive message for session_id [%d]",
            time(NULL), pthread_self(), session->session_id);

    session_send_message(session, keep_alive_msg);

    /* The keep alive timer will be (re)set once the message
     * is sent in session_logic_message_sent_handler() */
}


/* Send an error message with the corrected or offending object */
void send_pcep_error_with_object(pcep_session *session, enum pcep_error_type error_type,
        enum pcep_error_value error_value, struct pcep_object_header *object)
{
    double_linked_list *obj_list = dll_initialize();
    dll_append(obj_list, object);
    struct pcep_message *error_msg = pcep_msg_create_error_with_objects(error_type, error_value, obj_list);

    pcep_log(LOG_INFO, "[%ld-%ld] pcep_session_logic send error message with object [%d][%d] for session_id [%d]",
            time(NULL), pthread_self(), error_type, error_value, session->session_id);

    session_send_message(session, error_msg);
}


void send_pcep_error(pcep_session *session, enum pcep_error_type error_type, enum pcep_error_value error_value)
{
    struct pcep_message *error_msg = pcep_msg_create_error(error_type, error_value);

    pcep_log(LOG_INFO, "[%ld-%ld] pcep_session_logic send error message [%d][%d] for session_id [%d]",
            time(NULL), pthread_self(), error_type, error_value, session->session_id);

    session_send_message(session, error_msg);
}


void reset_dead_timer(pcep_session *session)
{
    if (session->timer_id_dead_timer == TIMER_ID_NOT_SET)
    {
        pcep_log(LOG_INFO, "[%ld-%ld] pcep_session_logic set dead timer [%d secs] for session_id [%d]",
                time(NULL), pthread_self(), session->pce_config.dead_timer_seconds, session->session_id);
        session->timer_id_dead_timer = create_timer(session->pce_config.dead_timer_seconds, session);
    }
    else
    {
        pcep_log(LOG_INFO, "[%ld-%ld] pcep_session_logic reset dead timer [%d secs] for session_id [%d]",
                time(NULL), pthread_self(), session->pce_config.dead_timer_seconds, session->session_id);
        reset_timer(session->timer_id_dead_timer);
    }
}


void enqueue_event(pcep_session *session, pcep_event_type event_type, struct pcep_message *message)
{
    if (event_type == MESSAGE_RECEIVED && message == NULL)
    {
        pcep_log(LOG_WARNING, "enqueue_event cannot enqueue a NULL message");
        return;
    }

    pcep_event *event = malloc(sizeof(pcep_event));
    bzero(event, sizeof(pcep_event));

    event->session = session;
    event->event_type = event_type;
    event->event_time = time(NULL);
    event->message = message;

    pthread_mutex_lock(&session_logic_event_queue_->event_queue_mutex);
    queue_enqueue(session_logic_event_queue_->event_queue, event);
    pthread_mutex_unlock(&session_logic_event_queue_->event_queue_mutex);
}

/* Verify the received PCEP Open object parameters are acceptable. If not,
 * update the unacceptable value(s) with an acceptable value so it can be sent
 * back to the sender. */
bool verify_pcep_open_object(pcep_session *session, struct pcep_object_open *open_object)
{
    int retval = true;

    if (open_object->open_keepalive < session->pcc_config.min_keep_alive_seconds)
    {
        pcep_log(LOG_INFO, "Rejecting unsupported Open Keep Alive value [%d] min [%d]",
               open_object->open_keepalive, session->pcc_config.min_keep_alive_seconds);
        open_object->open_keepalive =
                session->pcc_config.min_keep_alive_seconds;
        retval = false;
    }
    else if (open_object->open_keepalive > session->pcc_config.max_keep_alive_seconds)
    {
        pcep_log(LOG_INFO, "Rejecting unsupported Open Keep Alive value [%d] max [%d]",
               open_object->open_keepalive, session->pcc_config.max_keep_alive_seconds);
        open_object->open_keepalive =
                session->pcc_config.max_keep_alive_seconds;
        retval = false;
    }

    if (open_object->open_deadtimer < session->pcc_config.min_dead_timer_seconds)
    {
        pcep_log(LOG_INFO, "Rejecting unsupported Open Dead Timer value [%d]",
               open_object->open_deadtimer);
        open_object->open_deadtimer =
                session->pcc_config.min_dead_timer_seconds;
        retval = false;
    }
    else if (open_object->open_deadtimer > session->pcc_config.max_dead_timer_seconds)
    {
        pcep_log(LOG_INFO, "Rejecting unsupported Open Dead Timer value [%d]",
               open_object->open_deadtimer);
        open_object->open_deadtimer =
                session->pcc_config.max_dead_timer_seconds;
        retval = false;
    }

    /* Check for Open Object TLVs */
    if (pcep_object_has_tlvs((struct pcep_object_header*) open_object) == false)
    {
        /* There are no TLVs, all done */
        return retval;
    }

    double_linked_list_node *tlv_node = open_object->header.tlv_list->head;
    while (tlv_node != NULL)
    {
        struct pcep_object_tlv_header *tlv = tlv_node->data;
        tlv_node = tlv_node->next_node;

        /* Supported Open Object TLVs */
        switch (tlv->type)
        {
        case PCEP_OBJ_TLV_TYPE_LSP_DB_VERSION:
        case PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE_CAPABILITY:
        case PCEP_OBJ_TLV_TYPE_SPEAKER_ENTITY_ID:
        case PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY:
        case PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY:
            break;

        default:
            /* TODO how to handle unrecognized TLV ?? */
            pcep_log(LOG_INFO, "Unhandled OPEN Object TLV type: %d, length %d",
                    tlv->type, tlv->encoded_tlv_length);
            break;
        }

        /* Verify the STATEFUL-PCE-CAPABILITY TLV */
        if (tlv->type == PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY)
        {
            struct pcep_object_tlv_stateful_pce_capability *pce_cap_tlv =
                    (struct pcep_object_tlv_stateful_pce_capability *) tlv;

            /* If the U flag is set, then the PCE is
             * capable of updating LSP parameters */
            if (pce_cap_tlv->flag_u_lsp_update_capability)
            {
                if (session->pce_config.support_stateful_pce_lsp_update == false)
                {
                    /* Turn off the U bit, as it is not supported */
                    pcep_log(LOG_INFO, "Rejecting unsupported Open STATEFUL-PCE-CAPABILITY TLV U flag");
                    pce_cap_tlv->flag_u_lsp_update_capability = false;
                    retval = false;
                }
                else
                {
                    session->stateful_pce  = true;
                    pcep_log(LOG_INFO, "Setting PCEP session [%d] STATEFUL to support LSP updates",
                            session->session_id);
                }
            }
            /* TODO the rest of the flags are not implemented yet */
            else if (pce_cap_tlv->flag_s_include_db_version)
            {
                pcep_log(LOG_INFO, "Ignoring Open STATEFUL-PCE-CAPABILITY TLV S Include DB Version flag");
            }
            else if (pce_cap_tlv->flag_i_lsp_instantiation_capability)
            {
                pcep_log(LOG_INFO, "Ignoring Open STATEFUL-PCE-CAPABILITY TLV I LSP Instantiation Capability flag");
            }
            else if (pce_cap_tlv->flag_t_triggered_resync)
            {
                pcep_log(LOG_INFO, "Ignoring Open STATEFUL-PCE-CAPABILITY TLV T Triggered Resync flag");
            }
            else if (pce_cap_tlv->flag_d_delta_lsp_sync)
            {
                pcep_log(LOG_INFO, "Ignoring Open STATEFUL-PCE-CAPABILITY TLV D Delta LSP Sync flag");
            }
            else if (pce_cap_tlv->flag_f_triggered_initial_sync)
            {
                pcep_log(LOG_INFO, "Ignoring Open STATEFUL-PCE-CAPABILITY TLV F Triggered Initial Sync flag");
            }
        }
        else if (tlv->type == PCEP_OBJ_TLV_TYPE_LSP_DB_VERSION)
        {
            if (session->pce_config.support_include_db_version == false)
            {
                pcep_log(LOG_INFO, "Rejecting unsupported Open LSP DB VERSION TLV");
                /* Remove this TLV from the list */
                dll_delete_node(open_object->header.tlv_list, tlv_node);
                retval = false;
            }
        }
    }

    return retval;
}


bool handle_pcep_open(pcep_session *session, struct pcep_message *open_msg)
{
    /* Open Message validation and errors according to:
     * https://tools.ietf.org/html/rfc5440#section-7.15 */

    if (session->session_state != SESSION_STATE_PCEP_CONNECTING &&
        session->session_state != SESSION_STATE_INITIALIZED)
    {
        pcep_log(LOG_INFO, "Received unexpected OPEN, current session state [%d, replying with error]",
                 session->session_state);
        send_pcep_error(session, PCEP_ERRT_ATTEMPT_TO_ESTABLISH_2ND_PCEP_SESSION,
                PCEP_ERRV_RECVD_INVALID_OPEN_MSG);
        return false;
    }

    if (session->pce_open_received == true && session->pce_open_rejected == false)
    {
        pcep_log(LOG_INFO, "Received duplicate OPEN, replying with error");
        send_pcep_error(session, PCEP_ERRT_ATTEMPT_TO_ESTABLISH_2ND_PCEP_SESSION,
                        PCEP_ERRV_RECVD_INVALID_OPEN_MSG);
        return false;
    }

    struct pcep_object_open *open_object =
            (struct pcep_object_open *) pcep_obj_get(open_msg->obj_list, PCEP_OBJ_CLASS_OPEN);
    if (open_object == NULL)
    {
        pcep_log(LOG_INFO, "Received OPEN message with no OPEN object, replying with error");
        send_pcep_error(session, PCEP_ERRT_SESSION_FAILURE, PCEP_ERRV_RECVD_INVALID_OPEN_MSG);
        return false;
    }

    /* Check for additional Open Msg objects */
    if (open_msg->obj_list->num_entries > 1)
    {
        pcep_log(LOG_INFO, "Found additional unsupported objects in the Open message, replying with error");
        send_pcep_error(session, PCEP_ERRT_SESSION_FAILURE, PCEP_ERRV_RECVD_INVALID_OPEN_MSG);
        return false;
    }

    session->pce_open_received = true;

    /* Verify the open object parameters and TLVs */
    if (verify_pcep_open_object(session, open_object) == false)
    {
        enqueue_event(session, PCC_RCVD_INVALID_OPEN, NULL);
        if (session->pce_open_rejected)
        {
            /* The Open message was already rejected once, so according to
             * the spec, send an error message and close the TCP connection. */
            pcep_log(LOG_INFO, "Received 2 consecutive unsupported Open messages, closing the connection.");
            send_pcep_error(session, PCEP_ERRT_SESSION_FAILURE,
                            PCEP_ERRV_RECVD_SECOND_OPEN_MSG_UNACCEPTABLE);
            socket_comm_session_close_tcp_after_write(session->socket_comm_session);
            session->session_state = SESSION_STATE_INITIALIZED;
            enqueue_event(session, PCC_CONNECTION_FAILURE, NULL);
        }
        else
        {
            session->pce_open_rejected = true;
            /* Clone the object here, since the encapsulating message will
             * be deleted in handle_socket_comm_event() most likely before
             * this error message is sent */
            struct pcep_object_open *cloned_open_object = malloc(sizeof(struct pcep_object_open));
            memcpy(cloned_open_object, open_object, sizeof(struct pcep_object_open));
            open_object->header.tlv_list = NULL;
            cloned_open_object->header.encoded_object = NULL;
            cloned_open_object->header.encoded_object_length = 0;
            send_pcep_error_with_object(session, PCEP_ERRT_SESSION_FAILURE,
                    PCEP_ERRV_UNACCEPTABLE_OPEN_MSG_NEG, &cloned_open_object->header);
        }

        return false;
    }

    /* Open Message accepted */
    session->pce_config.dead_timer_seconds = open_object->open_deadtimer;
    session->pce_config.keep_alive_seconds = open_object->open_keepalive;
    send_keep_alive(session);

    return true;
}


/* The original PCEP Open message sent to the PCE was rejected,
 * try to reconcile the differences and re-send a new Open. */
void send_reconciled_pcep_open(pcep_session *session, struct pcep_message *error_msg)
{
    struct pcep_message *open_msg = create_pcep_open(session);

    struct pcep_object_open *error_open_obj =
            (struct pcep_object_open *) pcep_obj_get(error_msg->obj_list, PCEP_OBJ_CLASS_OPEN);
    if (error_open_obj == NULL)
    {
        /* Nothing to reconcile, send the same Open message again */
        pcep_log(LOG_INFO, "No Open object received in Error, sending the same Open message");
        session_send_message(session, open_msg);
        return;
    }

    struct pcep_object_open *open_obj =
            (struct pcep_object_open *) pcep_obj_get(open_msg->obj_list, PCEP_OBJ_CLASS_OPEN);
    if (error_open_obj->open_deadtimer >= session->pce_config.min_dead_timer_seconds &&
        error_open_obj->open_deadtimer <= session->pce_config.max_dead_timer_seconds)
    {
        open_obj->open_deadtimer = error_open_obj->open_deadtimer;
    }
    else
    {
        pcep_log(LOG_INFO, "Can not reconcile Open with suggested deadtimer [%d]", error_open_obj->open_deadtimer);
    }

    if (error_open_obj->open_keepalive >= session->pce_config.min_keep_alive_seconds &&
        error_open_obj->open_keepalive <= session->pce_config.max_keep_alive_seconds)
    {
        open_obj->open_keepalive = error_open_obj->open_keepalive;
    }
    else
    {
        pcep_log(LOG_INFO, "Can not reconcile Open with suggested keepalive [%d]", error_open_obj->open_keepalive);
    }

    /* TODO reconcile the TLVs */

    session_send_message(session, open_msg);
}


bool handle_pcep_update(pcep_session *session, struct pcep_message *upd_msg)
{
    /* Update Message validation and errors according to:
     * https://tools.ietf.org/html/rfc8231#section-6.2 */

    if (upd_msg->obj_list == NULL)
    {
        pcep_log(LOG_INFO, "Invalid PcUpd message: Message has no objects");
        send_pcep_error(session, PCEP_ERRT_MANDATORY_OBJECT_MISSING,
                PCEP_ERRV_SRP_OBJECT_MISSING);
        return false;
    }

    /* Verify the mandatory objects are present */
    struct pcep_object_header *obj = pcep_obj_get(upd_msg->obj_list, PCEP_OBJ_CLASS_SRP);
    if (obj == NULL)
    {
        pcep_log(LOG_INFO, "Invalid PcUpd message: Missing SRP object");
        send_pcep_error(session, PCEP_ERRT_MANDATORY_OBJECT_MISSING,
                PCEP_ERRV_SRP_OBJECT_MISSING);
        return false;
    }

    obj = pcep_obj_get(upd_msg->obj_list, PCEP_OBJ_CLASS_LSP);
    if (obj == NULL)
    {
        pcep_log(LOG_INFO, "Invalid PcUpd message: Missing LSP object");
        send_pcep_error(session, PCEP_ERRT_MANDATORY_OBJECT_MISSING,
                PCEP_ERRV_LSP_OBJECT_MISSING);
        return false;
    }

    obj = pcep_obj_get(upd_msg->obj_list, PCEP_OBJ_CLASS_ERO);
    if (obj == NULL)
    {
        pcep_log(LOG_INFO, "Invalid PcUpd message: Missing ERO object");
        send_pcep_error(session, PCEP_ERRT_MANDATORY_OBJECT_MISSING,
                PCEP_ERRV_ERO_OBJECT_MISSING);
        return false;
    }

    /* Verify the objects are are in the correct order */
    double_linked_list_node *node = upd_msg->obj_list->head;
    struct pcep_object_srp *srp_object = (struct pcep_object_srp *) node->data;
    if (srp_object->header.object_class != PCEP_OBJ_CLASS_SRP)
    {
        pcep_log(LOG_INFO, "Invalid PcUpd message: First object must be an SRP, found [%d]",
                srp_object->header.object_class);
        send_pcep_error(session, PCEP_ERRT_MANDATORY_OBJECT_MISSING,
                PCEP_ERRV_SRP_OBJECT_MISSING);
        return false;
    }

    node = node->next_node;
    struct pcep_object_lsp *lsp_object = (struct pcep_object_lsp *) node->data;
    if (lsp_object->header.object_class != PCEP_OBJ_CLASS_LSP)
    {
        pcep_log(LOG_INFO, "Invalid PcUpd message: Second object must be an LSP, found [%d]",
                lsp_object->header.object_class);
        send_pcep_error(session, PCEP_ERRT_MANDATORY_OBJECT_MISSING,
                PCEP_ERRV_LSP_OBJECT_MISSING);
        return false;
    }

    node = node->next_node;
    struct pcep_object_ro *ero_object = node->data;
    if (ero_object->header.object_class != PCEP_OBJ_CLASS_ERO)
    {
        pcep_log(LOG_INFO, "Invalid PcUpd message: Third object must be an ERO, found [%d]",
                ero_object->header.object_class);
        send_pcep_error(session, PCEP_ERRT_MANDATORY_OBJECT_MISSING,
                PCEP_ERRV_ERO_OBJECT_MISSING);
        return false;
    }

    return true;
}

bool handle_pcep_initiate(pcep_session *session, struct pcep_message *init_msg)
{
    /* Instantiate Message validation and errors according to:
     * https://tools.ietf.org/html/rfc8281#section-5 */

    if (init_msg->obj_list == NULL)
    {
        pcep_log(LOG_INFO, "Invalid PcInitiate message: Message has no objects");
        send_pcep_error(session, PCEP_ERRT_MANDATORY_OBJECT_MISSING,
                PCEP_ERRV_SRP_OBJECT_MISSING);
        return false;
    }

    /* Verify the mandatory objects are present */
    struct pcep_object_header *obj = pcep_obj_get(init_msg->obj_list, PCEP_OBJ_CLASS_SRP);
    if (obj == NULL)
    {
        pcep_log(LOG_INFO, "Invalid PcInitiate message: Missing SRP object");
        send_pcep_error(session, PCEP_ERRT_MANDATORY_OBJECT_MISSING,
                PCEP_ERRV_SRP_OBJECT_MISSING);
        return false;
    }

    obj = pcep_obj_get(init_msg->obj_list, PCEP_OBJ_CLASS_LSP);
    if (obj == NULL)
    {
        pcep_log(LOG_INFO, "Invalid PcInitiate message: Missing LSP object");
        send_pcep_error(session, PCEP_ERRT_MANDATORY_OBJECT_MISSING,
                PCEP_ERRV_LSP_OBJECT_MISSING);
        return false;
    }

    /* Verify the objects are are in the correct order */
    double_linked_list_node *node = init_msg->obj_list->head;
    struct pcep_object_srp *srp_object = (struct pcep_object_srp *) node->data;
    if (srp_object->header.object_class != PCEP_OBJ_CLASS_SRP)
    {
        pcep_log(LOG_INFO, "Invalid PcInitiate message: First object must be an SRP, found [%d]",
                srp_object->header.object_class);
        send_pcep_error(session, PCEP_ERRT_MANDATORY_OBJECT_MISSING,
                PCEP_ERRV_SRP_OBJECT_MISSING);
        return false;
    }

    node = node->next_node;
    struct pcep_object_lsp *lsp_object = (struct pcep_object_lsp *) node->data;
    if (lsp_object->header.object_class != PCEP_OBJ_CLASS_LSP)
    {
        pcep_log(LOG_INFO, "Invalid PcInitiate message: Second object must be an LSP, found [%d]",
                lsp_object->header.object_class);
        send_pcep_error(session, PCEP_ERRT_MANDATORY_OBJECT_MISSING,
                PCEP_ERRV_LSP_OBJECT_MISSING);
        return false;
    }

    /* There may be more optional objects */
    return true;
}

void increment_unknown_message(pcep_session *session)
{
    /* https://tools.ietf.org/html/rfc5440#section-6.9
     * If a PCC/PCE receives unrecognized messages at a rate equal or
     * greater than MAX-UNKNOWN-MESSAGES unknown message requests per
     * minute, the PCC/PCE MUST send a PCEP CLOSE message */

    time_t *unknown_message_time = malloc(sizeof(time_t));
    *unknown_message_time = time(NULL);
    time_t expire_time = *unknown_message_time + 60;
    queue_enqueue(session->num_unknown_messages_time_queue, unknown_message_time);

    /* Purge any entries older than 1 minute. The oldest entries are at the queue head */
    queue_node *time_node = session->num_unknown_messages_time_queue->head;
    while(time_node != NULL)
    {
        if (*((time_t *) time_node->data) > expire_time)
        {
            free(queue_dequeue(session->num_unknown_messages_time_queue));
            time_node = session->num_unknown_messages_time_queue->head;
        }
        else
        {
            time_node = NULL;
        }
    }

    if (session->num_unknown_messages_time_queue->num_entries >= session->pcc_config.max_unknown_messages)
    {
        close_pcep_session_with_reason(session, PCEP_CLOSE_REASON_UNREC_MSG);
    }
}

/*
 * these functions are called by session_logic_loop() from pcep_session_logic_loop.c
 * these functions are executed in the session_logic_loop thread, and the mutex
 * is locked before calling these functions, so they are thread safe.
 */

/* state machine handling for expired timers */
void handle_timer_event(pcep_session_event *event)
{
    if (event == NULL)
    {
        pcep_log(LOG_INFO, "handle_timer_event NULL event");
        return;
    }

    pcep_session *session = event->session;

    pcep_log(LOG_INFO, "[%ld-%ld] pcep_session_logic handle_timer_event: session_id [%d] event timer_id [%d] "
            "session timers [OKW, PRW, DT, KA] [%d, %d, %d, %d]",
            time(NULL), pthread_self(), session->session_id, event->expired_timer_id,
            session->timer_id_open_keep_wait, session->timer_id_pc_req_wait,
            session->timer_id_dead_timer, session->timer_id_keep_alive);

    /*
     * these timer expirations are independent of the session state
     */
    if (event->expired_timer_id == session->timer_id_dead_timer)
    {
        session->timer_id_dead_timer = TIMER_ID_NOT_SET;
        increment_event_counters(session, PCEP_EVENT_COUNTER_ID_TIMER_DEADTIMER);
        close_pcep_session_with_reason(session, PCEP_CLOSE_REASON_DEADTIMER);
        enqueue_event(session, PCE_DEAD_TIMER_EXPIRED, NULL);
        return;
    }
    else if(event->expired_timer_id == session->timer_id_keep_alive)
    {
        session->timer_id_keep_alive = TIMER_ID_NOT_SET;
        increment_event_counters(session, PCEP_EVENT_COUNTER_ID_TIMER_KEEPALIVE);
        send_keep_alive(session);
        return;
    }

    /*
     * handle timers that depend on the session state
     */
    switch(session->session_state)
    {
    case SESSION_STATE_PCEP_CONNECTING:
        if (event->expired_timer_id == session->timer_id_open_keep_wait)
        {
            /* close the TCP session */
            pcep_log(LOG_INFO, "handle_timer_event open_keep_wait timer expired for session [%d]", session->session_id);
            increment_event_counters(session, PCEP_EVENT_COUNTER_ID_TIMER_OPENKEEPWAIT);
            socket_comm_session_close_tcp_after_write(session->socket_comm_session);
            session->session_state = SESSION_STATE_INITIALIZED;
            session->timer_id_open_keep_wait = TIMER_ID_NOT_SET;
            enqueue_event(session, PCE_OPEN_KEEP_WAIT_TIMER_EXPIRED, NULL);
        }
        break;

    case SESSION_STATE_WAIT_PCREQ:
        if (event->expired_timer_id == session->timer_id_pc_req_wait)
        {
            pcep_log(LOG_INFO, "handle_timer_event PCReq_wait timer expired for session [%d]", session->session_id);
            increment_event_counters(session, PCEP_EVENT_COUNTER_ID_TIMER_PCREQWAIT);
            /* TODO is this the right reason?? */
            close_pcep_session_with_reason(session, PCEP_CLOSE_REASON_DEADTIMER);
            session->timer_id_pc_req_wait = TIMER_ID_NOT_SET;
            enqueue_event(session, PCE_OPEN_KEEP_WAIT_TIMER_EXPIRED, NULL);
        }
        break;

    case SESSION_STATE_IDLE:
    case SESSION_STATE_INITIALIZED:
    case SESSION_STATE_PCEP_CONNECTED:
    default:
        pcep_log(LOG_INFO, "handle_timer_event unrecognized state transition, timer_id [%d] state [%d] session_id [%d]",
                event->expired_timer_id, session->session_state, session->session_id);
        break;
    }
}

void log_pcc_pce_connection(pcep_session *session)
{
    char ipv6_buf[40];
    if (session->socket_comm_session == NULL)
    {
        /* This only happens in UT */
        return;
    }

    pcep_log(LOG_INFO, "[%ld-%ld] Successful PCC [%s:%d] connection to PCE [%s:%d]",
        time(NULL), pthread_self(),
        (session->socket_comm_session->is_ipv6 ?
            inet_ntop(AF_INET6,
                &session->socket_comm_session->src_sock_addr.src_sock_addr_ipv6.sin6_addr,
                ipv6_buf, sizeof(ipv6_buf)) :
            inet_ntoa(session->socket_comm_session->src_sock_addr.src_sock_addr_ipv4.sin_addr)),
        htons(session->socket_comm_session->is_ipv6 ?
            session->socket_comm_session->src_sock_addr.src_sock_addr_ipv6.sin6_port :
            session->socket_comm_session->src_sock_addr.src_sock_addr_ipv4.sin_port),
        (session->socket_comm_session->is_ipv6 ?
            inet_ntop(AF_INET6,
                &session->socket_comm_session->dest_sock_addr.dest_sock_addr_ipv6.sin6_addr,
                ipv6_buf, sizeof(ipv6_buf)) :
            inet_ntoa(session->socket_comm_session->dest_sock_addr.dest_sock_addr_ipv4.sin_addr)),
        htons(session->socket_comm_session->is_ipv6 ?
            session->socket_comm_session->dest_sock_addr.dest_sock_addr_ipv6.sin6_port :
            session->socket_comm_session->dest_sock_addr.dest_sock_addr_ipv4.sin_port));
}


/* State machine handling for received messages.
 * This event was created in session_logic_msg_ready_handler() in
 * pcep_session_logic_loop.c */
void handle_socket_comm_event(pcep_session_event *event)
{
    if (event == NULL)
    {
        pcep_log(LOG_INFO, "handle_socket_comm_event NULL event");
        return;
    }

    pcep_session *session = event->session;

    pcep_log(LOG_INFO, "[%ld-%ld] pcep_session_logic handle_socket_comm_event: session_id [%d] num messages [%d] socket_closed [%d]",
            time(NULL), pthread_self(),
            session->session_id,
            (event->received_msg_list == NULL ? -1 : event->received_msg_list->num_entries),
            event->socket_closed);

    /*
     * independent of the session state
     */
    if (event->socket_closed)
    {
        pcep_log(LOG_INFO, "handle_socket_comm_event socket closed for session [%d]", session->session_id);
        socket_comm_session_close_tcp(session->socket_comm_session);
        enqueue_event(session, PCE_CLOSED_SOCKET, NULL);
        if (session->session_state == SESSION_STATE_PCEP_CONNECTING)
        {
            enqueue_event(session, PCC_CONNECTION_FAILURE, NULL);
        }
        session->session_state = SESSION_STATE_INITIALIZED;
        increment_event_counters(session, PCEP_EVENT_COUNTER_ID_PCE_DISCONNECT);
        return;
    }

    reset_dead_timer(session);

    if (event->received_msg_list == NULL)
    {
        return;
    }

    /* Message received on socket */
    double_linked_list_node *msg_node;
    for (msg_node = event->received_msg_list->head;
         msg_node != NULL;
         msg_node = msg_node->next_node)
    {
        bool message_enqueued = false;
        struct pcep_message *msg = (struct pcep_message *) msg_node->data;
        pcep_log(LOG_INFO, "\t %s message", get_message_type_str(msg->msg_header->type));

        increment_message_rx_counters(session, msg);

        switch (msg->msg_header->type)
        {
        case PCEP_TYPE_OPEN:
            /* handle_pcep_open() checks session state, and for duplicate erroneous
             * open messages, and replies with error messages as needed. It also
             * sets pce_open_received. */
            if (handle_pcep_open(session, msg) == true)
            {
                /* PCE Open Message Accepted */
                enqueue_event(session, MESSAGE_RECEIVED, msg);
                message_enqueued = true;
                session->pce_open_accepted = true;
                session->pce_open_rejected = false;
                if (session->pcc_open_accepted)
                {
                    /* If both the PCC and PCE Opens are accepted, then the session is connected */
                    log_pcc_pce_connection(session);
                    session->session_state = SESSION_STATE_PCEP_CONNECTED;
                    increment_event_counters(session, PCEP_EVENT_COUNTER_ID_PCE_CONNECT);
                    enqueue_event(session, PCC_CONNECTED_TO_PCE, NULL);
                }
            }
            break;

        case PCEP_TYPE_KEEPALIVE:
            if (session->session_state == SESSION_STATE_PCEP_CONNECTING)
            {
                /* PCC Open Message Accepted */
                cancel_timer(session->timer_id_open_keep_wait);
                session->timer_id_open_keep_wait = TIMER_ID_NOT_SET;
                session->pcc_open_accepted = true;
                session->pcc_open_rejected = false;
                if (session->pce_open_accepted)
                {
                    /* If both the PCC and PCE Opens are accepted, then the session is connected */
                    log_pcc_pce_connection(session);
                    session->session_state = SESSION_STATE_PCEP_CONNECTED;
                    increment_event_counters(session, PCEP_EVENT_COUNTER_ID_PCC_CONNECT);
                    enqueue_event(session, PCC_CONNECTED_TO_PCE, NULL);
                }
            }
            /* The dead_timer was already reset above, so nothing extra to do here */
            break;

        case PCEP_TYPE_PCREP:
            if (session->session_state == SESSION_STATE_WAIT_PCREQ)
            {
                session->session_state = SESSION_STATE_IDLE;
                cancel_timer(session->timer_id_pc_req_wait);
                session->timer_id_pc_req_wait = TIMER_ID_NOT_SET;
                enqueue_event(session, MESSAGE_RECEIVED, msg);
                message_enqueued = true;
            }
            else
            {
                send_pcep_error(session, PCEP_ERRT_UNKNOWN_REQ_REF, PCEP_ERRV_UNASSIGNED);
            }
            break;

        case PCEP_TYPE_CLOSE:
            session->session_state = SESSION_STATE_INITIALIZED;
            socket_comm_session_close_tcp(session->socket_comm_session);
            /* TODO should we also enqueue the message, so they can see the reasons?? */
            enqueue_event(session, PCE_SENT_PCEP_CLOSE, NULL);
            /* TODO could this duplicate the disconnect counter with socket close ?? */
            increment_event_counters(session, PCEP_EVENT_COUNTER_ID_PCE_DISCONNECT);
            break;

        case PCEP_TYPE_PCREQ:
            /* The PCC does not support receiving PcReq messages */
            send_pcep_error(session, PCEP_ERRT_CAPABILITY_NOT_SUPPORTED, PCEP_ERRV_UNASSIGNED);
            break;

        case PCEP_TYPE_REPORT:
            /* The PCC does not support receiving Report messages */
            send_pcep_error(session, PCEP_ERRT_CAPABILITY_NOT_SUPPORTED, PCEP_ERRV_UNASSIGNED);
            break;

        case PCEP_TYPE_UPDATE:
            /* Should reply with a PcRpt */
            if (handle_pcep_update(session, msg) == true)
            {
                enqueue_event(session, MESSAGE_RECEIVED, msg);
                message_enqueued = true;
            }
            break;

        case PCEP_TYPE_INITIATE:
            /* Should reply with a PcRpt */
            if (handle_pcep_initiate(session, msg) == true)
            {
                enqueue_event(session, MESSAGE_RECEIVED, msg);
                message_enqueued = true;
            }
            break;

        case PCEP_TYPE_PCNOTF:
            enqueue_event(session, MESSAGE_RECEIVED, msg);
            message_enqueued = true;
            break;

        case PCEP_TYPE_ERROR:
            enqueue_event(session, MESSAGE_RECEIVED, msg);
            message_enqueued = true;
            if (session->session_state == SESSION_STATE_PCEP_CONNECTING)
            {
                /* A PCC_CONNECTION_FAILURE event will be sent when the socket is
                 * closed, if the state is SESSION_STATE_PCEP_CONNECTING, in case
                 * the PCE allows more than 2 failed open messages. */
                pcep_log(LOG_INFO, "PCC Open message rejected by PCC");
                enqueue_event(session, PCC_SENT_INVALID_OPEN, NULL);
                session->pcc_open_rejected = true;
                send_reconciled_pcep_open(session, msg);
            }
            break;

        default:
            pcep_log(LOG_INFO, "\t UnSupported message");
            send_pcep_error(session, PCEP_ERRT_CAPABILITY_NOT_SUPPORTED, PCEP_ERRV_UNASSIGNED);
            increment_unknown_message(session);
            break;
        }

        /* if the message was enqueued, dont free it yet */
        if (message_enqueued == false)
        {
            pcep_msg_free_message(msg);
        }
    }
    dll_destroy(event->received_msg_list);
}
