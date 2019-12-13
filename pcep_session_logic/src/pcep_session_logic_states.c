/*
 * pcep_session_logic_states.c
 *
 *  Created on: sep 20, 2019
 *      Author: brady
 */

#include <malloc.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

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

    pcep_log(LOG_INFO, "[%ld-%ld] pcep_session_logic send keep_alive message len [%d] for session_id [%d]\n",
            time(NULL), pthread_self(), keep_alive_msg->header->length, session->session_id);

    session_send_message(session, keep_alive_msg);

    /* The keep alive timer will be (re)set once the message
     * is sent in session_logic_message_sent_handler() */
}


/* Send an error message with the "corrected" open object */
void send_pcep_open_error(pcep_session *session, struct pcep_object_open *open_obj)
{
    struct pcep_object_error *error_obj =
            pcep_obj_create_error(PCEP_ERRT_SESSION_FAILURE, PCEP_ERRV_RECVD_INVALID_OPEN_MSG);

    uint16_t buffer_len = sizeof(struct pcep_header) +
            open_obj->header.object_length +
            error_obj->header.object_length;
    uint8_t *buffer = malloc(buffer_len);
    bzero(buffer, buffer_len);

    struct pcep_message *message = malloc(sizeof(struct pcep_message));
    message->header = (struct pcep_header*) buffer;
    message->header->length = buffer_len;
    message->header->type = PCEP_TYPE_ERROR;
    message->header->ver_flags = PCEP_COMMON_HEADER_VER_FLAGS;

    memcpy(buffer + sizeof(struct pcep_header), error_obj, error_obj->header.object_length);
    dll_append(message->obj_list, buffer + sizeof(struct pcep_header));
    memcpy(buffer + sizeof(struct pcep_header) + error_obj->header.object_length,
           open_obj, open_obj->header.object_length);
    dll_append(message->obj_list, buffer + sizeof(struct pcep_header) + error_obj->header.object_length);

    session_send_message(session, message);

    /* The open_obj will be freed when the received open message is freed */
    free(error_obj);
}


void send_pcep_error(pcep_session *session, enum pcep_error_type error_type, enum pcep_error_value error_value)
{
    struct pcep_message *error_msg = pcep_msg_create_error(error_type, error_value);
    session_send_message(session, error_msg);

    pcep_log(LOG_INFO, "[%ld-%ld] pcep_session_logic send error message [%d][%d] len [%d] for session_id [%d]\n",
            time(NULL), pthread_self(), error_type, error_value, error_msg->header->length, session->session_id);
}


void reset_dead_timer(pcep_session *session)
{
    if (session->timer_id_dead_timer == TIMER_ID_NOT_SET)
    {
        pcep_log(LOG_INFO, "[%ld-%ld] pcep_session_logic set dead timer [%d secs] for session_id [%d]\n",
                time(NULL), pthread_self(), session->pce_config.dead_timer_seconds, session->session_id);
        session->timer_id_dead_timer = create_timer(session->pce_config.dead_timer_seconds, session);
    }
    else
    {
        pcep_log(LOG_INFO, "[%ld-%ld] pcep_session_logic reset dead timer [%d secs] for session_id [%d]\n",
                time(NULL), pthread_self(), session->pce_config.dead_timer_seconds, session->session_id);
        reset_timer(session->timer_id_dead_timer);
    }
}


void enqueue_event(pcep_session *session, pcep_event_type event_type, struct pcep_message *message)
{
    if (event_type == MESSAGE_RECEIVED && message == NULL)
    {
        pcep_log(LOG_WARNING, "enqueue_event cannot enqueue a NULL message\n");
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
bool verify_pcep_open(pcep_session *session, struct pcep_object_open *open_object)
{
    int retval = true;

    if (open_object->open_keepalive < session->pcc_config.min_keep_alive_seconds)
    {
        pcep_log(LOG_INFO, "Rejecting unsupported Open Keep Alive value [%d] min [%d]\n",
               open_object->open_keepalive, session->pcc_config.min_keep_alive_seconds);
        open_object->open_keepalive =
                session->pcc_config.min_keep_alive_seconds;
        retval = false;
    }
    else if (open_object->open_keepalive > session->pcc_config.max_keep_alive_seconds)
    {
        pcep_log(LOG_INFO, "Rejecting unsupported Open Keep Alive value [%d] max [%d]\n",
               open_object->open_keepalive, session->pcc_config.max_keep_alive_seconds);
        open_object->open_keepalive =
                session->pcc_config.max_keep_alive_seconds;
        retval = false;
    }

    if (open_object->open_deadtimer < session->pcc_config.min_dead_timer_seconds)
    {
        pcep_log(LOG_INFO, "Rejecting unsupported Open Dead Timer value [%d]\n",
               open_object->open_deadtimer);
        open_object->open_deadtimer =
                session->pcc_config.min_dead_timer_seconds;
        retval = false;
    }
    else if (open_object->open_keepalive > session->pcc_config.max_dead_timer_seconds)
    {
        pcep_log(LOG_INFO, "Rejecting unsupported Open Dead Timer value [%d]\n",
               open_object->open_deadtimer);
        open_object->open_deadtimer =
                session->pcc_config.max_dead_timer_seconds;
        retval = false;
    }

    /* Check for Open Object TLVs */
    if (pcep_obj_has_tlv((struct pcep_object_header*) open_object) == false)
    {
        /* There are no TLVs, all done */
        return retval;
    }

    double_linked_list *tlv_list = pcep_obj_get_tlvs((struct pcep_object_header *) open_object);
    double_linked_list_node *tlv_node = tlv_list->head;
    for (; tlv_node != NULL; tlv_node = tlv_node->next_node)
    {
        struct pcep_object_tlv *tlv = tlv_node->data;

        /* Check for the STATEFUL-PCE-CAPABILITY TLV */
        if (tlv->header.type == PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY)
        {
            /* If the U flag is set, then the PCE is
             * capable of updating LSP parameters */
            if (tlv->value[0] & PCEP_TLV_FLAG_LSP_UPDATE_CAPABILITY)
            {
                if (session->pce_config.support_stateful_pce_lsp_update == false)
                {
                    /* Turn off the U bit, as it is not supported */
                    pcep_log(LOG_INFO, "Rejecting unsupported Open STATEFUL-PCE-CAPABILITY TLV U flag\n");
                    tlv->value[0] &= ~PCEP_TLV_FLAG_LSP_UPDATE_CAPABILITY;
                    retval = false;
                }
                else
                {
                    session->stateful_pce  = true;
                    pcep_log(LOG_INFO, "Setting PCEP session [%d] STATEFUL to support LSP updates\n",
                            session->session_id);
                }
            }
            /* TODO the rest of the flags are not implemented yet */
            else if (tlv->value[0] & PCEP_TLV_FLAG_INCLUDE_DB_VERSION)
            {
                pcep_log(LOG_INFO, "Ignoring Open STATEFUL-PCE-CAPABILITY TLV S flag\n");
            }
            else if (tlv->value[0] & PCEP_TLV_FLAG_LSP_INSTANTIATION)
            {
                pcep_log(LOG_INFO, "Ignoring Open STATEFUL-PCE-CAPABILITY TLV I flag\n");
            }
            else if (tlv->value[0] & PCEP_TLV_FLAG_TRIGGERED_RESYNC)
            {
                pcep_log(LOG_INFO, "Ignoring Open STATEFUL-PCE-CAPABILITY TLV T flag\n");
            }
            else if (tlv->value[0] & PCEP_TLV_FLAG_DELTA_LSP_SYNC)
            {
                pcep_log(LOG_INFO, "Ignoring Open STATEFUL-PCE-CAPABILITY TLV D flag\n");
            }
            else if (tlv->value[0] & PCEP_TLV_FLAG_TRIGGERED_INITIAL_SYNC)
            {
                pcep_log(LOG_INFO, "Ignoring Open STATEFUL-PCE-CAPABILITY TLV F flag\n");
            }
        }
        else
        {
            /* TODO TODO how to handle unrecognized TLV ?? */
            pcep_log(LOG_INFO, "Unhandled OPEN TLV type: %d, length %d\n",
                    tlv->header.type, tlv->header.length);
        }
    }
    dll_destroy(tlv_list);

    return retval;
}


void handle_pcep_open(pcep_session *session, pcep_message *open_msg)
{
    if (session->pcep_open_received == true)
    {
        /* TODO when this reaches a MAX, need to react */
        session->num_erroneous_messages++;
        return;
    }

    struct pcep_object_open *open_object =
            (struct pcep_object_open *) pcep_obj_get(open_msg->obj_list, PCEP_OBJ_CLASS_OPEN);
    if (open_object == NULL)
    {
        /* TODO when this reaches a MAX, need to react */
        session->num_erroneous_messages++;
        return;
    }

    /* Verify the open object parameters */
    if (verify_pcep_open(session, open_object) == false)
    {
        if (session->pcep_open_rejected)
        {
            /* The Open message was already rejected once, so according to
             * the spec, send an error message and close the TCP connection. */
            send_pcep_error(session, PCEP_ERRT_SESSION_FAILURE, PCEP_ERRV_RECVD_INVALID_OPEN_MSG);
            socket_comm_session_close_tcp_after_write(session->socket_comm_session);
            session->session_state = SESSION_STATE_INITIALIZED;
        }
        else
        {
            session->pcep_open_rejected = true;
            send_pcep_open_error(session, open_object);
        }

        return;
    }

    /* Check for additional Open Msg objects */
    if (open_msg->obj_list->num_entries > 1)
    {
        /* TODO finish this */
        pcep_log(LOG_INFO, "There are additional objects in the Open message\n");
    }

    session->pce_config.dead_timer_seconds = open_object->open_deadtimer;
    session->pce_config.keep_alive_seconds = open_object->open_keepalive;
    session->pcep_open_received = true;
    send_keep_alive(session);
}


void handle_pcep_update(pcep_session *session, pcep_message *upd_msg)
{
    if (upd_msg->obj_list == NULL)
    {
        /* TODO reply with error */
        pcep_log(LOG_INFO, "Invalid PcUpd message: Message has no objects\n");
    }

    if (upd_msg->obj_list->num_entries < 3)
    {
        /* TODO reply with error */
        pcep_log(LOG_INFO, "Invalid PcUpd message: Message only has [%d] objects, minimum 3 required\n",
                upd_msg->obj_list->num_entries);
    }

    double_linked_list_node *node = upd_msg->obj_list->head;
    struct pcep_object_srp *srp_object = (struct pcep_object_srp *) node->data;
    if (srp_object->header.object_class != PCEP_OBJ_CLASS_SRP)
    {
        /* TODO reply with error */
        pcep_log(LOG_INFO, "Invalid PcUpd message: First object must be an SRP, found [%d]\n",
                srp_object->header.object_class);
    }

    node = node->next_node;
    struct pcep_object_lsp *lsp_object = (struct pcep_object_lsp *) node->data;
    if (lsp_object->header.object_class != PCEP_OBJ_CLASS_LSP)
    {
        /* TODO reply with error */
        pcep_log(LOG_INFO, "Invalid PcUpd message: Second object must be an LSP, found [%d]\n",
                lsp_object->header.object_class);
    }

    node = node->next_node;
    struct pcep_object_ro *ero_object = node->data;
    if (ero_object->header.object_class != PCEP_OBJ_CLASS_ERO)
    {
        /* TODO reply with error */
        pcep_log(LOG_INFO, "Invalid PcUpd message: Third object must be an ERO, found [%d]\n",
                ero_object->header.object_class);
    }

    /* TODO finish this */

    if (upd_msg->obj_list->num_entries > 3)
    {
        for (; node != NULL; node = node->next_node)
        {
            struct pcep_object_header *object = node->data;
            pcep_log(LOG_INFO, "Extra PcUpd object: Class [%d] Type [%d] len [%d]\n",
                   object->object_class, object->object_type, object->object_length);
        }
    }
}

void handle_pcep_initiate(pcep_session *session, pcep_message *init_msg)
{
    if (init_msg->obj_list == NULL)
    {
        /* TODO reply with error */
        pcep_log(LOG_INFO, "Invalid PcInitiate message: Message has no objects\n");
    }

    if (init_msg->obj_list->num_entries < 2)
    {
        /* TODO reply with error */
        pcep_log(LOG_INFO, "Invalid PcInitiate message: Message only has [%d] objects, minimum 2 required\n",
                init_msg->obj_list->num_entries);
    }

    double_linked_list_node *node = init_msg->obj_list->head;
    struct pcep_object_srp *srp_object = (struct pcep_object_srp *) node->data;
    if (srp_object->header.object_class != PCEP_OBJ_CLASS_SRP)
    {
        /* TODO reply with error */
        pcep_log(LOG_INFO, "Invalid PcInitiate message: First object must be an SRP, found [%d]\n",
                srp_object->header.object_class);
    }

    node = node->next_node;
    struct pcep_object_lsp *lsp_object = (struct pcep_object_lsp *) node->data;
    if (lsp_object->header.object_class != PCEP_OBJ_CLASS_LSP)
    {
        /* TODO reply with error */
        pcep_log(LOG_INFO, "Invalid PcInitiate message: Second object must be an LSP, found [%d]\n",
                lsp_object->header.object_class);
    }

    /* TODO finish this */

    if (init_msg->obj_list->num_entries > 3)
    {
        for (; node != NULL; node = node->next_node)
        {
            struct pcep_object_header *object = node->data;
            pcep_log(LOG_INFO, "Extra PcInitiate object: Class [%d] Type [%d] len [%d]\n",
                   object->object_class, object->object_type, object->object_length);
        }
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
    pcep_session *session = event->session;

    pcep_log(LOG_INFO, "[%ld-%ld] pcep_session_logic handle_timer_event: session_id [%d] event timer_id [%d] "
            "session timers [OKW, PRW, DT, KA] [%d, %d, %d, %d]\n",
            time(NULL), pthread_self(), session->session_id, event->expired_timer_id,
            session->timer_id_open_keep_wait, session->timer_id_pc_req_wait,
            session->timer_id_dead_timer, session->timer_id_keep_alive);

    /*
     * these timer expirations are independent of the session state
     */
    if (event->expired_timer_id == session->timer_id_dead_timer)
    {
        session->timer_id_dead_timer = TIMER_ID_NOT_SET;
        close_pcep_session_with_reason(session, PCEP_CLOSE_REASON_DEADTIMER);
        enqueue_event(session, PCE_DEAD_TIMER_EXPIRED, NULL);
        return;
    }
    else if(event->expired_timer_id == session->timer_id_keep_alive)
    {
        session->timer_id_keep_alive = TIMER_ID_NOT_SET;
        send_keep_alive(session);
        return;
    }

    /*
     * handle timers that depend on the session state
     */
    switch(session->session_state)
    {
    case SESSION_STATE_TCP_CONNECTED:
        if (event->expired_timer_id == session->timer_id_open_keep_wait)
        {
            /* close the TCP session */
            pcep_log(LOG_INFO, "handle_timer_event open_keep_wait timer expired for session [%d]\n", session->session_id);
            socket_comm_session_close_tcp_after_write(session->socket_comm_session);
            session->session_state = SESSION_STATE_INITIALIZED;
            session->timer_id_open_keep_wait = TIMER_ID_NOT_SET;
            enqueue_event(session, PCE_OPEN_KEEP_WAIT_TIMER_EXPIRED, NULL);
        }
        break;

    case SESSION_STATE_WAIT_PCREQ:
        if (event->expired_timer_id == session->timer_id_pc_req_wait)
        {
            pcep_log(LOG_INFO, "handle_timer_event PCReq_wait timer expired for session [%d]\n", session->session_id);
            /* TODO is this the right reason?? */
            close_pcep_session_with_reason(session, PCEP_CLOSE_REASON_DEADTIMER);
            session->timer_id_pc_req_wait = TIMER_ID_NOT_SET;
            enqueue_event(session, PCE_OPEN_KEEP_WAIT_TIMER_EXPIRED, NULL);
        }
        break;

    case SESSION_STATE_IDLE:
    case SESSION_STATE_INITIALIZED:
    case SESSION_STATE_OPENED:
    default:
        pcep_log(LOG_INFO, "handle_timer_event unrecognized state transition, timer_id [%d] state [%d] session_id [%d]\n",
                event->expired_timer_id, session->session_state, session->session_id);
        break;
    }
}


/* State machine handling for received messages.
 * This event was created in session_logic_msg_ready_handler() in
 * pcep_session_logic_loop.c */
void handle_socket_comm_event(pcep_session_event *event)
{
    if (event == NULL)
    {
        pcep_log(LOG_INFO, "WARN handle_socket_comm_event NULL event\n");
        return;
    }

    pcep_session *session = event->session;

    pcep_log(LOG_INFO, "[%ld-%ld] pcep_session_logic handle_socket_comm_event: session_id [%d] num messages [%d] socket_closed [%d]\n",
            time(NULL), pthread_self(),
            session->session_id,
            (event->received_msg_list == NULL ? -1 : event->received_msg_list->num_entries),
            event->socket_closed);

    /*
     * independent of the session state
     */
    if (event->socket_closed)
    {
        pcep_log(LOG_INFO, "handle_socket_comm_event socket closed for session [%d]\n", session->session_id);
        session->session_state = SESSION_STATE_INITIALIZED;
        socket_comm_session_close_tcp(session->socket_comm_session);
        enqueue_event(session, PCE_CLOSED_SOCKET, NULL);
        return;
    }

    reset_dead_timer(session);

    if (event->received_msg_list == NULL)
    {
        return;
    }

    double_linked_list_node *msg_node;
    for (msg_node = event->received_msg_list->head;
         msg_node != NULL;
         msg_node = msg_node->next_node)
    {
        bool message_enqueued = false;
        pcep_message *msg = (pcep_message *) msg_node->data;
        pcep_log(LOG_INFO, "\t %s message\n", get_message_type_str(msg->header->type));

        switch (msg->header->type)
        {
        case PCEP_TYPE_OPEN:
            handle_pcep_open(session, msg);
            enqueue_event(session, MESSAGE_RECEIVED, msg);
            message_enqueued = true;
            break;

        case PCEP_TYPE_KEEPALIVE:
            if (session->session_state == SESSION_STATE_TCP_CONNECTED)
            {
                session->session_state = SESSION_STATE_OPENED;
                cancel_timer(session->timer_id_open_keep_wait);
                session->timer_id_open_keep_wait = TIMER_ID_NOT_SET;
                enqueue_event(session, PCC_CONNECTED_TO_PCE, NULL);
            }
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
                /* TODO when this reaches a MAX, need to react */
                session->num_erroneous_messages++;
            }
            break;

        case PCEP_TYPE_CLOSE:
            session->session_state = SESSION_STATE_INITIALIZED;
            socket_comm_session_close_tcp(session->socket_comm_session);
            /* TODO should we also enqueue the message, so they can see the reasons?? */
            enqueue_event(session, PCE_SENT_PCEP_CLOSE, NULL);
            break;

        case PCEP_TYPE_PCREQ:
            /* TODO when this reaches a MAX, need to react.
             *      reply with pcep_error msg. */
            session->num_erroneous_messages++;
            break;

        case PCEP_TYPE_REPORT:
            /* TODO when this reaches a MAX, need to react.
             *      reply with pcep_error msg. */
            session->num_erroneous_messages++;
            break;

        case PCEP_TYPE_UPDATE:
            /* Should reply with a PcRpt */
            handle_pcep_update(session, msg);
            enqueue_event(session, MESSAGE_RECEIVED, msg);
            message_enqueued = true;
            break;

        case PCEP_TYPE_INITIATE:
            /* Should reply with a PcRpt */
            handle_pcep_initiate(session, msg);
            enqueue_event(session, MESSAGE_RECEIVED, msg);
            message_enqueued = true;
            break;

        case PCEP_TYPE_PCNOTF:
            /* TODO implement this */
            enqueue_event(session, MESSAGE_RECEIVED, msg);
            message_enqueued = true;
            break;
        case PCEP_TYPE_ERROR:
            /* TODO implement this */
            enqueue_event(session, MESSAGE_RECEIVED, msg);
            message_enqueued = true;
            break;

        default:
            pcep_log(LOG_INFO, "\t UnSupported message\n");
            break;
        }

        if (message_enqueued == false)
        {
            pcep_msg_free_message(msg);
        }
    }
    dll_destroy(event->received_msg_list);
}
