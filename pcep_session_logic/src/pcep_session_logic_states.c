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

#include "pcep_timers.h"
#include "pcep_session_logic.h"
#include "pcep_session_logic_internals.h"

/* global var needed for message_responses */
extern pcep_session_logic_handle *session_logic_handle_;

/*
 * util functions called by the state handling below
 */

void send_keep_alive(pcep_session *session)
{
    struct pcep_header* keep_alive_msg = pcep_msg_create_keepalive();

    printf("[%ld-%ld] pcep_session_logic send keep_alive message len [%d] for session_id [%d]\n",
            time(NULL), pthread_self(), ntohs(keep_alive_msg->length), session->session_id);

    socket_comm_session_send_message(
            session->socket_comm_session,
            (char *) keep_alive_msg,
            ntohs(keep_alive_msg->length),
            true);

    /* The keep alive timer will be (re)set once the message
     * is sent in session_logic_message_sent_handler() */
}


/* Send an error message with the "corrected" open object */
void send_pcep_open_error(pcep_session *session, struct pcep_object_open *open_obj)
{
    uint8_t *buffer;
    uint16_t buffer_len;
    struct pcep_object_error *error_obj;
    struct pcep_header *hdr;

    error_obj = pcep_obj_create_error(PCEP_ERRT_SESSION_FAILURE, PCEP_ERRV_RECVD_INVALID_OPEN_MSG);

    buffer_len = sizeof(struct pcep_header) +
            ntohs(open_obj->header.object_length) +
            ntohs(error_obj->header.object_length);
    buffer = malloc(sizeof(uint8_t) * buffer_len);
    bzero(buffer, buffer_len);

    hdr = (struct pcep_header*) buffer;
    hdr->length = htons(buffer_len);
    hdr->type = PCEP_TYPE_ERROR;
    hdr->ver_flags = PCEP_COMMON_HEADER_VER_FLAGS;

    memcpy(buffer + sizeof(struct pcep_header), error_obj, ntohs(error_obj->header.object_length));
    memcpy(buffer + sizeof(struct pcep_header) + ntohs(error_obj->header.object_length),
           open_obj, ntohs(open_obj->header.object_length));

    /* The open_obj will be freed when the received open message is freed */
    free(error_obj);
}


void send_pcep_error(pcep_session *session, enum pcep_error_type error_type, enum pcep_error_value error_value)
{
    struct pcep_header* error_msg = pcep_msg_create_error(error_type, error_value);
    socket_comm_session_send_message(
            session->socket_comm_session,
            (char *) error_msg,
            ntohs(error_msg->length),
            true);

    printf("[%ld-%ld] pcep_session_logic send error message [%d][%d] len [%d] for session_id [%d]\n",
            time(NULL), pthread_self(), error_type, error_value, ntohs(error_msg->length), session->session_id);
}


void reset_dead_timer(pcep_session *session)
{
    if (session->timer_id_dead_timer == TIMER_ID_NOT_SET)
    {
        printf("[%ld-%ld] pcep_session_logic set dead timer [%d secs] for session_id [%d]\n",
                time(NULL), pthread_self(), session->pce_config.keep_alive_seconds, session->session_id);
        session->timer_id_dead_timer = create_timer(session->pce_config.dead_timer_seconds, session);
    }
    else
    {
        printf("[%ld-%ld] pcep_session_logic reset dead timer [%d secs] for session_id [%d]\n",
                time(NULL), pthread_self(), session->pce_config.dead_timer_seconds, session->session_id);
        reset_timer(session->timer_id_dead_timer);
    }
}


void update_response_message(pcep_session *session, pcep_message *received_msg)
{
    if (session == NULL)
    {
        printf("WARN update_response_message NULL session\n");
        return;
    }

    if (received_msg == NULL)
    {
        printf("WARN update_response_message NULL received_msg_list\n");
        return;
    }

    /* iterate the message objects to get the RP object */
    struct pcep_object_rp *rp_object =
            (struct pcep_object_rp *) pcep_obj_get(received_msg->obj_list, PCEP_OBJ_CLASS_RP);
    if (rp_object == NULL)
    {
        fprintf(stderr, "ERROR in PCREP message: cant find mandatory RP object\n");
        /* TODO when this reaches a MAX, need to react */
        session->num_erroneous_messages++;
        return;
    }

    pcep_message_response msg_response_search;
    msg_response_search.request_id = rp_object->rp_reqidnumb;
    ordered_list_node *node =
            ordered_list_find(session_logic_handle_->response_msg_list, &msg_response_search);
    if (node == NULL)
    {
        fprintf(stderr, "WARN received a messages response id [%u] len [%d] class [%c] type [%c] that was not registered\n",
                rp_object->rp_reqidnumb, ntohs(rp_object->header.object_length),
                rp_object->header.object_class, rp_object->header.object_type);
        return;
    }
    pcep_message_response *msg_response = node->data;
    printf("[%ld-%ld] pcep_session_logic update_response_message response ready: session_id [%d] request_id [%d]\n",
            time(NULL), pthread_self(), session->session_id, msg_response->request_id);

    ordered_list_remove_first_node_equals(session_logic_handle_->response_msg_list, &msg_response_search);

    pthread_mutex_lock(&msg_response->response_mutex);
    msg_response->prev_response_status = msg_response->response_status;
    msg_response->response_status = RESPONSE_STATE_READY;
    msg_response->response_msg = received_msg;
    msg_response->response_condition = true;
    clock_gettime(CLOCK_REALTIME, &msg_response->time_response_received);
    pthread_cond_signal(&msg_response->response_cond_var);
    pthread_mutex_unlock(&msg_response->response_mutex);
}


/* Verify the received PCEP Open object parameters are acceptable. If not,
 * update the unacceptable value(s) with an acceptable value so it can be sent
 * back to the sender. */
bool verify_pcep_open(pcep_session *session, struct pcep_object_open *open_object)
{
    int retval = true;

    if (open_object->open_keepalive < session->pcc_config.min_keep_alive_seconds)
    {
        printf("WARN rejecting unsupported Open Keep Alive value [%d] min [%d]\n",
               open_object->open_keepalive, session->pcc_config.min_keep_alive_seconds);
        open_object->open_keepalive =
                session->pcc_config.min_keep_alive_seconds;
        retval = false;
    }
    else if (open_object->open_keepalive > session->pcc_config.max_keep_alive_seconds)
    {
        printf("WARN rejecting unsupported Open Keep Alive value [%d] max [%d]\n",
               open_object->open_keepalive, session->pcc_config.max_keep_alive_seconds);
        open_object->open_keepalive =
                session->pcc_config.max_keep_alive_seconds;
        retval = false;
    }

    if (open_object->open_deadtimer < session->pcc_config.min_dead_timer_seconds)
    {
        printf("WARN rejecting unsupported Open Dead Timer value [%d]\n",
               open_object->open_deadtimer);
        open_object->open_deadtimer =
                session->pcc_config.min_dead_timer_seconds;
        retval = false;
    }
    else if (open_object->open_keepalive > session->pcc_config.max_dead_timer_seconds)
    {
        printf("WARN rejecting unsupported Open Dead Timer value [%d]\n",
               open_object->open_deadtimer);
        open_object->open_deadtimer =
                session->pcc_config.max_dead_timer_seconds;
        retval = false;
    }

    /* Check for Open Object TLVs */
    if (pcep_obj_has_tlv((struct pcep_object_header*) open_object, sizeof(struct pcep_object_open)) == false)
    {
        /* There are no TLVs, all done */
        return retval;
    }

    double_linked_list *tlv_list = pcep_obj_get_tlvs(
            (struct pcep_object_header *) open_object,
            (struct pcep_object_tlv *) (((char *) open_object) + sizeof(struct pcep_object_open)));

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
                    printf("WARN rejecting unsupported Open STATEFUL-PCE-CAPABILITY TLV U flag\n");
                    tlv->value[0] &= ~PCEP_TLV_FLAG_LSP_UPDATE_CAPABILITY;
                    retval = false;
                }
                else
                {
                    session->stateful_pce  = true;
                    printf("Setting PCEP session [%d] STATEFUL to support LSP updates\n",
                            session->session_id);
                }
            }
            /* TODO the rest of the flags are not implemented yet */
            else if (tlv->value[0] & PCEP_TLV_FLAG_INCLUDE_DB_VERSION)
            {
                printf("Ignoring Open STATEFUL-PCE-CAPABILITY TLV S flag\n");
            }
            else if (tlv->value[0] & PCEP_TLV_FLAG_LSP_INSTANTIATION)
            {
                printf("Ignoring Open STATEFUL-PCE-CAPABILITY TLV I flag\n");
            }
            else if (tlv->value[0] & PCEP_TLV_FLAG_TRIGGERED_RESYNC)
            {
                printf("Ignoring Open STATEFUL-PCE-CAPABILITY TLV T flag\n");
            }
            else if (tlv->value[0] & PCEP_TLV_FLAG_DELTA_LSP_SYNC)
            {
                printf("Ignoring Open STATEFUL-PCE-CAPABILITY TLV D flag\n");
            }
            else if (tlv->value[0] & PCEP_TLV_FLAG_TRIGGERED_INITIAL_SYNC)
            {
                printf("Ignoring Open STATEFUL-PCE-CAPABILITY TLV F flag\n");
            }
        }
        else
        {
            /* TODO TODO how to handle unrecognized TLV ?? */
            printf("Unhandled OPEN TLV type: %d, length %d\n",
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
        printf("There are additional objects in the Open message\n");
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
        fprintf(stderr, "Invalid PcUpd message: Message has no objects\n");
    }

    if (upd_msg->obj_list->num_entries < 3)
    {
        /* TODO reply with error */
        fprintf(stderr, "Invalid PcUpd message: Message only has [%d] objects, minimum 3 required\n",
                upd_msg->obj_list->num_entries);
    }

    double_linked_list_node *node = upd_msg->obj_list->head;
    struct pcep_object_srp *srp_object = (struct pcep_object_srp *) node->data;
    if (srp_object->header.object_class != PCEP_OBJ_CLASS_SRP)
    {
        /* TODO reply with error */
        fprintf(stderr, "Invalid PcUpd message: First object must be an SRP, found [%d]\n",
                srp_object->header.object_class);
    }

    node = node->next_node;
    struct pcep_object_lsp *lsp_object = (struct pcep_object_lsp *) node->data;
    if (lsp_object->header.object_class != PCEP_OBJ_CLASS_LSP)
    {
        /* TODO reply with error */
        fprintf(stderr, "Invalid PcUpd message: Second object must be an LSP, found [%d]\n",
                lsp_object->header.object_class);
    }

    node = node->next_node;
    struct pcep_object_ro *ero_object = node->data;
    if (ero_object->header.object_class != PCEP_OBJ_CLASS_ERO)
    {
        /* TODO reply with error */
        fprintf(stderr, "Invalid PcUpd message: Third object must be an ERO, found [%d]\n",
                ero_object->header.object_class);
    }

    /* TODO finish this */

    if (upd_msg->obj_list->num_entries > 3)
    {
        for (; node != NULL; node = node->next_node)
        {
            struct pcep_object_header *object = node->data;
            printf("Extra PcUpd object: Class [%d] Type [%d] len [%d]\n",
                   object->object_class, object->object_type, object->object_length);
        }
    }
}

void handle_pcep_initiate(pcep_session *session, pcep_message *init_msg)
{
    if (init_msg->obj_list == NULL)
    {
        /* TODO reply with error */
        fprintf(stderr, "Invalid PcInitiate message: Message has no objects\n");
    }

    if (init_msg->obj_list->num_entries < 2)
    {
        /* TODO reply with error */
        fprintf(stderr, "Invalid PcInitiate message: Message only has [%d] objects, minimum 2 required\n",
                init_msg->obj_list->num_entries);
    }

    double_linked_list_node *node = init_msg->obj_list->head;
    struct pcep_object_srp *srp_object = (struct pcep_object_srp *) node->data;
    if (srp_object->header.object_class != PCEP_OBJ_CLASS_SRP)
    {
        /* TODO reply with error */
        fprintf(stderr, "Invalid PcInitiate message: First object must be an SRP, found [%d]\n",
                srp_object->header.object_class);
    }

    node = node->next_node;
    struct pcep_object_lsp *lsp_object = (struct pcep_object_lsp *) node->data;
    if (lsp_object->header.object_class != PCEP_OBJ_CLASS_LSP)
    {
        /* TODO reply with error */
        fprintf(stderr, "Invalid PcInitiate message: Second object must be an LSP, found [%d]\n",
                lsp_object->header.object_class);
    }

    /* TODO finish this */

    if (init_msg->obj_list->num_entries > 3)
    {
        for (; node != NULL; node = node->next_node)
        {
            struct pcep_object_header *object = node->data;
            printf("Extra PcInitiate object: Class [%d] Type [%d] len [%d]\n",
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

    printf("[%ld-%ld] pcep_session_logic handle_timer_event: session_id [%d] event timer_id [%d] "
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
            printf("handle_timer_event open_keep_wait timer expired for session [%d]\n", session->session_id);
            socket_comm_session_close_tcp_after_write(session->socket_comm_session);
            session->session_state = SESSION_STATE_INITIALIZED;
            session->timer_id_open_keep_wait = TIMER_ID_NOT_SET;
        }
        break;

    case SESSION_STATE_WAIT_PCREQ:
        if (event->expired_timer_id == session->timer_id_pc_req_wait)
        {
            printf("handle_timer_event PCReq_wait timer expired for session [%d]\n", session->session_id);
            /* TODO is this the right reason?? */
            close_pcep_session_with_reason(session, PCEP_CLOSE_REASON_DEADTIMER);
            session->timer_id_pc_req_wait = TIMER_ID_NOT_SET;
        }
        break;

    case SESSION_STATE_IDLE:
    case SESSION_STATE_INITIALIZED:
    case SESSION_STATE_OPENED:
    default:
        fprintf(stderr, "handle_timer_event unrecognized state transition, timer_id [%d] state [%d] session_id [%d]\n",
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
        printf("WARN handle_socket_comm_event NULL event\n");
        return;
    }

    pcep_session *session = event->session;

    printf("[%ld-%ld] pcep_session_logic handle_socket_comm_event: session_id [%d] num messages [%d] socket_closed [%d]\n",
            time(NULL), pthread_self(),
            session->session_id,
            (event->received_msg_list == NULL ? -1 : event->received_msg_list->num_entries),
            event->socket_closed);

    /*
     * independent of the session state
     */
    if (event->socket_closed)
    {
        printf("handle_socket_comm_event socket closed for session [%d]\n", session->session_id);
        session->session_state = SESSION_STATE_INITIALIZED;
        socket_comm_session_close_tcp(session->socket_comm_session);
        return;
    }

    if (event->received_msg_list == NULL)
    {
        return;
    }

    double_linked_list_node *msg_node;
    for (msg_node = event->received_msg_list->head;
         msg_node != NULL;
         msg_node = msg_node->next_node)
    {
        pcep_message *msg = (pcep_message *) msg_node->data;
        reset_dead_timer(session);

        switch (msg->header.type)
        {
        case PCEP_TYPE_OPEN:
            printf("\t PCEP_OPEN message\n");
            handle_pcep_open(session, msg);

            break;

        case PCEP_TYPE_KEEPALIVE:
            printf("\t PCEP_KEEPALIVE message\n");
            if (session->session_state == SESSION_STATE_TCP_CONNECTED)
            {
                session->session_state = SESSION_STATE_OPENED;
                cancel_timer(session->timer_id_open_keep_wait);
                session->timer_id_open_keep_wait = TIMER_ID_NOT_SET;
            }
            break;

        case PCEP_TYPE_PCREP:
            printf("\t PCEP_PCREP message\n");
            update_response_message(session, msg);
            if (session->session_state == SESSION_STATE_WAIT_PCREQ)
            {
                session->session_state = SESSION_STATE_IDLE;
                cancel_timer(session->timer_id_pc_req_wait);
                session->timer_id_pc_req_wait = TIMER_ID_NOT_SET;
            }
            else
            {
                /* TODO when this reaches a MAX, need to react */
                session->num_erroneous_messages++;
            }
            break;

        case PCEP_TYPE_CLOSE:
            printf("\t PCEP_CLOSE message\n");
            session->session_state = SESSION_STATE_INITIALIZED;
            socket_comm_session_close_tcp(session->socket_comm_session);
            break;

        case PCEP_TYPE_PCREQ:
            printf("\t PCEP_PCREQ message\n");
            /* TODO when this reaches a MAX, need to react.
             *      reply with pcep_error msg. */
            session->num_erroneous_messages++;
            break;

        case PCEP_TYPE_REPORT:
            printf("\t PCEP_PCRPT message\n");
            /* TODO when this reaches a MAX, need to react.
             *      reply with pcep_error msg. */
            session->num_erroneous_messages++;
            break;

        case PCEP_TYPE_UPDATE:
            printf("\t PCEP_PCUPD message\n");
            /* Should reply with a PcRpt */
            handle_pcep_update(session, msg);
            break;

        case PCEP_TYPE_INITIATE:
            printf("\t PCEP_PCInitiate message\n");
            /* Should reply with a PcRpt */
            handle_pcep_initiate(session, msg);
            break;

        case PCEP_TYPE_PCNOTF:
            printf("\t PCEP_PCNOTF message\n");
            /* TODO implement this */
            break;
        case PCEP_TYPE_ERROR:
            printf("\t PCEP_ERROR message\n");
            /* TODO implement this */
            break;

        default:
            printf("\t UnSupported message\n");
            break;
        }
    }

    /* Traverse the msg_list and free everything */
    pcep_msg_free(event->received_msg_list);
}
