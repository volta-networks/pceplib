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
    socket_comm_session_send_message(
            session->socket_comm_session,
            (char *) keep_alive_msg,
            ntohs(keep_alive_msg->length),
            true);

    printf("[%ld-%ld] pcep_session_logic send keep_alive message len [%d] for session_id [%d]\n",
            time(NULL), pthread_self(), ntohs(keep_alive_msg->length), session->session_id);

    /* The keep alive timer will be (re)set once the message
     * is sent in session_logic_message_sent_handler() */
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


void update_response_message(pcep_session *session, struct pcep_messages_list *received_msg_list)
{
    if (session == NULL)
    {
        printf("WARN update_response_message NULL session\n");
        return;
    }

    if (received_msg_list == NULL)
    {
        printf("WARN update_response_message NULL received_msg_list\n");
        return;
    }

    /* iterate the message objects to get the RP object */
    bool found_rpObject = false;
    struct pcep_obj_list *list_entry = received_msg_list->list;
    while (list_entry != NULL && found_rpObject == false)
    {
        if (list_entry->header->object_class == PCEP_OBJ_CLASS_RP)
        {
            found_rpObject = true;
        }
        else
        {
            list_entry = list_entry->next;
        }
    }

    if (!found_rpObject)
    {
        fprintf(stderr, "ERROR in PCREP message: cant find mandatory RP object\n");
        /* TODO when this reaches a MAX, need to react */
        session->num_erroneous_messages++;
        return;
    }

    struct pcep_object_rp *rp_object = (struct pcep_object_rp *) list_entry->header;
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
    msg_response->response_msg_list = received_msg_list;
    msg_response->response_condition = true;
    clock_gettime(CLOCK_REALTIME, &msg_response->time_response_received);
    pthread_cond_signal(&msg_response->response_cond_var);
    pthread_mutex_unlock(&msg_response->response_mutex);
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


/* state machine handling for received messages */
void handle_socket_comm_event(pcep_session_event *event)
{
    if (event == NULL)
    {
        printf("WARN handle_socket_comm_event NULL event\n");
        return;
    }

    pcep_session *session = event->session;

    printf("[%ld-%ld] pcep_session_logic handle_socket_comm_event: session_id [%d] msg_type [%d] socket_closed [%d]\n",
            time(NULL), pthread_self(),
            session->session_id,
            (event->received_msg_list == NULL ? -1 : event->received_msg_list->header.type),
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

    switch (event->received_msg_list->header.type)
    {
    case PCEP_TYPE_OPEN:
        printf("\t PCEP_OPEN message\n");

        if (session->pcep_open_received == false)
        {
            struct pcep_object_open *open_object =
                    (struct pcep_object_open *) event->received_msg_list->list->header;
            session->pce_config.dead_timer_seconds = open_object->open_deadtimer;
            session->pce_config.keep_alive_seconds = open_object->open_keepalive;
            session->pcep_open_received = true;
            reset_dead_timer(session);
            send_keep_alive(session);
        }
        else
        {
            /* TODO when this reaches a MAX, need to react */
            session->num_erroneous_messages++;
        }
        break;

    case PCEP_TYPE_KEEPALIVE:
        printf("\t PCEP_KEEPALIVE message\n");
        reset_dead_timer(session);
        if (session->session_state == SESSION_STATE_TCP_CONNECTED)
        {
            session->session_state = SESSION_STATE_OPENED;
            cancel_timer(session->timer_id_open_keep_wait);
            session->timer_id_open_keep_wait = TIMER_ID_NOT_SET;
        }
        break;

    case PCEP_TYPE_PCREP:
        printf("\t PCEP_PCREP message\n");
        reset_dead_timer(session);
        update_response_message(session, event->received_msg_list);
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

    case PCEP_TYPE_PCNOTF:
        printf("\t PCEP_PCNOTF message\n");
        reset_dead_timer(session);
        /* TODO implement this */
        break;
    case PCEP_TYPE_ERROR:
        printf("\t PCEP_ERROR message\n");
        reset_dead_timer(session);
        /* TODO implement this */
        break;
    default:
        break;
    }

    /* Traverse the msg_list and free everything */
    pcep_msg_free(event->received_msg_list);
}
