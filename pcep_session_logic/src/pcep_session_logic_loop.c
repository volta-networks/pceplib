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

#include "pcep_session_logic.h"
#include "pcep_session_logic_internals.h"
#include "pcep_timers.h"
#include "pcep_utils_logging.h"

/* global var needed for callback handlers */
extern pcep_session_logic_handle *session_logic_handle_;

/* internal util function to create session_event's */
static pcep_session_event *create_session_event(pcep_session *session)
{
    pcep_session_event *event = malloc(sizeof(pcep_session_event));
    event->session = session;
    event->expired_timer_id = TIMER_ID_NOT_SET;
    event->received_msg_list = NULL;
    event->socket_closed = false;

    return event;
}


/* A function pointer to this function is passed to pcep_socket_comm
 * for each pcep_session creation, so it will be called whenever
 * messages are ready to be read. This function will be called
 * by the socket_comm thread.
 * This function will decode the read PCEP message and give it
 * to the session_logic_loop so it can be handled by the session_logic
 * state machine. */
int session_logic_msg_ready_handler(void *data, int socket_fd)
{
    if (data == NULL)
    {
        pcep_log(LOG_WARNING, "Cannot handle msg_ready with NULL data");
        return -1;
    }

    if (session_logic_handle_->active == false)
    {
        pcep_log(LOG_WARNING, "Received a message ready notification while the session logic is not active");
        return -1;
    }

    pcep_session *session = (pcep_session *) data;

    pthread_mutex_lock(&(session_logic_handle_->session_logic_mutex));
    session_logic_handle_->session_logic_condition = true;

    /* This event will ultimately be handled by handle_socket_comm_event()
     * in pcep_session_logic_states.c */
    pcep_session_event *rcvd_msg_event = create_session_event(session);

    int msg_length = 0;
    double_linked_list *msg_list = pcep_msg_read(socket_fd);

    if (msg_list == NULL || msg_list->num_entries == 0)
    {
        pcep_log(LOG_INFO, "PCEP connection closed for pcep_session [%d]", session->session_id);
        dll_destroy(msg_list);
        rcvd_msg_event->socket_closed = true;
        socket_comm_session_teardown(session->socket_comm_session);
        pcep_session_cancel_timers(session);
        session->socket_comm_session = NULL;
        session->session_state = SESSION_STATE_INITIALIZED;
    }
    else
    {
        /* Just logging the first of potentially several messages received */
        struct pcep_message *msg = ((struct pcep_message *) msg_list->head->data);
        pcep_log(LOG_INFO, "[%ld-%ld] session_logic_msg_ready_handler received message of type [%d] len [%d] on session_id [%d]",
                time(NULL), pthread_self(), msg->msg_header->type, msg->encoded_message_length, session->session_id);

        rcvd_msg_event->received_msg_list = msg_list;
        msg_length = msg->encoded_message_length;
    }

    queue_enqueue(session_logic_handle_->session_event_queue, rcvd_msg_event);
    pthread_cond_signal(&(session_logic_handle_->session_logic_cond_var));
    pthread_mutex_unlock(&(session_logic_handle_->session_logic_mutex));

    return msg_length;
}


/* A function pointer to this function was passed to pcep_socket_comm,
 * so it will be called when a message is sent. This is useful since
 * message sending is asynchronous, and there are times that actions
 * need to be performed only after a message has been sent. */
void session_logic_message_sent_handler(void *data, int socket_fd)
{
    if (data == NULL)
    {
        pcep_log(LOG_WARNING, "Cannot handle msg_sent with NULL data");
        return;
    }

    pcep_session *session = (pcep_session *) data;
    if (session->destroy_session_after_write == true)
    {
        /* Do not call destroy until all of the queued messages are written */
        if (session->socket_comm_session->message_queue->num_entries == 0)
        {
            destroy_pcep_session(session);
        }
    }
    else
    {
        /* Reset the keep alive timer for every message sent on
         * the session, only if the session is not destroyed */
        if (session->timer_id_keep_alive == TIMER_ID_NOT_SET)
        {
            pcep_log(LOG_INFO, "[%ld-%ld] pcep_session_logic set keep alive timer [%d secs] for session_id [%d]",
                    time(NULL), pthread_self(), session->pce_config.keep_alive_seconds, session->session_id);
            session->timer_id_keep_alive = create_timer(session->pce_config.keep_alive_seconds, session);
        }
        else
        {
            pcep_log(LOG_INFO, "[%ld-%ld] pcep_session_logic reset keep alive timer [%d secs] for session_id [%d]",
                    time(NULL), pthread_self(), session->pce_config.keep_alive_seconds, session->session_id);
            reset_timer(session->timer_id_keep_alive);
        }
    }

}


/* A function pointer to this function was passed to pcep_socket_comm,
 * so it will be called whenever the socket is closed. this function
 * will be called by the socket_comm thread. */
void session_logic_conn_except_notifier(void *data, int socket_fd)
{
    if (data == NULL)
    {
        pcep_log(LOG_WARNING, "Cannot handle conn_except with NULL data");
        return;
    }

    if (session_logic_handle_->active == false)
    {
        pcep_log(LOG_WARNING, "Received a connection exception notification while the session logic is not active");
        return;
    }

    pcep_session *session = (pcep_session *) data;
    pcep_log(LOG_INFO, "[%ld-%ld] pcep_session_logic session_logic_conn_except_notifier socket closed [%d], session_id [%d]",
            time(NULL), pthread_self(), socket_fd, session->session_id);

    pthread_mutex_lock(&(session_logic_handle_->session_logic_mutex));
    pcep_session_event *socket_event = create_session_event(session);
    socket_event->socket_closed = true;
    queue_enqueue(session_logic_handle_->session_event_queue, socket_event);
    session_logic_handle_->session_logic_condition = true;

    pthread_cond_signal(&(session_logic_handle_->session_logic_cond_var));
    pthread_mutex_unlock(&(session_logic_handle_->session_logic_mutex));
}


/*
 * this method is the timer expire handler, and will only
 * pass the event to the session_logic loop and notify it
 * that there is a timer available. this function will be
 * called by the timers thread.
 */
void session_logic_timer_expire_handler(void *data, int timer_id)
{
    if (data == NULL)
    {
        pcep_log(LOG_WARNING, "Cannot handle timer with NULL data");
        return;
    }

    if (session_logic_handle_->active == false)
    {
        pcep_log(LOG_WARNING, "Received a timer expiration while the session logic is not active");
        return;
    }

    pcep_log(LOG_INFO, "[%ld-%ld] timer expired handler timer_id [%d]", time(NULL), pthread_self(), timer_id);
    pcep_session_event *expired_timer_event = create_session_event((pcep_session *) data);
    expired_timer_event->expired_timer_id = timer_id;

    pthread_mutex_lock(&(session_logic_handle_->session_logic_mutex));
    session_logic_handle_->session_logic_condition = true;
    queue_enqueue(session_logic_handle_->session_event_queue, expired_timer_event);

    pthread_cond_signal(&(session_logic_handle_->session_logic_cond_var));
    pthread_mutex_unlock(&(session_logic_handle_->session_logic_mutex));
}


/*
 * session_logic event loop
 * this function is called upon thread creation from pcep_session_logic.c
 */
void *session_logic_loop(void *data)
{
    if (data == NULL)
    {
        pcep_log(LOG_WARNING, "Cannot start session_logic_loop with NULL data");

        return NULL;
    }

    pcep_log(LOG_NOTICE, "[%ld-%ld] Starting session_logic_loop thread", time(NULL), pthread_self());

    pcep_session_logic_handle *session_logic_handle = (pcep_session_logic_handle *) data;

    while (session_logic_handle->active)
    {
        pthread_mutex_lock(&(session_logic_handle->session_logic_mutex));

        /* this internal loop helps avoid spurious interrupts */
        while (!session_logic_handle->session_logic_condition)
        {
            pthread_cond_wait(&(session_logic_handle->session_logic_cond_var),
                              &(session_logic_handle->session_logic_mutex));
        }

        pcep_session_event *event = queue_dequeue(session_logic_handle->session_event_queue);
        while (event != NULL)
        {
            if (event->expired_timer_id != TIMER_ID_NOT_SET)
            {
                handle_timer_event(event);
            }

            if (event->received_msg_list != NULL)
            {
                handle_socket_comm_event(event);
            }

            /* TODO use this as the API to create sessions, etc
            handle_nbi(session_logic_handle);
             */

            free(event);
            event = queue_dequeue(session_logic_handle->session_event_queue);
        }

        session_logic_handle->session_logic_condition = false;
        pthread_mutex_unlock(&(session_logic_handle->session_logic_mutex));
    }

    pcep_log(LOG_NOTICE, "[%ld-%ld] Finished session_logic_loop thread", time(NULL), pthread_self());

    return NULL;
}
