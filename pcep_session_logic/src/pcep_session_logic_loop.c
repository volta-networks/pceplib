/*
 * pcep_session_logic_loop.c
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
 * messages are ready to be read. this function will be called
 * by the socket_comm thread.
 * this function will marshal the read PCEP message and give it
 * to the session_logic_loop so it can be handled by the session_logic
 * state machine. */
int session_logic_msg_ready_handler(void *data, int socket_fd)
{
    pcep_session *session = (pcep_session *) data;

    pthread_mutex_lock(&(session_logic_handle_->session_logic_mutex));
    session_logic_handle_->session_logic_condition = true;
    /* TODO how to determine if the socket was closed */
    struct pcep_messages_list *msg_list = pcep_msg_read(socket_fd);
    if (msg_list == NULL)
    {
        fprintf(stderr, "Error marshalling PCEP message\n");
        pthread_mutex_unlock(&(session_logic_handle_->session_logic_mutex));

        return -1;
    }

    printf("[%ld-%ld] session_logic_msg_ready_handler received message of type [%d] len [%d] on session_id [%d]\n",
            time(NULL), pthread_self(), msg_list->header.type, msg_list->header.length, session->session_id);

    pcep_session_event *rcvd_msg_event = create_session_event(session);
    rcvd_msg_event->received_msg_list = msg_list;
    queue_enqueue(session_logic_handle_->session_event_queue, rcvd_msg_event);


    pthread_cond_signal(&(session_logic_handle_->session_logic_cond_var));
    pthread_mutex_unlock(&(session_logic_handle_->session_logic_mutex));

    return msg_list->header.length;
}


/* A function pointer to this function was passed to pcep_socket_comm,
 * so it will be called whenever the socket is closed. this function
 * will be called by the socket_comm thread. */
void session_logic_conn_except_notifier(void *data, int socket_fd)
{
    pcep_session *session = (pcep_session *) data;
    printf("[%ld-%ld] pcep_session_logic session_logic_conn_except_notifier socket closed [%d], session_id [%d]\n",
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
        fprintf(stderr, "Cannot handle timer with NULL data\n");
        return;
    }

    printf("[%ld-%ld] timer expired handler timer_id [%d]\n", time(NULL), pthread_self(), timer_id);
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
        fprintf(stderr, "Cannot start session_logic_loop with NULL data");

        return NULL;
    }

    printf("[%ld-%ld] starting session_logic_loop thread\n", time(NULL), pthread_self());

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

    return NULL;
}
