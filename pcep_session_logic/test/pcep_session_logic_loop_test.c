/*
 * pcep_session_logic_loop_test.c
 *
 *  Created on: Oct 9, 2019
 *      Author: brady
 */


#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <CUnit/CUnit.h>

#include "pcep_session_logic.h"
#include "pcep_session_logic_internals.h"
#include "pcep_timers.h"
#include "pcep_utils_ordered_list.h"


extern pcep_session_logic_handle *session_logic_handle_;
extern int session_id_compare_function(void *list_entry, void *new_entry);


/*
 * Test case setup and teardown called before AND after each test.
 */

void pcep_session_logic_loop_test_setup()
{
    /* We need to setup the session_logic_handle_ without starting the thread */
    session_logic_handle_ = malloc(sizeof(pcep_session_logic_handle));
    bzero(session_logic_handle_, sizeof(pcep_session_logic_handle));
    session_logic_handle_->active = true;
    session_logic_handle_->session_logic_condition = false;
    session_logic_handle_->session_list = ordered_list_initialize(session_id_compare_function);
    session_logic_handle_->session_event_queue = queue_initialize();
    pthread_cond_init(&(session_logic_handle_->session_logic_cond_var), NULL);
    pthread_mutex_init(&(session_logic_handle_->session_logic_mutex), NULL);
}


void pcep_session_logic_loop_test_teardown()
{
    ordered_list_destroy(session_logic_handle_->session_list);
    queue_destroy(session_logic_handle_->session_event_queue);
    pthread_mutex_unlock(&(session_logic_handle_->session_logic_mutex));
    pthread_mutex_destroy(&(session_logic_handle_->session_logic_mutex));
    free(session_logic_handle_);
    session_logic_handle_ = NULL;
}


/*
 * Test cases
 */

void test_session_logic_loop_null_data()
{
    /* Just testing that it does not core dump */
    session_logic_loop(NULL);
}


void test_session_logic_loop_inactive()
{
    session_logic_handle_->active = false;

    session_logic_loop(session_logic_handle_);
}


void test_session_logic_msg_ready_handler()
{
    /* Just testing that it does not core dump */
    CU_ASSERT_EQUAL(session_logic_msg_ready_handler(NULL, 0), -1);

    /* Read from an empty file should return 0, thus session_logic_msg_ready_handler returns -1 */
    int fd = fileno(tmpfile());
    pcep_session session;
    bzero(&session, sizeof(pcep_session));
    session.session_id = 100;
    CU_ASSERT_EQUAL(session_logic_msg_ready_handler(&session, fd), -1);
    CU_ASSERT_EQUAL(session_logic_handle_->session_event_queue->num_entries, 0);

    /* A pcep_session_event should be created */
    struct pcep_header* keep_alive_msg = pcep_msg_create_keepalive();
    write(fd, (char *) keep_alive_msg, ntohs(keep_alive_msg->length));
    lseek(fd, 0, SEEK_SET);
    CU_ASSERT_EQUAL(session_logic_msg_ready_handler(&session, fd), ntohs(keep_alive_msg->length));
    CU_ASSERT_EQUAL(session_logic_handle_->session_event_queue->num_entries, 1);
    pcep_session_event *socket_event =
            (pcep_session_event *) queue_dequeue(session_logic_handle_->session_event_queue);
    CU_ASSERT_PTR_NOT_NULL_FATAL(socket_event);
    CU_ASSERT_FALSE(socket_event->socket_closed);
    CU_ASSERT_PTR_EQUAL(socket_event->session, &session);
    CU_ASSERT_EQUAL(socket_event->expired_timer_id, TIMER_ID_NOT_SET);
    CU_ASSERT_PTR_NOT_NULL(socket_event->received_msg_list);
    pcep_msg_free_message_list(socket_event->received_msg_list);
    free(socket_event);
    free(keep_alive_msg);
    close(fd);
}


void test_session_logic_conn_except_notifier()
{
    /* Just testing that it does not core dump */
    session_logic_conn_except_notifier(NULL, 1);

    /* A pcep_session_event should be created */
    pcep_session session;
    bzero(&session, sizeof(pcep_session));
    session.session_id = 100;
    session_logic_conn_except_notifier(&session, 10);
    CU_ASSERT_EQUAL(session_logic_handle_->session_event_queue->num_entries, 1);
    pcep_session_event *socket_event =
            (pcep_session_event *) queue_dequeue(session_logic_handle_->session_event_queue);
    CU_ASSERT_PTR_NOT_NULL_FATAL(socket_event);
    CU_ASSERT_TRUE(socket_event->socket_closed);
    CU_ASSERT_PTR_EQUAL(socket_event->session, &session);
    CU_ASSERT_EQUAL(socket_event->expired_timer_id, TIMER_ID_NOT_SET);
    CU_ASSERT_PTR_NULL(socket_event->received_msg_list);

    free(socket_event);
}


void test_session_logic_timer_expire_handler()
{
    /* Just testing that it does not core dump */
    session_logic_timer_expire_handler(NULL, 42);

    /* A pcep_session_event should be created */
    pcep_session session;
    bzero(&session, sizeof(pcep_session));
    session.session_id = 100;
    session_logic_timer_expire_handler(&session, 42);
    CU_ASSERT_EQUAL(session_logic_handle_->session_event_queue->num_entries, 1);
    pcep_session_event *socket_event =
            (pcep_session_event *) queue_dequeue(session_logic_handle_->session_event_queue);
    CU_ASSERT_PTR_NOT_NULL_FATAL(socket_event);
    CU_ASSERT_FALSE(socket_event->socket_closed);
    CU_ASSERT_PTR_EQUAL(socket_event->session, &session);
    CU_ASSERT_EQUAL(socket_event->expired_timer_id, 42);
    CU_ASSERT_PTR_NULL(socket_event->received_msg_list);

    free(socket_event);
}
