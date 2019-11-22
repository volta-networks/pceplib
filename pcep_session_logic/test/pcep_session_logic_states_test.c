/*
 * pcep_session_logic_states_test.c
 *
 *  Created on: Oct 9, 2019
 *      Author: brady
 */


#include <stdlib.h>
#include <string.h>

#include <CUnit/CUnit.h>

#include "mock_socket_comm.h"
#include "pcep_session_logic.h"
#include "pcep_session_logic_internals.h"
#include "pcep_timers.h"
#include "pcep_utils_ordered_list.h"
#include "pcep_utils_double_linked_list.h"
#include "pcep-objects.h"
#include "pcep-tools.h"

/* Functions being tested */
extern pcep_session_logic_handle *session_logic_handle_;
extern pcep_event_queue *session_logic_event_queue_;

static pcep_session_event event;
static pcep_session session;
/* A message list is a dll of struct pcep_messages_list_node items */
static double_linked_list *msg_list;
pcep_message *message;
static bool do_msg_free = true;

/*
 * Test case setup and teardown called before AND after each test.
 */

void pcep_session_logic_states_test_setup()
{
    session_logic_handle_ = malloc(sizeof(pcep_session_logic_handle));
    bzero(session_logic_handle_, sizeof(pcep_session_logic_handle));

    session_logic_event_queue_ = malloc(sizeof(pcep_event_queue));
    bzero(session_logic_event_queue_, sizeof(pcep_event_queue));
    session_logic_event_queue_->event_queue = queue_initialize();

    bzero(&session, sizeof(pcep_session));
    session.pcc_config.keep_alive_seconds = 5;
    session.pcc_config.min_keep_alive_seconds = 1;
    session.pcc_config.max_keep_alive_seconds = 10;
    session.pcc_config.dead_timer_seconds = 5;
    session.pcc_config.min_dead_timer_seconds = 1;
    session.pcc_config.max_dead_timer_seconds = 10;
    memcpy(&session.pce_config, &session.pcc_config, sizeof(pcep_configuration));

    bzero(&event, sizeof(pcep_session_event));
    event.socket_closed = false;
    event.session = &session;

    message = malloc(sizeof(pcep_message));
    bzero(message, sizeof(struct pcep_message));
    message->header = malloc(sizeof(struct pcep_header));
    message->obj_list = dll_initialize();

    msg_list = dll_initialize();
    dll_append(msg_list, message);

    reset_mock_socket_comm_info();
    do_msg_free = true;
}


void pcep_session_logic_states_test_teardown()
{
    /* Some test cases internally free the message, so we dont want to double free it */
    if (do_msg_free == true)
    {
        /* This will destroy both the msg_list and the obj_list */
        pcep_msg_free_message_list(msg_list);
    }
    free(session_logic_handle_);
    queue_destroy(session_logic_event_queue_->event_queue);
    free(session_logic_event_queue_);
    session_logic_handle_ = NULL;
    session_logic_event_queue_ = NULL;
}


/*
 * Test cases
 */

void test_handle_timer_event_dead_timer()
{
    /* Dead Timer expired */
    event.expired_timer_id = session.timer_id_dead_timer = 100;

    handle_timer_event(&event);

    CU_ASSERT_EQUAL(session.timer_id_dead_timer, TIMER_ID_NOT_SET);
    CU_ASSERT_EQUAL(session.session_state, SESSION_STATE_INITIALIZED);
    CU_ASSERT_EQUAL(session_logic_event_queue_->event_queue->num_entries, 1);

    pcep_event *e = queue_dequeue(session_logic_event_queue_->event_queue);
    CU_ASSERT_EQUAL(PCE_DEAD_TIMER_EXPIRED, e->event_type);
    free(e);

    /* verify_socket_comm_times_called(
     *     initialized, teardown, connect, send_message, close_after_write, close, destroy); */
    verify_socket_comm_times_called(0, 0, 0, 1, 1, 0, 0);
}


void test_handle_timer_event_keep_alive()
{
    /* Keep Alive timer expired */
    event.expired_timer_id = session.timer_id_keep_alive = 200;

    handle_timer_event(&event);

    CU_ASSERT_EQUAL(session.timer_id_keep_alive, TIMER_ID_NOT_SET);
    verify_socket_comm_times_called(0, 0, 0, 1, 0, 0, 0);
}


void test_handle_timer_event_open_keep_wait()
{
    /* Open Keep Wait timer expired */
    event.expired_timer_id = session.timer_id_open_keep_wait = 300;
    session.session_state = SESSION_STATE_TCP_CONNECTED;
    handle_timer_event(&event);

    CU_ASSERT_EQUAL(session.timer_id_open_keep_wait, TIMER_ID_NOT_SET);
    CU_ASSERT_EQUAL(session.session_state, SESSION_STATE_INITIALIZED);
    CU_ASSERT_EQUAL(session_logic_event_queue_->event_queue->num_entries, 1);
    verify_socket_comm_times_called(0, 0, 0, 0, 1, 0, 0);

    pcep_event *e = queue_dequeue(session_logic_event_queue_->event_queue);
    CU_ASSERT_EQUAL(PCE_OPEN_KEEP_WAIT_TIMER_EXPIRED, e->event_type);
    free(e);

    /* If the state is not SESSION_STATE_TCP_CONNECTED, then nothing should happen */
    reset_mock_socket_comm_info();
    session.session_state = SESSION_STATE_WAIT_PCREQ;
    event.expired_timer_id = session.timer_id_open_keep_wait = 300;
    handle_timer_event(&event);

    CU_ASSERT_EQUAL(session.timer_id_open_keep_wait, 300);
    CU_ASSERT_EQUAL(session.session_state, SESSION_STATE_WAIT_PCREQ);
    verify_socket_comm_times_called(0, 0, 0, 0, 0, 0, 0);
}


void test_handle_timer_event_pc_req_wait()
{
    /* Pc Req Wait timer expired */
    event.expired_timer_id = session.timer_id_pc_req_wait = 400;
    session.session_state = SESSION_STATE_WAIT_PCREQ;
    handle_timer_event(&event);

    CU_ASSERT_EQUAL(session.timer_id_pc_req_wait, TIMER_ID_NOT_SET);
    CU_ASSERT_EQUAL(session.session_state, SESSION_STATE_INITIALIZED);
    CU_ASSERT_EQUAL(session_logic_event_queue_->event_queue->num_entries, 1);
    verify_socket_comm_times_called(0, 0, 0, 1, 1, 0, 0);

    pcep_event *e = queue_dequeue(session_logic_event_queue_->event_queue);
    CU_ASSERT_EQUAL(PCE_OPEN_KEEP_WAIT_TIMER_EXPIRED, e->event_type);
    free(e);

    /* If the state is not SESSION_STATE_TCP_CONNECTED, then nothing should happen */
    reset_mock_socket_comm_info();
    session.session_state = SESSION_STATE_TCP_CONNECTED;
    event.expired_timer_id = session.timer_id_pc_req_wait = 400;
    handle_timer_event(&event);

    CU_ASSERT_EQUAL(session.timer_id_pc_req_wait, 400);
    CU_ASSERT_EQUAL(session.session_state, SESSION_STATE_TCP_CONNECTED);
    verify_socket_comm_times_called(0, 0, 0, 0, 0, 0, 0);
}


void test_handle_socket_comm_event_null_params()
{
    /* Verify it doesnt core dump */
    handle_socket_comm_event(NULL);
    verify_socket_comm_times_called(0, 0, 0, 0, 0, 0, 0);
    reset_mock_socket_comm_info();

    event.received_msg_list = NULL;
    handle_socket_comm_event(&event);
    verify_socket_comm_times_called(0, 0, 0, 0, 0, 0, 0);
}


void test_handle_socket_comm_event_close()
{
    event.socket_closed = true;
    handle_socket_comm_event(&event);

    CU_ASSERT_EQUAL(session.session_state, SESSION_STATE_INITIALIZED);
    CU_ASSERT_EQUAL(session_logic_event_queue_->event_queue->num_entries, 1);
    verify_socket_comm_times_called(0, 0, 0, 0, 0, 1, 0);

    pcep_event *e = queue_dequeue(session_logic_event_queue_->event_queue);
    CU_ASSERT_EQUAL(PCE_CLOSED_SOCKET, e->event_type);
    free(e);
}


void test_handle_socket_comm_event_open()
{
    struct pcep_object_open *open_object = pcep_obj_create_open(1, 1, 1, NULL);
    dll_append(message->obj_list, open_object);
    message->header->type = PCEP_TYPE_OPEN;
    event.received_msg_list = msg_list;
    session.pcep_open_received = false;

    handle_socket_comm_event(&event);

    CU_ASSERT_TRUE(session.pcep_open_received);
    verify_socket_comm_times_called(0, 0, 0, 1, 0, 0, 0);
    pcep_event *e = queue_dequeue(session_logic_event_queue_->event_queue);
    CU_ASSERT_EQUAL(MESSAGE_RECEIVED, e->event_type);
    free(e);
    /* The message_list was freed in handle_socket_comm_event() */
    pcep_msg_free_message(message);
    free(open_object);
    do_msg_free = false;
}


void test_handle_socket_comm_event_keep_alive()
{
    message->header->type = PCEP_TYPE_KEEPALIVE;
    event.received_msg_list = msg_list;
    session.session_state = SESSION_STATE_TCP_CONNECTED;
    session.timer_id_dead_timer = 100;

    handle_socket_comm_event(&event);

    CU_ASSERT_EQUAL(session.session_state, SESSION_STATE_OPENED);
    CU_ASSERT_EQUAL(session.timer_id_open_keep_wait, TIMER_ID_NOT_SET);
    CU_ASSERT_EQUAL(session.timer_id_dead_timer, 100);
    verify_socket_comm_times_called(0, 0, 0, 0, 0, 0, 0);

    /* The session is considered connected, when the Keep Alive is received after the Open */
    pcep_event *e = queue_dequeue(session_logic_event_queue_->event_queue);
    CU_ASSERT_EQUAL(PCC_CONNECTED_TO_PCE, e->event_type);
    free(e);
    do_msg_free = false;
}


void test_handle_socket_comm_event_pcrep()
{
    dll_append(message->obj_list, pcep_obj_create_rp(1, 1, 1, NULL));
    message->header->type = PCEP_TYPE_PCREP;
    event.received_msg_list = msg_list;
    session.session_state = SESSION_STATE_WAIT_PCREQ;

    handle_socket_comm_event(&event);

    CU_ASSERT_EQUAL(session.session_state, SESSION_STATE_IDLE);
    CU_ASSERT_EQUAL(session.timer_id_pc_req_wait, TIMER_ID_NOT_SET);
    CU_ASSERT_EQUAL(session_logic_event_queue_->event_queue->num_entries, 1);
    verify_socket_comm_times_called(0, 0, 0, 0, 0, 0, 0);
    pcep_event *e = queue_dequeue(session_logic_event_queue_->event_queue);
    CU_ASSERT_EQUAL(MESSAGE_RECEIVED, e->event_type);
    free(e);
    do_msg_free = false;
}
