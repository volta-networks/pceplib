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
#include "pcep-objects.h"
#include "pcep-tools.h"

/* Functions being tested */
extern void update_response_message(pcep_session *session, struct pcep_messages_list *received_msg_list);
extern int request_id_compare_function(void *list_entry, void *new_entry);
extern pcep_session_logic_handle *session_logic_handle_;

static pcep_session_event event;
static pcep_session session;
static struct pcep_messages_list *msg_list;
static struct pcep_obj_list *obj_list;

/*
 * Test case setup and teardown called before AND after each test.
 */

void pcep_session_logic_states_test_setup()
{
    session_logic_handle_ = malloc(sizeof(pcep_session_logic_handle));
    bzero(session_logic_handle_, sizeof(pcep_session_logic_handle));
    session_logic_handle_->response_msg_list =
            ordered_list_initialize(request_id_compare_function);

    bzero(&event, sizeof(pcep_session_event));
    bzero(&session, sizeof(pcep_session));
    event.socket_closed = false;
    event.session = &session;

    msg_list = malloc(sizeof(struct pcep_messages_list));
    obj_list = malloc(sizeof(struct pcep_obj_list));
    bzero(msg_list, sizeof(struct pcep_messages_list));
    bzero(obj_list, sizeof(struct pcep_obj_list));
    obj_list->next = obj_list;
    DL_APPEND(msg_list->list, obj_list);
    msg_list->prev = msg_list;

    reset_mock_socket_comm_info();
}


void pcep_session_logic_states_test_teardown()
{
    ordered_list_destroy(session_logic_handle_->response_msg_list);
    free(session_logic_handle_);
    session_logic_handle_ = NULL;
}


/*
 * Test cases
 */

void test_update_response_message_null_params()
{
    pcep_session session;
    struct pcep_messages_list msg_list;
    bzero(&session, sizeof(pcep_session));
    bzero(&msg_list, sizeof(struct pcep_messages_list));

    /* Verify that it does not core dump with NULL params */
    update_response_message(NULL, &msg_list);
    update_response_message(&session, NULL);
    update_response_message(NULL, NULL);

    /* If the RP object is not in the msg_list, then it should be an erroneous message */
    update_response_message(&session, &msg_list);
    CU_ASSERT_EQUAL(session.num_erroneous_messages, 1);
}


void test_update_response_message_not_registered()
{
    pcep_session session;
    struct pcep_messages_list msg_list;
    struct pcep_obj_list obj_list;
    pcep_message_response registered_msg_response;

    bzero(&session, sizeof(pcep_session));
    bzero(&msg_list, sizeof(struct pcep_messages_list));
    bzero(&obj_list, sizeof(struct pcep_obj_list));
    bzero(&registered_msg_response, sizeof(pcep_message_response));

    /*
     * If the received message was not registered, then nothing should happen.
     * Simulating a message was received (msg_list) with reqid=1,
     * but only a message was registered with reqid=2
     */

    msg_list.list = &obj_list;
    obj_list.header = (struct pcep_object_header *) pcep_obj_create_rp((uint8_t) 0, (uint32_t) 0, (uint32_t) 1);
    registered_msg_response.request_id = 2;
    ordered_list_add_node(session_logic_handle_->response_msg_list, &registered_msg_response);

    update_response_message(&session, &msg_list);
    /* The registered message should NOT have been taken off the list */
    CU_ASSERT_EQUAL(session_logic_handle_->response_msg_list->num_entries, 1);
    CU_ASSERT_PTR_NULL(registered_msg_response.response_msg_list);
    ordered_list_remove_first_node(session_logic_handle_->response_msg_list);
    free(obj_list.header);
}


void test_update_response_message()
{
    pcep_session session;
    struct pcep_messages_list msg_list;
    struct pcep_obj_list obj_list;
    pcep_message_response registered_msg_response;
    bzero(&registered_msg_response, sizeof(pcep_message_response));

    bzero(&session, sizeof(pcep_session));
    bzero(&msg_list, sizeof(struct pcep_messages_list));
    bzero(&obj_list, sizeof(struct pcep_obj_list));

    /*
     * A message was received, and it was registered, so it should be
     * removed from the session_logic_handle_->response_msg_list, and
     * the appropriate pcep_message_response fields should be updated.
     */

    msg_list.list = &obj_list;
    obj_list.header = (struct pcep_object_header *) pcep_obj_create_rp((uint8_t) 0, (uint32_t) 0, (uint32_t) 1);
    /*registered_msg_response.response_msg_list = &msg_list; */
    registered_msg_response.prev_response_status = RESPONSE_STATE_WAITING;
    registered_msg_response.response_status = RESPONSE_STATE_WAITING;
    registered_msg_response.request_id = htonl(1);
    pthread_mutex_init(&registered_msg_response.response_mutex, NULL);
    pthread_cond_init(&registered_msg_response.response_cond_var, NULL);
    ordered_list_add_node(session_logic_handle_->response_msg_list, &registered_msg_response);

    update_response_message(&session, &msg_list);
    CU_ASSERT_EQUAL(session_logic_handle_->response_msg_list->num_entries, 0);
    CU_ASSERT_PTR_EQUAL(registered_msg_response.response_msg_list, &msg_list);
    CU_ASSERT_EQUAL(registered_msg_response.response_status, RESPONSE_STATE_READY);
    CU_ASSERT_TRUE(registered_msg_response.response_condition);
    CU_ASSERT_NOT_EQUAL(registered_msg_response.time_response_received.tv_sec, 0);
    CU_ASSERT_NOT_EQUAL(registered_msg_response.time_response_received.tv_nsec, 0);

}


void test_handle_timer_event_dead_timer()
{
    /* Dead Timer expired */
    event.expired_timer_id = session.timer_idDead_timer = 100;
    handle_timer_event(&event);

    CU_ASSERT_EQUAL(session.timer_idDead_timer, TIMER_ID_NOT_SET);
    CU_ASSERT_EQUAL(session.session_state, SESSION_STATE_INITIALIZED);
    /* verify_socket_comm_times_called(
     *     int initialized, int teardown, int connect, int send_message, int close_after_write, int close); */
    verify_socket_comm_times_called(0, 0, 0, 1, 1, 0);
}


void test_handle_timer_event_keep_alive()
{
    /* Keep Alive timer expired */
    event.expired_timer_id = session.timer_idKeep_alive = 200;
    handle_timer_event(&event);

    CU_ASSERT_EQUAL(session.timer_idKeep_alive, TIMER_ID_NOT_SET);
    verify_socket_comm_times_called(0, 0, 0, 1, 0, 0);
}


void test_handle_timer_event_open_keep_wait()
{
    /* Open Keep Wait timer expired */
    event.expired_timer_id = session.timer_idOpen_keep_wait = 300;
    session.session_state = SESSION_STATE_TCP_CONNECTED;
    handle_timer_event(&event);

    CU_ASSERT_EQUAL(session.timer_idOpen_keep_wait, TIMER_ID_NOT_SET);
    CU_ASSERT_EQUAL(session.session_state, SESSION_STATE_INITIALIZED);
    verify_socket_comm_times_called(0, 0, 0, 0, 1, 0);

    /* If the state is not SESSION_STATE_TCP_CONNECTED, then nothing should happen */
    reset_mock_socket_comm_info();
    session.session_state = SESSION_STATE_WAIT_PCREQ;
    event.expired_timer_id = session.timer_idOpen_keep_wait = 300;
    handle_timer_event(&event);

    CU_ASSERT_EQUAL(session.timer_idOpen_keep_wait, 300);
    CU_ASSERT_EQUAL(session.session_state, SESSION_STATE_WAIT_PCREQ);
    verify_socket_comm_times_called(0, 0, 0, 0, 0, 0);
}


void test_handle_timer_event_pc_req_wait()
{
    /* Pc Req Wait timer expired */
    event.expired_timer_id = session.timer_idPc_req_wait = 400;
    session.session_state = SESSION_STATE_WAIT_PCREQ;
    handle_timer_event(&event);

    CU_ASSERT_EQUAL(session.timer_idPc_req_wait, TIMER_ID_NOT_SET);
    CU_ASSERT_EQUAL(session.session_state, SESSION_STATE_INITIALIZED);
    verify_socket_comm_times_called(0, 0, 0, 1, 1, 0);

    /* If the state is not SESSION_STATE_TCP_CONNECTED, then nothing should happen */
    reset_mock_socket_comm_info();
    session.session_state = SESSION_STATE_TCP_CONNECTED;
    event.expired_timer_id = session.timer_idPc_req_wait = 400;
    handle_timer_event(&event);

    CU_ASSERT_EQUAL(session.timer_idPc_req_wait, 400);
    CU_ASSERT_EQUAL(session.session_state, SESSION_STATE_TCP_CONNECTED);
    verify_socket_comm_times_called(0, 0, 0, 0, 0, 0);
}


void test_handle_socket_comm_event_null_params()
{
    /* Verify it doesnt core dump */
    handle_socket_comm_event(NULL);
    verify_socket_comm_times_called(0, 0, 0, 0, 0, 0);
    reset_mock_socket_comm_info();

    event.received_msg_list = NULL;
    handle_socket_comm_event(&event);
    verify_socket_comm_times_called(0, 0, 0, 0, 0, 0);
}


void test_handle_socket_comm_event_close()
{
    event.socket_closed = true;
    handle_socket_comm_event(&event);

    CU_ASSERT_EQUAL(session.session_state, SESSION_STATE_INITIALIZED);
    verify_socket_comm_times_called(0, 0, 0, 0, 0, 1);
}


void test_handle_socket_comm_event_open()
{
    pcep_message_response registered_msg_response;
    bzero(&registered_msg_response, sizeof(pcep_message_response));

    obj_list->header = (struct pcep_object_header *) pcep_obj_create_open(1, 1, 1);
    msg_list->header.type = PCEP_TYPE_OPEN;
    event.received_msg_list = msg_list;
    session.pcep_open_received = false;

    handle_socket_comm_event(&event);

    CU_ASSERT_TRUE(session.pcep_open_received);
    verify_socket_comm_times_called(0, 0, 0, 1, 0, 0);
}


void test_handle_socket_comm_event_keep_alive()
{
    pcep_message_response registered_msg_response;
    bzero(&registered_msg_response, sizeof(pcep_message_response));

    msg_list->header.type = PCEP_TYPE_KEEPALIVE;
    event.received_msg_list = msg_list;
    session.session_state = SESSION_STATE_TCP_CONNECTED;
    session.timer_idDead_timer = 100;

    handle_socket_comm_event(&event);

    CU_ASSERT_EQUAL(session.session_state, SESSION_STATE_OPENED);
    CU_ASSERT_EQUAL(session.timer_idOpen_keep_wait, TIMER_ID_NOT_SET);
    CU_ASSERT_EQUAL(session.timer_idDead_timer, 100);
    verify_socket_comm_times_called(0, 0, 0, 0, 0, 0);
}


void test_handle_socket_comm_event_pcrep()
{
    pcep_message_response registered_msg_response;
    bzero(&registered_msg_response, sizeof(pcep_message_response));

    obj_list->header = (struct pcep_object_header *) pcep_obj_create_rp(1, 1, 1);
    msg_list->header.type = PCEP_TYPE_PCREP;
    event.received_msg_list = msg_list;
    session.session_state = SESSION_STATE_WAIT_PCREQ;

    handle_socket_comm_event(&event);

    CU_ASSERT_EQUAL(session.session_state, SESSION_STATE_IDLE);
    CU_ASSERT_EQUAL(session.timer_idPc_req_wait, TIMER_ID_NOT_SET);
    verify_socket_comm_times_called(0, 0, 0, 0, 0, 0);
}
