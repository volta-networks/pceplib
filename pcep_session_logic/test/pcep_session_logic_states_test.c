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
extern void update_response_message(pcep_session *session, pcep_message *received_msg_list);
extern int request_id_compare_function(void *list_entry, void *new_entry);
extern pcep_session_logic_handle *session_logic_handle_;

static pcep_session_event event;
static pcep_session session;
/* A message list is a dll of struct pcep_messages_list_node items */
static double_linked_list *msg_list;
pcep_message *msg_node;
/* An object list is a dll of struct pcep_object_header *header items */
static double_linked_list *obj_list;
static bool do_msg_free = true;

/*
 * Test case setup and teardown called before AND after each test.
 */

void pcep_session_logic_states_test_setup()
{
    session_logic_handle_ = malloc(sizeof(pcep_session_logic_handle));
    bzero(session_logic_handle_, sizeof(pcep_session_logic_handle));
    session_logic_handle_->response_msg_list =
            ordered_list_initialize(request_id_compare_function);

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

    msg_list = dll_initialize();
    obj_list = dll_initialize();
    msg_node = malloc(sizeof(pcep_message));
    bzero(msg_node, sizeof(struct pcep_message));
    dll_append(msg_list, msg_node);
    msg_node->obj_list = obj_list;

    reset_mock_socket_comm_info();
    do_msg_free = true;
}


void pcep_session_logic_states_test_teardown()
{
    /* Some test cases internally free the message, so we dont want to double free it */
    if (do_msg_free == true)
    {
        /* This will destroy both the msg_list and the obj_list */
        pcep_msg_free(msg_list);
    }
    ordered_list_destroy(session_logic_handle_->response_msg_list);
    free(session_logic_handle_);
    session_logic_handle_ = NULL;
}


/*
 * Test cases
 */

void test_update_response_message_null_params()
{
    /* Verify that it does not core dump with NULL params */
    update_response_message(NULL, msg_node);
    update_response_message(&session, NULL);
    update_response_message(NULL, NULL);

    /* If the RP object is not in the msg_list, then it should be an erroneous message */
    update_response_message(&session, msg_node);
    CU_ASSERT_EQUAL(session.num_erroneous_messages, 1);
}


void test_update_response_message_not_registered()
{
    pcep_message_response registered_msg_response;
    bzero(&registered_msg_response, sizeof(pcep_message_response));

    /*
     * If the received message was not registered, then nothing should happen.
     * Simulating a message was received (msg_list) with reqid=1,
     * but only a message was registered with reqid=2
     */

    dll_append(obj_list, pcep_obj_create_rp((uint8_t) 0, (uint32_t) 0, (uint32_t) 1));
    registered_msg_response.request_id = 2;
    ordered_list_add_node(session_logic_handle_->response_msg_list, &registered_msg_response);

    update_response_message(&session, msg_node);
    /* The registered message should NOT have been taken off the list */
    CU_ASSERT_EQUAL(session_logic_handle_->response_msg_list->num_entries, 1);
    CU_ASSERT_PTR_NULL(registered_msg_response.response_msg);
    ordered_list_remove_first_node(session_logic_handle_->response_msg_list);
}


void test_update_response_message()
{
    pcep_message_response registered_msg_response;
    bzero(&registered_msg_response, sizeof(pcep_message_response));

    /*
     * A message was received, and it was registered, so it should be
     * removed from the session_logic_handle_->response_msg_list, and
     * the appropriate pcep_message_response fields should be updated.
     */

    dll_append(obj_list, pcep_obj_create_rp((uint8_t) 0, (uint32_t) 0, (uint32_t) 1));
    registered_msg_response.prev_response_status = RESPONSE_STATE_WAITING;
    registered_msg_response.response_status = RESPONSE_STATE_WAITING;
    registered_msg_response.request_id = htonl(1);
    pthread_mutex_init(&registered_msg_response.response_mutex, NULL);
    pthread_cond_init(&registered_msg_response.response_cond_var, NULL);
    ordered_list_add_node(session_logic_handle_->response_msg_list, &registered_msg_response);

    update_response_message(&session, msg_node);
    CU_ASSERT_EQUAL(session_logic_handle_->response_msg_list->num_entries, 0);
    CU_ASSERT_PTR_EQUAL(registered_msg_response.response_msg, msg_node);
    CU_ASSERT_EQUAL(registered_msg_response.response_status, RESPONSE_STATE_READY);
    CU_ASSERT_TRUE(registered_msg_response.response_condition);
    CU_ASSERT_NOT_EQUAL(registered_msg_response.time_response_received.tv_sec, 0);
    CU_ASSERT_NOT_EQUAL(registered_msg_response.time_response_received.tv_nsec, 0);
}


void test_handle_timer_event_dead_timer()
{
    /* Dead Timer expired */
    event.expired_timer_id = session.timer_id_dead_timer = 100;

    handle_timer_event(&event);

    CU_ASSERT_EQUAL(session.timer_id_dead_timer, TIMER_ID_NOT_SET);
    CU_ASSERT_EQUAL(session.session_state, SESSION_STATE_INITIALIZED);
    /* verify_socket_comm_times_called(
     *     int initialized, int teardown, int connect, int send_message, int close_after_write, int close, int destroy); */
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
    verify_socket_comm_times_called(0, 0, 0, 0, 1, 0, 0);

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
    verify_socket_comm_times_called(0, 0, 0, 1, 1, 0, 0);

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
    verify_socket_comm_times_called(0, 0, 0, 0, 0, 1, 0);
}


void test_handle_socket_comm_event_open()
{
    pcep_message_response registered_msg_response;
    bzero(&registered_msg_response, sizeof(pcep_message_response));

    struct pcep_object_open *open_object = pcep_obj_create_open(1, 1, 1);
    pcep_unpack_obj_header((struct pcep_object_header*) open_object);
    dll_append(obj_list, open_object);
    msg_node->header.type = PCEP_TYPE_OPEN;
    event.received_msg_list = msg_list;
    session.pcep_open_received = false;

    handle_socket_comm_event(&event);

    CU_ASSERT_TRUE(session.pcep_open_received);
    verify_socket_comm_times_called(0, 0, 0, 1, 0, 0, 0);
    do_msg_free = false;
}


void test_handle_socket_comm_event_keep_alive()
{
    pcep_message_response registered_msg_response;
    bzero(&registered_msg_response, sizeof(pcep_message_response));

    msg_node->header.type = PCEP_TYPE_KEEPALIVE;
    event.received_msg_list = msg_list;
    session.session_state = SESSION_STATE_TCP_CONNECTED;
    session.timer_id_dead_timer = 100;

    handle_socket_comm_event(&event);

    CU_ASSERT_EQUAL(session.session_state, SESSION_STATE_OPENED);
    CU_ASSERT_EQUAL(session.timer_id_open_keep_wait, TIMER_ID_NOT_SET);
    CU_ASSERT_EQUAL(session.timer_id_dead_timer, 100);
    verify_socket_comm_times_called(0, 0, 0, 0, 0, 0, 0);
    do_msg_free = false;
}


void test_handle_socket_comm_event_pcrep()
{
    pcep_message_response registered_msg_response;
    bzero(&registered_msg_response, sizeof(pcep_message_response));

    dll_append(obj_list, pcep_obj_create_rp(1, 1, 1));
    msg_node->header.type = PCEP_TYPE_PCREP;
    event.received_msg_list = msg_list;
    session.session_state = SESSION_STATE_WAIT_PCREQ;

    handle_socket_comm_event(&event);

    CU_ASSERT_EQUAL(session.session_state, SESSION_STATE_IDLE);
    CU_ASSERT_EQUAL(session.timer_id_pc_req_wait, TIMER_ID_NOT_SET);
    verify_socket_comm_times_called(0, 0, 0, 0, 0, 0, 0);
    do_msg_free = false;
}
