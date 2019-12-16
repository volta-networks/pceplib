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
static bool free_msg_list;
static bool msg_enqueued;
/* Forward declaration */
void destroy_message_for_test();

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
    session.pcc_config.max_unknown_messages = 2;
    memcpy(&session.pce_config, &session.pcc_config, sizeof(pcep_configuration));
    session.num_unknown_messages_time_queue = queue_initialize();

    bzero(&event, sizeof(pcep_session_event));
    event.socket_closed = false;
    event.session = &session;

    setup_mock_socket_comm_info();
    free_msg_list = false;
    msg_enqueued = false;
}


void pcep_session_logic_states_test_teardown()
{
    destroy_message_for_test();
    free(session_logic_handle_);
    queue_destroy(session_logic_event_queue_->event_queue);
    free(session_logic_event_queue_);
    session_logic_handle_ = NULL;
    session_logic_event_queue_ = NULL;
    queue_destroy_with_data(session.num_unknown_messages_time_queue);
    teardown_mock_socket_comm_info();
}

void create_message_for_test(uint8_t msg_type, bool free_msg_list_at_teardown, bool was_msg_enqueued)
{
    /* See the comments in pcep_session_logic_states_test_teardown() about these 2 variables */
    free_msg_list = free_msg_list_at_teardown;
    msg_enqueued = was_msg_enqueued;

    message = malloc(sizeof(pcep_message));
    bzero(message, sizeof(struct pcep_message));

    message->header = malloc(sizeof(struct pcep_header));
    bzero(message->header, sizeof(struct pcep_header));
    message->obj_list = dll_initialize();
    message->header->type = msg_type;

    msg_list = dll_initialize();
    dll_append(msg_list, message);
    event.received_msg_list = msg_list;
}

void destroy_message_for_test()
{
    /* Some test cases internally free the message list, so we dont
     * want to double free it */
    if (free_msg_list == true)
    {
        /* This will destroy both the msg_list and the obj_list */
        pcep_msg_free_message_list(msg_list);
    }

    /* Some tests cause the message to be enqueued and dont delete it,
     * so we have to delete it here */
    if (msg_enqueued == true)
    {
        pcep_msg_free_message(message);
    }
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
    create_message_for_test(PCEP_TYPE_OPEN, false, true);
    struct pcep_object_open *open_object = pcep_obj_create_open(1, 1, 1, NULL);
    dll_append(message->obj_list, open_object);
    session.pcep_open_received = false;

    handle_socket_comm_event(&event);

    CU_ASSERT_TRUE(session.pcep_open_received);
    verify_socket_comm_times_called(0, 0, 0, 1, 0, 0, 0);
    pcep_event *e = queue_dequeue(session_logic_event_queue_->event_queue);
    CU_ASSERT_EQUAL(MESSAGE_RECEIVED, e->event_type);
    free(e);
    free(open_object);
    destroy_message_for_test();

    /* Send a 2nd Open, an error should be sent */
    create_message_for_test(PCEP_TYPE_OPEN, false, false);
    reset_mock_socket_comm_info();
    mock_socket_comm_info *mock_info = get_mock_socket_comm_info();
    mock_info->send_message_save_message = true;

    handle_socket_comm_event(&event);

    CU_ASSERT_EQUAL(session_logic_event_queue_->event_queue->num_entries, 0);
    verify_socket_comm_times_called(0, 0, 0, 1, 0, 0, 0);
    struct pcep_header* msg = (struct pcep_header*) dll_delete_first_node(mock_info->sent_message_list);
    CU_ASSERT_PTR_NOT_NULL(msg);
    CU_ASSERT_EQUAL(PCEP_TYPE_ERROR, msg->type);
    /* Verify the error object */
    double_linked_list *obj_list = pcep_msg_get_objects(msg, false);
    CU_ASSERT_EQUAL(1, obj_list->num_entries);
    struct pcep_object_error *error_obj = obj_list->head->data;
    CU_ASSERT_EQUAL(PCEP_OBJ_CLASS_ERROR, error_obj->header.object_class);
    CU_ASSERT_EQUAL(PCEP_OBJ_TYPE_ERROR, error_obj->header.object_type);
    CU_ASSERT_EQUAL(PCEP_ERRT_ATTEMPT_TO_ESTABLISH_2ND_PCEP_SESSION, error_obj->error_type);
    CU_ASSERT_EQUAL(PCEP_ERRV_RECVD_INVALID_OPEN_MSG, error_obj->error_value);
    dll_destroy(obj_list);
    free(msg);
}


void test_handle_socket_comm_event_keep_alive()
{
    create_message_for_test(PCEP_TYPE_KEEPALIVE, false, false);
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
}


void test_handle_socket_comm_event_pcrep()
{
    create_message_for_test(PCEP_TYPE_PCREP, false, true);
    struct pcep_object_rp *rp = pcep_obj_create_rp(1, 1, 1, NULL);
    dll_append(message->obj_list, rp);
    session.session_state = SESSION_STATE_WAIT_PCREQ;

    handle_socket_comm_event(&event);

    CU_ASSERT_EQUAL(session.session_state, SESSION_STATE_IDLE);
    CU_ASSERT_EQUAL(session.timer_id_pc_req_wait, TIMER_ID_NOT_SET);
    CU_ASSERT_EQUAL(session_logic_event_queue_->event_queue->num_entries, 1);
    verify_socket_comm_times_called(0, 0, 0, 0, 0, 0, 0);
    pcep_event *e = queue_dequeue(session_logic_event_queue_->event_queue);
    CU_ASSERT_EQUAL(MESSAGE_RECEIVED, e->event_type);
    free(e);
    free(rp);
}


void test_handle_socket_comm_event_pcreq()
{
    create_message_for_test(PCEP_TYPE_PCREQ, false, false);
    mock_socket_comm_info *mock_info = get_mock_socket_comm_info();
    mock_info->send_message_save_message = true;

    handle_socket_comm_event(&event);

    /* The PCC does not support receiving PcReq messages, so an error should be sent */
    CU_ASSERT_EQUAL(session_logic_event_queue_->event_queue->num_entries, 0);
    verify_socket_comm_times_called(0, 0, 0, 1, 0, 0, 0);
    struct pcep_header* error_msg = (struct pcep_header*) dll_delete_first_node(mock_info->sent_message_list);
    CU_ASSERT_PTR_NOT_NULL(error_msg);
    CU_ASSERT_EQUAL(PCEP_TYPE_ERROR, error_msg->type);
    /* Verify the error object */
    double_linked_list *obj_list = pcep_msg_get_objects(error_msg, false);
    CU_ASSERT_EQUAL(1, obj_list->num_entries);
    struct pcep_object_error *obj = obj_list->head->data;
    CU_ASSERT_EQUAL(PCEP_OBJ_CLASS_ERROR, obj->header.object_class);
    CU_ASSERT_EQUAL(PCEP_OBJ_TYPE_ERROR, obj->header.object_type);
    CU_ASSERT_EQUAL(PCEP_ERRT_CAPABILITY_NOT_SUPPORTED, obj->error_type);
    CU_ASSERT_EQUAL(PCEP_ERRV_UNASSIGNED, obj->error_value);
    dll_destroy(obj_list);
    free(error_msg);
}


void test_handle_socket_comm_event_report()
{
    create_message_for_test(PCEP_TYPE_REPORT, false, false);
    mock_socket_comm_info *mock_info = get_mock_socket_comm_info();
    mock_info->send_message_save_message = true;

    handle_socket_comm_event(&event);

    /* The PCC does not support receiving Report messages, so an error should be sent */
    CU_ASSERT_EQUAL(session_logic_event_queue_->event_queue->num_entries, 0);
    verify_socket_comm_times_called(0, 0, 0, 1, 0, 0, 0);
    struct pcep_header* error_msg = (struct pcep_header*) dll_delete_first_node(mock_info->sent_message_list);
    CU_ASSERT_PTR_NOT_NULL(error_msg);
    CU_ASSERT_EQUAL(PCEP_TYPE_ERROR, error_msg->type);
    /* Verify the error object */
    double_linked_list *obj_list = pcep_msg_get_objects(error_msg, false);
    CU_ASSERT_EQUAL(1, obj_list->num_entries);
    struct pcep_object_error *obj = obj_list->head->data;
    CU_ASSERT_EQUAL(PCEP_OBJ_CLASS_ERROR, obj->header.object_class);
    CU_ASSERT_EQUAL(PCEP_OBJ_TYPE_ERROR, obj->header.object_type);
    CU_ASSERT_EQUAL(PCEP_ERRT_CAPABILITY_NOT_SUPPORTED, obj->error_type);
    CU_ASSERT_EQUAL(PCEP_ERRV_UNASSIGNED, obj->error_value);
    dll_destroy(obj_list);
    free(error_msg);
}


void test_handle_socket_comm_event_update()
{
    create_message_for_test(PCEP_TYPE_UPDATE, false, true);
    struct pcep_object_srp* srp = pcep_obj_create_srp(false, 100, NULL);
    struct pcep_object_lsp* lsp = pcep_obj_create_lsp(
            100, PCEP_LSP_OPERATIONAL_UP, true, true, true, true, true, NULL);
    double_linked_list *ero_subobj_list = dll_initialize();
    dll_append(ero_subobj_list, pcep_obj_create_ro_subobj_asn(0x0102));
    struct pcep_object_ro*  ero = pcep_obj_create_ero(ero_subobj_list);
    dll_append(message->obj_list, srp);
    dll_append(message->obj_list, lsp);
    dll_append(message->obj_list, ero);
    mock_socket_comm_info *mock_info = get_mock_socket_comm_info();
    mock_info->send_message_save_message = true;

    handle_socket_comm_event(&event);

    CU_ASSERT_EQUAL(session_logic_event_queue_->event_queue->num_entries, 1);
    verify_socket_comm_times_called(0, 0, 0, 0, 0, 0, 0);
    pcep_event *e = queue_dequeue(session_logic_event_queue_->event_queue);
    CU_ASSERT_EQUAL(MESSAGE_RECEIVED, e->event_type);
    CU_ASSERT_EQUAL(PCEP_TYPE_UPDATE, e->message->header->type);
    free(e);
    free(srp);
    free(lsp);
    free(ero);
    dll_destroy_with_data(ero_subobj_list);
}


void test_handle_socket_comm_event_initiate()
{
    create_message_for_test(PCEP_TYPE_INITIATE, false, true);
    struct pcep_object_srp* srp = pcep_obj_create_srp(false, 100, NULL);
    struct pcep_object_lsp* lsp = pcep_obj_create_lsp(
            100, PCEP_LSP_OPERATIONAL_UP, true, true, true, true, true, NULL);
    dll_append(message->obj_list, srp);
    dll_append(message->obj_list, lsp);
    mock_socket_comm_info *mock_info = get_mock_socket_comm_info();
    mock_info->send_message_save_message = true;

    handle_socket_comm_event(&event);

    CU_ASSERT_EQUAL(session_logic_event_queue_->event_queue->num_entries, 1);
    verify_socket_comm_times_called(0, 0, 0, 0, 0, 0, 0);
    pcep_event *e = queue_dequeue(session_logic_event_queue_->event_queue);
    CU_ASSERT_EQUAL(MESSAGE_RECEIVED, e->event_type);
    CU_ASSERT_EQUAL(PCEP_TYPE_INITIATE, e->message->header->type);
    free(e);
    free(srp);
    free(lsp);
}


void test_handle_socket_comm_event_notify()
{
    create_message_for_test(PCEP_TYPE_PCNOTF, false, true);
    handle_socket_comm_event(&event);

    CU_ASSERT_EQUAL(session_logic_event_queue_->event_queue->num_entries, 1);
    verify_socket_comm_times_called(0, 0, 0, 0, 0, 0, 0);
    pcep_event *e = queue_dequeue(session_logic_event_queue_->event_queue);
    CU_ASSERT_EQUAL(MESSAGE_RECEIVED, e->event_type);
    CU_ASSERT_EQUAL(PCEP_TYPE_PCNOTF, e->message->header->type);
    free(e);
}


void test_handle_socket_comm_event_error()
{
    create_message_for_test(PCEP_TYPE_ERROR, false, true);
    handle_socket_comm_event(&event);

    CU_ASSERT_EQUAL(session_logic_event_queue_->event_queue->num_entries, 1);
    verify_socket_comm_times_called(0, 0, 0, 0, 0, 0, 0);
    pcep_event *e = queue_dequeue(session_logic_event_queue_->event_queue);
    CU_ASSERT_EQUAL(MESSAGE_RECEIVED, e->event_type);
    CU_ASSERT_EQUAL(PCEP_TYPE_ERROR, e->message->header->type);
    free(e);
}


void test_handle_socket_comm_event_unknown_msg()
{
    create_message_for_test(13, false, false);
    mock_socket_comm_info *mock_info = get_mock_socket_comm_info();
    mock_info->send_message_save_message = true;

    handle_socket_comm_event(&event);

    /* Sending an unsupported message type, so an error should be sent,
     * but the connection should remain open, since max_unknown_messages = 2 */
    CU_ASSERT_EQUAL(session_logic_event_queue_->event_queue->num_entries, 0);
    verify_socket_comm_times_called(0, 0, 0, 1, 0, 0, 0);
    struct pcep_header* msg = (struct pcep_header*) dll_delete_first_node(mock_info->sent_message_list);
    CU_ASSERT_PTR_NOT_NULL(msg);
    CU_ASSERT_EQUAL(PCEP_TYPE_ERROR, msg->type);
    /* Verify the error object */
    double_linked_list *obj_list = pcep_msg_get_objects(msg, false);
    CU_ASSERT_EQUAL(1, obj_list->num_entries);
    struct pcep_object_error *error_obj = obj_list->head->data;
    CU_ASSERT_EQUAL(PCEP_OBJ_CLASS_ERROR, error_obj->header.object_class);
    CU_ASSERT_EQUAL(PCEP_OBJ_TYPE_ERROR, error_obj->header.object_type);
    CU_ASSERT_EQUAL(PCEP_ERRT_CAPABILITY_NOT_SUPPORTED, error_obj->error_type);
    CU_ASSERT_EQUAL(PCEP_ERRV_UNASSIGNED, error_obj->error_value);
    dll_destroy(obj_list);
    free(msg);
    destroy_message_for_test();

    /* Send another unsupported message type, an error should be sent and
     * the connection should be closed, since max_unknown_messages = 2 */
    create_message_for_test(13, false, false);
    reset_mock_socket_comm_info();
    mock_info = get_mock_socket_comm_info();
    mock_info->send_message_save_message = true;

    handle_socket_comm_event(&event);

    CU_ASSERT_EQUAL(session_logic_event_queue_->event_queue->num_entries, 0);
    verify_socket_comm_times_called(0, 0, 0, 2, 1, 0, 0);

    /* Verify the error message */
    msg = (struct pcep_header*) dll_delete_first_node(mock_info->sent_message_list);
    CU_ASSERT_PTR_NOT_NULL(msg);
    CU_ASSERT_EQUAL(PCEP_TYPE_ERROR, msg->type);
    /* Verify the error object */
    obj_list = pcep_msg_get_objects(msg, false);
    CU_ASSERT_EQUAL(1, obj_list->num_entries);
    error_obj = obj_list->head->data;
    CU_ASSERT_EQUAL(PCEP_OBJ_CLASS_ERROR, error_obj->header.object_class);
    CU_ASSERT_EQUAL(PCEP_OBJ_TYPE_ERROR, error_obj->header.object_type);
    CU_ASSERT_EQUAL(PCEP_ERRT_CAPABILITY_NOT_SUPPORTED, error_obj->error_type);
    CU_ASSERT_EQUAL(PCEP_ERRV_UNASSIGNED, error_obj->error_value);
    dll_destroy(obj_list);
    free(msg);

    /* Verify the Close message */
    msg = (struct pcep_header*) dll_delete_first_node(mock_info->sent_message_list);
    CU_ASSERT_PTR_NOT_NULL(msg);
    CU_ASSERT_EQUAL(PCEP_TYPE_CLOSE, msg->type);
    /* Verify the error object */
    obj_list = pcep_msg_get_objects(msg, false);
    CU_ASSERT_EQUAL(1, obj_list->num_entries);
    struct pcep_object_close *close_obj = obj_list->head->data;
    CU_ASSERT_EQUAL(PCEP_OBJ_CLASS_CLOSE, close_obj->header.object_class);
    CU_ASSERT_EQUAL(PCEP_OBJ_TYPE_CLOSE, close_obj->header.object_type);
    CU_ASSERT_EQUAL(PCEP_CLOSE_REASON_UNREC_MSG, close_obj->reason);
    dll_destroy(obj_list);
    free(msg);
}
