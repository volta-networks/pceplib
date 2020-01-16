/*
 * pcap_pcc_api_test.c
 *
 *  Created on: Jan 13, 2020
 *      Author: brady
 */

#include <netdb.h> // gethostbyname
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include <CUnit/CUnit.h>

#include "pcep_pcc_api.h"
#include "pcep_socket_comm_mock.h"

extern pcep_event_queue *session_logic_event_queue_;
extern const char MESSAGE_RECEIVED_STR[];
extern const char UNKNOWN_EVENT_STR[];

/*
 * Test case setup and teardown called before AND after each test.
 */

void pcep_pcc_api_test_setup()
{
    setup_mock_socket_comm_info();
}


void pcep_pcc_api_test_teardown()
{
    teardown_mock_socket_comm_info();
}

/*
 * Unit test cases
 */

void test_initialize_pcc()
{
    CU_ASSERT_TRUE(initialize_pcc());
    /* Give the PCC time to initialize */
    sleep(1);
    CU_ASSERT_TRUE(destroy_pcc());
}

void test_connect_pce()
{
    pcep_configuration *config = create_default_pcep_configuration();
    struct hostent *host_info = gethostbyname("localhost");
    struct in_addr dest_address;
    memcpy(&dest_address, host_info->h_addr, host_info->h_length);
    mock_socket_comm_info *mock_info = get_mock_socket_comm_info();
    mock_info->send_message_save_message = true;

    pcep_session *session = connect_pce(config, &dest_address);

    CU_ASSERT_PTR_NOT_NULL(session);
    CU_ASSERT_EQUAL(mock_info->sent_message_list->num_entries, 1);
    struct pcep_header* open_msg = (struct pcep_header*)
        dll_delete_first_node(mock_info->sent_message_list);
    CU_ASSERT_PTR_NOT_NULL(open_msg);
    CU_ASSERT_EQUAL(open_msg->type, PCEP_TYPE_OPEN);

    free(open_msg);
    destroy_pcep_session(session);
    destroy_pcep_configuration(config);
}

void test_connect_pce_with_src_ip()
{
    pcep_configuration *config = create_default_pcep_configuration();
    struct hostent *host_info = gethostbyname("localhost");
    struct in_addr dest_address;
    memcpy(&dest_address, host_info->h_addr, host_info->h_length);
    mock_socket_comm_info *mock_info = get_mock_socket_comm_info();
    mock_info->send_message_save_message = true;
    config->src_ip.s_addr = 0x0a0a0102;

    pcep_session *session = connect_pce(config, &dest_address);

    CU_ASSERT_PTR_NOT_NULL(session);
    CU_ASSERT_EQUAL(mock_info->sent_message_list->num_entries, 1);
    struct pcep_header* open_msg = (struct pcep_header*)
        dll_delete_first_node(mock_info->sent_message_list);
    CU_ASSERT_PTR_NOT_NULL(open_msg);
    CU_ASSERT_EQUAL(open_msg->type, PCEP_TYPE_OPEN);

    free(open_msg);
    destroy_pcep_session(session);
    destroy_pcep_configuration(config);
}

void test_disconnect_pce()
{
    pcep_configuration *config = create_default_pcep_configuration();
    struct hostent *host_info = gethostbyname("localhost");
    struct in_addr dest_address;
    memcpy(&dest_address, host_info->h_addr, host_info->h_length);
    mock_socket_comm_info *mock_info = get_mock_socket_comm_info();
    mock_info->send_message_save_message = true;

    pcep_session *session = connect_pce(config, &dest_address);
    disconnect_pce(session);

    CU_ASSERT_EQUAL(mock_info->sent_message_list->num_entries, 2);

    /* First there should be an open message from connect_pce() */
    struct pcep_header* msg = (struct pcep_header*)
        dll_delete_first_node(mock_info->sent_message_list);
    CU_ASSERT_PTR_NOT_NULL(msg);
    CU_ASSERT_EQUAL(msg->type, PCEP_TYPE_OPEN);
    free(msg);

    /* Then there should be a close message from disconnect_pce() */
    msg = (struct pcep_header*) dll_delete_first_node(mock_info->sent_message_list);
    CU_ASSERT_PTR_NOT_NULL(msg);
    CU_ASSERT_EQUAL(msg->type, PCEP_TYPE_CLOSE);

    free(msg);
    destroy_pcep_session(session);
    destroy_pcep_configuration(config);
}


void test_send_message()
{
    pcep_configuration *config = create_default_pcep_configuration();
    struct hostent *host_info = gethostbyname("localhost");
    struct in_addr dest_address;
    memcpy(&dest_address, host_info->h_addr, host_info->h_length);
    pcep_session *session = connect_pce(config, &dest_address);
    verify_socket_comm_times_called(0, 0, 1, 1, 0, 0, 0);

    struct pcep_message *msg = pcep_msg_create_keepalive();
    send_message(session, msg, false);

    verify_socket_comm_times_called(0, 0, 1, 2, 0, 0, 0);

    pcep_msg_free_message(msg);
    destroy_pcep_session(session);
    destroy_pcep_configuration(config);
}

void test_event_queue()
{
    /* This initializes the event_queue */
    CU_ASSERT_TRUE(initialize_pcc());

    /* Verify correct behavior when the queue is empty */
    CU_ASSERT_TRUE(event_queue_is_empty());
    CU_ASSERT_EQUAL(event_queue_num_events_available(), 0);
    CU_ASSERT_PTR_NULL(event_queue_get_event());
    destroy_pcep_event(NULL);

    /* Create an empty event and put it on the queue */
    pcep_event *event = malloc(sizeof(pcep_event));
    bzero(event, sizeof(pcep_event));
    pthread_mutex_lock(&session_logic_event_queue_->event_queue_mutex);
    queue_enqueue(session_logic_event_queue_->event_queue, event);
    pthread_mutex_unlock(&session_logic_event_queue_->event_queue_mutex);

    /* Verify correct behavior when there is an entry in the queue */
    CU_ASSERT_FALSE(event_queue_is_empty());
    CU_ASSERT_EQUAL(event_queue_num_events_available(), 1);
    pcep_event *queued_event = event_queue_get_event();
    CU_ASSERT_PTR_NOT_NULL(queued_event);
    CU_ASSERT_PTR_EQUAL(event, queued_event);
    destroy_pcep_event(queued_event);

    CU_ASSERT_TRUE(destroy_pcc());
}

void test_get_event_type_str()
{
    CU_ASSERT_EQUAL(strcmp(get_event_type_str(MESSAGE_RECEIVED), MESSAGE_RECEIVED_STR), 0);
    CU_ASSERT_EQUAL(strcmp(get_event_type_str(1000), UNKNOWN_EVENT_STR), 0);
}


