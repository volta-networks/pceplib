/*
 * pcep_session_logic_test.c
 *
 *  Created on: Oct 9, 2019
 *      Author: brady
 */


#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <CUnit/CUnit.h>

#include "pcep_socket_comm_mock.h"
#include "pcep_session_logic.h"

/*
 * Test case setup and teardown called before AND after each test.
 */

void pcep_session_logic_test_setup()
{
    setup_mock_socket_comm_info();
}


void pcep_session_logic_test_teardown()
{
    stop_session_logic();
    teardown_mock_socket_comm_info();
}


/*
 * Test cases
 */

void test_run_stop_session_logic()
{
    CU_ASSERT_TRUE(run_session_logic());
    CU_ASSERT_TRUE(stop_session_logic());
}


void test_run_session_logic_twice()
{
    CU_ASSERT_TRUE(run_session_logic());
    CU_ASSERT_FALSE(run_session_logic());
}


void test_session_logic_without_run()
{
    /* Verify the functions that depend on run_session_logic() being called */
    CU_ASSERT_FALSE(stop_session_logic());
}


void test_create_pcep_session_null_params()
{
    pcep_configuration config;
    struct in_addr pce_ip;

    CU_ASSERT_PTR_NULL(create_pcep_session(NULL, NULL));
    CU_ASSERT_PTR_NULL(create_pcep_session(NULL, &pce_ip));
    CU_ASSERT_PTR_NULL(create_pcep_session(&config, NULL));
}


void test_create_destroy_pcep_session()
{
    pcep_session *session;
    pcep_configuration config;
    struct in_addr pce_ip;

    bzero(&config, sizeof(pcep_configuration));
    config.keep_alive_seconds = 5;
    config.dead_timer_seconds = 5;
    config.request_time_seconds = 5;
    config.max_unknown_messages = 5;
    config.max_unknown_requests = 5;
    inet_pton(AF_INET, "127.0.0.1", &(pce_ip));

    mock_socket_comm_info *mock_info = get_mock_socket_comm_info();
    mock_info->send_message_save_message = true;
    session = create_pcep_session(&config, &pce_ip);
    CU_ASSERT_PTR_NOT_NULL(session);
    struct pcep_header* open_msg = (struct pcep_header*)
        dll_delete_first_node(mock_info->sent_message_list);
    CU_ASSERT_PTR_NOT_NULL(open_msg);
    /* Should be an Open, with no TLVs: length = 12 */
    CU_ASSERT_EQUAL(open_msg->type, PCEP_TYPE_OPEN);
    CU_ASSERT_EQUAL(open_msg->length, ntohs(12));
    destroy_pcep_session(session);
    free(open_msg);
}


void test_create_pcep_session_open_tlvs()
{
    pcep_session *session;
    struct in_addr pce_ip;
    struct pcep_header* open_msg;
    struct pcep_object_header *open_obj;
    double_linked_list *obj_list;
    double_linked_list *tlv_list;
    pcep_configuration config;
    bzero(&config, sizeof(pcep_configuration));
    inet_pton(AF_INET, "127.0.0.1", &(pce_ip));

    /* Verify the created Open message only has 1 TLV:
     *   pcep_tlv_create_stateful_pce_capability() */
    mock_socket_comm_info *mock_info = get_mock_socket_comm_info();
    mock_info->send_message_save_message = true;
    config.support_stateful_pce_lsp_update = true;
    config.use_pcep_sr_draft07 = false;
    config.support_sr_te_pst = false;

    session = create_pcep_session(&config, &pce_ip);
    CU_ASSERT_PTR_NOT_NULL(session);
    /* Get and verify the Open Message */
    open_msg = (struct pcep_header*)
        dll_delete_first_node(mock_info->sent_message_list);
    CU_ASSERT_PTR_NOT_NULL(open_msg);
    /* Get and verify the Open Message objects */
    obj_list = pcep_msg_get_objects(open_msg, false);
    CU_ASSERT_PTR_NOT_NULL(obj_list);
    CU_ASSERT_TRUE(obj_list->num_entries > 0);
    /* Get and verify the Open object */
    open_obj = pcep_obj_get(obj_list, PCEP_OBJ_CLASS_OPEN);
    CU_ASSERT_PTR_NOT_NULL(open_obj);
    CU_ASSERT_TRUE(pcep_obj_parse_decode(open_obj));
    /* Get and verify the Open object TLVs */
    tlv_list = pcep_obj_get_tlvs(open_obj);
    CU_ASSERT_PTR_NOT_NULL(tlv_list);
    CU_ASSERT_EQUAL(tlv_list->num_entries, 1);
    CU_ASSERT_EQUAL(((struct pcep_object_tlv_header *) tlv_list->head->data)->type,
            PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY);

    dll_destroy(obj_list);
    dll_destroy(tlv_list);
    destroy_pcep_session(session);
    free(open_msg);

    /* Verify the created Open message only has 2 TLVs:
     *   pcep_tlv_create_stateful_pce_capability()
     *   pcep_tlv_create_lsp_db_version() */
    reset_mock_socket_comm_info();
    mock_info->send_message_save_message = true;
    config.support_include_db_version = true;
    config.lsp_db_version = 100;

    session = create_pcep_session(&config, &pce_ip);
    CU_ASSERT_PTR_NOT_NULL(session);
    /* Get and verify the Open Message */
    open_msg = (struct pcep_header*)
        dll_delete_first_node(mock_info->sent_message_list);
    CU_ASSERT_PTR_NOT_NULL(open_msg);
    /* Get and verify the Open Message objects */
    obj_list = pcep_msg_get_objects(open_msg, false);
    CU_ASSERT_PTR_NOT_NULL(obj_list);
    CU_ASSERT_TRUE(obj_list->num_entries > 0);
    /* Get and verify the Open object */
    open_obj = pcep_obj_get(obj_list, PCEP_OBJ_CLASS_OPEN);
    CU_ASSERT_PTR_NOT_NULL(open_obj);
    CU_ASSERT_TRUE(pcep_obj_parse_decode(open_obj));
    /* Get and verify the Open object TLVs */
    tlv_list = pcep_obj_get_tlvs(open_obj);
    CU_ASSERT_PTR_NOT_NULL(tlv_list);
    CU_ASSERT_EQUAL(tlv_list->num_entries, 2);
    CU_ASSERT_EQUAL(((struct pcep_object_tlv_header *) tlv_list->head->data)->type,
            PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY);
    CU_ASSERT_EQUAL(((struct pcep_object_tlv_header *) tlv_list->head->next_node->data)->type,
            PCEP_OBJ_TLV_TYPE_LSP_DB_VERSION);

    dll_destroy(obj_list);
    dll_destroy(tlv_list);
    destroy_pcep_session(session);
    free(open_msg);


    /* Verify the created Open message only has 4 TLVs:
     *   pcep_tlv_create_stateful_pce_capability()
     *   pcep_tlv_create_lsp_db_version()
     *   pcep_tlv_create_sr_pce_capability()
     *   pcep_tlv_create_path_setup_type_capability() */
    reset_mock_socket_comm_info();
    mock_info->send_message_save_message = true;
    config.support_sr_te_pst = true;

    session = create_pcep_session(&config, &pce_ip);
    CU_ASSERT_PTR_NOT_NULL(session);
    /* Get and verify the Open Message */
    open_msg = (struct pcep_header*)
        dll_delete_first_node(mock_info->sent_message_list);
    CU_ASSERT_PTR_NOT_NULL(open_msg);
    /* Get and verify the Open Message objects */
    obj_list = pcep_msg_get_objects(open_msg, false);
    CU_ASSERT_PTR_NOT_NULL(obj_list);
    CU_ASSERT_TRUE(obj_list->num_entries > 0);
    /* Get and verify the Open object */
    open_obj = pcep_obj_get(obj_list, PCEP_OBJ_CLASS_OPEN);
    CU_ASSERT_PTR_NOT_NULL(open_obj);
    CU_ASSERT_TRUE(pcep_obj_parse_decode(open_obj));
    /* Get and verify the Open object TLVs */
    tlv_list = pcep_obj_get_tlvs(open_obj);
    CU_ASSERT_PTR_NOT_NULL(tlv_list);
    CU_ASSERT_EQUAL(tlv_list->num_entries, 3);
    double_linked_list_node *tlv_node = tlv_list->head;
    CU_ASSERT_EQUAL(((struct pcep_object_tlv_header *) tlv_node->data)->type,
            PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY);
    tlv_node = tlv_node->next_node;
    CU_ASSERT_EQUAL(((struct pcep_object_tlv_header *) tlv_node->data)->type,
            PCEP_OBJ_TLV_TYPE_LSP_DB_VERSION);
    tlv_node = tlv_node->next_node;
    CU_ASSERT_EQUAL(((struct pcep_object_tlv_header *) tlv_node->data)->type,
            PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE_CAPABILITY);

    dll_destroy(obj_list);
    dll_destroy(tlv_list);
    destroy_pcep_session(session);
    free(open_msg);

    /* Verify the created Open message only has 4 TLVs:
     *   pcep_tlv_create_stateful_pce_capability()
     *   pcep_tlv_create_lsp_db_version()
     *   pcep_tlv_create_sr_pce_capability()
     *   pcep_tlv_create_path_setup_type_capability() */
    reset_mock_socket_comm_info();
    mock_info->send_message_save_message = true;
    config.use_pcep_sr_draft07 = true;

    session = create_pcep_session(&config, &pce_ip);
    CU_ASSERT_PTR_NOT_NULL(session);
    /* Get and verify the Open Message */
    open_msg = (struct pcep_header*)
        dll_delete_first_node(mock_info->sent_message_list);
    CU_ASSERT_PTR_NOT_NULL(open_msg);
    /* Get and verify the Open Message objects */
    obj_list = pcep_msg_get_objects(open_msg, false);
    CU_ASSERT_PTR_NOT_NULL(obj_list);
    CU_ASSERT_TRUE(obj_list->num_entries > 0);
    /* Get and verify the Open object */
    open_obj = pcep_obj_get(obj_list, PCEP_OBJ_CLASS_OPEN);
    CU_ASSERT_PTR_NOT_NULL(open_obj);
    CU_ASSERT_TRUE(pcep_obj_parse_decode(open_obj));
    /* Get and verify the Open object TLVs */
    tlv_list = pcep_obj_get_tlvs(open_obj);
    CU_ASSERT_PTR_NOT_NULL(tlv_list);
    CU_ASSERT_EQUAL(tlv_list->num_entries, 4);
    tlv_node = tlv_list->head;
    CU_ASSERT_EQUAL(((struct pcep_object_tlv_header *) tlv_node->data)->type,
            PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY);
    tlv_node = tlv_node->next_node;
    CU_ASSERT_EQUAL(((struct pcep_object_tlv_header *) tlv_node->data)->type,
            PCEP_OBJ_TLV_TYPE_LSP_DB_VERSION);
    tlv_node = tlv_node->next_node;
    CU_ASSERT_EQUAL(((struct pcep_object_tlv_header *) tlv_node->data)->type,
            PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY);
    tlv_node = tlv_node->next_node;
    CU_ASSERT_EQUAL(((struct pcep_object_tlv_header *) tlv_node->data)->type,
            PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE_CAPABILITY);

    dll_destroy(obj_list);
    dll_destroy(tlv_list);
    destroy_pcep_session(session);
    free(open_msg);
}


void test_destroy_pcep_session_null_session()
{
    /* Just testing that it does not core dump */
    destroy_pcep_session(NULL);
}
