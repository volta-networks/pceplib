/*
 * pcep-messages-tests.c
 *
 *  Created on: Oct 11, 2019
 *      Author: brady
 */

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <CUnit/TestDB.h>

extern void test_pcep_msg_create_open(void);
extern void test_pcep_msg_create_request(void);
extern void test_pcep_msg_create_request_svec(void);
extern void test_pcep_msg_create_response_nopath(void);
extern void test_pcep_msg_create_response(void);
extern void test_pcep_msg_create_close(void);
extern void test_pcep_msg_create_error(void);
extern void test_pcep_msg_create_keepalive(void);

extern void test_pcep_tlv_create_stateful_pce_capability(void);
extern void test_pcep_tlv_create_speaker_entity_id(void);
extern void test_pcep_tlv_create_lsp_db_version(void);
extern void test_pcep_tlv_create_path_setup_type(void);
extern void test_pcep_tlv_create_sr_pce_capability(void);
extern void test_pcep_tlv_create_symbolic_path_name(void);
extern void test_pcep_tlv_create_ipv4_lsp_identifiers(void);
extern void test_pcep_tlv_create_ipv6_lsp_identifiers(void);
extern void test_pcep_tlv_create_lsp_error_code(void);
extern void test_pcep_tlv_create_rsvp_ipv4_error_spec(void);
extern void test_pcep_tlv_create_rsvp_ipv6_error_spec(void);

int main(int argc, char **argv)
{
    CU_initialize_registry();

    CU_pSuite messages_suite = CU_add_suite("PCEP Messages Test Suite", NULL, NULL);
    CU_add_test(messages_suite, "test_pcep_msg_create_open", test_pcep_msg_create_open);
    CU_add_test(messages_suite, "test_pcep_msg_create_request", test_pcep_msg_create_request);
    CU_add_test(messages_suite, "test_pcep_msg_create_request_svec", test_pcep_msg_create_request_svec);
    CU_add_test(messages_suite, "test_pcep_msg_create_response_nopath", test_pcep_msg_create_response_nopath);
    CU_add_test(messages_suite, "test_pcep_msg_create_response", test_pcep_msg_create_response);
    CU_add_test(messages_suite, "test_pcep_msg_create_close", test_pcep_msg_create_close);
    CU_add_test(messages_suite, "test_pcep_msg_create_error", test_pcep_msg_create_error);
    CU_add_test(messages_suite, "test_pcep_msg_create_keepalive", test_pcep_msg_create_keepalive);

    CU_pSuite tlvs_suite = CU_add_suite("PCEP TLVs Test Suite", NULL, NULL);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_stateful_pce_capability", test_pcep_tlv_create_stateful_pce_capability);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_speaker_entity_id", test_pcep_tlv_create_speaker_entity_id);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_lsp_db_version", test_pcep_tlv_create_lsp_db_version);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_path_setup_type", test_pcep_tlv_create_path_setup_type);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_sr_pce_capability", test_pcep_tlv_create_sr_pce_capability);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_symbolic_path_name", test_pcep_tlv_create_symbolic_path_name);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_ipv4_lsp_identifiers", test_pcep_tlv_create_ipv4_lsp_identifiers);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_ipv6_lsp_identifiers", test_pcep_tlv_create_ipv6_lsp_identifiers);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_lsp_error_code", test_pcep_tlv_create_lsp_error_code);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_rsvp_ipv4_error_spec", test_pcep_tlv_create_rsvp_ipv4_error_spec);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_rsvp_ipv6_error_spec", test_pcep_tlv_create_rsvp_ipv6_error_spec);

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_pRunSummary run_summary = CU_get_run_summary();
    int result = run_summary->nTestsFailed;
    CU_cleanup_registry();

    return result;
}
