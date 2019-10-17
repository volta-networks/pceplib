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

int main(int argc, char **argv)
{
    CU_initialize_registry();

    CU_pSuite test_messages_suite = CU_add_suite("PCEP Messages Test Suite", NULL, NULL);
    CU_add_test(test_messages_suite, "test_pcep_msg_create_open", test_pcep_msg_create_open);
    CU_add_test(test_messages_suite, "test_pcep_msg_create_request", test_pcep_msg_create_request);
    CU_add_test(test_messages_suite, "test_pcep_msg_create_request_svec", test_pcep_msg_create_request_svec);
    CU_add_test(test_messages_suite, "test_pcep_msg_create_response_nopath", test_pcep_msg_create_response_nopath);
    CU_add_test(test_messages_suite, "test_pcep_msg_create_response", test_pcep_msg_create_response);
    CU_add_test(test_messages_suite, "test_pcep_msg_create_close", test_pcep_msg_create_close);
    CU_add_test(test_messages_suite, "test_pcep_msg_create_error", test_pcep_msg_create_error);
    CU_add_test(test_messages_suite, "test_pcep_msg_create_keepalive", test_pcep_msg_create_keepalive);

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_pRunSummary run_summary = CU_get_run_summary();
    int result = run_summary->nTestsFailed;
    CU_cleanup_registry();

    return result;
}
