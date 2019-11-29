/*
 * pcep_session_logic_tests.c
 *
 *  Created on: Oct 9, 2019
 *      Author: brady
 */

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <CUnit/TestDB.h>

/* Test functions defined in pcep_session_logic_test.c */
extern void pcep_session_logic_test_setup(void);
extern void pcep_session_logic_test_teardown(void);
extern void test_run_stop_session_logic(void);
extern void test_run_session_logic_twice(void);
extern void test_session_logic_without_run(void);
extern void test_create_pcep_session_null_params(void);
extern void test_create_destroy_pcep_session(void);
extern void test_create_pcep_session_open_tlvs(void);
extern void test_destroy_pcep_session_null_session(void);

/* Test functions defined in pcep_session_logic_loop_test.c */
extern void pcep_session_logic_loop_test_setup(void);
extern void pcep_session_logic_loop_test_teardown(void);
extern void test_session_logic_loop_null_data(void);
extern void test_session_logic_loop_inactive(void);
extern void test_session_logic_msg_ready_handler(void);
extern void test_session_logic_conn_except_notifier(void);
extern void test_session_logic_timer_expire_handler(void);

/* Test functions defined in pcep_session_logic_states_test.c */
extern void pcep_session_logic_states_test_setup(void);
extern void pcep_session_logic_states_test_teardown(void);
extern void test_handle_timer_event_dead_timer(void);
extern void test_handle_timer_event_keep_alive(void);
extern void test_handle_timer_event_open_keep_wait(void);
extern void test_handle_timer_event_pc_req_wait(void);
extern void test_handle_socket_comm_event_null_params(void);
extern void test_handle_socket_comm_event_close(void);
extern void test_handle_socket_comm_event_open(void);
extern void test_handle_socket_comm_event_keep_alive(void);
extern void test_handle_socket_comm_event_pcrep(void);


int main(int argc, char **argv)
{
    CU_initialize_registry();

    /*
     * Tests defined in pcep_socket_comm_test.c
     */
    CU_pSuite test_session_logic_suite = CU_add_suite_with_setup_and_teardown(
            "PCEP Session Logic Test Suite",
            NULL, NULL, // suite setup and cleanup function pointers
            pcep_session_logic_test_setup,     // test case setup function pointer
            pcep_session_logic_test_teardown); // test case teardown function pointer

    CU_add_test(test_session_logic_suite,
                "test_run_stop_session_logic",
                test_run_stop_session_logic);
    CU_add_test(test_session_logic_suite,
                "test_run_session_logic_twice",
                test_run_session_logic_twice);
    CU_add_test(test_session_logic_suite,
                "test_session_logic_without_run",
                test_session_logic_without_run);
    CU_add_test(test_session_logic_suite,
                "test_create_pcep_session_null_params",
                test_create_pcep_session_null_params);
    CU_add_test(test_session_logic_suite,
                "test_create_destroy_pcep_session",
                test_create_destroy_pcep_session);
    CU_add_test(test_session_logic_suite,
                "test_create_pcep_session_open_tlvs",
                test_create_pcep_session_open_tlvs);
    CU_add_test(test_session_logic_suite,
                "test_destroy_pcep_session_null_session",
                test_destroy_pcep_session_null_session);

    CU_pSuite test_session_logic_loop_suite = CU_add_suite_with_setup_and_teardown(
            "PCEP Session Logic Loop Test Suite",
            NULL, NULL, // suite setup and cleanup function pointers
            pcep_session_logic_loop_test_setup,     // test case setup function pointer
            pcep_session_logic_loop_test_teardown); // test case teardown function pointer

    CU_add_test(test_session_logic_loop_suite,
                "test_session_logic_loop_null_data",
                test_session_logic_loop_null_data);
    CU_add_test(test_session_logic_loop_suite,
                "test_session_logic_loop_inactive",
                test_session_logic_loop_inactive);
    CU_add_test(test_session_logic_loop_suite,
                "test_session_logic_msg_ready_handler",
                test_session_logic_msg_ready_handler);
    CU_add_test(test_session_logic_loop_suite,
                "test_session_logic_conn_except_notifier",
                test_session_logic_conn_except_notifier);
    CU_add_test(test_session_logic_loop_suite,
                "test_session_logic_timer_expire_handler",
                test_session_logic_timer_expire_handler);

    CU_pSuite test_session_logic_states_suite = CU_add_suite_with_setup_and_teardown(
            "PCEP Session Logic States Test Suite",
            NULL, NULL, // suite setup and cleanup function pointers
            pcep_session_logic_states_test_setup,     // test case setup function pointer
            pcep_session_logic_states_test_teardown); // test case teardown function pointer

    CU_add_test(test_session_logic_states_suite,
                "test_handle_timer_event_dead_timer",
                test_handle_timer_event_dead_timer);
    CU_add_test(test_session_logic_states_suite,
                "test_handle_timer_event_keep_alive",
                test_handle_timer_event_keep_alive);
    CU_add_test(test_session_logic_states_suite,
                "test_handle_timer_event_open_keep_wait",
                test_handle_timer_event_open_keep_wait);
    CU_add_test(test_session_logic_states_suite,
                "test_handle_timer_event_pc_req_wait",
                test_handle_timer_event_pc_req_wait);
    CU_add_test(test_session_logic_states_suite,
                "test_handle_socket_comm_event_null_params",
                test_handle_socket_comm_event_null_params);
    CU_add_test(test_session_logic_states_suite,
                "test_handle_socket_comm_event_close",
                test_handle_socket_comm_event_close);
    CU_add_test(test_session_logic_states_suite,
                "test_handle_socket_comm_event_open",
                test_handle_socket_comm_event_open);
    CU_add_test(test_session_logic_states_suite,
                "test_handle_socket_comm_event_keep_alive",
                test_handle_socket_comm_event_keep_alive);
    CU_add_test(test_session_logic_states_suite,
                "test_handle_socket_comm_event_pcrep",
                test_handle_socket_comm_event_pcrep);

    /*
     * Run the tests and cleanup.
     */
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_pRunSummary run_summary = CU_get_run_summary();
    int result = run_summary->nTestsFailed;
    CU_cleanup_registry();

    return result;
}
