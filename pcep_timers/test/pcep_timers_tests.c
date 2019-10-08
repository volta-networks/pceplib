#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <CUnit/TestDB.h>

/* Functions defined in pcep_timers_test.c */
extern void pcep_timers_test_teardown(void);
extern void test_double_initialization(void);
extern void test_initialization_null_callback(void);
extern void test_not_initialized(void);
extern void test_create_timer(void);
extern void test_cancel_timer(void);
extern void test_cancel_timer_invalid(void);
extern void test_reset_timer(void);
extern void test_reset_timer_invalid(void);

/* Functions defined in pcep_timers_event_loop_test.c */
void pcep_timers_event_loop_test_setup(void);
void pcep_timers_event_loop_test_teardown(void);
void test_walk_and_process_timers_no_timers(void);
void test_walk_and_process_timers_timer_not_expired(void);
void test_walk_and_process_timers_timer_expired(void);
void test_event_loop_null_handle(void);
void test_event_loop_not_active(void);


int main(int argc, char **argv)
{
    CU_initialize_registry();

    /*
     * Tests defined in pcep_timers_test.c
     */
    CU_pSuite test_timers_suite = CU_add_suite_with_setup_and_teardown(
            "PCEP Timers Test Suite",
            NULL, NULL, // suite setup and cleanup function pointers
            NULL, pcep_timers_test_teardown); // test case setup and teardown function pointers
    CU_add_test(test_timers_suite,
                "test_double_initialization",
                test_double_initialization);
    CU_add_test(test_timers_suite,
                "test_initialization_null_callback",
                test_initialization_null_callback);
    CU_add_test(test_timers_suite,
                "test_not_initialized",
                test_not_initialized);
    CU_add_test(test_timers_suite,
                "test_create_timer",
                test_create_timer);
    CU_add_test(test_timers_suite,
                "test_cancel_timer",
                test_cancel_timer);
    CU_add_test(test_timers_suite,
                "test_cancel_timer_invalid",
                test_cancel_timer_invalid);
    CU_add_test(test_timers_suite,
                "test_reset_timer",
                test_reset_timer);
    CU_add_test(test_timers_suite,
                "test_reset_timer_invalid",
                test_reset_timer_invalid);

    /*
     * Tests defined in pcep_timers_event_loop_test.c
     */
    CU_pSuite test_timers_event_loop_suite = CU_add_suite_with_setup_and_teardown(
            "PCEP Timers Event Loop Test Suite",
            NULL, NULL, // suite setup and cleanup function pointers
            pcep_timers_event_loop_test_setup,     // test case setup function pointer
            pcep_timers_event_loop_test_teardown); // test case teardown function pointer
    CU_add_test(test_timers_event_loop_suite,
                "test_walk_and_process_timers_no_timers",
                test_walk_and_process_timers_no_timers);
    CU_add_test(test_timers_event_loop_suite,
                "test_walk_and_process_timers_timer_not_expired",
                test_walk_and_process_timers_timer_not_expired);
    CU_add_test(test_timers_event_loop_suite,
                "test_walk_and_process_timers_timer_expired",
                test_walk_and_process_timers_timer_expired);
    CU_add_test(test_timers_event_loop_suite,
                "test_event_loop_null_handle",
                test_event_loop_null_handle);
    CU_add_test(test_timers_event_loop_suite,
                "test_event_loop_not_active",
                test_event_loop_not_active);

    /*
     * Run the tests and cleanup.
     */
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();
}
