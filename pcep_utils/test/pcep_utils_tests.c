#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <CUnit/TestDB.h>

extern void test_empty_queue(void);
extern void test_null_queue_handle(void);
extern void test_enqueue(void);
extern void test_enqueue_with_limit(void);
extern void test_dequeue(void);

extern void test_empty_list(void);
extern void test_null_list_handle(void);
extern void test_add_to_list(void);
extern void test_find(void);
extern void test_remove_first_node(void);
extern void test_remove_first_node_equals(void);
extern void test_remove_node(void);

int main(int argc, char **argv)
{
    CU_initialize_registry();

    CU_pSuite test_list_suite = CU_add_suite("PCEP Utils Queue Test Suite", NULL, NULL);
    CU_add_test(test_list_suite, "test_empty_queue", test_empty_queue);
    CU_add_test(test_list_suite, "test_null_queue_handle", test_null_queue_handle);
    CU_add_test(test_list_suite, "test_enqueue", test_enqueue);
    CU_add_test(test_list_suite, "test_enqueue_with_limit", test_enqueue_with_limit);
    CU_add_test(test_list_suite, "test_dequeue", test_dequeue);

    CU_pSuite test_queue_suite = CU_add_suite("PCEP Utils Ordered List Test Suite", NULL, NULL);
    CU_add_test(test_queue_suite, "test_empty_list", test_empty_list);
    CU_add_test(test_queue_suite, "test_null_handle", test_null_list_handle);
    CU_add_test(test_queue_suite, "test_add_toList", test_add_to_list);
    CU_add_test(test_queue_suite, "test_find", test_find);
    CU_add_test(test_queue_suite, "test_remove_first_node", test_remove_first_node);
    CU_add_test(test_queue_suite, "test_remove_first_node_equals", test_remove_first_node_equals);
    CU_add_test(test_queue_suite, "test_remove_node", test_remove_node);

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();
}
