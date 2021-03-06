/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */


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

extern void test_empty_dl_list(void);
extern void test_null_dl_list_handle(void);
extern void test_dll_prepend_data(void);
extern void test_dll_append_data(void);
extern void test_dll_delete_first_node(void);
extern void test_dll_delete_last_node(void);
extern void test_dll_delete_node(void);

extern void test_create_counters_group(void);
extern void test_create_counters_subgroup(void);
extern void test_add_counters_subgroup(void);
extern void test_create_subgroup_counter(void);
extern void test_delete_counters_group(void);
extern void test_delete_counters_subgroup(void);
extern void test_reset_group_counters(void);
extern void test_reset_subgroup_counters(void);
extern void test_increment_counter(void);
extern void test_increment_subgroup_counter(void);
extern void test_dump_counters_group_to_log(void);
extern void test_dump_counters_subgroup_to_log(void);

int main(int argc, char **argv)
{
    CU_initialize_registry();

    CU_pSuite test_queue_suite = CU_add_suite("PCEP Utils Queue Test Suite", NULL, NULL);
    CU_add_test(test_queue_suite, "test_empty_queue", test_empty_queue);
    CU_add_test(test_queue_suite, "test_null_queue_handle", test_null_queue_handle);
    CU_add_test(test_queue_suite, "test_enqueue", test_enqueue);
    CU_add_test(test_queue_suite, "test_enqueue_with_limit", test_enqueue_with_limit);
    CU_add_test(test_queue_suite, "test_dequeue", test_dequeue);

    CU_pSuite test_list_suite = CU_add_suite("PCEP Utils Ordered List Test Suite", NULL, NULL);
    CU_add_test(test_list_suite, "test_empty_list", test_empty_list);
    CU_add_test(test_list_suite, "test_null_handle", test_null_list_handle);
    CU_add_test(test_list_suite, "test_add_toList", test_add_to_list);
    CU_add_test(test_list_suite, "test_find", test_find);
    CU_add_test(test_list_suite, "test_remove_first_node", test_remove_first_node);
    CU_add_test(test_list_suite, "test_remove_first_node_equals", test_remove_first_node_equals);
    CU_add_test(test_list_suite, "test_remove_node", test_remove_node);

    CU_pSuite test_dl_list_suite = CU_add_suite("PCEP Utils Double Linked List Test Suite", NULL, NULL);
    CU_add_test(test_dl_list_suite, "test_empty_dl_list", test_empty_dl_list);
    CU_add_test(test_dl_list_suite, "test_null_dl_handle", test_null_dl_list_handle);
    CU_add_test(test_dl_list_suite, "test_dll_prepend_data", test_dll_prepend_data);
    CU_add_test(test_dl_list_suite, "test_dll_append_data", test_dll_append_data);
    CU_add_test(test_dl_list_suite, "test_dll_delete_first_node", test_dll_delete_first_node);
    CU_add_test(test_dl_list_suite, "test_dll_delete_last_node", test_dll_delete_last_node);
    CU_add_test(test_dl_list_suite, "test_dll_delete_node", test_dll_delete_node);

    CU_pSuite test_counters_suite = CU_add_suite("PCEP Utils Counters Test Suite", NULL, NULL);
    CU_add_test(test_counters_suite, "test_create_counters_group", test_create_counters_group);
    CU_add_test(test_counters_suite, "test_create_counters_subgroup", test_create_counters_subgroup);
    CU_add_test(test_counters_suite, "test_add_counters_subgroup", test_add_counters_subgroup);
    CU_add_test(test_counters_suite, "test_create_subgroup_counter", test_create_subgroup_counter);
    CU_add_test(test_counters_suite, "test_delete_counters_group", test_delete_counters_group);
    CU_add_test(test_counters_suite, "test_delete_counters_subgroup", test_delete_counters_subgroup);
    CU_add_test(test_counters_suite, "test_reset_group_counters", test_reset_group_counters);
    CU_add_test(test_counters_suite, "test_reset_subgroup_counters", test_reset_subgroup_counters);
    CU_add_test(test_counters_suite, "test_increment_counter", test_increment_counter);
    CU_add_test(test_counters_suite, "test_increment_subgroup_counter", test_increment_subgroup_counter);
    CU_add_test(test_counters_suite, "test_dump_counters_group_to_log", test_dump_counters_group_to_log);
    CU_add_test(test_counters_suite, "test_dump_counters_subgroup_to_log", test_dump_counters_subgroup_to_log);

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_pRunSummary run_summary = CU_get_run_summary();
    int result = run_summary->nTestsFailed;
    CU_cleanup_registry();

    return result;
}
