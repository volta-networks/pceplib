/*
 * pcep_utils_ordered_list_test.cc
 *
 *  Created on: sep 23, 2019
 *      Aauthor: brady
 */

#include <stdio.h>
#include <stdlib.h>

#include "pcep_utils_ordered_list.h"

typedef struct node_data_
{
    int int_data;

} node_data;


int node_data_compare(void *list_entry, void *new_entry)
{
    /*
     *   < 0  if new_entry  < list_entry
     *   == 0 if new_entry == list_entry (new_entry will be inserted after list_entry)
     *   > 0  if new_entry  > list_entry
     */

    return ((node_data *) new_entry)->int_data - ((node_data *) list_entry)->int_data;
}

#define TEST_PASSED printf("\nTest passed: %s\n", __func__);

void assert_equals_int(int v1, int v2, const char *msg)
{
    if (v1 != v2)
    {
        fprintf(stderr, "Test failure assert_equals_int: %s\n", msg);
        fprintf(stderr, "value1 = [%d] value2 = [%d]\n", v1, v2);
        exit(-1);
    }
}

void assert_equals_pointer(void *v1, void *v2, const char *msg)
{
    if (v1 != v2)
    {
        fprintf(stderr, "Test failure assert_equals_pointer: %s\n", msg);
        fprintf(stderr, "value1 = [%p] value2 = [%p]\n", v1, v2);
        exit(-1);
    }
}

void assert_true(bool condition, const char *msg)
{
    if (!condition)
    {
        fprintf(stderr, "Test failure assert_true: %s\n", msg);
        exit(-1);
    }
}

void test_empty_list()
{
    ordered_list_handle *handle = ordered_list_initialize(node_data_compare);

    assert_true(handle != NULL, "test_empty_list handle not null");
    assert_equals_pointer(handle->head, NULL, "test_empty_list handle head is null");
    assert_true(handle->compare_function != NULL, "test_empty_list compare_func not null");
    assert_equals_int(handle->num_entries, 0, "test_empty_list num_entries is 0");

    TEST_PASSED;
}


void test_null_handle()
{
    node_data data;
    ordered_list_node node_data;

    void *ptr = ordered_list_add_node(NULL, &data);
    assert_true(ptr == NULL, "test_null_handle ordered_list_add_node");

    ptr = ordered_list_find(NULL, &data);
    assert_true(ptr == NULL, "test_null_handle ordered_list_find");

    ptr = ordered_list_remove_first_node(NULL);
    assert_true(ptr == NULL, "test_null_handle ordered_list_remove_first_node");

    ptr = ordered_list_remove_first_node_equals(NULL, &data);
    assert_true(ptr == NULL, "test_null_handle ordered_list_remove_first_node_equals");

    ptr = ordered_list_remove_node(NULL, &node_data, &node_data);
    assert_true(ptr == NULL, "test_null_handle ordered_list_remove_node");
}


void test_add_toList()
{
    node_data data1, data2, data3;
    data1.int_data = 1;
    data2.int_data = 2;
    data3.int_data = 3;

    ordered_list_handle *handle = ordered_list_initialize(node_data_compare);

    ordered_list_add_node(handle, &data3);
    ordered_list_add_node(handle, &data1);
    ordered_list_add_node(handle, &data2);

    assert_equals_int(handle->num_entries, 3, "test_add_toList num_entries is 3");

    ordered_list_node *node = handle->head;
    assert_equals_pointer(node->data, &data1, "test_add_toList 1st entry");

    node = node->next_node;
    assert_equals_pointer(node->data, &data2, "test_add_toList 2nd entry");

    node = node->next_node;
    assert_equals_pointer(node->data, &data3, "test_add_toList 3rd entry");

    node = node->next_node;
    assert_equals_pointer(node, NULL, "test_add_toList 3rd entry next is NULL");

    /*
    printf("&data1 = %p, %d\n", &data1, data1.int_data);
    printf("&data2 = %p, %d\n", &data2, data2.int_data);
    printf("&data3 = %p, %d\n", &data3, data3.int_data);
    node = handle->head;
    printf("&Node1 = %p\n", node->data);
    printf("&Node2 = %p\n", node->next_node->data);
    printf("&Node3 = %p\n", node->next_node->next_node->data);
    printf("END = %p\n",    node->next_node->next_node->next_node);
    */

    TEST_PASSED;
}


void test_find()
{
    node_data data1, data2, data3, data_not_inList;
    data1.int_data = 1;
    data2.int_data = 2;
    data3.int_data = 3;
    data_not_inList.int_data = 5;

    ordered_list_handle *handle = ordered_list_initialize(node_data_compare);

    ordered_list_add_node(handle, &data3);
    ordered_list_add_node(handle, &data2);
    ordered_list_add_node(handle, &data1);

    ordered_list_node *node = ordered_list_find(handle, &data1);
    assert_true(node != NULL, "test_find data1 not null");
    assert_equals_pointer(node->data, &data1, "test_find, found data1");

    node = ordered_list_find(handle, &data2);
    assert_true(node != NULL, "test_find data2 not null");
    assert_equals_pointer(node->data, &data2, "test_find, found data2");

    node = ordered_list_find(handle, &data3);
    assert_true(node != NULL, "test_find data3 not null");
    assert_equals_pointer(node->data, &data3, "test_find, found data3");

    node = ordered_list_find(handle, &data_not_inList);
    assert_true(node == NULL, "test_find data_not_inList");

    TEST_PASSED;
}


void test_remove_first_node()
{
    node_data data1, data2, data3;
    data1.int_data = 1;
    data2.int_data = 2;
    data3.int_data = 3;

    ordered_list_handle *handle = ordered_list_initialize(node_data_compare);

    ordered_list_add_node(handle, &data1);
    ordered_list_add_node(handle, &data2);
    ordered_list_add_node(handle, &data3);

    void *node_data = ordered_list_remove_first_node(handle);
    assert_true(node_data != NULL, "test_remove_first_node 1st remove not NULL");
    assert_equals_pointer(node_data, &data1, "test_remove_first_node 1st remove correct");
    assert_equals_int(handle->num_entries, 2, "test_remove_first_node 1st remove num_entries correct");

    node_data = ordered_list_remove_first_node(handle);
    assert_true(node_data != NULL, "test_remove_first_node 2nd remove not NULL");
    assert_equals_pointer(node_data, &data2, "test_remove_first_node 2nd remove correct");
    assert_equals_int(handle->num_entries, 1, "test_remove_first_node 2nd remove num_entries correct");

    node_data = ordered_list_remove_first_node(handle);
    assert_true(node_data != NULL, "test_remove_first_node 3rd remove not NULL");
    assert_equals_pointer(node_data, &data3, "test_remove_first_node 3rd remove correct");
    assert_equals_int(handle->num_entries, 0, "test_remove_first_node 3rd remove num_entries correct");
    assert_true(handle->head == NULL, "test_remove_first_node 3rd remove head is NULL");

    node_data = ordered_list_remove_first_node(handle);
    assert_true(node_data == NULL, "test_remove_first_node last remove is NULL");

    TEST_PASSED;
}


void test_remove_first_node_equals()
{
    node_data data1, data2, data3;
    data1.int_data = 1;
    data2.int_data = 2;
    data3.int_data = 3;

    ordered_list_handle *handle = ordered_list_initialize(node_data_compare);

    ordered_list_add_node(handle, &data1);
    ordered_list_add_node(handle, &data2);
    ordered_list_add_node(handle, &data3);

    void *node_data = ordered_list_remove_first_node_equals(handle, &data2);
    assert_true(node_data != NULL, "test_remove_first_node_equals 1st remove not NULL");
    assert_equals_pointer(node_data, &data2, "test_remove_first_node_equals 1st remove correct");
    assert_equals_int(handle->num_entries, 2, "test_remove_first_node_equals 1st remove num_entries correct");

    node_data = ordered_list_remove_first_node_equals(handle, &data3);
    assert_true(node_data != NULL, "test_remove_first_node_equals 2nd remove not NULL");
    assert_equals_pointer(node_data, &data3, "test_remove_first_node_equals 2nd remove correct");
    assert_equals_int(handle->num_entries, 1, "test_remove_first_node_equals 2nd remove num_entries correct");

    node_data = ordered_list_remove_first_node_equals(handle, &data1);
    assert_true(node_data != NULL, "test_remove_first_node_equals 3rd remove not NULL");
    assert_equals_pointer(node_data, &data1, "test_remove_first_node_equals 3rd remove correct");
    assert_equals_int(handle->num_entries, 0, "test_remove_first_node_equals 3rd remove num_entries correct");

    node_data = ordered_list_remove_first_node_equals(handle, &data1);
    assert_true(node_data == NULL, "test_remove_first_node_equals last remove is NULL");

    TEST_PASSED;
}


void test_remove_node()
{
    node_data data1, data2, data3;
    data1.int_data = 1;
    data2.int_data = 2;
    data3.int_data = 3;

    ordered_list_handle *handle = ordered_list_initialize(node_data_compare);

    ordered_list_node *node1 = ordered_list_add_node(handle, &data1);
    ordered_list_node *node2 = ordered_list_add_node(handle, &data2);
    ordered_list_node *node3 = ordered_list_add_node(handle, &data3);

    void *node_data = ordered_list_remove_node(handle, node2, node3);
    assert_true(node_data != NULL, "test_remove_node 1st remove not NULL");
    assert_equals_pointer(node_data, &data3, "test_remove_node 1st remove correct");
    assert_equals_int(handle->num_entries, 2, "test_remove_node 1st remove num_entries correct");

    node_data = ordered_list_remove_node(handle, node1, node2);
    assert_true(node_data != NULL, "test_remove_node 2nd remove not NULL");
    assert_equals_pointer(node_data, &data2, "test_remove_node 2nd remove correct");
    assert_equals_int(handle->num_entries, 1, "test_remove_node 2nd remove num_entries correct");

    TEST_PASSED;
}



int main(int argc, char **argv)
{
    /* TODO this is a homegrown test harness, later need to use c_unit */

    test_empty_list();
    test_null_handle();
    test_add_toList();
    test_find();
    test_remove_first_node();
    test_remove_first_node_equals();
    test_remove_node();

    printf("\nALL tests passed\n");
}
