/*
 * pcep_utils_queue_test.cc
 *
 * Ccreated on: sep 23, 2019
 *     Aauthor: brady
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "pcep_utils_queue.h"

typedef struct node_data_
{
    int int_data;

} node_data;


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

void test_empty_queue()
{
    queue_handle *handle = queue_initialize();

    assert_true(handle != NULL, "test_empty_queue handle not null");
    assert_equals_pointer(handle->head, NULL, "test_empty_queue handle head is null");
    assert_equals_int(handle->num_entries, 0, "test_empty_queue num_entries is 0");

    TEST_PASSED;
}


void test_null_handle()
{
    /* test each method handles a NULL handle without crashing */
    node_data data;
    queue_destroy(NULL);
    void *ptr = queue_enqueue(NULL, &data);
    assert_true(ptr == NULL, "test_null_handle queue_enqueue");

    ptr = queue_dequeue(NULL);
    assert_true(ptr == NULL, "test_null_handle queue_dequeue");
}


void test_enqueue()
{
    node_data data1, data2, data3;
    data1.int_data = 1;
    data2.int_data = 2;
    data3.int_data = 3;

    queue_handle *handle = queue_initialize();

    queue_enqueue(handle, &data1);
    queue_enqueue(handle, &data2);
    queue_enqueue(handle, &data3);

    assert_equals_int(handle->num_entries, 3, "test_enqueue num_entries is 3");

    queue_node *node = handle->head;
    assert_equals_pointer(node->data, &data1, "test_enqueue 1st entry");

    node = node->next_node;
    assert_equals_pointer(node->data, &data2, "test_enqueue 2nd entry");

    node = node->next_node;
    assert_equals_pointer(node->data, &data3, "test_enqueue 3rd entry");

    node = node->next_node;
    assert_equals_pointer(node, NULL, "test_enqueue 3rd entry next is NULL");

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


void test_enqueue_with_limit()
{
    node_data data1, data2, data3;
    data1.int_data = 1;
    data2.int_data = 2;
    data3.int_data = 3;

    queue_handle *handle = queue_initialize_with_size(2);

    queue_node *node = queue_enqueue(handle, &data1);
    assert_true(node != NULL, "test_enqueue_with_limit: 1st enqueue not null");

    node = queue_enqueue(handle, &data2);
    assert_true(node != NULL, "test_enqueue_with_limit: 2nd enqueue not null");

    node = queue_enqueue(handle, &data3);
    assert_true(node == NULL, "test_enqueue_with_limit: 3rd enqueue is null");

    assert_equals_int(handle->num_entries, 2, "test_enqueue num_entries is 2");

    node = handle->head;
    assert_equals_pointer(node->data, &data1, "test_enqueue_with_limit 1st entry");

    node = node->next_node;
    assert_equals_pointer(node->data, &data2, "test_enqueue_with_limit 2nd entry");

    node = node->next_node;
    assert_equals_pointer(node, NULL, "test_enqueue_with_limit 2nd entry next is NULL");

    TEST_PASSED;
}


void test_dequeue()
{
    node_data data1, data2, data3;
    data1.int_data = 1;
    data2.int_data = 2;
    data3.int_data = 3;

    queue_handle *handle = queue_initialize();

    /* first test dequeue handles an empty queue */
    void *node_data = queue_dequeue(handle);
    assert_true(node_data == NULL, "test_dequeue empty queue");

    queue_enqueue(handle, &data1);
    queue_enqueue(handle, &data2);
    queue_enqueue(handle, &data3);

    node_data = queue_dequeue(handle);
    assert_equals_pointer(node_data, &data1, "test_dequeue 1st entry");
    assert_equals_int(handle->num_entries, 2, "test_dequeue 1st entry num_entries is 2");

    node_data = queue_dequeue(handle);
    assert_equals_pointer(node_data, &data2, "test_dequeue 2nd entry");
    assert_equals_int(handle->num_entries, 1, "test_dequeue 2nd entry num_entries is 1");

    node_data = queue_dequeue(handle);
    assert_equals_pointer(node_data, &data3, "test_dequeue 3rd entry");
    assert_equals_int(handle->num_entries, 0, "test_dequeue 3rd entry num_entries is 0");

    node_data = queue_dequeue(handle);
    assert_equals_pointer(node_data, NULL, "test_dequeue last entry NULL");

    TEST_PASSED;
}



int main(int argc, char **argv)
{
    /* TODO this is a homegrown test harness, later need to use c_unit */

    /*
     * queue_handle *queue_initialize();
     * queue_handle *queue_initialize_with_size(unsigned int max_entries);
     * void queue_destroy(queue_handle *handle);
     * queue_node *queue_enqueue(queue_handle *handle, void *data);
     * void *queue_dequeue(queue_handle *handle);
     */

    test_empty_queue();
    test_null_handle();
    test_enqueue();
    test_enqueue_with_limit();
    test_dequeue();

    printf("\nALL tests passed\n");
}
