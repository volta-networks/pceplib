/*
 * PcepUtilsQueueTest.cc
 *
 *  Created on: Sep 23, 2019
 *      Author: brady
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "PcepUtilsQueue.h"

typedef struct NodeData_
{
    int intData;

} NodeData;


#define TEST_PASSED printf("\nTest passed: %s\n", __func__);

void assertEqualsInt(int v1, int v2, const char *msg)
{
	if (v1 != v2)
	{
		fprintf(stderr, "Test Failure assertEqualsInt: %s\n", msg);
		fprintf(stderr, "value1 = [%d] value2 = [%d]\n", v1, v2);
        exit(-1);
	}
}

void assertEqualsPointer(void *v1, void *v2, const char *msg)
{
	if (v1 != v2)
	{
		fprintf(stderr, "Test Failure assertEqualsPointer: %s\n", msg);
		fprintf(stderr, "value1 = [%p] value2 = [%p]\n", v1, v2);
        exit(-1);
	}
}

void assertTrue(bool condition, const char *msg)
{
	if (!condition)
	{
		fprintf(stderr, "Test Failure assertTrue: %s\n", msg);
        exit(-1);
	}
}

void testEmptyQueue()
{
	QueueHandle *handle = queueInitialize();

    assertTrue(handle != NULL, "testEmptyQueue Handle not null");
    assertEqualsPointer(handle->head, NULL, "testEmptyQueue Handle head is null");
    assertEqualsInt(handle->numEntries, 0, "testEmptyQueue numEntries is 0");

    TEST_PASSED;
}


void testNullHandle()
{
	/* Test each method handles a NULL handle without crashing */
    NodeData data;
	queueDestroy(NULL);
	void *ptr = queueEnqueue(NULL, &data);
    assertTrue(ptr == NULL, "testNullHandle queueEnqueue");

	ptr = queueDequeue(NULL);
    assertTrue(ptr == NULL, "testNullHandle queueDequeue");
}


void testEnqueue()
{
    NodeData data1, data2, data3;
    data1.intData = 1;
    data2.intData = 2;
    data3.intData = 3;

	QueueHandle *handle = queueInitialize();

	queueEnqueue(handle, &data1);
	queueEnqueue(handle, &data2);
	queueEnqueue(handle, &data3);

    assertEqualsInt(handle->numEntries, 3, "testEnqueue numEntries is 3");

    QueueNode *node = handle->head;
    assertEqualsPointer(node->data, &data1, "testEnqueue 1st entry");

    node = node->nextNode;
    assertEqualsPointer(node->data, &data2, "testEnqueue 2nd entry");

    node = node->nextNode;
    assertEqualsPointer(node->data, &data3, "testEnqueue 3rd entry");

    node = node->nextNode;
    assertEqualsPointer(node, NULL, "testEnqueue 3rd entry next is NULL");

    /*
    printf("&data1 = %p, %d\n", &data1, data1.intData);
    printf("&data2 = %p, %d\n", &data2, data2.intData);
    printf("&data3 = %p, %d\n", &data3, data3.intData);
    node = handle->head;
    printf("&Node1 = %p\n", node->data);
    printf("&Node2 = %p\n", node->nextNode->data);
    printf("&Node3 = %p\n", node->nextNode->nextNode->data);
    printf("END = %p\n",    node->nextNode->nextNode->nextNode);
    */

    TEST_PASSED;
}


void testEnqueueWithLimit()
{
    NodeData data1, data2, data3;
    data1.intData = 1;
    data2.intData = 2;
    data3.intData = 3;

	QueueHandle *handle = queueInitializeWithSize(2);

	QueueNode *node = queueEnqueue(handle, &data1);
    assertTrue(node != NULL, "testEnqueueWithLimit: 1st enqueue not null");

	node = queueEnqueue(handle, &data2);
    assertTrue(node != NULL, "testEnqueueWithLimit: 2nd enqueue not null");

	node = queueEnqueue(handle, &data3);
    assertTrue(node == NULL, "testEnqueueWithLimit: 3rd enqueue is null");

    assertEqualsInt(handle->numEntries, 2, "testEnqueue numEntries is 2");

    node = handle->head;
    assertEqualsPointer(node->data, &data1, "testEnqueueWithLimit 1st entry");

    node = node->nextNode;
    assertEqualsPointer(node->data, &data2, "testEnqueueWithLimit 2nd entry");

    node = node->nextNode;
    assertEqualsPointer(node, NULL, "testEnqueueWithLimit 2nd entry next is NULL");

    TEST_PASSED;
}


void testDequeue()
{
    NodeData data1, data2, data3;
    data1.intData = 1;
    data2.intData = 2;
    data3.intData = 3;

	QueueHandle *handle = queueInitialize();

    /* First test dequeue handles an empty queue */
    void *nodeData = queueDequeue(handle);
    assertTrue(nodeData == NULL, "testDequeue Empty queue");

	queueEnqueue(handle, &data1);
	queueEnqueue(handle, &data2);
	queueEnqueue(handle, &data3);

    nodeData = queueDequeue(handle);
    assertEqualsPointer(nodeData, &data1, "testDequeue 1st entry");
    assertEqualsInt(handle->numEntries, 2, "testDequeue 1st entry numEntries is 2");

    nodeData = queueDequeue(handle);
    assertEqualsPointer(nodeData, &data2, "testDequeue 2nd entry");
    assertEqualsInt(handle->numEntries, 1, "testDequeue 2nd entry numEntries is 1");

    nodeData = queueDequeue(handle);
    assertEqualsPointer(nodeData, &data3, "testDequeue 3rd entry");
    assertEqualsInt(handle->numEntries, 0, "testDequeue 3rd entry numEntries is 0");

    nodeData = queueDequeue(handle);
    assertEqualsPointer(nodeData, NULL, "testDequeue last entry NULL");

    TEST_PASSED;
}



int main(int argc, char **argv)
{
    /* TODO this is a homegrown test harness, later need to use cUnit */

    /*
     * QueueHandle *queueInitialize();
     * QueueHandle *queueInitializeWithSize(unsigned int maxEntries);
     * void queueDestroy(QueueHandle *handle);
     * QueueNode *queueEnqueue(QueueHandle *handle, void *data);
     * void *queueDequeue(QueueHandle *handle);
     */

	testEmptyQueue();
	testNullHandle();
	testEnqueue();
	testEnqueueWithLimit();
    testDequeue();

}
