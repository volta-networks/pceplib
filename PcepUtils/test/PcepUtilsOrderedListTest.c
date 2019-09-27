/*
 * PcepUtilsOrderedListTest.cc
 *
 *  Created on: Sep 23, 2019
 *      Author: brady
 */

#include <stdio.h>
#include <stdlib.h>

#include "PcepUtilsOrderedList.h"

typedef struct NodeData_
{
    int intData;

} NodeData;


int nodeDataCompare(void *listEntry, void *newEntry)
{
    /*
     *   < 0  if newEntry  < listEntry
     *   == 0 if newEntry == listEntry (newEntry will be inserted after listEntry)
     *   > 0  if newEntry  > listEntry
     */

	return ((NodeData *) newEntry)->intData - ((NodeData *) listEntry)->intData;
}

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

void testEmptyList()
{
	OrderedListHandle *handle = orderedListInitialize(nodeDataCompare);

    assertTrue(handle != NULL, "testEmptyList Handle not null");
    assertEqualsPointer(handle->head, NULL, "testEmptyList Handle head is null");
    assertTrue(handle->compareFunction != NULL, "testEmptyList compareFunc not null");
    assertEqualsInt(handle->numEntries, 0, "testEmptyList numEntries is 0");

    TEST_PASSED;
}


void testNullHandle()
{
    NodeData data;
    OrderedListNode nodeData;

	void *ptr = orderedListAddNode(NULL, &data);
    assertTrue(ptr == NULL, "testNullHandle orderedListAddNode");

    ptr = orderedListFind(NULL, &data);
    assertTrue(ptr == NULL, "testNullHandle orderedListFind");

    ptr = orderedListRemoveFirstNode(NULL);
    assertTrue(ptr == NULL, "testNullHandle orderedListRemoveFirstNode");

    ptr = orderedListRemoveFirstNodeEquals(NULL, &data);
    assertTrue(ptr == NULL, "testNullHandle orderedListRemoveFirstNodeEquals");

	ptr = orderedListRemoveNode(NULL, &nodeData, &nodeData);
    assertTrue(ptr == NULL, "testNullHandle orderedListRemoveNode");
}


void testAddToList()
{
    NodeData data1, data2, data3;
    data1.intData = 1;
    data2.intData = 2;
    data3.intData = 3;

	OrderedListHandle *handle = orderedListInitialize(nodeDataCompare);

    orderedListAddNode(handle, &data3);
    orderedListAddNode(handle, &data1);
    orderedListAddNode(handle, &data2);

    assertEqualsInt(handle->numEntries, 3, "testAddToList numEntries is 3");

    OrderedListNode *node = handle->head;
    assertEqualsPointer(node->data, &data1, "testAddToList 1st entry");

    node = node->nextNode;
    assertEqualsPointer(node->data, &data2, "testAddToList 2nd entry");

    node = node->nextNode;
    assertEqualsPointer(node->data, &data3, "testAddToList 3rd entry");

    node = node->nextNode;
    assertEqualsPointer(node, NULL, "testAddToList 3rd entry next is NULL");

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


void testFind()
{
    NodeData data1, data2, data3, dataNotInList;
    data1.intData = 1;
    data2.intData = 2;
    data3.intData = 3;
    dataNotInList.intData = 5;

	OrderedListHandle *handle = orderedListInitialize(nodeDataCompare);

    orderedListAddNode(handle, &data3);
    orderedListAddNode(handle, &data2);
    orderedListAddNode(handle, &data1);

    OrderedListNode *node = orderedListFind(handle, &data1);
    assertTrue(node != NULL, "testFind data1 not null");
    assertEqualsPointer(node->data, &data1, "testFind, found data1");

    node = orderedListFind(handle, &data2);
    assertTrue(node != NULL, "testFind data2 not null");
    assertEqualsPointer(node->data, &data2, "testFind, found data2");

    node = orderedListFind(handle, &data3);
    assertTrue(node != NULL, "testFind data3 not null");
    assertEqualsPointer(node->data, &data3, "testFind, found data3");

    node = orderedListFind(handle, &dataNotInList);
    assertTrue(node == NULL, "testFind dataNotInList");

    TEST_PASSED;
}


void testRemoveFirstNode()
{
    NodeData data1, data2, data3;
    data1.intData = 1;
    data2.intData = 2;
    data3.intData = 3;

	OrderedListHandle *handle = orderedListInitialize(nodeDataCompare);

    orderedListAddNode(handle, &data1);
    orderedListAddNode(handle, &data2);
    orderedListAddNode(handle, &data3);

    void *nodeData = orderedListRemoveFirstNode(handle);
    assertTrue(nodeData != NULL, "testRemoveFirstNode 1st remove not NULL");
    assertEqualsPointer(nodeData, &data1, "testRemoveFirstNode 1st remove correct");
    assertEqualsInt(handle->numEntries, 2, "testRemoveFirstNode 1st remove numEntries correct");

    nodeData = orderedListRemoveFirstNode(handle);
    assertTrue(nodeData != NULL, "testRemoveFirstNode 2nd remove not NULL");
    assertEqualsPointer(nodeData, &data2, "testRemoveFirstNode 2nd remove correct");
    assertEqualsInt(handle->numEntries, 1, "testRemoveFirstNode 2nd remove numEntries correct");

    nodeData = orderedListRemoveFirstNode(handle);
    assertTrue(nodeData != NULL, "testRemoveFirstNode 3rd remove not NULL");
    assertEqualsPointer(nodeData, &data3, "testRemoveFirstNode 3rd remove correct");
    assertEqualsInt(handle->numEntries, 0, "testRemoveFirstNode 3rd remove numEntries correct");
    assertTrue(handle->head == NULL, "testRemoveFirstNode 3rd remove head is NULL");

    nodeData = orderedListRemoveFirstNode(handle);
    assertTrue(nodeData == NULL, "testRemoveFirstNode last remove is NULL");

    TEST_PASSED;
}


void testRemoveFirstNodeEquals()
{
    NodeData data1, data2, data3;
    data1.intData = 1;
    data2.intData = 2;
    data3.intData = 3;

	OrderedListHandle *handle = orderedListInitialize(nodeDataCompare);

    orderedListAddNode(handle, &data1);
    orderedListAddNode(handle, &data2);
    orderedListAddNode(handle, &data3);

    void *nodeData = orderedListRemoveFirstNodeEquals(handle, &data2);
    assertTrue(nodeData != NULL, "testRemoveFirstNodeEquals 1st remove not NULL");
    assertEqualsPointer(nodeData, &data2, "testRemoveFirstNodeEquals 1st remove correct");
    assertEqualsInt(handle->numEntries, 2, "testRemoveFirstNodeEquals 1st remove numEntries correct");

    nodeData = orderedListRemoveFirstNodeEquals(handle, &data3);
    assertTrue(nodeData != NULL, "testRemoveFirstNodeEquals 2nd remove not NULL");
    assertEqualsPointer(nodeData, &data3, "testRemoveFirstNodeEquals 2nd remove correct");
    assertEqualsInt(handle->numEntries, 1, "testRemoveFirstNodeEquals 2nd remove numEntries correct");

    nodeData = orderedListRemoveFirstNodeEquals(handle, &data1);
    assertTrue(nodeData != NULL, "testRemoveFirstNodeEquals 3rd remove not NULL");
    assertEqualsPointer(nodeData, &data1, "testRemoveFirstNodeEquals 3rd remove correct");
    assertEqualsInt(handle->numEntries, 0, "testRemoveFirstNodeEquals 3rd remove numEntries correct");

    nodeData = orderedListRemoveFirstNodeEquals(handle, &data1);
    assertTrue(nodeData == NULL, "testRemoveFirstNodeEquals last remove is NULL");

    TEST_PASSED;
}


void testRemoveNode()
{
    NodeData data1, data2, data3;
    data1.intData = 1;
    data2.intData = 2;
    data3.intData = 3;

	OrderedListHandle *handle = orderedListInitialize(nodeDataCompare);

	OrderedListNode *node1 = orderedListAddNode(handle, &data1);
	OrderedListNode *node2 = orderedListAddNode(handle, &data2);
	OrderedListNode *node3 = orderedListAddNode(handle, &data3);

	void *nodeData = orderedListRemoveNode(handle, node2, node3);
    assertTrue(nodeData != NULL, "testRemoveNode 1st remove not NULL");
    assertEqualsPointer(nodeData, &data3, "testRemoveNode 1st remove correct");
    assertEqualsInt(handle->numEntries, 2, "testRemoveNode 1st remove numEntries correct");

	nodeData = orderedListRemoveNode(handle, node1, node2);
    assertTrue(nodeData != NULL, "testRemoveNode 2nd remove not NULL");
    assertEqualsPointer(nodeData, &data2, "testRemoveNode 2nd remove correct");
    assertEqualsInt(handle->numEntries, 1, "testRemoveNode 2nd remove numEntries correct");

    TEST_PASSED;
}



int main(int argc, char **argv)
{
    /* TODO this is a homegrown test harness, later need to use cUnit */

	testEmptyList();
	testNullHandle();
	testAddToList();
    testFind();
    testRemoveFirstNode();
    testRemoveFirstNodeEquals();
    testRemoveNode();

}
