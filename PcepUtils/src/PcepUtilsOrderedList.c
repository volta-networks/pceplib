/*
 * PcepUtilsOrderedList.c
 *
 *  Created on: Sep 18, 2019
 *      Author: brady
 */


#include <malloc.h>
#include <stdbool.h>
#include <stdio.h>
#include <strings.h>

#include "PcepUtilsOrderedList.h"

OrderedListHandle *orderedListInitialize(orderedCompareFunction funcPtr)
{
	OrderedListHandle *handle = malloc(sizeof(OrderedListHandle));
	handle->head = NULL;
	handle->numEntries = 0;
	handle->compareFunction = funcPtr;

	return handle;
}


/* Free all the OrderedListNode resources and the OrderedListHandle.
 * It is assumed that the user is responsible fore freeing the data
 * pointed to by the Nodes.
 */
void orderedListDestroy(OrderedListHandle *handle)
{
	if (handle == NULL)
	{
		return;
	}

	OrderedListNode *node = handle->head;
	OrderedListNode *next = node;

	while(node != NULL)
	{
		next = node->nextNode;
		free(node);
		node = next;
	}

	free(handle);
}


OrderedListNode *orderedListAddNode(OrderedListHandle *handle, void *data)
{
	if (handle == NULL)
	{
        fprintf(stderr, "ERROR orderedListAddNode, the list has not been initialized\n");
		return NULL;
	}
	handle->numEntries++;

	OrderedListNode *newNode = malloc(sizeof(OrderedListNode));
	newNode->data = data;
	newNode->nextNode = NULL;

	/* Check if its an empty list */
	if (handle->head == NULL)
	{
		handle->head = newNode;

		return newNode;
	}

	OrderedListNode *prevNode = handle->head;
	OrderedListNode *node = prevNode;
	int compareResult;

	while(node != NULL)
	{
		compareResult = handle->compareFunction(node->data, data);
        if (compareResult < 0)
        {
            /* Insert the node */
            newNode->nextNode = node;
            if (handle->head == node)
            {
            	/* add it at the beginning of the list */
            	handle->head = newNode;
            }
            else
            {
            	prevNode->nextNode = newNode;
            }

            return newNode;
        }

        /* keep searching with the next node in the list */
        prevNode = node;
        node = node->nextNode;
	}

	/* At the end of the list, add it here */
	prevNode->nextNode = newNode;

	return newNode;
}


OrderedListNode *orderedListFind(OrderedListHandle *handle, void *data)
{
	if (handle == NULL)
	{
        fprintf(stderr, "ERROR orderedListFind, the list has not been initialized\n");
		return NULL;
	}

	OrderedListNode *node = handle->head;
	int compareResult;

	while(node != NULL)
	{
		compareResult = handle->compareFunction(node->data, data);
		if (compareResult == 0)
		{
			return node;
		}
		else
		{
            node = node->nextNode;
		}
	}

    return NULL;
}


void *orderedListRemoveFirstNode(OrderedListHandle *handle)
{
	if (handle == NULL)
	{
        fprintf(stderr, "ERROR orderedListRemoveFirstNode, the list has not been initialized\n");
		return NULL;
	}

	if (handle->head == NULL)
	{
        fprintf(stderr, "WARN orderedListRemoveFirstNode, empty list\n");
		return NULL;
	}
	handle->numEntries--;

	void *data = handle->head->data;
	OrderedListNode *nextNode = handle->head->nextNode;
	free(handle->head);
	handle->head = nextNode;

	return data;
}


void *orderedListRemoveFirstNodeEquals2(OrderedListHandle *handle,
		                                void *data,
										orderedCompareFunction compareFunc)
{
	if (handle == NULL)
	{
        fprintf(stderr, "ERROR orderedListRemoveFirstNodeEquals2, the list has not been initialized\n");
		return NULL;
	}

	if (handle->head == NULL)
	{
        //printf("DEBUG orderedListRemoveFirstNodeEquals2, empty list\n");
		return NULL;
	}

	OrderedListNode *prevNode = handle->head;
	OrderedListNode *node = prevNode;
	bool keepWalking = true;
	void *returnData = NULL;
	int compareResult;

	while(node != NULL && keepWalking)
	{
		compareResult = compareFunc(node->data, data);
		if (compareResult == 0)
		{
			returnData = node->data;
			keepWalking = false;
			handle->numEntries--;

			/* Adjust the corresponding pointers accordingly */
			if (handle->head == node)
			{
				/* Its the first node in the list */
				handle->head = node->nextNode;
			}
			else
			{
				prevNode->nextNode = node->nextNode;
			}

			free(node);
		}
		else
		{
			prevNode = node;
			node = node->nextNode;
		}
	}

	return returnData;
}


void *orderedListRemoveFirstNodeEquals(OrderedListHandle *handle, void *data)
{
	if (handle == NULL)
	{
        fprintf(stderr, "ERROR orderedListRemoveFirstNodeEquals, the list has not been initialized\n");
		return NULL;
	}

	return orderedListRemoveFirstNodeEquals2(handle, data, handle->compareFunction);
}


void *orderedListRemoveNode(OrderedListHandle *handle, OrderedListNode *prevNode, OrderedListNode *nodeToRemove)
{
	if (handle == NULL)
	{
        fprintf(stderr, "ERROR orderedListRemoveNode, the list has not been initialized\n");
		return NULL;
	}

	if (handle->head == NULL)
	{
        fprintf(stderr, "WARN orderedListRemoveNode, empty list\n");
		return NULL;
	}

	void *returnData = nodeToRemove->data;
	handle->numEntries--;

	if (nodeToRemove == handle->head)
	{
		handle->head = nodeToRemove->nextNode;
	}
	else
	{
		prevNode->nextNode = nodeToRemove->nextNode;
	}

	free(nodeToRemove);

	return returnData;
}
