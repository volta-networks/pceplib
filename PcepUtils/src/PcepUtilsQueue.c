/*
 * PcepUtilsQueue.c
 *
 *  Created on: Sep 19, 2019
 *      Author: brady
 */

#include <malloc.h>
#include <stdbool.h>
#include <stdio.h>
#include <strings.h>

#include "PcepUtilsQueue.h"

QueueHandle *queueInitialize()
{
	/* Set the maxEntries to 0 to disable it */
	return queueInitializeWithSize(0);
}


QueueHandle *queueInitializeWithSize(unsigned int maxEntries)
{
	QueueHandle *handle = malloc(sizeof(QueueHandle));
	bzero(handle, sizeof(QueueHandle));
	handle->maxEntries = maxEntries;

	return handle;
}


void queueDestroy(QueueHandle *handle)
{
	while (queueDequeue(handle) != NULL) {}
}


QueueNode *queueEnqueue(QueueHandle *handle, void *data)
{
	if (handle == NULL)
	{
        fprintf(stderr, "ERROR queueEnqueue, the queue has not been initialized\n");
		return NULL;
	}

	if (handle->maxEntries > 0 && handle->numEntries >= handle->maxEntries)
	{
        fprintf(stderr, "WARN queueEnqueue, cannot enqueue: max entries hit [%d]\n",
        		handle->numEntries);
		return NULL;
	}

	QueueNode *newNode = malloc(sizeof(QueueNode));
	newNode->data = data;
	newNode->nextNode = NULL;

	(handle->numEntries)++;
	if (handle->head == NULL)
	{
		/* Its the first entry in the queue */
		handle->head = handle->tail = newNode;
	}
	else
	{
		handle->tail->nextNode = newNode;
		handle->tail = newNode;

	}

	return newNode;
}


void *queueDequeue(QueueHandle *handle)
{
	if (handle == NULL)
	{
        fprintf(stderr, "ERROR queueDequeue, the queue has not been initialized\n");
		return NULL;
	}

	if (handle->head == NULL)
	{
        //printf("DEBUG queueDequeue, the queue is empty\n");
		return NULL;
	}

	void *nodeData = handle->head->data;
	QueueNode *node = handle->head;
	(handle->numEntries)--;
	if (handle->head == handle->tail)
	{
		/* Its the last entry in the queue */
		handle->head = handle->tail = NULL;
	}
	else
	{
		handle->head = node->nextNode;
	}

	free(node);

	return nodeData;
}
