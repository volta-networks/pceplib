/*
 * PcepUtilsQueue.h
 *
 *  Created on: Sep 19, 2019
 *      Author: brady
 */

#ifndef INCLUDE_PCEPUTILSQUEUE_H_
#define INCLUDE_PCEPUTILSQUEUE_H_

typedef struct QueueNode_
{
	struct QueueNode_ *nextNode;
	void *data;

} QueueNode;

typedef struct QueueHandle_
{
	QueueNode *head;
	QueueNode *tail;
	unsigned int numEntries;
	/* Set to 0 to disable */
	unsigned int maxEntries;

} QueueHandle;

QueueHandle *queueInitialize();
QueueHandle *queueInitializeWithSize(unsigned int maxEntries);
void queueDestroy(QueueHandle *handle);
QueueNode *queueEnqueue(QueueHandle *handle, void *data);
void *queueDequeue(QueueHandle *handle);

#endif /* INCLUDE_PCEPUTILSQUEUE_H_ */
