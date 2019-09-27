/*
 * PcepSocketCommInternals.h
 *
 *  Created on: Sep 17, 2019
 *      Author: brady
 */

#ifndef SRC_PCEPSOCKETCOMMINTERNALS_H_
#define SRC_PCEPSOCKETCOMMINTERNALS_H_

#include <pthread.h>
#include <stdbool.h>

#include "PcepSocketComm.h"
#include "PcepUtilsOrderedList.h"


typedef struct PcepSocketCommHandle_
{
	bool active;
	pthread_t socketCommThread;
	pthread_mutex_t socketCommMutex;
	fd_set readMasterSet;
	fd_set writeMasterSet;
	fd_set exceptMasterSet;
    /* OrderedList of SocketDescriptors to read from */
	OrderedListHandle *readList;
    /* OrderedList of SocketDescriptors to write to */
	OrderedListHandle *writeList;

} PcepSocketCommHandle;


typedef struct PcepSocketCommQueuedMessage_
{
	const char *unmarshalledMessage;
	int msgLength;

} PcepSocketCommQueuedMessage;


/* functions implemented in PcepSocketCommLoop.c */
void *socketCommLoop(void *data);

#endif /* SRC_PCEPSOCKETCOMMINTERNALS_H_ */
