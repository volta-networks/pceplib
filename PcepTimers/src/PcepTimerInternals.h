/*
 * PcepTimer.h
 *
 *  Timer definitions to be used internally by the PcepTimers library.
 *
 *  Created on: Sep 16, 2019
 *      Author: brady
 */

#ifndef PCEPTIMERINTERNALS_H_
#define PCEPTIMERINTERNALS_H_

#include <pthread.h>

#include "PcepTimers.h"
#include "PcepUtilsOrderedList.h"


typedef struct PcepTimer_
{
	time_t expireTime;
	int timerId;
	void *data;
} PcepTimer;

typedef struct PcepTimersContext_
{
	OrderedListHandle *timerList;
	bool active;
	timerExpireHandler expireHandler;
	pthread_t eventLoopThread;
	pthread_mutex_t timerListLock;

} PcepTimersContext;

/* Functions implemented in PcepTimersLoop.c */
void *eventLoop(void *context);


#endif /* PCEPTIMERINTERNALS_H_ */
