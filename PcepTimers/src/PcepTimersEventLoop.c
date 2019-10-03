/*
 * PcepTimersEventLoop.c
 *
 *  Created on: Sep 16, 2019
 *      Author: brady
 */

#include <errno.h>
#include <malloc.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <strings.h>
#include <sys/select.h>

#include "PcepTimerInternals.h"
#include "PcepUtilsOrderedList.h"

/* For each expired timer: remove the timer from the list, call the
 * expireHandler, and free the timer. */
void walkAndProcessTimers(PcepTimersContext *timersContext)
{
	pthread_mutex_lock(&timersContext->timerListLock);

	bool keepWalking = true;
	OrderedListNode *timerNode = timersContext->timerList->head;
	time_t now = time(NULL);
	PcepTimer *timerData;

	/* The timers are sorted by expireTime, so we will only
	 * remove the top node each time through the loop */
	while (timerNode != NULL && keepWalking)
	{
		timerData = (PcepTimer *) timerNode->data;
		if (timerData->expireTime <= now)
		{
            timerNode = timerNode->nextNode;
			orderedListRemoveFirstNode(timersContext->timerList);
			/* Call the timer expired handler */
			timersContext->expireHandler(timerData->data, timerData->timerId);
			free(timerData);
		}
		else
		{
			keepWalking = false;
		}
	}

	pthread_mutex_unlock(&timersContext->timerListLock);
}


/* PcepTimers::initialize() will create a thread and invoke this method */
void *eventLoop(void *context)
{
	if (context == NULL)
	{
        fprintf(stderr, "PcepTimersEventLoop cannot start eventLoop with NULL data\n");
		return NULL;
	}

    printf("[%ld-%ld] Starting TimersEventLoop thread\n", time(NULL), pthread_self());

	PcepTimersContext *timersContext = (PcepTimersContext *) context;
	struct timeval timer;
	int retval;

	while (timersContext->active)
	{
        /* Check the timers every half second */
		timer.tv_sec = 0;
		timer.tv_usec = 500000;

		do
		{
			/* If the select() call gets interrupted, select() will set
			 * the remaining time in timer, so we need to call it again.
			 */
			retval = select(0, NULL, NULL, NULL, &timer);
		} while(retval != 0 && errno == EINTR);

		walkAndProcessTimers(timersContext);
	}

	return NULL;
}
