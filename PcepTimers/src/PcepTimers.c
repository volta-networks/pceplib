/*
 * PcepTimers.c
 *
 *  Created on: Sep 16, 2019
 *      Author: brady
 *
 *  Implementation of public API functions.
 */

#include <limits.h>
#include <malloc.h>
#include <pthread.h>
#include <stddef.h>
#include <stdbool.h>
#include <strings.h>

#include "PcepTimers.h"
#include "PcepTimerInternals.h"
#include "PcepUtilsOrderedList.h"

/* TODO should we just return this from initializeTimers
 *      instead of storing it globally here??
 *      I guess it just depends on if we will ever need more than one */
PcepTimersContext *timersContext_ = NULL;
static int timerId_ = 0;

/* Simple compare method callback used by PcepUtilsOrderedList
 * for ordered list insertion. */
int timerListNodeCompare(void *listEntry, void *newEntry)
{
	/* Return:
	 *   < 0  if newEntry < listEntry
     *   == 0 if newEntry == listEntry (newEntry will be inserted after listEntry)
     *   > 0  if newEntry > listEntry */
	return ((PcepTimer *) newEntry)->expireTime - ((PcepTimer *) listEntry)->expireTime;
}


/* Simple compare method callback used by PcepUtilsOrderedList
 * orderedListRemoveFirstNodeEquals2 to remove a timer based on
 * its timerId. */
int timerListNodeTimerIdCompare(void *listEntry, void *newEntry)
{
	return ((PcepTimer *) newEntry)->timerId - ((PcepTimer *) listEntry)->timerId;
}


/* Internal util method */
static PcepTimersContext *createTimersContext_()
{
	if (timersContext_ == NULL)
	{
		timersContext_ = malloc(sizeof(PcepTimersContext));
		bzero(timersContext_, sizeof(PcepTimersContext));
		timersContext_->active = false;
	}

	return timersContext_;
}


bool initializeTimers(timerExpireHandler expireHandler)
{
	timersContext_ = createTimersContext_();

	if (timersContext_->active == true)
	{
		/* Already initialized */
		return false;
	}

	timersContext_->active = true;
	timersContext_->timerList = orderedListInitialize(timerListNodeCompare);
	timersContext_->expireHandler = expireHandler;

	if (pthread_mutex_init(&(timersContext_->timerListLock), NULL) != 0)
	{
        fprintf(stderr, "ERROR initializing timers, cannot initialize the mutex\n");
		return false;
	}

	if(pthread_create(&(timersContext_->eventLoopThread), NULL, eventLoop, timersContext_))
	{
        fprintf(stderr, "ERROR initializing timers, cannot initialize the thread\n");
		return false;
	}

	return true;
}


/*
 * This function is only used to tearDown the timer data.
 * Only the timer data is deleted, not the list itself,
 * which is deleted by orderedListDestroy().
 */
void freeAllTimers(PcepTimersContext *timersContext)
{
	pthread_mutex_lock(&timersContext->timerListLock);

	OrderedListNode *timerNode = timersContext->timerList->head;

	while (timerNode != NULL)
	{
		free(timerNode->data);
		timerNode = timerNode->nextNode;
	}

	pthread_mutex_unlock(&timersContext->timerListLock);
}


bool teardownTimers()
{
	if (timersContext_ == NULL)
	{
        fprintf(stderr, "Trying to teardown the timers, but they are not initialized\n");
		return false;
	}

	if (timersContext_->active == false)
	{
        fprintf(stderr, "Trying to teardown the timers, but they are not active\n");
		return false;
	}

	timersContext_->active = false;

	/* TODO should we call phtread_join() here ?? */
	pthread_join(timersContext_->eventLoopThread, NULL);

	freeAllTimers(timersContext_);
	orderedListDestroy(timersContext_->timerList);

	if (pthread_mutex_destroy(&(timersContext_->timerListLock)) != 0)
	{
        fprintf(stderr, "Trying to teardown the timers, cannot destroy the mutex\n");
	}

	free(timersContext_);
	timersContext_ = NULL;

	return true;
}

int getNextTimerId()
{
    if (timerId_ == INT_MAX)
    {
    	timerId_ = 0;
    }

    return timerId_++;
}

int createTimer(int sleepSeconds, void *data)
{
	if (timersContext_ == NULL)
	{
        fprintf(stderr, "ERROR trying to create a timer, but the timers have not been initialized\n");
		return -1;
	}

	PcepTimer *timer = malloc(sizeof(PcepTimer));
	bzero(timer, sizeof(PcepTimer));
	timer->data = data;
	timer->expireTime = time(NULL) + sleepSeconds;
	timer->timerId = getNextTimerId();

	pthread_mutex_lock(&timersContext_->timerListLock);

	/* implemented in PcepUtilsOrderedList.c */
	if (orderedListAddNode(timersContext_->timerList, timer) == NULL)
	{
		free(timer);
		pthread_mutex_unlock(&timersContext_->timerListLock);
        fprintf(stderr, "ERROR trying to create a timer, cannot add the timer to the timer list\n");

		return -1;
	}

	pthread_mutex_unlock(&timersContext_->timerListLock);

	return timer->timerId;
}


bool cancelTimer(int timerId)
{
	static PcepTimer compareTimer;

	if (timersContext_ == NULL)
	{
        fprintf(stderr, "ERROR trying to cancel a timer, but the timers have not been initialized\n");
		return false;
	}

	pthread_mutex_lock(&timersContext_->timerListLock);

	compareTimer.timerId = timerId;
	PcepTimer *timerToRemove = orderedListRemoveFirstNodeEquals2(
			timersContext_->timerList, &compareTimer, timerListNodeTimerIdCompare);
	if (timerToRemove == NULL)
	{
        fprintf(stderr, "WARN trying to cancel a timer [%d] that does not exist\n", timerId);
		return false;
	}
	free(timerToRemove);

	pthread_mutex_unlock(&timersContext_->timerListLock);

	return true;
}

bool resetTimer(int timerId)
{
	static PcepTimer compareTimer;

	if (timersContext_ == NULL)
	{
        fprintf(stderr, "ERROR trying to reset a timer, but the timers have not been initialized\n");

		return false;
	}

	pthread_mutex_lock(&timersContext_->timerListLock);

	compareTimer.timerId = timerId;
	PcepTimer *timerToReset = orderedListRemoveFirstNodeEquals2(
			timersContext_->timerList, &compareTimer, timerListNodeTimerIdCompare);
	if (timerToReset == NULL)
	{
		pthread_mutex_unlock(&timersContext_->timerListLock);
        fprintf(stderr, "ERROR trying to reset a timer that does not exist\n");

		return false;
	}

	if (orderedListAddNode(timersContext_->timerList, timerToReset) == NULL)
	{
		free(timerToReset);
		pthread_mutex_unlock(&timersContext_->timerListLock);
        fprintf(stderr, "ERROR trying to reset a timer, cannot add the timer to the timer list\n");

		return -1;
	}

	pthread_mutex_unlock(&timersContext_->timerListLock);

	return true;
}

