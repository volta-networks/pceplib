/*
 * PcepSessionLogic.c
 *
 *  Created on: Sep 20, 2019
 *      Author: brady
 */

#include <malloc.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>

#include "PcepSessionLogic.h"
#include "PcepSessionLogicInternals.h"
#include "PcepTimers.h"
#include "PcepUtilsOrderedList.h"

/*
 * Public API function implementations for the SessionLogic
 */

PcepSessionLogicHandle *sessionLogicHandle_ = NULL;

int sessionIdCompareFunction(void *listEntry, void *newEntry)
{
    /* Return:
     *   < 0  if newEntry  < listEntry
     *   == 0 if newEntry == listEntry (newEntry will be inserted after listEntry)
     *   > 0  if newEntry  > listEntry
     */

    return ((PcepSession *) newEntry)->sessionId - ((PcepSession *) listEntry)->sessionId;
}

bool runSessionLogic()
{
    sessionLogicHandle_ = malloc(sizeof(PcepSessionLogicHandle));

    sessionLogicHandle_->active = true;
    sessionLogicHandle_->sessionLogicCondition = false;
    sessionLogicHandle_->sessionList = orderedListInitialize(sessionIdCompareFunction);
    sessionLogicHandle_->sessionEventQueue = queueInitialize();

    if (!initializeTimers(sessionLogicTimerExpireHandler))
    {
        fprintf(stderr, "Cannot initialize sessionLogic Timers.\n");
		return false;
    }

    pthread_cond_init(&(sessionLogicHandle_->sessionLogicCondVar), NULL);

	if (pthread_mutex_init(&(sessionLogicHandle_->sessionLogicMutex), NULL) != 0)
	{
        fprintf(stderr, "Cannot initialize sessionLogic Mutex.\n");
		return false;
	}

	if(pthread_create(&(sessionLogicHandle_->sessionLogicThread), NULL, sessionLogicLoop, sessionLogicHandle_))
	{
        fprintf(stderr, "Cannot initialize sessionLogic Thread.\n");
		return false;
	}

    return true;
}


bool runSessionLogicWaitForCompletion()
{
    if (!runSessionLogic())
    {
    	return false;
    }

    pthread_join(sessionLogicHandle_->sessionLogicThread, NULL);

    return true;
}


bool stopSessionLogic()
{
    if (sessionLogicHandle_ == NULL)
    {
    	return false;
    }

    sessionLogicHandle_->active = false;

    pthread_mutex_lock(&(sessionLogicHandle_->sessionLogicMutex));
    sessionLogicHandle_->sessionLogicCondition = true;
    pthread_cond_signal(&(sessionLogicHandle_->sessionLogicCondVar));
    pthread_mutex_unlock(&(sessionLogicHandle_->sessionLogicMutex));

    pthread_mutex_destroy(&(sessionLogicHandle_->sessionLogicMutex));
	orderedListDestroy(sessionLogicHandle_->sessionList);
	queueDestroy(sessionLogicHandle_->sessionEventQueue);

	free(sessionLogicHandle_);
	sessionLogicHandle_ = NULL;

    return true;
}
