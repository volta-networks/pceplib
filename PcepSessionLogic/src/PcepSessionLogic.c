/*
 * PcepSessionLogic.c
 *
 *  Created on: Sep 20, 2019
 *      Author: brady
 */

#include <limits.h>
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
int sessionId_ = 0;


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


void destroyPcepSession(PcepSession *session)
{
    if (session->timerIdDeadTimer != TIMER_ID_NOT_SET)
    {
    	cancelTimer(session->timerIdDeadTimer);
    }

    if (session->timerIdKeepAlive != TIMER_ID_NOT_SET)
    {
    	cancelTimer(session->timerIdKeepAlive);
    }

    if (session->timerIdOpenKeepWait != TIMER_ID_NOT_SET)
    {
    	cancelTimer(session->timerIdOpenKeepWait);
    }

    if (session->timerIdPcReqWait != TIMER_ID_NOT_SET)
    {
    	cancelTimer(session->timerIdPcReqWait);
    }

    socketCommSessionTeardown(session->socketCommSession);

    free(session);
}


int getNextSessionId()
{
	if (sessionId_ == INT_MAX)
	{
		sessionId_ = 0;
	}

	return sessionId_++;
}


PcepSession *createPcepSession(PcepConfiguration *config, struct in_addr *pceIp, short port)
{
    PcepSession *session = malloc(sizeof(PcepSession));
    session->sessionId = getNextSessionId();
    session->sessionState = SESSION_STATE_INITIALIZED;
    session->timerIdOpenKeepWait = TIMER_ID_NOT_SET;
    session->timerIdPcReqWait = TIMER_ID_NOT_SET;
    session->timerIdDeadTimer = TIMER_ID_NOT_SET;
    session->timerIdKeepAlive = TIMER_ID_NOT_SET;
    session->numErroneousMessages = 0;
    session->pcepOpenReceived = false;
    session->pccConfig = config;

    session->socketCommSession = socketCommSessionInitialize(
            NULL,
    		sessionLogicMsgReadyHandler,
			sessionLogicConnExceptNotifier,
			pceIp,
			port,
			session);
    if (session->socketCommSession == NULL)
    {
        fprintf(stderr, "Cannot establish socketCommSession.\n");
        destroyPcepSession(session);

    	return NULL;
    }

    if (!socketCommSessionConnectTcp(session->socketCommSession))
    {
        fprintf(stderr, "Cannot establish TCP socket.\n");
        destroyPcepSession(session);

    	return NULL;
    }
    session->sessionState = SESSION_STATE_TCP_CONNECTED;

    /* Create and Send PCEP Open */
    struct pcep_header* openMsg =
    		pcep_msg_create_open(config->keepAliveSeconds, config->deadTimerSeconds, session->sessionId);
    socketCommSessionSendMessage(session->socketCommSession, (const char *) openMsg, ntohs(openMsg->length));

    session->timerIdOpenKeepWait = createTimer(config->keepAliveSeconds, session);
    //session->sessionState = SESSION_STATE_OPENED;

    return session;
}
