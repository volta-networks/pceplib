/*
 * PcepSessionLogic.c
 *
 *  Created on: Sep 20, 2019
 *      Author: brady
 */

#include <errno.h>
#include <limits.h>
#include <malloc.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
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


int requestIdCompareFunction(void *listEntry, void *newEntry)
{
    return ((PcepMessageResponse *) newEntry)->requestId - ((PcepMessageResponse *) listEntry)->requestId;
}


bool runSessionLogic()
{
    sessionLogicHandle_ = malloc(sizeof(PcepSessionLogicHandle));

    sessionLogicHandle_->active = true;
    sessionLogicHandle_->sessionLogicCondition = false;
    sessionLogicHandle_->sessionList = orderedListInitialize(sessionIdCompareFunction);
    sessionLogicHandle_->responseMsgList = orderedListInitialize(requestIdCompareFunction);
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
	orderedListDestroy(sessionLogicHandle_->responseMsgList);
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
    memcpy(&(session->pccConfig), config, sizeof(PcepConfiguration));
    /* Copy the pccConfig to the pceConfig until we receive the Open KeepAlive response */
    memcpy(&(session->pceConfig), config, sizeof(PcepConfiguration));

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

    /* Create and Send PCEP Open
     * With PCEP, the PCC sends the config the PCE should use in the Open message,
     * and the PCE will send an Open with the config the PCC should use. */
    struct pcep_header* openMsg =
    		pcep_msg_create_open(session->pccConfig.keepAliveSeconds, session->pccConfig.deadTimerSeconds, session->sessionId);
    socketCommSessionSendMessage(session->socketCommSession, (const char *) openMsg, ntohs(openMsg->length));

    session->timerIdOpenKeepWait = createTimer(config->keepAliveSeconds, session);
    //session->sessionState = SESSION_STATE_OPENED;

    return session;
}


PcepMessageResponse *registerResponseMessage(
		PcepSession *session, int requestId, unsigned int maxWaitTimeMilliSeconds)
{
    /* The response will be updated in PcepSessionLogicStates.c */

    printf("[%ld-%ld] registerResponseMessage session [%d] requestId [%d] maxWait [%d]\n",
    		time(NULL), pthread_self(), session->sessionId, requestId, maxWaitTimeMilliSeconds);

	PcepMessageResponse *msgResponse = malloc(sizeof(PcepMessageResponse));
    msgResponse->session = session;
    msgResponse->requestId = requestId;
    msgResponse->maxWaitTimeMilliSeconds = maxWaitTimeMilliSeconds;
    msgResponse->responseMsgList = NULL;
    msgResponse->prevResponseStatus = RESPONSE_STATE_WAITING;
    msgResponse->responseStatus = RESPONSE_STATE_WAITING;
    clock_gettime(CLOCK_REALTIME, &msgResponse->timeRequestRegistered);
    msgResponse->timeResponseReceived.tv_nsec =
    		msgResponse->timeResponseReceived.tv_sec = 0;
    msgResponse->responseCondition = false;
    pthread_mutex_init(&(msgResponse->responseMutex), NULL);
    pthread_cond_init(&(msgResponse->responseCondVar), NULL);

    /* TODO we should periodically check purge the list of timed-out responses */
    pthread_mutex_lock(&(sessionLogicHandle_->sessionLogicMutex));
    session->sessionState = SESSION_STATE_WAIT_PCREQ;
    session->timerIdPcReqWait = createTimer(session->pceConfig.requestTimeSeconds, session);
    orderedListAddNode(sessionLogicHandle_->responseMsgList, msgResponse);
    pthread_mutex_unlock(&(sessionLogicHandle_->sessionLogicMutex));

    return msgResponse;
}


void destroyResponseMessage(PcepMessageResponse *msgResponse)
{
    if (msgResponse == NULL)
    {
    	return;
    }

    pthread_mutex_destroy(&msgResponse->responseMutex);
    pthread_cond_destroy(&msgResponse->responseCondVar);
    orderedListRemoveFirstNodeEquals(sessionLogicHandle_->responseMsgList, msgResponse);

	free(msgResponse);
}

/* Internal util method to calculate time diffs */
int timespecDiff(struct timespec *start, struct timespec *stop)
{
    int diffMillis;
    if ((stop->tv_nsec - start->tv_nsec) < 0) {
        diffMillis  = (stop->tv_sec  - start->tv_sec - 1) * 1000;
        diffMillis += (stop->tv_nsec - start->tv_nsec + 1000000000) / 1000000;
    } else {
        diffMillis  = (stop->tv_sec  - start->tv_sec) * 1000;
        diffMillis += (stop->tv_nsec - start->tv_nsec) / 1000000;
    }

    return diffMillis;
}


/* Internal util method to add times */
void addMillisToTimespec(struct timespec *ts, int milliSeconds)
{
    static const int SEC_IN_NANOS   = 1000000000;
    static const int MAX_NANO       =  999999999;
    static const int MILLI_IN_NANOS =    1000000;
    static const int SEC_IN_MILLIS  =       1000;
    int seconds1 = 0, seconds2 = 0;
    int nanoSeconds = 0;

    if (milliSeconds >= SEC_IN_MILLIS)
    {
        seconds1 = milliSeconds / SEC_IN_MILLIS;
        nanoSeconds = (milliSeconds - (seconds1 * SEC_IN_MILLIS)) * MILLI_IN_NANOS;
    }
    else
    {
        nanoSeconds = milliSeconds * MILLI_IN_NANOS;
    }

    if ((ts->tv_nsec + nanoSeconds) > MAX_NANO)
    {
        seconds2 = (ts->tv_nsec + nanoSeconds) / SEC_IN_NANOS;
        nanoSeconds = (ts->tv_nsec + nanoSeconds) - (seconds2 * SEC_IN_NANOS);
    }
    else
    {
        nanoSeconds = ts->tv_nsec + nanoSeconds;
    }

    ts->tv_sec += seconds1 + seconds2;
    ts->tv_nsec = nanoSeconds;
}


bool queryResponseMessage(PcepMessageResponse *msgResponse)
{
    if (msgResponse == NULL)
    {
    	fprintf(stderr, "ERROR queryResponseMessage cannot query with NULL PcepMessageResponse\n");
        return false;
    }

    pthread_mutex_lock(&msgResponse->responseMutex);

    /* If the message is already available, nothing else to do */
    if (msgResponse->responseStatus == RESPONSE_STATE_READY)
    {
    	pthread_mutex_unlock(&msgResponse->responseMutex);
    	return true;
    }

    /* If the status changed, then return true, nothing else to do */
    if (msgResponse->responseStatus != msgResponse->prevResponseStatus)
    {
    	pthread_mutex_unlock(&msgResponse->responseMutex);

        /* Return true that the state changed */
    	return true;
    }

    /* Check if it timed out */
    struct timespec timeNow;
    clock_gettime(CLOCK_REALTIME, &timeNow);
    int timeDiffMilliSeconds = timespecDiff(&msgResponse->timeRequestRegistered, &timeNow);
    if (timeDiffMilliSeconds >= msgResponse->maxWaitTimeMilliSeconds)
    {
        msgResponse->prevResponseStatus = msgResponse->responseStatus;
    	msgResponse->responseStatus = RESPONSE_STATE_TIMED_OUT;
    	pthread_mutex_unlock(&msgResponse->responseMutex);

        /* Return true that the state changed */
        return true;
    }

    pthread_mutex_unlock(&msgResponse->responseMutex);

    return false;
}


bool waitForResponseMessage(PcepMessageResponse *msgResponse)
{
    if (msgResponse == NULL)
    {
    	fprintf(stderr, "ERROR waitForResponseMessage cannot query with NULL PcepMessageResponse\n");
        return false;
    }

    pthread_mutex_lock(&msgResponse->responseMutex);

    /* If the message is already available, nothing else to do */
    if (msgResponse->responseStatus == RESPONSE_STATE_READY)
    {
    	pthread_mutex_unlock(&msgResponse->responseMutex);
    	return true;
    }

    int waitRetval = 0;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    addMillisToTimespec(&ts, msgResponse->maxWaitTimeMilliSeconds);

    while (!msgResponse->responseCondition && waitRetval == 0)
    {
    	waitRetval = pthread_cond_timedwait(
    			&msgResponse->responseCondVar, &msgResponse->responseMutex, &ts);
    }

    /* If the message is ready, just return now */
    if (msgResponse->responseStatus == RESPONSE_STATE_READY)
    {
    	pthread_mutex_unlock(&msgResponse->responseMutex);
        return true;
    }

    if (waitRetval != 0)
    {
    	if (waitRetval == ETIMEDOUT)
    	{
    		printf("WARN waitForResponseMessage TimedOut session [%d] requestId [%d]\n",
    				msgResponse->session->sessionId, msgResponse->requestId);
    		msgResponse->prevResponseStatus = msgResponse->responseStatus;
    		msgResponse->responseStatus = RESPONSE_STATE_TIMED_OUT;
    	}
    	else
    	{
    		printf("WARN waitForResponseMessage pthread_cond_timedwait returned error [%d] waitTime [%ld.%09ld] maxWait [%d]\n",
    				waitRetval, ts.tv_sec, ts.tv_nsec, msgResponse->maxWaitTimeMilliSeconds);
    	}
    }

    clock_gettime(CLOCK_REALTIME, &ts);
    pthread_mutex_unlock(&msgResponse->responseMutex);

    return false;
}
