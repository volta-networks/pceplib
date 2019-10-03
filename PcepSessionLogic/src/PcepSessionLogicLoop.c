/*
 * PcepSessionLogicLoop.c
 *
 *  Created on: Sep 20, 2019
 *      Author: brady
 */

#include <malloc.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>

#include "PcepSessionLogic.h"
#include "PcepSessionLogicInternals.h"
#include "PcepTimers.h"

/* Global var needed for callback handlers */
extern PcepSessionLogicHandle *sessionLogicHandle_;

/* Internal util function to create SessionEvent's */
static PcepSessionEvent *createSessionEvent(PcepSession *session)
{
    PcepSessionEvent *event = malloc(sizeof(PcepSessionEvent));
    event->session = session;
    event->expiredTimerId = TIMER_ID_NOT_SET;
    event->receivedMsgList = NULL;
    event->socketClosed = false;

    return event;
}


/* A function pointer to this function is passed to PcepSocketComm
 * for each PcepSession creation, so it will be called whenever
 * messages are ready to be read. This function will be called
 * by the SocketComm thread.
 * This function will marshal the read PCEP message and give it
 * to the SessionLogicLoop so it can be handled by the SessionLogic
 * state machine. */
int sessionLogicMsgReadyHandler(void *data, int socketFd)
{
    PcepSession *session = (PcepSession *) data;

    pthread_mutex_lock(&(sessionLogicHandle_->sessionLogicMutex));
    sessionLogicHandle_->sessionLogicCondition = true;
    /* TODO how to determine if the socket was closed */
    struct pcep_messages_list *msgList = pcep_msg_read(socketFd);
    if (msgList == NULL)
    {
        fprintf(stderr, "Error marshalling PCEP message\n");
    	pthread_mutex_unlock(&(sessionLogicHandle_->sessionLogicMutex));

        return -1;
    }

    printf("[%ld-%ld] sessionLogicMsgReadyHandler Received message of type [%d] len [%d] on sessionId [%d]\n",
    		time(NULL), pthread_self(), msgList->header.type, msgList->header.length, session->sessionId);

    PcepSessionEvent *rcvdMsgEvent = createSessionEvent(session);
    rcvdMsgEvent->receivedMsgList = msgList;
    queueEnqueue(sessionLogicHandle_->sessionEventQueue, rcvdMsgEvent);


    pthread_cond_signal(&(sessionLogicHandle_->sessionLogicCondVar));
    pthread_mutex_unlock(&(sessionLogicHandle_->sessionLogicMutex));

    return msgList->header.length;
}


/* A function pointer to this function was passed to PcepSocketComm,
 * so it will be called whenever the socket is closed. This function
 * will be called by the SocketComm thread. */
void sessionLogicConnExceptNotifier(void *data, int socketFd)
{
    PcepSession *session = (PcepSession *) data;
    printf("[%ld-%ld] PcepSessionLogic sessionLogicConnExceptNotifier socket closed [%d], sessionId [%d]\n",
    		time(NULL), pthread_self(), socketFd, session->sessionId);

    pthread_mutex_lock(&(sessionLogicHandle_->sessionLogicMutex));
    PcepSessionEvent *socketEvent = createSessionEvent(session);
    socketEvent->socketClosed = true;
    queueEnqueue(sessionLogicHandle_->sessionEventQueue, socketEvent);
    sessionLogicHandle_->sessionLogicCondition = true;

    pthread_cond_signal(&(sessionLogicHandle_->sessionLogicCondVar));
    pthread_mutex_unlock(&(sessionLogicHandle_->sessionLogicMutex));
}


/*
 * This method is the timer expire handler, and will only
 * pass the event to the SessionLogic loop and notify it
 * that there is a timer available. This function will be
 * called by the Timers thread.
 */
void sessionLogicTimerExpireHandler(void *data, int timerId)
{
    if (data == NULL)
    {
        fprintf(stderr, "Cannot handle timer with NULL data\n");
    	return;
    }

    printf("[%ld-%ld] Timer expired handler timerId [%d]\n", time(NULL), pthread_self(), timerId);
    PcepSessionEvent *expiredTimerEvent = createSessionEvent((PcepSession *) data);
    expiredTimerEvent->expiredTimerId = timerId;

    pthread_mutex_lock(&(sessionLogicHandle_->sessionLogicMutex));
    sessionLogicHandle_->sessionLogicCondition = true;
    queueEnqueue(sessionLogicHandle_->sessionEventQueue, expiredTimerEvent);

    pthread_cond_signal(&(sessionLogicHandle_->sessionLogicCondVar));
    pthread_mutex_unlock(&(sessionLogicHandle_->sessionLogicMutex));
}


/*
 * SessionLogic event loop
 * This function is called upon thread creation from PcepSessionLogic.c
 */
void *sessionLogicLoop(void *data)
{
    if (data == NULL)
    {
    	fprintf(stderr, "Cannot start sessionLogicLoop with NULL data");

    	return NULL;
    }

    printf("[%ld-%ld] Starting SessionLogicLoop thread\n", time(NULL), pthread_self());

    PcepSessionLogicHandle *sessionLogicHandle = (PcepSessionLogicHandle *) data;

    while (sessionLogicHandle->active)
    {
        pthread_mutex_lock(&(sessionLogicHandle->sessionLogicMutex));

        /* This internal loop helps avoid spurious interrupts */
        while (!sessionLogicHandle->sessionLogicCondition)
        {
        	pthread_cond_wait(&(sessionLogicHandle->sessionLogicCondVar),
    			              &(sessionLogicHandle->sessionLogicMutex));
        }

        PcepSessionEvent *event = queueDequeue(sessionLogicHandle->sessionEventQueue);
        while (event != NULL)
        {
        	if (event->expiredTimerId != TIMER_ID_NOT_SET)
        	{
        		handleTimerEvent(event);
        	}

        	if (event->receivedMsgList != NULL)
        	{
        		handleSocketCommEvent(event);
        	}

        	/* TODO use this as the API to create sessions, etc
		    handleNbi(sessionLogicHandle);
        	 */

            free(event);
        	event = queueDequeue(sessionLogicHandle->sessionEventQueue);
        }

        sessionLogicHandle->sessionLogicCondition = false;
        pthread_mutex_unlock(&(sessionLogicHandle->sessionLogicMutex));
    }

    return NULL;
}
