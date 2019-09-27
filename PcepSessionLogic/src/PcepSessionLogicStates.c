/*
 * PcepSessionLogicStates.c
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

/*
 * Util functions called by the state handling below
 */

void closePcepSession(PcepSession * session, enum pcep_close_reasons reason)
{
    printf("[%ld-%ld] PcepSessionLogic sendPcepClose for sessionId [%d]\n",
    		time(NULL), pthread_self(), session->sessionId);

	struct pcep_header* closeMsg = pcep_msg_create_close(0, reason);
	socketCommSessionSendMessage(
			session->socketCommSession,
			(const char *) closeMsg,
			ntohs(closeMsg->length));
	socketCommSessionCloseTcpAfterWrite(session->socketCommSession);
	session->sessionState = SESSION_STATE_INITIALIZED;
}


void sendKeepAlive(PcepSession *session)
{
    printf("[%ld-%ld] PcepSessionLogic sendKeepAlive for sessionId [%d]\n",
    		time(NULL), pthread_self(), session->sessionId);

	struct pcep_header* keepAliveMsg = pcep_msg_create_keepalive();
	socketCommSessionSendMessage(
			session->socketCommSession,
			(const char *) keepAliveMsg,
			ntohs(keepAliveMsg->length));
	if (session->timerIdKeepAlive == TIMER_ID_NOT_SET)
	{
		printf("[%ld-%ld] PcepSessionLogic set KeepAlive for sessionId [%d]\n",
				time(NULL), pthread_self(), session->sessionId);
		session->timerIdKeepAlive = createTimer(session->pccConfig->keepAliveSeconds, session);
	}
	else
	{
		printf("[%ld-%ld] PcepSessionLogic reset KeepAlive for sessionId [%d]\n",
				time(NULL), pthread_self(), session->sessionId);
		resetTimer(session->timerIdKeepAlive);
	}
}


/*
 * These functions are called by sessionLogicLoop() from PcepSessionLogicLoop.c
 * These functions are executed in the sessionLogicLoop thread.
 */

/* State Machine handling for expired timers */
void handleTimerEvent(PcepSessionEvent *event)
{
    PcepSession *session = event->session;

    printf("[%ld-%ld] PcepSessionLogic handleTimerEvent: sessionId [%d] event timerId [%d] "
    		"session timers [OKW, PRW, DT, KA] [%d, %d, %d, %d]\n",
    		time(NULL), pthread_self(), session->sessionId, event->expiredTimerId,
			session->timerIdOpenKeepWait, session->timerIdPcReqWait,
			session->timerIdDeadTimer, session->timerIdKeepAlive);

    /*
     * These timer expirations are independent of the session state
     */
    if (event->expiredTimerId == session->timerIdDeadTimer)
    {
        session->timerIdDeadTimer = TIMER_ID_NOT_SET;
        closePcepSession(session, PCEP_CLOSE_REASON_DEADTIMER);
        return;
    }
    else if(event->expiredTimerId == session->timerIdKeepAlive)
    {
        session->timerIdKeepAlive = TIMER_ID_NOT_SET;
        sendKeepAlive(session);
        return;
    }

    /*
     * Handle timers that depend on the session state
     */
    switch(session->sessionState)
    {
    case SESSION_STATE_TCP_CONNECTED:
        if (event->expiredTimerId == session->timerIdOpenKeepWait)
        {
            /* Close the TCP session */
        	printf("handleTimerEvent OpenKeepWait timer expired for session [%d]\n", session->sessionId);
            socketCommSessionCloseTcpAfterWrite(session->socketCommSession);
            session->sessionState = SESSION_STATE_INITIALIZED;
            session->timerIdOpenKeepWait = TIMER_ID_NOT_SET;
        }
    	break;

    case SESSION_STATE_WAIT_PCREQ:
        if (event->expiredTimerId == session->timerIdPcReqWait)
        {
        	printf("handleTimerEvent PCReqWait timer expired for session [%d]\n", session->sessionId);
            /* TODO is this the right reason?? */
            closePcepSession(session, PCEP_CLOSE_REASON_DEADTIMER);
            session->timerIdPcReqWait = TIMER_ID_NOT_SET;
        }
    	break;

    case SESSION_STATE_IDLE:
    case SESSION_STATE_INITIALIZED:
    case SESSION_STATE_OPENED:
    default:
        fprintf(stderr, "handleTimerEvent Unrecognized state transition, timerId [%d] state [%d] sessionId [%d]\n",
        		event->expiredTimerId, session->sessionState, session->sessionId);
    	break;
    }
}


/* State Machine handling for received messages */
void handleSocketCommEvent(PcepSessionEvent *event)
{
    PcepSession * session = event->session;

    printf("[%ld-%ld] PcepSessionLogic handleSocketCommEvent: sessionId [%d] msgType [%d] socketClosed [%d]\n",
    		time(NULL), pthread_self(),
			session->sessionId,
			(event->receivedMsgList == NULL ? -1 : event->receivedMsgList->header.type),
			event->socketClosed);

    /*
     * Independent of the session state
     */
    if (event->socketClosed)
    {
    	printf("handleSocketCommEvent Socket closed for session [%d]\n", session->sessionId);
    	session->sessionState = SESSION_STATE_INITIALIZED;
    	socketCommSessionCloseTcp(session->socketCommSession);
        return;
    }

    if (event->receivedMsgList == NULL)
    {
    	return;
    }

    /* TODO should we reset the DeadTimer for every message received */

    switch (event->receivedMsgList->header.type)
    {
    case PCEP_TYPE_OPEN:
        if (session->pcepOpenReceived == false)
        {
            sendKeepAlive(session);
            session->pcepOpenReceived = true;
        }
        else
        {
        	/* TODO when this reaches a MAX, need to react */
        	session->numErroneousMessages++;
        }
    	break;

    case PCEP_TYPE_KEEPALIVE:
        if (session->timerIdDeadTimer != TIMER_ID_NOT_SET)
        {
        	resetTimer(session->timerIdDeadTimer);
        }
        else
        {
        	session->timerIdDeadTimer = createTimer(session->pccConfig->deadTimerSeconds, session);
        }
    	break;

    case PCEP_TYPE_PCREQ:
        if (session->sessionState == SESSION_STATE_WAIT_PCREQ)
        {
            /* TODO store the results */
        }
        else
        {
        	/* TODO when this reaches a MAX, need to react */
        	session->numErroneousMessages++;
        }
    	break;

    case PCEP_TYPE_CLOSE:
    	session->sessionState = SESSION_STATE_INITIALIZED;
    	socketCommSessionCloseTcp(session->socketCommSession);
    	break;

    case PCEP_TYPE_PCREP:
    	/* TODO when this reaches a MAX, need to react.
    	 *      reply with PcepError msg. */
    	session->numErroneousMessages++;
    	break;

    case PCEP_TYPE_PCNOTF:
        /* TODO implement this */
    	break;
    case PCEP_TYPE_ERROR:
        /* TODO implement this */
    	break;
    default:
    	break;
    }
}
