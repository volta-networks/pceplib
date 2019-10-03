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

/* Global var needed for messageResponses */
extern PcepSessionLogicHandle *sessionLogicHandle_;

/*
 * Util functions called by the state handling below
 */

void closePcepSession(PcepSession * session, enum pcep_close_reasons reason)
{
	struct pcep_header* closeMsg = pcep_msg_create_close(0, reason);
	socketCommSessionSendMessage(
			session->socketCommSession,
			(const char *) closeMsg,
			ntohs(closeMsg->length));

    printf("[%ld-%ld] PcepSessionLogic send PcepClose message len [%d] for sessionId [%d]\n",
    		time(NULL), pthread_self(), ntohs(closeMsg->length), session->sessionId);

	socketCommSessionCloseTcpAfterWrite(session->socketCommSession);
	session->sessionState = SESSION_STATE_INITIALIZED;
}


void sendKeepAlive(PcepSession *session)
{
	struct pcep_header* keepAliveMsg = pcep_msg_create_keepalive();
	socketCommSessionSendMessage(
			session->socketCommSession,
			(const char *) keepAliveMsg,
			ntohs(keepAliveMsg->length));

    printf("[%ld-%ld] PcepSessionLogic send KeepAlive message len [%d] for sessionId [%d]\n",
    		time(NULL), pthread_self(), ntohs(keepAliveMsg->length), session->sessionId);

	if (session->timerIdKeepAlive == TIMER_ID_NOT_SET)
	{
		printf("[%ld-%ld] PcepSessionLogic set KeepAlive timer [%d secs] for sessionId [%d]\n",
				time(NULL), pthread_self(), session->pccConfig->keepAliveSeconds, session->sessionId);
		session->timerIdKeepAlive = createTimer(session->pccConfig->keepAliveSeconds, session);
	}
	else
	{
		printf("[%ld-%ld] PcepSessionLogic reset KeepAlive timer [%d secs] for sessionId [%d]\n",
				time(NULL), pthread_self(), session->pccConfig->keepAliveSeconds, session->sessionId);
		resetTimer(session->timerIdKeepAlive);
	}
}


void updateResponseMessage(PcepSession *session, struct pcep_messages_list *receivedMsgList)
{
    /* Iterate the message objects to get the RP object */
    bool foundRpObject = false;
	struct pcep_obj_list *listEntry = receivedMsgList->list;
    while (listEntry != NULL && foundRpObject == false)
    {
        if (listEntry->header->object_class == PCEP_OBJ_CLASS_RP)
        {
        	foundRpObject = true;
        }
        else
        {
        	listEntry = listEntry->next;
        }
    }

    if (!foundRpObject)
    {
    	fprintf(stderr, "ERROR in PCREP message: cant find mandatory RP object\n");
    	/* TODO when this reaches a MAX, need to react */
        session->numErroneousMessages++;
        return;
    }

    struct pcep_object_rp *rpObject = (struct pcep_object_rp *) listEntry->header;
    PcepMessageResponse msgResponseSearch;
    msgResponseSearch.requestId = rpObject->rp_reqidnumb;
    OrderedListNode *node =
    		orderedListFind(sessionLogicHandle_->responseMsgList, &msgResponseSearch);
    if (node == NULL)
    {
    	fprintf(stderr, "WARN Received a messages response id [%d] len [%d] class [%c] type [%c] that was not registered\n",
    			rpObject->rp_reqidnumb, ntohs(rpObject->header.object_length),
				rpObject->header.object_class, rpObject->header.object_type);
    	return;
    }
    PcepMessageResponse *msgResponse = node->data;
    printf("[%ld-%ld] PcepSessionLogic updateResponseMessage response ready: sessionId [%d] requestId [%d]\n",
    		time(NULL), pthread_self(), session->sessionId, msgResponse->requestId);

    orderedListRemoveFirstNodeEquals(sessionLogicHandle_->responseMsgList, &msgResponseSearch);

    pthread_mutex_lock(&msgResponse->responseMutex);
    msgResponse->prevResponseStatus = msgResponse->responseStatus;
    msgResponse->responseStatus = RESPONSE_STATE_READY;
    msgResponse->responseMsgList = receivedMsgList;
    msgResponse->responseCondition = true;
    clock_gettime(CLOCK_REALTIME, &msgResponse->timeResponseReceived);
    pthread_cond_signal(&msgResponse->responseCondVar);
    pthread_mutex_unlock(&msgResponse->responseMutex);
}


/*
 * These functions are called by sessionLogicLoop() from PcepSessionLogicLoop.c
 * These functions are executed in the sessionLogicLoop thread, and the mutex
 * is locked before calling these functions, so they are thread safe.
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
    PcepSession *session = event->session;

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
    	printf("\t PCEP_OPEN message\n");

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
    	printf("\t PCEP_KEEPALIVE message\n");
        if (session->sessionState == SESSION_STATE_TCP_CONNECTED)
        {
        	session->sessionState = SESSION_STATE_OPENED;
            cancelTimer(session->timerIdOpenKeepWait);
            session->timerIdOpenKeepWait = TIMER_ID_NOT_SET;
        }

        if (session->timerIdDeadTimer != TIMER_ID_NOT_SET)
        {
        	resetTimer(session->timerIdDeadTimer);
        }
        else
        {
        	session->timerIdDeadTimer = createTimer(session->pccConfig->deadTimerSeconds, session);
        }
    	break;

    case PCEP_TYPE_PCREP:
    	printf("\t PCEP_PCREP message\n");
    	updateResponseMessage(session, event->receivedMsgList);
        if (session->sessionState == SESSION_STATE_WAIT_PCREQ)
        {
        	session->sessionState = SESSION_STATE_IDLE;
            cancelTimer(session->timerIdPcReqWait);
            session->timerIdPcReqWait = TIMER_ID_NOT_SET;
        }
        else
        {
        	/* TODO when this reaches a MAX, need to react */
        	session->numErroneousMessages++;
        }
    	break;

    case PCEP_TYPE_CLOSE:
    	printf("\t PCEP_CLOSE message\n");
    	session->sessionState = SESSION_STATE_INITIALIZED;
    	socketCommSessionCloseTcp(session->socketCommSession);
    	break;

    case PCEP_TYPE_PCREQ:
    	printf("\t PCEP_PCREQ message\n");
    	/* TODO when this reaches a MAX, need to react.
    	 *      reply with PcepError msg. */
    	session->numErroneousMessages++;
    	break;

    case PCEP_TYPE_PCNOTF:
    	printf("\t PCEP_PCNOTF message\n");
        /* TODO implement this */
    	break;
    case PCEP_TYPE_ERROR:
    	printf("\t PCEP_ERROR message\n");
        /* TODO implement this */
    	break;
    default:
    	break;
    }
}
