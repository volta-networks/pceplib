/*
 * PcepSessionLogicNbi.c
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

#include "pcep-messages.h"
#include "pcep-objects.h"

#include "PcepSessionLogic.h"
#include "PcepSessionLogicInternals.h"
#include "PcepTimers.h"

/* Global var needed for callback handler */
extern PcepSessionLogicHandle *sessionLogicHandle_;
int sessionId_ = 0;

int getNextSessionId()
{
	if (sessionId_ == INT_MAX)
	{
		sessionId_ = 0;
	}

	return sessionId_++;
}

void destroySession()
{

}


/* TODO temporary function until NBI is created and integrated */
PcepSession *createNbiPcepSession(const char *host, int port)
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

    session->socketCommSession = socketCommSessionInitializeWithPort(
            NULL,
    		sessionLogicMsgReadyHandler,
			sessionLogicConnExceptNotifier,
			host,
			port,
			session);
    if (session->socketCommSession == NULL)
    {
        fprintf(stderr, "Cannot establish socketCommSession.\n");
        destroySession(session);

    	return NULL;
    }

    if (!socketCommSessionConnectTcp(session->socketCommSession))
    {
        fprintf(stderr, "Cannot establish TCP socket.\n");
        destroySession(session);

    	return NULL;
    }
    session->sessionState = SESSION_STATE_TCP_CONNECTED;

    /* Create and Send PCEP Open */
    struct pcep_header* openMsg = pcep_msg_create_open(TIME_KEEP_ALIVE, TIME_DEAD_TIMER, session->sessionId);
    socketCommSessionSendMessage(session->socketCommSession, (const char *) openMsg, ntohs(openMsg->length));

    session->timerIdOpenKeepWait = createTimer(TIME_OPEN_KEEP_WAIT, session);
    //session->sessionState = SESSION_STATE_OPENED;

    return session;
}
