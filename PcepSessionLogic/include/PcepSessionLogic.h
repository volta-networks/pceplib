/*
 * PcepSessionLogic.h
 *
 *  Created on: Sep 20, 2019
 *      Author: brady
 */

#ifndef INCLUDE_PCEPSESSIONLOGIC_H_
#define INCLUDE_PCEPSESSIONLOGIC_H_

#include <stdbool.h>

#include "PcepSocketComm.h"


typedef enum PcepSessionState_
{
    SESSION_STATE_UNKNOWN = 0,
	SESSION_STATE_INITIALIZED = 1,
	SESSION_STATE_TCP_CONNECTED = 2,
	SESSION_STATE_OPENED = 3,
	SESSION_STATE_WAIT_PCREQ = 4,
	SESSION_STATE_IDLE = 5

} PcepSessionState;

typedef struct PcepSession_
{
    int sessionId;
    PcepSessionState sessionState;
    int timerIdOpenKeepWait;
    int timerIdPcReqWait;
    int timerIdDeadTimer;
    int timerIdKeepAlive;
    PcepSocketCommSession *socketCommSession;
    bool pcepOpenReceived;
    int numErroneousMessages;

} PcepSession;

bool runSessionLogic();

bool runSessionLogicWaitForCompletion();

bool stopSessionLogic();

#endif /* INCLUDE_PCEPSESSIONLOGIC_H_ */
