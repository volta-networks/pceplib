/*
 * PcepSessionLogicInternals.h
 *
 *  Created on: Sep 20, 2019
 *      Author: brady
 */

#ifndef SRC_PCEPSESSIONLOGICINTERNALS_H_
#define SRC_PCEPSESSIONLOGICINTERNALS_H_


#include <pthread.h>
#include <stdbool.h>

#include "pcep-tools.h"

#include "PcepUtilsOrderedList.h"
#include "PcepUtilsQueue.h"


typedef struct PcepSessionLogicHandle_
{
	pthread_t sessionLogicThread;
	pthread_mutex_t sessionLogicMutex;
	pthread_cond_t sessionLogicCondVar;
    bool sessionLogicCondition;
    bool active;

    OrderedListHandle *sessionList;
    QueueHandle *sessionEventQueue;
    OrderedListHandle *responseMsgList;

} PcepSessionLogicHandle;


typedef struct PcepSessionEvent_
{
	PcepSession *session;
	int expiredTimerId;
	struct pcep_messages_list *receivedMsgList;
    bool socketClosed;

} PcepSessionEvent;


/* Functions implemented in PcepSessionLogicLoop.c */
void *sessionLogicLoop(void *data);
int sessionLogicMsgReadyHandler(void *data, int socketFd);
void sessionLogicConnExceptNotifier(void *data, int socketFd);
void sessionLogicTimerExpireHandler(void *data, int timerId);

void handleTimerEvent(PcepSessionEvent *event);
void handleSocketCommEvent(PcepSessionEvent *event);


#endif /* SRC_PCEPSESSIONLOGICINTERNALS_H_ */
