/*
 * PcepPccApi.h
 *
 *  Created on: Sep 27, 2019
 *      Author: brady
 */

#ifndef PCEPPCC_INCLUDE_PCEPPCCAPI_H_
#define PCEPPCC_INCLUDE_PCEPPCCAPI_H_

#include <stdbool.h>

#include "PcepSessionLogic.h"

#define PCEP_TCP_PORT 4189
#define DEFAULT_CONFIG_KEEP_ALIVE 30
#define DEFAULT_CONFIG_DEAD_TIMER DEFAULT_CONFIG_KEEP_ALIVE * 4
#define DEFAULT_CONFIG_REQUEST_TIME 30
#define DEFAULT_CONFIG_MAX_UNKNOWN_REQUESTS 5
#define DEFAULT_CONFIG_MAX_UNKNOWN_MESSAGES 5


typedef struct PcepPceReply_
{
    int pcepPceReplyId;

} PcepPceReply;


bool initializePcc();
/* This function is blocking */
bool initializePccWaitForCompletion();

bool destroyPcc();

PcepConfiguration *createDefaultPcepConfiguration();

/* Use the standard PCEP TCP port = 4189 */
PcepSession *connectPce(PcepConfiguration *config, struct in_addr *pceIp);
PcepSession *connectPceWithPort(PcepConfiguration *config, struct in_addr *pceIp, short port);

void disconnectPce(PcepSession *session);

/* Synchronously request path computation routes. This method will block
 * until the reply is available. For the objects in PcepPceReq, use the
 * pcep_obj_create_*() functions defined in pcep-objects.h */
PcepPceReply *requestPathComputation(PcepSession *session, PcepPceReq *pceReq, int maxWaitMilliSeconds);

int requestPathComputationAsync(PcepSession *session, PcepPceReq *pceReq);

PcepPceReply *getAsyncResult(PcepSession *session, int requestId);


#endif /* PCEPPCC_INCLUDE_PCEPPCCAPI_H_ */
