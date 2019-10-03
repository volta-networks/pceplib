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
    bool timedOut;
    bool responseError;
    int elapsedTimeMilliSeconds;
	struct pcep_messages_list *responseMsgList;
    /* Internally used field */
	PcepMessageResponse *response;

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
 * until the reply is available, or until maxWaitMilliSeconds is reached.
 * For the objects in PcepPceReq, use the pcep_obj_create_*() functions
 * defined in pcep-objects.h. Memory allocated by these creation functions
 * will be freed internally.
 * Returns a PcepPceReply when the response is available, or NULL on timeout */
PcepPceReply *requestPathComputation(PcepSession *session, PcepPceRequest *pceReq, int maxWaitMilliSeconds);

/* Asynchronously request path computation routes. This method will return
 * immediately and the response can be obtained by polling getAsyncResult()
 * with the PcepPceReply returned from this function.
 * Returns a PcepPceReply to be used with getAsyncResult() */
PcepPceReply *requestPathComputationAsync(PcepSession *session, PcepPceRequest *pceReq, int maxWaitMilliSeconds);

/* Check if a response is available yet, using the PcepPceReply returned
 * from requestPathComputationAsync().
 * Returns true if the response is ready and fills in the following fields:
 * - PcepPceReply->elapsedTimeMilliSeconds
 * - PcepPceReply->responseMsgList
 * Returns false for one of the following 3 reasons:
 * - if the reply is not ready yet
 * - if there is an error, sets PcepPceReply->responseError = true
 * - if there is a timeout, sets PcepPceReply->timedOut = true
 */
bool getAsyncResult(PcepPceReply *pceReply);


#endif /* PCEPPCC_INCLUDE_PCEPPCCAPI_H_ */
