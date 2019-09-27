/*
 * PcepPccApi.c
 *
 *  Created on: Sep 27, 2019
 *      Author: brady
 */

#include <limits.h>
#include <malloc.h>
#include <stdbool.h>
#include <stdio.h>

#include "pcep-messages.h"
#include "PcepPccApi.h"

int requestId_ = 0;

int getNextRequestId()
{
	if (requestId_ == INT_MAX)
	{
		requestId_ = 0;
	}

	return requestId_++;
}


bool initializePcc()
{
	if (!runSessionLogic())
	{
		fprintf(stderr, "Error initializing PCC Session logic.\n");
		return false;
	}

    return true;
}


/* This function is blocking */
bool initializePccWaitForCompletion()
{
    return runSessionLogicWaitForCompletion();
}


bool destroyPcc()
{
	if (!stopSessionLogic())
	{
		fprintf(stderr, "Error stopping PCC Session Logic.\n");
		return false;
	}

    return true;
}


PcepConfiguration *createDefaultPcepConfiguration()
{
	PcepConfiguration *config = malloc(sizeof(PcepConfiguration));
    config->keepAliveSeconds = DEFAULT_CONFIG_KEEP_ALIVE;
    config->deadTimerSeconds = DEFAULT_CONFIG_DEAD_TIMER;
    config->requestTimeSeconds = DEFAULT_CONFIG_REQUEST_TIME;
    config->maxUnknownMessages = DEFAULT_CONFIG_MAX_UNKNOWN_MESSAGES;
    config->maxUnknownRequests = DEFAULT_CONFIG_MAX_UNKNOWN_REQUESTS;

	return config;
}


PcepSession *connectPce(PcepConfiguration *config, struct in_addr *host)
{
    return connectPceWithPort(config, host, PCEP_TCP_PORT);
}


PcepSession *connectPceWithPort(PcepConfiguration *config, struct in_addr *host, short port)
{
	return createPcepSession(config, host, port);
}


void disconnectPce(PcepSession *session)
{
    destroyPcepSession(session);
}


/* Synchronously request Path Computation, so this method will block
 * until the reply is available */
PcepPceReply *requestPathComputation(PcepSession *pceConnection, PcepPceReq *pceReq, int maxWaitMilliSeconds)
{
    /* TODO make a pce request message, send it, and figure out how to wait for the response */
    return NULL;
}


/* Asynchronously request Path Computation, call getAsyncResult()
 * with the returned requestId to get the result */
int requestPathComputationAsync(PcepSession *session, PcepPceReq *pceReq)
{
    int requestId = getNextRequestId();

    /* RP flag bits: |O|B|R|Pri|
     * O - StrictLoose - 1 bit
     * B - Bidirectional - 1 bit
     * R - ReOptimization - 1 bit
     * Pri - Priority - 3 bits */
    uint32_t rpFlags = 0;
    if (pceReq->rpFlagLoosePath)
    {
        rpFlags |= 0x20;
    }
    if (pceReq->rpFlagBidirectional)
    {
        rpFlags |= 0x10;
    }
    if (pceReq->rpFlagReoptimization)
    {
        rpFlags |= 0x08;
    }
	struct pcep_object_rp *rp = pcep_obj_create_rp(0, rpFlags, requestId);

	struct pcep_object_endpoints_ipv4 *endpoints =
			pcep_obj_create_enpoint_ipv4(&(pceReq->srcEndpoint), &(pceReq->dstEndpoint));

	/*
	 * Optional fields
	 */
    /* Bandwidth */
	struct pcep_object_bandwidth *bw = NULL;
    if (pceReq->bandwidth > 0)
    {
    	bw = pcep_obj_create_bandwidth(pceReq->bandwidth);
    }

    /* Metrics */
    if (pceReq->metrics != NULL)
    {
        // TODO
    }

    /* RRO */
    if (pceReq->rroList != NULL)
    {
        // TODO
    }

    /* IRO */
    if (pceReq->iroList != NULL)
    {
        // TODO
    }

    /* Load Balancing */
    if (pceReq->loadBalancing != NULL)
    {
        // TODO
    }

    /* This function only uses rp, endpoints, and bw */
	struct pcep_header *request = pcep_msg_create_request(rp, endpoints, bw);
	/*uint32_t reqs_len = ntohs(request->length);*/

	socketCommSessionSendMessage(
			session->socketCommSession,
			(const char *) request,
			ntohs(request->length));

    return requestId;
}


PcepPceReply *getAsyncResult(PcepSession *session, int requestId)
{
    /* TODO look up the requestId and try to get the response */
    return NULL;
}
