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
#include <string.h>
#include <strings.h>

#include "pcep-messages.h"
#include "PcepPccApi.h"

int requestId_ = 0;

/* Simple util function implemented in PcepSessionLogic.c */
extern int timespecDiff(struct timespec *start, struct timespec *stop);

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
PcepPceReply *requestPathComputation(PcepSession *session, PcepPceRequest *pceReq, int maxWaitMilliSeconds)
{
	PcepPceReply *pceReply = requestPathComputationAsync(session, pceReq, maxWaitMilliSeconds);

    /* This call will block for at most maxWaitMilliSeconds */
    waitForResponseMessage(pceReply->response);

    pceReply->responseMsgList = pceReply->response->responseMsgList;
    pceReply->elapsedTimeMilliSeconds =
    		timespecDiff(&(pceReply->response->timeRequestRegistered),
    				     &(pceReply->response->timeResponseReceived));
    destroyResponseMessage(pceReply->response);
    pceReply->response = NULL;

    return pceReply;
}


/* Asynchronously request Path Computation, call getAsyncResult()
 * with the returned requestId to get the result */
PcepPceReply *requestPathComputationAsync(PcepSession *session, PcepPceRequest *pceReq, int maxWaitMilliSeconds)
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

    /* TODO currently only supporting IPv4 */
	struct pcep_object_endpoints_ipv4 *endpoints =
			pcep_obj_create_enpoint_ipv4(&(pceReq->srcEndpointIp.srcV4EndpointIp),
					                     &(pceReq->dstEndpointIp.dstV4EndpointIp));

    int messageSize =
    		sizeof(struct pcep_header) +
    		ntohs(rp->header.object_length) +
			ntohs(endpoints->header.object_length);

	/*
	 * Optional fields
	 * First calculate the size needed for the buffer
	 */
    if (pceReq->bandwidth != NULL)
    {
        messageSize += ntohs(pceReq->bandwidth->header.object_length);
    }
    if (pceReq->lspa != NULL)
    {
        messageSize += ntohs(pceReq->lspa->header.object_length);
    }
    if (pceReq->metrics != NULL)
    {
        messageSize += ntohs(pceReq->metrics->header.object_length);
    }
    if (pceReq->rroList != NULL)
    {
        messageSize += ntohs(pceReq->rroList->ero_hdr.header.object_length);
    }
    if (pceReq->iroList != NULL)
    {
        messageSize += ntohs(pceReq->iroList->ero_hdr.header.object_length);
    }
    if (pceReq->loadBalancing != NULL)
    {
        messageSize += ntohs(pceReq->loadBalancing->header.object_length);
    }

    /* Allocate the buffer and copy the objects into it */
    char *messageBuffer = malloc(messageSize);
    bzero(messageBuffer, messageSize);

    /* Common PcReq header
     * Flags
     *  0 1 2 3 4 5 6 7
     * +-+-+-+-+-+-+-+-+
     * | Ver |  Flags  |
     * +-+-+-+-+-+-+-+-+ */
    struct pcep_header *hdr = (struct pcep_header *) messageBuffer;
    hdr->ver_flags = 0x20; /* version 1 */
    hdr->length = htons(messageSize);
    hdr->type = PCEP_TYPE_PCREQ;
    int index = sizeof(struct pcep_header);

    /* Copy the RP */
    memcpy(messageBuffer + index, rp, ntohs(rp->header.object_length));
    index += ntohs(rp->header.object_length);
    free(rp); /* free the memory allocated by the pcep_obj_create*() functions */

    /* Copy the Endpoints */
    memcpy(messageBuffer + index, endpoints, ntohs(endpoints->header.object_length));
    index += ntohs(endpoints->header.object_length);
    free(endpoints);

    /* Bandwidth */
    if (pceReq->bandwidth != NULL)
    {
    	memcpy(messageBuffer + index, pceReq->bandwidth, ntohs(pceReq->bandwidth->header.object_length));
    	index += ntohs(pceReq->bandwidth->header.object_length);
        free(pceReq->bandwidth);
    }

    /* Label Switch Path Attributes */
    if (pceReq->lspa != NULL)
    {
    	memcpy(messageBuffer + index, pceReq->lspa, ntohs(pceReq->lspa->header.object_length));
    	index += ntohs(pceReq->lspa->header.object_length);
        free(pceReq->lspa);
    }

    /* Metrics */
    if (pceReq->metrics != NULL)
    {
    	memcpy(messageBuffer + index, pceReq->metrics, ntohs(pceReq->metrics->header.object_length));
    	index += ntohs(pceReq->metrics->header.object_length);
        free(pceReq->metrics);
    }

    /* RRO */
    if (pceReq->rroList != NULL)
    {
    	memcpy(messageBuffer + index, pceReq->rroList, ntohs(pceReq->rroList->ero_hdr.header.object_length));
    	index += ntohs(pceReq->rroList->ero_hdr.header.object_length);
        free(pceReq->rroList);
    }

    /* IRO */
    if (pceReq->iroList != NULL)
    {
        // TODO should we instead look at the header in case there is a list of IRO's?
    	memcpy(messageBuffer + index, pceReq->iroList, ntohs(pceReq->iroList->ero_hdr.header.object_length));
    	index += ntohs(pceReq->iroList->ero_hdr.header.object_length);
        free(pceReq->iroList);
    }

    /* Load Balancing */
    if (pceReq->loadBalancing != NULL)
    {
    	memcpy(messageBuffer + index, pceReq->loadBalancing, ntohs(pceReq->loadBalancing->header.object_length));
    	index += ntohs(pceReq->loadBalancing->header.object_length);
        free(pceReq->loadBalancing);
    }

	socketCommSessionSendMessage(
			session->socketCommSession,
			(const char *) messageBuffer,
			ntohs(hdr->length));

	PcepPceReply *pceReply = malloc(sizeof(PcepPceReply));
	pceReply->elapsedTimeMilliSeconds = 0;
	pceReply->responseError = false;
	pceReply->timedOut = false;
	pceReply->responseMsgList = NULL;
	pceReply->response =
			registerResponseMessage(session, requestId, maxWaitMilliSeconds);

    return pceReply;
}


bool getAsyncResult(PcepPceReply *pceReply)
{
    if (!queryResponseMessage(pceReply->response))
    {
        /* Its not ready yet, and nothing happened */
    	return false;
    }

    if (pceReply->response->responseStatus == RESPONSE_STATE_TIMED_OUT)
    {
    	pceReply->timedOut = true;
        return false;
    }

    if (pceReply->response->responseStatus == RESPONSE_STATE_ERROR)
    {
    	pceReply->responseError = true;
        return false;
    }

    if (pceReply->response->responseStatus == RESPONSE_STATE_READY)
    {
    	pceReply->responseMsgList = pceReply->response->responseMsgList;
    	pceReply->elapsedTimeMilliSeconds =
    			timespecDiff(&(pceReply->response->timeRequestRegistered),
    					     &(pceReply->response->timeResponseReceived));
    	destroyResponseMessage(pceReply->response);
    	pceReply->response = NULL;

        return true;
    }
    else
    {
    	return false;
    }

}
