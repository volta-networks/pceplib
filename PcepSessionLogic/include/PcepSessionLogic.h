/*
 * PcepSessionLogic.h
 *
 *  Created on: Sep 20, 2019
 *      Author: brady
 */

#ifndef INCLUDE_PCEPSESSIONLOGIC_H_
#define INCLUDE_PCEPSESSIONLOGIC_H_

#include <stdbool.h>

#include "pcep-objects.h"
#include "PcepSocketComm.h"


typedef struct PcepConfiguration_
{
    int keepAliveSeconds;
    int deadTimerSeconds;
    int requestTimeSeconds;
    int maxUnknownRequests;
    int maxUnknownMessages;

} PcepConfiguration;

/* Path Computation Request */

/* The format of a PCReq message is as follows:
       <PCReq Message>::= <Common Header>
                          [<svec-list>]
                          <request-list>

   where:
      <svec-list>::=<SVEC>[<svec-list>]
      <request-list>::=<request>[<request-list>]

      <request>::= <RP>
                   <END-POINTS>
                   [<LSPA>] Label Switched Path Attrs
                   [<BANDWIDTH>]
                   [<metric-list>]
                   [<RRO>[<BANDWIDTH>]]
                   [<IRO>]
                   [<LOAD-BALANCING>]

   where:
      <metric-list>::=<METRIC>[<metric-list>]
 */
typedef struct PcepPceRequest_
{
    /* RP Flags - Mandatory field
     * RP RequestId is created internally */
    bool rpFlagReoptimization;
    bool rpFlagBidirectional;
    bool rpFlagLoosePath;
    char rpFlagPriority; /* 3 bits, values from 0 - 7 */

    /* Endpoints - Mandatory field
     * ipVersion must be either IPPROTO_IP (for IPv4) or IPPROTO_IPV6,
     * defined in netinet/in.h */
    int endpointIpVersion;
    union srcEndpointIp_ {
    	struct in_addr srcV4EndpointIp;
    	struct in6_addr srcV6EndpointIp;
    } srcEndpointIp;
    union dstEndpointIp_ {
    	struct in_addr dstV4EndpointIp;
    	struct in6_addr dstV6EndpointIp;
    } dstEndpointIp;

    /*
     * The rest of these fields are optional
     */

    /* Populate with pcep_obj_create_bandwidth() */
	struct pcep_object_bandwidth *bandwidth;

    /* Label Switch Path Attributes
     * Populate with pcep_obj_create_lspa() */
	struct pcep_object_lspa *lspa;

    /* Contiguous group of metrics
     * Populate with pcep_obj_create_metric() */
	struct pcep_object_metric *metrics;

    /* Reported Route Object
     * Populate with pcep_obj_create_rro()
     * TODO Not supported yet, need to implement */
    struct pcep_object_eros_list *rroList;

    /* Include Route Object
     * Populate with pcep_obj_create_iro()
     * TODO Not supported yet, need to implement */
    struct pcep_object_eros_list *iroList;

    /* Populate with pcep_obj_create_load_balancing()
     * TODO Not supported yet, need to implement */
    struct pcep_object_load_balancing *loadBalancing;

    /* if pathCount > 1, use svec: synchronization vector
	int pathCount; */

} PcepPceRequest;


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
    bool pcepOpenReceived;
    int numErroneousMessages;
    PcepSocketCommSession *socketCommSession;
    PcepConfiguration *pccConfig;

} PcepSession;


typedef enum PcepMessageResponseStatus_
{
    RESPONSE_STATE_UNKNOWN = 0,
    RESPONSE_STATE_WAITING = 1,
    RESPONSE_STATE_READY = 2,
    RESPONSE_STATE_TIMED_OUT = 3,
    RESPONSE_STATE_ERROR = 4

} PcepMessageResponseStatus;

/* Currently used when PcReq messages are sent to wait for PcRep responses */
typedef struct PcepMessageResponse_
{
	int requestId;
	PcepMessageResponseStatus prevResponseStatus;
	PcepMessageResponseStatus responseStatus;
	struct timespec timeRequestRegistered;
	struct timespec timeResponseReceived;
    int maxWaitTimeMilliSeconds;
	PcepSession *session;
	struct pcep_messages_list *responseMsgList;
    bool responseCondition;
    pthread_mutex_t responseMutex;
	pthread_cond_t responseCondVar;

} PcepMessageResponse;


bool runSessionLogic();

bool runSessionLogicWaitForCompletion();

bool stopSessionLogic();

PcepSession *createPcepSession(PcepConfiguration *config, struct in_addr *pceIp, short port);

void destroyPcepSession(PcepSession *session);

/* Register a Request Message requestId as having been sent, and internally
 * store the details. When and if a Reply is received with the requestId,
 * then the PcepMessageResponse object will be updated. Intended to be used in
 * conjunction with either queryResponseMessage() or waitForResponseMessage()
 * Returns a pointer to the registered PcepMessageResponse object.  */
PcepMessageResponse *registerResponseMessage(
		PcepSession *session, int requestId, unsigned int maxWaitTimeMilliSeconds);

/* Destroy a previously registered PcepMessageResponse object */
void destroyResponseMessage(PcepMessageResponse *response);

PcepMessageResponse *getRegisteredResponseMessage(int requestId);

/* Query if a Message Response is available
 * If one is available, the supplied PcepMessageResponse will be updated.
 * Modification and querying of the msgResponse is thread safe.
 * Returns true if the Message Response is available or if there is a
 * change in the PcepMessageResponse status, false otherwise */
bool queryResponseMessage(PcepMessageResponse *msgResponse);

/* Wait for a Message Response until the response is available, or
 * until the PcepMessageResponse->maxWaitTimeMilliSeconds is reached.
 * Returns true if a response was received, false otherwise. */
bool waitForResponseMessage(PcepMessageResponse *msgResponse);

#endif /* INCLUDE_PCEPSESSIONLOGIC_H_ */
