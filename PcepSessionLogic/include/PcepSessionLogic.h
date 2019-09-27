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
typedef struct PcepPceReq_
{
    /* RP */
    bool rpFlagReoptimization;
    bool rpFlagBidirectional;
    bool rpFlagLoosePath;
    char rpFlagPriority; /* 3 bits, values from 0 - 7 */
    /* RP RequestId created internally */

    /* Endpoints */
	struct in_addr srcEndpoint;
	struct in_addr dstEndpoint;
    /*struct in6_addr srcV6Endpoint;
    struct in6_addr dstV6Endpoint;*/

    /*
     * The rest of these fields are optional
     */

    /* Label Switch Path Attrs */
	struct pcep_object_lspa *lspa;
	float bandwidth;

    /* Contiguous group of metrics */
	struct pcep_object_metric *metrics;
    int numMetrics;

    struct pcep_object_eros_list *rroList;
    struct pcep_object_eros_list *iroList;

    struct pcep_object_load_balancing *loadBalancing;

    /* if pathCount > 1, use svec: synchronization vector
	int pathCount; */

} PcepPceReq;

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

bool runSessionLogic();

bool runSessionLogicWaitForCompletion();

bool stopSessionLogic();

PcepSession *createPcepSession(PcepConfiguration *config, struct in_addr *pceIp, short port);

void destroyPcepSession(PcepSession *);

#endif /* INCLUDE_PCEPSESSIONLOGIC_H_ */
