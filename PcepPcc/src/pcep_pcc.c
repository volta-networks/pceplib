
#include <netdb.h> // gethostbyname
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "PcepPccApi.h"

/*
 * PCEP PCC Design spec:
 * https://docs.google.com/presentation/d/1DYc3ZhYA1cQg9A552HjhneJXQKdhYrKW6v3NRYPtnbw/edit?usp=sharing
 */

void handle_signal_action(int sig_number)
{
	if (sig_number == SIGINT)
	{
		printf("SIGINT was caught!\n");
		// TODO do something here
	}
	else if (sig_number == SIGPIPE)
	{
		printf("SIGPIPE was caught!\n");
		// TODO do something here
	}

	exit(1);
}


int setup_signals()
{
	struct sigaction sa;
	sa.sa_handler = handle_signal_action;
	if (sigaction(SIGINT, &sa, 0) != 0)
	{
		perror("sigaction()");
		return -1;
	}
	if (sigaction(SIGPIPE, &sa, 0) != 0)
	{
		perror("sigaction()");
		return -1;
	}

	return 0;
}


void sendPceReqMessageSync(PcepSession *session)
{
	PcepPceRequest *pceReq = malloc(sizeof(PcepPceRequest));
    bzero(pceReq, sizeof(PcepPceRequest));

    pceReq->endpointIpVersion = IPPROTO_IP;
    inet_pton(AF_INET, "192.168.10.33", &(pceReq->srcEndpointIp.srcV4EndpointIp));
    inet_pton(AF_INET, "172.100.80.56", &(pceReq->dstEndpointIp.dstV4EndpointIp));

    PcepPceReply *pceReply = requestPathComputation(session, pceReq, 1500);

    if (pceReply->responseError)
    {
    	fprintf(stderr, "ERROR pcep_pcc sendPceReqMessageSync response error\n");
    }
    else if (pceReply->timedOut)
    {
    	fprintf(stderr, "ERROR pcep_pcc sendPceReqMessageSync response timed-out\n");
    }
    else
    {
    	printf("pcep_pcc sendPceReqMessageSync got a response, elapsed time [%d ms]\n",
    			pceReply->elapsedTimeMilliSeconds);
    }
}

void sendPceReqMessageAsync(PcepSession *session)
{
	PcepPceRequest *pceReq = malloc(sizeof(PcepPceRequest));
    bzero(pceReq, sizeof(PcepPceRequest));

    pceReq->endpointIpVersion = IPPROTO_IP;
    inet_pton(AF_INET, "192.168.1.33", &(pceReq->srcEndpointIp.srcV4EndpointIp));
    inet_pton(AF_INET, "172.100.8.56", &(pceReq->dstEndpointIp.dstV4EndpointIp));

    PcepPceReply *pceReply = requestPathComputationAsync(session, pceReq, 1500);

    bool retval;
    bool keepChecking = true;
    while (keepChecking)
    {
    	retval = getAsyncResult(pceReply);
        if (retval)
        {
        	printf("pcep_pcc sendPceReqMessageAsync got a response, elapsed time [%d ms]\n",
        			pceReply->elapsedTimeMilliSeconds);
            keepChecking = false;
        }
        else
        {
        	if (pceReply->responseError)
        	{
        		fprintf(stderr, "ERROR pcep_pcc sendPceReqMessageAsync response error\n");
        		keepChecking = false;
        	}
        	else if (pceReply->timedOut)
        	{
        		fprintf(stderr, "ERROR pcep_pcc sendPceReqMessageAsync response timed-out\n");
        		keepChecking = false;
        	}
            else
            {
                /* Sleep 250 milliseconds */
                struct timespec ts;
                ts.tv_sec = 0;
                ts.tv_nsec = 250 * 1000 * 1000;
            	nanosleep(&ts, &ts);
            	printf("pcep_pcc sendPceReqMessageAsync sleep while waiting for a response\n");
            }
        }
    }

    free(pceReq);
}


int main(int argc, char **argv)
{

	printf("[%ld-%ld] Starting pcc_pcep example client\n",
			time(NULL), pthread_self());

	/* Blocking call:
	 * if (!runSessionLogicWaitForCompletion()) */

	if (!initializePcc())
	{
		fprintf(stderr, "Error initializing PCC.\n");
		return -1;
	}

	struct hostent *hostInfo = gethostbyname("localhost");
    if(hostInfo == NULL) {
		fprintf(stderr, "Error getting IP address.\n");
        return -1;
    }

    struct in_addr hostAddress;
    memcpy(&hostAddress, hostInfo->h_addr, hostInfo->h_length);

    PcepConfiguration *config = createDefaultPcepConfiguration();
	PcepSession *session = connectPce(config, &hostAddress);
    if (session == NULL)
    {
		fprintf(stderr, "Error in createNbiPcepSession.\n");
        return -1;
    }

    sleep(5);

    sendPceReqMessageAsync(session);
    sendPceReqMessageSync(session);

    sleep(30);

    printf("Disconnecting from PCE\n");
    disconnectPce(session);

	if (!destroyPcc())
	{
		fprintf(stderr, "Error stopping PCC.\n");
	}

	return 0;
}

