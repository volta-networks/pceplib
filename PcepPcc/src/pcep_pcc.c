
#include <netdb.h> // gethostbyname
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


void sendPceReqMessage(PcepSession *session)
{
	PcepPceReq *pceReq = malloc(sizeof(PcepPceReq));
    bzero(pceReq, sizeof(PcepPceReq));

	int requestId = requestPathComputationAsync(session, pceReq);
	getAsyncResult(session, requestId);
}


int main(int argc, char **argv)
{

	printf("[%ld] Starting pcc_pcep example client\n", time(NULL));
	fflush(stdout);

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

    sendPceReqMessage(session);

    sleep(60);

    printf("Disconnecting from PCE\n");
    disconnectPce(session);

	if (!destroyPcc())
	{
		fprintf(stderr, "Error stopping PCC.\n");
	}

	return 0;
}

