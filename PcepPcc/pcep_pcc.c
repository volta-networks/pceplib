
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "PcepSessionLogic.h"

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

/* TODO temporary functions to create a session and send a message */
extern PcepSession *createNbiPcepSession(const char *host, int port);
const char *message = "Hello World!\n";

int main(int argc, char **argv)
{

	printf("[%ld] Starting pcc_pcep example client\n", time(NULL));
	fflush(stdout);

	/* Blocking call:
	 * if (!runSessionLogicWaitForCompletion()) */

	if (!runSessionLogic())
	{
		fprintf(stderr, "Error initializing PCEP Session logic.\n");
		return -1;
	}

    char *host = "localhost";
	PcepSession *session = createNbiPcepSession(host, 4189);
    if (session == NULL)
    {
		fprintf(stderr, "Error in createNbiPcepSession.\n");
        return -1;
    }

    sleep(60);

	if (!stopSessionLogic())
	{
		fprintf(stderr, "Error stopping PCEP Session Logic.\n");
	}

	return 0;
}

