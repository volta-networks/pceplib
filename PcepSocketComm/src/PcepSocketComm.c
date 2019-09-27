/*
 * PcepSocketComm.c
 *
 *  Created on: Sep 17, 2019
 *      Author: brady
 *
 *  Implementation of public API functions.
 */


#include <malloc.h>
#include <netdb.h> // gethostbyname
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>  // close

#include <arpa/inet.h>  // sockets etc.
#include <sys/types.h>  // sockets etc.
#include <sys/socket.h> // sockets etc.

#include "PcepSocketComm.h"
#include "PcepSocketCommInternals.h"
#include "PcepUtilsOrderedList.h"
#include "PcepUtilsQueue.h"


PcepSocketCommHandle *socketCommHandle_ = NULL;


/* Simple compare method callback used by PcepUtilsOrderedList
 * for ordered list insertion. */
int socketFdNodeCompare(void *listEntry, void *newEntry)
{
	return ((PcepSocketCommSession *) newEntry)->socketFd - ((PcepSocketCommSession *) listEntry)->socketFd;
}


bool initializeSocketCommLoop()
{
	if (socketCommHandle_ != NULL)
	{
		/* Already initialized */
		return true;
	}

	socketCommHandle_ = malloc(sizeof(PcepSocketCommHandle));
	bzero(socketCommHandle_, sizeof(PcepSocketCommHandle));

	socketCommHandle_->active = true;
	socketCommHandle_->readList = orderedListInitialize(socketFdNodeCompare);
	socketCommHandle_->writeList = orderedListInitialize(socketFdNodeCompare);

	if (pthread_mutex_init(&(socketCommHandle_->socketCommMutex), NULL) != 0)
	{
		fprintf(stderr, "ERROR: Cannot initialize socketComm Mutex.\n");
		return false;
	}

	if(pthread_create(&(socketCommHandle_->socketCommThread), NULL, socketCommLoop, socketCommHandle_))
	{
		fprintf(stderr, "ERROR: Cannot initialize socketComm Thread.\n");
		return false;
	}

	return true;
}


PcepSocketCommSession *
socketCommSessionInitialize(messageReceivedHandler messageHandler,
		                    messageReadyToReadHandler messageReadyHandler,
		                    connectionExceptNotifier notifier,
							const char* host,
							void *sessionData)
{
	return socketCommSessionInitializeWithPort(
			messageHandler, messageReadyHandler, notifier, host, PCEP_PORT, sessionData);
}


PcepSocketCommSession *
socketCommSessionInitializeWithPort(messageReceivedHandler messageHandler,
		                            messageReadyToReadHandler messageReadyHandler,
		                            connectionExceptNotifier notifier,
									const char* host,
									int port,
									void *sessionData)
{
    /* Check that not both message handlers were set */
    if (messageHandler != NULL && messageReadyHandler != NULL)
    {
    	fprintf(stderr, "Only one of <messageReceivedHandler | messageReadyToReadHandler> can be set.\n");
    }

    /* Check that at least one message handler was set */
    if (messageHandler == NULL && messageReadyHandler == NULL)
    {
    	fprintf(stderr, "At least one of <messageReceivedHandler | messageReadyToReadHandler> must be set.\n");
    }

	if (!initializeSocketCommLoop())
	{
		fprintf(stderr, "ERROR: Cannot initialize socketCommLoop.\n");

		return NULL;
	}

	/* Initialize everything for a PcepSession SocketComm */

	PcepSocketCommSession *socketCommSession = malloc(sizeof(PcepSocketCommSession));
	bzero(socketCommSession, sizeof(PcepSocketCommSession));

	socketCommSession->socketFd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (socketCommSession->socketFd == -1) {
		fprintf(stderr, "ERROR: Cannot create socket.\n");
		socketCommSessionTeardown(socketCommSession);

		return NULL;
	}

	/* TODO make sure this is IPv6 compliant */
	struct hostent *hostInfo = gethostbyname(host);
    if(hostInfo == NULL) {
        fprintf(stderr, "ERROR: Failed to find address from host.\n");
        socketCommSessionTeardown(socketCommSession);

        return NULL;
    }

    socketCommSession->closeAfterWrite = false;
    socketCommSession->sessionData = sessionData;
	socketCommSession->messageHandler = messageHandler;
	socketCommSession->messageReadyToReadHandler = messageReadyHandler;
	socketCommSession->connExceptNotifier = notifier;
	socketCommSession->messageQueue = queueInitialize();
    socketCommSession->destSockAddr.sin_family = AF_INET;
    socketCommSession->destSockAddr.sin_port = htons(port);
    memcpy(&(socketCommSession->destSockAddr.sin_addr), hostInfo->h_addr, hostInfo->h_length);

    /* Dont connect to the destination yet, since the PCE will have a timer
     * for max time between TCP connect and PCEP open. We'll connect later
     * when we send the PCEP Open. */

	return socketCommSession;
}


bool socketCommSessionConnectTcp(PcepSocketCommSession *socketCommSession)
{
    int retval = connect(socketCommSession->socketFd,
    		             (struct sockaddr *) &(socketCommSession->destSockAddr),
						 sizeof(struct sockaddr));

    if (retval == -1) {
        fprintf(stderr, "ERROR: TCP Connect failed on socketFd [%d].\n",
        		socketCommSession->socketFd);
        socketCommSessionTeardown(socketCommSession);

        return false;
    }

	pthread_mutex_lock(&(socketCommHandle_->socketCommMutex));
    /* Once the TCP connection is open, we should be ready to read at any time */
	orderedListAddNode(socketCommHandle_->readList, socketCommSession);
	pthread_mutex_unlock(&(socketCommHandle_->socketCommMutex));

    return true;
}


bool socketCommSessionCloseTcp(PcepSocketCommSession *socketCommSession)
{
	pthread_mutex_lock(&(socketCommHandle_->socketCommMutex));
	orderedListRemoveFirstNodeEquals(socketCommHandle_->readList, socketCommSession);
	orderedListRemoveFirstNodeEquals(socketCommHandle_->writeList, socketCommSession);
	// TODO should it be close() or shutdown()??
	close(socketCommSession->socketFd);
	pthread_mutex_unlock(&(socketCommHandle_->socketCommMutex));

	return true;
}

bool socketCommSessionCloseTcpAfterWrite(PcepSocketCommSession *socketCommSession)
{
	pthread_mutex_lock(&(socketCommHandle_->socketCommMutex));
    socketCommSession->closeAfterWrite = true;
	pthread_mutex_unlock(&(socketCommHandle_->socketCommMutex));

	return true;
}

bool socketCommSessionTeardown(PcepSocketCommSession *socketCommSession)
{
	/* TODO when should we teardown the socketCommHandle_ ??
	 *      Should we keep a PcepSocketCommSession ref counter and free it when
	 *      the ref count reaches 0? */

	if (socketCommSession->socketFd > 0)
	{
		shutdown(socketCommSession->socketFd, SHUT_RDWR);
		close(socketCommSession->socketFd);
	}

	pthread_mutex_lock(&(socketCommHandle_->socketCommMutex));
	orderedListRemoveFirstNodeEquals(socketCommHandle_->readList, socketCommSession);
	orderedListRemoveFirstNodeEquals(socketCommHandle_->writeList, socketCommSession);
	pthread_mutex_unlock(&(socketCommHandle_->socketCommMutex));

	free(socketCommSession);

	return false;
}


void socketCommSessionSendMessage(PcepSocketCommSession *socketCommSession, const char *message, unsigned int msgLength)
{
	PcepSocketCommQueuedMessage *queuedMessage = malloc(sizeof(PcepSocketCommQueuedMessage));
	queuedMessage->unmarshalledMessage = message;
	queuedMessage->msgLength = msgLength;

	pthread_mutex_lock(&(socketCommHandle_->socketCommMutex));
	queueEnqueue(socketCommSession->messageQueue, queuedMessage);
	orderedListAddNode(socketCommHandle_->writeList, socketCommSession);
	pthread_mutex_unlock(&(socketCommHandle_->socketCommMutex));
}
