/*
 * PcepSocketComm.h
 *
 *  Created on: Sep 17, 2019
 *      Author: brady
 */

#ifndef INCLUDE_PCEPSOCKETCOMM_H_
#define INCLUDE_PCEPSOCKETCOMM_H_

#include <arpa/inet.h>  // sockaddr_in

#include "PcepUtilsQueue.h"

#define MAX_RECVD_MSG_SIZE 2048

/*
 * A socketCommSession can be initialized with 1 of 2 types of mutually exclusive
 * message callbacks:
 * - messageReceivedHandler : The SocketComm library reads the message and calls
 *                            the callback with the messageData and messageLength.
 *                            This callback should be used for smaller/simpler messages.
 * - messageReadyToReadHandler : The SocketComm library will call this callback
 *                               when a message is ready to be read on a socketFd.
 *                               This callback should be used if the
 */

/* Message Received Handler that receives the message data and message length */
typedef void (*messageReceivedHandler)(void *sessionData, char *messageData, unsigned int messageLength);
/* Message Ready Received Handler that should read the message on socketFd
 * and return the number of bytes read */
typedef int (*messageReadyToReadHandler)(void *sessionData, int socketFd);
/* Callback handler called when the socket is closed */
typedef void (*connectionExceptNotifier)(void *sessionData, int socketFd);

typedef struct PcepSocketCommSession_
{
	messageReceivedHandler messageHandler;
	messageReadyToReadHandler messageReadyToReadHandler;
	connectionExceptNotifier connExceptNotifier;
	struct sockaddr_in destSockAddr;
	int socketFd;
	void *sessionData;
	QueueHandle *messageQueue;
	char receivedMessage[MAX_RECVD_MSG_SIZE];
	int receivedBytes;
    bool closeAfterWrite;

} PcepSocketCommSession;


/* Need to document that when the msgRcvHandler is called, the data needs
 * to be handled in the same function call, else it may be overwritten by
 * the next read from this socket */

/* The msgRcvHandler and msgReadyHandler are mutually exclusive, and only
 * one can be set (as explained above), else NULL will be returned. */
PcepSocketCommSession *
socketCommSessionInitialize(messageReceivedHandler msgRcvHandler,
		                    messageReadyToReadHandler msgReadyHandler,
		                    connectionExceptNotifier notifier,
							struct in_addr *hostIp,
							short port,
							void *sessionData);

bool socketCommSessionTeardown(PcepSocketCommSession *socketCommSession);

bool socketCommSessionConnectTcp(PcepSocketCommSession *socketCommSession);

/* Immediately close the TCP connection, irregardless if there are pending
 * messages to be sent. */
bool socketCommSessionCloseTcp(PcepSocketCommSession *socketCommSession);

/* Sets a flag to close the TCP connection either after all the pending messages
 * are written, or if there are no pending messages, the next time the socket is
 * checked to be writeable. */
bool socketCommSessionCloseTcpAfterWrite(PcepSocketCommSession *socketCommSession);

void socketCommSessionSendMessage(PcepSocketCommSession *socketCommSession,
		                          const char *unmarshalledMessage,
								  unsigned int msgLength);


#endif /* INCLUDE_PCEPSOCKETCOMM_H_ */
