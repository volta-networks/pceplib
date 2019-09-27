/*
 * PcepSocketCommLoop.c
 *
 *  Created on: Sep 17, 2019
 *      Author: brady
 */

#include <errno.h>
#include <malloc.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "PcepSocketCommInternals.h"
#include "PcepUtilsOrderedList.h"


void writeMessage(int socketFd, const char *message, unsigned int msgLength)
{
	unsigned int bytesSent = 0;
	unsigned int totalBytesSent = 0;

	while (bytesSent < msgLength)
	{
		bytesSent = write(socketFd, message + totalBytesSent, msgLength);

        printf("[%ld] SocketComm writing on socket [%d] msgLenth [%d] bytes sent [%d]\n",
        		time(NULL), socketFd, msgLength, bytesSent);

		if (bytesSent < 0)
		{
		      if (errno != EAGAIN && errno != EWOULDBLOCK)
		      {
		        perror("send() failure");

		        return;
		      }
		}
		else
		{
			totalBytesSent += bytesSent;
		}
	}
}


unsigned int readMessage(int socketFd, char *receivedMessage, unsigned int maxMessageSize)
{

    /* TODO what if bytesRead == maxMessageSize? there could be more to read */
	unsigned int bytesRead = read(socketFd, receivedMessage, maxMessageSize);
	printf("[%ld] SocketComm read message bytesRead [%d] on socket [%d]\n",
			time(NULL), bytesRead, socketFd);

	return bytesRead;
}


int buildFdSets(PcepSocketCommHandle *socketCommHandle)
{
	int maxFd = 0;

	pthread_mutex_lock(&(socketCommHandle->socketCommMutex));

	FD_ZERO(&socketCommHandle->exceptMasterSet);
	FD_ZERO(&socketCommHandle->readMasterSet);
	OrderedListNode *node = socketCommHandle->readList->head;
	PcepSocketCommSession *commSession;
	while (node != NULL)
	{
		commSession = (PcepSocketCommSession *) node->data;
		if (commSession->socketFd > maxFd)
		{
			maxFd = commSession->socketFd;
		}

		/*printf("[%ld] SocketComm::buildFdSets set readyToRead [%d]\n",
				time(NULL), commSession->socketFd);*/
		FD_SET(commSession->socketFd, &socketCommHandle->readMasterSet);
		FD_SET(commSession->socketFd, &socketCommHandle->exceptMasterSet);
		node = node->nextNode;
	}

	FD_ZERO(&socketCommHandle->writeMasterSet);
	node = socketCommHandle->writeList->head;
	while (node != NULL)
	{
		commSession = (PcepSocketCommSession *) node->data;
		if (commSession->socketFd > maxFd)
		{
			maxFd = commSession->socketFd;
		}

		/*printf("[%ld] SocketComm::buildFdSets set readyToWrite [%d]\n",
				time(NULL), commSession->socketFd);*/
		FD_SET(commSession->socketFd, &socketCommHandle->writeMasterSet);
		FD_SET(commSession->socketFd, &socketCommHandle->exceptMasterSet);
		node = node->nextNode;
	}

	pthread_mutex_unlock(&(socketCommHandle->socketCommMutex));

	return maxFd + 1;
}


void handleReads(PcepSocketCommHandle *socketCommHandle)
{
	pthread_mutex_lock(&(socketCommHandle->socketCommMutex));

	/*
	 * Iterate all the socketFd's in the readList. It may be that not
	 * all of them have something to read. Dont remove the socketFd
	 * from the readList since messages could come at any time.
	 */

	OrderedListNode *node = socketCommHandle->readList->head;
	PcepSocketCommSession *commSession;
	while (node != NULL)
	{
		commSession = (PcepSocketCommSession *) node->data;
		node = node->nextNode;
		if (FD_ISSET(commSession->socketFd, &(socketCommHandle->readMasterSet)))
		{
            /* Either read the message locally, or call the messageReadyHandler to read it */
			if (commSession->messageHandler != NULL)
			{
				commSession->receivedBytes =
						readMessage(
								commSession->socketFd,
								commSession->receivedMessage,
								MAX_RECVD_MSG_SIZE);
				if (commSession->receivedBytes > 0)
				{
					/* Send the received message to the handler */
					commSession->messageHandler(
                			commSession->sessionData,
							commSession->receivedMessage,
							commSession->receivedBytes);
				}
			}
			else
			{
                /* Tell the handler a message is ready to be read */
                commSession->receivedBytes =
                		commSession->messageReadyToReadHandler(
                				commSession->sessionData,
								commSession->socketFd);
			}

            /* Handle the read results */
			if (commSession->receivedBytes == 0)
			{
                /* The socket was closed */
                /* TODO should we define a socket except enum? Or will the only
                 *      time we call this is when the socket is closed?? */
                if (commSession->connExceptNotifier != NULL)
                {
                	commSession->connExceptNotifier(
                			commSession->sessionData,
							commSession->socketFd);
                }

                /* Stop reading from the socket if its closed */
				orderedListRemoveFirstNodeEquals(socketCommHandle->readList, commSession);
			}
			else if (commSession->receivedBytes < 0)
			{
                /* TODO should we call connExceptNotifier() here ? */
                fprintf(stderr, "Error on socket [%d] : [%d][%s]\n",
                		commSession->socketFd, errno, strerror(errno));
			}
		}
	}

	pthread_mutex_unlock(&(socketCommHandle->socketCommMutex));
}


void handleWrites(PcepSocketCommHandle *socketCommHandle)
{
	pthread_mutex_lock(&(socketCommHandle->socketCommMutex));

	/*
	 * Iterate all the socketFd's in the WriteList. It may be that not
	 * all of them are ready to be written to. Only remove the socketFd
	 * from the list if it is ready to be written to.
	 */

	OrderedListNode *node = socketCommHandle->writeList->head;
	PcepSocketCommSession *commSession;
	while (node != NULL)
	{
		commSession = (PcepSocketCommSession *) node->data;
		node = node->nextNode;

		if (FD_ISSET(commSession->socketFd, &(socketCommHandle->writeMasterSet))) {
            /* Only remove the entry from the list, if it is written to */
			orderedListRemoveFirstNodeEquals(socketCommHandle->writeList, commSession);

			/* dequeue all the commSession messages and send them */
			PcepSocketCommQueuedMessage *queuedMessage = queueDequeue(commSession->messageQueue);
			while (queuedMessage != NULL)
			{
				writeMessage(
						commSession->socketFd,
						queuedMessage->unmarshalledMessage,
						queuedMessage->msgLength);
				free(queuedMessage);
				queuedMessage = queueDequeue(commSession->messageQueue);
			}
		}

        /* Check if the socket should be closed after writing */
        if (commSession->closeAfterWrite == true)
        {
        	if (commSession->messageQueue->numEntries == 0)
        	{
                /* TODO check to make sure modifying the writeList while
                 *      iterating it doesnt cause problems. */
        		orderedListRemoveFirstNodeEquals(socketCommHandle->readList, commSession);
        		orderedListRemoveFirstNodeEquals(socketCommHandle->writeList, commSession);
        		close(commSession->socketFd);
        	}
        }

	}

	pthread_mutex_unlock(&(socketCommHandle->socketCommMutex));
}


void handleExcepts(PcepSocketCommHandle *socketCommHandle)
{
	/* TODO finish this */
}


/* PcepSocketComm::initializeSocketCommLoop() will create a thread and invoke this method */
void *socketCommLoop(void *data)
{
	if (data == NULL)
	{
		fprintf(stderr, "Cannot start socketCommLoop with NULL PcepSocketcommHandle");
		return NULL;
	}

    printf("[%ld-%ld] Starting SocketCommLoop thread\n", time(NULL), pthread_self());

	PcepSocketCommHandle *socketCommHandle = (PcepSocketCommHandle *) data;
	struct timeval timer;
	int maxFd;

	while (socketCommHandle->active)
	{
		timer.tv_sec = 1;
		timer.tv_usec = 0;
		maxFd = buildFdSets(socketCommHandle);

		if (select(maxFd,
				&(socketCommHandle->readMasterSet),
				&(socketCommHandle->writeMasterSet),
				&(socketCommHandle->exceptMasterSet),
				&timer) < 0)
		{
			/* TODO handle the error */
            fprintf(stderr, "ERROR socketCommLoop on select\n");
		}

		handleReads(socketCommHandle);
		handleWrites(socketCommHandle);
		handleExcepts(socketCommHandle);
	}

	return NULL;
}
