/*
 * PcepUtilsOrderedList.h
 *
 *  Created on: Sep 18, 2019
 *      Author: brady
 */

#ifndef INCLUDE_PCEPUTILSORDEREDLIST_H_
#define INCLUDE_PCEPUTILSORDEREDLIST_H_

#include <stdbool.h>

typedef struct OrderedListNode_
{
	struct OrderedListNode_ *nextNode;
	void *data;

} OrderedListNode;

/* The implementation of this function will receive a pointer to the
 * new data to be inserted and a pointer to the listEntry, and should
 * return:
 *   < 0  if newEntry  < listEntry
 *   == 0 if newEntry == listEntry (newEntry will be inserted after listEntry)
 *   > 0  if newEntry  > listEntry
 */
typedef int (*orderedCompareFunction)(void *listEntry, void *newEntry);

typedef struct OrderedListHandle_
{
	OrderedListNode *head;
	unsigned int numEntries;
	orderedCompareFunction compareFunction;

} OrderedListHandle;

OrderedListHandle *orderedListInitialize(orderedCompareFunction funcPtr);
void orderedListDestroy(OrderedListHandle *handle);

/* Add a new OrderedListNode to the list, using the orderedCompareFunction
 * to determine where in the list to add it. The newly created OrderedListNode
 * will be returned.
 */
OrderedListNode *orderedListAddNode(OrderedListHandle *handle, void *data);

/* Find an entry in the OrderedList using the orderedCompareFunction to
 * compare the data passed in.
 * Return the Node if found, NULL otherwise.
 */
OrderedListNode *orderedListFind(OrderedListHandle *handle, void *data);

/* Remove the first entry in the list and return the data it points to.
 * Will return NULL if the handle is NULL or if the list is empty.
 */
void *orderedListRemoveFirstNode(OrderedListHandle *handle);

/* Remove the first entry in the list that has the same data, using the
 * orderedCompareFunction, and return the data it points to.
 * Will return NULL if the handle is NULL or if the list is empty or
 * if no entry is found that equals data.
 */
void *orderedListRemoveFirstNodeEquals(OrderedListHandle *handle, void *data);

/* The same as the previous function, but with a specific orderedComparefunction */
void *orderedListRemoveFirstNodeEquals2(OrderedListHandle *handle, void *data, orderedCompareFunction funcPtr);

/* Remove the node "nodeToRemove" and adjust the "prevNode" pointers accordingly,
 * returning the data pointed to by "nodeToRemove".
 * Will return NULL if the handle is NULL or if the list is empty.
 */
void *orderedListRemoveNode(OrderedListHandle *handle, OrderedListNode *prevNode, OrderedListNode *nodeToRemove);

#endif /* INCLUDE_PCEPUTILSORDEREDLIST_H_ */
