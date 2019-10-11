/*
 * pcep_utils_queue.c
 *
 *  Created on: Sep 19, 2019
 *      Author: brady
 */

#include <malloc.h>
#include <stdbool.h>
#include <stdio.h>
#include <strings.h>

#include "pcep_utils_queue.h"

queue_handle *queue_initialize()
{
    /* Set the max_entries to 0 to disable it */
    return queue_initialize_with_size(0);
}


queue_handle *queue_initialize_with_size(unsigned int max_entries)
{
    queue_handle *handle = malloc(sizeof(queue_handle));
    bzero(handle, sizeof(queue_handle));
    handle->max_entries = max_entries;

    return handle;
}


void queue_destroy(queue_handle *handle)
{
    while (queue_dequeue(handle) != NULL) {}
    free(handle);
}


queue_node *queue_enqueue(queue_handle *handle, void *data)
{
    if (handle == NULL)
    {
        fprintf(stderr, "ERROR queue_enqueue, the queue has not been initialized\n");
        return NULL;
    }

    if (handle->max_entries > 0 && handle->num_entries >= handle->max_entries)
    {
        fprintf(stderr, "WARN queue_enqueue, cannot enqueue: max entries hit [%u]\n",
                handle->num_entries);
        return NULL;
    }

    queue_node *new_node = malloc(sizeof(queue_node));
    new_node->data = data;
    new_node->next_node = NULL;

    (handle->num_entries)++;
    if (handle->head == NULL)
    {
        /* its the first entry in the queue */
        handle->head = handle->tail = new_node;
    }
    else
    {
        handle->tail->next_node = new_node;
        handle->tail = new_node;

    }

    return new_node;
}


void *queue_dequeue(queue_handle *handle)
{
    if (handle == NULL)
    {
        fprintf(stderr, "ERROR queue_dequeue, the queue has not been initialized\n");
        return NULL;
    }

    if (handle->head == NULL)
    {
        //printf("DEBUG queue_dequeue, the queue is empty\n");
        return NULL;
    }

    void *node_data = handle->head->data;
    queue_node *node = handle->head;
    (handle->num_entries)--;
    if (handle->head == handle->tail)
    {
        /* its the last entry in the queue */
        handle->head = handle->tail = NULL;
    }
    else
    {
        handle->head = node->next_node;
    }

    free(node);

    return node_data;
}
