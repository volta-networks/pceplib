/*
 * pcep_utils_double_linked_list.c
 *
 *  Created on: Oct 18, 2019
 *      Author: brady
 */

#include <malloc.h>
#include <strings.h>

#include "pcep_utils_double_linked_list.h"

double_linked_list *dll_initialize()
{
    double_linked_list *handle = malloc(sizeof(double_linked_list));
    if (handle != NULL)
    {
        bzero(handle, sizeof(double_linked_list));
        handle->num_entries = 0;
        handle->head = NULL;
        handle->tail = NULL;
    }
    else
    {
        fprintf(stderr, "ERROR dll_initialize cannot allocate memory for handle\n");
        return NULL;
    }

    return handle;
}


void dll_destroy(double_linked_list *handle)
{
    if (handle == NULL)
    {
        fprintf(stderr, "ERROR dll_destroy cannot destroy NULL handle\n");
        return;
    }

    double_linked_list_node *node = handle->head;
    while(node != NULL)
    {
        double_linked_list_node *node_to_delete = node;
        node = node->next_node;
        free(node_to_delete);
    }

    free(handle);
}


/* Creates a node and adds it as the first item in the list */
double_linked_list_node *dll_prepend(double_linked_list *handle, void *data)
{
    if (handle == NULL)
    {
        fprintf(stderr, "ERROR dll_prepend_data NULL handle\n");
        return NULL;
    }

    /* Create the new node */
    double_linked_list_node *new_node = malloc(sizeof(double_linked_list_node));
    bzero(new_node, sizeof(double_linked_list_node));
    new_node->data = data;

    if (handle->head == NULL)
    {
        handle->head = new_node;
        handle->tail = new_node;
    }
    else
    {
        new_node->next_node = handle->head;
        handle->head->prev_node = new_node;
        handle->head = new_node;
    }

    (handle->num_entries)++;

    return new_node;
}


/* Creates a node and adds it as the last item in the list */
double_linked_list_node *dll_append(double_linked_list *handle, void *data)
{
    if (handle == NULL)
    {
        fprintf(stderr, "ERROR dll_append_data NULL handle\n");
        return NULL;
    }

    /* Create the new node */
    double_linked_list_node *new_node = malloc(sizeof(double_linked_list_node));
    bzero(new_node, sizeof(double_linked_list_node));
    new_node->data = data;

    if (handle->head == NULL)
    {
        handle->head = new_node;
        handle->tail = new_node;
    }
    else
    {
        new_node->prev_node = handle->tail;
        handle->tail->next_node = new_node;
        handle->tail = new_node;
    }

    (handle->num_entries)++;

    return new_node;
}


/* Delete the first node in the list, and return the data */
void *dll_delete_first_node(double_linked_list *handle)
{
    if (handle == NULL)
    {
        fprintf(stderr, "ERROR dll_delete_first_node NULL handle\n");
        return NULL;
    }

    if (handle->head == NULL)
    {
        return NULL;
    }

    double_linked_list_node *delete_node = handle->head;
    void *data = delete_node->data;

    if (delete_node->next_node == NULL)
    {
        /* Its the last node in the list */
        handle->head = NULL;
        handle->tail = NULL;
    }
    else
    {
        handle->head = delete_node->next_node;
        handle->head->prev_node = NULL;
    }

    free(delete_node);
    (handle->num_entries)--;

    return data;
}


/* Delete the last node in the list, and return the data */
void *dll_delete_last_node(double_linked_list *handle)
{
    if (handle == NULL)
    {
        fprintf(stderr, "ERROR dll_delete_last_node NULL handle\n");
        return NULL;
    }

    if (handle->head == NULL)
    {
        return NULL;
    }

    double_linked_list_node *delete_node = handle->tail;
    void *data = delete_node->data;

    if (delete_node->prev_node == NULL)
    {
        /* Its the last node in the list */
        handle->head = NULL;
        handle->tail = NULL;
    }
    else
    {
        handle->tail = delete_node->prev_node;
        handle->tail->next_node = NULL;
    }

    free(delete_node);
    (handle->num_entries)--;

    return data;
}


/* Delete the designated node in the list, and return the data */
void *dll_delete_node(double_linked_list *handle, double_linked_list_node *node)
{
    if (handle == NULL)
    {
        fprintf(stderr, "ERROR dll_delete_node NULL handle\n");
        return NULL;
    }

    if (node == NULL)
    {
        return NULL;
    }

    if (handle->head == NULL)
    {
        return NULL;
    }

    void *data = node->data;

    if (handle->head == handle->tail)
    {
        /* Its the last node in the list */
        handle->head = NULL;
        handle->tail = NULL;
    }
    else if (handle->head == node)
    {
        handle->head = node->next_node;
        handle->head->prev_node = NULL;
    }
    else if (handle->tail == node)
    {
        handle->tail = node->prev_node;
        handle->tail->next_node = NULL;
    }
    else
    {
        /* Its somewhere in the middle of the list */
        node->next_node->prev_node = node->prev_node;
        node->prev_node->next_node = node->next_node;
    }

    free(node);
    (handle->num_entries)--;

    return data;
}