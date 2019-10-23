/*
 * pcep_utils_double_linked_list.h
 *
 *  Created on: Oct 18, 2019
 *      Author: brady
 */

#ifndef PCEP_UTILS_INCLUDE_PCEP_UTILS_DOUBLE_LINKED_LIST_H_
#define PCEP_UTILS_INCLUDE_PCEP_UTILS_DOUBLE_LINKED_LIST_H_

typedef struct double_linked_list_node_
{
    struct double_linked_list_node_ *prev_node;
    struct double_linked_list_node_ *next_node;
    void *data;

} double_linked_list_node;


typedef struct double_linked_list_
{
    double_linked_list_node *head;
    double_linked_list_node *tail;
    unsigned int num_entries;

} double_linked_list;


/* Initialize a double linked list */
double_linked_list *dll_initialize();

/* Destroy a double linked list, by freeing the handle and nodes,
 * user data will not be freed, and may be leaked if not handled
 * externally. */
void dll_destroy(double_linked_list *handle);

/* Creates a node and adds it as the first item in the list */
double_linked_list_node *dll_prepend(double_linked_list *handle, void *data);

/* Creates a node and adds it as the last item in the list */
double_linked_list_node *dll_append(double_linked_list *handle, void *data);

/* Delete the first node in the list, and return the data */
void *dll_delete_first_node(double_linked_list *handle);

/* Delete the last node in the list, and return the data */
void *dll_delete_last_node(double_linked_list *handle);

/* Delete the designated node in the list, and return the data */
void *dll_delete_node(double_linked_list *handle, double_linked_list_node *node);

#endif /* PCEP_UTILS_INCLUDE_PCEP_UTILS_DOUBLE_LINKED_LIST_H_ */