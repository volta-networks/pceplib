/*
 * This file is part of the libpcep, a PCEP library.
 *
 * Copyright (C) 2011 Acreo AB http://www.acreo.se
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author : Viktor Nordell <viktor.nordell@acreo.se>
 */

#ifndef PCEP_TOOLS_H
#define PCEP_TOOLS_H

#include <stdint.h>
#include <netinet/in.h> // struct in_addr

#include "pcep_utils_double_linked_list.h"
#include "pcep-messages.h"
#include "pcep-objects.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PCEP_MAX_SIZE 6000

#ifndef MAX
    #define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#ifndef MIN
    #define MIN(a, b) (((a) > (b)) ? (b) : (a))
#endif

/*
 * A list of pcep messages is a double_linked_list of pcep_message items.
 * A pcep_message->obj_list is a double_linked_list of struct pcep_object_header
 * headers.
 * A pointer to a struct pcep_object_header will point to the header with the actual
 * pcep object just after the header.
 */

typedef struct pcep_message
{
    struct pcep_header header;
    double_linked_list *obj_list;

} pcep_message;


/* Returns a double linked list of PCEP messages */
double_linked_list*          pcep_msg_read    (int sock_fd);
/* Given a double linked list of PCEP messages, return the first node that has the same message type */
pcep_message*                pcep_msg_get     (double_linked_list* msg_list, uint8_t type);
/* Given a double linked list of PCEP messages, return the next node after current node that has the same message type */
pcep_message*                pcep_msg_get_next(double_linked_list *msg_list, pcep_message* current, uint8_t type);
struct pcep_object_header*   pcep_obj_get     (double_linked_list* list, uint8_t type);
struct pcep_object_header*   pcep_obj_get_next(double_linked_list *list, struct pcep_object_header* current, uint8_t type);
void                         pcep_msg_free    (double_linked_list* list);
void                         pcep_msg_print   (double_linked_list* list);
int                          pcep_msg_send    (int sock_fd, struct pcep_header* hdr);

#ifdef __cplusplus
}
#endif

#endif
