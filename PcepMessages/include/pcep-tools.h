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

#include "utlist.h"
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

#define DL_COUNT(list, tmp, val) \
        val = 0;                 \
        DL_FOREACH(list, tmp) {  \
            val++;               \
        }

struct pcep_obj_list
{    
    struct pcep_object_header *header;
    
    struct pcep_obj_list *prev; 
    struct pcep_obj_list *next;
};

struct pcep_messages_list
{    
    struct pcep_header header;
    struct pcep_obj_list *list;
    
    struct pcep_messages_list *prev; 
    struct pcep_messages_list *next;
};

struct pcep_messages_list* pcep_msg_read    (int sock_fd);
struct pcep_messages_list* pcep_msg_get     (struct pcep_messages_list* list, uint8_t type);
struct pcep_messages_list* pcep_msg_get_next(struct pcep_messages_list* current, uint8_t type);
struct pcep_obj_list*      pcep_obj_get     (struct pcep_messages_list* list, uint8_t type);
struct pcep_obj_list*      pcep_obj_get_next(struct pcep_obj_list* current, uint8_t type);
void                       pcep_msg_free    (struct pcep_messages_list* list);
void                       pcep_msg_print   (struct pcep_messages_list* list);
int                        pcep_msg_send    (int sock_fd, struct pcep_header* hdr);

#ifdef __cplusplus
}
#endif

#endif