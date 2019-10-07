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

#ifndef PCEP_MESSAGES_H
#define PCEP_MESSAGES_H

#include <stdint.h>
#include <netinet/in.h> // struct in_addr

#include "pcep-objects.h"

#ifdef __cplusplus
extern "C" {
#endif

enum pcep_types
{
    PCEP_TYPE_OPEN = 1,   
    PCEP_TYPE_KEEPALIVE = 2, 
    PCEP_TYPE_PCREQ = 3,
    PCEP_TYPE_PCREP = 4,
    PCEP_TYPE_PCNOTF = 5,
    PCEP_TYPE_ERROR = 6, 
    PCEP_TYPE_CLOSE = 7
}; 

struct pcep_header
{
    uint8_t ver_flags;  // PCEP version, current version is 1.
    uint8_t type;       // Defines which type of message OPEN/KEEPALIVE/PCREQ/PCREP/PCNOTF/ERROR/CLOSE.
    uint16_t length;    //Total length of the PCEP message.
}__attribute__((packed));

struct pcep_header*     pcep_msg_create_open            (uint8_t keepalive, uint8_t deadtimer, uint8_t sid);
struct pcep_header*     pcep_msg_create_request         (struct pcep_object_rp *rp,  struct pcep_object_endpoints_ipv4 *enpoints, struct pcep_object_bandwidth *bandwidth);
struct pcep_header*     pcep_msg_create_request_svec    (struct pcep_header **requests, uint16_t request_count, float disjointness);
struct pcep_header*     pcep_msg_create_response_nopath (struct pcep_object_rp *rp,  struct pcep_object_nopath *nopath);
struct pcep_header*     pcep_msg_create_response        (struct pcep_object_rp *rp,  struct pcep_object_eros_list *eros);
struct pcep_header*     pcep_msg_create_close           (uint8_t flags, uint8_t reason);
struct pcep_header*     pcep_msg_create_error           (uint8_t error_type, uint8_t error_value);
struct pcep_header*     pcep_msg_create_keepalive       ();

void pcep_unpack_msg_header(struct pcep_header* hdr);

#ifdef __cplusplus
}
#endif

#endif
