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

#include "pcep_utils_double_linked_list.h"
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
    PCEP_TYPE_CLOSE = 7,
    PCEP_TYPE_REPORT = 10,
    PCEP_TYPE_UPDATE = 11,
    PCEP_TYPE_INITIATE = 12
};

/* PCEP Message Common Header, According to RFC 5440
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | Ver |  Flags  |  Message-Type |       Message-Length          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Ver (Version - 3 bits):  PCEP version number. Current version is version 1.
 *
 * Flags (5 bits):  No flags are currently defined. Unassigned bits are
 *    considered as reserved.  They MUST be set to zero on transmission
 *    and MUST be ignored on receipt.
 */

struct pcep_header
{
    uint8_t ver_flags;  // PCEP version, current version is 1.
    uint8_t type;       // Defines which type of message OPEN/KEEPALIVE/PCREQ/PCREP/PCNOTF/ERROR/CLOSE.
    uint16_t length;    // Total length of the PCEP message.
}__attribute__((packed));

/* A pcep message contains the entire PCEP message in contiguous memory.
 * A pcep_message->obj_list is a double_linked_list of struct pcep_object_header
 * pointers that point into the actual message, so these should not be deleted.
 * A pointer to a struct pcep_object_header will point to the PCEP message header
 * with the actual pcep objects just after the header. */
typedef struct pcep_message
{
    struct pcep_header *header;
    double_linked_list *obj_list;

} pcep_message;

/* Set the version to 001 and flags to 00000 */
#define PCEP_COMMON_HEADER_VER_FLAGS 0x20

struct pcep_message*  pcep_msg_create_open            (uint8_t keepalive, uint8_t deadtimer, uint8_t sid);
struct pcep_message*  pcep_msg_create_open_with_tlvs  (uint8_t keepalive, uint8_t deadtimer, uint8_t sid, double_linked_list *tlv_list);
struct pcep_message*  pcep_msg_create_request         (struct pcep_object_rp *rp,  struct pcep_object_endpoints_ipv4 *enpoints, struct pcep_object_bandwidth *bandwidth);
struct pcep_message*  pcep_msg_create_request_svec    (struct pcep_header **requests, uint16_t request_count, float disjointness);
struct pcep_message*  pcep_msg_create_reply_nopath    (struct pcep_object_rp *rp,  struct pcep_object_nopath *nopath);
struct pcep_message*  pcep_msg_create_reply           (struct pcep_object_rp *rp,  double_linked_list *object_list);
struct pcep_message*  pcep_msg_create_close           (uint8_t flags, uint8_t reason);
struct pcep_message*  pcep_msg_create_error           (uint8_t error_type, uint8_t error_value);
struct pcep_message*  pcep_msg_create_keepalive       ();

/* Message defined in RFC 8231 section 6.1. Expecting double_linked_list of
 * struct pcep_object_header* objects of type SRP, LSP, or path (ERO, Bandwidth,
 * metrics, and RRO objects). */
struct pcep_message*  pcep_msg_create_report          (double_linked_list *state_report_object_list);
/* Message defined in RFC 8231. Expecting double_linked_list of at least 3
 * struct pcep_object_header* objects of type SRP, LSP, and path (ERO and
 * intended-attribute-list). The ERO must be present, but may be empty if
 * the PCE cannot find a valid path for a delegated LSP. */
struct pcep_message*  pcep_msg_create_update          (double_linked_list *update_request_object_list);
/* Message defined in RFC 8281. Expecting double_linked_list of at least 2
 * struct pcep_object_header* objects of type SRP and LSP for LSP deletion, and
 * may also contain Endpoints, ERO and an attribute list for LSP creation. */
struct pcep_message*  pcep_msg_create_initiate        (double_linked_list *lsp_object_list);

void pcep_unpack_msg_header(struct pcep_header* hdr);

#ifdef __cplusplus
}
#endif

#endif
