/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
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
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */


/*
 * Encoding and decoding for PCEP messages.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pcep-encoding.h"
#include "pcep-messages.h"
#include "pcep-objects.h"
#include "pcep-tools.h"
#include "pcep_utils_logging.h"

#define ANY_OBJECT 0
#define NO_OBJECT -1
#define NUM_CHECKED_OBJECTS 4
/* It wont compile with this definition:
   static const int MANDATORY_MESSAGE_OBJECT_CLASSES[PCEP_TYPE_INITIATE+1][NUM_CHECKED_OBJECTS] */
static const int MANDATORY_MESSAGE_OBJECT_CLASSES[13][4] = {
    {NO_OBJECT, NO_OBJECT, NO_OBJECT, NO_OBJECT},                          /* unsupported message ID = 0 */
    {PCEP_OBJ_CLASS_OPEN, NO_OBJECT, NO_OBJECT, NO_OBJECT},                /* PCEP_TYPE_OPEN = 1 */
    {NO_OBJECT, NO_OBJECT, NO_OBJECT, NO_OBJECT},                          /* PCEP_TYPE_KEEPALIVE = 2 */
    {PCEP_OBJ_CLASS_RP, PCEP_OBJ_CLASS_ENDPOINTS, ANY_OBJECT, ANY_OBJECT}, /* PCEP_TYPE_PCREQ = 3 */
    {PCEP_OBJ_CLASS_RP, ANY_OBJECT, ANY_OBJECT, ANY_OBJECT},               /* PCEP_TYPE_PCREP = 4 */
    {PCEP_OBJ_CLASS_NOTF, ANY_OBJECT, ANY_OBJECT, ANY_OBJECT},             /* PCEP_TYPE_PCNOTF = 5 */
    {PCEP_OBJ_CLASS_ERROR, ANY_OBJECT, ANY_OBJECT, ANY_OBJECT},            /* PCEP_TYPE_ERROR = 6 */
    {PCEP_OBJ_CLASS_CLOSE, NO_OBJECT, NO_OBJECT, NO_OBJECT},               /* PCEP_TYPE_CLOSE = 7 */
    {NO_OBJECT, NO_OBJECT, NO_OBJECT, NO_OBJECT},                          /* unsupported message ID = 8 */
    {NO_OBJECT, NO_OBJECT, NO_OBJECT, NO_OBJECT},                          /* unsupported message ID = 9 */
    {PCEP_OBJ_CLASS_SRP, PCEP_OBJ_CLASS_LSP, ANY_OBJECT, ANY_OBJECT},      /* PCEP_TYPE_REPORT = 10 */
    {PCEP_OBJ_CLASS_SRP, PCEP_OBJ_CLASS_LSP, ANY_OBJECT, ANY_OBJECT},      /* PCEP_TYPE_UPDATE = 11 */
    {PCEP_OBJ_CLASS_SRP, PCEP_OBJ_CLASS_LSP, ANY_OBJECT, ANY_OBJECT},      /* PCEP_TYPE_INITIATE = 12 */
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
void pcep_encode_message(struct pcep_message *message, struct pcep_versioning *versioning)
{
    if (message == NULL)
    {
        return;
    }

    if (message->msg_header == NULL)
    {
        return;
    }

    /* Internal buffer used for the entire message. Later, once the entire length
     * is known, memory will be allocated and this buffer will be copied. */
    uint8_t message_buffer[1024];
    memset(message_buffer, 0, 1024);

    /* Write the message header. The message header length will be
     * written when the entire length is known. */
    uint16_t message_length = MESSAGE_HEADER_LENGTH;
    message_buffer[0] = (message->msg_header->pcep_version << 5) & 0xf0;
    message_buffer[1] = message->msg_header->type;
    uint16_t *length_ptr = (uint16_t *) (message_buffer + 2);

    if (message->obj_list == NULL)
    {
        *length_ptr = htons(message_length);
        message->encoded_message = malloc(message_length);
        memcpy(message->encoded_message, message_buffer, message_length);
        message->encoded_message_length = message_length;

        return;
    }

    /* Encode each of the objects */
    double_linked_list_node *node = message->obj_list->head;
    for (; node != NULL; node = node->next_node)
    {
        message_length += pcep_encode_object(node->data, versioning, message_buffer + message_length);
    }

    *length_ptr = htons(message_length);
    message->encoded_message = malloc(message_length);
    memcpy(message->encoded_message, message_buffer, message_length);
    message->encoded_message_length = message_length;
}

/*
 * Decoding functions
 */

/* Expecting Host byte ordered header */
static bool validate_msg_header(uint8_t msg_version, uint8_t msg_flags, uint8_t msg_type, uint16_t msg_length)
{
    /* Invalid message if the length is less than the header
     * size or if its not a multiple of 4 */
    if (msg_length < MESSAGE_HEADER_LENGTH || (msg_length % 4) != 0)
    {
        pcep_log(LOG_INFO, "Invalid PCEP message header length [%d]", msg_length);
        return false;
    }

    if (msg_version != PCEP_MESSAGE_HEADER_VERSION)
    {
        pcep_log(LOG_INFO, "Invalid PCEP message header version [0x%x]", msg_version);
        return false;
    }

    if (msg_flags != 0)
    {
        pcep_log(LOG_INFO, "Invalid PCEP message header flags [0x%x]", msg_flags);
        return false;
    }

    switch(msg_type)
    {
    /* Supported message types */
    case PCEP_TYPE_OPEN:
    case PCEP_TYPE_KEEPALIVE:
    case PCEP_TYPE_PCREQ:
    case PCEP_TYPE_PCREP:
    case PCEP_TYPE_PCNOTF:
    case PCEP_TYPE_ERROR:
    case PCEP_TYPE_CLOSE:
    case PCEP_TYPE_REPORT:
    case PCEP_TYPE_UPDATE:
    case PCEP_TYPE_INITIATE:
        break;
    default:
        pcep_log(LOG_INFO, "Invalid PCEP message header type [%d]", msg_type);
        return false;
        break;
    }

    return true;
}

/* Internal util function */
static void pcep_decode_msg_header(uint8_t *msg_buf, uint8_t *msg_version, uint8_t *msg_flags, uint8_t *msg_type, uint16_t *msg_length)
{
    *msg_version = (msg_buf[0] >> 5) & 0x07;
    *msg_flags = (msg_buf[0] & 0x1f);
    *msg_type = msg_buf[1];
    uint16_t *uint16_ptr = (uint16_t *) (msg_buf + 2);
    *msg_length = ntohs(*uint16_ptr);
}

/* Decode the message header and return the message length */
int16_t pcep_decode_validate_msg_header(uint8_t *msg_buf)
{
    uint8_t msg_version;
    uint8_t msg_flags;
    uint8_t msg_type;
    uint16_t msg_length;

    pcep_decode_msg_header(msg_buf, &msg_version, &msg_flags, &msg_type, &msg_length);

    return((validate_msg_header(msg_version, msg_flags, msg_type, msg_length) == false) ? -1 : (int16_t) msg_length);
}

bool validate_message_objects(struct pcep_message *msg)
{
    if (msg->msg_header->type >= PCEP_TYPE_UNKOWN_MSG)
    {
        pcep_log(LOG_INFO, "Rejecting received message: Unknown message type [%d]",
                msg->msg_header->type);
        return false;
    }

    const int *object_classes = MANDATORY_MESSAGE_OBJECT_CLASSES[msg->msg_header->type];
    double_linked_list_node *node;
    int index;
    for (node = (msg->obj_list == NULL ? NULL : msg->obj_list->head), index = 0;
         index < NUM_CHECKED_OBJECTS;
         index++, (node = (node==NULL ? NULL : node->next_node)))
    {
        struct pcep_object_header *obj = ((node == NULL) ? NULL : (struct pcep_object_header*) node->data);

        if (object_classes[index] == NO_OBJECT)
        {
            if (node != NULL)
            {
                pcep_log(LOG_INFO, "Rejecting received message: Unexpected object [%d] present",
                         obj->object_class);
                return false;
            }
        }
        else if (object_classes[index] != ANY_OBJECT)
        {
            if (node == NULL)
            {
                pcep_log(LOG_INFO, "Rejecting received message: Expecting object in position [%d], but none received",
                         index);
                return false;
            }
            else if (object_classes[index] != obj->object_class)
            {
                pcep_log(LOG_INFO, "Rejecting received message: Unexpected Object Class received [%d]",
                         object_classes[index]);
                return false;
            }
        }
    }

    return true;
}

struct pcep_message *pcep_decode_message(uint8_t *msg_buf)
{
    uint8_t msg_version;
    uint8_t msg_flags;
    uint8_t msg_type;
    uint16_t msg_length;

    pcep_decode_msg_header(msg_buf, &msg_version, &msg_flags, &msg_type, &msg_length);

    struct pcep_message *msg = malloc(sizeof(struct pcep_message));
    bzero(msg, sizeof(struct pcep_message));

    msg->msg_header = malloc(sizeof(struct pcep_message_header));
    msg->msg_header->pcep_version = msg_version;
    msg->msg_header->type = msg_type;

    msg->obj_list = dll_initialize();
    msg->encoded_message = malloc(msg_length);
    memcpy(msg->encoded_message, msg_buf, msg_length);
    msg->encoded_message_length = msg_length;

    uint16_t bytes_read = MESSAGE_HEADER_LENGTH;
    while ((msg_length - bytes_read) >= OBJECT_HEADER_LENGTH)
    {
        struct pcep_object_header *obj_hdr = pcep_decode_object(msg_buf + bytes_read);

        if (obj_hdr == NULL)
        {
            pcep_log(LOG_INFO, "Discarding invalid message");
            pcep_msg_free_message(msg);

            return NULL;
        }

        dll_append(msg->obj_list, obj_hdr);
        bytes_read += obj_hdr->encoded_object_length;
    }

    if (validate_message_objects(msg) == false)
    {
        pcep_log(LOG_INFO, "Discarding invalid message");
        pcep_msg_free_message(msg);

        return NULL;
    }

    return msg;
}

struct pcep_versioning *create_default_pcep_versioning()
{
    struct pcep_versioning *versioning = malloc(sizeof(struct pcep_versioning));
    memset(versioning, 0, sizeof(struct pcep_versioning));

    versioning->draft_ietf_pce_segment_routing_07 = false;

    return versioning;
}

void destroy_pcep_versioning(struct pcep_versioning *versioning)
{
    free(versioning);
}
