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

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <malloc.h>

#include "pcep-tools.h"
#include "pcep_utils_logging.h"

#define ANY_OBJECT 0
#define NO_OBJECT -1
#define NUM_CHECKED_OBJECTS 4
static const int MAX_PCEP_MESSAGE_TYPE = PCEP_TYPE_INITIATE;
//static const int MANDATORY_MESSAGE_OBJECT_CLASSES[PCEP_TYPE_INITIATE+1][NUM_CHECKED_OBJECTS] = {
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

void pcep_decode_msg_header(struct pcep_header* hdr)
{
    hdr->length = ntohs(hdr->length);
}

/* Expecting Host byte ordered header */
bool validate_message_header(struct pcep_header* msg_hdr)
{
    /* Invalid message if the length is less than the header
     * size or if its not a multiple of 4 */
    if (msg_hdr->length < sizeof(struct pcep_header) || (msg_hdr->length % 4) != 0)
    {
        pcep_log(LOG_INFO, "Invalid PCEP header length [%d]\n", msg_hdr->length);
        return false;
    }

    if (msg_hdr->ver_flags != PCEP_COMMON_HEADER_VER_FLAGS)
    {
        pcep_log(LOG_INFO, "Invalid PCEP header flags [0x%x]\n", msg_hdr->ver_flags);
        return false;
    }

    switch(msg_hdr->type)
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
        pcep_log(LOG_INFO, "Invalid PCEP header message type [%d]\n", msg_hdr->type);
        return false;
        break;
    }

    return true;
}

bool validate_message_objects(struct pcep_message *msg)
{
    if (msg->header->type > MAX_PCEP_MESSAGE_TYPE)
    {
        pcep_log(LOG_INFO, "Rejecting received message: Unknown message type [%d]\n",
                msg->header->type);
        return false;
    }

    const int *object_classes = MANDATORY_MESSAGE_OBJECT_CLASSES[msg->header->type];
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
                pcep_log(LOG_INFO, "Rejecting received message: Unexpected object [%d] present\n",
                         obj->object_class);
                return false;
            }
        }
        else if (object_classes[index] != ANY_OBJECT)
        {
            if (node == NULL)
            {
                pcep_log(LOG_INFO, "Rejecting received message: Expecting object in position [%d], but none received\n",
                         index);
                return false;
            }
            else if (object_classes[index] != obj->object_class)
            {
                pcep_log(LOG_INFO, "Rejecting received message: Unexpected Object Class received [%d]\n",
                         object_classes[index]);
                return false;
            }
        }
    }

    return true;
}

double_linked_list*
pcep_msg_read(int sock_fd)
{
    int ret;
    int err_count = 0;
    uint8_t buffer[PCEP_MAX_SIZE];
    uint16_t buffer_read = 0;
    struct pcep_header* msg_hdr;
    double_linked_list* msg_list = dll_initialize();
    struct pcep_message* msg = NULL;

    bzero(&buffer, PCEP_MAX_SIZE);

    ret = read(sock_fd, &buffer, PCEP_MAX_SIZE);

    if(ret < 0) {
        pcep_log(LOG_INFO, "pcep_msg_read: Failed to read from socket\n");
        return msg_list;
    } else if(ret == 0) {
        pcep_log(LOG_INFO, "pcep_msg_read: Remote shutdown\n");
        return msg_list;
    }

    while((ret - buffer_read) >= sizeof(struct pcep_header)) {

        uint16_t obj_read = sizeof(struct pcep_header);

        msg_hdr = (struct pcep_header*) &buffer[buffer_read];

        pcep_decode_msg_header(msg_hdr);
        if (validate_message_header(msg_hdr) == false)
        {
            /* If the message header is invalid, we cant keep reading,
             * since the length may be invalid */
            pcep_log(LOG_INFO, "pcep_msg_read: Received an invalid message\n");
            return msg_list;
        }

        if((ret - buffer_read) < msg_hdr->length) {
            int read_len = (msg_hdr->length - (ret - buffer_read));
            int read_ret = 0;
            pcep_log(LOG_INFO, "pcep_msg_read: Message not fully read! Trying to read %d bytes more\n", read_len);

            read_ret = read(sock_fd, &buffer[ret], read_len);

            if(read_ret != read_len) {
                pcep_log(LOG_INFO, "pcep_msg_read: Did not manage to read enough data (%d != %d)\n", read_ret, read_len);
                return msg_list;
            }
        }

        buffer_read += msg_hdr->length;

        msg = malloc(sizeof(struct pcep_message));
        bzero(msg, sizeof(struct pcep_message));

        msg->obj_list = dll_initialize();
        msg->header = malloc(msg_hdr->length);
        memcpy(msg->header, msg_hdr, msg_hdr->length);

        /* The obj_list will just have pointers into the message to each object */
        while((msg->header->length - obj_read) > sizeof(struct pcep_object_header)) {
            struct pcep_object_header* obj_hdr = (struct pcep_object_header*) (((uint8_t*) msg->header) + obj_read);

            if(pcep_obj_parse_decode(obj_hdr) == true) {
                dll_append(msg->obj_list, obj_hdr);
            } else {
                err_count++;
            }

            obj_read += obj_hdr->object_length;

            if(err_count > 5) break;
        }

        if (validate_message_objects(msg) == false)
        {
            pcep_log(LOG_INFO, "Discarding invalid message");
            pcep_msg_free_message(msg);
        }
        else
        {
            dll_append(msg_list, msg);
        }
    }

    return msg_list;
}

pcep_message*
pcep_msg_get(double_linked_list* msg_list, uint8_t type)
{
    if (msg_list == NULL)
    {
        return NULL;
    }

    double_linked_list_node *item;
    for (item = msg_list->head; item != NULL; item = item->next_node) {
        if(((pcep_message *) item->data)->header->type == type) {
            return (pcep_message *) item->data;
        }
    }

    return NULL;
}

pcep_message*
pcep_msg_get_next(double_linked_list* list, pcep_message* current, uint8_t type)
{
    if (list == NULL || current == NULL)
    {
        return NULL;
    }

    if (list->head == NULL)
    {
        return NULL;
    }

    double_linked_list_node *item;
    for (item = list->head; item != NULL; item = item->next_node) {
        if(item->data == current) continue;
        if(((pcep_message *) item->data)->header->type == type) {
            return (pcep_message *) item->data;
        }
    }

    return NULL;
}

struct pcep_object_header*
pcep_obj_get(double_linked_list* list, uint8_t object_class)
{
    if (list == NULL)
    {
        return NULL;
    }

    if (list->head == NULL)
    {
        return NULL;
    }

    double_linked_list_node *obj_item;
    for (obj_item = list->head; obj_item != NULL; obj_item = obj_item->next_node) {
        if(((struct pcep_object_header *) obj_item->data)->object_class == object_class) {
            return (struct pcep_object_header *) obj_item->data;
        }
    }

    return NULL;
}

struct pcep_object_header*
pcep_obj_get_next(double_linked_list* list, struct pcep_object_header* current, uint8_t object_class)
{
    if (list == NULL || current == NULL)
    {
        return NULL;
    }

    if (list->head == NULL)
    {
        return NULL;
    }

    double_linked_list_node *obj_item;
    for (obj_item = list->head; obj_item != NULL; obj_item = obj_item->next_node) {
        if(((struct pcep_object_header *) obj_item->data)->object_class == object_class) {
            return (struct pcep_object_header *) obj_item->data;
        }
    }

    return NULL;
}

void
pcep_msg_free_message(struct pcep_message *message)
{
    dll_destroy(message->obj_list);
    free(message->header);
    free(message);
}

void
pcep_msg_free_message_list(double_linked_list* list)
{
    /* Iterate the messages and free each one */
    pcep_message *msg = (pcep_message *) dll_delete_first_node(list);
    while (msg != NULL) {
        pcep_msg_free_message(msg);
        msg = (pcep_message *) dll_delete_first_node(list);
    }
    dll_destroy(list);
}

void
pcep_msg_print(double_linked_list* list)
{
    double_linked_list_node *item;
    for (item = list->head; item != NULL; item = item->next_node) {
        switch(((pcep_message *) item->data)->header->type) {
            case PCEP_TYPE_OPEN:
                pcep_log(LOG_INFO, "PCEP_TYPE_OPEN\n");
                break;
            case PCEP_TYPE_KEEPALIVE:
                pcep_log(LOG_INFO, "PCEP_TYPE_KEEPALIVE\n");
                break;
            case PCEP_TYPE_PCREQ:
                pcep_log(LOG_INFO, "PCEP_TYPE_PCREQ\n");
                break;
            case PCEP_TYPE_PCREP:
                pcep_log(LOG_INFO, "PCEP_TYPE_PCREP\n");
                break;
            case PCEP_TYPE_PCNOTF:
                pcep_log(LOG_INFO, "PCEP_TYPE_PCNOTF\n");
                break;
            case PCEP_TYPE_ERROR:
                pcep_log(LOG_INFO, "PCEP_TYPE_ERROR\n");
                break;
            case PCEP_TYPE_CLOSE:
                pcep_log(LOG_INFO, "PCEP_TYPE_CLOSE\n");
                break;
            default:
                pcep_log(LOG_INFO, "UNKOWN\n");
                continue;
        }

        double_linked_list_node *obj_item;
        for (obj_item = ((pcep_message *) item->data)->obj_list->head;
             obj_item != NULL;
             obj_item = obj_item->next_node) {
            struct pcep_object_header *obj_header = ((struct pcep_object_header *) obj_item->data);
            switch(obj_header->object_class) {
                case PCEP_OBJ_CLASS_OPEN:
                    pcep_log(LOG_INFO, "\tPCEP_OBJ_CLASS_OPEN\n");
                    break;
                case PCEP_OBJ_CLASS_RP:
                    pcep_log(LOG_INFO, "\tPCEP_OBJ_CLASS_RP\n");
                    break;
                case PCEP_OBJ_CLASS_NOPATH:
                    pcep_log(LOG_INFO, "\tPCEP_OBJ_CLASS_NOPATH\n");
                    break;
                case PCEP_OBJ_CLASS_ENDPOINTS:
                    if(obj_header->object_type == PCEP_OBJ_TYPE_ENDPOINT_IPV4) {
                        pcep_log(LOG_INFO, "\tPCEP_OBJ_CLASS_ENDPOINTS IPv4\n");
                    } else if(obj_header->object_type == PCEP_OBJ_TYPE_ENDPOINT_IPV6) {
                        pcep_log(LOG_INFO, "\tPCEP_OBJ_CLASS_ENDPOINTS IPv6\n");
                    }
                    break;
                case PCEP_OBJ_CLASS_BANDWIDTH:
                    pcep_log(LOG_INFO, "\tPCEP_OBJ_CLASS_BANDWIDTH\n");
                    break;
                case PCEP_OBJ_CLASS_METRIC:
                    pcep_log(LOG_INFO, "\tPCEP_OBJ_CLASS_METRIC\n");
                    break;
                case PCEP_OBJ_CLASS_ERO:
                    pcep_log(LOG_INFO, "\tPCEP_OBJ_CLASS_ERO\n");
                    break;
                case PCEP_OBJ_CLASS_LSPA:
                    pcep_log(LOG_INFO, "\tPCEP_OBJ_CLASS_LSPA\n");
                    break;
                case PCEP_OBJ_CLASS_SVEC:
                    pcep_log(LOG_INFO, "\tPCEP_OBJ_CLASS_SVEC\n");
                    break;
                case PCEP_OBJ_CLASS_ERROR:
                    pcep_log(LOG_INFO, "\tPCEP_OBJ_CLASS_ERROR\n");
                    break;
                case PCEP_OBJ_CLASS_CLOSE:
                    pcep_log(LOG_INFO, "PCEP_OBJ_CLASS_CLOSE\n");
                    break;
                case PCEP_OBJ_CLASS_RRO:
                case PCEP_OBJ_CLASS_IRO:
                case PCEP_OBJ_CLASS_NOTF:
                default:
                    pcep_log(LOG_INFO, "\tUNSUPPORTED CLASS\n");
                    break;
            }
        }
    }
}

int
pcep_msg_send(int sock_fd, struct pcep_header* hdr)
{
    if(hdr == NULL) return 0;

    return write(sock_fd, hdr, ntohs(hdr->length));
}

double_linked_list*
pcep_msg_get_objects(struct pcep_header* hdr, bool host_byte_ordered)
{
    if (hdr == NULL)
    {
        return NULL;
    }

    /* Assuming message and objects are in Host byte order */

    uint8_t *end_of_message = (((uint8_t *) hdr) +
            (host_byte_ordered ? hdr->length : ntohs(hdr->length)));
    double_linked_list *obj_list = dll_initialize();
    struct pcep_object_header *obj_ptr =
            (struct pcep_object_header *) (((uint8_t *) hdr) + sizeof(struct pcep_header));

    while ((uint8_t *) obj_ptr < end_of_message)
    {
        dll_append(obj_list, obj_ptr);
        obj_ptr = (struct pcep_object_header *) (((uint8_t *) obj_ptr) +
                (host_byte_ordered ? obj_ptr->object_length : ntohs(obj_ptr->object_length)));
    }

    return obj_list;
}

bool
pcep_msg_has_object(struct pcep_header* hdr, bool host_byte_ordered)
{
    if (hdr == NULL)
    {
        return false;
    }

    /* Assuming header is in Host byte order */
    if (host_byte_ordered)
    {
        return (hdr->length > sizeof(struct pcep_header) ? true : false);
    }
    else
    {
        return (ntohs(hdr->length) > sizeof(struct pcep_header) ? true : false);
    }
}
