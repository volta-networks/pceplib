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

#include <errno.h>
#include <malloc.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "pcep-tools.h"
#include "pcep-encoding.h"
#include "pcep_utils_logging.h"

static const char* message_type_strs[] = {
        "NOT_IMPLEMENTED0",
        "OPEN",
        "KEEPALIVE",
        "PCREQ",
        "PCREP",
        "PCNOTF",
        "ERROR",
        "CLOSE",
        "NOT_IMPLEMENTED8",
        "NOT_IMPLEMENTED9",
        "REPORT",
        "UPDATE",
        "INITIATE",
        "UNKOWN_MESSAGE_TYPE"};

static const char* object_class_strs[] = {
        "NOT_IMPLEMENTED0",
        "OPEN",
        "RP",
        "NOPATH",
        "ENDPOINTS",
        "BANDWIDTH",
        "METRIC",
        "ERO",
        "RRO",
        "LSPA",
        "IRO",
        "SVEC",
        "NOTF",
        "ERROR",
        "NOT_IMPLEMENTED14",
        "CLOSE",
        "NOT_IMPLEMENTED16", "NOT_IMPLEMENTED17", "NOT_IMPLEMENTED18", "NOT_IMPLEMENTED19",
        "NOT_IMPLEMENTED20", "NOT_IMPLEMENTED21", "NOT_IMPLEMENTED22", "NOT_IMPLEMENTED23",
        "NOT_IMPLEMENTED24", "NOT_IMPLEMENTED25", "NOT_IMPLEMENTED26", "NOT_IMPLEMENTED27",
        "NOT_IMPLEMENTED28", "NOT_IMPLEMENTED29", "NOT_IMPLEMENTED30", "NOT_IMPLEMENTED31",
        "LSP",
        "SRP",
        "UNKNOWN_MESSAGE_TYPE" };


double_linked_list*
pcep_msg_read(int sock_fd)
{
    int ret;
    uint8_t buffer[PCEP_MAX_SIZE];
    uint16_t buffer_read = 0;

    bzero(&buffer, PCEP_MAX_SIZE);

    ret = read(sock_fd, &buffer, PCEP_MAX_SIZE);

    if(ret < 0) {
        pcep_log(LOG_INFO, "pcep_msg_read: Failed to read from socket errno [%d %s]\n", errno, strerror(errno));
        return NULL;
    } else if(ret == 0) {
        pcep_log(LOG_INFO, "pcep_msg_read: Remote shutdown\n");
        return NULL;
    }

    double_linked_list* msg_list = dll_initialize();
    struct pcep_message* msg = NULL;

    while((ret - buffer_read) >= MESSAGE_HEADER_LENGTH) {

        /* Get the Message header, validate it, and return the msg length */
        int16_t msg_hdr_length = pcep_decode_validate_msg_header(buffer + buffer_read);
        if (msg_hdr_length < 0)
        {
            /* If the message header is invalid, we cant keep
             * reading since the length may be invalid */
            pcep_log(LOG_INFO, "pcep_msg_read: Received an invalid message\n");
            return msg_list;
        }

        /* Check if the msg_hdr_length is longer than what was read,
         * in which case, we need to read the rest of the message. */
        if((ret - buffer_read) < msg_hdr_length) {
            int read_len = (msg_hdr_length - (ret - buffer_read));
            int read_ret = 0;
            pcep_log(LOG_INFO, "pcep_msg_read: Message not fully read! Trying to read %d bytes more\n", read_len);

            read_ret = read(sock_fd, &buffer[ret], read_len);

            if(read_ret != read_len) {
                pcep_log(LOG_INFO, "pcep_msg_read: Did not manage to read enough data (%d != %d)\n", read_ret, read_len);
                return msg_list;
            }
        }

        msg = pcep_decode_message(buffer + buffer_read);
        buffer_read += msg_hdr_length;

        if (msg == NULL)
        {
            return msg_list;
        }
        else
        {
            dll_append(msg_list, msg);
        }
    }

    return msg_list;
}

struct pcep_message*
pcep_msg_get(double_linked_list* msg_list, uint8_t type)
{
    if (msg_list == NULL)
    {
        return NULL;
    }

    double_linked_list_node *node;
    for (node = msg_list->head; node != NULL; node = node->next_node)
    {
        if(((struct pcep_message *) node->data)->msg_header->type == type)
        {
            return (struct pcep_message *) node->data;
        }
    }

    return NULL;
}

struct pcep_message*
pcep_msg_get_next(double_linked_list* list, struct pcep_message* current, uint8_t type)
{
    if (list == NULL || current == NULL)
    {
        return NULL;
    }

    if (list->head == NULL)
    {
        return NULL;
    }

    double_linked_list_node *node;
    for (node = list->head; node != NULL; node = node->next_node)
    {
        if(node->data == current)
        {
            continue;
        }

        if(((struct pcep_message *) node->data)->msg_header->type == type)
        {
            return (struct pcep_message *) node->data;
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
    for (obj_item = list->head; obj_item != NULL; obj_item = obj_item->next_node)
    {
        if(((struct pcep_object_header *) obj_item->data)->object_class == object_class)
        {
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

    double_linked_list_node *node;
    for (node = list->head; node != NULL; node = node->next_node)
    {
        if(node->data == current)
        {
            continue;
        }

        if(((struct pcep_object_header *) node->data)->object_class == object_class)
        {
            return (struct pcep_object_header *) node->data;
        }
    }

    return NULL;
}

void
pcep_obj_free_tlv(struct pcep_object_tlv_header *tlv)
{
    /* Specific TLV freeing */
    switch (tlv->type)
    {
    case PCEP_OBJ_TLV_TYPE_SPEAKER_ENTITY_ID:
        if (((struct pcep_object_tlv_speaker_entity_identifier *) tlv)->speaker_entity_id_list != NULL)
        {
            dll_destroy_with_data(((struct pcep_object_tlv_speaker_entity_identifier *) tlv)->speaker_entity_id_list);
        }
        break;

    case PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE_CAPABILITY:
        if (((struct pcep_object_tlv_path_setup_type_capability *) tlv)->pst_list != NULL)
        {
            dll_destroy_with_data(((struct pcep_object_tlv_path_setup_type_capability *) tlv)->pst_list);
        }

        if (((struct pcep_object_tlv_path_setup_type_capability *) tlv)->sub_tlv_list != NULL)
        {
            dll_destroy_with_data(((struct pcep_object_tlv_path_setup_type_capability *) tlv)->sub_tlv_list);
        }
        break;

    default:
        break;
    }

    free(tlv);
}

void
pcep_obj_free_object(struct pcep_object_header *obj)
{
    /* Iterate the TLVs and free each one */
    if (obj->tlv_list != NULL)
    {
        struct pcep_object_tlv_header *tlv;
        while ((tlv = (struct pcep_object_tlv_header *) dll_delete_first_node(obj->tlv_list)) != NULL)
        {
            pcep_obj_free_tlv(tlv);
        }

        dll_destroy(obj->tlv_list);
    }

    /* Specific object freeing */
    switch (obj->object_class)
    {
    case PCEP_OBJ_CLASS_ERO:
    case PCEP_OBJ_CLASS_IRO:
    case PCEP_OBJ_CLASS_RRO:
    {
        if (((struct pcep_object_ro *) obj)->sub_objects != NULL)
        {
            double_linked_list_node *node = ((struct pcep_object_ro *) obj)->sub_objects->head;
            for (; node != NULL; node = node->next_node)
            {
                struct pcep_object_ro_subobj *ro_subobj = (struct pcep_object_ro_subobj *) node->data;
                if (ro_subobj->ro_subobj_type == RO_SUBOBJ_TYPE_SR)
                {
                    if (((struct pcep_ro_subobj_sr *) ro_subobj)->nai_list != NULL)
                    {
                        dll_destroy_with_data(((struct pcep_ro_subobj_sr *) ro_subobj)->nai_list);
                    }
                }
            }
            dll_destroy_with_data(((struct pcep_object_ro *) obj)->sub_objects);
        }
    }
    break;

    case PCEP_OBJ_CLASS_SVEC:
        if (((struct pcep_object_svec *) obj)->request_id_list != NULL)
        {
            dll_destroy_with_data(((struct pcep_object_svec *) obj)->request_id_list);
        }
        break;

    default:
        break;
    }

    free(obj);
}

void
pcep_msg_free_message(struct pcep_message *message)
{
    /* Iterate the objects and free each one */
    if (message->obj_list != NULL)
    {
        struct pcep_object_header *obj;
        while ((obj = (struct pcep_object_header *) dll_delete_first_node(message->obj_list)) != NULL)
        {
            pcep_obj_free_object(obj);
        }

        dll_destroy(message->obj_list);
    }

    if (message->msg_header != NULL)
    {
        free(message->msg_header);
    }

    if (message->encoded_message != NULL)
    {
        free(message->encoded_message);
    }

    free(message);
}

void
pcep_msg_free_message_list(double_linked_list* list)
{
    /* Iterate the messages and free each one */
    struct pcep_message *msg;
    while ((msg = (struct pcep_message *) dll_delete_first_node(list)) != NULL)
    {
        pcep_msg_free_message(msg);
    }

    dll_destroy(list);
}

const char *get_message_type_str(uint8_t type)
{
    uint8_t msg_type = (type > PCEP_TYPE_INITIATE) ? PCEP_TYPE_INITIATE + 1 : type;

    return message_type_strs[msg_type];
}

const char *get_object_class_str(uint8_t class)
{
    uint8_t object_class = (class > PCEP_OBJ_CLASS_SRP) ? PCEP_OBJ_CLASS_SRP + 1 : class;

    return object_class_strs[object_class];
}

/* Expecting a list of struct pcep_message pointers */
void pcep_msg_print(double_linked_list* msg_list)
{
    double_linked_list_node *node;
    for (node = msg_list->head; node != NULL; node = node->next_node) {
        struct pcep_message *msg = (struct pcep_message *) node->data;
        pcep_log(LOG_INFO, "PCEP_MSG %s\n", get_message_type_str(msg->msg_header->type));

        double_linked_list_node *obj_node = (msg->obj_list == NULL ? NULL : msg->obj_list->head);
        for (; obj_node != NULL; obj_node = obj_node->next_node) {
            struct pcep_object_header *obj_header = ((struct pcep_object_header *) obj_node->data);
            pcep_log(LOG_INFO, "PCEP_OBJ %s\n", get_object_class_str(obj_header->object_class));
        }
    }
}

int
pcep_msg_send(int sock_fd, struct pcep_message* msg)
{
    if(msg == NULL)
    {
        return 0;
    }

    return write(sock_fd, msg->encoded_message, ntohs(msg->encoded_message_length));
}
