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

static uint8_t pcep_object_class_lengths[] = {
        0, sizeof(struct pcep_object_open), sizeof(struct pcep_object_rp), sizeof(struct pcep_object_nopath),
        /* Setting PCEP_OBJ_CLASS_ENDPOINTS length to 0, since it could be ipv4 or ipv6 */
        0, sizeof(struct pcep_object_bandwidth), sizeof(struct pcep_object_metric), sizeof(struct pcep_object_ro),
        sizeof(struct pcep_object_ro), sizeof(struct pcep_object_lspa), sizeof(struct pcep_object_ro), sizeof(struct pcep_object_svec),
        sizeof(struct pcep_object_notify), sizeof(struct pcep_object_error), 0, sizeof(struct pcep_object_close),
        0, 0, 0, 0, 0, 0, 0, 0, /* Object classes 16 - 23 are not used */
        0, 0, 0, 0, 0, 0, 0, 0, /* Object classes 24 - 31 are not used */
        sizeof(struct pcep_object_lsp), sizeof(struct pcep_object_srp) };

bool
pcep_obj_parse(struct pcep_object_header* hdr)
{
    switch(hdr->object_class) {
        case PCEP_OBJ_CLASS_OPEN:
            pcep_unpack_obj_open((struct pcep_object_open*) hdr);
            break;
        case PCEP_OBJ_CLASS_RP:
            pcep_unpack_obj_rp((struct pcep_object_rp*) hdr);
            break;
        case PCEP_OBJ_CLASS_NOPATH:
            pcep_unpack_obj_nopath((struct pcep_object_nopath*) hdr);
            break;
        case PCEP_OBJ_CLASS_ENDPOINTS:
            if(hdr->object_type == PCEP_OBJ_TYPE_ENDPOINT_IPV4) {
                pcep_unpack_obj_ep_ipv4((struct pcep_object_endpoints_ipv4*) hdr);
            } else if(hdr->object_type == PCEP_OBJ_TYPE_ENDPOINT_IPV6) {
                pcep_unpack_obj_ep_ipv6((struct pcep_object_endpoints_ipv6*) hdr);
            }
            break;
        case PCEP_OBJ_CLASS_BANDWIDTH:
            pcep_unpack_obj_bandwidth((struct pcep_object_bandwidth*) hdr);
            break;
        case PCEP_OBJ_CLASS_METRIC:
            pcep_unpack_obj_metic((struct pcep_object_metric*) hdr);
            break;
        case PCEP_OBJ_CLASS_IRO:
        case PCEP_OBJ_CLASS_RRO:
        case PCEP_OBJ_CLASS_ERO:
            pcep_unpack_obj_ro((struct pcep_object_ro*) hdr);
            break;
        case PCEP_OBJ_CLASS_LSPA:
            pcep_unpack_obj_lspa((struct pcep_object_lspa*) hdr);
            break;
        case PCEP_OBJ_CLASS_SVEC:
            pcep_unpack_obj_svec((struct pcep_object_svec*) hdr);
            break;
        case PCEP_OBJ_CLASS_ERROR:
            pcep_unpack_obj_error((struct pcep_object_error*) hdr);
            break;
        case PCEP_OBJ_CLASS_CLOSE:
            pcep_unpack_obj_close((struct pcep_object_close*) hdr);
            break;
        case PCEP_OBJ_CLASS_SRP:
            pcep_unpack_obj_srp((struct pcep_object_srp*) hdr);
            break;
        case PCEP_OBJ_CLASS_LSP:
            pcep_unpack_obj_lsp((struct pcep_object_lsp*) hdr);
            break;
        case PCEP_OBJ_CLASS_NOTF:
            pcep_unpack_obj_notify((struct pcep_object_notify*) hdr);
            break;
        default:
            fprintf(stderr, "WARNING pcep_obj_parse: Unknown object class\n");
            return false;
    }

    /* Unpack the TLVs, if the object has them, but not for Route
     * Objects, since the sub-objects will be confused for TLVs. */
    if (hdr->object_class != PCEP_OBJ_CLASS_ERO &&
        hdr->object_class != PCEP_OBJ_CLASS_IRO &&
        hdr->object_class != PCEP_OBJ_CLASS_RRO)
    {
        if (pcep_obj_has_tlv(hdr))
        {
            /* This function call unpacks the TLVs */
            double_linked_list *tlv_list = pcep_obj_get_packed_tlvs(hdr);
            dll_destroy(tlv_list);
        }
    }

    return true;
}

/* Expecting Host byte ordered header */
bool validate_message_header(struct pcep_header* msg_hdr)
{
    /* Invalid message if the length is less than the header
     * size or if its not a multiple of 4 */
    if (msg_hdr->length < sizeof(struct pcep_header) || (msg_hdr->length % 4) != 0)
    {
        fprintf(stderr, "Invalid PCEP header length [%d]\n", msg_hdr->length);
        return false;
    }

    if (msg_hdr->ver_flags != PCEP_COMMON_HEADER_VER_FLAGS)
    {
        fprintf(stderr, "Invalid PCEP header flags [0x%x]\n", msg_hdr->ver_flags);
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
        fprintf(stderr, "Invalid PCEP header message type [%d]\n", msg_hdr->type);
        return false;
        break;
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
        perror("WARNING pcep_msg_read");
        fprintf(stderr, "WARNING pcep_msg_read: Failed to read from socket\n");
        return msg_list;
    } else if(ret == 0) {
        fprintf(stderr, "WARNING pcep_msg_read: Remote shutdown\n");
        return msg_list;
    }

    while((ret - buffer_read) >= sizeof(struct pcep_header)) {

        uint16_t obj_read = sizeof(struct pcep_header);

        msg_hdr = (struct pcep_header*) &buffer[buffer_read];

        pcep_unpack_msg_header(msg_hdr);
        if (validate_message_header(msg_hdr) == false)
        {
            fprintf(stderr, "WARNING pcep_msg_read: Received an invalid message\n");
            return msg_list;
        }

        if((ret - buffer_read) < msg_hdr->length) {
            int read_len = (msg_hdr->length - (ret - buffer_read));
            int read_ret = 0;
            fprintf(stderr, "WARNING pcep_msg_read: Message not fully read! Trying to read %d bytes more\n", read_len);

            read_ret = read(sock_fd, &buffer[ret], read_len);

            if(read_ret != read_len) {
                fprintf(stderr, "WARNING pcep_msg_read: Did not manage to read enough data (%d != %d)\n", read_ret, read_len);
                return msg_list;
            }
        }

        buffer_read += msg_hdr->length;

        msg = malloc(sizeof(struct pcep_message));
        bzero(msg, sizeof(struct pcep_message));
        dll_append(msg_list, msg);

        msg->obj_list = dll_initialize();
        msg->header = malloc(msg_hdr->length);
        memcpy(msg->header, msg_hdr, msg_hdr->length);

        /* The obj_list will just have pointers into the message to each object */
        while((msg->header->length - obj_read) > sizeof(struct pcep_object_header)) {
            struct pcep_object_header* obj_hdr = (struct pcep_object_header*) (((uint8_t*) msg->header) + obj_read);
            pcep_unpack_obj_header(obj_hdr);

            if(pcep_obj_parse(obj_hdr) == true) {
                dll_append(msg->obj_list, obj_hdr);
            } else {
                err_count++;
            }

            obj_read += obj_hdr->object_length;

            if(err_count > 5) break;
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
                printf("PCEP_TYPE_OPEN\n");
                break;
            case PCEP_TYPE_KEEPALIVE:
                printf("PCEP_TYPE_KEEPALIVE\n");
                break;
            case PCEP_TYPE_PCREQ:
                printf("PCEP_TYPE_PCREQ\n");
                break;
            case PCEP_TYPE_PCREP:
                printf("PCEP_TYPE_PCREP\n");
                break;
            case PCEP_TYPE_PCNOTF:
                printf("PCEP_TYPE_PCNOTF\n");
                break;
            case PCEP_TYPE_ERROR:
                printf("PCEP_TYPE_ERROR\n");
                break;
            case PCEP_TYPE_CLOSE:
                printf("PCEP_TYPE_CLOSE\n");
                break;
            default:
                printf("UNKOWN\n");
                continue;
        }

        double_linked_list_node *obj_item;
        for (obj_item = ((pcep_message *) item->data)->obj_list->head;
             obj_item != NULL;
             obj_item = obj_item->next_node) {
            printf("\t");
            struct pcep_object_header *obj_header = ((struct pcep_object_header *) obj_item->data);
            switch(obj_header->object_class) {
                case PCEP_OBJ_CLASS_OPEN:
                    printf("PCEP_OBJ_CLASS_OPEN\n");
                    break;
                case PCEP_OBJ_CLASS_RP:
                    printf("PCEP_OBJ_CLASS_RP\n");
                    break;
                case PCEP_OBJ_CLASS_NOPATH:
                    printf("PCEP_OBJ_CLASS_NOPATH\n");
                    break;
                case PCEP_OBJ_CLASS_ENDPOINTS:
                    if(obj_header->object_type == PCEP_OBJ_TYPE_ENDPOINT_IPV4) {
                        printf("PCEP_OBJ_CLASS_ENDPOINTS IPv4\n");
                    } else if(obj_header->object_type == PCEP_OBJ_TYPE_ENDPOINT_IPV6) {
                        printf("PCEP_OBJ_CLASS_ENDPOINTS IPv6\n");
                    }
                    break;
                case PCEP_OBJ_CLASS_BANDWIDTH:
                    printf("PCEP_OBJ_CLASS_BANDWIDTH\n");
                    break;
                case PCEP_OBJ_CLASS_METRIC:
                    printf("PCEP_OBJ_CLASS_METRIC\n");
                    break;
                case PCEP_OBJ_CLASS_ERO:
                    printf("PCEP_OBJ_CLASS_ERO\n");
                    break;
                case PCEP_OBJ_CLASS_LSPA:
                    printf("PCEP_OBJ_CLASS_LSPA\n");
                    break;
                case PCEP_OBJ_CLASS_SVEC:
                    printf("PCEP_OBJ_CLASS_SVEC\n");
                    break;
                case PCEP_OBJ_CLASS_ERROR:
                    printf("PCEP_OBJ_CLASS_ERROR\n");
                    break;
                case PCEP_OBJ_CLASS_CLOSE:
                    printf("PCEP_OBJ_CLASS_CLOSE\n");
                    break;
                case PCEP_OBJ_CLASS_RRO:
                case PCEP_OBJ_CLASS_IRO:
                case PCEP_OBJ_CLASS_NOTF:
                default:
                    printf("UNSUPPORTED CLASS\n");
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

bool
pcep_obj_has_tlv(struct pcep_object_header* hdr)
{
    uint8_t object_length = pcep_object_class_lengths[hdr->object_class];
    if (object_length == 0)
    {
        return false;
    }

    return (hdr->object_length - object_length) > 0;
}

struct pcep_object_tlv*
pcep_obj_get_next_tlv(struct pcep_object_header *hdr, uint8_t current_index)
{
    uint8_t *next_tlv = ((uint8_t *) hdr) + current_index;
    return (next_tlv >= (((uint8_t *)hdr) + hdr->object_length)) ?
            NULL : (struct pcep_object_tlv*) next_tlv;
}

/* Internal util function used by pcep_obj_get_tlvs() and pcep_obj_get_packed_tlvs() */
static double_linked_list*
pcep_obj_get_tlvs_(struct pcep_object_header *obj, bool do_unpack)
{
    /* Get the size of the object, not including TLVs */
    uint8_t object_length = pcep_object_class_lengths[obj->object_class];
    if (object_length == 0)
    {
        if (obj->object_class == PCEP_OBJ_CLASS_ENDPOINTS)
        {
            if (obj->object_type == PCEP_OBJ_TYPE_ENDPOINT_IPV4)
            {
                object_length = sizeof(struct pcep_object_endpoints_ipv4);
            }
            else
            {
                object_length = sizeof(struct pcep_object_endpoints_ipv6);
            }
        }
        else
        {
            return NULL;
        }
    }

    double_linked_list *tlv_list = dll_initialize();
    struct pcep_object_tlv *next_tlv = pcep_obj_get_next_tlv(obj, object_length);

    while (next_tlv != NULL)
    {
        if (do_unpack == true)
        {
            pcep_unpack_obj_tlv(next_tlv);
        }
        dll_append(tlv_list, next_tlv);
        /* The TLV length is the length of the value, need to also get past the TLV header */
        object_length += next_tlv->header.length + 4;
        next_tlv = pcep_obj_get_next_tlv(obj, object_length);
    }

    return tlv_list;
}

double_linked_list*
pcep_obj_get_tlvs(struct pcep_object_header *obj)
{
    return pcep_obj_get_tlvs_(obj, false);
}

double_linked_list*
pcep_obj_get_packed_tlvs(struct pcep_object_header *obj)
{
    return pcep_obj_get_tlvs_(obj, true);
}

