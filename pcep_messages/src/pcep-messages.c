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

#include <strings.h>
#include <string.h>
#include <arpa/inet.h>
#include <malloc.h>
#include <stdarg.h>
#include <unistd.h>

#include "pcep-messages.h"
#include "pcep-objects.h"
#include "pcep_utils_double_linked_list.h"
#include "pcep_utils_logging.h"

const char* message_type_strs[] = {
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

struct pcep_message*
pcep_msg_create_open(uint8_t keepalive, uint8_t deadtimer, uint8_t sid)
{
    uint8_t *buffer;
    uint16_t buffer_len;
    struct pcep_object_open *obj;
    struct pcep_message *message = malloc(sizeof(struct pcep_message));
    message->obj_list = dll_initialize();

    obj = pcep_obj_create_open(keepalive, deadtimer, sid, NULL);

    buffer_len = sizeof(struct pcep_header) + obj->header.object_length;
    buffer = malloc(sizeof(uint8_t) * buffer_len);

    bzero(buffer, buffer_len);

    message->header = (struct pcep_header*) buffer;
    message->header->length = buffer_len;
    message->header->type = PCEP_TYPE_OPEN;
    message->header->ver_flags = PCEP_COMMON_HEADER_VER_FLAGS;

    memcpy(buffer + sizeof(struct pcep_header), obj, obj->header.object_length);
    dll_append(message->obj_list, buffer + sizeof(struct pcep_header));
    free(obj);

    return message;
}

struct pcep_message*
pcep_msg_create_open_with_tlvs(uint8_t keepalive, uint8_t deadtimer, uint8_t sid, double_linked_list *tlv_list)
{
    uint8_t *buffer;
    uint16_t buffer_len;
    struct pcep_object_open *obj;
    struct pcep_message *message = malloc(sizeof(struct pcep_message));
    message->obj_list = dll_initialize();

    obj = pcep_obj_create_open(keepalive, deadtimer, sid, tlv_list);

    buffer_len = sizeof(struct pcep_header) + obj->header.object_length;
    buffer = malloc(buffer_len);
    bzero(buffer, buffer_len);

    message->header = (struct pcep_header*) buffer;
    message->header->length = buffer_len;
    message->header->type = PCEP_TYPE_OPEN;
    message->header->ver_flags = PCEP_COMMON_HEADER_VER_FLAGS;

    /* Copy the Open object to the message buffer, and free the object */
    memcpy(buffer + sizeof(struct pcep_header), obj, obj->header.object_length);
    dll_append(message->obj_list, buffer + sizeof(struct pcep_header));
    free(obj);

    return message;
}

static uint32_t
pcep_msg_get_request_id(struct pcep_header *hdr)
{
    uint8_t *buffer = (uint8_t*)hdr;
    uint16_t buffer_len = hdr->length;
    uint16_t buffer_pos = sizeof(struct pcep_header);

    while(buffer_pos < buffer_len) {
        struct pcep_object_header *obj = (struct pcep_object_header*)(buffer + buffer_pos);

        if((obj->object_class == PCEP_OBJ_CLASS_RP) &&
           (obj->object_type == PCEP_OBJ_TYPE_RP)) {
            struct pcep_object_rp *rp = (struct pcep_object_rp*)(buffer + buffer_pos);

            return rp->rp_reqidnumb;
        }

        buffer_pos += obj->object_length;
    }

    pcep_log(LOG_INFO, "pcep_msg_get_request_id: Failed to find the RP object.\n");

    return 0;
}

struct pcep_message*
pcep_msg_create_request_svec(struct pcep_header **requests, uint16_t request_count, float disjointness)
{
    int i;
    uint8_t *buffer;
    uint16_t buffer_len = 0;
    uint16_t buffer_pos = 0;

    uint32_t *svec_id_list;

    struct pcep_object_svec *svec;
    struct pcep_message *message = malloc(sizeof(struct pcep_message));
    message->obj_list = dll_initialize();

    svec_id_list = malloc(request_count * sizeof(uint32_t));

    for(i = 0; i < request_count; i++) {
        svec_id_list[i] = pcep_msg_get_request_id(requests[i]);
        buffer_len += (requests[i]->length - sizeof(struct pcep_header));

        if(svec_id_list[i] == 0) {
            free(svec_id_list);
            return NULL;
        }
    }

    svec = pcep_obj_create_svec(TRUE, TRUE, TRUE, request_count, svec_id_list);
    svec->reserved_disjointness = (uint8_t) (disjointness * 100);

    buffer_len += svec->header.object_length;
    buffer_len += sizeof(struct pcep_header);
    buffer_pos = sizeof(struct pcep_header);
    buffer = (uint8_t*) malloc(buffer_len * sizeof(uint8_t));

    bzero(buffer, buffer_len);

    message->header = (struct pcep_header*) buffer;
    message->header->length = buffer_len;
    message->header->type = PCEP_TYPE_PCREQ;
    message->header->ver_flags = PCEP_COMMON_HEADER_VER_FLAGS;

    //<PCReq Message>::= <Common Header>
    //                    [<svec-list>]
    //                    <request-list>

    memcpy(buffer + buffer_pos, svec, svec->header.object_length);
    dll_append(message->obj_list, buffer + buffer_pos);
    buffer_pos += svec->header.object_length;

    for(i = 0; i < request_count; i++) {
        uint16_t cpy_len = requests[i]->length - sizeof(struct pcep_header);
        memcpy(buffer + buffer_pos, ((uint8_t*)requests[i]) + sizeof(struct pcep_header), cpy_len);
        buffer_pos += cpy_len;
    }

    free(svec);
    free(svec_id_list);

    return message;
}

struct pcep_message*
pcep_msg_create_request(struct pcep_object_rp *rp,  struct pcep_object_endpoints_ipv4 *enpoints, double_linked_list *object_list)
{
    uint8_t *buffer;
    uint16_t buffer_len;
    uint16_t buffer_pos;

    if((rp == NULL) || (enpoints == NULL))
    {
        return NULL;
    }

    struct pcep_message *message = malloc(sizeof(struct pcep_message));
    message->obj_list = dll_initialize();
    buffer_len = sizeof(struct pcep_header) + rp->header.object_length + enpoints->header.object_length;
    buffer_pos = sizeof(struct pcep_header);

    /* Calculate the buffer_len by summing the length
     * of all the objects in the object_list */
    if (object_list != NULL) {
        double_linked_list_node *object;
        for (object = object_list->head; object != NULL; object = object->next_node) {
            buffer_len += ((struct pcep_object_header*) (object->data))->object_length;
        }
    }

    buffer = malloc(sizeof(uint8_t) * buffer_len);
    bzero(buffer, buffer_len);

    message->header = (struct pcep_header*) buffer;
    message->header->length = buffer_len;
    message->header->type = PCEP_TYPE_PCREQ;
    message->header->ver_flags = PCEP_COMMON_HEADER_VER_FLAGS;

    /* Copy the RP object */
    memcpy(buffer + buffer_pos, rp, rp->header.object_length);
    dll_append(message->obj_list, buffer + buffer_pos);
    buffer_pos += rp->header.object_length;

    /* Copy the Endpoints object */
    memcpy(buffer + buffer_pos, enpoints, enpoints->header.object_length);
    dll_append(message->obj_list, buffer + buffer_pos);
    buffer_pos += enpoints->header.object_length;

    if (object_list != NULL)
    {
        double_linked_list_node *object;
        for (object = object_list->head; object != NULL; object = object->next_node) {
            memcpy(buffer + buffer_pos, object->data,
                   ((struct pcep_object_header*) object->data)->object_length);
            dll_append(message->obj_list, buffer + buffer_pos);
            buffer_pos += ((struct pcep_object_header*) object->data)->object_length;
        }
    }

    return message;
}

struct pcep_message*
pcep_msg_create_reply_nopath(struct pcep_object_rp *rp,  struct pcep_object_nopath* nopath)
{
    uint8_t *buffer;
    uint16_t buffer_len;
    uint16_t buffer_pos;
    struct pcep_message *message = malloc(sizeof(struct pcep_message));
    message->obj_list = dll_initialize();

    buffer_len = sizeof(struct pcep_header);
    buffer_pos = sizeof(struct pcep_header);

    if(rp != NULL) {
        buffer_len += rp->header.object_length;
    }
    if(nopath != NULL) {
        buffer_len += nopath->header.object_length;
    }

    buffer = malloc(sizeof(uint8_t) * buffer_len);
    bzero(buffer, buffer_len);

    message->header = (struct pcep_header*) buffer;
    message->header->length = buffer_len;
    message->header->type = PCEP_TYPE_PCREP;
    message->header->ver_flags = PCEP_COMMON_HEADER_VER_FLAGS;

    if(rp != NULL) {
        memcpy(buffer + buffer_pos, rp, rp->header.object_length);
        dll_append(message->obj_list, buffer + buffer_pos);
        buffer_pos += rp->header.object_length;
    }
    if(nopath != NULL) {
        memcpy(buffer + buffer_pos, nopath, nopath->header.object_length);
        dll_append(message->obj_list, buffer + buffer_pos);
        buffer_pos += nopath->header.object_length;
    }

    return message;
}

struct pcep_message*
pcep_msg_create_reply(struct pcep_object_rp *rp, double_linked_list *object_list)
{
    uint8_t *buffer;
    uint16_t buffer_len;
    uint16_t buffer_pos;
    struct pcep_message *message = malloc(sizeof(struct pcep_message));
    message->obj_list = dll_initialize();

    buffer_len = sizeof(struct pcep_header);
    buffer_pos = sizeof(struct pcep_header);

    if(rp != NULL) {
        buffer_len += rp->header.object_length;
    }

    /* Calculate the buffer_len by summing the length
     * of all the objects in the object_list */
    if (object_list != NULL) {
        double_linked_list_node *object;
        for (object = object_list->head; object != NULL; object = object->next_node) {
            buffer_len += ((struct pcep_object_header*) (object->data))->object_length;
        }
    }

    buffer = malloc(sizeof(uint8_t) * buffer_len);

    bzero(buffer, buffer_len);

    message->header = (struct pcep_header*) buffer;
    message->header->length = buffer_len;
    message->header->type = PCEP_TYPE_PCREP;
    message->header->ver_flags = PCEP_COMMON_HEADER_VER_FLAGS;

    if(rp != NULL) {
        memcpy(buffer + buffer_pos, rp, rp->header.object_length);
        dll_append(message->obj_list, buffer + buffer_pos);
        buffer_pos += rp->header.object_length;
    }

    if (object_list != NULL) {
        double_linked_list_node *object;
        for (object = object_list->head; object != NULL; object = object->next_node) {
            memcpy(buffer + buffer_pos, object->data,
                   ((struct pcep_object_header*) object->data)->object_length);
            dll_append(message->obj_list, buffer + buffer_pos);
            buffer_pos += ((struct pcep_object_header*) object->data)->object_length;
        }
    }

    return message;
}

struct pcep_message*
pcep_msg_create_close(uint8_t flags, uint8_t reason)
{
    uint8_t *buffer;
    uint16_t buffer_len;
    struct pcep_object_close *obj;
    struct pcep_message *message = malloc(sizeof(struct pcep_message));
    message->obj_list = dll_initialize();

    obj = pcep_obj_create_close(flags, reason);

    buffer_len = sizeof(struct pcep_header) + obj->header.object_length;
    buffer = malloc(sizeof(uint8_t) * buffer_len);

    bzero(buffer, buffer_len);

    message->header = (struct pcep_header*) buffer;
    message->header->length = buffer_len;
    message->header->type = PCEP_TYPE_CLOSE;
    message->header->ver_flags = PCEP_COMMON_HEADER_VER_FLAGS;

    memcpy(buffer + sizeof(struct pcep_header), obj, obj->header.object_length);
    dll_append(message->obj_list, buffer + sizeof(struct pcep_header));
    free(obj);

    return message;
}

struct pcep_message*
pcep_msg_create_error(uint8_t error_type, uint8_t error_value)
{
    uint8_t *buffer;
    uint16_t buffer_len;
    struct pcep_object_error *obj;
    struct pcep_message *message = malloc(sizeof(struct pcep_message));
    message->obj_list = dll_initialize();

    obj = pcep_obj_create_error(error_type, error_value);

    buffer_len = sizeof(struct pcep_header) + obj->header.object_length;
    buffer = malloc(sizeof(uint8_t) * buffer_len);

    bzero(buffer, buffer_len);

    message->header = (struct pcep_header*) buffer;
    message->header->length = buffer_len;
    message->header->type = PCEP_TYPE_ERROR;
    message->header->ver_flags = PCEP_COMMON_HEADER_VER_FLAGS;

    memcpy(buffer + sizeof(struct pcep_header), obj, obj->header.object_length);
    dll_append(message->obj_list, buffer + sizeof(struct pcep_header));
    free(obj);

    return message;
}

struct pcep_message*
pcep_msg_create_keepalive()
{
    uint8_t *buffer;
    uint16_t buffer_len;
    struct pcep_message *message = malloc(sizeof(struct pcep_message));
    message->obj_list = dll_initialize();

    buffer_len = sizeof(struct pcep_header);
    buffer = malloc(sizeof(uint8_t) * buffer_len);

    bzero(buffer, buffer_len);

    message->header = (struct pcep_header*) buffer;
    message->header->length = buffer_len;
    message->header->type = PCEP_TYPE_KEEPALIVE;
    message->header->ver_flags = PCEP_COMMON_HEADER_VER_FLAGS;

    return message;
}

/* Common message creation function to handle double_linked_list of
 * objects, Used by pcep_msg_create_report(), pcep_msg_create_update(),
 * and pcep_msg_create_initiate() */
static struct pcep_message*
pcep_msg_create_from_object_list(double_linked_list *object_list)
{
    if (object_list == NULL)
    {
        pcep_log(LOG_INFO, "pcep_msg_create_from_object_list NULL object_list\n");
        return NULL;
    }

    if (object_list->num_entries == 0)
    {
        pcep_log(LOG_INFO, "pcep_msg_create_from_object_list empty object_list\n");
        return NULL;
    }

    pcep_message *message = malloc(sizeof(struct pcep_message));
    message->obj_list = dll_initialize();

    int buffer_len = sizeof(struct pcep_header);
    double_linked_list_node *node = object_list->head;
    for(; node != NULL; node = node->next_node)
    {
        struct pcep_object_header *obj_hdr = (struct pcep_object_header*) node->data;
        buffer_len += obj_hdr->object_length;
    }

    uint8_t *buffer = malloc(buffer_len);
    message->header = (struct pcep_header *) buffer;
    message->header->length = buffer_len;
    message->header->type = 0; /* Should be filled in by calling function */
    message->header->ver_flags = PCEP_COMMON_HEADER_VER_FLAGS;

    int index = sizeof(struct pcep_header);
    node = object_list->head;
    for(; node != NULL; node = node->next_node)
    {
        struct pcep_object_header *obj_hdr = (struct pcep_object_header*) node->data;
        memcpy(buffer + index, obj_hdr, obj_hdr->object_length);
        dll_append(message->obj_list, buffer + index);
        index += obj_hdr->object_length;
    }

    return message;
}

struct pcep_message*
pcep_msg_create_report(double_linked_list *state_report_object_list)
{
    struct pcep_message *message =
            pcep_msg_create_from_object_list(state_report_object_list);
    if (message != NULL)
    {
        message->header->type = PCEP_TYPE_REPORT;
    }

    return message;
}

struct pcep_message*
pcep_msg_create_update(double_linked_list *update_request_object_list)
{
    if (update_request_object_list == NULL)
    {
        pcep_log(LOG_INFO, "pcep_msg_create_update NULL update_request_object_list\n");
        return NULL;
    }

    /* There must be at least 3 objects:
     * These 3 are mandatory: SRP, LSP, and ERO. The ERO may be empty */
    if (update_request_object_list->num_entries < 3)
    {
        pcep_log(LOG_INFO, "pcep_msg_create_update there must be at least 3 update objects\n");
        return NULL;
    }

    double_linked_list_node *node = update_request_object_list->head;
    struct pcep_object_header *obj_hdr = (struct pcep_object_header*) node->data;

    /* Check for the mandatory first SRP object */
    if (obj_hdr->object_class != PCEP_OBJ_CLASS_SRP)
    {
        /* If the SRP object is missing, the receiving PCC MUST send a PCErr
         * message with Error-type=6 (Mandatory Object missing) and Error-value=10
         * (SRP object missing). */
        pcep_log(LOG_INFO, "pcep_msg_create_update missing mandatory first SRP object\n");
        return NULL;
    }

    /* Check for the mandatory 2nd LSP object */
    node = node->next_node;
    obj_hdr = (struct pcep_object_header*) node->data;
    if (obj_hdr->object_class != PCEP_OBJ_CLASS_LSP)
    {
        /* If the LSP object is missing, the receiving PCC MUST send a PCErr
         * message with Error-type=6 (Mandatory Object missing) and Error-value=8
         * (LSP object missing). */
        pcep_log(LOG_INFO, "pcep_msg_create_update missing mandatory second LSP object\n");
        return NULL;
    }

    /* Check for the mandatory 3rd ERO object */
    node = node->next_node;
    obj_hdr = (struct pcep_object_header*) node->data;
    if (obj_hdr->object_class != PCEP_OBJ_CLASS_ERO)
    {
        /* If the ERO object is missing, the receiving PCC MUST send a PCErr
         * message with Error-type=6 (Mandatory Object missing) and Error-value=9
         * (ERO object missing). */
        pcep_log(LOG_INFO, "pcep_msg_create_update missing mandatory third ERO object\n");
        return NULL;
    }

    struct pcep_message *message =
            pcep_msg_create_from_object_list(update_request_object_list);
    if (message != NULL)
    {
        message->header->type = PCEP_TYPE_UPDATE;
    }

    return message;
}

struct pcep_message*
pcep_msg_create_initiate(double_linked_list *lsp_object_list)
{
    if (lsp_object_list == NULL)
    {
        pcep_log(LOG_INFO, "pcep_msg_create_initiate NULL update_request_object_list\n");
        return NULL;
    }

    /* There must be at least 2 objects: SRP and LSP. */
    if (lsp_object_list->num_entries < 2)
    {
        pcep_log(LOG_INFO, "pcep_msg_create_initiate there must be at least 2 objects\n");
        return NULL;
    }

    double_linked_list_node *node = lsp_object_list->head;
    struct pcep_object_header *obj_hdr = (struct pcep_object_header*) node->data;

    /* Check for the mandatory first SRP object */
    if (obj_hdr->object_class != PCEP_OBJ_CLASS_SRP)
    {
        pcep_log(LOG_INFO, "pcep_msg_create_initiate missing mandatory first SRP object\n");
        return NULL;
    }

    /* Check for the mandatory 2nd LSP object */
    node = node->next_node;
    obj_hdr = (struct pcep_object_header*) node->data;
    if (obj_hdr->object_class != PCEP_OBJ_CLASS_LSP)
    {
        pcep_log(LOG_INFO, "pcep_msg_create_initiate missing mandatory second LSP object\n");
        return NULL;
    }

    struct pcep_message *message =
            pcep_msg_create_from_object_list(lsp_object_list);
    if (message != NULL)
    {
        message->header->type = PCEP_TYPE_INITIATE;
    }

    return message;
}

void
pcep_msg_encode(struct pcep_message *message)
{
    double_linked_list_node *object_node = message->obj_list->head;
    while(object_node != NULL)
    {
        struct pcep_object_header *obj_hdr = (struct pcep_object_header *) object_node->data;
        pcep_obj_encode(obj_hdr);
        object_node = object_node->next_node;
    }

    message->header->length = htons(message->header->length);
}

const char *get_message_type_str(uint8_t type)
{
    uint8_t msg_type = (type > PCEP_TYPE_INITIATE) ? PCEP_TYPE_INITIATE + 1 : type;

    return message_type_strs[msg_type];
}
