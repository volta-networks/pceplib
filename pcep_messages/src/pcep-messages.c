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

struct pcep_header*
pcep_msg_create_open(uint8_t keepalive, uint8_t deadtimer, uint8_t sid)
{
    uint8_t *buffer;
    uint16_t buffer_len;
    struct pcep_object_open *obj;
    struct pcep_header *hdr;

    obj = pcep_obj_create_open(keepalive, deadtimer, sid);

    buffer_len = sizeof(struct pcep_header) + ntohs(obj->header.object_length);
    buffer = malloc(sizeof(uint8_t) * buffer_len);

    bzero(buffer, buffer_len);

    hdr = (struct pcep_header*) buffer;
    hdr->length = htons(buffer_len);
    hdr->type = PCEP_TYPE_OPEN;
    hdr->ver_flags = PCEP_COMMON_HEADER_VER_FLAGS;

    memcpy(buffer + sizeof(struct pcep_header), obj, ntohs(obj->header.object_length));

    free(obj);

    return hdr;
}

struct pcep_header*
pcep_msg_create_open_with_tlvs(uint8_t keepalive, uint8_t deadtimer, uint8_t sid, double_linked_list *tlv_list)
{
    uint8_t *buffer;
    uint16_t buffer_len;
    uint16_t tlv_len = 0;
    struct pcep_object_open *obj;
    struct pcep_header *hdr;

    /* Calculate the extra buffer size needed for the TLVs */
    double_linked_list_node *tlv_node = tlv_list->head;
    for(; tlv_node != NULL; tlv_node = tlv_node->next_node)
    {
        struct pcep_object_tlv *tlv = tlv_node->data;
        tlv_len += sizeof(struct pcep_object_tlv_header) + ntohs(tlv->header.length);
    }

    obj = pcep_obj_create_open(keepalive, deadtimer, sid);
    obj->header.object_length = htons(ntohs(obj->header.object_length) + tlv_len);

    buffer_len = sizeof(struct pcep_header) + ntohs(obj->header.object_length);
    buffer = malloc(sizeof(uint8_t) * buffer_len);
    bzero(buffer, buffer_len);

    hdr = (struct pcep_header*) buffer;
    hdr->length = htons(buffer_len);
    hdr->type = PCEP_TYPE_OPEN;
    hdr->ver_flags = PCEP_COMMON_HEADER_VER_FLAGS;

    memcpy(buffer + sizeof(struct pcep_header), obj, sizeof(struct pcep_object_open));

    /* memcpy the TLVs */
    int index = sizeof(struct pcep_header) + sizeof(struct pcep_object_open);
    tlv_node = tlv_list->head;
    for(; tlv_node != NULL; tlv_node = tlv_node->next_node)
    {
        struct pcep_object_tlv *tlv = tlv_node->data;
        memcpy(buffer + index, tlv,
               sizeof(struct pcep_object_tlv_header) + ntohs(tlv->header.length));
        index += sizeof(struct pcep_object_tlv_header) + ntohs(tlv->header.length);
    }

    free(obj);

    return hdr;
}

static uint32_t
pcep_msg_get_request_id(struct pcep_header *hdr)
{
    uint8_t *buffer = (uint8_t*)hdr;
    uint16_t buffer_len = ntohs(hdr->length);
    uint16_t buffer_pos = sizeof(struct pcep_header);

    while(buffer_pos < buffer_len) {
        struct pcep_object_header *obj = (struct pcep_object_header*)(buffer + buffer_pos);

        if((obj->object_class == PCEP_OBJ_CLASS_RP) &&
           (obj->object_type == PCEP_OBJ_TYPE_RP)) {
            struct pcep_object_rp *rp = (struct pcep_object_rp*)(buffer + buffer_pos);

            return ntohl(rp->rp_reqidnumb);
        }

        buffer_pos += ntohl(obj->object_length);
    }

    fprintf(stderr, "WARNING pcep_msg_get_request_id: Failed to find the RP object.\n");

    return 0;
}

struct pcep_header*
pcep_msg_create_request_svec(struct pcep_header **requests, uint16_t request_count, float disjointness)
{
    int i;
    uint8_t *buffer;
    uint16_t buffer_len = 0;
    uint16_t buffer_pos = 0;

    uint32_t *svec_id_list;

    struct pcep_header *hdr;
    struct pcep_object_svec *svec;

    svec_id_list = malloc(request_count * sizeof(uint32_t));

    for(i = 0; i < request_count; i++) {
        svec_id_list[i] = pcep_msg_get_request_id(requests[i]);
        buffer_len += (ntohs(requests[i]->length) - sizeof(struct pcep_header));

        if(svec_id_list[i] == 0) {
            free(svec_id_list);
            return NULL;
        }
    }

    svec = pcep_obj_create_svec(TRUE, TRUE, TRUE, request_count, svec_id_list);
    svec->reserved_disjointness = (uint8_t) (disjointness * 100);

    buffer_len += ntohs(svec->header.object_length);
    buffer_len += sizeof(struct pcep_header);
    buffer_pos = sizeof(struct pcep_header);
    buffer = (uint8_t*) malloc(buffer_len * sizeof(uint8_t));

    bzero(buffer, buffer_len);

    hdr = (struct pcep_header*) buffer;
    hdr->length = htons(buffer_len);
    hdr->type = PCEP_TYPE_PCREQ;
    hdr->ver_flags = PCEP_COMMON_HEADER_VER_FLAGS;

    //<PCReq Message>::= <Common Header>
    //                    [<svec-list>]
    //                    <request-list>

    memcpy(buffer + buffer_pos, svec, ntohs(svec->header.object_length));
    buffer_pos += ntohs(svec->header.object_length);

    for(i = 0; i < request_count; i++) {
        uint16_t cpy_len = ntohs(requests[i]->length) - sizeof(struct pcep_header);
        memcpy(buffer + buffer_pos, ((uint8_t*)requests[i]) + sizeof(struct pcep_header), cpy_len);
        buffer_pos += cpy_len;
    }

    free(svec);
    free(svec_id_list);

    return hdr;
}

struct pcep_header*
pcep_msg_create_request(struct pcep_object_rp *rp,  struct pcep_object_endpoints_ipv4 *enpoints, struct pcep_object_bandwidth *bandwidth)
{
    uint8_t *buffer;
    uint16_t buffer_len;
    uint16_t buffer_pos;
    struct pcep_header *hdr;

    if((rp == NULL) || (enpoints == NULL)) return NULL;

    buffer_len = sizeof(struct pcep_header);
    buffer_pos = sizeof(struct pcep_header);

    if(rp != NULL) {
        buffer_len += ntohs(rp->header.object_length);
    }
    if(enpoints != NULL) {
        buffer_len += ntohs(enpoints->header.object_length);
    }
    if(bandwidth != NULL) {
        buffer_len += ntohs(bandwidth->header.object_length);
    }

    buffer = malloc(sizeof(uint8_t) * buffer_len);

    bzero(buffer, buffer_len);

    hdr = (struct pcep_header*) buffer;
    hdr->length = htons(buffer_len);
    hdr->type = PCEP_TYPE_PCREQ;
    hdr->ver_flags = PCEP_COMMON_HEADER_VER_FLAGS;

    if(rp != NULL) {
        memcpy(buffer + buffer_pos, rp, ntohs(rp->header.object_length));
        buffer_pos += ntohs(rp->header.object_length);
    }
    if(enpoints != NULL) {
        memcpy(buffer + buffer_pos, enpoints, ntohs(enpoints->header.object_length));
        buffer_pos += ntohs(enpoints->header.object_length);
    }
    if(bandwidth != NULL) {
        memcpy(buffer + buffer_pos, bandwidth, ntohs(bandwidth->header.object_length));
        buffer_pos += ntohs(bandwidth->header.object_length);
    }

    return hdr;
}

struct pcep_header*
pcep_msg_create_response_nopath(struct pcep_object_rp *rp,  struct pcep_object_nopath* nopath)
{
    uint8_t *buffer;
    uint16_t buffer_len;
    uint16_t buffer_pos;
    struct pcep_header *hdr;

    buffer_len = sizeof(struct pcep_header);
    buffer_pos = sizeof(struct pcep_header);

    if(rp != NULL) {
        buffer_len += ntohs(rp->header.object_length);
    }
    if(nopath != NULL) {
        buffer_len += ntohs(nopath->header.object_length);
    }

    buffer = malloc(sizeof(uint8_t) * buffer_len);

    bzero(buffer, buffer_len);

    hdr = (struct pcep_header*) buffer;
    hdr->length = htons(buffer_len);
    hdr->type = PCEP_TYPE_PCREP;
    hdr->ver_flags = PCEP_COMMON_HEADER_VER_FLAGS;

    if(rp != NULL) {
        memcpy(buffer + buffer_pos, rp, ntohs(rp->header.object_length));
        buffer_pos += ntohs(rp->header.object_length);
    }
    if(nopath != NULL) {
        memcpy(buffer + buffer_pos, nopath, ntohs(nopath->header.object_length));
        buffer_pos += ntohs(nopath->header.object_length);
    }

    return hdr;
}

struct pcep_header*
pcep_msg_create_response(struct pcep_object_rp *rp, double_linked_list *eros_list)
{
    uint8_t *buffer;
    uint16_t buffer_len;
    uint16_t buffer_pos;
    struct pcep_header *hdr;


    buffer_len = sizeof(struct pcep_header);
    buffer_pos = sizeof(struct pcep_header);

    if(rp != NULL) {
        buffer_len += ntohs(rp->header.object_length);
    }

    /* Calculate the buffer_len by summing the length
     * of all the eros items in the eros_list */
    if (eros_list != NULL) {
        double_linked_list_node *eros_item;
        for (eros_item = eros_list->head;
                eros_item != NULL;
                eros_item = eros_item->next_node) {
            buffer_len += ntohs(((struct pcep_object_route_object*) (eros_item->data))->ro_hdr.header.object_length);
        }
    }

    buffer = malloc(sizeof(uint8_t) * buffer_len);

    bzero(buffer, buffer_len);

    hdr = (struct pcep_header*) buffer;
    hdr->length = htons(buffer_len);
    hdr->type = PCEP_TYPE_PCREP;
    hdr->ver_flags = PCEP_COMMON_HEADER_VER_FLAGS;

    if(rp != NULL) {
        memcpy(buffer + buffer_pos, rp, ntohs(rp->header.object_length));
        buffer_pos += ntohs(rp->header.object_length);
    }

    if (eros_list != NULL) {
        double_linked_list_node *eros_item;
        for (eros_item = eros_list->head;
                eros_item != NULL;
                eros_item = eros_item->next_node) {
            struct pcep_ro_subobj_hdr *ero_subobj;

            memcpy(buffer + buffer_pos,
                    &((struct pcep_object_route_object*) eros_item->data)->ro_hdr.header,
                    sizeof(struct pcep_object_ro));
            buffer_pos += sizeof(struct pcep_object_ro);

            double_linked_list_node *ero_item;
            for (ero_item = ((struct pcep_object_route_object*) eros_item->data)->ro_list->head;
                    ero_item != NULL;
                    ero_item = ero_item->next_node) {
                ero_subobj = (struct pcep_ro_subobj_hdr*) ero_item->data;
                memcpy(buffer + buffer_pos, ero_subobj, ero_subobj->length);
                buffer_pos += ero_subobj->length;
            }
        }
    }

    return hdr;
}

struct pcep_header*
pcep_msg_create_close(uint8_t flags, uint8_t reason)
{
    uint8_t *buffer;
    uint16_t buffer_len;
    struct pcep_object_close *obj;
    struct pcep_header *hdr;

    obj = pcep_obj_create_close(flags, reason);

    buffer_len = sizeof(struct pcep_header) + ntohs(obj->header.object_length);
    buffer = malloc(sizeof(uint8_t) * buffer_len);

    bzero(buffer, buffer_len);

    hdr = (struct pcep_header*) buffer;
    hdr->length = htons(buffer_len);
    hdr->type = PCEP_TYPE_CLOSE;
    hdr->ver_flags = PCEP_COMMON_HEADER_VER_FLAGS;

    memcpy(buffer + sizeof(struct pcep_header), obj, ntohs(obj->header.object_length));

    free(obj);

    return hdr;
}

struct pcep_header*
pcep_msg_create_error(uint8_t error_type, uint8_t error_value)
{
    uint8_t *buffer;
    uint16_t buffer_len;
    struct pcep_object_error *obj;
    struct pcep_header *hdr;

    obj = pcep_obj_create_error(error_type, error_value);

    buffer_len = sizeof(struct pcep_header) + ntohs(obj->header.object_length);
    buffer = malloc(sizeof(uint8_t) * buffer_len);

    bzero(buffer, buffer_len);

    hdr = (struct pcep_header*) buffer;
    hdr->length = htons(buffer_len);
    hdr->type = PCEP_TYPE_ERROR;
    hdr->ver_flags = PCEP_COMMON_HEADER_VER_FLAGS;

    memcpy(buffer + sizeof(struct pcep_header), obj, ntohs(obj->header.object_length));

    free(obj);

    return hdr;
}

struct pcep_header*
pcep_msg_create_keepalive()
{
    uint8_t *buffer;
    uint16_t buffer_len;

    struct pcep_header *hdr;

    buffer_len = sizeof(struct pcep_header);
    buffer = malloc(sizeof(uint8_t) * buffer_len);

    bzero(buffer, buffer_len);

    hdr = (struct pcep_header*) buffer;
    hdr->length = htons(buffer_len);
    hdr->type = PCEP_TYPE_KEEPALIVE;
    hdr->ver_flags = PCEP_COMMON_HEADER_VER_FLAGS;

    return hdr;
}

void
pcep_unpack_msg_header(struct pcep_header* hdr)
{
    hdr->length = ntohs(hdr->length);
}

