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

    obj = pcep_obj_create_open(keepalive, deadtimer, sid, NULL);

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
    struct pcep_object_open *obj;
    struct pcep_header *hdr;

    obj = pcep_obj_create_open(keepalive, deadtimer, sid, tlv_list);

    buffer_len = sizeof(struct pcep_header) + ntohs(obj->header.object_length);
    buffer = malloc(buffer_len);
    bzero(buffer, buffer_len);

    hdr = (struct pcep_header*) buffer;
    hdr->length = htons(buffer_len);
    hdr->type = PCEP_TYPE_OPEN;
    hdr->ver_flags = PCEP_COMMON_HEADER_VER_FLAGS;

    /* Copy the Open object to the message buffer, and free the object */
    memcpy(buffer + sizeof(struct pcep_header), obj, ntohs(obj->header.object_length));
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
pcep_msg_create_reply_nopath(struct pcep_object_rp *rp,  struct pcep_object_nopath* nopath)
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
pcep_msg_create_reply(struct pcep_object_rp *rp, double_linked_list *object_list)
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
     * of all the objects in the object_list */
    if (object_list != NULL) {
        double_linked_list_node *object;
        for (object = object_list->head; object != NULL; object = object->next_node) {
            buffer_len += ntohs(((struct pcep_object_header*) (object->data))->object_length);
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

    if (object_list != NULL) {
        double_linked_list_node *object;
        for (object = object_list->head; object != NULL; object = object->next_node) {
            memcpy(buffer + buffer_pos, object->data,
                   ntohs(((struct pcep_object_header*) object->data)->object_length));
            buffer_pos += ntohs(((struct pcep_object_header*) object->data)->object_length);
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

/* Common message creation function to handle double_linked_list of
 * objects, Used by pcep_msg_create_report(), pcep_msg_create_update(),
 * and pcep_msg_create_initiate() */
static struct pcep_header*
pcep_msg_create_from_object_list(double_linked_list *object_list)
{
    /* Messaged defined in RFC 8231 */

    if (object_list == NULL)
    {
        fprintf(stderr, "pcep_msg_create_from_object_list NULL object_list\n");
        return NULL;
    }

    if (object_list->num_entries == 0)
    {
        fprintf(stderr, "pcep_msg_create_from_object_list empty object_list\n");
        return NULL;
    }

    int buffer_len = sizeof(struct pcep_header);
    double_linked_list_node *node = object_list->head;
    for(; node != NULL; node = node->next_node)
    {
        struct pcep_object_header *obj_hdr = (struct pcep_object_header*) node->data;
        buffer_len += ntohs(obj_hdr->object_length);
    }

    uint8_t *buffer = malloc(buffer_len);
    struct pcep_header *hdr = (struct pcep_header *) buffer;
    hdr->length = htons(buffer_len);
    hdr->type = 0; /* Should be filled in by calling function */
    hdr->ver_flags = PCEP_COMMON_HEADER_VER_FLAGS;

    int index = sizeof(struct pcep_header);
    node = object_list->head;
    for(; node != NULL; node = node->next_node)
    {
        struct pcep_object_header *obj_hdr = (struct pcep_object_header*) node->data;
        memcpy(buffer + index, obj_hdr, ntohs(obj_hdr->object_length));
        index += ntohs(obj_hdr->object_length);
    }

    return hdr;
}

struct pcep_header*
pcep_msg_create_report(double_linked_list *state_report_object_list)
{
    struct pcep_header* report =
            pcep_msg_create_from_object_list(state_report_object_list);
    if (report != NULL)
    {
        report->type = PCEP_TYPE_REPORT;
    }

    return report;
}

struct pcep_header*
pcep_msg_create_update(double_linked_list *update_request_object_list)
{
    if (update_request_object_list == NULL)
    {
        fprintf(stderr, "pcep_msg_create_update NULL update_request_object_list\n");
        return NULL;
    }

    /* There must be at least 3 objects:
     * These 3 are mandatory: SRP, LSP, and ERO. The ERO may be empty */
    if (update_request_object_list->num_entries < 3)
    {
        fprintf(stderr, "pcep_msg_create_update there must be at least 3 update objects\n");
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
        fprintf(stderr, "pcep_msg_create_update missing mandatory first SRP object\n");
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
        fprintf(stderr, "pcep_msg_create_update missing mandatory second LSP object\n");
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
        fprintf(stderr, "pcep_msg_create_update missing mandatory third ERO object\n");
        return NULL;
    }

    struct pcep_header* update =
            pcep_msg_create_from_object_list(update_request_object_list);
    if (update != NULL)
    {
        update->type = PCEP_TYPE_UPDATE;
    }

    return update;
}

struct pcep_header*
pcep_msg_create_initiate(double_linked_list *lsp_object_list)
{
    if (lsp_object_list == NULL)
    {
        fprintf(stderr, "pcep_msg_create_initiate NULL update_request_object_list\n");
        return NULL;
    }

    /* There must be at least 2 objects: SRP and LSP. */
    if (lsp_object_list->num_entries < 2)
    {
        fprintf(stderr, "pcep_msg_create_initiate there must be at least 2 objects\n");
        return NULL;
    }

    double_linked_list_node *node = lsp_object_list->head;
    struct pcep_object_header *obj_hdr = (struct pcep_object_header*) node->data;

    /* Check for the mandatory first SRP object */
    if (obj_hdr->object_class != PCEP_OBJ_CLASS_SRP)
    {
        fprintf(stderr, "pcep_msg_create_initiate missing mandatory first SRP object\n");
        return NULL;
    }

    /* Check for the mandatory 2nd LSP object */
    node = node->next_node;
    obj_hdr = (struct pcep_object_header*) node->data;
    if (obj_hdr->object_class != PCEP_OBJ_CLASS_LSP)
    {
        fprintf(stderr, "pcep_msg_create_initiate missing mandatory second LSP object\n");
        return NULL;
    }

    struct pcep_header* initiate =
            pcep_msg_create_from_object_list(lsp_object_list);
    if (initiate != NULL)
    {
        initiate->type = PCEP_TYPE_INITIATE;
    }

    return initiate;
}

void
pcep_unpack_msg_header(struct pcep_header* hdr)
{
    hdr->length = ntohs(hdr->length);
}

