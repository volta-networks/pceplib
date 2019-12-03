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

#include "pcep_utils_double_linked_list.h"
#include "pcep-objects.h"
#include "pcep-tlvs.h"

/* Internal common function used to create a pcep_object and populate the header */
static struct pcep_object_header*
pcep_obj_create_common(uint16_t buffer_len, uint8_t object_class, uint8_t object_type)
{
    uint8_t *buffer = malloc(buffer_len);
    bzero(buffer, buffer_len);

    struct pcep_object_header *hdr = (struct pcep_object_header *) buffer;
    hdr->object_class = object_class;
    hdr->object_type = object_type;
    hdr->object_length = htons(buffer_len);

    return hdr;
}

static uint16_t get_tlvs_length(double_linked_list *tlv_list)
{
    if (tlv_list == NULL)
    {
        return 0;
    }

    uint16_t tlvs_length = 0;
    double_linked_list_node *node = tlv_list->head;
    for( ; node != NULL; node = node->next_node)
    {
        struct pcep_object_tlv_header *tlv = (struct pcep_object_tlv_header *) node->data;
        /* The TLV length does not include the length of the header, but
         * that needs to be included for the object length calculations. */
        tlvs_length += ntohs(tlv->length) + sizeof(struct pcep_object_tlv_header);
    }

    /* The TLV length does not include padding, but
     * must be included in the enclosing object */
    if (tlvs_length % 4 != 0)
    {
        tlvs_length += (4 - (tlvs_length % 4));
    }

    return tlvs_length;
}

static void append_tlvs(struct pcep_object_header *obj, uint16_t index, double_linked_list *tlv_list)
{
    if (tlv_list == NULL)
    {
        return;
    }

    uint16_t buffer_index = index;
    double_linked_list_node *node = tlv_list->head;
    for( ; node != NULL; node = node->next_node)
    {
        struct pcep_object_tlv_header *tlv = (struct pcep_object_tlv_header *) node->data;
        /* Any pad bytes are not specified in the TLV length, but mus be copied */
        int length = ntohs(tlv->length) + sizeof(struct pcep_object_tlv_header);
        if (length % 4 != 0)
        {
            length += (4 - (length % 4));
        }
        memcpy(((uint8_t *) obj) + buffer_index, tlv, length);
        buffer_index += length;
    }
}

struct pcep_object_open*
pcep_obj_create_open(uint8_t keepalive, uint8_t deadtimer, uint8_t sid, double_linked_list *tlv_list)
{
    uint16_t tlv_length = get_tlvs_length(tlv_list);

    struct pcep_object_open *open =
            (struct pcep_object_open *) pcep_obj_create_common(
                    sizeof(struct pcep_object_open) + tlv_length,
                    PCEP_OBJ_CLASS_OPEN, PCEP_OBJ_TYPE_OPEN);

    open->open_ver_flags = 1<<5;        // PCEP version. Current version is 1 /No flags are currently defined.
    open->open_keepalive = keepalive;   // Maximum period of time between two consecutive PCEP messages sent by the sender.
    open->open_deadtimer = deadtimer;   // Specifies the amount of time before closing the session down.
    open->open_sid = sid;               // PCEP session number that identifies the current session.

    append_tlvs((struct pcep_object_header *) open, sizeof(struct pcep_object_open), tlv_list);

    return open;
}

struct pcep_object_rp*
pcep_obj_create_rp(uint8_t obj_hdr_flags, uint32_t obj_flags, uint32_t reqid, double_linked_list *tlv_list)
{
    uint16_t tlv_length = get_tlvs_length(tlv_list);

    struct pcep_object_rp *obj =
            (struct pcep_object_rp *) pcep_obj_create_common(
                    sizeof(struct pcep_object_rp) + tlv_length,
                    PCEP_OBJ_CLASS_RP, PCEP_OBJ_TYPE_RP);

    obj->header.object_flags = obj_hdr_flags;
    obj->rp_flags = obj_flags;  //|O|B|R|Pri|
    obj->rp_reqidnumb = htonl(reqid); //Set the request id

    append_tlvs((struct pcep_object_header *) obj, sizeof(struct pcep_object_rp), tlv_list);

    return obj;
}

struct pcep_object_nopath*
pcep_obj_create_nopath(uint8_t obj_hdr_flags, uint8_t ni, uint16_t unsat_constr_flag, uint32_t errorcode)
{
    struct pcep_object_nopath *obj =
            (struct pcep_object_nopath *) pcep_obj_create_common(
                    sizeof(struct pcep_object_nopath) + 4, /* Adding 4 bytes for the TLV value */
                    PCEP_OBJ_CLASS_NOPATH, PCEP_OBJ_TYPE_NOPATH);

    obj->header.object_flags = obj_hdr_flags;
    obj->ni = ni;
    obj->flags = htons(unsat_constr_flag << 15);
    obj->reserved = 0;
    obj->err_code.header.type = htons(1); // Type 1 from IANA
    obj->err_code.header.length = htons(sizeof(uint32_t));
    obj->err_code.value[0] = htonl(errorcode);

    return obj;
}

struct pcep_object_endpoints_ipv4*
pcep_obj_create_enpoint_ipv4(const struct in_addr* src_ipv4, const struct in_addr* dst_ipv4)
{
    if (src_ipv4 == NULL || dst_ipv4 == NULL)
    {
        return NULL;
    }

    struct pcep_object_endpoints_ipv4 *obj =
            (struct pcep_object_endpoints_ipv4 *) pcep_obj_create_common(
                    sizeof(struct pcep_object_endpoints_ipv4),
                    PCEP_OBJ_CLASS_ENDPOINTS, PCEP_OBJ_TYPE_ENDPOINT_IPV4);

    obj->src_ipv4.s_addr = htonl(src_ipv4->s_addr);
    obj->dst_ipv4.s_addr = htonl(dst_ipv4->s_addr);

    return obj;
}

struct pcep_object_endpoints_ipv6*
pcep_obj_create_enpoint_ipv6(const struct in6_addr* src_ipv6, const struct in6_addr* dst_ipv6)
{
    if (src_ipv6 == NULL || dst_ipv6 == NULL)
    {
        return NULL;
    }

    struct pcep_object_endpoints_ipv6 *obj =
            (struct pcep_object_endpoints_ipv6 *) pcep_obj_create_common(
                    sizeof(struct pcep_object_endpoints_ipv6),
                    PCEP_OBJ_CLASS_ENDPOINTS, PCEP_OBJ_TYPE_ENDPOINT_IPV6);

    obj->src_ipv6.__in6_u.__u6_addr32[0] = htonl(src_ipv6->__in6_u.__u6_addr32[0]);
    obj->src_ipv6.__in6_u.__u6_addr32[1] = htonl(src_ipv6->__in6_u.__u6_addr32[1]);
    obj->src_ipv6.__in6_u.__u6_addr32[2] = htonl(src_ipv6->__in6_u.__u6_addr32[2]);
    obj->src_ipv6.__in6_u.__u6_addr32[3] = htonl(src_ipv6->__in6_u.__u6_addr32[3]);

    obj->dst_ipv6.__in6_u.__u6_addr32[0] = htonl(dst_ipv6->__in6_u.__u6_addr32[0]);
    obj->dst_ipv6.__in6_u.__u6_addr32[1] = htonl(dst_ipv6->__in6_u.__u6_addr32[1]);
    obj->dst_ipv6.__in6_u.__u6_addr32[2] = htonl(dst_ipv6->__in6_u.__u6_addr32[2]);
    obj->dst_ipv6.__in6_u.__u6_addr32[3] = htonl(dst_ipv6->__in6_u.__u6_addr32[3]);

    return obj;
}

struct pcep_object_bandwidth*
pcep_obj_create_bandwidth(float bandwidth)
{
    struct pcep_object_bandwidth *obj =
            (struct pcep_object_bandwidth *) pcep_obj_create_common(
                    sizeof(struct pcep_object_bandwidth),
                    PCEP_OBJ_CLASS_BANDWIDTH, PCEP_OBJ_TYPE_BANDWIDTH_REQ);

    obj->bandwidth = bandwidth;

    return obj;
}

struct pcep_object_metric*
pcep_obj_create_metric(uint8_t flags, uint8_t type, float value)
{
    struct pcep_object_metric *obj =
            (struct pcep_object_metric*) pcep_obj_create_common(
                    sizeof(struct pcep_object_metric),
                    PCEP_OBJ_CLASS_METRIC, PCEP_OBJ_TYPE_METRIC);

    obj->flags = flags;
    obj->type  = type;
    obj->value = value;

    return obj;
}

struct pcep_object_lspa*
pcep_obj_create_lspa(uint8_t prio, uint8_t hold_prio)
{
    struct pcep_object_lspa *obj =
            (struct pcep_object_lspa*) pcep_obj_create_common(
                    sizeof(struct pcep_object_lspa),
                    PCEP_OBJ_CLASS_LSPA, PCEP_OBJ_TYPE_LSPA);

    obj->lspa_prio = prio;
    obj->lspa_holdprio = hold_prio;

    return obj;
}

uint32_t*
pcep_obj_svec_get(struct pcep_object_svec* obj, uint16_t *length)
{
    uint8_t *buff = (uint8_t*) obj;

    *length = (obj->header.object_length - sizeof(struct pcep_object_svec)) / sizeof(uint32_t);

    return (uint32_t*)(buff + sizeof(struct pcep_object_svec));
}

void
pcep_obj_svec_print(struct pcep_object_svec* obj)
{
    uint16_t len;
    uint32_t i = 0;
    uint32_t *array = pcep_obj_svec_get(obj, &len);

    printf("PCEP_OBJ_CLASS_SVEC request IDs:\n");

    for(i = 0; i < len; i++) {
        printf("\tID: 0x%x\n", array[i]);
    }
}

struct pcep_object_svec*
pcep_obj_create_svec(bool srlg, bool node, bool link, uint16_t ids_count, uint32_t *ids)
{
    if (ids == NULL)
    {
        return NULL;
    }

    struct pcep_object_svec *obj =
            (struct pcep_object_svec*) pcep_obj_create_common(
                    sizeof(struct pcep_object_svec) + (ids_count*sizeof(uint32_t)),
                    PCEP_OBJ_CLASS_SVEC, PCEP_OBJ_TYPE_SVEC);

    obj->flag_srlg = (srlg == true ? 1 : 0);
    obj->flag_node = (node == true ? 1 : 0);
    obj->flag_link = (link == true ? 1 : 0);

    uint32_t i;
    uint32_t *svec_ids = (uint32_t *) (((uint8_t *) obj) + sizeof(struct pcep_object_svec));
    for(i = 0; i < ids_count; i++) {
        svec_ids[i] = htonl(ids[i]);
    }

    return obj;
}

struct pcep_object_error*
pcep_obj_create_error(uint8_t error_type, uint8_t error_value)
{
    struct pcep_object_error *obj =
            (struct pcep_object_error*) pcep_obj_create_common(
                    sizeof(struct pcep_object_error),
                    PCEP_OBJ_CLASS_ERROR, PCEP_OBJ_TYPE_ERROR);

    obj->error_type = error_type;
    obj->error_value = error_value;

    return obj;
}

struct pcep_object_close*
pcep_obj_create_close(uint8_t flags, uint8_t reason)
{
    struct pcep_object_close *obj =
            (struct pcep_object_close*) pcep_obj_create_common(
                    sizeof(struct pcep_object_close),
                    PCEP_OBJ_CLASS_CLOSE, PCEP_OBJ_TYPE_CLOSE);

    obj->flags = flags;
    obj->reason = reason;

    return obj;
}

struct pcep_object_srp*
pcep_obj_create_srp(bool lsp_remove, uint32_t srp_id_number, double_linked_list *tlv_list)
{
    uint16_t tlv_length = get_tlvs_length(tlv_list);

    struct pcep_object_srp *obj =
            (struct pcep_object_srp*) pcep_obj_create_common(
                    sizeof(struct pcep_object_srp) + tlv_length,
                    PCEP_OBJ_CLASS_SRP, PCEP_OBJ_TYPE_SRP);

    obj->lsp_remove = (lsp_remove == true ? 1 : 0);
    obj->srp_id_number = htonl(srp_id_number);

    append_tlvs((struct pcep_object_header *) obj, sizeof(struct pcep_object_srp), tlv_list);

    return obj;
}

struct pcep_object_lsp*
pcep_obj_create_lsp(uint32_t plsp_id, enum pcep_lsp_operational_status status,
                    bool c_flag, bool a_flag, bool r_flag, bool s_flag, bool d_flag,
                    double_linked_list *tlv_list)
{
    /* The plsp_id is only 20 bits */
    if (plsp_id > MAX_PLSP_ID)
    {
        fprintf(stderr, "pcep_obj_create_lsp invalid plsp_id [%d] max value [%d]\n",
                plsp_id, MAX_PLSP_ID);
        return NULL;
    }

    /* The status is only 3 bits */
    if (status > MAX_LSP_STATUS)
    {
        fprintf(stderr, "pcep_obj_create_lsp invalid status [%d] max value [%d]\n",
                plsp_id, MAX_PLSP_ID);
        return NULL;
    }

    uint16_t tlv_length = get_tlvs_length(tlv_list);

    struct pcep_object_lsp *obj =
            (struct pcep_object_lsp*) pcep_obj_create_common(
                    sizeof(struct pcep_object_lsp) + tlv_length,
                    PCEP_OBJ_CLASS_LSP, PCEP_OBJ_TYPE_LSP);

    obj->plsp_id_flags = (0xfffff000 & (plsp_id << 12));
    obj->plsp_id_flags |= status;
    obj->plsp_id_flags |= (c_flag == true ? PCEP_LSP_C_FLAG : 0);
    obj->plsp_id_flags |= (a_flag == true ? PCEP_LSP_A_FLAG : 0);
    obj->plsp_id_flags |= (r_flag == true ? PCEP_LSP_R_FLAG : 0);
    obj->plsp_id_flags |= (s_flag == true ? PCEP_LSP_S_FLAG : 0);
    obj->plsp_id_flags |= (d_flag == true ? PCEP_LSP_D_FLAG : 0);

    /* Convert the plsp_id and flags to network byte order */
    obj->plsp_id_flags = htonl(obj->plsp_id_flags);

    append_tlvs((struct pcep_object_header *) obj, sizeof(struct pcep_object_lsp), tlv_list);

    return obj;
}

/* Internal common function used to create a pcep_object_route_object,
 * used internally by:
 *     pcep_obj_create_ero()
 *     pcep_obj_create_iro()
 *     pcep_obj_create_rro() */
static struct pcep_object_ro*
pcep_obj_create_common_route_object(double_linked_list* ro_list)
{
    uint16_t buffer_len = sizeof(struct pcep_object_ro);

    if (ro_list != NULL)
    {
        double_linked_list_node *node;
        for (node = ro_list->head; node != NULL; node = node->next_node)
        {
            struct pcep_ro_subobj_hdr *subobj = (struct pcep_ro_subobj_hdr*) node->data;
            buffer_len += subobj->length;
        }
    }

    uint8_t *buffer = malloc(buffer_len);
    bzero(buffer, buffer_len);

    /* object_class and object_type MUST be set by calling functions */
    struct pcep_object_ro *route_object = (struct pcep_object_ro *) buffer;
    route_object->header.object_flags = 0;
    route_object->header.object_length = htons(buffer_len);

    if (ro_list != NULL)
    {
        uint8_t index = sizeof(struct pcep_object_ro);
        double_linked_list_node *node;
        for (node = ro_list->head; node != NULL; node = node->next_node)
        {
            struct pcep_ro_subobj_hdr *subobj = (struct pcep_ro_subobj_hdr*) node->data;
            memcpy(buffer + index, subobj, subobj->length);
            index += subobj->length;
        }
    }

    return route_object;
}

/* Wrap a list of ro subobjects in a structure with an object header */
struct pcep_object_ro*
pcep_obj_create_ero(double_linked_list* ero_list)
{
    struct pcep_object_ro *ero = pcep_obj_create_common_route_object(ero_list);
    ero->header.object_class = PCEP_OBJ_CLASS_ERO;
    ero->header.object_type = PCEP_OBJ_TYPE_ERO;

    return ero;
}

/* Wrap a list of ro subobjects in a structure with an object header */
struct pcep_object_ro*
pcep_obj_create_iro(double_linked_list* iro_list)
{
    struct pcep_object_ro *iro = pcep_obj_create_common_route_object(iro_list);
    iro->header.object_class = PCEP_OBJ_CLASS_IRO;
    iro->header.object_type = PCEP_OBJ_TYPE_IRO;

    return iro;
}

/* Wrap a list of ro subobjects in a structure with an object header */
struct pcep_object_ro*
pcep_obj_create_rro(double_linked_list* rro_list)
{
    struct pcep_object_ro *rro = pcep_obj_create_common_route_object(rro_list);
    rro->header.object_class = PCEP_OBJ_CLASS_RRO;
    rro->header.object_type = PCEP_OBJ_TYPE_RRO;

    return rro;
}

/*
 * Route Object Sub-object creation functions
 */

static struct pcep_object_ro_subobj*
pcep_obj_create_ro_subobj_common()
{
    uint8_t *buffer = malloc(sizeof(struct pcep_object_ro_subobj));
    bzero(buffer, sizeof(struct pcep_object_ro_subobj));

    return (struct pcep_object_ro_subobj*) buffer;
}

struct pcep_object_ro_subobj*
pcep_obj_create_ro_subobj_unnum(struct in_addr* router_id, uint32_t ifId, uint16_t resv)
{
    if (router_id == NULL)
    {
        return NULL;
    }

    struct pcep_object_ro_subobj *obj = pcep_obj_create_ro_subobj_common();

    obj->subobj.unnum.header.length = sizeof(struct pcep_ro_subobj_unnum);
    obj->subobj.unnum.header.type = RO_SUBOBJ_TYPE_UNNUM;
    obj->subobj.unnum.ifId = htonl(ifId);

    obj->subobj.unnum.routerId.s_addr = htonl(router_id->s_addr);
    obj->subobj.unnum.resv = htons(resv);

    return obj;
}

struct pcep_object_ro_subobj*
pcep_obj_create_ro_subobj_32label(uint8_t dir, uint32_t label)
{
    struct pcep_object_ro_subobj *obj = pcep_obj_create_ro_subobj_common();

    obj->subobj.label.header.length = sizeof(struct pcep_ro_subobj_32label);
    obj->subobj.label.header.type = RO_SUBOBJ_TYPE_LABEL;
    obj->subobj.label.class_type = 2;
    obj->subobj.label.upstream = dir;
    obj->subobj.label.label = htonl(label);

    return obj;
}

struct pcep_object_ro_subobj*
pcep_obj_create_ro_subobj_border(uint8_t direction, uint8_t swcap_from, uint8_t swcap_to)
{
    struct pcep_object_ro_subobj *obj = pcep_obj_create_ro_subobj_common();

    obj->subobj.border.header.length = sizeof(struct pcep_ro_subobj_border);
    obj->subobj.border.header.type = RO_SUBOBJ_TYPE_BORDER;
    obj->subobj.border.direction = direction;
    obj->subobj.border.swcap_from = swcap_from;
    obj->subobj.border.swcap_to = swcap_to;

    return obj;
}

struct pcep_object_ro_subobj*
pcep_obj_create_ro_subobj_ipv4(bool loose_hop, const struct in_addr* rro_ipv4, uint8_t prefix_length)
{
    if (rro_ipv4 == NULL)
    {
        return NULL;
    }

    struct pcep_object_ro_subobj *obj = pcep_obj_create_ro_subobj_common();

    obj->subobj.ipv4.header.length = sizeof(struct pcep_ro_subobj_ipv4);
    obj->subobj.ipv4.header.type = RO_SUBOBJ_TYPE_IPV4;
    obj->subobj.ipv4.prefix_length = prefix_length;
    obj->subobj.ipv4.ip_addr.s_addr = htonl(rro_ipv4->s_addr);
    if (loose_hop == true)
    {
        // The first bit of the type field is used to specify Loose Hop
        obj->subobj.ipv4.header.type |= LOOSE_HOP_BIT;
    }

    return obj;
}

struct pcep_object_ro_subobj*
pcep_obj_create_ro_subobj_ipv6(bool loose_hop, const struct in6_addr* rro_ipv6, uint8_t prefix_length)
{
    if (rro_ipv6 == NULL)
    {
        return NULL;
    }

    struct pcep_object_ro_subobj *obj = pcep_obj_create_ro_subobj_common();

    obj->subobj.ipv6.header.length = sizeof(struct pcep_ro_subobj_ipv6);
    obj->subobj.ipv6.header.type = RO_SUBOBJ_TYPE_IPV6;
    obj->subobj.ipv6.prefix_length = prefix_length;
    obj->subobj.ipv6.ip_addr.__in6_u.__u6_addr32[0] = htonl(rro_ipv6->__in6_u.__u6_addr32[0]);
    obj->subobj.ipv6.ip_addr.__in6_u.__u6_addr32[1] = htonl(rro_ipv6->__in6_u.__u6_addr32[1]);
    obj->subobj.ipv6.ip_addr.__in6_u.__u6_addr32[2] = htonl(rro_ipv6->__in6_u.__u6_addr32[2]);
    obj->subobj.ipv6.ip_addr.__in6_u.__u6_addr32[3] = htonl(rro_ipv6->__in6_u.__u6_addr32[3]);
    if (loose_hop == true)
    {
        // The first bit of the type field is used to specify Loose Hop
        obj->subobj.ipv6.header.type |= LOOSE_HOP_BIT;
    }

    return obj;
}

struct pcep_object_ro_subobj*
pcep_obj_create_ro_subobj_asn(uint16_t asn)
{
    struct pcep_object_ro_subobj *obj = pcep_obj_create_ro_subobj_common();

    obj->subobj.asn.header.length = sizeof(struct pcep_ro_subobj_asn);
    obj->subobj.asn.header.type = RO_SUBOBJ_TYPE_ASN;
    obj->subobj.asn.aut_sys_number = asn;

    return obj;
}

/* Internal util function to create pcep_object_ro_subobj sub-objects */
static struct pcep_object_ro_subobj*
pcep_obj_create_ro_subobj_sr_common(uint8_t extra_length, enum pcep_sr_subobj_nai nai,
        bool loose_hop, bool f_flag, bool s_flag, bool c_flag_in, bool m_flag_in)
{
    uint8_t *buffer = malloc(sizeof(struct pcep_object_ro_subobj) + extra_length);
    bzero(buffer, sizeof(struct pcep_object_ro_subobj));

    /* Flag logic according to draft-ietf-pce-segment-routing-16 */
    bool c_flag = c_flag_in;
    bool m_flag = m_flag_in;
    if (s_flag)
    {
        c_flag = false;
        m_flag = false;
    }

    if (m_flag == false)
    {
        c_flag = false;
    }

    struct pcep_object_ro_subobj *obj = (struct pcep_object_ro_subobj*) buffer;

    obj->subobj.sr.header.length = sizeof(struct pcep_ro_subobj_sr) + extra_length;
    obj->subobj.sr.header.type = RO_SUBOBJ_TYPE_SR;
    obj->subobj.sr.nt_flags = nai;

    obj->subobj.sr.nt_flags |= (f_flag == true) ? PCEP_SR_SUBOBJ_F_FLAG : 0;
    obj->subobj.sr.nt_flags |= (s_flag == true) ? PCEP_SR_SUBOBJ_S_FLAG : 0;
    obj->subobj.sr.nt_flags |= (c_flag == true) ? PCEP_SR_SUBOBJ_C_FLAG : 0;
    obj->subobj.sr.nt_flags |= (m_flag == true) ? PCEP_SR_SUBOBJ_M_FLAG : 0;
    obj->subobj.sr.nt_flags = htons(obj->subobj.sr.nt_flags);

    if (loose_hop == true)
    {
        // The first bit of the type field is used to specify Loose Hop
        obj->subobj.sr.header.type |= LOOSE_HOP_BIT;
    }

    return obj;
}

struct pcep_object_ro_subobj*
pcep_obj_create_ro_subobj_sr_nonai(bool loose_hop, uint32_t sid)
{
    /* According to draft-ietf-pce-segment-routing-16#section-5.2.1
     * If NT=0, the F bit MUST be 1, the S bit MUST be zero and the
     * Length MUST be 8. */
    struct pcep_object_ro_subobj *obj = pcep_obj_create_ro_subobj_sr_common(
            sizeof(uint32_t), PCEP_SR_SUBOBJ_NAI_ABSENT,
            loose_hop, true, false, false, false);
    obj->subobj.sr.sid_nai[0] = htonl(sid);

    return obj;
}

struct pcep_object_ro_subobj*
pcep_obj_create_ro_subobj_sr_ipv4_node(
        bool loose_hop, bool sid_absent, bool c_flag, bool m_flag,
        uint32_t sid, struct in_addr *ipv4_node_id)
{
    if (ipv4_node_id == NULL)
    {
        return NULL;
    }

    uint8_t extra_buf_len = (sid_absent ? sizeof(uint32_t) : sizeof(uint32_t) * 2);

    /* According to draft-ietf-pce-segment-routing-16#section-5.2.1
     * If NT=1, the F bit MUST be zero.  If the S bit is 1, the Length
     * MUST be 8, otherwise the Length MUST be 12 */
    struct pcep_object_ro_subobj *obj = pcep_obj_create_ro_subobj_sr_common(
            extra_buf_len, PCEP_SR_SUBOBJ_NAI_IPV4_NODE,
            loose_hop, false, sid_absent, c_flag, m_flag);

    int index = 0;
    if (! sid_absent)
    {
        obj->subobj.sr.sid_nai[index++] = htonl(sid);
    }
    obj->subobj.sr.sid_nai[index] = htonl(ipv4_node_id->s_addr);

    return obj;
}

struct pcep_object_ro_subobj*
pcep_obj_create_ro_subobj_sr_ipv6_node(
        bool loose_hop, bool sid_absent, bool c_flag, bool m_flag,
        uint32_t sid, struct in6_addr *ipv6_node_id)
{
    if (ipv6_node_id == NULL)
    {
        return NULL;
    }

    uint8_t extra_buf_len = sizeof(struct in6_addr);
    if (!sid_absent)
    {
        extra_buf_len += sizeof(uint32_t);
    }

    /* According to draft-ietf-pce-segment-routing-16#section-5.2.1
     * If NT=2, the F bit MUST be zero.  If the S bit is 1, the Length
     * MUST be 20, otherwise the Length MUST be 24. */
    struct pcep_object_ro_subobj *obj = pcep_obj_create_ro_subobj_sr_common(
            extra_buf_len, PCEP_SR_SUBOBJ_NAI_IPV6_NODE,
            loose_hop, false, sid_absent, c_flag, m_flag);

    int index = 0;
    if (! sid_absent)
    {
        obj->subobj.sr.sid_nai[index++] = htonl(sid);
    }
    obj->subobj.sr.sid_nai[index++] = htonl(ipv6_node_id->__in6_u.__u6_addr32[0]);
    obj->subobj.sr.sid_nai[index++] = htonl(ipv6_node_id->__in6_u.__u6_addr32[1]);
    obj->subobj.sr.sid_nai[index++] = htonl(ipv6_node_id->__in6_u.__u6_addr32[2]);
    obj->subobj.sr.sid_nai[index]   = htonl(ipv6_node_id->__in6_u.__u6_addr32[3]);

    return obj;
}

struct pcep_object_ro_subobj*
pcep_obj_create_ro_subobj_sr_ipv4_adj(
        bool loose_hop, bool sid_absent, bool c_flag, bool m_flag,
        uint32_t sid, struct in_addr *local_ipv4, struct in_addr *remote_ipv4)
{
    if (local_ipv4 == NULL || remote_ipv4 == NULL)
    {
        return NULL;
    }

    uint8_t extra_buf_len = sizeof(struct in_addr) * 2;
    if (!sid_absent)
    {
        extra_buf_len += sizeof(uint32_t);
    }

    /* According to draft-ietf-pce-segment-routing-16#section-5.2.1
     * If NT=3, the F bit MUST be zero.  If the S bit is 1, the Length
     * MUST be 12, otherwise the Length MUST be 16 */
    struct pcep_object_ro_subobj *obj = pcep_obj_create_ro_subobj_sr_common(
            extra_buf_len, PCEP_SR_SUBOBJ_NAI_IPV4_ADJACENCY,
            loose_hop, false, sid_absent, c_flag, m_flag);

    int index = 0;
    if (! sid_absent)
    {
        obj->subobj.sr.sid_nai[index++] = htonl(sid);
    }
    obj->subobj.sr.sid_nai[index++] = htonl(local_ipv4->s_addr);
    obj->subobj.sr.sid_nai[index]   = htonl(remote_ipv4->s_addr);

    return obj;
}

struct pcep_object_ro_subobj*
pcep_obj_create_ro_subobj_sr_ipv6_adj(
        bool loose_hop, bool sid_absent, bool c_flag, bool m_flag,
        uint32_t sid, struct in6_addr *local_ipv6, struct in6_addr *remote_ipv6)
{
    if (local_ipv6 == NULL || remote_ipv6 == NULL)
    {
        return NULL;
    }

    uint8_t extra_buf_len = sizeof(struct in6_addr) * 2;
    if (!sid_absent)
    {
        extra_buf_len += sizeof(uint32_t);
    }

    /* According to draft-ietf-pce-segment-routing-16#section-5.2.1
     * If NT=4, the F bit MUST be zero.  If the S bit is 1, the Length
     * MUST be 36, otherwise the Length MUST be 40 */
    struct pcep_object_ro_subobj *obj = pcep_obj_create_ro_subobj_sr_common(
            extra_buf_len, PCEP_SR_SUBOBJ_NAI_IPV6_ADJACENCY,
            loose_hop, false, sid_absent, c_flag, m_flag);

    int index = 0;
    if (! sid_absent)
    {
        obj->subobj.sr.sid_nai[index++] = htonl(sid);
    }
    obj->subobj.sr.sid_nai[index++] = htonl(local_ipv6->__in6_u.__u6_addr32[0]);
    obj->subobj.sr.sid_nai[index++] = htonl(local_ipv6->__in6_u.__u6_addr32[1]);
    obj->subobj.sr.sid_nai[index++] = htonl(local_ipv6->__in6_u.__u6_addr32[2]);
    obj->subobj.sr.sid_nai[index++] = htonl(local_ipv6->__in6_u.__u6_addr32[3]);

    obj->subobj.sr.sid_nai[index++] = htonl(remote_ipv6->__in6_u.__u6_addr32[0]);
    obj->subobj.sr.sid_nai[index++] = htonl(remote_ipv6->__in6_u.__u6_addr32[1]);
    obj->subobj.sr.sid_nai[index++] = htonl(remote_ipv6->__in6_u.__u6_addr32[2]);
    obj->subobj.sr.sid_nai[index]   = htonl(remote_ipv6->__in6_u.__u6_addr32[3]);

    return obj;
}

struct pcep_object_ro_subobj*
pcep_obj_create_ro_subobj_sr_unnumbered_ipv4_adj(
        bool loose_hop, bool sid_absent, bool c_flag, bool m_flag,
        uint32_t sid, uint32_t local_node_id, uint32_t local_if_id,
        uint32_t remote_node_id, uint32_t remote_if_id)
{
    uint8_t extra_buf_len = (sid_absent ? sizeof(uint32_t) * 4 : sizeof(uint32_t) * 5);

    /* According to draft-ietf-pce-segment-routing-16#section-5.2.1
     * If NT=5, the F bit MUST be zero.  If the S bit is 1, the Length
     * MUST be 20, otherwise the Length MUST be 24. */
    struct pcep_object_ro_subobj *obj = pcep_obj_create_ro_subobj_sr_common(
            extra_buf_len, PCEP_SR_SUBOBJ_NAI_UNNUMBERED_IPV4_ADJACENCY,
            loose_hop, false, sid_absent, c_flag, m_flag);

    int index = 0;
    if (! sid_absent)
    {
        obj->subobj.sr.sid_nai[index++] = htonl(sid);
    }
    obj->subobj.sr.sid_nai[index++] = htonl(local_node_id);
    obj->subobj.sr.sid_nai[index++] = htonl(local_if_id);
    obj->subobj.sr.sid_nai[index++] = htonl(remote_node_id);
    obj->subobj.sr.sid_nai[index]   = htonl(remote_if_id);

    return obj;
}

struct pcep_object_ro_subobj*
pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj(
        bool loose_hop, bool sid_absent, bool c_flag, bool m_flag,
        uint32_t sid, struct in6_addr *local_ipv6, uint32_t local_if_id,
        struct in6_addr *remote_ipv6, uint32_t remote_if_id)
{
    if (local_ipv6 == NULL || remote_ipv6 == NULL)
    {
        return NULL;
    }

    uint8_t extra_buf_len = (sizeof(struct in6_addr) * 2) + (sizeof(uint32_t) * 2);
    if (!sid_absent)
    {
        extra_buf_len += sizeof(uint32_t);
    }

    /* According to draft-ietf-pce-segment-routing-16#section-5.2.1
     * If NT=6, the F bit MUST be zero.  If the S bit is 1, the Length
     * MUST be 44, otherwise the Length MUST be 48 */
    struct pcep_object_ro_subobj *obj = pcep_obj_create_ro_subobj_sr_common(
            extra_buf_len, PCEP_SR_SUBOBJ_NAI_LINK_LOCAL_IPV6_ADJACENCY,
            loose_hop, false, sid_absent, c_flag, m_flag);

    int index = 0;
    if (! sid_absent)
    {
        obj->subobj.sr.sid_nai[index++] = htonl(sid);
    }
    obj->subobj.sr.sid_nai[index++] = htonl(local_ipv6->__in6_u.__u6_addr32[0]);
    obj->subobj.sr.sid_nai[index++] = htonl(local_ipv6->__in6_u.__u6_addr32[1]);
    obj->subobj.sr.sid_nai[index++] = htonl(local_ipv6->__in6_u.__u6_addr32[2]);
    obj->subobj.sr.sid_nai[index++] = htonl(local_ipv6->__in6_u.__u6_addr32[3]);
    obj->subobj.sr.sid_nai[index++] = htonl(local_if_id);

    obj->subobj.sr.sid_nai[index++] = htonl(remote_ipv6->__in6_u.__u6_addr32[0]);
    obj->subobj.sr.sid_nai[index++] = htonl(remote_ipv6->__in6_u.__u6_addr32[1]);
    obj->subobj.sr.sid_nai[index++] = htonl(remote_ipv6->__in6_u.__u6_addr32[2]);
    obj->subobj.sr.sid_nai[index++] = htonl(remote_ipv6->__in6_u.__u6_addr32[3]);
    obj->subobj.sr.sid_nai[index]   = htonl(remote_if_id);

    return obj;
}


/*
 * Object unpack functions.
 */
void
pcep_unpack_obj_header(struct pcep_object_header* hdr)
{
    hdr->object_length = ntohs(hdr->object_length);
}

void
pcep_unpack_obj_open(struct pcep_object_open *obj)
{
    /* TLVs will be unpacked when the message is parsed */
}

void
pcep_unpack_obj_tlv(struct pcep_object_tlv *tlv)
{
    tlv->header.type   = ntohs(tlv->header.type);
    tlv->header.length = ntohs(tlv->header.length);
    /*
    int i;
    for (i = 0; i < tlv->header.length; i++)
    {
        tlv->value[i]  = ntohl(tlv->value[i]);
    }
    */
}

void
pcep_unpack_obj_rp(struct pcep_object_rp *obj)
{
    obj->rp_flags = ntohl(obj->rp_flags);
    obj->rp_reqidnumb = ntohl(obj->rp_reqidnumb);
}

void
pcep_unpack_obj_nopath(struct pcep_object_nopath *obj)
{
    obj->flags = ntohs(obj->flags);
    obj->err_code.header.type = ntohs(obj->err_code.header.type);
    obj->err_code.header.length = ntohs(obj->err_code.header.length);

    if(obj->err_code.header.type == 1) {
        obj->err_code.value[0] = ntohl(obj->err_code.value[0]);
    }
}

void
pcep_unpack_obj_ep_ipv4(struct pcep_object_endpoints_ipv4 *obj)
{
    // nothing to unpack.
}

void
pcep_unpack_obj_ep_ipv6(struct pcep_object_endpoints_ipv6 *obj)
{
    // nothing to unpack.
}

void
pcep_unpack_obj_bandwidth(struct pcep_object_bandwidth *obj)
{
    // TODO maybe unpack float?
}

void
pcep_unpack_obj_metic(struct pcep_object_metric *obj)
{
    obj->resv = ntohs(obj->resv);
    // TODO maybe unpack float?
}

void
pcep_unpack_obj_ro(struct pcep_object_ro *obj)
{
    uint16_t read_count = sizeof(struct pcep_object_header);

    while((obj->header.object_length - read_count) > sizeof(struct pcep_ro_subobj_hdr)) {
        struct pcep_ro_subobj_hdr *hdr = (struct pcep_ro_subobj_hdr*) (((uint8_t*)obj) + read_count);
        /* Some sub-objects store the loose_hop bit in the top bit of the type field */
        uint8_t hdr_type = (hdr->type & 0x7f);

        if(hdr_type == RO_SUBOBJ_TYPE_UNNUM) {
            struct pcep_ro_subobj_unnum *unum = (struct pcep_ro_subobj_unnum*) hdr;
            unum->ifId = ntohl(unum->ifId);
            unum->routerId.s_addr = ntohl(unum->routerId.s_addr);
        }
        else if(hdr_type == RO_SUBOBJ_TYPE_IPV4)
        {
            struct pcep_ro_subobj_ipv4 *ipv4 = (struct pcep_ro_subobj_ipv4*) hdr;
            ipv4->ip_addr.s_addr = ntohl(ipv4->ip_addr.s_addr);
        }
        else if(hdr_type == RO_SUBOBJ_TYPE_IPV6)
        {
            struct pcep_ro_subobj_ipv6 *ipv6 = (struct pcep_ro_subobj_ipv6*) hdr;
            ipv6->ip_addr.__in6_u.__u6_addr32[0] = ntohl(ipv6->ip_addr.__in6_u.__u6_addr32[0]);
            ipv6->ip_addr.__in6_u.__u6_addr32[1] = ntohl(ipv6->ip_addr.__in6_u.__u6_addr32[1]);
            ipv6->ip_addr.__in6_u.__u6_addr32[2] = ntohl(ipv6->ip_addr.__in6_u.__u6_addr32[2]);
            ipv6->ip_addr.__in6_u.__u6_addr32[3] = ntohl(ipv6->ip_addr.__in6_u.__u6_addr32[3]);
        }
        else if(hdr_type == RO_SUBOBJ_TYPE_SR || hdr_type == RO_SUBOBJ_TYPE_SR_DRAFT07)
        {
            struct pcep_ro_subobj_sr *sr_subobj = (struct pcep_ro_subobj_sr*) hdr;
            sr_subobj->nt_flags = ntohs(sr_subobj->nt_flags);
            int words_to_convert = 0;
            switch (sr_subobj->nt_flags & 0xF000)
            {
            case PCEP_SR_SUBOBJ_NAI_IPV4_NODE:
                /* If the sid_absent flag is true, then dont convert the sid */
                words_to_convert = ((sr_subobj->nt_flags & PCEP_SR_SUBOBJ_S_FLAG) ? 1 : 2);
                break;

            case PCEP_SR_SUBOBJ_NAI_IPV6_NODE:
            case PCEP_SR_SUBOBJ_NAI_UNNUMBERED_IPV4_ADJACENCY:
                words_to_convert = ((sr_subobj->nt_flags & PCEP_SR_SUBOBJ_S_FLAG) ? 4 : 5);
                break;

            case PCEP_SR_SUBOBJ_NAI_IPV4_ADJACENCY:
                words_to_convert = ((sr_subobj->nt_flags & PCEP_SR_SUBOBJ_S_FLAG) ? 2 : 3);
                break;

            case PCEP_SR_SUBOBJ_NAI_IPV6_ADJACENCY:
                words_to_convert = ((sr_subobj->nt_flags & PCEP_SR_SUBOBJ_S_FLAG) ? 8 : 9);
                break;

            case PCEP_SR_SUBOBJ_NAI_LINK_LOCAL_IPV6_ADJACENCY:
                words_to_convert = ((sr_subobj->nt_flags & PCEP_SR_SUBOBJ_S_FLAG) ? 10 : 11);
                break;

            case PCEP_SR_SUBOBJ_NAI_ABSENT:
            default:
                break;
            }

            int i = 0;
            for (; i < words_to_convert; i++)
            {
                sr_subobj->sid_nai[i] = ntohl(sr_subobj->sid_nai[i]);
            }
        }
        read_count += hdr->length;
    }
}

void
pcep_unpack_obj_lspa(struct pcep_object_lspa *obj)
{
    obj->lspa_exclude_any = ntohl(obj->lspa_exclude_any);
    obj->lspa_include_any = ntohl(obj->lspa_include_any);
    obj->lspa_include_all = ntohl(obj->lspa_include_all);
}

void
pcep_unpack_obj_svec(struct pcep_object_svec *obj)
{
    uint16_t len;
    uint32_t i = 0;
    uint32_t *array = pcep_obj_svec_get(obj, &len);

    for(i = 0; i < len; i++) {
        array[i] = ntohl(array[i]);
    }
}

void
pcep_unpack_obj_error(struct pcep_object_error *obj)
{
    // nothing to unpack.
}

void
pcep_unpack_obj_close(struct pcep_object_close *obj)
{
    // nothing to unpack.
}

void pcep_unpack_obj_srp(struct pcep_object_srp *srp)
{
    srp->srp_id_number = ntohl(srp->srp_id_number);
}

void pcep_unpack_obj_lsp(struct pcep_object_lsp *lsp)
{
    /* TLVs will be unpacked when the message is parsed */
    lsp->plsp_id_flags = ntohl(lsp->plsp_id_flags);
}

void pcep_unpack_obj_notify(struct pcep_object_notify *notify)
{
    // nothing to unpack.
}

struct pcep_ro_subobj_hdr*
pcep_obj_get_next_ro_subobject(struct pcep_object_header *base, uint8_t current_index)
{
    uint8_t *next_subobj = ((uint8_t *) base) + current_index;
    return (next_subobj >= (((uint8_t *)base) + base->object_length)) ?
            NULL : (struct pcep_ro_subobj_hdr*) next_subobj;
}

/* Used to get Sub-objects for PCEP_OBJ_CLASS_ERO, PCEP_OBJ_CLASS_IRO,
 * and PCEP_OBJ_CLASS_RRO objects */
double_linked_list*
pcep_obj_get_ro_subobjects(struct pcep_object_header *ro_obj)
{
    if (ro_obj->object_class != PCEP_OBJ_CLASS_ERO &&
        ro_obj->object_class != PCEP_OBJ_CLASS_RRO &&
        ro_obj->object_class != PCEP_OBJ_CLASS_IRO)
    {
        return NULL;
    }

    double_linked_list *subobj_list = dll_initialize();
    uint8_t base_length = sizeof(struct pcep_object_ro);
    struct pcep_ro_subobj_hdr *next_subobj = pcep_obj_get_next_ro_subobject(ro_obj, base_length);

    while (next_subobj != NULL)
    {
        dll_append(subobj_list, next_subobj);
        /* assuming ntohs() has already been called on the next_subobj->length */
        base_length += next_subobj->length;
        next_subobj = pcep_obj_get_next_ro_subobject(ro_obj, base_length);
    }

    return subobj_list;
}
