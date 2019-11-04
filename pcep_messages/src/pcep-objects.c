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

struct pcep_object_open*
pcep_obj_create_open(uint8_t keepalive, uint8_t deadtimer, uint8_t sid)
{
    uint8_t *buffer;
    uint16_t buffer_len = sizeof(struct pcep_object_open);
    struct pcep_object_open *open;

    buffer = malloc(sizeof(uint8_t) * buffer_len);

    bzero(buffer, buffer_len);

    open = (struct pcep_object_open*) buffer;
    open->header.object_class = PCEP_OBJ_CLASS_OPEN;
    open->header.object_type = PCEP_OBJ_TYPE_OPEN;
    open->header.object_length = htons(sizeof(struct pcep_object_open));
    open->open_ver_flags = 1<<5;        // PCEP version. Current version is 1 /No flags are currently defined.
    open->open_keepalive = keepalive;   // Maximum period of time between two consecutive PCEP messages sent by the sender.
    open->open_deadtimer = deadtimer;   // Specifies the amount of time before closing the session down.
    open->open_sid = sid;               // PCEP session number that identifies the current session.

    return open;
}

struct pcep_object_rp*
pcep_obj_create_rp(uint8_t obj_hdr_flags, uint32_t obj_flags, uint32_t reqid)
{
    uint8_t *buffer;
    uint16_t buffer_len;
    struct pcep_object_rp *obj;

    buffer_len = sizeof(struct pcep_object_rp);
    buffer = malloc(sizeof(uint8_t) * buffer_len);

    bzero(buffer, buffer_len);

    obj = (struct pcep_object_rp*) buffer;
    obj->header.object_class = PCEP_OBJ_CLASS_RP;
    obj->header.object_type = PCEP_OBJ_TYPE_RP;
    obj->header.object_flags = obj_hdr_flags;
    obj->header.object_length = htons(buffer_len);

    obj->rp_flags = obj_flags;  //|O|B|R|Pri|
    obj->rp_reqidnumb = htonl(reqid); //Set the request id

    return obj;
}

struct pcep_object_nopath*
pcep_obj_create_nopath(uint8_t obj_hdr_flags, uint8_t ni, uint16_t unsat_constr_flag, uint32_t errorcode)
{
    uint8_t *buffer;
    uint16_t buffer_len;
    uint16_t flags = (unsat_constr_flag << 15);
    struct pcep_object_nopath *obj;

    /* Adding 4 bytes for the TLV value */
    buffer_len = sizeof(struct pcep_object_nopath) + 4;
    buffer = malloc(sizeof(uint8_t) * buffer_len);

    bzero(buffer, buffer_len);

    obj = (struct pcep_object_nopath*) buffer;
    obj->header.object_class = PCEP_OBJ_CLASS_NOPATH;
    obj->header.object_type = PCEP_OBJ_TYPE_NOPATH;
    obj->header.object_flags = obj_hdr_flags;
    obj->header.object_length = htons(buffer_len);
    obj->ni = ni;
    obj->flags = htons(flags);
    obj->reserved = 0;

    obj->err_code.header.type = htons(1); // Type 1 from IANA
    obj->err_code.header.length = htons(sizeof(uint32_t));
    obj->err_code.value[0] = htonl(errorcode);

    return obj;
}

struct pcep_object_endpoints_ipv4*
pcep_obj_create_enpoint_ipv4(const struct in_addr* src_ipv4, const struct in_addr* dst_ipv4)
{
    uint8_t *buffer;
    uint16_t buffer_len;
    struct pcep_object_endpoints_ipv4 *obj;

    buffer_len = sizeof(struct pcep_object_endpoints_ipv4);
    buffer = malloc(sizeof(uint8_t) * buffer_len);

    bzero(buffer, buffer_len);

    obj = (struct pcep_object_endpoints_ipv4*) buffer;
    obj->header.object_class = PCEP_OBJ_CLASS_ENDPOINTS;
    obj->header.object_type = PCEP_OBJ_TYPE_ENDPOINT_IPV4;
    obj->header.object_flags = 0;
    obj->header.object_length = htons(buffer_len);

    memcpy(&obj->src_ipv4, src_ipv4, sizeof(struct in_addr));
    memcpy(&obj->dst_ipv4, dst_ipv4, sizeof(struct in_addr));

    return obj;
}

struct pcep_object_endpoints_ipv6*
pcep_obj_create_enpoint_ipv6(const struct in6_addr* src_ipv6, const struct in6_addr* dst_ipv6)
{
    uint8_t *buffer;
    uint16_t buffer_len;
    struct pcep_object_endpoints_ipv6 *obj;

    buffer_len = sizeof(struct pcep_object_endpoints_ipv6);
    buffer = malloc(sizeof(uint8_t) * buffer_len);

    bzero(buffer, buffer_len);

    obj = (struct pcep_object_endpoints_ipv6*) buffer;
    obj->header.object_class = PCEP_OBJ_CLASS_ENDPOINTS;
    obj->header.object_type = PCEP_OBJ_TYPE_ENDPOINT_IPV6;
    obj->header.object_flags = 0;
    obj->header.object_length = htons(buffer_len);

    memcpy(&obj->src_ipv6, src_ipv6, sizeof(struct in6_addr));
    memcpy(&obj->dst_ipv6, dst_ipv6, sizeof(struct in6_addr));

    return obj;
}

struct pcep_object_bandwidth*
pcep_obj_create_bandwidth(float bandwidth)
{
    uint8_t *buffer;
    uint16_t buffer_len;
    struct pcep_object_bandwidth *obj;

    buffer_len = sizeof(struct pcep_object_bandwidth);
    buffer = malloc(sizeof(uint8_t) * buffer_len);

    bzero(buffer, buffer_len);

    obj = (struct pcep_object_bandwidth*) buffer;
    obj->header.object_class = PCEP_OBJ_CLASS_BANDWIDTH;
    obj->header.object_type = PCEP_OBJ_TYPE_BANDWIDTH_REQ;
    obj->header.object_flags = 0;
    obj->header.object_length = htons(buffer_len);
    obj->bandwidth = bandwidth;

    return obj;
}

struct pcep_object_metric*
pcep_obj_create_metric(uint8_t flags, uint8_t type, float value)
{
    uint8_t *buffer;
    uint16_t buffer_len;
    struct pcep_object_metric *obj;

    buffer_len = sizeof(struct pcep_object_metric);
    buffer = malloc(sizeof(uint8_t) * buffer_len);

    bzero(buffer, buffer_len);

    obj = (struct pcep_object_metric*) buffer;
    obj->header.object_class = PCEP_OBJ_CLASS_METRIC;
    obj->header.object_type = PCEP_OBJ_TYPE_METRIC;
    obj->header.object_flags = 0;
    obj->header.object_length = htons(buffer_len);
    obj->flags = flags;
    obj->type = type;
    obj->value = value;

    return obj;
}

/* Internal common function used to create a pcep_object_route_object,
 * used internally by:
 *     pcep_obj_create_eroute_object()
 *     pcep_obj_create_iroute_object()
 *     pcep_obj_create_rroute_object() */
static struct pcep_object_route_object*
pcep_obj_create_common_route_object(double_linked_list* ro_list)
{
    uint16_t buffer_len = 0;
    struct pcep_object_route_object *route_object = malloc(sizeof(struct pcep_object_route_object));
    bzero(route_object, sizeof(struct pcep_object_route_object));

    double_linked_list_node *node;
    for (node = ro_list->head; node != NULL; node = node->next_node)
    {
        struct pcep_ro_subobj_hdr *subobj = (struct pcep_ro_subobj_hdr*) node->data;
        buffer_len += subobj->length;
    }

    buffer_len += sizeof(struct pcep_object_ro);

    /* object_class and object_type MUST be set by calling functions */
    route_object->ro_hdr.header.object_flags = 0;
    route_object->ro_hdr.header.object_length = htons(buffer_len);

    route_object->ro_list = ro_list;

    return route_object;
}

/* Wrap a list of ro subobjects in a structure with an object header */
struct pcep_object_route_object*
pcep_obj_create_eroute_object(double_linked_list* ero_list)
{
    struct pcep_object_route_object *ero = pcep_obj_create_common_route_object(ero_list);
    ero->ro_hdr.header.object_class = PCEP_OBJ_CLASS_ERO;
    ero->ro_hdr.header.object_type = PCEP_OBJ_TYPE_ERO;

    return ero;
}

/* Wrap a list of ro subobjects in a structure with an object header */
struct pcep_object_route_object*
pcep_obj_create_iroute_object(double_linked_list* iro_list)
{
    struct pcep_object_route_object *iro = pcep_obj_create_common_route_object(iro_list);
    iro->ro_hdr.header.object_class = PCEP_OBJ_CLASS_IRO;
    iro->ro_hdr.header.object_type = PCEP_OBJ_TYPE_IRO;

    return iro;
}

/* Wrap a list of ro subobjects in a structure with an object header */
struct pcep_object_route_object*
pcep_obj_create_rroute_object(double_linked_list* rro_list)
{
    struct pcep_object_route_object *rro = pcep_obj_create_common_route_object(rro_list);
    rro->ro_hdr.header.object_class = PCEP_OBJ_CLASS_RRO;
    rro->ro_hdr.header.object_type = PCEP_OBJ_TYPE_RRO;

    return rro;
}

/*
 * Route Object Sub-object creation functions
 */

static struct pcep_object_ro_subobj*
pcep_obj_create_ro_subobj_common()
{
    uint8_t *buffer = malloc(sizeof(uint8_t) * sizeof(struct pcep_object_ro_subobj));
    bzero(buffer, sizeof(struct pcep_object_ro_subobj));

    return (struct pcep_object_ro_subobj*) buffer;
}

struct pcep_object_ro_subobj*
pcep_obj_create_ro_subobj_unnum(struct in_addr* routerId, uint32_t ifId, uint16_t resv)
{
    struct pcep_object_ro_subobj *obj = pcep_obj_create_ro_subobj_common();

    obj->subobj.unnum.header.length = sizeof(struct pcep_ro_subobj_unnum);
    obj->subobj.unnum.header.type = RO_SUBOBJ_TYPE_UNNUM;
    obj->subobj.unnum.ifId = htonl(ifId);

    memcpy(&obj->subobj.unnum.routerId, routerId, sizeof(struct in_addr));
    memcpy(&obj->subobj.unnum.resv, &resv, sizeof(uint16_t));

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
    struct pcep_object_ro_subobj *obj = pcep_obj_create_ro_subobj_common();

    obj->subobj.ipv4.header.length = sizeof(struct pcep_ro_subobj_ipv4);
    obj->subobj.ipv4.header.type = RO_SUBOBJ_TYPE_IPV4;
    obj->subobj.ipv4.prefix_length = prefix_length;
    memcpy(&obj->subobj.ipv4.ip_addr, rro_ipv4, sizeof(struct in_addr));
    if (loose_hop == true)
    {
        // The first bit of the type field is used to specify Loose Hop
        obj->subobj.ipv4.header.type |= 0x08;
    }

    return obj;
}

struct pcep_object_ro_subobj*
pcep_obj_create_ro_subobj_ipv6(bool loose_hop, const struct in6_addr* rro_ipv6, uint8_t prefix_length)
{
    struct pcep_object_ro_subobj *obj = pcep_obj_create_ro_subobj_common();

    obj->subobj.ipv6.header.length = sizeof(struct pcep_ro_subobj_ipv6);
    obj->subobj.ipv6.header.type = RO_SUBOBJ_TYPE_IPV6;
    obj->subobj.ipv6.prefix_length = prefix_length;
    memcpy(&obj->subobj.ipv6.ip_addr, rro_ipv6, sizeof(struct in6_addr));
    if (loose_hop == true)
    {
        // The first bit of the type field is used to specify Loose Hop
        obj->subobj.ipv6.header.type |= 0x08;
    }

    return obj;
}

struct pcep_object_ro_subobj*
pcep_obj_create_ro_subobj_asn(uint16_t asn)
{
    struct pcep_object_ro_subobj *obj = pcep_obj_create_ro_subobj_common();

    obj->subobj.asn.header.length = sizeof(struct pcep_ro_subobj_border);
    obj->subobj.asn.header.type = RO_SUBOBJ_TYPE_ASN;
    obj->subobj.asn.aut_sys_number = asn;

    return obj;
}

struct pcep_object_lspa*
pcep_obj_create_lspa(uint8_t prio, uint8_t hold_prio)
{
    uint8_t *buffer;
    uint16_t buffer_len;
    struct pcep_object_lspa *obj;

    buffer_len = sizeof(struct pcep_object_lspa);
    buffer = malloc(sizeof(uint8_t) * buffer_len);

    bzero(buffer, buffer_len);

    obj = (struct pcep_object_lspa*) buffer;
    obj->header.object_class = PCEP_OBJ_CLASS_LSPA;
    obj->header.object_type = PCEP_OBJ_TYPE_LSPA;
    obj->header.object_flags = 0;
    obj->header.object_length = htons(buffer_len);
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
pcep_obj_create_svec(uint8_t srlg, uint8_t node, uint8_t link, uint16_t ids_count, uint32_t *ids)
{
    uint32_t i;
    uint8_t *buffer;
    uint16_t buffer_len;
    uint16_t buffer_pos;
    struct pcep_object_svec *obj;

    buffer_len = sizeof(struct pcep_object_svec) + (ids_count*sizeof(uint32_t));
    buffer_pos = sizeof(struct pcep_object_svec);
    buffer = malloc(sizeof(uint8_t) * buffer_len);

    bzero(buffer, buffer_len);

    obj = (struct pcep_object_svec*) buffer;
    obj->header.object_class = PCEP_OBJ_CLASS_SVEC;
    obj->header.object_type = PCEP_OBJ_TYPE_SVEC;
    obj->header.object_flags = 0;
    obj->header.object_length = htons(buffer_len);
    obj->flag_srlg = srlg;
    obj->flag_node = node;
    obj->flag_link = link;

    for(i = 0; i < ids_count; i++) {
        uint32_t id = htonl(ids[i]);
        memcpy((buffer + buffer_pos), &id, sizeof(uint32_t));
        buffer_pos += sizeof(uint32_t);
    }

    return obj;
}

struct pcep_object_error*
pcep_obj_create_error(uint8_t error_type, uint8_t error_value)
{
    uint8_t *buffer;
    uint16_t buffer_len;
    struct pcep_object_error *obj;

    buffer_len = sizeof(struct pcep_object_error);
    buffer = malloc(sizeof(uint8_t) * buffer_len);

    bzero(buffer, buffer_len);

    obj = (struct pcep_object_error*) buffer;
    obj->header.object_class = PCEP_OBJ_CLASS_ERROR;
    obj->header.object_type = PCEP_OBJ_TYPE_ERROR;
    obj->header.object_flags = 0;
    obj->header.object_length = htons(buffer_len);
    obj->error_type = error_type;
    obj->error_value = error_value;

    return obj;
}

struct pcep_object_close*
pcep_obj_create_close(uint8_t flags, uint8_t reason)
{
    uint8_t *buffer;
    uint16_t buffer_len;
    struct pcep_object_close *obj;

    buffer_len = sizeof(struct pcep_object_close);
    buffer = malloc(sizeof(uint8_t) * buffer_len);

    bzero(buffer, buffer_len);

    obj = (struct pcep_object_close*) buffer;
    obj->header.object_class = PCEP_OBJ_CLASS_CLOSE;
    obj->header.object_type = PCEP_OBJ_TYPE_CLOSE;
    obj->header.object_flags = 0;
    obj->header.object_length = htons(buffer_len);
    obj->flags = flags;
    obj->reason = reason;

    return obj;
}

void
pcep_unpack_obj_header(struct pcep_object_header* hdr)
{
    hdr->object_length = ntohs(hdr->object_length);
}

void
pcep_unpack_obj_open(struct pcep_object_open *obj)
{
    struct pcep_object_header* obj_header = (struct pcep_object_header*) obj;

    /* Check if the Open has TLVs, and unpack them */
    if (pcep_obj_has_tlv(obj_header, sizeof(struct pcep_object_open)) == false)
    {
        return;
    }

    struct pcep_object_tlv *tlv = (struct pcep_object_tlv *)
               (((char *) obj) + sizeof(struct pcep_object_open));
    while (tlv != NULL)
    {
        pcep_unpack_obj_tlv(tlv);
        tlv = pcep_obj_get_next_tlv(obj_header, tlv);
    }
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

        if(hdr->type == RO_SUBOBJ_TYPE_UNNUM) {
            struct pcep_ro_subobj_unnum *unum = (struct pcep_ro_subobj_unnum*) (((uint8_t*)obj) + read_count);
            unum->ifId = ntohl(unum->ifId);
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

bool
pcep_obj_has_tlv(struct pcep_object_header* hdr, uint16_t obj_len)
{
    return (hdr->object_length - obj_len) > 0;
}

struct pcep_object_tlv*
pcep_obj_get_next_tlv(struct pcep_object_header *base, struct pcep_object_tlv *current_tlv)
{
    /* assuming ntohs() has already been called on the current_tlv->length */
    /* The TLV length is the length of the value, need to also get past the TLV header */
    char *next_tlv = ((char *) current_tlv) + current_tlv->header.length + 4;
    return (next_tlv >= (((char *)base) + base->object_length)) ?
            NULL : (struct pcep_object_tlv*) next_tlv;
}

double_linked_list*
pcep_obj_get_tlvs(struct pcep_object_header *base, struct pcep_object_tlv *first_tlv)
{
    double_linked_list *tlv_list = dll_initialize();
    struct pcep_object_tlv *next_tlv = first_tlv;

    while (next_tlv != NULL)
    {
        dll_append(tlv_list, next_tlv);
        next_tlv = pcep_obj_get_next_tlv(base, next_tlv);
    }

    return tlv_list;
}

void
pcep_obj_free_ro(double_linked_list *route_object_list)
{
    if(route_object_list == NULL) return;

    /* Iterate the route object items and free each one */
    struct pcep_object_route_object *eros = (struct pcep_object_route_object *) dll_delete_first_node(route_object_list);
    while (eros != NULL) {
        pcep_obj_free_ro_hop(eros->ro_list);
        free(eros);
        eros = (struct pcep_object_route_object *) dll_delete_first_node(route_object_list);
    }
    dll_destroy(route_object_list);
}

void
pcep_obj_free_ro_hop(double_linked_list *hop_list)
{
    /* Iterate the ero items and free each one */
    struct pcep_object_ro *ro = (struct pcep_object_ro *) dll_delete_first_node(hop_list);
    while (ro != NULL) {
        free(ro);
        ro = (struct pcep_object_ro *) dll_delete_first_node(hop_list);
    }

    dll_destroy(hop_list);
}
