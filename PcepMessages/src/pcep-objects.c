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

#include "pcep-objects.h"
#include "utlist.h"

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
        
    buffer_len = sizeof(struct pcep_object_nopath);
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

    obj->err_code.type = htons(1); // Type 1 from IANA
    obj->err_code.length = htons(sizeof(struct pcep_opt_tlv_uint32)); 
    obj->err_code.value = htonl(errorcode);

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

struct pcep_object_eros_list*                 
pcep_obj_create_ero(struct pcep_object_ero_list* list)
{
    uint16_t buffer_len = 0;   
    struct pcep_object_eros_list *ero = NULL;
    struct pcep_object_ero_list *item;
    struct pcep_ero_subobj_hdr *subobj;
            
    DL_FOREACH(list, item) {
        subobj = (struct pcep_ero_subobj_hdr*) item;
        buffer_len += subobj->length;
    }
    
    ero = malloc(sizeof(struct pcep_object_eros_list));
    
    bzero(ero, sizeof(struct pcep_object_eros_list));
    
    buffer_len += sizeof(struct pcep_object_ero);

    ero->ero_hdr.header.object_class = PCEP_OBJ_CLASS_ERO;
    ero->ero_hdr.header.object_type = PCEP_OBJ_TYPE_ERO;
    ero->ero_hdr.header.object_flags = 0;  
    ero->ero_hdr.header.object_length = htons(buffer_len);    
    
    ero->ero_list = list;
    ero->prev = ero;
    
    return ero;     
}

struct pcep_object_ero_list*            
pcep_obj_create_ero_unnum(struct in_addr* routerId, uint32_t ifId, uint16_t resv)
{
    uint8_t *buffer;
    uint16_t buffer_len;   
    struct pcep_object_ero_list *obj;
        
    buffer_len = sizeof(struct pcep_object_ero_list);
    buffer = malloc(sizeof(uint8_t) * buffer_len);
        
    bzero(buffer, buffer_len);
    
    obj = (struct pcep_object_ero_list*) buffer;    
    obj->subobj.unnum.header.length = sizeof(struct pcep_ero_subobj_unnum);
    obj->subobj.unnum.header.type = ERO_SUBOBJ_TYPE_UNNUM;
    obj->subobj.unnum.ifId = htonl(ifId);
    obj->prev = obj;
    
    memcpy(&obj->subobj.unnum.routerId, routerId, sizeof(struct in_addr));
    memcpy(&obj->subobj.unnum.resv, &resv, sizeof(uint16_t));
    
    return obj;
}

struct pcep_object_ero_list*         
pcep_obj_create_ero_32label (uint8_t dir, uint32_t label)
{
    uint8_t *buffer;
    uint16_t buffer_len;   
    struct pcep_object_ero_list *obj;
        
    buffer_len = sizeof(struct pcep_object_ero_list);
    buffer = malloc(sizeof(uint8_t) * buffer_len);
        
    bzero(buffer, buffer_len);
    
    obj = (struct pcep_object_ero_list*) buffer;    
    obj->subobj.label.header.length = sizeof(struct pcep_ero_subobj_32label);
    obj->subobj.label.header.type = ERO_SUBOBJ_TYPE_LABEL;
    obj->subobj.label.class_type = 2;
    obj->subobj.label.upstream = dir;
    obj->subobj.label.label = htonl(label);    
    obj->prev = obj;
    
    return obj;    
}

struct pcep_object_ero_list*
pcep_obj_create_ero_border  (uint8_t direction, uint8_t swcap_from, uint8_t swcap_to)
{
    uint8_t *buffer;
    uint16_t buffer_len;   
    struct pcep_object_ero_list *obj;
        
    buffer_len = sizeof(struct pcep_object_ero_list);
    buffer = malloc(sizeof(uint8_t) * buffer_len);
        
    bzero(buffer, buffer_len);
    
    obj = (struct pcep_object_ero_list*) buffer;    
    obj->subobj.border.header.length = sizeof(struct pcep_ero_subobj_border);
    obj->subobj.border.header.type = ERO_SUBOBJ_TYPE_BORDER;
    obj->subobj.border.direction = direction;
    obj->subobj.border.swcap_from = swcap_from;
    obj->subobj.border.swcap_to = swcap_to;
    obj->prev = obj;
    
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
    // nothing to unpack.
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
    obj->err_code.type = ntohs(obj->err_code.type);
    obj->err_code.length = ntohs(obj->err_code.length);
    
    if(obj->err_code.type == 1) {
        obj->err_code.value = ntohl(obj->err_code.value);
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
pcep_unpack_obj_ero(struct pcep_object_ero *obj)
{
    uint16_t read_count = sizeof(struct pcep_object_header);
    
    while((obj->header.object_length - read_count) > sizeof(struct pcep_ero_subobj_hdr)) {
        struct pcep_ero_subobj_hdr *hdr = (struct pcep_ero_subobj_hdr*) (((uint8_t*)obj) + read_count);
        
        if(hdr->type == ERO_SUBOBJ_TYPE_UNNUM) {
            struct pcep_ero_subobj_unnum *unum = (struct pcep_ero_subobj_unnum*) (((uint8_t*)obj) + read_count);
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

void 
pcep_obj_free_ero(struct pcep_object_eros_list *ero_list)
{
    struct pcep_object_eros_list *item, *tmp;
    
    if(ero_list == NULL) return;    
    
    DL_FOREACH_SAFE(ero_list, item, tmp) {        
        pcep_obj_free_ero_hop(item->ero_list);
        DL_DELETE(ero_list, item);
        free(item);
    }
}

void 
pcep_obj_free_ero_hop(struct pcep_object_ero_list *hop_list)
{
    struct pcep_object_ero_list *item, *tmp;
    
    DL_FOREACH_SAFE(hop_list, item, tmp) {
        DL_DELETE(hop_list, item);
        free(item);
    }
}