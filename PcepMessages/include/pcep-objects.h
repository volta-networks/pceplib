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

#ifndef PCEP_OBJECTS_H
#define PCEP_OBJECTS_H

#include <stdint.h>
#include <netinet/in.h> // struct in_addr

#ifdef __cplusplus
extern "C" {
#endif

#ifndef TRUE
    #define TRUE 1 
    #define FALSE 0
#endif

enum pcep_object_class
{
    PCEP_OBJ_CLASS_OPEN = 1,
    PCEP_OBJ_CLASS_RP = 2,
    PCEP_OBJ_CLASS_NOPATH = 3,
    PCEP_OBJ_CLASS_ENDPOINTS = 4,
    PCEP_OBJ_CLASS_BANDWIDTH = 5,
    PCEP_OBJ_CLASS_METRIC = 6,
    PCEP_OBJ_CLASS_ERO = 7,
    PCEP_OBJ_CLASS_RRO = 8,
    PCEP_OBJ_CLASS_LSPA = 9,
    PCEP_OBJ_CLASS_IRO = 10,
    PCEP_OBJ_CLASS_SVEC = 11,
    PCEP_OBJ_CLASS_NOTF = 12,
    PCEP_OBJ_CLASS_ERROR = 13,
    PCEP_OBJ_CLASS_CLOSE = 15,
};

enum pcep_object_types
{
    PCEP_OBJ_TYPE_OPEN = 1,
    
    PCEP_OBJ_TYPE_RP = 1,
    
    PCEP_OBJ_TYPE_NOPATH = 1,
    
    PCEP_OBJ_TYPE_ENDPOINT_IPV4 = 1,
    PCEP_OBJ_TYPE_ENDPOINT_IPV6 = 2,
    
    PCEP_OBJ_TYPE_BANDWIDTH_REQ = 1,
    PCEP_OBJ_TYPE_BANDWIDTH_TELSP = 2,
    
    PCEP_OBJ_TYPE_METRIC = 1,
    
    PCEP_OBJ_TYPE_ERO = 1,
    
    PCEP_OBJ_TYPE_RRO = 1,
    
    PCEP_OBJ_TYPE_LSPA = 1,
    
    PCEP_OBJ_TYPE_IRO = 1,
    
    PCEP_OBJ_TYPE_SVEC = 1,
    
    PCEP_OBJ_TYPE_NOTF = 1,
    
    PCEP_OBJ_TYPE_ERROR = 1,
    
    PCEP_OBJ_TYPE_CLOSE = 1
};


struct pcep_object_header
{
    uint8_t object_class;       //Identifies the PCEP object class.
    uint8_t object_flags:4;     //Identifies the PCEP object flags.
    uint8_t object_type:4;      //Identifies the PCEP object type.    
    uint16_t object_length;     //Specifies the total object length including the header.
}__attribute__((packed));

struct pcep_object_open
{
    struct pcep_object_header header;
    uint8_t open_ver_flags; //PCEP version. Current version is 1 /No flags are currently defined.
    uint8_t open_keepalive; //Maximum period of time between two consecutive PCEP messages sent by the sender.
    uint8_t open_deadtimer; //Specifies the amount of time before closing the session down.
    uint8_t open_sid;       //PCEP session number that identifies the current session.   
}__attribute__((packed));

struct pcep_object_rp
{
    struct pcep_object_header header;
    uint32_t rp_flags;          //The following flags are defined
    uint32_t rp_reqidnumb;      //The Request-id-number value combined with the source for PCC & PCE creates a uniquely number.
}__attribute__((packed));

//For future work, optional tlvs in objects
struct pcep_opt_tlv_uint32
{
    uint16_t type;
    uint16_t length;
    uint32_t value;
}__attribute__((packed));

enum pcep_nopath_err_codes {
    PCEP_NOPATH_ERR_UNAVAILABLE = (1 << 0),
    PCEP_NOPATH_ERR_UNKNOWN_DST = (1 << 1),
    PCEP_NOPATH_ERR_UNKNOWN_SRC = (1 << 2)
};

struct pcep_object_nopath
{
    struct pcep_object_header header;
    uint8_t ni;         //Nature of Issue, reports the nature of the issue that led to a negative reply
    uint16_t flags;     //One flag is defined: C, when set it indicates that an unsatisfied constraint
    uint8_t reserved;   //Reserved field
    struct pcep_opt_tlv_uint32 err_code;
}__attribute__((packed));

struct pcep_object_endpoints_ipv4
{
    struct pcep_object_header header;
    struct in_addr src_ipv4;  //Source ip
    struct in_addr dst_ipv4;    //Destination ip
}__attribute__((packed));

struct pcep_object_endpoints_ipv6
{
    struct pcep_object_header header;
    struct in6_addr src_ipv6;
    struct in6_addr dst_ipv6;
}__attribute__((packed));

struct pcep_object_bandwidth
{
    struct pcep_object_header header;
    float bandwidth;  
}__attribute__((packed));

enum pcep_metric_types
{
    PCEP_METRIC_IGP = 1,
    PCEP_METRIC_TE = 2,
    PCEP_METRIC_HOP_COUNT = 3,
    PCEP_METRIC_DISJOINTNESS = 4
};

struct pcep_object_metric
{
    struct pcep_object_header header;
    uint16_t resv;      //Must be set to zero on transmission
    uint8_t type;       //Specifies the metric type
    uint8_t flags;      //Flags
    float value;        //Metric value in 32 bit
}__attribute__((packed));

struct pcep_object_ero
{
    struct pcep_object_header header;
}__attribute__((packed));

enum pcep_ero_subobj_types
{
    ERO_SUBOBJ_TYPE_IPV4 = 1,
    ERO_SUBOBJ_TYPE_IPV6 = 2,
    ERO_SUBOBJ_TYPE_LABEL = 3,
    ERO_SUBOBJ_TYPE_UNNUM = 4,
    ERO_SUBOBJ_TYPE_BORDER = 10
};

struct pcep_ero_subobj_hdr
{
    uint8_t type;         /* loose bit and sub-object type (0x01 = strict IPv4 hop) */
    uint8_t length;        /* sub-object length (in bytes) */    
}__attribute__((packed));

struct pcep_ero_subobj_ipv4
{
    struct pcep_ero_subobj_hdr header;
    uint16_t ifAddrHi;     /* interface IPv4 address (high part) */
    uint16_t ifAddrLo;     /* interface IPv4 address (low part) */
    uint8_t ifPrefix;      /* interface prefix length (in bits) */
    uint8_t resvd;         // reserved bits (padding)
}__attribute__((packed));

struct pcep_ero_subobj_unnum
{
    struct pcep_ero_subobj_hdr header;
    uint16_t resv;
    struct in_addr routerId;
    uint32_t ifId;
}__attribute__((packed));

struct pcep_ero_subobj_32label
{
    struct pcep_ero_subobj_hdr header;
    uint8_t upstream:1; // upstream(1)/downstream(0) bit indication
    uint8_t resvd:7;            
    uint8_t class_type; // label class-type (generalized label = 2) 
    uint32_t label;     // label supported */
}__attribute__((packed));

// Non standard object to include layer information in the returned path.
struct pcep_ero_subobj_border
{
    struct pcep_ero_subobj_hdr header;
    uint8_t direction:1;
    uint8_t flags:7;
    uint8_t swcap_from;
    uint8_t swcap_to;
    uint8_t swcap_info_fst;
    uint8_t swcap_info_sec;
    uint8_t swcap_info_thr;
}__attribute__((packed));

struct pcep_object_eros_list
{
    struct pcep_object_ero ero_hdr;
    struct pcep_object_ero_list *ero_list;
    
    struct pcep_object_eros_list *prev;
    struct pcep_object_eros_list *next;
};

struct pcep_object_ero_list
{    
    union subobj {
        struct pcep_ero_subobj_ipv4 ipv4;
        struct pcep_ero_subobj_unnum unnum;
        struct pcep_ero_subobj_32label label;
        struct pcep_ero_subobj_border border;
    } subobj;
    
    struct pcep_object_ero_list *prev; /* needed for a doubly-linked list only */
    struct pcep_object_ero_list *next; /* needed for singly- or doubly-linked lists */
};

struct pcep_object_lspa
{
    struct pcep_object_header header;
    uint32_t lspa_exclude_any; //Exclude any
    uint32_t lspa_include_any; //Include any
    uint32_t lspa_include_all; //Include all
    uint8_t lspa_prio;     //The priority of the TE LSP with respect to taking resources.
    uint8_t lspa_holdprio; //The priority of the TE LSP with respect to holding resources.
    uint8_t lspa_flags;    //Flags
    uint8_t lspa_resv;     //This field must be set to 0    
}__attribute__((packed));

// The SVEC object with some custom extensions.
struct pcep_object_svec
{
    struct pcep_object_header header;
    uint8_t reserved_disjointness;   
    uint16_t flags_reserved;
    uint8_t flag_srlg:1;
    uint8_t flag_node:1;
    uint8_t flag_link:1;    
    uint8_t flag_reserved:5;    
}__attribute__((packed));

enum pcep_error_type
{
  PCEP_ERRT_SESSION_FAILURE = 1,
  PCEP_ERRT_CAPABILITY_NOT_SUPPORTED = 2,
  PCEP_ERRT_UNKNOW_OBJECT = 3,
  PCEP_ERRT_NOT_SUPPORTED_OBJECT = 4,
  PCEP_ERRT_POLICY_VIOLATION = 5,
  PCEP_ERRT_MANDATORY_OBJECT_MISSING = 6,
  PCEP_ERRT_SYNCH_PC_REQ_MISSING = 7,
  PCEP_ERRT_UNKNOWN_REQ_REF = 8,
  PCEP_ERRT_ATTEMPT_TO_ESTABLISH_A_SEC_PCEP_SESSION = 9,
  PCEP_ERRT_RECEPTION_OF_INV_OBJECT = 10,
};

enum pcep_error_value
{  
  PCEP_ERRV_RECVD_INVALID_OPEN_MSG = 1,
  PCEP_ERRV_OPENWAIT_TIMED_OUT = 2,
  PCEP_ERRV_UNACCEPTABLE_OPEN_MSG_NO_NEG = 3,
  PCEP_ERRV_UNACCEPTABLE_OPEN_MSG_NEG = 4,
  PCEP_ERRV_RECVD_SECOND_OPEN_MSG_UNACCEPTABLE = 5,
  PCEP_ERRV_RECVD_PCERR = 6,
  PCEP_ERRV_KEEPALIVEWAIT_TIMED_OUT = 7,
  
  PCEP_ERRV_UNREC_OBJECT_CLASS = 1,
  PCEP_ERRV_UNREC_OBJECT_TYPE = 2,
  
  PCEP_ERRV_NOT_SUPPORTED_OBJECT_CLASS = 1,
  PCEP_ERRV_NOT_SUPPORTED_OBJECT_TYPE = 2,
  
  PCEP_ERRV_C_BIT_SET_IN_METRIC_OBJECT = 1,
  PCEP_ERRV_O_BIt_CLEARD_IN_RP_OBJECT = 2,
  
  PCEP_ERRV_RP_OBJECT_MISSING = 1,
  PCEP_ERRV_RRO_OBJECT_MISSING_FOR_REOP = 2,
  PCEP_ERRV_EP_OBJECT_MISSING = 3,
  
  PCEP_ERRV_P_FLAG_NOT_CORRECT_IN_OBJECT = 1,
}; 

struct pcep_object_error
{
    struct pcep_object_header header;
    uint8_t reserved; 
    uint8_t flags; 
    uint8_t error_type; 
    uint8_t error_value;       
}__attribute__((packed));

struct pcep_object_load_balancing
{
    struct pcep_object_header header;
    uint16_t load_res;   //This field must set to 0
    uint8_t load_flags;  //Flags
    uint8_t load_maxlsp; //Maximum number of the TE LSPs in the set
    uint32_t load_minband; //Specifies the minimum bandwidth of each element
}__attribute__((packed));

enum pcep_close_reasons
{
    PCEP_CLOSE_REASON_NO = 1,
    PCEP_CLOSE_REASON_DEADTIMER = 2,
    PCEP_CLOSE_REASON_FORMAT = 3,
    PCEP_CLOSE_REASON_UNKNOWN_REQ = 4,
    PCEP_CLOSE_REASON_UNREC = 5
};

struct pcep_object_close
{
    struct pcep_object_header header;
    uint16_t reserved; 
    uint8_t flags; 
    uint8_t reason;  
}__attribute__((packed));

struct pcep_object_open*                pcep_obj_create_open        (uint8_t keepalive, uint8_t deadtimer, uint8_t sid);
struct pcep_object_rp*                  pcep_obj_create_rp          (uint8_t obj_hdr_flags, uint32_t obj_flags, uint32_t reqid);
struct pcep_object_nopath*              pcep_obj_create_nopath      (uint8_t obj_hdr_flags, uint8_t ni, uint16_t obj_flags, uint32_t errorcode);
struct pcep_object_endpoints_ipv4*      pcep_obj_create_enpoint_ipv4(const struct in_addr* src_ipv4, const struct in_addr* dst_ipv4);
struct pcep_object_endpoints_ipv6*      pcep_obj_create_enpoint_ipv6(const struct in6_addr* src_ipv6, const struct in6_addr* dst_ipv6);
struct pcep_object_bandwidth*           pcep_obj_create_bandwidth   (float bandwidth);
struct pcep_object_metric*              pcep_obj_create_metric      (uint8_t flags, uint8_t type, float value);
struct pcep_object_eros_list*           pcep_obj_create_ero         (struct pcep_object_ero_list* list);
struct pcep_object_ero_list*            pcep_obj_create_ero_unnum   (struct in_addr* routerId, uint32_t ifId, uint16_t resv);
struct pcep_object_ero_list*            pcep_obj_create_ero_32label (uint8_t dir, uint32_t label);
struct pcep_object_ero_list*            pcep_obj_create_ero_border  (uint8_t direction, uint8_t swcap_from, uint8_t swcap_to);
struct pcep_object_lspa*                pcep_obj_create_lspa        (uint8_t prio, uint8_t hold_prio);
struct pcep_object_svec*                pcep_obj_create_svec        (uint8_t srlg, uint8_t node, uint8_t link, uint16_t ids_count, uint32_t *ids);
struct pcep_object_error*               pcep_obj_create_error       (uint8_t error_type, uint8_t error_value);
struct pcep_object_close*               pcep_obj_create_close       (uint8_t flags, uint8_t reason);

uint32_t*       pcep_obj_svec_get       (struct pcep_object_svec* obj, uint16_t *length);      
void            pcep_obj_svec_print     (struct pcep_object_svec* obj);      

void pcep_unpack_obj_header(struct pcep_object_header* hdr);
void pcep_unpack_obj_open(struct pcep_object_open *open);
void pcep_unpack_obj_rp(struct pcep_object_rp *rp);
void pcep_unpack_obj_nopath(struct pcep_object_nopath *nopath);
void pcep_unpack_obj_ep_ipv4(struct pcep_object_endpoints_ipv4 *ep_ipv4);
void pcep_unpack_obj_ep_ipv6(struct pcep_object_endpoints_ipv6 *ep_ipv6);
void pcep_unpack_obj_bandwidth(struct pcep_object_bandwidth *bandwidth);
void pcep_unpack_obj_metic(struct pcep_object_metric *metric);
void pcep_unpack_obj_ero(struct pcep_object_ero *ero);
void pcep_unpack_obj_lspa(struct pcep_object_lspa *lspa);
void pcep_unpack_obj_svec(struct pcep_object_svec *svec);
void pcep_unpack_obj_error(struct pcep_object_error *error);
void pcep_unpack_obj_close(struct pcep_object_close *close);

void pcep_obj_free_ero          (struct pcep_object_eros_list *ero_list);
void pcep_obj_free_ero_hop      (struct pcep_object_ero_list *hop_list);

#ifdef __cplusplus
}
#endif

#endif
