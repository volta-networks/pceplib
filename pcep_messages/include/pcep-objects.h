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

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h> // struct in_addr

#include "pcep_utils_double_linked_list.h"
#include "pcep-tlvs.h"

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
    PCEP_OBJ_CLASS_LSP = 32,
    PCEP_OBJ_CLASS_SRP = 33,
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

    PCEP_OBJ_TYPE_SRP = 1,
    PCEP_OBJ_TYPE_LSP = 1,

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

/* PCEP Message Common Object Header, According to RFC 5440
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | Object-Class  |   OT  |Res|P|I|   Object Length (bytes)       |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   //                        (Object body)                        //
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

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

enum pcep_notification_types {
    PCEP_NOTIFY_TYPE_PENDING_REQUEST_CANCELLED = 1,
    PCEP_NOTIFY_TYPE_PCE_OVERLOADED = 2
};

enum pcep_notification_values {
    PCEP_NOTIFY_VALUE_PCC_CANCELLED_REQUEST = 1,
    PCEP_NOTIFY_VALUE_PCE_CANCELLED_REQUEST = 2,
    PCEP_NOTIFY_VALUE_PCE_CURRENTLY_OVERLOADED = 1,
    PCEP_NOTIFY_VALUE_PCE_NO_LONGER_OVERLOADED = 2
};

struct pcep_object_notify
{
    struct pcep_object_header header;
    uint8_t reserved;
    uint8_t flags;    /* No flags currently defined */
    uint8_t notification_type;
    uint8_t notification_value;
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
    struct pcep_object_tlv err_code;
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

struct pcep_object_ro
{
    struct pcep_object_header header;
}__attribute__((packed));

/* Common Route Object sub-object types
 * used by ERO, IRO, and RRO */
enum pcep_ro_subobj_types
{
    RO_SUBOBJ_TYPE_IPV4 = 1,
    RO_SUBOBJ_TYPE_IPV6 = 2,
    RO_SUBOBJ_TYPE_LABEL = 3,
    RO_SUBOBJ_TYPE_UNNUM = 4,
    RO_SUBOBJ_TYPE_BORDER = 10,
    RO_SUBOBJ_TYPE_ASN = 32,
    RO_SUBOBJ_TYPE_SR_DRAFT07 = 5,
    RO_SUBOBJ_TYPE_SR = 36
};

#define LOOSE_HOP_BIT 0x80

/*
 * Common Route Object sub-object definitions
 * used by ERO, IRO, and RRO
 */

struct pcep_ro_subobj_hdr
{
    uint8_t type;          /* loose bit and sub-object type (0x01 = strict IPv4 hop) */
    uint8_t length;        /* sub-object length (in bytes) */
}__attribute__((packed));

struct pcep_ro_subobj_ipv4
{
    struct pcep_ro_subobj_hdr header;
    struct in_addr ip_addr;
    uint8_t prefix_length; // prefix length
    uint8_t resvd;         // reserved bits (padding)
}__attribute__((packed));

struct pcep_ro_subobj_ipv6
{
    struct pcep_ro_subobj_hdr header;
    struct in6_addr ip_addr;
    uint8_t prefix_length; // prefix length
    uint8_t resvd;         // reserved bits (padding)
}__attribute__((packed));

struct pcep_ro_subobj_unnum
{
    struct pcep_ro_subobj_hdr header;
    uint16_t resv;
    struct in_addr routerId;
    uint32_t ifId;
}__attribute__((packed));

struct pcep_ro_subobj_32label
{
    struct pcep_ro_subobj_hdr header;
    uint8_t upstream:1; // upstream(1)/downstream(0) bit indication
    uint8_t resvd:7;
    uint8_t class_type; // label class-type (generalized label = 2)
    uint32_t label;     // label supported */
}__attribute__((packed));

struct pcep_ro_subobj_asn
{
    struct pcep_ro_subobj_hdr header;
    uint16_t aut_sys_number;       // Autonomous system number
}__attribute__((packed));

/* Non standard object to include layer information in the returned path. */
struct pcep_ro_subobj_border
{
    struct pcep_ro_subobj_hdr header;
    uint8_t direction:1;
    uint8_t flags:7;
    uint8_t swcap_from;
    uint8_t swcap_to;
    uint8_t swcap_info_fst;
    uint8_t swcap_info_sec;
    uint8_t swcap_info_thr;
}__attribute__((packed));

/* The SR ERO and SR RRO subojbects are the same, except
 * the SR-RRO does not have the L flag in the Type field.
 * Defined in draft-ietf-pce-segment-routing-16
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |L|   Type=36   |     Length    |  NT   |     Flags     |F|S|C|M|
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
enum pcep_sr_subobj_nai
{
      PCEP_SR_SUBOBJ_NAI_ABSENT = 0,
      PCEP_SR_SUBOBJ_NAI_IPV4_NODE = (1 << 12),
      PCEP_SR_SUBOBJ_NAI_IPV6_NODE = (2 << 12),
      PCEP_SR_SUBOBJ_NAI_IPV4_ADJACENCY = (3 << 12),
      PCEP_SR_SUBOBJ_NAI_IPV6_ADJACENCY = (4 << 12),
      PCEP_SR_SUBOBJ_NAI_UNNUMBERED_IPV4_ADJACENCY = (5 << 12),
      PCEP_SR_SUBOBJ_NAI_LINK_LOCAL_IPV6_ADJACENCY = (6 << 12)
};

enum pcep_sr_subobj_flags
{
    PCEP_SR_SUBOBJ_M_FLAG = 1,
    PCEP_SR_SUBOBJ_C_FLAG = 2,
    PCEP_SR_SUBOBJ_S_FLAG = 4,
    PCEP_SR_SUBOBJ_F_FLAG = 8
};

struct pcep_ro_subobj_sr
{
    struct pcep_ro_subobj_hdr header;
    uint16_t nt_flags;
    /* The SID and NAI are optional depending on the flags,
     * and the NAI can be variable length */
    uint32_t sid_nai[];
}__attribute__((packed));

#define GET_SR_SUBOBJ_NT(sr_subobj_ptr)    ((sr_subobj_ptr)->nt_flags & 0xf000)
#define GET_SR_SUBOBJ_FLAGS(sr_subobj_ptr) ((sr_subobj_ptr)->nt_flags & 0x000f)
/* 0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ Label
   |                Label                  | TC  |S|       TTL     | Stack
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ Entry
 */
#define ENCODE_SR_ERO_SID(label_20bits, tc_3bits, stack_bottom_bit, ttl_8bits) \
    ( (((label_20bits)    << 12) & 0xfffff000) | \
      (((tc_3bits)         << 9) & 0x00000e00) | \
      (((stack_bottom_bit) << 8) & 0x00000100) | \
       ((ttl_8bits) & 0xff) )
#define GET_SR_ERO_SID_LABEL(SID)   ((SID & 0xfffff000) >> 12)
#define GET_SR_ERO_SID_TC(SID)      ((SID & 0x00000e00) >> 9)
#define GET_SR_ERO_SID_S(SID)       ((SID & 0x00000100) >> 8)
#define GET_SR_ERO_SID_TTL(SID)     ((SID & 0x000000ff))

struct pcep_object_ro_subobj
{
    union subobj {
        struct pcep_ro_subobj_ipv4 ipv4;
        struct pcep_ro_subobj_ipv6 ipv6;
        struct pcep_ro_subobj_unnum unnum;
        struct pcep_ro_subobj_32label label;
        struct pcep_ro_subobj_border border;
        struct pcep_ro_subobj_asn asn;
        struct pcep_ro_subobj_sr sr;
    } subobj;
};
#define GET_RO_SUBOBJ_LFLAG(ro_subobj_ptr) (((ro_subobj_ptr)->type & 0x80) >> 7)
#define GET_RO_SUBOBJ_TYPE(ro_subobj_ptr)  ((ro_subobj_ptr)->type & 0x7f)

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

/* Stateful PCE Request Parameters */
struct pcep_object_srp
{
    struct pcep_object_header header;
    uint32_t unused_flags:31;
    uint32_t lsp_remove:1;
    uint32_t srp_id_number;
}__attribute__((packed));

/* Label Switched Path Object
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                PLSP-ID                |Flags  |C|  O  |A|R|S|D|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
enum pcep_lsp_flags
{
    PCEP_LSP_D_FLAG =  1,
    PCEP_LSP_S_FLAG = (1 << 1),
    PCEP_LSP_R_FLAG = (1 << 2),
    PCEP_LSP_A_FLAG = (1 << 3),
    /* O Flag defined below in pcep_lsp_operational_status */
    PCEP_LSP_C_FLAG = (1 << 7),
};

enum pcep_lsp_operational_status
{
    PCEP_LSP_OPERATIONAL_DOWN       = 0,
    PCEP_LSP_OPERATIONAL_UP         = (1 << 4),
    PCEP_LSP_OPERATIONAL_ACTIVE     = (2 << 4),
    PCEP_LSP_OPERATIONAL_GOING_DOWN = (3 << 4),
    PCEP_LSP_OPERATIONAL_GOING_UP   = (4 << 4),
};

#define MAX_PLSP_ID 0x000fffff  /* The plsp_id is only 20 bits */
#define MAX_LSP_STATUS (7 << 4) /* The status is only 3 bits */
struct pcep_object_lsp
{
    struct pcep_object_header header;
    /* Since the plsp_id is 20 bits, bit fields wont work here*/
    uint32_t plsp_id_flags;
}__attribute__((packed));
#define GET_LSP_PCEPID(lsp_obj_ptr) ((MAX_PLSP_ID) & ((lsp_obj_ptr)->plsp_id_flags >> 12))

/* When iterating sub-objects or TLVs, limit to 10 in case corrupt data is received */
#define MAX_ITERATIONS 10

/*
 * All created objects will be in Host byte order.
 * The message containing the objects should be converted to Network byte order
 * with pcep_encode_msg_header() before sending, which will also convert the
 * Objects, TLVs, and sub-objects.
 */

struct pcep_object_open*                pcep_obj_create_open        (uint8_t keepalive, uint8_t deadtimer, uint8_t sid, double_linked_list *tlv_list);
struct pcep_object_rp*                  pcep_obj_create_rp          (uint8_t obj_hdr_flags, uint32_t obj_flags, uint32_t reqid, double_linked_list *tlv_list);
struct pcep_object_nopath*              pcep_obj_create_nopath      (uint8_t obj_hdr_flags, uint8_t ni, uint16_t obj_flags, uint32_t errorcode);
struct pcep_object_endpoints_ipv4*      pcep_obj_create_enpoint_ipv4(const struct in_addr* src_ipv4, const struct in_addr* dst_ipv4);
struct pcep_object_endpoints_ipv6*      pcep_obj_create_enpoint_ipv6(const struct in6_addr* src_ipv6, const struct in6_addr* dst_ipv6);
struct pcep_object_bandwidth*           pcep_obj_create_bandwidth   (float bandwidth);
struct pcep_object_metric*              pcep_obj_create_metric      (uint8_t flags, uint8_t type, float value);
struct pcep_object_lspa*                pcep_obj_create_lspa        (uint8_t prio, uint8_t hold_prio);
struct pcep_object_svec*                pcep_obj_create_svec        (bool srlg, bool node, bool link, uint16_t ids_count, uint32_t *ids);
struct pcep_object_error*               pcep_obj_create_error       (uint8_t error_type, uint8_t error_value);
struct pcep_object_close*               pcep_obj_create_close       (uint8_t flags, uint8_t reason);
struct pcep_object_srp*                 pcep_obj_create_srp         (bool lsp_remove, uint32_t srp_id_number, double_linked_list *tlv_list);
struct pcep_object_lsp*                 pcep_obj_create_lsp         (uint32_t plsp_id, enum pcep_lsp_operational_status status,
                                                                     bool c_flag, bool a_flag, bool r_flag, bool s_flag, bool d_flag,
                                                                     double_linked_list *tlv_list);

/* Route Object (Explicit ero, Reported rro, and Include iro) functions
 * First, the sub-objects should be created and appended to a double_linked_list,
 * then call one of these Route Object creation functions with the subobj list */
struct pcep_object_ro*            pcep_obj_create_ero      (double_linked_list* ero_list);
struct pcep_object_ro*            pcep_obj_create_rro      (double_linked_list* rro_list);
struct pcep_object_ro*            pcep_obj_create_iro      (double_linked_list* iro_list);
/* Route Object sub-object creation functions */
struct pcep_object_ro_subobj*     pcep_obj_create_ro_subobj_ipv4     (bool loose_hop, const struct in_addr* ro_ipv4, uint8_t prefix_len);
struct pcep_object_ro_subobj*     pcep_obj_create_ro_subobj_ipv6     (bool loose_hop, const struct in6_addr* ro_ipv6, uint8_t prefix_len);
struct pcep_object_ro_subobj*     pcep_obj_create_ro_subobj_unnum    (struct in_addr* routerId, uint32_t ifId, uint16_t resv);
struct pcep_object_ro_subobj*     pcep_obj_create_ro_subobj_32label  (uint8_t dir, uint32_t label);
struct pcep_object_ro_subobj*     pcep_obj_create_ro_subobj_border   (uint8_t direction, uint8_t swcap_from, uint8_t swcap_to);
struct pcep_object_ro_subobj*     pcep_obj_create_ro_subobj_asn      (uint16_t asn);

/* SR ERO and SR RRO creation functions for different NAI (Node/Adj ID) types.
 *  - The loose_hop is only used for sr ero and must always be false for sr rro.
 *  - The NAI value will be set internally, depending on which function is used.
 * m_flag:
 *  - If this flag is true, the SID value represents an MPLS label stack
 *    entry as specified in [RFC3032].  Otherwise, the SID value is an
 *    administratively configured value which represents an index into
 *    an MPLS label space (either SRGB or SRLB) per [RFC8402].
 * c_flag:
 *  - If the M flag and the C flag are both true, then the TC, S, and TTL
 *    fields in the MPLS label stack entry are specified by the PCE.  However,
 *    a PCC MAY choose to override these values according to its local policy
 *    and MPLS forwarding rules.
 *  - If the M flag is true but the C flag is false, then the TC, S, and TTL
 *    fields MUST be ignored by the PCC.
 *  - The PCC MUST set these fields according to its local policy and MPLS
 *    forwarding rules.
 *  - If the M flag is false then the C bit MUST be false. */
struct pcep_object_ro_subobj*     pcep_obj_create_ro_subobj_sr_nonai(bool loose_hop, uint32_t sid, bool draft07);
struct pcep_object_ro_subobj*     pcep_obj_create_ro_subobj_sr_ipv4_node(bool loose_hop, bool sid_absent, bool c_flag, bool m_flag,
                                                                         uint32_t sid, struct in_addr *ipv4_node_id,bool draft07);
struct pcep_object_ro_subobj*     pcep_obj_create_ro_subobj_sr_ipv6_node(bool loose_hop, bool sid_absent, bool c_flag, bool m_flag,
                                                                         uint32_t sid, struct in6_addr *ipv6_node_id, bool draft07);
struct pcep_object_ro_subobj*     pcep_obj_create_ro_subobj_sr_ipv4_adj(bool loose_hop, bool sid_absent, bool c_flag, bool m_flag,
                                                                        uint32_t sid, struct in_addr *local_ipv4, struct in_addr *remote_ipv4, bool draft07);
struct pcep_object_ro_subobj*     pcep_obj_create_ro_subobj_sr_ipv6_adj(bool loose_hop, bool sid_absent, bool c_flag, bool m_flag,
                                                                        uint32_t sid, struct in6_addr *local_ipv6, struct in6_addr *remote_ipv6, bool draft07);
struct pcep_object_ro_subobj*     pcep_obj_create_ro_subobj_sr_unnumbered_ipv4_adj(bool loose_hop, bool sid_absent, bool c_flag, bool m_flag,
                                                                                   uint32_t sid, uint32_t local_node_id, uint32_t local_if_id,
                                                                                   uint32_t remote_node_id, uint32_t remote_if_id, bool draft07);
struct pcep_object_ro_subobj*     pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj(bool loose_hop, bool sid_absent, bool c_flag, bool m_flag,
                                                                                  uint32_t sid, struct in6_addr *local_ipv6, uint32_t local_if_id,
                                                                                  struct in6_addr *remote_ipv6, uint32_t remote_if_id, bool draft07);

uint32_t*       pcep_obj_svec_get       (struct pcep_object_svec* obj, uint16_t *length, bool host_byte_order);
void            pcep_obj_svec_print     (struct pcep_object_svec* obj, bool host_byte_order);

/* This function is called by pcep_msg_encode() before sending messages
 * to change to Network byte order */
void pcep_obj_encode(struct pcep_object_header* hdr);

/* Called when a new message is received to parse and decode the objects in a message.
 * Returns false if the object is not valid, true otherwise. */
bool pcep_obj_parse_decode(struct pcep_object_header* hdr);

/* Used to get Sub-objects for PCEP_OBJ_CLASS_ERO, PCEP_OBJ_CLASS_IRO,
 * and PCEP_OBJ_CLASS_RRO objects. Will return NULL if the obj is not
 * one of these classes. Returns a double linked list of pointers of
 * type struct pcep_ro_subobj_hdr. Do not free these list entries, as
 * they are just pointers into the object structure. */
double_linked_list* pcep_obj_get_ro_subobjects(struct pcep_object_header *ro_obj);

/* Returns a double linked list of pointers of type struct pcep_object_tlv.
 * May return NULL for unrecognized object classes. Do not free these list
 * entries, as they are just pointers into the object structure. */
double_linked_list* pcep_obj_get_tlvs(struct pcep_object_header *hdr);
/* Only used by pcep-tools when the tlvs are in network byte order.
 * This version will decode the TLVs. */
double_linked_list* pcep_obj_get_encoded_tlvs(struct pcep_object_header *hdr);
bool pcep_obj_has_tlv(struct pcep_object_header* hdr);

#ifdef __cplusplus
}
#endif

#endif
