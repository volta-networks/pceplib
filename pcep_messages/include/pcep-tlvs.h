/*
 * pcep-tlvs.h
 *
 *  Created on: Oct 29, 2019
 *      Author: brady
 */

#ifndef PCEP_MESSAGES_INCLUDE_PCEP_TLVS_H_
#define PCEP_MESSAGES_INCLUDE_PCEP_TLVS_H_

#include <arpa/inet.h>
#include <stdint.h>

#include "pcep_utils_double_linked_list.h"

struct pcep_object_tlv_header
{
    uint16_t type;
    uint16_t length;
}__attribute__((packed));

/* TLV with a variable length value */
struct pcep_object_tlv
{
    struct pcep_object_tlv_header header;
    /* The TLV is padded to 4-bytes alignment,
     * padding not included in length */
    uint32_t value[];
}__attribute__((packed));

/* RSVP Object header defined for creating RSVP error TLVs: RFC 2205 */
struct rsvp_object_header
{
    uint16_t length;
    uint8_t  class_num;
    uint8_t  c_type;
}__attribute__((packed));

/* RSVP Error Spec defined for creating RSVP error TLVs: RFC 2205 */
struct rsvp_error_spec_ipv4
{
    struct in_addr error_node_ip;
    uint8_t flags;
    uint8_t error_code;
    uint16_t error_value;
}__attribute__((packed));

/* RSVP Error Spec defined for creating RSVP error TLVs: RFC 2205 */
struct rsvp_error_spec_ipv6
{
    struct in6_addr error_node_ip;
    uint8_t flags;
    uint8_t error_code;
    uint16_t error_value;
}__attribute__((packed));

/* These numbers can be found here:
 * https://www.iana.org/assignments/pcep/pcep.xhtml */
enum pcep_object_tlv_types
{
    PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY = 16,     /* RFC 8231 */
    PCEP_OBJ_TLV_TYPE_SYMBOLIC_PATH_NAME = 17,          /* RFC 8232 */
    PCEP_OBJ_TLV_TYPE_IPV4_LSP_IDENTIFIERS = 18,        /* RFC 8231 */
    PCEP_OBJ_TLV_TYPE_IPV6_LSP_IDENTIFIERS = 19,        /* RFC 8231 */
    PCEP_OBJ_TLV_TYPE_LSP_ERROR_CODE = 20,              /* RFC 8232 */
    PCEP_OBJ_TLV_TYPE_RSVP_ERROR_SPEC = 21,             /* RFC 8232 */
    PCEP_OBJ_TLV_TYPE_LSP_DB_VERSION = 23,              /* RFC 8232 */
    PCEP_OBJ_TLV_TYPE_SPEAKER_ENTITY_ID = 24,           /* RFC 8232 */
    PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY = 26,           /* draft-ietf-pce-segment-routing-16 */
    PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE = 34,             /* draft-ietf-pce-segment-routing-16, RFC 8408 */
};

/* Open STATEFUL-PCE-CAPABILITY TLV Capability flags
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |               Type            |            Length=4           |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |              Flags                                |F|D|T|I|S|U|
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+
 */
enum pcep_tlv_flags_stateful_pce_capability {
    PCEP_TLV_FLAG_LSP_UPDATE_CAPABILITY   = (1 << 0),  /* U flag - RFC 8231 */
    PCEP_TLV_FLAG_INCLUDE_DB_VERSION      = (1 << 1),  /* S flag - RFC 8232 */
    PCEP_TLV_FLAG_LSP_INSTANTIATION       = (1 << 2),  /* I flag - RFC 8281 */
    PCEP_TLV_FLAG_TRIGGERED_RESYNC        = (1 << 3),  /* T flag - RFC 8281 */
    PCEP_TLV_FLAG_DELTA_LSP_SYNC          = (1 << 4),  /* D flag - RFC 8281 */
    PCEP_TLV_FLAG_TRIGGERED_INITIAL_SYNC  = (1 << 5),  /* F flag - RFC 8281 */
};

enum pcep_tlv_flags_sr_pce_capability {
    PCEP_TLV_FLAG_NO_MSD_LIMITS           = (1 << 0),  /* SR PCE CAPABILITY X flag - draft-ietf-pce-segment-routing-16 */
    PCEP_TLV_FLAG_SR_PCE_CAPABILITY_NAI   = (1 << 1)   /* SR PCE CAPABILITY N flag - draft-ietf-pce-segment-routing-16 */
};

enum pcep_tlv_lsp_error_codes {
    PCEP_TLV_LSP_ERROR_CODE_UNKNOWN = 1,
    PCEP_TLV_LSP_ERROR_CODE_LSP_LIMIT_REACHED = 2,
    PCEP_TLV_LSP_ERROR_CODE_TOO_MANY_PENDING_LSP_UPDATES = 3,
    PCEP_TLV_LSP_ERROR_CODE_UNACCEPTABLE_PARAMS = 4,
    PCEP_TLV_LSP_ERROR_CODE_INTERNAL_ERROR = 5,
    PCEP_TLV_LSP_ERROR_CODE_LSP_BROUGHT_DOWN = 6,
    PCEP_TLV_LSP_ERROR_CODE_LSP_PREEMPTED = 7,
    PCEP_TLV_LSP_ERROR_CODE_RSVP_SIGNALING_ERROR = 8,
};

/*
 * TLV creation functions
 */

/*
 * Open Object TLVs
 */

    /* Use enum pcep_tlv_flags_stateful_pce_capability to populate the flags field */
struct pcep_object_tlv *pcep_tlv_create_stateful_pce_capability(uint8_t flags);

    /* speaker_entity_id_list is a double linked list of uint32_t* */
struct pcep_object_tlv *pcep_tlv_create_speaker_entity_id(double_linked_list *speaker_entity_id_list);

struct pcep_object_tlv *pcep_tlv_create_lsp_db_version(uint64_t lsp_db_version);

    /* pst_list is a double linked list of uint8_t* and sub_tlv_list is a double linked list of struct pcep_object_tlv* */
struct pcep_object_tlv *pcep_tlv_create_path_setup_type(double_linked_list *pst_list, double_linked_list *sub_tlv_list);

    /* Use enum pcep_tlv_flags_sr_pce_capability to populate the flags field */
struct pcep_object_tlv *pcep_tlv_create_sr_pce_capability(uint8_t flags, uint8_t max_sid_depth);


/*
 * LSP Object TLVs
 */

    /* symbolic_path_name_length should NOT include the null terminator and cannot be zero */
struct pcep_object_tlv *pcep_tlv_create_symbolic_path_name(
        char *symbolic_path_name, uint16_t symbolic_path_name_length);

struct pcep_object_tlv *pcep_tlv_create_ipv4_lsp_identifiers(
        struct in_addr *ipv4_tunnel_sender, struct in_addr *ipv4_tunnel_endpoint,
        uint16_t lsp_id, uint16_t tunnel_id, uint32_t extended_tunnel_id);

    /* extended_tunnel_id must be uint32_t[4] */
struct pcep_object_tlv *pcep_tlv_create_ipv6_lsp_identifiers(
        struct in6_addr *ipv6_tunnel_sender, struct in6_addr *ipv6_tunnel_endpoint,
        uint16_t lsp_id, uint16_t tunnel_id, uint32_t extended_tunnel_id[]);

struct pcep_object_tlv *pcep_tlv_create_lsp_error_code(enum pcep_tlv_lsp_error_codes rsvp_error_code);

struct pcep_object_tlv*
pcep_tlv_create_rsvp_ipv4_error_spec(
        struct in_addr *error_node_ip, uint8_t flags, uint8_t error_code, uint16_t error_value);

struct pcep_object_tlv*
pcep_tlv_create_rsvp_ipv6_error_spec(
        struct in6_addr *error_node_ip, uint8_t flags, uint8_t error_code, uint16_t error_value);

#endif /* PCEP_MESSAGES_INCLUDE_PCEP_TLVS_H_ */
