/*
 * pcep-tlvs.c
 *
 *  Created on: Oct 29, 2019
 *      Author: brady
 */

#include <malloc.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "pcep-tlvs.h"

/*
 * Open Object TLVs
 */

struct pcep_object_tlv*
pcep_tlv_create_stateful_pce_capability(uint8_t flags)
{
    /* Use enum pcep_tlv_pce_capability_flags to populate the flags field */
    struct pcep_object_tlv *tlv = malloc(sizeof(struct pcep_object_tlv_header) + 4);
    bzero(tlv, sizeof(struct pcep_object_tlv_header) + 4);

    tlv->header.type = htons(PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY);
    tlv->header.length = htons(4);
    tlv->value[0] = htonl(0x000000ff & flags);

    return tlv;
}

struct pcep_object_tlv*
pcep_tlv_create_speaker_entity_id(double_linked_list *speaker_entity_id_list)
{
    if (speaker_entity_id_list == NULL)
    {
        return NULL;
    }

    if (speaker_entity_id_list->num_entries == 0)
    {
        return NULL;
    }

    /* speaker_entity_id_list is a double list of uint32_t* */
    struct pcep_object_tlv *tlv = malloc(sizeof(struct pcep_object_tlv_header) + speaker_entity_id_list->num_entries);
    bzero(tlv, sizeof(struct pcep_object_tlv_header) + speaker_entity_id_list->num_entries);

    tlv->header.type = htons(PCEP_OBJ_TLV_TYPE_SPEAKER_ENTITY_ID);
    tlv->header.length = htons(speaker_entity_id_list->num_entries * sizeof(uint32_t));

    int index = 0;
    double_linked_list_node *entity_id_node = speaker_entity_id_list->head;
    for(; entity_id_node != NULL; entity_id_node = entity_id_node->next_node)
    {
        tlv->value[index++] = htonl(*((uint32_t *) entity_id_node->data));
    }

    return tlv;
}

struct pcep_object_tlv*
pcep_tlv_create_lsp_db_version(uint64_t lsp_db_version)
{
    struct pcep_object_tlv *tlv = malloc(sizeof(struct pcep_object_tlv_header) + 8);
    bzero(tlv, sizeof(struct pcep_object_tlv_header) + 8);

    tlv->header.type = htons(PCEP_OBJ_TLV_TYPE_LSP_DB_VERSION);
    tlv->header.length = htons(8);
    /* the lsp_db_version should be network byte order, which is big endian */
    *((uint64_t *) tlv->value) = htobe64(lsp_db_version);

    return tlv;
}

struct pcep_object_tlv*
pcep_tlv_create_path_setup_type(double_linked_list *pst_list, double_linked_list *sub_tlv_list)
{
    if (pst_list == NULL)
    {
        return NULL;
    }

    if (pst_list->num_entries == 0)
    {
        return NULL;
    }

    /*
     * pst_list is a double list of uint8_t* and sub_tlv_list
     * is a double list of struct pcep_object_tlv*
     * The Rub TLVs are optional.
     */

    /* Calculate the length of the psts */
    /* We need to take into account the padding when allocating the buffer */
    int buffer_length = sizeof(uint32_t) + /* The reserved + Num Pst's is a uint 32_t */
            pst_list->num_entries + (4 - (pst_list->num_entries % 4));

    /* Calculate the length of the sub-tlvs */
    int sub_tlv_length = 0;
    double_linked_list_node *node;
    if (sub_tlv_list != NULL)
    {
        node = sub_tlv_list->head;
        for(; node != NULL; node = node->next_node)
        {
            struct pcep_object_tlv_header *sub_tlv = node->data;
            sub_tlv_length += ntohs(sub_tlv->length) + sizeof(struct pcep_object_tlv_header);
        }
        buffer_length += sub_tlv_length;
    }

    struct pcep_object_tlv *tlv = malloc(sizeof(struct pcep_object_tlv_header) + buffer_length);
    bzero(tlv, sizeof(struct pcep_object_tlv_header) + buffer_length);

    /* The TLV length does not include padding */
    tlv->header.length = htons(pst_list->num_entries + sub_tlv_length);
    tlv->header.type = htons(PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE);

    /* Write the number of PSTs */
    tlv->value[0] = pst_list->num_entries;

    /* Write each of the PSTs */
    int index = 4; /* Get past the reserved and NumPSTs bytes */
    node = pst_list->head;
    for(; node != NULL; node = node->next_node)
    {
        uint8_t *pst = (uint8_t *) node->data;
        memcpy(((uint8_t *) tlv->value) + index, pst, sizeof(uint8_t));
        index += sizeof(uint8_t);
    }

    /* Write each of the sub-tlvs */
    if (sub_tlv_list != NULL)
    {
        index = 4 + pst_list->num_entries + (4 - (pst_list->num_entries % 4));
        node = sub_tlv_list->head;
        for(; node != NULL; node = node->next_node)
        {
            struct pcep_object_tlv_header *sub_tlv = node->data;
            memcpy(((uint8_t *) tlv->value) + index, sub_tlv,
                    sizeof(struct pcep_object_tlv_header) + ntohs(sub_tlv->length));
            index += sizeof(struct pcep_object_tlv_header) + ntohs(sub_tlv->length);
        }
    }

    return tlv;
}

struct pcep_object_tlv*
pcep_tlv_create_sr_pce_capability(uint8_t flags, uint8_t max_sid_depth)
{
    struct pcep_object_tlv *tlv = malloc(sizeof(struct pcep_object_tlv_header) + 4);
    bzero(tlv, sizeof(struct pcep_object_tlv_header) + 4);

    tlv->header.type = htons(PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY);
    tlv->header.length = htons(4);
    tlv->value[0] = htonl((flags << 8) | max_sid_depth);

    return tlv;
}

/*
 * LSP Object TLVs
 */

struct pcep_object_tlv*
pcep_tlv_create_symbolic_path_name(char *symbolic_path_name, uint16_t symbolic_path_name_length)
{
    /* symbolic_path_name_length should NOT include the null terminator and cannot be zero */
    if (symbolic_path_name == NULL || symbolic_path_name_length == 0)
    {
        return NULL;
    }

    struct pcep_object_tlv *tlv = malloc(
            sizeof(struct pcep_object_tlv_header) +
            symbolic_path_name_length + (4 - (symbolic_path_name_length % 4)));
    bzero(tlv, sizeof(struct pcep_object_tlv_header) +
               symbolic_path_name_length + (4 - (symbolic_path_name_length % 4)));

    tlv->header.type = htons(PCEP_OBJ_TLV_TYPE_SYMBOLIC_PATH_NAME);
    tlv->header.length = htons(symbolic_path_name_length);
    memcpy((uint8_t *) tlv->value, symbolic_path_name, symbolic_path_name_length);

    return tlv;
}

struct pcep_object_tlv*
pcep_tlv_create_ipv4_lsp_identifiers(struct in_addr *ipv4_tunnel_sender,
        struct in_addr *ipv4_tunnel_endpoint, uint16_t lsp_id,
        uint16_t tunnel_id, uint32_t extended_tunnel_id)
{
    if (ipv4_tunnel_sender == NULL || ipv4_tunnel_endpoint == NULL)
    {
        return NULL;
    }

    struct pcep_object_tlv *tlv = malloc(sizeof(struct pcep_object_tlv_header) + 16);
    bzero(tlv, sizeof(struct pcep_object_tlv_header) + 16);

    tlv->header.type = htons(PCEP_OBJ_TLV_TYPE_IPV4_LSP_IDENTIFIERS);
    tlv->header.length = htons(16);
    tlv->value[0] = htonl(ipv4_tunnel_sender->s_addr);
    tlv->value[1] = 0x0000ffff & htons(tunnel_id);
    tlv->value[1] |= (htons(lsp_id) << 16);
    tlv->value[2] = htonl(extended_tunnel_id);
    tlv->value[3] = htonl(ipv4_tunnel_endpoint->s_addr);

    return tlv;
}

    /* extended_tunnel_id must be uint32_t[4] */
struct pcep_object_tlv*
pcep_tlv_create_ipv6_lsp_identifiers(struct in6_addr *ipv6_tunnel_sender,
        struct in6_addr *ipv6_tunnel_endpoint, uint16_t lsp_id,
        uint16_t tunnel_id, uint32_t extended_tunnel_id[])
{
    if (ipv6_tunnel_sender == NULL || ipv6_tunnel_endpoint == NULL)
    {
        return NULL;
    }

    struct pcep_object_tlv *tlv = malloc(sizeof(struct pcep_object_tlv_header) + 52);
    bzero(tlv, sizeof(struct pcep_object_tlv_header) + 52);

    tlv->header.type = htons(PCEP_OBJ_TLV_TYPE_IPV6_LSP_IDENTIFIERS);
    tlv->header.length = htons(52);

    tlv->value[0] = htonl(ipv6_tunnel_sender->__in6_u.__u6_addr32[0]);
    tlv->value[1] = htonl(ipv6_tunnel_sender->__in6_u.__u6_addr32[1]);
    tlv->value[2] = htonl(ipv6_tunnel_sender->__in6_u.__u6_addr32[2]);
    tlv->value[3] = htonl(ipv6_tunnel_sender->__in6_u.__u6_addr32[3]);

    tlv->value[4] = 0x0000ffff & htons(tunnel_id);
    tlv->value[4] |= (htons(lsp_id) << 16);

    tlv->value[5] = htonl(extended_tunnel_id[0]);
    tlv->value[6] = htonl(extended_tunnel_id[1]);
    tlv->value[7] = htonl(extended_tunnel_id[2]);
    tlv->value[8] = htonl(extended_tunnel_id[3]);

    tlv->value[9]  = htonl(ipv6_tunnel_endpoint->__in6_u.__u6_addr32[0]);
    tlv->value[10] = htonl(ipv6_tunnel_endpoint->__in6_u.__u6_addr32[1]);
    tlv->value[11] = htonl(ipv6_tunnel_endpoint->__in6_u.__u6_addr32[2]);
    tlv->value[12] = htonl(ipv6_tunnel_endpoint->__in6_u.__u6_addr32[3]);

    return tlv;
}

struct pcep_object_tlv*
pcep_tlv_create_lsp_error_code(enum pcep_tlv_lsp_error_codes rsvp_error_code)
{
    struct pcep_object_tlv *tlv = malloc(sizeof(struct pcep_object_tlv_header) + 4);
    bzero(tlv, sizeof(struct pcep_object_tlv_header) + 4);

    tlv->header.type = htons(PCEP_OBJ_TLV_TYPE_LSP_ERROR_CODE);
    tlv->header.length = htons(4);
    tlv->value[0] = htonl(rsvp_error_code);

    return tlv;
}

struct pcep_object_tlv*
pcep_tlv_create_rsvp_ipv4_error_spec(struct in_addr *error_node_ip, uint8_t flags,
        uint8_t error_code, uint16_t error_value)
{
    if (error_node_ip == NULL)
    {
        return NULL;
    }

    uint16_t rsvp_length = sizeof(struct rsvp_object_header) +
                           sizeof(struct rsvp_error_spec_ipv4);
    struct pcep_object_tlv *tlv = malloc(sizeof(struct pcep_object_tlv_header) + rsvp_length);
    bzero(tlv, sizeof(struct pcep_object_tlv_header) + rsvp_length);

    tlv->header.type = htons(PCEP_OBJ_TLV_TYPE_RSVP_ERROR_SPEC);
    tlv->header.length = htons(rsvp_length);

    struct rsvp_object_header *rsvp_header = (struct rsvp_object_header *) tlv->value;
    rsvp_header->c_type = 1;
    rsvp_header->class_num = 6;
    rsvp_header->length = htons(rsvp_length);

    struct rsvp_error_spec_ipv4 *error_spec = (struct rsvp_error_spec_ipv4 *) &(tlv->value[4]);
    error_spec->error_node_ip.s_addr = htonl(error_node_ip->s_addr);
    error_spec->flags = flags;
    error_spec->error_code = error_code;
    error_spec->error_value = htons(error_value);

    return tlv;
}

struct pcep_object_tlv*
pcep_tlv_create_rsvp_ipv6_error_spec(struct in6_addr *error_node_ip, uint8_t flags,
        uint8_t error_code, uint16_t error_value)
{
    if (error_node_ip == NULL)
    {
        return NULL;
    }

    uint16_t rsvp_length = sizeof(struct rsvp_object_header) +
                           sizeof(struct rsvp_error_spec_ipv6);
    struct pcep_object_tlv *tlv = malloc(sizeof(struct pcep_object_tlv_header) + rsvp_length);
    bzero(tlv, sizeof(struct pcep_object_tlv_header) + rsvp_length);

    tlv->header.type = htons(PCEP_OBJ_TLV_TYPE_RSVP_ERROR_SPEC);
    tlv->header.length = htons(rsvp_length);

    struct rsvp_object_header *rsvp_header = (struct rsvp_object_header *) tlv->value;
    rsvp_header->c_type = 2;
    rsvp_header->class_num = 6;
    rsvp_header->length = htons(rsvp_length);

    struct rsvp_error_spec_ipv6 * error_spec = (struct rsvp_error_spec_ipv6 *) &(tlv->value[4]);
    error_spec->error_node_ip.__in6_u.__u6_addr32[0] = htonl(error_node_ip->__in6_u.__u6_addr32[0]);
    error_spec->error_node_ip.__in6_u.__u6_addr32[1] = htonl(error_node_ip->__in6_u.__u6_addr32[1]);
    error_spec->error_node_ip.__in6_u.__u6_addr32[2] = htonl(error_node_ip->__in6_u.__u6_addr32[2]);
    error_spec->error_node_ip.__in6_u.__u6_addr32[3] = htonl(error_node_ip->__in6_u.__u6_addr32[3]);
    error_spec->flags = flags;
    error_spec->error_code = error_code;
    error_spec->error_value = htons(error_value);

    return tlv;
}
