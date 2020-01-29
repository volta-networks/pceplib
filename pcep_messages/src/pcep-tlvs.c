/*
 * This is the implementation of a High Level PCEP message object TLV API.
 *
 * Author : Brady Johnson <brady@voltanet.io>
 */

#include <malloc.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "pcep-tlvs.h"

static struct pcep_object_tlv_header* pcep_tlv_common_create(enum pcep_object_tlv_types type, uint16_t size)
{
    struct pcep_object_tlv_header *tlv = malloc(size);
    bzero(tlv, size);
    tlv->type = type;

    return tlv;
}

/*
 * Open Object TLVs
 */

struct pcep_object_tlv_stateful_pce_capability*
pcep_tlv_create_stateful_pce_capability(bool flag_u_lsp_update_capability,
                                        bool flag_s_include_db_version,
                                        bool flag_i_lsp_instantiation_capability,
                                        bool flag_t_triggered_resync,
                                        bool flag_d_delta_lsp_sync,
                                        bool flag_f_triggered_initial_sync)
{
    struct pcep_object_tlv_stateful_pce_capability *tlv =
            (struct pcep_object_tlv_stateful_pce_capability *)
            pcep_tlv_common_create(PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY,
                    sizeof(struct pcep_object_tlv_stateful_pce_capability));
    tlv->flag_u_lsp_update_capability         =  flag_u_lsp_update_capability;
    tlv->flag_s_include_db_version            =  flag_s_include_db_version;
    tlv->flag_i_lsp_instantiation_capability  =  flag_i_lsp_instantiation_capability;
    tlv->flag_t_triggered_resync              =  flag_t_triggered_resync;
    tlv->flag_d_delta_lsp_sync                =  flag_d_delta_lsp_sync;
    tlv->flag_f_triggered_initial_sync        =  flag_f_triggered_initial_sync;

    return tlv;
}

struct pcep_object_tlv_lsp_db_version*
pcep_tlv_create_lsp_db_version(uint64_t lsp_db_version)
{
    struct pcep_object_tlv_lsp_db_version *tlv =
            (struct pcep_object_tlv_lsp_db_version *)
            pcep_tlv_common_create(PCEP_OBJ_TLV_TYPE_LSP_DB_VERSION,
                    sizeof(struct pcep_object_tlv_lsp_db_version));
    tlv->lsp_db_version = lsp_db_version;

    return tlv;
}

struct pcep_object_tlv_speaker_entity_identifier*
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

    struct pcep_object_tlv_speaker_entity_identifier *tlv =
            (struct pcep_object_tlv_speaker_entity_identifier *)
            pcep_tlv_common_create(PCEP_OBJ_TLV_TYPE_SPEAKER_ENTITY_ID,
                    sizeof(struct pcep_object_tlv_speaker_entity_identifier));
    tlv->speaker_entity_id_list = speaker_entity_id_list;

    return tlv;
}

struct pcep_object_tlv_path_setup_type*
pcep_tlv_create_path_setup_type(uint8_t pst)
{
    struct pcep_object_tlv_path_setup_type *tlv =
            (struct pcep_object_tlv_path_setup_type *)
            pcep_tlv_common_create(PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE,
                    sizeof(struct pcep_object_tlv_path_setup_type));
    tlv->path_setup_type = pst;

    return tlv;
}

struct pcep_object_tlv_path_setup_type_capability*
pcep_tlv_create_path_setup_type_capability(double_linked_list *pst_list, double_linked_list *sub_tlv_list)
{
    if (pst_list == NULL)
    {
        return NULL;
    }

    if (pst_list->num_entries == 0)
    {
        return NULL;
    }

    struct pcep_object_tlv_path_setup_type_capability *tlv =
            (struct pcep_object_tlv_path_setup_type_capability *)
            pcep_tlv_common_create(PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE_CAPABILITY,
                    sizeof(struct pcep_object_tlv_path_setup_type_capability));

    tlv->pst_list = pst_list;
    tlv->sub_tlv_list = sub_tlv_list;

    return tlv;
}

struct pcep_object_tlv_sr_pce_capability*
pcep_tlv_create_sr_pce_capability(bool flag_n, bool flag_x, uint8_t max_sid_depth)
{
    struct pcep_object_tlv_sr_pce_capability *tlv =
            (struct pcep_object_tlv_sr_pce_capability *)
            pcep_tlv_common_create(PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY,
                    sizeof(struct pcep_object_tlv_sr_pce_capability));
    tlv->flag_n = flag_n;
    tlv->flag_x = flag_x;
    tlv->max_sid_depth = max_sid_depth;

    return tlv;
}


/*
 * LSP Object TLVs
 */

struct pcep_object_tlv_ipv4_lsp_identifier*
pcep_tlv_create_ipv4_lsp_identifiers(struct in_addr *ipv4_tunnel_sender,
        struct in_addr *ipv4_tunnel_endpoint, uint16_t lsp_id,
        uint16_t tunnel_id, struct in_addr *extended_tunnel_id)
{
    if (ipv4_tunnel_sender == NULL || ipv4_tunnel_endpoint == NULL)
    {
        return NULL;
    }

    struct pcep_object_tlv_ipv4_lsp_identifier *tlv =
            (struct pcep_object_tlv_ipv4_lsp_identifier *)
            pcep_tlv_common_create(PCEP_OBJ_TLV_TYPE_IPV4_LSP_IDENTIFIERS,
                    sizeof(struct pcep_object_tlv_ipv4_lsp_identifier));
    tlv->ipv4_tunnel_sender.s_addr = ipv4_tunnel_sender->s_addr;
    tlv->ipv4_tunnel_endpoint.s_addr = ipv4_tunnel_endpoint->s_addr;
    tlv->lsp_id = lsp_id;
    tlv->tunnel_id = tunnel_id;
    tlv->extended_tunnel_id.s_addr = extended_tunnel_id->s_addr ;

    return tlv;
}

struct pcep_object_tlv_ipv6_lsp_identifier*
pcep_tlv_create_ipv6_lsp_identifiers(struct in6_addr *ipv6_tunnel_sender,
        struct in6_addr *ipv6_tunnel_endpoint, uint16_t lsp_id,
        uint16_t tunnel_id, struct in6_addr *extended_tunnel_id)
{
    if (ipv6_tunnel_sender == NULL || ipv6_tunnel_endpoint == NULL)
    {
        return NULL;
    }

    struct pcep_object_tlv_ipv6_lsp_identifier *tlv =
            (struct pcep_object_tlv_ipv6_lsp_identifier *)
            pcep_tlv_common_create(PCEP_OBJ_TLV_TYPE_IPV6_LSP_IDENTIFIERS,
                    sizeof(struct pcep_object_tlv_ipv6_lsp_identifier));

    tlv->ipv6_tunnel_sender.__in6_u.__u6_addr32[0] = ipv6_tunnel_sender->__in6_u.__u6_addr32[0];
    tlv->ipv6_tunnel_sender.__in6_u.__u6_addr32[1] = ipv6_tunnel_sender->__in6_u.__u6_addr32[1];
    tlv->ipv6_tunnel_sender.__in6_u.__u6_addr32[2] = ipv6_tunnel_sender->__in6_u.__u6_addr32[2];
    tlv->ipv6_tunnel_sender.__in6_u.__u6_addr32[3] = ipv6_tunnel_sender->__in6_u.__u6_addr32[3];

    tlv->tunnel_id = tunnel_id;
    tlv->lsp_id = lsp_id;

    tlv->extended_tunnel_id.__in6_u.__u6_addr32[0] = extended_tunnel_id->__in6_u.__u6_addr32[0];
    tlv->extended_tunnel_id.__in6_u.__u6_addr32[1] = extended_tunnel_id->__in6_u.__u6_addr32[1];
    tlv->extended_tunnel_id.__in6_u.__u6_addr32[2] = extended_tunnel_id->__in6_u.__u6_addr32[2];
    tlv->extended_tunnel_id.__in6_u.__u6_addr32[3] = extended_tunnel_id->__in6_u.__u6_addr32[3];

    tlv->ipv6_tunnel_endpoint.__in6_u.__u6_addr32[0] = ipv6_tunnel_endpoint->__in6_u.__u6_addr32[0];
    tlv->ipv6_tunnel_endpoint.__in6_u.__u6_addr32[1] = ipv6_tunnel_endpoint->__in6_u.__u6_addr32[1];
    tlv->ipv6_tunnel_endpoint.__in6_u.__u6_addr32[2] = ipv6_tunnel_endpoint->__in6_u.__u6_addr32[2];
    tlv->ipv6_tunnel_endpoint.__in6_u.__u6_addr32[3] = ipv6_tunnel_endpoint->__in6_u.__u6_addr32[3];

    return tlv;
}

struct pcep_object_tlv_symbolic_path_name*
pcep_tlv_create_symbolic_path_name(char *symbolic_path_name, uint16_t symbolic_path_name_length)
{
    /* symbolic_path_name_length should NOT include the null terminator and cannot be zero */
    if (symbolic_path_name == NULL || symbolic_path_name_length == 0)
    {
        return NULL;
    }

    struct pcep_object_tlv_symbolic_path_name *tlv =
            (struct pcep_object_tlv_symbolic_path_name *)
            pcep_tlv_common_create(PCEP_OBJ_TLV_TYPE_SYMBOLIC_PATH_NAME,
                    sizeof(struct pcep_object_tlv_symbolic_path_name));

    uint16_t length =(symbolic_path_name_length > MAX_SYMBOLIC_PATH_NAME) ?
            MAX_SYMBOLIC_PATH_NAME : symbolic_path_name_length;
    memcpy(tlv->symbolic_path_name, symbolic_path_name, length);
    tlv->symbolic_path_name_length = length;

    return tlv;
}

struct pcep_object_tlv_lsp_error_code*
pcep_tlv_create_lsp_error_code(enum pcep_tlv_lsp_error_codes lsp_error_code)
{
    struct pcep_object_tlv_lsp_error_code *tlv =
            (struct pcep_object_tlv_lsp_error_code *)
            pcep_tlv_common_create(PCEP_OBJ_TLV_TYPE_LSP_ERROR_CODE,
                    sizeof(struct pcep_object_tlv_lsp_error_code));
    tlv->lsp_error_code = lsp_error_code;

    return tlv;
}

struct pcep_object_tlv_rsvp_error_spec*
pcep_tlv_create_rsvp_ipv4_error_spec(struct in_addr *error_node_ip, uint8_t error_code, uint16_t error_value)
{
    if (error_node_ip == NULL)
    {
        return NULL;
    }

    struct pcep_object_tlv_rsvp_error_spec *tlv =
            (struct pcep_object_tlv_rsvp_error_spec *)
            pcep_tlv_common_create(PCEP_OBJ_TLV_TYPE_RSVP_ERROR_SPEC,
                    sizeof(struct pcep_object_tlv_rsvp_error_spec));

    tlv->c_type = RSVP_ERROR_SPEC_IPV4_CTYPE;
    tlv->class_num = RSVP_ERROR_SPEC_CLASS_NUM;
    tlv->error_code = error_code;
    tlv->error_value = error_value;
    tlv->error_spec_ip.ipv4_error_node_address.s_addr = error_node_ip->s_addr;

    return tlv;
}

struct pcep_object_tlv_rsvp_error_spec*
pcep_tlv_create_rsvp_ipv6_error_spec(struct in6_addr *error_node_ip, uint8_t error_code, uint16_t error_value)
{
    if (error_node_ip == NULL)
    {
        return NULL;
    }

    struct pcep_object_tlv_rsvp_error_spec *tlv =
            (struct pcep_object_tlv_rsvp_error_spec *)
            pcep_tlv_common_create(PCEP_OBJ_TLV_TYPE_RSVP_ERROR_SPEC,
                    sizeof(struct pcep_object_tlv_rsvp_error_spec));

    tlv->c_type = RSVP_ERROR_SPEC_IPV6_CTYPE;
    tlv->class_num = RSVP_ERROR_SPEC_CLASS_NUM;
    tlv->error_code = error_code;
    tlv->error_value = error_value;
    tlv->error_spec_ip.ipv6_error_node_address.__in6_u.__u6_addr32[0] = error_node_ip->__in6_u.__u6_addr32[0];
    tlv->error_spec_ip.ipv6_error_node_address.__in6_u.__u6_addr32[1] = error_node_ip->__in6_u.__u6_addr32[1];
    tlv->error_spec_ip.ipv6_error_node_address.__in6_u.__u6_addr32[2] = error_node_ip->__in6_u.__u6_addr32[2];
    tlv->error_spec_ip.ipv6_error_node_address.__in6_u.__u6_addr32[3] = error_node_ip->__in6_u.__u6_addr32[3];

    return tlv;
}

struct pcep_object_tlv_nopath_vector*
pcep_tlv_create_nopath_vector(uint32_t error_code)
{
    struct pcep_object_tlv_nopath_vector *tlv =
            (struct pcep_object_tlv_nopath_vector *)
            pcep_tlv_common_create(PCEP_OBJ_TLV_TYPE_NO_PATH_VECTOR,
                    sizeof(struct pcep_object_tlv_nopath_vector));

    tlv->error_code = error_code;

    return tlv;
}
