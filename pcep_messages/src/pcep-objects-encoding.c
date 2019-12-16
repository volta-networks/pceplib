/*
 * pcep-tools.c
 *
 *  Created on: Nov 22, 2019
 *      Author: brady
 */

#include <stdio.h>

#include "pcep-objects.h"
#include "pcep-tlvs.h"
#include "pcep_utils_logging.h"

/* forward declarations */
void pcep_decode_obj_tlv(struct pcep_object_tlv *tlv);
void pcep_encode_obj_tlv(struct pcep_object_tlv *tlv);

/*
 * Object decode functions.
 */

void
pcep_decode_obj_open(struct pcep_object_open *obj)
{
    /* TLVs will be decoded in pcep_obj_get_tlvs() */
}

void
pcep_decode_obj_rp(struct pcep_object_rp *obj)
{
    obj->rp_flags = ntohl(obj->rp_flags);
    obj->rp_reqidnumb = ntohl(obj->rp_reqidnumb);
}

void
pcep_decode_obj_nopath(struct pcep_object_nopath *obj)
{
    obj->flags = ntohs(obj->flags);
}

void
pcep_decode_obj_ep_ipv4(struct pcep_object_endpoints_ipv4 *obj)
{
    // nothing to decode.
}

void
pcep_decode_obj_ep_ipv6(struct pcep_object_endpoints_ipv6 *obj)
{
    // nothing to decode.
}

void
pcep_decode_obj_bandwidth(struct pcep_object_bandwidth *obj)
{
    // TODO maybe decode float?
}

void
pcep_decode_obj_metric(struct pcep_object_metric *obj)
{
    obj->resv = ntohs(obj->resv);
    // TODO maybe decode float?
}

void
pcep_decode_obj_ro(struct pcep_object_ro *obj)
{
    uint16_t read_count = sizeof(struct pcep_object_header);
    int num_sub_objects = 1;

    while((obj->header.object_length - read_count) > sizeof(struct pcep_ro_subobj_hdr) &&
            num_sub_objects < MAX_ITERATIONS) {
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
        num_sub_objects++;
    }
}

void
pcep_decode_obj_lspa(struct pcep_object_lspa *obj)
{
    obj->lspa_exclude_any = ntohl(obj->lspa_exclude_any);
    obj->lspa_include_any = ntohl(obj->lspa_include_any);
    obj->lspa_include_all = ntohl(obj->lspa_include_all);
}

void
pcep_decode_obj_svec(struct pcep_object_svec *obj)
{
    uint16_t len;
    uint32_t i = 0;
    uint32_t *array = pcep_obj_svec_get(obj, &len, false);

    for(i = 0; i < len; i++) {
        array[i] = ntohl(array[i]);
    }
}

void
pcep_decode_obj_error(struct pcep_object_error *obj)
{
    // nothing to decode.
}

void
pcep_decode_obj_close(struct pcep_object_close *obj)
{
    // nothing to decode.
}

void
pcep_decode_obj_notify(struct pcep_object_notify *obj)
{
    // nothing to decode.
}

void pcep_decode_obj_srp(struct pcep_object_srp *srp)
{
    srp->srp_id_number = ntohl(srp->srp_id_number);
}

void pcep_decode_obj_lsp(struct pcep_object_lsp *lsp)
{
    /* TLVs will be decoded in pcep_obj_get_tlvs() */
    lsp->plsp_id_flags = ntohl(lsp->plsp_id_flags);
}

/*
 * Functions to decode TLVs
 */

void pcep_decode_tlv_lsp_db_version(struct pcep_object_tlv *tlv)
{
    *((uint64_t *) tlv->value) = htobe64(*((uint64_t *) tlv->value));
}

void pcep_decode_tlv_path_setup_type_capability(struct pcep_object_tlv *tlv)
{
    /* Need to determine if an optional sub-tlv is present */
    int buffer_length = sizeof(uint32_t) + /* The reserved + Num Pst's is a uint 32_t */
            tlv->value[0] +
            ((tlv->value[0] % 4 == 0) ? 0 : (4 - (tlv->value[0] % 4)));

    if (tlv->header.length > buffer_length)
    {
        int num_sub_tlvs = 1;
        int index = buffer_length;
        while(index < tlv->header.length && num_sub_tlvs < MAX_ITERATIONS)
        {
            struct pcep_object_tlv *sub_tlv =
                    (struct pcep_object_tlv *) (((uint8_t *) tlv->value) + index);
            pcep_decode_obj_tlv(sub_tlv);
            index += sizeof(struct pcep_object_tlv_header) + sub_tlv->header.length;
            num_sub_tlvs++;
        }
    }

    tlv->value[0] = ntohl(tlv->value[0]);
}

void pcep_decode_tlv_ipv4_lsp_identifiers(struct pcep_object_tlv *tlv)
{
    tlv->value[0] = ntohl(tlv->value[0]);
    tlv->value[2] = ntohl(tlv->value[2]);
    tlv->value[3] = ntohl(tlv->value[3]);

    uint16_t *short_ptr = (uint16_t *) (tlv->value + 1);
    short_ptr[0] = htons(short_ptr[0]);
    short_ptr[1] = htons(short_ptr[1]);
}

void pcep_decode_tlv_ipv6_lsp_identifiers(struct pcep_object_tlv *tlv)
{
    tlv->value[0] = ntohl(tlv->value[0]);
    tlv->value[1] = ntohl(tlv->value[1]);
    tlv->value[2] = ntohl(tlv->value[2]);
    tlv->value[3] = ntohl(tlv->value[3]);

    uint16_t *short_ptr = (uint16_t *) (tlv->value + 4);
    short_ptr[0] = ntohs(short_ptr[0]);
    short_ptr[1] = ntohs(short_ptr[1]);

    tlv->value[5] = ntohl(tlv->value[5]);
    tlv->value[6] = ntohl(tlv->value[6]);
    tlv->value[7] = ntohl(tlv->value[7]);
    tlv->value[8] = ntohl(tlv->value[8]);

    tlv->value[9]  = ntohl(tlv->value[9]);
    tlv->value[10] = ntohl(tlv->value[10]);
    tlv->value[11] = ntohl(tlv->value[11]);
    tlv->value[12] = ntohl(tlv->value[12]);
}

void pcep_decode_tlv_rsvp_error_spec(struct pcep_object_tlv *tlv)
{
    /* Same decode tlv function for both types:
       pcep_create_tlv_rsvp_ipv4_error_spec(tlv);
       pcep_create_tlv_rsvp_ipv6_error_spec(tlv); */

    struct rsvp_object_header *rsvp_header = (struct rsvp_object_header *) tlv->value;
    rsvp_header->length = ntohs(rsvp_header->length);
    if (rsvp_header->c_type == 1)
    {
        struct rsvp_error_spec_ipv4 *error_spec = (struct rsvp_error_spec_ipv4 *) &(tlv->value[1]);
        error_spec->error_node_ip.s_addr = ntohl(error_spec->error_node_ip.s_addr);
        error_spec->error_value = ntohs(error_spec->error_value);
    }
    else
    {
        struct rsvp_error_spec_ipv6 * error_spec = (struct rsvp_error_spec_ipv6 *) &(tlv->value[1]);
        error_spec->error_node_ip.__in6_u.__u6_addr32[0] = ntohl(error_spec->error_node_ip.__in6_u.__u6_addr32[0]);
        error_spec->error_node_ip.__in6_u.__u6_addr32[1] = ntohl(error_spec->error_node_ip.__in6_u.__u6_addr32[1]);
        error_spec->error_node_ip.__in6_u.__u6_addr32[2] = ntohl(error_spec->error_node_ip.__in6_u.__u6_addr32[2]);
        error_spec->error_node_ip.__in6_u.__u6_addr32[3] = ntohl(error_spec->error_node_ip.__in6_u.__u6_addr32[3]);
        error_spec->error_value = ntohs(error_spec->error_value);
    }
}

void pcep_decode_obj_tlv(struct pcep_object_tlv *tlv)
{
    tlv->header.type   = ntohs(tlv->header.type);
    tlv->header.length = ntohs(tlv->header.length);
    int words_to_decode = 0;

    switch(tlv->header.type)
    {
    case PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY:
        words_to_decode = 1;
        break;
    case PCEP_OBJ_TLV_TYPE_SYMBOLIC_PATH_NAME:
        /* Nothing to decode */
        break;
    case PCEP_OBJ_TLV_TYPE_IPV4_LSP_IDENTIFIERS:
        pcep_decode_tlv_ipv4_lsp_identifiers(tlv);
        break;
    case PCEP_OBJ_TLV_TYPE_IPV6_LSP_IDENTIFIERS:
        pcep_decode_tlv_ipv6_lsp_identifiers(tlv);
        break;
    case PCEP_OBJ_TLV_TYPE_LSP_ERROR_CODE:
        words_to_decode = 1;
        break;
    case PCEP_OBJ_TLV_TYPE_RSVP_ERROR_SPEC:
        pcep_decode_tlv_rsvp_error_spec(tlv);
        break;
    case PCEP_OBJ_TLV_TYPE_LSP_DB_VERSION:
        pcep_decode_tlv_lsp_db_version(tlv);
        break;
    case PCEP_OBJ_TLV_TYPE_SPEAKER_ENTITY_ID:
        words_to_decode = tlv->header.length / sizeof(uint32_t);
        break;
    case PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY:
        words_to_decode = 1;
        break;
    case PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE:
        words_to_decode = 1;
        break;
    case PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE_CAPABILITY:
        pcep_decode_tlv_path_setup_type_capability(tlv);
        break;
    case PCEP_OBJ_TLV_TYPE_NO_PATH_VECTOR:
        words_to_decode = 1;
        break;
    default:
        pcep_log(LOG_INFO, "Cannot decode unknown TLV type [%d]\n", tlv->header.type);
        break;
    }

    if (words_to_decode > 0)
    {
        int index = 0;
        for(; index < words_to_decode; index++)
        {
            tlv->value[index] = htonl(tlv->value[index]);
        }
    }
}

bool pcep_obj_parse_decode(struct pcep_object_header* hdr)
{
    hdr->object_length = ntohs(hdr->object_length);

    switch(hdr->object_class) {
        case PCEP_OBJ_CLASS_OPEN:
            pcep_decode_obj_open((struct pcep_object_open*) hdr);
            break;
        case PCEP_OBJ_CLASS_RP:
            pcep_decode_obj_rp((struct pcep_object_rp*) hdr);
            break;
        case PCEP_OBJ_CLASS_NOPATH:
            pcep_decode_obj_nopath((struct pcep_object_nopath*) hdr);
            break;
        case PCEP_OBJ_CLASS_ENDPOINTS:
            if(hdr->object_type == PCEP_OBJ_TYPE_ENDPOINT_IPV4) {
                pcep_decode_obj_ep_ipv4((struct pcep_object_endpoints_ipv4*) hdr);
            } else if(hdr->object_type == PCEP_OBJ_TYPE_ENDPOINT_IPV6) {
                pcep_decode_obj_ep_ipv6((struct pcep_object_endpoints_ipv6*) hdr);
            }
            break;
        case PCEP_OBJ_CLASS_BANDWIDTH:
            pcep_decode_obj_bandwidth((struct pcep_object_bandwidth*) hdr);
            break;
        case PCEP_OBJ_CLASS_METRIC:
            pcep_decode_obj_metric((struct pcep_object_metric*) hdr);
            break;
        case PCEP_OBJ_CLASS_IRO:
        case PCEP_OBJ_CLASS_RRO:
        case PCEP_OBJ_CLASS_ERO:
            pcep_decode_obj_ro((struct pcep_object_ro*) hdr);
            break;
        case PCEP_OBJ_CLASS_LSPA:
            pcep_decode_obj_lspa((struct pcep_object_lspa*) hdr);
            break;
        case PCEP_OBJ_CLASS_SVEC:
            pcep_decode_obj_svec((struct pcep_object_svec*) hdr);
            break;
        case PCEP_OBJ_CLASS_ERROR:
            pcep_decode_obj_error((struct pcep_object_error*) hdr);
            break;
        case PCEP_OBJ_CLASS_CLOSE:
            pcep_decode_obj_close((struct pcep_object_close*) hdr);
            break;
        case PCEP_OBJ_CLASS_SRP:
            pcep_decode_obj_srp((struct pcep_object_srp*) hdr);
            break;
        case PCEP_OBJ_CLASS_LSP:
            pcep_decode_obj_lsp((struct pcep_object_lsp*) hdr);
            break;
        case PCEP_OBJ_CLASS_NOTF:
            pcep_decode_obj_notify((struct pcep_object_notify*) hdr);
            break;
        default:
            pcep_log(LOG_INFO, "pcep_obj_parse: Unknown object class\n");
            return false;
    }

    /* decode the TLVs, if the object has them, but not for Route
     * Objects, since the sub-objects will be confused for TLVs. */
    if (hdr->object_class != PCEP_OBJ_CLASS_ERO &&
        hdr->object_class != PCEP_OBJ_CLASS_IRO &&
        hdr->object_class != PCEP_OBJ_CLASS_RRO &&
        hdr->object_class != PCEP_OBJ_CLASS_SVEC)
    {
        if (pcep_obj_has_tlv(hdr))
        {
            double_linked_list *tlv_list = pcep_obj_get_encoded_tlvs(hdr);
            double_linked_list_node *tlv_node = tlv_list->head;
            while (tlv_node != NULL)
            {
                struct pcep_object_tlv *tlv = (struct pcep_object_tlv *) tlv_node->data;
                pcep_decode_obj_tlv(tlv);

                tlv_node = tlv_node->next_node;
            }
            dll_destroy(tlv_list);
        }
    }

    return true;
}

/*
 * Functions to encode objects
 */

void pcep_encode_obj_open(struct pcep_object_open *open)
{
}

void pcep_encode_obj_rp(struct pcep_object_rp *obj)
{
    obj->rp_flags = htonl(obj->rp_flags);
    obj->rp_reqidnumb = htonl(obj->rp_reqidnumb);
}

void pcep_encode_obj_nopath(struct pcep_object_nopath *obj)
{
    obj->flags = htons(obj->flags);
}

void pcep_encode_obj_ep_ipv4(struct pcep_object_endpoints_ipv4 *obj)
{
    obj->src_ipv4.s_addr = htonl(obj->src_ipv4.s_addr);
    obj->dst_ipv4.s_addr = htonl(obj->dst_ipv4.s_addr);
}

void pcep_encode_obj_ep_ipv6(struct pcep_object_endpoints_ipv6 *obj)
{
    obj->src_ipv6.__in6_u.__u6_addr32[0] = htonl(obj->src_ipv6.__in6_u.__u6_addr32[0]);
    obj->src_ipv6.__in6_u.__u6_addr32[1] = htonl(obj->src_ipv6.__in6_u.__u6_addr32[1]);
    obj->src_ipv6.__in6_u.__u6_addr32[2] = htonl(obj->src_ipv6.__in6_u.__u6_addr32[2]);
    obj->src_ipv6.__in6_u.__u6_addr32[3] = htonl(obj->src_ipv6.__in6_u.__u6_addr32[3]);

    obj->dst_ipv6.__in6_u.__u6_addr32[0] = htonl(obj->dst_ipv6.__in6_u.__u6_addr32[0]);
    obj->dst_ipv6.__in6_u.__u6_addr32[1] = htonl(obj->dst_ipv6.__in6_u.__u6_addr32[1]);
    obj->dst_ipv6.__in6_u.__u6_addr32[2] = htonl(obj->dst_ipv6.__in6_u.__u6_addr32[2]);
    obj->dst_ipv6.__in6_u.__u6_addr32[3] = htonl(obj->dst_ipv6.__in6_u.__u6_addr32[3]);
}

void pcep_encode_obj_bandwidth(struct pcep_object_bandwidth *bandwidth)
{
}

void pcep_encode_obj_metric(struct pcep_object_metric *obj)
{
    obj->resv = htons(obj->resv);
}

void pcep_encode_obj_ro(struct pcep_object_ro *obj)
{
    uint16_t read_count = sizeof(struct pcep_object_header);
    uint16_t obj_length = obj->header.object_length;
    int num_sub_objects = 1;

    while((obj_length - read_count) > sizeof(struct pcep_ro_subobj_hdr) &&
            num_sub_objects < MAX_ITERATIONS) {
        struct pcep_ro_subobj_hdr *hdr = (struct pcep_ro_subobj_hdr*) (((uint8_t*)obj) + read_count);
        /* Some sub-objects store the loose_hop bit in the top bit of the type field */
        uint8_t hdr_type = (hdr->type & 0x7f);

        if(hdr_type == RO_SUBOBJ_TYPE_UNNUM) {
            struct pcep_ro_subobj_unnum *unum = (struct pcep_ro_subobj_unnum*) hdr;
            unum->ifId = htonl(unum->ifId);
            unum->routerId.s_addr = htonl(unum->routerId.s_addr);
            unum->resv = htons(unum->resv);
        }
        else if(hdr_type == RO_SUBOBJ_TYPE_LABEL)
        {
            struct pcep_ro_subobj_32label *label = (struct pcep_ro_subobj_32label*) hdr;
            label->label = htonl(label->label);
        }
        else if(hdr_type == RO_SUBOBJ_TYPE_IPV4)
        {
            struct pcep_ro_subobj_ipv4 *ipv4 = (struct pcep_ro_subobj_ipv4*) hdr;
            ipv4->ip_addr.s_addr = htonl(ipv4->ip_addr.s_addr);
        }
        else if(hdr_type == RO_SUBOBJ_TYPE_IPV6)
        {
            struct pcep_ro_subobj_ipv6 *ipv6 = (struct pcep_ro_subobj_ipv6*) hdr;
            ipv6->ip_addr.__in6_u.__u6_addr32[0] = htonl(ipv6->ip_addr.__in6_u.__u6_addr32[0]);
            ipv6->ip_addr.__in6_u.__u6_addr32[1] = htonl(ipv6->ip_addr.__in6_u.__u6_addr32[1]);
            ipv6->ip_addr.__in6_u.__u6_addr32[2] = htonl(ipv6->ip_addr.__in6_u.__u6_addr32[2]);
            ipv6->ip_addr.__in6_u.__u6_addr32[3] = htonl(ipv6->ip_addr.__in6_u.__u6_addr32[3]);
        }
        else if(hdr_type == RO_SUBOBJ_TYPE_SR || hdr_type == RO_SUBOBJ_TYPE_SR_DRAFT07)
        {
            struct pcep_ro_subobj_sr *sr_subobj = (struct pcep_ro_subobj_sr*) hdr;
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
                words_to_convert = 1;
                break;
            default:
                break;
            }
            sr_subobj->nt_flags = htons(sr_subobj->nt_flags);

            int i = 0;
            for (; i < words_to_convert; i++)
            {
                sr_subobj->sid_nai[i] = htonl(sr_subobj->sid_nai[i]);
            }
        }
        read_count += hdr->length;
        num_sub_objects++;
    }
}

void pcep_encode_obj_lspa(struct pcep_object_lspa *obj)
{
    obj->lspa_exclude_any = htonl(obj->lspa_exclude_any);
    obj->lspa_include_any = htonl(obj->lspa_include_any);
    obj->lspa_include_all = htonl(obj->lspa_include_all);
}

void pcep_encode_obj_svec(struct pcep_object_svec *obj)
{
    uint16_t len;
    uint32_t i = 0;
    uint32_t *array = pcep_obj_svec_get(obj, &len, true);

    for(i = 0; i < len; i++) {
        array[i] = htonl(array[i]);
    }
}

void pcep_encode_obj_error(struct pcep_object_error *error)
{
}

void pcep_encode_obj_close(struct pcep_object_close *close)
{
}

void pcep_encode_obj_srp(struct pcep_object_srp *srp)
{
    srp->srp_id_number = htonl(srp->srp_id_number);
}

void pcep_encode_obj_lsp(struct pcep_object_lsp *lsp)
{
    lsp->plsp_id_flags = htonl(lsp->plsp_id_flags);
}

/*
 * Functions to encode TLVs
 */

void pcep_encode_tlv_lsp_db_version(struct pcep_object_tlv *tlv)
{
    *((uint64_t *) tlv->value) = be64toh(*((uint64_t *) tlv->value));
}

void pcep_encode_tlv_path_setup_type_capability(struct pcep_object_tlv *tlv)
{
    /* Need to determine if an optional sub-tlv is present */
    int buffer_length = sizeof(uint32_t) + /* The reserved + Num Pst's is a uint 32_t */
            tlv->value[0] +
            ((tlv->value[0] % 4 == 0) ? 0 : (4 - (tlv->value[0] % 4)));

    if (tlv->header.length > buffer_length)
    {
        int num_sub_tlvs = 1;
        int index = buffer_length;
        while(index < tlv->header.length && num_sub_tlvs < MAX_ITERATIONS)
        {
            struct pcep_object_tlv *sub_tlv =
                    (struct pcep_object_tlv *) (((uint8_t *) tlv->value) + index);
            pcep_encode_obj_tlv(sub_tlv);
            index += sizeof(struct pcep_object_tlv_header) + sub_tlv->header.length;
            num_sub_tlvs++;
        }
    }

    tlv->value[0] = htonl(tlv->value[0]);
}

void pcep_encode_tlv_ipv4_lsp_identifiers(struct pcep_object_tlv *tlv)
{
    tlv->value[0] = htonl(tlv->value[0]);
    tlv->value[2] = htonl(tlv->value[2]);
    tlv->value[3] = htonl(tlv->value[3]);

    uint16_t *short_ptr = (uint16_t *) (tlv->value + 1);
    short_ptr[0] = htons(short_ptr[0]);
    short_ptr[1] = htons(short_ptr[1]);
}

void pcep_encode_tlv_ipv6_lsp_identifiers(struct pcep_object_tlv *tlv)
{
    tlv->value[0] = htonl(tlv->value[0]);
    tlv->value[1] = htonl(tlv->value[1]);
    tlv->value[2] = htonl(tlv->value[2]);
    tlv->value[3] = htonl(tlv->value[3]);

    uint16_t *short_ptr = (uint16_t *) (tlv->value + 4);
    short_ptr[0] = htons(short_ptr[0]);
    short_ptr[1] = htons(short_ptr[1]);

    tlv->value[5] = htonl(tlv->value[5]);
    tlv->value[6] = htonl(tlv->value[6]);
    tlv->value[7] = htonl(tlv->value[7]);
    tlv->value[8] = ntohl(tlv->value[8]);

    tlv->value[9]  = htonl(tlv->value[9]);
    tlv->value[10] = htonl(tlv->value[10]);
    tlv->value[11] = htonl(tlv->value[11]);
    tlv->value[12] = htonl(tlv->value[12]);
}

void pcep_encode_tlv_rsvp_error_spec(struct pcep_object_tlv *tlv)
{
    /* Same decode tlv function for both types:
       pcep_create_tlv_rsvp_ipv4_error_spec(tlv);
       pcep_create_tlv_rsvp_ipv6_error_spec(tlv); */

    struct rsvp_object_header *rsvp_header = (struct rsvp_object_header *) tlv->value;
    rsvp_header->length = htons(rsvp_header->length);
    if (rsvp_header->c_type == 1)
    {
        struct rsvp_error_spec_ipv4 *error_spec = (struct rsvp_error_spec_ipv4 *) &(tlv->value[1]);
        error_spec->error_node_ip.s_addr = htonl(error_spec->error_node_ip.s_addr);
        error_spec->error_value = htons(error_spec->error_value);
    }
    else
    {
        struct rsvp_error_spec_ipv6 * error_spec = (struct rsvp_error_spec_ipv6 *) &(tlv->value[1]);
        error_spec->error_node_ip.__in6_u.__u6_addr32[0] = htonl(error_spec->error_node_ip.__in6_u.__u6_addr32[0]);
        error_spec->error_node_ip.__in6_u.__u6_addr32[1] = htonl(error_spec->error_node_ip.__in6_u.__u6_addr32[1]);
        error_spec->error_node_ip.__in6_u.__u6_addr32[2] = htonl(error_spec->error_node_ip.__in6_u.__u6_addr32[2]);
        error_spec->error_node_ip.__in6_u.__u6_addr32[3] = htonl(error_spec->error_node_ip.__in6_u.__u6_addr32[3]);
        error_spec->error_value = htons(error_spec->error_value);
    }
}

void pcep_encode_obj_tlv(struct pcep_object_tlv *tlv)
{
    int words_to_encode = 0;

    switch(tlv->header.type)
    {
    case PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY:
        words_to_encode = 1;
        break;
    case PCEP_OBJ_TLV_TYPE_SYMBOLIC_PATH_NAME:
        /* Nothing to decode */
        break;
    case PCEP_OBJ_TLV_TYPE_IPV4_LSP_IDENTIFIERS:
        pcep_encode_tlv_ipv4_lsp_identifiers(tlv);
        break;
    case PCEP_OBJ_TLV_TYPE_IPV6_LSP_IDENTIFIERS:
        pcep_encode_tlv_ipv6_lsp_identifiers(tlv);
        break;
    case PCEP_OBJ_TLV_TYPE_LSP_ERROR_CODE:
        words_to_encode = 1;
        break;
    case PCEP_OBJ_TLV_TYPE_RSVP_ERROR_SPEC:
        pcep_encode_tlv_rsvp_error_spec(tlv);
        break;
    case PCEP_OBJ_TLV_TYPE_LSP_DB_VERSION:
        pcep_encode_tlv_lsp_db_version(tlv);
        break;
    case PCEP_OBJ_TLV_TYPE_SPEAKER_ENTITY_ID:
        words_to_encode = tlv->header.length / sizeof(uint32_t);
        break;
    case PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY:
        words_to_encode = 1;
        break;
    case PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE:
        words_to_encode = 1;
        break;
    case PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE_CAPABILITY:
        pcep_encode_tlv_path_setup_type_capability(tlv);
        break;
    case PCEP_OBJ_TLV_TYPE_NO_PATH_VECTOR:
        words_to_encode = 1;
        break;
    default:
        pcep_log(LOG_INFO, "Cannot encode unknown TLV type [%d]\n", tlv->header.type);
        break;
    }

    if (words_to_encode > 0)
    {
        int index = 0;
        for(; index < words_to_encode; index++)
        {
            tlv->value[index] = htonl(tlv->value[index]);
        }
    }

    tlv->header.type   = htons(tlv->header.type);
    tlv->header.length = htons(tlv->header.length);
}

void pcep_obj_encode(struct pcep_object_header* hdr)
{
    switch(hdr->object_class) {
        case PCEP_OBJ_CLASS_OPEN:
            pcep_encode_obj_open((struct pcep_object_open*) hdr);
            break;
        case PCEP_OBJ_CLASS_RP:
            pcep_encode_obj_rp((struct pcep_object_rp*) hdr);
            break;
        case PCEP_OBJ_CLASS_NOPATH:
            pcep_encode_obj_nopath((struct pcep_object_nopath*) hdr);
            break;
        case PCEP_OBJ_CLASS_ENDPOINTS:
            if(hdr->object_type == PCEP_OBJ_TYPE_ENDPOINT_IPV4) {
                pcep_encode_obj_ep_ipv4((struct pcep_object_endpoints_ipv4*) hdr);
            } else if(hdr->object_type == PCEP_OBJ_TYPE_ENDPOINT_IPV6) {
                pcep_encode_obj_ep_ipv6((struct pcep_object_endpoints_ipv6*) hdr);
            }
            break;
        case PCEP_OBJ_CLASS_BANDWIDTH:
            pcep_encode_obj_bandwidth((struct pcep_object_bandwidth*) hdr);
            break;
        case PCEP_OBJ_CLASS_METRIC:
            pcep_encode_obj_metric((struct pcep_object_metric*) hdr);
            break;
        case PCEP_OBJ_CLASS_IRO:
        case PCEP_OBJ_CLASS_RRO:
        case PCEP_OBJ_CLASS_ERO:
            pcep_encode_obj_ro((struct pcep_object_ro*) hdr);
            break;
        case PCEP_OBJ_CLASS_LSPA:
            pcep_encode_obj_lspa((struct pcep_object_lspa*) hdr);
            break;
        case PCEP_OBJ_CLASS_SVEC:
            pcep_encode_obj_svec((struct pcep_object_svec*) hdr);
            break;
        case PCEP_OBJ_CLASS_ERROR:
            pcep_encode_obj_error((struct pcep_object_error*) hdr);
            break;
        case PCEP_OBJ_CLASS_CLOSE:
            pcep_encode_obj_close((struct pcep_object_close*) hdr);
            break;
        case PCEP_OBJ_CLASS_SRP:
            pcep_encode_obj_srp((struct pcep_object_srp*) hdr);
            break;
        case PCEP_OBJ_CLASS_LSP:
            pcep_encode_obj_lsp((struct pcep_object_lsp*) hdr);
            break;
        case PCEP_OBJ_CLASS_NOTF:
        default:
            pcep_log(LOG_INFO, "pcep_obj_encode: Unknown object class\n");
    }

    /* Encode the TLVs, if the object has them, but not for Route
     * Objects, since the sub-objects will be confused for TLVs. */
    if (hdr->object_class != PCEP_OBJ_CLASS_ERO &&
        hdr->object_class != PCEP_OBJ_CLASS_IRO &&
        hdr->object_class != PCEP_OBJ_CLASS_RRO &&
        hdr->object_class != PCEP_OBJ_CLASS_SVEC)
    {
        if (pcep_obj_has_tlv(hdr))
        {
            double_linked_list *tlv_list = pcep_obj_get_tlvs(hdr);
            double_linked_list_node *tlv_node = tlv_list->head;
            while (tlv_node != NULL)
            {
                struct pcep_object_tlv *tlv = (struct pcep_object_tlv *) tlv_node->data;
                pcep_encode_obj_tlv(tlv);

                tlv_node = tlv_node->next_node;
            }
            dll_destroy(tlv_list);
        }
    }

    hdr->object_length = htons(hdr->object_length);
}
