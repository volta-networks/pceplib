/*
 * pcep-tlvs-test.c
 *
 *  Created on: Oct 31, 2019
 *      Author: brady
 */

#include <stdlib.h>

#include <CUnit/CUnit.h>

#include "pcep-objects.h"
#include "pcep-tlvs.h"

/*
 * Notice:
 * All of these TLV Unit Tests encode the created TLVs by explicitly calling
 * pcep_encode_obj_tlv() thus testing the TLV creation and the TLV encoding.
 */

extern void pcep_encode_obj_tlv(struct pcep_object_tlv *tlv);

void test_pcep_tlv_create_stateful_pce_capability()
{
    struct pcep_object_tlv *tlv = pcep_tlv_create_stateful_pce_capability(0xff);
    CU_ASSERT_PTR_NOT_NULL(tlv);

    pcep_encode_obj_tlv(tlv);
    CU_ASSERT_EQUAL(tlv->header.type, htons(PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY));
    CU_ASSERT_EQUAL(tlv->header.length, htons(sizeof(uint32_t)));
    CU_ASSERT_EQUAL(tlv->value[0], htonl(0x000000ff));

    free(tlv);
}

void test_pcep_tlv_create_speaker_entity_id()
{
    struct pcep_object_tlv *tlv = pcep_tlv_create_speaker_entity_id(NULL);
    CU_ASSERT_PTR_NULL(tlv);

    double_linked_list *list = dll_initialize();
    tlv = pcep_tlv_create_speaker_entity_id(list);
    CU_ASSERT_PTR_NULL(tlv);

    uint32_t speaker_entity = 42;
    dll_append(list, &speaker_entity);
    tlv = pcep_tlv_create_speaker_entity_id(list);
    CU_ASSERT_PTR_NOT_NULL(tlv);

    pcep_encode_obj_tlv(tlv);
    CU_ASSERT_EQUAL(tlv->header.type, htons(PCEP_OBJ_TLV_TYPE_SPEAKER_ENTITY_ID));
    CU_ASSERT_EQUAL(tlv->header.length, htons(sizeof(uint32_t)));
    CU_ASSERT_EQUAL(tlv->value[0], htonl(speaker_entity));

    dll_destroy(list);
    free(tlv);
}

void test_pcep_tlv_create_lsp_db_version()
{
    uint64_t lsp_db_version = 0xf005ba11ba5eba11;
    struct pcep_object_tlv *tlv = pcep_tlv_create_lsp_db_version(lsp_db_version);
    CU_ASSERT_PTR_NOT_NULL(tlv);

    pcep_encode_obj_tlv(tlv);
    CU_ASSERT_EQUAL(tlv->header.type, htons(PCEP_OBJ_TLV_TYPE_LSP_DB_VERSION));
    CU_ASSERT_EQUAL(tlv->header.length, htons(sizeof(uint64_t)));
    CU_ASSERT_EQUAL(*((uint64_t*) tlv->value), be64toh(lsp_db_version));

    free(tlv);
}

void test_pcep_tlv_create_path_setup_type()
{
    uint8_t pst = 0x89;

    struct pcep_object_tlv *tlv = pcep_tlv_create_path_setup_type(pst);
    CU_ASSERT_PTR_NOT_NULL(tlv);
    pcep_encode_obj_tlv(tlv);
    CU_ASSERT_EQUAL(tlv->header.type, htons(PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE));
    CU_ASSERT_EQUAL(tlv->header.length, htons(sizeof(uint32_t)));
    CU_ASSERT_EQUAL(tlv->value[0], htonl(0x000000FF & pst));

    free(tlv);
}

void test_pcep_tlv_create_path_setup_type_capability()
{
    /* The sub_tlv list is optional */

    /* Should return NULL if pst_list is NULL */
    struct pcep_object_tlv *tlv = pcep_tlv_create_path_setup_type_capability(NULL, NULL);
    CU_ASSERT_PTR_NULL(tlv);

    /* Should return NULL if pst_list is empty */
    double_linked_list *pst_list = dll_initialize();
    tlv = pcep_tlv_create_path_setup_type_capability(pst_list, NULL);
    CU_ASSERT_PTR_NULL(tlv);

    /* Should still return NULL if pst_list is NULL */
    double_linked_list *sub_tlv_list = dll_initialize();
    tlv = pcep_tlv_create_path_setup_type_capability(NULL, sub_tlv_list);
    CU_ASSERT_PTR_NULL(tlv);

    /* Should still return NULL if pst_list is empty */
    tlv = pcep_tlv_create_path_setup_type_capability(pst_list, sub_tlv_list);
    CU_ASSERT_PTR_NULL(tlv);

    /* Test only populating the pst list */
    uint8_t pst1 = 1;
    uint8_t pst2 = 2;
    uint8_t pst3 = 3;
    dll_append(pst_list, &pst1);
    dll_append(pst_list, &pst2);
    dll_append(pst_list, &pst3);
    tlv = pcep_tlv_create_path_setup_type_capability(pst_list, sub_tlv_list);
    CU_ASSERT_PTR_NOT_NULL(tlv);

    pcep_encode_obj_tlv(tlv);
    CU_ASSERT_EQUAL(tlv->header.type, htons(PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE_CAPABILITY));
    CU_ASSERT_EQUAL(tlv->header.length, htons(sizeof(uint32_t) * 2));
    CU_ASSERT_EQUAL(tlv->value[0], htonl(0x00000003));
    CU_ASSERT_EQUAL(tlv->value[1], htonl(0x01020300));
    free(tlv);

    /* Now test populating both the pst_list and the sub_tlv_list */
    struct pcep_object_tlv *sub_tlv = pcep_tlv_create_stateful_pce_capability(0xff);
    dll_append(sub_tlv_list, sub_tlv);
    tlv = pcep_tlv_create_path_setup_type_capability(pst_list, sub_tlv_list);
    CU_ASSERT_PTR_NOT_NULL(tlv);

    pcep_encode_obj_tlv(tlv);
    CU_ASSERT_EQUAL(tlv->header.type, htons(PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE_CAPABILITY));
    CU_ASSERT_EQUAL(tlv->header.length,
            htons(sizeof(uint32_t) * 2 + sizeof(struct pcep_object_tlv_header) + sub_tlv->header.length));
    CU_ASSERT_EQUAL(tlv->value[0], htonl(0x00000003));
    CU_ASSERT_EQUAL(tlv->value[1], htonl(0x01020300));
    struct pcep_object_tlv *sub_tlv_ptr = (struct pcep_object_tlv*) &(tlv->value[2]);
    CU_ASSERT_EQUAL(sub_tlv_ptr->header.type, htons(PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY));

    dll_destroy(pst_list);
    dll_destroy(sub_tlv_list);
    free(sub_tlv);
    free(tlv);
}

void test_pcep_tlv_create_sr_pce_capability()
{
    struct pcep_object_tlv *tlv = pcep_tlv_create_sr_pce_capability(
            PCEP_TLV_FLAG_NO_MSD_LIMITS|PCEP_TLV_FLAG_SR_PCE_CAPABILITY_NAI, 8);
    CU_ASSERT_PTR_NOT_NULL(tlv);

    pcep_encode_obj_tlv(tlv);
    CU_ASSERT_EQUAL(tlv->header.type, htons(PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY));
    CU_ASSERT_EQUAL(tlv->header.length, htons(sizeof(uint32_t)));
    CU_ASSERT_EQUAL(tlv->value[0], htonl(0x00000308));

    free(tlv);
}

void test_pcep_tlv_create_symbolic_path_name()
{
    /* char *symbolic_path_name, uint16_t symbolic_path_name_length); */
    char path_name[16] = "Some Path Name";
    uint16_t path_name_length = 14;
    struct pcep_object_tlv *tlv =
            pcep_tlv_create_symbolic_path_name(path_name, path_name_length);
    CU_ASSERT_PTR_NOT_NULL(tlv);

    pcep_encode_obj_tlv(tlv);
    CU_ASSERT_EQUAL(tlv->header.type, htons(PCEP_OBJ_TLV_TYPE_SYMBOLIC_PATH_NAME));
    CU_ASSERT_EQUAL(tlv->header.length, htons(path_name_length));
    /* Test the padding is correct */
    CU_ASSERT_EQUAL(0, strncmp((char *) &(tlv->value[0]), &path_name[0], 4));
    CU_ASSERT_EQUAL(0, strncmp((char *) &(tlv->value[1]), &path_name[4], 4));
    CU_ASSERT_EQUAL(0, strncmp((char *) &(tlv->value[2]), &path_name[8], 4));
    char *byte_ptr = (char *) &(tlv->value[3]);
    CU_ASSERT_EQUAL(byte_ptr[0], 'm');
    CU_ASSERT_EQUAL(byte_ptr[1], 'e');
    CU_ASSERT_EQUAL(byte_ptr[2], 0);
    CU_ASSERT_EQUAL(byte_ptr[3], 0);
    free(tlv);

    tlv = pcep_tlv_create_symbolic_path_name(path_name, 3);
    CU_ASSERT_PTR_NOT_NULL(tlv);
    pcep_encode_obj_tlv(tlv);
    CU_ASSERT_EQUAL(tlv->header.type, htons(PCEP_OBJ_TLV_TYPE_SYMBOLIC_PATH_NAME));
    CU_ASSERT_EQUAL(tlv->header.length, htons(3));
    byte_ptr = (char *) tlv->value;
    CU_ASSERT_EQUAL(byte_ptr[0], 'S');
    CU_ASSERT_EQUAL(byte_ptr[1], 'o');
    CU_ASSERT_EQUAL(byte_ptr[2], 'm');
    CU_ASSERT_EQUAL(byte_ptr[3], 0);

    free(tlv);
}

void test_pcep_tlv_create_ipv4_lsp_identifiers()
{
    struct in_addr sender_ip, endpoint_ip;
    uint16_t lsp_id = 1;
    uint16_t tunnel_id = 16;
    uint32_t extended_tunnel_id = 256;
    inet_pton(AF_INET, "192.168.1.1", &sender_ip);
    inet_pton(AF_INET, "192.168.1.2", &endpoint_ip);

    struct pcep_object_tlv *tlv = pcep_tlv_create_ipv4_lsp_identifiers(
            NULL, &endpoint_ip, lsp_id, tunnel_id, extended_tunnel_id);
    CU_ASSERT_PTR_NULL(tlv);

    tlv = pcep_tlv_create_ipv4_lsp_identifiers(
            &sender_ip, NULL, lsp_id, tunnel_id, extended_tunnel_id);
    CU_ASSERT_PTR_NULL(tlv);

    tlv = pcep_tlv_create_ipv4_lsp_identifiers(
            NULL, NULL, lsp_id, tunnel_id, extended_tunnel_id);
    CU_ASSERT_PTR_NULL(tlv);

    tlv = pcep_tlv_create_ipv4_lsp_identifiers(
            &sender_ip, &endpoint_ip, lsp_id, tunnel_id, extended_tunnel_id);
    CU_ASSERT_PTR_NOT_NULL(tlv);

    pcep_encode_obj_tlv(tlv);
    CU_ASSERT_EQUAL(tlv->header.type, htons(PCEP_OBJ_TLV_TYPE_IPV4_LSP_IDENTIFIERS));
    CU_ASSERT_EQUAL(tlv->header.length, htons(sizeof(uint32_t) * 4));
    CU_ASSERT_EQUAL(tlv->value[0], htonl(sender_ip.s_addr));
    CU_ASSERT_EQUAL(tlv->value[1], (htons(lsp_id) << 16) | htons(tunnel_id));
    CU_ASSERT_EQUAL(tlv->value[2], htonl(extended_tunnel_id));
    CU_ASSERT_EQUAL(tlv->value[3], htonl(endpoint_ip.s_addr));

    free(tlv);
}

void test_pcep_tlv_create_ipv6_lsp_identifiers()
{
    struct in6_addr sender_ip, endpoint_ip;
    uint16_t lsp_id = 1;
    uint16_t tunnel_id = 16;
    uint32_t extended_tunnel_id[4];

    inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", &sender_ip);
    inet_pton(AF_INET6, "2001:db8::8a2e:370:8446", &endpoint_ip);
    extended_tunnel_id[0] = 1;
    extended_tunnel_id[1] = 2;
    extended_tunnel_id[2] = 3;
    extended_tunnel_id[3] = 4;

    struct pcep_object_tlv *tlv = pcep_tlv_create_ipv6_lsp_identifiers(
            NULL, &endpoint_ip, lsp_id, tunnel_id, extended_tunnel_id);
    CU_ASSERT_PTR_NULL(tlv);

    tlv = pcep_tlv_create_ipv6_lsp_identifiers(
            &sender_ip, NULL, lsp_id, tunnel_id, extended_tunnel_id);
    CU_ASSERT_PTR_NULL(tlv);

    tlv = pcep_tlv_create_ipv6_lsp_identifiers(
            NULL, NULL, lsp_id, tunnel_id, extended_tunnel_id);
    CU_ASSERT_PTR_NULL(tlv);

    tlv = pcep_tlv_create_ipv6_lsp_identifiers(
            &sender_ip, &endpoint_ip, lsp_id, tunnel_id, extended_tunnel_id);
    CU_ASSERT_PTR_NOT_NULL(tlv);

    pcep_encode_obj_tlv(tlv);
    CU_ASSERT_EQUAL(tlv->header.type, htons(PCEP_OBJ_TLV_TYPE_IPV6_LSP_IDENTIFIERS));
    CU_ASSERT_EQUAL(tlv->header.length, htons(52));
    CU_ASSERT_EQUAL(tlv->value[4], (htons(lsp_id) << 16) | htons(tunnel_id));

    free(tlv);
}

void test_pcep_tlv_create_lsp_error_code()
{
    struct pcep_object_tlv *tlv =
            pcep_tlv_create_lsp_error_code(PCEP_TLV_LSP_ERROR_CODE_RSVP_SIGNALING_ERROR);
    CU_ASSERT_PTR_NOT_NULL(tlv);

    pcep_encode_obj_tlv(tlv);
    CU_ASSERT_EQUAL(tlv->header.type, htons(PCEP_OBJ_TLV_TYPE_LSP_ERROR_CODE));
    CU_ASSERT_EQUAL(tlv->header.length, htons(sizeof(uint32_t)));
    CU_ASSERT_EQUAL(tlv->value[0], htonl(PCEP_TLV_LSP_ERROR_CODE_RSVP_SIGNALING_ERROR));

    free(tlv);
}

void test_pcep_tlv_create_rsvp_ipv4_error_spec()
{
    struct in_addr error_node_ip;
    inet_pton(AF_INET, "192.168.1.1", &error_node_ip);
    uint8_t flags = 0xff;
    uint8_t error_code = 8;
    uint16_t error_value = 0xaabb;

    struct pcep_object_tlv *tlv =
            pcep_tlv_create_rsvp_ipv4_error_spec(NULL, flags, error_code, error_value);
    CU_ASSERT_PTR_NULL(tlv);

    tlv = pcep_tlv_create_rsvp_ipv4_error_spec(&error_node_ip, flags, error_code, error_value);
    CU_ASSERT_PTR_NOT_NULL(tlv);

    pcep_encode_obj_tlv(tlv);
    CU_ASSERT_EQUAL(tlv->header.type, htons(PCEP_OBJ_TLV_TYPE_RSVP_ERROR_SPEC));
    CU_ASSERT_EQUAL(tlv->header.length,
            htons(sizeof(struct rsvp_object_header) + sizeof(struct rsvp_error_spec_ipv4)));

    free(tlv);
}

void test_pcep_tlv_create_rsvp_ipv6_error_spec()
{
    struct in6_addr error_node_ip;
    inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", &error_node_ip);
    uint8_t flags = 0xff;
    uint8_t error_code = 8;
    uint16_t error_value = 0xaabb;

    struct pcep_object_tlv *tlv =
            pcep_tlv_create_rsvp_ipv6_error_spec(NULL, flags, error_code, error_value);
    CU_ASSERT_PTR_NULL(tlv);

    tlv = pcep_tlv_create_rsvp_ipv6_error_spec(&error_node_ip, flags, error_code, error_value);
    CU_ASSERT_PTR_NOT_NULL(tlv);

    pcep_encode_obj_tlv(tlv);
    CU_ASSERT_EQUAL(tlv->header.type, htons(PCEP_OBJ_TLV_TYPE_RSVP_ERROR_SPEC));
    CU_ASSERT_EQUAL(tlv->header.length,
            htons(sizeof(struct rsvp_object_header) + sizeof(struct rsvp_error_spec_ipv6)));

    free(tlv);
}
