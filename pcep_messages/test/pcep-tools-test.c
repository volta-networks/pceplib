/*
 * pcep-tools-test.c
 *
 *  Created on: Nov 21, 2019
 *      Author: brady
 */

#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <CUnit/CUnit.h>

#include "pcep-tools.h"
#include "pcep_utils_double_linked_list.h"

const uint8_t any_obj_class = 255;

extern bool validate_message_header(struct pcep_header* msg_hdr);
extern bool validate_message_objects(struct pcep_message *msg);

uint16_t pcep_open_hexbyte_strs_length = 28;
char *pcep_open_odl_hexbyte_strs[] = {
    "20", "01", "00", "1c", "01", "10", "00", "18",
    "20", "1e", "78", "55", "00", "10", "00", "04",
    "00", "00", "00", "3f", "00", "1a", "00", "04",
    "00", "00", "00", "00" };

/* PCEP INITIATE str received from ODL with 4 objects: [SRP, LSP, Endpoints, ERO]
 * The LSP has a SYMBOLIC_PATH_NAME TLV.
 * The ERO has 2 IPV4 Endpoints. */
uint16_t pcep_initiate_hexbyte_strs_length = 68;
char *pcep_initiate_hexbyte_strs[] = {
    "20", "0c", "00", "44", "21", "12", "00", "0c",
    "00", "00", "00", "00", "00", "00", "00", "01",
    "20", "10", "00", "14", "00", "00", "00", "09",
    "00", "11", "00", "08", "66", "61", "39", "33",
    "33", "39", "32", "39", "04", "10", "00", "0c",
    "7f", "00", "00", "01", "28", "28", "28", "28",
    "07", "10", "00", "14", "01", "08", "0a", "00",
    "01", "01", "18", "00", "01", "08", "0a", "00",
    "07", "04", "18", "00"};

uint16_t pcep_initiate2_hexbyte_strs_length = 72;
char *pcep_initiate2_hexbyte_strs[] = {
    "20", "0c", "00", "48", "21", "12", "00", "14",
    "00", "00", "00", "00", "00", "00", "00", "01",
    "00", "1c", "00", "04", "00", "00", "00", "01",
    "20", "10", "00", "14", "00", "00", "00", "09",
    "00", "11", "00", "08", "36", "65", "31", "31",
    "38", "39", "32", "31", "04", "10", "00", "0c",
    "c0", "a8", "14", "05", "01", "01", "01", "01",
    "07", "10", "00", "10", "05", "0c", "10", "01",
    "03", "e8", "a0", "00", "01", "01", "01", "01"};

uint16_t pcep_update_hexbyte_strs_length = 48;
char *pcep_update_hexbyte_strs[] = {
    "20", "0b", "00", "30", "21", "12", "00", "14",
    "00", "00", "00", "00", "00", "00", "00", "01",
    "00", "1c", "00", "04", "00", "00", "00", "01",
    "20", "10", "00", "08", "00", "02", "a0", "09",
    "07", "10", "00", "10", "05", "0c", "10", "01",
    "03", "e8", "a0", "00", "01", "01", "01", "01"};

/* Test that pcep_msg_read() can read multiple messages in 1 call */
uint16_t pcep_open_initiate_hexbyte_strs_length = 100;
char *pcep_open_initiate_odl_hexbyte_strs[] = {
    "20", "01", "00", "1c", "01", "10", "00", "18",
    "20", "1e", "78", "55", "00", "10", "00", "04",
    "00", "00", "00", "3f", "00", "1a", "00", "04",
    "00", "00", "00", "00",
    "20", "0c", "00", "48", "21", "12", "00", "14",
    "00", "00", "00", "00", "00", "00", "00", "01",
    "00", "1c", "00", "04", "00", "00", "00", "01",
    "20", "10", "00", "14", "00", "00", "00", "09",
    "00", "11", "00", "08", "36", "65", "31", "31",
    "38", "39", "32", "31", "04", "10", "00", "0c",
    "c0", "a8", "14", "05", "01", "01", "01", "01",
    "07", "10", "00", "10", "05", "0c", "10", "01",
    "03", "e8", "a0", "00", "01", "01", "01", "01"};


/* Reads an array of hexbyte strs, and writes them to a temporary file.
 * The caller should close the returned file. */
int convert_hexstrs_to_binary(char *hexbyte_strs[], uint16_t hexbyte_strs_length)
{
    int fd = fileno(tmpfile());

    int i = 0;
    for ( ; i < hexbyte_strs_length; i++)
    {
        uint8_t byte = (uint8_t) strtol(hexbyte_strs[i], 0, 16);
        write(fd, (char *) &byte, 1);
    }

    /* Go back to the beginning of the file */
    lseek(fd, 0, SEEK_SET);
    return fd;
}

void test_pcep_msg_read_pcep_initiate()
{
    int fd = convert_hexstrs_to_binary(pcep_initiate_hexbyte_strs, pcep_initiate_hexbyte_strs_length);
    double_linked_list *msg_list = pcep_msg_read(fd);
    CU_ASSERT_PTR_NOT_NULL(msg_list);
    CU_ASSERT_EQUAL(msg_list->num_entries, 1);

    struct pcep_message *msg = (struct pcep_message *) msg_list->head->data;
    CU_ASSERT_EQUAL(msg->obj_list->num_entries, 4);
    CU_ASSERT_EQUAL(msg->header->type, PCEP_TYPE_INITIATE);
    CU_ASSERT_EQUAL(msg->header->length, pcep_initiate_hexbyte_strs_length);

    /* Verify each of the object types */

    /* SRP object */
    double_linked_list_node *node = msg->obj_list->head;
    struct pcep_object_header *obj_hdr = (struct pcep_object_header *) node->data;
    CU_ASSERT_EQUAL(obj_hdr->object_class, PCEP_OBJ_CLASS_SRP);
    CU_ASSERT_EQUAL(obj_hdr->object_type, PCEP_OBJ_TYPE_SRP);
    CU_ASSERT_EQUAL(obj_hdr->object_length, sizeof(struct pcep_object_srp));
    CU_ASSERT_FALSE(pcep_obj_has_tlv(obj_hdr));

    /* LSP object and its TLV*/
    node = node->next_node;
    obj_hdr = (struct pcep_object_header *) node->data;
    CU_ASSERT_EQUAL(obj_hdr->object_class, PCEP_OBJ_CLASS_LSP);
    CU_ASSERT_EQUAL(obj_hdr->object_type, PCEP_OBJ_TYPE_LSP);
    CU_ASSERT_EQUAL(obj_hdr->object_length, 20);
    uint8_t id = GET_LSP_PCEPID((struct pcep_object_lsp *) obj_hdr);
    CU_ASSERT_EQUAL(id, 0);
    //CU_ASSERT_EQUAL(GET_LSP_PCEPID((struct pcep_object_lsp *) obj_hdr), 0);
    CU_ASSERT_EQUAL(((struct pcep_object_lsp *) obj_hdr)->plsp_id_flags, (PCEP_LSP_D_FLAG | PCEP_LSP_A_FLAG));

     /* LSP TLV */
    CU_ASSERT_TRUE(pcep_obj_has_tlv(obj_hdr));
    double_linked_list *tlv_list = pcep_obj_get_tlvs(obj_hdr);
    CU_ASSERT_EQUAL(tlv_list->num_entries, 1);
    struct pcep_object_tlv *tlv = (struct pcep_object_tlv *) tlv_list->head->data;
    CU_ASSERT_EQUAL(tlv->header.type, PCEP_OBJ_TLV_TYPE_SYMBOLIC_PATH_NAME);
    CU_ASSERT_EQUAL(tlv->header.length, 8);
    dll_destroy(tlv_list);

    /* Endpoints object */
    node = node->next_node;
    obj_hdr = (struct pcep_object_header *) node->data;
    CU_ASSERT_EQUAL(obj_hdr->object_class, PCEP_OBJ_CLASS_ENDPOINTS);
    CU_ASSERT_EQUAL(obj_hdr->object_type, PCEP_OBJ_TYPE_ENDPOINT_IPV4);
    CU_ASSERT_EQUAL(obj_hdr->object_length, sizeof(struct pcep_object_endpoints_ipv4));
    CU_ASSERT_FALSE(pcep_obj_has_tlv(obj_hdr));

    /* ERO object */
    node = node->next_node;
    obj_hdr = (struct pcep_object_header *) node->data;
    CU_ASSERT_EQUAL(obj_hdr->object_class, PCEP_OBJ_CLASS_ERO);
    CU_ASSERT_EQUAL(obj_hdr->object_type, PCEP_OBJ_TYPE_ERO);
    CU_ASSERT_EQUAL(obj_hdr->object_length, 20);

    /* ERO Subobjects */
    double_linked_list *ero_subobj_list = pcep_obj_get_ro_subobjects(obj_hdr);
    CU_ASSERT_PTR_NOT_NULL(ero_subobj_list);
    CU_ASSERT_EQUAL(ero_subobj_list->num_entries, 2);
    double_linked_list_node *subobj_node = ero_subobj_list->head;
    struct pcep_ro_subobj_hdr *subobj_hdr = (struct pcep_ro_subobj_hdr *) subobj_node->data;
    CU_ASSERT_EQUAL(subobj_hdr->type, RO_SUBOBJ_TYPE_IPV4);
    CU_ASSERT_EQUAL(subobj_hdr->length, 8);
    struct in_addr ero_subobj_ip;
    inet_pton(AF_INET, "10.0.1.1", &ero_subobj_ip);
    CU_ASSERT_EQUAL(((struct pcep_ro_subobj_ipv4 *) subobj_hdr)->ip_addr.s_addr, ntohl(ero_subobj_ip.s_addr));
    CU_ASSERT_EQUAL(((struct pcep_ro_subobj_ipv4 *) subobj_hdr)->prefix_length, 24);

    subobj_hdr = (struct pcep_ro_subobj_hdr *) subobj_node->next_node->data;
    CU_ASSERT_EQUAL(subobj_hdr->type, RO_SUBOBJ_TYPE_IPV4);
    CU_ASSERT_EQUAL(subobj_hdr->length, 8);
    inet_pton(AF_INET, "10.0.7.4", &ero_subobj_ip);
    CU_ASSERT_EQUAL(((struct pcep_ro_subobj_ipv4 *) subobj_hdr)->ip_addr.s_addr, ntohl(ero_subobj_ip.s_addr));
    CU_ASSERT_EQUAL(((struct pcep_ro_subobj_ipv4 *) subobj_hdr)->prefix_length, 24);

    pcep_msg_free_message(msg);
    dll_destroy(ero_subobj_list);
    dll_destroy(msg_list);
    close(fd);
}


void test_pcep_msg_read_pcep_initiate2()
{
    int fd = convert_hexstrs_to_binary(pcep_initiate2_hexbyte_strs, pcep_initiate2_hexbyte_strs_length);
    double_linked_list *msg_list = pcep_msg_read(fd);
    CU_ASSERT_PTR_NOT_NULL(msg_list);
    CU_ASSERT_EQUAL(msg_list->num_entries, 1);

    struct pcep_message *msg = (struct pcep_message *) msg_list->head->data;
    CU_ASSERT_EQUAL(msg->obj_list->num_entries, 4);
    CU_ASSERT_EQUAL(msg->header->type, PCEP_TYPE_INITIATE);
    CU_ASSERT_EQUAL(msg->header->length, pcep_initiate2_hexbyte_strs_length);

    /* Verify each of the object types */

    /* SRP object */
    double_linked_list_node *node = msg->obj_list->head;
    struct pcep_object_header *obj_hdr = (struct pcep_object_header *) node->data;
    CU_ASSERT_EQUAL(obj_hdr->object_class, PCEP_OBJ_CLASS_SRP);
    CU_ASSERT_EQUAL(obj_hdr->object_type, PCEP_OBJ_TYPE_SRP);
    CU_ASSERT_EQUAL(obj_hdr->object_length, 20);
    CU_ASSERT_TRUE(pcep_obj_has_tlv(obj_hdr));
    /* TODO test the TLVs */

    /* LSP object and its TLV*/
    node = node->next_node;
    obj_hdr = (struct pcep_object_header *) node->data;
    CU_ASSERT_EQUAL(obj_hdr->object_class, PCEP_OBJ_CLASS_LSP);
    CU_ASSERT_EQUAL(obj_hdr->object_type, PCEP_OBJ_TYPE_LSP);
    CU_ASSERT_EQUAL(obj_hdr->object_length, 20);

     /* LSP TLV */
    CU_ASSERT_TRUE(pcep_obj_has_tlv(obj_hdr));
    double_linked_list *tlv_list = pcep_obj_get_tlvs(obj_hdr);
    CU_ASSERT_EQUAL(tlv_list->num_entries, 1);
    struct pcep_object_tlv *tlv = (struct pcep_object_tlv *) tlv_list->head->data;
    CU_ASSERT_EQUAL(tlv->header.type, PCEP_OBJ_TLV_TYPE_SYMBOLIC_PATH_NAME);
    CU_ASSERT_EQUAL(tlv->header.length, 8);
    dll_destroy(tlv_list);

    /* Endpoints object */
    node = node->next_node;
    obj_hdr = (struct pcep_object_header *) node->data;
    CU_ASSERT_EQUAL(obj_hdr->object_class, PCEP_OBJ_CLASS_ENDPOINTS);
    CU_ASSERT_EQUAL(obj_hdr->object_type, PCEP_OBJ_TYPE_ENDPOINT_IPV4);
    CU_ASSERT_EQUAL(obj_hdr->object_length, sizeof(struct pcep_object_endpoints_ipv4));
    CU_ASSERT_FALSE(pcep_obj_has_tlv(obj_hdr));

    /* ERO object */
    node = node->next_node;
    obj_hdr = (struct pcep_object_header *) node->data;
    CU_ASSERT_EQUAL(obj_hdr->object_class, PCEP_OBJ_CLASS_ERO);
    CU_ASSERT_EQUAL(obj_hdr->object_type, PCEP_OBJ_TYPE_ERO);
    CU_ASSERT_EQUAL(obj_hdr->object_length, 16);

    /* ERO Subobjects */
    double_linked_list *ero_subobj_list = pcep_obj_get_ro_subobjects(obj_hdr);
    CU_ASSERT_PTR_NOT_NULL(ero_subobj_list);
    CU_ASSERT_EQUAL(ero_subobj_list->num_entries, 1);
    double_linked_list_node *subobj_node = ero_subobj_list->head;
    struct pcep_ro_subobj_hdr *subobj_hdr = (struct pcep_ro_subobj_hdr *) subobj_node->data;
    CU_ASSERT_EQUAL(subobj_hdr->type, RO_SUBOBJ_TYPE_SR_DRAFT07);
    CU_ASSERT_EQUAL(subobj_hdr->length, 12);
    struct pcep_ro_subobj_sr *subobj_sr = (struct pcep_ro_subobj_sr *) subobj_hdr;
    CU_ASSERT_EQUAL(subobj_sr->nt_flags, (PCEP_SR_SUBOBJ_NAI_IPV4_NODE | PCEP_SR_SUBOBJ_M_FLAG));
    CU_ASSERT_EQUAL(subobj_sr->sid_nai[0], 65576960);
    CU_ASSERT_EQUAL(subobj_sr->sid_nai[1], 0x01010101);

    pcep_msg_free_message(msg);
    dll_destroy(ero_subobj_list);
    dll_destroy(msg_list);
    close(fd);
}

void test_pcep_msg_read_pcep_open()
{
    int fd = convert_hexstrs_to_binary(pcep_open_odl_hexbyte_strs, pcep_open_hexbyte_strs_length);
    double_linked_list *msg_list = pcep_msg_read(fd);
    CU_ASSERT_PTR_NOT_NULL(msg_list);
    CU_ASSERT_EQUAL(msg_list->num_entries, 1);

    struct pcep_message *msg = (struct pcep_message *) msg_list->head->data;
    CU_ASSERT_EQUAL(msg->obj_list->num_entries, 1);
    CU_ASSERT_EQUAL(msg->header->type, PCEP_TYPE_OPEN);
    CU_ASSERT_EQUAL(msg->header->length, pcep_open_hexbyte_strs_length);

    /* Verify the Open message */
    struct pcep_object_header *obj_hdr = (struct pcep_object_header *) msg->obj_list->head->data;
    CU_ASSERT_EQUAL(obj_hdr->object_class, PCEP_OBJ_CLASS_OPEN);
    CU_ASSERT_EQUAL(obj_hdr->object_type, PCEP_OBJ_TYPE_OPEN);
    CU_ASSERT_EQUAL(obj_hdr->object_length, 24);
    CU_ASSERT_TRUE(pcep_obj_has_tlv(obj_hdr));

    /* Open TLV: Stateful PCE Capability */
    double_linked_list *tlv_list = pcep_obj_get_tlvs(obj_hdr);
    CU_ASSERT_EQUAL(tlv_list->num_entries, 2);
    double_linked_list_node *tlv_node = tlv_list->head;
    struct pcep_object_tlv *tlv = (struct pcep_object_tlv *) tlv_node->data;
    CU_ASSERT_EQUAL(tlv->header.type, PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY);
    CU_ASSERT_EQUAL(tlv->header.length, 4);

    /* Open TLV: SR PCE Capability */
    tlv_node = tlv_node->next_node;
    tlv = (struct pcep_object_tlv *) tlv_node->data;
    CU_ASSERT_EQUAL(tlv->header.type, PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY);
    CU_ASSERT_EQUAL(tlv->header.length, 4);

    dll_destroy(tlv_list);
    pcep_msg_free_message(msg);
    dll_destroy(msg_list);
    close(fd);
}

void test_pcep_msg_read_pcep_update()
{
    int fd = convert_hexstrs_to_binary(pcep_update_hexbyte_strs, pcep_update_hexbyte_strs_length);
    double_linked_list *msg_list = pcep_msg_read(fd);
    CU_ASSERT_PTR_NOT_NULL(msg_list);
    CU_ASSERT_EQUAL(msg_list->num_entries, 1);

    struct pcep_message *msg = (struct pcep_message *) msg_list->head->data;
    CU_ASSERT_EQUAL(msg->obj_list->num_entries, 3);

    CU_ASSERT_EQUAL(msg->header->type, PCEP_TYPE_UPDATE);
    CU_ASSERT_EQUAL(msg->header->length, pcep_update_hexbyte_strs_length);

    /* Verify each of the object types */

    double_linked_list_node *node = msg->obj_list->head;

    /* SRP object */
    struct pcep_object_header *obj_hdr = (struct pcep_object_header *) node->data;
    CU_ASSERT_EQUAL(obj_hdr->object_class, PCEP_OBJ_CLASS_SRP);
    CU_ASSERT_EQUAL(obj_hdr->object_type, PCEP_OBJ_TYPE_SRP);
    CU_ASSERT_EQUAL(obj_hdr->object_length, 20);
    CU_ASSERT_TRUE(pcep_obj_has_tlv(obj_hdr));

     /* SRP TLV */
    double_linked_list *tlv_list = pcep_obj_get_tlvs(obj_hdr);
    CU_ASSERT_EQUAL(tlv_list->num_entries, 1);
    struct pcep_object_tlv *tlv = (struct pcep_object_tlv *) tlv_list->head->data;
    CU_ASSERT_EQUAL(tlv->header.type, PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE);
    CU_ASSERT_EQUAL(tlv->header.length, 4);
    /* TODO verify the path setup type */
    dll_destroy(tlv_list);

    /* LSP object */
    node = node->next_node;
    obj_hdr = (struct pcep_object_header *) node->data;
    CU_ASSERT_EQUAL(obj_hdr->object_class, PCEP_OBJ_CLASS_LSP);
    CU_ASSERT_EQUAL(obj_hdr->object_type, PCEP_OBJ_TYPE_LSP);
    CU_ASSERT_EQUAL(obj_hdr->object_length, 8);
    CU_ASSERT_FALSE(pcep_obj_has_tlv(obj_hdr));

    /* ERO object */
    node = node->next_node;
    obj_hdr = (struct pcep_object_header *) node->data;
    CU_ASSERT_EQUAL(obj_hdr->object_class, PCEP_OBJ_CLASS_ERO);
    CU_ASSERT_EQUAL(obj_hdr->object_type, PCEP_OBJ_TYPE_ERO);
    CU_ASSERT_EQUAL(obj_hdr->object_length, 16);

    /* ERO Subobjects */
    double_linked_list *ero_subobj_list = pcep_obj_get_ro_subobjects(obj_hdr);
    CU_ASSERT_PTR_NOT_NULL(ero_subobj_list);
    CU_ASSERT_EQUAL(ero_subobj_list->num_entries, 1);
    double_linked_list_node *subobj_node = ero_subobj_list->head;
    struct pcep_ro_subobj_hdr *subobj_hdr = (struct pcep_ro_subobj_hdr *) subobj_node->data;
    CU_ASSERT_EQUAL(subobj_hdr->type, RO_SUBOBJ_TYPE_SR_DRAFT07);
    CU_ASSERT_EQUAL(subobj_hdr->length, 12);
    struct pcep_ro_subobj_sr *subobj_sr = (struct pcep_ro_subobj_sr *) subobj_hdr;
    CU_ASSERT_EQUAL(GET_SR_SUBOBJ_NT(subobj_sr), PCEP_SR_SUBOBJ_NAI_IPV4_NODE);
    CU_ASSERT_EQUAL(GET_SR_SUBOBJ_FLAGS(subobj_sr), PCEP_SR_SUBOBJ_M_FLAG);
    CU_ASSERT_EQUAL(subobj_sr->nt_flags, (PCEP_SR_SUBOBJ_NAI_IPV4_NODE | PCEP_SR_SUBOBJ_M_FLAG));
    CU_ASSERT_EQUAL(subobj_sr->sid_nai[0], 65576960);
    CU_ASSERT_EQUAL(subobj_sr->sid_nai[1], 0x01010101);

    pcep_msg_free_message(msg);
    dll_destroy(ero_subobj_list);
    dll_destroy(msg_list);
    close(fd);
}

void test_pcep_msg_read_pcep_open_initiate()
{
    int fd = convert_hexstrs_to_binary(pcep_open_initiate_odl_hexbyte_strs, pcep_open_initiate_hexbyte_strs_length);
    double_linked_list *msg_list = pcep_msg_read(fd);
    CU_ASSERT_PTR_NOT_NULL(msg_list);
    CU_ASSERT_EQUAL(msg_list->num_entries, 2);

    struct pcep_message *msg = (struct pcep_message *) msg_list->head->data;
    CU_ASSERT_EQUAL(msg->obj_list->num_entries, 1);
    CU_ASSERT_EQUAL(msg->header->type, PCEP_TYPE_OPEN);
    CU_ASSERT_EQUAL(msg->header->length, pcep_open_hexbyte_strs_length);
    pcep_msg_free_message(msg);

    msg = (struct pcep_message *) msg_list->head->next_node->data;
    CU_ASSERT_EQUAL(msg->obj_list->num_entries, 4);
    CU_ASSERT_EQUAL(msg->header->type, PCEP_TYPE_INITIATE);
    CU_ASSERT_EQUAL(msg->header->length, pcep_initiate2_hexbyte_strs_length);
    pcep_msg_free_message(msg);

    dll_destroy(msg_list);
    close(fd);
}

void test_validate_message_header()
{
    uint8_t pcep_message_invalid_version[] = {0x22, 0x01, 0x04, 0x00};
    uint8_t pcep_message_invalid_length[]  = {0x20, 0x01, 0x00, 0x00};
    uint8_t pcep_message_invalid_type[]    = {0x20, 0xff, 0x04, 0x00};
    uint8_t pcep_message_valid[]           = {0x20, 0x01, 0x04, 0x00};

    /* Verify invalid message header version */
    CU_ASSERT_FALSE(validate_message_header((struct pcep_header*) pcep_message_invalid_version));

    /* Verify invalid message header lengths */
    CU_ASSERT_FALSE(validate_message_header((struct pcep_header*) pcep_message_invalid_length));
    pcep_message_invalid_length[2] = 0x05;
    CU_ASSERT_FALSE(validate_message_header((struct pcep_header*) pcep_message_invalid_length));

    /* Verify invalid message header types */
    CU_ASSERT_FALSE(validate_message_header((struct pcep_header*) pcep_message_invalid_type));
    pcep_message_invalid_type[1] = 0x00;
    CU_ASSERT_FALSE(validate_message_header((struct pcep_header*) pcep_message_invalid_type));

    /* Verify a valid message header */
    CU_ASSERT_TRUE(validate_message_header((struct pcep_header*) pcep_message_valid));
}

/* Internal util function */
struct pcep_message *create_message(uint8_t msg_type, uint8_t obj1_class, uint8_t obj2_class, uint8_t obj3_class, uint8_t obj4_class)
{
    struct pcep_message *msg = malloc(sizeof(struct pcep_message));
    msg->obj_list = dll_initialize();
    msg->header = malloc(sizeof(struct pcep_header) + (sizeof(struct pcep_object_header) * 4));
    msg->header->type = msg_type;

    struct pcep_object_header *obj_hdr = (struct pcep_object_header *) (msg->header + 1);
    if (obj1_class > 0)
    {
        obj_hdr->object_class = obj1_class;
        obj_hdr->object_length = sizeof(struct pcep_object_header);
        dll_append(msg->obj_list, obj_hdr);
    }

    if (obj2_class > 0)
    {
        obj_hdr += 1;
        obj_hdr->object_class = obj2_class;
        obj_hdr->object_length = sizeof(struct pcep_object_header);
        dll_append(msg->obj_list, obj_hdr);
    }

    if (obj3_class > 0)
    {
        obj_hdr += 1;
        obj_hdr->object_class = obj3_class;
        obj_hdr->object_length = sizeof(struct pcep_object_header);
        dll_append(msg->obj_list, obj_hdr);
    }

    if (obj4_class > 0)
    {
        obj_hdr += 1;
        obj_hdr->object_class = obj4_class;
        obj_hdr->object_length = sizeof(struct pcep_object_header);
        dll_append(msg->obj_list, obj_hdr);
    }

    return msg;
}

void test_validate_message_objects()
{
    /* Valid Open message */
    struct pcep_message *msg = create_message(PCEP_TYPE_OPEN, PCEP_OBJ_CLASS_OPEN, 0, 0, 0);
    CU_ASSERT_TRUE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    /* Valid KeepAlive message */
    msg = create_message(PCEP_TYPE_KEEPALIVE, 0, 0, 0, 0);
    CU_ASSERT_TRUE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    /* Valid PcReq message */
    /* Using object_class=255 to verify it can take any object */
    msg = create_message(PCEP_TYPE_PCREQ, PCEP_OBJ_CLASS_RP, PCEP_OBJ_CLASS_ENDPOINTS, any_obj_class, 0);
    CU_ASSERT_TRUE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    /* Valid PcRep message */
    msg = create_message(PCEP_TYPE_PCREP, PCEP_OBJ_CLASS_RP, any_obj_class, 0, 0);
    CU_ASSERT_TRUE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    /* Valid Notify message */
    msg = create_message(PCEP_TYPE_PCNOTF, PCEP_OBJ_CLASS_NOTF, any_obj_class, 0, 0);
    CU_ASSERT_TRUE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    /* Valid Error message */
    msg = create_message(PCEP_TYPE_ERROR, PCEP_OBJ_CLASS_ERROR, any_obj_class, 0, 0);
    CU_ASSERT_TRUE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    /* Valid Close message */
    msg = create_message(PCEP_TYPE_CLOSE, PCEP_OBJ_CLASS_CLOSE, 0, 0, 0);
    CU_ASSERT_TRUE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    /* Valid Report message */
    msg = create_message(PCEP_TYPE_REPORT, PCEP_OBJ_CLASS_SRP, PCEP_OBJ_CLASS_LSP, any_obj_class, any_obj_class);
    CU_ASSERT_TRUE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    /* Valid Update message */
    msg = create_message(PCEP_TYPE_UPDATE, PCEP_OBJ_CLASS_SRP, PCEP_OBJ_CLASS_LSP, any_obj_class, any_obj_class);
    CU_ASSERT_TRUE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    /* Valid Initiate message */
    msg = create_message(PCEP_TYPE_INITIATE, PCEP_OBJ_CLASS_SRP, PCEP_OBJ_CLASS_LSP, any_obj_class, any_obj_class);
    CU_ASSERT_TRUE(validate_message_objects(msg));
    pcep_msg_free_message(msg);
}

void test_validate_message_objects_invalid()
{
    /* unsupported message ID = 0
     * {NO_OBJECT, NO_OBJECT, NO_OBJECT, NO_OBJECT} */
    struct pcep_message *msg = create_message(0, any_obj_class, 0, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    /* Open message
     * {PCEP_OBJ_CLASS_OPEN, NO_OBJECT, NO_OBJECT, NO_OBJECT} */
    msg = create_message(PCEP_TYPE_OPEN, 0, 0, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    msg = create_message(PCEP_TYPE_OPEN, any_obj_class, 0, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    msg = create_message(PCEP_TYPE_OPEN, PCEP_OBJ_CLASS_OPEN, any_obj_class, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    /* KeepAlive message
     * {NO_OBJECT, NO_OBJECT, NO_OBJECT, NO_OBJECT} */
    msg = create_message(PCEP_TYPE_KEEPALIVE, any_obj_class, 0, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    /* PcReq message
     * {PCEP_OBJ_CLASS_RP, PCEP_OBJ_CLASS_ENDPOINTS, ANY_OBJECT, ANY_OBJECT} */
    msg = create_message(PCEP_TYPE_PCREQ, 0, 0, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    msg = create_message(PCEP_TYPE_PCREQ, PCEP_OBJ_CLASS_RP, any_obj_class, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    /* PcRep message
     * {PCEP_OBJ_CLASS_RP, ANY_OBJECT, ANY_OBJECT, ANY_OBJECT} */
    msg = create_message(PCEP_TYPE_PCREP, 0, 0, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    msg = create_message(PCEP_TYPE_PCREP, any_obj_class, 0, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    /* Notify message
     * {PCEP_OBJ_CLASS_NOTF, ANY_OBJECT, ANY_OBJECT, ANY_OBJECT} */
    msg = create_message(PCEP_TYPE_PCNOTF, 0, 0, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    msg = create_message(PCEP_TYPE_PCNOTF, any_obj_class, 0, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    /* Error message
     * {PCEP_OBJ_CLASS_ERROR, ANY_OBJECT, ANY_OBJECT, ANY_OBJECT} */
    msg = create_message(PCEP_TYPE_ERROR, 0, 0, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    msg = create_message(PCEP_TYPE_ERROR, any_obj_class, 0, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    /* Close message
     * {PCEP_OBJ_CLASS_CLOSE, NO_OBJECT, NO_OBJECT, NO_OBJECT} */
    msg = create_message(PCEP_TYPE_CLOSE, 0, 0, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    msg = create_message(PCEP_TYPE_CLOSE, any_obj_class, 0, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    /* unsupported message ID = 8
     * {NO_OBJECT, NO_OBJECT, NO_OBJECT, NO_OBJECT} */
    msg = create_message(8, any_obj_class, 0, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    /* unsupported message ID = 9
     * {NO_OBJECT, NO_OBJECT, NO_OBJECT, NO_OBJECT} */
    msg = create_message(9, any_obj_class, 0, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    /* Report message
     * {PCEP_OBJ_CLASS_SRP, PCEP_OBJ_CLASS_LSP, ANY_OBJECT, ANY_OBJECT} */
    msg = create_message(PCEP_TYPE_REPORT, 0, 0, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    msg = create_message(PCEP_TYPE_REPORT, any_obj_class, 0, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    msg = create_message(PCEP_TYPE_REPORT, PCEP_OBJ_CLASS_SRP, 0, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    msg = create_message(PCEP_TYPE_REPORT, PCEP_OBJ_CLASS_SRP, any_obj_class, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    /* Update message
     * {PCEP_OBJ_CLASS_SRP, PCEP_OBJ_CLASS_LSP, ANY_OBJECT, ANY_OBJECT} */
    msg = create_message(PCEP_TYPE_UPDATE, 0, 0, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    msg = create_message(PCEP_TYPE_UPDATE, any_obj_class, 0, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    msg = create_message(PCEP_TYPE_UPDATE, PCEP_OBJ_CLASS_SRP, 0, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    msg = create_message(PCEP_TYPE_UPDATE, PCEP_OBJ_CLASS_SRP, any_obj_class, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    /* Initiate message
     * {PCEP_OBJ_CLASS_SRP, PCEP_OBJ_CLASS_LSP, ANY_OBJECT, ANY_OBJECT} */
    msg = create_message(PCEP_TYPE_INITIATE, 0, 0, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    msg = create_message(PCEP_TYPE_INITIATE, any_obj_class, 0, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    msg = create_message(PCEP_TYPE_INITIATE, PCEP_OBJ_CLASS_SRP, 0, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);

    msg = create_message(PCEP_TYPE_INITIATE, PCEP_OBJ_CLASS_SRP, any_obj_class, 0, 0);
    CU_ASSERT_FALSE(validate_message_objects(msg));
    pcep_msg_free_message(msg);
}
