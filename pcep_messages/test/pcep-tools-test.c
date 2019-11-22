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

void pcep_msg_read_pcep_initiate_test()
{
    int fd = convert_hexstrs_to_binary(pcep_initiate_hexbyte_strs, pcep_initiate_hexbyte_strs_length);
    double_linked_list *msg_list = pcep_msg_read(fd);
    CU_ASSERT_PTR_NOT_NULL(msg_list);
    CU_ASSERT_EQUAL(msg_list->num_entries, 1);

    struct pcep_message *msg = (struct pcep_message *) msg_list->head->data;
    CU_ASSERT_EQUAL(msg->obj_list->num_entries, 4);

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
