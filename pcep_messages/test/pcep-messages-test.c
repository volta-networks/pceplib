/*
 * pcep-messages-test.c
 *
 *  Created on: Oct 11, 2019
 *      Author: brady
 */

#include <stdlib.h>

#include <CUnit/CUnit.h>

#include "pcep_utils_double_linked_list.h"
#include "pcep-objects.h"
#include "pcep-messages.h"
#include "pcep-tools.h"

void test_pcep_msg_create_open()
{
    uint8_t keepalive = 30;
    uint8_t deadtimer = 60;
    uint8_t sid = 255;

    struct pcep_message *message = pcep_msg_create_open(keepalive, deadtimer, sid);
    CU_ASSERT_PTR_NOT_NULL(message);
    CU_ASSERT_PTR_NOT_NULL(message->header);
    CU_ASSERT_PTR_NOT_NULL(message->obj_list);
    CU_ASSERT_EQUAL(message->obj_list->num_entries, 1);
    struct pcep_header* open_msg = message->header;
    struct pcep_object_open *open_obj = (struct pcep_object_open *) message->obj_list->head->data;

    CU_ASSERT_EQUAL(ntohs(open_msg->length),
            sizeof(struct pcep_header) + sizeof(struct pcep_object_open));
    CU_ASSERT_EQUAL(open_msg->type, PCEP_TYPE_OPEN);
    CU_ASSERT_EQUAL(open_msg->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);

    /* Just check the class and type, the rest of the hdr fields
     * are verified in pcep-objects-test.c */
    CU_ASSERT_EQUAL(open_obj->header.object_class, PCEP_OBJ_CLASS_OPEN);
    CU_ASSERT_EQUAL(open_obj->header.object_type, PCEP_OBJ_TYPE_OPEN);

    CU_ASSERT_EQUAL(open_obj->open_deadtimer, deadtimer);
    CU_ASSERT_EQUAL(open_obj->open_keepalive, keepalive);
    CU_ASSERT_EQUAL(open_obj->open_sid, sid);
    CU_ASSERT_EQUAL(open_obj->open_ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);
    pcep_msg_free_message(message);
}


void test_pcep_msg_create_request()
{
    /* First test with NULL objects */
    struct pcep_message *message = pcep_msg_create_request(NULL, NULL, NULL);
    CU_ASSERT_PTR_NULL(message);

    struct pcep_object_rp *rp_obj = pcep_obj_create_rp(0, 0, 0, NULL);
    struct in_addr src_addr, dst_addr;
    struct pcep_object_endpoints_ipv4 *ipv4_obj = pcep_obj_create_enpoint_ipv4(&src_addr, &dst_addr);
    struct pcep_object_bandwidth *bandwidth_obj = pcep_obj_create_bandwidth(4.2);
    message = pcep_msg_create_request(rp_obj, ipv4_obj, bandwidth_obj);

    CU_ASSERT_PTR_NOT_NULL(message);
    CU_ASSERT_PTR_NOT_NULL(message->header);
    CU_ASSERT_PTR_NOT_NULL(message->obj_list);
    CU_ASSERT_EQUAL(message->obj_list->num_entries, 3);
    CU_ASSERT_EQUAL(ntohs(message->header->length),
            sizeof(struct pcep_header) + sizeof(struct pcep_object_rp) +
            sizeof(struct pcep_object_endpoints_ipv4) + sizeof(struct pcep_object_bandwidth));
    CU_ASSERT_EQUAL(message->header->type, PCEP_TYPE_PCREQ);
    CU_ASSERT_EQUAL(message->header->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);
    free(rp_obj);
    free(ipv4_obj);
    free(bandwidth_obj);
    pcep_msg_free_message(message);
}


void test_pcep_msg_create_request_svec()
{
}


void test_pcep_msg_create_reply_nopath()
{
    /* First test with NULL nopath and rp objects */
    struct pcep_message *message = pcep_msg_create_reply_nopath(NULL, NULL);

    CU_ASSERT_PTR_NOT_NULL(message);
    CU_ASSERT_PTR_NOT_NULL(message->header);
    CU_ASSERT_PTR_NOT_NULL(message->obj_list);
    CU_ASSERT_EQUAL(message->obj_list->num_entries, 0);
    CU_ASSERT_EQUAL(ntohs(message->header->length), sizeof(struct pcep_header));
    CU_ASSERT_EQUAL(message->header->type, PCEP_TYPE_PCREP);
    CU_ASSERT_EQUAL(message->header->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);
    pcep_msg_free_message(message);

    struct pcep_object_rp *rp_obj = pcep_obj_create_rp(0, 0, 0, NULL);
    struct pcep_object_nopath *nopath_obj = pcep_obj_create_nopath(0, 0, 0, 0);
    message = pcep_msg_create_reply_nopath(rp_obj, nopath_obj);

    CU_ASSERT_PTR_NOT_NULL(message);
    CU_ASSERT_PTR_NOT_NULL(message->header);
    CU_ASSERT_PTR_NOT_NULL(message->obj_list);
    CU_ASSERT_EQUAL(message->obj_list->num_entries, 2);
    CU_ASSERT_EQUAL(ntohs(message->header->length),
            (sizeof(struct pcep_header) +
             sizeof(struct pcep_object_rp) +
             sizeof(struct pcep_object_nopath) +
             sizeof(uint32_t))); /* Add 4 for the TLV value */
    CU_ASSERT_EQUAL(message->header->type, PCEP_TYPE_PCREP);
    CU_ASSERT_EQUAL(message->header->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);
    free(rp_obj);
    free(nopath_obj);
    pcep_msg_free_message(message);
}


void test_pcep_msg_create_reply()
{
    /* First test with NULL ero and rp objects */
    struct pcep_message *message = pcep_msg_create_reply(NULL, NULL);

    CU_ASSERT_PTR_NOT_NULL(message);
    CU_ASSERT_PTR_NOT_NULL(message->header);
    CU_ASSERT_PTR_NOT_NULL(message->obj_list);
    CU_ASSERT_EQUAL(message->obj_list->num_entries, 0);
    CU_ASSERT_EQUAL(ntohs(message->header->length), sizeof(struct pcep_header));
    CU_ASSERT_EQUAL(message->header->type, PCEP_TYPE_PCREP);
    CU_ASSERT_EQUAL(message->header->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);
    pcep_msg_free_message(message);

    double_linked_list *ero_subobj_list = dll_initialize();
    struct pcep_object_ro_subobj *ero_subobj = pcep_obj_create_ro_subobj_32label(1, 10);
    dll_append(ero_subobj_list, ero_subobj);
    struct pcep_object_ro *ero = pcep_obj_create_ero(ero_subobj_list);

    double_linked_list *object_list = dll_initialize();
    dll_append(object_list, ero);
    struct pcep_object_rp *rp_obj = pcep_obj_create_rp(0, 0, 0, NULL);
    message = pcep_msg_create_reply(rp_obj, object_list);

    CU_ASSERT_PTR_NOT_NULL(message);
    CU_ASSERT_PTR_NOT_NULL(message->header);
    CU_ASSERT_PTR_NOT_NULL(message->obj_list);
    CU_ASSERT_EQUAL(message->obj_list->num_entries, 2);
    CU_ASSERT_EQUAL(ntohs(message->header->length),
            sizeof(struct pcep_header) + sizeof(struct pcep_object_rp) +
            sizeof(struct pcep_object_ro) + sizeof(struct pcep_ro_subobj_32label));
    CU_ASSERT_EQUAL(message->header->type, PCEP_TYPE_PCREP);
    CU_ASSERT_EQUAL(message->header->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);
    dll_destroy_with_data(ero_subobj_list);
    dll_destroy_with_data(object_list);
    free(rp_obj);
    pcep_msg_free_message(message);
}


void test_pcep_msg_create_close()
{
    uint8_t flags = 0xFF;
    uint8_t reason = PCEP_CLOSE_REASON_UNREC;

    struct pcep_message *message = pcep_msg_create_close(flags, reason);

    CU_ASSERT_PTR_NOT_NULL(message);
    CU_ASSERT_PTR_NOT_NULL(message->header);
    CU_ASSERT_PTR_NOT_NULL(message->obj_list);
    CU_ASSERT_EQUAL(message->obj_list->num_entries, 1);
    CU_ASSERT_EQUAL(ntohs(message->header->length),
            sizeof(struct pcep_header) + sizeof(struct pcep_object_close));
    CU_ASSERT_EQUAL(message->header->type, PCEP_TYPE_CLOSE);
    CU_ASSERT_EQUAL(message->header->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);

    /* Just check the class and type, the rest of the hdr fields
     * are verified in pcep-objects-test.c */
    struct pcep_object_close *close_obj =
            (struct pcep_object_close *) message->obj_list->head->data;
    CU_ASSERT_EQUAL(close_obj->header.object_class, PCEP_OBJ_CLASS_CLOSE);
    CU_ASSERT_EQUAL(close_obj->header.object_type, PCEP_OBJ_TYPE_CLOSE);

    CU_ASSERT_EQUAL(close_obj->flags, flags);
    CU_ASSERT_EQUAL(close_obj->reason, reason);
    pcep_msg_free_message(message);
}


void test_pcep_msg_create_error()
{
    uint8_t error_type = PCEP_ERRT_RECEPTION_OF_INV_OBJECT;
    uint8_t error_value = PCEP_ERRV_KEEPALIVEWAIT_TIMED_OUT;

    struct pcep_message *message = pcep_msg_create_error(error_type, error_value);

    CU_ASSERT_PTR_NOT_NULL(message);
    CU_ASSERT_PTR_NOT_NULL(message->header);
    CU_ASSERT_PTR_NOT_NULL(message->obj_list);
    CU_ASSERT_EQUAL(message->obj_list->num_entries, 1);
    CU_ASSERT_EQUAL(ntohs(message->header->length),
            sizeof(struct pcep_header) + sizeof(struct pcep_object_error));
    CU_ASSERT_EQUAL(message->header->type, PCEP_TYPE_ERROR);
    CU_ASSERT_EQUAL(message->header->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);

    /* Just check the class and type, the rest of the hdr fields
     * are verified in pcep-objects-test.c */
    struct pcep_object_error *error_obj =
            (struct pcep_object_error *) message->obj_list->head->data;
    CU_ASSERT_EQUAL(error_obj->header.object_class, PCEP_OBJ_CLASS_ERROR);
    CU_ASSERT_EQUAL(error_obj->header.object_type, PCEP_OBJ_TYPE_ERROR);

    CU_ASSERT_EQUAL(error_obj->error_type, error_type);
    CU_ASSERT_EQUAL(error_obj->error_value, error_value);
    pcep_msg_free_message(message);
}


void test_pcep_msg_create_keepalive()
{
    struct pcep_message *message = pcep_msg_create_keepalive();

    CU_ASSERT_PTR_NOT_NULL(message);
    CU_ASSERT_PTR_NOT_NULL(message->header);
    CU_ASSERT_PTR_NOT_NULL(message->obj_list);
    CU_ASSERT_EQUAL(message->obj_list->num_entries, 0);
    CU_ASSERT_EQUAL(ntohs(message->header->length), sizeof(struct pcep_header));
    CU_ASSERT_EQUAL(message->header->type, PCEP_TYPE_KEEPALIVE);
    CU_ASSERT_EQUAL(message->header->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);
    pcep_msg_free_message(message);
}

void test_pcep_msg_create_report()
{
    double_linked_list *obj_list = dll_initialize();

    /* Should return NULL if obj_list is empty */
    struct pcep_message *message = pcep_msg_create_report(NULL);
    CU_ASSERT_PTR_NULL(message);

    struct pcep_object_lsp* lsp = pcep_obj_create_lsp(
            100, PCEP_LSP_OPERATIONAL_UP, true, true, true, true, true, NULL);
    dll_append(obj_list, lsp);
    message = pcep_msg_create_report(obj_list);
    CU_ASSERT_PTR_NOT_NULL(message);
    CU_ASSERT_PTR_NOT_NULL(message->header);
    CU_ASSERT_PTR_NOT_NULL(message->obj_list);
    CU_ASSERT_EQUAL(message->obj_list->num_entries, 1);
    CU_ASSERT_EQUAL(ntohs(message->header->length),
            sizeof(struct pcep_header) + ntohs(lsp->header.object_length));
    CU_ASSERT_EQUAL(message->header->type, PCEP_TYPE_REPORT);
    CU_ASSERT_EQUAL(message->header->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);

    free(lsp);
    dll_destroy(obj_list);
    pcep_msg_free_message(message);
}

void test_pcep_msg_create_update()
{
    double_linked_list *obj_list = dll_initialize();
    double_linked_list *ero_subobj_list = dll_initialize();

    struct pcep_message *message = pcep_msg_create_update(NULL);
    CU_ASSERT_PTR_NULL(message);

    /* Should return NULL if obj_list is empty */
    message = pcep_msg_create_update(obj_list);
    CU_ASSERT_PTR_NULL(message);

    struct pcep_object_srp* srp = pcep_obj_create_srp(false, 100, NULL);
    struct pcep_object_lsp* lsp = pcep_obj_create_lsp(
            100, PCEP_LSP_OPERATIONAL_UP, true, true, true, true, true, NULL);
    dll_append(ero_subobj_list, pcep_obj_create_ro_subobj_asn(0x0102));
    struct pcep_object_ro*  ero = pcep_obj_create_ero(ero_subobj_list);

    /* Should return NULL if obj_list does not have 3 entries */
    dll_append(obj_list, srp);
    dll_append(obj_list, lsp);
    message = pcep_msg_create_update(obj_list);
    CU_ASSERT_PTR_NULL(message);

    dll_append(obj_list, ero);
    message = pcep_msg_create_update(obj_list);
    CU_ASSERT_PTR_NOT_NULL(message);
    CU_ASSERT_PTR_NOT_NULL(message->header);
    CU_ASSERT_PTR_NOT_NULL(message->obj_list);
    CU_ASSERT_EQUAL(message->obj_list->num_entries, 3);
    CU_ASSERT_EQUAL(ntohs(message->header->length),
            sizeof(struct pcep_header) +
            ntohs(srp->header.object_length) +
            ntohs(lsp->header.object_length) +
            ntohs(ero->header.object_length));
    CU_ASSERT_EQUAL(message->header->type, PCEP_TYPE_UPDATE);
    CU_ASSERT_EQUAL(message->header->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);

    dll_destroy_with_data(ero_subobj_list);
    dll_destroy_with_data(obj_list);
    pcep_msg_free_message(message);
}

void test_pcep_msg_create_initiate()
{
    double_linked_list *obj_list = dll_initialize();
    double_linked_list *ero_subobj_list = dll_initialize();

    /* Should return NULL if obj_list is empty */
    struct pcep_message *message = pcep_msg_create_initiate(NULL);
    CU_ASSERT_PTR_NULL(message);

    struct pcep_object_srp* srp = pcep_obj_create_srp(false, 100, NULL);
    struct pcep_object_lsp* lsp = pcep_obj_create_lsp(
            100, PCEP_LSP_OPERATIONAL_UP, true, true, true, true, true, NULL);
    dll_append(ero_subobj_list, pcep_obj_create_ro_subobj_asn(0x0102));
    struct pcep_object_ro*  ero = pcep_obj_create_ero(ero_subobj_list);

    /* Should return NULL if obj_list does not have 2 entries */
    dll_append(obj_list, srp);
    message = pcep_msg_create_initiate(obj_list);
    CU_ASSERT_PTR_NULL(message);

    dll_append(obj_list, lsp);
    dll_append(obj_list, ero);
    message = pcep_msg_create_initiate(obj_list);
    CU_ASSERT_PTR_NOT_NULL(message);
    CU_ASSERT_PTR_NOT_NULL(message->header);
    CU_ASSERT_PTR_NOT_NULL(message->obj_list);
    CU_ASSERT_EQUAL(message->obj_list->num_entries, 3);
    CU_ASSERT_EQUAL(ntohs(message->header->length),
            sizeof(struct pcep_header) +
            ntohs(srp->header.object_length) +
            ntohs(lsp->header.object_length) +
            ntohs(ero->header.object_length));
    CU_ASSERT_EQUAL(message->header->type, PCEP_TYPE_INITIATE);
    CU_ASSERT_EQUAL(message->header->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);

    dll_destroy_with_data(ero_subobj_list);
    dll_destroy_with_data(obj_list);
    pcep_msg_free_message(message);
}

