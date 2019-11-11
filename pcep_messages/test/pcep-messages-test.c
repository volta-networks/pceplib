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

void test_pcep_msg_create_open()
{
    uint8_t keepalive = 30;
    uint8_t deadtimer = 60;
    uint8_t sid = 255;

    struct pcep_header* open_msg = pcep_msg_create_open(keepalive, deadtimer, sid);
    struct pcep_object_open *open_obj =
            (struct pcep_object_open *) (((char *) open_msg) + sizeof(struct pcep_header));

    CU_ASSERT_PTR_NOT_NULL(open_msg);
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
    free(open_msg);
}


void test_pcep_msg_create_request()
{
    /* First test with NULL objects */
    struct pcep_header* request_msg = pcep_msg_create_request(NULL, NULL, NULL);
    CU_ASSERT_PTR_NULL(request_msg);

    struct pcep_object_rp *rp_obj = pcep_obj_create_rp(0, 0, 0);
    struct in_addr src_addr, dst_addr;
    struct pcep_object_endpoints_ipv4 *ipv4_obj = pcep_obj_create_enpoint_ipv4(&src_addr, &dst_addr);
    struct pcep_object_bandwidth *bandwidth_obj = pcep_obj_create_bandwidth(4.2);
    request_msg = pcep_msg_create_request(rp_obj, ipv4_obj, bandwidth_obj);

    CU_ASSERT_PTR_NOT_NULL(request_msg);
    CU_ASSERT_EQUAL(ntohs(request_msg->length),
            sizeof(struct pcep_header) + sizeof(struct pcep_object_rp) +
            sizeof(struct pcep_object_endpoints_ipv4) + sizeof(struct pcep_object_bandwidth));
    CU_ASSERT_EQUAL(request_msg->type, PCEP_TYPE_PCREQ);
    CU_ASSERT_EQUAL(request_msg->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);
    free(rp_obj);
    free(ipv4_obj);
    free(bandwidth_obj);
    free(request_msg);

}


void test_pcep_msg_create_request_svec()
{
}


void test_pcep_msg_create_reply_nopath()
{
    /* First test with NULL nopath and rp objects */
    struct pcep_header* reply_msg = pcep_msg_create_reply_nopath(NULL, NULL);

    CU_ASSERT_PTR_NOT_NULL(reply_msg);
    CU_ASSERT_EQUAL(ntohs(reply_msg->length), sizeof(struct pcep_header));
    CU_ASSERT_EQUAL(reply_msg->type, PCEP_TYPE_PCREP);
    CU_ASSERT_EQUAL(reply_msg->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);
    free(reply_msg);

    struct pcep_object_rp *rp_obj = pcep_obj_create_rp(0, 0, 0);
    struct pcep_object_nopath *nopath_obj = pcep_obj_create_nopath(0, 0, 0, 0);
    reply_msg = pcep_msg_create_reply_nopath(rp_obj, nopath_obj);

    CU_ASSERT_PTR_NOT_NULL(reply_msg);
    CU_ASSERT_EQUAL(ntohs(reply_msg->length),
            (sizeof(struct pcep_header) +
             sizeof(struct pcep_object_rp) +
             sizeof(struct pcep_object_nopath) +
             sizeof(uint32_t))); /* Add 4 for the TLV value */
    CU_ASSERT_EQUAL(reply_msg->type, PCEP_TYPE_PCREP);
    CU_ASSERT_EQUAL(reply_msg->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);
    free(reply_msg);
    free(rp_obj);
    free(nopath_obj);
}


void test_pcep_msg_create_reply()
{
    /* First test with NULL ero and rp objects */
    struct pcep_header* reply_msg = pcep_msg_create_reply(NULL, NULL);

    CU_ASSERT_PTR_NOT_NULL(reply_msg);
    CU_ASSERT_EQUAL(ntohs(reply_msg->length), sizeof(struct pcep_header));
    CU_ASSERT_EQUAL(reply_msg->type, PCEP_TYPE_PCREP);
    CU_ASSERT_EQUAL(reply_msg->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);
    free(reply_msg);

    double_linked_list *ero_subobj_list = dll_initialize();
    struct pcep_object_ro_subobj *ero_subobj = pcep_obj_create_ro_subobj_32label(1, 10);
    dll_append(ero_subobj_list, ero_subobj);
    struct pcep_object_ro *ero = pcep_obj_create_eroute_object(ero_subobj_list);

    double_linked_list *object_list = dll_initialize();
    dll_append(object_list, ero);
    struct pcep_object_rp *rp_obj = pcep_obj_create_rp(0, 0, 0);
    reply_msg = pcep_msg_create_reply(rp_obj, object_list);

    CU_ASSERT_PTR_NOT_NULL(reply_msg);
    CU_ASSERT_EQUAL(ntohs(reply_msg->length),
            sizeof(struct pcep_header) + sizeof(struct pcep_object_rp) +
            sizeof(struct pcep_object_ro) + sizeof(struct pcep_ro_subobj_32label));
    CU_ASSERT_EQUAL(reply_msg->type, PCEP_TYPE_PCREP);
    CU_ASSERT_EQUAL(reply_msg->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);
    dll_destroy_with_data(ero_subobj_list);
    dll_destroy_with_data(object_list);
    free(rp_obj);
    free(reply_msg);
}


void test_pcep_msg_create_close()
{
    uint8_t flags = 0xFF;
    uint8_t reason = PCEP_CLOSE_REASON_UNREC;

    struct pcep_header* close_msg = pcep_msg_create_close(flags, reason);
    struct pcep_object_close *close_obj =
            (struct pcep_object_close *) (((char *) close_msg) + sizeof(struct pcep_header));

    CU_ASSERT_PTR_NOT_NULL(close_msg);
    CU_ASSERT_EQUAL(ntohs(close_msg->length),
            sizeof(struct pcep_header) + sizeof(struct pcep_object_close));
    CU_ASSERT_EQUAL(close_msg->type, PCEP_TYPE_CLOSE);
    CU_ASSERT_EQUAL(close_msg->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);

    /* Just check the class and type, the rest of the hdr fields
     * are verified in pcep-objects-test.c */
    CU_ASSERT_EQUAL(close_obj->header.object_class, PCEP_OBJ_CLASS_CLOSE);
    CU_ASSERT_EQUAL(close_obj->header.object_type, PCEP_OBJ_TYPE_CLOSE);

    CU_ASSERT_EQUAL(close_obj->flags, flags);
    CU_ASSERT_EQUAL(close_obj->reason, reason);
    free(close_msg);
}


void test_pcep_msg_create_error()
{
    uint8_t error_type = PCEP_ERRT_RECEPTION_OF_INV_OBJECT;
    uint8_t error_value = PCEP_ERRV_KEEPALIVEWAIT_TIMED_OUT;

    struct pcep_header* error_msg = pcep_msg_create_error(error_type, error_value);
    struct pcep_object_error *error_obj =
            (struct pcep_object_error *) (((char *) error_msg) + sizeof(struct pcep_header));

    CU_ASSERT_PTR_NOT_NULL(error_msg);
    CU_ASSERT_EQUAL(ntohs(error_msg->length),
            sizeof(struct pcep_header) + sizeof(struct pcep_object_error));
    CU_ASSERT_EQUAL(error_msg->type, PCEP_TYPE_ERROR);
    CU_ASSERT_EQUAL(error_msg->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);

    /* Just check the class and type, the rest of the hdr fields
     * are verified in pcep-objects-test.c */
    CU_ASSERT_EQUAL(error_obj->header.object_class, PCEP_OBJ_CLASS_ERROR);
    CU_ASSERT_EQUAL(error_obj->header.object_type, PCEP_OBJ_TYPE_ERROR);

    CU_ASSERT_EQUAL(error_obj->error_type, error_type);
    CU_ASSERT_EQUAL(error_obj->error_value, error_value);
    free(error_msg);
}


void test_pcep_msg_create_keepalive()
{
    struct pcep_header* ka_msg = pcep_msg_create_keepalive();

    CU_ASSERT_PTR_NOT_NULL(ka_msg);
    CU_ASSERT_EQUAL(ntohs(ka_msg->length), sizeof(struct pcep_header));
    CU_ASSERT_EQUAL(ka_msg->type, PCEP_TYPE_KEEPALIVE);
    CU_ASSERT_EQUAL(ka_msg->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);
    free(ka_msg);
}

void test_pcep_msg_create_report()
{
    double_linked_list *obj_list = dll_initialize();
    double_linked_list *tlv_list = dll_initialize();

    struct pcep_header* report_msg = pcep_msg_create_report(NULL, NULL);
    CU_ASSERT_PTR_NULL(report_msg);

    report_msg = pcep_msg_create_report(NULL, tlv_list);
    CU_ASSERT_PTR_NULL(report_msg);

    /* Should return NULL if obj_list is empty */
    report_msg = pcep_msg_create_report(obj_list, tlv_list);
    CU_ASSERT_PTR_NULL(report_msg);

    struct pcep_object_lsp* lsp = pcep_obj_create_lsp(100, PCEP_LSP_OPERATIONAL_UP, true, true, true, true, true);
    dll_append(obj_list, lsp);
    report_msg = pcep_msg_create_report(obj_list, tlv_list);
    CU_ASSERT_PTR_NOT_NULL(report_msg);
    CU_ASSERT_EQUAL(ntohs(report_msg->length),
            sizeof(struct pcep_header) + ntohs(lsp->header.object_length));
    CU_ASSERT_EQUAL(report_msg->type, PCEP_TYPE_REPORT);
    CU_ASSERT_EQUAL(report_msg->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);
    free(report_msg);

    struct pcep_object_tlv *tlv =
            pcep_tlv_create_lsp_error_code(PCEP_TLV_LSP_ERROR_CODE_LSP_LIMIT_REACHED);
    dll_append(tlv_list, tlv);
    report_msg = pcep_msg_create_report(obj_list, tlv_list);
    CU_ASSERT_PTR_NOT_NULL(report_msg);
    CU_ASSERT_EQUAL(ntohs(report_msg->length),
            sizeof(struct pcep_header) +
            ntohs(lsp->header.object_length) +
            ntohs(tlv->header.length) + sizeof(struct pcep_object_tlv_header));
    CU_ASSERT_EQUAL(report_msg->type, PCEP_TYPE_REPORT);
    CU_ASSERT_EQUAL(report_msg->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);
    free(tlv);
    free(lsp);
    free(report_msg);
    dll_destroy(obj_list);
    dll_destroy(tlv_list);
}

void test_pcep_msg_create_update()
{
    double_linked_list *obj_list = dll_initialize();
    double_linked_list *ero_subobj_list = dll_initialize();

    struct pcep_header* update_msg = pcep_msg_create_update(NULL);
    CU_ASSERT_PTR_NULL(update_msg);

    /* Should return NULL if obj_list is empty */
    update_msg = pcep_msg_create_update(obj_list);
    CU_ASSERT_PTR_NULL(update_msg);

    struct pcep_object_srp* srp = pcep_obj_create_srp(false, 100);
    struct pcep_object_lsp* lsp = pcep_obj_create_lsp(100, PCEP_LSP_OPERATIONAL_UP, true, true, true, true, true);
    dll_append(ero_subobj_list, pcep_obj_create_ro_subobj_asn(0x0102));
    struct pcep_object_ro*  ero = pcep_obj_create_eroute_object(ero_subobj_list);

    /* Should return NULL if obj_list does not have 3 entries */
    dll_append(obj_list, srp);
    dll_append(obj_list, lsp);
    update_msg = pcep_msg_create_update(obj_list);
    CU_ASSERT_PTR_NULL(update_msg);

    dll_append(obj_list, ero);
    update_msg = pcep_msg_create_update(obj_list);
    CU_ASSERT_PTR_NOT_NULL(update_msg);
    CU_ASSERT_EQUAL(ntohs(update_msg->length),
            sizeof(struct pcep_header) +
            ntohs(srp->header.object_length) +
            ntohs(lsp->header.object_length) +
            ntohs(ero->header.object_length));
    CU_ASSERT_EQUAL(update_msg->type, PCEP_TYPE_UPDATE);
    CU_ASSERT_EQUAL(update_msg->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);

    dll_destroy_with_data(ero_subobj_list);
    dll_destroy_with_data(obj_list);
    free(update_msg);
}

void test_pcep_msg_create_initiate()
{
    double_linked_list *obj_list = dll_initialize();
    double_linked_list *tlv_list = dll_initialize();
    double_linked_list *ero_subobj_list = dll_initialize();

    struct pcep_header* initiate_msg = pcep_msg_create_initiate(NULL, NULL);
    CU_ASSERT_PTR_NULL(initiate_msg);

    initiate_msg = pcep_msg_create_initiate(NULL, tlv_list);
    CU_ASSERT_PTR_NULL(initiate_msg);

    /* Should return NULL if obj_list is empty */
    initiate_msg = pcep_msg_create_initiate(obj_list, tlv_list);
    CU_ASSERT_PTR_NULL(initiate_msg);

    struct pcep_object_srp* srp = pcep_obj_create_srp(false, 100);
    struct pcep_object_lsp* lsp = pcep_obj_create_lsp(100, PCEP_LSP_OPERATIONAL_UP, true, true, true, true, true);
    dll_append(ero_subobj_list, pcep_obj_create_ro_subobj_asn(0x0102));
    struct pcep_object_ro*  ero = pcep_obj_create_eroute_object(ero_subobj_list);

    /* Should return NULL if obj_list does not have 2 entries */
    dll_append(obj_list, srp);
    initiate_msg = pcep_msg_create_initiate(obj_list, tlv_list);
    CU_ASSERT_PTR_NULL(initiate_msg);

    dll_append(obj_list, lsp);
    dll_append(obj_list, ero);
    initiate_msg = pcep_msg_create_initiate(obj_list, tlv_list);
    CU_ASSERT_PTR_NOT_NULL(initiate_msg);
    CU_ASSERT_EQUAL(ntohs(initiate_msg->length),
            sizeof(struct pcep_header) +
            ntohs(srp->header.object_length) +
            ntohs(lsp->header.object_length) +
            ntohs(ero->header.object_length));
    CU_ASSERT_EQUAL(initiate_msg->type, PCEP_TYPE_INITIATE);
    CU_ASSERT_EQUAL(initiate_msg->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);

    dll_destroy_with_data(ero_subobj_list);
    dll_destroy_with_data(obj_list);
    dll_destroy(tlv_list);
    free(initiate_msg);
}

