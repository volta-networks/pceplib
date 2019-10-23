/*
 * pcep-messages-test.c
 *
 *  Created on: Oct 11, 2019
 *      Author: brady
 */

#include <stdlib.h>

#include <CUnit/CUnit.h>

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
    free(ipv4_obj);
    free(bandwidth_obj);
    free(request_msg);

}


void test_pcep_msg_create_request_svec()
{
}


void test_pcep_msg_create_response_nopath()
{
    /* First test with NULL nopath and rp objects */
    struct pcep_header* response_msg = pcep_msg_create_response_nopath(NULL, NULL);

    CU_ASSERT_PTR_NOT_NULL(response_msg);
    CU_ASSERT_EQUAL(ntohs(response_msg->length), sizeof(struct pcep_header));
    CU_ASSERT_EQUAL(response_msg->type, PCEP_TYPE_PCREP);
    CU_ASSERT_EQUAL(response_msg->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);
    free(response_msg);

    struct pcep_object_rp *rp_obj = pcep_obj_create_rp(0, 0, 0);
    struct pcep_object_nopath *nopath_obj = pcep_obj_create_nopath(0, 0, 0, 0);
    response_msg = pcep_msg_create_response_nopath(rp_obj, nopath_obj);

    CU_ASSERT_PTR_NOT_NULL(response_msg);
    CU_ASSERT_EQUAL(ntohs(response_msg->length),
            (sizeof(struct pcep_header) + sizeof(struct pcep_object_rp) + sizeof(struct pcep_object_nopath)));
    CU_ASSERT_EQUAL(response_msg->type, PCEP_TYPE_PCREP);
    CU_ASSERT_EQUAL(response_msg->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);
    free(response_msg);
    free(rp_obj);
    free(nopath_obj);
}


void test_pcep_msg_create_response()
{
    /* First test with NULL eros and rp objects */
    struct pcep_header* response_msg = pcep_msg_create_response(NULL, NULL);

    CU_ASSERT_PTR_NOT_NULL(response_msg);
    CU_ASSERT_EQUAL(ntohs(response_msg->length), sizeof(struct pcep_header));
    CU_ASSERT_EQUAL(response_msg->type, PCEP_TYPE_PCREP);
    CU_ASSERT_EQUAL(response_msg->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);
    free(response_msg);

    struct pcep_object_rp *rp_obj = pcep_obj_create_rp(0, 0, 0);
    double_linked_list *ero_subobj_list = dll_initialize();
    struct pcep_object_ro_subobj *ero_subobj = pcep_obj_create_ro_subobj_32label(1, 10);
    dll_append(ero_subobj_list, ero_subobj);
    struct pcep_object_route_object *eros = pcep_obj_create_eroute_object(ero_subobj_list);

    double_linked_list *eros_list = dll_initialize();
    dll_append(eros_list, eros);
    response_msg = pcep_msg_create_response(rp_obj, eros_list);

    CU_ASSERT_PTR_NOT_NULL(response_msg);
    CU_ASSERT_EQUAL(ntohs(response_msg->length),
            sizeof(struct pcep_header) + sizeof(struct pcep_object_rp) +
            sizeof(struct pcep_object_ro) + sizeof(struct pcep_ro_subobj_32label));
    CU_ASSERT_EQUAL(response_msg->type, PCEP_TYPE_PCREP);
    CU_ASSERT_EQUAL(response_msg->ver_flags, PCEP_COMMON_HEADER_VER_FLAGS);
    pcep_obj_free_ro(eros_list);
    free(response_msg);
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
