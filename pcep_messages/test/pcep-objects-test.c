/*
 * pcep-objects-test.c
 *
 *  Created on: Nov 6, 2019
 *      Author: brady
 */

#include <stdlib.h>

#include <CUnit/CUnit.h>

#include "pcep-encoding.h"
#include "pcep-objects.h"
#include "pcep-tools.h"

/*
 * Notice:
 * All of these object Unit Tests encode the created objects by explicitly calling
 * pcep_encode_object() thus testing the object creation and the object encoding.
 */

static struct pcep_versioning *versioning = NULL;
static uint8_t object_buf[2000];

void reset_objects_buffer()
{
    memset(object_buf, 0, 2000);
}

void pcep_objects_test_setup()
{
    versioning = create_default_pcep_versioning();
    reset_objects_buffer();
}

void pcep_objects_test_teardown()
{
    destroy_pcep_versioning(versioning);
}

void test_pcep_obj_create_open()
{
    uint8_t deadtimer = 60;
    uint8_t keepalive = 30;
    uint8_t sid = 1;

    struct pcep_object_open *open = pcep_obj_create_open(keepalive, deadtimer, sid, NULL);

    CU_ASSERT_PTR_NOT_NULL(open);
    pcep_encode_object(&open->header, versioning, object_buf);
    CU_ASSERT_EQUAL(open->header.object_class, PCEP_OBJ_CLASS_OPEN);
    CU_ASSERT_EQUAL(open->header.object_type, PCEP_OBJ_TYPE_OPEN);
    CU_ASSERT_FALSE(open->header.flag_i);
    CU_ASSERT_FALSE(open->header.flag_p);
    CU_ASSERT_EQUAL(open->header.encoded_object_length, pcep_object_get_length_by_hdr(&open->header));

    CU_ASSERT_EQUAL(open->open_deadtimer, deadtimer);
    CU_ASSERT_EQUAL(open->open_keepalive, keepalive);
    CU_ASSERT_EQUAL(open->open_sid, sid);
    CU_ASSERT_EQUAL(open->open_version, PCEP_OBJECT_OPEN_VERSION);

    pcep_obj_free_object((struct pcep_object_header *) open);
}

void test_pcep_obj_create_open_with_tlvs()
{
    uint8_t deadtimer = 60;
    uint8_t keepalive = 30;
    uint8_t sid = 1;
    double_linked_list *tlv_list = dll_initialize();

    struct pcep_object_tlv_stateful_pce_capability *tlv =
            pcep_tlv_create_stateful_pce_capability(true, true, true, true, true, true);
    dll_append(tlv_list, tlv);
    struct pcep_object_open *open = pcep_obj_create_open(keepalive, deadtimer, sid, tlv_list);

    CU_ASSERT_PTR_NOT_NULL(open);
    pcep_encode_object(&open->header, versioning, object_buf);
    CU_ASSERT_EQUAL(open->header.object_class, PCEP_OBJ_CLASS_OPEN);
    CU_ASSERT_EQUAL(open->header.object_type, PCEP_OBJ_TYPE_OPEN);
    CU_ASSERT_FALSE(open->header.flag_i);
    CU_ASSERT_FALSE(open->header.flag_p);
    CU_ASSERT_PTR_NOT_NULL(open->header.tlv_list);
    CU_ASSERT_EQUAL(open->header.tlv_list->num_entries, 1);

    CU_ASSERT_EQUAL(open->open_deadtimer, deadtimer);
    CU_ASSERT_EQUAL(open->open_keepalive, keepalive);
    CU_ASSERT_EQUAL(open->open_sid, sid);
    CU_ASSERT_EQUAL(open->open_version, PCEP_OBJECT_OPEN_VERSION);

    pcep_obj_free_object((struct pcep_object_header *) open);
}

void test_pcep_obj_create_rp()
{
    uint32_t reqid = 15;

    struct pcep_object_rp *rp = pcep_obj_create_rp(100, true, false, false, reqid, NULL);

    CU_ASSERT_PTR_NOT_NULL(rp);
    pcep_encode_object(&rp->header, versioning, object_buf);
    CU_ASSERT_EQUAL(rp->header.object_class, PCEP_OBJ_CLASS_RP);
    CU_ASSERT_EQUAL(rp->header.object_type, PCEP_OBJ_TYPE_RP);
    CU_ASSERT_FALSE(rp->header.flag_i);
    CU_ASSERT_FALSE(rp->header.flag_p);
    CU_ASSERT_EQUAL(rp->header.encoded_object_length, pcep_object_get_length_by_hdr(&rp->header));

    CU_ASSERT_TRUE(rp->flag_reoptimization);
    CU_ASSERT_FALSE(rp->flag_bidirectional);
    CU_ASSERT_FALSE(rp->flag_strict);
    CU_ASSERT_EQUAL(rp->request_id, reqid);

    pcep_obj_free_object((struct pcep_object_header *) rp);
}

void test_pcep_obj_create_nopath()
{
    uint8_t ni = 8;
    uint32_t errorcode = 42;

    struct pcep_object_nopath *nopath = pcep_obj_create_nopath(ni, true, errorcode);

    CU_ASSERT_PTR_NOT_NULL(nopath);
    pcep_encode_object(&nopath->header, versioning, object_buf);
    CU_ASSERT_EQUAL(nopath->header.object_class, PCEP_OBJ_CLASS_NOPATH);
    CU_ASSERT_EQUAL(nopath->header.object_type, PCEP_OBJ_TYPE_NOPATH);
    CU_ASSERT_FALSE(nopath->header.flag_i);
    CU_ASSERT_FALSE(nopath->header.flag_p);
    CU_ASSERT_EQUAL(nopath->header.encoded_object_length, pcep_object_get_length_by_hdr(&nopath->header));

    CU_ASSERT_EQUAL(nopath->ni, ni);
    CU_ASSERT_TRUE(nopath->flag_c);
    CU_ASSERT_PTR_NOT_NULL(nopath->header.tlv_list);
    struct pcep_object_tlv_nopath_vector *tlv =
            (struct pcep_object_tlv_nopath_vector *) nopath->header.tlv_list->head->data;
    CU_ASSERT_EQUAL(tlv->header.encoded_tlv_length, 4);
    CU_ASSERT_EQUAL(tlv->header.type, 1);
    CU_ASSERT_EQUAL(tlv->error_code, errorcode);

    pcep_obj_free_object((struct pcep_object_header *) nopath);
}

void test_pcep_obj_create_enpoint_ipv4()
{
    struct in_addr src_ipv4, dst_ipv4;
    inet_pton(AF_INET, "192.168.1.2", &src_ipv4);
    inet_pton(AF_INET, "172.168.1.2", &dst_ipv4);

    struct pcep_object_endpoints_ipv4 *ipv4 = pcep_obj_create_enpoint_ipv4(NULL, NULL);
    CU_ASSERT_PTR_NULL(ipv4);

    ipv4 = pcep_obj_create_enpoint_ipv4(&src_ipv4, NULL);
    CU_ASSERT_PTR_NULL(ipv4);

    ipv4 = pcep_obj_create_enpoint_ipv4(NULL, &dst_ipv4);
    CU_ASSERT_PTR_NULL(ipv4);

    ipv4 = pcep_obj_create_enpoint_ipv4(&src_ipv4, &dst_ipv4);
    CU_ASSERT_PTR_NOT_NULL(ipv4);
    pcep_encode_object(&ipv4->header, versioning, object_buf);
    CU_ASSERT_EQUAL(ipv4->header.object_class, PCEP_OBJ_CLASS_ENDPOINTS);
    CU_ASSERT_EQUAL(ipv4->header.object_type, PCEP_OBJ_TYPE_ENDPOINT_IPV4);
    CU_ASSERT_FALSE(ipv4->header.flag_i);
    CU_ASSERT_FALSE(ipv4->header.flag_p);
    CU_ASSERT_EQUAL(ipv4->header.encoded_object_length, pcep_object_get_length_by_hdr(&ipv4->header));
    CU_ASSERT_EQUAL(ipv4->src_ipv4.s_addr, src_ipv4.s_addr);
    CU_ASSERT_EQUAL(ipv4->dst_ipv4.s_addr, dst_ipv4.s_addr);

    pcep_obj_free_object((struct pcep_object_header *) ipv4);
}

void test_pcep_obj_create_enpoint_ipv6()
{
    struct in6_addr src_ipv6, dst_ipv6;
    inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", &src_ipv6);
    inet_pton(AF_INET6, "2001:db8::8a2e:370:8446", &dst_ipv6);

    struct pcep_object_endpoints_ipv6 *ipv6 = pcep_obj_create_enpoint_ipv6(NULL, NULL);
    CU_ASSERT_PTR_NULL(ipv6);

    ipv6 = pcep_obj_create_enpoint_ipv6(&src_ipv6, NULL);
    CU_ASSERT_PTR_NULL(ipv6);

    ipv6 = pcep_obj_create_enpoint_ipv6(NULL, &dst_ipv6);
    CU_ASSERT_PTR_NULL(ipv6);

    ipv6 = pcep_obj_create_enpoint_ipv6(&src_ipv6, &dst_ipv6);
    CU_ASSERT_PTR_NOT_NULL(ipv6);
    pcep_encode_object(&ipv6->header, versioning, object_buf);
    CU_ASSERT_EQUAL(ipv6->header.object_class, PCEP_OBJ_CLASS_ENDPOINTS);
    CU_ASSERT_EQUAL(ipv6->header.object_type, PCEP_OBJ_TYPE_ENDPOINT_IPV6);
    CU_ASSERT_FALSE(ipv6->header.flag_i);
    CU_ASSERT_FALSE(ipv6->header.flag_p);
    CU_ASSERT_EQUAL(ipv6->header.encoded_object_length, pcep_object_get_length_by_hdr(&ipv6->header));
    CU_ASSERT_EQUAL(ipv6->src_ipv6.__in6_u.__u6_addr32[0], src_ipv6.__in6_u.__u6_addr32[0]);
    CU_ASSERT_EQUAL(ipv6->src_ipv6.__in6_u.__u6_addr32[1], src_ipv6.__in6_u.__u6_addr32[1]);
    CU_ASSERT_EQUAL(ipv6->src_ipv6.__in6_u.__u6_addr32[2], src_ipv6.__in6_u.__u6_addr32[2]);
    CU_ASSERT_EQUAL(ipv6->src_ipv6.__in6_u.__u6_addr32[3], src_ipv6.__in6_u.__u6_addr32[3]);
    CU_ASSERT_EQUAL(ipv6->dst_ipv6.__in6_u.__u6_addr32[0], dst_ipv6.__in6_u.__u6_addr32[0]);
    CU_ASSERT_EQUAL(ipv6->dst_ipv6.__in6_u.__u6_addr32[1], dst_ipv6.__in6_u.__u6_addr32[1]);
    CU_ASSERT_EQUAL(ipv6->dst_ipv6.__in6_u.__u6_addr32[2], dst_ipv6.__in6_u.__u6_addr32[2]);
    CU_ASSERT_EQUAL(ipv6->dst_ipv6.__in6_u.__u6_addr32[3], dst_ipv6.__in6_u.__u6_addr32[3]);

    pcep_obj_free_object((struct pcep_object_header *) ipv6);
}

void test_pcep_obj_create_bandwidth()
{
    float bandwidth = 1.8;

    struct pcep_object_bandwidth *bw = pcep_obj_create_bandwidth(bandwidth);

    CU_ASSERT_PTR_NOT_NULL(bw);
    pcep_encode_object(&bw->header, versioning, object_buf);
    CU_ASSERT_EQUAL(bw->header.object_class, PCEP_OBJ_CLASS_BANDWIDTH);
    CU_ASSERT_EQUAL(bw->header.object_type, PCEP_OBJ_TYPE_BANDWIDTH_REQ);
    CU_ASSERT_FALSE(bw->header.flag_i);
    CU_ASSERT_FALSE(bw->header.flag_p);
    CU_ASSERT_EQUAL(bw->header.encoded_object_length, pcep_object_get_length_by_hdr(&bw->header));
    CU_ASSERT_EQUAL(bw->bandwidth, bandwidth);

    pcep_obj_free_object((struct pcep_object_header *) bw);
}

void test_pcep_obj_create_metric()
{
    uint8_t type = PCEP_METRIC_DISJOINTNESS;
    float value = 42.24;

    struct pcep_object_metric *metric = pcep_obj_create_metric(type, true, true, value);

    CU_ASSERT_PTR_NOT_NULL(metric);
    pcep_encode_object(&metric->header, versioning, object_buf);
    CU_ASSERT_EQUAL(metric->header.object_class, PCEP_OBJ_CLASS_METRIC);
    CU_ASSERT_EQUAL(metric->header.object_type, PCEP_OBJ_TYPE_METRIC);
    CU_ASSERT_FALSE(metric->header.flag_i);
    CU_ASSERT_FALSE(metric->header.flag_p);
    CU_ASSERT_EQUAL(metric->header.encoded_object_length, pcep_object_get_length_by_hdr(&metric->header));
    CU_ASSERT_TRUE(metric->flag_b);
    CU_ASSERT_TRUE(metric->flag_c);
    CU_ASSERT_EQUAL(metric->type, type);
    CU_ASSERT_EQUAL(metric->value, value);

    pcep_obj_free_object((struct pcep_object_header *) metric);
}

void test_pcep_obj_create_lspa()
{
    uint32_t exclude_any = 10;
    uint32_t include_any = 20;
    uint32_t include_all = 30;
    uint8_t prio = 0;
    uint8_t hold_prio = 10;

    struct pcep_object_lspa *lspa = pcep_obj_create_lspa(exclude_any, include_any, include_all, prio, hold_prio, true);

    CU_ASSERT_PTR_NOT_NULL(lspa);
    pcep_encode_object(&lspa->header, versioning, object_buf);
    CU_ASSERT_EQUAL(lspa->header.object_class, PCEP_OBJ_CLASS_LSPA);
    CU_ASSERT_EQUAL(lspa->header.object_type, PCEP_OBJ_TYPE_LSPA);
    CU_ASSERT_FALSE(lspa->header.flag_i);
    CU_ASSERT_FALSE(lspa->header.flag_p);
    CU_ASSERT_EQUAL(lspa->header.encoded_object_length, pcep_object_get_length_by_hdr(&lspa->header));
    CU_ASSERT_TRUE(lspa->flag_local_protection);
    CU_ASSERT_EQUAL(lspa->lspa_exclude_any, exclude_any);
    CU_ASSERT_EQUAL(lspa->lspa_include_any, include_any);
    CU_ASSERT_EQUAL(lspa->lspa_include_all, include_all);
    CU_ASSERT_EQUAL(lspa->setup_priority, prio);

    pcep_obj_free_object((struct pcep_object_header *) lspa);
}

void test_pcep_obj_create_svec()
{
    struct pcep_object_svec *svec = pcep_obj_create_svec(true, true, true, NULL);
    CU_ASSERT_PTR_NULL(svec);

    double_linked_list *id_list = dll_initialize();
    uint32_t *uint32_ptr = malloc(sizeof(uint32_t));
    *uint32_ptr = 10;
    dll_append(id_list, uint32_ptr);

    svec = pcep_obj_create_svec(true, true, true, id_list);
    CU_ASSERT_PTR_NOT_NULL(svec);
    pcep_encode_object(&svec->header, versioning, object_buf);
    CU_ASSERT_EQUAL(svec->header.object_class, PCEP_OBJ_CLASS_SVEC);
    CU_ASSERT_EQUAL(svec->header.object_type, PCEP_OBJ_TYPE_SVEC);
    CU_ASSERT_FALSE(svec->header.flag_i);
    CU_ASSERT_FALSE(svec->header.flag_p);
    CU_ASSERT_EQUAL(svec->header.encoded_object_length,
            OBJECT_HEADER_LENGTH + sizeof(uint32_t) * 2);
    CU_ASSERT_TRUE(svec->flag_link_diverse);
    CU_ASSERT_TRUE(svec->flag_node_diverse);
    CU_ASSERT_TRUE(svec->flag_srlg_diverse);
    double_linked_list_node *node = svec->request_id_list->head;
    uint32_t *svec_id = (uint32_t *) node->data;
    CU_ASSERT_EQUAL(*svec_id, *uint32_ptr);

    pcep_obj_free_object((struct pcep_object_header *) svec);
}

void test_pcep_obj_create_error()
{
    uint8_t error_type = PCEP_ERRT_SESSION_FAILURE;
    uint8_t error_value = PCEP_ERRV_RECVD_INVALID_OPEN_MSG;

    struct pcep_object_error *error = pcep_obj_create_error(error_type, error_value);

    CU_ASSERT_PTR_NOT_NULL(error);
    pcep_encode_object(&error->header, versioning, object_buf);
    CU_ASSERT_EQUAL(error->header.object_class, PCEP_OBJ_CLASS_ERROR);
    CU_ASSERT_EQUAL(error->header.object_type, PCEP_OBJ_TYPE_ERROR);
    CU_ASSERT_FALSE(error->header.flag_i);
    CU_ASSERT_FALSE(error->header.flag_p);
    CU_ASSERT_EQUAL(error->header.encoded_object_length, pcep_object_get_length_by_hdr(&error->header));
    CU_ASSERT_EQUAL(error->error_type, error_type);
    CU_ASSERT_EQUAL(error->error_value, error_value);

    pcep_obj_free_object((struct pcep_object_header *) error);
}

void test_pcep_obj_create_close()
{
    uint8_t reason = PCEP_CLOSE_REASON_DEADTIMER;

    struct pcep_object_close *close = pcep_obj_create_close(reason);

    CU_ASSERT_PTR_NOT_NULL(close);
    pcep_encode_object(&close->header, versioning, object_buf);
    CU_ASSERT_EQUAL(close->header.object_class, PCEP_OBJ_CLASS_CLOSE);
    CU_ASSERT_EQUAL(close->header.object_type, PCEP_OBJ_TYPE_CLOSE);
    CU_ASSERT_FALSE(close->header.flag_i);
    CU_ASSERT_FALSE(close->header.flag_p);
    CU_ASSERT_EQUAL(close->header.encoded_object_length, pcep_object_get_length_by_hdr(&close->header));
    CU_ASSERT_EQUAL(close->reason, reason);

    pcep_obj_free_object((struct pcep_object_header *) close);
}

void test_pcep_obj_create_srp()
{
    bool lsp_remove = true;
    uint32_t srp_id_number = 0x89674523;
    struct pcep_object_srp *srp = pcep_obj_create_srp(lsp_remove, srp_id_number, NULL);

    CU_ASSERT_PTR_NOT_NULL(srp);
    pcep_encode_object(&srp->header, versioning, object_buf);
    CU_ASSERT_EQUAL(srp->header.object_class, PCEP_OBJ_CLASS_SRP);
    CU_ASSERT_EQUAL(srp->header.object_type, PCEP_OBJ_TYPE_SRP);
    CU_ASSERT_FALSE(srp->header.flag_i);
    CU_ASSERT_FALSE(srp->header.flag_p);
    CU_ASSERT_EQUAL(srp->header.encoded_object_length, pcep_object_get_length_by_hdr(&srp->header));
    CU_ASSERT_EQUAL(srp->srp_id_number, srp_id_number);
    CU_ASSERT_EQUAL(srp->flag_lsp_remove, lsp_remove);

    pcep_obj_free_object((struct pcep_object_header *) srp);
}

void test_pcep_obj_create_lsp()
{
    uint32_t plsp_id = 0x000fffff;
    enum pcep_lsp_operational_status status = PCEP_LSP_OPERATIONAL_ACTIVE;
    bool c_flag = true;
    bool a_flag = true;
    bool r_flag = true;
    bool s_flag = true;
    bool d_flag = true;

    struct pcep_object_lsp *lsp =
            pcep_obj_create_lsp(0x001fffff, status, c_flag, a_flag, r_flag, s_flag, d_flag, NULL);
    CU_ASSERT_PTR_NULL(lsp);

    /* Should return for invalid status */
    lsp = pcep_obj_create_lsp(plsp_id, 8, c_flag, a_flag, r_flag, s_flag, d_flag, NULL);
    CU_ASSERT_PTR_NULL(lsp);

    lsp = pcep_obj_create_lsp(plsp_id, status, c_flag, a_flag, r_flag, s_flag, d_flag, NULL);

    CU_ASSERT_PTR_NOT_NULL(lsp);
    pcep_encode_object(&lsp->header, versioning, object_buf);
    CU_ASSERT_EQUAL(lsp->header.object_class, PCEP_OBJ_CLASS_LSP);
    CU_ASSERT_EQUAL(lsp->header.object_type, PCEP_OBJ_TYPE_LSP);
    CU_ASSERT_FALSE(lsp->header.flag_i);
    CU_ASSERT_FALSE(lsp->header.flag_p);
    CU_ASSERT_EQUAL(lsp->header.encoded_object_length, pcep_object_get_length_by_hdr(&lsp->header));
    CU_ASSERT_EQUAL(lsp->plsp_id, plsp_id);
    CU_ASSERT_TRUE(lsp->flag_a);
    CU_ASSERT_TRUE(lsp->flag_c);
    CU_ASSERT_TRUE(lsp->flag_r);
    CU_ASSERT_TRUE(lsp->flag_s);
    CU_ASSERT_TRUE(lsp->flag_d);
    CU_ASSERT_EQUAL(lsp->operational_status, PCEP_LSP_OPERATIONAL_ACTIVE);

    pcep_obj_free_object((struct pcep_object_header *) lsp);
}

/* Internal test function. The only difference between pcep_obj_create_ero(),
 * pcep_obj_create_iro(), and pcep_obj_create_rro() is the object_class
 * and the object_type.
 */
typedef struct pcep_object_ro* (*ro_func)(double_linked_list*);
static void test_pcep_obj_create_object_common(ro_func func_to_test, uint8_t object_class, uint8_t object_type)
{
    double_linked_list *ero_list = dll_initialize();

    struct pcep_object_ro *ero = func_to_test(NULL);
    CU_ASSERT_PTR_NOT_NULL(ero);
    pcep_encode_object(&ero->header, versioning, object_buf);
    CU_ASSERT_EQUAL(ero->header.object_class, object_class);
    CU_ASSERT_EQUAL(ero->header.object_type, object_type);
    CU_ASSERT_FALSE(ero->header.flag_i);
    CU_ASSERT_FALSE(ero->header.flag_p);
    pcep_obj_free_object((struct pcep_object_header *) ero);

    ero = func_to_test(ero_list);
    CU_ASSERT_PTR_NOT_NULL(ero);
    pcep_encode_object(&ero->header, versioning, object_buf);
    CU_ASSERT_EQUAL(ero->header.object_class, object_class);
    CU_ASSERT_EQUAL(ero->header.object_type, object_type);
    CU_ASSERT_FALSE(ero->header.flag_i);
    CU_ASSERT_FALSE(ero->header.flag_p);
    pcep_obj_free_object((struct pcep_object_header *) ero);

    reset_objects_buffer();
    struct pcep_ro_subobj_32label *ro_subobj = pcep_obj_create_ro_subobj_32label(false, 0, 101);
    ero_list = dll_initialize();
    dll_append(ero_list, ro_subobj);
    ero = func_to_test(ero_list);
    CU_ASSERT_PTR_NOT_NULL(ero);
    pcep_encode_object(&ero->header, versioning, object_buf);
    CU_ASSERT_EQUAL(ero->header.object_class, object_class);
    CU_ASSERT_EQUAL(ero->header.object_type, object_type);
    CU_ASSERT_FALSE(ero->header.flag_i);
    CU_ASSERT_FALSE(ero->header.flag_p);
    pcep_obj_free_object((struct pcep_object_header *) ero);
}

void test_pcep_obj_create_ero()
{
    test_pcep_obj_create_object_common(
            pcep_obj_create_ero, PCEP_OBJ_CLASS_ERO, PCEP_OBJ_TYPE_ERO);
}

void test_pcep_obj_create_rro()
{
    test_pcep_obj_create_object_common(
            pcep_obj_create_rro, PCEP_OBJ_CLASS_RRO, PCEP_OBJ_TYPE_RRO);
}

void test_pcep_obj_create_iro()
{
    test_pcep_obj_create_object_common(
            pcep_obj_create_iro, PCEP_OBJ_CLASS_IRO, PCEP_OBJ_TYPE_IRO);
}

/* Internal util function to wrap an RO Subobj in a RO and encode it */
static struct pcep_object_ro *encode_ro_subobj(struct pcep_object_ro_subobj *sr)
{
    double_linked_list *sr_subobj_list = dll_initialize();
    dll_append(sr_subobj_list, sr);
    struct pcep_object_ro *ro = pcep_obj_create_ero(sr_subobj_list);
    pcep_encode_object(&ro->header, versioning, object_buf);

    return ro;
}

void test_pcep_obj_create_ro_subobj_ipv4()
{
    struct in_addr ro_ipv4;
    inet_pton(AF_INET, "192.168.1.2", &ro_ipv4);
    uint8_t prefix_len = 8;

    struct pcep_ro_subobj_ipv4 *ipv4 = pcep_obj_create_ro_subobj_ipv4(true, NULL, prefix_len, false);
    CU_ASSERT_PTR_NULL(ipv4);

    ipv4 = pcep_obj_create_ro_subobj_ipv4(false, &ro_ipv4, prefix_len, false);
    CU_ASSERT_PTR_NOT_NULL(ipv4);
    struct pcep_object_ro *ro = encode_ro_subobj(&ipv4->ro_subobj);
    CU_ASSERT_EQUAL(ipv4->ro_subobj.ro_subobj_type, RO_SUBOBJ_TYPE_IPV4);
    CU_ASSERT_FALSE(ipv4->ro_subobj.flag_subobj_loose_hop);
    CU_ASSERT_EQUAL(ipv4->prefix_length, prefix_len);
    CU_ASSERT_EQUAL(ipv4->ip_addr.s_addr, ro_ipv4.s_addr);
    pcep_obj_free_object((struct pcep_object_header *) ro);

    reset_objects_buffer();
    ipv4 = pcep_obj_create_ro_subobj_ipv4(true, &ro_ipv4, prefix_len, false);
    CU_ASSERT_PTR_NOT_NULL(ipv4);
    ro = encode_ro_subobj(&ipv4->ro_subobj);
    CU_ASSERT_EQUAL(ipv4->ro_subobj.ro_subobj_type, RO_SUBOBJ_TYPE_IPV4);
    CU_ASSERT_TRUE(ipv4->ro_subobj.flag_subobj_loose_hop);
    CU_ASSERT_EQUAL(ipv4->prefix_length, prefix_len);
    CU_ASSERT_EQUAL(ipv4->ip_addr.s_addr, ro_ipv4.s_addr);
    pcep_obj_free_object((struct pcep_object_header *) ro);
}

void test_pcep_obj_create_ro_subobj_ipv6()
{
    struct in6_addr ro_ipv6;
    uint8_t prefix_len = 16;

    struct pcep_ro_subobj_ipv6 *ipv6 = pcep_obj_create_ro_subobj_ipv6(true, NULL, prefix_len, true);
    CU_ASSERT_PTR_NULL(ipv6);

    inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", &ro_ipv6);
    ipv6 = pcep_obj_create_ro_subobj_ipv6(false, &ro_ipv6, prefix_len, false);
    CU_ASSERT_PTR_NOT_NULL(ipv6);
    struct pcep_object_ro *ro = encode_ro_subobj(&ipv6->ro_subobj);
    CU_ASSERT_EQUAL(ipv6->ro_subobj.ro_subobj_type, RO_SUBOBJ_TYPE_IPV6);
    CU_ASSERT_FALSE(ipv6->ro_subobj.flag_subobj_loose_hop);
    CU_ASSERT_EQUAL(ipv6->prefix_length, prefix_len);
    CU_ASSERT_EQUAL(ipv6->ip_addr.__in6_u.__u6_addr32[0], ro_ipv6.__in6_u.__u6_addr32[0]);
    CU_ASSERT_EQUAL(ipv6->ip_addr.__in6_u.__u6_addr32[1], ro_ipv6.__in6_u.__u6_addr32[1]);
    CU_ASSERT_EQUAL(ipv6->ip_addr.__in6_u.__u6_addr32[2], ro_ipv6.__in6_u.__u6_addr32[2]);
    CU_ASSERT_EQUAL(ipv6->ip_addr.__in6_u.__u6_addr32[3], ro_ipv6.__in6_u.__u6_addr32[3]);
    pcep_obj_free_object((struct pcep_object_header *) ro);

    reset_objects_buffer();
    ipv6 = pcep_obj_create_ro_subobj_ipv6(true, &ro_ipv6, prefix_len, false);
    CU_ASSERT_PTR_NOT_NULL(ipv6);
    ro = encode_ro_subobj(&ipv6->ro_subobj);
    CU_ASSERT_EQUAL(ipv6->ro_subobj.ro_subobj_type, RO_SUBOBJ_TYPE_IPV6);
    CU_ASSERT_TRUE(ipv6->ro_subobj.flag_subobj_loose_hop);
    CU_ASSERT_EQUAL(ipv6->prefix_length, prefix_len);
    CU_ASSERT_EQUAL(ipv6->ip_addr.__in6_u.__u6_addr32[0], ro_ipv6.__in6_u.__u6_addr32[0]);
    CU_ASSERT_EQUAL(ipv6->ip_addr.__in6_u.__u6_addr32[1], ro_ipv6.__in6_u.__u6_addr32[1]);
    CU_ASSERT_EQUAL(ipv6->ip_addr.__in6_u.__u6_addr32[2], ro_ipv6.__in6_u.__u6_addr32[2]);
    CU_ASSERT_EQUAL(ipv6->ip_addr.__in6_u.__u6_addr32[3], ro_ipv6.__in6_u.__u6_addr32[3]);
    pcep_obj_free_object((struct pcep_object_header *) ro);
}

void test_pcep_obj_create_ro_subobj_unnum()
{
    struct in_addr router_id;
    uint32_t if_id = 123;

    struct pcep_ro_subobj_unnum *unnum = pcep_obj_create_ro_subobj_unnum(NULL, if_id);
    CU_ASSERT_PTR_NULL(unnum);

    inet_pton(AF_INET, "192.168.1.2", &router_id);
    unnum = pcep_obj_create_ro_subobj_unnum(&router_id, if_id);
    CU_ASSERT_PTR_NOT_NULL(unnum);
    struct pcep_object_ro *ro = encode_ro_subobj(&unnum->ro_subobj);
    CU_ASSERT_EQUAL(unnum->ro_subobj.ro_subobj_type, RO_SUBOBJ_TYPE_UNNUM);
    CU_ASSERT_EQUAL(unnum->interface_id, if_id);
    CU_ASSERT_EQUAL(unnum->router_id.s_addr, router_id.s_addr);

    pcep_obj_free_object((struct pcep_object_header *) ro);
}

void test_pcep_obj_create_ro_subobj_32label()
{
    uint8_t class_type = 1;
    uint32_t label = 0xeeffaabb;

    struct pcep_ro_subobj_32label *label32 = pcep_obj_create_ro_subobj_32label(true, class_type, label);
    CU_ASSERT_PTR_NOT_NULL(label32);
    struct pcep_object_ro *ro = encode_ro_subobj(&label32->ro_subobj);
    CU_ASSERT_EQUAL(label32->ro_subobj.ro_subobj_type, RO_SUBOBJ_TYPE_LABEL);
    CU_ASSERT_EQUAL(label32->label, label);
    CU_ASSERT_EQUAL(label32->class_type, class_type);
    CU_ASSERT_TRUE(label32->flag_global_label);

    pcep_obj_free_object((struct pcep_object_header *) ro);
}

void test_pcep_obj_create_ro_subobj_asn()
{
    uint16_t asn = 0x0102;

    struct pcep_ro_subobj_asn *asn_obj = pcep_obj_create_ro_subobj_asn(asn);
    CU_ASSERT_PTR_NOT_NULL(asn_obj);
    struct pcep_object_ro *ro = encode_ro_subobj(&asn_obj->ro_subobj);
    CU_ASSERT_EQUAL(asn_obj->ro_subobj.ro_subobj_type, RO_SUBOBJ_TYPE_ASN);
    CU_ASSERT_EQUAL(asn_obj->asn, asn);

    pcep_obj_free_object((struct pcep_object_header *) ro);
}

void test_pcep_obj_create_ro_subobj_sr_nonai()
{
    uint32_t sid = 0x01020304;

    struct pcep_ro_subobj_sr *sr = pcep_obj_create_ro_subobj_sr_nonai(false, sid);
    CU_ASSERT_PTR_NOT_NULL(sr);
    struct pcep_object_ro *ro = encode_ro_subobj(&sr->ro_subobj);
    CU_ASSERT_EQUAL(sr->ro_subobj.ro_subobj_type, RO_SUBOBJ_TYPE_SR);
    CU_ASSERT_FALSE(sr->ro_subobj.flag_subobj_loose_hop);
    CU_ASSERT_FALSE(sr->flag_s);
    CU_ASSERT_TRUE(sr->flag_f);
    CU_ASSERT_FALSE(sr->flag_c);
    CU_ASSERT_FALSE(sr->flag_m);
    pcep_obj_free_object((struct pcep_object_header *) ro);

    reset_objects_buffer();
    sr = pcep_obj_create_ro_subobj_sr_nonai(true, sid);
    CU_ASSERT_PTR_NOT_NULL(sr);
    ro = encode_ro_subobj(&sr->ro_subobj);
    CU_ASSERT_EQUAL(sr->ro_subobj.ro_subobj_type, RO_SUBOBJ_TYPE_SR);
    CU_ASSERT_TRUE(sr->ro_subobj.flag_subobj_loose_hop);
    CU_ASSERT_FALSE(sr->flag_s);
    CU_ASSERT_TRUE(sr->flag_f);
    CU_ASSERT_FALSE(sr->flag_c);
    CU_ASSERT_FALSE(sr->flag_m);
    pcep_obj_free_object((struct pcep_object_header *) ro);
}

void test_pcep_obj_create_ro_subobj_sr_ipv4_node()
{
    uint32_t sid = 0x01020304;
    struct in_addr *ipv4_node_id = malloc(sizeof(struct in_addr));
    inet_pton(AF_INET, "192.168.1.2", ipv4_node_id);

    /* (loose_hop, sid_absent, c_flag, m_flag, sid, ipv4_node_id) */
    struct pcep_ro_subobj_sr *sr =
            pcep_obj_create_ro_subobj_sr_ipv4_node(true, false, true, true, sid, NULL);
    CU_ASSERT_PTR_NULL(sr);

    /* Test the sid is absent */
    sr = pcep_obj_create_ro_subobj_sr_ipv4_node(true, true, false, false, sid, ipv4_node_id);
    CU_ASSERT_PTR_NOT_NULL(sr);
    struct pcep_object_ro *ro = encode_ro_subobj(&sr->ro_subobj);
    CU_ASSERT_EQUAL(sr->ro_subobj.ro_subobj_type, RO_SUBOBJ_TYPE_SR);
    CU_ASSERT_TRUE(sr->ro_subobj.flag_subobj_loose_hop);
    CU_ASSERT_EQUAL(sr->nai_type, PCEP_SR_SUBOBJ_NAI_IPV4_NODE);
    CU_ASSERT_TRUE(sr->flag_s);
    CU_ASSERT_FALSE(sr->flag_m);
    CU_ASSERT_FALSE(sr->flag_c);
    CU_ASSERT_FALSE(sr->flag_f);
    CU_ASSERT_EQUAL(sr->sid, 0);
    CU_ASSERT_EQUAL(((struct in_addr *) sr->nai_list->head->data)->s_addr, ipv4_node_id->s_addr);
    pcep_obj_free_object((struct pcep_object_header *) ro);

    /* Test the sid is present */
    reset_objects_buffer();
    ipv4_node_id = malloc(sizeof(struct in_addr));
    inet_pton(AF_INET, "192.168.1.2", ipv4_node_id);
    sr = pcep_obj_create_ro_subobj_sr_ipv4_node(false, false, true, true, sid, ipv4_node_id);
    CU_ASSERT_PTR_NOT_NULL(sr);
    ro = encode_ro_subobj(&sr->ro_subobj);
    CU_ASSERT_EQUAL(sr->ro_subobj.ro_subobj_type, RO_SUBOBJ_TYPE_SR);
    CU_ASSERT_FALSE(sr->ro_subobj.flag_subobj_loose_hop);
    CU_ASSERT_EQUAL(sr->nai_type, PCEP_SR_SUBOBJ_NAI_IPV4_NODE);
    CU_ASSERT_TRUE(sr->flag_c);
    CU_ASSERT_TRUE(sr->flag_m);
    CU_ASSERT_FALSE(sr->flag_s);
    CU_ASSERT_FALSE(sr->flag_f);
    CU_ASSERT_EQUAL(sr->sid, sid);
    CU_ASSERT_EQUAL(((struct in_addr *) sr->nai_list->head->data)->s_addr, ipv4_node_id->s_addr);
    pcep_obj_free_object((struct pcep_object_header *) ro);
}

void test_pcep_obj_create_ro_subobj_sr_ipv6_node()
{
    uint32_t sid = 0x01020304;
    struct in6_addr *ipv6_node_id = malloc(sizeof(struct in6_addr));
    inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", ipv6_node_id);

    /* (loose_hop, sid_absent, c_flag, m_flag, sid, ipv6_node_id) */
    struct pcep_ro_subobj_sr *sr = pcep_obj_create_ro_subobj_sr_ipv6_node(false, true, true, true, sid, NULL);
    CU_ASSERT_PTR_NULL(sr);

    /* Test the sid is absent */
    sr = pcep_obj_create_ro_subobj_sr_ipv6_node(true, true, true, true, sid, ipv6_node_id);
    CU_ASSERT_PTR_NOT_NULL(sr);
    struct pcep_object_ro *ro = encode_ro_subobj(&sr->ro_subobj);
    CU_ASSERT_EQUAL(sr->ro_subobj.ro_subobj_type, RO_SUBOBJ_TYPE_SR);
    CU_ASSERT_TRUE(sr->ro_subobj.flag_subobj_loose_hop);
    CU_ASSERT_EQUAL(sr->nai_type, PCEP_SR_SUBOBJ_NAI_IPV6_NODE);
    CU_ASSERT_TRUE(sr->flag_s);
    CU_ASSERT_FALSE(sr->flag_c);
    CU_ASSERT_FALSE(sr->flag_m);
    CU_ASSERT_FALSE(sr->flag_f);
    uint32_t *uint32_ptr = (uint32_t *) sr->nai_list->head->data;
    CU_ASSERT_EQUAL(uint32_ptr[0], ipv6_node_id->__in6_u.__u6_addr32[0]);
    CU_ASSERT_EQUAL(uint32_ptr[1], ipv6_node_id->__in6_u.__u6_addr32[1]);
    CU_ASSERT_EQUAL(uint32_ptr[2], ipv6_node_id->__in6_u.__u6_addr32[2]);
    CU_ASSERT_EQUAL(uint32_ptr[3], ipv6_node_id->__in6_u.__u6_addr32[3]);
    pcep_obj_free_object((struct pcep_object_header *) ro);

    /* Test the sid is present */
    reset_objects_buffer();
    ipv6_node_id = malloc(sizeof(struct in6_addr));
    inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", ipv6_node_id);
    sr = pcep_obj_create_ro_subobj_sr_ipv6_node(false, false, true, true, sid, ipv6_node_id);
    CU_ASSERT_PTR_NOT_NULL(sr);
    ro = encode_ro_subobj(&sr->ro_subobj);
    CU_ASSERT_EQUAL(sr->ro_subobj.ro_subobj_type, RO_SUBOBJ_TYPE_SR);
    CU_ASSERT_FALSE(sr->ro_subobj.flag_subobj_loose_hop);
    CU_ASSERT_EQUAL(sr->nai_type, PCEP_SR_SUBOBJ_NAI_IPV6_NODE);
    CU_ASSERT_TRUE(sr->flag_m);
    CU_ASSERT_TRUE(sr->flag_c);
    CU_ASSERT_FALSE(sr->flag_s);
    CU_ASSERT_FALSE(sr->flag_f);
    CU_ASSERT_EQUAL(sr->sid, sid);
    uint32_ptr = (uint32_t *) sr->nai_list->head->data;
    CU_ASSERT_EQUAL(uint32_ptr[0], ipv6_node_id->__in6_u.__u6_addr32[0]);
    CU_ASSERT_EQUAL(uint32_ptr[1], ipv6_node_id->__in6_u.__u6_addr32[1]);
    CU_ASSERT_EQUAL(uint32_ptr[2], ipv6_node_id->__in6_u.__u6_addr32[2]);
    CU_ASSERT_EQUAL(uint32_ptr[3], ipv6_node_id->__in6_u.__u6_addr32[3]);
    pcep_obj_free_object((struct pcep_object_header *) ro);
}

void test_pcep_obj_create_ro_subobj_sr_ipv4_adj()
{
    struct in_addr *local_ipv4 = malloc(sizeof(struct in_addr));
    struct in_addr *remote_ipv4 = malloc(sizeof(struct in_addr));
    inet_pton(AF_INET, "192.168.1.2", local_ipv4);
    inet_pton(AF_INET, "172.168.1.2", remote_ipv4);

    uint32_t sid = ENCODE_SR_ERO_SID(3, 7, 0, 188);
    CU_ASSERT_EQUAL(sid, 16060);

    /* (loose_hop, sid_absent, c_flag, m_flag, sid, local_ipv4, remote_ipv4) */
    struct pcep_ro_subobj_sr *sr =
            pcep_obj_create_ro_subobj_sr_ipv4_adj(false, true, true, true, sid, NULL, NULL);
    CU_ASSERT_PTR_NULL(sr);

    sr = pcep_obj_create_ro_subobj_sr_ipv4_adj(false, true, true, true, sid, local_ipv4, NULL);
    CU_ASSERT_PTR_NULL(sr);

    sr = pcep_obj_create_ro_subobj_sr_ipv4_adj(false, true, true, true, sid, NULL, remote_ipv4);
    CU_ASSERT_PTR_NULL(sr);

    /* Test the sid is absent */
    sr = pcep_obj_create_ro_subobj_sr_ipv4_adj(true, true, true, true, sid, local_ipv4, remote_ipv4);
    CU_ASSERT_PTR_NOT_NULL(sr);
    struct pcep_object_ro *ro = encode_ro_subobj(&sr->ro_subobj);
    CU_ASSERT_EQUAL(sr->ro_subobj.ro_subobj_type, RO_SUBOBJ_TYPE_SR);
    CU_ASSERT_TRUE(sr->ro_subobj.flag_subobj_loose_hop);
    CU_ASSERT_EQUAL(sr->nai_type, PCEP_SR_SUBOBJ_NAI_IPV4_ADJACENCY);
    CU_ASSERT_TRUE(sr->flag_s);
    CU_ASSERT_FALSE(sr->flag_m);
    CU_ASSERT_FALSE(sr->flag_c);
    CU_ASSERT_FALSE(sr->flag_f);
    CU_ASSERT_EQUAL(sr->sid, 0);
    double_linked_list_node *node = sr->nai_list->head;
    struct in_addr *ip_ptr = (struct in_addr *) node->data;
    CU_ASSERT_EQUAL(ip_ptr->s_addr, local_ipv4->s_addr);

    node = node->next_node;
    ip_ptr = (struct in_addr *) node->data;
    CU_ASSERT_EQUAL(ip_ptr->s_addr, remote_ipv4->s_addr);
    pcep_obj_free_object((struct pcep_object_header *) ro);

    /* Test the sid is present */
    local_ipv4 = malloc(sizeof(struct in_addr));
    remote_ipv4 = malloc(sizeof(struct in_addr));
    inet_pton(AF_INET, "192.168.1.2", local_ipv4);
    inet_pton(AF_INET, "172.168.1.2", remote_ipv4);
    reset_objects_buffer();
    sr = pcep_obj_create_ro_subobj_sr_ipv4_adj(false, false, true, true, sid, local_ipv4, remote_ipv4);
    CU_ASSERT_PTR_NOT_NULL(sr);
    ro = encode_ro_subobj(&sr->ro_subobj);
    CU_ASSERT_EQUAL(sr->ro_subobj.ro_subobj_type, RO_SUBOBJ_TYPE_SR);
    CU_ASSERT_FALSE(sr->ro_subobj.flag_subobj_loose_hop);
    CU_ASSERT_EQUAL(sr->nai_type, PCEP_SR_SUBOBJ_NAI_IPV4_ADJACENCY);
    CU_ASSERT_TRUE(sr->flag_c);
    CU_ASSERT_TRUE(sr->flag_m);
    CU_ASSERT_FALSE(sr->flag_s);
    CU_ASSERT_FALSE(sr->flag_f);
    CU_ASSERT_EQUAL(sr->sid, sid);
    node = sr->nai_list->head;
    ip_ptr = (struct in_addr *) node->data;
    CU_ASSERT_EQUAL(ip_ptr->s_addr, local_ipv4->s_addr);

    node = node->next_node;
    ip_ptr = (struct in_addr *) node->data;
    CU_ASSERT_EQUAL(ip_ptr->s_addr, remote_ipv4->s_addr);

    pcep_obj_free_object((struct pcep_object_header *) ro);
}

void test_pcep_obj_create_ro_subobj_sr_ipv6_adj()
{
    uint32_t sid = 0x01020304;
    struct in6_addr *local_ipv6 = malloc(sizeof(struct in6_addr));
    struct in6_addr *remote_ipv6 = malloc(sizeof(struct in6_addr));
    inet_pton(AF_INET6, "2001:db8::8a2e:370:8221", local_ipv6);
    inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", remote_ipv6);

    /* (loose_hop, sid_absent, c_flag, m_flag, sid, local_ipv6, remote_ipv6) */
    struct pcep_ro_subobj_sr *sr = pcep_obj_create_ro_subobj_sr_ipv6_adj(false, true, true, true, sid, NULL, NULL);
    CU_ASSERT_PTR_NULL(sr);

    sr = pcep_obj_create_ro_subobj_sr_ipv6_adj(false, true, true, true, sid, local_ipv6, NULL);
    CU_ASSERT_PTR_NULL(sr);

    sr = pcep_obj_create_ro_subobj_sr_ipv6_adj(false, true, true, true, sid, NULL, remote_ipv6);
    CU_ASSERT_PTR_NULL(sr);

    /* Test the sid is absent */
    sr = pcep_obj_create_ro_subobj_sr_ipv6_adj(true, true, true, true, sid, local_ipv6, remote_ipv6);
    CU_ASSERT_PTR_NOT_NULL(sr);
    struct pcep_object_ro *ro = encode_ro_subobj(&sr->ro_subobj);
    CU_ASSERT_EQUAL(sr->ro_subobj.ro_subobj_type, RO_SUBOBJ_TYPE_SR);
    CU_ASSERT_TRUE(sr->ro_subobj.flag_subobj_loose_hop);
    CU_ASSERT_EQUAL(sr->nai_type, PCEP_SR_SUBOBJ_NAI_IPV6_ADJACENCY);
    CU_ASSERT_TRUE(sr->flag_s);
    CU_ASSERT_FALSE(sr->flag_m);
    CU_ASSERT_FALSE(sr->flag_c);
    CU_ASSERT_FALSE(sr->flag_f);
    CU_ASSERT_EQUAL(sr->sid, 0);
    double_linked_list_node *node = sr->nai_list->head;
    struct in6_addr *ip6_ptr = (struct in6_addr *) node->data;
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[0], local_ipv6->__in6_u.__u6_addr32[0]);
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[1], local_ipv6->__in6_u.__u6_addr32[1]);
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[2], local_ipv6->__in6_u.__u6_addr32[2]);
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[3], local_ipv6->__in6_u.__u6_addr32[3]);

    node = node->next_node;
    ip6_ptr = (struct in6_addr *) node->data;
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[0], remote_ipv6->__in6_u.__u6_addr32[0]);
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[1], remote_ipv6->__in6_u.__u6_addr32[1]);
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[2], remote_ipv6->__in6_u.__u6_addr32[2]);
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[3], remote_ipv6->__in6_u.__u6_addr32[3]);
    pcep_obj_free_object((struct pcep_object_header *) ro);

    /* Test the sid is present */
    local_ipv6 = malloc(sizeof(struct in6_addr));
    remote_ipv6 = malloc(sizeof(struct in6_addr));
    inet_pton(AF_INET6, "2001:db8::8a2e:370:8221", local_ipv6);
    inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", remote_ipv6);
    reset_objects_buffer();
    sr = pcep_obj_create_ro_subobj_sr_ipv6_adj(false, false, true, false, sid, local_ipv6, remote_ipv6);
    CU_ASSERT_PTR_NOT_NULL(sr);
    ro = encode_ro_subobj(&sr->ro_subobj);
    CU_ASSERT_EQUAL(sr->ro_subobj.ro_subobj_type, RO_SUBOBJ_TYPE_SR);
    CU_ASSERT_FALSE(sr->ro_subobj.flag_subobj_loose_hop);
    CU_ASSERT_EQUAL(sr->nai_type, PCEP_SR_SUBOBJ_NAI_IPV6_ADJACENCY);
    CU_ASSERT_FALSE(sr->flag_s);
    CU_ASSERT_FALSE(sr->flag_m);
    CU_ASSERT_FALSE(sr->flag_c);
    CU_ASSERT_FALSE(sr->flag_f);
    CU_ASSERT_EQUAL(sr->sid, sid);
    node = sr->nai_list->head;
    ip6_ptr = (struct in6_addr *) node->data;
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[0], local_ipv6->__in6_u.__u6_addr32[0]);
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[1], local_ipv6->__in6_u.__u6_addr32[1]);
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[2], local_ipv6->__in6_u.__u6_addr32[2]);
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[3], local_ipv6->__in6_u.__u6_addr32[3]);

    node = node->next_node;
    ip6_ptr = (struct in6_addr *) node->data;
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[0], remote_ipv6->__in6_u.__u6_addr32[0]);
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[1], remote_ipv6->__in6_u.__u6_addr32[1]);
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[2], remote_ipv6->__in6_u.__u6_addr32[2]);
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[3], remote_ipv6->__in6_u.__u6_addr32[3]);
    pcep_obj_free_object((struct pcep_object_header *) ro);
}

void test_pcep_obj_create_ro_subobj_sr_unnumbered_ipv4_adj()
{
    uint32_t sid = 0x01020304;
    uint32_t local_node_id  = 0x11223344;
    uint32_t local_if_id    = 0x55667788;
    uint32_t remote_node_id = 0x99aabbcc;
    uint32_t remote_if_id   = 0xddeeff11;

    /* (loose_hop, sid_absent, c_flag, m_flag,
        sid, local_node_id, local_if_id, remote_node_id, remote_if_id) */

    /* Test the sid is absent */
    struct pcep_ro_subobj_sr *sr = pcep_obj_create_ro_subobj_sr_unnumbered_ipv4_adj(
            true, true, true, true, sid,
            local_node_id, local_if_id, remote_node_id, remote_if_id);
    CU_ASSERT_PTR_NOT_NULL(sr);
    struct pcep_object_ro *ro = encode_ro_subobj(&sr->ro_subobj);
    CU_ASSERT_EQUAL(sr->ro_subobj.ro_subobj_type, RO_SUBOBJ_TYPE_SR);
    CU_ASSERT_TRUE(sr->ro_subobj.flag_subobj_loose_hop);
    CU_ASSERT_EQUAL(sr->nai_type, PCEP_SR_SUBOBJ_NAI_UNNUMBERED_IPV4_ADJACENCY);
    CU_ASSERT_TRUE(sr->flag_s);
    CU_ASSERT_FALSE(sr->flag_m);
    CU_ASSERT_FALSE(sr->flag_c);
    CU_ASSERT_FALSE(sr->flag_f);
    CU_ASSERT_EQUAL(sr->sid, 0);
    double_linked_list_node *node = sr->nai_list->head;
    uint32_t *uint32_ptr = (uint32_t *) node->data;
    CU_ASSERT_EQUAL(*uint32_ptr, local_node_id);

    node = node->next_node;
    uint32_ptr = (uint32_t *) node->data;
    CU_ASSERT_EQUAL(*uint32_ptr, local_if_id);

    node = node->next_node;
    uint32_ptr = (uint32_t *) node->data;
    CU_ASSERT_EQUAL(*uint32_ptr, remote_node_id);

    node = node->next_node;
    uint32_ptr = (uint32_t *) node->data;
    CU_ASSERT_EQUAL(*uint32_ptr, remote_if_id);
    pcep_obj_free_object((struct pcep_object_header *) ro);

    /* Test the sid is present */
    reset_objects_buffer();
    sr = pcep_obj_create_ro_subobj_sr_unnumbered_ipv4_adj(
            false, false, true, true, sid,
            local_node_id, local_if_id, remote_node_id, remote_if_id);
    CU_ASSERT_PTR_NOT_NULL(sr);
    ro = encode_ro_subobj(&sr->ro_subobj);
    CU_ASSERT_EQUAL(sr->ro_subobj.ro_subobj_type, RO_SUBOBJ_TYPE_SR);
    CU_ASSERT_FALSE(sr->ro_subobj.flag_subobj_loose_hop);
    CU_ASSERT_EQUAL(sr->nai_type, PCEP_SR_SUBOBJ_NAI_UNNUMBERED_IPV4_ADJACENCY);
    CU_ASSERT_TRUE(sr->flag_c);
    CU_ASSERT_TRUE(sr->flag_m);
    CU_ASSERT_FALSE(sr->flag_s);
    CU_ASSERT_FALSE(sr->flag_f);
    CU_ASSERT_EQUAL(sr->sid, sid);
    node = sr->nai_list->head;
    uint32_ptr = (uint32_t *) node->data;
    CU_ASSERT_EQUAL(*uint32_ptr, local_node_id);

    node = node->next_node;
    uint32_ptr = (uint32_t *) node->data;
    CU_ASSERT_EQUAL(*uint32_ptr, local_if_id);

    node = node->next_node;
    uint32_ptr = (uint32_t *) node->data;
    CU_ASSERT_EQUAL(*uint32_ptr, remote_node_id);

    node = node->next_node;
    uint32_ptr = (uint32_t *) node->data;
    CU_ASSERT_EQUAL(*uint32_ptr, remote_if_id);
    pcep_obj_free_object((struct pcep_object_header *) ro);

    /* TODO Test draft07 types  */

}

void test_pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj()
{
    uint32_t sid = 0x01020304;
    uint32_t local_if_id = 0x11002200;
    uint32_t remote_if_id = 0x00110022;
    struct in6_addr *local_ipv6 = malloc(sizeof(struct in6_addr));
    struct in6_addr *remote_ipv6 = malloc(sizeof(struct in6_addr));
    inet_pton(AF_INET6, "2001:db8::8a2e:370:8221", local_ipv6);
    inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", remote_ipv6);

    /* (loose_hop, sid_absent, c_flag, m_flag, sid, local_ipv6, local_if_id, remote_ipv6, remote_if_id */
    struct pcep_ro_subobj_sr *sr = pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj(
            false, true, true, true, sid, NULL, local_if_id, NULL, remote_if_id);
    CU_ASSERT_PTR_NULL(sr);

    sr = pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj(
            false, true, true, true, sid, local_ipv6, local_if_id, NULL, remote_if_id);
    CU_ASSERT_PTR_NULL(sr);

    sr = pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj(
            false, true, true, true, sid, NULL, local_if_id, remote_ipv6, remote_if_id);
    CU_ASSERT_PTR_NULL(sr);

    /* Test the sid is absent */
    sr = pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj(
            true, true, true, true, sid, local_ipv6, local_if_id, remote_ipv6, remote_if_id);
    CU_ASSERT_PTR_NOT_NULL(sr);
    struct pcep_object_ro *ro = encode_ro_subobj(&sr->ro_subobj);
    CU_ASSERT_EQUAL(sr->ro_subobj.ro_subobj_type, RO_SUBOBJ_TYPE_SR);
    CU_ASSERT_TRUE(sr->ro_subobj.flag_subobj_loose_hop);
    CU_ASSERT_EQUAL(sr->nai_type, PCEP_SR_SUBOBJ_NAI_LINK_LOCAL_IPV6_ADJACENCY);
    CU_ASSERT_TRUE(sr->flag_s);
    CU_ASSERT_FALSE(sr->flag_m);
    CU_ASSERT_FALSE(sr->flag_c);
    CU_ASSERT_FALSE(sr->flag_f);
    CU_ASSERT_EQUAL(sr->sid, 0);
    double_linked_list_node *node = sr->nai_list->head;
    struct in6_addr *ip6_ptr = (struct in6_addr *) node->data;
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[0], local_ipv6->__in6_u.__u6_addr32[0]);
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[1], local_ipv6->__in6_u.__u6_addr32[1]);
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[2], local_ipv6->__in6_u.__u6_addr32[2]);
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[3], local_ipv6->__in6_u.__u6_addr32[3]);

    node = node->next_node;
    CU_ASSERT_EQUAL(*((uint32_t *) node->data), local_if_id);

    node = node->next_node;
    ip6_ptr = (struct in6_addr *) node->data;
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[0], remote_ipv6->__in6_u.__u6_addr32[0]);
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[1], remote_ipv6->__in6_u.__u6_addr32[1]);
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[2], remote_ipv6->__in6_u.__u6_addr32[2]);
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[3], remote_ipv6->__in6_u.__u6_addr32[3]);

    node = node->next_node;
    CU_ASSERT_EQUAL(*((uint32_t *) node->data), remote_if_id);
    pcep_obj_free_object((struct pcep_object_header *) ro);

    /* Test the sid is present */
    local_ipv6 = malloc(sizeof(struct in6_addr));
    remote_ipv6 = malloc(sizeof(struct in6_addr));
    inet_pton(AF_INET6, "2001:db8::8a2e:370:8221", local_ipv6);
    inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", remote_ipv6);
    reset_objects_buffer();
    sr = pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj(
            false, false, true, true, sid, local_ipv6, local_if_id, remote_ipv6, remote_if_id);
    CU_ASSERT_PTR_NOT_NULL(sr);
    ro = encode_ro_subobj(&sr->ro_subobj);

    CU_ASSERT_EQUAL(sr->ro_subobj.ro_subobj_type, RO_SUBOBJ_TYPE_SR);
    CU_ASSERT_FALSE(sr->ro_subobj.flag_subobj_loose_hop);
    CU_ASSERT_EQUAL(sr->nai_type, PCEP_SR_SUBOBJ_NAI_LINK_LOCAL_IPV6_ADJACENCY);
    CU_ASSERT_TRUE(sr->flag_c);
    CU_ASSERT_TRUE(sr->flag_m);
    CU_ASSERT_FALSE(sr->flag_s);
    CU_ASSERT_FALSE(sr->flag_f);
    CU_ASSERT_EQUAL(sr->sid, sid);
    node = sr->nai_list->head;
    ip6_ptr = (struct in6_addr *) node->data;
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[0], local_ipv6->__in6_u.__u6_addr32[0]);
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[1], local_ipv6->__in6_u.__u6_addr32[1]);
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[2], local_ipv6->__in6_u.__u6_addr32[2]);
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[3], local_ipv6->__in6_u.__u6_addr32[3]);

    node = node->next_node;
    CU_ASSERT_EQUAL(*((uint32_t *) node->data), local_if_id);

    node = node->next_node;
    ip6_ptr = (struct in6_addr *) node->data;
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[0], remote_ipv6->__in6_u.__u6_addr32[0]);
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[1], remote_ipv6->__in6_u.__u6_addr32[1]);
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[2], remote_ipv6->__in6_u.__u6_addr32[2]);
    CU_ASSERT_EQUAL(ip6_ptr->__in6_u.__u6_addr32[3], remote_ipv6->__in6_u.__u6_addr32[3]);

    node = node->next_node;
    CU_ASSERT_EQUAL(*((uint32_t *) node->data), remote_if_id);
    pcep_obj_free_object((struct pcep_object_header *) ro);
}
