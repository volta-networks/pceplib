/*
 * pcep-objects-test.c
 *
 *  Created on: Nov 6, 2019
 *      Author: brady
 */

#include <stdlib.h>

#include <CUnit/CUnit.h>

#include "pcep-objects.h"

/*
 * Notice:
 * All of these object Unit Tests encode the created objects by explicitly calling
 * pcep_obj_encode() thus testing the object creation and the object encoding.
 */

void test_pcep_obj_create_open()
{
    uint8_t deadtimer = 60;
    uint8_t keepalive = 30;
    uint8_t sid = 1;

    struct pcep_object_open *open = pcep_obj_create_open(keepalive, deadtimer, sid, NULL);

    CU_ASSERT_PTR_NOT_NULL(open);
    pcep_obj_encode(&open->header);
    CU_ASSERT_EQUAL(open->header.object_class, PCEP_OBJ_CLASS_OPEN);
    CU_ASSERT_EQUAL(open->header.object_type, PCEP_OBJ_TYPE_OPEN);
    CU_ASSERT_EQUAL(open->header.object_flags, 0);
    CU_ASSERT_EQUAL(ntohs(open->header.object_length), sizeof(struct pcep_object_open));

    CU_ASSERT_EQUAL(open->open_deadtimer, deadtimer);
    CU_ASSERT_EQUAL(open->open_keepalive, keepalive);
    CU_ASSERT_EQUAL(open->open_sid, sid);
    CU_ASSERT_EQUAL(open->open_ver_flags, 0x20);

    free(open);
}

void test_pcep_obj_create_open_with_tlvs()
{
    uint8_t deadtimer = 60;
    uint8_t keepalive = 30;
    uint8_t sid = 1;
    double_linked_list *tlv_list = dll_initialize();

    struct pcep_object_tlv *tlv =
            pcep_tlv_create_stateful_pce_capability(PCEP_TLV_FLAG_LSP_UPDATE_CAPABILITY);
    dll_append(tlv_list, tlv);
    struct pcep_object_open *open = pcep_obj_create_open(keepalive, deadtimer, sid, tlv_list);

    CU_ASSERT_PTR_NOT_NULL(open);
    pcep_obj_encode(&open->header);
    CU_ASSERT_EQUAL(open->header.object_class, PCEP_OBJ_CLASS_OPEN);
    CU_ASSERT_EQUAL(open->header.object_type, PCEP_OBJ_TYPE_OPEN);
    CU_ASSERT_EQUAL(open->header.object_flags, 0);
    CU_ASSERT_EQUAL(ntohs(open->header.object_length),
            sizeof(struct pcep_object_open) +
            sizeof(struct pcep_object_tlv_header) +
            tlv->header.length);

    CU_ASSERT_EQUAL(open->open_deadtimer, deadtimer);
    CU_ASSERT_EQUAL(open->open_keepalive, keepalive);
    CU_ASSERT_EQUAL(open->open_sid, sid);
    CU_ASSERT_EQUAL(open->open_ver_flags, 0x20);

    dll_destroy(tlv_list);
    free(tlv);
    free(open);
}

void test_pcep_obj_create_rp()
{
    uint8_t hdrflags = 0x0f;
    uint32_t objflags = 8;
    uint32_t reqid = 15;

    struct pcep_object_rp *rp = pcep_obj_create_rp(hdrflags, objflags, reqid, NULL);

    CU_ASSERT_PTR_NOT_NULL(rp);
    pcep_obj_encode(&rp->header);
    CU_ASSERT_EQUAL(rp->header.object_class, PCEP_OBJ_CLASS_RP);
    CU_ASSERT_EQUAL(rp->header.object_type, PCEP_OBJ_TYPE_RP);
    CU_ASSERT_EQUAL(rp->header.object_flags, hdrflags);
    CU_ASSERT_EQUAL(rp->header.object_length, ntohs(sizeof(struct pcep_object_rp)));

    CU_ASSERT_EQUAL(rp->rp_flags, ntohl(objflags));
    CU_ASSERT_EQUAL(rp->rp_reqidnumb, ntohl(reqid));

    free(rp);
}

void test_pcep_obj_create_nopath()
{
    uint8_t hdrflags = 0x0f;
    uint32_t objflags = 0x16;
    uint8_t ni = 8;
    uint32_t errorcode = 42;

    struct pcep_object_nopath *nopath = pcep_obj_create_nopath(hdrflags, ni, objflags, errorcode);

    CU_ASSERT_PTR_NOT_NULL(nopath);
    pcep_obj_encode(&nopath->header);
    CU_ASSERT_EQUAL(nopath->header.object_class, PCEP_OBJ_CLASS_NOPATH);
    CU_ASSERT_EQUAL(nopath->header.object_type, PCEP_OBJ_TYPE_NOPATH);
    CU_ASSERT_EQUAL(nopath->header.object_flags, hdrflags);
    CU_ASSERT_EQUAL(nopath->header.object_length, ntohs(sizeof(struct pcep_object_nopath) + 4));

    CU_ASSERT_EQUAL(nopath->ni, ni);
    CU_ASSERT_EQUAL(nopath->flags, ntohs(objflags << 15));
    CU_ASSERT_EQUAL(nopath->err_code.header.length, ntohs(4));
    CU_ASSERT_EQUAL(nopath->err_code.header.type, ntohs(1));
    CU_ASSERT_EQUAL(nopath->err_code.value[0], ntohl(errorcode));

    free(nopath);
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
    pcep_obj_encode(&ipv4->header);
    CU_ASSERT_EQUAL(ipv4->header.object_class, PCEP_OBJ_CLASS_ENDPOINTS);
    CU_ASSERT_EQUAL(ipv4->header.object_type, PCEP_OBJ_TYPE_ENDPOINT_IPV4);
    CU_ASSERT_EQUAL(ipv4->header.object_flags, 0);
    CU_ASSERT_EQUAL(ipv4->header.object_length, ntohs(sizeof(struct pcep_object_endpoints_ipv4)));
    CU_ASSERT_EQUAL(ipv4->src_ipv4.s_addr, ntohl(src_ipv4.s_addr));
    CU_ASSERT_EQUAL(ipv4->dst_ipv4.s_addr, ntohl(dst_ipv4.s_addr));

    free(ipv4);
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
    pcep_obj_encode(&ipv6->header);
    CU_ASSERT_EQUAL(ipv6->header.object_class, PCEP_OBJ_CLASS_ENDPOINTS);
    CU_ASSERT_EQUAL(ipv6->header.object_type, PCEP_OBJ_TYPE_ENDPOINT_IPV6);
    CU_ASSERT_EQUAL(ipv6->header.object_flags, 0);
    CU_ASSERT_EQUAL(ipv6->header.object_length, ntohs(sizeof(struct pcep_object_endpoints_ipv6)));
    CU_ASSERT_EQUAL(ipv6->src_ipv6.__in6_u.__u6_addr32[0], ntohl(src_ipv6.__in6_u.__u6_addr32[0]));
    CU_ASSERT_EQUAL(ipv6->src_ipv6.__in6_u.__u6_addr32[1], ntohl(src_ipv6.__in6_u.__u6_addr32[1]));
    CU_ASSERT_EQUAL(ipv6->src_ipv6.__in6_u.__u6_addr32[2], ntohl(src_ipv6.__in6_u.__u6_addr32[2]));
    CU_ASSERT_EQUAL(ipv6->src_ipv6.__in6_u.__u6_addr32[3], ntohl(src_ipv6.__in6_u.__u6_addr32[3]));
    CU_ASSERT_EQUAL(ipv6->dst_ipv6.__in6_u.__u6_addr32[0], ntohl(dst_ipv6.__in6_u.__u6_addr32[0]));
    CU_ASSERT_EQUAL(ipv6->dst_ipv6.__in6_u.__u6_addr32[1], ntohl(dst_ipv6.__in6_u.__u6_addr32[1]));
    CU_ASSERT_EQUAL(ipv6->dst_ipv6.__in6_u.__u6_addr32[2], ntohl(dst_ipv6.__in6_u.__u6_addr32[2]));
    CU_ASSERT_EQUAL(ipv6->dst_ipv6.__in6_u.__u6_addr32[3], ntohl(dst_ipv6.__in6_u.__u6_addr32[3]));

    free(ipv6);
}

void test_pcep_obj_create_bandwidth()
{
    float bandwidth = 1.8;

    struct pcep_object_bandwidth *bw = pcep_obj_create_bandwidth(bandwidth);

    CU_ASSERT_PTR_NOT_NULL(bw);
    pcep_obj_encode(&bw->header);
    CU_ASSERT_EQUAL(bw->header.object_class, PCEP_OBJ_CLASS_BANDWIDTH);
    CU_ASSERT_EQUAL(bw->header.object_type, PCEP_OBJ_TYPE_BANDWIDTH_REQ);
    CU_ASSERT_EQUAL(bw->header.object_flags, 0);
    CU_ASSERT_EQUAL(bw->header.object_length, ntohs(sizeof(struct pcep_object_bandwidth)));
    CU_ASSERT_EQUAL(bw->bandwidth, bandwidth);

    free(bw);
}

void test_pcep_obj_create_metric()
{
    uint8_t flags = 0xba;
    uint8_t type = PCEP_METRIC_DISJOINTNESS;
    float value = 42.24;

    struct pcep_object_metric *metric = pcep_obj_create_metric(flags, type, value);

    CU_ASSERT_PTR_NOT_NULL(metric);
    pcep_obj_encode(&metric->header);
    CU_ASSERT_EQUAL(metric->header.object_class, PCEP_OBJ_CLASS_METRIC);
    CU_ASSERT_EQUAL(metric->header.object_type, PCEP_OBJ_TYPE_METRIC);
    CU_ASSERT_EQUAL(metric->header.object_flags, 0);
    CU_ASSERT_EQUAL(metric->header.object_length, ntohs(sizeof(struct pcep_object_metric)));
    CU_ASSERT_EQUAL(metric->flags, flags);
    CU_ASSERT_EQUAL(metric->type, type);
    CU_ASSERT_EQUAL(metric->value, value);

    free(metric);
}

void test_pcep_obj_create_lspa()
{
    uint8_t prio = 0;
    uint8_t hold_prio = 10;

    struct pcep_object_lspa *lspa = pcep_obj_create_lspa(prio, hold_prio);

    CU_ASSERT_PTR_NOT_NULL(lspa);
    pcep_obj_encode(&lspa->header);
    CU_ASSERT_EQUAL(lspa->header.object_class, PCEP_OBJ_CLASS_LSPA);
    CU_ASSERT_EQUAL(lspa->header.object_type, PCEP_OBJ_TYPE_LSPA);
    CU_ASSERT_EQUAL(lspa->header.object_flags, 0);
    CU_ASSERT_EQUAL(lspa->header.object_length, ntohs(sizeof(struct pcep_object_lspa)));
    CU_ASSERT_EQUAL(lspa->lspa_holdprio, hold_prio);
    CU_ASSERT_EQUAL(lspa->lspa_prio, prio);

    free(lspa);
}

void test_pcep_obj_create_svec()
{
    uint8_t srlg = true;
    uint8_t node = false;
    uint8_t link = true;
    uint16_t ids_count = 3;
    uint32_t ids[] = {10, 20, 30};

    struct pcep_object_svec *svec = pcep_obj_create_svec(srlg, node, link, 0, NULL);
    CU_ASSERT_PTR_NULL(svec);

    svec = pcep_obj_create_svec(srlg, node, link, ids_count, ids);
    CU_ASSERT_PTR_NOT_NULL(svec);
    pcep_obj_encode(&svec->header);
    CU_ASSERT_EQUAL(svec->header.object_class, PCEP_OBJ_CLASS_SVEC);
    CU_ASSERT_EQUAL(svec->header.object_type, PCEP_OBJ_TYPE_SVEC);
    CU_ASSERT_EQUAL(svec->header.object_flags, 0);
    CU_ASSERT_EQUAL(svec->header.object_length,
            htons(sizeof(struct pcep_object_svec) + (ids_count*sizeof(uint32_t))));
    CU_ASSERT_EQUAL(svec->flag_srlg, srlg);
    CU_ASSERT_EQUAL(svec->flag_node, node);
    CU_ASSERT_EQUAL(svec->flag_link, link);
    uint32_t *svec_ids = (uint32_t *) (((uint8_t *) svec) + sizeof(struct pcep_object_svec));
    CU_ASSERT_EQUAL(svec_ids[0], htonl(ids[0]));
    CU_ASSERT_EQUAL(svec_ids[1], htonl(ids[1]));
    CU_ASSERT_EQUAL(svec_ids[2], htonl(ids[2]));

    free(svec);

    svec = pcep_obj_create_svec(srlg, node, link, 0, ids);
    CU_ASSERT_PTR_NOT_NULL(svec);
    pcep_obj_encode(&svec->header);
    CU_ASSERT_EQUAL(svec->header.object_class, PCEP_OBJ_CLASS_SVEC);
    CU_ASSERT_EQUAL(svec->header.object_type, PCEP_OBJ_TYPE_SVEC);
    CU_ASSERT_EQUAL(svec->header.object_flags, 0);
    CU_ASSERT_EQUAL(svec->header.object_length, ntohs(sizeof(struct pcep_object_svec)));

    free(svec);
}

void test_pcep_obj_create_error()
{
    uint8_t error_type = PCEP_ERRT_SESSION_FAILURE;
    uint8_t error_value = PCEP_ERRV_RECVD_INVALID_OPEN_MSG;

    struct pcep_object_error *error = pcep_obj_create_error(error_type, error_value);

    CU_ASSERT_PTR_NOT_NULL(error);
    pcep_obj_encode(&error->header);
    CU_ASSERT_EQUAL(error->header.object_class, PCEP_OBJ_CLASS_ERROR);
    CU_ASSERT_EQUAL(error->header.object_type, PCEP_OBJ_TYPE_ERROR);
    CU_ASSERT_EQUAL(error->header.object_flags, 0);
    CU_ASSERT_EQUAL(error->header.object_length, ntohs(sizeof(struct pcep_object_error)));
    CU_ASSERT_EQUAL(error->error_type, error_type);
    CU_ASSERT_EQUAL(error->error_value, error_value);

    free(error);
}

void test_pcep_obj_create_close()
{
    uint8_t flags = 0x42;
    uint8_t reason = PCEP_CLOSE_REASON_DEADTIMER;

    struct pcep_object_close *close = pcep_obj_create_close(flags, reason);

    CU_ASSERT_PTR_NOT_NULL(close);
    pcep_obj_encode(&close->header);
    CU_ASSERT_EQUAL(close->header.object_class, PCEP_OBJ_CLASS_CLOSE);
    CU_ASSERT_EQUAL(close->header.object_type, PCEP_OBJ_TYPE_CLOSE);
    CU_ASSERT_EQUAL(close->header.object_flags, 0);
    CU_ASSERT_EQUAL(close->header.object_length, ntohs(sizeof(struct pcep_object_close)));
    CU_ASSERT_EQUAL(close->flags, flags);
    CU_ASSERT_EQUAL(close->reason, reason);

    free(close);
}

void test_pcep_obj_create_srp()
{
    bool lsp_remove = true;
    uint32_t srp_id_number = 0x89674523;
    struct pcep_object_srp *srp = pcep_obj_create_srp(lsp_remove, srp_id_number, NULL);

    CU_ASSERT_PTR_NOT_NULL(srp);
    pcep_obj_encode(&srp->header);
    CU_ASSERT_EQUAL(srp->header.object_class, PCEP_OBJ_CLASS_SRP);
    CU_ASSERT_EQUAL(srp->header.object_type, PCEP_OBJ_TYPE_SRP);
    CU_ASSERT_EQUAL(srp->header.object_flags, 0);
    CU_ASSERT_EQUAL(srp->header.object_length, ntohs(sizeof(struct pcep_object_srp)));
    CU_ASSERT_EQUAL(srp->srp_id_number, ntohl(srp_id_number));
    CU_ASSERT_EQUAL(srp->lsp_remove, 1);

    free(srp);
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
    lsp = pcep_obj_create_lsp(plsp_id, (8 << 4), c_flag, a_flag, r_flag, s_flag, d_flag, NULL);
    CU_ASSERT_PTR_NULL(lsp);

    lsp = pcep_obj_create_lsp(plsp_id, status, c_flag, a_flag, r_flag, s_flag, d_flag, NULL);

    CU_ASSERT_PTR_NOT_NULL(lsp);
    pcep_obj_encode(&lsp->header);
    CU_ASSERT_EQUAL(lsp->header.object_class, PCEP_OBJ_CLASS_LSP);
    CU_ASSERT_EQUAL(lsp->header.object_type, PCEP_OBJ_TYPE_LSP);
    CU_ASSERT_EQUAL(lsp->header.object_flags, 0);
    CU_ASSERT_EQUAL(lsp->header.object_length, ntohs(sizeof(struct pcep_object_lsp)));
    /* decode the lsp fields */
    uint32_t *lsp_fields = (uint32_t *) (((uint8_t *) lsp) + 4);
    *lsp_fields = ntohl(*lsp_fields);
    CU_ASSERT_EQUAL(GET_LSP_PCEPID(lsp), plsp_id);
    CU_ASSERT_TRUE(lsp->plsp_id_flags & PCEP_LSP_C_FLAG);
    CU_ASSERT_TRUE(lsp->plsp_id_flags & PCEP_LSP_A_FLAG);
    CU_ASSERT_TRUE(lsp->plsp_id_flags & PCEP_LSP_R_FLAG);
    CU_ASSERT_TRUE(lsp->plsp_id_flags & PCEP_LSP_S_FLAG);
    CU_ASSERT_TRUE(lsp->plsp_id_flags & PCEP_LSP_D_FLAG);
    CU_ASSERT_TRUE(lsp->plsp_id_flags & PCEP_LSP_OPERATIONAL_ACTIVE);

    free(lsp);
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
    pcep_obj_encode(&ero->header);
    CU_ASSERT_EQUAL(ero->header.object_class, object_class);
    CU_ASSERT_EQUAL(ero->header.object_type, object_type);
    CU_ASSERT_EQUAL(ero->header.object_flags, 0);
    CU_ASSERT_EQUAL(ero->header.object_length, ntohs(sizeof(struct pcep_object_ro)));
    free(ero);

    ero = func_to_test(ero_list);
    CU_ASSERT_PTR_NOT_NULL(ero);
    pcep_obj_encode(&ero->header);
    CU_ASSERT_EQUAL(ero->header.object_class, object_class);
    CU_ASSERT_EQUAL(ero->header.object_type, object_type);
    CU_ASSERT_EQUAL(ero->header.object_flags, 0);
    CU_ASSERT_EQUAL(ero->header.object_length, ntohs(sizeof(struct pcep_object_ro)));
    free(ero);

    struct pcep_object_ro_subobj *ro_subobj = pcep_obj_create_ro_subobj_32label(0, 101);
    dll_append(ero_list, ro_subobj);
    ero = func_to_test(ero_list);
    CU_ASSERT_PTR_NOT_NULL(ero);
    pcep_obj_encode(&ero->header);
    CU_ASSERT_EQUAL(ero->header.object_class, object_class);
    CU_ASSERT_EQUAL(ero->header.object_type, object_type);
    CU_ASSERT_EQUAL(ero->header.object_flags, 0);
    CU_ASSERT_EQUAL(ero->header.object_length,
            ntohs(sizeof(struct pcep_object_ro) + ro_subobj->subobj.label.header.length));
    free(ro_subobj);
    free(ero);
    dll_destroy(ero_list);
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
static void encode_ro_subobj(struct pcep_object_ro_subobj *sr)
{
    double_linked_list *sr_subobj_list = dll_initialize();
    dll_append(sr_subobj_list, sr);
    struct pcep_object_ro *ero = pcep_obj_create_ero(sr_subobj_list);
    pcep_obj_encode(&ero->header);

    /* The original sr is copied to the ero in pcep_obj_create_ero(),
     * so now we need to copy the encoded sr back to the original sr */
    memcpy(sr, ((uint8_t *) &ero->header) + sizeof(struct pcep_object_ro),
           ntohs(ero->header.object_length) - sizeof(struct pcep_object_ro));

    free(ero);
    dll_destroy(sr_subobj_list);
}

void test_pcep_obj_create_ro_subobj_ipv4()
{
    struct in_addr ro_ipv4;
    uint8_t prefix_len = 8;

    struct pcep_object_ro_subobj *ipv4 = pcep_obj_create_ro_subobj_ipv4(true, NULL, prefix_len);
    CU_ASSERT_PTR_NULL(ipv4);

    inet_pton(AF_INET, "192.168.1.2", &ro_ipv4);
    ipv4 = pcep_obj_create_ro_subobj_ipv4(false, &ro_ipv4, prefix_len);
    CU_ASSERT_PTR_NOT_NULL(ipv4);
    encode_ro_subobj(ipv4);
    CU_ASSERT_EQUAL(ipv4->subobj.ipv4.header.type, RO_SUBOBJ_TYPE_IPV4);
    CU_ASSERT_EQUAL(ipv4->subobj.ipv4.header.length, sizeof(struct pcep_ro_subobj_ipv4));
    CU_ASSERT_EQUAL(ipv4->subobj.ipv4.prefix_length, prefix_len);
    CU_ASSERT_EQUAL(ipv4->subobj.ipv4.ip_addr.s_addr, ntohl(ro_ipv4.s_addr));
    free(ipv4);

    ipv4 = pcep_obj_create_ro_subobj_ipv4(true, &ro_ipv4, prefix_len);
    CU_ASSERT_PTR_NOT_NULL(ipv4);
    encode_ro_subobj(ipv4);
    CU_ASSERT_EQUAL(ipv4->subobj.ipv4.header.type, (LOOSE_HOP_BIT | RO_SUBOBJ_TYPE_IPV4));
    CU_ASSERT_EQUAL(ipv4->subobj.ipv4.header.length, sizeof(struct pcep_ro_subobj_ipv4));
    CU_ASSERT_EQUAL(ipv4->subobj.ipv4.prefix_length, prefix_len);
    CU_ASSERT_EQUAL(ipv4->subobj.ipv4.ip_addr.s_addr, ntohl(ro_ipv4.s_addr));
    free(ipv4);
}

void test_pcep_obj_create_ro_subobj_ipv6()
{
    struct in6_addr ro_ipv6;
    uint8_t prefix_len = 16;

    struct pcep_object_ro_subobj *ipv6 = pcep_obj_create_ro_subobj_ipv6(true, NULL, prefix_len);
    CU_ASSERT_PTR_NULL(ipv6);

    inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", &ro_ipv6);
    ipv6 = pcep_obj_create_ro_subobj_ipv6(false, &ro_ipv6, prefix_len);
    CU_ASSERT_PTR_NOT_NULL(ipv6);
    encode_ro_subobj(ipv6);
    CU_ASSERT_EQUAL(ipv6->subobj.ipv6.header.type, RO_SUBOBJ_TYPE_IPV6);
    CU_ASSERT_EQUAL(ipv6->subobj.ipv6.header.length, sizeof(struct pcep_ro_subobj_ipv6));
    CU_ASSERT_EQUAL(ipv6->subobj.ipv6.prefix_length, prefix_len);
    CU_ASSERT_EQUAL(ipv6->subobj.ipv6.ip_addr.__in6_u.__u6_addr32[0],
            ntohl(ro_ipv6.__in6_u.__u6_addr32[0]));
    CU_ASSERT_EQUAL(ipv6->subobj.ipv6.ip_addr.__in6_u.__u6_addr32[1],
            ntohl(ro_ipv6.__in6_u.__u6_addr32[1]));
    CU_ASSERT_EQUAL(ipv6->subobj.ipv6.ip_addr.__in6_u.__u6_addr32[2],
            ntohl(ro_ipv6.__in6_u.__u6_addr32[2]));
    CU_ASSERT_EQUAL(ipv6->subobj.ipv6.ip_addr.__in6_u.__u6_addr32[3],
            ntohl(ro_ipv6.__in6_u.__u6_addr32[3]));
    free(ipv6);

    ipv6 = pcep_obj_create_ro_subobj_ipv6(true, &ro_ipv6, prefix_len);
    CU_ASSERT_PTR_NOT_NULL(ipv6);
    encode_ro_subobj(ipv6);
    CU_ASSERT_EQUAL(ipv6->subobj.ipv6.header.type, (LOOSE_HOP_BIT | RO_SUBOBJ_TYPE_IPV6));
    CU_ASSERT_EQUAL(ipv6->subobj.ipv6.header.length, sizeof(struct pcep_ro_subobj_ipv6));
    CU_ASSERT_EQUAL(ipv6->subobj.ipv6.prefix_length, prefix_len);
    CU_ASSERT_EQUAL(ipv6->subobj.ipv6.ip_addr.__in6_u.__u6_addr32[0],
            ntohl(ro_ipv6.__in6_u.__u6_addr32[0]));
    CU_ASSERT_EQUAL(ipv6->subobj.ipv6.ip_addr.__in6_u.__u6_addr32[1],
            ntohl(ro_ipv6.__in6_u.__u6_addr32[1]));
    CU_ASSERT_EQUAL(ipv6->subobj.ipv6.ip_addr.__in6_u.__u6_addr32[2],
            ntohl(ro_ipv6.__in6_u.__u6_addr32[2]));
    CU_ASSERT_EQUAL(ipv6->subobj.ipv6.ip_addr.__in6_u.__u6_addr32[3],
            ntohl(ro_ipv6.__in6_u.__u6_addr32[3]));
    free(ipv6);
}

void test_pcep_obj_create_ro_subobj_unnum()
{
    struct in_addr router_id;
    uint32_t ifId = 123;
    uint16_t resv = 321;

    struct pcep_object_ro_subobj *unnum = pcep_obj_create_ro_subobj_unnum(NULL, ifId, resv);
    CU_ASSERT_PTR_NULL(unnum);

    inet_pton(AF_INET, "192.168.1.2", &router_id);
    unnum = pcep_obj_create_ro_subobj_unnum(&router_id, ifId, resv);
    CU_ASSERT_PTR_NOT_NULL(unnum);
    encode_ro_subobj(unnum);
    CU_ASSERT_EQUAL(unnum->subobj.unnum.header.type, RO_SUBOBJ_TYPE_UNNUM);
    CU_ASSERT_EQUAL(unnum->subobj.unnum.header.length, sizeof(struct pcep_ro_subobj_unnum));
    CU_ASSERT_EQUAL(unnum->subobj.unnum.ifId, ntohl(ifId));
    CU_ASSERT_EQUAL(unnum->subobj.unnum.resv, ntohs(resv));
    CU_ASSERT_EQUAL(unnum->subobj.unnum.routerId.s_addr, ntohl(router_id.s_addr));

    free(unnum);
}

void test_pcep_obj_create_ro_subobj_32label()
{
    uint8_t dir = 1;
    uint32_t label = 0xeeffaabb;

    struct pcep_object_ro_subobj *label32 = pcep_obj_create_ro_subobj_32label(dir, label);
    CU_ASSERT_PTR_NOT_NULL(label32);
    encode_ro_subobj(label32);
    CU_ASSERT_EQUAL(label32->subobj.label.header.type, RO_SUBOBJ_TYPE_LABEL);
    CU_ASSERT_EQUAL(label32->subobj.label.header.length, sizeof(struct pcep_ro_subobj_32label));
    CU_ASSERT_EQUAL(label32->subobj.label.label, ntohl(label));
    CU_ASSERT_EQUAL(label32->subobj.label.upstream, dir);
    CU_ASSERT_EQUAL(label32->subobj.label.resvd, 0);

    free(label32);
}

void test_pcep_obj_create_ro_subobj_border()
{
    uint8_t direction = 1;
    uint8_t swcap_from = 16;
    uint8_t swcap_to = 8;

    struct pcep_object_ro_subobj *border = pcep_obj_create_ro_subobj_border(direction, swcap_from, swcap_to);
    CU_ASSERT_PTR_NOT_NULL(border);
    encode_ro_subobj(border);
    CU_ASSERT_EQUAL(border->subobj.border.header.type, RO_SUBOBJ_TYPE_BORDER);
    CU_ASSERT_EQUAL(border->subobj.border.header.length, sizeof(struct pcep_ro_subobj_border));
    CU_ASSERT_EQUAL(border->subobj.border.direction, direction);
    CU_ASSERT_EQUAL(border->subobj.border.swcap_from, swcap_from);
    CU_ASSERT_EQUAL(border->subobj.border.swcap_to, swcap_to);

    free(border);
}

void test_pcep_obj_create_ro_subobj_asn()
{
    uint16_t asn = 0x0102;

    struct pcep_object_ro_subobj *asn_obj = pcep_obj_create_ro_subobj_asn(asn);
    CU_ASSERT_PTR_NOT_NULL(asn_obj);
    encode_ro_subobj(asn_obj);
    CU_ASSERT_EQUAL(asn_obj->subobj.asn.header.type, RO_SUBOBJ_TYPE_ASN);
    CU_ASSERT_EQUAL(asn_obj->subobj.asn.header.length, sizeof(struct pcep_ro_subobj_asn));
    CU_ASSERT_EQUAL(asn_obj->subobj.asn.aut_sys_number, asn);

    free(asn_obj);
}

void test_pcep_obj_create_ro_subobj_sr_nonai()
{
    uint32_t sid = 0x01020304;
    struct pcep_object_ro_subobj *sr = pcep_obj_create_ro_subobj_sr_nonai(false, sid);
    CU_ASSERT_PTR_NOT_NULL(sr);
    encode_ro_subobj(sr);
    CU_ASSERT_EQUAL(sr->subobj.sr.header.type, RO_SUBOBJ_TYPE_SR);
    CU_ASSERT_EQUAL(sr->subobj.sr.header.length,
            sizeof(struct pcep_ro_subobj_sr) + sizeof(uint32_t));
    CU_ASSERT_EQUAL(sr->subobj.sr.nt_flags, htons((PCEP_SR_SUBOBJ_NAI_ABSENT | PCEP_SR_SUBOBJ_F_FLAG)));
    free(sr);

    sr = pcep_obj_create_ro_subobj_sr_nonai(true, sid);
    CU_ASSERT_PTR_NOT_NULL(sr);
    encode_ro_subobj(sr);
    CU_ASSERT_EQUAL(sr->subobj.sr.header.type, (LOOSE_HOP_BIT | RO_SUBOBJ_TYPE_SR));
    CU_ASSERT_EQUAL(sr->subobj.sr.header.length,
            sizeof(struct pcep_ro_subobj_sr) + sizeof(uint32_t));
    CU_ASSERT_EQUAL(sr->subobj.sr.nt_flags, htons((PCEP_SR_SUBOBJ_NAI_ABSENT | PCEP_SR_SUBOBJ_F_FLAG)));
    free(sr);
}

void test_pcep_obj_create_ro_subobj_sr_ipv4_node()
{
    uint32_t sid = 0x01020304;
    struct in_addr ipv4_node_id;
    inet_pton(AF_INET, "192.168.1.2", &ipv4_node_id);

    /* (loose_hop, sid_absent, c_flag, m_flag, sid, ipv4_node_id) */
    struct pcep_object_ro_subobj *sr =
            pcep_obj_create_ro_subobj_sr_ipv4_node(true, false, true, true, sid, NULL);
    CU_ASSERT_PTR_NULL(sr);

    /* Test the sid is absent */
    sr = pcep_obj_create_ro_subobj_sr_ipv4_node(true, true, false, false, sid, &ipv4_node_id);
    CU_ASSERT_PTR_NOT_NULL(sr);
    encode_ro_subobj(sr);
    CU_ASSERT_EQUAL(sr->subobj.sr.header.type, (LOOSE_HOP_BIT | RO_SUBOBJ_TYPE_SR));
    CU_ASSERT_EQUAL(sr->subobj.sr.header.length, sizeof(struct pcep_ro_subobj_sr) + sizeof(struct in_addr));
    CU_ASSERT_EQUAL(sr->subobj.sr.nt_flags, htons((PCEP_SR_SUBOBJ_NAI_IPV4_NODE | PCEP_SR_SUBOBJ_S_FLAG)));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[0], htonl(ipv4_node_id.s_addr));
    free(sr);

    /* Test the sid is present */
    sr = pcep_obj_create_ro_subobj_sr_ipv4_node(false, false, true, true, sid, &ipv4_node_id);
    CU_ASSERT_PTR_NOT_NULL(sr);
    encode_ro_subobj(sr);
    CU_ASSERT_EQUAL(sr->subobj.sr.header.type, RO_SUBOBJ_TYPE_SR);
    CU_ASSERT_EQUAL(sr->subobj.sr.header.length,
            sizeof(struct pcep_ro_subobj_sr) + sizeof(struct in_addr) + sizeof(uint32_t));
    CU_ASSERT_EQUAL(sr->subobj.sr.nt_flags, htons((PCEP_SR_SUBOBJ_NAI_IPV4_NODE | PCEP_SR_SUBOBJ_C_FLAG | PCEP_SR_SUBOBJ_M_FLAG)));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[0], htonl(sid));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[1], htonl(ipv4_node_id.s_addr));
    free(sr);
}

void test_pcep_obj_create_ro_subobj_sr_ipv6_node()
{
    uint32_t sid = 0x01020304;
    struct in6_addr ipv6_node_id;
    inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", &ipv6_node_id);

    /* (loose_hop, sid_absent, c_flag, m_flag, sid, ipv6_node_id) */
    struct pcep_object_ro_subobj *sr = pcep_obj_create_ro_subobj_sr_ipv6_node(false, true, true, true, sid, NULL);
    CU_ASSERT_PTR_NULL(sr);

    /* Test the sid is absent */
    sr = pcep_obj_create_ro_subobj_sr_ipv6_node(true, true, true, true, sid, &ipv6_node_id);
    CU_ASSERT_PTR_NOT_NULL(sr);
    encode_ro_subobj(sr);
    CU_ASSERT_EQUAL(sr->subobj.sr.header.type, (LOOSE_HOP_BIT | RO_SUBOBJ_TYPE_SR));
    CU_ASSERT_EQUAL(sr->subobj.sr.header.length, sizeof(struct pcep_ro_subobj_sr) + sizeof(struct in6_addr));
    CU_ASSERT_EQUAL(sr->subobj.sr.nt_flags, htons((PCEP_SR_SUBOBJ_NAI_IPV6_NODE | PCEP_SR_SUBOBJ_S_FLAG)));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[0], htonl(ipv6_node_id.__in6_u.__u6_addr32[0]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[1], htonl(ipv6_node_id.__in6_u.__u6_addr32[1]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[2], htonl(ipv6_node_id.__in6_u.__u6_addr32[2]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[3], htonl(ipv6_node_id.__in6_u.__u6_addr32[3]));
    free(sr);

    /* Test the sid is present */
    sr = pcep_obj_create_ro_subobj_sr_ipv6_node(false, false, true, true, sid, &ipv6_node_id);
    CU_ASSERT_PTR_NOT_NULL(sr);
    encode_ro_subobj(sr);
    CU_ASSERT_EQUAL(sr->subobj.sr.header.type, RO_SUBOBJ_TYPE_SR);
    CU_ASSERT_EQUAL(sr->subobj.sr.header.length,
            sizeof(struct pcep_ro_subobj_sr) + sizeof(struct in6_addr) + sizeof(uint32_t));
    CU_ASSERT_EQUAL(sr->subobj.sr.nt_flags, htons((PCEP_SR_SUBOBJ_NAI_IPV6_NODE | PCEP_SR_SUBOBJ_C_FLAG | PCEP_SR_SUBOBJ_M_FLAG)));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[0], htonl(sid));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[1], htonl(ipv6_node_id.__in6_u.__u6_addr32[0]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[2], htonl(ipv6_node_id.__in6_u.__u6_addr32[1]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[3], htonl(ipv6_node_id.__in6_u.__u6_addr32[2]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[4], htonl(ipv6_node_id.__in6_u.__u6_addr32[3]));
    free(sr);
}

void test_pcep_obj_create_ro_subobj_sr_ipv4_adj()
{
    struct in_addr local_ipv4;
    struct in_addr remote_ipv4;
    inet_pton(AF_INET, "192.168.1.2", &local_ipv4);
    inet_pton(AF_INET, "172.168.1.2", &remote_ipv4);

    uint32_t sid = ENCODE_SR_ERO_SID(3, 7, 0, 188);
    CU_ASSERT_EQUAL(sid, 16060);

    /* (loose_hop, sid_absent, c_flag, m_flag, sid, local_ipv4, remote_ipv4) */
    struct pcep_object_ro_subobj *sr =
            pcep_obj_create_ro_subobj_sr_ipv4_adj(false, true, true, true, sid, NULL, NULL);
    CU_ASSERT_PTR_NULL(sr);

    sr = pcep_obj_create_ro_subobj_sr_ipv4_adj(false, true, true, true, sid, &local_ipv4, NULL);
    CU_ASSERT_PTR_NULL(sr);

    sr = pcep_obj_create_ro_subobj_sr_ipv4_adj(false, true, true, true, sid, NULL, &remote_ipv4);
    CU_ASSERT_PTR_NULL(sr);

    /* Test the sid is absent */
    sr = pcep_obj_create_ro_subobj_sr_ipv4_adj(true, true, true, true, sid, &local_ipv4, &remote_ipv4);
    CU_ASSERT_PTR_NOT_NULL(sr);
    encode_ro_subobj(sr);
    CU_ASSERT_EQUAL(sr->subobj.sr.header.type, (LOOSE_HOP_BIT | RO_SUBOBJ_TYPE_SR));
    CU_ASSERT_EQUAL(sr->subobj.sr.header.length,
            sizeof(struct pcep_ro_subobj_sr) + (sizeof(struct in_addr) * 2));
    CU_ASSERT_EQUAL(sr->subobj.sr.nt_flags, htons((PCEP_SR_SUBOBJ_NAI_IPV4_ADJACENCY | PCEP_SR_SUBOBJ_S_FLAG)));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[0], htonl(local_ipv4.s_addr));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[1], htonl(remote_ipv4.s_addr));
    free(sr);

    /* Test the sid is present */
    sr = pcep_obj_create_ro_subobj_sr_ipv4_adj(false, false, true, true, sid, &local_ipv4, &remote_ipv4);
    CU_ASSERT_PTR_NOT_NULL(sr);
    encode_ro_subobj(sr);
    CU_ASSERT_EQUAL(sr->subobj.sr.header.type, RO_SUBOBJ_TYPE_SR);
    CU_ASSERT_EQUAL(sr->subobj.sr.header.length,
            sizeof(struct pcep_ro_subobj_sr) + (sizeof(struct in_addr) * 2) + sizeof(uint32_t));
    CU_ASSERT_EQUAL(sr->subobj.sr.nt_flags, htons((PCEP_SR_SUBOBJ_NAI_IPV4_ADJACENCY | PCEP_SR_SUBOBJ_C_FLAG | PCEP_SR_SUBOBJ_M_FLAG)));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[0], htonl(sid));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[1], htonl(local_ipv4.s_addr));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[2], htonl(remote_ipv4.s_addr));
    free(sr);
}

void test_pcep_obj_create_ro_subobj_sr_ipv6_adj()
{
    uint32_t sid = 0x01020304;
    struct in6_addr local_ipv6;
    struct in6_addr remote_ipv6;
    inet_pton(AF_INET6, "2001:db8::8a2e:370:8221", &local_ipv6);
    inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", &remote_ipv6);

    /* (loose_hop, sid_absent, c_flag, m_flag, sid, local_ipv6, remote_ipv6) */
    struct pcep_object_ro_subobj *sr = pcep_obj_create_ro_subobj_sr_ipv6_adj(false, true, true, true, sid, NULL, NULL);
    CU_ASSERT_PTR_NULL(sr);

    sr = pcep_obj_create_ro_subobj_sr_ipv6_adj(false, true, true, true, sid, &local_ipv6, NULL);
    CU_ASSERT_PTR_NULL(sr);

    sr = pcep_obj_create_ro_subobj_sr_ipv6_adj(false, true, true, true, sid, NULL, &remote_ipv6);
    CU_ASSERT_PTR_NULL(sr);

    /* Test the sid is absent */
    sr = pcep_obj_create_ro_subobj_sr_ipv6_adj(true, true, true, true, sid, &local_ipv6, &remote_ipv6);
    CU_ASSERT_PTR_NOT_NULL(sr);
    encode_ro_subobj(sr);
    CU_ASSERT_EQUAL(sr->subobj.sr.header.type, (LOOSE_HOP_BIT | RO_SUBOBJ_TYPE_SR));
    CU_ASSERT_EQUAL(sr->subobj.sr.header.length, sizeof(struct pcep_ro_subobj_sr) + (sizeof(struct in6_addr) * 2));
    CU_ASSERT_EQUAL(sr->subobj.sr.nt_flags, htons((PCEP_SR_SUBOBJ_NAI_IPV6_ADJACENCY | PCEP_SR_SUBOBJ_S_FLAG)));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[0], htonl(local_ipv6.__in6_u.__u6_addr32[0]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[1], htonl(local_ipv6.__in6_u.__u6_addr32[1]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[2], htonl(local_ipv6.__in6_u.__u6_addr32[2]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[3], htonl(local_ipv6.__in6_u.__u6_addr32[3]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[4], htonl(remote_ipv6.__in6_u.__u6_addr32[0]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[5], htonl(remote_ipv6.__in6_u.__u6_addr32[1]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[6], htonl(remote_ipv6.__in6_u.__u6_addr32[2]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[7], htonl(remote_ipv6.__in6_u.__u6_addr32[3]));
    free(sr);

    /* Test the sid is present */
    sr = pcep_obj_create_ro_subobj_sr_ipv6_adj(false, false, true, false, sid, &local_ipv6, &remote_ipv6);
    CU_ASSERT_PTR_NOT_NULL(sr);
    encode_ro_subobj(sr);
    CU_ASSERT_EQUAL(sr->subobj.sr.header.type, RO_SUBOBJ_TYPE_SR);
    CU_ASSERT_EQUAL(sr->subobj.sr.header.length,
            sizeof(struct pcep_ro_subobj_sr) + (sizeof(struct in6_addr) * 2) + sizeof(uint32_t));
    CU_ASSERT_EQUAL(sr->subobj.sr.nt_flags, htons(PCEP_SR_SUBOBJ_NAI_IPV6_ADJACENCY));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[0], htonl(sid));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[1], htonl(local_ipv6.__in6_u.__u6_addr32[0]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[2], htonl(local_ipv6.__in6_u.__u6_addr32[1]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[3], htonl(local_ipv6.__in6_u.__u6_addr32[2]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[4], htonl(local_ipv6.__in6_u.__u6_addr32[3]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[5], htonl(remote_ipv6.__in6_u.__u6_addr32[0]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[6], htonl(remote_ipv6.__in6_u.__u6_addr32[1]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[7], htonl(remote_ipv6.__in6_u.__u6_addr32[2]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[8], htonl(remote_ipv6.__in6_u.__u6_addr32[3]));
    free(sr);
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
    struct pcep_object_ro_subobj *sr = pcep_obj_create_ro_subobj_sr_unnumbered_ipv4_adj(
            true, true, true, true, sid,
            local_node_id, local_if_id, remote_node_id, remote_if_id);
    CU_ASSERT_PTR_NOT_NULL(sr);
    encode_ro_subobj(sr);
    CU_ASSERT_EQUAL(sr->subobj.sr.header.type, (LOOSE_HOP_BIT | RO_SUBOBJ_TYPE_SR));
    CU_ASSERT_EQUAL(sr->subobj.sr.header.length, sizeof(struct pcep_ro_subobj_sr) + (sizeof(struct in_addr) * 4));
    CU_ASSERT_EQUAL(sr->subobj.sr.nt_flags,
            htons((PCEP_SR_SUBOBJ_NAI_UNNUMBERED_IPV4_ADJACENCY | PCEP_SR_SUBOBJ_S_FLAG)));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[0], htonl(local_node_id));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[1], htonl(local_if_id));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[2], htonl(remote_node_id));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[3], htonl(remote_if_id));
    free(sr);

    /* Test the sid is present */
    sr = pcep_obj_create_ro_subobj_sr_unnumbered_ipv4_adj(
            false, false, true, true, sid,
            local_node_id, local_if_id, remote_node_id, remote_if_id);
    CU_ASSERT_PTR_NOT_NULL(sr);
    encode_ro_subobj(sr);
    CU_ASSERT_EQUAL(sr->subobj.sr.header.type, RO_SUBOBJ_TYPE_SR);
    CU_ASSERT_EQUAL(sr->subobj.sr.header.length, sizeof(struct pcep_ro_subobj_sr) + (sizeof(struct in_addr) * 5));
    CU_ASSERT_EQUAL(sr->subobj.sr.nt_flags,
            htons((PCEP_SR_SUBOBJ_NAI_UNNUMBERED_IPV4_ADJACENCY | PCEP_SR_SUBOBJ_C_FLAG | PCEP_SR_SUBOBJ_M_FLAG)));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[0], htonl(sid));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[1], htonl(local_node_id));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[2], htonl(local_if_id));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[3], htonl(remote_node_id));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[4], htonl(remote_if_id));
    free(sr);
}

void test_pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj()
{
    uint32_t sid = 0x01020304;
    uint32_t local_if_id = 0x11002200;
    uint32_t remote_if_id = 0x00110022;
    struct in6_addr local_ipv6;
    struct in6_addr remote_ipv6;
    inet_pton(AF_INET6, "2001:db8::8a2e:370:8221", &local_ipv6);
    inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", &remote_ipv6);

    /* (loose_hop, sid_absent, c_flag, m_flag, sid, local_ipv6, local_if_id, remote_ipv6, remote_if_id */
    struct pcep_object_ro_subobj *sr = pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj(
            false, true, true, true, sid, NULL, local_if_id, NULL, remote_if_id);
    CU_ASSERT_PTR_NULL(sr);

    sr = pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj(
            false, true, true, true, sid, &local_ipv6, local_if_id, NULL, remote_if_id);
    CU_ASSERT_PTR_NULL(sr);

    sr = pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj(
            false, true, true, true, sid, NULL, local_if_id, &remote_ipv6, remote_if_id);
    CU_ASSERT_PTR_NULL(sr);

    /* Test the sid is absent */
    sr = pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj(
            true, true, true, true, sid, &local_ipv6, local_if_id, &remote_ipv6, remote_if_id);
    CU_ASSERT_PTR_NOT_NULL(sr);
    encode_ro_subobj(sr);
    CU_ASSERT_EQUAL(sr->subobj.sr.header.type, (LOOSE_HOP_BIT | RO_SUBOBJ_TYPE_SR));
    CU_ASSERT_EQUAL(sr->subobj.sr.header.length, sizeof(struct pcep_ro_subobj_sr) +
                                                 (sizeof(struct in_addr) * 2) +
                                                 (sizeof(struct in6_addr) * 2));
    CU_ASSERT_EQUAL(sr->subobj.sr.nt_flags,
            htons((PCEP_SR_SUBOBJ_NAI_LINK_LOCAL_IPV6_ADJACENCY | PCEP_SR_SUBOBJ_S_FLAG)));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[0], htonl(local_ipv6.__in6_u.__u6_addr32[0]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[1], htonl(local_ipv6.__in6_u.__u6_addr32[1]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[2], htonl(local_ipv6.__in6_u.__u6_addr32[2]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[3], htonl(local_ipv6.__in6_u.__u6_addr32[3]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[4], htonl(local_if_id));

    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[5], htonl(remote_ipv6.__in6_u.__u6_addr32[0]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[6], htonl(remote_ipv6.__in6_u.__u6_addr32[1]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[7], htonl(remote_ipv6.__in6_u.__u6_addr32[2]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[8], htonl(remote_ipv6.__in6_u.__u6_addr32[3]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[9], htonl(remote_if_id));
    free(sr);

    /* Test the sid is present */
    sr = pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj(
            false, false, true, true, sid, &local_ipv6, local_if_id, &remote_ipv6, remote_if_id);
    CU_ASSERT_PTR_NOT_NULL(sr);
    encode_ro_subobj(sr);

    CU_ASSERT_EQUAL(sr->subobj.sr.header.type, RO_SUBOBJ_TYPE_SR);
    CU_ASSERT_EQUAL(sr->subobj.sr.header.length, sizeof(struct pcep_ro_subobj_sr) +
                                                 (sizeof(struct in_addr) * 2) +
                                                 (sizeof(struct in6_addr) * 2) +
                                                 (sizeof(uint32_t)));
    CU_ASSERT_EQUAL(sr->subobj.sr.nt_flags,
            ntohs(PCEP_SR_SUBOBJ_NAI_LINK_LOCAL_IPV6_ADJACENCY | PCEP_SR_SUBOBJ_C_FLAG | PCEP_SR_SUBOBJ_M_FLAG));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[0], htonl(sid));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[1], htonl(local_ipv6.__in6_u.__u6_addr32[0]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[2], htonl(local_ipv6.__in6_u.__u6_addr32[1]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[3], htonl(local_ipv6.__in6_u.__u6_addr32[2]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[4], htonl(local_ipv6.__in6_u.__u6_addr32[3]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[5], htonl(local_if_id));

    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[6], htonl(remote_ipv6.__in6_u.__u6_addr32[0]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[7], htonl(remote_ipv6.__in6_u.__u6_addr32[1]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[8], htonl(remote_ipv6.__in6_u.__u6_addr32[2]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[9], htonl(remote_ipv6.__in6_u.__u6_addr32[3]));
    CU_ASSERT_EQUAL(sr->subobj.sr.sid_nai[10], htonl(remote_if_id));
    free(sr);
}

void test_pcep_decode_obj_ro()
{
    struct in_addr local_ipv4;
    struct in_addr remote_ipv4;
    struct in6_addr local_ipv6;
    struct in6_addr remote_ipv6;
    uint32_t local_if_id = 0x55667788;

    inet_pton(AF_INET, "192.168.1.2", &local_ipv4);
    inet_pton(AF_INET, "172.168.1.2", &remote_ipv4);
    inet_pton(AF_INET6, "2001:db8::8a2e:370:8221", &local_ipv6);
    inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", &remote_ipv6);

    /* RO_SUBOBJ_TYPE_UNNUM */
    struct pcep_object_ro_subobj *unnum = pcep_obj_create_ro_subobj_unnum(&local_ipv4, local_if_id, 0);
    CU_ASSERT_EQUAL(unnum->subobj.unnum.ifId, local_if_id);
    CU_ASSERT_EQUAL(unnum->subobj.unnum.routerId.s_addr, local_ipv4.s_addr);
    encode_ro_subobj(unnum);
    CU_ASSERT_EQUAL(unnum->subobj.unnum.ifId, ntohl(local_if_id));
    CU_ASSERT_EQUAL(unnum->subobj.unnum.routerId.s_addr, ntohl(local_ipv4.s_addr));
    free(unnum);

    /* RO_SUBOBJ_TYPE_IPV4 */
    struct pcep_object_ro_subobj *ipv4 = pcep_obj_create_ro_subobj_ipv4(true, &local_ipv4, 8);
    CU_ASSERT_EQUAL(ipv4->subobj.ipv4.ip_addr.s_addr, local_ipv4.s_addr);
    encode_ro_subobj(ipv4);
    CU_ASSERT_EQUAL(ipv4->subobj.ipv4.ip_addr.s_addr, ntohl(local_ipv4.s_addr));
    free(ipv4);

    /* RO_SUBOBJ_TYPE_IPV6 */
    struct pcep_object_ro_subobj *ipv6 = pcep_obj_create_ro_subobj_ipv6(true, &local_ipv6, 8);
    CU_ASSERT_EQUAL(ipv6->subobj.ipv6.ip_addr.__in6_u.__u6_addr32[0], local_ipv6.__in6_u.__u6_addr32[0]);
    CU_ASSERT_EQUAL(ipv6->subobj.ipv6.ip_addr.__in6_u.__u6_addr32[1], local_ipv6.__in6_u.__u6_addr32[1]);
    CU_ASSERT_EQUAL(ipv6->subobj.ipv6.ip_addr.__in6_u.__u6_addr32[2], local_ipv6.__in6_u.__u6_addr32[2]);
    CU_ASSERT_EQUAL(ipv6->subobj.ipv6.ip_addr.__in6_u.__u6_addr32[3], local_ipv6.__in6_u.__u6_addr32[3]);
    encode_ro_subobj(ipv6);
    CU_ASSERT_EQUAL(ipv6->subobj.ipv6.ip_addr.__in6_u.__u6_addr32[0], ntohl(local_ipv6.__in6_u.__u6_addr32[0]));
    CU_ASSERT_EQUAL(ipv6->subobj.ipv6.ip_addr.__in6_u.__u6_addr32[1], ntohl(local_ipv6.__in6_u.__u6_addr32[1]));
    CU_ASSERT_EQUAL(ipv6->subobj.ipv6.ip_addr.__in6_u.__u6_addr32[2], ntohl(local_ipv6.__in6_u.__u6_addr32[2]));
    CU_ASSERT_EQUAL(ipv6->subobj.ipv6.ip_addr.__in6_u.__u6_addr32[3], ntohl(local_ipv6.__in6_u.__u6_addr32[3]));
    free(ipv6);
}

void verify_sid_nai(const char *fail_message, struct pcep_ro_subobj_sr *sr, uint32_t entries[], uint8_t num_elements)
{
    int i;
    for (i = 0; i < num_elements; i++)
    {
        /* Using CU_ASSERT_EQUAL() in this function makes
         * it hard to know which calling function failed
         * CU_ASSERT_EQUAL(sr->sid_nai[i], entries[i]); */
        if (sr->sid_nai[i] != entries[i])
        {
            fprintf(stderr, "verify_sid_nai test failed [%s] index [%d] expected [%d] actual [%d]\n",
                    fail_message, i, sr->sid_nai[i], entries[i]);
            CU_FAIL();
        }
    }
}

void verify_sid_nai_ntohl(const char *fail_message, struct pcep_ro_subobj_sr *sr, uint32_t entries[], uint8_t num_elements)
{
    int i;
    for (i = 0; i < num_elements; i++)
    {
        /* Using CU_ASSERT_EQUAL() in this function makes
         * it hard to know which calling function failed
         * CU_ASSERT_EQUAL(sr->sid_nai[i], ntohl(entries[i])); */
        if (sr->sid_nai[i] != ntohl(entries[i]))
        {
            fprintf(stderr, "verify_sid_nai_ntohl test failed [%s] index [%d] expected [%d] actual [%d]\n",
                    fail_message, i, sr->sid_nai[i], ntohl(entries[i]));
            CU_FAIL();
        }
    }
}

void test_pcep_decode_obj_ro_sr()
{
    struct in_addr local_ipv4;
    struct in_addr remote_ipv4;
    struct in6_addr local_ipv6;
    struct in6_addr remote_ipv6;
    uint32_t sid  = 0x44332211;
    uint32_t local_node_id  = 0x11223344;
    uint32_t local_if_id    = 0x55667788;
    uint32_t remote_node_id = 0x99aabbcc;
    uint32_t remote_if_id   = 0xddeeff11;
    uint32_t compare_entries[11];
    bzero(compare_entries, sizeof(uint32_t) * 10);

    inet_pton(AF_INET, "192.168.1.2", &local_ipv4);
    inet_pton(AF_INET, "172.168.1.2", &remote_ipv4);
    inet_pton(AF_INET6, "2001:db8::8a2e:370:8221", &local_ipv6);
    inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", &remote_ipv6);

    /*
     * RO_SUBOBJ_TYPE_SR functions, with different NAI types
     */

    /* PCEP_SR_SUBOBJ_NAI_IPV4_NODE */
    struct pcep_object_ro_subobj *sr =
            pcep_obj_create_ro_subobj_sr_ipv4_node(true, false, true, true, sid, &local_ipv4);
    compare_entries[0] = sid;
    compare_entries[1] = local_ipv4.s_addr;
    verify_sid_nai("sr_ipv4_node", &sr->subobj.sr, compare_entries, 2);
    encode_ro_subobj(sr);
    verify_sid_nai_ntohl("sr_ipv4_node", &sr->subobj.sr, compare_entries, 2);
    free(sr);

    /* PCEP_SR_SUBOBJ_NAI_IPV6_NODE */
    sr = pcep_obj_create_ro_subobj_sr_ipv6_node(false, false, true, true, sid, &local_ipv6);
    compare_entries[0] = sid;
    memcpy(&(compare_entries[1]), local_ipv6.__in6_u.__u6_addr32, sizeof(uint32_t) * 4);
    verify_sid_nai("sr_ipv6_node", &sr->subobj.sr, compare_entries, 5);
    encode_ro_subobj(sr);
    verify_sid_nai_ntohl("sr_ipv6_node", &sr->subobj.sr, compare_entries, 5);
    free(sr);

    /* PCEP_SR_SUBOBJ_NAI_IPV4_ADJACENCY */
    sr = pcep_obj_create_ro_subobj_sr_ipv4_adj(false, false, true, true, sid, &local_ipv4, &remote_ipv4);
    compare_entries[0] = sid;
    compare_entries[1] = local_ipv4.s_addr;
    compare_entries[2] = remote_ipv4.s_addr;
    verify_sid_nai("sr_ipv4_adj", &sr->subobj.sr, compare_entries, 3);
    encode_ro_subobj(sr);
    verify_sid_nai_ntohl("sr_ipv4_adj", &sr->subobj.sr, compare_entries, 3);
    free(sr);

    /* PCEP_SR_SUBOBJ_NAI_IPV6_ADJACENCY */
    sr = pcep_obj_create_ro_subobj_sr_ipv6_adj(false, false, true, true, sid, &local_ipv6, &remote_ipv6);
    compare_entries[0] = sid;
    memcpy(&(compare_entries[1]), local_ipv6.__in6_u.__u6_addr32, sizeof(uint32_t) * 4);
    memcpy(&(compare_entries[5]), remote_ipv6.__in6_u.__u6_addr32, sizeof(uint32_t) * 4);
    verify_sid_nai("sr_ipv6_adj", &sr->subobj.sr, compare_entries, 9);
    encode_ro_subobj(sr);
    verify_sid_nai_ntohl("sr_ipv6_adj", &sr->subobj.sr, compare_entries, 9);
    free(sr);

    /* PCEP_SR_SUBOBJ_NAI_UNNUMBERED_IPV4_ADJACENCY */
    sr = pcep_obj_create_ro_subobj_sr_unnumbered_ipv4_adj(false, false, true, true,
            sid, local_node_id, local_if_id, remote_node_id, remote_if_id);
    compare_entries[0] = sid;
    compare_entries[1] = local_node_id;
    compare_entries[2] = local_if_id;
    compare_entries[3] = remote_node_id;
    compare_entries[4] = remote_if_id;
    verify_sid_nai("sr_unnumbered_ipv4_adj", &sr->subobj.sr, compare_entries, 5);
    encode_ro_subobj(sr);
    verify_sid_nai_ntohl("sr_unnumbered_ipv4_adj", &sr->subobj.sr, compare_entries, 5);
    free(sr);

    /* PCEP_SR_SUBOBJ_NAI_LINK_LOCAL_IPV6_ADJACENCY sid absent */
    sr = pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj(
            true, true, true, true, sid, &local_ipv6, local_if_id, &remote_ipv6, remote_if_id);
    compare_entries[4] = local_if_id;
    compare_entries[9] = remote_if_id;
    memcpy(&(compare_entries[0]), local_ipv6.__in6_u.__u6_addr32, sizeof(uint32_t) * 4);
    memcpy(&(compare_entries[5]), remote_ipv6.__in6_u.__u6_addr32, sizeof(uint32_t) * 4);
    verify_sid_nai("sr_linklocal_ipv6_adj", &sr->subobj.sr, compare_entries, 10);
    encode_ro_subobj(sr);
    verify_sid_nai_ntohl("sr_linklocal_ipv6_adj", &sr->subobj.sr, compare_entries, 10);
    free(sr);

    /* PCEP_SR_SUBOBJ_NAI_LINK_LOCAL_IPV6_ADJACENCY sid present */
    sr = pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj(
            true, false, true, true, sid, &local_ipv6, local_if_id, &remote_ipv6, remote_if_id);
    compare_entries[0] = sid;
    compare_entries[5] = local_if_id;
    compare_entries[10] = remote_if_id;
    memcpy(&(compare_entries[1]), local_ipv6.__in6_u.__u6_addr32, sizeof(uint32_t) * 4);
    memcpy(&(compare_entries[6]), remote_ipv6.__in6_u.__u6_addr32, sizeof(uint32_t) * 4);
    verify_sid_nai("sr_linklocal_ipv6_adj", &sr->subobj.sr, compare_entries, 11);
    encode_ro_subobj(sr);
    verify_sid_nai_ntohl("sr_linklocal_ipv6_adj", &sr->subobj.sr, compare_entries, 11);
    free(sr);
}

