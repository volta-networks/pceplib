/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */


#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <CUnit/TestDB.h>

/* functions to be tested from pcep-messages.c */
extern void pcep_messages_test_setup(void);
extern void pcep_messages_test_teardown(void);
extern void test_pcep_msg_create_open(void);
extern void test_pcep_msg_create_request(void);
extern void test_pcep_msg_create_request_svec(void);
extern void test_pcep_msg_create_reply_nopath(void);
extern void test_pcep_msg_create_reply(void);
extern void test_pcep_msg_create_close(void);
extern void test_pcep_msg_create_error(void);
extern void test_pcep_msg_create_keepalive(void);
extern void test_pcep_msg_create_report(void);
extern void test_pcep_msg_create_update(void);
extern void test_pcep_msg_create_initiate(void);

/* functions to be tested from pcep-tlvs.c */
extern void pcep_tlvs_test_setup(void);
extern void pcep_tlvs_test_teardown(void);
extern void test_pcep_tlv_create_stateful_pce_capability(void);
extern void test_pcep_tlv_create_speaker_entity_id(void);
extern void test_pcep_tlv_create_lsp_db_version(void);
extern void test_pcep_tlv_create_path_setup_type(void);
extern void test_pcep_tlv_create_path_setup_type_capability(void);
extern void test_pcep_tlv_create_sr_pce_capability(void);
extern void test_pcep_tlv_create_symbolic_path_name(void);
extern void test_pcep_tlv_create_ipv4_lsp_identifiers(void);
extern void test_pcep_tlv_create_ipv6_lsp_identifiers(void);
extern void test_pcep_tlv_create_lsp_error_code(void);
extern void test_pcep_tlv_create_rsvp_ipv4_error_spec(void);
extern void test_pcep_tlv_create_rsvp_ipv6_error_spec(void);
extern void test_pcep_tlv_create_srpag_pol_id_ipv4(void);
extern void test_pcep_tlv_create_srpag_pol_id_ipv6(void);
extern void test_pcep_tlv_create_srpag_pol_name(void);
extern void test_pcep_tlv_create_srpag_cp_id(void);
extern void test_pcep_tlv_create_srpag_cp_pref(void);
extern void test_pcep_tlv_create_nopath_vector(void);
extern void test_pcep_tlv_create_arbitrary(void);

/* functions to be tested from pcep-objects.c */
extern void pcep_objects_test_setup(void);
extern void pcep_objects_test_teardown(void);
extern void test_pcep_obj_create_open(void);
extern void test_pcep_obj_create_open_with_tlvs(void);
extern void test_pcep_obj_create_rp(void);
extern void test_pcep_obj_create_nopath(void);
extern void test_pcep_obj_create_endpoint_ipv4(void);
extern void test_pcep_obj_create_endpoint_ipv6(void);
extern void test_pcep_obj_create_association_ipv4(void);
extern void test_pcep_obj_create_association_ipv6(void);
extern void test_pcep_obj_create_bandwidth(void);
extern void test_pcep_obj_create_metric(void);
extern void test_pcep_obj_create_lspa(void);
extern void test_pcep_obj_create_svec(void);
extern void test_pcep_obj_create_error(void);
extern void test_pcep_obj_create_close(void);
extern void test_pcep_obj_create_srp(void);
extern void test_pcep_obj_create_lsp(void);
extern void test_pcep_obj_create_vendor_info(void);
extern void test_pcep_obj_create_ero(void);
extern void test_pcep_obj_create_rro(void);
extern void test_pcep_obj_create_iro(void);
extern void test_pcep_obj_create_ro_subobj_ipv4(void);
extern void test_pcep_obj_create_ro_subobj_ipv6(void);
extern void test_pcep_obj_create_ro_subobj_unnum(void);
extern void test_pcep_obj_create_ro_subobj_32label(void);
extern void test_pcep_obj_create_ro_subobj_asn(void);
extern void test_pcep_obj_create_ro_subobj_sr_nonai(void);
extern void test_pcep_obj_create_ro_subobj_sr_ipv4_node(void);
extern void test_pcep_obj_create_ro_subobj_sr_ipv6_node(void);
extern void test_pcep_obj_create_ro_subobj_sr_ipv4_adj(void);
extern void test_pcep_obj_create_ro_subobj_sr_ipv6_adj(void);
extern void test_pcep_obj_create_ro_subobj_sr_unnumbered_ipv4_adj(void);
extern void test_pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj(void);

/* functions to be tested from pcep-tools.c */
extern void test_pcep_msg_read_pcep_initiate(void);
extern void test_pcep_msg_read_pcep_initiate2(void);
extern void test_pcep_msg_read_pcep_update(void);
extern void test_pcep_msg_read_pcep_open(void);
extern void test_pcep_msg_read_pcep_open_initiate(void);
extern void test_validate_message_header(void);
extern void test_validate_message_objects(void);
extern void test_validate_message_objects_invalid(void);
extern void test_pcep_msg_read_pcep_open_cisco_pce(void);
extern void test_pcep_msg_read_pcep_update_cisco_pce(void);
extern void test_pcep_msg_read_pcep_report_cisco_pcc(void);
extern void test_pcep_msg_read_pcep_initiate_cisco_pcc(void);


int main(int argc, char **argv)
{
    CU_initialize_registry();

    CU_pSuite messages_suite = CU_add_suite_with_setup_and_teardown(
            "PCEP Messages Test Suite",
            NULL, NULL, /* suite setup and cleanup function pointers */
            pcep_messages_test_setup, pcep_messages_test_teardown);
    CU_add_test(messages_suite, "test_pcep_msg_create_open", test_pcep_msg_create_open);
    CU_add_test(messages_suite, "test_pcep_msg_create_request", test_pcep_msg_create_request);
    CU_add_test(messages_suite, "test_pcep_msg_create_request_svec", test_pcep_msg_create_request_svec);
    CU_add_test(messages_suite, "test_pcep_msg_create_reply_nopath", test_pcep_msg_create_reply_nopath);
    CU_add_test(messages_suite, "test_pcep_msg_create_reply", test_pcep_msg_create_reply);
    CU_add_test(messages_suite, "test_pcep_msg_create_close", test_pcep_msg_create_close);
    CU_add_test(messages_suite, "test_pcep_msg_create_error", test_pcep_msg_create_error);
    CU_add_test(messages_suite, "test_pcep_msg_create_keepalive", test_pcep_msg_create_keepalive);
    CU_add_test(messages_suite, "test_pcep_msg_create_report", test_pcep_msg_create_report);
    CU_add_test(messages_suite, "test_pcep_msg_create_update", test_pcep_msg_create_update);
    CU_add_test(messages_suite, "test_pcep_msg_create_initiate", test_pcep_msg_create_initiate);

    CU_pSuite tlvs_suite = CU_add_suite_with_setup_and_teardown(
            "PCEP TLVs Test Suite",
            NULL, NULL, /* suite setup and cleanup function pointers */
            pcep_tlvs_test_setup, pcep_tlvs_test_teardown);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_stateful_pce_capability", test_pcep_tlv_create_stateful_pce_capability);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_speaker_entity_id", test_pcep_tlv_create_speaker_entity_id);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_lsp_db_version", test_pcep_tlv_create_lsp_db_version);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_path_setup_type", test_pcep_tlv_create_path_setup_type);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_path_setup_type_capability", test_pcep_tlv_create_path_setup_type_capability);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_sr_pce_capability", test_pcep_tlv_create_sr_pce_capability);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_symbolic_path_name", test_pcep_tlv_create_symbolic_path_name);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_ipv4_lsp_identifiers", test_pcep_tlv_create_ipv4_lsp_identifiers);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_ipv6_lsp_identifiers", test_pcep_tlv_create_ipv6_lsp_identifiers);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_srpag_pol_id_ipv4", test_pcep_tlv_create_srpag_pol_id_ipv4);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_srpag_pol_id_ipv6", test_pcep_tlv_create_srpag_pol_id_ipv6);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_srpag_pol_name", test_pcep_tlv_create_srpag_pol_name);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_srpag_cp_id", test_pcep_tlv_create_srpag_cp_id);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_srpag_cp_pref", test_pcep_tlv_create_srpag_cp_pref);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_lsp_error_code", test_pcep_tlv_create_lsp_error_code);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_rsvp_ipv4_error_spec", test_pcep_tlv_create_rsvp_ipv4_error_spec);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_rsvp_ipv6_error_spec", test_pcep_tlv_create_rsvp_ipv6_error_spec);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_nopath_vector", test_pcep_tlv_create_nopath_vector);
    CU_add_test(tlvs_suite, "test_pcep_tlv_create_arbitrary", test_pcep_tlv_create_arbitrary);

    CU_pSuite objects_suite = CU_add_suite_with_setup_and_teardown(
            "PCEP Objects Test Suite",
            NULL, NULL, /* suite setup and cleanup function pointers */
            pcep_objects_test_setup, pcep_objects_test_teardown);
    CU_add_test(objects_suite, "test_pcep_obj_create_open", test_pcep_obj_create_open);
    CU_add_test(objects_suite, "test_pcep_obj_create_open", test_pcep_obj_create_open_with_tlvs);
    CU_add_test(objects_suite, "test_pcep_obj_create_rp", test_pcep_obj_create_rp);
    CU_add_test(objects_suite, "test_pcep_obj_create_nopath", test_pcep_obj_create_nopath);
    CU_add_test(objects_suite, "test_pcep_obj_create_enpoint_ipv4", test_pcep_obj_create_endpoint_ipv4);
    CU_add_test(objects_suite, "test_pcep_obj_create_enpoint_ipv6", test_pcep_obj_create_endpoint_ipv6);
    CU_add_test(objects_suite, "test_pcep_obj_create_association_ipv4", test_pcep_obj_create_association_ipv4);
    CU_add_test(objects_suite, "test_pcep_obj_create_association_ipv6", test_pcep_obj_create_association_ipv6);
    CU_add_test(objects_suite, "test_pcep_obj_create_bandwidth", test_pcep_obj_create_bandwidth);
    CU_add_test(objects_suite, "test_pcep_obj_create_metric", test_pcep_obj_create_metric);
    CU_add_test(objects_suite, "test_pcep_obj_create_lspa", test_pcep_obj_create_lspa);
    CU_add_test(objects_suite, "test_pcep_obj_create_svec", test_pcep_obj_create_svec);
    CU_add_test(objects_suite, "test_pcep_obj_create_error", test_pcep_obj_create_error);
    CU_add_test(objects_suite, "test_pcep_obj_create_close", test_pcep_obj_create_close);
    CU_add_test(objects_suite, "test_pcep_obj_create_srp", test_pcep_obj_create_srp);
    CU_add_test(objects_suite, "test_pcep_obj_create_lsp", test_pcep_obj_create_lsp);
    CU_add_test(objects_suite, "test_pcep_obj_create_vendor_info", test_pcep_obj_create_vendor_info);

    CU_add_test(objects_suite, "test_pcep_obj_create_ero", test_pcep_obj_create_ero);
    CU_add_test(objects_suite, "test_pcep_obj_create_rro", test_pcep_obj_create_rro);
    CU_add_test(objects_suite, "test_pcep_obj_create_iro", test_pcep_obj_create_iro);
    CU_add_test(objects_suite, "test_pcep_obj_create_ro_subobj_ipv4", test_pcep_obj_create_ro_subobj_ipv4);
    CU_add_test(objects_suite, "test_pcep_obj_create_ro_subobj_ipv6", test_pcep_obj_create_ro_subobj_ipv6);
    CU_add_test(objects_suite, "test_pcep_obj_create_ro_subobj_unnum", test_pcep_obj_create_ro_subobj_unnum);
    CU_add_test(objects_suite, "test_pcep_obj_create_ro_subobj_32label", test_pcep_obj_create_ro_subobj_32label);
    CU_add_test(objects_suite, "test_pcep_obj_create_ro_subobj_asn", test_pcep_obj_create_ro_subobj_asn);

    CU_add_test(objects_suite, "test_pcep_obj_create_ro_subobj_sr_nonai", test_pcep_obj_create_ro_subobj_sr_nonai);
    CU_add_test(objects_suite, "test_pcep_obj_create_ro_subobj_sr_ipv4_node", test_pcep_obj_create_ro_subobj_sr_ipv4_node);
    CU_add_test(objects_suite, "test_pcep_obj_create_ro_subobj_sr_ipv6_node", test_pcep_obj_create_ro_subobj_sr_ipv6_node);
    CU_add_test(objects_suite, "test_pcep_obj_create_ro_subobj_sr_ipv4_adj", test_pcep_obj_create_ro_subobj_sr_ipv4_adj);
    CU_add_test(objects_suite, "test_pcep_obj_create_ro_subobj_sr_ipv6_adj", test_pcep_obj_create_ro_subobj_sr_ipv6_adj);
    CU_add_test(objects_suite, "test_pcep_obj_create_ro_subobj_sr_unnumbered_ipv4_adj",
            test_pcep_obj_create_ro_subobj_sr_unnumbered_ipv4_adj);
    CU_add_test(objects_suite, "test_pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj",
            test_pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj);

    CU_pSuite tools_suite = CU_add_suite("PCEP Tools Test Suite", NULL, NULL);
    CU_add_test(tools_suite, "test_pcep_msg_read_pcep_initiate", test_pcep_msg_read_pcep_initiate);
    CU_add_test(tools_suite, "test_pcep_msg_read_pcep_initiate2", test_pcep_msg_read_pcep_initiate2);
    CU_add_test(tools_suite, "test_pcep_msg_read_pcep_update", test_pcep_msg_read_pcep_update);
    CU_add_test(tools_suite, "test_pcep_msg_read_pcep_open", test_pcep_msg_read_pcep_open);
    CU_add_test(tools_suite, "test_pcep_msg_read_pcep_open_initiate", test_pcep_msg_read_pcep_open_initiate);
    CU_add_test(tools_suite, "test_validate_message_header", test_validate_message_header);
    CU_add_test(tools_suite, "test_validate_message_objects", test_validate_message_objects);
    CU_add_test(tools_suite, "test_validate_message_objects_invalid", test_validate_message_objects_invalid);
    CU_add_test(tools_suite, "test_pcep_msg_read_pcep_open_cisco_pce", test_pcep_msg_read_pcep_open_cisco_pce);
    CU_add_test(tools_suite, "test_pcep_msg_read_pcep_update_cisco_pce", test_pcep_msg_read_pcep_update_cisco_pce);
    CU_add_test(tools_suite, "test_pcep_msg_read_pcep_report_cisco_pcc", test_pcep_msg_read_pcep_report_cisco_pcc);
    CU_add_test(tools_suite, "test_pcep_msg_read_pcep_initiate_cisco_pcc", test_pcep_msg_read_pcep_initiate_cisco_pcc);

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_pRunSummary run_summary = CU_get_run_summary();
    int result = run_summary->nTestsFailed;
    CU_cleanup_registry();

    return result;
}
