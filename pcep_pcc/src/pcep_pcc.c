
#include <netdb.h> // gethostbyname
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "pcep_pcc_api.h"
#include "pcep_utils_double_linked_list.h"
#include "pcep_utils_logging.h"

/*
 * PCEP PCC design spec:
 * https://docs.google.com/presentation/d/1DYc3ZhYA1c_qg9A552HjhneJXQKdh_yrKW6v3NRYPtnbw/edit?usp=sharing
 */

bool pcc_active_ = true;
pcep_session *session = NULL;

void handle_signal_action(int sig_number)
{
    if (sig_number == SIGINT)
    {
        pcep_log(LOG_INFO, "SIGINT was caught!");
        pcc_active_ = false;
    }
    else if (sig_number == SIGUSR1)
    {
        pcep_log(LOG_INFO, "SIGUSR1 was caught, dumping counters");
        dump_pcep_session_counters(session);
    }
    else if (sig_number == SIGUSR2)
    {
        pcep_log(LOG_INFO, "SIGUSR2 was caught, reseting counters");
        reset_pcep_session_counters(session);
    }
}


int setup_signals()
{
    struct sigaction sa;
    bzero(&sa, sizeof(struct sigaction));
    sa.sa_handler = handle_signal_action;
    if (sigaction(SIGINT, &sa, 0) != 0)
    {
        perror("sigaction()");
        return -1;
    }

    if (sigaction(SIGUSR1, &sa, 0) != 0)
    {
        perror("sigaction()");
        return -1;
    }

    if (sigaction(SIGUSR2, &sa, 0) != 0)
    {
        perror("sigaction()");
        return -1;
    }

    return 0;
}

void send_pce_path_request_message(pcep_session *session)
{
    struct in_addr src_ipv4;
    struct in_addr dst_ipv4;
    inet_pton(AF_INET, "1.2.3.4", &src_ipv4);
    inet_pton(AF_INET, "10.20.30.40", &dst_ipv4);

    struct pcep_object_rp *rp_object = pcep_obj_create_rp(1, false, false, false, 42, NULL);
    struct pcep_object_endpoints_ipv4 *ep_object = pcep_obj_create_endpoint_ipv4(&src_ipv4, &dst_ipv4);

    struct pcep_message *path_request = pcep_msg_create_request(rp_object,  ep_object, NULL);
    send_message(session,  path_request, true);
}

void send_pce_report_message(pcep_session *session)
{
    double_linked_list *report_list = dll_initialize();

    /* SRP Path Setup Type TLV */
    struct pcep_object_tlv_path_setup_type *pst_tlv = pcep_tlv_create_path_setup_type(SR_TE_PST);
    double_linked_list *srp_tlv_list = dll_initialize();
    dll_append(srp_tlv_list, pst_tlv);

    /*
     * Create the SRP object
     */
    uint32_t srp_id_number = 0x10203040;
    struct pcep_object_header *obj =
            (struct pcep_object_header*) pcep_obj_create_srp(false, srp_id_number, srp_tlv_list);
    if (obj == NULL)
    {
        pcep_log(LOG_WARNING, "send_pce_report_message SRP object was NULL");
        return;
    }
    dll_append(report_list, obj);

    /* LSP Symbolic path name TLV */
    char symbolic_path_name[] = "second-default";
    struct pcep_object_tlv_symbolic_path_name *spn_tlv = pcep_tlv_create_symbolic_path_name(symbolic_path_name, 14);
    double_linked_list *lsp_tlv_list = dll_initialize();
    dll_append(lsp_tlv_list, spn_tlv);

    /* LSP IPv4 LSP ID TLV */
    struct in_addr ipv4_tunnel_sender;
    struct in_addr ipv4_tunnel_endpoint;
    inet_pton(AF_INET, "9.9.1.1", &ipv4_tunnel_sender);
    inet_pton(AF_INET, "9.9.2.1", &ipv4_tunnel_endpoint);
    struct pcep_object_tlv_ipv4_lsp_identifier *ipv4_lsp_id_tlv =
            pcep_tlv_create_ipv4_lsp_identifiers(&ipv4_tunnel_sender, &ipv4_tunnel_endpoint, 42, 1, NULL);
    dll_append(lsp_tlv_list, ipv4_lsp_id_tlv);

    /*
     * Create the LSP object
     */
    uint32_t plsp_id = 42;
    enum pcep_lsp_operational_status lsp_status = PCEP_LSP_OPERATIONAL_ACTIVE;
    bool c_flag = false;  /* Lsp was created by PcInitiate msg */
    bool a_flag = false;  /* Admin state, active / inactive */
    bool r_flag = false;  /* true if LSP has been removed */
    bool s_flag = true;   /* Synchronization */
    bool d_flag = false;  /* Delegate LSP to PCE */
    obj = (struct pcep_object_header *)
            pcep_obj_create_lsp(plsp_id, lsp_status, c_flag, a_flag, r_flag, s_flag, d_flag, lsp_tlv_list);
    if (obj == NULL)
    {
        pcep_log(LOG_WARNING, "send_pce_report_message LSP object was NULL");
        return;
    }
    dll_append(report_list, obj);

    /* Create 2 ERO NONAI sub-objects */
    double_linked_list* ero_subobj_list = dll_initialize();
    struct pcep_ro_subobj_sr *sr_subobj_nonai1 = pcep_obj_create_ro_subobj_sr_nonai(false, 503808, true, true);
    dll_append(ero_subobj_list, sr_subobj_nonai1);

    struct pcep_ro_subobj_sr *sr_subobj_nonai2 = pcep_obj_create_ro_subobj_sr_nonai(false, 1867776, true, true);
    dll_append(ero_subobj_list, sr_subobj_nonai2);

    /* Create ERO IPv4 node sub-object */
    struct in_addr sr_subobj_ipv4;
    inet_pton(AF_INET, "9.9.9.1", &sr_subobj_ipv4);
    struct pcep_ro_subobj_sr *sr_subobj_ipv4node =
            pcep_obj_create_ro_subobj_sr_ipv4_node(false, false, false, true, 16060, &sr_subobj_ipv4);
    if (sr_subobj_ipv4node == NULL)
    {
        pcep_log(LOG_WARNING, "send_pce_report_message ERO sub-object was NULL");
        return;
    }
    dll_append(ero_subobj_list, sr_subobj_ipv4node);

    /*
     * Create the ERO object
     */
    obj = (struct pcep_object_header *) pcep_obj_create_ero(ero_subobj_list);
    if (obj == NULL)
    {
        pcep_log(LOG_WARNING, "send_pce_report_message ERO object was NULL");
        return;
    }
    dll_append(report_list, obj);

    /* Create and send the report message */
    struct pcep_message *report_msg = pcep_msg_create_report(report_list);
    send_message(session, report_msg, true);
}

void print_queue_event(struct pcep_event *event)
{
    pcep_log(LOG_INFO, "[%ld-%ld] Received Event: type [%s] on session [%d] occurred at [%ld]",
            time(NULL), pthread_self(),
            get_event_type_str(event->event_type),
            event->session->session_id,
            event->event_time);

    if (event->event_type == MESSAGE_RECEIVED)
    {
        pcep_log(LOG_INFO, "\t Event message type [%s]", get_message_type_str(event->message->msg_header->type));
    }
}

int main(int argc, char **argv)
{
    pcep_log(LOG_NOTICE, "[%ld-%ld] starting pcc_pcep example client",
            time(NULL), pthread_self());

    setup_signals();

    /* blocking call:
     * if (!run_session_logic_wait_for_completion()) */

    if (!initialize_pcc())
    {
        pcep_log(LOG_ERR, "Error initializing PCC.");
        return -1;
    }

    struct hostent *host_info = gethostbyname("localhost");
    if(host_info == NULL) {
        pcep_log(LOG_ERR, "Error getting IP address.");
        return -1;
    }

    struct in_addr host_address;
    memcpy(&host_address, host_info->h_addr, host_info->h_length);

    pcep_configuration *config = create_default_pcep_configuration();
    config->pcep_msg_versioning->draft_ietf_pce_segment_routing_07 = true;
    //config->pcep_msg_versioning->draft_ietf_pce_segment_routing_07 = false;
    config->src_pcep_port = 4999;
    session = connect_pce(config, &host_address);
    if (session == NULL)
    {
        pcep_log(LOG_WARNING, "Error in connect_pce.");
        destroy_pcep_configuration(config);
        return -1;
    }

    sleep(5);

    send_pce_report_message(session);
    /*send_pce_path_request_message(session);*/

    while(pcc_active_)
    {
        if (event_queue_is_empty() == false)
        {
            struct pcep_event *event = event_queue_get_event();
            print_queue_event(event);
            destroy_pcep_event(event);
        }

        sleep(5);
    }


    pcep_log(LOG_NOTICE, "Disconnecting from PCE");
    disconnect_pce(session);
    destroy_pcep_configuration(config);

    if (!destroy_pcc())
    {
        pcep_log(LOG_NOTICE, "Error stopping PCC.");
    }

    return 0;
}

