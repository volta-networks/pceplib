
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

/*
 * PCEP PCC design spec:
 * https://docs.google.com/presentation/d/1DYc3ZhYA1c_qg9A552HjhneJXQKdh_yrKW6v3NRYPtnbw/edit?usp=sharing
 */

void handle_signal_action(int sig_number)
{
    if (sig_number == SIGINT)
    {
        printf("SIGINT was caught!\n");
        // TODO do something here
    }
    else if (sig_number == SIGPIPE)
    {
        printf("SIGPIPE was caught!\n");
        // TODO do something here
    }

    exit(1);
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
    if (sigaction(SIGPIPE, &sa, 0) != 0)
    {
        perror("sigaction()");
        return -1;
    }

    return 0;
}

void send_pce_report_message(pcep_session *session)
{
    uint32_t srp_id_number = 0x10203040;
    //uint32_t plsp_id = 0x00050607;
    uint32_t plsp_id = 42;
    enum pcep_lsp_operational_status lsp_status = PCEP_LSP_OPERATIONAL_ACTIVE;
    bool c_flag = true;  /* Lsp was created by PcInitiate msg */
    bool a_flag = true;  /* Admin state, active / inactive */
    bool r_flag = false; /* true if LSP has been removed */
    bool s_flag = true;  /* Syncronization */
    bool d_flag = true;  /* Delegate LSP to PCE */
    struct in_addr sr_subobj_ipv4;
    double_linked_list *report_list = dll_initialize();

    /* Create the SRP object */
    struct pcep_object_header *obj =
            (struct pcep_object_header*) pcep_obj_create_srp(false, srp_id_number, NULL);
    if (obj == NULL)
    {
        fprintf(stderr, "send_pce_report_message SRP object was NULL\n");
        return;
    }
    dll_append(report_list, obj);

    /* Create the LSP object */
    obj = (struct pcep_object_header *)
            pcep_obj_create_lsp(plsp_id, lsp_status, c_flag, a_flag, r_flag, s_flag, d_flag, NULL);
    if (obj == NULL)
    {
        fprintf(stderr, "send_pce_report_message LSP object was NULL\n");
        return;
    }
    dll_append(report_list, obj);

    /* Create the ERO sub-object */
    double_linked_list* ero_subobj_list = dll_initialize();
    inet_pton(AF_INET, "9.9.9.1", &(sr_subobj_ipv4.s_addr));
    struct pcep_object_ro_subobj *subobj =
            pcep_obj_create_ro_subobj_sr_ipv4_node(false, false, false, true, 16060, &sr_subobj_ipv4);
    if (subobj == NULL)
    {
        fprintf(stderr, "send_pce_report_message ERO sub-object was NULL\n");
        return;
    }
    dll_append(ero_subobj_list, subobj);

    /* Create the ERO object */
    obj = (struct pcep_object_header *) pcep_obj_create_ero(ero_subobj_list);
    if (obj == NULL)
    {
        fprintf(stderr, "send_pce_report_message ERO object was NULL\n");
        return;
    }
    dll_append(report_list, obj);

    /* Create and send the report message */
    struct pcep_header *report_msg = pcep_msg_create_report(report_list);
    send_message(session, report_msg, true);

    dll_destroy_with_data(report_list);
    dll_destroy_with_data(ero_subobj_list);
}


int main(int argc, char **argv)
{
    printf("[%ld-%ld] starting pcc_pcep example client\n",
            time(NULL), pthread_self());

    setup_signals();

    /* blocking call:
     * if (!run_session_logic_wait_for_completion()) */

    if (!initialize_pcc())
    {
        fprintf(stderr, "Error initializing PCC.\n");
        return -1;
    }

    struct hostent *host_info = gethostbyname("localhost");
    if(host_info == NULL) {
        fprintf(stderr, "Error getting IP address.\n");
        return -1;
    }

    struct in_addr host_address;
    memcpy(&host_address, host_info->h_addr, host_info->h_length);

    pcep_configuration *config = create_default_pcep_configuration();
    config->use_pcep_sr_draft07 = true;
    pcep_session *session = connect_pce(config, &host_address);
    free(config);
    if (session == NULL)
    {
        fprintf(stderr, "Error in connect_pce.\n");
        return -1;
    }

    sleep(5);

    send_pce_report_message(session);

    /* Sleep for a while to let the timers expire */
    sleep(30);

    printf("Disconnecting from PCE\n");
    disconnect_pce(session);

    if (!destroy_pcc())
    {
        fprintf(stderr, "Error stopping PCC.\n");
    }

    return 0;
}

