
#include <netdb.h> // gethostbyname
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "pcep_pcc_api.h"

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


void send_pce_req_message_sync(pcep_session *session)
{
    pcep_pce_request *pce_req = malloc(sizeof(pcep_pce_request));
    bzero(pce_req, sizeof(pcep_pce_request));

    pce_req->endpoint_ipVersion = IPPROTO_IP;
    /*
    inet_pton(AF_INET, "192.168.10.33", &(pce_req->src_endpoint_ip.srcV4Endpoint_ip));
    inet_pton(AF_INET, "172.100.80.56", &(pce_req->dst_endpoint_ip.dstV4Endpoint_ip));
    */
    /* These IPs are used with the Telefonica Open source PCE - it doesnt make sense they're in the same NW */
    inet_pton(AF_INET, "192.168.1.1", &(pce_req->src_endpoint_ip.srcV4Endpoint_ip));
    inet_pton(AF_INET, "192.168.1.3", &(pce_req->dst_endpoint_ip.dstV4Endpoint_ip));

    pcep_pce_reply *pce_reply = request_path_computation(session, pce_req, 1500);

    if (pce_reply->response_error)
    {
        fprintf(stderr, "ERROR pcep_pcc send_pce_req_message_sync response error\n");
    }
    else if (pce_reply->timed_out)
    {
        fprintf(stderr, "ERROR pcep_pcc send_pce_req_message_sync response timed-out\n");
    }
    else
    {
        printf("pcep_pcc send_pce_req_message_sync got a response, elapsed time [%d ms]\n",
                pce_reply->elapsed_time_milli_seconds);
    }

    free(pce_req);
    free(pce_reply);
}

void send_pce_req_message_async(pcep_session *session)
{
    pcep_pce_request *pce_req = malloc(sizeof(pcep_pce_request));
    bzero(pce_req, sizeof(pcep_pce_request));

    pce_req->endpoint_ipVersion = IPPROTO_IP;
    inet_pton(AF_INET, "192.168.1.33", &(pce_req->src_endpoint_ip.srcV4Endpoint_ip));
    inet_pton(AF_INET, "172.100.8.56", &(pce_req->dst_endpoint_ip.dstV4Endpoint_ip));

    pcep_pce_reply *pce_reply = request_path_computation_async(session, pce_req, 1500);

    bool retval;
    bool keep_checking = true;
    while (keep_checking)
    {
        retval = get_async_result(pce_reply);
        if (retval)
        {
            printf("pcep_pcc send_pce_req_message_async got a response, elapsed time [%d ms]\n",
                    pce_reply->elapsed_time_milli_seconds);
            keep_checking = false;
        }
        else
        {
            if (pce_reply->response_error)
            {
                fprintf(stderr, "ERROR pcep_pcc send_pce_req_message_async response error\n");
                keep_checking = false;
            }
            else if (pce_reply->timed_out)
            {
                fprintf(stderr, "ERROR pcep_pcc send_pce_req_message_async response timed-out\n");
                keep_checking = false;
            }
            else
            {
                /* sleep 250 milliseconds */
                struct timespec ts;
                ts.tv_sec = 0;
                ts.tv_nsec = 250 * 1000 * 1000;
                nanosleep(&ts, &ts);
                printf("pcep_pcc send_pce_req_message_async sleep while waiting for a response\n");
            }
        }
    }

    free(pce_req);
    free(pce_reply);
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
    pcep_session *session = connect_pce(config, &host_address);
    free(config);
    if (session == NULL)
    {
        fprintf(stderr, "Error in create_nbi_pcep_session.\n");
        return -1;
    }

    sleep(5);

    send_pce_req_message_async(session);
    send_pce_req_message_sync(session);

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

