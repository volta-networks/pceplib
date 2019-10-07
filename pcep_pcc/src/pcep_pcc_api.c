/*
 * pcep_pcc_api.c
 *
 *  Created on: sep 27, 2019
 *      Author: brady
 */

#include <limits.h>
#include <malloc.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "pcep-messages.h"
#include "pcep_pcc_api.h"

int request_id_ = 0;

/* simple util function implemented in pcep_session_logic.c */
extern int timespec_diff(struct timespec *start, struct timespec *stop);

int get_next_request_id()
{
    if (request_id_ == INT_MAX)
    {
        request_id_ = 0;
    }

    return request_id_++;
}


bool initialize_pcc()
{
    if (!run_session_logic())
    {
        fprintf(stderr, "Error initializing PCC session logic.\n");
        return false;
    }

    return true;
}


/* this function is blocking */
bool initialize_pcc_wait_for_completion()
{
    return run_session_logic_wait_for_completion();
}


bool destroy_pcc()
{
    if (!stop_session_logic())
    {
        fprintf(stderr, "Error stopping PCC session logic.\n");
        return false;
    }

    return true;
}


pcep_configuration *create_default_pcep_configuration()
{
    pcep_configuration *config = malloc(sizeof(pcep_configuration));
    config->keep_alive_seconds = DEFAULT_CONFIG_KEEP_ALIVE;
    config->dead_timer_seconds = DEFAULT_CONFIG_DEAD_TIMER;
    config->request_time_seconds = DEFAULT_CONFIG_REQUEST_TIME;
    config->max_unknown_messages = DEFAULT_CONFIG_MAX_UNKNOWN_MESSAGES;
    config->max_unknown_requests = DEFAULT_CONFIG_MAX_UNKNOWN_REQUESTS;

    return config;
}


pcep_session *connect_pce(pcep_configuration *config, struct in_addr *host)
{
    return connect_pce_with_port(config, host, PCEP_TCP_PORT);
}


pcep_session *connect_pce_with_port(pcep_configuration *config, struct in_addr *host, short port)
{
    return create_pcep_session(config, host, port);
}


void disconnect_pce(pcep_session *session)
{
    destroy_pcep_session(session);
}


/* synchronously request path computation, so this method will block
 * until the reply is available */
pcep_pce_reply *request_path_computation(pcep_session *session, pcep_pce_request *pce_req, int max_wait_milli_seconds)
{
    pcep_pce_reply *pce_reply = request_path_computation_async(session, pce_req, max_wait_milli_seconds);

    /* this call will block for at most max_wait_milli_seconds */
    wait_for_response_message(pce_reply->response);

    pce_reply->response_msg_list = pce_reply->response->response_msg_list;
    pce_reply->elapsed_time_milli_seconds =
            timespec_diff(&(pce_reply->response->time_request_registered),
                         &(pce_reply->response->time_response_received));
    destroy_response_message(pce_reply->response);
    pce_reply->response = NULL;

    return pce_reply;
}


/* asynchronously request path computation, call get_async_result()
 * with the returned request_id to get the result */
pcep_pce_reply *request_path_computation_async(pcep_session *session, pcep_pce_request *pce_req, int max_wait_milli_seconds)
{
    int request_id = get_next_request_id();

    /* RP flag bits: |O|B|R|Pri|
     * O - strict_loose - 1 bit
     * B - bidirectional - 1 bit
     * R - reOptimization - 1 bit
     * pri - priority - 3 bits */
    uint32_t rp_flags = 0;
    if (pce_req->rp_flag_loose_path)
    {
        rp_flags |= 0x20;
    }
    if (pce_req->rp_flag_bidirectional)
    {
        rp_flags |= 0x10;
    }
    if (pce_req->rp_flag_reoptimization)
    {
        rp_flags |= 0x08;
    }
    struct pcep_object_rp *rp = pcep_obj_create_rp(0, rp_flags, request_id);

    /* TODO currently only supporting IPv4 */
    struct pcep_object_endpoints_ipv4 *endpoints =
            pcep_obj_create_enpoint_ipv4(&(pce_req->src_endpoint_ip.srcV4Endpoint_ip),
                                         &(pce_req->dst_endpoint_ip.dstV4Endpoint_ip));

    int message_size =
            sizeof(struct pcep_header) +
            ntohs(rp->header.object_length) +
            ntohs(endpoints->header.object_length);

    /*
     * optional fields
     * first calculate the size needed for the buffer
     */
    if (pce_req->bandwidth != NULL)
    {
        message_size += ntohs(pce_req->bandwidth->header.object_length);
    }
    if (pce_req->lspa != NULL)
    {
        message_size += ntohs(pce_req->lspa->header.object_length);
    }
    if (pce_req->metrics != NULL)
    {
        message_size += ntohs(pce_req->metrics->header.object_length);
    }
    if (pce_req->rro_list != NULL)
    {
        message_size += ntohs(pce_req->rro_list->ero_hdr.header.object_length);
    }
    if (pce_req->iro_list != NULL)
    {
        message_size += ntohs(pce_req->iro_list->ero_hdr.header.object_length);
    }
    if (pce_req->load_balancing != NULL)
    {
        message_size += ntohs(pce_req->load_balancing->header.object_length);
    }

    /* allocate the buffer and copy the objects into it */
    char *message_buffer = malloc(message_size);
    bzero(message_buffer, message_size);

    /* common pcReq header
     * flags
     *  0 1 2 3 4 5 6 7
     * +-+-+-+-+-+-+-+-+
     * | ver |  flags  |
     * +-+-+-+-+-+-+-+-+ */
    struct pcep_header *hdr = (struct pcep_header *) message_buffer;
    hdr->ver_flags = 0x20; /* version 1 */
    hdr->length = htons(message_size);
    hdr->type = PCEP_TYPE_PCREQ;
    int index = sizeof(struct pcep_header);

    /* copy the RP */
    memcpy(message_buffer + index, rp, ntohs(rp->header.object_length));
    index += ntohs(rp->header.object_length);
    free(rp); /* free the memory allocated by the pcep_obj_create*() functions */

    /* copy the endpoints */
    memcpy(message_buffer + index, endpoints, ntohs(endpoints->header.object_length));
    index += ntohs(endpoints->header.object_length);
    free(endpoints);

    /* bandwidth */
    if (pce_req->bandwidth != NULL)
    {
        memcpy(message_buffer + index, pce_req->bandwidth, ntohs(pce_req->bandwidth->header.object_length));
        index += ntohs(pce_req->bandwidth->header.object_length);
        free(pce_req->bandwidth);
    }

    /* label Switch Path Attributes */
    if (pce_req->lspa != NULL)
    {
        memcpy(message_buffer + index, pce_req->lspa, ntohs(pce_req->lspa->header.object_length));
        index += ntohs(pce_req->lspa->header.object_length);
        free(pce_req->lspa);
    }

    /* metrics */
    if (pce_req->metrics != NULL)
    {
        memcpy(message_buffer + index, pce_req->metrics, ntohs(pce_req->metrics->header.object_length));
        index += ntohs(pce_req->metrics->header.object_length);
        free(pce_req->metrics);
    }

    /* RRO */
    if (pce_req->rro_list != NULL)
    {
        memcpy(message_buffer + index, pce_req->rro_list, ntohs(pce_req->rro_list->ero_hdr.header.object_length));
        index += ntohs(pce_req->rro_list->ero_hdr.header.object_length);
        free(pce_req->rro_list);
    }

    /* IRO */
    if (pce_req->iro_list != NULL)
    {
        // TODO should we instead look at the header in case there is a list of IRO's?
        memcpy(message_buffer + index, pce_req->iro_list, ntohs(pce_req->iro_list->ero_hdr.header.object_length));
        index += ntohs(pce_req->iro_list->ero_hdr.header.object_length);
        free(pce_req->iro_list);
    }

    /* load balancing */
    if (pce_req->load_balancing != NULL)
    {
        memcpy(message_buffer + index, pce_req->load_balancing, ntohs(pce_req->load_balancing->header.object_length));
        index += ntohs(pce_req->load_balancing->header.object_length);
        free(pce_req->load_balancing);
    }

    socket_comm_session_send_message(
            session->socket_comm_session,
            (const char *) message_buffer,
            ntohs(hdr->length));

    pcep_pce_reply *pce_reply = malloc(sizeof(pcep_pce_reply));
    pce_reply->elapsed_time_milli_seconds = 0;
    pce_reply->response_error = false;
    pce_reply->timed_out = false;
    pce_reply->response_msg_list = NULL;
    pce_reply->response =
            register_response_message(session, request_id, max_wait_milli_seconds);

    return pce_reply;
}


bool get_async_result(pcep_pce_reply *pce_reply)
{
    if (!query_response_message(pce_reply->response))
    {
        /* Its not ready yet, and nothing happened */
        return false;
    }

    if (pce_reply->response->response_status == RESPONSE_STATE_TIMED_OUT)
    {
        pce_reply->timed_out = true;
        return false;
    }

    if (pce_reply->response->response_status == RESPONSE_STATE_ERROR)
    {
        pce_reply->response_error = true;
        return false;
    }

    if (pce_reply->response->response_status == RESPONSE_STATE_READY)
    {
        pce_reply->response_msg_list = pce_reply->response->response_msg_list;
        pce_reply->elapsed_time_milli_seconds =
                timespec_diff(&(pce_reply->response->time_request_registered),
                             &(pce_reply->response->time_response_received));
        destroy_response_message(pce_reply->response);
        pce_reply->response = NULL;

        return true;
    }
    else
    {
        return false;
    }

}
