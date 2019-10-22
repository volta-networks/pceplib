/*
 * pcep_pcc_api.h
 *
 *  Created on: sep 27, 2019
 *      Author: brady
 */

#ifndef PCEPPCC_INCLUDE_PCEPPCCAPI_H_
#define PCEPPCC_INCLUDE_PCEPPCCAPI_H_

#include <stdbool.h>

#include "pcep_session_logic.h"

#define PCEP_TCP_PORT 4189
#define DEFAULT_CONFIG_KEEP_ALIVE 30
#define DEFAULT_CONFIG_DEAD_TIMER DEFAULT_CONFIG_KEEP_ALIVE * 4
#define DEFAULT_CONFIG_REQUEST_TIME 30
#define DEFAULT_CONFIG_MAX_UNKNOWN_REQUESTS 5
#define DEFAULT_CONFIG_MAX_UNKNOWN_MESSAGES 5


typedef struct pcep_pce_reply_
{
    bool timed_out;
    bool response_error;
    int elapsed_time_milli_seconds;
    pcep_message *response_msg;
    /* internally used field */
    pcep_message_response *response;

} pcep_pce_reply;


bool initialize_pcc();
/* this function is blocking */
bool initialize_pcc_wait_for_completion();

bool destroy_pcc();

pcep_configuration *create_default_pcep_configuration();

/* use the standard PCEP TCP port = 4189 */
pcep_session *connect_pce(pcep_configuration *config, struct in_addr *pce_ip);
pcep_session *connect_pce_with_port(pcep_configuration *config, struct in_addr *pce_ip, short port);

void disconnect_pce(pcep_session *session);

/* Synchronously request path computation routes. This method will block
 * until the reply is available, or until max_wait_milli_seconds is reached.
 * For the objects in pcep_pce_req, use the pcep_obj_create_*() functions
 * defined in pcep-objects.h. Memory allocated by these creation functions
 * will be freed internally.
 * Returns a pcep_pce_reply when the response is available, or NULL on timeout */
pcep_pce_reply *request_path_computation(pcep_session *session, pcep_pce_request *pce_req, int max_wait_milli_seconds);

/* Asynchronously request path computation routes. This method will return
 * immediately and the response can be obtained by polling get_async_result()
 * with the pcep_pce_reply returned from this function.
 * Returns a pcep_pce_reply to be used with get_async_result() */
pcep_pce_reply *request_path_computation_async(pcep_session *session, pcep_pce_request *pce_req, int max_wait_milli_seconds);

/* Check if a response is available yet, using the pcep_pce_reply returned
 * from request_path_computation_async().
 * Returns true if the response is ready and fills in the following fields:
 * - pcep_pce_reply->elapsed_time_milli_seconds
 * - pcep_pce_reply->response_msg_list
 * Returns false for one of the following 3 reasons:
 * - if the reply is not ready yet
 * - if there is an error, sets pcep_pce_reply->response_error = true
 * - if there is a timeout, sets pcep_pce_reply->timed_out = true
 */
bool get_async_result(pcep_pce_reply *pce_reply);


#endif /* PCEPPCC_INCLUDE_PCEPPCCAPI_H_ */
