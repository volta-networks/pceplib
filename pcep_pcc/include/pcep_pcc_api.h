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


/*
 * Public PCEPlib PCC API
 */

#ifndef PCEPPCC_INCLUDE_PCEPPCCAPI_H_
#define PCEPPCC_INCLUDE_PCEPPCCAPI_H_

#include <stdbool.h>

#include "pcep_session_logic.h"

#define DEFAULT_PCEP_TCP_PORT 4189
#define DEFAULT_CONFIG_KEEP_ALIVE 30
#define DEFAULT_CONFIG_DEAD_TIMER DEFAULT_CONFIG_KEEP_ALIVE * 4
#define DEFAULT_CONFIG_REQUEST_TIME 30
#define DEFAULT_CONFIG_MAX_UNKNOWN_REQUESTS 5
#define DEFAULT_CONFIG_MAX_UNKNOWN_MESSAGES 5
#define DEFAULT_TCP_CONNECT_TIMEOUT_MILLIS 250

/* Acceptable MIN and MAX values used in deciding if the PCEP
 * Open received from a PCE should be accepted or rejected. */
#define DEFAULT_MIN_CONFIG_KEEP_ALIVE 5
#define DEFAULT_MAX_CONFIG_KEEP_ALIVE 120
#define DEFAULT_MIN_CONFIG_DEAD_TIMER DEFAULT_MIN_CONFIG_KEEP_ALIVE * 4
#define DEFAULT_MAX_CONFIG_DEAD_TIMER DEFAULT_MAX_CONFIG_KEEP_ALIVE * 4


/*
 * PCEP PCC library initialization/teardown functions
 */

bool initialize_pcc();
/* this function is blocking */
bool initialize_pcc_wait_for_completion();
bool destroy_pcc();


/*
 * PCEP session functions
 */

pcep_configuration *create_default_pcep_configuration();
void destroy_pcep_configuration(pcep_configuration *config);

/* Uses the standard PCEP TCP src and dest port = 4189.
 * To use a specific dest or src port, set them other than 0 in the pcep_configuration.
 * If src_ip is not set, INADDR_ANY will be used. */
pcep_session *connect_pce(pcep_configuration *config, struct in_addr *pce_ip);
pcep_session *connect_pce_ipv6(pcep_configuration *config, struct in6_addr *pce_ip);
void disconnect_pce(pcep_session *session);
void send_message(pcep_session *session, struct pcep_message *msg, bool free_after_send);

void dump_pcep_session_counters(pcep_session *session);
void reset_pcep_session_counters(pcep_session *session);

/*
 * Event Queue functions
 */

/* Returns true if the queue is empty, false otherwise */
bool event_queue_is_empty();

/* Return the number of events on the queue, 0 if empty */
uint32_t event_queue_num_events_available();

/* Return the next event on the queue, NULL if empty */
struct pcep_event *event_queue_get_event();

/* Free the PCEP Event resources, including the PCEP message */
void destroy_pcep_event(struct pcep_event *event);

const char *get_event_type_str(int event_type);


#endif /* PCEPPCC_INCLUDE_PCEPPCCAPI_H_ */
