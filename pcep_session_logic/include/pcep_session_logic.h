/*
 * pcep_session_logic.h
 *
 *  Created on: sep 20, 2019
 *      Author: brady
 */

#ifndef INCLUDE_PCEPSESSIONLOGIC_H_
#define INCLUDE_PCEPSESSIONLOGIC_H_

#include <stdbool.h>

#include "pcep-encoding.h"
#include "pcep_socket_comm.h"
#include "pcep-objects.h"
#include "pcep-tools.h"
#include "pcep_utils_queue.h"

#define PCEP_TCP_PORT 4189

typedef struct pcep_configuration_
{
    /* These are the configuration values that will
     * be sent to the PCE in the PCEP Open message */
    int keep_alive_seconds;
    int dead_timer_seconds;
    int request_time_seconds;

    /* These are the acceptable ranges of values received by
     * the PCE in the initial PCEP Open Message. If a value is
     * received outside of these ranges, then the Open message
     * will be rejected. */
    int min_keep_alive_seconds;
    int max_keep_alive_seconds;
    int min_dead_timer_seconds;
    int max_dead_timer_seconds;

    /* If more than this many unknown messages/requests are received
     * per minute, then the session will be closed. */
    int max_unknown_messages;
    int max_unknown_requests;

    /* Maximum amount of time to wait to connect to the
     * PCE TCP socket before failing, in milliseconds. */
    uint32_t socket_connect_timeout_millis;

    /* Set if the PCE/PCC will support stateful PCE LSP Updates
     * according to RCF8231, section 7.1.1, defaults to true.
     * Will cause an additional TLV to be sent from the PCC in
     * the PCEP Open */
    bool support_stateful_pce_lsp_update;

    /* RFC 8281: I-bit, the PCC allows instantiation of an LSP by a PCE */
    bool support_pce_lsp_instantiation;

    /* RFC 8232: S-bit, the PCC will include the LSP-DB-VERSION
     * TLV in each LSP object */
    bool support_include_db_version;

    /* Only set if support_include_db_version is true and if the LSP-DB
     * survived a restart and is available. If this has a value other than
     * 0, then a LSP-DB-VERSION TLV will be sent in the OPEN object. This
     * value will be copied over to the pcep_session upon init. */
    uint64_t lsp_db_version;

    /* RFC 8232: T-bit, the PCE can trigger resynchronization of
     * LSPs at any point in the life of the session */
    bool support_lsp_triggered_resync;

    /* RFC 8232: D-bit, the PCEP speaker allows incremental (delta)
     * State Synchronization */
    bool support_lsp_delta_sync;

    /* RFC 8232: F-bit, the PCE SHOULD trigger initial (first)
     * State Synchronization */
    bool support_pce_triggered_initial_sync;

    /* draft-ietf-pce-segment-routing-16: Send a SR PCE Capability
     * sub-TLV in a Path Setup Type Capability TLV with a PST = 1,
     * Path is setup using SR TE. */
    bool support_sr_te_pst;
    /* Used in the SR PCE Capability sub-TLV */
    bool pcc_can_resolve_nai_to_sid;
    /* Used in the SR TE Capability sub-TLV, 0 means there are no max sid limits */
    uint8_t max_sid_depth;

    /* If set to 0, then the default 4189 PCEP port will be used */
    uint16_t dst_pcep_port;

    /* If set to 0, then the default 4189 PCEP port will be used.
     * This is according to the RFC5440, Section 5 */
    uint16_t src_pcep_port;

    union src_ip {
        struct in_addr  src_ipv4;
        struct in6_addr src_ipv6;
    } src_ip;
    bool is_src_ipv6;

    struct pcep_versioning *pcep_msg_versioning;

} pcep_configuration;


typedef enum pcep_session_state_
{
    SESSION_STATE_UNKNOWN = 0,
    SESSION_STATE_INITIALIZED = 1,
    SESSION_STATE_PCEP_CONNECTING = 2,
    SESSION_STATE_PCEP_CONNECTED = 3,
    SESSION_STATE_WAIT_PCREQ = 4,
    SESSION_STATE_IDLE = 5  /* Only used in conjunction with SESSION_STATE_WAIT_PCREQ */

} pcep_session_state;


typedef struct pcep_session_
{
    int session_id;
    pcep_session_state session_state;
    int timer_id_open_keep_wait;
    int timer_id_pc_req_wait;
    int timer_id_dead_timer;
    int timer_id_keep_alive;
    bool pce_open_received;
    bool pce_open_rejected;
    bool pce_open_accepted;
    bool pcc_open_rejected;
    bool pcc_open_accepted;
    bool stateful_pce;
    time_t time_connected;
    uint64_t lsp_db_version;
    queue_handle *num_unknown_messages_time_queue;
    /* set this flag when finalizing the session */
    bool destroy_session_after_write;
    pcep_socket_comm_session *socket_comm_session;
    /* Configuration sent from the PCC to the PCE */
    pcep_configuration pcc_config;
    /* Configuration received from the PCE, to be used in the PCC */
    pcep_configuration pce_config;
    struct counters_group *pcep_session_counters;

} pcep_session;


typedef enum pcep_event_type
{
    MESSAGE_RECEIVED = 0,
    PCE_CLOSED_SOCKET = 1,
    PCE_SENT_PCEP_CLOSE = 2,
    PCE_DEAD_TIMER_EXPIRED = 3,
    PCE_OPEN_KEEP_WAIT_TIMER_EXPIRED = 4,
    PCC_CONNECTED_TO_PCE = 100,
    PCC_CONNECTION_FAILURE = 101,
    PCC_PCEP_SESSION_CLOSED = 102,
    PCC_RCVD_INVALID_OPEN = 103,
    PCC_SENT_INVALID_OPEN = 104,
    PCC_RCVD_MAX_INVALID_MSGS = 105,
    PCC_RCVD_MAX_UNKOWN_MSGS = 106

} pcep_event_type;


typedef struct pcep_event
{
    enum pcep_event_type event_type;
    time_t event_time;
    struct pcep_message *message;
    pcep_session *session;

} pcep_event;


typedef struct pcep_event_queue
{
    queue_handle *event_queue;
    pthread_mutex_t event_queue_mutex;

} pcep_event_queue;


bool run_session_logic();

bool run_session_logic_wait_for_completion();

bool stop_session_logic();

/* Uses the standard PCEP TCP dest port = 4189 and an ephemeral src port.
 * To use a specific dest or src port, set them other than 0 in the pcep_configuration. */
pcep_session *create_pcep_session(pcep_configuration *config, struct in_addr *pce_ip);
pcep_session *create_pcep_session_ipv6(pcep_configuration *config, struct in6_addr *pce_ip);

/* Send a PCEP close for this pcep_session */
void close_pcep_session(pcep_session *session);
void close_pcep_session_with_reason(pcep_session *session, enum pcep_close_reason);

/* Destroy the PCEP session, a PCEP close should have
 * already been sent with close_pcep_session() */
void destroy_pcep_session(pcep_session *session);

void pcep_session_cancel_timers(pcep_session *session);

/* Increments transmitted message counters, additionally counters for the objects,
 * sub-objects, and TLVs in the message will be incremented.  Received counters
 * are incremented internally. */
void increment_message_tx_counters(pcep_session *session, struct pcep_message *message);

#endif /* INCLUDE_PCEPSESSIONLOGIC_H_ */
