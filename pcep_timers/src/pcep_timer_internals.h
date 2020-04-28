/*
 * pcep_timer.h
 *
 *  Timer definitions to be used internally by the pcep_timers library.
 *
 *  Created on: sep 16, 2019
 *      Author: brady
 */

#ifndef PCEPTIMERINTERNALS_H_
#define PCEPTIMERINTERNALS_H_

#include <pthread.h>

#include "pcep_utils_ordered_list.h"
#include "pcep_timers.h"


typedef struct pcep_timer_
{
    time_t expire_time;
    uint16_t sleep_seconds;
    int timer_id;
    void *data;
    void *external_timer;

} pcep_timer;

typedef struct pcep_timers_context_
{
    ordered_list_handle *timer_list;
    bool active;
    timer_expire_handler expire_handler;
    pthread_t event_loop_thread;
    pthread_mutex_t timer_list_lock;
    void *external_timer_infra_data;
    ext_timer_create timer_create_func;
    ext_timer_cancel timer_cancel_func;

} pcep_timers_context;

/* functions implemented in pcep_timers_loop.c */
void *event_loop(void *context);


#endif /* PCEPTIMERINTERNALS_H_ */
