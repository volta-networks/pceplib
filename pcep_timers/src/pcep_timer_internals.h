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
 *  Timer definitions to be used internally by the pcep_timers library.
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
