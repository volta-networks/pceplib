/*
 * pcep_timers_event_loop.c
 *
 *  Created on: sep 16, 2019
 *      Author: brady
 */

#include <errno.h>
#include <malloc.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <strings.h>
#include <sys/select.h>

#include "pcep_utils_ordered_list.h"
#include "pcep_timer_internals.h"

/* For each expired timer: remove the timer from the list, call the
 * expire_handler, and free the timer. */
void walk_and_process_timers(pcep_timers_context *timers_context)
{
    pthread_mutex_lock(&timers_context->timer_list_lock);

    bool keep_walking = true;
    ordered_list_node *timer_node = timers_context->timer_list->head;
    time_t now = time(NULL);
    pcep_timer *timer_data;

    /* the timers are sorted by expire_time, so we will only
     * remove the top node each time through the loop */
    while (timer_node != NULL && keep_walking)
    {
        timer_data = (pcep_timer *) timer_node->data;
        if (timer_data->expire_time <= now)
        {
            timer_node = timer_node->next_node;
            ordered_list_remove_first_node(timers_context->timer_list);
            /* call the timer expired handler */
            timers_context->expire_handler(timer_data->data, timer_data->timer_id);
            free(timer_data);
        }
        else
        {
            keep_walking = false;
        }
    }

    pthread_mutex_unlock(&timers_context->timer_list_lock);
}


/* pcep_timers::initialize() will create a thread and invoke this method */
void *event_loop(void *context)
{
    if (context == NULL)
    {
        fprintf(stderr, "pcep_timers_event_loop cannot start event_loop with NULL data\n");
        return NULL;
    }

    printf("[%ld-%ld] Starting timers_event_loop thread\n", time(NULL), pthread_self());

    pcep_timers_context *timers_context = (pcep_timers_context *) context;
    struct timeval timer;
    int retval;

    while (timers_context->active)
    {
        /* check the timers every half second */
        timer.tv_sec = 0;
        timer.tv_usec = 500000;

        do
        {
            /* if the select() call gets interrupted, select() will set
             * the remaining time in timer, so we need to call it again.
             */
            retval = select(0, NULL, NULL, NULL, &timer);
        } while(retval != 0 && errno == EINTR);

        walk_and_process_timers(timers_context);
    }

    return NULL;
}
