/*
 * pcep_timers.c
 *
 *  Created on: sep 16, 2019
 *      Author: brady
 *
 *  Implementation of public API functions.
 */

#include <limits.h>
#include <pthread.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "pcep_timer_internals.h"
#include "pcep_timers.h"
#include "pcep_utils_logging.h"
#include "pcep_utils_memory.h"
#include "pcep_utils_ordered_list.h"

/* TODO should we just return this from initialize_timers
 *      instead of storing it globally here??
 *      I guess it just depends on if we will ever need more than one */
pcep_timers_context *timers_context_ = NULL;
static int timer_id_ = 0;

/* simple compare method callback used by pcep_utils_ordered_list
 * for ordered list insertion. */
int timer_list_node_compare(void *list_entry, void *new_entry)
{
    /* return:
     *   < 0  if new_entry < list_entry
     *   == 0 if new_entry == list_entry (new_entry will be inserted after list_entry)
     *   > 0  if new_entry > list_entry */
    return ((pcep_timer *) new_entry)->expire_time - ((pcep_timer *) list_entry)->expire_time;
}


/* simple compare method callback used by pcep_utils_ordered_list
 * ordered_list_remove_first_node_equals2 to remove a timer based on
 * its timer_id. */
int timer_list_node_timer_id_compare(void *list_entry, void *new_entry)
{
    return ((pcep_timer *) new_entry)->timer_id - ((pcep_timer *) list_entry)->timer_id;
}


/* internal util method */
static pcep_timers_context *create_timers_context_()
{
    if (timers_context_ == NULL)
    {
        timers_context_ = pceplib_malloc(PCEPLIB_INFRA, sizeof(pcep_timers_context));
        memset(timers_context_, 0, sizeof(pcep_timers_context));
        timers_context_->active = false;
    }

    return timers_context_;
}


bool initialize_timers(timer_expire_handler expire_handler)
{
    if (expire_handler == NULL)
    {
        /* Cannot have a NULL handler function */
        return false;
    }

    timers_context_ = create_timers_context_();

    if (timers_context_->active == true)
    {
        /* already initialized */
        return false;
    }

    timers_context_->active = true;
    timers_context_->timer_list = ordered_list_initialize(timer_list_node_compare);
    timers_context_->expire_handler = expire_handler;

    if (pthread_mutex_init(&(timers_context_->timer_list_lock), NULL) != 0)
    {
        pcep_log(LOG_ERR, "ERROR initializing timers, cannot initialize the mutex");
        return false;
    }

    if(pthread_create(&(timers_context_->event_loop_thread), NULL, event_loop, timers_context_))
    {
        pcep_log(LOG_ERR, "ERROR initializing timers, cannot initialize the thread");
        return false;
    }

    return true;
}


/*
 * This function is only used to tear_down the timer data.
 * Only the timer data is deleted, not the list itself,
 * which is deleted by ordered_list_destroy().
 */
void free_all_timers(pcep_timers_context *timers_context)
{
    pthread_mutex_lock(&timers_context->timer_list_lock);

    ordered_list_node *timer_node = timers_context->timer_list->head;

    while (timer_node != NULL)
    {
        if (timer_node->data != NULL)
        {
            pceplib_free(PCEPLIB_INFRA, timer_node->data);
        }
        timer_node = timer_node->next_node;
    }

    pthread_mutex_unlock(&timers_context->timer_list_lock);
}


bool teardown_timers()
{
    if (timers_context_ == NULL)
    {
        pcep_log(LOG_WARNING, "Trying to teardown the timers, but they are not initialized");
        return false;
    }

    if (timers_context_->active == false)
    {
        pcep_log(LOG_WARNING, "Trying to teardown the timers, but they are not active");
        return false;
    }

    timers_context_->active = false;
    pthread_join(timers_context_->event_loop_thread, NULL);

    /* TODO this doesnt buld
     * Instead of calling pthread_join() which could block if the thread
     * is blocked, try joining for at most 1 second.
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 1;
    int retval = pthread_timedjoin_np(timers_context_->event_loop_thread, NULL, &ts);
    if (retval != 0)
    {
        pcep_log(LOG_WARNING, "thread did not stop after 1 second waiting on it.");
    }
    */

    free_all_timers(timers_context_);
    ordered_list_destroy(timers_context_->timer_list);

    if (pthread_mutex_destroy(&(timers_context_->timer_list_lock)) != 0)
    {
        pcep_log(LOG_WARNING, "Trying to teardown the timers, cannot destroy the mutex");
    }

    pceplib_free(PCEPLIB_INFRA, timers_context_);
    timers_context_ = NULL;

    return true;
}


int get_next_timer_id()
{
    if (timer_id_ == INT_MAX)
    {
        timer_id_ = 0;
    }

    return timer_id_++;
}

int create_timer(uint16_t sleep_seconds, void *data)
{
    if (timers_context_ == NULL)
    {
        pcep_log(LOG_WARNING, "Trying to create a timer: the timers have not been initialized");
        return -1;
    }

    pcep_timer *timer = pceplib_malloc(PCEPLIB_INFRA, sizeof(pcep_timer));
    memset(timer, 0, sizeof(pcep_timer));
    timer->data = data;
    timer->sleep_seconds = sleep_seconds;
    timer->expire_time = time(NULL) + sleep_seconds;
    timer->timer_id = get_next_timer_id();

    pthread_mutex_lock(&timers_context_->timer_list_lock);

    /* implemented in pcep_utils_ordered_list.c */
    if (ordered_list_add_node(timers_context_->timer_list, timer) == NULL)
    {
        pceplib_free(PCEPLIB_INFRA, timer);
        pthread_mutex_unlock(&timers_context_->timer_list_lock);
        pcep_log(LOG_WARNING, "Trying to create a timer, cannot add the timer to the timer list");

        return -1;
    }

    pthread_mutex_unlock(&timers_context_->timer_list_lock);

    return timer->timer_id;
}


bool cancel_timer(int timer_id)
{
    static pcep_timer compare_timer;

    if (timers_context_ == NULL)
    {
        pcep_log(LOG_WARNING, "Trying to cancel a timer: the timers have not been initialized");
        return false;
    }

    pthread_mutex_lock(&timers_context_->timer_list_lock);

    compare_timer.timer_id = timer_id;
    pcep_timer *timer_toRemove = ordered_list_remove_first_node_equals2(
            timers_context_->timer_list, &compare_timer, timer_list_node_timer_id_compare);
    if (timer_toRemove == NULL)
    {
        pthread_mutex_unlock(&timers_context_->timer_list_lock);
        pcep_log(LOG_WARNING, "Trying to cancel a timer [%d] that does not exist", timer_id);
        return false;
    }
    pceplib_free(PCEPLIB_INFRA, timer_toRemove);

    pthread_mutex_unlock(&timers_context_->timer_list_lock);

    return true;
}

bool reset_timer(int timer_id)
{
    static pcep_timer compare_timer;

    if (timers_context_ == NULL)
    {
        pcep_log(LOG_WARNING, "Trying to reset a timer: the timers have not been initialized");

        return false;
    }

    pthread_mutex_lock(&timers_context_->timer_list_lock);

    compare_timer.timer_id = timer_id;
    pcep_timer *timer_toReset = ordered_list_remove_first_node_equals2(
            timers_context_->timer_list, &compare_timer, timer_list_node_timer_id_compare);
    if (timer_toReset == NULL)
    {
        pthread_mutex_unlock(&timers_context_->timer_list_lock);
        pcep_log(LOG_WARNING, "Trying to reset a timer that does not exist");

        return false;
    }

    timer_toReset->expire_time = time(NULL) + timer_toReset->sleep_seconds;
    if (ordered_list_add_node(timers_context_->timer_list, timer_toReset) == NULL)
    {
        pceplib_free(PCEPLIB_INFRA, timer_toReset);
        pthread_mutex_unlock(&timers_context_->timer_list_lock);
        pcep_log(LOG_WARNING, "Trying to reset a timer, cannot add the timer to the timer list");

        return false;
    }

    pthread_mutex_unlock(&timers_context_->timer_list_lock);

    return true;
}

