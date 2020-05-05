/*
 * pcep_timers.h
 *
 * Public API for pcep_timers
 *
 *  Created on: sep 16, 2019
 *      Author: brady
 */

#ifndef PCEPTIMERS_H_
#define PCEPTIMERS_H_

#include <stdbool.h>
#include <stdint.h>

#define TIMER_ID_NOT_SET -1

/* Function pointer to be called when timers expire.
 * Parameters:
 *    void *data - passed into create_timer
 *    int timer_id - the timer_id returned by create_timer
 */
typedef void (*timer_expire_handler)(void *, int);

/* Function pointer when an external timer infrastructure is used */
typedef void (*ext_timer_create)(void *infra_data, void **timer, int seconds, void *data);
typedef void (*ext_timer_cancel)(void **timer);

/*
 * Initialize the timers module.
 * The timer_expire_handler function pointer will be called each time a timer expires.
 * Return true for successful initialization, false otherwise.
 */
bool initialize_timers(timer_expire_handler expire_handler);

/*
 * Initialize the timers module with an external back-end infrastructure, like FRR.
 */
bool initialize_timers_external_infra(
        timer_expire_handler expire_handler,
        void *external_timer_infra_data,
        ext_timer_create timer_create_func,
        ext_timer_cancel timer_cancel_func);

/*
 * Teardown the timers module.
 */
bool teardown_timers();

/*
 * Create a new timer for "sleep_seconds" seconds.
 * If the timer expires before being cancelled, the timer_expire_handler
 * passed to initialize_timers() will be called with the pointer to "data".
 * Returns a timer_id <= 0 that can be used to cancel_timer.
 * Returns < 0 on error.
 */
int create_timer(uint16_t sleep_seconds, void *data);

/*
 * Cancel a timer created with create_timer().
 * Returns true if the timer was found and cancelled, false otherwise.
 */
bool cancel_timer(int timer_id);

/*
 * Reset an previously created timer, maintaining the same timer_id.
 * Returns true if the timer was found and reset, false otherwise.
 */
bool reset_timer(int timer_id);

/*
 * If an external timer infra like FRR is used, then this function
 * will be called when the timers expire in the external infra.
 */
void pceplib_external_timer_expire_handler(void *data);

#endif /* PCEPTIMERS_H_ */
