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
 * Public API for pcep_timers
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

/*
 * Initialize the timers module.
 * The timer_expire_handler function pointer will be called each time a timer expires.
 * Return true for successful initialization, false otherwise.
 */
bool initialize_timers(timer_expire_handler expire_handler);

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

#endif /* PCEPTIMERS_H_ */
