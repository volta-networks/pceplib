/*
 * PcepTimers.h
 *
 * Public API for PcepTimers
 *
 *  Created on: Sep 16, 2019
 *      Author: brady
 */

#ifndef PCEPTIMERS_H_
#define PCEPTIMERS_H_

#include <stdbool.h>

#define TIMER_ID_NOT_SET -1

/* Function pointer to be called when timers expire.
 * Parameters:
 *    void *data - passed into createTimer
 *    int timerId - the timerId returned by createTimer
 */
typedef void (*timerExpireHandler)(void *, int);

/*
 * Initialize the timers module.
 * The timerExpireHandler function pointer will be called each time a timer expires.
 * Return true for successful initialization, false otherwise.
 */
bool initializeTimers(timerExpireHandler expireHandler);

/*
 * Teardown the timers module.
 */
bool teardownTimers();

/*
 * Create a new timer for "sleepSeconds" seconds.
 * If the timer expires before being cancelled, the timerExpireHandler
 * passed to initializeTimers() will be called with the pointer to "data".
 * Returns a timerId <= 0 that can be used to cancelTimer.
 * Returns < 0 on error.
 */
int createTimer(int sleepSeconds, void *data);

/*
 * Cancel a timer created with createTimer().
 * Returns true if the timer was found and cancelled, false otherwise.
 */
bool cancelTimer(int timerId);

/*
 * Reset an previously created timer, maintaining the same timerId.
 * Returns true if the timer was found and reset, false otherwise.
 */
bool resetTimer(int timerId);

#endif /* PCEPTIMERS_H_ */
