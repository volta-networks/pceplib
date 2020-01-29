/*
 * pcep_utils_logging.h
 *
 *  Created on: Dec 13, 2019
 *      Author: brady
 */

#ifndef PCEP_UTILS_INCLUDE_PCEP_UTILS_LOGGING_H_
#define PCEP_UTILS_INCLUDE_PCEP_UTILS_LOGGING_H_

#include <syslog.h> /* Logging levels */
#include <stdarg.h> /* va_list */

/*
 * The logging defined here i intended to provide the infrastructure to
 * be able to plug-in an external logger, primarily the FRR logger. There
 * will be a default internal logger implemented that will write to stdout,
 * but any other advanced logging features should be implemented externally.
 */

/* Only the following logging levels from syslog.h should be used:
 *
 *   LOG_DEBUG    - For all messages that are enabled by optional debugging
 *                  features, typically preceded by "if (IS...DEBUG...)"
 *   LOG_INFO     - Information that may be of interest, but
 *                  everything seems to be working properly.
 *   LOG_NOTICE   - Only for message pertaining to daemon startup or shutdown.
 *   LOG_WARNING  - Warning conditions: unexpected events, but the daemon
 *                  believes it can continue to operate correctly.
 *   LOG_ERR      - Error situations indicating malfunctions.
 *                  Probably requires attention.
 */


/* The signature of this logger function is the same as the FRR logger */
typedef int (*pcep_logger_func)(int, const char*, va_list);
void register_logger(pcep_logger_func logger);

/* These functions only take affect when using the internal stdout logger */
void set_logging_level(int level);
int get_logging_level();

/* Log messages either to a previously registered
 * logger or to the internal default stdout logger. */
void pcep_log(int priority, const char *format, ...);

#endif /* PCEP_UTILS_INCLUDE_PCEP_UTILS_LOGGING_H_ */
