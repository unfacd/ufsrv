/*
 * instrumentation_backend.h
 *
 *  Created on: 4 Jul 2015
 *      Author: ayman
 */

#ifndef INCLUDE_INSTRUMENTATION_BACKEND_H_
#define INCLUDE_INSTRUMENTATION_BACKEND_H_

struct InstrumentationBackend {
	int socket;
	char name_space[SBUF];
};
typedef struct InstrumentationBackend InstrumentationBackend;

int InstrumentationBackendServerInit (const char *host, int port);
InstrumentationBackend *InstrumentationBackendInit (const char *ns);
void InstrumentationBackendReset(InstrumentationBackend *);
int statsd_send(InstrumentationBackend *link, const char *message);

int statsd_count(InstrumentationBackend *link, char *stat, ssize_t value, float sample_rate);
int statsd_dec(InstrumentationBackend *link, char *stat, float sample_rate);
int statsd_inc(InstrumentationBackend *link, char *stat, float sample_rate);
int statsd_gauge(InstrumentationBackend *link, char *stat, ssize_t value);
int statsd_gauge_inc(InstrumentationBackend *link, char *stat_name,  ssize_t value);
int statsd_gauge_dec(InstrumentationBackend *link, char *stat_name,  ssize_t value);
int statsd_timing(InstrumentationBackend *link, char *stat, ssize_t ms);

#endif /* SRC_INCLUDE_INSTRUMENTATION_BACKEND_H_ */
