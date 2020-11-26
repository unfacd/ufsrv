/**
 * Copyright (C) 2015-2020 unfacd works
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef INCLUDE_INSTRUMENTATION_BACKEND_H_
#define INCLUDE_INSTRUMENTATION_BACKEND_H_

#include <standard_c_includes.h>
#include <standard_defs.h>
#include "instrumentation_backend_type.h"

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
