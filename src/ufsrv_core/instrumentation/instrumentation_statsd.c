/**
 * Copyright (C) 2015-2019 unfacd works
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <ufsrv_core/instrumentation/instrumentation_backend.h>
#include <nportredird.h>

extern ufsrv *const masterptr;
static int 	should_send(float sample_rate);
static void statsd_prepare (InstrumentationBackend *link, char *stat_name, const char *delta_sign, ssize_t stat_value, const char *type, float sample_rate, char *message, size_t buflen, int lf);
static int 	send_stat(InstrumentationBackend *link, char *stat_name, const char *delta_sign, ssize_t stat_value, const char *type, float sample_rate);
/* will change the original string */
static void cleanup(char *stat);


//this server definition is shared across all invocations to statsd
int
InstrumentationBackendServerInit (const char *host, int port)
{
	memset(&masterptr->instrumentation_backend_server, 0, sizeof(masterptr->instrumentation_backend_server));
	masterptr->instrumentation_backend_server.sin_family = AF_INET;
	masterptr->instrumentation_backend_server.sin_port = htons(port);

	struct addrinfo *result = NULL, hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;

	int error;
	if ((error = getaddrinfo(host, NULL, &hints, &result))) {
		syslog(LOG_ERR, "InstrumentationBackendServerInit COULD NOT invoke 'getaddrinfo' on BackendInstrumentation....");
		return errno;
	}

	memcpy(&(masterptr->instrumentation_backend_server.sin_addr), &((struct sockaddr_in*)result->ai_addr)->sin_addr, sizeof(struct in_addr));
	freeaddrinfo(result);

	syslog(LOG_ERR, "InstrumentationBackendServerInit SUCCESSFULLY INITIALISED InstrumentationBackendServer %s:%d....", host, port);

    return 1;

}

InstrumentationBackend *
InstrumentationBackendInit (const char *ns)
{
	InstrumentationBackend *temp=calloc(1, sizeof(InstrumentationBackend));

	if ((temp->socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		syslog(LOG_ERR, "InstrumentationBackendInit COULD NOT create socket for BackendInstrumentation....");

		return NULL;
	}

	if (IS_STR_LOADED(ns)) {
		strncpy(temp->name_space, ns, SBUF-1);
	} else {
		snprintf(temp->name_space, SBUF-1, "%s-%d", masterptr->server_class, masterptr->serverid_by_user);
	}

	return temp;

}

void
InstrumentationBackendReset(InstrumentationBackend *link)
{
  if (link->socket != -1) {
    close (link->socket);
    link->socket = -1;
  }

  free(link);
}

static int should_send(float sample_rate)
{
  if (sample_rate < 1.0) {
      float p = ((float)random() / RAND_MAX);
      return sample_rate > p;
  } else {
      return 1;
  }
}

/* will change the original string */
__attribute__((unused)) static void
cleanup(char *stat_name)
{
    char *p;
    for (p = stat_name; *p; p++) {
        if (*p == ':' || *p == '|' || *p == '@') {
            *p = '_';
        }
    }
}

//inventory:+2|g
static void
statsd_prepare (InstrumentationBackend *link, char *stat_name, const char *delta_sign, ssize_t stat_value, const char *type, float sample_rate, char *message, size_t buflen, int lf)
{
  //save some cycles. This is invoked in a controlled environment: we never include invalid characters in stat names
  //cleanup(stat_name);

  if (likely(sample_rate == 1.0)) {
      snprintf(message, buflen, "%s.%s:%s%zd|%s%s", link->name_space, stat_name, delta_sign, stat_value, type, lf ? "\n" : "");
  } else {
      snprintf(message, buflen, "%s.%s:%s%zd|%s|@%.2f%s", link->name_space, stat_name, delta_sign, stat_value, type, sample_rate, lf ? "\n" : "");
  }
}

static int
send_stat(InstrumentationBackend *link, char *stat_name, const char *delta_sign, ssize_t stat_value, const char *type, float sample_rate)
{
  char message[SMBUF];
  if (!should_send(sample_rate)) {
    return 0;
  }

  statsd_prepare(link, stat_name, delta_sign, stat_value, type, sample_rate, message, SMBUF, 1);

  return statsd_send(link, message);
}

int
statsd_send(InstrumentationBackend *link, const char *message)
{
  int slen = sizeof(masterptr->instrumentation_backend_server);

  if (sendto(link->socket, message, strlen(message), 0, (struct sockaddr *) &masterptr->instrumentation_backend_server, slen) == -1) {
    perror("sendto");
    return -1;
  }

  return 0;
}

/* public interface */
int
statsd_count(InstrumentationBackend *link, char *stat_name, ssize_t stat_value, float sample_rate)
{
    return send_stat(link, stat_name, "", stat_value, "c", sample_rate);
}

int
statsd_dec(InstrumentationBackend *link, char *stat_name, float sample_rate)
{
    return statsd_count(link, stat_name, -1, sample_rate);
}

int
statsd_inc(InstrumentationBackend *link, char *stat_name, float sample_rate)
{
    return statsd_count(link, stat_name, 1, sample_rate);
}

/**
 *  supports deltas as per statsite server:
 *  inventory:100|g
		inventory:-5|g
		inventory:+2|g
 */
int
statsd_gauge(InstrumentationBackend *link, char *stat_name, ssize_t value)
{
    return send_stat(link, stat_name, "", value, "g", 1.0);
}

int
statsd_gauge_inc(InstrumentationBackend *link, char *stat_name, ssize_t value)
{
    return send_stat(link, stat_name, "+", value, "g", 1.0);
}

int
statsd_gauge_dec(InstrumentationBackend *link, char *stat_name, ssize_t value)
{
    return send_stat(link, stat_name, "-", value, "g", 1.0);
}

//inventory:+2|g
int
statsd_timing(InstrumentationBackend *link, char *stat_name, ssize_t ms)
{
    return send_stat(link, stat_name, "", ms, "ms", 1.0);
}
