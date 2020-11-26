/*
 * backendconfig_type.h
 *
 *  Created on: 24 Jul 2015
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_BACKENDCONFIG_TYPE_H_
#define SRC_INCLUDE_BACKENDCONFIG_TYPE_H_

#include <sys/time.h>//struct timeval
#include <ufsrv_core/cache_backend/persistance_type.h>

	struct BackendConfig {
	    unsigned type;
	    char *backend_label;

	    struct {
	        const char *host;
	        int port;
	        struct timeval timeout;
	    } con_tcp;
	    struct {
	        const char *path;
	    } con_unix;

	    PersistanceBackend cache_backend;
	};

#endif /* SRC_INCLUDE_BACKENDCONFIG_TYPE_H_ */
