/*

 Copyright (c) 2015-2026 unfacd works

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.

 */

/*
 * backendconfig_type.h
 *
 *  Created on: 24 Jul 2015
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_BACKENDCONFIG_TYPE_H_
#define SRC_INCLUDE_BACKENDCONFIG_TYPE_H_

#include <sys/time.h>//struct timeval
#include "ufsrv_core/cache_backend/persistance_type.h"

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
