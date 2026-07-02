/**
 * Copyright (C) 2015-2024 unfacd works
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

/**
* @file cloud_authenticator_descriptor.h
* @brief Data and state information for holding and interacting with cloud authorization tokens.
*/

#ifndef UFSRV_CLOUD_AUTHENTICATOR_DESCRIPTOR_TYPE_H
#define UFSRV_CLOUD_AUTHENTICATOR_DESCRIPTOR_TYPE_H

#include <stdbool.h>
#include <pthread.h>
#include <gpc_service_request_descriptor.h>

/**
 * Determine blocking semantics when accessing the authorization token.
 */
enum AccessBlockingMode {
    BLOCKING, ///> if the producer is busy updating the token, block until token is refreshed
    NON_BLOCKING,
    FORCED, ///> return current value regardless of update state. Don't do this unless you know what you want to do.
    UNINITIALISED ///> token was in uninitialised state when accessed
};

#define AS_CLOUD_AUTHORIZATION_DESCRIPTOR(x) ((CloudAuthorizationDescriptor *)(x))

struct CloudAuthorizationDescriptor {
    bool is_initialised; ///> Set when token is successfully retrieved
    char *authorization_token; ///> aAuthorization token as returned by the authentication service
    time_t when_last_refresh; ///> last time token was refreshed expressed with classic unix time
    const GpcServiceRequestDescriptor *service_request_descriptor_ptr;
    struct {
        pthread_rwlock_t rwlock; ///> Multiple-readers, single-writer lock, controlling access to authorization token during token refresh
    } concurrency_control;
};

typedef struct CloudAuthorizationDescriptor CloudAuthorizationDescriptor;

/**
 * State descriptor returned for token requests
 */
struct CloudAuthorizationTokenState {
    enum AccessBlockingMode access_blocking_mode; ///< state in which the token was retrieved
    char *authorization_token;
    time_t when_last_refresh;
};

typedef struct CloudAuthorizationTokenState CloudAuthorizationTokenState;

#endif //UFSRV_CLOUD_AUTHENTICATOR_DESCRIPTOR_TYPE_H
