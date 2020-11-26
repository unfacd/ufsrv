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

#ifndef UFSRV_REST_REQUEST_DESCRIPTOR_TYPE_H
#define UFSRV_REST_REQUEST_DESCRIPTOR_TYPE_H

#include <session_type.h>
#include <http_session_type.h>
#include <json/json.h>

/**
 * Generalised mechanism for callback executions in the context of processing REST endpoints
 */

typedef enum RestRequestHandlingState {
  SUCCESS_STATE,
  ERROR_STATE

} RestRequestHandlingState;

typedef struct RestRequestDescriptor {
  struct {
    ClientContextData *ctx_data;
  } handler;
  struct {
    InstanceContextForSession *session_ctx;
    HttpSession *http_ptr;
    json_object *jobj;
  } requester;
} RestRequestDescriptor;

typedef int (*on_request_handled)(RestRequestHandlingState, RestRequestDescriptor *);

#endif //UFSRV_REST_REQUEST_DESCRIPTOR_TYPE_H
