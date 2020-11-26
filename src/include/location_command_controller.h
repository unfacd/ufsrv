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

//
// Created by devops on 8/7/19.
//

#ifndef UFSRV_LOCATION_COMMAND_CONTROLLER_H
#define UFSRV_LOCATION_COMMAND_CONTROLLER_H

#include <recycler/instance_type.h>
#include <session_type.h>
#include <ufsrvresult_type.h>
#include <command_controllers.h>

#include <WebSocketMessage.pb-c.h>
#include <ufsrv_core/SignalService.pb-c.h>

UFSRVResult *CommandCallbackControllerLocationCommand (InstanceContextForSession *ctx_ptr_local_user, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);

UFSRVResult *IsUserAllowedToChangeLocation (InstanceContextForSession *ctx_ptr,  DataMessage *data_msg_received,  WebSocketMessage *wsm_ptr_received, UfsrvEvent *event_ptr, CallbackCommandMarshaller command_marshaller, unsigned long fence_call_flags);

#endif //UFSRV_LOCATION_COMMAND_CONTROLLER_H
