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

#ifndef UFSRV_FENCE_COMMAND_CONTROLLER_H
#define UFSRV_FENCE_COMMAND_CONTROLLER_H

#include <ufsrvmsg_core/SignalService.pb-c.h>
#include <ufsrvmsg_core/include/ufsrvresult_type.h>
#include <ufsrvmsg_core/fence/fence_type.h>
#include <ufsrvmsg_core/fence/fence_state_descriptor_type.h>
#include <include/WebSocketMessage.pb-c.h>

typedef void (*CallbackRestoreFenceValue)(FenceStateDescriptor *fence_state_ptr, FenceRecord *fence_record_ptr);

UFSRVResult *HandleFenceCommandError(InstanceContextForSession *ctx_ptr, FenceStateDescriptor *fence_state_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr, int rescode, FenceCommand__CommandTypes command_type, CallbackRestoreFenceValue restore_callback);

#endif //UFSRV_FENCE_COMMAND_CONTROLLER_H
