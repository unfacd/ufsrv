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

#ifndef SRC_INCLUDE_COMMAND_CONTROLLERS_H_
#define SRC_INCLUDE_COMMAND_CONTROLLERS_H_

#include <command_base_context_type.h>
#include <ufsrvresult_type.h>
#include <ufsrv_core/fence/fence_type.h>
#include <ufsrv_core/fence/fence_state_descriptor_type.h>
#include <session_type.h>
#include <incoming_message_descriptor_type.h>

//DO NOT INCLUDE ANY OF xxx_command_controller.h files here

#include <ufsrv_core/SignalService.pb-c.h>
#include <ufsrvwebsock/include/WebSocketMessage.pb-c.h>


//todo: this style is to be phased out in favour of one defined below
typedef UFSRVResult * (*CallbackCommandMarshaller)(InstanceContextForSession *ctx_ptr, ClientContextData *ctx_data_ptr, DataMessage *data_msg_ptr_received, WebSocketMessage *wsm_ptr_received, UfsrvEvent *event_ptr);
#define _INVOKE_COMMAND_MARSHALLER(command_marshaller, ctx_ptr, ctx_data_ptr, data_msg_ptr_received,  wsm_ptr_received, event_ptr) return (*command_marshaller)(ctx_ptr, CLIENT_CTX_DATA((ctx_data_ptr)), data_msg_ptr_received, wsm_ptr_received, event_ptr)

typedef UFSRVResult * (*CommandMarshallerCallback)(CommandBaseContext *);
#define INVOKE_COMMAND_MARSHALLER(command_marshaller, command_context) (*command_marshaller)((command_context))

UFSRVResult *CommandCallbackControllerFenceCommand (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
UFSRVResult *CommandCallbackControllerCallCommand (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
UFSRVResult *CommandCallbackControllerUserCommand (InstanceHolderForSession *instance_sesn_ptr_local_user, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);

UFSRVResult *CommandCallbackControllerReceiptCommand (InstanceContextForSession *ctx_ptr_local_user, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);

UFSRVResult *MarshalFenceJoinToUser (InstanceContextForSession *, FenceStateDescriptor *fence_state_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
UFSRVResult *MarshalFenceJoinInvitedToUser (InstanceContextForSession *, FenceStateDescriptor *fence_state_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
UFSRVResult *MarshalFenceStateSync (InstanceContextForSession *ctx_ptr, FenceStateDescriptor *fstate_ptr, WebSocketMessage *, DataMessage *data_msg_ptr, unsigned long call_flags);
UFSRVResult *MarshalGeoFenceJoinToUser (InstanceContextForSession *, InstanceContextForSession *, FenceStateDescriptor *fence_state_ptr, WebSocketMessage *wsm_ptr, unsigned call_flags);
UFSRVResult *MarshalFenceStateSyncForLeave (InstanceContextForSession *, InstanceContextForSession *ctx_ptr_newly_left, InstanceContextForFence *, DataMessage *data_msg_ptr, unsigned call_flags);
UFSRVResult *MarshalFenceStateSyncForJoin (InstanceContextForSession *, Session *sesn_ptr_newly_joined, InstanceHolderForFence *, unsigned call_flags);
UFSRVResult *MarshalFenceInvitation (InstanceContextForSession *, InstanceHolderForFence *, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, CollectionDescriptor *invited_eids_collection_ptr, CollectionDescriptor *unchanged_collection_ptr, unsigned call_flags);
UFSRVResult *MarshalFenceUnInvitedToUser (InstanceContextForSession *ctx_ptr, InstanceContextForSession *ctx_ptr_uninvited, Fence *f_ptr, FenceEvent *fence_event_ptr, unsigned call_flags);
UFSRVResult *MarshalUserPrefProfile(InstanceContextForSession *ctx_ptr, ClientContextData *ctx_data_ptr, WebSocketMessage *, DataMessage *data_msg_ptr_received, UfsrvEvent *event_ptr);
UFSRVResult *MarshalUserPrefProfileForFence  (InstanceContextForSession *, ClientContextData *ctx_ptr, WebSocketMessage *, DataMessage *data_msg_ptr_received, UfsrvEvent *event_ptr);
UFSRVResult *MarshalUserPrefNetstate(InstanceContextForSession *ctx_ptr, ClientContextData *ctx_data_ptr, WebSocketMessage *, DataMessage *data_msg_ptr_received, unsigned long call_flags, UfsrvEvent *fence_event_ptr);
UFSRVResult *MarshalUserPrefGroupRoaming(InstanceContextForSession *, ClientContextData *ctx_ptr, WebSocketMessage *, DataMessage *data_msg_ptr_received, unsigned long call_flags, UfsrvEvent *fence_event_ptr);

UFSRVResult *MarshalFenceUserPrefProfileSharing(InstanceContextForSession *, ClientContextData *ctx_ptr, DataMessage *data_msg_ptr_recieved, WebSocketMessage *, UfsrvEvent *fence_event_ptr);
UFSRVResult *MarshalUserPref (InstanceContextForSession *ctx_ptr, ClientContextData *ctx_data_ptr, DataMessage *data_msg_ptr_recieved, WebSocketMessage *wsm_ptr_received, UfsrvEvent *event_ptr);

#endif /* SRC_INCLUDE_COMMAND_CONTROLLERS_H_ */
