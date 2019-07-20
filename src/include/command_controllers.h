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

#include <ufsrvresult_type.h>
#include <fence_type.h>
#include <fence_state_descriptor_type.h>
#include <session_type.h>
#include <SignalService.pb-c.h>
#include <WebSocketMessage.pb-c.h>

typedef UFSRVResult * (*CallbackCommandMarshaller)(Session *sesn_ptr, ClientContextData *ctx_ptr, DataMessage *data_msg_ptr_recieved, UfsrvEvent *event_ptr);
#define INVOKE_COMMAND_MARSHALLER(command_marshaller, sesn_ptr, ctx_ptr, data_msg_ptr_received, event_ptr) return (*command_marshaller)(sesn_ptr, CLIENT_CTX_DATA(&share_list_ctx), data_msg_ptr_received,  event_ptr)

UFSRVResult *CommandCallbackControllerFenceCommand (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, MessageQueueMsgPayload *mqp_ptr);
UFSRVResult *CommandCallbackControllerCallCommand (Session *sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, MessageQueueMsgPayload *mqp_ptr);
UFSRVResult *CommandCallbackControllerUserCommand (InstanceHolderForSession *instance_sesn_ptr_local_user, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, MessageQueueMsgPayload *mqp_ptr);
UFSRVResult *CommandCallbackControllerMessageCommand (Session *sesn_ptr_local_user, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, MessageQueueMsgPayload *mqp_ptr);
UFSRVResult *CommandCallbackControllerReceiptCommand (Session *sesn_ptr_local_user, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, MessageQueueMsgPayload *mqp_ptr);

UFSRVResult *MarshalFenceJoinToUser (Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
UFSRVResult *MarshalFenceJoinInvitedToUser (Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
UFSRVResult *MarshalFenceStateSync (Session *sesn_ptr, FenceStateDescriptor *fstate_ptr, DataMessage *data_msg_ptr, unsigned long call_flags);
UFSRVResult *MarshalGeoFenceJoinToUser (Session *sesn_ptr, Session *sesn_ptr_target, FenceStateDescriptor *fence_state_ptr, WebSocketMessage *wsm_ptr, unsigned call_flags);
UFSRVResult *MarshalFenceStateSyncForLeave (Session *sesn_ptr, Session *sesn_ptr_newly_left, Fence *f_ptr, DataMessage *data_msg_ptr, unsigned call_flags);
UFSRVResult *MarshalFenceStateSyncForJoin (Session *sesn_ptr, Session *sesn_ptr_newly_joined, Fence *f_ptr, unsigned call_flags);
UFSRVResult *MarshalFenceInvitation (Session *sesn_ptr, Fence *f_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, CollectionDescriptor *invited_eids_collection_ptr, CollectionDescriptor *unchanged_collection_ptr, unsigned call_flags);
UFSRVResult *MarshalFenceUnInvitedToUser (Session *sesn_ptr, Session *sesn_ptr_uninvited, Fence *f_ptr, FenceEvent *fence_event_ptr, unsigned call_flags);
UFSRVResult *MarshalUserPrefProfile(Session *sesn_ptr, ClientContextData *ctx_ptr, DataMessage *data_msg_ptr_recieved, UfsrvEvent *event_ptr);
UFSRVResult *MarshalUserPrefProfileForFence  (Session *sesn_ptr, ClientContextData *ctx_ptr, DataMessage *data_msg_ptr_recieved, UfsrvEvent *event_ptr);
UFSRVResult *MarshalUserPrefNetstate(Session *sesn_ptr, ClientContextData *ctx_ptr, DataMessage *data_msg_ptr_recieved, unsigned long call_flags, UfsrvEvent *fence_event_ptr);
UFSRVResult *MarshalUserPrefGroupRoaming(Session *sesn_ptr, ClientContextData *ctx_ptr, DataMessage *data_msg_ptr_recieved, unsigned long call_flags, UfsrvEvent *fence_event_ptr);

UFSRVResult *MarshalFenceUserPrefProfileSharing(Session *sesn_ptr, ClientContextData *ctx_ptr, DataMessage *data_msg_ptr_recieved, UfsrvEvent *fence_event_ptr);
UFSRVResult *MarshalUserPref (Session *sesn_ptr, ClientContextData *ctx_ptr, DataMessage *data_msg_ptr_recieved, UfsrvEvent *event_ptr);

#endif /* SRC_INCLUDE_COMMAND_CONTROLLERS_H_ */
