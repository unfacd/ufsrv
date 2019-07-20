/*
 * fence_broadcast.h
 *
 *  Created on: 4 Feb 2017
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_FENCE_BROADCAST_H_
#define SRC_INCLUDE_FENCE_BROADCAST_H_


#include <fence_type.h>
#include <fence_event_type.h>
#include <session_type.h>
#include <ufsrvresult_type.h>
#include <SignalService.pb-c.h>
#include <UfsrvMessageQueue.pb-c.h>

typedef struct ContextDataFenceInvite {
	Session 							*sesn_ptr_inviter,
												*sesn_ptr_invited;
	FenceStateDescriptor 	*fence_state_ptr;
} ContextDataFenceInvite;

int HandleInterBroadcastForFence (MessageQueueMsgPayload *mqp_ptr, MessageQueueMessage 		*mqm_ptr, UFSRVResult *res_ptr, unsigned long);
int HandleInterBroadcastForUser (MessageQueueMsgPayload *mqp_ptr, MessageQueueMessage 		*mqm_ptr, UFSRVResult *res_ptr, unsigned long);
UFSRVResult *InterBroadcastFenceJoin (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg);
UFSRVResult *InterBroadcastFenceMake (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg);
UFSRVResult *InterBroadcastFenceLeave (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg);
UFSRVResult *InterBroadcastFenceDnameMessage (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg);
UFSRVResult *InterBroadcastFenceAvatarMessage (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg);
UFSRVResult *InterBroadcastFenceMsgExpiry (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg);
UFSRVResult *InterBroadcastFenceMaxMembers (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg);
UFSRVResult *InterBroadcastFenceDeliveryMode (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg);
UFSRVResult *InterBroadcastFencePermission (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg);
UFSRVResult *InterBroadcastFenceListSemantics (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg);
UFSRVResult *InterBroadcastFenceInvite (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg);
UFSRVResult *InterBroadcastFenceDestruct (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg);
UFSRVResult *InterBroadcastFenceReload (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg);

int HandleIntraBroadcastForFence (MessageQueueMsgPayload *mqp_ptr, MessageQueueMessage *, UFSRVResult *res_ptr, unsigned long call_flags);
int HandleIntraBroadcastForUser (MessageQueueMsgPayload *mqp_ptr, MessageQueueMessage *, UFSRVResult *res_ptr, unsigned long call_flags);

#endif /* SRC_INCLUDE_FENCE_BROADCAST_H_ */
