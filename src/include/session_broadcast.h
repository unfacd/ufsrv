/*
 * session_broadcast.h
 *
 *  Created on: 4 Feb 2017
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_SESSION_BROADCAST_H_
#define SRC_INCLUDE_SESSION_BROADCAST_H_



#include <fence_type.h>
#include <fence_event_type.h>
#include <session_type.h>
#include <ufsrvresult_type.h>
#include <SignalService.pb-c.h>
#include <UfsrvMessageQueue.pb-c.h>

int HandleInterBroadcastForSession (MessageQueueMsgPayload *mqp_ptr, MessageQueueMessage 		*mqm_ptr, UFSRVResult *res_ptr, unsigned long);
UFSRVResult *InterBroadcastSessionGeoFenced (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg);
UFSRVResult *InterBroadcastSessionStatus (Session *sesn_ptr, ClientContextData *context_ptr,  enum _SessionMessage__Status, enum _CommandArgs command_arg);
UFSRVResult *InterBroadcastSessionStatusRebooted (Session *sesn_ptr, ClientContextData *context_ptr, enum _SessionMessage__Status sesn_status, enum _CommandArgs command_arg);

int HandleIntraBroadcastForSession (MessageQueueMsgPayload *mqp_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
UFSRVResult *IntraBroadcastSessionStatusRebooted (Session *sesn_ptr, ClientContextData *context_ptr, enum _SessionMessage__Status sesn_status, enum _CommandArgs command_arg);

#endif /* SRC_INCLUDE_SESSION_BROADCAST_H_ */
