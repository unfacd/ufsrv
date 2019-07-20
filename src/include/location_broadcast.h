/*
 * location_roadcast.h
 *
 *  Created on: 4 Feb 2017
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_LOCATION_BROADCAST_H_
#define SRC_INCLUDE_LOCATION_BROADCAST_H_




#include <fence_type.h>
#include <fence_event_type.h>
#include <session_type.h>
#include <ufsrvresult_type.h>
#include <SignalService.pb-c.h>
#include <UfsrvMessageQueue.pb-c.h>

UFSRVResult *InterBroadcastLocationAddressByServer (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg);
UFSRVResult *InterBroadcastLocationAddressByUser (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg);
UFSRVResult *InterBroadcastBaseLoc (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg);
int HandleInterBroadcastForLocation (MessageQueueMsgPayload *mqp_ptr, MessageQueueMessage 		*mqm_ptr, UFSRVResult *res_ptr, unsigned long callflags);

int HandleIntraBroadcastForLocationAddress (MessageQueueMsgPayload *mqp_ptr, MessageQueueMessage *, UFSRVResult *res_ptr, unsigned long call_flags);

#endif /* SRC_INCLUDE_MESSAGE_BROADCAST_H_ */
