/*
 * user_broadcast.h
 *
 *  Created on: 4 Feb 2017
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_USER_BROADCAST_H_
#define SRC_INCLUDE_USER_BROADCAST_H_


#include <fence_type.h>
#include <fence_event_type.h>
#include <session_type.h>
#include <ufsrvresult_type.h>
#include <ufsrvmsgqueue_type.h>
#include <SignalService.pb-c.h>
#include <UfsrvMessageQueue.pb-c.h>


int HandleInterBroadcastForUser (MessageQueueMsgPayload *mqp_ptr, MessageQueueMessage 		*mqm_ptr, UFSRVResult *res_ptr, unsigned long);
UFSRVResult *InterBroadcastUserMessageUserPrefsBoolean(Session *sesn_ptr, ClientContextData *context_ptr, UfsrvEvent *event_ptr, enum _CommandArgs command_arg);
UFSRVResult *InterBroadcastUserNicknameMessage(Session *sesn_ptr, ClientContextData *context_ptr, UfsrvEvent *event_ptr,
                                               enum _CommandArgs command_arg);
UFSRVResult *InterBroadcastUserAvatarMessage(Session *sesn_ptr, ClientContextData *context_ptr, UfsrvEvent *event_ptr,
                                             enum _CommandArgs command_arg);
UFSRVResult *InterBroadcastUserShareListMessage(Session *sesn_ptr, ClientContextData *context_ptr, UfsrvEvent *event_ptr,
                                                enum _CommandArgs command_arg);
UFSRVResult *InterBroadcastUserMessageFenceUserPrefs(Session *sesn_ptr, ClientContextData *context_ptr, UfsrvEvent *event_ptr,
                                                     enum _CommandArgs command_arg);

int HandleIntraBroadcastForUser (MessageQueueMsgPayload *mqp_ptr, MessageQueueMessage *, UFSRVResult *res_ptr, unsigned long call_flags);

#endif /* SRC_INCLUDE_USER_BROADCAST_H_ */
