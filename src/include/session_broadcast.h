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

#ifndef SRC_INCLUDE_SESSION_BROADCAST_H_
#define SRC_INCLUDE_SESSION_BROADCAST_H_

#include <ufsrv_core/fence/fence_type.h>
#include <ufsrv_core/fence/fence_event_type.h>
#include <session_type.h>
#include <ufsrvresult_type.h>
#include <ufsrv_core/SignalService.pb-c.h>
#include <ufsrv_core/msgqueue_backend/UfsrvMessageQueue.pb-c.h>

int HandleInterBroadcastForSession (MessageQueueMessage 		*mqm_ptr, UFSRVResult *res_ptr, unsigned long);
UFSRVResult *InterBroadcastSessionGeoFenced (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg);
UFSRVResult *InterBroadcastSessionStatus (Session *sesn_ptr, ClientContextData *context_ptr,  enum _SessionMessage__Status, enum _CommandArgs command_arg);
UFSRVResult *InterBroadcastSessionStatusRebooted (Session *sesn_ptr, ClientContextData *context_ptr, enum _SessionMessage__Status sesn_status, enum _CommandArgs command_arg);

int HandleIntraBroadcastForSession (MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
UFSRVResult *IntraBroadcastSessionStatusRebooted (Session *sesn_ptr, ClientContextData *context_ptr, enum _SessionMessage__Status sesn_status, enum _CommandArgs command_arg);

#endif /* SRC_INCLUDE_SESSION_BROADCAST_H_ */
