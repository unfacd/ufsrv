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

#ifndef SRC_INCLUDE_PROTOCOL_WEBSOCKET_SESSION_H_
#define SRC_INCLUDE_PROTOCOL_WEBSOCKET_SESSION_H_
#include <queue.h>
#include <list.h>
#include <queue.h>
#include <sockets.h>
#include <hashtable.h>
#include <instrumentation_backend.h>
#include <persistance_type.h>
#include <ufsrvmsgqueue_type.h>
#include <fence_type.h>
#include <fence.h>
#include <pthread.h>
#include <hiredis.h>
#include <session_type.h>
#include <recycler_type.h>


UFSRVResult *ClearBackendCacheForInvalidUserId (Session *sesn_ptr_this, Session *sesn_ptr_target, Fence *, unsigned long call_flags);
UFSRVResult *ClearBackendCacheForSessionlessInvalidUserId (Session *sesn_ptr_carrier, unsigned long userid, unsigned long sesn_call_flags, unsigned long fence_call_flags);
UFSRVResult *InvalidateLocalSessionReferenceFromProto (InstanceHolderForSession *instance_sesn_ptr, MessageQueueMessage *mqm_ptr, unsigned long call_flags);
UFSRVResult *UpdateBackendSessionGeoJoinData (Session *sesn_ptr, Fence *f_ptr_current, Fence *f_ptr_past);
#endif /* SRC_INCLUDE_PROTOCOL_WEBSOCKET_SESSION_H_ */
