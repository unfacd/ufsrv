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

#ifndef SRC_INCLUDE_PROTOCOL_HTTP_H_
#define SRC_INCLUDE_PROTOCOL_HTTP_H_

#include <ufsrvresult_type.h>
#include<transmission_message_type.h>
#include <redirection.h>
#include <ufsrvwebsock/include/WebSocketMessage.pb-c.h>
#include <session.h>
#include <session_service.h>
#include <ufsrv_core/protocol/protocol.h>
#include <nportredird.h>
#include <json/json.h>
#include <ufsrv_core/msgqueue_backend/ufsrvcmd_broadcast_type.h>
#include "protocol_http_type.h"
#include <ufsrv_core/msgqueue_backend/ufsrv_msgcmd_type_enum.h>

bool IsConnectionKeepAlive (Session *);

UFSRVResult *proto_http_init_callback (Protocol *);
UFSRVResult *proto_http_init_listener (void);
UFSRVResult *proto_http_config_callback (ClientContextData *config_file_handler_ptr);
UFSRVResult *proto_http_init_session_callback (ClientContextData *, unsigned);
UFSRVResult *proto_http_reset_session_callback (InstanceHolderForSession *, unsigned);
UFSRVResult *proto_http_hanshake_callback (InstanceHolderForSession *, SocketMessage *, unsigned, int **);

UFSRVResult *proto_http_post_hanshake_callback (InstanceHolderForSession *);
UFSRVResult *proto_http_msg_callback (InstanceHolderForSession *, SocketMessage *, unsigned, size_t);
UFSRVResult *proto_http_init_workers_delegator_callback (void);
UFSRVResult *proto_http_main_listener_callback (Socket *, ClientContextData *);
UFSRVResult *proto_http_msg_out_callback (InstanceHolderForSession *, SocketMessage *sock_msg_ptr, unsigned frame_offset, size_t len);
UFSRVResult *proto_http_service_timeout_callback (InstanceHolderForSession *, time_t, unsigned long call_flags);
UFSRVResult *proto_http_error_callback (InstanceHolderForSession *, unsigned);
UFSRVResult *proto_http_recycler_error_callback (InstanceHolderForSession *, unsigned);
UFSRVResult *proto_http_close_callback (InstanceHolderForSession *);
UFSRVResult *proto_http_msgqueue_topics_callback (UFSRVResult *res_ptr);

UFSRVResult *UfsrvApiIntraBroadcastMessage (Session *sesn_ptr_this, WireProtocolData *data, UfsrvMsgCommandType msgcmd_type, enum BroadcastSemantics, const unsigned char *);

#endif /* SRC_INCLUDE_PROTOCOL_HTTP_H_ */
