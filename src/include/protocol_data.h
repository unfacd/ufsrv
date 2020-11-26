/**
 * Copyright (C) 2015-2020 unfacd works
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

#ifndef PROTOCOL_WEBSOCKETS_DATA_H_
#define PROTOCOL_WEBSOCKETS_DATA_H_

#include <session_type.h>
#include <ufsrv_core/protocol/protocol.h>
//#include <nportredird.h>

#include <ufsrvwebsock/include/protocol_websocket.h>//function definitions for this protocol
#include <ufsrvrest/include/protocol_http.h>
#include <proto_stun/include/protocol_stun.h>
#include <proto_stun/include/worker_stun_thread.h>

//#include <protocol_future.h>

#define _GET_PROTOCOL_CALLBACKS_WEBSOCKETS \
	(protocols_registry_ptr+PROTOCOLID_WEBSOCKTES)->protocol_callback

#define _GET_PROTOCOL_CALLBACKS_HTTP \
	(protocols_registry_ptr+PROTOCOLID_HTTP)->protocol_callback

//included in protocol.c
//static definition should only be accessed via 'const ProtocolsRegistry *const ptr'
//declared as 'extern  const  ProtocolsRegistry *const protocols_registry_ptr'

static  Protocol ProtocolsRegistry [] = {
{
 "WebSockets", 0, ThreadWebSockets,
 {
	proto_websocket_protocol_init_callback,//proto init
	NULL, //config
	proto_websocket_init_listener,
	proto_websocket_init_workers_delegator_callback,//init_workers_delegator_callback -> to be phased out
	proto_websocket_main_listener_callback,
  proto_websocket_init_session_callback,
	proto_websocket_reset_callback,
	proto_websocket_hanshake_callback,
	proto_websocket_post_hanshake_callback,
	proto_websocket_msg_callback,
	NULL,//msg_out
	proto_websocket_decode_msg_callback,
	proto_websocket_encode_msg_callback,
	proto_websocket_service_timeout_callback,
	proto_websocket_error_callback,
	proto_websocket_recycler_error_callback,
	proto_websocket_close_callback,
	proto_websocket_msgqueue_topics_callback
 },
 0, NULL,
 {
	1,//unsigned read_blocked_session
	1,//unsigned read_inservice_session
	1,//retain_session_on_error
	1,//_PROTOCOL_CTL_ABORT_IOERROR
	1,//CLIENT_OF_RECYCLER
	1,//cloudmsgonioerror
	1,//pub_session_transitions
	1,//msgqueue subscriber
	1//main listener semantics
 }//end of struct
}//end of array entry

,

{
 "Http", 1, ThreadWebSockets,
 {
	proto_http_init_callback,
	proto_http_config_callback,
	proto_http_init_listener,
	proto_http_init_workers_delegator_callback,//init_workers_delegator_callback -> to be phased out
	proto_http_main_listener_callback,
	proto_http_init_session_callback,
	proto_http_reset_session_callback,
	NULL/*proto_http_hanshake_callback*/,
	NULL/*proto_http_post_hanshake_callback*/,
	proto_http_msg_callback,
	proto_http_msg_out_callback,
	NULL, //decode
	NULL, //encode
	proto_http_service_timeout_callback,
	proto_http_error_callback,
	proto_http_recycler_error_callback,
	proto_http_close_callback,
	proto_http_msgqueue_topics_callback
 },
 0, NULL,
 {
	1,//unsigned read_blocked_session
	0,//unsigned read_inservice_session
	0,//retain_session_on_error
	1,//_PROTOCOL_CTL_ABORT_IOERROR
	1,//CLIENT_OF_RECYCLER
	0,//cloud msg on io error
	0,//pub_session_transitions
	0,//msgqueue subscriber
	1//main listener semantics
 }//end of struct//end of struct
}//end of protocol entry
#if 0
,{
 "STUN", 1, ThreadStunWorker,
 {
	proto_stun_init_callback,
	NULL, //config
	proto_stun_init_listener,
	NULL,//init_workers_delegator_callback -> to be phased out
	proto_stun_main_listener_callback,
	proto_stun_init_session_callback,
	proto_stun_reset_session_callback,
	NULL/*proto_http_hanshake_callback*/,
	NULL/*proto_http_post_hanshake_callback*/,
	proto_stun_msg_callback,
	proto_stun_msg_out_callback,
	NULL, //decode
	NULL, //encode
	proto_stun_service_timeout_callback,
	proto_stun_error_callback,
	proto_stun_recycler_error_callback,
	proto_stun_close_callback,
	NULL//msgqueue_topics_callback
 },
 0, NULL,
 {
	0,//unsigned read_blocked_session
	0,//unsigned read_inservice_session
	0,//retain_session_on_error
	0,//_PROTOCOL_CTL_ABORT_IOERROR
	0,//CLIENT_OF_RECYCLER
	0,//cloud msg on io error
	0,//pub_session_transitions
	0,//msgqueue subscriber
	0//main listener semantics
 }//end of struct//end of struct
}//end of protocol entry
#endif
,
{
 "", -1, NULL, {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL}, 0, NULL, {0, 0, 0, 0, 0, 0, 0, 0, 0}
}
};

#endif /* SRC_INCLUDE_PROTOCOL_DATA_WEBSOCKETS_H_ */
