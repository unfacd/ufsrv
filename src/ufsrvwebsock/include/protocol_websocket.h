/**
 * Copyright (C) 2015-2024 unfacd works
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

#ifndef PROTOCOL_WEBSOCKETS_H_
#define PROTOCOL_WEBSOCKETS_H_

#include <ufsrvresult_type.h>
#include<transmission_message_type.h>
#include <ufsrvwebsock/include/WebSocketMessage.pb-c.h>
#include <ufsrvmsg_core/SignalService.pb-c.h>//proto
#include <session_type.h>
#include <session_service.h>
#include <ufsrvmsg_core/protocol/protocol.h>
#include <nportredird.h>
#include <json/json.h>
#include <ufsrvwebsock/include/protocol_websocket_type.h>
#include <http_request_context_type.h>
#include <ufsrvmsg_core/msgqueue_backend/ufsrv_msgcmd_type_enum.h>

//use with Session *
#define SESSION_PROTOCOL_HEADER_WS(x)	((ProtocolHeaderWebsocket *)(x)->ssptr->header)

//convenient decorator interface around protobuf key operations, simplifying the final dispatcher by abstracting out final message type.
//Also, decouples from current chosen protobuf implementation in case it gets swapped out with a different package
/**
 *  @struct UfsrvCommandMarshallingMetaData
 *  @brief Convenient decorator interface around protobuf key operations, simplifying the final dispatcher by abstracting out final message type.
 *  Also, decouples from current chosen protobuf implementation in case it gets swapped out with a different package
 */
typedef struct UfsrvCommandMarshallingMetaData {
	void (*initialiser)(WireProtocolData *);
	size_t (*packer)(WireProtocolData *, uint8_t *); ///< type in
	WireProtocolData * (*unpacker)(void *, size_t, const uint8_t *); ///< type out
	size_t (*sizer)(const WireProtocolData *);

} UfsrvCommandMarshallingMetaData;

/**
 *  @struct UfsrvCommandMarshallingDescriptor
 *  @brief Intermediate abstraction that handles wire protocol data packing and feeds into final marshalling and delivery phase which uses \ref TransmissionMessage
 */
typedef struct UfsrvCommandMarshallingDescriptor {
	unsigned long 									eid, //command specific eid
																	fid,
																	timestamp;
	UfsrvCommandMarshallingMetaData *metadata; ///< marshalling and handling ops that are wire protocol specific and knows how to handle the opaque \ref UfsrvCommandMarshallingDescriptor.payload
	WireProtocolData *payload; ///< opaque protocol payload
  unsigned long                   gid; ///< ufsr wide eid todo: reshuffle to the top, but first update all references
} UfsrvCommandMarshallingDescriptor;

//IMPORTANT: if the underlying type names in the source proto file change, depending on what changed, the function names below may need updating
static UfsrvCommandMarshallingMetaData EnvelopeMetaData = {
		(void (*)(WireProtocolData *))envelope__init,
		(size_t (*)(WireProtocolData *, uint8_t *))envelope__pack,
		(WireProtocolData * (*)(void *, size_t, const uint8_t *))ufsrv_command_wire__unpack,
		(size_t (*)(const WireProtocolData *))envelope__get_packed_size
};

static UfsrvCommandMarshallingMetaData UfsrvCommandMetaData = {
		(void (*)(WireProtocolData *))ufsrv_command_wire__init,
		(size_t (*)(WireProtocolData *, uint8_t *))ufsrv_command_wire__pack,
		(WireProtocolData * (*)(void *, size_t, const uint8_t *))envelope__unpack,
		(size_t (*)(const WireProtocolData *))ufsrv_command_wire__get_packed_size
};

#if 0
//not implemented
//intended to decouple the wire data types, specifically, protobufs from the internal machination
//but at this stage we only act as a surface level type "anonymiser". WireData is nothing more than obscured protobuf DataMessage
typedef struct WireProtocolData {
	UfsrvMsgCommandType command;
	WireData *wire_data;
} ;
#endif

UFSRVResult *UfsrvCommandInvokeUserCommand(InstanceContextForSession *ctx_ptr, InstanceContextForSession *ctx_ptr_target, WebSocketMessage *wsm_ptr, struct json_object *jobj_in, WireProtocolData *payload, unsigned req_cmd_idx);
int UfsrvCommandMarshalTransmission(InstanceContextForSession *ctx_ptr, InstanceContextForSession *ctx_ptr_target, TransmissionMessage *, unsigned long call_flags);
UFSRVResult *UfsrvCommandMarshalCloudMessagingNotification(Session *sesn_ptr, HttpRequestContext *http_ptr, WireProtocolData *data);
UFSRVResult *UfsrvCommandMarshalCloudMessagingChallenge(HttpRequestContext *http_ptr, const char *gcm_id, const char *challenge);
bool IsUserCloudRegistered(Session *sesn_ptr, HttpRequestContext *http_ptr);

void ResetWebSocketProtocolSession(WebSocketSession *ws_ptr, bool is_self_destruct);
UFSRVResult *proto_websocket_protocol_init_callback(Protocol *);
UFSRVResult *proto_websocket_init_listener(void);
UFSRVResult *proto_websocket_init_workers_delegator_callback(void);
UFSRVResult *proto_websocket_main_listener_callback(Socket *sock_ptr_listener, ClientContextData *context_ptr);
UFSRVResult *proto_websocket_hanshake_callback(InstanceHolder *, SocketMessage *, unsigned, int **);
UFSRVResult *proto_websocket_post_hanshake_callback(InstanceHolder *, SocketMessage *sock_msg_ptr, unsigned callflags);
UFSRVResult *proto_websocket_msg_callback(InstanceHolder *, SocketMessage *, unsigned, size_t);
UFSRVResult *proto_websocket_decode_msg_callback(InstanceHolder *, SocketMessage *sock_msg_ptr, unsigned);
UFSRVResult *proto_websocket_encode_msg_callback(InstanceHolder *, SocketMessage *sock_msg_ptr, unsigned);
UFSRVResult *proto_websocket_init_session_callback(ClientContextData *ctx_data_ptr, unsigned callflags);
UFSRVResult *proto_websocket_reset_callback(InstanceHolder *instance_sesn_ptr, unsigned callflags);
UFSRVResult *proto_websocket_service_timeout_callback(InstanceHolder *instance_sesn_ptr, time_t now, unsigned long call_flags);
UFSRVResult *proto_websocket_error_callback(InstanceHolder *, unsigned);
UFSRVResult *proto_websocket_recycler_error_callback(InstanceHolder *, unsigned);
UFSRVResult *proto_websocket_close_callback(InstanceHolder *);
UFSRVResult *proto_websocket_msgqueue_topics_callback(UFSRVResult *);
UFSRVResult *proto_websocket_generate_session_id_callback(UFSRVResult *res_ptr, ClientContextData *context_data);

void *ThreadWebSockets(void *);

#endif /* SRC_INCLUDE_PROTOCOL_DATA_WEBSOCKETS_H_ */
