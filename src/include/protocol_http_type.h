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

#ifndef SRC_INCLUDE_PROTOCOL_HTTP_TYPE_H_
#define SRC_INCLUDE_PROTOCOL_HTTP_TYPE_H_

#include <protocol_type.h>
#include <request.h>
#include <response.h>

#define HTTP_RESPONSE_CODE_GENERIC_ERROR    409
#define HTTP_RESPONSE_CODE_UNSUPPORTED_OP   405
#define HTTP_RESPONSE_CODE_NOT_FOUND        404

//data definitions per protocol type ie irrespective of individual requests/sessions
//this is the protocol-typeata referenced in Protocol.protocol_data as ProtocolTypeData
struct ProtocolHttp {
	struct	{
	  size_t max_post_size; // 1MB
	  size_t max_file_size; // 1GB
	} 	constants;
	struct {
	  onion_handler *root_handler;	/// Root processing handler for this server.
	  onion_handler *root_auth_handler;//authentication handler
	  onion_handler *internal_error_handler;	/// Root processing handler for this server.
	}	http_handlers;
};
typedef struct ProtocolHttp ProtocolHttp;

#define PROTOCOLID_HTTP 		1

/*
#define HTTP_PROTOCOL_MAXPOSTSIZE(x) ((ProtocolHttp *)((x+PROTOCOLID_HTTP))->protocol_data)->constants.max_post_size
#define HTTP_PROTOCOL_MAXFILESIZE(x) ((ProtocolHttp *)((x+PROTOCOLID_HTTP))->protocol_data)->constants.max_file_size
#define HTTP_PROTOCOL_ROOTHANDLER(x) ((ProtocolHttp *)((x+PROTOCOLID_HTTP))->protocol_data)->http_handlers.root_handler
#define HTTP_PROTOCOL_ERRORHANDLER(x) ((ProtocolHttp *)((x+PROTOCOLID_HTTP))->protocol_data)->http_handlers.internal_error_handler
*/

//this is more parametric and generic than the set above, as it relies on the protocol id as set n the session
//x is tha master protocol registry array, which y below indexes into
//y is PROTO_PROTOCOL_ID((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr)
//
//to call the handler using  a typical parameter-set:
//onion_handler *h=HTTP_PROTOCOL_ROOTHANDLER(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))));

#define HTTP_PROTOCOL_MAXPOSTSIZE(x, y) ((ProtocolHttp *)((x+y))->protocol_data)->constants.max_post_size
#define HTTP_PROTOCOL_MAXFILESIZE(x, y) ((ProtocolHttp *)((x+y))->protocol_data)->constants.max_file_size
#define HTTP_PROTOCOL_ROOTHANDLER(x, y) ((ProtocolHttp *)((x+y))->protocol_data)->http_handlers.root_handler
#define HTTP_PROTOCOL_ROOTAUTHHANDLER(x, y) ((ProtocolHttp *)((x+y))->protocol_data)->http_handlers.root_auth_handler
#define HTTP_PROTOCOL_ERRORHANDLER(x, y) ((ProtocolHttp *)((x+y))->protocol_data)->http_handlers.internal_error_handler

#define PROTOHTTP_MAXPOSTSIZE(x)	x->constants.max_post_size
#define PROTOHTTP_MAXFILESIZE(x)	x->constants.max_file_size

#define PROTOHTTP_ROOTHANDLER(x)	x->http_handlers.root_handler
#define PROTOHTTP_ERRORHANDLER(x)	x->http_handlers.internal_error_handler

#define HTTP_PROTOCOL_NAME(x) ((x+PROTOCOLID_HTTP))->protocol_name
#define HTTP_PROTOCOL_DATA(x) ((ProtocolHttp *)((x+PROTOCOLID_HTTP))->protocol_data)
#define HTTP_PROTOCOL_THREAD(x) ((x+PROTOCOLID_HTTP))->protocol_thread
#define HTTP_PROTOCOL_CLLBACKS(x) ((x+PROTOCOLID_HTTP))->protocol_callbacks

#define HTTP_PROTOCOL_CLLBACKS_INIT(x) ((x+PROTOCOLID_HTTP))->protocol_callbacks.protocol_init_callback
#define HTTP_PROTOCOL_CLLBACKS_INIT_INVOKE(x, ...) ((x+PROTOCOLID_HTTP)->protocol_callbacks.protocol_init_callback)(__VA_ARGS__)

#define HTTP_PROTOCOL_CLLBACKS_INIT_SESSION(x) ((x+PROTOCOLID_HTTP))->protocol_callbacks.session_init_callback
#define HTTP_PROTOCOL_CLLBACKS_INIT_SESSION_INVOKE(x, ...) ((x+PROTOCOLID_HTTP)->protocol_callbacks.session_init_callback)(__VA_ARGS__)

#define HTTP_PROTOCOL_CLLBACKS_RESET_SESSION(x) ((x+PROTOCOLID_HTTP))->protocol_callbacks.session_reset_callback
#define HTTP_PROTOCOL_CLLBACKS_RESET_SESSION_INVOKE(x, ...) ((x+PROTOCOLID_HTTP)->protocol_callbacks.session_reset_callback)(__VA_ARGS__)

#define HTTP_PROTOCOL_CLLBACKS_HANDSHAKE(x) ((x+PROTOCOLID_HTTP))->protocol_callbacks.handshake_callback
#define HTTP_PROTOCOL_CLLBACKS_HANDSHAKE_SESSION_INVOKE(x, ...) ((x+PROTOCOLID_HTTP)->protocol_callbacks.handshake_callback)(__VA_ARGS__)

#define HTTP_PROTOCOL_CLLBACKS_MSG(x) ((x+PROTOCOLID_HTTP))->protocol_callbacks.msg_callback
#define HTTP_PROTOCOL_CLLBACKS_MSG_INVOKE(x, ...) ((x+PROTOCOLID_HTTP)->protocol_callbacks.msg_callback)(__VA_ARGS__)

#define HTTP_PROTOCOL_CLLBACKS_ERROR(x) ((x+PROTOCOLID_HTTP))->protocol_callbacks.error_callback
#define HTTP_PROTOCOL_CLLBACKS_ERROR_INVOKE(x, ...) ((x+PROTOCOLID_HTTP)->protocol_callbacks.errorcallback)(__VA_ARGS__)

#define HTTP_PROTOCOL_CLLBACKS_CLOSE(x) ((x+PROTOCOLID_HTTP))->protocol_callbacks.close_callback
#define HTTP_PROTOCOL_CLLBACKS_CLOSE_INVOKE(x, ...) ((x+PROTOCOLID_HTTP)->protocol_callbacks.close_callback)(__VA_ARGS__)

#endif /* SRC_INCLUDE_PROTOCOL_HTTP_TYPE_H_ */
