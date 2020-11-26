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

#ifndef INCLUDE_PROTOCOL_DATA_WEBSOCKET_TYPE_H_
#define INCLUDE_PROTOCOL_DATA_WEBSOCKET_TYPE_H_

#include <ufsrvwebsock/include/websocket_session_type.h>

#ifndef MEDIUMBUF
#	define MEDIUMBUF   300
#endif

#if 0
struct ProtocolHeaderWebsocket {
    /*char path[1024+1];
    char host[1024+1];
    char origin[1024+1];
    char version[1024+1];
    char connection[1024+1];
    char protocols[1024+1];
    //char cookie[1024+1]; //TODO: make dynamic cookie string
	char validation_token[MEDIUMBUF+1]; //TODO: make validation_token dynamic string*/
    char key1[1024+1];
    char key2[1024+1];//TODO: make smaller as dont use
    char key3[8+1];
    char x_ufsrvcid[MINIBUF];
    /*char x_forwaded_for[SBUF];
	 int        hixie;
    int        hybi;*/
} ;
typedef struct ProtocolHeaderWebsocket ProtocolHeaderWebsocket;

struct WebSocketSession {
	ProtocolHeaderWebsocket protocol_header;
} ;
typedef struct WebSocketSession WebSocketSession;
#endif

#define PROTOCOLID_WEBSOCKET 		0

//#define WS_PROTOCOL_MAXPOSTSIZE(x) ((ProtocolHttp *)((x+PROTOCOLID_WEBSOCKET))->protocol_data)->constants.max_post_size


#define WS_PROTOCOL_NAME(x) ((x+PROTOCOLID_WEBSOCKET))->protocol_name
#define WS_PROTOCOL_DATA(x) ((x+PROTOCOLID_WEBSOCKET))->protocol_data
#define WS_PROTOCOL_THREAD(x) ((x+PROTOCOLID_WEBSOCKET))->protocol_thread
#define WS_PROTOCOL_CLLBACKS(x) ((x+PROTOCOLID_WEBSOCKET))->protocol_callbacks

#define WS_PROTOCOL_CLLBACKS_INIT(x) ((x+PROTOCOLID_WEBSOCKET))->protocol_callbacks.protocol_init_calback
#define WS_PROTOCOL_CLLBACKS_INIT_INVOKE(x, ...) (*((x+PROTOCOLID_WEBSOCKET))->protocol_callbacks.protocol_init_calback)(...)

#define WS_PROTOCOL_CLLBACKS_INIT_SESSION(x) ((x+PROTOCOLID_WEBSOCKET))->protocol_callbacks.session_init_calback
#define WS_PROTOCOL_CLLBACKS_INIT_SESSION_INVOKE(x, ...) (*((x+PROTOCOLID_WEBSOCKET))->protocol_callbacks.session_init_calback)(...)

#define WS_PROTOCOL_CLLBACKS_RESET_SESSION(x) ((x+PROTOCOLID_WEBSOCKET))->protocol_callbacks.session_reset_callback
#define WS_PROTOCOL_CLLBACKS_RESET_SESSION_INVOKE(x, ...) (*((x+PROTOCOLID_WEBSOCKET))->protocol_callbacks.session_reset_callback)(...)

#define WS_PROTOCOL_CLLBACKS_HANDSHAKE(x) (((x+PROTOCOLID_WEBSOCKET))->protocol_callbacks.handshake_callback
#define WS_PROTOCOL_CLLBACKS_HANDSHAKE_SESSION_INVOKE(x, ...) (*((x+PROTOCOLID_WEBSOCKET))->protocol_callbacks.handshake_callback)(...)

#define WS_PROTOCOL_CLLBACKS_MSG(x) ((x+PROTOCOLID_WEBSOCKET))->protocol_callbacks.msg_calback
#define WS_PROTOCOL_CLLBACKS_MSG_INVOKE(x, ...) (*((x+PROTOCOLID_WEBSOCKET))->protocol_callbacks.msg_calback)(...)

#define WS_PROTOCOL_CLLBACKS_ERROR(x) ((x+PROTOCOLID_WEBSOCKET))->protocol_callbacks.error_calback
#define WS_PROTOCOL_CLLBACKS_ERROR_INVOKE(x, ...) (*((x+PROTOCOLID_WEBSOCKET))->protocol_callbacks.error_calback)(...)

#define WS_PROTOCOL_CLLBACKS_CLOSE(x) ((x+PROTOCOLID_WEBSOCKET))->protocol_callbacks.close_calback
#define WS_PROTOCOL_CLLBACKS_CLOSE_INVOKE(x, ...) (*((x+PROTOCOLID_WEBSOCKET))->protocol_callbacks.close_calback)(...)


#endif /* SRC_INCLUDE_PROTOCOL_DATA_WEBSOCKET_TYPE_H_ */
