/*
 * websocket_session_type.h
 *
 *  Created on: 1 Jul 2016
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_WEBSOCKET_SESSION_TYPE_H_
#define SRC_INCLUDE_WEBSOCKET_SESSION_TYPE_H_

#include <main.h> //for MINIBUF


struct ProtocolHeaderWebsocket {
    char key1[1024+1];
    char key2[1024+1];//TODO: make smaller as dont use
    char key3[8+1];
    char x_ufsrvcid[MINIBUF];
} ;
typedef struct ProtocolHeaderWebsocket ProtocolHeaderWebsocket;

struct WebSocketSession {
	ProtocolHeaderWebsocket protocol_header;
} ;
typedef struct WebSocketSession WebSocketSession;


#endif /* SRC_INCLUDE_WEBSOCKET_SESSION_TYPE_H_ */
