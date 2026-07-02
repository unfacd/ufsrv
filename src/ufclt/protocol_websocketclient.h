/*
 * protocol_websocketclient.h
 *
 *  Created on: 21 Jul 2016
 *      Author: ayman
 */

#ifndef UFCLT_PROTOCOL_WEBSOCKETCLIENT_H_
#define UFCLT_PROTOCOL_WEBSOCKETCLIENT_H_

#include <session.h>
#include <ufsrvresult_type.h>

UFSRVResult *
proto_websocketclient_msg_callback(Session *sesn_ptr, SocketMessage *sock_msg_ptr, unsigned call_flags, size_t len);
UFSRVResult *
proto_websocketclient_decode_msg_callback(Session *sesn_ptr, SocketMessage *sm_ptr, unsigned frame_offset);

UFSRVResult *
proto_websocketclient_encode_msg_callback(Session *sesn_ptr, SocketMessage *sock_msg_ptr, unsigned frame_offset);


#endif /* UFCLT_PROTOCOL_WEBSOCKETCLIENT_H_ */
