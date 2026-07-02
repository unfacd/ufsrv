/*
 *
 *
 *  Created on: 5 May 2015
 *      Author: ayman
 */

#ifndef INCLUDE_TRANSMISSION_MESSAGE_TYPE_H_
#define INCLUDE_TRANSMISSION_MESSAGE_TYPE_H_

enum {
	TRANSMSG_TEXT=0,
	TRANSMSG_SOCKMSG,
	TRANSMSG_PROTOBUF
};

/**
 *  @struct TransmissionMessage
 *  @brief Final message encapsulation ahead of transmission to a connecting client endpoint's socket. \ref TransmissionMessage.msg_packed holds final protobuf encoded message.
 */
struct TransmissionMessage {
	unsigned type;        ///< as per unnamed enum: TRANSMSG_TEXT, TRANSMSG_SOCKMSG, etc...
	unsigned long gid,     ///< ufsrv wide unique eid
                eid,    ///< command type specific eid
								fid,    ///< fence id
								timestamp;
	size_t len;
	void *msg; ///< binary protobuf WebSocketMessage
	void *msg_packed; ///< protobuf encoded \ref TransmissionMessage.msg

} ;
typedef struct TransmissionMessage TransmissionMessage;


#endif /* SRC_INCLUDE_PROTOCOL_DATA_WEBSOCKET_TYPE_H_ */
