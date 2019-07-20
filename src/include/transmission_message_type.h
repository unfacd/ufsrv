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
struct TransmissionMessage {
	unsigned type;
	unsigned long eid,
								fid,
								timestamp;
	size_t len;
	void *msg;
	void *msg_packed;

} ;
typedef struct TransmissionMessage TransmissionMessage;


#endif /* SRC_INCLUDE_PROTOCOL_DATA_WEBSOCKET_TYPE_H_ */
