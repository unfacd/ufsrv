/*
 * protocol_websocket_io.h
 *
 *  Created on: 14 Aug 2015
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_PROTOCOL_WEBSOCKET_IO_H_
#define SRC_INCLUDE_PROTOCOL_WEBSOCKET_IO_H_

#include <ufsrvresult_type.h>
#include <transmission_message_type.h>

int
ReadFromSocketWS (Session *sesnptr, SocketMessage *, int);//, Socket *sptr);
int
ReadFromSocketRaw (Session *sesnptr, SocketMessage *);
int
ReadFromSocketToMessageQueueRaw (Session *sesn_ptr);

int
SendToSocketWS (Session *, SocketMessage *, const char *, unsigned);
int
SendToSocketWS2 (Session *sesn_ptr, TransmissionMessage *tmsg_ptr, unsigned flag);

int
SendToSocketRaw (Session *sesnptr, const char *msg);
UFSRVResult *
HandshakeSocketWS (Session *, SocketMessage *, unsigned);
UFSRVResult *
ProcessIncomingWsHandshake (Session *, SocketMessage *);
UFSRVResult *
ProcessOutgoingWsHandshake (Session *, SocketMessage *);
UFSRVResult *
ProcessIncomingWsHandshakeAsClient (Session *sesnptr, SocketMessage *sock_msg_ptr);
char *
io_error (int error);

int DispatchSocketMessageQueue (Session *, size_t);

#endif /* SRC_INCLUDE_PROTOCOL_WEBSOCKET_IO_H_ */
