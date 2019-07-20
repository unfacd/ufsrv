/*
 * protocol_http_io.h
 *
 *  Created on: 30 Jun 2016
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_PROTOCOL_HTTP_IO_H_
#define SRC_INCLUDE_PROTOCOL_HTTP_IO_H_


#include <ufsrvresult_type.h>
#include <transmission_message_type.h>
#include <session.h>

ssize_t
ReadFromSocket (Session *sesn_ptr, SocketMessage *sock_msg_ptr, unsigned flag);

int
SendTextMessage (Session *sesn_ptr, const char *msg, size_t msglen);

ssize_t
SendToSocket (Session *sesn_ptr, TransmissionMessage *tmsg_ptr, unsigned flag);
int DispatchSocketMessageQueue (Session *sesn_ptr, size_t entries);

UFSRVResult *ConsolidateSocketMessageQueue (Session *sesn_ptr, unsigned call_flags, UFSRVResult *);
void ErrorFromSocket (InstanceHolderForSession *instance_sesn_ptr, unsigned);
#endif /* SRC_INCLUDE_PROTOCOL_HTTP_IO_H_ */
