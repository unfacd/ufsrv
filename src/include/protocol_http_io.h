/*
 * protocol_http_io.h
 *
 *  Created on: 30 Jun 2016
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_PROTOCOL_IO_H_
#define SRC_INCLUDE_PROTOCOL_IO_H_

#include <session.h>
#include <http_request_handler.h>
#include <attachment_descriptor_type.h>

//ssize_t ReadFromSocket (Session *sesn_ptr, SocketMessage *sock_msg_ptr, unsigned flag);
onion_connection_status HttpSendFile_orig (Session *sesn_ptr, const char *filename, AttachmentDescriptor *attch_ptr);
onion_connection_status HttpSendFile (Session *sesn_ptr);
int
InitialiseSendFileContext (Session *sesn_ptr, const char *filename, AttachmentDescriptor *attch_ptr);
int HttpSendMessage (Session *sesn_ptr, const char *msg, size_t msglen);
#endif /* SRC_INCLUDE_PROTOCOL_IO_H_ */
