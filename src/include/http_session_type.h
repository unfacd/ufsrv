/*
 * http_session_type.h
 *
 *  Created on: 29 Jun 2016
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_HTTP_SESSION_TYPE_H_
#define SRC_INCLUDE_HTTP_SESSION_TYPE_H_


#include <request.h>
#include <response.h>
#include <json/json.h>

//this is meant to be set into theSession.protocol_session field

struct HttpSession {
	unsigned long 	session_id;	//session as kept by ufsrv
	onion_request 	request;
	onion_response 	response;
	json_object 		*jobj;

	struct {
		int 		file_fd;
		size_t	file_size;
	} send_file_ctx;

};
typedef struct HttpSession HttpSession;

#define HTTPSESN_SESSIONID(x)	(x)->session_id
#define HTTPSESN_REQUEST(x)		(x)->request
#define HTTPSESN_RESPONSE(x)	(x)->response
#define HTTPSESN_JSONDATA(x)	(x)->jobj
#define HTTPSESN_FILEFD(x)		(x)->send_file_ctx.file_fd
#define HTTPSESN_FILESZ(x)		(x)->send_file_ctx.file_size


//use with params assignments and/or method calls params
#define HTTPSESN_REQUEST_PTR(x)	&(x->request)
#define HTTPSESN_RESPONSE_PTR(x)	&(x->response)

#endif /* SRC_INCLUDE_HTTP_SESSION_TYPE_H_ */
