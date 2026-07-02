/*
 Copyright (c) 2015-2025 unfacd works

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.

 */

#ifndef SRC_INCLUDE_HTTP_SESSION_TYPE_H_
#define SRC_INCLUDE_HTTP_SESSION_TYPE_H_


#include <ufsrv_core/http/request.h>
#include <ufsrv_core/http/response.h>
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
