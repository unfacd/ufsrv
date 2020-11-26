/*
	Onion HTTP server library
	Copyright (C) 2010-2016 David Moreno Montero and others

	This library is free software; you can redistribute it and/or
	modify it under the terms of, at your choice:

	a. the Apache License Version 2.0.

	b. the GNU General Public License as published by the
		Free Software Foundation; either version 2.0 of the License,
		or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of both libraries, if not see
	<http://www.gnu.org/licenses/> and
	<http://www.apache.org/licenses/LICENSE-2.0>.
	*/

#include <main.h>

#ifdef __DEBUG__
#ifdef __EXECINFO__
#include <execinfo.h>
#endif
#endif

#include "h_handler.h"
#include <url.h>
#include <response.h>
#include <request.h>
#include <recycler/recycler.h>

/// @defgroup handler Handler. Creates and manages the user handlers so that onion can call them when required.

/**
 * @short Tryes to handle the petition with that handler.
 * @memberof onion_handler_t
 * @ingroup handler
 *
 * It needs the handler to handle, the request and the response.
 *
 * It checks this parser, and siblings.
 *
 * @returns If can not, returns OCS_NOT_PROCESSED (0), else the onion_connection_status. (normally OCS_PROCESSED)
 */
onion_connection_status onion_handler_handle(InstanceHolderForSession *instance_sesn_ptr, onion_handler *handler, onion_request *request, onion_response *response){
	onion_connection_status res;


	while (handler){
		if (handler->handler) {
#ifdef __DEBUG0__
//			char **bs=backtrace_symbols((void * const *)&handler->handler, 1);
//			ONION_DEBUG0("Calling handler: %s",bs[0]);
//			/* backtrace_symbols is explicitly documented
//			   to malloc. We need to call the system free
//			   routine, not our onion_low_free ! */
//			onion_low_free(bs); /* Can't be onion_low_free.... */
#endif
			res = handler->handler(instance_sesn_ptr, handler->priv_data, request, response);//callback function

#if __FULL_DEBUG
			syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): HANDLER RETURNED: '%d'", __func__, pthread_self(), SESSION_ID(sesn_ptr), res);
#endif

			if (res) {
				// write pending data.
				if (!(response->flags&OR_HEADER_SENT) && response->buffer_pos<sizeof(response->buffer))
					onion_response_set_length(response, response->buffer_pos);

				onion_response_flush(instance_sesn_ptr, response);

				/*if (res==OCS_WEBSOCKET){
					if (request->websocket)
						return onion_websocket_call(request->websocket);
					else{
						ONION_ERROR("Handler did set the OCS_WEBSOCKET, but did not initialize the websocket on this request.");
						return OCS_INTERNAL_ERROR;
					}
				}*/
				return res;
			}
		}
		handler = handler->next;
	}
	return OCS_NOT_PROCESSED;
}


/**
 * @short Creates an onion handler with that private datas.
 * @memberof onion_handler_t
 * @ingroup handler
 *
 */
onion_handler *onion_handler_new(onion_handler_handler handler, void *priv_data, onion_handler_private_data_free priv_data_free){
	onion_handler *phandler=calloc(1, sizeof(onion_handler));
	phandler->handler=handler;
	phandler->priv_data=priv_data;
	phandler->priv_data_free=priv_data_free;
	return phandler;
}

/**
 * @short Frees the memory used by this handler.
 * @memberof onion_handler_t
 * @ingroup handler
 *
 * It calls the private data handler free if available, and free the 'next' handler too.
 *
 * It should be called when this handler is not going to be used anymore. Most of the cases you
 * call it over the root handler, and from there it removes all the handlers.
 *
 * Returns the number of handlers freed on this level.
 */
int onion_handler_free(onion_handler *handler){
	int n=0;
	onion_handler *next=handler;
	while (next){
		handler=next;
		if (handler->priv_data_free && handler->priv_data){
			handler->priv_data_free(handler->priv_data);
		}
		next=handler->next;
		free(handler);
		n++;
	}
	return n;
}

/**
 * @short Adds a handler to the list of handlers of this level
 * @memberof onion_handler_t
 * @ingroup handler
 *
 * Adds a handler at the end of the list of handlers of this level. Each handler is called in order,
 * until one of them succeds. So each handler is in charge of cheching if its itself who is being called.
 */
void onion_handler_add(onion_handler *base, onion_handler *new_handler){
	while(base->next)
		base=base->next;
	base->next=new_handler;
}

/**
 * @short Returns the private data part of a handler
 * @memberof onion_handler_t
 * @ingroup handler
 *
 * This is useful to allow external users of a given handler to modify the behaviour. For example
 * on the directory handler this helps to change the default header and footers.
 */
void *onion_handler_get_private_data(onion_handler *handler){
	return handler->priv_data;
}

//AA+
//Ported across as base root handler
onion_url *onion_root_url(void)
{
	/*if (server->root_handler){
		if (server->root_handler->priv_data_free==(void*)onion_url_free_data) // Only available check
			return (onion_url*)server->root_handler;
		ONION_WARNING("Could not get root url handler, as there is another non url handler at root.");
		return NULL;
	}*/

	//ONION_DEBUG("New root url handler");
	onion_url *url = onion_url_new();
	//ms->root_handler=(onion_handler*)url;
	return url;
}

#define ERROR_500 "<h1>500 - Internal error</h1> Check server logs or contact administrator."
#define ERROR_403 "<h1>403 - Forbidden</h1>"
#define ERROR_404 "<h1>404 - Not found</h1>"
#define ERROR_501 "<h1>501 - Not implemented</h1>"

//AA+ ported across
int onion_default_error(InstanceHolderForSession *instance_sesn_ptr, void *handler, onion_request *req, onion_response *res){
	const char *msg;
	int l;
	int code;
	switch(req->flags&0x0F000){
		case OR_INTERNAL_ERROR:
			msg=ERROR_500;
			l=sizeof(ERROR_500)-1;
			code=HTTP_INTERNAL_ERROR;
			break;
		case OR_NOT_IMPLEMENTED:
			msg=ERROR_501;
			l=sizeof(ERROR_501)-1;
			code=HTTP_NOT_IMPLEMENTED;
			break;
    case OR_FORBIDDEN:
      msg=ERROR_403;
      l=sizeof(ERROR_403)-1;
      code=HTTP_FORBIDDEN;
      break;
		default:
			msg=ERROR_404;
			l=sizeof(ERROR_404)-1;
			code=HTTP_NOT_FOUND;
			break;
	}

	syslog(LOG_DEBUG, "%s: (pid:'%lu', o:'%p')Internally managed error: %s, code %d.", __func__, pthread_self(), SessionOffInstanceHolder(instance_sesn_ptr), msg, code);

	onion_response_set_code(res,code);
	onion_response_set_length(res, l);
	onion_response_write_headers(instance_sesn_ptr, res);

	onion_response_write(instance_sesn_ptr, res,msg,l);

	return OCS_PROCESSED;
}
