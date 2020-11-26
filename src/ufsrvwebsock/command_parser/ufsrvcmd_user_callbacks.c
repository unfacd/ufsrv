/**
 * Copyright (C) 2015-2019 unfacd works
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <nportredird.h>
#include <ufsrv_core/location/location.h>
#include <ufsrvwebsock/include/protocol_websocket.h>
#include <ufsrvcmd_user_callbacks.h>

/**
 * @brief These are client-bound command invocations which can happen either as responses, or server-initiated requests through
 * the dedicated Websocket connection.
 * WEB_SOCKET_MESSAGE__TYPE__REQUEST and WEB_SOCKET_MESSAGE__TYPE__RESPONSE type reflect the semantic ordering of messaging. Initiator
 * always sends WEB_SOCKET_MESSAGE__TYPE__REQUEST.
 */

extern ufsrv *const masterptr;

#define _COMMAND_RESPONSE(x, y, z) \
	/*we are responding to a request*/\
	if (wsm_ptr_received->type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) {\
		TransmissionMessage tmsg = {0};\
		WebSocketMessage wsmsg = WEB_SOCKET_MESSAGE__INIT;\
		WebSocketResponseMessage wsmsg_r = WEB_SOCKET_RESPONSE_MESSAGE__INIT;\
		\
		wsmsg.response = &wsmsg_r;\
		wsmsg.type = WEB_SOCKET_MESSAGE__TYPE__RESPONSE;\
		wsmsg.has_type = 1;\
		wsmsg.command = x;\
		wsmsg_r.id = wsm_ptr_received->request->id;\
		wsmsg_r.status = y; wsmsg_r.has_status = 1;\
		if (z) {\
			wsmsg_r.message = z;\
		}\
		\
		tmsg.msg = (void *)&wsmsg;\
		tmsg.type = TRANSMSG_PROTOBUF;\
		\
		if (UfsrvCommandMarshalTransmission (ctx_ptr, NULL, &tmsg, 0) >= 0) {\
			_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)\
		}\
	}

#define _COMMAND_REQUEST(x, y, z) \
	/*we are responding to a request*/\
	{\
		TransmissionMessage tmsg = {0};\
		WebSocketMessage wsmsg   = WEB_SOCKET_MESSAGE__INIT;\
		WebSocketRequestMessage wsmsg_r = WEB_SOCKET_REQUEST_MESSAGE__INIT;\
		\
		wsmsg.request = &wsmsg_r;\
		wsmsg.type    = WEB_SOCKET_MESSAGE__TYPE__REQUEST;\
		wsmsg.has_type= 1;\
		wsmsg.command = x;\
		wsmsg_r.id    = time(NULL);\
		if (z) {\
			wsmsg_r.path = z;\
		}\
		\
		tmsg.msg  = (void *)&wsmsg;\
		tmsg.type = TRANSMSG_PROTOBUF;\
		\
		if (UfsrvCommandMarshalTransmission (ctx_ptr, NULL, &tmsg, 0) >= 0) {\
			_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)\
		}\
	}

//0
UFSRV_USER_COMMAND(uOK_V1)
{
	if (wsm_ptr_received->type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) {
		TransmissionMessage		tmsg				={0};
		WebSocketMessage			wsmsg				= WEB_SOCKET_MESSAGE__INIT;
		WebSocketResponseMessage	wsmsg_r	= WEB_SOCKET_RESPONSE_MESSAGE__INIT;

		wsmsg_r.id = wsm_ptr_received->request->id; wsmsg_r.has_id = 1;
		wsmsg_r.status = 200; wsmsg_r.has_status = 1;
		wsmsg.response = &wsmsg_r;

		wsmsg.command = wsm_ptr_received->command;
		wsmsg.type = WEB_SOCKET_MESSAGE__TYPE__RESPONSE; wsmsg.has_type = 1;

		tmsg.msg = (void *)&wsmsg;
		tmsg.type = TRANSMSG_PROTOBUF;

		if (UfsrvCommandMarshalTransmission (ctx_ptr, NULL, &tmsg, 0) >= 0) {
			_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
		}
	}

	_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

//1 REUSED FOR CONNECTION REJECTION AND SESSION INVALIDATION
UFSRV_USER_COMMAND(uACCOUNT_VERIFIED_V1)
{
	syslog (LOG_DEBUG, "%s: CALLBACK: ...", __func__);

  if (IS_PRESENT(JsonFormatStateSyncForSessionState(ctx_ptr->sesn_ptr, INVALID_COOKIE, jobj))) {
    char *json_str = (char *)json_object_to_json_string(jobj);

    //client can request this anytime to sync its own state
    if (wsm_ptr_received && wsm_ptr_received->type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) {
//      _COMMAND_RESPONSE("/v1/StateSync", 200, json_str)
    } else {//could be null wsm, we build our own
      _COMMAND_REQUEST("/v1/StateSync", 0, json_str)
    }
  }
  _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);

}

//TODO: TEMPORARILY USED FOR RECEIPT COMMAND
UFSRV_USER_COMMAND(uSETACCOUNT_ATTRS_V1)
{
	UfsrvCommandMarshallingDescriptor	*ufsrv_descpription_ptr	= (UfsrvCommandMarshallingDescriptor *)msgload;
	TransmissionMessage					tmsg          = {0};
	WebSocketMessage__Type			type;
	WebSocketMessage						wsmsg					= WEB_SOCKET_MESSAGE__INIT;

	wsmsg.command="ufsrv://v1/Receipt";

	tmsg.msg = (void *)&wsmsg;
	tmsg.type = TRANSMSG_PROTOBUF;
	tmsg.eid = ufsrv_descpription_ptr->eid;
	tmsg.fid = ufsrv_descpription_ptr->fid;
	tmsg.timestamp = ufsrv_descpription_ptr->timestamp;

	if (wsm_ptr_received)	type = wsm_ptr_received->type;
	else					type = WEB_SOCKET_MESSAGE__TYPE__RESPONSE;

	if (type == WEB_SOCKET_MESSAGE__TYPE__RESPONSE) {
		WebSocketResponseMessage wsmsg_r = WEB_SOCKET_RESPONSE_MESSAGE__INIT;

		wsmsg.response = &wsmsg_r;
		wsmsg.type = WEB_SOCKET_MESSAGE__TYPE__RESPONSE; wsmsg.has_type=1;

		if (msgload) {
			wsmsg_r.body.len = (*ufsrv_descpription_ptr->metadata->sizer)(ufsrv_descpription_ptr->payload);
			wsmsg_r.body.data = calloc(1, wsmsg_r.body.len);
			ufsrv_descpription_ptr->metadata->packer(ufsrv_descpription_ptr->payload, wsmsg_r.body.data);
			wsmsg_r.has_body = 1;
		}
	} else if (type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) {
		WebSocketRequestMessage wsmsg_rq = WEB_SOCKET_REQUEST_MESSAGE__INIT;

		wsmsg.request = &wsmsg_rq;
		wsmsg.type = WEB_SOCKET_MESSAGE__TYPE__REQUEST; wsmsg.has_type=1;

		if (msgload) {
			wsmsg_rq.body.len = (*ufsrv_descpription_ptr->metadata->sizer)(ufsrv_descpription_ptr->payload);
			wsmsg_rq.body.data = calloc(1, wsmsg_rq.body.len);
			ufsrv_descpription_ptr->metadata->packer(ufsrv_descpription_ptr->payload, wsmsg_rq.body.data);
			wsmsg_rq.has_body = 1;
		}
	} else {
		_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}

	if ((UfsrvCommandMarshalTransmission(ctx_ptr, ctx_ptr_target, &tmsg, 0)) >= 0) {
		if ((wsmsg.type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) && (wsmsg.request->has_body))	free(wsmsg.request->body.data);
		else
		if ((wsmsg.type == WEB_SOCKET_MESSAGE__TYPE__RESPONSE) && (wsmsg.response->has_body))	free(wsmsg.response->body.data);

		_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
	}

	_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

UFSRV_USER_COMMAND(uSYNC_V1)
{
  UfsrvCommandMarshallingDescriptor	*ufsrv_description_ptr	= (UfsrvCommandMarshallingDescriptor *)msgload;
  TransmissionMessage					tmsg				= {0};
  WebSocketMessage__Type				type;
  WebSocketMessage					wsmsg					= WEB_SOCKET_MESSAGE__INIT;

  wsmsg.command = "ufsrv://v1/Sync";

  tmsg.msg = (void *)&wsmsg;
  tmsg.type = TRANSMSG_PROTOBUF;
  tmsg.eid = ufsrv_description_ptr->eid;
  tmsg.fid = ufsrv_description_ptr->fid;
  tmsg.timestamp = ufsrv_description_ptr->timestamp;

  if (wsm_ptr_received)	type = wsm_ptr_received->type;
  else	type = WEB_SOCKET_MESSAGE__TYPE__RESPONSE;

  if (type == WEB_SOCKET_MESSAGE__TYPE__RESPONSE) {
    WebSocketResponseMessage wsmsg_r = WEB_SOCKET_RESPONSE_MESSAGE__INIT;

    wsmsg.response = &wsmsg_r;
    wsmsg.type = WEB_SOCKET_MESSAGE__TYPE__RESPONSE; wsmsg.has_type = 1;

    if (msgload) {
      wsmsg_r.body.len = (*ufsrv_description_ptr->metadata->sizer)(ufsrv_description_ptr->payload);
      wsmsg_r.body.data = calloc(1, wsmsg_r.body.len);
      ufsrv_description_ptr->metadata->packer(ufsrv_description_ptr->payload, wsmsg_r.body.data);
      wsmsg_r.has_body = 1;
    }
  } else if (type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) {
    WebSocketRequestMessage wsmsg_rq = WEB_SOCKET_REQUEST_MESSAGE__INIT;

    wsmsg.request = &wsmsg_rq;
    wsmsg.type = WEB_SOCKET_MESSAGE__TYPE__REQUEST; wsmsg.has_type = 1;

    if (msgload) {
      wsmsg_rq.body.len = (*ufsrv_description_ptr->metadata->sizer)(ufsrv_description_ptr->payload);
      wsmsg_rq.body.data = calloc(1, wsmsg_rq.body.len);
      ufsrv_description_ptr->metadata->packer(ufsrv_description_ptr->payload, wsmsg_rq.body.data);
      wsmsg_rq.has_body = 1;
    }
  } else {
    _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  if ((UfsrvCommandMarshalTransmission(ctx_ptr, ctx_ptr_target, &tmsg, 0)) >= 0) {
    if ((wsmsg.type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) && (wsmsg.request->has_body))	free(wsmsg.request->body.data);
    else
    if ((wsmsg.type == WEB_SOCKET_MESSAGE__TYPE__RESPONSE) && (wsmsg.response->has_body))	free(wsmsg.response->body.data);

    _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
  }

  _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
}

UFSRV_USER_COMMAND(uSTATE_V1)
{
  UfsrvCommandMarshallingDescriptor	*ufsrv_description_ptr	= (UfsrvCommandMarshallingDescriptor *)msgload;
  TransmissionMessage					tmsg					= {0};
  WebSocketMessage__Type			type;
  WebSocketMessage						wsmsg					= WEB_SOCKET_MESSAGE__INIT;

  wsmsg.command="ufsrv://v1/ActivityState";

  tmsg.msg = (void *)&wsmsg;
  tmsg.type = TRANSMSG_PROTOBUF;
  tmsg.eid = ufsrv_description_ptr->eid;
  tmsg.fid = ufsrv_description_ptr->fid;
  tmsg.timestamp = ufsrv_description_ptr->timestamp;

  if (wsm_ptr_received)	type = wsm_ptr_received->type;
  else	type = WEB_SOCKET_MESSAGE__TYPE__RESPONSE;

  if (type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) {
    WebSocketRequestMessage wsmsg_rq = WEB_SOCKET_REQUEST_MESSAGE__INIT;

    wsmsg.request = &wsmsg_rq;
    wsmsg.type = WEB_SOCKET_MESSAGE__TYPE__REQUEST; wsmsg.has_type = 1;

    if (msgload) {
      wsmsg_rq.body.len = (*ufsrv_description_ptr->metadata->sizer)(ufsrv_description_ptr->payload);
      wsmsg_rq.body.data = calloc(1, wsmsg_rq.body.len);
      ufsrv_description_ptr->metadata->packer(ufsrv_description_ptr->payload, wsmsg_rq.body.data);
      wsmsg_rq.has_body = 1;
    }
  } else if (type == WEB_SOCKET_MESSAGE__TYPE__RESPONSE) {
    goto return_error;
    //state commands are of relay-to-user semantics so this is not applicable
  } else {
    _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  if ((UfsrvCommandMarshalTransmission(ctx_ptr, ctx_ptr_target, &tmsg, 0)) >= 0) {
    if ((wsmsg.type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) && (wsmsg.request->has_body))	free(wsmsg.request->body.data);
    else
    if ((wsmsg.type == WEB_SOCKET_MESSAGE__TYPE__RESPONSE) && (wsmsg.response->has_body))	free(wsmsg.response->body.data);

    _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
  }

  return_error:
  _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

//TODO: TEMPORARILY USED FOR CALL COMMAND
UFSRV_USER_COMMAND(uSETKEYS_V1)
{
	UfsrvCommandMarshallingDescriptor	*ufsrv_description_ptr	= (UfsrvCommandMarshallingDescriptor *)msgload;
	TransmissionMessage					tmsg					= {0};
	WebSocketMessage__Type			type;
	WebSocketMessage						wsmsg					= WEB_SOCKET_MESSAGE__INIT;

	wsmsg.command="ufsrv://v1/Call";

	tmsg.msg = (void *)&wsmsg;
	tmsg.type = TRANSMSG_PROTOBUF;
	tmsg.eid = ufsrv_description_ptr->eid;
	tmsg.fid = ufsrv_description_ptr->fid;
	tmsg.timestamp = ufsrv_description_ptr->timestamp;

	if (wsm_ptr_received)	type = wsm_ptr_received->type;
	else	type = WEB_SOCKET_MESSAGE__TYPE__RESPONSE;

	if (type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) {
		WebSocketRequestMessage wsmsg_rq = WEB_SOCKET_REQUEST_MESSAGE__INIT;

		wsmsg.request = &wsmsg_rq;
		wsmsg.type = WEB_SOCKET_MESSAGE__TYPE__REQUEST; wsmsg.has_type = 1;

		if (msgload) {
			wsmsg_rq.body.len = (*ufsrv_description_ptr->metadata->sizer)(ufsrv_description_ptr->payload);
			wsmsg_rq.body.data = calloc(1, wsmsg_rq.body.len);
      ufsrv_description_ptr->metadata->packer(ufsrv_description_ptr->payload, wsmsg_rq.body.data);
			wsmsg_rq.has_body = 1;
		}
	} else if (type == WEB_SOCKET_MESSAGE__TYPE__RESPONSE) {
	  goto return_error;
	  //call commands are of relay-to-user semantics so this is not applicable
//    WebSocketResponseMessage wsmsg_r = WEB_SOCKET_RESPONSE_MESSAGE__INIT;
//
//    wsmsg.response = &wsmsg_r;
//    wsmsg.type = WEB_SOCKET_MESSAGE__TYPE__RESPONSE; wsmsg.has_type = 1;
//
//    if (msgload) {
//      wsmsg_r.body.len = (*ufsrv_descpription_ptr->metadata->sizer)(ufsrv_descpription_ptr->payload);
//      wsmsg_r.body.data = calloc(1, wsmsg_r.body.len);
//      ufsrv_descpription_ptr->metadata->packer(ufsrv_descpription_ptr->payload, wsmsg_r.body.data);
//      wsmsg_r.has_body = 1;
//    }
  } else {
		_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}

	if ((UfsrvCommandMarshalTransmission(ctx_ptr, ctx_ptr_target, &tmsg, 0)) >= 0) {
		if ((wsmsg.type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) && (wsmsg.request->has_body))	free(wsmsg.request->body.data);
		else
		if ((wsmsg.type == WEB_SOCKET_MESSAGE__TYPE__RESPONSE) && (wsmsg.response->has_body))	free(wsmsg.response->body.data);

		_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
	}

  return_error:
	_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

//TODO: Temporarily used for USER COMMAND
UFSRV_USER_COMMAND(uGETKEYS_V1)
{
	UfsrvCommandMarshallingDescriptor		*ufsrv_descpription_ptr	= (UfsrvCommandMarshallingDescriptor *)msgload;
	TransmissionMessage										tmsg 										= {0};
	WebSocketMessage__Type								type;
	WebSocketMessage											wsmsg										= WEB_SOCKET_MESSAGE__INIT;


	wsmsg.command="ufsrv://v1/User";

	tmsg.msg = (void *)&wsmsg;
	tmsg.type = TRANSMSG_PROTOBUF;
	tmsg.eid = ufsrv_descpription_ptr->eid;
	tmsg.timestamp = ufsrv_descpription_ptr->timestamp;

	if (wsm_ptr_received)	type = wsm_ptr_received->type;
	else	type = WEB_SOCKET_MESSAGE__TYPE__RESPONSE;

	if (type == WEB_SOCKET_MESSAGE__TYPE__RESPONSE) {
		WebSocketResponseMessage wsmsg_r = WEB_SOCKET_RESPONSE_MESSAGE__INIT;

		wsmsg.response = &wsmsg_r;
		wsmsg.type = WEB_SOCKET_MESSAGE__TYPE__RESPONSE; wsmsg.has_type=1;

		if (msgload) {
			wsmsg_r.body.len = (*ufsrv_descpription_ptr->metadata->sizer)(ufsrv_descpription_ptr->payload);
			wsmsg_r.body.data = calloc(1, wsmsg_r.body.len);
			ufsrv_descpription_ptr->metadata->packer(ufsrv_descpription_ptr->payload, wsmsg_r.body.data);
			wsmsg_r.has_body = 1;
		}
	} else if (type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) {
		WebSocketRequestMessage wsmsg_rq=WEB_SOCKET_REQUEST_MESSAGE__INIT;

		wsmsg.request = &wsmsg_rq;
		wsmsg.type = WEB_SOCKET_MESSAGE__TYPE__REQUEST; wsmsg.has_type=1;

		if (msgload) {
			wsmsg_rq.body.len = (*ufsrv_descpription_ptr->metadata->sizer)(ufsrv_descpription_ptr->payload);
			wsmsg_rq.body.data = calloc(1, wsmsg_rq.body.len);
			ufsrv_descpription_ptr->metadata->packer(ufsrv_descpription_ptr->payload, wsmsg_rq.body.data);
			wsmsg_rq.has_body = 1;
		}
	} else {
		syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu', wsm_type:'%d'} ERROR: UNKNOWN WSM MESSAGE TYPE...", __func__, pthread_self(), ctx_ptr->sesn_ptr, SESSION_ID(ctx_ptr->sesn_ptr), type);
		_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}

	if ((UfsrvCommandMarshalTransmission(ctx_ptr, ctx_ptr_target, &tmsg, 0)) >= 0) {
		if ((wsmsg.type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) && (wsmsg.request->has_body))	free(wsmsg.request->body.data);
		else
		if ((wsmsg.type == WEB_SOCKET_MESSAGE__TYPE__RESPONSE) && (wsmsg.response->has_body))	free(wsmsg.response->body.data);

		_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
	}

	_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

UFSRV_USER_COMMAND(uMSG_V1)
{
	UfsrvCommandMarshallingDescriptor	*ufsrv_descpription_ptr	= (UfsrvCommandMarshallingDescriptor *)msgload;
	TransmissionMessage					tmsg				= {0};
	WebSocketMessage__Type				type;
	WebSocketMessage					wsmsg					= WEB_SOCKET_MESSAGE__INIT;


	wsmsg.command = "ufsrv://v1/Message";

	tmsg.msg = (void *)&wsmsg;
	tmsg.type = TRANSMSG_PROTOBUF;
	tmsg.eid = ufsrv_descpription_ptr->eid;
	tmsg.fid = ufsrv_descpription_ptr->fid;
	tmsg.timestamp = ufsrv_descpription_ptr->timestamp;

	if (wsm_ptr_received)	type = wsm_ptr_received->type;
	else	type = WEB_SOCKET_MESSAGE__TYPE__RESPONSE;

	if (type == WEB_SOCKET_MESSAGE__TYPE__RESPONSE) {
		WebSocketResponseMessage wsmsg_r = WEB_SOCKET_RESPONSE_MESSAGE__INIT;

		wsmsg.response = &wsmsg_r;
		wsmsg.type = WEB_SOCKET_MESSAGE__TYPE__RESPONSE; wsmsg.has_type=1;

		if (msgload) {
			wsmsg_r.body.len = (*ufsrv_descpription_ptr->metadata->sizer)(ufsrv_descpription_ptr->payload);
			wsmsg_r.body.data = calloc(1, wsmsg_r.body.len);
			ufsrv_descpription_ptr->metadata->packer(ufsrv_descpription_ptr->payload, wsmsg_r.body.data);
			wsmsg_r.has_body = 1;
		}
	} else if (type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) {
		WebSocketRequestMessage wsmsg_rq = WEB_SOCKET_REQUEST_MESSAGE__INIT;

		wsmsg.request = &wsmsg_rq;
		wsmsg.type = WEB_SOCKET_MESSAGE__TYPE__REQUEST; wsmsg.has_type=1;

		if (msgload) {
			wsmsg_rq.body.len=(*ufsrv_descpription_ptr->metadata->sizer)(ufsrv_descpription_ptr->payload);
			wsmsg_rq.body.data=calloc(1, wsmsg_rq.body.len);
			ufsrv_descpription_ptr->metadata->packer(ufsrv_descpription_ptr->payload, wsmsg_rq.body.data);
			wsmsg_rq.has_body=1;
		}
	} else {
		_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}

	if ((UfsrvCommandMarshalTransmission(ctx_ptr, ctx_ptr_target, &tmsg, 0)) >= 0) {
		if ((wsmsg.type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) && (wsmsg.request->has_body))	free(wsmsg.request->body.data);
		else
		if ((wsmsg.type == WEB_SOCKET_MESSAGE__TYPE__RESPONSE) && (wsmsg.response->has_body))	free(wsmsg.response->body.data);

		_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
	}

	_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

//8
UFSRV_USER_COMMAND(uLOCATION_V1)
{
	/*//we are responding to a request
	if (wsm_ptr->type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) {
		//assuming job is cleaned up before
		if (JsonFormatUserLocation(ctx_ptr->sesn_ptr, jobj)) {//load jobj with current location description
			char *json_str = (char *)json_object_to_json_string(jobj);//this str gets automatically deleted when jobj is 'put'
			_COMMAND_RESPONSE("/v1/Location", 200, json_str)
		} else {
			syslog (LOG_DEBUG, "%s (cid: '%lu) ERROR COULD NOT LOAD LOACTION INTO JSON...", __func__, SESSION_ID(ctx_ptr->sesn_ptr));
		}
	} else { //if (wsm_ptr->type==WEB_SOCKET_MESSAGE__TYPE__RESPONSE)
		//we are building a request
	}

	_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)*/

	//current semantics for Location involves responding to locatio for changes initiated (REQUEST) by clients
  UfsrvCommandMarshallingDescriptor	*ufsrv_descpription_ptr	= (UfsrvCommandMarshallingDescriptor *)msgload;
  TransmissionMessage					tmsg          = {0};
  WebSocketMessage__Type			type;
  WebSocketMessage						wsmsg					= WEB_SOCKET_MESSAGE__INIT;

  wsmsg.command = "ufsrv://v1/Location"; //note no 'ufsrv://' prefix

  tmsg.msg = (void *)&wsmsg;
  tmsg.type = TRANSMSG_PROTOBUF;
  tmsg.eid = ufsrv_descpription_ptr->eid;
  tmsg.fid = ufsrv_descpription_ptr->fid;
  tmsg.timestamp = ufsrv_descpription_ptr->timestamp;

  if (IS_PRESENT(wsm_ptr_received))	type = wsm_ptr_received->type;
  else					type = WEB_SOCKET_MESSAGE__TYPE__RESPONSE;

  //The logic here is inverted. If original type was request, reply with 'response'
  if (type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) {
    WebSocketResponseMessage wsmsg_r = WEB_SOCKET_RESPONSE_MESSAGE__INIT;

    wsmsg.response = &wsmsg_r;
    wsmsg.type = WEB_SOCKET_MESSAGE__TYPE__RESPONSE; wsmsg.has_type = 1;
    wsmsg_r.id = wsm_ptr_received->request->id; wsmsg_r.has_id = 1;
    wsmsg_r.status = 200; wsmsg_r.has_status = 1;

    if (msgload) {
      wsmsg_r.body.len = (*ufsrv_descpription_ptr->metadata->sizer)(ufsrv_descpription_ptr->payload);
      wsmsg_r.body.data = calloc(1, wsmsg_r.body.len);
      ufsrv_descpription_ptr->metadata->packer(ufsrv_descpription_ptr->payload, wsmsg_r.body.data);
      wsmsg_r.has_body = 1;
    }
  } else if (type == WEB_SOCKET_MESSAGE__TYPE__RESPONSE) {
    WebSocketRequestMessage wsmsg_rq = WEB_SOCKET_REQUEST_MESSAGE__INIT;

    wsmsg.request = &wsmsg_rq;
    wsmsg.type = WEB_SOCKET_MESSAGE__TYPE__REQUEST; wsmsg.has_type = 1;

    if (msgload) {
      wsmsg_rq.body.len = (*ufsrv_descpription_ptr->metadata->sizer)(ufsrv_descpription_ptr->payload);
      wsmsg_rq.body.data = calloc(1, wsmsg_rq.body.len);
      ufsrv_descpription_ptr->metadata->packer(ufsrv_descpription_ptr->payload, wsmsg_rq.body.data);
      wsmsg_rq.has_body = 1;
    }
  } else {
    _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  if ((UfsrvCommandMarshalTransmission(ctx_ptr, ctx_ptr_target, &tmsg, 0)) >= 0) {
    if ((wsmsg.type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) && (wsmsg.request->has_body))	free(wsmsg.request->body.data);
    else
    if ((wsmsg.type == WEB_SOCKET_MESSAGE__TYPE__RESPONSE) && (wsmsg.response->has_body))	free(wsmsg.response->body.data);

    _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
  }

  _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
}

/**
 *	9
 * 	@dynamic_memory smsg_r.body.data: dynamically allocated to pack FenceCommand into, once packed it it free'd herein
 */
UFSRV_USER_COMMAND(uFENCE_V1)
{
	UfsrvCommandMarshallingDescriptor	*ufsrv_descpription_ptr	= (UfsrvCommandMarshallingDescriptor *)msgload;
	TransmissionMessage					tmsg        = {0};
	WebSocketMessage__Type			type;
	WebSocketMessage					  wsmsg				= WEB_SOCKET_MESSAGE__INIT;

	wsmsg.command = "ufsrv://v1/Fence";

	tmsg.msg = (void *)&wsmsg;
	tmsg.type = TRANSMSG_PROTOBUF;
	tmsg.eid = ufsrv_descpription_ptr->eid;
	tmsg.fid = ufsrv_descpription_ptr->fid;
	tmsg.timestamp = ufsrv_descpription_ptr->timestamp;

	if (IS_PRESENT(wsm_ptr_received))	{
	  type = wsm_ptr_received->type;
	}
	else	type = WEB_SOCKET_MESSAGE__TYPE__RESPONSE;

	if (type == WEB_SOCKET_MESSAGE__TYPE__RESPONSE) {
		WebSocketResponseMessage wsmsg_r = WEB_SOCKET_RESPONSE_MESSAGE__INIT;

		wsmsg.response = &wsmsg_r;
		wsmsg.type = WEB_SOCKET_MESSAGE__TYPE__RESPONSE; wsmsg.has_type = 1;

		wsmsg_r.status = 200; wsmsg_r.has_status = 1;
    if (IS_PRESENT(wsm_ptr_received->request) && wsm_ptr_received->request->has_id) {
      //some requests have no
      wsmsg_r.id = wsm_ptr_received->request->id; //e.g incoming StateSync for fences. todo: this should be looked it.
      wsmsg_r.has_id = 1;
    }

		if (msgload) {
			wsmsg_r.body.len = (*ufsrv_descpription_ptr->metadata->sizer)(ufsrv_descpription_ptr->payload);
			wsmsg_r.body.data = calloc(1, wsmsg_r.body.len);
			ufsrv_descpription_ptr->metadata->packer(ufsrv_descpription_ptr->payload, wsmsg_r.body.data);
			wsmsg_r.has_body = 1;
		}
	} else if (type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) {
		WebSocketRequestMessage wsmsg_rq = WEB_SOCKET_REQUEST_MESSAGE__INIT;

		wsmsg.request = &wsmsg_rq;
		wsmsg.type = WEB_SOCKET_MESSAGE__TYPE__REQUEST; wsmsg.has_type = 1;

		if (msgload) {
			wsmsg_rq.body.len = (*ufsrv_descpription_ptr->metadata->sizer)(ufsrv_descpription_ptr->payload);
			wsmsg_rq.body.data = calloc(1, wsmsg_rq.body.len);
			ufsrv_descpription_ptr->metadata->packer(ufsrv_descpription_ptr->payload, wsmsg_rq.body.data);
			wsmsg_rq.has_body = 1;
		}
	} else {
		syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu', wsm_type:'%d'} ERROR: UNKNOWN WSM MESSAGE TYPE...", __func__, pthread_self(), ctx_ptr->sesn_ptr, SESSION_ID(ctx_ptr->sesn_ptr), type);
		_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}

	if ((UfsrvCommandMarshalTransmission(ctx_ptr, ctx_ptr_target, &tmsg, 0)) >= 0) {
		if ((wsmsg.type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) && (wsmsg.request->has_body))	free(wsmsg.request->body.data);
		else
		if ((wsmsg.type == WEB_SOCKET_MESSAGE__TYPE__RESPONSE) && (wsmsg.response->has_body))	free(wsmsg.response->body.data);

		_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
	}

	_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

//10
UFSRV_USER_COMMAND(uSTATESYNC_V1)
{
	if (IS_PRESENT(JsonFormatStateSync(ctx_ptr->sesn_ptr, DIGESTMODE_BRIEF, false, jobj))) {
		char *json_str = (char *)json_object_to_json_string(jobj);//this str gets automatically deleted when jobj is 'put'

		//client can request this anytime to sync its own state
		if (wsm_ptr_received && wsm_ptr_received->type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) {
			_COMMAND_RESPONSE("/v1/StateSync", 200, json_str)
		} else {//could be null wsm, we build our own
			_COMMAND_REQUEST("/v1/StateSync", 0, json_str)
		}
	}

	_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
}
