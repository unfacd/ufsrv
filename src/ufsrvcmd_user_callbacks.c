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
#include <misc.h>
#include <location.h>
#include <fence.h>
#include <user_backend.h>
#include <protocol_websocket.h>
#include <ufsrvcmd_user_callbacks.h>

extern ufsrv *const masterptr;

#define _COMMAND_RESPONSE(x, y, z) \
	/*we are responding to a request*/\
	if (wsm_ptr->type==WEB_SOCKET_MESSAGE__TYPE__REQUEST)\
	{\
		TransmissionMessage tmsg={0};\
		WebSocketMessage wsmsg=WEB_SOCKET_MESSAGE__INIT;\
		WebSocketResponseMessage wsmsg_r=WEB_SOCKET_RESPONSE_MESSAGE__INIT;\
		\
		wsmsg.response=&wsmsg_r;\
		wsmsg.type=WEB_SOCKET_MESSAGE__TYPE__RESPONSE;\
		wsmsg.has_type=1;\
		wsmsg.command=x;\
		wsmsg_r.id=wsm_ptr->request->id;\
		wsmsg_r.status=y;\
		if (z)\
		{\
			wsmsg_r.message=z;\
		}\
		\
		tmsg.msg=(void *)&wsmsg;\
		tmsg.type=TRANSMSG_PROTOBUF;\
		\
		if (UfsrvCommandMarshalTransmission (sesn_ptr, NULL, &tmsg, 0)>=0)\
		{\
			__RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)\
		}\
	}

#if 0
#define _COMMAND_RESPONSE_MSGLOAD(x, y, z) \
	/*we are responding to a request*/\
	if (wsm_ptr->type==WEB_SOCKET_MESSAGE__TYPE__REQUEST)\
	{\
		TransmissionMessage tmsg;\
		WebSocketMessage wsmsg=WEB_SOCKET_MESSAGE__INIT;\
		WebSocketResponseMessage wsmsg_r=WEB_SOCKET_RESPONSE_MESSAGE__INIT;\
		\
		wsmsg.response=&wsmsg_r;\
		wsmsg.type=WEB_SOCKET_MESSAGE__TYPE__RESPONSE;\
		wsmsg.has_type=1;\
		wsmsg.command=x;\
		wsmsg_r.id=wsm_ptr->request->id;\
		wsmsg_r.status=y;\
		if (z)\
		{\
			wsmsg_r.body.len=fence_command__get_packed_size((FenceCommand *)z);\
			wsmsg_r.body.data=calloc(1, wsmsg_r.body.len);\
			fence_commnd__pack (z, wsmsg_r.body.data);\
			web_socket_message__pack ((FenceCommand *)z, wsmsg_r.body.data);\
			wsmsg_r.has_body=1;\
		}\
		\
		tmsg.msg=(void *)&wsmsg;\
		tmsg.type=TRANSMSG_PROTOBUF;\
		\
		if (UfsrvCommandMarshalTransmission (sesn_ptr, NULL, &tmsg, 0)>=0)\
		{\
			__RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);\
		}\
	}
#endif

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
		if (UfsrvCommandMarshalTransmission (sesn_ptr, NULL, &tmsg, 0)>=0) {\
			__RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);\
		}\
	}

//0
UFSRV_USER_COMMAND(uOK_V1)
{
	//we are responding to a request
	if (wsm_ptr->type==WEB_SOCKET_MESSAGE__TYPE__REQUEST)
	{
		TransmissionMessage		tmsg				={0};
		WebSocketMessage			wsmsg				= WEB_SOCKET_MESSAGE__INIT;
		WebSocketResponseMessage	wsmsg_r	= WEB_SOCKET_RESPONSE_MESSAGE__INIT;

		wsmsg_r.id=wsm_ptr->request->id;
		wsmsg_r.status=200;
		wsmsg.response=&wsmsg_r;

		wsmsg.command="/v1/KeepAlive";
		wsmsg.type=WEB_SOCKET_MESSAGE__TYPE__RESPONSE; wsmsg.has_type=1;

		tmsg.msg=(void *)&wsmsg;
		tmsg.type=TRANSMSG_PROTOBUF;

		if (UfsrvCommandMarshalTransmission (sesn_ptr, NULL, &tmsg, 0)>=0) {
			__RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);
		}
	}

	__RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);

}

//1 REUSED FOR CONNECTION REJECTION AND SESSION INVALIDATION
UFSRV_USER_COMMAND(uACCOUNT_VERIFIED_V1)
{
	syslog (LOG_DEBUG, "%s: CALLBACK: ...", __func__);

  if (IS_PRESENT(JsonFormatStateSyncForSessionState(sesn_ptr, INVALID_COOKIE, jobj))) {
    char *json_str=(char *)json_object_to_json_string(jobj);

    //client can request this anytime to sync its own state
    if (wsm_ptr && wsm_ptr->type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) {
//      _COMMAND_RESPONSE("/v1/StateSync", 200, json_str)
    } else {//could be null wsm, we build our own
      _COMMAND_REQUEST("/v1/StateSync", 0, json_str)
    }
  }
  __RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);

}


//TODO: TEMPORARILY USED FOR RECEIPT COMMAND

UFSRV_USER_COMMAND(uSETACCOUNT_ATTRS_V1)
{
	UfsrvCommandMarshallingDescription	*ufsrv_descpription_ptr	= (UfsrvCommandMarshallingDescription *)msgload;
	TransmissionMessage					tmsg          = {0};
	WebSocketMessage__Type			type;
	WebSocketMessage						wsmsg					= WEB_SOCKET_MESSAGE__INIT;


	wsmsg.command="ufsrv://v1/Receipt";

	tmsg.msg=(void *)&wsmsg;
	tmsg.type=TRANSMSG_PROTOBUF;
	tmsg.eid=ufsrv_descpription_ptr->eid;
	tmsg.fid=ufsrv_descpription_ptr->fid;
	tmsg.timestamp=ufsrv_descpription_ptr->timestamp;

	if (wsm_ptr)	type=wsm_ptr->type;
	else					type=WEB_SOCKET_MESSAGE__TYPE__RESPONSE;

	if (type==WEB_SOCKET_MESSAGE__TYPE__RESPONSE)
	{
		WebSocketResponseMessage wsmsg_r=WEB_SOCKET_RESPONSE_MESSAGE__INIT;

		wsmsg.response=&wsmsg_r;
		wsmsg.type=WEB_SOCKET_MESSAGE__TYPE__RESPONSE; wsmsg.has_type=1;

		if (msgload)
		{
			wsmsg_r.body.len=(*ufsrv_descpription_ptr->metadata->sizer)(ufsrv_descpription_ptr->payload);
			wsmsg_r.body.data=calloc(1, wsmsg_r.body.len);
			ufsrv_descpription_ptr->metadata->packer(ufsrv_descpription_ptr->payload, wsmsg_r.body.data);
			wsmsg_r.has_body=1;
		}
	}
	else
	if (type==WEB_SOCKET_MESSAGE__TYPE__REQUEST)
	{
		WebSocketRequestMessage wsmsg_rq=WEB_SOCKET_REQUEST_MESSAGE__INIT;

		wsmsg.request=&wsmsg_rq;
		wsmsg.type=WEB_SOCKET_MESSAGE__TYPE__REQUEST; wsmsg.has_type=1;

		if (msgload)
		{
			wsmsg_rq.body.len=(*ufsrv_descpription_ptr->metadata->sizer)(ufsrv_descpription_ptr->payload);
			wsmsg_rq.body.data=calloc(1, wsmsg_rq.body.len);
			ufsrv_descpription_ptr->metadata->packer(ufsrv_descpription_ptr->payload, wsmsg_rq.body.data);
			wsmsg_rq.has_body=1;
		}
	}
	else
	{
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
	}

	if ((UfsrvCommandMarshalTransmission(sesn_ptr, target, &tmsg, 0))>=0)
	{
		if ((wsmsg.type==WEB_SOCKET_MESSAGE__TYPE__REQUEST) && (wsmsg.request->has_body))	free(wsmsg.request->body.data);
		else
		if ((wsmsg.type==WEB_SOCKET_MESSAGE__TYPE__RESPONSE) && (wsmsg.response->has_body))	free(wsmsg.response->body.data);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);

}

UFSRV_USER_COMMAND(uACCOUNT_GCM_V1)
{
	_COMMAND_RESPONSE("/v1/AccountGcm", 200, NULL)

	__RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
}


UFSRV_USER_COMMAND(uACCOUNT_DIR_V1)
{
	char *json_str;
	if (jobj)
	{
		json_str=(char *)json_object_to_json_string(jobj);//this str gets automatically deleted when jobj is 'put'
	}
	else
	{
		json_str="{\"contacts\":[]}";
	}

	_COMMAND_RESPONSE("/v1/AccountDirectory", 200, json_str)

	__RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);

}

//TODO: TEMPORARILY USED FOR CALL COMMAND
UFSRV_USER_COMMAND(uSETKEYS_V1)
{
	UfsrvCommandMarshallingDescription	*ufsrv_descpription_ptr	= (UfsrvCommandMarshallingDescription *)msgload;
	TransmissionMessage					tmsg					= {0};
	WebSocketMessage__Type			type;
	WebSocketMessage						wsmsg					= WEB_SOCKET_MESSAGE__INIT;


	wsmsg.command="ufsrv://v1/Call";

	tmsg.msg=(void *)&wsmsg;
	tmsg.type=TRANSMSG_PROTOBUF;
	tmsg.eid=ufsrv_descpription_ptr->eid;
	tmsg.fid=ufsrv_descpription_ptr->fid;
	tmsg.timestamp=ufsrv_descpription_ptr->timestamp;

	if (wsm_ptr)	type=wsm_ptr->type;
	else	type=WEB_SOCKET_MESSAGE__TYPE__RESPONSE;

	if (type==WEB_SOCKET_MESSAGE__TYPE__RESPONSE)
	{
		WebSocketResponseMessage wsmsg_r=WEB_SOCKET_RESPONSE_MESSAGE__INIT;

		wsmsg.response=&wsmsg_r;
		wsmsg.type=WEB_SOCKET_MESSAGE__TYPE__RESPONSE; wsmsg.has_type=1;

		if (msgload)
		{
			wsmsg_r.body.len=(*ufsrv_descpription_ptr->metadata->sizer)(ufsrv_descpription_ptr->payload);
			wsmsg_r.body.data=calloc(1, wsmsg_r.body.len);
			ufsrv_descpription_ptr->metadata->packer(ufsrv_descpription_ptr->payload, wsmsg_r.body.data);
			wsmsg_r.has_body=1;
		}
	}
	else
	if (type==WEB_SOCKET_MESSAGE__TYPE__REQUEST)
	{
		WebSocketRequestMessage wsmsg_rq=WEB_SOCKET_REQUEST_MESSAGE__INIT;

		wsmsg.request=&wsmsg_rq;
		wsmsg.type=WEB_SOCKET_MESSAGE__TYPE__REQUEST; wsmsg.has_type=1;

		if (msgload)
		{
			wsmsg_rq.body.len=(*ufsrv_descpription_ptr->metadata->sizer)(ufsrv_descpription_ptr->payload);
			wsmsg_rq.body.data=calloc(1, wsmsg_rq.body.len);
			ufsrv_descpription_ptr->metadata->packer(ufsrv_descpription_ptr->payload, wsmsg_rq.body.data);
			wsmsg_rq.has_body=1;
		}
	}
	else
	{
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
	}

	if ((UfsrvCommandMarshalTransmission(sesn_ptr, target, &tmsg, 0))>=0)
	{
		if ((wsmsg.type==WEB_SOCKET_MESSAGE__TYPE__REQUEST) && (wsmsg.request->has_body))	free(wsmsg.request->body.data);
		else
		if ((wsmsg.type==WEB_SOCKET_MESSAGE__TYPE__RESPONSE) && (wsmsg.response->has_body))	free(wsmsg.response->body.data);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);

}


//TODO: Temporarily used for USER COMMAND
UFSRV_USER_COMMAND(uGETKEYS_V1)
{
	UfsrvCommandMarshallingDescription		*ufsrv_descpription_ptr	= (UfsrvCommandMarshallingDescription *)msgload;
	TransmissionMessage										tmsg 										= {0};
	WebSocketMessage__Type								type;
	WebSocketMessage											wsmsg										= WEB_SOCKET_MESSAGE__INIT;


	wsmsg.command="ufsrv://v1/User";

	tmsg.msg=(void *)&wsmsg;
	tmsg.type=TRANSMSG_PROTOBUF;
	tmsg.eid=ufsrv_descpription_ptr->eid;
//	tmsg.fid=ufsrv_descpription_ptr->fid;
	tmsg.timestamp=ufsrv_descpription_ptr->timestamp;

	if (wsm_ptr)	type=wsm_ptr->type;
	else	type=WEB_SOCKET_MESSAGE__TYPE__RESPONSE;

	if (type==WEB_SOCKET_MESSAGE__TYPE__RESPONSE)
	{
		WebSocketResponseMessage wsmsg_r=WEB_SOCKET_RESPONSE_MESSAGE__INIT;\
		\
		wsmsg.response=&wsmsg_r;\
		wsmsg.type=WEB_SOCKET_MESSAGE__TYPE__RESPONSE; wsmsg.has_type=1;\

		if (msgload)\
		{
			wsmsg_r.body.len=(*ufsrv_descpription_ptr->metadata->sizer)(ufsrv_descpription_ptr->payload);
			wsmsg_r.body.data=calloc(1, wsmsg_r.body.len);
			ufsrv_descpription_ptr->metadata->packer(ufsrv_descpription_ptr->payload, wsmsg_r.body.data);
			wsmsg_r.has_body=1;
		}\
	}
	else
	if (type==WEB_SOCKET_MESSAGE__TYPE__REQUEST)
	{
		WebSocketRequestMessage wsmsg_rq=WEB_SOCKET_REQUEST_MESSAGE__INIT;\

		\
		wsmsg.request=&wsmsg_rq;\
		wsmsg.type=WEB_SOCKET_MESSAGE__TYPE__REQUEST; wsmsg.has_type=1;\

		if (msgload)
		{
			wsmsg_rq.body.len=(*ufsrv_descpription_ptr->metadata->sizer)(ufsrv_descpription_ptr->payload);
			wsmsg_rq.body.data=calloc(1, wsmsg_rq.body.len);
			ufsrv_descpription_ptr->metadata->packer(ufsrv_descpription_ptr->payload, wsmsg_rq.body.data);
			wsmsg_rq.has_body=1;
		}
	}
	else
	{
		syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu', wsm_type:'%d'} ERROR: UNKNOWN WSM MESSAGE TYPE...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), type);
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
	}

	if ((UfsrvCommandMarshalTransmission(sesn_ptr, target, &tmsg, 0))>=0)
	{
		if ((wsmsg.type==WEB_SOCKET_MESSAGE__TYPE__REQUEST) && (wsmsg.request->has_body))	free(wsmsg.request->body.data);\
		else
		if ((wsmsg.type==WEB_SOCKET_MESSAGE__TYPE__RESPONSE) && (wsmsg.response->has_body))	free(wsmsg.response->body.data);\

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);\
	}\

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);

}

UFSRV_USER_COMMAND(uMSG_V1)
{
	UfsrvCommandMarshallingDescription	*ufsrv_descpription_ptr	= (UfsrvCommandMarshallingDescription *)msgload;
	TransmissionMessage					tmsg				= {0};
	WebSocketMessage__Type				type;
	WebSocketMessage					wsmsg					= WEB_SOCKET_MESSAGE__INIT;


	wsmsg.command="ufsrv://v1/Message";

	tmsg.msg=(void *)&wsmsg;
	tmsg.type=TRANSMSG_PROTOBUF;
	tmsg.eid=ufsrv_descpription_ptr->eid;
	tmsg.fid=ufsrv_descpription_ptr->fid;
	tmsg.timestamp=ufsrv_descpription_ptr->timestamp;

	if (wsm_ptr)	type=wsm_ptr->type;
	else	type=WEB_SOCKET_MESSAGE__TYPE__RESPONSE;

	if (type==WEB_SOCKET_MESSAGE__TYPE__RESPONSE)
	{
		WebSocketResponseMessage wsmsg_r=WEB_SOCKET_RESPONSE_MESSAGE__INIT;

		wsmsg.response=&wsmsg_r;
		wsmsg.type=WEB_SOCKET_MESSAGE__TYPE__RESPONSE; wsmsg.has_type=1;

		if (msgload)
		{
			wsmsg_r.body.len=(*ufsrv_descpription_ptr->metadata->sizer)(ufsrv_descpription_ptr->payload);
			wsmsg_r.body.data=calloc(1, wsmsg_r.body.len);
			ufsrv_descpription_ptr->metadata->packer(ufsrv_descpription_ptr->payload, wsmsg_r.body.data);
			wsmsg_r.has_body=1;
		}
	}
	else
	if (type==WEB_SOCKET_MESSAGE__TYPE__REQUEST)
	{
		WebSocketRequestMessage wsmsg_rq=WEB_SOCKET_REQUEST_MESSAGE__INIT;

		wsmsg.request=&wsmsg_rq;
		wsmsg.type=WEB_SOCKET_MESSAGE__TYPE__REQUEST; wsmsg.has_type=1;

		if (msgload)
		{
			wsmsg_rq.body.len=(*ufsrv_descpription_ptr->metadata->sizer)(ufsrv_descpription_ptr->payload);
			wsmsg_rq.body.data=calloc(1, wsmsg_rq.body.len);
			ufsrv_descpription_ptr->metadata->packer(ufsrv_descpription_ptr->payload, wsmsg_rq.body.data);
			wsmsg_rq.has_body=1;
		}
	}
	else
	{
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
	}

	if ((UfsrvCommandMarshalTransmission(sesn_ptr, target, &tmsg, 0))>=0)
	{
		if ((wsmsg.type==WEB_SOCKET_MESSAGE__TYPE__REQUEST) && (wsmsg.request->has_body))	free(wsmsg.request->body.data);
		else
		if ((wsmsg.type==WEB_SOCKET_MESSAGE__TYPE__RESPONSE) && (wsmsg.response->has_body))	free(wsmsg.response->body.data);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);

}

//8
UFSRV_USER_COMMAND(uLOCATION_V1)
{
	//we are responding to a request
	if (wsm_ptr->type==WEB_SOCKET_MESSAGE__TYPE__REQUEST)
	{
		//assuming job is cleaned up before
		if (JsonFormatUserLocation(sesn_ptr, jobj))//load jobj with current location description
		{
			char *json_str=(char *)json_object_to_json_string(jobj);//this str gets automatically deleted when jobj is 'put'
			_COMMAND_RESPONSE("/v1/Location", 200, json_str)
		}
		else
		{
			syslog (LOG_DEBUG, "%s (cid: '%lu) ERROR COULD NOT LOAD LOACTION INTO JSON...", __func__, SESSION_ID(sesn_ptr));
		}
	}
	else
	//if (wsm_ptr->type==WEB_SOCKET_MESSAGE__TYPE__RESPONSE)
	{
		//we are building a request
	}

	__RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
}

/**
 *	9
 * 	@dynamic_memory smsg_r.body.data: dynamically allocated to pack FenceCommand into, once packed it it free'd herein
 */
UFSRV_USER_COMMAND(uFENCE_V1)
{
#if 1
	UfsrvCommandMarshallingDescription	*ufsrv_descpription_ptr	= (UfsrvCommandMarshallingDescription *)msgload;
	TransmissionMessage					tmsg        = {0};
	WebSocketMessage__Type			type;
	WebSocketMessage					  wsmsg				= WEB_SOCKET_MESSAGE__INIT;


	wsmsg.command="ufsrv://v1/Fence";

	tmsg.msg=(void *)&wsmsg;
	tmsg.type=TRANSMSG_PROTOBUF;
	tmsg.eid=ufsrv_descpription_ptr->eid;
	tmsg.fid=ufsrv_descpription_ptr->fid;
	tmsg.timestamp=ufsrv_descpription_ptr->timestamp;

	if (wsm_ptr)	type=wsm_ptr->type;
	else	type=WEB_SOCKET_MESSAGE__TYPE__RESPONSE;

	if (type==WEB_SOCKET_MESSAGE__TYPE__RESPONSE)
	{
		WebSocketResponseMessage wsmsg_r=WEB_SOCKET_RESPONSE_MESSAGE__INIT;\
		\
		wsmsg.response=&wsmsg_r;\
		wsmsg.type=WEB_SOCKET_MESSAGE__TYPE__RESPONSE; wsmsg.has_type=1;\

		if (msgload)\
		{
			wsmsg_r.body.len=(*ufsrv_descpription_ptr->metadata->sizer)(ufsrv_descpription_ptr->payload);
			wsmsg_r.body.data=calloc(1, wsmsg_r.body.len);
			ufsrv_descpription_ptr->metadata->packer(ufsrv_descpription_ptr->payload, wsmsg_r.body.data);
			wsmsg_r.has_body=1;
		}\
	}
	else
	if (type==WEB_SOCKET_MESSAGE__TYPE__REQUEST)
	{
		WebSocketRequestMessage wsmsg_rq=WEB_SOCKET_REQUEST_MESSAGE__INIT;\

		\
		wsmsg.request=&wsmsg_rq;\
		wsmsg.type=WEB_SOCKET_MESSAGE__TYPE__REQUEST; wsmsg.has_type=1;\

		if (msgload)
		{
			wsmsg_rq.body.len=(*ufsrv_descpription_ptr->metadata->sizer)(ufsrv_descpription_ptr->payload);
			wsmsg_rq.body.data=calloc(1, wsmsg_rq.body.len);
			ufsrv_descpription_ptr->metadata->packer(ufsrv_descpription_ptr->payload, wsmsg_rq.body.data);
			wsmsg_rq.has_body=1;
		}
	}
	else
	{
		syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu', wsm_type:'%d'} ERROR: UNKNOWN WSM MESSAGE TYPE...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), type);
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
	}

	if ((UfsrvCommandMarshalTransmission(sesn_ptr, target, &tmsg, 0))>=0)
	{
		if ((wsmsg.type==WEB_SOCKET_MESSAGE__TYPE__REQUEST) && (wsmsg.request->has_body))	free(wsmsg.request->body.data);\
		else
		if ((wsmsg.type==WEB_SOCKET_MESSAGE__TYPE__RESPONSE) && (wsmsg.response->has_body))	free(wsmsg.response->body.data);\

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);\
	}\

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);


#endif
}

//10
UFSRV_USER_COMMAND(uSTATESYNC_V1)
{
	if (IS_PRESENT(JsonFormatStateSync (sesn_ptr, DIGESTMODE_BRIEF, false, jobj))) {
		char *json_str=(char *)json_object_to_json_string(jobj);//this str gets automatically deleted when jobj is 'put'

		//client can request this anytime to sync its own state
		if (wsm_ptr && wsm_ptr->type==WEB_SOCKET_MESSAGE__TYPE__REQUEST) {

			_COMMAND_RESPONSE("/v1/StateSync", 200, json_str)
		} else {//could be null wsm, we build our own

			_COMMAND_REQUEST("/v1/StateSync", 0, json_str)
		}
	}
	__RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
}
