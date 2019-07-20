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
#include <misc.h>
#include <fence.h>
#include <user_backend.h>
#include <protocol_websocket.h>
#include <protocol_websocket_session.h>
#include <ufsrvcmd_user_callbacks.h>
#include <ufsrvcmd_callbacks.h>
#include <SignalService.pb-c.h>
#include <command_controllers.h>
#include <location.h>

//Currently few incoming user commands are processed via these callbacks.

//0
UFSRV_COMMAND(sKEEPALIVE_V1)

{
#ifdef __UF_FULLDEBUG
	syslog (LOG_DEBUG, "%s: CALLBACK: ...", __func__);
#endif

	return (UfsrvCommandInvokeCommand (sesn_ptr, NULL, wsm_ptr, jobj, NULL, uOK_V1_IDX));

}

//1
UFSRV_COMMAND(sVERIFY_NEW_ACCOUNT_V1)

{
	__RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_NOOP, RESCODE_PROG_NULL_POINTER);

}

//2
UFSRV_COMMAND(sSET_ACCOUNT_ATTRIBUTES_V1)

{
	syslog (LOG_DEBUG, "%s: CALLBACK: ... (NONE EXECUTED)", __func__);

	//we are responding to a request
//	if (wsm_ptr->type==WEB_SOCKET_MESSAGE__TYPE__REQUEST)
//	{
//		syslog (LOG_DEBUG, "%s (cid:'%lu'): CREATING PREKEY entries...", __func__, SESSION_ID(sesn_ptr));
//
//		if ((SetUserKeys (sesn_ptr, jobj, 1)==0))
//		{
//			return (UfsrvCommandInvokeCommand (sesn_ptr, NULL, wsm_ptr, jobj, NULL, uSETACCOUNT_ATTRS_V1));
//		}
//	}

	__RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);

}

//3
UFSRV_COMMAND(sACCOUNT_GCM_V1)
{
	//we are responding to a request
	if (wsm_ptr->type==WEB_SOCKET_MESSAGE__TYPE__REQUEST) {
		syslog (LOG_DEBUG, "%s (cid:'%lu'): GCM id:'%s'...", __func__, SESSION_ID(sesn_ptr), wsm_ptr->request->verb?wsm_ptr->request->verb:"not_set");
		if (1) {
			char *gcm_id=wsm_ptr->request->verb?wsm_ptr->request->verb:"";
			size_t gcm_id_len=0;
			//length has to be max of LBUF-1 to allow for terminating null when we memcpy belowif the len is large
			if ((gcm_id_len=strlen(gcm_id))>SMBUF-1) {
				gcm_id="";
				gcm_id_len=0;
			} else {
				ReloadCMToken(sesn_ptr, gcm_id);
			}

			DbSetGcmId (sesn_ptr, &(SESSION_UFSRVUIDSTORE(sesn_ptr)), 1, gcm_id);

			return (UfsrvCommandInvokeCommand (sesn_ptr, NULL, wsm_ptr, jobj, NULL, uACCOUNT_GCM_V1_IDX));
		}
	}

	__RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);

}

//4
//{"contacts":["HSasDj77+hyY5w","WGYFTryHOznWVg","26p5JSZkr9mHxA"]}
UFSRV_COMMAND(sACCOUNT_DIR_V1)
{
	syslog (LOG_DEBUG, "%s: CALLBACK: ...", __func__);
	//we are responding to a request
	if (wsm_ptr->type==WEB_SOCKET_MESSAGE__TYPE__REQUEST) {
	}//request_type

	__RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_NOOP, RESCODE_PROG_NULL_POINTER);

}

//{
// "identityKey":"BVtqnUDDutbzzz0KVEqgmyJ7hiin3joVhOIoi5Y4kWEB",
// "lastResortKey":{"keyId":16777215,"publicKey":"BdbtzhknZ/q0Um2I+W7RNXTXOK9i4f0x0Oyphr2Kw6Uq"},
// "preKeys":[{"keyId":647918,"publicKey":"BVo3cFV1eb95XvAbC8sS25snmUwc/zs4utWa6vhaR5J7"},...]
//}
//5
UFSRV_COMMAND(sSET_KEYS_V1)
{
	syslog (LOG_DEBUG, "%s: CALLBACK: ...", __func__);

	//we are responding to a request
	if (wsm_ptr->type==WEB_SOCKET_MESSAGE__TYPE__REQUEST) {
		syslog (LOG_DEBUG, "%s (cid:'%lu'): CREATING PREKEY entries...", __func__, SESSION_ID(sesn_ptr));

		if ((SetUserKeys (sesn_ptr, &(SESSION_UFSRVUIDSTORE(sesn_ptr)), jobj, DEFAULT_DEVICE_ID)==0)) {
			return (UfsrvCommandInvokeCommand (sesn_ptr, NULL, wsm_ptr, jobj, NULL, uSETKEYS_V1_IDX));
		}
	}

	__RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);

}

//6
UFSRV_COMMAND(sGET_KEYS_V1)
{
	syslog (LOG_DEBUG, "%s: CALLBACK: ...", __func__);

	//we are responding to a request
	if (wsm_ptr->type==WEB_SOCKET_MESSAGE__TYPE__REQUEST)
	{
		syslog (LOG_DEBUG, "%s (cid:'%lu'): GETTING PREKEY entries...", __func__, SESSION_ID(sesn_ptr));
	}

	__RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);

}

//7
UFSRV_COMMAND(sMSG_V1)
{
	syslog (LOG_DEBUG, "%s: CALLBACK: ...", __func__);

	//we are responding to a request
	if (wsm_ptr->type==WEB_SOCKET_MESSAGE__TYPE__REQUEST)
	{
		//syslog (LOG_DEBUG, "%s (cid:'%lu'): GETTING PREKEY entries...", __func__, SESSION_ID(sesn_ptr));
	}

	__RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);

}

#define _CLEANUP_LOCTION_JSON_OBJECT\
		json_object_object_del(jobj, "longitude");\
				json_object_object_del(jobj, "longitude");\
				json_object_object_del(jobj, "status");\
				json_object_object_del(jobj, "origin");\
				json_object_object_del(jobj, "locality");\
				json_object_object_del(jobj, "country");\
				json_object_object_del(jobj, "adminArea")

//{"adminArea":"New South Wales","country":"Australia","latitude":-33.8495328,"locality":"Auburn","longitude":151.0231204,"status":0}'


//8
/**
 * 	@locks: Fence *
 * 	@unlocks: Fence *
 * 	@locked: Session *
 */
UFSRV_COMMAND(sLOCATION_V1)
{
	//we are responding to a request
	if (wsm_ptr->type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) {
		unsigned short origin					=	0;
		int location_status						=	json_object_get_int(json__get(jobj, "status"));
		LocationDescription *loc_ptr	=	NULL;

		json_bool self_zoned = json_object_get_boolean(json__get(jobj, "isSelfZoned"));
		if (self_zoned != 0)	USER_ATTRIBUTE_SET(sesn_ptr, USERATTRIBUTE_DEFINES_USERZONE);

		//0: completely resolved, 1: partially 2: unknown. In partially we could be missing any of the address components
		if (location_status > 0) {
			loc_ptr = DetermineLocationByServerByJson (sesn_ptr, GetHttpRequestContext(sesn_ptr), jobj);
			origin = 1;
		} else {
			UpdateUserLocationByUser(sesn_ptr, jobj, CALL_FLAG_BROADCAST_SESSION_EVENT|CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND);
			loc_ptr = (LocationDescription *)SESSION_RESULT_USERDATA(sesn_ptr);
			origin = 2;
		}

		//clean up for reuse
		_CLEANUP_LOCTION_JSON_OBJECT;

		//creates a base fence if one doesn't not already exist
	   switch (ProcessUserLocation(sesn_ptr, loc_ptr, origin))
	   {
		   case LOCATION_STATE_UNCHANGED:
			   //do nothing
		   break;

		   case LOCATION_STATE_CHANGED:
		   case LOCATION_STATE_INITIALISED:
		   {
				UfsrvCommandInvokeCommand (sesn_ptr, NULL, wsm_ptr, jobj, NULL, uLOCATION_V1_IDX);
				if (sesn_ptr->sservice.result.result_type == RESULT_TYPE_ERR)	_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);

				_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
		   }//case
		   break;

		   case LOCATION_STATE_UNINITIALISED:
			 {
				syslog (LOG_NOTICE, "%s (pid:'%lu' cid:'%lu'): COULD NOT INITIALISE USER LOCATION", __func__, pthread_self(), sesn_ptr->session_id);

				_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_LOCATIONERR, RESCODE_LOCATION_UNINIT)
			 }

		   case LOCATION_STATE_ERROR:
		   {
			   syslog (LOG_NOTICE, "%s (pid:'%lu' cid:'%lu'): ERROR: COULD NOT INITIALISE USER LOCATION", __func__, pthread_self(), sesn_ptr->session_id);

			   _RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_LOCATIONERR, RESCODE_LOCATION_UNINIT)
		   }
	   }//switch
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);

}

//9
UFSRV_COMMAND(sFENCE_V1)
{
#if 0
	//reflects old format
	syslog (LOG_DEBUG, "%s: CALLBACK: ...", __func__);

	//we are responding to a request
	if (wsm_ptr->type==WEB_SOCKET_MESSAGE__TYPE__REQUEST)
	{
		FenceCommand *fence_cmd=fence_command__unpack(NULL, wsm_ptr->request->body.len, wsm_ptr->request->body.data);
		if (fence_cmd->command)
		{
			FenceRecord *fence_record_ptr=NULL;

			//syslog (LOG_DEBUG, "%s: Received '%d' fence references: ...", __func__, fence_cmd->n_fence);

			if (fence_cmd->n_fences)
			{
				fence_record_ptr=fence_cmd->fences[0];
				syslog (LOG_DEBUG, "%s: PROCESSING FENCE: '%s' ...", __func__, fence_record_ptr->fname);

			}
			else
			{
				syslog (LOG_DEBUG, "%s: FENCE COMMAND CONTAINED NO FENCE REFERENCES...", __func__);

				__RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);
			}

			if (strcasecmp(FENCECMND_JOIN, fence_cmd->command)==0)
			{	//TODO: rafactor to use FenceCommand instead of FenceRecord
				return(UfsrvCommandCallbackControllerFenceJoin (sesn_ptr, wsm_ptr, NULL));//fence_record_ptr));
			}
			else
			if (strcasecmp(FENCECMND_LEAVE, fence_cmd->command)==0)
			{

			}
			else
			if (strcasecmp(FENCECMND_UPDATE, fence_cmd->command)==0)
			{

			}
			else
			{
				syslog (LOG_NOTICE, "%s: UNKNOWN FENCE COMMAND: '%s'...", __func__, fence_cmd->command);
			}

		}
#if 0
		if ((strcasecmp(wsm_ptr->request->path, "MAKE"))==0)
		{
			//const char *json_string=json_object_to_json_string(jobj);
			//syslog (LOG_DEBUG, "%s: JSON ARGUMENTS STRING: '%s'...", __func__, json_string?json_string:"VALUE NOT SET");
			//ProtobufCBinaryData
			DataMessage *datamsg=data_message__unpack(NULL, wsm_ptr->request->body.len, wsm_ptr->request->body.data);
			if (datamsg)
			{
				syslog (LOG_DEBUG, "%s: MAKING FENCE: '%s'. Number of users: '%lu'", __func__, datamsg->group->name, datamsg->group->n_members);

			}

			return (UfsrvCommandInvokeCommand (sesn_ptr, wsm_ptr, jobj, uOK_V1_IDX));
		}
		else
		{
			const char *json_string=json_object_to_json_string(jobj);
			syslog (LOG_DEBUG, "%s: FENCE COMMAND UNKNOWN. JSON ARGUMENTS STRING: '%s'...", __func__, json_string?json_string:"VALUE NOT SET");

		}
#endif
		__RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);
	}
#endif
	__RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);

}

//10
UFSRV_COMMAND(sSTATESYNC_V1)
{
	//we are responding to a request
	if (wsm_ptr->type==WEB_SOCKET_MESSAGE__TYPE__REQUEST) {
		return (UfsrvCommandInvokeCommand (sesn_ptr, NULL, wsm_ptr, jobj, NULL, uSTATESYNC_V1_IDX));
	}

	__RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
}



