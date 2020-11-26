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

#include <thread_context_type.h>
#include "protocol_websocket.h"
#include <ufsrvcmd_user_callbacks.h>
#include <ufsrvcmd_callbacks.h>
#include <ufsrv_core/SignalService.pb-c.h>
#include <command_controllers.h>
#include <recycler/recycler.h>

/**
 * These are server bound commands invoked by users via the WebSocket channel. This is in contrast to user bound commands
 * initiated by the server (commands prefixed with 'u' as opposed to 's'), which are invoked via @UfsrvCommandInvokeCommand
 * Currently few incoming user commands are processed via these callbacks.
 */

extern __thread ThreadContext ufsrv_thread_context;

//0
UFSRV_COMMAND(sKEEPALIVE_V1)
{
	return (UfsrvCommandInvokeUserCommand(ctx_ptr, NULL, wsm_ptr, NULL, NULL, uOK_V1_IDX));

}

#include <call_command_broadcast.h>
//1
UFSRV_COMMAND(sCALL_V1) {
  DataMessage *data_ptr = (DataMessage *)dm_ptr;
  Session *sesn_ptr = ctx_ptr->sesn_ptr;

  if ((VerifyCallCommandFromUser(_WIRE_PROTOCOL_DATA(data_ptr->ufsrvcommand->callcommand))) < 0) {
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROTOCOL_CMD_VERIFICATION)
  }

  SESSION_WHEN_SERVICE_STARTED(sesn_ptr) = time(NULL);
  //>>>>>>>>><<<<<<<<<<
  CommandCallbackControllerCallCommand (ctx_ptr, wsm_ptr, dm_ptr);
  //>>>>>>>>><<<<<<<<<<
  SESSION_WHEN_SERVICED(sesn_ptr) = time(NULL);

  syslog (LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', o:'%p'}: CALLBACK: EXECUTED", __func__, pthread_self(), THREAD_CONTEXT_PTR, sesn_ptr);

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_NOOP, RESCODE_PROG_NULL_POINTER)

}

//2
UFSRV_COMMAND(sUSER_V1) {
  Session *sesn_ptr = ctx_ptr->sesn_ptr;

  syslog (LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', o:'%p'}: CALLBACK: ... (NONE EXECUTED)", __func__, pthread_self(), THREAD_CONTEXT_PTR, sesn_ptr);

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_NOOP, RESCODE_PROG_NULL_POINTER)

}

//3
UFSRV_COMMAND(sACCOUNT_GCM_V1)
{
  Session *sesn_ptr = ctx_ptr->sesn_ptr;
//
//	//we are responding to a request
//	if (wsm_ptr->type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) {
//		syslog (LOG_DEBUG, "%s (cid:'%lu'): GCM id:'%s'...", __func__, SESSION_ID(sesn_ptr), wsm_ptr->request->verb?wsm_ptr->request->verb:"not_set");
//		if (1) {
//			char *gcm_id=wsm_ptr->request->verb?wsm_ptr->request->verb:"";
//			size_t gcm_id_len=0;
//			//length has to be max of LBUF-1 to allow for terminating null when we memcpy belowif the len is large
//			if ((gcm_id_len=strlen(gcm_id))>SMBUF-1) {
//				gcm_id="";
//				gcm_id_len=0;
//			} else {
//				ReloadCMToken(sesn_ptr, gcm_id);
//			}
//
//			DbSetGcmId (sesn_ptr, &(SESSION_UFSRVUIDSTORE(sesn_ptr)), 1, gcm_id);
//
//			return (UfsrvCommandInvokeUserCommand(ctx_ptr, NULL, wsm_ptr, NULL, NULL, uACCOUNT_GCM_V1_IDX));
//		}
//	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

//4
#include <state_command_broadcast.h>
#include <state_command_controller.h>
UFSRV_COMMAND(sACTIVITY_STATE_V1)
{
  DataMessage *data_ptr = (DataMessage *)dm_ptr;
  Session *sesn_ptr = ctx_ptr->sesn_ptr;

  if ((VerifyStateCommandFromUser(_WIRE_PROTOCOL_DATA(data_ptr->ufsrvcommand->statecommand))) < 0) {
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROTOCOL_CMD_VERIFICATION)
  }

  SESSION_WHEN_SERVICE_STARTED(sesn_ptr) = time(NULL);
  //>>>>>>>>><<<<<<<<<<
  CommandCallbackControllerStateCommand (ctx_ptr, wsm_ptr, dm_ptr);
  //>>>>>>>>><<<<<<<<<<
  SESSION_WHEN_SERVICED(sesn_ptr) = time(NULL);

  syslog (LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', o:'%p'}: CALLBACK: EXECUTED", __func__, pthread_self(), THREAD_CONTEXT_PTR, sesn_ptr);

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_NOOP, RESCODE_PROG_NULL_POINTER)

}

//{
// "identityKey":"BVtqnUDDutbzzz0KVEqgmyJ7hiin3joVhOIoi5Y4kWEB",
// "lastResortKey":{"keyId":16777215,"publicKey":"BdbtzhknZ/q0Um2I+W7RNXTXOK9i4f0x0Oyphr2Kw6Uq"},
// "preKeys":[{"keyId":647918,"publicKey":"BVo3cFV1eb95XvAbC8sS25snmUwc/zs4utWa6vhaR5J7"},...]
//}
//5
UFSRV_COMMAND(sSET_KEYS_V1)
{
  Session *sesn_ptr = ctx_ptr->sesn_ptr;

//	syslog (LOG_DEBUG, "%s: CALLBACK: ...", __func__);
//
//	//we are responding to a request
//	if (wsm_ptr->type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) {
//		syslog (LOG_DEBUG, "%s (cid:'%lu'): CREATING PREKEY entries...", __func__, SESSION_ID(sesn_ptr));
//
//		if ((SetUserKeys (sesn_ptr, &(SESSION_UFSRVUIDSTORE(sesn_ptr)), jobj, DEFAULT_DEVICE_ID)==0)) {
//			return (UfsrvCommandInvokeUserCommand(ctx_ptr, NULL, wsm_ptr, jobj, NULL, uSETKEYS_V1_IDX));
//		}
//	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

//6
UFSRV_COMMAND(sGET_KEYS_V1)
{
  Session *sesn_ptr = ctx_ptr->sesn_ptr;
	syslog (LOG_DEBUG, "%s: CALLBACK: ...", __func__);

	//we are responding to a request
	if (wsm_ptr->type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) {
		syslog (LOG_DEBUG, "%s (cid:'%lu'): GETTING PREKEY entries...", __func__, SESSION_ID(sesn_ptr));
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

//7
UFSRV_COMMAND(sMSG_V1)
{
  Session *sesn_ptr = ctx_ptr->sesn_ptr;

	syslog (LOG_DEBUG, "%s: CALLBACK: ...", __func__);

	//we are responding to a request
	if (wsm_ptr->type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) {
		//syslog (LOG_DEBUG, "%s (cid:'%lu'): GETTING PREKEY entries...", __func__, SESSION_ID(sesn_ptr));
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

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
#include <location_broadcast.h>
#include <location_command_controller.h>
/**
 * 	@locks: Fence *
 * 	@unlocks: Fence *
 * 	@locked: Session *
 */
UFSRV_COMMAND(sLOCATION_V1)
{
  DataMessage *data_ptr = (DataMessage *)dm_ptr;
  Session *sesn_ptr = ctx_ptr->sesn_ptr;

  if ((VerifyLocationCommandForIntra(_WIRE_PROTOCOL_DATA(data_ptr->ufsrvcommand->locationcommand))) < 0) {
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROTOCOL_CMD_VERIFICATION)
  }

  SESSION_WHEN_SERVICE_STARTED(sesn_ptr) = time(NULL);
  //>>>>>>>>><<<<<<<<<<
  CommandCallbackControllerLocationCommand (ctx_ptr, wsm_ptr, dm_ptr);
  //>>>>>>>>><<<<<<<<<<
  SESSION_WHEN_SERVICED(sesn_ptr) = time(NULL);

  syslog (LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', o:'%p'}: CALLBACK: EXECUTED", __func__, pthread_self(), THREAD_CONTEXT_PTR, sesn_ptr);

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_NOOP, RESCODE_PROG_NULL_POINTER)

  //todo port away from json. payload should be in protobuf
//	//we are responding to a request
//	if (wsm_ptr->type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) {
//		unsigned short origin					=	0;
//		int location_status						=	json_object_get_int(json__get(jobj, "status"));
//		LocationDescription *loc_ptr	=	NULL;
//
//		json_bool self_zoned = json_object_get_boolean(json__get(jobj, "isSelfZoned"));
//		if (self_zoned != 0)	USER_ATTRIBUTE_SET(sesn_ptr, USERATTRIBUTE_DEFINES_USERZONE);
//
//		//0: completely resolved, 1: partially 2: unknown. In partially we could be missing any of the address components
//		if (location_status > 0) {
//			loc_ptr = DetermineLocationByServerByJson (sesn_ptr, GetHttpRequestContext(sesn_ptr), jobj);
//			origin = 1;
//		} else {
//			UpdateUserLocationByUser(sesn_ptr, jobj, CALL_FLAG_BROADCAST_SESSION_EVENT|CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND);
//			loc_ptr = (LocationDescription *)SESSION_RESULT_USERDATA(sesn_ptr);
//			origin = 2;
//		}
//
//		//clean up for reuse
//		_CLEANUP_LOCTION_JSON_OBJECT;
//
//		//creates a base fence if one doesn't not already exist
//	   switch (ProcessUserLocation(ctx_ptr->instance_sesn_ptr, loc_ptr, origin))
//	   {
//		   case LOCATION_STATE_UNCHANGED:
//			   //do nothing
//		   break;
//
//		   case LOCATION_STATE_CHANGED:
//		   case LOCATION_STATE_INITIALISED:
//		   {
//         UfsrvCommandInvokeUserCommand(ctx_ptr, NULL, wsm_ptr, jobj, NULL, uLOCATION_V1_IDX);
//				if (sesn_ptr->sservice.result.result_type == RESULT_TYPE_ERR)	_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
//
//				_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
//		   }//case
//		   break;
//
//		   case LOCATION_STATE_UNINITIALISED:
//			 {
//				syslog (LOG_NOTICE, "%s (pid:'%lu',  cid:'%lu'): COULD NOT INITIALISE USER LOCATION", __func__, pthread_self(), sesn_ptr->session_id);
//
//				_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_LOCATIONERR, RESCODE_LOCATION_UNINIT)
//			 }
//
//		   case LOCATION_STATE_ERROR:
//		   {
//			   syslog (LOG_NOTICE, "%s (pid:'%lu', cid:'%lu'): ERROR: COULD NOT INITIALISE USER LOCATION", __func__, pthread_self(), sesn_ptr->session_id);
//
//			   _RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_LOCATIONERR, RESCODE_LOCATION_UNINIT)
//		   }
//	   }//switch
//	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

#include <fence_broadcast.h>
//9
UFSRV_COMMAND(sFENCE_V1)
{
  DataMessage *data_ptr = (DataMessage *)dm_ptr;
  Session *sesn_ptr = ctx_ptr->sesn_ptr;

  if ((VerifyFenceCommandFromUser(_WIRE_PROTOCOL_DATA(data_ptr->ufsrvcommand->fencecommand))) < 0) {
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROTOCOL_CMD_VERIFICATION)
  }

  SESSION_WHEN_SERVICE_STARTED(sesn_ptr) = time(NULL);
  //>>>>>>>>><<<<<<<<<<
  CommandCallbackControllerFenceCommand(ctx_ptr->instance_sesn_ptr, wsm_ptr, dm_ptr);
  //>>>>>>>>><<<<<<<<<<
  SESSION_WHEN_SERVICED(sesn_ptr) = time(NULL);

  syslog (LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', o:'%p'}: CALLBACK: EXECUTED", __func__, pthread_self(), THREAD_CONTEXT_PTR, sesn_ptr);

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_NOOP, RESCODE_PROG_NULL_POINTER)

}

//10
UFSRV_COMMAND(sSTATESYNC_V1)
{
  Session *sesn_ptr = ctx_ptr->sesn_ptr;
//	//we are responding to a request
//	if (wsm_ptr->type == WEB_SOCKET_MESSAGE__TYPE__REQUEST) {
//		return (UfsrvCommandInvokeUserCommand(ctx_ptr, NULL, wsm_ptr, jobj, NULL, uSTATESYNC_V1_IDX));
//	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
}





