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
#include <location_command_controller.h>
#include <ufsrvwebsock/include/protocol_websocket.h>
#include <ufsrvcmd_user_callbacks.h>
#include <ufsrvcmd_callbacks.h>
#include <ufsrv_core/msgqueue_backend/ufsrvcmd_broadcast.h>
#include <ufsrv_core/SignalService.pb-c.h>
#include <ufsrv_core/location/location.h>
#include <recycler/recycler.h>
#include <command_controllers.h>
#include <ufsrvuid.h>

extern ufsrv							*const masterptr;
extern __thread ThreadContext ufsrv_thread_context;

typedef struct LocationContext {
  InstanceHolderForSession 							*instance_sesn_ptr_originator; //user for whom command is sent (original sender) matches uid_originator in protobuf
  UfsrvEvent						*event_ptr;
  unsigned long					*eid;
}	LocationContext;

struct MarshalMessageEnvelopeForLocation {
  UfsrvCommandWire		*ufsrv_command_wire;
  Envelope						*envelope;
  LocationCommand 		*location_command;
  CommandHeader 			*header;
  LocationRecord			*location_record;
  UserRecord 				  *originator;
};
typedef struct MarshalMessageEnvelopeForLocation MarshalMessageEnvelopeForLocation;

#define _GENERATE_MESSAGECOMMAND_ENVELOPE_INITIALISATION() \
	UfsrvCommandWire								ufsrv_command_wire	= UFSRV_COMMAND_WIRE__INIT;	\
	Envelope												command_envelope		=	ENVELOPE__INIT;	\
	LocationCommand 								location_command		=	LOCATION_COMMAND__INIT;	\
	CommandHeader 									header							=	COMMAND_HEADER__INIT;	\
	LocationRecord 									location_record     =	LOCATION_RECORD__INIT;	\
	UserRecord 				              user_record_originator; \
	\
	MarshalMessageEnvelopeForLocation	envelope_marshal = {	\
			.ufsrv_command_wire	=	&ufsrv_command_wire,	\
			.envelope						=	&command_envelope,	\
			.location_command		=	&location_command,	\
			.header							=	&header,	\
			.location_record			=	&location_record, \
      .originator         = &user_record_originator \
	}

inline static void
_PrepareMarshalMessageForLocation (MarshalMessageEnvelopeForLocation *envelope_ptr, Session *sesn_ptr, DataMessage *data_msg_ptr_orig, UfsrvEvent *event_ptr, enum _LocationCommand__CommandTypes command_type, enum _CommandArgs command_arg);
inline static UFSRVResult *_CommandControllerLocation (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
inline static UFSRVResult *_CommandControllerLocationAddress (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
inline static UFSRVResult *_CommandControllerLocationLongLat (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
inline static UFSRVResult *_MarshalLocation  (InstanceContextForSession *ctx_ptr, ClientContextData *ctx_data_ptr, DataMessage *data_msg_ptr_received, WebSocketMessage *wsm_ptr_received, UfsrvEvent *event_ptr);
inline static UFSRVResult *_HandleLocationCommandError (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, int rescode, int command_type);

UFSRVResult *
CommandCallbackControllerLocationCommand (InstanceContextForSession *ctx_ptr_local_user, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr)
{
  CommandHeader *command_header = data_msg_ptr->ufsrvcommand->locationcommand->header;

  if (unlikely(IS_EMPTY(command_header)))	_RETURN_RESULT_SESN(SessionOffInstanceHolder(ctx_ptr_local_user->instance_sesn_ptr), NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

  UFSRVResult *res_ptr = NULL;
  switch (command_header->command)
  {
    case LOCATION_COMMAND__COMMAND_TYPES__ADDRESS:
      res_ptr = _CommandControllerLocationAddress(ctx_ptr_local_user, wsm_ptr_received, data_msg_ptr);
      break;

    case LOCATION_COMMAND__COMMAND_TYPES__LONGLAT:
      res_ptr = _CommandControllerLocationLongLat(ctx_ptr_local_user, wsm_ptr_received, data_msg_ptr);
      break;

    case LOCATION_COMMAND__COMMAND_TYPES__LOCATION:
      res_ptr = _CommandControllerLocation(ctx_ptr_local_user, wsm_ptr_received, data_msg_ptr);
      break;
  }

  return res_ptr;

}

inline static UFSRVResult *
_CommandControllerLocationLongLat (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr)
{
  exit_catch_all:
  _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
}

inline static UFSRVResult *
_CommandControllerLocationAddress (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr)
{
  exit_catch_all:
  _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
}

inline static UFSRVResult *
_CommandControllerLocation (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received)
{
  Session *sesn_ptr = ctx_ptr->sesn_ptr;
  LocationCommand *location_command_ptr = data_msg_ptr_received->ufsrvcommand->locationcommand;

  IsUserAllowedToChangeLocation (ctx_ptr, data_msg_ptr_received, wsm_ptr_received, NULL, _MarshalLocation, CALLFLAGS_EMPTY);

  if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))	{
  } else {
    _HandleLocationCommandError(ctx_ptr, wsm_ptr_received, data_msg_ptr_received, SESSION_RESULT_CODE(sesn_ptr), location_command_ptr->header->command);
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

inline static void
_PrepareMarshalMessageForLocation (MarshalMessageEnvelopeForLocation *envelope_ptr, Session *sesn_ptr, DataMessage *data_msg_ptr_orig, UfsrvEvent *event_ptr, enum _LocationCommand__CommandTypes command_type, enum _CommandArgs command_arg)
{
  envelope_ptr->envelope->ufsrvcommand								=	envelope_ptr->ufsrv_command_wire;

  envelope_ptr->envelope->ufsrvcommand->locationcommand		=	envelope_ptr->location_command;
  envelope_ptr->envelope->ufsrvcommand->ufsrvtype			=	UFSRV_COMMAND_WIRE__UFSRV_TYPE__UFSRV_LOCATION;
  envelope_ptr->envelope->ufsrvcommand->header				=	envelope_ptr->header;

  envelope_ptr->location_command->header							=	envelope_ptr->header;

  envelope_ptr->envelope->sourceufsrvuid							=	"0";
  envelope_ptr->envelope->timestamp										=	GetTimeNowInMillis(); envelope_ptr->envelope->has_timestamp = 1;

  envelope_ptr->header->when													=	envelope_ptr->envelope->timestamp; 	envelope_ptr->header->has_when = 1;
  envelope_ptr->header->cid														=	SESSION_ID(sesn_ptr); 							envelope_ptr->header->has_cid = 1;
  envelope_ptr->header->command												=	command_type;
  envelope_ptr->header->args													=	command_arg;												envelope_ptr->header->has_args = 1;

  if (IS_PRESENT(event_ptr)) {
    envelope_ptr->header->when_eid										=	event_ptr->when; 					envelope_ptr->header->has_when_eid = 1;
    envelope_ptr->header->eid													=	event_ptr->eid; 					envelope_ptr->header->has_eid = 1;
  }

  if (IS_PRESENT(data_msg_ptr_orig)) {
    envelope_ptr->header->when_client								  =	data_msg_ptr_orig->ufsrvcommand->locationcommand->header->when;
    envelope_ptr->header->has_when_client						  =	data_msg_ptr_orig->ufsrvcommand->locationcommand->header->has_when_client = 1;
  }

}

inline static UFSRVResult *
_MarshalLocation (InstanceContextForSession *ctx_ptr, ClientContextData *ctx_data_ptr, DataMessage *data_msg_ptr_received, WebSocketMessage *wsm_ptr_received, UfsrvEvent *event_ptr)
{
  _GENERATE_MESSAGECOMMAND_ENVELOPE_INITIALISATION();

  __unused LocationContext *location_ctx_ptr = (LocationContext *)ctx_data_ptr; //currently null

  _PrepareMarshalMessageForLocation (&envelope_marshal, ctx_ptr->sesn_ptr, NULL, NULL, data_msg_ptr_received->ufsrvcommand->locationcommand->header->command, COMMAND_ARGS__SYNCED);

  BuildUserLocationByProto (ctx_ptr->sesn_ptr, envelope_marshal.location_record);

  UfsrvCommandMarshallingDescriptor ufsrv_description = {header.eid, 0, header.when, &EnvelopeMetaData, &command_envelope};
  UfsrvCommandInvokeUserCommand(ctx_ptr, NULL, wsm_ptr_received, NULL, &ufsrv_description, uLOCATION_V1_IDX);//todo: update Websocket message from NULL

  _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

UFSRVResult *
IsUserAllowedToChangeLocation (InstanceContextForSession *ctx_ptr,  DataMessage *data_msg_received,  WebSocketMessage *wsm_ptr_received, UfsrvEvent *event_ptr, CallbackCommandMarshaller command_marshaller, unsigned long call_flags)
{
  LocationRecord *location_record_ptr = data_msg_received->ufsrvcommand->locationcommand->location;

  if (location_record_ptr->source == LOCATION_RECORD__SOURCE__BY_USER) {
    UpdateLocationByProto(ctx_ptr, location_record_ptr);
    if (SESSION_RESULT_TYPE_SUCCESS(ctx_ptr->sesn_ptr) && (SESSION_RESULT_CODE(ctx_ptr->sesn_ptr) == RESCODE_LOCATION_CHANGED || SESSION_RESULT_CODE(ctx_ptr->sesn_ptr) == RESCODE_LOCATION_INIT)) {
      if (IS_PRESENT(command_marshaller)) {
        _INVOKE_COMMAND_MARSHALLER(command_marshaller, ctx_ptr, NULL, data_msg_received, wsm_ptr_received, event_ptr);
      }
    } else {
      return (UfsrvCommandInvokeUserCommand(ctx_ptr, NULL, wsm_ptr_received, NULL, NULL, uOK_V1_IDX));
    }
  }

  _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
}

static void _BuildErrorHeaderForLocationCommand (LocationCommand *command_ptr, LocationCommand *command_ptr_incoming, int errcode, int command_type);
inline static UFSRVResult *_MarshalCommandErrorToUser	(InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_received, Envelope *command_envelope_ptr, unsigned req_cmd_idx);

inline static UFSRVResult *
_HandleLocationCommandError (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, int rescode, int command_type)
{
  Envelope 					command_envelope	= ENVELOPE__INIT;
  CommandHeader 		header						= COMMAND_HEADER__INIT;
  UfsrvCommandWire	ufsrv_command			= UFSRV_COMMAND_WIRE__INIT;
  LocationCommand 			location_command			= LOCATION_COMMAND__INIT;

  Session           *sesn_ptr         = ctx_ptr->sesn_ptr;

  command_envelope.ufsrvcommand				=	&ufsrv_command;
  ufsrv_command.header								=	&header;
  location_command.header							=	&header;

  ufsrv_command.locationcommand				=	&location_command;
  ufsrv_command.ufsrvtype							=	UFSRV_COMMAND_WIRE__UFSRV_TYPE__UFSRV_LOCATION;

  command_envelope.sourceufsrvuid			=	"0";
  command_envelope.timestamp					=	GetTimeNowInMillis(); command_envelope.has_timestamp = 1;

  header.when													=	command_envelope.timestamp; header.has_when		=	1;
  header.cid													=	SESSION_ID(sesn_ptr);				header.has_cid		=	1;

  _BuildErrorHeaderForLocationCommand (&location_command, data_msg_ptr->ufsrvcommand->locationcommand, rescode, command_type);

#ifdef __UF_TESTING
  syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', uid:'%lu', cid:'%lu', arg_error:'%d', rescode:'%d'}: Marshaling Error response message...", __func__, pthread_self(), sesn_ptr, SESSION_USERID(sesn_ptr), SESSION_ID(sesn_ptr), header.args_error, rescode);
#endif

  return (_MarshalCommandErrorToUser(ctx_ptr, wsm_ptr_orig, &command_envelope,  uLOCATION_V1_IDX));

}

static void
_BuildErrorHeaderForLocationCommand (LocationCommand *command_ptr, LocationCommand *command_ptr_incoming, int errcode, int command_type)
{
  CommandHeader *header_ptr_incoming 	= command_ptr_incoming->header;
  CommandHeader *header_ptr 					=	command_ptr->header;

  switch (errcode)
  {
    //todo add relevant error codes
//    case RESCODE_FENCE_INVITATION_LIST:
//      header_ptr->args_error	=	FENCE_COMMAND__ERRORS__INVITE_ONLY; 	header_ptr->has_args_error	=	1;
//      header_ptr->args				=	COMMAND_ARGS__REJECTED;								header_ptr->has_args				=	1;
//      break;

    default:
      break;//goto exit_error;
  }

  if (command_type > 0)		header_ptr->command	=	command_type;
  else									header_ptr->command	=	header_ptr_incoming->command;//restore original command
  header_ptr->when_client	=	header_ptr_incoming->when;							header_ptr->has_when_client = header_ptr_incoming->has_when_client;
  header_ptr->args_error_client	=	header_ptr_incoming->args; 				header_ptr->has_args_error_client = 1;
  return;

  exit_error:
  return;

}

inline static UFSRVResult *
_MarshalCommandErrorToUser	(InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_received, Envelope *command_envelope_ptr, unsigned req_cmd_idx)
{
  Session *sesn_ptr = ctx_ptr->sesn_ptr;

  CommandHeader *command_header_ptr	=	command_envelope_ptr->ufsrvcommand->header;

  UfsrvCommandMarshallingDescriptor ufsrv_description = {command_header_ptr->eid, 0, command_header_ptr->when, &EnvelopeMetaData, command_envelope_ptr};

#ifdef __UF_TESTING
  syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'} Marshalling command error... ", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
#endif

  UfsrvCommandInvokeUserCommand(ctx_ptr, NULL, IS_EMPTY(wsm_ptr_received)?(&(WebSocketMessage){.request=NULL, .type=WEB_SOCKET_MESSAGE__TYPE__REQUEST}):wsm_ptr_received, NULL, &ufsrv_description, req_cmd_idx);

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}