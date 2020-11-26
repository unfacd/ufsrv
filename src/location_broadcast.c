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
#include <ufsrv_core/user/users_protobuf.h>
#include <ufsrv_core/location/location.h>
#include <location_command_controller.h>
#include <net.h>
#include <nportredird.h>
#include <ufsrvwebsock/include/protocol_websocket_session.h>
#include <location_broadcast.h>
#include <ufsrv_core/location/location.h>
#include <fence_proto.h>
#include <sessions_delegator_type.h>
#include <ufsrv_core/msgqueue_backend/ufsrvcmd_broadcast.h>
#include <ufsrv_core/msgqueue_backend/UfsrvMessageQueue.pb-c.h>
#include <hiredis.h>
#include <ufsrvuid.h>

extern ufsrv *const masterptr;
extern SessionsDelegator *const sessions_delegator_ptr;
extern __thread ThreadContext ufsrv_thread_context;

/**
 * 	@brief: Main interface method for broadcasting backend data model state change for Fence display name attribute.
 * 	@
 */

struct BroadcastLocationEnvelopeForMessage {
	MessageQueueMessage 			*msgqueue_msg;
	LocationCommand 					*location_command;
	LocationRecord						*location_record;
	CommandHeader 						*header;
};

typedef struct BroadcastLocationEnvelopeForMessage BroadcastLocationEnvelopeForMessage;

////// INTER \\\\\\

inline static void
_PrepareBroadcastMessageForLocation (BroadcastLocationEnvelopeForMessage *envelope_ptr, Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg);

//TODO: needs updating
#define _GENERATE_ENVELOPE_INITIALISATION() \
	do \
	{\
		MessageQueueMessage msgqueue_msg				=	MESSAGE_QUEUE_MESSAGE__INIT;	\
		CommandHeader 			header							=	COMMAND_HEADER__INIT;	\
		LocationCommand			location_command		=	LOCATION_COMMAND__INIT;	\
		LocationRecord			location_record;	\
		\
		BroadcastMessageEnvelopeForLocation	envelope = {	\
				.msgqueue_msg						=	&msgqueue_msg,	\
				.location_command				=	&location_command,	\
				.location_record				=	&location_record,	\
				.header									=	&header	\
		};	\
		\
		_PrepareBroadcastMessageForLocation (&envelope, sesn_ptr, context_ptr, event_ptr, command_arg);	\
	} while(true)

inline static void
_PrepareBroadcastMessageForLocation (BroadcastLocationEnvelopeForMessage *envelope_ptr, Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg)
{
	envelope_ptr->msgqueue_msg->command_type					=	UFSRV_LOC;	envelope_ptr->msgqueue_msg->has_command_type=1;
	envelope_ptr->msgqueue_msg->broadcast_semantics		=	MESSAGE_QUEUE_MESSAGE__BROADCAST_SEMANTICS__INTER; envelope_ptr->msgqueue_msg->has_broadcast_semantics	=	1;
	envelope_ptr->msgqueue_msg->location							=	envelope_ptr->location_command;
	envelope_ptr->msgqueue_msg->location->header			=	envelope_ptr->header;

	envelope_ptr->header->args												=	command_arg;
	envelope_ptr->header->when												=	event_ptr->when; 					envelope_ptr->header->has_when=1;
	envelope_ptr->header->eid													=	event_ptr->eid; 					envelope_ptr->header->has_eid=1;
	envelope_ptr->header->cid													=	SESSION_ID(sesn_ptr); 		envelope_ptr->header->has_cid=1;
  MakeUfsrvUidInProto(&SESSION_UFSRVUIDSTORE(sesn_ptr), &(envelope_ptr->header->ufsrvuid), true); envelope_ptr->header->has_ufsrvuid=1;
}

/**
 * 	@brief: Main interface function for INTER broadcasting user message postings Invoked by teh main handler that processed the original
 * 	INTRA message.
 *
 *	@param ClientContextData *: must beLocationDescription object that stays in scope as its fields are copied by reference
 * 	@ param context_ptr: MessageCommand * as provided to the original handler
 */
UFSRVResult *
InterBroadcastLocationAddressByServer (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg)
{
	MessageQueueMessage 			msgqueue_msg					=	MESSAGE_QUEUE_MESSAGE__INIT;
	CommandHeader							header								=	COMMAND_HEADER__INIT;
	LocationCommand						location_command			=	LOCATION_COMMAND__INIT;
	LocationRecord						location_record;

	BroadcastLocationEnvelopeForMessage	envelope = {
				.msgqueue_msg						=	&msgqueue_msg,
				.location_command				=	&location_command,
				.location_record				=	&location_record,
				.header									=	&header,
		};

	_PrepareBroadcastMessageForLocation (&envelope, sesn_ptr, context_ptr, event_ptr, command_arg);

	//_GENERATE_ENVELOPE_INITIALISATION(); //replaces above

	//IMPORTANT: LocationDescription/ufsrvid copied by reference (country, locality etc...) keep object in scope until finished
	MakeLocationDescriptionInProto ((const LocationDescription *)context_ptr, false, false, &location_record);
	location_record.source							=	LOCATION_RECORD__SOURCE__BY_SERVER;
	location_command.location		        =	&location_record;
	header.command											=		LOCATION_COMMAND__COMMAND_TYPES__ADDRESS; //should this be LOCATION_COMMAND__COMMAND_TYPES__LOCATION?

	return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg, msgqueue_msg.command_type));
}

UFSRVResult *
InterBroadcastLocationAddressByUser (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg)
{
	MessageQueueMessage 			msgqueue_msg					=	MESSAGE_QUEUE_MESSAGE__INIT;
	CommandHeader							header								=	COMMAND_HEADER__INIT;
	LocationCommand						location_command			=	LOCATION_COMMAND__INIT;
	LocationRecord						location_record;

	BroadcastLocationEnvelopeForMessage	envelope = {
				.msgqueue_msg						=	&msgqueue_msg,
				.location_command				=	&location_command,
				.location_record				=	&location_record,
				.header									=	&header,
		};

	_PrepareBroadcastMessageForLocation (&envelope, sesn_ptr, context_ptr, event_ptr, command_arg);

	//_GENERATE_ENVELOPE_INITIALISATION(); //replaces above

	//IMPORTANT: LocationDescription/ufsrvid copied by reference (country, locality etc...) keep object in scope until finished
	MakeLocationDescriptionInProto ((const LocationDescription *)context_ptr, false, false, &location_record);
	location_record.source							=	LOCATION_RECORD__SOURCE__BY_USER;
	location_command.location		        =	&location_record;
	header.command											=	LOCATION_COMMAND__COMMAND_TYPES__ADDRESS;

	return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg, msgqueue_msg.command_type));
}

/**
 * 	@param context_ptr: char *
 */
UFSRVResult *
InterBroadcastBaseLoc (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg)
{
	MessageQueueMessage 			msgqueue_msg					=	MESSAGE_QUEUE_MESSAGE__INIT;
	CommandHeader							header								=	COMMAND_HEADER__INIT;
	LocationCommand						location_command			=	LOCATION_COMMAND__INIT;
	LocationRecord						location_record				=	LOCATION_RECORD__INIT;

	BroadcastLocationEnvelopeForMessage	envelope = {
				.msgqueue_msg						=	&msgqueue_msg,
				.location_command				=	&location_command,
				.location_record				=	&location_record,
				.header									=	&header,
		};

	_PrepareBroadcastMessageForLocation (&envelope, sesn_ptr, context_ptr, event_ptr, command_arg);

	//_GENERATE_ENVELOPE_INITIALISATION(); //replaces above

	//IMPORTANT: baseloc/ufsrvid (into header.ufsrvid) copied by reference keep object in scope until finished
	location_record.baseloc							=	(char *)context_ptr;
	location_record.source							=	LOCATION_RECORD__SOURCE__BY_USER;
	location_command.location		        =	&location_record;
	header.command											=	LOCATION_COMMAND__COMMAND_TYPES__BASELOC;

	return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg, msgqueue_msg.command_type));

//todo update the treatment for baseloc
return _ufsrv_result_generic_error;
}

static UFSRVResult *_HandleInterBroadcastLocationAddressByServer (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastLocationAddressByUser (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastBaseLoc (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
/**
 * 	@brief: Main interfae for handling incoming INTER broadcasts for location messages. Basic verification will have taken place as per
 * 	'_VerifyInterMessageQueueCommand()' in ufsrv_broadcast.c
 */
int
HandleInterBroadcastForLocation (MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	int 										rescode	= 0;
	UFSRVResult				result	=	{0};
#define FLAG_ONLY_LOCAL_SESSION	1

	//update local state for example update event number for the fence
	LocationDescription *location_ptr	=	NULL;
	LocationCommand *location_cmd_ptr = mqm_ptr->location;

	//if we dont have a this local session, we dont care
	PrepareForInterBroadcastHandling (mqm_ptr,
																		mqm_ptr->location->header,
																		(ClientContextData *)NULL,
																		&result,
																		mqm_ptr->location->header->command,
																		FLAG_ONLY_LOCAL_SESSION);

	if (result.result_type == RESULT_TYPE_ERR)	{rescode=-1; goto return_final;}
	Session *sesn_ptr_local_user	=	(Session *)result.result_user_data;

	//SESSION LOCKED ND IN EPHEMERAL MODE
	switch (mqm_ptr->location->header->command)
	{
		case LOCATION_COMMAND__COMMAND_TYPES__ADDRESS:
		  if (location_cmd_ptr->location->source == LOCATION_RECORD__SOURCE__BY_SERVER)
			  _HandleInterBroadcastLocationAddressByServer ((ClientContextData *)sesn_ptr_local_user, mqm_ptr, &result, call_flags);
		  else if (location_cmd_ptr->location->source == LOCATION_RECORD__SOURCE__BY_USER)
        _HandleInterBroadcastLocationAddressByUser ((ClientContextData *)sesn_ptr_local_user, mqm_ptr, &result, call_flags);
			break;

		case LOCATION_COMMAND__COMMAND_TYPES__BASELOC:
			_HandleInterBroadcastBaseLoc ((ClientContextData *)sesn_ptr_local_user, mqm_ptr, &result, call_flags);
			break;

		default:
			break;
	}

	return_success:
	SESSION_WHEN_SERVICED(sesn_ptr_local_user) = time(NULL);
	SessionUnLoadEphemeralMode(sesn_ptr_local_user);
	SessionUnLockCtx (THREAD_CONTEXT_PTR, sesn_ptr_local_user, __func__);
	goto return_final;

	return_final:
	return rescode;

}

/**
 * 	@locked: Session *
 */
static UFSRVResult *
_HandleInterBroadcastLocationAddressByServer (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	Session *sesn_ptr_local_user				=	(Session *)context_ptr;

	if (unlikely(IS_EMPTY(mqm_ptr->location->location)))	goto return_empty_location_record;

	UpdateUserLocationAssignmentByProto (SESSION_ULOCATION_BYSERVER_PTR(sesn_ptr_local_user),  mqm_ptr->location->location);

	return_success:
	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_LOCATION_CHANGED)

	return_empty_location_record:
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: ERROR: MISSING LOCATION RECORD", __func__, pthread_self(), sesn_ptr_local_user, SESSION_ID(sesn_ptr_local_user));
	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOCATION_UNCHANGED)
}

static UFSRVResult *
_HandleInterBroadcastLocationAddressByUser (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	Session *sesn_ptr_local_user				=	(Session *)context_ptr;

	if (unlikely(IS_EMPTY(mqm_ptr->location->location)))	goto return_empty_location_record;

	UpdateUserLocationAssignmentByProto (SESSION_ULOCATION_BYUSER_PTR(sesn_ptr_local_user),  mqm_ptr->location->location);

	return_success:
	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_LOCATION_CHANGED)

	return_empty_location_record:
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: ERROR: MISSING LOCATION RECORD", __func__, pthread_self(), sesn_ptr_local_user, SESSION_ID(sesn_ptr_local_user));
	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOCATION_UNCHANGED)
}

static UFSRVResult *
_HandleInterBroadcastBaseLoc (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	Session *sesn_ptr_local_user				=	(Session *)context_ptr;

	if (unlikely(IS_EMPTY(mqm_ptr->location->location)))								goto return_empty_location_record;
	if (unlikely(!IS_STR_LOADED(mqm_ptr->location->location->baseloc)))	goto return_invalid_baseloc;

	UpdateBaseLocAssignment (sesn_ptr_local_user, (const char *)mqm_ptr->location->location->baseloc, 0);//only locally

	return_success:
	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_LOCATION_CHANGED)

	return_empty_location_record:
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: ERROR: MISSING LOCATION RECORD", __func__, pthread_self(), sesn_ptr_local_user, SESSION_ID(sesn_ptr_local_user));
	goto return_final;

	return_invalid_baseloc:
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: ERROR: INVALID BASELOC VALUE", __func__, pthread_self(), sesn_ptr_local_user, SESSION_ID(sesn_ptr_local_user));
	goto return_final;

	return_final:
	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOCATION_UNCHANGED)
}

///// END INTER \\\\


///// INTRA	\\\\\\

int
HandleIntraBroadcastForLocation (MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	int				rc					= 0;
	long long timer_start	=	GetTimeNowInMicros();
	long long timer_end;

	if ((rc = VerifyLocationCommandForIntra(_WIRE_PROTOCOL_DATA(mqm_ptr->wire_data->ufsrvcommand->locationcommand))) < 0)	goto return_final;

  unsigned long userid = UfsrvUidGetSequenceId((const UfsrvUid *)(mqm_ptr->ufsrvuid.data));

  InstanceHolderForSession  *instance_sesn_ptr_carrier			=	InstantiateCarrierSession (NULL, WORKERTYPE_UFSRVWORKER, SESSION_CALLFLAGS_EMPTY);
  if (IS_EMPTY(instance_sesn_ptr_carrier))	{
    rc = -4;
    goto return_final;
  }

  Session *sesn_ptr_carrier = SessionOffInstanceHolder(instance_sesn_ptr_carrier);

  unsigned long sesn_call_flags				=	(	CALL_FLAG_LOCK_SESSION|CALL_FLAG_LOCK_SESSION_BLOCKING|
                                             CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY| CALL_FLAG_HASH_USERNAME_LOCALLY|
                                             CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION|CALL_FLAG_REMOTE_SESSION);

  bool lock_already_owned = false;
  GetSessionForThisUserByUserId (sesn_ptr_carrier, userid, &lock_already_owned, sesn_call_flags);
  InstanceHolderForSession *instance_sesn_ptr_local_user = (InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr_carrier);

  if (unlikely(IS_EMPTY(instance_sesn_ptr_local_user)))	goto return_error_unknown_uname;

  Session *sesn_ptr_local_user = SessionOffInstanceHolder(instance_sesn_ptr_local_user);

  //>>> sesn_ptr_local_user IS NOW LOCKED

  SESSION_WHEN_SERVICE_STARTED(sesn_ptr_local_user) = time(NULL);

  //////////////////////////
  SessionLoadEphemeralMode(sesn_ptr_local_user);

  CommandCallbackControllerLocationCommand(&(InstanceContextForSession){instance_sesn_ptr_local_user, sesn_ptr_local_user}, NULL, mqm_ptr->wire_data);

  SESSION_WHEN_SERVICED(sesn_ptr_local_user) = time(NULL);
  SessionUnLoadEphemeralMode(sesn_ptr_local_user);
  if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_local_user, __func__);
  //TODO: Error checking from command controller
  /////////////////////////

  return_success:
  goto return_deallocate_carrier;

  return_error_unknown_uname:
  syslog(LOG_DEBUG, "%s {pid:'%lu', userid:'%lu'}: ERROR: COULD NOT RETRIEVE SESSION FOR USER", __func__, pthread_self(), userid);
  rc = -7;
  goto return_deallocate_carrier;

  return_deallocate_carrier:
  SessionReturnToRecycler (instance_sesn_ptr_carrier, (ContextData *)NULL, 0);

  return_final:
  timer_end = GetTimeNowInMicros();
  statsd_timing(pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_instrumentation_backend_key), "delegator.ufsrv.job.command.msg.elapsed_time", (timer_end-timer_start));
  return rc;

}

/**
 * 	@brief: Verify the fitness of the FenceCommand message in the context of on INTRA broadcast
 */
int
VerifyLocationCommandForIntra	(WireProtocolData *data_ptr)
{
	int rc = 1;
  LocationCommand *cmd_ptr = (LocationCommand *)data_ptr;

	if (unlikely(IS_EMPTY((cmd_ptr))))				goto return_error_ufsrvcommand_missing;
	if (unlikely(IS_EMPTY(cmd_ptr->header)))	goto return_error_commandheader_missing;

	return_success:
	goto return_final;

	return_error_ufsrvcommand_missing:
	syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: COULD NOT FIND UFSRV COMMAND IN UNPACKED MESAGEQUEUE", __func__, pthread_self());
	rc = -3;
	goto return_free;

	return_error_commandheader_missing:
	syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: COULD NOT FIND COMMAND HEADER", __func__, pthread_self());
	rc = -8;
	goto return_free;

	return_free:
	return_final:
	return rc;

}

//////////////////
