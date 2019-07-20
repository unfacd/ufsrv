#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <fence_state.h>
#include <user_preferences.h>
#include <users_proto.h>
#include <location.h>
#include <persistance.h>
#include <misc.h>
#include <net.h>
#include <nportredird.h>
#include <protocol_websocket_session.h>
#include <protocol_http.h>
#include <location_broadcast.h>
#include <location.h>
#include <fence_proto.h>
#include <sessions_delegator_type.h>
#include <ufsrvcmd_broadcast.h>
#include <command_controllers.h>
#include <UfsrvMessageQueue.pb-c.h>
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

#if 1

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
	location_record.source							=	LOCATION_RECORD__SOURCE__SERVER;
	location_command.location_by_serv		=	&location_record;
	header.command											=		LOCATION_COMMAND__COMMAND_TYPES__ADDRESS_BYS;

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
	location_record.source							=	LOCATION_RECORD__SOURCE__USER;
	location_command.location_by_user		=	&location_record;
	header.command											=	LOCATION_COMMAND__COMMAND_TYPES__ADDRESS_BYU;

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
	location_record.source							=	LOCATION_RECORD__SOURCE__USER;
	location_command.location_by_user		=	&location_record;
	header.command											=	LOCATION_COMMAND__COMMAND_TYPES__BASELOC;

	return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg, msgqueue_msg.command_type));
}


static UFSRVResult *_HandleInterBroadcastLocationAddressByServer (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastLocationAddressByUser (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastBaseLoc (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
/**
 * 	@brief: Main interfae for handling incoming INTER broadcasts for location messages. Basic verification will have taken place as per
 * 	'_VerifyInterMessageQueueCommand()' in ufsrv_broadcast.c
 */
int
HandleInterBroadcastForLocation (MessageQueueMsgPayload *mqp_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	int 										rescode	= 0;
	UFSRVResult				result	=	{0};
#define FLAG_ONLY_LOCAL_SESSION	1

	//update local state for example update event number for the fence
	LocationDescription *location_ptr	=	NULL;

	//if we dont have a this local session, we dont care
	PrepareForInterBroadcastHandling (mqm_ptr,
																		mqm_ptr->location->header,
																		(ClientContextData *)NULL,
																		&result,
																		mqm_ptr->location->header->command,
																		FLAG_ONLY_LOCAL_SESSION);

	if (result.result_type==RESULT_TYPE_ERR)	{rescode=-1; goto return_final;}
	Session *sesn_ptr_local_user	=	(Session *)result.result_user_data;

	//SESSION LOCKED ND IN EPHEMERAL MODE
	switch (mqm_ptr->location->header->command)
	{
		case LOCATION_COMMAND__COMMAND_TYPES__ADDRESS_BYS:
			_HandleInterBroadcastLocationAddressByServer ((ClientContextData *)sesn_ptr_local_user, mqm_ptr, &result, call_flags);
			break;

		case LOCATION_COMMAND__COMMAND_TYPES__ADDRESS_BYU:
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
	return rescode;//_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, rescode);

}


/**
 * 	@locked: Session *
 */
static UFSRVResult *
_HandleInterBroadcastLocationAddressByServer (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	Session *sesn_ptr_local_user				=	(Session *)context_ptr;

	if (unlikely(IS_EMPTY(mqm_ptr->location->location_by_serv)))	goto return_empty_location_record;

	UpdateUserLocationAssignmentByProto (SESSION_ULOCATION_BYSERVER_PTR(sesn_ptr_local_user),  mqm_ptr->location->location_by_serv);

	return_success:
	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_LOCATION_CHANGED);

	return_empty_location_record:
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: ERROR: MISSING LOCATION RECORD", __func__, pthread_self(), sesn_ptr_local_user, SESSION_ID(sesn_ptr_local_user));
	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOCATION_UNCHANGED);
}


static UFSRVResult *
_HandleInterBroadcastLocationAddressByUser (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	Session *sesn_ptr_local_user				=	(Session *)context_ptr;

	if (unlikely(IS_EMPTY(mqm_ptr->location->location_by_user)))	goto return_empty_location_record;

	UpdateUserLocationAssignmentByProto (SESSION_ULOCATION_BYUSER_PTR(sesn_ptr_local_user),  mqm_ptr->location->location_by_user);

	return_success:
	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_LOCATION_CHANGED);

	return_empty_location_record:
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: ERROR: MISSING LOCATION RECORD", __func__, pthread_self(), sesn_ptr_local_user, SESSION_ID(sesn_ptr_local_user));
	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOCATION_UNCHANGED);
}


static UFSRVResult *
_HandleInterBroadcastBaseLoc (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	Session *sesn_ptr_local_user				=	(Session *)context_ptr;

	if (unlikely(IS_EMPTY(mqm_ptr->location->location_by_user)))								goto return_empty_location_record;
	if (unlikely(!IS_STR_LOADED(mqm_ptr->location->location_by_user->baseloc)))	goto return_invalid_baseloc;

	UpdateBaseLocAssignment (sesn_ptr_local_user, (const char *)mqm_ptr->location->location_by_user->baseloc, 0);//only locally

	return_success:
	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_LOCATION_CHANGED);

	return_empty_location_record:
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: ERROR: MISSING LOCATION RECORD", __func__, pthread_self(), sesn_ptr_local_user, SESSION_ID(sesn_ptr_local_user));
	goto return_final;

	return_invalid_baseloc:
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: ERROR: INVALID BASELOC VALUE", __func__, pthread_self(), sesn_ptr_local_user, SESSION_ID(sesn_ptr_local_user));
	goto return_final;

	return_final:
	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOCATION_UNCHANGED);
}

#endif
///// END INTER \\\\


///// INTRA	\\\\\\

#if 0 //INTRA NOT SUPPORTED FYET FOT LOCATION

inline static int _VetrifyLocationCommandForIntra	(MessageQueueMessage *mqm_ptr, bool flag_free_unpacked);


int
HandleIntraBroadcastForLocation (MessageQueueMsgPayload *mqp_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	int				rc					= 0;
	long long timer_start	=	GetTimeNowInMicros();
	long long timer_end;

	if ((rc=_VetrifyUserMessageCommandForIntra(mqm_ptr, false))<0)	goto return_final;

	const char		*username_origin			= mqm_ptr->uname;

	Session				*sesn_ptr_carrier			=	InstantiateCarrierSession (NULL, WORKERTYPE_UFSRVWORKER);
	if (IS_EMPTY(sesn_ptr_carrier))	{rc=-4; goto return_final;}

	unsigned long sesn_call_flags				=	(	CALL_FLAG_LOCK_SESSION|CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY|
																					CALL_FLAG_HASH_USERNAME_LOCALLY|CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION|CALL_FLAG_REMOTE_SESSION);
	Session 			*sesn_ptr_local_user	= GetSessionForThisUser (sesn_ptr_carrier, username_origin, sesn_call_flags);

	if (unlikely(IS_EMPTY(sesn_ptr_local_user)))	goto return_error_unknown_uname;

	//>>> sesn_ptr_local_user IS NOW LOCKED

#ifdef __UF_TESTING
	MessageCommand 		*msgcmd_ptr	= mqm_ptr->wire_data->ufsrvcommand->msgcommand;
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fid:'%lu', uname:'%s'}: FULLY CONSTRUCTED MESAAGE COMMAND.", __func__, pthread_self(),sesn_ptr_local_user, SESSION_ID(sesn_ptr_local_user), msgcmd_ptr->fences[0]->fid, username_origin);
#endif

	AttachmentRecord *attchment_ptr=NULL;

#ifdef __UF_TESTING
	if ((msgcmd_ptr->n_attachments>0) && !(IS_EMPTY((attchment_ptr=msgcmd_ptr->attachments[0]))))
	{
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fid:'%lu', id:'%s', size:'%u', type:'%s'}: Attachment found...", __func__, pthread_self(),sesn_ptr_local_user, SESSION_ID(sesn_ptr_local_user), msgcmd_ptr->fences[0]->fid, attchment_ptr->id, attchment_ptr->size, attchment_ptr->contenttype);
	}
#endif

	//////////////////////////
	SessionLoadEphemeralMode(sesn_ptr_local_user);

	CommandCallbackControllerMessageCommand (sesn_ptr_local_user, NULL, mqm_ptr->wire_data, mqp_ptr);

	SessionUnLoadEphemeralMode(sesn_ptr_local_user);
	SessionUnLock(sesn_ptr_local_user);
	//TODO: Error checking from command controller
	/////////////////////////

	return_success:
	goto return_deallocate_carrier;//rc=0

	return_error_unknown_uname:
	syslog(LOG_DEBUG, "%s {pid:'%lu', uname:'%s'}: ERROR: COULD NOT RETRIEVE SESSION FOR USER", __func__, pthread_self(), username_origin);
	rc=-7;
	goto return_deallocate_carrier;

	return_deallocate_carrier:
	SessionReturnToRecycler (sesn_ptr_carrier, (ContextData *)NULL, 0);

	return_final:
	timer_end=GetTimeNowInMicros();
	statsd_timing(pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_instrumentation_backend_key), "delegator.ufsrv.job.command.msg.elapsed_time", (timer_end-timer_start));
	return rc;

#if 0
	int					rc			= 0;
	MessageCommand 		*msgcmd_ptr	= NULL;
	MessageQueueMessage *mqm_ptr	= NULL;

	long long timer_start=GetTimeNowInMicros();

	mqm_ptr=message_queue_message__unpack(NULL, mqp_ptr->payload_sz, mqp_ptr->payload);
	if (unlikely(IS_EMPTY(mqm_ptr)))
	{
		syslog(LOG_DEBUG, "%s (pid:'%lu'): ERROR: COULD NOT UNPACK MessageQueue Message", __func__, pthread_self());
		return -1;
	}

	if (unlikely(IS_EMPTY(mqm_ptr->wire_data)))
	{
		syslog(LOG_DEBUG, "%s (pid:'%lu'): ERROR: UNPACKED MessageQueue DID NOT CONTAIN VALID WIRE DATA", __func__, pthread_self());
		rc=-2;
		goto exit_proto;
	}

	if (unlikely((IS_EMPTY(mqm_ptr->wire_data->ufsrvcommand)) || ((msgcmd_ptr=mqm_ptr->wire_data->ufsrvcommand->msgcommand)==NULL)))
	{
		syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: COULD NOT FIND MESSAGE COMMAND IN UNPACKED MESAGEQUEUE", __func__, pthread_self());
		rc=-2;
		goto exit_proto;
	}

	//only this named instance can change backend model; rest get inter-broadcast
	if (mqm_ptr->origin==masterptr->serverid)
	{
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s {pid:'%lu' origin:'%d'}: BROADCAST FROM SELF: IGNORING.", __func__, pthread_self(), mqm_ptr->origin);
#endif
		rc=1;
		goto exit_proto;
	}

	if (mqm_ptr->target_ufsrv!=masterptr->serverid_by_user)
	{
#ifdef __UF_FULLDEBUG
				syslog(LOG_DEBUG, "%s {pid:'%lu' origin:'%d', target_ufsrv:'%d'}: BROADCAST FOR OTHER TARGET: IGNORING.", __func__, pthread_self(), mqm_ptr->origin, mqm_ptr->target_ufsrv);
#endif
	}

	if (unlikely(IS_EMPTY(mqm_ptr->uname)))
	{
		syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: USERNAME MISSING FROM MESSAGE", __func__, pthread_self());

		rc=-3;
		goto exit_proto;
	}

	const char	*username_origin		= mqm_ptr->uname;
	Session 	*sesn_ptr_local_user	= LocateSessionByUsername(username_origin);

	if (unlikely(IS_EMPTY(sesn_ptr_local_user)))
	{
		syslog(LOG_DEBUG, "%s (pid:'%lu' uname:'%s'): ERROR: COULD NOT RETRIEVE SESSION FOR USER", __func__, pthread_self(),username_origin);
		rc=-3;
		goto exit_proto;
	}

	if (msgcmd_ptr->n_fences<1)
	{
		syslog(LOG_DEBUG, "%s (pid:'%lu', uname:'%s' args:'%d'): ERROR: MESSAGE COMMAND DID NOT INCLUDE VALID FENCE DEFINITION", __func__, pthread_self(), username_origin, msgcmd_ptr->header->args);
		rc=-3;
		goto exit_proto;
	}

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fid:'%lu', uname:'%s'}: FULLY CONSTRUCTED MESAAGE COMMAND.", __func__, pthread_self(),sesn_ptr_local_user, SESSION_ID(sesn_ptr_local_user), msgcmd_ptr->fences[0]->fid, username_origin);
#endif

	AttachmentRecord *attchment_ptr=NULL;

#ifdef __UF_TESTING
	if ((msgcmd_ptr->n_attachments>0) && !(IS_EMPTY((attchment_ptr=msgcmd_ptr->attachments[0]))))
	{
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fid:'%lu', id:'%s', size:'%u', type:'%s'}: Attachment found...", __func__, pthread_self(),sesn_ptr_local_user, SESSION_ID(sesn_ptr_local_user), msgcmd_ptr->fences[0]->fid, attchment_ptr->id, attchment_ptr->size, attchment_ptr->contenttype);
	}
#endif

	//////////////////////////
	CommandCallbackControllerMessageCommand (sesn_ptr_local_user, NULL, mqm_ptr->wire_data, mqp_ptr);
	//TODO: Error checking

	rc=1;//having reach this far we must have done OK

	exit_proto:
	message_queue_message__free_unpacked(mqm_ptr, NULL);
	long long timer_end=GetTimeNowInMicros();
		statsd_timing(pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_instrumentation_backend_key), "delegator.ufsrv.job.command.msg.elapsed_time", (timer_end-timer_start));
	return rc;//goto exit_final;
#endif
}


/**
 * 	@brief: Verify the fitness of the FenceCommand message in the context of on INTRA broadcast
 */
inline static int
_VetrifyLocationCommandForIntra	(MessageQueueMessage *mqm_ptr, bool flag_free_unpacked)
{
	int rc=1;

	if (unlikely(IS_EMPTY((mqm_ptr->wire_data->ufsrvcommand->msgcommand))))				goto return_error_fencecommand_missing;
	if (unlikely(IS_EMPTY(mqm_ptr->wire_data->ufsrvcommand->msgcommand->header)))	goto return_error_commandheader_missing;
	if (unlikely(mqm_ptr->wire_data->ufsrvcommand->msgcommand->n_fences<1))				goto return_error_missing_fence_definition;
	if (unlikely(mqm_ptr->uname==NULL))																						goto return_error_missing_uname;

	return_success:
	goto return_final;

	return_error_missing_payload:
	syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: DATA PAYLOAD MISSING FROM MessageQueue Message", __func__, pthread_self());
	rc=-2;
	goto return_free;

	return_error_ufsrvcommand_missing:
	syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: COULD NOT FIND UFSRV COMMAND IN UNPACKED MESAGEQUEUE", __func__, pthread_self());
	rc=-3;
	goto return_free;

	return_error_commandheader_missing:
	syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: COULD NOT FIND COMMAND HEADER", __func__, pthread_self());
	rc=-8;
	goto return_free;

	return_error_fencecommand_missing:
	syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: COULD NOT FIND FENCE COMMAND IN UNPACKED MESAGEQUEUE", __func__, pthread_self());
	rc=-4;
	goto return_free;

	return_error_missing_uname:
	syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: USERNAME MISSING FROM MESSAGE", __func__, pthread_self());
	rc=-5;
	goto return_free;

	return_error_missing_fence_definition:
	syslog(LOG_DEBUG, "%s (pid:'%lu): ERROR: FENCE COMMAND DID NOT INCLUDE VALID FENCE DEFINITION", __func__, pthread_self());
	rc=-6;
	goto	return_free;

	return_free://exit_proto:
	if (flag_free_unpacked)	message_queue_message__free_unpacked(mqm_ptr, NULL);

	return_final:
	return rc;

}

#endif
//////////////////
