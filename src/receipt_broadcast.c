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
#include <thread_context_type.h>
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
#include <receipt_broadcast.h>
#include <sessions_delegator_type.h>
#include <ufsrvcmd_broadcast.h>
#include <ufsrvuid.h>
#include <command_controllers.h>
#include <UfsrvMessageQueue.pb-c.h>
#include <hiredis.h>

extern ufsrv *const masterptr;
extern SessionsDelegator *const sessions_delegator_ptr;
extern __thread ThreadContext ufsrv_thread_context;


struct BroadcastMessageEnvelopeForReceipt {
	MessageQueueMessage 			*msgqueue_msg;
	ReceiptCommand 						*call_command;
	CommandHeader 						*header;
};

typedef struct BroadcastMessageEnvelopeForReceipt BroadcastMessageEnvelopeForReceipt;

////// INTER \\\\\\

#if 0

inline static void
_PrepareBroadcastMessageForCall (BroadcastMessageEnvelopeForCall *envelope_ptr, Session *sesn_ptr, ClientContextData *context_ptr, FenceEventTemp *event_ptr, enum _CommandArgs command_arg);



inline static void
_PrepareBroadcastMessageForMessage (BroadcastMessageEnvelopeForMessage *envelope_ptr, Session *sesn_ptr, ClientContextData *context_ptr, FenceEventTemp *event_ptr, enum _CommandArgs command_arg)
{
	envelope_ptr->msgqueue_msg->command_type					=	UFSRV_MSG;	envelope_ptr->msgqueue_msg->has_command_type=1;
	envelope_ptr->msgqueue_msg->broadcast_semantics	=	MESSAGE_QUEUE_MESSAGE__BROADCAST_SEMANTICS__INTER; envelope_ptr->msgqueue_msg->has_broadcast_semantics	=	1;
	envelope_ptr->msgqueue_msg->message								=	envelope_ptr->message_command;
	envelope_ptr->msgqueue_msg->message->header				=	envelope_ptr->header;

	envelope_ptr->header->args												=	command_arg;
	envelope_ptr->header->when												=	event_ptr->when; 					envelope_ptr->header->has_when=1;
	envelope_ptr->header->eid													=	event_ptr->eid; 					envelope_ptr->header->has_eid=1;
	envelope_ptr->header->cid													=	SESSION_ID(sesn_ptr); 		envelope_ptr->header->has_cid=1;
	envelope_ptr->header->uid													=	SESSION_USERID(sesn_ptr); envelope_ptr->header->has_uid=1;

}


/**
 * 	@brief: Main interface function for INTER broadcasting user message postings Invoked by teh main handler that processed the original
 * 	INTRA message.
 *
 * 	@ param context_ptr: MessageCommand * as provided to the original handler
 */
UFSRVResult *
InterBroadcastUserMessage (Session *sesn_ptr, ClientContextData *context_ptr, FenceEventTemp *event_ptr, enum _CommandArgs command_arg)
{

	MessageQueueMessage 			msgqueue_msg					=	MESSAGE_QUEUE_MESSAGE__INIT;
	CommandHeader							header								=	COMMAND_HEADER__INIT;
	MessageCommand						message_command				=	MESSAGE_COMMAND__INIT;

	BroadcastMessageEnvelopeForMessage	envelope = {
				.msgqueue_msg						=	&msgqueue_msg,
				.message_command				=	&message_command,
				.header									=	&header,
		};

	_PrepareBroadcastMessageForMessage (&envelope, sesn_ptr, context_ptr, event_ptr, command_arg);

	//_GENERATE_ENVELOPE_INITIALISATION(); //replaces above

	MessageCommand	*msgcmd_ptr	=	(MessageCommand *)context_ptr;
	//msgcmd_ptr->fences[0]->fid;
	//actual delta
	message_command.fences		=	msgcmd_ptr->fences;
	message_command.n_fences	=	msgcmd_ptr->n_fences;
	message_command.messages	=	msgcmd_ptr->messages;
	message_command.n_messages	=	msgcmd_ptr->n_messages;

	return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg, msgqueue_msg.command_type));
}

int
HandleInterBroadcastForUserMessage (MessageQueueMsgPayload *mqp_ptr, MessageQueueMessage 		*mqm_ptr, UFSRVResult *res_ptr, unsigned long callflags)
{
	int 										rescode	= 0;

	//update local state for example update event number for the fence

	return_success:
	return rescode;


	return_final:
	return rescode;//_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, rescode);

}

#endif
///// END INTER \\\\


///// INTRA	\\\\\\

#if 1

inline static int _VetrifyReceiptCommandForIntra	(MessageQueueMessage *mqm_ptr, bool flag_free_unpacked);


int
HandleIntraBroadcastForReceipt (MessageQueueMsgPayload *mqp_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	int				rc					= 0;
	long long timer_start	=	GetTimeNowInMicros();
	long long timer_end;

	if ((rc = _VetrifyReceiptCommandForIntra(mqm_ptr, false))<0)	goto return_final;

  unsigned long userid = UfsrvUidGetSequenceId((const UfsrvUid *)(mqm_ptr->ufsrvuid.data));

	InstanceHolderForSession				*instance_sesn_ptr_carrier			=	InstantiateCarrierSession (NULL, WORKERTYPE_UFSRVWORKER, SESSION_CALLFLAGS_EMPTY);
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

	//>>> sesn_ptr_local_user IS NOW LOCKED
  Session	*sesn_ptr_local_user = SessionOffInstanceHolder(instance_sesn_ptr_local_user);
	SESSION_WHEN_SERVICE_STARTED(sesn_ptr_local_user) = time(NULL);

#ifdef __UF_TESTING
	ReceiptCommand 		*recptcmd_ptr	= mqm_ptr->wire_data->ufsrvcommand->receiptcommand;
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fid:'%lu', userid:'%lu'}: FULLY CONSTRUCTED RECEIPT COMMAND.", __func__, pthread_self(), sesn_ptr_local_user, SESSION_ID(sesn_ptr_local_user), recptcmd_ptr->fid, userid);
#endif

	//////////////////////////
	SessionLoadEphemeralMode(sesn_ptr_local_user);

	CommandCallbackControllerReceiptCommand (sesn_ptr_local_user, NULL, mqm_ptr->wire_data, mqp_ptr);

	SessionUnLoadEphemeralMode(sesn_ptr_local_user);
	SESSION_WHEN_SERVICED(sesn_ptr_local_user) = time(NULL);
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
inline static int
_VetrifyReceiptCommandForIntra	(MessageQueueMessage *mqm_ptr, bool flag_free_unpacked)
{
	int rc=1;

	if (unlikely(IS_EMPTY((mqm_ptr->wire_data->ufsrvcommand->receiptcommand))))				goto return_error_receiptcommand_missing;
	if (unlikely(IS_EMPTY(mqm_ptr->wire_data->ufsrvcommand->receiptcommand->header)))	goto return_error_commandheader_missing;
//	if (unlikely(IS_EMPTY(mqm_ptr->wire_data->ufsrvcommand->receiptcommand->fence)))		goto return_error_missing_fence_definition;
//	if (unlikely(mqm_ptr->wire_data->ufsrvcommand->callcommand->fence->fid<=0))			goto return_error_invalid_fence_definition;

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

	return_error_receiptcommand_missing:
	syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: COULD NOT FIND CALL COMMAND IN UNPACKED MESAGEQUEUE", __func__, pthread_self());
	rc=-4;
	goto return_free;

	return_error_missing_uname:
	syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: USERNAME MISSING FROM MESSAGE", __func__, pthread_self());
	rc=-5;
	goto return_free;

	return_error_missing_fence_definition:
	syslog(LOG_DEBUG, "%s (pid:'%lu, command:'%d'): ERROR: FENCE COMMAND DID NOT INCLUDE FENCE DEFINITION", __func__, pthread_self(), mqm_ptr->wire_data->ufsrvcommand->callcommand->header->command);
	rc=-6;
	goto	return_free;

	return_error_invalid_fence_definition:
	syslog(LOG_DEBUG, "%s (pid:'%lu, command:'%d', fid:'%lu'): ERROR: FENCE COMMAND DID NOT INCLUDE VALID FENCE DEFINITION", __func__, pthread_self(), mqm_ptr->wire_data->ufsrvcommand->callcommand->header->command, mqm_ptr->wire_data->ufsrvcommand->callcommand->fence->fid);
	rc=-7;
	goto	return_free;

	return_free://exit_proto:
	if (flag_free_unpacked)	message_queue_message__free_unpacked(mqm_ptr, NULL);

	return_final:
	return rc;

}

#endif
//////////////////




