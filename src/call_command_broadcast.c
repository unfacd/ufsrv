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
#include <ufsrv_core/user/user_preferences.h>
#include <nportredird.h>
#include <call_command_broadcast.h>
#include <sessions_delegator_type.h>
#include <ufsrv_core/msgqueue_backend/ufsrvcmd_broadcast.h>
#include <ufsrvuid.h>
#include <command_controllers.h>
#include <ufsrv_core/msgqueue_backend/UfsrvMessageQueue.pb-c.h>
#include <hiredis.h>

extern ufsrv *const masterptr;
extern SessionsDelegator *const sessions_delegator_ptr;
extern __thread ThreadContext ufsrv_thread_context;


struct BroadcastMessageEnvelopeForCall {
	MessageQueueMessage 			*msgqueue_msg;
	CallCommand 							*call_command;
	CommandHeader 						*header;
};

typedef struct BroadcastMessageEnvelopeForCall BroadcastMessageEnvelopeForCall;

////// INTER \\\\\\


///// END INTER \\\\


///// INTRA	\\\\\\

int
HandleIntraBroadcastForCall (MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	int				rc					= 0;
	long long timer_start	=	GetTimeNowInMicros();
	long long timer_end;

  if (unlikely(mqm_ptr->has_ufsrvuid == 0)) goto return_error_undefined_ufsrvuid;

	if ((rc = VerifyCallCommandFromUser(_WIRE_PROTOCOL_DATA(mqm_ptr->wire_data->ufsrvcommand->callcommand))) < 0)	goto return_final;

  unsigned long userid = UfsrvUidGetSequenceId((const UfsrvUid *)(mqm_ptr->ufsrvuid.data));

  InstanceHolderForSession *instance_sesn_ptr_carrier = InstantiateCarrierSession (NULL, WORKERTYPE_UFSRVWORKER, SESSION_CALLFLAGS_EMPTY);
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
	InstanceHolderForSession	*instance_sesn_ptr_local_user = (InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr_carrier);
  Session *sesn_ptr_local_user = SessionOffInstanceHolder(instance_sesn_ptr_local_user);

	if (unlikely(IS_EMPTY(sesn_ptr_local_user)))	goto return_error_unknown_uname;

	//>>> sesn_ptr_local_user IS NOW LOCKED

	SESSION_WHEN_SERVICE_STARTED(sesn_ptr_local_user) = time(NULL);

#ifdef __UF_TESTING
	CallCommand 		*callcmd_ptr	= mqm_ptr->wire_data->ufsrvcommand->callcommand;
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fid:'%lu', userid:'%lu'}: FULLY CONSTRUCTED CALL COMMAND.", __func__, pthread_self(),sesn_ptr_local_user, SESSION_ID(sesn_ptr_local_user), callcmd_ptr->fence->fid, userid);
#endif

	//////////////////////////
	SessionLoadEphemeralMode(sesn_ptr_local_user);

	CommandCallbackControllerCallCommand(&(InstanceContextForSession){.instance_sesn_ptr=instance_sesn_ptr_local_user, .sesn_ptr=sesn_ptr_local_user}, NULL, mqm_ptr->wire_data);

	SESSION_WHEN_SERVICED(sesn_ptr_local_user) = time(NULL);
	SessionUnLoadEphemeralMode(sesn_ptr_local_user);
	if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_local_user, __func__);
	//TODO: Error checking from command controller
	/////////////////////////

	return_success:
	goto return_deallocate_carrier;

  return_error_undefined_ufsrvuid:
  syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: COULD NOT FIND UFSRVUID", __func__, pthread_self());
  rc = -7;
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
VerifyCallCommandFromUser	(WireProtocolData *data_ptr)
{
	int rc = 1;
  CallCommand *cmd_ptr = (CallCommand *)data_ptr;

	if (unlikely(IS_EMPTY((cmd_ptr))))				goto return_error_callcommand_missing;
	if (unlikely(IS_EMPTY(cmd_ptr->header)))	goto return_error_commandheader_missing;
	if (unlikely(IS_EMPTY(cmd_ptr->fence)))		goto return_error_missing_fence_definition;
	if (unlikely(cmd_ptr->fence->fid <= 0))			goto return_error_invalid_fence_definition;

	return_success:
	goto return_final;

	return_error_missing_payload:
	syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: DATA PAYLOAD MISSING FROM MessageQueue Message", __func__, pthread_self());
	rc=-2;
	goto return_free;

	return_error_ufsrvcommand_missing:
	syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: COULD NOT FIND UFSRV COMMAND IN UNPACKED MESAGEQUEUE", __func__, pthread_self());
	rc = -3;
	goto return_free;

	return_error_commandheader_missing:
	syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: COULD NOT FIND COMMAND HEADER", __func__, pthread_self());
	rc = -8;
	goto return_free;

	return_error_callcommand_missing:
	syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: COULD NOT FIND CALL COMMAND IN UNPACKED MESAGEQUEUE", __func__, pthread_self());
	rc = -4;
	goto return_free;

	return_error_missing_fence_definition:
	syslog(LOG_DEBUG, "%s (pid:'%lu, command:'%d'): ERROR: FENCE COMMAND DID NOT INCLUDE FENCE DEFINITION", __func__, pthread_self(), cmd_ptr->header->command);
	rc = -6;
	goto	return_free;

	return_error_invalid_fence_definition:
	syslog(LOG_DEBUG, "%s (pid:'%lu, command:'%d', fid:'%lu'): ERROR: FENCE COMMAND DID NOT INCLUDE VALID FENCE DEFINITION", __func__, pthread_self(), cmd_ptr->header->command, cmd_ptr->fence->fid);
	rc = -7;
	goto	return_free;

  return_free:
	return_final:
	return rc;

}
//////////////////


