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
#include <incoming_message_descriptor_type.h>
#include <ufsrv_core/user/user_preferences.h>
#include <ufsrv_core/user/users_protobuf.h>
#include <ufsrv_core/cache_backend/persistance.h>
#include <nportredird.h>
#include <ufsrvwebsock/include/protocol_websocket_session.h>
#include <message.h>
#include <sessions_delegator_type.h>
#include <ufsrv_core/msgqueue_backend/ufsrvcmd_broadcast.h>
#include <ufsrvuid.h>
#include <message_command_controller.h>
#include <message_command_broadcast.h>
#include <command_controllers.h>
#include <ufsrv_core/msgqueue_backend/UfsrvMessageQueue.pb-c.h>


extern ufsrv *const masterptr;
extern SessionsDelegator *const sessions_delegator_ptr;
extern __thread ThreadContext ufsrv_thread_context;

/**
 * 	@brief: Main interface method for broadcasting backend data model state change for Fence display name attribute.
 * 	@
 */

typedef struct BroadcastMessageEnvelopeForMessage {
	MessageQueueMessage 			*msgqueue_msg;
	MessageCommand 						*message_command;
	CommandHeader 						*header;
} BroadcastMessageEnvelopeForMessage;

typedef struct BroadcastMessageGuardianDescriptor {
  InstanceContextForSession ctx_sesn_ptr_guardian,
          ctx_sesn_ptr_originator;
} BroadcastMessageGuardianDescriptor ;


////// INTER \\\\\\

static UFSRVResult *_PrepareForInterBroadcastHandlingMessageReported (MessageQueueMessage *mqm_ptr, FenceSessionPair *fence_sesn_pair_ptr, UFSRVResult *res_ptr);
static UFSRVResult *_PrepareForInterBroadcastHandlingGuardian (MessageQueueMessage *mqm_ptr, BroadcastMessageGuardianDescriptor *descriptor_ptr, UFSRVResult *res_ptr);
static UFSRVResult *_HandleInterBroadcastUserMessageSay (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastUserMessageIntro (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastUserMessageReported (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastUserMessageGuardianRequest (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastUserMessageGuardianLink (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastUserMessageGuardianUnlink (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);

inline static void
_PrepareBroadcastMessageForMessage (BroadcastMessageEnvelopeForMessage *envelope_ptr, Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg);

//TODO: needs updating
#define _GENERATE_ENVELOPE_INITIALISATION() \
		MessageQueueMessage msgqueue_msg	=	MESSAGE_QUEUE_MESSAGE__INIT;	\
		MessageCommand 	message_command		=	MESSAGE_COMMAND__INIT;	\
		CommandHeader header							=	COMMAND_HEADER__INIT;	\
		\
		BroadcastMessageEnvelopeForMessage	envelope = {	\
				.msgqueue_msg				=	&msgqueue_msg,	\
				.message_command		=	&message_command,	\
				.header							=	&header,	\
		}


inline static void
_PrepareBroadcastMessageForMessage (BroadcastMessageEnvelopeForMessage *envelope_ptr, Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg)
{
	envelope_ptr->msgqueue_msg->command_type					=	UFSRV_MSG;	envelope_ptr->msgqueue_msg->has_command_type = 1;
	envelope_ptr->msgqueue_msg->broadcast_semantics	=	MESSAGE_QUEUE_MESSAGE__BROADCAST_SEMANTICS__INTER; envelope_ptr->msgqueue_msg->has_broadcast_semantics	=	1;
	envelope_ptr->msgqueue_msg->message								=	envelope_ptr->message_command;
	envelope_ptr->msgqueue_msg->message->header				=	envelope_ptr->header;

	envelope_ptr->header->args												=	command_arg;
	envelope_ptr->header->when												=	event_ptr->when; 					envelope_ptr->header->has_when = 1;
	envelope_ptr->header->eid													=	SESSION_EID(sesn_ptr);		envelope_ptr->header->has_eid = 1;
	envelope_ptr->header->cid													=	SESSION_ID(sesn_ptr); 		envelope_ptr->header->has_cid = 1;
	MakeUfsrvUidInProto(&SESSION_UFSRVUIDSTORE(sesn_ptr), &(envelope_ptr->header->ufsrvuid), true); envelope_ptr->header->has_ufsrvuid = 1;

}

/**
 * 	@brief: Main interface function for INTER broadcasting user message postings Invoked by teh main handler that processed the original
 * 	INTRA message.
 *
 * 	@ param context_ptr: MessageCommand * as provided to the original handler
 */
UFSRVResult *
InterBroadcastUserMessage (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg)
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
	message_command.fences		  =	msgcmd_ptr->fences;
	message_command.n_fences	  =	msgcmd_ptr->n_fences;
	if (IS_PRESENT(event_ptr) && !IS_EMPTY(message_command.fences)) {//intro msg dont have fences
	  message_command.fences[0]->eid = event_ptr->eid;
	  message_command.fences[0]->has_eid = 1;
	}

	message_command.messages	  =	msgcmd_ptr->messages;
	message_command.n_messages	=	msgcmd_ptr->n_messages;
	message_command.to          = msgcmd_ptr->to;
	message_command.n_to        = msgcmd_ptr->n_to;
  message_command.intro       = msgcmd_ptr->intro;

	return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg, msgqueue_msg.command_type));
}

UFSRVResult *
InterBroadcastUserMessageReported (CommandBaseContext *cmd_base_ctx, enum _CommandArgs command_arg)
{
  MessageCommandContext *cmd_ctx_ptr = (MessageCommandContext *) cmd_base_ctx;

  _GENERATE_ENVELOPE_INITIALISATION(); //replaces above
  _PrepareBroadcastMessageForMessage(&envelope, CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), CMDCTX_DATA_MESSAGE(cmd_ctx_ptr)->ufsrvcommand->msgcommand, (FenceEvent *)CMDCTX_EVENT(cmd_ctx_ptr), command_arg);

  MessageCommand	*msgcmd_ptr	=	CMDCTX_DATA_MESSAGE(cmd_ctx_ptr)->ufsrvcommand->msgcommand;
  //actual delta
  message_command.reported		  =	msgcmd_ptr->reported;
  message_command.n_reported	  =	msgcmd_ptr->n_reported;

  return (UfsrvInterBroadcastMessage(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), &msgqueue_msg, msgqueue_msg.command_type));
}

UFSRVResult *
InterBroadcastGuardianRequest (CommandBaseContext *cmd_base_ctx, enum _CommandArgs command_arg)
{
  MessageCommandContext *cmd_ctx_ptr = (MessageCommandContext *) cmd_base_ctx;
  _GENERATE_ENVELOPE_INITIALISATION();
  _PrepareBroadcastMessageForMessage(&envelope, CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), CMDCTX_DATA_MESSAGE(cmd_ctx_ptr)->ufsrvcommand->msgcommand, (FenceEvent *)CMDCTX_EVENT(cmd_ctx_ptr), command_arg);

  MessageCommand	*msgcmd_ptr	=	CMDCTX_DATA_MESSAGE(cmd_ctx_ptr)->ufsrvcommand->msgcommand;
  //actual delta

  return (UfsrvInterBroadcastMessage(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), &msgqueue_msg, msgqueue_msg.command_type));
}

int
HandleInterBroadcastForUserMessage (MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long callflags)
{
	int 										rescode	= 0;
  FenceSessionPair	fence_sesn_pair				=	{0};
  BroadcastMessageGuardianDescriptor guardian_descriptor ={0};
  UFSRVResult 			result								=	{0};
  CommandHeader 		*command_header_ptr		=	mqm_ptr->message->header;

  void *command_types [] = {
          &&MESSAGE_COMMAND__COMMAND_TYPES__SAY,
          &&MESSAGE_COMMAND__COMMAND_TYPES__CONTACTS,
          &&MESSAGE_COMMAND__COMMAND_TYPES__FLAG,
          &&MESSAGE_COMMAND__COMMAND_TYPES__LIKE,
          &&MESSAGE_COMMAND__COMMAND_TYPES__FOLLOW,
          &&MESSAGE_COMMAND__COMMAND_TYPES__PREVIEW,
          &&MESSAGE_COMMAND__COMMAND_TYPES__INTRO,
          &&MESSAGE_COMMAND__COMMAND_TYPES__STICKER,
          &&MESSAGE_COMMAND__COMMAND_TYPES__GUARDIAN_REQUEST,
          &&MESSAGE_COMMAND__COMMAND_TYPES__GUARDIAN_LINK,
          &&MESSAGE_COMMAND__COMMAND_TYPES__GUARDIAN_UNLINK,
  }; //ALIGN WITH PROTOBUF

  goto *command_types[command_header_ptr->command];

  MESSAGE_COMMAND__COMMAND_TYPES__SAY:
  PrepareForMessageCommandInterBroadcastHandling (mqm_ptr, &fence_sesn_pair, &result, command_header_ptr->command); //SESSION LOCKED, FENCE LOCKED, SESSION LOADED WITH ACCESS CONTEXT FROM UFSRVWORKER
  if (_RESULT_TYPE_ERROR(&result))	goto return_final;
  _HandleInterBroadcastUserMessageSay((ClientContextData *)&fence_sesn_pair, mqm_ptr, &result, callflags);
  goto return_success;

  MESSAGE_COMMAND__COMMAND_TYPES__INTRO:
  PrepareForMessageCommandInterBroadcastHandling (mqm_ptr, &fence_sesn_pair, &result, command_header_ptr->command);//SESSION LOCKED, FENCE LOCKED, SESSION LOADED WITH ACCESS CONTEXT FROM UFSRVWORKER
  if (_RESULT_TYPE_ERROR(&result))	goto return_final;
  _HandleInterBroadcastUserMessageIntro((ClientContextData *)&fence_sesn_pair, mqm_ptr, &result, callflags);
  goto return_success;

  MESSAGE_COMMAND__COMMAND_TYPES__FLAG:
  _PrepareForInterBroadcastHandlingMessageReported(mqm_ptr, &fence_sesn_pair, res_ptr);
  if (_RESULT_TYPE_ERROR(&result))	goto return_final;
  _HandleInterBroadcastUserMessageReported((ClientContextData *)&fence_sesn_pair, mqm_ptr, &result, callflags);

  MESSAGE_COMMAND__COMMAND_TYPES__GUARDIAN_REQUEST:
  _PrepareForInterBroadcastHandlingGuardian(mqm_ptr, &guardian_descriptor, &result);
  if (_RESULT_TYPE_ERROR(&result))	goto return_final;
  _HandleInterBroadcastUserMessageGuardianRequest((ClientContextData *)&fence_sesn_pair, mqm_ptr, &result, callflags);
  goto return_success_for_guardian;

  MESSAGE_COMMAND__COMMAND_TYPES__GUARDIAN_LINK:
  _PrepareForInterBroadcastHandlingGuardian(mqm_ptr, &guardian_descriptor, &result);
  if (_RESULT_TYPE_ERROR(&result))	goto return_final;
  _HandleInterBroadcastUserMessageGuardianLink((ClientContextData *)&fence_sesn_pair, mqm_ptr, &result, callflags);
  goto return_success_for_guardian;

  MESSAGE_COMMAND__COMMAND_TYPES__GUARDIAN_UNLINK:
  _PrepareForInterBroadcastHandlingGuardian(mqm_ptr, &guardian_descriptor, &result);
  if (_RESULT_TYPE_ERROR(&result))	goto return_final;
  _HandleInterBroadcastUserMessageGuardianUnlink((ClientContextData *)&fence_sesn_pair, mqm_ptr, &result, callflags);
  goto return_success_for_guardian;

  MESSAGE_COMMAND__COMMAND_TYPES__CONTACTS:
  MESSAGE_COMMAND__COMMAND_TYPES__LIKE:
  MESSAGE_COMMAND__COMMAND_TYPES__FOLLOW:
  MESSAGE_COMMAND__COMMAND_TYPES__PREVIEW:
  MESSAGE_COMMAND__COMMAND_TYPES__STICKER:
  goto return_final;

  return_success:
  if (IS_PRESENT(fence_sesn_pair.instance_f_ptr))	if (!fence_sesn_pair.fence_lock_already_owned)	FenceEventsUnLockCtx (THREAD_CONTEXT_PTR, FenceOffInstanceHolder(fence_sesn_pair.instance_f_ptr), THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));
  if (IS_PRESENT(fence_sesn_pair.instance_sesn_ptr)) {
    Session *sesn_ptr = SessionOffInstanceHolder(fence_sesn_pair.instance_sesn_ptr);
    SessionUnLoadEphemeralMode(sesn_ptr);
    SessionUnLockCtx (THREAD_CONTEXT_PTR, sesn_ptr, __func__);
  }
  return rescode;

  return_success_for_guardian:
  if (!guardian_descriptor.ctx_sesn_ptr_guardian.lock_already_owned) SessionUnLockCtx (THREAD_CONTEXT_PTR, guardian_descriptor.ctx_sesn_ptr_guardian.sesn_ptr, __func__);
  if (!guardian_descriptor.ctx_sesn_ptr_originator.lock_already_owned) SessionUnLockCtx (THREAD_CONTEXT_PTR, guardian_descriptor.ctx_sesn_ptr_originator.sesn_ptr, __func__);
  goto return_final;

  return_final:
  return rescode;

}

static UFSRVResult *
_HandleInterBroadcastUserMessageSay (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
  FenceSessionPair *pair_ptr				=	(FenceSessionPair *)context_ptr;
  FenceRecord *fence_record_ptr = mqm_ptr->message->fences[0];
  Fence *f_ptr = FenceOffInstanceHolder(pair_ptr->instance_f_ptr);
  FENCE_FENECE_EVENTS_COUNTER(f_ptr) = mqm_ptr->message->fences[0]->eid;

  Session *sesn_ptr = SessionOffInstanceHolder(pair_ptr->instance_sesn_ptr);
  SESSION_EID(sesn_ptr) = mqm_ptr->message->header->eid;

  //todo: what to do with time of event?

  _RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
}

static UFSRVResult *
_HandleInterBroadcastUserMessageIntro (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
  FenceSessionPair *pair_ptr				=	(FenceSessionPair *)context_ptr;

  Session *sesn_ptr = SessionOffInstanceHolder(pair_ptr->instance_sesn_ptr);
  SESSION_EID(sesn_ptr) = mqm_ptr->message->header->eid;
  //todo: what to do with time of event?

  _RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
}

static UFSRVResult *
_HandleInterBroadcastUserMessageReported (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
  FenceSessionPair *pair_ptr				=	(FenceSessionPair *)context_ptr;
  Fence *f_ptr = FenceOffInstanceHolder(pair_ptr->instance_f_ptr);
  FENCE_ID(f_ptr) = mqm_ptr->message->reported[0]->eid;

  _RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
}

static UFSRVResult *
_HandleInterBroadcastUserMessageGuardianRequest (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
  BroadcastMessageGuardianDescriptor *descriptor_ptr				=	(BroadcastMessageGuardianDescriptor *)context_ptr;
  GuardianRecord *guardian_record = mqm_ptr->message->guardian;

  if (guardian_record->originator->eid > 0) SESSION_EID(descriptor_ptr->ctx_sesn_ptr_originator.sesn_ptr) = guardian_record->originator->eid;

  _RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
}

static UFSRVResult *
_HandleInterBroadcastUserMessageGuardianLink (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
  BroadcastMessageGuardianDescriptor *descriptor_ptr				=	(BroadcastMessageGuardianDescriptor *)context_ptr;
  GuardianRecord *guardian_record = mqm_ptr->message->guardian;

  if (guardian_record->originator->eid > 0) SESSION_EID(descriptor_ptr->ctx_sesn_ptr_originator.sesn_ptr) = guardian_record->originator->eid;
  if (guardian_record->guardian->eid > 0) SESSION_EID(descriptor_ptr->ctx_sesn_ptr_guardian.sesn_ptr) = guardian_record->guardian->eid;

  SESSION_USERGUARDIAN_UID(descriptor_ptr->ctx_sesn_ptr_originator.sesn_ptr) = SESSION_USERID(descriptor_ptr->ctx_sesn_ptr_guardian.sesn_ptr);

  _RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
}

static UFSRVResult *
_HandleInterBroadcastUserMessageGuardianUnlink (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
  BroadcastMessageGuardianDescriptor *descriptor_ptr				=	(BroadcastMessageGuardianDescriptor *)context_ptr;
  GuardianRecord *guardian_record = mqm_ptr->message->guardian;

  if (guardian_record->originator->eid > 0) SESSION_EID(descriptor_ptr->ctx_sesn_ptr_originator.sesn_ptr) = guardian_record->originator->eid;
  if (guardian_record->guardian->eid > 0) SESSION_EID(descriptor_ptr->ctx_sesn_ptr_guardian.sesn_ptr) = guardian_record->guardian->eid;

  SESSION_USERGUARDIAN_UID(descriptor_ptr->ctx_sesn_ptr_originator.sesn_ptr) = 0;

  _RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
}

/**
 * 	@brief: Helper routine to load a session for further INTER processing
 * 	@IMPORTANT: THIS LOADS backend access via ephemeral mode
 *
 * 	The logic is as follows:
 * 	1)Load fence locally:
 * 	1.1) fence local fails: load session locally
 * 	1.1.1)session local success -> user we  know of joined a fence we don't know of
 * 													 -> backend-load Fence  (we'll retrieve full user list from loading fence in user list anyway, include ing this session)
 * 													 -> link up and update locally consistent with INTER semantics (may not be necessary as backend load will build the user list incuding this one)
 * 	1.1.2)session local fail -> user we don't know of with msg for a fence we don't know of -> exit
 *
 * 	1.2) fence local success:
 * 	1.2.1) load session locally:
 * 				success:
 * 				 				-> great known user + known fence
 * 								-> link up and update locally consistent with INTER semantics
 * 								-> backend-load user sessionwith full list
 * 								-> link up and update locally consistent with INTER semantics (linkup may not be necessary because backend load will do that anyway)
 *
 *	@locks Session *, except when fence is geo type
 *	@locks Fence *
 */
UFSRVResult *
PrepareForMessageCommandInterBroadcastHandling (MessageQueueMessage *mqm_ptr, FenceSessionPair *fence_sesn_pair_ptr, UFSRVResult *res_ptr, int command)
{
  Fence				*f_ptr;
  FenceRecord *fence_record_ptr	=	mqm_ptr->message->fences[0];

  UFSRVResult *res_ptr_returned = FindFenceById(NULL, fence_record_ptr->fid, FENCE_CALLFLAG_KEEP_FENCE_LOCKED|FENCE_CALLFLAG_LOCK_FENCE_BLOCKING);
  InstanceHolderForFence *instance_f_ptr = (InstanceHolder *)_RESULT_USERDATA(res_ptr_returned);

  if (IS_EMPTY(instance_f_ptr) && _RESULT_TYPE_EQUAL(res_ptr_returned, RESCODE_PROG_WONTLOCK)) {
    _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_WONTLOCK)
  }

  bool fence_lock_already_owned = false;

  //at this stage fence could be existent or not
  if (IS_PRESENT((instance_f_ptr))) {
    fence_lock_already_owned = (_RESULT_CODE_EQUAL(res_ptr_returned, RESCODE_PROG_LOCKED_BY_THIS_THREAD));

    f_ptr = FenceOffInstanceHolder(instance_f_ptr);

    //>>>>> Fence locked

    if (mqm_ptr->message->header->cid == 0)	goto return_unlock_fence;//no session associated with event

    Session                   *sesn_ptr_localuser;
    InstanceHolderForSession  *instance_sesn_ptr_localuser;

    if (IS_PRESENT((instance_sesn_ptr_localuser = LocallyLocateSessionById(mqm_ptr->message->header->cid)))) {
      sesn_ptr_localuser = SessionOffInstanceHolder(instance_sesn_ptr_localuser);
      SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_localuser, _LOCK_TRY_FLAG_FALSE, __func__);
      if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR)) {
        goto return_locked_session_error;
      }

      bool lock_already_owned = (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_BY_THIS_THREAD));

      SessionLoadEphemeralMode(sesn_ptr_localuser);
      fence_sesn_pair_ptr->instance_f_ptr = instance_f_ptr;
      fence_sesn_pair_ptr->instance_sesn_ptr = instance_sesn_ptr_localuser;
      fence_sesn_pair_ptr->lock_already_owned = lock_already_owned;
      fence_sesn_pair_ptr->fence_lock_already_owned = fence_lock_already_owned;
      fence_sesn_pair_ptr->flag_fence_local = fence_sesn_pair_ptr->flag_session_local = true;
      //both session/fence locked

      _RETURN_RESULT_RES(res_ptr, fence_sesn_pair_ptr, RESULT_TYPE_SUCCESS, RESCODE_USER_SESN_LOCAL)
    } else {
#define SESSION_CALL_FLAGS (CALL_FLAG_LOCK_SESSION|CALL_FLAG_HASH_SESSION_LOCALLY|					\
                          CALL_FLAG_HASH_UID_LOCALLY|CALL_FLAG_HASH_USERNAME_LOCALLY|			\
                          CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION|CALL_FLAG_REMOTE_SESSION)

      //given NULL session, load backend context from ufsrvworker's
      unsigned  long uid = UfsrvUidGetSequenceId((const UfsrvUid *) mqm_ptr->message->header->ufsrvuid.data);
      if (IS_PRESENT((instance_sesn_ptr_localuser = SessionInstantiateFromBackend (NULL, uid, SESSION_CALL_FLAGS)))) {
        sesn_ptr_localuser = SessionOffInstanceHolder(instance_sesn_ptr_localuser);
        SESSION_WHEN_SERVICE_STARTED(sesn_ptr_localuser) = time(NULL);
        SessionLoadEphemeralMode(sesn_ptr_localuser);
        fence_sesn_pair_ptr->instance_f_ptr = instance_f_ptr;
        fence_sesn_pair_ptr->instance_sesn_ptr = instance_sesn_ptr_localuser;
        fence_sesn_pair_ptr->flag_fence_local = true;
        fence_sesn_pair_ptr->flag_session_local = false; //no need to set session lock state since it is backend instantiated and no prior lock could've existed
        fence_sesn_pair_ptr->fence_lock_already_owned = fence_lock_already_owned;
        //both session/fence locked

        _RETURN_RESULT_RES(res_ptr, fence_sesn_pair_ptr, RESULT_TYPE_SUCCESS, RESCODE_USER_SESN_LOCAL)
      }
      else goto return_unlock_fence;
    }
  } else { //1)fence not found locally 2)no locks instated so far
    if (mqm_ptr->message->header->cid == 0)	goto exit_error; //no session associated with event

    Session                   *sesn_ptr_localuser;
    InstanceHolderForSession  *instance_sesn_ptr_localuser;

    if (IS_PRESENT((instance_sesn_ptr_localuser = LocallyLocateSessionById(mqm_ptr->message->header->cid)))) {
      sesn_ptr_localuser = SessionOffInstanceHolder(instance_sesn_ptr_localuser);

      SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_localuser, _LOCK_TRY_FLAG_FALSE, __func__);
      if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR)) goto return_unlock_fence;
      bool lock_already_owned = (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_BY_THIS_THREAD));

      InstanceHolderForSession *instance_sesn_ptr_carrier = InstantiateCarrierSession(NULL, WORKERTYPE_UFSRVWORKER, SESSION_CALLFLAGS_EMPTY);
      Session *sesn_ptr_carrier = SessionOffInstanceHolder(instance_sesn_ptr_carrier);
#define FENCE_CALLFLAGS (FENCE_CALLFLAG_HASH_FENCE_LOCALLY|FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE|FENCE_CALLFLAG_KEEP_FENCE_LOCKED|FENCE_CALLFLAG_LOCK_FENCE_BLOCKING)
      GetCacheRecordForFence(sesn_ptr_carrier, 0, fence_record_ptr->fid, UNSPECIFIED_UID, &fence_lock_already_owned, FENCE_CALLFLAGS);
      instance_f_ptr = (InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr_carrier);

      SessionReturnToRecycler(instance_sesn_ptr_carrier, (ContextData *) NULL, CALL_FLAG_CARRIER_INSTANCE);

      if (IS_PRESENT(instance_f_ptr)) {
        //>> SESSION/FENCE LOCKED >>>
        SESSION_WHEN_SERVICE_STARTED(sesn_ptr_localuser) = time(NULL);
        fence_sesn_pair_ptr->instance_f_ptr = instance_f_ptr;
        fence_sesn_pair_ptr->instance_sesn_ptr = instance_sesn_ptr_localuser;
        fence_sesn_pair_ptr->flag_fence_local = false;
        fence_sesn_pair_ptr->flag_session_local = true;
        fence_sesn_pair_ptr->lock_already_owned = lock_already_owned;
        fence_sesn_pair_ptr->fence_lock_already_owned = fence_lock_already_owned;
        _RETURN_RESULT_RES(res_ptr, fence_sesn_pair_ptr, RESULT_TYPE_SUCCESS, RESCODE_USER_SESN_LOCAL)
      } else {
        syslog(LOG_ERR, "%s {pid:'%lu', eid:'%lu', cid:'%lu', fid:'%lu'}: ERROR: COULD NOT LOCATE FENCE...", __func__, pthread_self(), mqm_ptr->message->header->eid, mqm_ptr->message->header->cid, fence_record_ptr->fid);
        if (!lock_already_owned)  SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_localuser, __func__);
        goto exit_error;
      }
    } else {
      syslog(LOG_ERR, "%s {pid:'%lu', eid:'%lu', cid:'%lu', fid:'%lu'}: ERROR: COULD NOT LOCATE LOCAL SESSION", __func__, pthread_self(), mqm_ptr->message->header->eid, mqm_ptr->message->header->cid, fence_record_ptr->fid);
      goto exit_error;
    }
  }

  return_unlock_fence:
  if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, THREAD_CONTEXT_UFSRV_RESULT(ufsrv_thread_context));
  fence_sesn_pair_ptr->instance_f_ptr = instance_f_ptr;
  fence_sesn_pair_ptr->instance_sesn_ptr = NULL;
  goto exit_error;

  return_locked_session_error:
  if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, THREAD_CONTEXT_UFSRV_RESULT(ufsrv_thread_context));
  fence_sesn_pair_ptr->instance_f_ptr = instance_f_ptr;
  fence_sesn_pair_ptr->instance_sesn_ptr = NULL;
  goto exit_error_locked_session;

  exit_error:
  _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_USER_SESN_LOCAL)

  exit_error_locked_session:
  _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOGIC_CANTLOCK)

#undef 	SESSION_CALL_FLAGS
#undef 	FENCE_CALL_FLAGS
}

static UFSRVResult *
_PrepareForInterBroadcastHandlingMessageReported (MessageQueueMessage *mqm_ptr, FenceSessionPair *fence_sesn_pair_ptr, UFSRVResult *res_ptr)
{
  if (IS_PRESENT(mqm_ptr->message->reported) && IS_PRESENT(mqm_ptr->message->reported[0])) {
    UFSRVResult *res_ptr_returned = FindFenceById(NULL, mqm_ptr->message->reported[0]->fid, FENCE_CALLFLAG_KEEP_FENCE_LOCKED | FENCE_CALLFLAG_LOCK_FENCE_BLOCKING);
    InstanceHolderForFence *instance_f_ptr = (InstanceHolder *) _RESULT_USERDATA(res_ptr_returned);

    if (IS_EMPTY(instance_f_ptr) && _RESULT_TYPE_EQUAL(res_ptr_returned, RESCODE_PROG_WONTLOCK)) {
      _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_WONTLOCK)
    }

    bool fence_lock_already_owned = false;

    //at this stage fence could be existent or not
    if (IS_PRESENT((instance_f_ptr))) {
      fence_lock_already_owned = (_RESULT_CODE_EQUAL(res_ptr_returned, RESCODE_PROG_LOCKED_BY_THIS_THREAD));

      fence_sesn_pair_ptr->instance_f_ptr = instance_f_ptr;
      fence_sesn_pair_ptr->fence_lock_already_owned = fence_lock_already_owned;
      fence_sesn_pair_ptr->flag_fence_local = true;
      _RETURN_RESULT_RES(res_ptr, fence_sesn_pair_ptr, RESULT_TYPE_SUCCESS, RESCODE_USER_SESN_LOCAL)
    }
  }

  _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
}

static UFSRVResult *
_PrepareForInterBroadcastHandlingGuardian (MessageQueueMessage *mqm_ptr, BroadcastMessageGuardianDescriptor *descriptor_ptr, UFSRVResult *res_ptr)
{
#define SESSION_CALL_FLAGS (CALL_FLAG_LOCK_SESSION|CALL_FLAG_HASH_SESSION_LOCALLY|					\
                          CALL_FLAG_HASH_UID_LOCALLY|CALL_FLAG_HASH_USERNAME_LOCALLY|			\
                          CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION|CALL_FLAG_REMOTE_SESSION)

  if (IS_PRESENT(mqm_ptr->message->guardian)) {
    bool lock_already_owned_guardian = false,
         lock_already_owned_originator = false;

    GuardianRecord *guardian_record_ptr = mqm_ptr->message->guardian;
    InstanceHolderForSession *instance_sesn_ptr_guardian = LocallyLocateSessionByUfsrvUid((const UfsrvUid *)guardian_record_ptr->guardian->ufsrvuid.data);
    InstanceHolderForSession *instance_sesn_ptr_originator = LocallyLocateSessionByUfsrvUid((const UfsrvUid *)guardian_record_ptr->originator->ufsrvuid.data);

    if (IS_PRESENT(instance_sesn_ptr_guardian)) {
      SessionLockRWCtx(THREAD_CONTEXT_PTR, SessionOffInstanceHolder(instance_sesn_ptr_guardian), _LOCK_TRY_FLAG_FALSE, __func__);
      if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR)) {
        _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
      }

      descriptor_ptr->ctx_sesn_ptr_guardian.lock_already_owned = lock_already_owned_guardian = (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_BY_THIS_THREAD));

      if (!IS_PRESENT(instance_sesn_ptr_originator)) {
        instance_sesn_ptr_originator = SessionInstantiateFromBackend(NO_SESSION, UfsrvUidGetSequenceId((const UfsrvUid *)guardian_record_ptr->originator->ufsrvuid.data), SESSION_CALL_FLAGS);
        if (IS_EMPTY(instance_sesn_ptr_originator)) {
          if (!lock_already_owned_guardian) SessionUnLockCtx(THREAD_CONTEXT_PTR, SessionOffInstanceHolder(instance_sesn_ptr_guardian), __func__);
          _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
        }
      } else {
        //both are locally available
        SessionLockRWCtx(THREAD_CONTEXT_PTR, SessionOffInstanceHolder(instance_sesn_ptr_originator), _LOCK_TRY_FLAG_FALSE, __func__);
        if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR)) {
          if (!lock_already_owned_guardian) SessionUnLockCtx(THREAD_CONTEXT_PTR, SessionOffInstanceHolder(instance_sesn_ptr_guardian), __func__);
          _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
        }

        descriptor_ptr->ctx_sesn_ptr_originator.lock_already_owned = (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_BY_THIS_THREAD));
      }
    } else if (IS_PRESENT(instance_sesn_ptr_originator)) {
      SessionLockRWCtx(THREAD_CONTEXT_PTR, SessionOffInstanceHolder(instance_sesn_ptr_originator), _LOCK_TRY_FLAG_FALSE, __func__);
      if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR)) {
        _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
      }

      descriptor_ptr->ctx_sesn_ptr_originator.lock_already_owned = lock_already_owned_originator = (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_BY_THIS_THREAD));

      if (!IS_PRESENT(instance_sesn_ptr_guardian)) {//must be true
        instance_sesn_ptr_guardian = SessionInstantiateFromBackend(NO_SESSION, UfsrvUidGetSequenceId((const UfsrvUid *)guardian_record_ptr->guardian->ufsrvuid.data), SESSION_CALL_FLAGS);
        if (IS_EMPTY(instance_sesn_ptr_guardian)) {
          if (!lock_already_owned_originator) SessionUnLockCtx(THREAD_CONTEXT_PTR, SessionOffInstanceHolder(instance_sesn_ptr_originator), __func__);
          _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
        }

        descriptor_ptr->ctx_sesn_ptr_guardian.lock_already_owned = (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_BY_THIS_THREAD));
      }
    } else {
      //both non local
      _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_USER_SESN_LOCAL)
    }
  }

  _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
}

///// END INTER \\\\


///// INTRA	\\\\\\

inline static int _VetrifyUserMessageCommandForIntra	(MessageQueueMessage *mqm_ptr, bool flag_free_unpacked);

int
HandleIntraBroadcastForUserMessage (MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	int				rc					= 0;
	long long timer_start	=	GetTimeNowInMicros();
	long long timer_end;

	if ((rc = _VetrifyUserMessageCommandForIntra(mqm_ptr, false)) < 0)	goto return_final;

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

	ParsedMessageDescriptor msg_descriptor = {0};
	UFSRVResult *res_ptr_returned = CommandCallbackControllerMessageCommand(&(InstanceContextForSession){instance_sesn_ptr_local_user, sesn_ptr_local_user}, NULL, mqm_ptr->wire_data, &msg_descriptor);
	if (_RESULT_CODE_EQUAL(res_ptr_returned, RESCODE_UFSRV_STORE_MSG)) {
    DbBackendInsertMessageRecord ((const ParsedMessageDescriptor *)&msg_descriptor);
    free (msg_descriptor.rawmsg);
	}

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
inline static int
_VetrifyUserMessageCommandForIntra	(MessageQueueMessage *mqm_ptr, bool flag_free_unpacked)
{
	int rc = 1;
	MessageCommand *msgcmd_ptr = mqm_ptr->wire_data->ufsrvcommand->msgcommand;

	if (unlikely(IS_EMPTY((msgcmd_ptr))))				goto return_error_fencecommand_missing;
	if (unlikely(IS_EMPTY(msgcmd_ptr->header)))	goto return_error_commandheader_missing;
	if (unlikely(msgcmd_ptr->header->command == MESSAGE_COMMAND__COMMAND_TYPES__SAY &&
	             (IS_EMPTY(msgcmd_ptr->fences) || IS_EMPTY(msgcmd_ptr->fences[0]))))				goto return_error_missing_fence_definition;
	if (unlikely(mqm_ptr->has_ufsrvuid == 0))																				goto return_error_missing_ufsrvuid;

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
	rc = -8;
	goto return_free;

	return_error_fencecommand_missing:
	syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: COULD NOT FIND MESSAGE COMMAND IN UNPACKED MESAGEQUEUE", __func__, pthread_self());
	rc=-4;
	goto return_free;

	return_error_missing_ufsrvuid:
	syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: UFSRVUID MISSING FROM MESSAGE", __func__, pthread_self());
	rc=-5;
	goto return_free;

	return_error_missing_fence_definition:
	syslog(LOG_DEBUG, "%s (pid:'%lu): ERROR: MESSAGE COMMAND DID NOT INCLUDE VALID FENCE DEFINITION", __func__, pthread_self());
	rc=-6;
	goto	return_free;

	return_free://exit_proto:
	if (flag_free_unpacked)	message_queue_message__free_unpacked(mqm_ptr, NULL);

	return_final:
	return rc;

}

//////////////////


