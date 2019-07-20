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
#include <fence_state.h>
#include <user_preferences.h>
#include <location.h>
#include <share_list.h>
#include <persistance.h>
#include <nportredird.h>
#include <protocol_websocket_session.h>
#include <protocol_http.h>
#include <ufsrvcmd_broadcast.h>
#include <user_broadcast.h>
#include <command_controllers.h>
#include <ufsrvuid.h>
#include <users_proto.h>

extern ufsrv 							*const masterptr;
extern SessionsDelegator 	*const sessions_delegator_ptr;
extern __thread ThreadContext ufsrv_thread_context;

struct BroadcastMessageEnvelopeForUser {
		MessageQueueMessage *msgqueue_msg;
		UserCommand 				*user_command;
		CommandHeader 			*header;
		UserPreference			*userpref_record;
		UserPreference 			**userpref_records;
		FenceUserPreference	*fence_userpref_record;
		FenceUserPreference **fence_userpref_records;
		FenceRecord					*fence_record;
		FenceRecord					**fence_records;
};

typedef struct BroadcastMessageEnvelopeForUser BroadcastMessageEnvelopeForUser;

inline static void _PrepareInterBroadcastMessageForUser(BroadcastMessageEnvelopeForUser *envelope_ptr, Session *sesn_ptr, UfsrvEvent *event_ptr, enum _CommandArgs command_arg);
static inline UFSRVResult *_PrepareForInterBroadcastHandling (MessageQueueMessage *mqm_ptr, ShareListContextData *, UFSRVResult *res_ptr, int);

////// INTER \\\\\\

static UFSRVResult *_HandleInterBroadcastUserPrefs (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastUserPrefsDefaultBooleans (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastUserPrefsNickname (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastUserPrefsAvatar (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastShareListProfile (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastForShareList(ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr,
                                                      UFSRVResult *res_ptr, unsigned long call_flags);

static UFSRVResult *_HandleInterBroadcastFenceUserPrefs (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastFenceUserPrefsDefaultBooleans(ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
//static UFSRVResult *_HandleInterBroadcastFenceUserPrefsProfileSharing (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
//static UFSRVResult *_HandleInterBroadcastFenceUserPrefsStickyGroups (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
//static UFSRVResult *_HandleInterBroadcastFenceUserPrefsIgnoring (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);

#define _GENERATE_ENVELOPE_INITIALISATION() \
		MessageQueueMessage 	msgqueue_msg				=	MESSAGE_QUEUE_MESSAGE__INIT;	\
		UserCommand 					user_command				=	USER_COMMAND__INIT;	\
		CommandHeader 				header							=	COMMAND_HEADER__INIT;	\
		\
		UserPreference				userpref_record			=	USER_PREFERENCE__INIT;	\
		UserPreference 				*userpref_records[1];	\
		\
		BroadcastMessageEnvelopeForUser	envelope_broadcast = {	\
				.msgqueue_msg				=	&msgqueue_msg,	\
				.user_command				=	&user_command,	\
				.header							=	&header,	\
				.userpref_record		=	&userpref_record,	\
				.userpref_records		=	userpref_records,	\
				.fence_userpref_record		=	NULL,	\
				.fence_userpref_records		=	NULL,	\
				.fence_record				=	NULL, \
				.fence_records			=	NULL	\
		}

#define _GENERATE_ENVELOPE_INITIALISATION_FENCE_USERPREF() \
		MessageQueueMessage 	msgqueue_msg				=	MESSAGE_QUEUE_MESSAGE__INIT;	\
		UserCommand 					user_command				=	USER_COMMAND__INIT;	\
		CommandHeader 				header							=	COMMAND_HEADER__INIT;	\
		\
		FenceUserPreference		fence_userpref_record			=	FENCE_USER_PREFERENCE__INIT;	\
		FenceUserPreference 	*fence_userpref_records[1];	\
		FenceRecord						fence_record			=	FENCE_RECORD__INIT;	\
		FenceRecord 					*fence_records[1];	\
		\
		BroadcastMessageEnvelopeForUser	envelope_broadcast = {	\
				.msgqueue_msg				=	&msgqueue_msg,	\
				.user_command				=	&user_command,	\
				.header							=	&header,	\
				.userpref_record		=	NULL,	\
				.userpref_records		=	NULL,	\
				.fence_userpref_record		=	&fence_userpref_record,	\
				.fence_userpref_records		=	fence_userpref_records,	\
				.fence_record				=	&fence_record, \
				.fence_records			=	fence_records	\
		}

#define _GENERATE_ENVELOPE_INITIALISATION_SHARELIST(x) \
		MessageQueueMessage 	msgqueue_msg				=	MESSAGE_QUEUE_MESSAGE__INIT;	\
		\
		BroadcastMessageEnvelopeForUser	envelope_broadcast = {	\
				.msgqueue_msg				=	&msgqueue_msg,	\
				.user_command				=	x,	\
		}

inline static void
_PrepareInterBroadcastMessageForUser(BroadcastMessageEnvelopeForUser *envelope_ptr, Session *sesn_ptr, UfsrvEvent *event_ptr, enum _CommandArgs command_arg)
{
	//consider using UfsrvMsgCommandType msgcmd_type for command_type
	envelope_ptr->msgqueue_msg->command_type				=	UFSRV_USER; envelope_ptr->msgqueue_msg->has_command_type=1;
	envelope_ptr->msgqueue_msg->broadcast_semantics	=	MESSAGE_QUEUE_MESSAGE__BROADCAST_SEMANTICS__INTER; envelope_ptr->msgqueue_msg->has_broadcast_semantics	=1;
	envelope_ptr->msgqueue_msg->user								=	envelope_ptr->user_command;


	if (IS_PRESENT(envelope_ptr->userpref_records)) {
	envelope_ptr->user_command->prefs								=	envelope_ptr->userpref_records;
	envelope_ptr->user_command->prefs[0]						=	envelope_ptr->userpref_record;
	envelope_ptr->user_command->n_prefs							=	1;
	}

	if (IS_PRESENT(envelope_ptr->fence_userpref_records)) {
		envelope_ptr->user_command->fence_prefs								=	envelope_ptr->fence_userpref_records;
		envelope_ptr->user_command->fence_prefs[0]						=	envelope_ptr->fence_userpref_record;
		envelope_ptr->user_command->n_fence_prefs							=	1;
		}

	if (IS_PRESENT(envelope_ptr->fence_records)) {
		envelope_ptr->user_command->fences							=	envelope_ptr->fence_records;
		envelope_ptr->user_command->fences[0]						=	envelope_ptr->fence_record;
		envelope_ptr->user_command->n_fences						=	1;
	}

	//sometimes headers are already included whole-sale assignment of usercommand
	if (IS_PRESENT(envelope_ptr->header)) {
		envelope_ptr->header->args											=	command_arg;							envelope_ptr->header->has_args=1;
		envelope_ptr->user_command->header							=	envelope_ptr->header;
		envelope_ptr->header->when											=	GetTimeNowInMillis(); 		envelope_ptr->header->has_when=1;
		envelope_ptr->header->cid												=	SESSION_ID(sesn_ptr); 		envelope_ptr->header->has_cid=1;
		MakeUfsrvUidInProto(&SESSION_UFSRVUIDSTORE(sesn_ptr), &(envelope_ptr->header->ufsrvuid), true); envelope_ptr->header->has_ufsrvuid = 1;

		if (IS_PRESENT(event_ptr)) {
			envelope_ptr->header->when_eid								=	event_ptr->when; 					envelope_ptr->header->has_when_eid=1;
			envelope_ptr->header->eid											=	event_ptr->eid; 					envelope_ptr->header->has_eid=1;
		}
	}
}

/**
 * 	@brief: Main handler for USER INTER broadcast messages arriving via messagequeue. The handler will be run from UfsrvWorker context,
 * 	as opposed to SessionWorker one, therefore the affected user session must be loaded in ephemeral mode.
 * 	Prior to invoking this function a command-type specific verification will have taken place inside '_VerifyInterMessageQueueCommand()'
 *
 * 	@locks: Session *
 * 	@unlocks Session *
 * 	@worker: ufsrv
 */
int
HandleInterBroadcastForUser (MessageQueueMsgPayload *mqp_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	int 										rescode					=	0;

	ShareListContextData	context_data			=	{0};//convenient type. command maynot be sharelist related
	UFSRVResult 			result								=	{0};
	CommandHeader 		*command_header_ptr		=	mqm_ptr->user->header;

	_PrepareForInterBroadcastHandling (mqm_ptr, &context_data, &result, command_header_ptr->command);

	if (_RESULT_TYPE_ERROR(&result))	goto return_error_nonlocal_user;

	//
	//SESSION LOCKED,  SESSION LOADED WITH ACCESS CONTEXT FROM UFSRVWORKER
	//SESSION TARGET IS NOT LOCKED
	//

	switch (command_header_ptr->command)
	{
		case USER_COMMAND__COMMAND_TYPES__PREFERENCE:
			_HandleInterBroadcastUserPrefs ((ClientContextData *)&context_data, mqm_ptr, &result, call_flags);
			break;

		case USER_COMMAND__COMMAND_TYPES__FENCE_PREFERENCE:
			_HandleInterBroadcastFenceUserPrefs ((ClientContextData *)&context_data, mqm_ptr, &result, call_flags);
			break;

		default:
			syslog(LOG_ERR, "%s {pid:'%lu', o:'%p', cid_localuser:'%lu', command:'%d'}: ERROR: UNKNOWN USER COMMAND ", __func__, pthread_self(), context_data.sesn_ptr, SESSION_ID(context_data.sesn_ptr), command_header_ptr->command);
			break;
	}

	return_success:
	if (IS_PRESENT(context_data.sesn_ptr)) {
		SESSION_WHEN_SERVICED(context_data.sesn_ptr) = time(NULL);
		SessionUnLoadEphemeralMode(context_data.sesn_ptr);
		if (!context_data.lock_already_owned_sesn)	SessionUnLockCtx (THREAD_CONTEXT_PTR, context_data.sesn_ptr, __func__);
	}

	return rescode;

	return_error_nonlocal_user:
	rescode=-1;
	goto return_final;

	return_error_unknown_command:
	rescode=-1;

	return_final:
	return rescode;

}

static UFSRVResult *
_HandleInterBroadcastUserPrefs (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	ShareListContextData *ctx_ptr				=	(ShareListContextData *)context_ptr;

	//TODO: this needs to be placed in  loop in case we have more than one pref. curent we only support one
	switch (mqm_ptr->user->prefs[0]->pref_id)
	{
    case USER_PREFS__ROAMING_MODE:
    case USER_PREFS__RM_WANDERER:
    case USER_PREFS__RM_JOURNALER:
    case USER_PREFS__RM_CONQUERER:
      return(_HandleInterBroadcastUserPrefsDefaultBooleans(context_ptr, mqm_ptr, res_ptr, call_flags));

		case	USER_PREFS__NICKNAME:
			return (_HandleInterBroadcastUserPrefsNickname(context_ptr, mqm_ptr, res_ptr, call_flags));

		case 	USER_PREFS__USERAVATAR:
			return (_HandleInterBroadcastUserPrefsAvatar(context_ptr, mqm_ptr, res_ptr, call_flags));

		case 	USER_PREFS__PROFILE:
      ctx_ptr->shlist_ptr = SESSION_USERPREF_SHLIST_PROFILE_PTR(ctx_ptr->sesn_ptr);
			return (_HandleInterBroadcastShareListProfile(context_ptr, mqm_ptr, res_ptr, call_flags));

		case 	USER_PREFS__NETSTATE:
      ctx_ptr->shlist_ptr = SESSION_USERPREF_SHLIST_NETSTATE_PTR(ctx_ptr->sesn_ptr);
			return (_HandleInterBroadcastForShareList(context_ptr, mqm_ptr, res_ptr, call_flags));

    case 	USER_PREFS__READ_RECEIPT:
      ctx_ptr->shlist_ptr = SESSION_USERPREF_SHLIST_READ_RECEIPT_PTR(ctx_ptr->sesn_ptr);
      return (_HandleInterBroadcastForShareList(context_ptr, mqm_ptr, res_ptr, call_flags));

    case 	USER_PREFS__ACTIVITY_STATE:
      ctx_ptr->shlist_ptr = SESSION_USERPREF_SHLIST_ACTIVITY_STATE_PTR(ctx_ptr->sesn_ptr);
      return (_HandleInterBroadcastForShareList(context_ptr, mqm_ptr, res_ptr, call_flags));

		case 	USER_PREFS__LOCATION:
      ctx_ptr->shlist_ptr = SESSION_USERPREF_SHLIST_LOCATION_PTR(ctx_ptr->sesn_ptr);
      return (_HandleInterBroadcastForShareList(context_ptr, mqm_ptr, res_ptr, call_flags));

		case 	USER_PREFS__CONTACTS:
      ctx_ptr->shlist_ptr = SESSION_USERPREF_SHLIST_CONTACTS_PTR(ctx_ptr->sesn_ptr);
      return (_HandleInterBroadcastForShareList(context_ptr, mqm_ptr, res_ptr, call_flags));

    case 	USER_PREFS__BLOCKING:
      ctx_ptr->shlist_ptr = SESSION_USERPREF_SHLIST_BLOCKED_PTR(ctx_ptr->sesn_ptr);
      return (_HandleInterBroadcastForShareList(context_ptr, mqm_ptr, res_ptr, call_flags));

		default:
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', prefid:'%d'}: ERROR: UNKNOWN PEREFERENCE TYPE", __func__, pthread_self(), ctx_ptr->sesn_ptr, SESSION_ID(ctx_ptr->sesn_ptr), mqm_ptr->user->prefs[0]->pref_id);
	}

	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_FENCE_MEMBERSHIP);
}

UFSRVResult *
InterBroadcastUserMessageUserPrefsBoolean(Session *sesn_ptr, ClientContextData *context_ptr, UfsrvEvent *event_ptr, enum _CommandArgs command_arg)
{
  UserPreferenceDescriptor 		*pref_ptr	=	(UserPreferenceDescriptor *)context_ptr;

  _GENERATE_ENVELOPE_INITIALISATION_FENCE_USERPREF();

  _PrepareInterBroadcastMessageForUser (&envelope_broadcast, sesn_ptr,  event_ptr, command_arg);

  header.command										=	USER_COMMAND__COMMAND_TYPES__PREFERENCE;

  //actual delta TODO: currently assume boolean
  fence_userpref_record.pref_id						=	pref_ptr->pref_id;
  fence_userpref_record.values_int				=	pref_ptr->value.pref_value_bool;
  fence_userpref_record.has_values_int		=	1;

  return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg, UFSRV_USER));

}

static UFSRVResult *
_HandleInterBroadcastUserPrefsDefaultBooleans (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
  ShareListContextData 			*ctx_ptr		=	(ShareListContextData *)context_ptr;
  UserPreferenceDescriptor 	pref				=	{0};

  const UserPreferenceDescriptor *prefdef_ptr=GetPrefDescriptorById (mqm_ptr->user->prefs[0]->pref_id);
  if (IS_EMPTY(prefdef_ptr)) goto return_error;

  //prefill with data
  pref=*prefdef_ptr;
  pref.value.pref_value_bool = mqm_ptr->user->fence_prefs[0]->values_int;

  if (IS_PRESENT(prefdef_ptr->pref_validate))	(*prefdef_ptr->pref_validate)(ctx_ptr->sesn_ptr, &pref);

  (*pref.pref_ops->pref_set_local)(ctx_ptr->sesn_ptr, &pref);

  if (mqm_ptr->user->header->has_eid) SESSION_EID(ctx_ptr->sesn_ptr)=mqm_ptr->user->header->eid;

  _RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_FENCE_MEMBERSHIP);

  return_error:
  _RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_INCONSISTENT_STATE);
}

static UFSRVResult *
_HandleInterBroadcastUserPrefsNickname (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	ShareListContextData *ctx_ptr				=	(ShareListContextData *)context_ptr;
	UserPreferenceDescriptor 	pref		=	{0};
	GetUserPreferenceNickname (ctx_ptr->sesn_ptr, PREF_NICKNAME, PREFSTORE_MEM, &pref);
	pref.value.pref_value_str = mqm_ptr->user->prefs[0]->values_str;
//
//	SetUserPreferenceNickname(ctx_ptr->sesn_ptr, &pref, PREFSTORE_MEM, NULL);
//
//  if (mqm_ptr->user->header->has_eid) SESSION_EID(ctx_ptr->sesn_ptr)=mqm_ptr->user->header->eid;

	(*pref.pref_ops->pref_set_local)(ctx_ptr->sesn_ptr, &pref);

	if (mqm_ptr->user->header->has_eid) SESSION_EID(ctx_ptr->sesn_ptr)=mqm_ptr->user->header->eid;

	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_FENCE_MEMBERSHIP);
}

UFSRVResult *
InterBroadcastUserNicknameMessage(Session *sesn_ptr, ClientContextData *context_ptr, UfsrvEvent *event_ptr, enum _CommandArgs command_arg)
{
	_GENERATE_ENVELOPE_INITIALISATION();

	char *nickname_new	=	(char *)context_ptr;

	_PrepareInterBroadcastMessageForUser (&envelope_broadcast, sesn_ptr, event_ptr, command_arg);

	header.command										=	USER_COMMAND__COMMAND_TYPES__PREFERENCE;

	//actual delta
	userpref_record.pref_id						=	USER_PREFS__NICKNAME;
	userpref_record.values_str				=	nickname_new;//by reference. DONT LOSE SCOPE

	return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg, UFSRV_USER));

}

static UFSRVResult *
_HandleInterBroadcastUserPrefsAvatar (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	ShareListContextData *ctx_ptr				=	(ShareListContextData *)context_ptr;
	UserPreferenceDescriptor 	pref		=	{0};

	GetUserPreferenceAvatar (ctx_ptr->sesn_ptr, PREF_AVATAR, PREFSTORE_MEM, &pref);
	pref.value.pref_value_str = mqm_ptr->user->prefs[0]->values_str;

	SetUserPreferenceString(ctx_ptr->sesn_ptr, &pref, PREFSTORE_MEM, NULL);

  if (mqm_ptr->user->header->has_eid) SESSION_EID(ctx_ptr->sesn_ptr)=mqm_ptr->user->header->eid;

	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_FENCE_MEMBERSHIP);
}

UFSRVResult *
InterBroadcastUserAvatarMessage(Session *sesn_ptr, ClientContextData *context_ptr, UfsrvEvent *event_ptr, enum _CommandArgs command_arg)
{
	_GENERATE_ENVELOPE_INITIALISATION();

	char *avatar_new	=	(char *)context_ptr;

	_PrepareInterBroadcastMessageForUser (&envelope_broadcast, sesn_ptr,  event_ptr, command_arg);

	header.command										=	USER_COMMAND__COMMAND_TYPES__PREFERENCE;

	//actual delta
	userpref_record.pref_id						=	USER_PREFS__USERAVATAR;
	userpref_record.values_str				=	avatar_new;//by reference. DONT LOSE SCOPE

	return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg, UFSRV_USER));

}

//TODO: this should be re-implemented so as to avoid referencing received USerCommand from sender. See BroadcastInterUserMessageFenceUserPrefs()
UFSRVResult *
InterBroadcastUserShareListMessage(Session *sesn_ptr, ClientContextData *context_ptr, UfsrvEvent *event_ptr, enum _CommandArgs command_arg) {
	ShareListContextData 	*shlist_ctx_ptr =	(ShareListContextData *)context_ptr;
	UserCommand 					*usercommand		=	shlist_ctx_ptr->data_msg_received->ufsrvcommand->usercommand;

	_GENERATE_ENVELOPE_INITIALISATION_SHARELIST(usercommand);
	usercommand->header->when_client 	= usercommand->header->when;usercommand->header->has_when_client=1; //retain client's orig sent time
	usercommand->header->when 				= GetTimeNowInMillis(); 		usercommand->header->has_when=1;
	if (IS_PRESENT(event_ptr)) {
		usercommand->header->when_eid		=	event_ptr->when; 					usercommand->header->has_when_eid=1;
		usercommand->header->eid				=	event_ptr->eid; 					usercommand->header->has_eid=1;
	}

	_PrepareInterBroadcastMessageForUser (&envelope_broadcast, sesn_ptr,  event_ptr, command_arg);

	return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg, UFSRV_USER));

}

static UFSRVResult *
_HandleInterBroadcastShareListProfile (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	ShareListContextData 			*ctx_ptr						=	(ShareListContextData *)context_ptr;
	UserPreferenceDescriptor 	pref								=	{0};
	UserCommand 							*user_command_ptr		=	mqm_ptr->user;
	UserPreference 						*user_command_prefs =	user_command_ptr->prefs[0];

	if (user_command_prefs->vaues_blob.len != CONFIG_USER_PROFILEKEY_MAX_SIZE || IS_EMPTY(user_command_prefs->vaues_blob.data)) {
			_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_USERCMD_MISSING_PARAM);
		}

		//this is not foolproof as the first byte could be legit '\0': use memcmp instead
		if (SESSION_USER_PROFILE_KEY(ctx_ptr->sesn_ptr)[0] == '\0')	{
			redisReply *redis_ptr;
			memcpy (SESSION_USER_PROFILE_KEY(ctx_ptr->sesn_ptr), user_command_prefs->vaues_blob.data, CONFIG_USER_PROFILEKEY_MAX_SIZE);
		}

	switch (user_command_ptr->header->args)
	{
    case COMMAND_ARGS__DELETED: //user removed
      RemoveUserFromShareList(ctx_ptr->sesn_ptr, SESSION_USERPREF_SHLIST_PROFILE_PTR(ctx_ptr->sesn_ptr),
                              ctx_ptr->instance_sesn_ptr_target, SESSION_CALLFLAGS_EMPTY);
      if (mqm_ptr->user->header->has_eid) SESSION_EID(ctx_ptr->sesn_ptr) = mqm_ptr->user->header->eid;
      break;

    case COMMAND_ARGS__ADDED:
      AddUserToShareList(ctx_ptr->sesn_ptr, SESSION_USERPREF_SHLIST_PROFILE_PTR(ctx_ptr->sesn_ptr),
                         ctx_ptr->instance_sesn_ptr_target, SESSION_CALLFLAGS_EMPTY);
      if (mqm_ptr->user->header->has_eid) SESSION_EID(ctx_ptr->sesn_ptr) = mqm_ptr->user->header->eid;
      break;

    default:
      _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}

	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_FENCE_MEMBERSHIP)
}

/*
 * @brief: Generic handler for ShareList updates. ShareList type must be set in context data
 */
static UFSRVResult *
_HandleInterBroadcastForShareList(ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	ShareListContextData 			*ctx_ptr						=	(ShareListContextData *)context_ptr;
	UserCommand 							*user_command_ptr		=	mqm_ptr->user;
	UserPreference 						*user_command_prefs =	user_command_ptr->prefs[0];

	switch (user_command_ptr->header->args)
	{
		case COMMAND_ARGS__DELETED:
			RemoveUserFromShareList(ctx_ptr->sesn_ptr, ctx_ptr->shlist_ptr, ctx_ptr->instance_sesn_ptr_target, SESSION_CALLFLAGS_EMPTY);
			if (mqm_ptr->user->header->has_eid) SESSION_EID(ctx_ptr->sesn_ptr) = mqm_ptr->user->header->eid;
			break;

		case COMMAND_ARGS__ADDED:
			AddUserToShareList(ctx_ptr->sesn_ptr, ctx_ptr->shlist_ptr, ctx_ptr->instance_sesn_ptr_target, SESSION_CALLFLAGS_EMPTY);
			if (mqm_ptr->user->header->has_eid) SESSION_EID(ctx_ptr->sesn_ptr) = mqm_ptr->user->header->eid;
			break;

		default:
		_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}

	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_FENCE_MEMBERSHIP)
}

//FenceUserPrefs

/**
 * 	@locked f_ptr:
 * 	@locked sesn_ptr:
 */
static UFSRVResult *
_HandleInterBroadcastFenceUserPrefs (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	ShareListContextData *ctx_ptr				=	(ShareListContextData *)context_ptr;

	//TODO: this needs to be placed in  loop in case we have more than one pref. curent we only support one
	switch (mqm_ptr->user->prefs[0]->pref_id)
	{
		case	FENCE_USER_PREFS__PROFILE_SHARING:
		case 	FENCE_USER_PREFS__STICKY_GEOGROUP:
		case 	FENCE_USER_PREFS__IGNORING:
			return (_HandleInterBroadcastFenceUserPrefsDefaultBooleans(context_ptr, mqm_ptr, res_ptr, call_flags));

		default:
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', prefid:'%d'}: ERROR: UNKNOWN PEREFERENCE TYPE", __func__, pthread_self(), ctx_ptr->sesn_ptr, SESSION_ID(ctx_ptr->sesn_ptr), mqm_ptr->user->prefs[0]->pref_id);
	}

	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_FENCE_MEMBERSHIP);
}

static UFSRVResult *
_HandleInterBroadcastFenceUserPrefsDefaultBooleans (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	ShareListContextData 			*ctx_ptr		=	(ShareListContextData *)context_ptr;
	UserPreferenceDescriptor 	pref				=	{0};

	GetFenceUserPreferenceDescriptorById (mqm_ptr->user->fence_prefs[0]->pref_id, &pref);
	pref.value.pref_value_bool = mqm_ptr->user->fence_prefs[0]->values_int;
	(*pref.pref_ops->pref_set_local)(&(PairedSessionFenceState){ctx_ptr->fstate_ptr, ctx_ptr->sesn_ptr}, &pref);

  if (mqm_ptr->user->header->has_eid) SESSION_EID(ctx_ptr->sesn_ptr)=mqm_ptr->user->header->eid;

	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_FENCE_MEMBERSHIP);
}

//replaced by _HandleInterBroadcastFenceUserPrefsDefaultBooleans
//static UFSRVResult *
//_HandleInterBroadcastFenceUserPrefsProfileSharing (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
//{
//	ShareListContextData 			*ctx_ptr		=	(ShareListContextData *)context_ptr;
//	UserPreferenceDescriptor 	pref				=	{0};
//
//	GetFenceUserPreferenceDescriptorById (PREF_PROFILE_SHARING, &pref);
//	pref.value.pref_value_bool = mqm_ptr->user->fence_prefs[0]->values_int;
//	(*pref.pref_ops)->pref_set_local(&(PairedSessionFenceState){ctx_ptr->sesn_ptr, ctx_ptr->fstate_ptr}, &pref);
//
//	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_FENCE_MEMBERSHIP);
//}
//
////TODO: IMPLEMENT
//static UFSRVResult *
//_HandleInterBroadcastFenceUserPrefsStickyGroups (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
//{
//	ShareListContextData *ctx_ptr				=	(ShareListContextData *)context_ptr;
//	UserPreferenceDescriptor 	pref		=	{0};
//
////	GetUserPreferenceAvatar (ctx_ptr->sesn_ptr, PREF_AVATAR, PREFSTORE_MEM, &pref);
////	pref.value.pref_value_str = mqm_ptr->user->prefs[0]->values_str;
////
////	SetUserPreferenceString(ctx_ptr->sesn_ptr, &pref, PREFSTORE_MEM, NULL);
//
//	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_FENCE_MEMBERSHIP);
//}
//
////TODO: IMPLEMENT
//static UFSRVResult *
//_HandleInterBroadcastFenceUserPrefsIgnoring (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
//{
//	ShareListContextData *ctx_ptr				=	(ShareListContextData *)context_ptr;
//	UserPreferenceDescriptor 	pref		=	{0};
//
////	GetUserPreferenceAvatar (ctx_ptr->sesn_ptr, PREF_AVATAR, PREFSTORE_MEM, &pref);
////	pref.value.pref_value_str = mqm_ptr->user->prefs[0]->values_str;
////
////	SetUserPreferenceString(ctx_ptr->sesn_ptr, &pref, PREFSTORE_MEM, NULL);
//
//	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_FENCE_MEMBERSHIP);
//}
//

UFSRVResult *
InterBroadcastUserMessageFenceUserPrefs(Session *sesn_ptr, ClientContextData *context_ptr, UfsrvEvent *event_ptr, enum _CommandArgs command_arg)
{
	PairedFencePrefCollections 	*collections_ptr=(PairedFencePrefCollections *)context_ptr;
	UserPreferenceDescriptor 		*pref_ptr	=	(UserPreferenceDescriptor *)collections_ptr->collection_prefs->collection[0];
	FenceStateDescriptor 				*fstate_ptr	=	(FenceStateDescriptor *)collections_ptr->collection_fences->collection[0];

	_GENERATE_ENVELOPE_INITIALISATION_FENCE_USERPREF();

	_PrepareInterBroadcastMessageForUser (&envelope_broadcast, sesn_ptr,  event_ptr, command_arg);

	header.command										=	USER_COMMAND__COMMAND_TYPES__FENCE_PREFERENCE;

	//actual delta TODO: currently assume boolean
	fence_userpref_record.pref_id						=	pref_ptr->pref_id;
	fence_userpref_record.values_int				=	pref_ptr->value.pref_value_bool;
	fence_userpref_record.has_values_int		=	1;

	fence_record.fid									=	FENCE_ID(FENCESTATE_FENCE(fstate_ptr));

	return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg, UFSRV_USER));

}

//

/**
 * 	@locks sesn_ptr:
 */
static inline UFSRVResult *
_PrepareForInterBroadcastHandling (MessageQueueMessage *mqm_ptr, ShareListContextData *ctx_ptr, UFSRVResult *res_ptr, int command)
{
	bool lock_already_owned	=	false;
	Session 		*sesn_ptr_localuser,
	            *sesn_ptr_target;
  InstanceHolderForSession *instance_sesn_ptr_localuser;

	if (IS_PRESENT((instance_sesn_ptr_localuser = LocallyLocateSessionById(mqm_ptr->user->header->cid)))) {
	  sesn_ptr_localuser = SessionOffInstanceHolder(instance_sesn_ptr_localuser);

		SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_localuser, _LOCK_TRY_FLAG_FALSE, __func__);
		if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR)) {
			_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOGIC_CANTLOCK)
		}
		lock_already_owned = (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_THIS_THREAD));

		SESSION_WHEN_SERVICE_STARTED(sesn_ptr_localuser) = time(NULL);
		SessionLoadEphemeralMode(sesn_ptr_localuser);
		ctx_ptr->sesn_ptr                 = sesn_ptr_localuser;
		ctx_ptr->lock_already_owned_sesn  = lock_already_owned;
//		ctx_ptr->flag_session_local=true; //do we need this?

		//TODO: CURRENTLY ONLY HANDLING SINGLE USER
		if (IS_PRESENT(mqm_ptr->user->target_list) && (mqm_ptr->user->n_target_list > 0)) {
		  InstanceHolderForSession *instance_sesn_ptr_target;
			if (IS_PRESENT((instance_sesn_ptr_target = LocallyLocateSessionById(UfsrvUidGetSequenceId((const UfsrvUid *)mqm_ptr->user->target_list[0]->ufsrvuid.data))))) {
				ctx_ptr->sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr_localuser);
			}
			else	goto exit_unlock_session;
		}

		InstanceHolderForFenceStateDescriptor *instance_fstate_ptr;
		if (IS_PRESENT(mqm_ptr->user->fences) && mqm_ptr->user->n_fences>0) {
			instance_fstate_ptr = IsUserMemberOfFenceById(&SESSION_FENCE_LIST(ctx_ptr->sesn_ptr), mqm_ptr->user->fences[0]->fid, false);
			if (IS_EMPTY(instance_fstate_ptr))	goto exit_unlock_session;

			ctx_ptr->fstate_ptr	=	FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
		}

		exit_success:
		_RETURN_RESULT_RES(res_ptr, ctx_ptr, RESULT_TYPE_SUCCESS, RESCODE_USER_SESN_LOCAL)
	}

	exit_unlock_session:
	SESSION_WHEN_SERVICED(sesn_ptr_localuser) = time(NULL);
	if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_localuser, __func__);
	goto exit_error;

	exit_error:
		_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_USER_SESN_LOCAL)

}

///// END INTER	\\\\


/////// INTRA	\\\\\


static inline int _VetrifyUserCommandForIntra	(MessageQueueMessage *mqm_ptr, bool flag_free_unpacked);

/**
 * 	@brief: Main controller for handling INTRA broadcasts for UserComands.
 */
int
HandleIntraBroadcastForUser (MessageQueueMsgPayload *mqp_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	int 			rc					=	0;
	long long timer_start	=	GetTimeNowInMicros(),
						timer_end;

	if ((rc=_VetrifyUserCommandForIntra(mqm_ptr, false))<0)	goto return_final;

	unsigned long userid = UfsrvUidGetSequenceId((const UfsrvUid *)(mqm_ptr->ufsrvuid.data));

	InstanceHolderForSession  *instance_sesn_ptr_carrier	=	InstantiateCarrierSession (NULL, WORKERTYPE_UFSRVWORKER, SESSION_CALLFLAGS_EMPTY);
	if (IS_EMPTY(instance_sesn_ptr_carrier))	{
	  rc = -4;
	  goto return_final;
	}

	unsigned long sesn_call_flags				=	(	CALL_FLAG_LOCK_SESSION|CALL_FLAG_LOCK_SESSION_BLOCKING|
																					CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY| CALL_FLAG_HASH_USERNAME_LOCALLY|
																					CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION|CALL_FLAG_REMOTE_SESSION);
	bool lock_already_owned = false;
	Session *sesn_ptr_carrier = SessionOffInstanceHolder(instance_sesn_ptr_carrier);

	GetSessionForThisUserByUserId (sesn_ptr_carrier, userid, &lock_already_owned,    sesn_call_flags);
	InstanceHolderForSession *instance_sesn_ptr_local_user = (InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr_carrier);

	if (unlikely(IS_EMPTY(instance_sesn_ptr_local_user)))	goto return_error_unknown_uname;

	//>>> sesn_ptr_local_user IS NOW LOCKED
  Session	*sesn_ptr_local_user = SessionOffInstanceHolder(instance_sesn_ptr_local_user);

	SESSION_WHEN_SERVICE_STARTED(sesn_ptr_local_user) = time(NULL);

#ifdef __UF_TESTING
	UserCommand 				*ucmd_ptr	= mqm_ptr->wire_data->ufsrvcommand->usercommand;
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', nprefs:'%lu',  userid:'%lu'}: FULLY CONSTRUCTED USER COMMAND.", __func__, pthread_self(),sesn_ptr_local_user, SESSION_ID(sesn_ptr_local_user),  ucmd_ptr->n_prefs, userid);
#endif

	SessionLoadEphemeralMode(sesn_ptr_local_user);
	//>>>>>>>>><<<<<<<<<<
	CommandCallbackControllerUserCommand (instance_sesn_ptr_local_user, NULL, mqm_ptr->wire_data, mqp_ptr);
	//>>>>>>>>><<<<<<<<<<

	SESSION_WHEN_SERVICED(sesn_ptr_local_user) = time(NULL);
	SessionUnLoadEphemeralMode(sesn_ptr_local_user);
	if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_local_user, __func__);

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
	statsd_timing(pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_instrumentation_backend_key), "delegator.ufsrv.job.command.user.elapsed_time", (timer_end-timer_start));
	return rc;

}

/**
 * 	@brief: Verify the fitness of the UserCommand message in the context of on INTRA broadcast
 */
inline static int
_VetrifyUserCommandForIntra	(MessageQueueMessage *mqm_ptr, bool flag_free_unpacked)
{
	int rc=1;

	if (unlikely(IS_EMPTY((mqm_ptr->wire_data->ufsrvcommand->usercommand))))				goto return_error_usercommand_missing;
	if (unlikely(IS_EMPTY(mqm_ptr->wire_data->ufsrvcommand->usercommand->header)))	goto return_error_commandheader_missing;
	if (mqm_ptr->wire_data->ufsrvcommand->usercommand->header->command==USER_COMMAND__COMMAND_TYPES__PREFERENCE)
	{
		if (unlikely((mqm_ptr->wire_data->ufsrvcommand->usercommand->n_prefs<1) ||
								 IS_EMPTY(mqm_ptr->wire_data->ufsrvcommand->usercommand->prefs)))				goto return_error_missing_prefs_definition;
	}

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

	return_error_usercommand_missing:
	syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: COULD NOT FIND USER COMMAND IN UNPACKED MESAGEQUEUE", __func__, pthread_self());
	rc=-4;
	goto return_free;

	return_error_missing_prefs_definition:
	syslog(LOG_DEBUG, "%s (pid:'%lu): ERROR: USER COMMAND DID NOT INCLUDE VALID PREFS DEFINITION", __func__, pthread_self());
	rc=-6;
	goto	return_free;

	return_free://exit_proto:
	if (flag_free_unpacked)	message_queue_message__free_unpacked(mqm_ptr, NULL);

	return_final:
	return rc;

}

///////////////////
