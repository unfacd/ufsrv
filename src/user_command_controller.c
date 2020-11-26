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
#include <ufsrv_core/user/user_profile.h>
#include <misc.h>
#include <fence.h>
#include <ufsrv_core/fence/fence_utils.h>
#include <ufsrv_core/fence/fence_state.h>
#include <ufsrv_core/user/users_protobuf.h>
#include <share_list.h>
#include <ufsrvcmd_user_callbacks.h>
#include <user_broadcast.h>
#include <ufsrv_core/location/location.h>
#include <command_controllers.h>
#include <ufsrvuid.h>

extern ufsrv							*const masterptr;
extern __thread ThreadContext ufsrv_thread_context;

struct MarshalMessageEnvelopeForUser {
	UfsrvCommandWire		*ufsrv_command_wire;
	Envelope						*envelope;
	UserCommand 				*user_command;
	CommandHeader 			*header;
	UserPreference			*userpref_record;
	UserPreference 			**userpref_records;
	FenceUserPreference	*fence_userpref_record;
	FenceUserPreference **fence_userpref_records;
	FenceRecord					*fence_record;
	FenceRecord					**fence_records;
	UserRecord          *user_record;
	UserRecord          **user_records;
};
typedef struct MarshalMessageEnvelopeForUser MarshalMessageEnvelopeForUser;

typedef struct UserCommandExecutorContext {
	InstanceContextForSession  *ctx_ptr_originator;
	Envelope  *envelope;
	WebSocketMessage *wsm_ptr_received;
} UserCommandExecutorContext;

#define _GENERATE_USER_COMMAND_ENVELOPE_INITIALISATION() \
	UfsrvCommandWire								ufsrv_command_wire	= UFSRV_COMMAND_WIRE__INIT;	\
	Envelope												command_envelope		=	ENVELOPE__INIT;	\
	UserCommand 										user_command				=	USER_COMMAND__INIT;	\
	CommandHeader 									header							=	COMMAND_HEADER__INIT;	\
	\
	UserPreference									userpref_record			=	USER_PREFERENCE__INIT;	\
	UserPreference 									*userpref_records[1];	\
	\
	MarshalMessageEnvelopeForUser	envelope_marshal = {	\
			.ufsrv_command_wire	=	&ufsrv_command_wire,	\
			.envelope						=	&command_envelope,	\
			.user_command				=	&user_command,	\
			.header							=	&header,	\
			.userpref_record		=	&userpref_record,	\
			.userpref_records		=	userpref_records,	\
			.fence_userpref_record		=	NULL,	\
			.fence_userpref_records		=	NULL,	\
			.fence_record				=	NULL, \
			.fence_records			=	NULL,	\
      .user_record        = NULL, \
      .user_records       = NULL \
	}

#define _GENERATE_USER_COMMAND_ENVELOPE_INITIALISATION_FENCE_USERPREF() \
	UfsrvCommandWire								ufsrv_command_wire	= UFSRV_COMMAND_WIRE__INIT;	\
	Envelope												command_envelope		=	ENVELOPE__INIT;	\
	UserCommand 										user_command				=	USER_COMMAND__INIT;	\
	CommandHeader 									header							=	COMMAND_HEADER__INIT;	\
	\
	FenceUserPreference		fence_userpref_record			    =	FENCE_USER_PREFERENCE__INIT;	\
	FenceUserPreference 	*fence_userpref_records[1];	\
	FenceRecord						fence_record			            =	FENCE_RECORD__INIT;	\
	FenceRecord 					*fence_records[1];	\
	\
	MarshalMessageEnvelopeForUser	envelope_marshal = {	\
			.ufsrv_command_wire	=	&ufsrv_command_wire,	\
			.envelope						=	&command_envelope,	\
			.user_command				=	&user_command,	\
			.header							=	&header,	\
			.userpref_record		=	NULL,	\
			.userpref_records		=	NULL,	\
			.fence_userpref_record		=	&fence_userpref_record,	\
			.fence_userpref_records		=	fence_userpref_records,	\
			.fence_record				=	&fence_record, \
			.fence_records			=	fence_records,	\
      .user_record        = NULL, \
      .user_records       = NULL \
	}

#define _GENERATE_USER_COMMAND_ENVELOPE_INITIALISATION_END_SESSION() \
	UfsrvCommandWire								ufsrv_command_wire	= UFSRV_COMMAND_WIRE__INIT;	\
	Envelope												command_envelope		=	ENVELOPE__INIT;	\
	UserCommand 										user_command				=	USER_COMMAND__INIT;	\
	CommandHeader 									header							=	COMMAND_HEADER__INIT;	\
	\
	UserRecord		user_record			    =	USER_RECORD__INIT;	\
	UserRecord 	*user_records[1];	\
	\
	MarshalMessageEnvelopeForUser	envelope_marshal = {	\
			.ufsrv_command_wire	=	&ufsrv_command_wire,	\
			.envelope						=	&command_envelope,	\
			.user_command				=	&user_command,	\
			.header							=	&header,	\
			.userpref_record		=	NULL,	\
			.userpref_records		=	NULL,	\
			.fence_userpref_record		=	NULL,	\
			.fence_userpref_records		=	NULL,	\
			.fence_record				=	NULL, \
			.fence_records			=	NULL,	\
      .user_record        = &user_record, \
      .user_records       = user_records \
	}

inline static void _PrepareMarshalMessageForUser(MarshalMessageEnvelopeForUser *envelope_ptr, Session *sesn_ptr, Fence *f_ptr, UfsrvEvent *event_ptr, DataMessage *data_msg_ptr_orig, enum _UserCommand__CommandTypes command_type, enum _CommandArgs command_arg);
static UFSRVResult *_HandleUserCommandError (InstanceContextForSession *, ClientContextData *, WebSocketMessage *, DataMessage *, int rescode, int command_type);
static void	_BuildErrorHeaderForUserCommand (CommandHeader *header_ptr, CommandHeader *header_pyr_incoming, int errcode, int command_type);
inline static UFSRVResult *_MarshalCommandToUser	(InstanceContextForSession *ctx_ptr, InstanceContextForSession *ctx_ptr_target, WebSocketMessage *,Envelope *command_envelope_ptr, unsigned req_cmd_idx);
inline static UFSRVResult *_CommandControllerPreferences (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
inline static UFSRVResult *_CommandControllerAllPreferences (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received);
inline static UFSRVResult *_CommandControllerUserResetFences (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received);
inline static UFSRVResult *_CommandControllerUserPrefsSyncAll (Session *sesn_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received);

inline static UFSRVResult *_CommandControllerEndSession (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received);

inline static UFSRVResult *_CommandControllerFenceUserPreferences (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received);
inline static UFSRVResult *_CommandControllerFenceUserAllPreferences (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received);
inline static UFSRVResult *_CommandControllerUserFencePrefsSyncAll (InstanceHolderForSession *, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received);
inline static UFSRVResult *_CommandControllerFenceUserPrefStickyGeogroup (InstanceHolderForSession *, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received);
inline static UFSRVResult *_CommandControllerFenceUserProfileSharing (InstanceContextForSession *, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received);
inline static UFSRVResult *_CommandControllerFenceUserIgnoring (InstanceContextForSession *, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received);

inline static void
_PrepareMarshalMessageForUser(MarshalMessageEnvelopeForUser *envelope_ptr, Session *sesn_ptr, Fence *f_ptr, UfsrvEvent *event_ptr, DataMessage *data_msg_ptr_orig,
                              enum _UserCommand__CommandTypes command_type, enum _CommandArgs command_arg) {
	envelope_ptr->envelope->ufsrvcommand								=	envelope_ptr->ufsrv_command_wire;

	envelope_ptr->envelope->ufsrvcommand->usercommand		=	envelope_ptr->user_command;
	envelope_ptr->envelope->ufsrvcommand->ufsrvtype			=	UFSRV_COMMAND_WIRE__UFSRV_TYPE__UFSRV_USER;
	envelope_ptr->envelope->ufsrvcommand->header				=	envelope_ptr->header;

	envelope_ptr->user_command->header									=	envelope_ptr->header;

	if (IS_PRESENT(envelope_ptr->userpref_records)) {
		envelope_ptr->user_command->prefs										=	envelope_ptr->userpref_records;
		envelope_ptr->user_command->prefs[0]								=	envelope_ptr->userpref_record;
		envelope_ptr->user_command->n_prefs									=	1;
	}

  if (IS_PRESENT(envelope_ptr->user_records)) {
    envelope_ptr->user_command->target_list										=	envelope_ptr->user_records;
    envelope_ptr->user_command->target_list[0]								=	envelope_ptr->user_record;
    envelope_ptr->user_command->n_target_list									=	1;
  }

	envelope_ptr->envelope->sourceufsrvuid		=	"0";
	envelope_ptr->envelope->timestamp					=	GetTimeNowInMillis(); envelope_ptr->envelope->has_timestamp=1;

	envelope_ptr->header->when								=	envelope_ptr->envelope->timestamp; 	envelope_ptr->header->has_when=1;
	envelope_ptr->header->cid									=	SESSION_ID(sesn_ptr); 							envelope_ptr->header->has_cid=1;
	envelope_ptr->header->command							=	command_type;
	envelope_ptr->header->args								=	command_arg;												envelope_ptr->header->has_args=1;

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

	if (IS_PRESENT(event_ptr)) {
		envelope_ptr->header->when_eid					=	event_ptr->when; 					envelope_ptr->header->has_when_eid=1;
		envelope_ptr->header->eid								=	event_ptr->eid; 					envelope_ptr->header->has_eid=1;
	}

	envelope_ptr->header->when								=	envelope_ptr->envelope->timestamp; 					envelope_ptr->header->has_when=1;

	if (IS_PRESENT(data_msg_ptr_orig)) {
		envelope_ptr->header->when_client				=	data_msg_ptr_orig->ufsrvcommand->usercommand->header->when;
		envelope_ptr->header->has_when_client		=	1;
		envelope_ptr->header->args_client				=	PROTO_USERCOMMAND_HEADER_ARGS(data_msg_ptr_orig);
		envelope_ptr->header->has_args_client		=	1;
	}

}

/**
 * 	@brief: This is invoked in the context of INTRA wire data message arriving via the msgqueue bus. The message is in raw wire format (proto).
 * 	The session may or may not be connected to this ufsrv.
 *
 *	@param sesn_ptr_local_user: The user who sent this message, for whom a local Session has been found. This Session may be concurrently
 *	operated on by a Worker thread (in which case the lock on it will fail. However, in the context of this routine,
 *	it is operated on by a Ufsrv Worker Thread
 *
 * 	@param data_msg_ptr: The raw DataMessage protobuf as provided by the sending user. This message will have been previously verified
 * 	by the caller, being bearer of structurally valid  data
 *
 *	@locked sesn_ptr_local_user: must be locked by the caller
 * 	@locks: NONE directly, but downstream will, eg Fence
 * 	@unlocks NONE:
 */
UFSRVResult *
CommandCallbackControllerUserCommand (InstanceHolderForSession *instance_sesn_ptr_local_user, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr)
{
	CommandHeader *command_header = data_msg_ptr->ufsrvcommand->usercommand->header;
	Session *sesn_ptr_local_user = SessionOffInstanceHolder(instance_sesn_ptr_local_user);

	if (unlikely(IS_EMPTY(command_header)))	_RETURN_RESULT_SESN(sesn_ptr_local_user, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

	switch (command_header->command)
	{

	case USER_COMMAND__COMMAND_TYPES__PREFERENCE:
		_CommandControllerPreferences (instance_sesn_ptr_local_user, NULL, data_msg_ptr);
		break;

	case USER_COMMAND__COMMAND_TYPES__PREFERENCES:
		_CommandControllerAllPreferences (instance_sesn_ptr_local_user, NULL, data_msg_ptr);
		break;

	case USER_COMMAND__COMMAND_TYPES__FENCE_PREFERENCE:
		_CommandControllerFenceUserPreferences (instance_sesn_ptr_local_user, NULL, data_msg_ptr);
		break;

	case USER_COMMAND__COMMAND_TYPES__FENCE_PREFERENCES:
		_CommandControllerFenceUserAllPreferences (instance_sesn_ptr_local_user, NULL, data_msg_ptr);
		break;

	case USER_COMMAND__COMMAND_TYPES__RESET:
		_CommandControllerUserResetFences (&(InstanceContextForSession){instance_sesn_ptr_local_user, sesn_ptr_local_user}, NULL, data_msg_ptr);
			break;

	case USER_COMMAND__COMMAND_TYPES__END_SESSION:
		_CommandControllerEndSession (&(InstanceContextForSession){instance_sesn_ptr_local_user, sesn_ptr_local_user}, NULL, data_msg_ptr);
			break;

	default:
		syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', o:'%p', command:'%d'}: RECEIVED UKNOWN USER COMMAND", __func__, pthread_self(), &ufsrv_thread_context, sesn_ptr_local_user, command_header->command);
	}

	_RETURN_RESULT_SESN(sesn_ptr_local_user, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

//// PREFS \\\\
///
static UFSRVResult *_MarshalIntegerTypeUserPref (InstanceContextForSession *ctx_ptr, ClientContextData *ctx_data_ptr, DataMessage *data_msg_ptr_received, WebSocketMessage *wsm_ptr_received, UfsrvEvent *fence_event_ptr);
static UFSRVResult *_MarshalStringTypeUserPref (InstanceContextForSession *ctx_ptr, ClientContextData *ctx_data_ptr, DataMessage *data_msg_ptr_received, WebSocketMessage *wsm_ptr_received, UfsrvEvent *fence_event_ptr);

inline static UFSRVResult *_CommandControllerUserPrefGroupRoaming(InstanceContextForSession *, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received);
inline static UFSRVResult *_CommandControllerUserPrefNickname(InstanceContextForSession *, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received);
inline static UFSRVResult *_MarshalUserNicknameUpdate(InstanceContextForSession *, ClientContextData *ctx_ptr, WebSocketMessage *, DataMessage *data_msg_ptr_received, unsigned long call_flags, UfsrvEvent *event_ptr);
static UFSRVResult *_MarshalUserNicknameUpdateToUser(UserCommandExecutorContext *ctx_ptr, ClientContextData  *);

inline static UFSRVResult *_CommandControllerUserPrefAvatar (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received);
inline static UFSRVResult *_MarshalAvatarUpdate(InstanceContextForSession *ctx_ptr, ClientContextData *ctx_data_ptr, WebSocketMessage *, DataMessage *data_msg_ptr_recieved, unsigned long call_flags, UfsrvEvent *event_ptr);
static UFSRVResult *_MarshalAvatarUpdateToUser(UserCommandExecutorContext *ctx_ptr, ClientContextData *);

inline static UFSRVResult *_CommandControllerUserPrefProfile (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received);
inline static UFSRVResult *_CommandControllerUserPrefNetstate (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received);
inline static UFSRVResult *_CommandControllerUserPrefReadReceipt (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received);
inline static UFSRVResult *_CommandControllerUserPrefContacts (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received);
inline static UFSRVResult *_CommandControllerUserPrefBlocked (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received);
inline static UFSRVResult *_CommandControllerUserPrefUnsolicitedContactAction (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received);

inline static UFSRVResult *
_CommandControllerFenceUserAllPreferences (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	int command_arg = data_msg_ptr_received->ufsrvcommand->usercommand->header->args;
	switch (command_arg)
	{
		case COMMAND_ARGS__SYNCED:
			return (_CommandControllerUserFencePrefsSyncAll(instance_sesn_ptr, wsm_ptr_received, data_msg_ptr_received));

		default:
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', args:'%d'}: ERROR: UNKNOWN COMMAND ARGS TYPE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), command_arg);

	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

inline static UFSRVResult *
_CommandControllerUserFencePrefsSyncAll (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received)
{

	_RETURN_RESULT_SESN(SessionOffInstanceHolder(instance_sesn_ptr), NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

inline static UFSRVResult *
_CommandControllerFenceUserPreferences (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	if (unlikely(data_msg_ptr_received->ufsrvcommand->usercommand->n_fence_prefs <= 0)) {
		syslog(LOG_ERR, "%s {pid:'%lu', o:'%p'}: ERROR: PREFEREN COMMAND MISSING PREFERENCE DEFINITION", __func__, pthread_self(), sesn_ptr);
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}

	FenceUserPreference *user_command_prefs = data_msg_ptr_received->ufsrvcommand->usercommand->fence_prefs[0];
	switch (user_command_prefs->pref_id)
		{
			case	FENCE_USER_PREFS__STICKY_GEOGROUP:
				return (_CommandControllerFenceUserPrefStickyGeogroup(instance_sesn_ptr, wsm_ptr_received, data_msg_ptr_received));

			case 	FENCE_USER_PREFS__PROFILE_SHARING:
				return (_CommandControllerFenceUserProfileSharing(&(InstanceContextForSession){instance_sesn_ptr, sesn_ptr}, wsm_ptr_received, data_msg_ptr_received));

			case 	FENCE_USER_PREFS__IGNORING:
				return (_CommandControllerFenceUserIgnoring(&(InstanceContextForSession){instance_sesn_ptr, sesn_ptr}, wsm_ptr_received, data_msg_ptr_received));

			default:
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', prefid:'%d'}: ERROR: UNKNOWN FENCE USER PREFERENCE TYPE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), user_command_prefs->pref_id);

		}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

//todo: port from ufsrvapi based call
inline static UFSRVResult *
_CommandControllerFenceUserPrefStickyGeogroup (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received)
{
	UserPreference *user_command_prefs=data_msg_ptr_received->ufsrvcommand->usercommand->prefs[0];
//	if (!IS_STR_LOADED(user_command_prefs->values_str))
//	{
//		if (data_msg_ptr_received->ufsrvcommand->usercommand->header->args!=COMMAND_ARGS__DELETED)
//		{
//			_HandleUserCommandError (sesn_ptr, NULL, wsm_ptr_received, data_msg_ptr_received, RESCODE_USERCMD_MISSING_PARAM, data_msg_ptr_received->ufsrvcommand->usercommand->header->command);
//			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_USERCMD_MISSING_PARAM);
//		}
//	}
//
//	UFSRVResult *res_ptr=IsUserAllowedToChangeNickname (sesn_ptr, user_command_prefs->values_str, 1, NULL);//1 for store if valid
//	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))
//	{
//		exit_success:
//		_MarshalUserNicknameUpdate (sesn_ptr, NULL, data_msg_ptr_received, 0, NULL);
//
//		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);
//	}
//	else
//		_HandleUserCommandError (sesn_ptr, NULL, wsm_ptr_received, data_msg_ptr_received, SESSION_RESULT_CODE(sesn_ptr), USER_COMMAND__COMMAND_TYPES__PREFERENCE);
//
//
	_RETURN_RESULT_SESN(SessionOffInstanceHolder(instance_sesn_ptr), NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

inline static UFSRVResult *
_CommandControllerFenceUserProfileSharing (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received)
{
	FenceUserPreference *user_command_prefs = data_msg_ptr_received->ufsrvcommand->usercommand->fence_prefs[0];

	Session *sesn_ptr = SessionOffInstanceHolder(ctx_ptr->instance_sesn_ptr);

  UfsrvEvent event = {.event_type=MSGCMD_SESSION};
	IsUserAllowedToChangeFenceUserPrefProfileSharing(ctx_ptr, user_command_prefs, data_msg_ptr_received, &event, (CallbackCommandMarshaller)MarshalFenceUserPrefProfileSharing);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
		return SESSION_RESULT_PTR(sesn_ptr);
	} else {
    _HandleUserCommandError(ctx_ptr, NULL, wsm_ptr_received, data_msg_ptr_received, SESSION_RESULT_CODE(sesn_ptr), USER_COMMAND__COMMAND_TYPES__PREFERENCE);
  }

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

inline static UFSRVResult *
_CommandControllerFenceUserIgnoring (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received)
{
	FenceUserPreference *user_command_prefs = data_msg_ptr_received->ufsrvcommand->usercommand->fence_prefs[0];
//
//	UFSRVResult *res_ptr=IsUserAllowedToChangeFenceUserPrefProfileSharing (sesn_ptr, user_command_prefs, data_msg_ptr_received->ufsrvcommand->usercommand, SESSION_CALLFLAGS_EMPTY);
//	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))
//	{
//		exit_success:
//		_MarshalUserNicknameUpdate (sesn_ptr, NULL, data_msg_ptr_received, 0, NULL);
//
//		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);
//	}
//	else
//		_HandleUserCommandError (sesn_ptr, NULL, wsm_ptr_received, data_msg_ptr_received, SESSION_RESULT_CODE(sesn_ptr), USER_COMMAND__COMMAND_TYPES__PREFERENCE);


	_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);

}

/**
 * @brief Standard Fence user profile command update. This function expects data context to be fully loaded, including FenceStateDescriptor.
 * This function will propogate the update to all fence members.
 * @param sesn_ptr Session which invoked the command
 * @param ctx_ptr
 * @param data_msg_ptr_recieved
 * @param event_ptr
 * @return
 */
UFSRVResult *
MarshalFenceUserPrefProfileSharing(InstanceContextForSession *ctx_ptr, ClientContextData *ctx_data_ptr, DataMessage *data_msg_ptr_received, WebSocketMessage *wsm_ptr_received, UfsrvEvent *event_ptr)
{
  Session *sesn_ptr = ctx_ptr->sesn_ptr;

	_GENERATE_USER_COMMAND_ENVELOPE_INITIALISATION_FENCE_USERPREF();
	_PrepareMarshalMessageForUser(&envelope_marshal, sesn_ptr, ctx_data_ptr, event_ptr, data_msg_ptr_received, USER_COMMAND__COMMAND_TYPES__FENCE_PREFERENCE, COMMAND_ARGS__ACCEPTED);

	UserCommand *user_command_ptr = ((ShareListContextData *)ctx_data_ptr)->data_msg_received->ufsrvcommand->usercommand;

	fence_userpref_record.pref_id					=	user_command_ptr->fence_prefs[0]->pref_id;
	fence_userpref_record.values_int			=	user_command_ptr->fence_prefs[0]->values_int;
	fence_userpref_record.has_values_int	=	user_command_ptr->fence_prefs[0]->has_values_int;

	user_command.fences							      =	user_command_ptr->fences;

	_MarshalCommandToUser(ctx_ptr, NULL, wsm_ptr_received, &command_envelope,  uGETKEYS_V1_IDX);//TODO: temporary command idx uGETKEYS_V1_IDX

  return MarshalUserPrefProfileForFence(ctx_ptr, ctx_data_ptr, wsm_ptr_received, data_msg_ptr_received, event_ptr);

}

//=-------------------------------------------------------------=

/**
 * 	@brief: The main controller for handling user user commandgroup avatar update.
 * 	A pre check on user's ability to edit should have been done prior to invoking this function
 *
 * 	param sesn_ptr: the user session for which the command is executed
 * 	@locked sesn_ptr: by caller
 * 	@locks RW Fence *: by downstream function
 * 	@unlocks: Fence *:
 */
inline static UFSRVResult *
_CommandControllerPreferences (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	if (unlikely(data_msg_ptr_received->ufsrvcommand->usercommand->n_prefs <= 0)) {
		syslog(LOG_ERR, "%s {pid:'%lu', th_ctx:'%p', o:'%p'}: ERROR: PREFEREN COMMAND MISSING PREFERENCE DEFINITION", __func__, pthread_self(), &ufsrv_thread_context, sesn_ptr);
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}

	InstanceContextForSession instance_ctx = {instance_sesn_ptr, sesn_ptr};

	UserPreference *user_command_prefs = data_msg_ptr_received->ufsrvcommand->usercommand->prefs[0];
	switch (user_command_prefs->pref_id)
  {
    case USER_PREFS__ROAMING_MODE:
    case USER_PREFS__RM_CONQUERER:
    case USER_PREFS__RM_JOURNALER:
    case USER_PREFS__RM_WANDERER:
      return (_CommandControllerUserPrefGroupRoaming(&instance_ctx, wsm_ptr_received, data_msg_ptr_received));

    case	USER_PREFS__NICKNAME:
      return (_CommandControllerUserPrefNickname (&instance_ctx, wsm_ptr_received, data_msg_ptr_received));

    case 	USER_PREFS__USERAVATAR:
      return (_CommandControllerUserPrefAvatar (&instance_ctx, wsm_ptr_received, data_msg_ptr_received));

    case USER_PREFS__PROFILE:
      return (_CommandControllerUserPrefProfile (&instance_ctx, wsm_ptr_received, data_msg_ptr_received));

    case USER_PREFS__LOCATION:

    case USER_PREFS__NETSTATE:
      return (_CommandControllerUserPrefNetstate (&instance_ctx, wsm_ptr_received, data_msg_ptr_received));

    case USER_PREFS__READ_RECEIPT:
      return (_CommandControllerUserPrefReadReceipt (&instance_ctx, wsm_ptr_received, data_msg_ptr_received));

    case USER_PREFS__BLOCKING:
      return (_CommandControllerUserPrefBlocked (&instance_ctx, wsm_ptr_received, data_msg_ptr_received));

    case USER_PREFS__CONTACTS:
      return (_CommandControllerUserPrefContacts (&instance_ctx, wsm_ptr_received, data_msg_ptr_received));

    case USER_PREFS__UNSOLICITED_CONTACT:
      return (_CommandControllerUserPrefUnsolicitedContactAction (&instance_ctx, wsm_ptr_received, data_msg_ptr_received));

    case USER_PREFS__ACTIVITY_STATE:
    case USER_PREFS__FRIENDS:

      //TODO: Add more types below...

    default:
      syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', pref_id:'%d'}: ERROR: UNKNOWN PREFERENCE TYPE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), user_command_prefs->pref_id);
  }

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

inline static UFSRVResult *
_CommandControllerAllPreferences (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	int command_arg = data_msg_ptr_received->ufsrvcommand->usercommand->header->args;
	switch (command_arg)
	{
		case COMMAND_ARGS__SYNCED:
			return (_CommandControllerUserPrefsSyncAll(sesn_ptr, wsm_ptr_received, data_msg_ptr_received));

		default:
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', args:'%d'}: ERROR: UNKNOWN COMMAND ARGS TYPE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), command_arg);

	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);

}

inline static UFSRVResult *
_CommandControllerUserPrefsSyncAll (Session *sesn_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received)
{

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);

}

inline static UFSRVResult *
_CommandControllerUserPrefGroupRoaming (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received)
{
  UserPreference *user_command_prefs = data_msg_ptr_received->ufsrvcommand->usercommand->prefs[0];

  Session *sesn_ptr = ctx_ptr->sesn_ptr;

  UfsrvEvent event = {.event_type=MSGCMD_SESSION};
  IsUserAllowedToChangeUserPrefGroupRoaming (ctx_ptr, user_command_prefs, wsm_ptr_received, data_msg_ptr_received, &event, SESSION_CALLFLAGS_EMPTY);
  if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
  } else {
    _HandleUserCommandError (ctx_ptr, NULL, wsm_ptr_received, data_msg_ptr_received, SESSION_RESULT_CODE(sesn_ptr), USER_COMMAND__COMMAND_TYPES__PREFERENCE);
  }

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

UFSRVResult *
MarshalUserPrefGroupRoaming (InstanceContextForSession *ctx_ptr, ClientContextData *ctx_data_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received, unsigned long call_flags, UfsrvEvent *fence_event_ptr)
{
  _GENERATE_USER_COMMAND_ENVELOPE_INITIALISATION();
  _PrepareMarshalMessageForUser (&envelope_marshal, ctx_ptr->sesn_ptr, ctx_data_ptr, fence_event_ptr, data_msg_ptr_received, USER_COMMAND__COMMAND_TYPES__PREFERENCE, COMMAND_ARGS__ACCEPTED);

  UserCommand *user_command_ptr = ((ShareListContextData *)ctx_data_ptr)->data_msg_received->ufsrvcommand->usercommand;

  //TODO: not sure is this necessary, especially sharelist, which can be huge
  userpref_record.pref_id					=	user_command_ptr->prefs[0]->pref_id;
  userpref_record.values_int		  =	user_command_ptr->prefs[0]->values_int;
  userpref_record.has_values_int	=	1;

  _MarshalCommandToUser(ctx_ptr, NULL, wsm_ptr_received, &command_envelope,  uGETKEYS_V1_IDX);//TODO: temporary command idx uGETKEYS_V1_IDX

  _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

//NICKNAME

inline static UFSRVResult *
_CommandControllerUserPrefNickname (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received)
{
	UserPreference *user_command_prefs = PROTO_USERCOMMAND(data_msg_ptr_received)->prefs[0];

	Session *sesn_ptr = ctx_ptr->sesn_ptr;

	if (!IS_STR_LOADED(user_command_prefs->values_str)) {
		if (PROTO_USERCOMMAND_HEADER_ARGS(data_msg_ptr_received) != COMMAND_ARGS__DELETED) {
			_HandleUserCommandError(ctx_ptr, NULL, wsm_ptr_received, data_msg_ptr_received, RESCODE_USERCMD_MISSING_PARAM, PROTO_USERCOMMAND_HEADER_COMMAND(data_msg_ptr_received));
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_USERCMD_MISSING_PARAM)
		}
	}

  UfsrvEvent event = {.event_type=MSGCMD_SESSION};
	IsUserAllowedToChangeNickname (ctx_ptr, user_command_prefs->values_str, CALL_FLAG_BROADCAST_SESSION_EVENT, &event);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
		_MarshalUserNicknameUpdate(ctx_ptr, NULL, wsm_ptr_received, data_msg_ptr_received, 0, &event);
	} else {
		_HandleUserCommandError(ctx_ptr, NULL, wsm_ptr_received, data_msg_ptr_received, SESSION_RESULT_CODE(sesn_ptr), USER_COMMAND__COMMAND_TYPES__PREFERENCE);
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

inline static UFSRVResult *
_MarshalUserNicknameUpdate(InstanceContextForSession *ctx_ptr, ClientContextData *ctx_data_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received, unsigned long call_flags, UfsrvEvent *event_ptr)
{
	_GENERATE_USER_COMMAND_ENVELOPE_INITIALISATION();
	_PrepareMarshalMessageForUser (&envelope_marshal, ctx_ptr->sesn_ptr, ctx_data_ptr, event_ptr, data_msg_ptr_received, USER_COMMAND__COMMAND_TYPES__PREFERENCE, COMMAND_ARGS__ACCEPTED);

	userpref_record.pref_id			=	USER_PREFS__NICKNAME;
	userpref_record.values_str	=	SESSION_USERNICKNAME(ctx_ptr->sesn_ptr);
	_MarshalCommandToUser(ctx_ptr, NULL, wsm_ptr_received, &command_envelope,  uGETKEYS_V1_IDX);//TODO: temporray command idx uGETKEYS_V1_IDX

	//update envelope for other users
	user_command.header->args       =	PROTO_USERCOMMAND_HEADER_ARGS(data_msg_ptr_received);
	user_command.originator         = MakeUserRecordForSelfInProto (ctx_ptr->sesn_ptr, PROTO_USER_RECORD_MINIMAL);
	UserCommandExecutorContext  ctx = {ctx_ptr, &command_envelope };
	InvokeShareListIteratorExecutor(ctx_ptr->sesn_ptr, SESSION_USERPREF_SHLIST_PROFILE_PTR(ctx_ptr->sesn_ptr), (CallbackExecutor)_MarshalUserNicknameUpdateToUser, CLIENT_CTX_DATA(&ctx), true);

	DestructUserInfoInProto (user_command.originator, true/* flag_self_destruct*/);

	_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

/**
 * 	@brief: designed to be called back from the hashtable iterator for each user who is member of originators' fence's list
 * 	@param ctx_data_ptr item held by the hashtable. Passed by the hastable iterator
 * 	@param ctx_ptr Context data packaged by the original caller (which invoked the iterator)
 */
static UFSRVResult *
_MarshalUserNicknameUpdateToUser (UserCommandExecutorContext *ctx_ptr, ClientContextData *ctx_data_ptr)
{
  Session *sesn_ptr_target = SessionOffInstanceHolder((InstanceHolderForSession *)ctx_data_ptr);
	//don't send to self as this user gets ACCEPTRED
	if (memcmp(SESSION_UFSRVUID(sesn_ptr_target), SESSION_UFSRVUID(ctx_ptr->ctx_ptr_originator->sesn_ptr), CONFIG_MAX_UFSRV_ID_SZ) == 0)	goto return_success;

	ctx_ptr->envelope->ufsrvcommand->usercommand->header->cid = SESSION_ID(sesn_ptr_target);
	_MarshalCommandToUser(ctx_ptr->ctx_ptr_originator, &((InstanceContextForSession){(InstanceHolderForSession *)ctx_data_ptr, sesn_ptr_target}),ctx_ptr-> wsm_ptr_received, ctx_ptr->envelope,  uGETKEYS_V1_IDX);//TODO: temporray command idx uGETKEYS_V1_IDX

	return_success:
	_RETURN_RESULT_SESN(ctx_ptr->ctx_ptr_originator->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
}
//

//AVATAR

inline static UFSRVResult *
_CommandControllerUserPrefAvatar (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received)
{
  UserCommand       *userCommand            = PROTO_USERCOMMAND(data_msg_ptr_received);
	UserPreference    *user_command_prefs     = userCommand->prefs[0];
	AttachmentRecord  *attachment_record_ptr  = NULL;

  if (PROTO_USERCOMMAND_HEADER_ARGS(data_msg_ptr_received)!=COMMAND_ARGS__DELETED) {
    if (!IS_STR_LOADED(user_command_prefs->values_str)) {
      _HandleUserCommandError(ctx_ptr, NULL, wsm_ptr_received, data_msg_ptr_received, RESCODE_USERCMD_MISSING_PARAM, PROTO_USERCOMMAND_HEADER_COMMAND(data_msg_ptr_received));
      _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_USERCMD_MISSING_PARAM)
    }

    if (IS_EMPTY(PROTO_USERCOMMAND_ATTACHMENTS(data_msg_ptr_received))) {
      _HandleUserCommandError(ctx_ptr, NULL, wsm_ptr_received, data_msg_ptr_received, RESCODE_USERCMD_MISSING_PARAM, PROTO_USERCOMMAND_HEADER_COMMAND(data_msg_ptr_received));
      _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_USERCMD_MISSING_PARAM)
    }

    attachment_record_ptr = userCommand->attachments[0];
  }

  const char *avatar_id = user_command_prefs->values_str;
  UfsrvEvent event      = {0};
	IsUserAllowedToChangeAvatar(ctx_ptr, avatar_id, attachment_record_ptr, CALLFLAGS_EMPTY, &event);
	if (SESSION_RESULT_TYPE_SUCCESS(ctx_ptr->sesn_ptr)) {
		exit_success:
		_MarshalAvatarUpdate(ctx_ptr, NULL, wsm_ptr_received, data_msg_ptr_received, CALLFLAGS_EMPTY, &event);

		_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
	} else
		_HandleUserCommandError(ctx_ptr, NULL, wsm_ptr_received, data_msg_ptr_received, SESSION_RESULT_CODE(ctx_ptr->sesn_ptr), USER_COMMAND__COMMAND_TYPES__PREFERENCE);

	_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

/**
 * @brief Push Avatar event.
 * @command_arg UPDATED: value of avatar has changed, along with corresponding avatar blob
 * @command_arg DELETED: avatar has been removed
 * @return_arg ACCEPTED: confirmation sent to the originator for both, UPDATED and DELETED
 * @return_arg: UPDATED, DELETED other users
 * @param sesn_ptr
 * @param ctx_ptr
 * @param data_msg_ptr_recieved
 * @param call_flags
 * @param event_ptr
 * @return
 */
inline static UFSRVResult *
_MarshalAvatarUpdate(InstanceContextForSession *ctx_ptr, ClientContextData *ctx_data_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_recieved, unsigned long call_flags, UfsrvEvent *event_ptr)
{
  Session *sesn_ptr = ctx_ptr->sesn_ptr;

	_GENERATE_USER_COMMAND_ENVELOPE_INITIALISATION();
	_PrepareMarshalMessageForUser (&envelope_marshal, sesn_ptr, ctx_data_ptr, event_ptr, data_msg_ptr_recieved, USER_COMMAND__COMMAND_TYPES__PREFERENCE, COMMAND_ARGS__ACCEPTED);

	userpref_record.pref_id			=	USER_PREFS__USERAVATAR;
  userpref_record.values_str = SESSION_USERAVATAR(sesn_ptr);
	if (PROTO_USERCOMMAND_HEADER_ARGS(data_msg_ptr_recieved)!=COMMAND_ARGS__DELETED) {
    user_command.attachments = data_msg_ptr_recieved->ufsrvcommand->usercommand->attachments; //todo: do we need this for the original sender?
    user_command.n_attachments = data_msg_ptr_recieved->ufsrvcommand->usercommand->n_attachments;
  }
	_MarshalCommandToUser(ctx_ptr, NULL, wsm_ptr_received, &command_envelope,  uGETKEYS_V1_IDX);//TODO: temporray command idx uGETKEYS_V1_IDX

	//update envelope for other users
	user_command.header->args =		PROTO_USERCOMMAND_HEADER_ARGS(data_msg_ptr_recieved);
	user_command.originator   = MakeUserRecordForSelfInProto (sesn_ptr, PROTO_USER_RECORD_MINIMAL);
  UserCommandExecutorContext  ctx = {ctx_ptr, &command_envelope, wsm_ptr_received };
  InvokeShareListIteratorExecutor(sesn_ptr, SESSION_USERPREF_SHLIST_PROFILE_PTR(sesn_ptr), (CallbackExecutor)_MarshalAvatarUpdateToUser, CLIENT_CTX_DATA(&ctx), true);

  DestructUserInfoInProto (user_command.originator, true);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

/**
 * 	@brief: designed to be called back from the hashtable iterator for each user who is member of originators' fence's list
 * 	@param ctx_ptr Context data provided by the originating caller (which invoked the iterator)
 * 	@param ctx_data_ptr Data item provided through a serial iteration on the hashmap
 */
static UFSRVResult *
_MarshalAvatarUpdateToUser (UserCommandExecutorContext *ctx_ptr, ClientContextData *ctx_data_ptr)
{
  Session *sesn_ptr_target = SessionOffInstanceHolder((InstanceHolderForSession *)ctx_data_ptr);
  //don't send to self as this user gets ACCEPTRED
  if (memcmp(SESSION_UFSRVUID(sesn_ptr_target), SESSION_UFSRVUID(ctx_ptr->ctx_ptr_originator->sesn_ptr), CONFIG_MAX_UFSRV_ID_SZ) == 0)	goto return_success;

	ctx_ptr->envelope->ufsrvcommand->usercommand->header->cid = SESSION_ID(sesn_ptr_target);
	_MarshalCommandToUser(ctx_ptr->ctx_ptr_originator, &(InstanceContextForSession){(InstanceHolderForSession *)ctx_data_ptr, sesn_ptr_target}, ctx_ptr->wsm_ptr_received, ctx_ptr->envelope,  uGETKEYS_V1_IDX);//TODO: temporray command idx uGETKEYS_V1_IDX

	return_success:
	_RETURN_RESULT_SESN(ctx_ptr->ctx_ptr_originator->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
}

//

//PROFILE
inline static UFSRVResult *
_CommandControllerUserPrefProfile (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received)
{
  Session *sesn_ptr = ctx_ptr->sesn_ptr;

	UserPreference *user_command_prefs = data_msg_ptr_received->ufsrvcommand->usercommand->prefs[0];
	if (IS_EMPTY(user_command_prefs->vaues_blob.data) || user_command_prefs->vaues_blob.len <= 0) {
		if (data_msg_ptr_received->ufsrvcommand->usercommand->header->args != COMMAND_ARGS__DELETED) {
			_HandleUserCommandError (ctx_ptr, NULL, wsm_ptr_received, data_msg_ptr_received, RESCODE_USERCMD_MISSING_PARAM, data_msg_ptr_received->ufsrvcommand->usercommand->header->command);
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_USERCMD_MISSING_PARAM)
		}
	}

  UfsrvEvent event = {0};
  IsUserAllowedToShareProfile(ctx_ptr, wsm_ptr_received, data_msg_ptr_received, &event, 0);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
	} else {
    _HandleUserCommandError(ctx_ptr, NULL, wsm_ptr_received, data_msg_ptr_received, SESSION_RESULT_CODE(sesn_ptr), USER_COMMAND__COMMAND_TYPES__PREFERENCE);
  }

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
}

/**
 * @brief Marshals a profile update event
 * @param sesn_ptr Session for the user who issued the command
 * @param ctx_ptr context specific data bundle
 * @param data_msg_ptr_recieved
 * @param event_ptr pre-allocated event structure to return event generation information into
 * @return
 */
UFSRVResult *
MarshalUserPrefProfile(InstanceContextForSession *ctx_ptr, ClientContextData *ctx_data_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received, UfsrvEvent *event_ptr)
{
  Session *sesn_ptr = ctx_ptr->sesn_ptr;

	_GENERATE_USER_COMMAND_ENVELOPE_INITIALISATION();
	_PrepareMarshalMessageForUser(&envelope_marshal, sesn_ptr, ctx_data_ptr, event_ptr, data_msg_ptr_received, USER_COMMAND__COMMAND_TYPES__PREFERENCE, COMMAND_ARGS__ACCEPTED);

	UserCommand *user_command_ptr = ((ShareListContextData *)ctx_data_ptr)->data_msg_received->ufsrvcommand->usercommand;

	//TODO: not sure is this necessary, especially sharelist, which can be huge
	userpref_record.pref_id					  =	user_command_ptr->prefs[0]->pref_id;
	userpref_record.vaues_blob.data		=	user_command_ptr->prefs[0]->vaues_blob.data;
	userpref_record.vaues_blob.len		=	user_command_ptr->prefs[0]->vaues_blob.len;
	user_command.target_list					=	user_command_ptr->target_list;
	user_command.n_target_list			  =	user_command_ptr->n_target_list;

	_MarshalCommandToUser(ctx_ptr, NULL, wsm_ptr_received, &command_envelope,  uGETKEYS_V1_IDX);//TODO: temporary command idx uGETKEYS_V1_IDX

	//update envelope for other users
	user_command.prefs										=	userpref_records;
	user_command.header->args	            =	user_command_ptr->header->args; user_command.header->has_args = 1;
	user_command.prefs[0]								  =	&userpref_record;
	user_command.n_prefs									=	1;

	user_command.originator		            = MakeUserRecordForSelfInProto(sesn_ptr, PROTO_USER_RECORD_MINIMAL);
	if (user_command.header->args == COMMAND_ARGS__ADDED) {
    if (!IsProfileKeyLoaded(sesn_ptr)) {
      ProfileKeyStore key_store = {0};
      DbBackendGetProfileKey(sesn_ptr, &(SESSION_UFSRVUIDSTORE(sesn_ptr)), KEY_RAW, &key_store);
      if (key_store.raw_sz > 0) {
        memcpy(SESSION_USER_PROFILE_KEY(sesn_ptr), key_store.raw, key_store.raw_sz);
        memset(key_store.raw, 0, CONFIG_USER_PROFILEKEY_MAX_SIZE);
        free(key_store.raw);
      } else {
        syslog(LOG_ERR, "%s {pid:'%lu', o:'%p'}: ERROR: COULD NOT LOAD PROFILE KEY FOR USER", __func__, pthread_self(), ctx_ptr->sesn_ptr);
        _HandleUserCommandError(ctx_ptr, NULL, wsm_ptr_received, data_msg_ptr_received, SESSION_RESULT_CODE(sesn_ptr), USER_COMMAND__COMMAND_TYPES__PREFERENCE);
        DestructUserInfoInProto(user_command.originator, FLAG_SELF_DESTRUCT_TRUE);

        _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
      }
    }
    user_command.profile_key.data = SESSION_USER_PROFILE_KEY(sesn_ptr);
    user_command.profile_key.len  = CONFIG_USER_PROFILEKEY_MAX_SIZE;
    user_command.has_profile_key  = 1;
	} else {
	  //already empty
	}
  InstanceContextForSession instance_ctx = {((ShareListContextData *)ctx_data_ptr)->instance_sesn_ptr_target, SessionOffInstanceHolder(((ShareListContextData *)ctx_data_ptr)->instance_sesn_ptr_target)};
	_MarshalCommandToUser(ctx_ptr, &instance_ctx, wsm_ptr_received, &command_envelope,  uGETKEYS_V1_IDX);//TODO: temporray command idx uGETKEYS_V1_IDX

	DestructUserInfoInProto(user_command.originator, FLAG_SELF_DESTRUCT_TRUE);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

#define _CONSTRUCT_MOCK_DATA_MESSAGE_FOR_USER_PROFILE_SHARING \
  DataMessage data_msg_mock           = DATA_MESSAGE__INIT; \
  UfsrvCommandWire command_wire_mock  = UFSRV_COMMAND_WIRE__INIT; \
  data_msg_mock.ufsrvcommand          = &command_wire_mock; \
  command_wire_mock.usercommand       = &user_command; \
  UserRecord user_record_target       = USER_RECORD__INIT; \
  UserRecord *user_record_ptr_target; \
  UserRecord *user_records_target[1]; \
  user_record_ptr_target  =  &user_record_target; \
  user_records_target[0]  = user_record_ptr_target

/**
 * @brief Marshals a user profile update command to members of a given fence based on the context of user sharing their profile with a fence.
 * Since sharing profile with a fence vs individual users requires slightly different data context, some data adatptation is preformed, so this function
 * cannot be reliably invoked without the prior context of fence share profile command.
 * @param sesn_ptr Session for the user who issued the command
 * @param ctx_ptr ctx_ptr context specific data bundle. FenceStateMember must be provided.
 * @param data_msg_ptr_recieved IMPORTANT this will be the DataMessage for the FenceShare command, not UserProfile share, which in this context is a side effect
 * @param event_ptr
 * @return
 */
UFSRVResult *
MarshalUserPrefProfileForFence  (InstanceContextForSession *ctx_ptr, ClientContextData *ctx_data_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_recieved, UfsrvEvent *event_ptr)
{
  Session *sesn_ptr = ctx_ptr->sesn_ptr;

  if (IS_EMPTY(((ShareListContextData *)ctx_data_ptr)->fstate_ptr)) {
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_MISSING_PARAM)
  }

  FenceStateDescriptor *fstate_ptr =  ((ShareListContextData *)ctx_data_ptr)->fstate_ptr;

  _GENERATE_USER_COMMAND_ENVELOPE_INITIALISATION();
  _PrepareMarshalMessageForUser (&envelope_marshal, sesn_ptr, ctx_data_ptr, event_ptr, data_msg_ptr_recieved, USER_COMMAND__COMMAND_TYPES__PREFERENCE, COMMAND_ARGS__ACCEPTED);

  //this will hold a fence profile share command
  UserCommand *user_command_ptr = ((ShareListContextData *)ctx_data_ptr)->data_msg_received->ufsrvcommand->usercommand;

  userpref_record.pref_id					  =	USER_PREFS__PROFILE;
  //note: we don't set profile key in the pref; instead we just assign it to user record

  unsigned int command_arg_other        = user_command_ptr->header->args==COMMAND_ARGS__SET?COMMAND_ARGS__ADDED:COMMAND_ARGS__DELETED;
  //update envelope for other users
  user_command.prefs										=	userpref_records;//overriden from initialisation performed above
  user_command.prefs[0]								  =	&userpref_record;
  user_command.n_prefs									=	1;
  user_command.header->args	            =	command_arg_other;
  user_command.header->args_client      =	user_command.header->args;
  user_command.header->has_args_client  =	1;
  user_command.header->when             = user_command_ptr->header->when; //overriden

  user_command.originator		            = MakeUserRecordForSelfInProto (sesn_ptr, PROTO_USER_RECORD_MINIMAL);
  if (user_command_ptr->header->args == COMMAND_ARGS__SET) {
    user_command.profile_key.data	  =	(uint8_t *)SESSION_USER_PROFILE_KEY(sesn_ptr);
    user_command.profile_key.len		=	CONFIG_USER_PROFILEKEY_MAX_SIZE;
    user_command.has_profile_key		=	1;
  }

  UserPreferenceDescriptor 	pref			=	{0};
  if (IS_EMPTY(GetUserPreferenceShareList(sesn_ptr, (UserPrefsOffsets) USER_PREFS__PROFILE, PREFSTORE_MEM, &pref))) {
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  //This is necessary, as data_msg_received was for FenceUserPref profile sharing
  _CONSTRUCT_MOCK_DATA_MESSAGE_FOR_USER_PROFILE_SHARING;

  FenceRawSessionList raw_session_list = {0};
  GetRawMemberUsersListForFence (sesn_ptr, FENCESTATE_INSTANCE_HOLDER(fstate_ptr), FENCE_CALLFLAG_LOCK_FENCE|FENCE_CALLFLAG_INCLUDE_REMOTE_SESSIONS, &raw_session_list);//fence returned unlocked

  typedef UFSRVResult *(*ShareListOp)(Session *, ShareList *, InstanceHolderForSession *, unsigned long);
  ShareListOp share_list_op;
  if (user_command.header->args == COMMAND_ARGS__ADDED) share_list_op = AddUserToShareList;
  else                                                  share_list_op = RemoveUserFromShareList;

  size_t i = 0;
  for (; i<raw_session_list.sessions_sz; i++) {
    Session *sesn_ptr_listed = SessionOffInstanceHolder(raw_session_list.sessions[i]);
    if (!(SESSION_ID(sesn_ptr) == SESSION_ID(sesn_ptr_listed))) {
      //raw_session_list.sessions[i] NOT LOCKED
      (*share_list_op)(sesn_ptr, SESSION_USERPREF_SHLIST_PROFILE_PTR(sesn_ptr), raw_session_list.sessions[i], CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND);

      if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
        if (!SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_USER_SHARELIST_PRESENT)) {
          ShareListContextData share_list_ctx = {.sesn_ptr=sesn_ptr, .instance_sesn_ptr_target=raw_session_list.sessions[i],
                                                 .shlist_ptr=SESSION_USERPREF_SHLIST_PROFILE_PTR(sesn_ptr), .pref_descriptor_ptr=&pref,
                                                 .data_msg_received=&data_msg_mock, false, false};

          RegisterUfsrvEvent(sesn_ptr, MSGCMD_SESSION, 0, NULL, event_ptr); //todo: set session event instance type

          if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
            header.eid = event_ptr->eid;

            user_command.header->args	        =	COMMAND_ARGS__ACCEPTED;
            user_command.header->args_client  = command_arg_other;
            header.cid                        = SESSION_ID(sesn_ptr);
            user_command.target_list    = user_records_target;
            user_command.n_target_list  = 1;
            MakeUserRecordFromSessionInProto (sesn_ptr_listed, user_record_ptr_target, true, true);
            _MarshalCommandToUser(ctx_ptr, NULL, wsm_ptr_received, &command_envelope, uFENCE_V1_IDX);

            header.cid                  = SESSION_ID(sesn_ptr_listed);
            user_command.header->args	  =	command_arg_other;
            user_command.target_list    = NULL;
            user_command.n_target_list  = 0;

            InstanceContextForSession instance_ctx = {raw_session_list.sessions[i], sesn_ptr_listed};
            _MarshalCommandToUser(ctx_ptr, &instance_ctx, wsm_ptr_received, &command_envelope, uFENCE_V1_IDX);

            InterBroadcastUserShareListMessage(sesn_ptr, CLIENT_CTX_DATA((&share_list_ctx)), event_ptr, user_command.header->args);
          }
        }
      }
    }
  }

  DestructFenceRawSessionList (&raw_session_list, false);

  DestructUserInfoInProto (user_command.originator, FLAG_SELF_DESTRUCT_TRUE);

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}
//

//NETSTATE
/**
 *  User is requesting to share/unshare their presence information with another user. Doesn't not automatically enable sharing from
 *  the other user to this user. User's sharelist is modified accordingly.
 */
inline static UFSRVResult *
_CommandControllerUserPrefNetstate (InstanceContextForSession *ctx_ptr,  WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received)
{
  UserPreference  *user_command_prefs = data_msg_ptr_received->ufsrvcommand->usercommand->prefs[0];
  Session         *sesn_ptr           = ctx_ptr->sesn_ptr;

  UfsrvEvent event = {0};
  IsUserAllowedToShareNetstate(ctx_ptr, wsm_ptr_received, data_msg_ptr_received, &event, 0);
  if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
    exit_success:
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
  }
  else {
		_HandleUserCommandError(ctx_ptr, NULL, wsm_ptr_received, data_msg_ptr_received, SESSION_RESULT_CODE(sesn_ptr), USER_COMMAND__COMMAND_TYPES__PREFERENCE);
	}

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

UFSRVResult *
MarshalUserPrefNetstate(InstanceContextForSession *ctx_ptr, ClientContextData *ctx_data_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received, unsigned long call_flags, UfsrvEvent *fence_event_ptr)
{
  Session *sesn_ptr = ctx_ptr->sesn_ptr;

  _GENERATE_USER_COMMAND_ENVELOPE_INITIALISATION();
  _PrepareMarshalMessageForUser (&envelope_marshal, sesn_ptr, ctx_data_ptr, fence_event_ptr, data_msg_ptr_received, USER_COMMAND__COMMAND_TYPES__PREFERENCE, COMMAND_ARGS__ACCEPTED);

  UserCommand *user_command_ptr = ((ShareListContextData *)ctx_data_ptr)->data_msg_received->ufsrvcommand->usercommand;

  //TODO: not sure is this necessary, especially sharelist, which can be huge
  userpref_record.pref_id					=	user_command_ptr->prefs[0]->pref_id;
	userpref_record.values_int			=	user_command_ptr->prefs[0]->values_int;
	userpref_record.has_values_int  = 1;
  user_command.target_list					=	user_command_ptr->target_list;
  user_command.n_target_list				=	user_command_ptr->n_target_list;

  _MarshalCommandToUser(ctx_ptr, NULL, wsm_ptr_received, &command_envelope,  uGETKEYS_V1_IDX);//TODO: temporary command idx uGETKEYS_V1_IDX


  //update envelope for other users
	user_command.target_list					=	NULL;
	user_command.n_target_list				=	0;

	user_command.header->cid = 0; user_command.header->has_cid = 0;
	user_command.header->args	=		user_command_ptr->header->args;//retain original command arg
  user_command.originator		= MakeUserRecordForSelfInProto (sesn_ptr, PROTO_USER_RECORD_MINIMAL);
  InstanceContextForSession instance_ctx = {((ShareListContextData *)ctx_data_ptr)->instance_sesn_ptr_target, SessionOffInstanceHolder(((ShareListContextData *)ctx_data_ptr)->instance_sesn_ptr_target)};
  _MarshalCommandToUser(ctx_ptr, &instance_ctx, wsm_ptr_received, &command_envelope,  uGETKEYS_V1_IDX);//TODO: temporray command idx uGETKEYS_V1_IDX

  DestructUserInfoInProto (user_command.originator, true/* flag_self_destruct*/);

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}
//

//READ_RECEIPT
/**
 *  User is requesting to share/unshare their presence information with another user. Doesn't not automatically enable sharing from
 *  the other user to this user. User's sharelist is modified accordingly.
 */
inline static UFSRVResult *
_CommandControllerUserPrefReadReceipt (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received)
{
  UserPreference *user_command_prefs  = data_msg_ptr_received->ufsrvcommand->usercommand->prefs[0];
  Session *sesn_ptr                   = ctx_ptr->sesn_ptr;
  UfsrvEvent event = {0};

  IsUserAllowedToShareReadReceipt(ctx_ptr, data_msg_ptr_received, &event, CALLFLAGS_EMPTY);
  if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
    exit_success:
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
  }
  else {
    _HandleUserCommandError(ctx_ptr, NULL, wsm_ptr_received, data_msg_ptr_received, SESSION_RESULT_CODE(sesn_ptr), USER_COMMAND__COMMAND_TYPES__PREFERENCE);
  }

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

//

//CONTACTS
/**
 *  User is requesting to share/unshare their presence information with another user. Doesn't not automatically enable sharing from
 *  the other user to this user. User's sharelist is modified accordingly.
 */
inline static UFSRVResult *
_CommandControllerUserPrefContacts (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received)
{
  UserPreference *user_command_prefs = data_msg_ptr_received->ufsrvcommand->usercommand->prefs[0];
  Session         *sesn_ptr          = ctx_ptr->sesn_ptr;

  UfsrvEvent event = {0};
  IsUserAllowedToShareContacts(ctx_ptr, data_msg_ptr_received, wsm_ptr_received, &event, MarshalUserPref, CALLFLAGS_EMPTY);
  if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
  } else {
    _HandleUserCommandError(ctx_ptr, NULL, wsm_ptr_received, data_msg_ptr_received, SESSION_RESULT_CODE(sesn_ptr), USER_COMMAND__COMMAND_TYPES__PREFERENCE);
  }

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}
//

//
inline static UFSRVResult *
_CommandControllerUserPrefUnsolicitedContactAction (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received)
{
  UserPreference *user_command_prefs = data_msg_ptr_received->ufsrvcommand->usercommand->prefs[0];
  Session *sesn_ptr = ctx_ptr->sesn_ptr;

  UfsrvEvent event = {0};
  IsUserAllowedToChangeUnsolicitedContactAction(ctx_ptr, user_command_prefs, data_msg_ptr_received, wsm_ptr_received, &event, _MarshalIntegerTypeUserPref, CALLFLAGS_EMPTY);
  if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
  }
  else {
    _HandleUserCommandError(ctx_ptr, NULL, wsm_ptr_received, data_msg_ptr_received, SESSION_RESULT_CODE(sesn_ptr), USER_COMMAND__COMMAND_TYPES__PREFERENCE);
  }

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}
//

static UFSRVResult *
_MarshalIntegerTypeUserPref (InstanceContextForSession *ctx_ptr, ClientContextData *ctx_data_ptr, DataMessage *data_msg_ptr_received, WebSocketMessage *wsm_ptr_received, UfsrvEvent *fence_event_ptr)
{
  Session *sesn_ptr = ctx_ptr->sesn_ptr;

  _GENERATE_USER_COMMAND_ENVELOPE_INITIALISATION();
  _PrepareMarshalMessageForUser (&envelope_marshal, sesn_ptr, ctx_data_ptr, fence_event_ptr, data_msg_ptr_received, USER_COMMAND__COMMAND_TYPES__PREFERENCE, COMMAND_ARGS__ACCEPTED);

  UserCommand *user_command_ptr = ((ShareListContextData *)ctx_data_ptr)->data_msg_received->ufsrvcommand->usercommand;

  userpref_record.pref_id					=	user_command_ptr->prefs[0]->pref_id;
  userpref_record.values_int		  =	user_command_ptr->prefs[0]->values_int;
  userpref_record.has_values_int	=	1;

  _MarshalCommandToUser(ctx_ptr, NULL, wsm_ptr_received, &command_envelope,  uGETKEYS_V1_IDX);//TODO: temporary command idx uGETKEYS_V1_IDX

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

__unused static UFSRVResult *
_MarshalStringTypeUserPref (InstanceContextForSession *ctx_ptr, ClientContextData *ctx_data_ptr, DataMessage *data_msg_ptr_received, WebSocketMessage *wsm_ptr_received, UfsrvEvent *fence_event_ptr)
{
  _GENERATE_USER_COMMAND_ENVELOPE_INITIALISATION();
  _PrepareMarshalMessageForUser (&envelope_marshal, ctx_ptr->sesn_ptr, ctx_data_ptr, fence_event_ptr, data_msg_ptr_received, USER_COMMAND__COMMAND_TYPES__PREFERENCE, COMMAND_ARGS__ACCEPTED);

  UserCommand *user_command_ptr = ((ShareListContextData *)ctx_data_ptr)->data_msg_received->ufsrvcommand->usercommand;

  userpref_record.pref_id					=	user_command_ptr->prefs[0]->pref_id;
  userpref_record.values_str		  =	user_command_ptr->prefs[0]->values_str;

  _MarshalCommandToUser(ctx_ptr, NULL, wsm_ptr_received, &command_envelope,  uGETKEYS_V1_IDX);//TODO: temporary command idx uGETKEYS_V1_IDX

  _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);

}
//

//BLOCKED
/**
 *  User is requesting to share/unshare their presence information with another user. Doesn't not automatically enable sharing from
 *  the other user to this user. User's sharelist is modified accordingly.
 */
inline static UFSRVResult *
_CommandControllerUserPrefBlocked (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received)
{
  __unused UserPreference  *user_command_prefs = data_msg_ptr_received->ufsrvcommand->usercommand->prefs[0];
  Session         *sesn_ptr           = ctx_ptr->sesn_ptr;

  UfsrvEvent event = {0};
  IsUserAllowedToShareBlocked(ctx_ptr, data_msg_ptr_received, wsm_ptr_received, &event, MarshalUserPref, CALLFLAGS_EMPTY);
  if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
    exit_success:
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
  }
  else {
    _HandleUserCommandError(ctx_ptr, NULL, wsm_ptr_received, data_msg_ptr_received, SESSION_RESULT_CODE(sesn_ptr), USER_COMMAND__COMMAND_TYPES__PREFERENCE);
  }

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

//

UFSRVResult *
MarshalUserPref (InstanceContextForSession *ctx_ptr, ClientContextData *ctx_data_ptr, DataMessage *data_msg_ptr_received,  WebSocketMessage *wsm_ptr_received, UfsrvEvent *event_ptr)
{
  Session *sesn_ptr = ctx_ptr->sesn_ptr;

  _GENERATE_USER_COMMAND_ENVELOPE_INITIALISATION();
  _PrepareMarshalMessageForUser (&envelope_marshal, sesn_ptr, ctx_data_ptr, event_ptr, data_msg_ptr_received, USER_COMMAND__COMMAND_TYPES__PREFERENCE, COMMAND_ARGS__ACCEPTED);

  UserCommand *user_command_ptr = ((ShareListContextData *)ctx_data_ptr)->data_msg_received->ufsrvcommand->usercommand;

  //TODO: not sure is this necessary, especially sharelist, which can be huge
  userpref_record.pref_id					=	user_command_ptr->prefs[0]->pref_id;
  userpref_record.values_int			=	user_command_ptr->prefs[0]->values_int;
  userpref_record.has_values_int  = 1;
  user_command.target_list					=	user_command_ptr->target_list;
  user_command.n_target_list				=	user_command_ptr->n_target_list;

  _MarshalCommandToUser(ctx_ptr, NULL, wsm_ptr_received, &command_envelope,  uGETKEYS_V1_IDX);//TODO: temporary command idx uGETKEYS_V1_IDX

  //update envelope for other users
  user_command.target_list					=	NULL;
  user_command.n_target_list				=	0;

  user_command.header->cid = 0; user_command.header->has_cid = 0;
  user_command.header->args	=		user_command_ptr->header->args;//retain original command arg
  user_command.originator		= MakeUserRecordForSelfInProto(sesn_ptr, PROTO_USER_RECORD_MINIMAL);
  InstanceContextForSession instance_ctx = {((ShareListContextData *)ctx_data_ptr)->instance_sesn_ptr_target, SessionOffInstanceHolder(((ShareListContextData *)ctx_data_ptr)->instance_sesn_ptr_target)};
  _MarshalCommandToUser(ctx_ptr, &instance_ctx, wsm_ptr_received, &command_envelope, uGETKEYS_V1_IDX);//TODO: temporray command idx uGETKEYS_V1_IDX

  DestructUserInfoInProto (user_command.originator, FLAG_SELF_DESTRUCT_TRUE);

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

inline static UFSRVResult *
_CommandControllerUserResetFences (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received)
{
  Session *sesn_ptr = SessionOffInstanceHolder(ctx_ptr->instance_sesn_ptr);

	ResetFencesForUser (ctx_ptr->instance_sesn_ptr, MEMBER_FENCES);
	ResetFencesForUser (ctx_ptr->instance_sesn_ptr, INVITED_FENCES);
	//ResetFencesForUser (sesn_ptr, BLOCKED_FENCES);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

//// END PREFS \\\\


//// START END_SESSION \\\\

inline static UFSRVResult *_MarshalEndSession (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr_received, CommandContextData *context_ptr);

inline static UFSRVResult *
_CommandControllerEndSession (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received)
{
  Session *sesn_ptr = ctx_ptr->sesn_ptr;

  UserCommand *user_cmd_ptr = data_msg_ptr_received->ufsrvcommand->usercommand;
  size_t list_sz = user_cmd_ptr->n_target_list;

	if (unlikely(list_sz <= 0)) {
		syslog(LOG_ERR, "%s {pid:'%lu', o:'%p'}: ERROR: MISSING TARGET USER FOR END SESSION", __func__, pthread_self(), sesn_ptr);
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}

	for (size_t i=0; i<list_sz; i++) {
    _MarshalEndSession (ctx_ptr, wsm_ptr_received, data_msg_ptr_received, (CommandContextData *)(user_cmd_ptr->target_list[i]));
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

inline static UFSRVResult *
_MarshalEndSession (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr_received, CommandContextData *ctx_data_ptr)
{
  UserRecord	user_record_originator = {0};
  UserRecord *user_record_ptr = (UserRecord *)ctx_data_ptr; //target user
  FenceRecord **fence_records_ptr = data_msg_ptr_received->ufsrvcommand->usercommand->fences;

  Session *sesn_ptr = ctx_ptr->sesn_ptr;

  _GENERATE_USER_COMMAND_ENVELOPE_INITIALISATION_END_SESSION();
  _PrepareMarshalMessageForUser (&envelope_marshal, sesn_ptr, ctx_data_ptr, NULL, data_msg_ptr_received, USER_COMMAND__COMMAND_TYPES__END_SESSION, COMMAND_ARGS__SET);
  envelope_marshal.user_command->originator =	MakeUserRecordFromSessionInProto (sesn_ptr, &user_record_originator, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF);

  envelope_marshal.user_record		=	MakeUserRecordFromSessionInProto (sesn_ptr, envelope_marshal.user_record, PROTO_USER_RECORD_MINIMAL, 1);

  if (data_msg_ptr_received->ufsrvcommand->usercommand->n_fences > 0 && IS_PRESENT(fence_records_ptr) && IS_PRESENT(fence_records_ptr[0])) {
    envelope_marshal.user_command->fences = fence_records_ptr;
    envelope_marshal.user_command->n_fences = data_msg_ptr_received->ufsrvcommand->usercommand->n_fences;
  }

  unsigned long sesn_call_flags = (CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY|CALL_FLAG_HASH_USERNAME_LOCALLY|
                                 CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION|CALL_FLAG_REMOTE_SESSION);
  GetSessionForThisUserByUserId(sesn_ptr, UfsrvUidGetSequenceId((const UfsrvUid *)user_record_ptr->ufsrvuid.data), NULL, sesn_call_flags);
  if (SESSION_RESULT_TYPE(sesn_ptr) != RESULT_TYPE_SUCCESS) {
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, SESSION_RESULT_CODE(sesn_ptr))
  }

  InstanceHolderForSession *instance_sesn_ptr_target = (InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr);

  UfsrvCommandMarshallingDescriptor ufsrv_descpription = {header.eid, 0, header.when, &EnvelopeMetaData, &command_envelope};
  UfsrvCommandInvokeUserCommand(ctx_ptr,
                                &(InstanceContextForSession) {instance_sesn_ptr_target,
                                                              SessionOffInstanceHolder(instance_sesn_ptr_target)},
                                &((WebSocketMessage) {.type=WEB_SOCKET_MESSAGE__TYPE__REQUEST}), NULL,
                                &ufsrv_descpription, uGETKEYS_V1_IDX);

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}
//// END END_SESSION \\\\

/**
 * 	@brief: Generalised command sending
 */
inline static UFSRVResult *
_MarshalCommandToUser	(InstanceContextForSession *ctx_ptr, InstanceContextForSession *ctx_ptr_target, WebSocketMessage *wsm_ptr_received, Envelope *command_envelope_ptr, unsigned req_cmd_idx)
{
	CommandHeader *command_header_ptr	=	command_envelope_ptr->ufsrvcommand->usercommand->header;

	UfsrvCommandMarshallingDescriptor ufsrv_description = {command_header_ptr->eid, 0, command_header_ptr->when, &EnvelopeMetaData, command_envelope_ptr};

  UfsrvCommandInvokeUserCommand(ctx_ptr, ctx_ptr_target,
          IS_EMPTY(wsm_ptr_received)?(&(WebSocketMessage){.request=NULL, .type=WEB_SOCKET_MESSAGE__TYPE__REQUEST}):wsm_ptr_received,
          NULL, &ufsrv_description, req_cmd_idx);

	_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

/*
 * @param errcode: should reflect a UFSRVResult.rescode type
 * @param command_type: should reflect a protobif command type, or -1 to re use original
 *
 */
__unused static void
_BuildErrorHeaderForUserCommand (CommandHeader *header_ptr, CommandHeader *header_ptr_incoming, int errcode, int command_type)
{
	switch (errcode)
	{
		case RESCODE_USERCMD_MISSING_PARAM:
			header_ptr->args_error	=	USER_COMMAND__ERRORS__MISSING_PARAMETER; 	header_ptr->has_args_error	=	1;
			header_ptr->args				=	COMMAND_ARGS__REJECTED;									header_ptr->has_args				=	1;
			break;

//		case RESCODE_USERCMD_TOOLONG_PARAM:
//			header_ptr->args_error	=	USER_COMMAND__ERRORS__TOO_LONG; 	header_ptr->has_args_error	=	1;
//			header_ptr->args				=	COMMAND_ARGS__REJECTED;									header_ptr->has_args				=	1;
//			break;

		default:
			goto exit_error;
	}

	if (command_type>0)		header_ptr->command			=	command_type;
	else									header_ptr->command			=	header_ptr_incoming->command;//restore original command
	header_ptr->when_client	=	header_ptr_incoming->when;							header_ptr->has_when_client=header_ptr_incoming->has_when_client;
	return;

	exit_error:
	return;

}

/**
 * 	@brief: Marshal an error response message to user. This is invoked in the context of command processing.
 * 	@data_msg_ptr: the original wire command that triggered the error as packaged by user
 * 	@locked f_ptr: f_ptr
 * 	@locked sesn_ptr:
 * 	@unlocks: none
 */
__unused static UFSRVResult *
_HandleUserCommandError (InstanceContextForSession *ctx_ptr, ClientContextData *ctx_data_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, int rescode, int command_type)
{
	Envelope 					command_envelope	= ENVELOPE__INIT;
	CommandHeader 		header						= COMMAND_HEADER__INIT;
	UfsrvCommandWire	ufsrv_command			= UFSRV_COMMAND_WIRE__INIT;
	UserCommand 			user_command			= USER_COMMAND__INIT;

	command_envelope.ufsrvcommand				=	&ufsrv_command;
	ufsrv_command.header								=	&header;
	user_command.header									=	&header;

	ufsrv_command.usercommand						=	&user_command;
	ufsrv_command.ufsrvtype							=	UFSRV_COMMAND_WIRE__UFSRV_TYPE__UFSRV_USER;

	command_envelope.sourceufsrvuid 		=	"0";
	command_envelope.timestamp					=	GetTimeNowInMillis(); command_envelope.has_timestamp=1;

	header.when													=	command_envelope.timestamp; header.has_when		=	1;
	header.cid													=	SESSION_ID(ctx_ptr->sesn_ptr);				header.has_cid		=	1;

	_BuildErrorHeaderForUserCommand (&header, data_msg_ptr->ufsrvcommand->usercommand->header, rescode, command_type);

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', uid:'%lu', cid:'%lu', arg_error:'%d', rescode:'%d'}: Marshaling Error response message...", __func__, pthread_self(), ctx_ptr->sesn_ptr, SESSION_USERID(ctx_ptr->sesn_ptr), SESSION_ID(ctx_ptr->sesn_ptr), header.args_error, rescode);
#endif

	return (_MarshalCommandToUser(ctx_ptr, NULL, wsm_ptr_orig, &command_envelope,  uGETKEYS_V1_IDX));//TODO: temp use of uGETKEYS_V1

}