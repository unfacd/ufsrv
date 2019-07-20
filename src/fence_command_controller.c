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
#include <utils_str.h>
#include <thread_context_type.h>
#include <fence.h>
#include <fence_state.h>
#include <fence_utils.h>
#include <fence_proto.h>
#include <fence_permission.h>
#include <user_backend.h>
#include <users_proto.h>
#include <recycler.h>
#include <protocol_websocket.h>
#include <ufsrvcmd_user_callbacks.h>
#include <ufsrvcmd_callbacks.h>
#include <ufsrvcmd_broadcast.h>
#include <SignalService.pb-c.h>
#include <message_broadcast.h>
#include <location.h>
#include <command_controllers.h>
#include <attachments.h>
#include <ufsrvuid.h>

extern ufsrv							*const masterptr;
extern __thread ThreadContext ufsrv_thread_context;

typedef void (*CallbackRestoreFenceValue)(FenceStateDescriptor *fence_state_ptr, FenceRecord *fence_record_ptr);

inline static UFSRVResult *_CommandControllerFenceJoin (InstanceHolderForSession *, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
inline static UFSRVResult *_CommandControllerFenceStateSync (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
inline static UFSRVResult *_CommandControllerFenceStateSyncSynced (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
inline static UFSRVResult *_CommandControllerFenceName (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
inline static UFSRVResult *_CommandControllerFenceAvatar (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
inline static UFSRVResult *_CommandControllerFenceMaxMembers(InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
inline static UFSRVResult *_CommandControllerFenceJoinMode (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
inline static UFSRVResult *_CommandControllerFenceDeliveryMode (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
inline static UFSRVResult *_CommandControllerFencePrivacyMode (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
inline static UFSRVResult *_CommandControllerFenceLeave (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
inline static UFSRVResult *_CommandControllerFenceInvite (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
inline static UFSRVResult *_CommandControllerFenceInviteAdd (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
inline static UFSRVResult *_CommandControllerFenceInviteSynced (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
inline static UFSRVResult *_CommandControllerFenceMessageExpiry (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
inline static UFSRVResult *_CommandControllerFencePermission (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);

inline static UFSRVResult *_MarshalFenceStateSync(Session *sesn_ptr, Session *sesn_ptr_target, Fence *f_ptr, Envelope *command_envelope_ptr);
static inline UFSRVResult *_MarshalServerRequestForFenceStateSync (Session *sesn_ptr, Fence *f_ptr, DataMessage *data_msg_ptr_received, unsigned long call_flags);
static inline UFSRVResult *_MarshalFenceInvitation(Session *sesn_ptr, Session *sesn_ptr_target, Fence *f_ptr, Envelope *command_envelope_ptr, unsigned long eid);
//static UFSRVResult 				*_MarshalNewFenceInvitation (Session *sesn_ptr, Fence *f_ptr, Envelope *command_envelope_ptr, CollectionDescriptor *invited_eids_collection_ptr, unsigned call_flags);
inline static UFSRVResult *_MarshalFenceInvitationReceipt (Session *sesn_ptr, Fence *f_ptr, DataMessage *data_msg_ptr, CollectionDescriptor *invited_eids_collection_ptr, CollectionDescriptor *rejected_collection_ptr);
inline static UFSRVResult *_MarshalNewFenceJoin (Session *sesn_ptr, UFSRVResult *res_ptr, WebSocketMessage *wsm_ptr_orig, FenceRecord *fence_record_ptr, DataMessage *data_msg_ptr, CollectionDescriptor *invited_eids_collection_ptr);
inline static UFSRVResult *_MarshalNewFenceReJoin (Session *sesn_ptr, UFSRVResult *res_ptr, WebSocketMessage *wsm_ptr_orig, FenceRecord *fence_record_ptr, DataMessage *data_msg_ptr_received);
inline static UFSRVResult *_MarshalFenceNameUpdate (Session *sesn_ptr, Fence *f_ptr, DataMessage *data_msg_ptr, unsigned long call_flags, FenceEvent *fence_event_ptr);
inline static UFSRVResult *_MarshalFenceAvatarUpdate (Session *sesn_ptr, Fence *f_ptr, DataMessage *data_msg_ptr, unsigned long call_flags, FenceEvent *fence_event_ptr);
inline static UFSRVResult *_MarshalFenceMessageExpiryUpdate (Session *sesn_ptr, Fence *f_ptr, DataMessage *data_msg_ptr, unsigned long call_flags, FenceEvent *fence_event_ptr);
inline static UFSRVResult *_MarshalFenceMAxMembersUpdate (Session *sesn_ptr, Fence *f_ptr, DataMessage *data_msg_ptr_received, unsigned long call_flags, FenceEvent *fence_event_ptr);
inline static UFSRVResult *_MarshalFenceDeliveryModeUpdate (Session *sesn_ptr, Fence *f_ptr, DataMessage *data_msg_ptr_received, unsigned long call_flags, FenceEvent *fence_event_ptr);
inline static UFSRVResult *_MarshalCommandToUser	(Session *sesn_ptr, Session *sesn_ptr_target, Fence *f_ptr, Envelope *command_envelope_ptr, unsigned req_cmd_idx);

static UFSRVResult *_HandleFenceCommandError (Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, int rescode, int command_type, CallbackRestoreFenceValue restore_callback);
static void	_BuildErrorHeaderForFenceCommand (FenceCommand *fence_command_ptr, FenceCommand *fence_command_ptr_incoming, int errcode, int command_type);


struct MarshalMessageEnvelopeForFence {
	UfsrvCommandWire		*ufsrv_command_wire;
	Envelope						*envelope;
	FenceCommand 				*fence_command;
	CommandHeader 			*header;
	FenceRecord					*fence_record;
	FenceRecord 				**fence_records;
	UserRecord					*user_record_originator;
};
typedef struct MarshalMessageEnvelopeForFence MarshalMessageEnvelopeForFence;


#define _GENERATE_FENCE_COMMAND_ENVELOPE_INITIALISATION() \
	UfsrvCommandWire								ufsrv_command_wire	= UFSRV_COMMAND_WIRE__INIT;	\
	Envelope												command_envelope		=	ENVELOPE__INIT;	\
	FenceCommand 										fence_command				=	FENCE_COMMAND__INIT;	\
	CommandHeader 									header							=	COMMAND_HEADER__INIT;	\
	\
	FenceRecord											fence_record;	\
	FenceRecord 										*fence_records[1];	\
	UserRecord											_user_record_originator = {{0}};	\
	\
	MarshalMessageEnvelopeForFence	envelope_marshal = {	\
			.ufsrv_command_wire	=	&ufsrv_command_wire,	\
			.envelope						=	&command_envelope,	\
			.fence_command			=	&fence_command,	\
			.header							=	&header,	\
			.fence_record				=	&fence_record,	\
			.fence_records			=	fence_records,	\
			.user_record_originator	=	&_user_record_originator	\
	}

inline static void _PrepareMarshalMessageForFence (MarshalMessageEnvelopeForFence *envelope_ptr, Session *sesn_ptr, Fence *f_ptr, FenceEvent *event_ptr, DataMessage *data_msg_ptr_orig, enum _FenceCommand__CommandTypes, enum _CommandArgs command_arg);

inline static void
_PrepareMarshalMessageForFence (MarshalMessageEnvelopeForFence *envelope_ptr, Session *sesn_ptr, Fence *f_ptr, FenceEvent *event_ptr, DataMessage *data_msg_ptr_orig, enum _FenceCommand__CommandTypes command_type, enum _CommandArgs command_arg)
{
	envelope_ptr->envelope->ufsrvcommand								=	envelope_ptr->ufsrv_command_wire;

	envelope_ptr->envelope->ufsrvcommand->fencecommand	=	envelope_ptr->fence_command;
	envelope_ptr->envelope->ufsrvcommand->ufsrvtype			=	UFSRV_COMMAND_WIRE__UFSRV_TYPE__UFSRV_FENCE;
	envelope_ptr->envelope->ufsrvcommand->header				=	envelope_ptr->header;

	envelope_ptr->fence_command->header									=	envelope_ptr->header;
	envelope_ptr->fence_command->fences									=	envelope_ptr->fence_records;
	envelope_ptr->fence_records[0]											=	envelope_ptr->fence_record;
	envelope_ptr->fence_command->n_fences								=	1;
	MakeFenceRecordInProtoAsIdentifier(sesn_ptr, f_ptr, envelope_ptr->fence_record);

//	envelope_ptr->fence_command->originator		=	MakeUserRecordForSelfInProto (sesn_ptr, PROTO_USER_RECORD_MINIMAL);
	//todo: enable this in place of above
	envelope_ptr->fence_command->originator		=	MakeUserRecordFromSessionInProto (sesn_ptr, envelope_ptr->user_record_originator, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF);
	envelope_ptr->envelope->source						=	"0";
	envelope_ptr->envelope->timestamp					=	GetTimeNowInMillis(); envelope_ptr->envelope->has_timestamp=1;

	envelope_ptr->header->when								=	envelope_ptr->envelope->timestamp; 	envelope_ptr->header->has_when=1;
	envelope_ptr->header->cid									=	SESSION_ID(sesn_ptr); 							envelope_ptr->header->has_cid=1;
	envelope_ptr->header->command							=	command_type;
	envelope_ptr->header->args								=	command_arg;												envelope_ptr->header->has_args=1;
	envelope_ptr->header->args_error					=	FENCE_COMMAND__ERRORS__NONE;				envelope_ptr->header->has_args_error=1;

	if (IS_PRESENT(event_ptr)) {
		envelope_ptr->header->when_eid					=	event_ptr->when; 					envelope_ptr->header->has_when_eid=1;
		envelope_ptr->header->eid								=	event_ptr->eid; 					envelope_ptr->header->has_eid=1;
	} else {
		envelope_ptr->header->eid								=	FENCE_LAST_EID(f_ptr); 					envelope_ptr->header->has_eid=1;
	}

	if (IS_PRESENT(data_msg_ptr_orig)) {
		envelope_ptr->header->when_client				=	data_msg_ptr_orig->ufsrvcommand->fencecommand->header->when;
		envelope_ptr->header->has_when_client		=	data_msg_ptr_orig->ufsrvcommand->fencecommand->header->has_when_client=1;
	}

}

/**
 * 	@brief: This is invoked in the context of wire data message arriving via the msgqueue bus. The message is in raw wire format (proto).
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
CommandCallbackControllerFenceCommand (InstanceHolderForSession *instance_sesn_ptr_local_user, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, MessageQueueMsgPayload *mqp_ptr)
{
	void *command_types []={
					&&FENCE_COMMAND_JOIN,
					&&FENCE_COMMAND_LEAVE,
					&&FENCE_COMMAND_INVITE,
					&&FENCE_COMMAND_BLOCK,
					&&FENCE_COMMAND_FNAME,
					&&FENCE_COMMAND_BANNER,
					&&FENCE_COMMAND_AVATAR,
					&&FENCE_COMMAND_MAXUSERS,
					&&FENCE_COMMAND_TTL,
					&&FENCE_COMMAND_FKEY,
					&&FENCE_COMMAND_JOIN_MODE,
					&&FENCE_COMMAND_TAGS,
					&&FENCE_COMMAND_MAKE,
					&&FENCE_COMMAND_STATE,
					&&FENCE_COMMAND_EXPIRY,
					&&FENCE_COMMAND_MUTE,
					&&FENCE_COMMAND_PERMISSION,
					&&FENCE_COMMAND_NICKNAME,
					&&FENCE_COMMAND_KICK,
					&&FENCE_COMMAND_DESTRUCT,
					&&FENCE_COMMAND_PRIVACY_MODE,
					&&FENCE_COMMAND_DELIVERY_MODE,
          &&FENCE_COMMAND_PERMISSION_LIST_SEMANTICS,
	}; //ALIGN WITH PROTOBUF

	Session *sesn_ptr_local_user = SessionOffInstanceHolder(instance_sesn_ptr_local_user);
	CommandHeader *command_header = data_msg_ptr->ufsrvcommand->fencecommand->header;
	if (unlikely(command_header == NULL))	_RETURN_RESULT_SESN(sesn_ptr_local_user, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

	goto *command_types[command_header->command];

	FENCE_COMMAND_JOIN:
		return (_CommandControllerFenceJoin (instance_sesn_ptr_local_user, NULL, data_msg_ptr));

	FENCE_COMMAND_LEAVE:
		return (_CommandControllerFenceLeave (instance_sesn_ptr_local_user, NULL, data_msg_ptr));

	FENCE_COMMAND_INVITE:
		return (_CommandControllerFenceInvite (instance_sesn_ptr_local_user, NULL, data_msg_ptr));

	FENCE_COMMAND_BLOCK:
		goto return_unknown;

	FENCE_COMMAND_FNAME:
		return (_CommandControllerFenceName (instance_sesn_ptr_local_user, NULL, data_msg_ptr));

	FENCE_COMMAND_BANNER:
		goto return_unknown;

	FENCE_COMMAND_AVATAR:
		return (_CommandControllerFenceAvatar(instance_sesn_ptr_local_user, NULL, data_msg_ptr));

	FENCE_COMMAND_MAXUSERS:
		return (_CommandControllerFenceMaxMembers(instance_sesn_ptr_local_user, NULL, data_msg_ptr));

	FENCE_COMMAND_TTL:
		goto return_unknown;

	FENCE_COMMAND_FKEY:
		goto return_unknown;

	FENCE_COMMAND_JOIN_MODE:
	return (_CommandControllerFenceJoinMode(instance_sesn_ptr_local_user, NULL, data_msg_ptr));

	FENCE_COMMAND_TAGS:
		goto return_unknown;

	FENCE_COMMAND_MAKE:
		goto return_unknown;

	FENCE_COMMAND_STATE:
		return (_CommandControllerFenceStateSync (instance_sesn_ptr_local_user, NULL, data_msg_ptr));

	FENCE_COMMAND_EXPIRY:
		return (_CommandControllerFenceMessageExpiry(instance_sesn_ptr_local_user, NULL, data_msg_ptr));

	FENCE_COMMAND_MUTE:
		goto return_unknown;

	FENCE_COMMAND_PERMISSION:
		return (_CommandControllerFencePermission(instance_sesn_ptr_local_user, NULL, data_msg_ptr));

	FENCE_COMMAND_NICKNAME:
		goto return_unknown;

	FENCE_COMMAND_KICK:
		goto return_unknown;

	FENCE_COMMAND_DESTRUCT:
		goto return_unknown;

	FENCE_COMMAND_PRIVACY_MODE:
		return (_CommandControllerFencePrivacyMode(instance_sesn_ptr_local_user, NULL, data_msg_ptr));

	FENCE_COMMAND_DELIVERY_MODE:
		return (_CommandControllerFenceDeliveryMode(instance_sesn_ptr_local_user, NULL, data_msg_ptr));

  FENCE_COMMAND_PERMISSION_LIST_SEMANTICS:
	//todo: currently this mode is not supported. Can only be set once at fence creation time. send proper error message
  goto return_unknown;

	return_unknown:
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', command:'%d'}: RECEIVED UKNOWN FENCE COMMAND", __func__, pthread_self(), sesn_ptr_local_user, command_header->command);
	SESSION_RETURN_RESULT (sesn_ptr_local_user, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_UKNOWN_TYPE);

}

/// JOIN \\\

/**
 * 	@brief: All join command originating from client-side are passed through this we determine if fence is new or existing.
 * 	This function is designed to work with ephemeral sessions, not io sessions through the main loop.
 *
 *	@param sesn_ptr:	Target session loaded in ephemeral mode
 * 	@locked RW sesn_ptr: must be locked by the caller
 * 	@locks RW f_ptr: issues flags to cause locking
 * 	@unlocks f_ptr: unless RESCODE_PROG_NULL_POINTER was returned as error
 */
inline static UFSRVResult *
_CommandControllerFenceJoin (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr)

{
	bool 							fence_lock_already_owned	= false;
	EnumFenceJoinType join_type					=	JT_USER_INITIATED;
	Fence 						*f_ptr						= NULL;
	FenceCommand			*fcmd_ptr;
	UFSRVResult 			*res_ptr					= NULL;
	FenceRecord 			*fence_record_ptr	= NULL;
	FenceStateDescriptor *fstate_ptr = NULL;

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	fcmd_ptr = data_msg_ptr->ufsrvcommand->fencecommand;

	fence_record_ptr = fcmd_ptr->fences[0];

  //join an existing fence
	if (fence_record_ptr->fid > 0)	{
		res_ptr = IsUserAllowedToJoinFenceById(instance_sesn_ptr, fence_record_ptr->fid, FENCE_CALLFLAG_JOIN|FENCE_CALLFLAG_KEEP_FENCE_LOCKED|FENCE_CALLFLAG_LOCK_FENCE_BLOCKING, &fence_lock_already_owned);

		if (SESSION_RESULT_TYPE_ERROR(sesn_ptr)) {
			if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST)) {
				//no fence lock
				_HandleFenceCommandError (sesn_ptr, NULL, wsm_ptr_orig, data_msg_ptr, RESCODE_FENCE_DOESNT_EXIST, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);
				return SESSION_RESULT_PTR(sesn_ptr);
			}

			//fence invitation only and user is not on it
			if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_INVITATION_LIST)) {
				if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, (Fence *)SESSION_RESULT_USERDATA(sesn_ptr), SESSION_RESULT_PTR(sesn_ptr));
				_HandleFenceCommandError (sesn_ptr, NULL, wsm_ptr_orig, data_msg_ptr, RESCODE_FENCE_INVITATION_LIST, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);
				return SESSION_RESULT_PTR(sesn_ptr);
			}

			//fence's memory store did not contain reference session: instruct user to issue a state sync request
			if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_SESSION_INTEGRITY)) {
			  InstanceHolderForFence *instance_f_ptr_impaired = (InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr);
			  Fence *f_ptr_impaired = FenceOffInstanceHolder(instance_f_ptr_impaired);
				RepairFenceMembershipForUser(instance_sesn_ptr, instance_f_ptr_impaired, ImpairedFenceMembershipFence);
				if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) _MarshalServerRequestForFenceStateSync(sesn_ptr, f_ptr_impaired, data_msg_ptr, CALLFLAGS_EMPTY);

				if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr_impaired, SESSION_RESULT_PTR(sesn_ptr));
				return SESSION_RESULT_PTR(sesn_ptr);
			}

			//session's memory store did not contain reference to fence
			if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_SESSION_FENCE_INTEGRITY)) {
        InstanceHolderForFence *instance_f_ptr_impaired = (InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr);
        Fence *f_ptr_impaired = FenceOffInstanceHolder(instance_f_ptr_impaired);
				RepairFenceMembershipForUser(instance_sesn_ptr, instance_f_ptr_impaired, ImpairedFenceMembershipSession);
				if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))	_MarshalServerRequestForFenceStateSync (sesn_ptr, f_ptr_impaired, data_msg_ptr, CALLFLAGS_EMPTY);
				if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr_impaired, SESSION_RESULT_PTR(sesn_ptr));
				return SESSION_RESULT_PTR(sesn_ptr);
			}

			//reported as error with data returned as InstanceForFenceStateDescriptor
			if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_USER_FENCE_ALREADYIN))	goto process_fence_join;

			//catch-all
			if (!(SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_PROG_NULL_POINTER))) {
				if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, (Fence *)SESSION_RESULT_USERDATA(sesn_ptr), SESSION_RESULT_PTR(sesn_ptr));
			}

			return SESSION_RESULT_PTR(sesn_ptr); //terminal with original error message
		}

		fstate_ptr = FenceStateDescriptorOffInstanceHolder((InstanceHolderForFenceStateDescriptor *)SESSION_RESULT_USERDATA(sesn_ptr));

		unsigned long userid_invitedby = UfsrvUidGetSequenceId(&(fstate_ptr->invited_by));
		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr) && userid_invitedby > 0) {
			join_type = JT_INVITED;
		}

		//>>>>>>>>f_ptr MAY BE LOCKED depending on return value on success only <<<<<<<<<<<
		//TODO: IsUserAllowedToJoinFenceById doesn't always return FenceState -> check is needed
		HandleJoinFence(sesn_ptr, (InstanceHolderForFenceStateDescriptor *)_RESULT_USERDATA(res_ptr), data_msg_ptr, join_type, res_ptr);
		if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_USER_FENCE_ALREADYIN) || SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_USER_FENCE_JOINED)) {
      f_ptr = FENCESTATE_FENCE(fstate_ptr);
    } else f_ptr = (Fence *)SESSION_RESULT_USERDATA(sesn_ptr);

		if (IS_PRESENT(f_ptr) && !fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));
		return SESSION_RESULT_PTR(sesn_ptr);

	} else if (IS_PRESENT(fence_record_ptr->fname)) {
		//event incremented 2x once for creation and one for join. If you locked the fence, keep it like that
		AttachmentRecord attachment_record = {0};

		try_fence_name:
		if (IS_PRESENT(TransferFenceAvatarAttachmentIfPresent(data_msg_ptr->group->avatar, &attachment_record))) {/*this is temporary treatment*/
	  	fence_record_ptr->avatar = &attachment_record;
	  }
		res_ptr = IsUserAllowedToMakeUserFence(instance_sesn_ptr, fence_record_ptr->fname,
																					fence_record_ptr->location?fence_record_ptr->location->baseloc:"",
																					&((FenceContextDescriptor){sesn_ptr, NULL, (ClientContextData *)fence_record_ptr, {UpdateFenceAssignments}}),
																					&fence_lock_already_owned,
																					FENCE_CALLFLAG_JOIN|FENCE_CALLFLAG_KEEP_FENCE_LOCKED);
		if (fence_record_ptr->avatar == &attachment_record)	fence_record_ptr->avatar = NULL; //reset temporary transfer
	} else {
		syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: RECEIVED INCOMPLETE OR ILL-FORMATTED COMMAND MESSAGE", __func__, pthread_self());
		goto exit_catch_all;
	}

	//>>>>>> f_ptr in LOCKED STATE <<<<<<<<<<<<<<<

	//up-to this point: user made to join an existing or brand new fence
	//res_ptr either originated from IsUserAllowedToJoinFenceById() or IsUserAllowedToMakeUserFence()
	//We have reference to FenceStateDescriptor
	process_fence_join:
	switch (res_ptr->result_code)
	{
		case RESCODE_USER_FENCE_MADE:
			if (_RESULT_TYPE_SUCCESS(res_ptr) && _RESULT_USERDATA(res_ptr)) {
				//set set aside, otherwise it gets overwritten by subsequent invocations on the Ssession
				InstanceHolderForFenceStateDescriptor *instance_fstate_ptr_processed = (InstanceHolderForFenceStateDescriptor *)_RESULT_USERDATA(res_ptr);
				InstanceHolderForFence *instance_f_ptr_processed = FENCESTATE_INSTANCE_HOLDER(FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr_processed));
				Fence *f_ptr_processed = FenceOffInstanceHolder(instance_f_ptr_processed);
				UFSRVResult res = {.result_user_data=f_ptr_processed, .result_code=res_ptr->result_code, .result_type=res_ptr->result_type};

//				UpdateFenceTypeAssignment (sesn_ptr, f_ptr_processed, fence_record_ptr->fence_type, 0);
//				UpdateFencePrivacyModeAssignment (sesn_ptr, f_ptr_processed, fence_record_ptr->privacy_mode, 0);
//				UpdateFenceDeliveryModeAssignment (sesn_ptr, f_ptr_processed, fence_record_ptr->delivery_mode, 0);

				//fence in locked state
				if (fence_record_ptr->n_invited_members > 0) {
					unsigned long invited_eids[fence_record_ptr->n_invited_members];
					CollectionDescriptorPair invited_collections_for_result = {0};
					invited_collections_for_result.first.collection			=(collection_t **)invited_eids;
					invited_collections_for_result.first.collection_sz	=	0;

					for (size_t i=0; i<fence_record_ptr->n_invited_members; i++)	invited_eids[i]=0;
#ifdef __UF_FULLDEBUG
					syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cname:'%s', list_sz:'%lu} Fence with invitation list...", __func__, pthread_self(), sesn_ptr, fence_record_ptr->cname, fence_record_ptr->n_invited_members);
#endif
					AddToFenceInvitedListFromProtoRecord(instance_sesn_ptr, instance_f_ptr_processed, fence_record_ptr->invited_members, fence_record_ptr->n_invited_members, &invited_collections_for_result, true);

					_MarshalNewFenceJoin (sesn_ptr, &res, wsm_ptr_orig, fence_record_ptr, data_msg_ptr, &(invited_collections_for_result.first));
					//note: we use thread ufsrv result ptr because we want to preserve the return of the call function
					if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr_processed, THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));
					return SESSION_RESULT_PTR(sesn_ptr);
				} else {
					_MarshalNewFenceJoin (sesn_ptr, &res, wsm_ptr_orig, fence_record_ptr, data_msg_ptr, NULL);
					if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr_processed, THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));
					return SESSION_RESULT_PTR(sesn_ptr);
				}
			} //no other condition possible

		//signifies the fact that a fence by the same name already existed and user was dropped into it
		case RESCODE_USER_FENCE_JOINED:
			//TODO: implement similar handling to JOIN case above
			break;

		case RESCODE_USER_FENCE_ALREADYIN:
			if (IS_PRESENT((FenceStateDescriptor *)res_ptr->result_user_data)) {
			  InstanceHolderForFenceStateDescriptor *instance_fstate_ptr = (InstanceHolderForFenceStateDescriptor *)res_ptr->result_user_data;
				f_ptr = FenceOffInstanceHolder(FENCESTATE_INSTANCE_HOLDER(FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr)));

				syslog (LOG_DEBUG, "%s (pid:'%lu' cid:'%lu', fo:'%p', bid:'%lu'): WARNING: DOUBLE MAKE: 'uid='%lu' IS ALREADY IN", __func__, pthread_self(), SESSION_ID(sesn_ptr), f_ptr, FENCE_ID(f_ptr), SESSION_USERID(sesn_ptr));

				res_ptr->result_user_data = f_ptr; //no need for state

				//indicates  across client/server state
				if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, (Fence *)SESSION_RESULT_USERDATA(sesn_ptr), THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));
				_MarshalNewFenceReJoin(sesn_ptr, res_ptr, wsm_ptr_orig, fence_record_ptr, data_msg_ptr);
				return SESSION_RESULT_PTR(sesn_ptr);
			}
			break;

		case RESCODE_USER_FENCE_FULL:
		case RESCODE_USER_FENCE_WRITEOFF:
		case RESCODE_USER_FENCE_LOCATION:
		case RESCODE_USER_FENCE_KEY:

			if (IS_PRESENT((InstanceHolderForFence *)res_ptr->result_user_data)) {
			  f_ptr = FenceOffInstanceHolder((InstanceHolderForFence *)res_ptr->result_user_data);
				if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
				syslog (LOG_DEBUG, "%s (pid:'%lu' cid:'%lu' uid:'%lu'): NOTICE: UNSUPPORTED RETURN CONDITION 'bid=%lu'",  __func__, pthread_self(), SESSION_ID(sesn_ptr), SESSION_USERID(sesn_ptr), FENCE_ID(f_ptr));
			}
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

		case RESCODE_FENCE_DOESNT_EXIST:
			return _HandleFenceCommandError (sesn_ptr, NULL, wsm_ptr_orig, data_msg_ptr, RESCODE_FENCE_DOESNT_EXIST, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);

		default:
			//Irrecoverable errors: f_ptr unlocked at source
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}


	exit_catch_all:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_NOOP, RESCODE_PROG_NULL_POINTER)

}


/**
 * @locks: NONE.  The state of Fence * must be controlled by the calling environment and reflected in call_flags.
 * @locked RW f_ptr: must be locked by the caller
 */
UFSRVResult *
MarshalGeoFenceJoinToUser (Session *sesn_ptr, Session *sesn_ptr_target, FenceStateDescriptor *fence_state_ptr, WebSocketMessage *wsm_ptr, unsigned call_flags)
{
	Fence *f_ptr=FENCESTATE_FENCE(fence_state_ptr);

	Envelope command_envelope				=	ENVELOPE__INIT;
	UfsrvCommandWire ufsrv_command	=	UFSRV_COMMAND_WIRE__INIT;
	FenceCommand fence_command			=	FENCE_COMMAND__INIT;
	CommandHeader header						=	COMMAND_HEADER__INIT;

	command_envelope.ufsrvcommand	=	&ufsrv_command;	//connect ufrsvcommand
	ufsrv_command.header					=	&header;	//connect header to outer ufrsrv command
	ufsrv_command.fencecommand		=	&fence_command; //connect user command

	command_envelope.source="0";
	//command_envelope.sourcedevice=1; command_envelope.has_sourcedevice=1;
	command_envelope.timestamp=GetTimeNowInMillis(); command_envelope.has_timestamp=1;

	//header initialisation
	header.cid			=	SESSION_ID(sesn_ptr); header.has_cid=1;
	header.when			=	command_envelope.timestamp; header.has_when=1;
	header.command	=	FENCE_COMMAND__COMMAND_TYPES__JOIN;
	header.args			=	COMMAND_ARGS__GEO_BASED; header.has_args=1;

	//ufsrvcommand initialisation
	ufsrv_command.ufsrvtype=UFSRV_COMMAND_WIRE__UFSRV_TYPE__UFSRV_FENCE;
	fence_command.header=&header;

	//setup fences
	UserRecord user_record_originator;
	FenceRecord *fence_records[1];
	FenceRecord	fence_record;
	fence_records[0]=&fence_record;
	fence_command.fences=fence_records;

	MakeUserRecordFromSessionInProto (GetUfsrvSystemUser(), &user_record_originator, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF);
	fence_command.originator		=	&user_record_originator;

	MakeUfsrvUidInProto(&(fence_state_ptr->invited_by), &(fence_record.invited_by), false); //dynamically allocates buffer
	fence_record.has_invited_by	=	1;
	fence_record.invited_when		=	fence_state_ptr->when_invited;	fence_record.has_invited_when	=	1;

	fence_records[0]=MakeFenceRecordInProto (sesn_ptr, f_ptr, &fence_record);
	MakeFenceUserPreferencesInProto(sesn_ptr, fence_state_ptr, &fence_record);
	fence_command.n_fences=1;

	wsm_ptr->type=WEB_SOCKET_MESSAGE__TYPE__REQUEST;
	UfsrvCommandMarshallingDescription ufsrv_descpription={header.eid, FENCE_ID(f_ptr), header.when, &EnvelopeMetaData, &command_envelope};
	UFSRVResult *res_ptr=UfsrvCommandInvokeCommand (sesn_ptr, sesn_ptr_target, wsm_ptr, NULL, (void *)&ufsrv_descpription/*&ufsrv_command*/, uFENCE_V1_IDX);

	//DestructFenceRecordsProto (fence_records, fence_command.n_fences, false);//fence_records statically allocated
	DestructFenceRecordProto (&fence_record, false);

	return res_ptr;
}


/**
 * 	@brief: Marshaled for new fence formation.
 *
 * 	@param data_msg_ptr: is the original wire message sent by the client. We'll have to copy bits and pieces from  it for this transmission
 *  @locked f_ptr: from previous processing
 *
 *  @unlocks: None
 *  @dynamic_memory fence_records_ptr: array of FenceRecord initiated with dynamic values. Must be freed with DestructFenceRecordProto (FenceRecord **fence_records_ptr, unsigned count)
 */
inline static UFSRVResult *
_MarshalNewFenceJoin (Session *sesn_ptr, UFSRVResult *res_ptr, WebSocketMessage *wsm_ptr_orig, FenceRecord *fence_record_ptr, DataMessage *data_msg_ptr_received, CollectionDescriptor *invited_eids_collection_ptr)
{
	Fence *f_ptr;

	if (unlikely(IS_EMPTY((f_ptr=(Fence *)res_ptr->result_user_data))))	{_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)}

	_GENERATE_FENCE_COMMAND_ENVELOPE_INITIALISATION();

	_PrepareMarshalMessageForFence (&envelope_marshal, sesn_ptr, f_ptr, NULL, data_msg_ptr_received, FENCE_COMMAND__COMMAND_TYPES__JOIN, COMMAND_ARGS__CREATED);
	MakeFenceRecordInProto(sesn_ptr, f_ptr, &fence_record);

	size_t legacymessage_encoded_sz=data_message__get_packed_size(data_msg_ptr_received);
	uint8_t legacymessage_encoded[legacymessage_encoded_sz];
	data_message__pack(data_msg_ptr_received, legacymessage_encoded);
	command_envelope.legacymessage.data=legacymessage_encoded;
	command_envelope.legacymessage.len=legacymessage_encoded_sz;
	command_envelope.has_legacymessage=1;
	//command_envelope.type=ENVE//this originally comes from the incoming json msg read by the api endpoint /v1/Fence

	command_envelope.sourcedevice=1; command_envelope.has_sourcedevice=1;

	UfsrvCommandMarshallingDescription ufsrv_descpription={header.eid, FENCE_ID(f_ptr), header.when, &EnvelopeMetaData, &command_envelope};
	UfsrvCommandInvokeCommand (sesn_ptr, NULL, wsm_ptr_orig, NULL, &ufsrv_descpription, uFENCE_V1_IDX);

	if (IS_PRESENT(invited_eids_collection_ptr) && invited_eids_collection_ptr->collection_sz>0)
		MarshalFenceInvitation (sesn_ptr, f_ptr, wsm_ptr_orig, data_msg_ptr_received, invited_eids_collection_ptr, NULL, 0);

	DestructFenceRecordProto (&fence_record, false);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}


/**
 * 	@brief: Similar to '_MarshalNewFenceJoin', except the user is given an indication of rejoining a group of which it is already
 * 	a member. Invitations are not re-sent for invited users.
 */
inline static UFSRVResult *
_MarshalNewFenceReJoin (Session *sesn_ptr, UFSRVResult *res_ptr, WebSocketMessage *wsm_ptr_orig, FenceRecord *fence_record_ptr, DataMessage *data_msg_ptr_received)
{
	Fence *f_ptr;

	if (unlikely(IS_EMPTY((f_ptr=(Fence *)res_ptr->result_user_data))))	{_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)}

	_GENERATE_FENCE_COMMAND_ENVELOPE_INITIALISATION();

	_PrepareMarshalMessageForFence (&envelope_marshal, sesn_ptr, f_ptr, NULL, data_msg_ptr_received, FENCE_COMMAND__COMMAND_TYPES__JOIN, COMMAND_ARGS__UNCHANGED);
	MakeFenceRecordInProto(sesn_ptr, f_ptr, &fence_record);

	size_t legacymessage_encoded_sz=data_message__get_packed_size(data_msg_ptr_received);
	uint8_t legacymessage_encoded[legacymessage_encoded_sz];
	data_message__pack(data_msg_ptr_received, legacymessage_encoded);
	command_envelope.legacymessage.data=legacymessage_encoded;
	command_envelope.legacymessage.len=legacymessage_encoded_sz;
	command_envelope.has_legacymessage=1;

	command_envelope.sourcedevice=1; command_envelope.has_sourcedevice=1;

	UfsrvCommandMarshallingDescription ufsrv_descpription={header.eid, FENCE_ID(f_ptr), header.when, &EnvelopeMetaData, &command_envelope};
	UfsrvCommandInvokeCommand (sesn_ptr, NULL, wsm_ptr_orig, NULL, &ufsrv_descpription, uFENCE_V1_IDX);

	DestructFenceRecordProto (&fence_record, false);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}


/**
 * 	@brief:	Marshal a confirmation of a fence join event, which could've been based on prior invitation, or self-initiated.
  * 	Such message will be followed by a FenceStateSync message to all participants. As well as this confirmation msg, the joiner gets another sync msg detailing the group/fence configuration.
 *
 * 	@param data_msg_ptr: is the original wire message sent by the client. We'll have to copy bits and pieces from  it for this transmission
 *  @locked f_ptr: from previous processing
 *
 *  @unlocks f_ptr: NONE
 *  @dynamic_memory fence_records_ptr: array of FenceRecord initiated with dynamic values. Must be freed with DestructFenceRecordProto (FenceRecord **fence_records_ptr, unsigned count)
 */
UFSRVResult *
MarshalFenceJoinToUser (Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr)
{
	Fence *f_ptr=FENCESTATE_FENCE(fence_state_ptr);

	_GENERATE_FENCE_COMMAND_ENVELOPE_INITIALISATION();

	_PrepareMarshalMessageForFence (&envelope_marshal, sesn_ptr, f_ptr, NULL, data_msg_ptr, FENCE_COMMAND__COMMAND_TYPES__JOIN, COMMAND_ARGS__ACCEPTED);
	MakeFenceRecordInProto(sesn_ptr, f_ptr, &fence_record);
	MakeFenceUserPreferencesInProto(sesn_ptr, fence_state_ptr, &fence_record);

	if (IS_PRESENT(data_msg_ptr))
	{
		size_t 	legacymessage_encoded_sz=data_message__get_packed_size(data_msg_ptr);
		uint8_t legacymessage_encoded[legacymessage_encoded_sz];
		data_message__pack(data_msg_ptr, legacymessage_encoded);
		command_envelope.legacymessage.data=legacymessage_encoded;
		command_envelope.legacymessage.len=legacymessage_encoded_sz;
		command_envelope.has_legacymessage=1;
	}

	UfsrvCommandMarshallingDescription ufsrv_descpription={header.eid, FENCE_ID(f_ptr), header.when, &EnvelopeMetaData, &command_envelope};
	UfsrvCommandInvokeCommand (sesn_ptr, NULL, wsm_ptr_orig, NULL, &ufsrv_descpription, uFENCE_V1_IDX);

	DestructFenceRecordProto (&fence_record, false);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

#if 0
	unsigned long eid;

	eid=GetFenceEventId (f_ptr, 0/*LOCK_FLAG*/);

	Envelope 			command_envelope	= ENVELOPE__INIT;
	CommandHeader 		header				= COMMAND_HEADER__INIT;
	UfsrvCommandWire	ufsrv_command		= UFSRV_COMMAND_WIRE__INIT;
	FenceCommand 		fence_command		= FENCE_COMMAND__INIT;

	//plumb in static elements
	command_envelope.ufsrvcommand=&ufsrv_command;	//connect ufrsvcommand
	ufsrv_command.header=&header;	//connect header to outer ufrsrv command
	fence_command.header=&header;	//connect header to fence command

	//plumb in FenceRecords array
	FenceRecord *fence_records[1];
	ufsrv_command.fencecommand=&fence_command;	//connect command
	ufsrv_command.ufsrvtype=UFSRV_COMMAND_WIRE__UFSRV_TYPE__UFSRV_FENCE;

	FenceRecord *fence_record_ptr=MakeFenceRecordInProto(sesn_ptr, f_ptr, NULL);

	fence_records[0]=fence_record_ptr;
	fence_command.fences=fence_records;
	fence_command.n_fences=1;

	//envelope initialisations
	if (IS_PRESENT(data_msg_ptr))
	{
		size_t legacymessage_encoded_sz=data_message__get_packed_size(data_msg_ptr);
		unsigned char *legacymessage_encoded=calloc(1, legacymessage_encoded_sz);
		data_message__pack(data_msg_ptr, legacymessage_encoded);
		command_envelope.legacymessage.data=legacymessage_encoded;
		command_envelope.legacymessage.len=legacymessage_encoded_sz;
		command_envelope.has_legacymessage=1;
		//command_envelope.type=ENVE//this originally comes from the incoming json msg read by the api endpoint /v1/Fence
	}

	command_envelope.source="0";
	command_envelope.sourcedevice=1; command_envelope.has_sourcedevice=1;
	command_envelope.timestamp=GetTimeNowInMillis(); command_envelope.has_timestamp=1;

	header.cid=SESSION_ID(sesn_ptr); header.has_cid=1;
	header.eid=eid; header.has_eid=1;
	header.when=command_envelope.timestamp; header.has_when=1;
	header.command=FENCE_COMMAND__COMMAND_TYPES__JOIN;
	header.args=COMMAND_ARGS__ACCEPTED; header.has_args=1;

	UfsrvCommandMarshallingDescription ufsrv_descpription={header.eid, FENCE_ID(f_ptr), header.when, &EnvelopeMetaData, &command_envelope};
	UfsrvCommandInvokeCommand (sesn_ptr, NULL, wsm_ptr_orig, NULL, &ufsrv_descpription, uFENCE_V1_IDX);

	DestructFenceRecordsProto (fence_records, fence_command.n_fences, false);//false because fence_records array was stack allocation

	MarshalFenceStateSyncForJoin (sesn_ptr, sesn_ptr, f_ptr, 0);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
#endif
}


/**
 * 	@brief:	Marshal a confirmation of a fence join event, which is based on prior invitation either GEO or by a another user
  * 	Such message will be followed by a FenceStateSync message to all participants. As well as this confirmation msg, the joiner gets another sync msg detailing the group/fence configuration.
 *
 * 	@param data_msg_ptr: is the original wire message sent by the client. We'll have to copy bits and pieces from  it for this transmission
 *  @locked f_ptr: from previous processing
 *
 *  @unlocks f_ptr: NONE
 *  @dynamic_memory fence_records_ptr: array of FenceRecord initiated with dynamic values. Must be freed with DestructFenceRecordProto (FenceRecord **fence_records_ptr, unsigned count)
 */
UFSRVResult *
MarshalFenceJoinInvitedToUser (Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr)
{
	Fence *f_ptr=FENCESTATE_FENCE(fence_state_ptr);

	_GENERATE_FENCE_COMMAND_ENVELOPE_INITIALISATION();

	_PrepareMarshalMessageForFence (&envelope_marshal, sesn_ptr, f_ptr, NULL, data_msg_ptr, FENCE_COMMAND__COMMAND_TYPES__JOIN, COMMAND_ARGS__ACCEPTED_INVITE);
	MakeFenceRecordInProto(sesn_ptr, f_ptr, &fence_record); //we have to reinitialise record with full load, because it is anew fence join
	MakeFenceUserPreferencesInProto(sesn_ptr, fence_state_ptr, &fence_record);

	MakeUfsrvUidInProto(&(fence_state_ptr->invited_by), &(fence_record.invited_by), false); //dynamically allocates buffer
	fence_record.has_invited_by	=	1;
	fence_record.invited_when		=	fence_state_ptr->when_invited;	fence_record.has_invited_when	=	1;

	wsm_ptr_orig->type=WEB_SOCKET_MESSAGE__TYPE__REQUEST;
	UfsrvCommandMarshallingDescription ufsrv_descpription={header.eid, FENCE_ID(f_ptr), header.when, &EnvelopeMetaData, &command_envelope};
	UfsrvCommandInvokeCommand (sesn_ptr, NULL, wsm_ptr_orig, NULL, &ufsrv_descpription, uFENCE_V1_IDX);

	DestructFenceRecordProto (&fence_record, false);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}


/**
 * 	@brief: Marshals a Fence state sync message with emphasis on new join to Fence participants, enabling clients to refresh their views.
 * 	If sesn_ptr_newly_joined is passed, this user gets  a full state sync, otherwise only Fence's membership is refreshed.
 * 	There is currently no end user mechanism to invoke this command explicitly, hence data_msg_ptr is not used.
 * 	newly joined does not get this marshal, as their get confirmation of join event separately.
 *
 * 	@locked sesn_ptr
 * 	@locks sesn_ptr_newly_joined: down stream. Watch out if sesn_ptr and sesn_ptr_newly_joined are passed as the same.
 *
 */
UFSRVResult *
MarshalFenceStateSyncForJoin (Session *sesn_ptr, Session *sesn_ptr_newly_joined, Fence *f_ptr, unsigned call_flags)
{

	if (FENCE_SESSIONS_LIST_SIZE(f_ptr)<=0)
	{
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cname:'%s', fid:'%lu'} Fence has zero members ", __func__, pthread_self(), sesn_ptr, FENCE_CNAME(f_ptr), FENCE_ID(f_ptr));
#endif
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_EMPTY_INVITATION_LIST);
	}

	_GENERATE_FENCE_COMMAND_ENVELOPE_INITIALISATION();
	_PrepareMarshalMessageForFence (&envelope_marshal, sesn_ptr, f_ptr, NULL, NULL, FENCE_COMMAND__COMMAND_TYPES__JOIN, COMMAND_ARGS__SYNCED);

	UserRecord user_record_originator;
//	DestructUserInfoInProto (fence_command.originator, true);//we don't need this, as it's the wrong user
	fence_command.originator	=	MakeUserRecordFromSessionInProto(sesn_ptr_newly_joined, &user_record_originator, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF);

	MakeFenceRecordInProto(sesn_ptr, f_ptr, &fence_record);

	ListEntry *eptr				= NULL;

	for (eptr=f_ptr->fence_user_sessions_list.head; eptr; eptr=eptr->next) {
	  Session *sesn_ptr_listed = SessionOffInstanceHolder((InstanceHolderForSession *)eptr->whatever);
		//source user
		if ((IS_PRESENT(sesn_ptr_newly_joined)) && (SESSION_ID(sesn_ptr_newly_joined) == SESSION_ID(sesn_ptr_listed))) {
			//skip the newly joined user as they'd have received their own marshal

//			fence_command.originator=NULL;
//			_MarshalFenceStateSync(sesn_ptr, NULL, f_ptr, &command_envelope, false);
//			fence_command.originator=originator_ptr;
//			header.has_when_client	=	0;
		}
		else
		{
			_MarshalFenceStateSync(sesn_ptr, sesn_ptr_listed, f_ptr, &command_envelope);
		}
	}

	DestructFenceRecordProto (&fence_record, false);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

#if 0
	UserRecord 				*originator_ptr		= NULL;
	Envelope 					command_envelope	= ENVELOPE__INIT;
	CommandHeader 		header						= COMMAND_HEADER__INIT;
	UfsrvCommandWire	ufsrv_command			= UFSRV_COMMAND_WIRE__INIT;
	FenceCommand 			fence_command			= FENCE_COMMAND__INIT;

	//plumb in static elements
	command_envelope.ufsrvcommand				=	&ufsrv_command;	//connect ufrsvcommand
	ufsrv_command.header								=	&header;	//connect header to outer ufrsrv command
	fence_command.header								=	&header;	//connect header to fence command

	//plumb in FenceRecords array
	FenceRecord *fence_records[1];
	ufsrv_command.fencecommand					=	&fence_command;	//connect command
	ufsrv_command.ufsrvtype							=	UFSRV_COMMAND_WIRE__UFSRV_TYPE__UFSRV_FENCE;

	FenceRecord *fence_record_ptr				=	MakeFenceRecordInProto(sesn_ptr, f_ptr, NULL);

	if (sesn_ptr_newly_joined )	originator_ptr=MakeUserRecordForSelfInProto (sesn_ptr_newly_joined, PROTO_USER_RECORD_MINIMAL);

	fence_records[0]=fence_record_ptr;
	fence_command.fences=fence_records;
	fence_command.n_fences=1;
	fence_command.originator=originator_ptr;

	command_envelope.source="0";//ufsrv initiated origin
	command_envelope.timestamp=GetTimeNowInMillis(); command_envelope.has_timestamp=1;

	header.when=command_envelope.timestamp; header.has_when=1;
	header.command=FENCE_COMMAND__COMMAND_TYPES__JOIN;
	header.args=COMMAND_ARGS__SYNCED; header.has_args=1;

	ListEntry *eptr				= NULL;

	for (eptr=f_ptr->fence_user_sessions_list.head; eptr; eptr=eptr->next)
	{
		//source user
		if ((!IS_EMPTY(sesn_ptr_newly_joined)) && (SESSION_ID(sesn_ptr_newly_joined)==SESSION_ID(SESSION_IN_LISTENTRY(eptr))))
		{
			header.command=FENCE_COMMAND__COMMAND_TYPES__STATE;
			fence_command.originator=NULL;
			_MarshalFenceStateSync(sesn_ptr, NULL, f_ptr, &command_envelope, false);
			header.command=FENCE_COMMAND__COMMAND_TYPES__JOIN;//restore for other users
			fence_command.originator=originator_ptr;
		}
		else
		{
			_MarshalFenceStateSync(sesn_ptr, SESSION_IN_LISTENTRY(eptr), f_ptr, &command_envelope, false);
		}
	}

	DestructFenceRecordsProto (fence_records, fence_command.n_fences, false);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
#endif
}

//// END JOIN \\\\


//// LEAVE \\\

/**
 * 	param sesn_ptr: the user session which is leaving
 */
inline static UFSRVResult *
_CommandControllerFenceLeave (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr)

{
	bool					fence_lock_already_owned = false;
	Fence 				*f_ptr = NULL;
	FenceCommand	*fcmd_ptr;
	UFSRVResult 	*res_ptr = NULL;
	FenceRecord 	*fence_record_ptr = NULL;
	InstanceHolder *instance_holder_ptr = NULL;

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	fcmd_ptr = data_msg_ptr->ufsrvcommand->fencecommand;

	if (unlikely(fcmd_ptr->n_fences == 0)) {
		syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: FENCE COMMAND CONTAINED ZERO FENCE DEFINITION...", __func__, pthread_self(), sesn_ptr);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}

	fence_record_ptr = fcmd_ptr->fences[0];

	if (fence_record_ptr->fid > 0) {
		FindFenceById (sesn_ptr, fence_record_ptr->fid,
				FENCE_CALLFLAG_SEARCH_BACKEND|FENCE_CALLFLAG_HASH_FENCE_LOCALLY|
				FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE|FENCE_CALLFLAG_KEEP_FENCE_LOCKED|FENCE_CALLFLAG_LOCK_FENCE_BLOCKING);

    instance_holder_ptr = (InstanceHolder *)SESSION_RESULT_USERDATA(sesn_ptr);
		fence_lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_PROG_LOCKED_THIS_THREAD));
	} else if	(IS_STR_LOADED(fence_record_ptr->cname)) {
		FindFenceByCanonicalName (sesn_ptr, fence_record_ptr->cname, &fence_lock_already_owned,
				FENCE_CALLFLAG_SEARCH_BACKEND|FENCE_CALLFLAG_HASH_FENCE_LOCALLY|
				FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE|FENCE_CALLFLAG_KEEP_FENCE_LOCKED|FENCE_CALLFLAG_LOCK_FENCE_BLOCKING);
		instance_holder_ptr = (InstanceHolder *)SESSION_RESULT_USERDATA(sesn_ptr);
	}

	if (IS_EMPTY(instance_holder_ptr)) {
	  //try flag is off, so if empty fence could not be located
		if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST)||
				SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_RESOURCE_NULL)) {
#ifdef __UF_TESTING
			syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', uname:'%s', fid:'%lu'}: ERROR: COULD NOT FIND FENCE: LEAVE COMMAND IGNORED: User not part of fence", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_USERNAME(sesn_ptr), fence_record_ptr->fid);
#endif

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_FENCE_MEMBERSHIP);
		} else {
			//could be locking issue
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, SESSION_RESULT_CODE(sesn_ptr));
		}
	}

	//>>> FENCE SHOULD BE IN RW LOCKED STATE

	f_ptr = (Fence *)GetInstance(instance_holder_ptr);

	NetworkRemoveUserFromFence (instance_sesn_ptr, f_ptr, COMMAND_CTX_DATA(data_msg_ptr), LT_USER_INITIATED, 0);
	if (SESSION_RESULT_TYPE_ERROR(sesn_ptr)) {
		NetworkRemoveUserFromInvitedFence (instance_sesn_ptr, f_ptr, COMMAND_CTX_DATA(data_msg_ptr), LT_USER_INITIATED, 0);
	}

	if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));

	exit_catch_all:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_NOOP, RESCODE_PROG_NULL_POINTER)

}

/**
 * 	@brief: Marshals a Fence state sync message with emphasis on leave to Fence participants, enabling clients to refresh their views.
 * 	If sesn_ptr_newly_left is passed, this user gets  a full state sync, otherwise only Fence's membership is refreshed
 *
 *	@param sesn_ptr: A session with loaded backend context
 *
 *	@locked RW f_ptr: must be locked by the caller
 */
UFSRVResult *
MarshalFenceStateSyncForLeave (Session *sesn_ptr, Session *sesn_ptr_newly_left, Fence *f_ptr, DataMessage *data_msg_ptr_orig, unsigned call_flags)
{
#if 0
	_GENERATE_FENCE_COMMAND_ENVELOPE_INITIALISATION();
	_PrepareMarshalMessageForFence (&envelope_marshal, sesn_ptr, f_ptr, fence_event_ptr, data_msg_ptr_recieved, FENCE_COMMAND__COMMAND_TYPES__FNAME, COMMAND_ARGS__UPDATED);
#endif
#if 1
	UserRecord 				*originator_ptr		= NULL;
	Envelope 					command_envelope	= ENVELOPE__INIT;
	CommandHeader 		header						= COMMAND_HEADER__INIT;
	UfsrvCommandWire	ufsrv_command			= UFSRV_COMMAND_WIRE__INIT;
	FenceCommand 			fence_command			= FENCE_COMMAND__INIT;

	command_envelope.ufsrvcommand				=	&ufsrv_command;
	ufsrv_command.header								=	&header;
	fence_command.header								=	&header;

	//plumb in FenceRecords array
	FenceRecord *fence_records[1];
	ufsrv_command.fencecommand	=	&fence_command;
	ufsrv_command.ufsrvtype			=	UFSRV_COMMAND_WIRE__UFSRV_TYPE__UFSRV_FENCE;

	FenceRecord *fence_record_ptr=MakeFenceRecordInProto(sesn_ptr, f_ptr, NULL);

	if (!IS_EMPTY(sesn_ptr_newly_left))	originator_ptr=MakeUserRecordForSelfInProto (sesn_ptr_newly_left, PROTO_USER_RECORD_MINIMAL);

	fence_records[0]				=	fence_record_ptr;
	fence_command.fences		=	fence_records;
	fence_command.n_fences	=	1;
	fence_command.originator=	NULL;

	command_envelope.source			=	"0";
	command_envelope.timestamp	=	GetTimeNowInMillis(); command_envelope.has_timestamp=1;

	header.when									=	command_envelope.timestamp; header.has_when=1;
	header.command							=	FENCE_COMMAND__COMMAND_TYPES__LEAVE;
	header.eid									=	f_ptr->fence_events.last_event_id;	header.has_eid=1;
	if (call_flags == LT_GEO_BASED)		header.args=COMMAND_ARGS__GEO_BASED;
	//else if (call_flags==LT_BANNED)	header.args=COMMAND_ARGS__BANNED;
	else header.args = COMMAND_ARGS__ACCEPTED;
	header.has_args = 1;

	if (IS_PRESENT(data_msg_ptr_orig)) {
    header.when_client					=	data_msg_ptr_orig->ufsrvcommand->fencecommand->header->when;
    header.has_when_client	= 1;
	}

	_MarshalFenceStateSync(sesn_ptr, NULL, f_ptr, &command_envelope);

	if (FENCE_SESSIONS_LIST_SIZE(f_ptr) <= 0) {
		DestructFenceRecordsProto (fence_records, fence_command.n_fences, false);
#ifdef __UF_TESTING
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cname:'%s', fid:'%lu'} Fence has zero members ", __func__, pthread_self(), sesn_ptr, FENCE_CNAME(f_ptr), FENCE_ID(f_ptr));
#endif
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_EMPTY_INVITATION_LIST)
	}

	//other members get SYNC but only if the leave was self initiated, otherwise we communicate reason
	if (header.args == COMMAND_ARGS__ACCEPTED)	header.args = COMMAND_ARGS__SYNCED;
	header.has_when_client	= 0; //not relevant for others

	fence_command.originator = originator_ptr;//so they know who is leaving

	//time_t		time_now	=	time(NULL);
	ListEntry	*eptr		= 	NULL;

	for (eptr=FENCE_USER_SESSION_LIST(f_ptr).head; eptr; eptr=eptr->next) {
    _MarshalFenceStateSync(sesn_ptr, SessionOffInstanceHolder((InstanceHolderForSession *)eptr->whatever), f_ptr, &command_envelope);
	}

	DestructUserInfoInProto (originator_ptr, true);
	DestructFenceRecordsProto (fence_records, fence_command.n_fences, false);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
#endif
}

//// END LEAVE	\\\\

//// INVITE \\\

#if 1

static inline UFSRVResult *_VerifyInviteCommand (Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, DataMessage *data_msg_ptr, WebSocketMessage *wsm_ptr_received, unsigned long fence_call_flags);
static inline UFSRVResult *_MarshalFenceStateSyncForInvite (Session *sesn_ptr, Session *sesn_ptr_newly_invited, Fence *f_ptr, FenceEvent *fence_event_ptr, unsigned call_flags);
static inline UFSRVResult *_MarshalFenceSyncInviteForSelf (Session *sesn_ptr, Session *sesn_ptr_newly_invited, FenceStateDescriptor *, FenceEvent *fence_event_ptr, unsigned call_flags);
static inline UFSRVResult *_MarshalFenceInviteUnchanged (Session *sesn_ptr, unsigned long userid, Fence *f_ptr, DataMessage *data_msg_ptr, unsigned call_flags);

/**
 * 	@brief: The main controller for handling user commands for adding/removing users to groups
 * 	param sesn_ptr: the user session for which the command is executed
 * 	@locked sesn_ptr: by caller
 * 	@locks RW Fence: by downstream
 */
inline static UFSRVResult *
_CommandControllerFenceInvite (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_recieved, DataMessage *data_msg_ptr)
{
	Fence									*f_ptr		=	NULL;
	UFSRVResult 					*res_ptr	=	NULL;

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	switch (data_msg_ptr->ufsrvcommand->fencecommand->header->args)
	{
		case COMMAND_ARGS__ADDED://user added members to invite list
			res_ptr=_CommandControllerFenceInviteAdd (instance_sesn_ptr, wsm_ptr_recieved, data_msg_ptr);
			break;

		case COMMAND_ARGS__DELETED:
			//res_ptr=_CommandControllerFenceInviteDelete	(sesn_ptr, wsm_ptr_recieved, data_msg_ptr);
			break;

		case COMMAND_ARGS__SYNCED:
				res_ptr = _CommandControllerFenceInviteSynced	(instance_sesn_ptr, wsm_ptr_recieved, data_msg_ptr);
		break;
		default:
			syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', arg:'%d'}: ERROR: UKNOWN FENCE INVITE COMMAND ARG...", __func__, pthread_self(), sesn_ptr, data_msg_ptr->ufsrvcommand->fencecommand->header->args);
	}


	exit_final:
	if (IS_EMPTY(res_ptr))	goto exit_catch_all; //this catches the default case
	return res_ptr;

	exit_catch_all:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

/**
 *	@brief: A request from a user to invite one-or-more other user(s) to fence.
 *	@locks Fence *:
 *	@unlocks Fence *:
 */
inline static UFSRVResult *
_CommandControllerFenceInviteAdd (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr)
{
	bool 									fence_already_locked = false;
	InstanceHolderForFenceStateDescriptor *instance_fstate_ptr;
	FenceStateDescriptor	*fstate_ptr;
	FenceCommand					*fcmd_ptr;
	FenceRecord 					*fence_record_ptr = NULL;
#define _FENCE_CALL_FLAGS_STATESYNC	(FENCE_CALLFLAG_CHECK_FENCEOWNERSHIP|FENCE_CALLFLAG_KEEP_FENCE_LOCKED)

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	//locks by default
	IsUserAllowedToChangeFence (sesn_ptr,
															data_msg_ptr->ufsrvcommand->fencecommand->fences[0]->fid,
															data_msg_ptr->ufsrvcommand->fencecommand->fences[0]->cname,
															&fence_already_locked,
															_FENCE_CALL_FLAGS_STATESYNC);

	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))	{
	  instance_fstate_ptr = (InstanceHolderForFenceStateDescriptor *)SESSION_RESULT_USERDATA(sesn_ptr);
	  fstate_ptr          = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
	} else {
		Fence *f_ptr		=	NULL;
		int 	rescode		=	SESSION_RESULT_CODE(sesn_ptr);

		if (SESSION_RESULT_TYPE_ERROR(sesn_ptr) && !SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST)) {
			//FENCE LOCKED...
      if (SESSION_RESULT_CODE(sesn_ptr) == RESCODE_FENCE_OWNERSHIP) {
				fstate_ptr = FenceStateDescriptorOffInstanceHolder((InstanceHolderForFenceStateDescriptor *)SESSION_RESULT_USERDATA(sesn_ptr));
				f_ptr		=	FenceOffInstanceHolder(fstate_ptr->instance_holder_fence);
        _HandleFenceCommandError (sesn_ptr, fstate_ptr, wsm_ptr_orig, data_msg_ptr, rescode, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);
      } else { //RESCODE_FENCE_FENCE_MEMBERSHIP
				f_ptr		=	FenceOffInstanceHolder((InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr));
        _HandleFenceCommandError (sesn_ptr, &((FenceStateDescriptor){.instance_holder_fence=(InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr)}), wsm_ptr_orig, data_msg_ptr, rescode, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);
      }

			if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
			goto return_catch_all;
		}

		return_catch_all:
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)
	}

	fcmd_ptr = data_msg_ptr->ufsrvcommand->fencecommand;
	fence_record_ptr = fcmd_ptr->fences[0];

	//>>> FENCE SHOULD BE IN RW LOCKED STATE

	_VerifyInviteCommand(sesn_ptr, fstate_ptr, data_msg_ptr, wsm_ptr_orig, FENCE_CALLFLAG_MARSHAL_COMMAND_ERROR);
	if (SESSION_RESULT_TYPE_ERROR(sesn_ptr)) {
		//no change to fence state just command semantics are wrong
		if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fstate_ptr), SESSION_RESULT_PTR(sesn_ptr));
		return SESSION_RESULT_PTR(sesn_ptr);
	}

	unsigned long invited_eids[fence_record_ptr->n_invited_members];			memset(invited_eids, 0, sizeof(invited_eids));
	unsigned long unprocessed_uids[fence_record_ptr->n_invited_members]; 	memset(unprocessed_uids, 0, sizeof(unprocessed_uids));
	CollectionDescriptorPair invited_collections_for_result = {0};
	invited_collections_for_result.first.collection			=(collection_t **)invited_eids;
	invited_collections_for_result.first.collection_sz	=	0;
	invited_collections_for_result.second.collection		=(collection_t **)unprocessed_uids;
	invited_collections_for_result.second.collection_sz	=		0;

	AddToFenceInvitedListFromProtoRecord(instance_sesn_ptr, FENCESTATE_INSTANCE_HOLDER(fstate_ptr), fence_record_ptr->invited_members, fence_record_ptr->n_invited_members, &invited_collections_for_result, true);

	MarshalFenceInvitation (sesn_ptr, FENCESTATE_FENCE(fstate_ptr), wsm_ptr_orig, data_msg_ptr, &(invited_collections_for_result.first), &(invited_collections_for_result.second), 0);
	//_MarshalFenceInvitationReceipt (sesn_ptr, FENCESTATE_FENCE(fence_state_ptr), data_msg_ptr, &invited_eids_collection, NULL);

	if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fstate_ptr), SESSION_RESULT_PTR(sesn_ptr));

	return_success:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

#undef _FENCE_CALL_FLAGS_STATESYNC
}

/**
 * 	@brief: Reissue an invite to user. This should originate from the same user (as sesn_ptr)
 */
inline static UFSRVResult *
_CommandControllerFenceInviteSynced (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr)
{
	bool 									fence_lock_already_owned = false;
	int 									rescode;
	Fence									*f_ptr;
	FenceStateDescriptor	*fence_state_ptr;
	InstanceHolder        *instance_holder_ptr_fence;
#define _FENCE_CALL_FLAGS_STATESYNC	(FENCE_CALLFLAG_KEEP_FENCE_LOCKED)

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	//locks by default
	FindFence (sesn_ptr,
						data_msg_ptr->ufsrvcommand->fencecommand->fences[0]->fid,
						data_msg_ptr->ufsrvcommand->fencecommand->fences[0]->cname,
						&fence_lock_already_owned,
						_FENCE_CALL_FLAGS_STATESYNC);

	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))	instance_holder_ptr_fence = (InstanceHolder *)SESSION_RESULT_USERDATA(sesn_ptr);
	else {
		rescode		=	RESCODE_FENCE_DOESNT_EXIST;
		//todo: implement error handling
//			_HandleFenceCommandError (sesn_ptr, &((FenceStateDescriptor){.fence=f_ptr}), wsm_ptr_orig, data_msg_ptr, rescode, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);
//			FenceEventsUnLock(f_ptr);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)
	}

	f_ptr = FenceOffInstanceHolder(instance_holder_ptr_fence);

	//>>> FENCE SHOULD BE IN RW LOCKED STATE

	if (FENCE_USER_SESSION_LIST_SIZE(f_ptr) == 0)	goto return_marshal_remove_invitation;

	if (!IsUserOnFenceInvitedList(f_ptr, SESSION_USERID(sesn_ptr)))	goto return_error_membership;

	InstanceHolderForFenceStateDescriptor *instance_fstate_ptr;
	if (IS_EMPTY((instance_fstate_ptr = IsUserMemberOfThisFence(SESSION_INVITED_FENCE_LIST_PTR(sesn_ptr), f_ptr, false))))	goto return_error_membership;

  fence_state_ptr = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);

	bool lock_already_owned 	= false;
	Session *sesn_ptr_inviter = NULL;
	InstanceHolderForSession *instance_sesn_ptr_inviter;
	unsigned long invited_by 	= UfsrvUidGetSequenceId(&(fence_state_ptr->invited_by));

	if (invited_by != 1) {
		GetSessionForThisUserByUserId(sesn_ptr, invited_by, &lock_already_owned, CALL_FLAG_LOCK_SESSION|CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION);
    instance_sesn_ptr_inviter = (InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr);
	} else {
		instance_sesn_ptr_inviter = InstantiateCarrierSession(NULL, WORKERTYPE_UFSRVWORKER, CALL_FLAG_INSTANTIATE_FROM_SYSTEM_USER);
	}

	if (IS_EMPTY(instance_sesn_ptr_inviter))	goto return_error_internal_state;

	sesn_ptr_inviter = SessionOffInstanceHolder(instance_sesn_ptr_inviter);

	_MarshalFenceSyncInviteForSelf (sesn_ptr_inviter, sesn_ptr/*invited*/, fence_state_ptr, &((FenceEvent){0}), 0);

	if (invited_by == 1)	SessionReturnToRecycler (instance_sesn_ptr_inviter, (ContextData *)NULL, CALLFLAGS_EMPTY);//this is not locked
	else if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_inviter, __func__);

	if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fence_state_ptr), SESSION_RESULT_PTR(sesn_ptr));

	return_success:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

	return_error_membership:
	rescode		=	RESCODE_FENCE_FENCE_MEMBERSHIP;
	_HandleFenceCommandError (sesn_ptr, &((FenceStateDescriptor){.instance_holder_fence=instance_holder_ptr_fence}), wsm_ptr_orig, data_msg_ptr, rescode, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);
	if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)

	return_error_internal_state:
	rescode		=	RESCODE_FENCE_STATE;
	_HandleFenceCommandError (sesn_ptr, &((FenceStateDescriptor){.instance_holder_fence=instance_holder_ptr_fence}), wsm_ptr_orig, data_msg_ptr, rescode, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);
	if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)

	return_marshal_remove_invitation://orphan fence
	{
		InstanceHolderForSession *instance_sesn_ptr_carrier			=	InstantiateCarrierSession(NULL, WORKERTYPE_UFSRVWORKER, CALL_FLAG_INSTANTIATE_FROM_SYSTEM_USER);
		rescode												=	RESCODE_FENCE_FENCE_MEMBERSHIP;
		size_t 	dangling_users_counter=	NetworkRemoveUsersFromInviteList (SessionOffInstanceHolder(instance_sesn_ptr_carrier), instance_holder_ptr_fence);

		if (dangling_users_counter)	syslog(LOG_NOTICE, "%s {pid:'%lu, o:'%p', cid:'%lu', fo:'%p', fid:'%lu', dangling_sz:'%lu}: NOTICE: COULD NOT REMOVE ALL INVITED USERS", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), f_ptr, FENCE_ID(f_ptr), dangling_users_counter);

		SessionReturnToRecycler (instance_sesn_ptr_carrier, (ContextData *)NULL, CALLFLAGS_EMPTY);
		if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

#undef _FENCE_CALL_FLAGS_STATESYNC

}

/**
 * 	@brief: Acknowledge the outcome of previous user request for which invited others
 */
inline static UFSRVResult *
_MarshalFenceInvitationReceipt (Session *sesn_ptr, Fence *f_ptr, DataMessage *data_msg_ptr, CollectionDescriptor *invited_eids_collection_ptr, CollectionDescriptor *rejected_collection_ptr)
{

	_GENERATE_FENCE_COMMAND_ENVELOPE_INITIALISATION();

	enum _CommandArgs command_arg;
	if (IS_PRESENT(rejected_collection_ptr))	command_arg		=	COMMAND_ARGS__ACCEPTED_PARTIAL;
	else 																			command_arg		=	COMMAND_ARGS__ACCEPTED;

	_PrepareMarshalMessageForFence (&envelope_marshal, sesn_ptr, f_ptr, NULL, data_msg_ptr, FENCE_COMMAND__COMMAND_TYPES__INVITE, command_arg);

	_MarshalCommandToUser(sesn_ptr, NULL, f_ptr, &command_envelope,  uFENCE_V1_IDX);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

#if 0
	Envelope 					command_envelope	= ENVELOPE__INIT;
	CommandHeader 		header						= COMMAND_HEADER__INIT;
	UfsrvCommandWire	ufsrv_command			= UFSRV_COMMAND_WIRE__INIT;
	FenceCommand 			fence_command			= FENCE_COMMAND__INIT;

	command_envelope.ufsrvcommand=&ufsrv_command;
	ufsrv_command.header=&header;
	fence_command.header=&header;

	FenceRecord	fence_record;
	FenceRecord *fence_records[1];
	ufsrv_command.fencecommand	=	&fence_command;
	ufsrv_command.ufsrvtype			=	UFSRV_COMMAND_WIRE__UFSRV_TYPE__UFSRV_FENCE;

	FenceRecord *fence_record_ptr=MakeFenceRecordInProto(sesn_ptr, f_ptr, NULL);

	fence_records[0]						=	MakeFenceRecordInProtoAsIdentifier(sesn_ptr, f_ptr, &fence_record);
	fence_command.fences				=	fence_records;
	fence_command.n_fences			=	1;

	command_envelope.source			=	"0";
	command_envelope.timestamp	=	GetTimeNowInMillis(); command_envelope.has_timestamp=1;

	header.cid									=	SESSION_ID(sesn_ptr); header.has_cid=1;
	header.when									=	command_envelope.timestamp; header.has_when=1;
	header.command							=	FENCE_COMMAND__COMMAND_TYPES__INVITE;
	header.when_client					=	data_msg_ptr->ufsrvcommand->fencecommand->header->when;	header.has_when_client=data_msg_ptr->ufsrvcommand->fencecommand->header->has_when_client;
	if (IS_PRESENT(rejected_collection_ptr))	header.args		=	COMMAND_ARGS__ACCEPTED_PARTIAL;
	else 																			header.args		=	COMMAND_ARGS__ACCEPTED;
	header.has_args=1;

	_MarshalCommandToUser(sesn_ptr, NULL, f_ptr, &command_envelope,  uFENCE_V1_IDX);


	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
#endif
}

static inline UFSRVResult *_MarshalFenceInvitationFromWireSource (Session *sesn_ptr, Fence *f_ptr, Envelope *command_envelope_ptr, DataMessage *data_msg_ptr, CollectionDescriptor *invited_eids_collection_ptr, unsigned call_flags);
static inline UFSRVResult *_MarshalFenceInvitationFromSystemSource (Session *sesn_ptr, Fence *f_ptr, Envelope *command_envelope_ptr, CollectionDescriptor *invited_eids_collection_ptr, unsigned call_flags);

/**
 * 	@brief: Helper method to deal with marshaling a fully formed invitation messages for a collection of users, based
 * 	on prior invitation request from another user. The request has come through the wire, from a user, as opposed to system initiated,
 * 	for example, geofence roaming mode.
 *
 * 	@param sesn_ptr: the user initiating the invite
 */
static inline UFSRVResult *
_MarshalFenceInvitationFromWireSource (Session *sesn_ptr, Fence *f_ptr, Envelope *command_envelope_ptr, DataMessage *data_msg_ptr, CollectionDescriptor *invited_eids_collection_ptr, unsigned call_flags)
{
	for (struct{size_t i; FenceRecord *frec_ptr;} loop={0, data_msg_ptr->ufsrvcommand->fencecommand->fences[0]}; loop.i<loop.frec_ptr->n_invited_members; loop.i++) {
		unsigned long sesn_call_flags=(CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY|CALL_FLAG_HASH_USERNAME_LOCALLY|
																		CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION|CALL_FLAG_REMOTE_SESSION);
		Session *sesn_ptr_invited;

		if (((unsigned long *)invited_eids_collection_ptr->collection)[loop.i]==0) {
			syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', uid_invited:'%lu', idx:'%lu'}: ERROR: Invited Events Collection contain eid=0: Skipping this user", __func__, pthread_self(), sesn_ptr, UfsrvUidGetSequenceId((UfsrvUid *)loop.frec_ptr->invited_members[loop.i]->ufsrvuid.data), loop.i);
			continue;
		}
    if ((memcmp(SESSION_UFSRVUID(sesn_ptr), loop.frec_ptr->invited_members[loop.i]->ufsrvuid.data, CONFIG_MAX_UFSRV_ID_SZ)==0))	continue;	//found myself in the list

		//TODO: check if user already in fence..
		__unused bool lock_already_owned = false;
		GetSessionForThisUserByUserId(sesn_ptr, UfsrvUidGetSequenceId((UfsrvUid *)loop.frec_ptr->invited_members[loop.i]->ufsrvuid.data), &lock_already_owned, sesn_call_flags);

    InstanceHolderForSession *instance_sesn_ptr_invited = (InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr);
		//>>>>>>> INVITED SESSION NOT LOCKED

		if (IS_PRESENT(instance_sesn_ptr_invited)) {
		  sesn_ptr_invited = SessionOffInstanceHolder(instance_sesn_ptr_invited);

			_MarshalFenceInvitation(sesn_ptr, sesn_ptr_invited, f_ptr, command_envelope_ptr, ((unsigned long *)invited_eids_collection_ptr->collection)[loop.i]);
			_MarshalFenceStateSyncForInvite (sesn_ptr, sesn_ptr_invited, f_ptr, &((FenceEvent){.eid=((unsigned long *)invited_eids_collection_ptr->collection)[loop.i]}), 0);
		}
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
}

/**
 * @brief inform original inviter  of users who weren't sent invitation message because they are already on the invitation list
 * @param sesn_ptr
 * @param f_ptr
 * @param command_envelope_ptr
 * @param data_msg_ptr
 * @param invited_eids_collection_ptr
 * @param call_flags
 * @return
 */
static inline UFSRVResult *
_MarshalUnchangedFenceInvitationFromWireSource (Session *sesn_ptr, Fence *f_ptr, Envelope *command_envelope_ptr, DataMessage *data_msg_ptr, CollectionDescriptor *unchanged_collection_ptr, unsigned call_flags)
{
	for (size_t i=0; i<unchanged_collection_ptr->collection_sz; i++) {
		unsigned long userid=(((unsigned long *)unchanged_collection_ptr->collection)[i]);

		if (userid==0) {
			syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', uid_invited:'%lu', idx:'%lu'}: NOTICE: unchanged invite userids contain eid=0: Skipping this user", __func__, pthread_self(), sesn_ptr, userid, i);
			continue;
		}

		_MarshalFenceInviteUnchanged (sesn_ptr, userid, f_ptr, data_msg_ptr, call_flags);
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
}

/**
 * 	@brief: Helper method to deal with marshaling system-initiated invitations,
 * 	for example, geofence roaming mode.
 *
 * 	@param sesn_ptr: the user being invited, which is different in semantics from WireInitiated above
 */
static inline UFSRVResult *
_MarshalFenceInvitationFromSystemSource (Session *sesn_ptr, Fence *f_ptr, Envelope *command_envelope_ptr, CollectionDescriptor *invited_eids_collection_ptr, unsigned call_flags)
{
	//for (struct{size_t i; FenceRecord *frec_ptr;} loop={0, data_msg_ptr->ufsrvcommand->fencecommand->fences[0]}; loop.i<loop.frec_ptr->n_invited_members; loop.i++)
	for (struct{size_t i, i_max; unsigned long *eids;} loop={0, invited_eids_collection_ptr->collection_sz, (unsigned long *)invited_eids_collection_ptr->collection}; loop.i<loop.i_max; loop.i++) {
		unsigned long sesn_call_flags=(CALL_FLAG_LOCK_SESSION|CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY|CALL_FLAG_HASH_USERNAME_LOCALLY|CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION);
		//Session *sesn_ptr_invited;

		if (((unsigned long *)invited_eids_collection_ptr->collection)[loop.i]==0) {
			syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', uname_invited:'%s', idx:'%lu'}: ERROR: Invited Events Collection contain eid=0: Skipping this user", __func__, pthread_self(), sesn_ptr, SESSION_USERNAME(sesn_ptr), loop.i);
			continue;
		}

		_MarshalFenceInvitation(sesn_ptr, NULL, f_ptr, command_envelope_ptr, ((unsigned long *)invited_eids_collection_ptr->collection)[loop.i]);
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
}


/**
 * 	@brief: Given a COLLECTION of invitees, marshal to/inform the invitee the invitation to join. They may decline it.
 * 	The collection index and fence_user_sessions_invited_list are aligned index-wise, because tthe events were generated based on that list
 * 	and since the Fence is locked, no modification is possible since the events collections was created.
 * 	Where the value of eid is zer, we skip the user.
 *
 *	@param invited_eid_collection_ptr: contains array of unsigned long eids
 * 	@locked f_ptr: must be locked in the caller's environment
 * 	@locked sesn_ptr: must be locked in the callers environment
 *
 */
UFSRVResult *
MarshalFenceInvitation (Session *sesn_ptr, Fence *f_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, CollectionDescriptor *invited_eids_collection_ptr, CollectionDescriptor *unchanged_collection_ptr, unsigned call_flags)
{
	if (invited_eids_collection_ptr->collection_sz==0 && unchanged_collection_ptr->collection_sz==0) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fo:'%p', cname:'%s', fid:'%lu', invited_sz:'%d', collection_sz:'%lu', unchanged:'%lu'} Invited Members: Fence has zero invited members ", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), f_ptr, FENCE_CNAME(f_ptr), FENCE_ID(f_ptr), f_ptr->fence_user_sessions_invited_list.nEntries, invited_eids_collection_ptr?invited_eids_collection_ptr->collection_sz:0, unchanged_collection_ptr->collection_sz);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_EMPTY_INVITATION_LIST);
	}

	Envelope 					command_envelope= ENVELOPE__INIT;
	CommandHeader 		header					=	COMMAND_HEADER__INIT;
	UfsrvCommandWire	ufsrv_command		= UFSRV_COMMAND_WIRE__INIT;
	FenceCommand 			fence_command		= FENCE_COMMAND__INIT;

	//plumb in static elements
	command_envelope.ufsrvcommand=&ufsrv_command;
	ufsrv_command.header=&header;
	fence_command.header=&header;

	//plumb in FenceRecords array
	FenceRecord *fence_records[1];
	ufsrv_command.fencecommand	=	&fence_command;
	ufsrv_command.ufsrvtype			=	UFSRV_COMMAND_WIRE__UFSRV_TYPE__UFSRV_FENCE;


	FenceRecord *fence_record_ptr	=	MakeFenceRecordInProto(sesn_ptr, f_ptr, NULL);//MakeFenceRecordInProtoAsIdentifier
	fence_records[0]							=	fence_record_ptr;
	fence_command.fences					=	fence_records;
	fence_command.n_fences				=	1;

	command_envelope.source				=	"0";
	command_envelope.sourcedevice	=	1; command_envelope.has_sourcedevice=1;
	command_envelope.timestamp		=	GetTimeNowInMillis(); command_envelope.has_timestamp=1;

	header.cid			=	SESSION_ID(sesn_ptr); header.has_cid=1;
	header.when			=	command_envelope.timestamp; header.has_when=1;
	header.command	=	FENCE_COMMAND__COMMAND_TYPES__JOIN;

	//UfsrvCommandMarshallingDescription ufsrv_descpription={header.eid, FENCE_ID(f_ptr), header.when, &EnvelopeMetaData, &command_envelope};
	//UfsrvCommandInvokeCommand (sesn_ptr, NULL, wsm_ptr_orig, NULL, &ufsrv_descpription, uFENCE_V1_IDX);

	UFSRVResult *res_ptr;
	UserRecord user_record_originator;

	if (IS_PRESENT(data_msg_ptr)) {
		fence_command.originator	=	MakeUserRecordFromSessionInProto (sesn_ptr, &user_record_originator, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF);
		header.args								=	COMMAND_ARGS__INVITED; header.has_args=1;
		if (invited_eids_collection_ptr->collection_sz>0) {
      res_ptr = _MarshalFenceInvitationFromWireSource(sesn_ptr, f_ptr, &command_envelope, data_msg_ptr, invited_eids_collection_ptr, call_flags);
    }
		if (IS_PRESENT(unchanged_collection_ptr) && unchanged_collection_ptr->collection_sz>0) {
			_MarshalUnchangedFenceInvitationFromWireSource (sesn_ptr, f_ptr, &command_envelope, data_msg_ptr, unchanged_collection_ptr, call_flags);
		}
	} else {
		//TODO: use static originator ptr overall when invoking MakeUserRecordForSelfInProto and generate a static one for system user or reuse
		fence_command.originator	=	MakeUserRecordFromSessionInProto (GetUfsrvSystemUser(), &user_record_originator, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF);
		header.args								=	COMMAND_ARGS__INVITED_GEO; header.has_args=1;
		res_ptr										=	_MarshalFenceInvitationFromSystemSource (sesn_ptr, f_ptr, &command_envelope, invited_eids_collection_ptr, call_flags);
	}

	DestructFenceRecordsProto (fence_records, fence_command.n_fences, false);//false because fence_records array was stack allocation

	return res_ptr;

}

#if 0
/**
 * 	@brief: Given a NEWLY formed fence with an invitation list, marshal to/inform the invitee the invitation to join. They may decline it.
 * 	The collection index and fence_user_sessions_invited_list are aligned index-wise, because tthe events were generated based on that list
 * 	and since the Fence is locked, no modification is possible since the events collections was created.
 * 	Where the value of eid is zer, we skip the user.
 *
 *	@param invited_eid_collection_ptr: contains array of unsigned long eids
 * 	@locked f_ptr: must be locked in the caller's environment
 * 	@locked sesn_ptr: must be locked in the callers environment
 *
 */
static UFSRVResult *
_MarshalNewFenceInvitation (Session *sesn_ptr, Fence *f_ptr, Envelope *command_envelope_ptr, CollectionDescriptor *invited_eids_collection_ptr, unsigned call_flags)
{
	FenceRecord *fence_record_ptr=command_envelope_ptr->ufsrvcommand->fencecommand->fences[0];

	if (f_ptr->fence_user_sessions_invited_list.nEntries<=0)
	{
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cname:'%s', fid:'%lu', invited_sz:'%d'} Invited Members: Fence has zero invited members ", __func__, pthread_self(), sesn_ptr, fence_record_ptr->cname, fence_record_ptr->fid, f_ptr->fence_user_sessions_invited_list.nEntries);
#endif

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_EMPTY_INVITATION_LIST);
	}


	if (IS_EMPTY(invited_eids_collection_ptr) || invited_eids_collection_ptr->collection_sz==0)
	{
		syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fo:'%p', cname:'%s', fid:'%lu', invited_sz:'%d', collection_sz:'%lu'} Invited Members: Fence has zero invited members ", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), f_ptr, fence_record_ptr->cname, fence_record_ptr->fid, f_ptr->fence_user_sessions_invited_list.nEntries, invited_eids_collection_ptr?invited_eids_collection_ptr->collection_sz:0);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_EMPTY_INVITATION_LIST);
	}


	ListEntry	*eptr				= NULL;
	UserRecord	*originator_ptr		= NULL;

	originator_ptr=MakeUserRecordForSelfInProto (sesn_ptr, PROTO_USER_RECORD_MINIMAL);

	size_t i=0;
	for (eptr=f_ptr->fence_user_sessions_invited_list.head; eptr; i++, eptr=eptr->next)
	{
		if (((unsigned long *)invited_eids_collection_ptr->collection)[i])
		{
			command_envelope_ptr->ufsrvcommand->fencecommand->originator=originator_ptr;
			command_envelope_ptr->ufsrvcommand->header->args=COMMAND_ARGS__INVITED; command_envelope_ptr->ufsrvcommand->header->has_args=1;
			command_envelope_ptr->source="0"; //orignally was set to the user who created the fence. This has important effect on how the client handle the request. "0'means usfsrv native command
			_MarshalFenceInvitation(sesn_ptr, (Session *)eptr->whatever, f_ptr, command_envelope_ptr, ((unsigned long *)invited_eids_collection_ptr->collection)[i]);
		}
		else
		{
			syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid_invited:'%lu', idx:'%lu'}: ERROR: Invited Events Collection contain eid=0: Skipping this user", __func__, pthread_self(), sesn_ptr, ((Session *)eptr->whatever)->session_id, i);
		}
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}
#endif

/**
 * 	@brief: Works in tandem with _MarshalNewFenceInvitation(), specialising the command message to the target user
 *
 * 	@locked f_ptr: must be locked in the caller's environment
 * 	@locked sesn_ptr: must be locked in the callers environment
 * 	@locks: sesn_ptr_target will be locked further down stream
 * 	@unlocks: NONE
 */
static inline UFSRVResult *
_MarshalFenceInvitation(Session *sesn_ptr, Session *sesn_ptr_target, Fence *f_ptr, Envelope *command_envelope_ptr, unsigned long eid)
{
	CommandHeader *command_header_ptr=command_envelope_ptr->ufsrvcommand->header;

	command_header_ptr->cid=SESSION_ID((sesn_ptr_target?:sesn_ptr)); command_header_ptr->has_cid=1;
	MakeUfsrvUidInProto(sesn_ptr_target?&SESSION_UFSRVUIDSTORE(sesn_ptr_target):&SESSION_UFSRVUIDSTORE(sesn_ptr), &(command_header_ptr->ufsrvuid), true); //ufsrvuid by reference
	command_header_ptr->has_ufsrvuid=1;

	command_header_ptr->eid=eid; command_header_ptr->has_eid=1;

	WebSocketMessage wsmsg; wsmsg.type=WEB_SOCKET_MESSAGE__TYPE__REQUEST;//dummy
	UfsrvCommandMarshallingDescription ufsrv_descpription={command_header_ptr->eid, FENCE_ID(f_ptr), command_header_ptr->when, &EnvelopeMetaData, command_envelope_ptr};

#ifdef __UF_TESTING
	syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', cid_target:'%lu' uname_target:'%s', uname_originator:'%s', fcname:'%s'} Inviting member ", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr),
				SESSION_ID((sesn_ptr_target?:sesn_ptr)), SESSION_USERNAME((sesn_ptr_target?:sesn_ptr)), command_envelope_ptr->ufsrvcommand->fencecommand->originator->username, FENCE_CNAME(f_ptr));
#endif

	UfsrvCommandInvokeCommand (sesn_ptr, sesn_ptr_target, &wsmsg, NULL, &ufsrv_descpription, uFENCE_V1_IDX);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

/**
 * 	@brief: Marshals a Fence state sync message informing members of a new member being added to invite list.
 * 	There is currently no end user mechanism to invoke this command explicitly, hence data_msg_ptr is not used.
 * 	No event is generated for sync other than original event generated for adding the new member to the invited list
 *
 * 	@param sesn_ptr: The session that originated the request.
 *
 * 	@locked sesn_ptr:
 * 	@locks sesn_ptr_newly_invited: downstream
 *
 */
static inline UFSRVResult *
_MarshalFenceStateSyncForInvite (Session *sesn_ptr, Session *sesn_ptr_newly_invited, Fence *f_ptr, FenceEvent *fence_event_ptr, unsigned call_flags)
{
	if (FENCE_INVITED_LIST_SIZE(f_ptr)<=0) {
		syslog(LOG_WARNING, "%s {pid:'%lu', o:'%p', cname:'%s', fid:'%lu'} WARNING: COMMAND INVOKED WITH zero members ", __func__, pthread_self(), sesn_ptr, FENCE_CNAME(f_ptr), FENCE_ID(f_ptr));
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_EMPTY_INVITATION_LIST);
	}

	_GENERATE_FENCE_COMMAND_ENVELOPE_INITIALISATION();
	_PrepareMarshalMessageForFence (&envelope_marshal, sesn_ptr, f_ptr, fence_event_ptr, NULL, FENCE_COMMAND__COMMAND_TYPES__INVITE, COMMAND_ARGS__ADDED);

	MakeFenceRecordInProtoAsIdentifier(sesn_ptr, f_ptr, &fence_record);

	UserRecord	*user_records_invited[1];
	UserRecord 	user_record_invited;

	MakeUserRecordFromSessionInProto(sesn_ptr_newly_invited, &user_record_invited, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF);
	user_records_invited[0]							=	&user_record_invited;
	fence_record.invited_members				=	user_records_invited;
	fence_record.n_invited_members			=	1;

	ListEntry *eptr;
	Session		*sesn_ptr_target;

	for (eptr=f_ptr->fence_user_sessions_list.head; eptr; eptr=eptr->next) {
	  Session *sesn_ptr_listed = SessionOffInstanceHolder(eptr->whatever);
			if ((sesn_ptr_target = sesn_ptr_listed) == sesn_ptr)	sesn_ptr_target = NULL; //prevent double locking
			if	(sesn_ptr_target == sesn_ptr_newly_invited)	continue;	//this user already got an invitation nothing to sync

			_MarshalFenceStateSync(sesn_ptr, sesn_ptr_target, f_ptr, &command_envelope);
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

static inline UFSRVResult *
_MarshalFenceInviteUnchanged (Session *sesn_ptr, unsigned long userid, Fence *f_ptr, DataMessage *data_msg_ptr_orig, unsigned call_flags)
{
	_GENERATE_FENCE_COMMAND_ENVELOPE_INITIALISATION();
	_PrepareMarshalMessageForFence (&envelope_marshal, sesn_ptr, f_ptr, EMPTY_EVENT, data_msg_ptr_orig, FENCE_COMMAND__COMMAND_TYPES__INVITE, COMMAND_ARGS__UNCHANGED);

	MakeFenceRecordInProtoAsIdentifier(sesn_ptr, f_ptr, &fence_record);

	UserRecord	*user_records_invited[1];
	UserRecord 	user_record_invited;

	MakeUserRecordFromUseridInProto (sesn_ptr, userid, &user_record_invited);
	user_records_invited[0]							=	&user_record_invited;
	fence_record.invited_members				=	user_records_invited;
	fence_record.n_invited_members			=	1;

	_MarshalFenceStateSync(sesn_ptr, NULL, f_ptr, &command_envelope);

	free (user_record_invited.ufsrvuid.data);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

/**
 * 	@brief: Marshals a Fence Invite sync message to user. Typically when user wants to regenerate a previously received invite.
 * 	This has slight twist over conventional treatment, params are hand-tweaked, but otherwise uses familiar constructs.
 *
 * 	@param sesn_ptr_inviter: The session that originated the invite request. Can be user or system generated (aka wire)
 *
 * 	@locked sesn_ptr_inviter:
 * 	@locks sesn_ptr_newly_invited:
 *
 */
static inline UFSRVResult *
_MarshalFenceSyncInviteForSelf (Session *sesn_ptr_inviter, Session *sesn_ptr_newly_invited, FenceStateDescriptor *fence_state_ptr, FenceEvent *fence_event_ptr, unsigned call_flags)
{
	_GENERATE_FENCE_COMMAND_ENVELOPE_INITIALISATION();

	Fence							*f_ptr=FENCESTATE_FENCE(fence_state_ptr);

	_PrepareMarshalMessageForFence (&envelope_marshal, sesn_ptr_inviter, f_ptr, fence_event_ptr, NULL, FENCE_COMMAND__COMMAND_TYPES__JOIN, SESSION_USERID(sesn_ptr_inviter)==1?COMMAND_ARGS__INVITED_GEO:COMMAND_ARGS__INVITED);

	//fence_record populated in _Preparexx, but as identifier only
	MakeFenceRecordInProto(sesn_ptr_newly_invited, f_ptr, &fence_record);

	MakeUfsrvUidInProto(&(SESSION_UFSRVUIDSTORE(sesn_ptr_inviter)), &(fence_record.invited_by), true); //ufsrvid by reference
	fence_record.has_invited_by=1;
	fence_record.invited_when						=	fence_state_ptr->when_invited; fence_record.has_invited_when=1;
	fence_record.has_eid	=	0; //todo: this is hack because we dont have access to historic eids at this stage

	_MarshalFenceStateSync(sesn_ptr_newly_invited, NULL, f_ptr, &command_envelope);

	fence_record.invited_by.data = NULL; //ufsrvid by reference

	DestructFenceRecordProto (&fence_record, false);

	_RETURN_RESULT_SESN(sesn_ptr_newly_invited, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

/**
 * 	@brief: Marshals a Fence uninvited message to user and fence. This works with two scenarios:
 * 	1)system initiated univite (eg fence being destructed by system)
 * 	2)user declining an invite
 *
 * 	@param sesn_ptr_originator: The session that originated the request. Can be system user, or individual user (in which case sesn_ptr_originator==sesn_ptr_uninvited)
 *
 * 	@locked sesn_ptr_originator: Except for system user, which doesn't require it because it is a throwaway, ephemeral session
 * 	@locks sesn_ptr_uninvited: downstream
 *
 */
UFSRVResult *
MarshalFenceUnInvitedToUser (Session *sesn_ptr_originator, Session *sesn_ptr_uninvited, Fence *f_ptr, FenceEvent *fence_event_ptr, unsigned sesn_call_flags)
{
	_GENERATE_FENCE_COMMAND_ENVELOPE_INITIALISATION();

	_PrepareMarshalMessageForFence (&envelope_marshal, sesn_ptr_originator, f_ptr, fence_event_ptr, NULL, FENCE_COMMAND__COMMAND_TYPES__LEAVE, COMMAND_ARGS__UNINVITED);
//  UserRecord				user_record_originator;
  fence_command.originator						=	MakeUserRecordFromSessionInProto (sesn_ptr_originator==NULL?GetUfsrvSystemUser():sesn_ptr_originator, &_user_record_originator, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF);
	MakeFenceRecordInProtoAsIdentifier(sesn_ptr_originator, f_ptr, &fence_record);

	UserRecord	*user_records_uninvited[1];
	UserRecord 	user_record_uninvited;

	MakeUserRecordFromSessionInProto(sesn_ptr_uninvited, &user_record_uninvited, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF);
	user_records_uninvited[0]							=	&user_record_uninvited;
	fence_record.invited_members				=	user_records_uninvited;
	fence_record.n_invited_members			=	1;

	ListEntry *eptr;
	Session		*sesn_ptr_target;

	//Signal intended user separately, as they may (should) have already been removed from invite list
	if (sesn_ptr_originator==sesn_ptr_uninvited)	sesn_ptr_target=NULL; //also prevents double locking
	else 																					sesn_ptr_target=sesn_ptr_uninvited;//system initiated

	_MarshalFenceStateSync(sesn_ptr_originator, sesn_ptr_target, f_ptr, &command_envelope);

	for (eptr=f_ptr->fence_user_sessions_list.head; eptr; eptr=eptr->next) {
//		This doesnt apply given the above equality check uninvited==originator. Plus, user shouldn't be on the list
//			if (unlikely((sesn_ptr_target=SESSION_IN_LISTENTRY(eptr))==sesn_ptr_originator))	sesn_ptr_target=NULL; //prevent double locking.
			sesn_ptr_target = SessionOffInstanceHolder(eptr->whatever);
//			if	(sesn_ptr_target==sesn_ptr_uninvited)	continue;	//this user already got the msg; nothing to sync

			_MarshalFenceStateSync(sesn_ptr_originator, sesn_ptr_target, f_ptr, &command_envelope);
	}

	_RETURN_RESULT_SESN(sesn_ptr_originator, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

static inline UFSRVResult *
_VerifyInviteCommand (Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, DataMessage *data_msg_ptr, WebSocketMessage *wsm_ptr_received, unsigned long fence_call_flags)
{
	FenceCommand					*fcmd_ptr	=	data_msg_ptr->ufsrvcommand->fencecommand;
	FenceRecord						*fence_record_ptr	=	fence_record_ptr = fcmd_ptr->fences[0];

	if (fence_record_ptr->n_invited_members<=0 || fence_record_ptr->n_invited_members>CONFIG_MAX_INVITE_SET_SIZE) {
		if (fence_call_flags&FENCE_CALLFLAG_MARSHAL_COMMAND_ERROR) {
			_HandleFenceCommandError (sesn_ptr, &((FenceStateDescriptor){.instance_holder_fence=FENCESTATE_INSTANCE_HOLDER(fence_state_ptr)}),
							wsm_ptr_received, data_msg_ptr, RESCODE_FENCE_INVITE_SIZE, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_INVITE_SIZE)
		}
	}

	return_success:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
}

///// END INVITE \\\\

#endif

//// FENCE NAME \\\\

#if 1
/**
 * 	@brief: The main controller for handling user command for group name's change.
 * 	A pre check on user's ability to edit should have been done prior to invoking this function
 *
 * 	param sesn_ptr: the user session for which the command is executed
 * 	@locked sesn_ptr: by caller
 * 	@locks RW Fence *: by downstream function
 * 	@unlocks: Fence *:
 */
inline static UFSRVResult *
_CommandControllerFenceName (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr)
{
	bool fence_already_locked = false;
  InstanceHolderForFenceStateDescriptor *instance_fstate_ptr;
	FenceStateDescriptor *fstate_ptr;
	FenceEvent 		fence_event 			= {0};
	FenceCommand	*fcmd_ptr;
#define _FENCE_CALL_FLAGS_STATESYNC	(FENCE_CALLFLAG_CHECK_FENCEOWNERSHIP|FENCE_CALLFLAG_KEEP_FENCE_LOCKED)

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	//locks by default
	IsUserAllowedToChangeFence (sesn_ptr,
															data_msg_ptr->ufsrvcommand->fencecommand->fences[0]->fid,
															data_msg_ptr->ufsrvcommand->fencecommand->fences[0]->cname,
															&fence_already_locked,
															_FENCE_CALL_FLAGS_STATESYNC);

	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))	{
	  instance_fstate_ptr  = (InstanceHolderForFenceStateDescriptor *)SESSION_RESULT_USERDATA(sesn_ptr);
	  fstate_ptr           =  FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
	}
	else {
		Fence *f_ptr		=	NULL;
		int 	rescode		=	SESSION_RESULT_CODE(sesn_ptr);

		if (SESSION_RESULT_TYPE_ERROR(sesn_ptr) && !SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST)) {
			//FENCE LOCKED...
			if (SESSION_RESULT_CODE(sesn_ptr) == RESCODE_FENCE_OWNERSHIP) {
        fstate_ptr = FenceStateDescriptorOffInstanceHolder((InstanceHolderForFenceStateDescriptor *)SESSION_RESULT_USERDATA(sesn_ptr));
        f_ptr           = FENCESTATE_FENCE(fstate_ptr);
			  _HandleFenceCommandError (sesn_ptr, fstate_ptr, wsm_ptr_orig, data_msg_ptr, rescode, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);
			} else { //RESCODE_FENCE_FENCE_MEMBERSHIP
			  InstanceHolderForFence *instance_f_ptr = (InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr);
        f_ptr		=	FenceOffInstanceHolder(instance_f_ptr);
			  _HandleFenceCommandError (sesn_ptr, &((FenceStateDescriptor){.instance_holder_fence=instance_f_ptr}), wsm_ptr_orig, data_msg_ptr, rescode, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);
			}
			if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
			goto exit_catch_all;
		}

		if (IS_EMPTY(SESSION_RESULT_USERDATA(sesn_ptr)) && SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST)) {
			//fence doesn't exist. NO lock
			_HandleFenceCommandError (sesn_ptr, NULL, wsm_ptr_orig, data_msg_ptr, rescode, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);
			goto exit_catch_all;
		}

		exit_catch_all:
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)
	}

	//FENCE NOW LOCKED

	fcmd_ptr = data_msg_ptr->ufsrvcommand->fencecommand;

	const char *fname_new;
	if (IS_STR_LOADED((fname_new = fcmd_ptr->fences[0]->fname))) {
		IsUserAllowedToChangeFenceName (sesn_ptr, fstate_ptr, fname_new, _FENCE_CALL_FLAGS_STATESYNC, &fence_event);
		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
			exit_success:
			_MarshalFenceNameUpdate (sesn_ptr, FENCESTATE_FENCE(fstate_ptr), data_msg_ptr, 0, &fence_event);
			if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fstate_ptr), SESSION_RESULT_PTR(sesn_ptr));

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
		}
		else
			_HandleFenceCommandError (sesn_ptr, fstate_ptr, wsm_ptr_orig, data_msg_ptr, SESSION_RESULT_CODE(sesn_ptr), FENCE_COMMAND__COMMAND_TYPES__FNAME, NULL);
	}
	else
	{
		_HandleFenceCommandError (sesn_ptr, fstate_ptr, wsm_ptr_orig, data_msg_ptr, RESCODE_PROG_MISSING_PARAM, FENCE_COMMAND__COMMAND_TYPES__FNAME, NULL);
	}

	exit_unlock:
	if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fstate_ptr), SESSION_RESULT_PTR(sesn_ptr));

	exit_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)


#undef _FENCE_CALL_FLAGS_STATESYNC
}

/**
 * 	@param data_msg_ptr_recieved: wire command as packaged by the originating user
 * 	@locked f_ptr:
 * 	@locked sesn_ptr
 */
inline static UFSRVResult *
_MarshalFenceNameUpdate (Session *sesn_ptr, Fence *f_ptr, DataMessage *data_msg_ptr_recieved, unsigned long call_flags, FenceEvent *fence_event_ptr)
{
	_GENERATE_FENCE_COMMAND_ENVELOPE_INITIALISATION();
	_PrepareMarshalMessageForFence (&envelope_marshal, sesn_ptr, f_ptr, fence_event_ptr, data_msg_ptr_recieved, FENCE_COMMAND__COMMAND_TYPES__FNAME, COMMAND_ARGS__UPDATED);

	//actual delta
	fence_record.fname = FENCE_DNAME(f_ptr);//by reference

	FenceRawSessionList raw_session_list = {0};
	GetRawMemberUsersListForFence (sesn_ptr, InstanceHolderFromClientContext(CLIENT_CTX_DATA(f_ptr)), FENCE_CALLFLAG_INCLUDE_REMOTE_SESSIONS, &raw_session_list);//no locking
	assert (raw_session_list.sessions_sz > 0);

	size_t i = 0;
	for (; i<raw_session_list.sessions_sz; i++) {
    Session *sesn_ptr_listed = SessionOffInstanceHolder(raw_session_list.sessions[i]);
		if (SESSION_ID(sesn_ptr) == SESSION_ID(sesn_ptr_listed)) {
			header.args	=	COMMAND_ARGS__ACCEPTED;//self
			_MarshalCommandToUser(sesn_ptr, NULL, f_ptr, &command_envelope,  uFENCE_V1_IDX);
			header.args	=	COMMAND_ARGS__UPDATED;//restore for others
		} else {
			header.cid	=	SESSION_ID(sesn_ptr_listed);
		  _MarshalCommandToUser(sesn_ptr, sesn_ptr_listed, f_ptr, &command_envelope,  uFENCE_V1_IDX);
		}
	}

	DestructFenceRawSessionList (&raw_session_list, false);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

//// END FENCENAME
#endif


//// AVATAR \\\\

#if 1
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
_CommandControllerFenceAvatar (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr)
{
	bool fence_already_locked = false;
	FenceStateDescriptor *fstate_ptr;
	InstanceHolderForFenceStateDescriptor *instance_fstate_ptr;
	FenceEvent 		fence_event 			= {0};
#define _FENCE_CALL_FLAGS_STATESYNC	(FENCE_CALLFLAG_CHECK_FENCEOWNERSHIP|FENCE_CALLFLAG_KEEP_FENCE_LOCKED)

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	//locks by default
	IsUserAllowedToChangeFence (sesn_ptr,
															data_msg_ptr->ufsrvcommand->fencecommand->fences[0]->fid,
															data_msg_ptr->ufsrvcommand->fencecommand->fences[0]->cname,
															&fence_already_locked,
															_FENCE_CALL_FLAGS_STATESYNC);

	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))	{
	  instance_fstate_ptr = (InstanceHolderForFenceStateDescriptor *)SESSION_RESULT_USERDATA(sesn_ptr);
	  fstate_ptr          = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
	} else {
	  //All errors return f_ptr except where error is RESCODE_FENCE_OWNERSHIP, which returns fstate
		InstanceHolderForFence *instance_f_ptr		=	(InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr);
    Fence *f_ptr                              = NULL;
		int 	rescode                             =	SESSION_RESULT_CODE(sesn_ptr);

		if (SESSION_RESULT_TYPE_ERROR(sesn_ptr) && !SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST)) {
			//FENCE LOCKED... membership or permisions issue
      if (SESSION_RESULT_CODE(sesn_ptr) == RESCODE_FENCE_OWNERSHIP) {
        instance_fstate_ptr = (InstanceHolderForFenceStateDescriptor *)SESSION_RESULT_USERDATA(sesn_ptr);
        f_ptr           = FENCESTATE_FENCE(FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr));
      } else { //RESCODE_FENCE_FENCE_MEMBERSHIP
        f_ptr		=	FenceOffInstanceHolder((InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr));
      }

			_HandleFenceCommandError (sesn_ptr, &((FenceStateDescriptor){.instance_holder_fence=instance_f_ptr}), wsm_ptr_orig, data_msg_ptr, rescode, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);

			if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
			goto exit_catch_all;
		}

		if (IS_EMPTY(SESSION_RESULT_USERDATA(sesn_ptr)) && SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST)) {
			//fence doesn't exist. NO lock
			_HandleFenceCommandError (sesn_ptr, NULL, wsm_ptr_orig, data_msg_ptr, rescode, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);
			goto exit_catch_all;
		}

		exit_catch_all:
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)
	}

	//FENCE NOW LOCKED
	unsigned long 				fence_call_flags_avatar	=	0;

	memset(&fence_event, 0, sizeof(FenceEvent));

	//>>>> AVATAR >>>>>>>>>
	IsUserAllowedToChangeFenceAvatar (sesn_ptr, fstate_ptr, data_msg_ptr, fence_call_flags_avatar, &fence_event);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
		exit_success:
		_MarshalFenceAvatarUpdate (sesn_ptr, FENCESTATE_FENCE(fstate_ptr), data_msg_ptr, 0, &fence_event);

		if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fstate_ptr), SESSION_RESULT_PTR(sesn_ptr));

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
	}

	exit_unlock:
	if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fstate_ptr), SESSION_RESULT_PTR(sesn_ptr));

	exit_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)


#undef _FENCE_CALL_FLAGS_STATESYNC
}

inline static UFSRVResult *
_MarshalFenceAvatarUpdate (Session *sesn_ptr, Fence *f_ptr, DataMessage *data_msg_ptr_recieved, unsigned long call_flags, FenceEvent *fence_event_ptr)
{
	_GENERATE_FENCE_COMMAND_ENVELOPE_INITIALISATION();
	_PrepareMarshalMessageForFence (&envelope_marshal, sesn_ptr, f_ptr, fence_event_ptr, data_msg_ptr_recieved, FENCE_COMMAND__COMMAND_TYPES__AVATAR, COMMAND_ARGS__UPDATED);

	//actual delta
	CollectionDescriptor 	collection_attachment_records	= {0};
	AttachmentRecord 			attachment_record							=	{0};
	AttachmentRecord 			*attachment_records[1]				=	{0};

	attachment_records[0]																=	&attachment_record;
	collection_attachment_records.collection						=	(collection_t **)attachment_records;
	collection_attachment_records.collection_sz					=	1;

	TEMPMakeAttachmentRecordFromAttachmentPointerInProto (data_msg_ptr_recieved->group->avatar, &collection_attachment_records);
	fence_command.attachments														=	attachment_records;
	fence_command.n_attachments													=	1;
	//end delta

	if (IS_PRESENT(fence_event_ptr))	{header.eid=fence_event_ptr->eid; header.has_eid=1;}

	FenceRawSessionList raw_session_list = {0};
	GetRawMemberUsersListForFence (sesn_ptr, InstanceHolderFromClientContext(CLIENT_CTX_DATA(f_ptr)), FENCE_CALLFLAG_INCLUDE_REMOTE_SESSIONS, &raw_session_list);//no locking
	assert (raw_session_list.sessions_sz > 0);

	size_t i = 0;
	for (; i<raw_session_list.sessions_sz; i++) {
	  Session *sesn_ptr_listed = SessionOffInstanceHolder(raw_session_list.sessions[i]);
		if (SESSION_ID(sesn_ptr)==SESSION_ID(sesn_ptr_listed)) {
			header.args	=	COMMAND_ARGS__ACCEPTED;//self
			_MarshalCommandToUser(sesn_ptr, NULL, f_ptr, &command_envelope,  uFENCE_V1_IDX);
			header.args	=	COMMAND_ARGS__UPDATED;//restore for others
		}
		else
		{
			header.cid	=	SESSION_ID(sesn_ptr_listed);
		_MarshalCommandToUser(sesn_ptr, sesn_ptr_listed, f_ptr, &command_envelope,  uFENCE_V1_IDX);
		}
	}

	DestructFenceRawSessionList (&raw_session_list, false);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

//// END AVATAR \\\\

#endif

//// MAX USERS \\\

static void _RestoreFenceMaxMembers (FenceStateDescriptor *fence_state_ptr, FenceRecord *fence_record_ptr);

inline static UFSRVResult *
_CommandControllerFenceMaxMembers(InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr)

{
	bool									fence_already_locked = false;
  InstanceHolderForFenceStateDescriptor *instance_fstate_ptr;
	FenceStateDescriptor *fstate_ptr;
	FenceEvent 		fence_event 			= {0};
	FenceCommand	*fcmd_ptr					=	data_msg_ptr->ufsrvcommand->fencecommand;
	UFSRVResult 	*res_ptr 	__unused;
	#define _FENCE_CALL_FLAGS_FENCEEMAXMEMBERS	(FENCE_CALLFLAG_CHECK_FENCEOWNERSHIP|FENCE_CALLFLAG_KEEP_FENCE_LOCKED)

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	int32_t maxmembers_by_user;
	if (!fcmd_ptr->fences[0]->has_maxmembers)	goto exit_expiry_not_set;
	maxmembers_by_user = fcmd_ptr->fences[0]->maxmembers;
	if (maxmembers_by_user < 0 || maxmembers_by_user > INT_MAX) {
		_HandleFenceCommandError (sesn_ptr, NULL, wsm_ptr_orig, data_msg_ptr, RESCODE_FENCE_INVALID_MAXMEMBERS, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);
		goto exit_catch_all;
	}

		//locks by default
	IsUserAllowedToChangeFence (sesn_ptr, data_msg_ptr->ufsrvcommand->fencecommand->fences[0]->fid, data_msg_ptr->ufsrvcommand->fencecommand->fences[0]->cname, &fence_already_locked, _FENCE_CALL_FLAGS_FENCEEMAXMEMBERS);

	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))	{
	  instance_fstate_ptr = (InstanceHolderForFenceStateDescriptor *)SESSION_RESULT_USERDATA(sesn_ptr);
	  fstate_ptr          = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
	} else if (SESSION_RESULT_TYPE_ERROR(sesn_ptr) && SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_OWNERSHIP)) {
		instance_fstate_ptr = (InstanceHolderForFenceStateDescriptor *)SESSION_RESULT_USERDATA(sesn_ptr);
		fstate_ptr          = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);

		if (!IsUserWithPermission(sesn_ptr, FENCESTATE_FENCE(fstate_ptr), FENCE_PERMISSIONS_MEMBERSHIP_PTR(FENCESTATE_FENCE(fstate_ptr)))) {
			_HandleFenceCommandError (sesn_ptr, &((FenceStateDescriptor){.instance_holder_fence=FENCESTATE_INSTANCE_HOLDER(fstate_ptr)}), wsm_ptr_orig, data_msg_ptr, RESCODE_FENCE_PERMISSION, data_msg_ptr->ufsrvcommand->fencecommand->header->command, _RestoreFenceMaxMembers);
			if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fstate_ptr), SESSION_RESULT_PTR(sesn_ptr));
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_PERMISSION)
		}
	} else {
		Fence *f_ptr		=	FenceOffInstanceHolder((InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr));
		int 	rescode		=	SESSION_RESULT_CODE(sesn_ptr);

		if (SESSION_RESULT_TYPE_ERROR(sesn_ptr) && !SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST)) {
			//FENCE LOCKED... membership issue
			_HandleFenceCommandError (sesn_ptr, &((FenceStateDescriptor){.instance_holder_fence=(InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr)}), wsm_ptr_orig, data_msg_ptr, rescode, data_msg_ptr->ufsrvcommand->fencecommand->header->command, _RestoreFenceMaxMembers);
			if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
			goto exit_catch_all;
		}

		if (IS_EMPTY(SESSION_RESULT_USERDATA(sesn_ptr)) && SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST)) {
			//fence doesn't exist. NO lock
			_HandleFenceCommandError (sesn_ptr, NULL, wsm_ptr_orig, data_msg_ptr, rescode, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);
			goto exit_catch_all;
		}

		exit_catch_all:
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)
	}

	//FENCE NOW LOCKED

	unsigned long 				fence_call_flags_msgexpiry	=	0;

	memset(&fence_event, 0, sizeof(FenceEvent));

	IsUserAllowedToChangeFenceMaxMembers (sesn_ptr, fstate_ptr, maxmembers_by_user, fence_call_flags_msgexpiry, &fence_event);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
	exit_success:
    _MarshalFenceMAxMembersUpdate (sesn_ptr, FENCESTATE_FENCE(fstate_ptr), data_msg_ptr, 0, &fence_event);

    if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fstate_ptr), SESSION_RESULT_PTR(sesn_ptr));

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
	}

	exit_unlock:
	if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fstate_ptr), SESSION_RESULT_PTR(sesn_ptr));
	goto exit_error;

	exit_expiry_not_set:
	//TODO: ERROR MSG

	exit_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

#undef _FENCE_CALL_FLAGS_FENCEEMAXMEMBERS
}

inline static UFSRVResult *
_MarshalFenceMAxMembersUpdate (Session *sesn_ptr, Fence *f_ptr, DataMessage *data_msg_ptr_received, unsigned long call_flags, FenceEvent *fence_event_ptr)
{
	_GENERATE_FENCE_COMMAND_ENVELOPE_INITIALISATION();
	_PrepareMarshalMessageForFence (&envelope_marshal, sesn_ptr, f_ptr, fence_event_ptr, data_msg_ptr_received, FENCE_COMMAND__COMMAND_TYPES__MAXMEMBERS, COMMAND_ARGS__UPDATED);

	//actual delta
	fence_record.maxmembers	=	FENCE_MAX_MEMBERS(f_ptr); fence_record.has_maxmembers=1;
	//end delta

	if (IS_PRESENT(fence_event_ptr))	{header.eid=fence_event_ptr->eid; header.has_eid=1;}

	FenceRawSessionList raw_session_list = {0};
	GetRawMemberUsersListForFence (sesn_ptr, InstanceHolderFromClientContext(CLIENT_CTX_DATA(f_ptr)), FENCE_CALLFLAG_INCLUDE_REMOTE_SESSIONS, &raw_session_list);//no locking
	assert (raw_session_list.sessions_sz > 0);

	size_t i = 0;
	for (; i<raw_session_list.sessions_sz; i++) {
    Session *sesn_ptr_listed = SessionOffInstanceHolder(raw_session_list.sessions[i]);
		if (SESSION_ID(sesn_ptr) == SESSION_ID(sesn_ptr_listed)) {
			header.args	=	COMMAND_ARGS__ACCEPTED;//self
			_MarshalCommandToUser(sesn_ptr, NULL, f_ptr, &command_envelope,  uFENCE_V1_IDX);
			header.args	=	COMMAND_ARGS__UPDATED;//restore for others
		} else {
			header.cid	=	SESSION_ID(sesn_ptr_listed);
			_MarshalCommandToUser(sesn_ptr, sesn_ptr_listed, f_ptr, &command_envelope,  uFENCE_V1_IDX);
		}
	}

	DestructFenceRawSessionList (&raw_session_list, false);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

static void
_RestoreFenceMaxMembers (FenceStateDescriptor *fence_state_ptr, FenceRecord *fence_record_ptr)
{
	fence_record_ptr->maxmembers=FENCE_MAX_MEMBERS(FENCESTATE_FENCE(fence_state_ptr));
	fence_record_ptr->has_maxmembers=1;
}

////

//// JoinMode \\\

static void _RestoreFenceJoinMode (FenceStateDescriptor *fence_state_ptr, FenceRecord *fence_record_ptr);

inline static UFSRVResult *
_CommandControllerFenceJoinMode(InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr)

{
//	bool									fence_already_locked= false;
//	FenceStateDescriptor *fence_state_ptr;
//	FenceEvent 		fence_event 			= {0};
//	FenceCommand	*fcmd_ptr					=	data_msg_ptr->ufsrvcommand->fencecommand;
//	UFSRVResult 	*res_ptr 	__unused;
//	FenceRecord 	*fence_record_ptr	=	NULL;
//#define _FENCE_CALL_FLAGS_FENCEEMAXMEMBERS	(FENCE_CALLFLAG_CHECK_FENCEOWNERSHIP|FENCE_CALLFLAG_KEEP_FENCE_LOCKED)
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
//
//	int32_t maxmembers_by_user;
//	if (!fcmd_ptr->fences[0]->has_maxmembers)	goto exit_expiry_not_set;
//	maxmembers_by_user = fcmd_ptr->fences[0]->maxmembers;
//	if (maxmembers_by_user<0 || maxmembers_by_user > INT_MAX) {
//		_HandleFenceCommandError (sesn_ptr, NULL, wsm_ptr_orig, data_msg_ptr, RESCODE_FENCE_INVALID_MAXMEMBERS, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);
//		goto exit_catch_all;
//	}
//
//	//locks by default
//	IsUserAllowedToChangeFence (sesn_ptr, data_msg_ptr->ufsrvcommand->fencecommand->fences[0]->fid, data_msg_ptr->ufsrvcommand->fencecommand->fences[0]->cname, &fence_already_locked, _FENCE_CALL_FLAGS_FENCEEMAXMEMBERS);
//
//	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))	fence_state_ptr=(FenceStateDescriptor *)SESSION_RESULT_USERDATA(sesn_ptr);
//	else if (SESSION_RESULT_TYPE_ERROR(sesn_ptr) && SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_OWNERSHIP)) {
//		fence_state_ptr=(FenceStateDescriptor *)SESSION_RESULT_USERDATA(sesn_ptr);
//		if (IsUserWithPermission(sesn_ptr, FENCESTATE_FENCE(fence_state_ptr), FENCE_PERMISSIONS_MEMBERSHIP_PTR(FENCESTATE_FENCE(fence_state_ptr)))) {
//			_HandleFenceCommandError (sesn_ptr, &((FenceStateDescriptor){.fence=FENCESTATE_FENCE(fence_state_ptr)}), wsm_ptr_orig, data_msg_ptr, RESCODE_FENCE_PERMISSION, data_msg_ptr->ufsrvcommand->fencecommand->header->command, _RestoreFenceMaxMembers);
//			if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fence_state_ptr), SESSION_RESULT_PTR(sesn_ptr));
//			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_PERMISSION);
//		}
//	} else {
//		Fence *f_ptr		=	(Fence *)SESSION_RESULT_USERDATA(sesn_ptr);
//		int 	rescode		=	SESSION_RESULT_CODE(sesn_ptr);
//
//		if (SESSION_RESULT_TYPE_ERROR(sesn_ptr) && !SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST))
//		{
//			//FENCE LOCKED... membership or permissions issue
//			_HandleFenceCommandError (sesn_ptr, &((FenceStateDescriptor){.fence=f_ptr}), wsm_ptr_orig, data_msg_ptr, rescode, data_msg_ptr->ufsrvcommand->fencecommand->header->command, _RestoreFenceMaxMembers);
//			if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
//			goto exit_catch_all;
//		}
//		if (IS_EMPTY(SESSION_RESULT_USERDATA(sesn_ptr)) && SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST))
//		{
//			//fence doesn't exist. NO lock
//			_HandleFenceCommandError (sesn_ptr, NULL, wsm_ptr_orig, data_msg_ptr, rescode, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);
//			goto exit_catch_all;
//		}
//
//		exit_catch_all:
//		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);
//	}
//
//	//FENCE NOW LOCKED
//
//	unsigned long 				fence_call_flags_msgexpiry	=	0;
//
//	memset(&fence_event, 0, sizeof(FenceEvent));
//
//	IsUserAllowedToChangeFenceMaxMembers (sesn_ptr, fence_state_ptr, maxmembers_by_user, fence_call_flags_msgexpiry, &fence_event);
//	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))
//	{
//		exit_success:
//		_MarshalFenceMAxMembersUpdate (sesn_ptr, FENCESTATE_FENCE(fence_state_ptr), data_msg_ptr, 0, &fence_event);
//
//		if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fence_state_ptr), SESSION_RESULT_PTR(sesn_ptr));
//
//		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
//	}
//
//	exit_unlock:
//	if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fence_state_ptr), SESSION_RESULT_PTR(sesn_ptr));
//	goto exit_error;
//
//	exit_expiry_not_set:
//	//TODO: ERROR MSG

	exit_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

#undef _FENCE_CALL_FLAGS_FENCEEMAXMEMBERS
}

inline static UFSRVResult *
_MarshalFenceJoinModeUpdate (Session *sesn_ptr, Fence *f_ptr, DataMessage *data_msg_ptr_received, unsigned long call_flags, FenceEvent *fence_event_ptr)
{
	_GENERATE_FENCE_COMMAND_ENVELOPE_INITIALISATION();
	_PrepareMarshalMessageForFence (&envelope_marshal, sesn_ptr, f_ptr, fence_event_ptr, data_msg_ptr_received, FENCE_COMMAND__COMMAND_TYPES__JOIN_MODE, COMMAND_ARGS__UPDATED);

//	//actual delta
//	fence_record.join_mode	=	FENCE_MAX_MEMBERS(f_ptr); fence_record.has_join_mode=1;
//	//end delta
//
//	if (IS_PRESENT(fence_event_ptr))	{header.eid=fence_event_ptr->eid; header.has_eid=1;}
//
//	FenceRawSessionList raw_session_list={0};
//	GetRawMemberUsersListForFence (sesn_ptr, f_ptr, FENCE_CALLFLAG_INCLUDE_REMOTE_SESSIONS, &raw_session_list);//no locking
//	assert (raw_session_list.sessions_sz>0);
//
//	size_t i=0;
//	for (; i<raw_session_list.sessions_sz; i++)
//	{
//		if (SESSION_ID(sesn_ptr)==SESSION_ID(raw_session_list.sessions[i]))
//		{
//			header.args	=	COMMAND_ARGS__ACCEPTED;//self
//			_MarshalCommandToUser(sesn_ptr, NULL, f_ptr, &command_envelope,  uFENCE_V1_IDX);
//			header.args	=	COMMAND_ARGS__UPDATED;//restore for others
//		}
//		else
//		{
//			header.cid	=	SESSION_ID(raw_session_list.sessions[i]);
//			_MarshalCommandToUser(sesn_ptr, raw_session_list.sessions[i], f_ptr, &command_envelope,  uFENCE_V1_IDX);
//		}
//	}
//
//	DestructFenceRawSessionList (&raw_session_list, false);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

__unused static void
_RestoreFenceJoinMode(FenceStateDescriptor *fence_state_ptr, FenceRecord *fence_record_ptr)
{
	fence_record_ptr->maxmembers=FENCE_MAX_MEMBERS(FENCESTATE_FENCE(fence_state_ptr));
	fence_record_ptr->has_maxmembers=1;
}

////


//// DeliveryMode \\\

static void _RestoreFenceDeliveryMode (FenceStateDescriptor *fence_state_ptr, FenceRecord *fence_record_ptr);

inline static UFSRVResult *
_CommandControllerFenceDeliveryMode(InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr)

{
	bool									fence_already_locked = false;
  InstanceHolderForFenceStateDescriptor *instance_fstate_ptr;
	FenceStateDescriptor  *fstate_ptr;
	FenceEvent 						fence_event 			= {0};
	FenceCommand					*fcmd_ptr					=	data_msg_ptr->ufsrvcommand->fencecommand;
	UFSRVResult 					*res_ptr 	__unused;
#define _FENCE_CALL_FLAGS_FENCE_DELIVERYMODE	(FENCE_CALLFLAG_CHECK_FENCEOWNERSHIP|FENCE_CALLFLAG_KEEP_FENCE_LOCKED)

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	if (!fcmd_ptr->fences[0]->has_delivery_mode)	goto exit_delivery_mode_not_set;
	if (fcmd_ptr->fences[0]->delivery_mode < FENCE_RECORD__DELIVERY_MODE__MANY || fcmd_ptr->fences[0]->delivery_mode>FENCE_RECORD__DELIVERY_MODE__BROADCAST_ONEWAY) goto exit_invalid_delivery_mode;

//	//locks by default
	IsUserAllowedToChangeFence (sesn_ptr, data_msg_ptr->ufsrvcommand->fencecommand->fences[0]->fid, data_msg_ptr->ufsrvcommand->fencecommand->fences[0]->cname, &fence_already_locked, _FENCE_CALL_FLAGS_FENCE_DELIVERYMODE);

	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))	{
	  instance_fstate_ptr = (InstanceHolderForFenceStateDescriptor *)SESSION_RESULT_USERDATA(sesn_ptr);
	  fstate_ptr          = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
	} else if (SESSION_RESULT_TYPE_ERROR(sesn_ptr) && SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_OWNERSHIP)) {
		instance_fstate_ptr = (InstanceHolderForFenceStateDescriptor *)SESSION_RESULT_USERDATA(sesn_ptr);
		FenceStateDescriptor *fstate_ptr = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
    //currently only owner is allowed to change delivery mode. No permission associated with that
    _HandleFenceCommandError (sesn_ptr, FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr), wsm_ptr_orig, data_msg_ptr, RESCODE_FENCE_PERMISSION, data_msg_ptr->ufsrvcommand->fencecommand->header->command, _RestoreFenceMaxMembers);
    if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fstate_ptr), SESSION_RESULT_PTR(sesn_ptr));

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_PERMISSION)
	} else {
		InstanceHolderForFence *instance_f_ptr		=	(InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr);
		int 	rescode		=	SESSION_RESULT_CODE(sesn_ptr);

		if (SESSION_RESULT_TYPE_ERROR(sesn_ptr) && !SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST)) {
			//FENCE LOCKED... membership
			_HandleFenceCommandError (sesn_ptr, &((FenceStateDescriptor){.instance_holder_fence=instance_f_ptr}), wsm_ptr_orig, data_msg_ptr, rescode, data_msg_ptr->ufsrvcommand->fencecommand->header->command, _RestoreFenceDeliveryMode);
			if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FenceOffInstanceHolder(instance_f_ptr), SESSION_RESULT_PTR(sesn_ptr));
			goto exit_catch_all;
		}

		if (IS_EMPTY(SESSION_RESULT_USERDATA(sesn_ptr)) && SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST)) {
			//fence doesn't exist. NO lock
			_HandleFenceCommandError (sesn_ptr, NULL, wsm_ptr_orig, data_msg_ptr, rescode, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);
			goto exit_catch_all;
		}

		exit_catch_all:
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)
	}
//
	//FENCE NOW LOCKED

	unsigned long 				fence_call_flags_msgexpiry	=	0;

	memset(&fence_event, 0, sizeof(FenceEvent));

	IsUserAllowedToChangeFenceDeliveryMode (sesn_ptr, fstate_ptr, fcmd_ptr->fences[0]->delivery_mode, fence_call_flags_msgexpiry, &fence_event);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
		exit_success:
		_MarshalFenceDeliveryModeUpdate (sesn_ptr, FENCESTATE_FENCE(fstate_ptr), data_msg_ptr, 0, &fence_event);

		if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fstate_ptr), SESSION_RESULT_PTR(sesn_ptr));

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
	}

	exit_unlock:
	if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fstate_ptr), SESSION_RESULT_PTR(sesn_ptr));
	goto exit_error;
//
	exit_delivery_mode_not_set:
		_HandleFenceCommandError (sesn_ptr, NULL, wsm_ptr_orig, data_msg_ptr, RESCODE_FENCE_MISSING_PARAM, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);
		goto exit_error;

	exit_invalid_delivery_mode:
	_HandleFenceCommandError (sesn_ptr, NULL, wsm_ptr_orig, data_msg_ptr, RESCODE_FENCE_INVALID_DELIVERY_MODE, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);
	goto exit_error;

	exit_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

#undef _FENCE_CALL_FLAGS_FENCEEMAXMEMBERS
}

inline static UFSRVResult *
_MarshalFenceDeliveryModeUpdate (Session *sesn_ptr, Fence *f_ptr, DataMessage *data_msg_ptr_received, unsigned long call_flags, FenceEvent *fence_event_ptr)
{
	_GENERATE_FENCE_COMMAND_ENVELOPE_INITIALISATION();
	_PrepareMarshalMessageForFence (&envelope_marshal, sesn_ptr, f_ptr, fence_event_ptr, data_msg_ptr_received, FENCE_COMMAND__COMMAND_TYPES__DELIVERY_MODE, COMMAND_ARGS__UPDATED);

	//actual delta
  MakeFenceDeliveryModeInProto (f_ptr, &fence_record);
	//end delta

	if (IS_PRESENT(fence_event_ptr))	{header.eid=fence_event_ptr->eid; header.has_eid=1;}

	FenceRawSessionList raw_session_list = {0};
	GetRawMemberUsersListForFence (sesn_ptr, InstanceHolderFromClientContext(CLIENT_CTX_DATA(f_ptr)), FENCE_CALLFLAG_INCLUDE_REMOTE_SESSIONS, &raw_session_list);//no locking
	assert (raw_session_list.sessions_sz > 0);

	size_t i = 0;
	for (; i<raw_session_list.sessions_sz; i++) {
    Session *sesn_ptr_listed = SessionOffInstanceHolder(raw_session_list.sessions[i]);
		if (SESSION_ID(sesn_ptr)==SESSION_ID(sesn_ptr_listed)) {
			header.args	=	COMMAND_ARGS__ACCEPTED;//self
			_MarshalCommandToUser(sesn_ptr, NULL, f_ptr, &command_envelope,  uFENCE_V1_IDX);
			header.args	=	COMMAND_ARGS__UPDATED;//restore for others
		} else {
			header.cid	=	SESSION_ID(sesn_ptr_listed);
			_MarshalCommandToUser(sesn_ptr, sesn_ptr_listed, f_ptr, &command_envelope,  uFENCE_V1_IDX);
		}
	}

	DestructFenceRawSessionList (&raw_session_list, false);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

static void
_RestoreFenceDeliveryMode(FenceStateDescriptor *fence_state_ptr, FenceRecord *fence_record_ptr)
{
//	fence_record_ptr->maxmembers=FENCE_MAX_MEMBERS(FENCESTATE_FENCE(fence_state_ptr));
//	fence_record_ptr->has_maxmembers=1;
}

////

//// PrivacyMode \\\

static void _RestoreFencePrivacyMode (FenceStateDescriptor *fence_state_ptr, FenceRecord *fence_record_ptr);

inline static UFSRVResult *
_CommandControllerFencePrivacyMode(InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr)
{
//	bool									fence_already_locked= false;
//	FenceStateDescriptor *fence_state_ptr;
//	FenceEvent 		fence_event 			= {0};
//	FenceCommand	*fcmd_ptr					=	data_msg_ptr->ufsrvcommand->fencecommand;
//	UFSRVResult 	*res_ptr 	__unused;
//	FenceRecord 	*fence_record_ptr	=	NULL;
//#define _FENCE_CALL_FLAGS_FENCEEMAXMEMBERS	(FENCE_CALLFLAG_CHECK_FENCEOWNERSHIP|FENCE_CALLFLAG_KEEP_FENCE_LOCKED)
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
//
//	int32_t maxmembers_by_user;
//	if (!fcmd_ptr->fences[0]->has_maxmembers)	goto exit_expiry_not_set;
//	maxmembers_by_user = fcmd_ptr->fences[0]->maxmembers;
//	if (maxmembers_by_user<0 || maxmembers_by_user > INT_MAX) {
//		_HandleFenceCommandError (sesn_ptr, NULL, wsm_ptr_orig, data_msg_ptr, RESCODE_FENCE_INVALID_MAXMEMBERS, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);
//		goto exit_catch_all;
//	}
//
//	//locks by default
//	IsUserAllowedToChangeFence (sesn_ptr, data_msg_ptr->ufsrvcommand->fencecommand->fences[0]->fid, data_msg_ptr->ufsrvcommand->fencecommand->fences[0]->cname, &fence_already_locked, _FENCE_CALL_FLAGS_FENCEEMAXMEMBERS);
//
//	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))	fence_state_ptr=(FenceStateDescriptor *)SESSION_RESULT_USERDATA(sesn_ptr);
//	else if (SESSION_RESULT_TYPE_ERROR(sesn_ptr) && SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_OWNERSHIP)) {
//		fence_state_ptr=(FenceStateDescriptor *)SESSION_RESULT_USERDATA(sesn_ptr);
//		if (IsUserWithPermission(sesn_ptr, FENCESTATE_FENCE(fence_state_ptr), FENCE_PERMISSIONS_MEMBERSHIP_PTR(FENCESTATE_FENCE(fence_state_ptr)))) {
//			_HandleFenceCommandError (sesn_ptr, &((FenceStateDescriptor){.fence=FENCESTATE_FENCE(fence_state_ptr)}), wsm_ptr_orig, data_msg_ptr, RESCODE_FENCE_PERMISSION, data_msg_ptr->ufsrvcommand->fencecommand->header->command, _RestoreFenceMaxMembers);
//			if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fence_state_ptr), SESSION_RESULT_PTR(sesn_ptr));
//			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_PERMISSION);
//		}
//	} else {
//		Fence *f_ptr		=	(Fence *)SESSION_RESULT_USERDATA(sesn_ptr);
//		int 	rescode		=	SESSION_RESULT_CODE(sesn_ptr);
//
//		if (SESSION_RESULT_TYPE_ERROR(sesn_ptr) && !SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST))
//		{
//			//FENCE LOCKED... membership or permissions issue
//			_HandleFenceCommandError (sesn_ptr, &((FenceStateDescriptor){.fence=f_ptr}), wsm_ptr_orig, data_msg_ptr, rescode, data_msg_ptr->ufsrvcommand->fencecommand->header->command, _RestoreFenceMaxMembers);
//			if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
//			goto exit_catch_all;
//		}
//		if (IS_EMPTY(SESSION_RESULT_USERDATA(sesn_ptr)) && SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST))
//		{
//			//fence doesn't exist. NO lock
//			_HandleFenceCommandError (sesn_ptr, NULL, wsm_ptr_orig, data_msg_ptr, rescode, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);
//			goto exit_catch_all;
//		}
//
//		exit_catch_all:
//		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);
//	}
//
//	//FENCE NOW LOCKED
//
//	unsigned long 				fence_call_flags_msgexpiry	=	0;
//
//	memset(&fence_event, 0, sizeof(FenceEvent));
//
//	IsUserAllowedToChangeFenceMaxMembers (sesn_ptr, fence_state_ptr, maxmembers_by_user, fence_call_flags_msgexpiry, &fence_event);
//	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))
//	{
//		exit_success:
//		_MarshalFenceMAxMembersUpdate (sesn_ptr, FENCESTATE_FENCE(fence_state_ptr), data_msg_ptr, 0, &fence_event);
//
//		if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fence_state_ptr), SESSION_RESULT_PTR(sesn_ptr));
//
//		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
//	}
//
//	exit_unlock:
//	if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fence_state_ptr), SESSION_RESULT_PTR(sesn_ptr));
//	goto exit_error;
//
//	exit_expiry_not_set:
//	//TODO: ERROR MSG

	exit_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

#undef _FENCE_CALL_FLAGS_FENCEEMAXMEMBERS
}

inline static UFSRVResult *
_MarshalFencePrivacyModeUpdate (Session *sesn_ptr, Fence *f_ptr, DataMessage *data_msg_ptr_received, unsigned long call_flags, FenceEvent *fence_event_ptr)
{
	_GENERATE_FENCE_COMMAND_ENVELOPE_INITIALISATION();
	_PrepareMarshalMessageForFence (&envelope_marshal, sesn_ptr, f_ptr, fence_event_ptr, data_msg_ptr_received, FENCE_COMMAND__COMMAND_TYPES__PRIVACY_MODE, COMMAND_ARGS__UPDATED);

//	//actual delta
//	fence_record.join_mode	=	FENCE_MAX_MEMBERS(f_ptr); fence_record.has_join_mode=1;
//	//end delta
//
//	if (IS_PRESENT(fence_event_ptr))	{header.eid=fence_event_ptr->eid; header.has_eid=1;}
//
//	FenceRawSessionList raw_session_list={0};
//	GetRawMemberUsersListForFence (sesn_ptr, f_ptr, FENCE_CALLFLAG_INCLUDE_REMOTE_SESSIONS, &raw_session_list);//no locking
//	assert (raw_session_list.sessions_sz>0);
//
//	size_t i=0;
//	for (; i<raw_session_list.sessions_sz; i++)
//	{
//		if (SESSION_ID(sesn_ptr)==SESSION_ID(raw_session_list.sessions[i]))
//		{
//			header.args	=	COMMAND_ARGS__ACCEPTED;//self
//			_MarshalCommandToUser(sesn_ptr, NULL, f_ptr, &command_envelope,  uFENCE_V1_IDX);
//			header.args	=	COMMAND_ARGS__UPDATED;//restore for others
//		}
//		else
//		{
//			header.cid	=	SESSION_ID(raw_session_list.sessions[i]);
//			_MarshalCommandToUser(sesn_ptr, raw_session_list.sessions[i], f_ptr, &command_envelope,  uFENCE_V1_IDX);
//		}
//	}
//
//	DestructFenceRawSessionList (&raw_session_list, false);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

__unused static void
_RestoreFencePrivacyMode(FenceStateDescriptor *fence_state_ptr, FenceRecord *fence_record_ptr)
{
	fence_record_ptr->maxmembers=FENCE_MAX_MEMBERS(FENCESTATE_FENCE(fence_state_ptr));
	fence_record_ptr->has_maxmembers=1;
}

////

//// EXPIRY \\\\\

static void _RestoreFenceExpiryTimer (FenceStateDescriptor *fence_state_ptr, FenceRecord *fence_record_ptr);

inline static UFSRVResult *
_CommandControllerFenceMessageExpiry (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr)

{
	bool									fence_already_locked = false;
	FenceStateDescriptor *fstate_ptr;
	FenceEvent 		fence_event 			= {0};
	FenceCommand	*fcmd_ptr					=	data_msg_ptr->ufsrvcommand->fencecommand;
	UFSRVResult 	*res_ptr 	__unused;
#define _FENCE_CALL_FLAGS_FENCEEXPIRY	(FENCE_CALLFLAG_CHECK_FENCEOWNERSHIP|FENCE_CALLFLAG_KEEP_FENCE_LOCKED)

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	if (!fcmd_ptr->fences[0]->has_expire_timer)	goto exit_expiry_not_set;

	//locks by default
	IsUserAllowedToChangeFence (sesn_ptr,
															data_msg_ptr->ufsrvcommand->fencecommand->fences[0]->fid,
															data_msg_ptr->ufsrvcommand->fencecommand->fences[0]->cname,
															&fence_already_locked,
															_FENCE_CALL_FLAGS_FENCEEXPIRY);

	InstanceHolderForFenceStateDescriptor *instance_fstate_ptr = NULL;

	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))	{
	  instance_fstate_ptr = (InstanceHolderForFenceStateDescriptor *)SESSION_RESULT_USERDATA(sesn_ptr);
	  fstate_ptr = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
	} else {
		Fence *f_ptr		=	NULL;
    InstanceHolderForFence *instance_f_ptr = NULL;
		int 	rescode		=	SESSION_RESULT_CODE(sesn_ptr);

		if (SESSION_RESULT_TYPE_ERROR(sesn_ptr) && !SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST)) {
			//FENCE LOCKED... membership or permissions issue
      if (SESSION_RESULT_CODE(sesn_ptr) == RESCODE_FENCE_OWNERSHIP) {
        instance_fstate_ptr = (InstanceHolderForFenceStateDescriptor *)SESSION_RESULT_USERDATA(sesn_ptr);
        fstate_ptr = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
        f_ptr           = FENCESTATE_FENCE(fstate_ptr);
      } else { //RESCODE_FENCE_FENCE_MEMBERSHIP
        instance_f_ptr		=	(InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr);
        f_ptr = FenceOffInstanceHolder(instance_f_ptr);
      }

      if (SESSION_RESULT_CODE(sesn_ptr) == RESCODE_FENCE_OWNERSHIP) {
        _HandleFenceCommandError (sesn_ptr, fstate_ptr, wsm_ptr_orig, data_msg_ptr, rescode, data_msg_ptr->ufsrvcommand->fencecommand->header->command, _RestoreFenceExpiryTimer);
      } else { //RESCODE_FENCE_FENCE_MEMBERSHIP
        _HandleFenceCommandError (sesn_ptr, &((FenceStateDescriptor){.instance_holder_fence=FENCESTATE_INSTANCE_HOLDER(fstate_ptr)}), wsm_ptr_orig, data_msg_ptr, rescode, data_msg_ptr->ufsrvcommand->fencecommand->header->command, _RestoreFenceExpiryTimer);
      }
			if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
			goto exit_catch_all;
		}

		if (IS_EMPTY(SESSION_RESULT_USERDATA(sesn_ptr)) && SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST)) {
			//fence doesn't exist. NO lock
			_HandleFenceCommandError (sesn_ptr, NULL, wsm_ptr_orig, data_msg_ptr, rescode, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);
			goto exit_catch_all;
		}

		exit_catch_all:
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)
	}

	//FENCE NOW LOCKED

	unsigned long 				fence_call_flags_msgexpiry	=	0;

	memset(&fence_event, 0, sizeof(FenceEvent));

	IsUserAllowedToChangeFenceMessageExpiry (sesn_ptr, fstate_ptr, data_msg_ptr->ufsrvcommand->fencecommand->fences[0]->expire_timer, fence_call_flags_msgexpiry, &fence_event);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
		exit_success:
		_MarshalFenceMessageExpiryUpdate (sesn_ptr, FENCESTATE_FENCE(fstate_ptr), data_msg_ptr, 0, &fence_event);

		if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fstate_ptr), SESSION_RESULT_PTR(sesn_ptr));

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
	}

	exit_unlock:
	if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fstate_ptr), SESSION_RESULT_PTR(sesn_ptr));
	goto exit_error;

	exit_expiry_not_set:
	//TODO: ERROR MSG

	exit_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

#undef _FENCE_CALL_FLAGS_FENCEEXPIRY
}

static void
_RestoreFenceExpiryTimer (FenceStateDescriptor *fence_state_ptr, FenceRecord *fence_record_ptr)
{
	fence_record_ptr->expire_timer=FENCE_MSG_EXPIRY(FENCESTATE_FENCE(fence_state_ptr));
	fence_record_ptr->has_expire_timer=1;
}

inline static UFSRVResult *
_MarshalFenceMessageExpiryUpdate (Session *sesn_ptr, Fence *f_ptr, DataMessage *data_msg_ptr_received, unsigned long call_flags, FenceEvent *fence_event_ptr)
{
	_GENERATE_FENCE_COMMAND_ENVELOPE_INITIALISATION();
	_PrepareMarshalMessageForFence (&envelope_marshal, sesn_ptr, f_ptr, fence_event_ptr, data_msg_ptr_received, FENCE_COMMAND__COMMAND_TYPES__EXPIRY, COMMAND_ARGS__UPDATED);

	//actual delta
	fence_record.expire_timer	=	FENCE_MSG_EXPIRY(f_ptr); fence_record.has_expire_timer=1;//in millis
	//end delta

	if (IS_PRESENT(fence_event_ptr))	{header.eid=fence_event_ptr->eid; header.has_eid=1;}

	FenceRawSessionList raw_session_list = {0};
	GetRawMemberUsersListForFence (sesn_ptr, InstanceHolderFromClientContext(CLIENT_CTX_DATA(f_ptr)), FENCE_CALLFLAG_INCLUDE_REMOTE_SESSIONS, &raw_session_list);//no locking
	assert (raw_session_list.sessions_sz > 0);

	size_t i = 0;
	for (; i<raw_session_list.sessions_sz; i++) {
    Session *sesn_ptr_listed = SessionOffInstanceHolder(raw_session_list.sessions[i]);
		if (SESSION_ID(sesn_ptr) == SESSION_ID(sesn_ptr_listed)) {
			header.args	=	COMMAND_ARGS__ACCEPTED;//self
			_MarshalCommandToUser(sesn_ptr, NULL, f_ptr, &command_envelope,  uFENCE_V1_IDX);
			header.args	=	COMMAND_ARGS__UPDATED;//restore for others
		} else {
			header.cid	=	SESSION_ID(sesn_ptr_listed);
		  _MarshalCommandToUser(sesn_ptr, sesn_ptr_listed, f_ptr, &command_envelope,  uFENCE_V1_IDX);
		}
	}

	DestructFenceRawSessionList (&raw_session_list, false);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

//// END EXPIRY \\\


//// PERMISSION \\


inline static UFSRVResult *_MarshalFencePermissionUpdate (Session *sesn_ptr, FencePermissionContextData *context_ptr, DataMessage *data_msg_ptr_received, unsigned long call_flags, FenceEvent *fence_event_ptr);

inline static UFSRVResult *
_CommandControllerFencePermission (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr)

{
	bool fence_already_locked = false;
	FenceStateDescriptor *fstate_ptr;
  InstanceHolderForFenceStateDescriptor *instance_fstate_ptr;
	FenceEvent 		fence_event 			= {0};
	UFSRVResult 	*res_ptr 	__unused;
#define _FENCE_CALL_FLAGS_FENCEPERMISSION	(FENCE_CALLFLAG_CHECK_FENCEOWNERSHIP|FENCE_CALLFLAG_KEEP_FENCE_LOCKED)

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	//locks by default
	IsUserAllowedToChangeFence (sesn_ptr,
															data_msg_ptr->ufsrvcommand->fencecommand->fences[0]->fid,
															data_msg_ptr->ufsrvcommand->fencecommand->fences[0]->cname,
															&fence_already_locked,
															_FENCE_CALL_FLAGS_FENCEPERMISSION);

	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))	{
	  instance_fstate_ptr = (InstanceHolderForFenceStateDescriptor *)SESSION_RESULT_USERDATA(sesn_ptr);
	  fstate_ptr          = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
	} else {
		int 	rescode		=	SESSION_RESULT_CODE(sesn_ptr);
    Fence *f_ptr    = NULL;

		if (SESSION_RESULT_TYPE_ERROR(sesn_ptr) && !SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST)) {
			//FENCE LOCKED... membership or permissions issue
      if (SESSION_RESULT_CODE(sesn_ptr) == RESCODE_FENCE_OWNERSHIP) {
        fstate_ptr = FenceStateDescriptorOffInstanceHolder((InstanceHolderForFenceStateDescriptor *)SESSION_RESULT_USERDATA(sesn_ptr));
        f_ptr           = FENCESTATE_FENCE(fstate_ptr);
      } else { //RESCODE_FENCE_FENCE_MEMBERSHIP
        f_ptr		=	FenceOffInstanceHolder((InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr));
      }

      _HandleFenceCommandError (sesn_ptr, &((FenceStateDescriptor){.instance_holder_fence=(InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr)}), wsm_ptr_orig, data_msg_ptr, rescode, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL/*_RestoreFenceExpiryTimer*/);

			if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
			goto exit_catch_all;
		}

		if (IS_EMPTY(SESSION_RESULT_USERDATA(sesn_ptr)) && SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST)) {
			//fence doesn't exist. NO lock
			_HandleFenceCommandError (sesn_ptr, NULL, wsm_ptr_orig, data_msg_ptr, rescode, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);
			goto exit_catch_all;
		}

		exit_catch_all:
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)
	}

	//FENCE NOW LOCKED

	unsigned long 					fence_call_flags_permission	=	0;
	FencePermission 				*permission_ptr							=	NULL;
	FenceRecord__Permission	*fence_record_permission		=	NULL;

	if ((ValidateFencePermissionCommandFromProto (sesn_ptr, data_msg_ptr->ufsrvcommand->fencecommand, FENCESTATE_FENCE(fstate_ptr), &permission_ptr, &fence_record_permission))!=0) {
		goto	exit_unlock;
	}

	UFSRVResult * (*permission_op_callback)(Session *, Fence *, FencePermission *, unsigned long, FenceEvent *);

	if (data_msg_ptr->ufsrvcommand->fencecommand->header->args == COMMAND_ARGS__ADDED)				permission_op_callback = AddUserToFencePermissions;
	else if (data_msg_ptr->ufsrvcommand->fencecommand->header->args == COMMAND_ARGS__DELETED)	permission_op_callback = RemoveUserFromFencePermissions;
	else {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', command_arg:'%d'}: ERROR: INVALID COMMAND ARG", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), data_msg_ptr->ufsrvcommand->fencecommand->header->args);
		goto	exit_unlock;
	}


	if (UfsrvUidIsEqual((const UfsrvUid *)fence_record_permission->users[0]->ufsrvuid.data, &SESSION_UFSRVUIDSTORE(sesn_ptr)) &&
			(FENCE_OWNER_UID(FENCESTATE_FENCE(fstate_ptr)) == SESSION_USERID(sesn_ptr))) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', command_arg:'%d'}: ERROR: FENCE OWNER UID MATCHES PERMISSION's TARGET UID", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), data_msg_ptr->ufsrvcommand->fencecommand->header->args);
		_HandleFenceCommandError (sesn_ptr, fstate_ptr, wsm_ptr_orig, data_msg_ptr, RESCODE_FENCE_PERMISSION, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);
		goto	exit_unlock;
	}

	//yes the full catastrophe. We need the user due to association with the inviter
	unsigned long sesn_call_flags_permission	=	(CALL_FLAG_LOCK_SESSION|CALL_FLAG_LOCK_SESSION_BLOCKING|
																							CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY| CALL_FLAG_HASH_USERNAME_LOCALLY|
																							CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION|CALL_FLAG_REMOTE_SESSION);
	bool lock_already_owned = false;
	Session *sesn_ptr_target = NULL;
	InstanceHolderForSession *instance_sesn_ptr_target;

	if (UfsrvUidIsEqual((const UfsrvUid *)fence_record_permission->users[0]->ufsrvuid.data, &SESSION_UFSRVUIDSTORE(sesn_ptr))) {
		sesn_ptr_target = sesn_ptr; //user targeting setting on themselves
	} else {
		GetSessionForThisUserByUserId(sesn_ptr, UfsrvUidGetSequenceId((const UfsrvUid *)fence_record_permission->users[0]->ufsrvuid.data), &lock_already_owned, sesn_call_flags_permission);
		instance_sesn_ptr_target = (InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr);
		if (IS_PRESENT(instance_sesn_ptr_target)) {
		  sesn_ptr_target = SessionOffInstanceHolder(instance_sesn_ptr_target);
		} else LOAD_NULL(sesn_ptr_target);
	}

	if (IS_PRESENT(sesn_ptr_target) && sesn_ptr_target != sesn_ptr) {
			SessionTransferAccessContext(sesn_ptr, sesn_ptr_target, false);
			SESNSTATUS_SET(sesn_ptr_target->stat, SESNSTATUS_EPHEMERAL);//this's necessary to emulate standard semantics for marshaling target sessions. Alternatively we could set 'false" above to 'true'

			(*permission_op_callback)(sesn_ptr_target, FENCESTATE_FENCE(fstate_ptr), permission_ptr, FENCE_CALLFLAG_WRITEBACK_DATA_TO_BACKEND, &fence_event);

			if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr_target)) {
				exit_success:
				_MarshalFencePermissionUpdate (sesn_ptr,
																			 &((FencePermissionContextData){.sesn_ptr=sesn_ptr_target, .fence.f_ptr=FENCESTATE_FENCE(fstate_ptr), .permission_ptr=permission_ptr}),
																			 data_msg_ptr, 0, &fence_event);

				SESNSTATUS_UNSET(sesn_ptr_target->stat, SESNSTATUS_EPHEMERAL);
				SessionResetTransferAccessContext(sesn_ptr_target);
				if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_target, __func__);
				if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fstate_ptr), SESSION_RESULT_PTR(sesn_ptr));

				_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
			} else if (SESSION_RESULT_CODE_EQUAL(sesn_ptr_target, RESCODE_FENCE_PERMISSION_MEMBER)) {
				_HandleFenceCommandError (sesn_ptr, &((FenceStateDescriptor){.instance_holder_fence=FENCESTATE_INSTANCE_HOLDER(fstate_ptr)}), wsm_ptr_orig, data_msg_ptr, RESCODE_FENCE_PERMISSION_MEMBER, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);
			}

			SessionResetTransferAccessContext (sesn_ptr_target);
			if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_target, __func__);//lost thread context assignment n session
	} else if (IS_PRESENT(sesn_ptr_target)) {//user targeting themselves (sesn_ptr==sesn_ptr_target)
		(*permission_op_callback)(sesn_ptr_target, FENCESTATE_FENCE(fstate_ptr), permission_ptr, FENCE_CALLFLAG_WRITEBACK_DATA_TO_BACKEND, &fence_event);

		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr_target)) {
			exit_success_same_target:
			_MarshalFencePermissionUpdate (sesn_ptr,
																		 &((FencePermissionContextData){.sesn_ptr=sesn_ptr_target, .fence.f_ptr=FENCESTATE_FENCE(fstate_ptr), .permission_ptr=permission_ptr}),
																		 data_msg_ptr, 0, &fence_event);

			if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fstate_ptr), SESSION_RESULT_PTR(sesn_ptr));

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
		}

		SessionResetTransferAccessContext (sesn_ptr_target);
		if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_target, __func__);
	}

	exit_unlock:
	if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fstate_ptr), SESSION_RESULT_PTR(sesn_ptr));
	goto exit_error;

	exit_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_PERMISSION)

#undef _FENCE_CALL_FLAGS_FENCEPERMISSION
}

/**
 * 	@param sesn_ptr_target: context_ptr->sesn_ptr: must have full access context loaded
 * 	@locked sesn_ptr:
 * 	@locked sesn_ptr_target:
 * 	@locked f_ptr:
 * 	@locks: None
 * 	@unlocks: None
 */
inline static UFSRVResult *
_MarshalFencePermissionUpdate (Session *sesn_ptr,  FencePermissionContextData *context_ptr, DataMessage *data_msg_ptr_received, unsigned long call_flags, FenceEvent *fence_event_ptr)
{
	FenceCommand 	*fence_command_recieved	=	data_msg_ptr_received->ufsrvcommand->fencecommand;
	Session 			*sesn_ptr_target				=	context_ptr->sesn_ptr;//user being updated

	_GENERATE_FENCE_COMMAND_ENVELOPE_INITIALISATION();
	_PrepareMarshalMessageForFence (&envelope_marshal, sesn_ptr, context_ptr->fence.f_ptr, fence_event_ptr, data_msg_ptr_received, FENCE_COMMAND__COMMAND_TYPES__PERMISSION, fence_command_recieved->header->args/*COMMAND_ARGS__ACCEPTED*/);

	//actual delta
	UserRecord *user_records[1];
	UserRecord	user_record;
	FenceRecord__Permission	fence_permission = FENCE_RECORD__PERMISSION__INIT;

	user_records[0]											=	&user_record;
	MakeUserRecordFromSessionInProto (sesn_ptr_target, &user_record, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF);
	user_record.cid											=	SESSION_ID(sesn_ptr_target); 		user_record.has_cid	=	1;
	fence_permission.users							=	user_records;
	fence_permission.n_users						=	1;
	fence_permission.type								=	context_ptr->permission_ptr->type; //aligned with protobuf enum
	fence_command.type									=	context_ptr->permission_ptr->type; fence_command.has_type = 1;
	AssignFencePermissionForProto (context_ptr->permission_ptr, &fence_record, &fence_permission);
	//end delta

	if (IS_PRESENT(fence_event_ptr))	{header.eid=fence_event_ptr->eid; header.has_eid=1;}

	//originator gets accepted (disabled)
	if (sesn_ptr_target != sesn_ptr) {
		header.args	=	fence_command_recieved->header->args;
		_MarshalCommandToUser(sesn_ptr, NULL, context_ptr->fence.f_ptr, &command_envelope,  uFENCE_V1_IDX);
		_MarshalCommandToUser(sesn_ptr_target, NULL, context_ptr->fence.f_ptr, &command_envelope,  uFENCE_V1_IDX);
	} else {
		//users targeting themselves get one confirmation
		header.args	=	fence_command_recieved->header->args;
		_MarshalCommandToUser(sesn_ptr_target, NULL, context_ptr->fence.f_ptr, &command_envelope,  uFENCE_V1_IDX);
	}

	if (FENCE_USERS_COUNT(context_ptr->fence.f_ptr)	<= 2) goto return_short_circuited;

	FenceRawSessionList raw_session_list = {0};
	GetRawMemberUsersListForFence (sesn_ptr, InstanceHolderFromClientContext(CLIENT_CTX_DATA(context_ptr->fence.f_ptr)), FENCE_CALLFLAG_INCLUDE_REMOTE_SESSIONS, &raw_session_list);//no locking
	assert (raw_session_list.sessions_sz > 0);


	size_t i = 0;
	for (; i<raw_session_list.sessions_sz; i++) {
    Session *sesn_ptr_listed = SessionOffInstanceHolder(raw_session_list.sessions[i]);
		if ((SESSION_ID(sesn_ptr)!=SESSION_ID(sesn_ptr_listed)) && (SESSION_ID(sesn_ptr_target)!=SESSION_ID(sesn_ptr_listed))) {
			header.cid	=	SESSION_ID(sesn_ptr_listed);
			_MarshalCommandToUser(sesn_ptr, sesn_ptr_listed, context_ptr->fence.f_ptr, &command_envelope,  uFENCE_V1_IDX);
		}
	}

	DestructFenceRawSessionList (&raw_session_list, false);

	return_short_circuited:

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

/// END PERMISSION \\\


///// FENCE STATE \\\\

/**
 * 	@brief: The main controller for handling user commands for changing Fence attributes or
 * 	requesting uptodate Fence StateSync.
 * 	param sesn_ptr: the user session for which the command is executed
 * 	@locked sesn_ptr: by caller
 * 	@locks RW Fence: by downstream
 */
inline static UFSRVResult *
_CommandControllerFenceStateSync (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr)
{
	UFSRVResult 					*res_ptr	=	NULL;

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	switch (data_msg_ptr->ufsrvcommand->fencecommand->header->args)
	{
#if 0
		//TODO: TO BE PHASED OUT: group attributes are processed individuly now
		case COMMAND_ARGS__UPDATED://user updated a fence attribute
			res_ptr=_CommandCallbackControllerFenceStateSyncUpdated(sesn_ptr, wsm_ptr_orig, data_msg_ptr);
			break;
#endif
		case COMMAND_ARGS__SYNCED://user requests a snapshot of current fence view
			res_ptr = _CommandControllerFenceStateSyncSynced(instance_sesn_ptr, wsm_ptr_orig, data_msg_ptr);
			break;

		default:
			syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', arg:'%d'}: ERROR: UKNOWN FENCE COMMAND ARG...", __func__, pthread_self(), sesn_ptr, data_msg_ptr->ufsrvcommand->fencecommand->header->args);
	}


	exit_final:
	if (IS_EMPTY(res_ptr))	goto exit_catch_all; //this catches the default case
	return res_ptr;

	exit_catch_all:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

/**
 * 	@brief: Main controller for responding to fence state sync requests
 * 	@locked sesn_ptr: by caller
 * 	@locks RW Fence:
 * 	@unlocks Fence:
 */
inline static UFSRVResult *
_CommandControllerFenceStateSyncSynced (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr)

{
	bool 									fence_already_locked  = false;
	FenceStateDescriptor 	*fstate_ptr           = NULL;
  InstanceHolderForFenceStateDescriptor *instance_fstate_ptr;
#define _FENCE_CALL_FLAGS_STATESYNC	(FENCE_CALLFLAG_KEEP_FENCE_LOCKED)

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	//locks by default, only checking for membership
	IsUserAllowedToChangeFence (sesn_ptr,
															data_msg_ptr->ufsrvcommand->fencecommand->fences[0]->fid,
															data_msg_ptr->ufsrvcommand->fencecommand->fences[0]->cname,
															&fence_already_locked,
															_FENCE_CALL_FLAGS_STATESYNC);

	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))	{
	  instance_fstate_ptr = (InstanceHolderForFenceStateDescriptor *)SESSION_RESULT_USERDATA(sesn_ptr);
	  fstate_ptr          = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
	} else {
		int rescode;
		Fence	*f_ptr		=	NULL;

		rescode	=	SESSION_RESULT_CODE(sesn_ptr);

		if (SESSION_RESULT_TYPE_ERROR(sesn_ptr) && !SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST)) {
			//FENCE LOCKED... membership or permisions issue
      if (SESSION_RESULT_CODE(sesn_ptr) == RESCODE_FENCE_OWNERSHIP) {
        fstate_ptr = FenceStateDescriptorOffInstanceHolder((InstanceHolderForFenceStateDescriptor *)SESSION_RESULT_USERDATA(sesn_ptr));
        f_ptr           = FENCESTATE_FENCE(fstate_ptr);
      } else { //RESCODE_FENCE_FENCE_MEMBERSHIP
        f_ptr		=	FenceOffInstanceHolder((InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr));
      }

			_HandleFenceCommandError (sesn_ptr, &((FenceStateDescriptor){.instance_holder_fence=(InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr)}), wsm_ptr_orig, data_msg_ptr, rescode, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);

			if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
			goto exit_catch_all;
		}

		if (IS_EMPTY(SESSION_RESULT_USERDATA(sesn_ptr)) && SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST)) {
			//fence doesn't exist. NO lock
			_HandleFenceCommandError (sesn_ptr, NULL, wsm_ptr_orig, data_msg_ptr, rescode, data_msg_ptr->ufsrvcommand->fencecommand->header->command, NULL);
			goto exit_catch_all;
		}

		exit_catch_all:
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);
	}

	//FENCE NOW LOCKED

	MarshalFenceStateSync (sesn_ptr, fstate_ptr, data_msg_ptr, 0);

	exit_success:
	if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fstate_ptr), SESSION_RESULT_PTR(sesn_ptr));
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

#undef _FENCE_CALL_FLAGS_STATESYNC
}


/**
 * 	@brief: Marshals a general Fence state sync message to the named Session, enabling client to refresh their views.
 *	This may or may not be based on prior user request. The presence of data_msg_ptr will determine that.
 *	No event is associated with syncs.
 *
 *	@param data_msg_ptr_received: The original wire command as packed by the user. Can be null, in which case it means the sync was
 *	server initiated.
 *	@locks: NONE
 *	@locked RW f_ptr:
 *	@locked RW sesn_ptr:
 *
 *	@call_flags: NONE
 *
 */
UFSRVResult *
MarshalFenceStateSync (Session *sesn_ptr, FenceStateDescriptor *fstate_ptr, DataMessage *data_msg_ptr_received, unsigned long call_flags)
{
	_GENERATE_FENCE_COMMAND_ENVELOPE_INITIALISATION();

	Fence *f_ptr = FENCESTATE_FENCE(fstate_ptr);

	_PrepareMarshalMessageForFence (&envelope_marshal, sesn_ptr, f_ptr, NULL, data_msg_ptr_received, FENCE_COMMAND__COMMAND_TYPES__STATE, COMMAND_ARGS__SYNCED);
	MakeFenceRecordInProto(sesn_ptr, f_ptr, &fence_record); //we need more info on the fence than just identifier
	MakeFenceUserPreferencesInProto(sesn_ptr, fstate_ptr, &fence_record);

	WebSocketMessage wsmsg; wsmsg.type=WEB_SOCKET_MESSAGE__TYPE__REQUEST;//dummy
	UfsrvCommandMarshallingDescription ufsrv_descpription={header.eid, FENCE_ID(f_ptr), header.when, &EnvelopeMetaData, &command_envelope};

	#ifdef __UF_TESTING
		syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', cid_target:'%lu' uid:'%lu', fcname:'%s'} Sending fence Sync State ", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr),
					SESSION_ID(sesn_ptr), SESSION_USERID(sesn_ptr), FENCE_CNAME(f_ptr));
	#endif

	UfsrvCommandInvokeCommand (sesn_ptr, NULL, &wsmsg, NULL, &ufsrv_descpription, uFENCE_V1_IDX);

	DestructFenceRecordProto (&fence_record, false);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}


/**
 * 	@brief: Marshals a general Fence state sync message to the named Session, enabling client to refresh their views.
 *	This may or may not be based on prior user request. The presence of data_msg_ptr will determine that.
 *	No event is associated with syncs.
 *
 *	@param data_msg_ptr_received: The original wire command as packed by the user. Can be null, in which case it means the sync was
 *	server initiated.
 *	@locks: NONE
 *	@locked RW f_ptr:
 *	@locked RW sesn_ptr:
 *
 *	@call_flags: NONE
 *
 */
static inline UFSRVResult *
_MarshalServerRequestForFenceStateSync (Session *sesn_ptr, Fence *f_ptr, DataMessage *data_msg_ptr_received, unsigned long call_flags)
{
	_GENERATE_FENCE_COMMAND_ENVELOPE_INITIALISATION();
	_PrepareMarshalMessageForFence (&envelope_marshal, sesn_ptr, f_ptr, NULL, data_msg_ptr_received, FENCE_COMMAND__COMMAND_TYPES__STATE, COMMAND_ARGS__RESYNC);
	MakeFenceRecordInProtoAsIdentifier(sesn_ptr, f_ptr, &fence_record);

	WebSocketMessage wsmsg; wsmsg.type=WEB_SOCKET_MESSAGE__TYPE__REQUEST;//dummy
	UfsrvCommandMarshallingDescription ufsrv_descpription={header.eid, FENCE_ID(f_ptr), header.when, &EnvelopeMetaData, &command_envelope};

#ifdef __UF_TESTING
		syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', cid_target:'%lu' uid:'%lu', fcname:'%s'} Sending Server request for fence Sync State ", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr),
					SESSION_ID(sesn_ptr), SESSION_USERID(sesn_ptr), FENCE_CNAME(f_ptr));
#endif

	UfsrvCommandInvokeCommand (sesn_ptr, NULL, &wsmsg, NULL, &ufsrv_descpription, uFENCE_V1_IDX);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}


/**
 * 	@brief: works in tandem with _MarshalFenceStateSyncForJoin() & et al to specialise the message for a specific target user
 * 	Where both sesn_ptr and sesn_ptr_target are present, target would be used to as "target"otherwise sesn_ptr, which means the session owner.
 *
 * 	@locked RW f_ptr:
 */
inline static UFSRVResult *
_MarshalFenceStateSync(Session *sesn_ptr, Session *sesn_ptr_target, Fence *f_ptr, Envelope *command_envelope_ptr)
{
	CommandHeader *command_header_ptr	=	command_envelope_ptr->ufsrvcommand->header;
	command_header_ptr->cid						=	SESSION_ID((sesn_ptr_target?sesn_ptr_target:sesn_ptr)); command_header_ptr->has_cid=1;

	WebSocketMessage wsmsg; wsmsg.type=WEB_SOCKET_MESSAGE__TYPE__REQUEST;//dummy
	UfsrvCommandMarshallingDescription ufsrv_descpription={command_header_ptr->eid, FENCE_ID(f_ptr), command_header_ptr->when, &EnvelopeMetaData, command_envelope_ptr};

#ifdef __UF_TESTING
	syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', cid_target:'%lu' uname_target:'%s', fid:'%lu'} Syncing fence State ", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr),
				SESSION_ID((sesn_ptr_target?sesn_ptr_target:sesn_ptr)), SESSION_USERNAME((sesn_ptr_target?sesn_ptr_target:sesn_ptr)), FENCE_ID(f_ptr));
#endif

	UfsrvCommandInvokeCommand (sesn_ptr, sesn_ptr_target, &wsmsg, NULL, &ufsrv_descpription, uFENCE_V1_IDX);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

//// END STATE \\\\

/**
 * 	@brief: Generalised command sending
 */
inline static UFSRVResult *
_MarshalCommandToUser	(Session *sesn_ptr, Session *sesn_ptr_target, Fence *f_ptr, Envelope *command_envelope_ptr, unsigned req_cmd_idx)
{
	CommandHeader *command_header_ptr	=	command_envelope_ptr->ufsrvcommand->header;

	WebSocketMessage wsmsg; wsmsg.type=WEB_SOCKET_MESSAGE__TYPE__REQUEST;//dummy
	UfsrvCommandMarshallingDescription ufsrv_descpription={command_header_ptr->eid, IS_PRESENT(f_ptr)?FENCE_ID(f_ptr):0, command_header_ptr->when, &EnvelopeMetaData, command_envelope_ptr};

#ifdef __UF_TESTING
	syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', cid_target:'%lu', uname_target:'%s', fid:'%lu'} Marshaling command... ", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr),
				SESSION_ID((sesn_ptr_target?sesn_ptr_target:sesn_ptr)), SESSION_USERNAME((sesn_ptr_target?sesn_ptr_target:sesn_ptr)), IS_PRESENT(f_ptr)?FENCE_ID(f_ptr):0);
#endif

	UfsrvCommandInvokeCommand (sesn_ptr, sesn_ptr_target, &wsmsg, NULL, &ufsrv_descpription, req_cmd_idx);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}


/*
 * @param errcode: should reflect a UFSRVResult.rescode type
 * @param command_type: should reflect a protobif command type, or -1 to re use original
 *
 */
static void
_BuildErrorHeaderForFenceCommand (FenceCommand *fence_command_ptr, FenceCommand *fence_command_ptr_incoming, int errcode, int command_type)
{
	CommandHeader *header_ptr_incoming 	= fence_command_ptr_incoming->header;
	CommandHeader *header_ptr 					=	fence_command_ptr->header;

	switch (errcode)
	{
		case RESCODE_FENCE_EXISTS:
			header_ptr->args_error	=	FENCE_COMMAND__ERRORS__ALREADY_EXISTS; 	header_ptr->has_args_error	=	1;
			header_ptr->args				=	COMMAND_ARGS__REJECTED;									header_ptr->has_args				=	1;
			break;

		case RESCODE_FENCE_FENCE_MEMBERSHIP:
			header_ptr->args_error	=	FENCE_COMMAND__ERRORS__NOT_MEMBER; 			header_ptr->has_args_error	=	1;
			header_ptr->args				=	COMMAND_ARGS__REJECTED;									header_ptr->has_args				=	1;
			break;

		case RESCODE_FENCE_OWNERSHIP:
			header_ptr->args_error	=	FENCE_COMMAND__ERRORS__PERMISSIONS_ADMIN; 	header_ptr->has_args_error	=	1;
			header_ptr->args				=	COMMAND_ARGS__REJECTED;											header_ptr->has_args				=	1;
			break;

		case RESCODE_FENCE_DOESNT_EXIST:
			header_ptr->args_error	=	FENCE_COMMAND__ERRORS__GROUP_DOESNT_EXIST; 	header_ptr->has_args_error	=	1;
			header_ptr->args				=	COMMAND_ARGS__REJECTED;											header_ptr->has_args				=	1;
			break;

			//command parameter empty, for example missing fence name
		case RESCODE_FENCE_MISSING_PARAM:
		case RESCODE_PROG_MISSING_PARAM:
			header_ptr->args_error	=	FENCE_COMMAND__ERRORS__MISSING_PARAMETER; 	header_ptr->has_args_error	=	1;
			header_ptr->args				=	COMMAND_ARGS__REJECTED;											header_ptr->has_args				=	1;
			break;

		case RESCODE_FENCE_INVALID_MAXMEMBERS:
			header_ptr->args_error	=	FENCE_COMMAND__ERRORS__MISSING_PARAMETER; 	header_ptr->has_args_error	=	1;
			header_ptr->args				=	COMMAND_ARGS__REJECTED;											header_ptr->has_args				=	1;
			break;

    case RESCODE_FENCE_INVALID_DELIVERY_MODE:
			header_ptr->args_error	=	FENCE_COMMAND__ERRORS__MISSING_PARAMETER; 	header_ptr->has_args_error	=	1;
			header_ptr->args				=	COMMAND_ARGS__REJECTED;											header_ptr->has_args				=	1;
			break;

		case RESCODE_BACKEND_DATA:
			header_ptr->args_error	=	FENCE_COMMAND__ERRORS__EXECUTION_ERROR; 	header_ptr->has_args_error	=	1;
			header_ptr->args				=	COMMAND_ARGS__REJECTED;											header_ptr->has_args			=	1;
			break;

		case RESCODE_FENCE_PERMISSION_MEMBER:
			header_ptr->args_error	=	FENCE_COMMAND__ERRORS__PERMISSIONS; 	header_ptr->has_args_error	=	1;
			header_ptr->args				=	COMMAND_ARGS__REJECTED;								header_ptr->has_args				=	1;
			fence_command_ptr->type	=	fence_command_ptr_incoming->type;			fence_command_ptr->has_type	=	1;
			GetFenceRecordPermissionForProto (fence_command_ptr_incoming->fences[0], fence_command_ptr->fences[0], fence_command_ptr->type);
			break;

		case RESCODE_FENCE_PERMISSION:
			header_ptr->args_error	=	FENCE_COMMAND__ERRORS__PERMISSIONS; 	header_ptr->has_args_error	=	1;
			header_ptr->args				=	COMMAND_ARGS__REJECTED;								header_ptr->has_args				=	1;
			break;

		case RESCODE_FENCE_INVITATION_LIST:
			header_ptr->args_error	=	FENCE_COMMAND__ERRORS__INVITE_ONLY; 	header_ptr->has_args_error	=	1;
			header_ptr->args				=	COMMAND_ARGS__REJECTED;								header_ptr->has_args				=	1;
			break;

		default:
			goto exit_error;
	}

	if (command_type>0)		header_ptr->command	=	command_type;
	else									header_ptr->command	=	header_ptr_incoming->command;//restore original command
	header_ptr->when_client	=	header_ptr_incoming->when;							header_ptr->has_when_client=header_ptr_incoming->has_when_client;
	header_ptr->args_error_client	=	header_ptr_incoming->args; 				header_ptr->has_args_error_client=1;
	return;

	exit_error:
	return;

}


/**
 * 	@brief: Marshal an error response message to user. This is invoked in the context of command processing.
 *
 * 	@param restore_callback: rebuild elements of the FenceCommand context so as to enable correct processing at the receiving end
 *
 * 	@data_msg_ptr: the original wire command that triggered the error as packaged by user
 * 	@locked f_ptr: f_ptr
 * 	@locked sesn_ptr:
 * 	@unlocks: none
 */
static UFSRVResult *
_HandleFenceCommandError (Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, int rescode, int command_type, CallbackRestoreFenceValue restore_callback)
{
	Envelope 					command_envelope	= ENVELOPE__INIT;
	CommandHeader 		header						= COMMAND_HEADER__INIT;
	UfsrvCommandWire	ufsrv_command			= UFSRV_COMMAND_WIRE__INIT;
	FenceCommand 			fence_command			= FENCE_COMMAND__INIT;

	command_envelope.ufsrvcommand				=	&ufsrv_command;
	ufsrv_command.header								=	&header;
	fence_command.header								=	&header;

	ufsrv_command.fencecommand					=	&fence_command;
	ufsrv_command.ufsrvtype							=	UFSRV_COMMAND_WIRE__UFSRV_TYPE__UFSRV_FENCE;

	FenceRecord	fence_record						= {0};
	FenceRecord *fence_records[1];

	fence_command.fences								=	fence_records;
	fence_command.n_fences							=	1;
	if (IS_PRESENT(fence_state_ptr)) {
		fence_records[0]										=	MakeFenceRecordInProtoAsIdentifier(sesn_ptr, FENCESTATE_FENCE(fence_state_ptr), &fence_record);
		fence_records[0]->fname							=	 FENCE_DNAME(FENCESTATE_FENCE(fence_state_ptr)); //by reference
		fence_records[0]->cname							=	 FENCE_CNAME(FENCESTATE_FENCE(fence_state_ptr)); //by reference This is necessary to synch.. but might relax it in the future
	} else {
		fence_records[0]										=	MakeFenceRecordInProtoAsIdentifierByParams (sesn_ptr, data_msg_ptr->ufsrvcommand->fencecommand->fences[0]->fid, &fence_record);
	}

	if (IS_PRESENT(restore_callback))	(*restore_callback)(fence_state_ptr, &fence_record);

	command_envelope.source							=	"0";
	command_envelope.timestamp					=	GetTimeNowInMillis(); command_envelope.has_timestamp=1;

	header.when													=	command_envelope.timestamp; header.has_when		=	1;
	header.cid													=	SESSION_ID(sesn_ptr);				header.has_cid		=	1;

	_BuildErrorHeaderForFenceCommand (&fence_command, data_msg_ptr->ufsrvcommand->fencecommand, rescode, command_type);

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', uid:'%lu', cid:'%lu', arg_error:'%d', rescode:'%d'}: Marshaling Error response message...", __func__, pthread_self(), sesn_ptr, SESSION_USERID(sesn_ptr), SESSION_ID(sesn_ptr), header.args_error, rescode);
#endif

	return (_MarshalCommandToUser(sesn_ptr, NULL,  IS_PRESENT(fence_state_ptr)?FENCESTATE_FENCE(fence_state_ptr):NULL, &command_envelope,  uFENCE_V1_IDX));

}

