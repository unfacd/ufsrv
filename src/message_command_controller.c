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
#include <fence.h>
#include <fence_utils.h>
#include <fence_proto.h>
#include <user_backend.h>
#include <users_proto.h>
#include <protocol_websocket.h>
#include <ufsrvcmd_user_callbacks.h>
#include <ufsrvcmd_callbacks.h>
#include <ufsrvcmd_broadcast.h>
#include <SignalService.pb-c.h>
#include <message_broadcast.h>
#include <location.h>
#include <recycler.h>
#include <command_controllers.h>
#include <attachments.h>
#include <ufsrvuid.h>

extern ufsrv							*const masterptr;
extern __thread ThreadContext ufsrv_thread_context;

struct MarshalMessageEnvelopeForUser {
        UfsrvCommandWire		*ufsrv_command_wire;
        Envelope						*envelope;
        MessageCommand 			*message_command;
        CommandHeader 			*header;
        FenceRecord					*fence_record;
        FenceRecord					**fence_records;
        UserRecord          *user_record;
        UserRecord          **user_records;
        UserRecord 				  *originator;
};
typedef struct MarshalMessageEnvelopeForUser MarshalMessageEnvelopeForUser;

#define _GENERATE_MESSAGECOMMAND_ENVELOPE_INITIALISATION() \
	UfsrvCommandWire								ufsrv_command_wire	= UFSRV_COMMAND_WIRE__INIT;	\
	Envelope												command_envelope		=	ENVELOPE__INIT;	\
	MessageCommand 									message_command			=	MESSAGE_COMMAND__INIT;	\
	CommandHeader 									header							=	COMMAND_HEADER__INIT;	\
	UserRecord 				              user_record_originator; \
	\
	MarshalMessageEnvelopeForUser	envelope_marshal = {	\
			.ufsrv_command_wire	=	&ufsrv_command_wire,	\
			.envelope						=	&command_envelope,	\
			.message_command		=	&message_command,	\
			.header							=	&header,	\
			.fence_record				=	NULL, \
			.fence_records			=	NULL,	\
      .user_record        = NULL, \
      .user_records       = NULL, \
      .originator         = &user_record_originator \
	}

#define _GENERATE_FENCEMESSAGECOMMAND_ENVELOPE_INITIALISATION() \
	UfsrvCommandWire								ufsrv_command_wire	= UFSRV_COMMAND_WIRE__INIT;	\
	Envelope												command_envelope		=	ENVELOPE__INIT;	\
	MessageCommand 									message_command			=	MESSAGE_COMMAND__INIT;	\
	CommandHeader 									header							=	COMMAND_HEADER__INIT;	\
	FenceRecord						          fence_record			  =	FENCE_RECORD__INIT;	\
	FenceRecord 					          *fence_records[1];	\
	UserRecord 				              user_record_originator; \
	\
	MarshalMessageEnvelopeForUser	envelope_marshal = {	\
			.ufsrv_command_wire	=	&ufsrv_command_wire,	\
			.envelope						=	&command_envelope,	\
			.message_command		=	&message_command,	\
			.header							=	&header,	\
			.fence_record				=	&fence_record, \
			.fence_records			=	fence_records,	\
      .user_record        = NULL, \
      .user_records       = NULL, \
      originator         = &user_record_originator \
	}

inline static void _PrepareMarshalMessageForUserMessage(MarshalMessageEnvelopeForUser *envelope_ptr, Session *sesn_ptr, Fence *f_ptr, UfsrvEvent *event_ptr, DataMessage *data_msg_ptr_orig, enum _UserCommand__CommandTypes command_type, enum _CommandArgs command_arg);
inline static UFSRVResult *_UfsrvCommandControllerMessageSay (Session *sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, MessageQueueMsgPayload *mqp_ptr);
inline static UFSRVResult *_UfsrvCommandControllerMessageIntro (Session *sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, MessageQueueMsgPayload *mqp_ptr);
inline static UFSRVResult *_MarshalMessageToFence (Session *sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, Fence *f_ptr, FenceEvent *);
inline static UFSRVResult *_MarshalFenceMessageToUser(Session *sesn_ptr, Session *sesn_ptr_target, Fence *f_ptr, Envelope *command_envelope_ptr);
inline static UFSRVResult *_MarshalUserMessage(Session *sesn_ptr, Session *sesn_ptr_target, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr_recieved, UfsrvEvent *event_ptr);
inline static UFSRVResult *_MarshalUserMessageToUser(Session *sesn_ptr, Session *sesn_ptr_target, Envelope *command_envelope_ptr);

static bool _IsContactSharing(Session *sesn_ptr, ContactRecord **contact_records_ptr);

static void _BuildErrorHeaderForMessageCommand (CommandHeader *header_ptr, CommandHeader *header_ptr_incoming, int errcode, int command_type);
inline static UFSRVResult *_MarshalCommandToUser	(Session *sesn_ptr, Session *sesn_ptr_target, Envelope *command_envelope_ptr, unsigned req_cmd_idx);
static UFSRVResult *_HandleMessageCommandError (Session *sesn_ptr, ClientContextData *ctx_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, int rescode, int command_type);

inline static void
_PrepareMarshalMessageForUserMessage (MarshalMessageEnvelopeForUser *envelope_ptr, Session *sesn_ptr, Fence *f_ptr, UfsrvEvent *event_ptr, DataMessage *data_msg_ptr_orig, enum _UserCommand__CommandTypes command_type, enum _CommandArgs command_arg) {
  envelope_ptr->envelope->ufsrvcommand								  =	envelope_ptr->ufsrv_command_wire;

  envelope_ptr->envelope->ufsrvcommand->msgcommand		  =	envelope_ptr->message_command;
  envelope_ptr->envelope->ufsrvcommand->ufsrvtype			  =	UFSRV_COMMAND_WIRE__UFSRV_TYPE__UFSRV_MESSAGE;
  envelope_ptr->envelope->ufsrvcommand->header				  =	envelope_ptr->header;

  envelope_ptr->message_command->header									=	envelope_ptr->header;

  if (IS_PRESENT(envelope_ptr->user_records)) {
    envelope_ptr->message_command->to										=	envelope_ptr->user_records;
    envelope_ptr->message_command->to[0]								=	envelope_ptr->user_record;
    envelope_ptr->message_command->n_to									=	1;
  }

//  envelope_ptr->message_command->originator = MakeUserRecordFromSessionInProto (sesn_ptr, envelope_ptr->originator, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF);

  envelope_ptr->envelope->source						=	"0";
  envelope_ptr->envelope->timestamp					=	GetTimeNowInMillis(); envelope_ptr->envelope->has_timestamp = 1;

  envelope_ptr->header->when								=	envelope_ptr->envelope->timestamp; 	envelope_ptr->header->has_when = 1;
  envelope_ptr->header->cid									=	SESSION_ID(sesn_ptr); 							envelope_ptr->header->has_cid = 1;
  envelope_ptr->header->command							=	command_type;
  envelope_ptr->header->args								=	command_arg;												envelope_ptr->header->has_args = 1;

  if (IS_PRESENT(envelope_ptr->fence_records)) {
    envelope_ptr->message_command->fences							=	envelope_ptr->fence_records;
    envelope_ptr->message_command->fences[0]					=	envelope_ptr->fence_record;
    envelope_ptr->message_command->n_fences						=	1;
  }

  if (IS_PRESENT(event_ptr)) {
    envelope_ptr->header->when_eid					=	event_ptr->when; 					envelope_ptr->header->has_when_eid = 1;
    envelope_ptr->header->eid								=	event_ptr->eid; 					envelope_ptr->header->has_eid = 1;
  }

  envelope_ptr->header->when								=	envelope_ptr->envelope->timestamp; 					envelope_ptr->header->has_when=1;

  if (IS_PRESENT(data_msg_ptr_orig)) {
    envelope_ptr->header->when_client				=	data_msg_ptr_orig->ufsrvcommand->msgcommand->header->when;
    envelope_ptr->header->has_when_client		=	1;
    envelope_ptr->header->args_client				=	PROTO_MESSAGECOMMAND_HEADER_ARGS(data_msg_ptr_orig);
    envelope_ptr->header->has_args_client		=	1;
  }

}

//// MSG \\\

/**
 * 	@brief: Main handler for INTRA message commands arriving via the wire
 * 	@param sesn_ptr_local_user: User session, maynot be a connected one, loaded in ephemeral mode
 * 	@locked sesn_ptr_local_user: by caller
 */
UFSRVResult *
CommandCallbackControllerMessageCommand (Session *sesn_ptr_local_user, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, MessageQueueMsgPayload *mqp_ptr)
{
	CommandHeader *command_header = data_msg_ptr->ufsrvcommand->msgcommand->header;
	if (unlikely(IS_EMPTY(command_header)))	_RETURN_RESULT_SESN(sesn_ptr_local_user, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);

	UFSRVResult *res_ptr = NULL;
	switch (command_header->command)
	{
    case MESSAGE_COMMAND__COMMAND_TYPES__SAY:
      res_ptr = _UfsrvCommandControllerMessageSay (sesn_ptr_local_user, NULL, data_msg_ptr, mqp_ptr);
      break;

    case MESSAGE_COMMAND__COMMAND_TYPES__INTRO:
      res_ptr = _UfsrvCommandControllerMessageIntro (sesn_ptr_local_user, NULL, data_msg_ptr, mqp_ptr);
      break;
	}

	return res_ptr;

}

inline static UFSRVResult *
_UfsrvCommandControllerMessageSay (Session *sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, MessageQueueMsgPayload *mqp_ptr)
{
  unsigned long	fid;
  Fence 			*f_ptr				= NULL;
  MessageCommand	*msgcmd_ptr;
  UFSRVResult 	*res_ptr		= NULL;

  msgcmd_ptr = data_msg_ptr->ufsrvcommand->msgcommand;

  if (unlikely(msgcmd_ptr->n_fences <= 0)) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: FENCECOMMAND CONTAINED ZERO FENCE DEFINITION...", __func__, pthread_self(), sesn_ptr);

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
  }

  if (unlikely(msgcmd_ptr->n_messages <= 0)) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: FENCECOMMAND CONTAINED ZERO MESSAGE DEFINITION...", __func__, pthread_self(), sesn_ptr);

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
  }

  fid = msgcmd_ptr->fences[0]->fid;

  if (fid > 0) {
    bool lock_already_owned = false;
    unsigned long fence_call_flags_final = FENCE_CALLFLAG_SEARCH_BACKEND |
                                           FENCE_CALLFLAG_HASH_FENCE_LOCALLY |
                                           FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE |
                                           FENCE_CALLFLAG_KEEP_FENCE_LOCKED | FENCE_CALLFLAG_LOCK_FENCE_BLOCKING;

    FindFenceById(sesn_ptr, fid, fence_call_flags_final);
    InstanceHolderForFence *instance_f_ptr =  (InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr);

    if (IS_EMPTY(instance_f_ptr)) {
      if (SESSION_RESULT_TYPE_EQUAL(sesn_ptr, RESCODE_PROG_WONTLOCK)) {
        _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, SESSION_RESULT_CODE(sesn_ptr))
      } else {
        syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu'): COULD NOT FIND FENCE bid:'%lu'...", __func__, pthread_self(), SESSION_ID(sesn_ptr), fid);

        _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, SESSION_RESULT_CODE(sesn_ptr))
      }
    }

    //lock acquired
    lock_already_owned = SESSION_RESULT_TYPE_EQUAL(sesn_ptr, RESCODE_PROG_LOCKED_THIS_THREAD);

    f_ptr = FenceOffInstanceHolder(instance_f_ptr);

    delivery_mode_oneway_broadcast: //only owner allowed to publish
    if (F_ATTR_IS_SET(FENCE_ATTRIBUTES(f_ptr), F_ATTR_BROADCAST_ONEWAY)) {
      if (SESSION_USERID(sesn_ptr) != FENCE_OWNER_UID(f_ptr)) {
        syslog(LOG_DEBUG, "%s (pid:'%lu', co:'%p', cid:'%lu', fo:'%p', fid:'%lu', uid_owner:'%lu', uid_sender:'%lu'): ERROR: F_ATTR_BROADCAST_ONEWAY IS SET", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), f_ptr, fid, FENCE_OWNER_UID(f_ptr), SESSION_USERID(sesn_ptr));

        if (!lock_already_owned)
          FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));

        _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOGIC_EMPTY_RESOURCE)
      }
    }

    //FENCE RD-LOCKED. unlocked upon return
    if (!(IsUserMemberOfThisFence(&SESSION_FENCE_LIST(sesn_ptr), f_ptr, false/*LOCK_FLAG*/))) {
      syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', bid:'%lu'): ERROR: USER IS NOT MEMBER OF FENCE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), fid);

      if (!lock_already_owned)
        FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));

      _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOGIC_EMPTY_RESOURCE)
    }

    unsigned char *msg = (unsigned char *) strndupa((char *) msgcmd_ptr->messages[0]->message.data, msgcmd_ptr->messages[0]->message.len);

    syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', bid:'%lu', msg:'%s'): RECEIVED MSG TO FENCE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), fid, "...");//msg);

    FenceEvent fence_event = {0};
    if (IS_EMPTY((RegisterFenceEvent(sesn_ptr, f_ptr, EVENT_TYPE_FENCE_USR_MSG, NULL, 0/*LOCK_FLAG*/, &fence_event)))) {
      if (!lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));

      _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_EVENT_GENERATION);
    }

    //TODO: REPLACE THIS BLOCK WITH attachments.c:AttachmentDescriptorValidateFromProto
    //this is the point where we actually formally capture a record for the attachment,previously uploaded by the user
    AttachmentRecord *attachment_record = NULL;
    AttachmentDescriptor attachment     = {0}; //IMPORTANT ufsrv doesnt implement TypePool for this type

    if ((msgcmd_ptr->n_attachments > 0) && (!IS_EMPTY((attachment_record = msgcmd_ptr->attachments[0])))) {
      //TODO: why is it an error to resend the same attachment? we shouldn't store it, but should be OK to forward it
      //if (!IS_EMPTY(GetAttachmentDescriptorEphemeral(sesn_ptr, attachment_record->id, &attachment))) goto return_attachment_already_exists;

      if (AttachmentDescriptorGetFromProto(sesn_ptr, attachment_record, fence_event.eid, &attachment, true/*encode_key*/)) {
        DbAttachmentStore(sesn_ptr, &attachment, FENCE_ID(f_ptr), 1);//ufsrv instances currently doesn't support lru-caching attachments
        AttachmentDescriptorDestruct(&attachment, true, false);
      } else {
        //TODO: we should prevent the attachment from being forwarded, but perhaps let the msg through, or drop the msg altogether
      }
    }

    if (!lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));

    if (F_ATTR_IS_SET(FENCE_ATTRIBUTES(f_ptr), F_ATTR_BROADCAST)) {
      if (SESSION_USERID(sesn_ptr) == FENCE_OWNER_UID(f_ptr)) {
        InterBroadcastUserMessage(sesn_ptr, (ClientContextData *) msgcmd_ptr, &fence_event, COMMAND_ARGS__ADDED);
        return SESSION_RESULT_PTR(sesn_ptr); //only fence owner can see, but sender and owner are the same, so nothing to marshall
      }
    }

    UFSRVResult *res_ptr = _MarshalMessageToFence(sesn_ptr, wsm_ptr_orig, data_msg_ptr, f_ptr, &fence_event);
    if (_RESULT_TYPE_SUCCESS(res_ptr) && _RESULT_CODE_EQUAL(res_ptr, RESCODE_UFSRV_INTERBROADCAST)) {
      InterBroadcastUserMessage(sesn_ptr, (ClientContextData *) msgcmd_ptr, &fence_event, COMMAND_ARGS__ADDED);//update to COMMAND_ARGS__POSTED
    }

    return res_ptr;//this will reflect whatever result recorded in InterBroadcastUserMessage()


    return_attachment_already_exists:
    if (!lock_already_owned)
      FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', blocb_id:'%s'}: ERROR: ATTACHMENT ID ALREADY EXISTS", __func__,
           pthread_self(), sesn_ptr, attachment_record->id);
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOGIC_EMPTY_RESOURCE)
  }
  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
}

inline static UFSRVResult *_ProcessAvatarAttachment (Session *sesn_ptr, AttachmentRecord *attachment_ptr, UfsrvEvent *event_ptr);
inline static UFSRVResult *
_ProcessAvatarAttachment (Session *sesn_ptr, AttachmentRecord *attachment_ptr, UfsrvEvent *event_ptr)
{
  //this is the point where we actually formally capture a record for the attachment,previously uploaded by the user
  AttachmentDescriptor *attachment_descriptors[1];
  AttachmentDescriptor attachment_descriptor = {0};
  attachment_descriptors[0] = &attachment_descriptor;
  CollectionDescriptor attachment_descriptors_collection = {
          .collection_sz  = 1,
          .collection     = COLLECTION_TYPE(attachment_descriptors)
  };

  AttachmentRecord *attachment_records[1];
  attachment_records[0] = attachment_ptr;
  CollectionDescriptor attachments_collection = {
          .collection_sz  = 1,
          .collection     = COLLECTION_TYPE(attachment_records)
  };
  AttachmentDescriptorValidateFromProto (sesn_ptr, NULL, &attachments_collection, event_ptr->eid, true, &attachment_descriptors_collection);

  return SESSION_RESULT_PTR(sesn_ptr);
}

/**
 * @brief Main controller for Intro messages
 * @param sesn_ptr
 * @param wsm_ptr_orig
 * @param data_msg_ptr
 * @param mqp_ptr
 * @return
 * @locks sesn_ptr_target
 * @locked sesn_ptr
 *
 */
inline static UFSRVResult *
_UfsrvCommandControllerMessageIntro (Session *sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, MessageQueueMsgPayload *mqp_ptr)
{
	MessageCommand	*msgcmd_ptr;
	UFSRVResult 	*res_ptr			= NULL;

	msgcmd_ptr = data_msg_ptr->ufsrvcommand->msgcommand;

	if (unlikely(msgcmd_ptr->n_to <= 0) || IS_EMPTY(msgcmd_ptr->to) || IS_EMPTY(msgcmd_ptr->to[0])) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', o:'%p'}: ERROR: COMMAND CONTAINED ZERO TARGET USERS...", __func__, pthread_self(), THREAD_CONTEXT_PTR, sesn_ptr);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}

	UserRecord *user_ptr = msgcmd_ptr->to[0];
	if (user_ptr->ufsrvuid.len <= 0 || user_ptr->ufsrvuid.len > CONFIG_MAX_UFSRV_ID_SZ) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', o:'%p', ufsrvuid_sz:'%lu'}: ERROR: COMMAND CONTAINED INVALID UFSRVUID...", __func__, pthread_self(), THREAD_CONTEXT_PTR, sesn_ptr, user_ptr->ufsrvuid.len);

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}

  bool		lock_already_owned    = false;
  unsigned long sesn_call_flags	=	(CALL_FLAG_LOCK_SESSION|CALL_FLAG_LOCK_SESSION_BLOCKING|
                                     CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY| CALL_FLAG_HASH_USERNAME_LOCALLY|
                                     CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION|CALL_FLAG_REMOTE_SESSION);
  GetSessionForThisUserByUserId(sesn_ptr, UfsrvUidGetSequenceId((UfsrvUid *)user_ptr->ufsrvuid.data), &lock_already_owned, sesn_call_flags);
  InstanceHolderForSession *instance_sesn_ptr_target = (InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr);

  if (unlikely(IS_EMPTY(instance_sesn_ptr_target))) {
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  //sesn_ptr_target locked

  Session *sesn_ptr_target = SessionOffInstanceHolder(instance_sesn_ptr_target);

  if (IsUserOnShareListBlocked(sesn_ptr_target, sesn_ptr)) {
    if (!lock_already_owned)				SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_target, __func__);
#ifdef __UF__FULLDEBUG
    syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', o:'%p', o_target:'%lu'}: ERROR: REQUESTING USER IS ON TAGET USER"S BLOCK LIST, __func__, pthread_self(), THREAD_CONTEXT_PTR, sesn_ptr, sesn_ptr_target);
#endif

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_USER_SHARELIST_PRESENT)
  }

  if (GetUserPreferenceUnsolicitedContactAction(sesn_ptr_target, PREFSTORE_CACHED) == ACTION_ALLOW) {
    UfsrvEvent event = {0};
    RegisterSessionEvent (sesn_ptr, EVENT_TYPE_MESSAGE, MESSAGE_COMMAND__COMMAND_TYPES__INTRO, NULL, &event);

    if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
      //this is the point where we actually formally capture a record for the attachment,previously uploaded by the user

      if (IS_PRESENT(user_ptr->avatar)) {
        _ProcessAvatarAttachment(sesn_ptr, user_ptr->avatar, &event);
      }

      if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
        InterBroadcastUserMessage(sesn_ptr, CLIENT_CTX_DATA(msgcmd_ptr), (FenceEvent *) &event, msgcmd_ptr->header->args);

        _MarshalUserMessage(sesn_ptr, sesn_ptr_target, wsm_ptr_orig, data_msg_ptr, &event);

        if (!lock_already_owned) SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_target, __func__);

        return SESSION_RESULT_PTR(sesn_ptr);
      } else {
        //todo: return attachment error to user
      }
    }
  }

  if (!lock_already_owned) SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_target, __func__);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
}

inline static Envelope__Type _GetProtocolType (MessageCommand *msg_ptr);
inline static Envelope__Type _GetProtocolType (MessageCommand *msg_ptr)
{
	if (likely(msg_ptr->n_messages > 0 && IS_PRESENT(msg_ptr->messages[0]))) {
		return (Envelope__Type)msg_ptr->messages[0]->protocol_type;
	}

	return ENVELOPE__TYPE__UNKNOWN;
}

inline static UFSRVResult *
_MarshalUserMessage(Session *sesn_ptr, Session *sesn_ptr_target, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr_recieved, UfsrvEvent *event_ptr)
{
  _GENERATE_MESSAGECOMMAND_ENVELOPE_INITIALISATION();
  _PrepareMarshalMessageForUserMessage (&envelope_marshal, sesn_ptr, CLIENT_CTX_DATA(sesn_ptr_target), event_ptr, data_msg_ptr_recieved, MESSAGE_COMMAND__COMMAND_TYPES__INTRO, COMMAND_ARGS__ACCEPTED);

  MessageCommand		*msgcmd_ptr				= data_msg_ptr_recieved->ufsrvcommand->msgcommand;

  message_command.to    = msgcmd_ptr->to;
  message_command.n_to  = msgcmd_ptr->n_to;

  _MarshalUserMessageToUser (sesn_ptr, NULL, &command_envelope);

  //only to target user
  message_command.to            = NULL;
  message_command.n_to          = 0;
  message_command.header->args  = COMMAND_ARGS__SYNCED;

  if (msgcmd_ptr->n_messages > 0) {
    message_command.messages					=	msgcmd_ptr->messages;
    message_command.n_messages				=	msgcmd_ptr->n_messages;
  }

  //target user
  message_command.originator    =	MakeUserRecordFromSessionInProto (sesn_ptr, &user_record_originator, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF);

  if (IS_PRESENT(msgcmd_ptr->to[0]->avatar)) {
    message_command.originator->avatar =   msgcmd_ptr->to[0]->avatar;
  }

  _MarshalUserMessageToUser (sesn_ptr, sesn_ptr_target, &command_envelope);

  return SESSION_RESULT_PTR(sesn_ptr);
}

/**
 * 	@locks f_ptr: RW
 */
inline static UFSRVResult *
_MarshalMessageToFence (Session *sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, Fence *f_ptr, FenceEvent *fence_event_ptr)
{

	if (FENCE_SESSIONS_LIST_SIZE(f_ptr) <= 0) {
		syslog(LOG_NOTICE, "%s {pid:'%lu', o:'%p', cname:'%s', fid:'%lu'} NOTICE: Fence has zero members: RETURNING... ", __func__, pthread_self(), sesn_ptr, FENCE_CNAME(f_ptr), FENCE_ID(f_ptr));
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_EMPTY_INVITATION_LIST);
	}

	UserRecord 				user_record_originator;
	FenceRecord				*fence_record_ptr	= NULL;
	Envelope 					command_envelope	= ENVELOPE__INIT;
	CommandHeader 		header						= COMMAND_HEADER__INIT;
	UfsrvCommandWire	ufsrv_command			= UFSRV_COMMAND_WIRE__INIT;
	MessageCommand 		message_command		= MESSAGE_COMMAND__INIT;
	MessageCommand		*msgcmd_ptr				= data_msg_ptr->ufsrvcommand->msgcommand;

	//plumb in static elements
	command_envelope.ufsrvcommand				=	&ufsrv_command;
	ufsrv_command.header								=	&header;
	message_command.header							=	&header;

	//plumb in FenceRecords array
	FenceRecord *fence_records[1];
	ufsrv_command.msgcommand						=	&message_command;	//connect command
	ufsrv_command.ufsrvtype							=	UFSRV_COMMAND_WIRE__UFSRV_TYPE__UFSRV_MESSAGE;

	fence_record_ptr										=	MakeFenceRecordInProtoAsIdentifier(sesn_ptr, f_ptr, NULL);
	fence_record_ptr->expire_timer			=	FENCE_MSG_EXPIRY(f_ptr); fence_record_ptr->has_expire_timer=1;
//	originator_ptr											=	//MakeUserRecordForSelfInProto (sesn_ptr, PROTO_USER_RECORD_MINIMAL);

	fence_records[0]										=	fence_record_ptr;
	message_command.fences							=	fence_records;
	message_command.n_fences						=	1;
	message_command.originator					=	MakeUserRecordFromSessionInProto (sesn_ptr, &user_record_originator, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF);

	if (msgcmd_ptr->n_messages > 0) {
		message_command.messages					=	msgcmd_ptr->messages;
		message_command.n_messages				=	msgcmd_ptr->n_messages;
	}

	if (msgcmd_ptr->n_attachments > 0) {
		message_command.attachments		=	msgcmd_ptr->attachments;
		message_command.n_attachments	=	msgcmd_ptr->n_attachments;
	}

	if (msgcmd_ptr->quoted_message != NULL) {
		message_command.quoted_message		=	msgcmd_ptr->quoted_message;
	}

  if (msgcmd_ptr->contacts != NULL) {
    if (_IsContactSharing(sesn_ptr, msgcmd_ptr->contacts)) {
      message_command.contacts		=	msgcmd_ptr->contacts;
      message_command.n_contacts  = msgcmd_ptr->n_contacts;
    } else {
      //todo: error message
    }
  }

	if (msgcmd_ptr->preview != NULL) {
		message_command.preview		 =  msgcmd_ptr->preview;
		message_command.n_preview  =  msgcmd_ptr->n_preview;
	}

	command_envelope.source			=	"0";//ufsrv initiated origin
	command_envelope.timestamp	=	GetTimeNowInMillis(); command_envelope.has_timestamp = 1;
	command_envelope.type				= _GetProtocolType(msgcmd_ptr); command_envelope.has_type = 1;
	header.when									=	command_envelope.timestamp; header.has_when = 1;
	header.when_client					=	msgcmd_ptr->header->when; header.has_when_client = 1;//this the timestamp internal to the client (date_sent)
	header.command							=	MESSAGE_COMMAND__COMMAND_TYPES__SAY;
	header.args									=	COMMAND_ARGS__SYNCED; header.has_args = 1;

	bool fence_lock_already_owned = false;
	FenceEventsLockRWCtx(THREAD_CONTEXT_PTR, f_ptr, _LOCK_TRY_FLAG_FALSE, SESSION_RESULT_PTR(sesn_ptr), __func__);
	if (SESSION_RESULT_TYPE_EQUAL(sesn_ptr, RESULT_TYPE_ERR)) goto return_error;
	fence_lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_PROG_LOCKED_THIS_THREAD));

	FenceEvent *fe_ptr = fence_event_ptr;

	header.eid = fe_ptr->eid; header.has_eid = 1;

	delivery_mode_broadcast:
	if (F_ATTR_IS_SET(FENCE_ATTRIBUTES(f_ptr), F_ATTR_BROADCAST)) {
		Session *sesn_ptr_fence_owner = GetSessionForFenceOwner(sesn_ptr, f_ptr);
		if (IS_PRESENT(sesn_ptr_fence_owner)) {
      _MarshalFenceMessageToUser(sesn_ptr, sesn_ptr_fence_owner, f_ptr, &command_envelope);//f_ptr just to enable logging

			goto return_destruct_proto;
		}
	}

	FenceRawSessionList raw_session_list = {0};
	GetRawMemberUsersListForFence (sesn_ptr, InstanceHolderFromClientContext(CLIENT_CTX_DATA(f_ptr)), FENCE_CALLFLAG_INCLUDE_REMOTE_SESSIONS, &raw_session_list);//no locking
	if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));

	if (raw_session_list.sessions_sz > 0) {
		for (size_t i=0; i<raw_session_list.sessions_sz; i++) {
      Session *sesn_ptr_listed = SessionOffInstanceHolder(raw_session_list.sessions[i]);
			if (SESSION_ID(sesn_ptr) == SESSION_ID(sesn_ptr_listed))	continue; //skip self

      _MarshalFenceMessageToUser(sesn_ptr, sesn_ptr_listed, f_ptr, &command_envelope);//f_ptr just to enable logging
		}
	}

	DestructFenceRawSessionList (&raw_session_list, false);

	return_destruct_proto:
	DestructFenceRecordsProto (fence_records, message_command.n_fences, false);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_UFSRV_INTERBROADCAST);

	return_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_UFSRV_INTERBROADCAST);
}

inline static UFSRVResult *
_MarshalFenceMessageToUser(Session *sesn_ptr, Session *sesn_ptr_target, Fence *f_ptr, Envelope *command_envelope_ptr)
{
	CommandHeader *command_header_ptr	=	command_envelope_ptr->ufsrvcommand->header;
	command_header_ptr->cid						=	SESSION_ID((sesn_ptr_target?sesn_ptr_target:sesn_ptr)); command_header_ptr->has_cid=1;

	WebSocketMessage wsmsg; wsmsg.type=WEB_SOCKET_MESSAGE__TYPE__REQUEST;//dummy
	UfsrvCommandMarshallingDescription ufsrv_descpription={command_header_ptr->eid, FENCE_ID(f_ptr), command_header_ptr->when, &EnvelopeMetaData, command_envelope_ptr};

#ifdef __UF_TESTING
	syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', cid_target:'%lu' uname_target:'%s', fcname:'%s'} Sending Message to User ", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr),
				SESSION_ID((sesn_ptr_target?sesn_ptr_target:sesn_ptr)), SESSION_USERNAME((sesn_ptr_target?sesn_ptr_target:sesn_ptr)), FENCE_CNAME(f_ptr));
#endif

	UfsrvCommandInvokeCommand (sesn_ptr, sesn_ptr_target, &wsmsg, NULL, &ufsrv_descpription, uMSG_V1_IDX);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

inline static UFSRVResult *
_MarshalUserMessageToUser(Session *sesn_ptr, Session *sesn_ptr_target, Envelope *command_envelope_ptr)
{
  CommandHeader *command_header_ptr	=	command_envelope_ptr->ufsrvcommand->header;
  command_header_ptr->cid						=	SESSION_ID((sesn_ptr_target?sesn_ptr_target:sesn_ptr)); command_header_ptr->has_cid=1;

  WebSocketMessage wsmsg; wsmsg.type = WEB_SOCKET_MESSAGE__TYPE__REQUEST;//dummy
  UfsrvCommandMarshallingDescription ufsrv_descpription={command_header_ptr->eid, 0, command_header_ptr->when, &EnvelopeMetaData, command_envelope_ptr};

#ifdef __UF_TESTING
  syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', cid_target:'%lu' uname_target:'%s'} Sending UserMessage to User ", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr),
          SESSION_ID((sesn_ptr_target?sesn_ptr_target:sesn_ptr)), SESSION_USERNAME((sesn_ptr_target?sesn_ptr_target:sesn_ptr)));
#endif

  UfsrvCommandInvokeCommand (sesn_ptr, sesn_ptr_target, &wsmsg, NULL, &ufsrv_descpription, uMSG_V1_IDX);

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

/**
 * @brief Check if shared contact is permitting sender to share their contact info
 * @param sesn_ptr the sender of the contact
 * @param contact_record_ptr
 */
static bool
_IsContactSharing(Session *sesn_ptr, ContactRecord **contact_records_ptr)
{
  bool          is_allowed_status   = true;
  ContactRecord *contact_record_ptr = contact_records_ptr[0];
  if (contact_record_ptr->has_ufsrvuid && contact_record_ptr->ufsrvuid.data != NULL && contact_record_ptr->ufsrvuid.len == CONFIG_MAX_UFSRV_ID_SZ) {
    bool          lock_already_owned  = false;
    unsigned long sesn_call_flags     =	(CALL_FLAG_LOCK_SESSION|CALL_FLAG_LOCK_SESSION_BLOCKING|
                                         CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY| CALL_FLAG_HASH_USERNAME_LOCALLY|
                                         CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION|CALL_FLAG_REMOTE_SESSION);

    GetSessionForThisUserByUserId(sesn_ptr, UfsrvUidGetSequenceId((const UfsrvUid *)contact_record_ptr->ufsrvuid.data), &lock_already_owned, sesn_call_flags);
    InstanceHolderForSession *instance_sesn_ptr_shared = (InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr);
    if (IS_PRESENT(instance_sesn_ptr_shared)) {
      Session *sesn_ptr_shared = SessionOffInstanceHolder(instance_sesn_ptr_shared);
      if (!IsUserOnShareListContacts(sesn_ptr_shared, sesn_ptr)) {
        is_allowed_status = false;
      }

      if (!lock_already_owned)				SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_shared, __func__);
    }
  }

  return is_allowed_status;

}
/// END MSG \\\

/*
 * @param errcode: should reflect a UFSRVResult.rescode type
 * @param command_type: should reflect a protobif command type, or -1 to re use original
 *
 */
static void
_BuildErrorHeaderForMessageCommand (CommandHeader *header_ptr, CommandHeader *header_ptr_incoming, int errcode, int command_type)
{
  switch (errcode)
  {
    case RESCODE_USERCMD_MISSING_PARAM:
      header_ptr->args_error	=	MESSAGE_COMMAND__ERRORS__NO_POSTING_ALLOWED; 	header_ptr->has_args_error	=	1;
      header_ptr->args				=	COMMAND_ARGS__REJECTED;									header_ptr->has_args				=	1;
      break;

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
_HandleMessageCommandError (Session *sesn_ptr, ClientContextData *ctx_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, int rescode, int command_type)
{
  Envelope 					command_envelope	= ENVELOPE__INIT;
  CommandHeader 		header						= COMMAND_HEADER__INIT;
  UfsrvCommandWire	ufsrv_command			= UFSRV_COMMAND_WIRE__INIT;
  MessageCommand 		message_command		= MESSAGE_COMMAND__INIT;

  command_envelope.ufsrvcommand				=	&ufsrv_command;
  ufsrv_command.header								=	&header;
  message_command.header							=	&header;

  ufsrv_command.msgcommand						=	&message_command;
  ufsrv_command.ufsrvtype							=	UFSRV_COMMAND_WIRE__UFSRV_TYPE__UFSRV_MESSAGE;


  command_envelope.source							=	"0";
  command_envelope.timestamp					=	GetTimeNowInMillis(); command_envelope.has_timestamp=1;

  header.when													=	command_envelope.timestamp; header.has_when		=	1;
  header.cid													=	SESSION_ID(sesn_ptr);				header.has_cid		=	1;

  _BuildErrorHeaderForMessageCommand (&header, data_msg_ptr->ufsrvcommand->msgcommand->header, rescode, command_type);

#ifdef __UF_TESTING
  syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', uid:'%lu', cid:'%lu', arg_error:'%d', rescode:'%d'}: Marshaling Error response message...", __func__, pthread_self(), sesn_ptr, SESSION_USERID(sesn_ptr), SESSION_ID(sesn_ptr), header.args_error, rescode);
#endif

  return (_MarshalCommandToUser(sesn_ptr, NULL, &command_envelope,  uGETKEYS_V1_IDX));//TODO: temp use of uGETKEYS_V1
}

/**
 * 	@brief Generalised command sending
 */
inline static UFSRVResult *
_MarshalCommandToUser	(Session *sesn_ptr, Session *sesn_ptr_target, Envelope *command_envelope_ptr, unsigned req_cmd_idx)
{
  CommandHeader *command_header_ptr	=	command_envelope_ptr->ufsrvcommand->msgcommand->header;

  WebSocketMessage wsmsg; wsmsg.type = WEB_SOCKET_MESSAGE__TYPE__RESPONSE;//dummy
  UfsrvCommandMarshallingDescription ufsrv_descpription = {command_header_ptr->eid, 0, command_header_ptr->when, &EnvelopeMetaData, command_envelope_ptr};

  UfsrvCommandInvokeCommand (sesn_ptr, sesn_ptr_target, &wsmsg, NULL, &ufsrv_descpription, req_cmd_idx);

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}
