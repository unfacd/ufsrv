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
#include <incoming_message_descriptor_type.h>
#include <command_base_context_type.h>
#include <message.h>
#include <fence.h>
#include <ufsrv_core/fence/fence_utils.h>
#include <fence_proto.h>
#include <ufsrv_events.h>
#include <ufsrv_core/user/user_backend.h>
#include <ufsrv_core/user/users_protobuf.h>
#include <ufsrvwebsock/include/protocol_websocket.h>
#include <ufsrvcmd_user_callbacks.h>
#include <ufsrvcmd_callbacks.h>
#include <ufsrv_core/SignalService.pb-c.h>
#include <message_command_broadcast.h>
#include <message_command_controller.h>
#include <ufsrv_core/location/location.h>
#include <recycler/recycler.h>
#include <attachments.h>
#include <ufsrvuid.h>
#include <include/guardian_record_descriptor.h>


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

#define _GENERATE_MESSAGECOMMAND_FOR_INTRO_ENVELOPE_INITIALISATION() \
	UfsrvCommandWire								ufsrv_command_wire	= UFSRV_COMMAND_WIRE__INIT;	\
	Envelope												command_envelope		=	ENVELOPE__INIT;	\
	MessageCommand 									message_command			=	MESSAGE_COMMAND__INIT;	\
	CommandHeader 									header							=	COMMAND_HEADER__INIT;	\
	IntroMessageRecord              intro_message       = INTRO_MESSAGE_RECORD__INIT; \
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

#define _BUILD_COMMAND_CONTEXT() \
 MessageCommandContext command_ctx = { \
         .command_base_context = { \
          .data_msg_ptr_received = data_msg_ptr_received, \
          .wsm_ptr_received = wsm_ptr_received, \
          .sesn_originator = { \
            .ctx_ptr = ctx_sesn_ptr, \
            .lock_state = false \
          } \
         }, \
       .msg_descriptor_ptr = msg_descriptor_ptr_out \
 }; \

inline static void _PrepareMarshalMessageForUserMessage(MarshalMessageEnvelopeForUser *envelope_ptr, Session *sesn_ptr, Fence *f_ptr, UfsrvEvent *event_ptr, DataMessage *data_msg_ptr_orig, enum _UserCommand__CommandTypes command_type, enum _CommandArgs command_arg);
inline static UFSRVResult *_UfsrvCommandControllerMessageSay (InstanceContextForSession *ctx_sesn_ptr_local_user, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, ParsedMessageDescriptor *msg_descriptor_ptr_out);
inline static UFSRVResult *_UfsrvCommandControllerMessageIntro (InstanceContextForSession *ctx_sesn_ptr_local_user, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, ParsedMessageDescriptor *msg_descriptor_ptr_out);
inline static UFSRVResult *_UfsrvCommandControllerMessageReported (CommandBaseContext *cmd_base_ctx);
inline static UFSRVResult *_UfsrvCommandControllerGuardianRequest (CommandBaseContext *cmd_base_ctx);
inline static UFSRVResult *_UfsrvCommandControllerGuardianLink (CommandBaseContext *cmd_base_ctx);
inline static UFSRVResult *_UfsrvCommandControllerGuardianUnlink (CommandBaseContext *cmd_base_ctx);
inline static UFSRVResult *_UfsrvCommandControllerMessageEffect (CommandBaseContext *cmd_base_ctx);
inline static UFSRVResult *_UfsrvCommandControllerMessageReaction (CommandBaseContext *cmd_base_ctx);

inline static UFSRVResult *_MarshalMessageToFence (InstanceContextForSession *ctx_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, InstanceContextForFence *, FenceEvent *);
inline static UFSRVResult *_MarshalFenceMessageToUser(InstanceContextForSession *ctx_sesn_ptr, InstanceHolderForSession *instance_sesn_ptr_target, WebSocketMessage *wsm_ptr_orig, unsigned long fid, Envelope *command_envelope_ptr);

inline static UFSRVResult *_MarshalIntroMessage(InstanceContextForSession *ctx_sesn_ptr, InstanceHolderForSession *instance_sesn_ptr_target, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received, UfsrvEvent *event_ptr);
inline static UFSRVResult *_MarshalUserMessageToUser(InstanceContextForSession *ctx_sesn_ptr, InstanceHolderForSession *, WebSocketMessage *, Envelope *command_envelope_ptr);
static UFSRVResult *_MarshalMessageCommandSync(InstanceContextForSession *ctx_sesn_ptr, DataMessage *dm_received, WebSocketMessage *wsm_ptr_received, Envelope *command_envelope_ptr);
static bool _IsContactSharing(Session *sesn_ptr, UserContactRecord **contact_records_ptr);

static void _BuildErrorHeaderForMessageCommand (CommandHeader *header_ptr, CommandHeader *header_ptr_incoming, int errcode, int command_type);
inline static UFSRVResult *_MarshalCommandToUser	(InstanceHolderForSession *, InstanceHolderForSession *, WebSocketMessage *, Envelope *command_envelope_ptr, unsigned req_cmd_idx);
static UFSRVResult *_HandleMessageCommandError (InstanceHolderForSession *, ClientContextData *ctx_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, int rescode, int command_type);
static ParsedMessageDescriptor *_ParsedMessageDescriptorForMessageCommand (InstanceContextForSession *ctx_sesn_ptr, DataMessage *dm_ptr, ParsedMessageDescriptor *msg_descriptor_ptr_out);

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

  envelope_ptr->envelope->sourceufsrvuid		=	"0";
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
    envelope_ptr->header->gid								=	event_ptr->gid; 					envelope_ptr->header->has_gid = 1;
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
 * 	@param msg_descriptor_ptr_out allocated descriptor. must be set to zero state in all fields.
 * 	@locked sesn_ptr_local_user: by caller
 */
UFSRVResult *
CommandCallbackControllerMessageCommand (InstanceContextForSession *ctx_sesn_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received, ParsedMessageDescriptor *msg_descriptor_ptr_out)
{
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
          &&MESSAGE_COMMAND__COMMAND_TYPES__EFFECT,
          &&MESSAGE_COMMAND__COMMAND_TYPES__REACTION
  }; //ALIGN WITH PROTOBUF

  _BUILD_COMMAND_CONTEXT();

	CommandHeader *command_header = data_msg_ptr_received->ufsrvcommand->msgcommand->header;
	if (unlikely(IS_EMPTY(command_header)))	_RETURN_RESULT_SESN(ctx_sesn_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

	UFSRVResult *res_ptr = NULL;
  goto *command_types[command_header->command];

  MESSAGE_COMMAND__COMMAND_TYPES__SAY:
  return _UfsrvCommandControllerMessageSay (ctx_sesn_ptr, wsm_ptr_received, data_msg_ptr_received, msg_descriptor_ptr_out);

  MESSAGE_COMMAND__COMMAND_TYPES__CONTACTS: goto return_unknown;

  MESSAGE_COMMAND__COMMAND_TYPES__FLAG:
  return _UfsrvCommandControllerMessageReported(COMMAND_BASE_CONTEXT(&command_ctx));

  MESSAGE_COMMAND__COMMAND_TYPES__LIKE: goto return_unknown;
  MESSAGE_COMMAND__COMMAND_TYPES__FOLLOW: goto return_unknown;
  MESSAGE_COMMAND__COMMAND_TYPES__PREVIEW: goto return_unknown;

  MESSAGE_COMMAND__COMMAND_TYPES__INTRO:
  return _UfsrvCommandControllerMessageIntro (ctx_sesn_ptr, wsm_ptr_received, data_msg_ptr_received, msg_descriptor_ptr_out);

  MESSAGE_COMMAND__COMMAND_TYPES__STICKER: goto return_unknown;

  MESSAGE_COMMAND__COMMAND_TYPES__GUARDIAN_REQUEST:
  return _UfsrvCommandControllerGuardianRequest(COMMAND_BASE_CONTEXT(&command_ctx));

  MESSAGE_COMMAND__COMMAND_TYPES__GUARDIAN_LINK:
  return _UfsrvCommandControllerGuardianLink(COMMAND_BASE_CONTEXT(&command_ctx));

  MESSAGE_COMMAND__COMMAND_TYPES__GUARDIAN_UNLINK:
  return _UfsrvCommandControllerGuardianUnlink(COMMAND_BASE_CONTEXT(&command_ctx));

  MESSAGE_COMMAND__COMMAND_TYPES__EFFECT:
  return _UfsrvCommandControllerMessageEffect(COMMAND_BASE_CONTEXT(&command_ctx));

  MESSAGE_COMMAND__COMMAND_TYPES__REACTION:
  return _UfsrvCommandControllerMessageReaction(COMMAND_BASE_CONTEXT(&command_ctx));

  return_unknown:
  syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cmd:'%d'}: ERROR: UNKNOWN MESSAGE COMMAND", __func__, pthread_self(), ctx_sesn_ptr->sesn_ptr, command_header->command);
  res_ptr = SESSION_RESULT_PTR(ctx_sesn_ptr->sesn_ptr);
  return res_ptr;

}

inline static UFSRVResult * _ProcessMessageAttachments (Session *sesn_ptr, const MessageCommand *msgcmd_ptr, unsigned long fid, unsigned long event_rowid);

/**
 *
 * @param ctx_sesn_ptr Session for sender
 * @param wsm_ptr_received only set id command arrived via websocket
 * @param data_msg_ptr As packeged by sender
 * @param msg_descriptor_ptr_out packaging describing elements of the parsed message that can be used for backend persistence
 * @locks f_ptr
 * @unlocks f_ptr on error
 */
inline static UFSRVResult *
_UfsrvCommandControllerMessageSay (InstanceContextForSession *ctx_sesn_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr, ParsedMessageDescriptor *msg_descriptor_ptr_out)
{
  int rescode = RESCODE_PROG_NULL_POINTER;
  unsigned long	fid;
  Fence 			*f_ptr				= NULL;
  MessageCommand	*msgcmd_ptr;

  Session *sesn_ptr = SessionOffInstanceHolder(ctx_sesn_ptr->instance_sesn_ptr);

  msgcmd_ptr = data_msg_ptr->ufsrvcommand->msgcommand;

  if (unlikely(msgcmd_ptr->n_fences <= 0)) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: MESSAGECOMMAND CONTAINED ZERO FENCE DEFINITION...", __func__, pthread_self(), sesn_ptr);

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  if (unlikely(msgcmd_ptr->n_messages <= 0)) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: MESSAGECOMMAND CONTAINED ZERO MESSAGE DEFINITION...", __func__, pthread_self(), sesn_ptr);

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  fid = msgcmd_ptr->fences[0]->fid;

  bool lock_already_owned = false;

  if (fid > 0) {
    unsigned long fence_call_flags_final = FENCE_CALLFLAG_SEARCH_BACKEND |
                                           FENCE_CALLFLAG_HASH_FENCE_LOCALLY |
                                           FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE |
                                           FENCE_CALLFLAG_KEEP_FENCE_LOCKED | FENCE_CALLFLAG_LOCK_FENCE_BLOCKING;

    FindFenceById(sesn_ptr, fid, fence_call_flags_final);
    InstanceHolderForFence *instance_f_ptr = SESSION_RESULT_USERDATA(sesn_ptr);

    if (IS_EMPTY(instance_f_ptr)) {
      if (SESSION_RESULT_TYPE_EQUAL(sesn_ptr, RESCODE_PROG_WONTLOCK)) {
        _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, SESSION_RESULT_CODE(sesn_ptr))
      } else {
        syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu'): COULD NOT FIND FENCE bid:'%lu'...", __func__, pthread_self(), SESSION_ID(sesn_ptr), fid);

        _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, SESSION_RESULT_CODE(sesn_ptr))
      }
    }

    //lock acquired

    lock_already_owned = SESSION_RESULT_TYPE_EQUAL(sesn_ptr, RESCODE_PROG_LOCKED_BY_THIS_THREAD);

    f_ptr = FenceOffInstanceHolder(instance_f_ptr);

    delivery_mode_oneway_broadcast: //only owner allowed to publish
    if (F_ATTR_IS_SET(FENCE_ATTRIBUTES(f_ptr), F_ATTR_BROADCAST_ONEWAY)) {
      if (SESSION_USERID(sesn_ptr) != FENCE_OWNER_UID(f_ptr)) {
        syslog(LOG_DEBUG,
               "%s (pid:'%lu', co:'%p', cid:'%lu', fo:'%p', fid:'%lu', uid_owner:'%lu', uid_sender:'%lu'): ERROR: F_ATTR_BROADCAST_ONE-WAY IS SET",
               __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), f_ptr, fid, FENCE_OWNER_UID(f_ptr),
               SESSION_USERID(sesn_ptr));

        rescode = RESCODE_LOGIC_EMPTY_RESOURCE; goto return_unlock_fence;
      }
    }

    if (!(IsUserMemberOfThisFence(&SESSION_FENCE_LIST(sesn_ptr), f_ptr, false))) {
      syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', bid:'%lu'): ERROR: USER IS NOT MEMBER OF FENCE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), fid);

      rescode = RESCODE_LOGIC_EMPTY_RESOURCE; goto return_unlock_fence;
    }

    FenceEvent fence_event = {0};
    if (IS_EMPTY((RegisterFenceEvent(sesn_ptr, f_ptr, EVENT_TYPE_FENCE_USR_MSG, NULL, 0, &fence_event)))) {
      rescode = RESCODE_FENCE_EVENT_GENERATION; goto return_unlock_fence;
    }

    fence_event.event_cmd_type = MSGCMD_MESSAGE;

    bool is_fence_public = F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_BASEFENCE) || !F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_PRIVATE);

    DbBackendInsertUfsrvEvent((UfsrvEvent *) &fence_event);
    if (THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA) {
      _ProcessMessageAttachments (sesn_ptr, msgcmd_ptr, FENCE_ID(f_ptr), fence_event.gid);
      if (SESSION_RESULT_TYPE_ERROR(sesn_ptr)) {
        rescode = SESSION_RESULT_CODE(sesn_ptr);
        goto return_unlock_fence;
      }

      if (F_ATTR_IS_SET(FENCE_ATTRIBUTES(f_ptr), F_ATTR_BROADCAST)) {
        if (SESSION_USERID(sesn_ptr) == FENCE_OWNER_UID(f_ptr)) {
          InterBroadcastUserMessage(sesn_ptr, (ClientContextData *) msgcmd_ptr, &fence_event, COMMAND_ARGS__ADDED);

          if (!lock_already_owned) FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));

          return SESSION_RESULT_PTR(sesn_ptr); //only fence owner can see, but sender and owner are the same, so nothing to marshall
        }
      }

      InstanceContextForFence fence_context = {instance_f_ptr, f_ptr, lock_already_owned, true};
      UFSRVResult *res_ptr = _MarshalMessageToFence(ctx_sesn_ptr, wsm_ptr_received, data_msg_ptr, &fence_context, &fence_event);
      if (fence_context.is_locked && !lock_already_owned) FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));

      if (_RESULT_TYPE_SUCCESS(res_ptr) && _RESULT_CODE_EQUAL(res_ptr, RESCODE_UFSRV_INTERBROADCAST)) {
        InterBroadcastUserMessage(sesn_ptr, (ClientContextData *) msgcmd_ptr, &fence_event, COMMAND_ARGS__ADDED);//update to COMMAND_ARGS__POSTED
      }

      if (is_fence_public) {
        msg_descriptor_ptr_out->eid = fence_event.eid;
        msg_descriptor_ptr_out->gid = fence_event.gid;
        _RETURN_RESULT_SESN(sesn_ptr,
                            _ParsedMessageDescriptorForMessageCommand(ctx_sesn_ptr, data_msg_ptr, msg_descriptor_ptr_out),
                            RESULT_TYPE_SUCCESS, RESCODE_UFSRV_STORE_MSG)
      } else _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
    }
  } else {
    goto return_unlock_fence;
  }

  return_unlock_fence:
  if (!lock_already_owned)  FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));

  return_error:
  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)
}

inline static UFSRVResult *
_ProcessMessageAttachments (Session *sesn_ptr, const MessageCommand *msgcmd_ptr, unsigned long fid, unsigned long event_rowid)
{
  //TODO: REPLACE THIS BLOCK WITH attachments.c:AttachmentDescriptorValidateFromProto
  //this is the point where we actually formally capture a record for the attachment, previously uploaded by the user

  size_t attachments_sz = msgcmd_ptr->n_attachments;
  if (attachments_sz == 0) {
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_LOGIC_EMPTY_RESOURCE)
  }

  if (msgcmd_ptr->n_attachments > _CONFIGDEFAULT_MESSAGE_MAX_ATTACHMENTS_SZ) {
    attachments_sz = _CONFIGDEFAULT_MESSAGE_MAX_ATTACHMENTS_SZ;
  }

  AttachmentRecord *attachment_record[attachments_sz];
  AttachmentDescriptor attachment[attachments_sz]; //IMPORTANT ufsrv doesnt implement TypePool for this type
  memset(attachment, 0, sizeof(attachment));

  size_t idx;
  for (idx=0; idx<attachments_sz; idx++) {
    //TODO: why is it an error to resend the same attachment? we shouldn't store it, but should be OK to forward it
    //if (!IS_EMPTY(GetAttachmentDescriptorEphemeral(sesn_ptr, attachment_record->id, &attachment))) goto return_attachment_already_exists;
    if (IS_EMPTY((attachment_record[idx] = msgcmd_ptr->attachments[idx]))) {
      _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_INCONSISTENT_DATA)
    }

    if (!AttachmentDescriptorGetFromProto(sesn_ptr, attachment_record[idx], event_rowid, &attachment[idx], true)) {
      _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_INCONSISTENT_DATA)
    }
  }

  //todo error handling for db insertion
  for (idx=0; idx<attachments_sz; idx++) {
    DbAttachmentStore(sesn_ptr, &attachment[idx], fid, DEFAULT_DEVICE_ID);//ufsrv instances currently doesn't support lru-caching attachments
    AttachmentDescriptorDestruct(&attachment[idx], true, false);
  }

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
}

inline static UFSRVResult *_ProcessAvatarAttachment (Session *sesn_ptr, AttachmentRecord *attachment_ptr, UfsrvEvent *event_ptr);
inline static UFSRVResult *
_ProcessAvatarAttachment (Session *sesn_ptr, AttachmentRecord *attachment_ptr, UfsrvEvent *event_ptr)
{
  //this is the point where we actually formally capture a record for the attachment, previously uploaded by the user
  AttachmentDescriptor *attachment_descriptors[1];
  AttachmentDescriptor attachment_descriptor = {0};
  attachment_descriptors[0] = &attachment_descriptor;
  CollectionDescriptor attachment_descriptors_collection = {
          .collection_sz  = 1,
          .collection     = AS_COLLECTION_TYPE(attachment_descriptors)
  };

  AttachmentRecord *attachment_records[1];
  attachment_records[0] = attachment_ptr;
  CollectionDescriptor attachments_collection = {
          .collection_sz  = 1,
          .collection     = AS_COLLECTION_TYPE(attachment_records)
  };
  AttachmentDescriptorValidateFromProto(sesn_ptr, NULL, &attachments_collection, event_ptr->eid, true, &attachment_descriptors_collection);

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
_UfsrvCommandControllerMessageIntro (InstanceContextForSession *ctx_sesn_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr, ParsedMessageDescriptor *msg_descriptor_ptr_out)
{
	MessageCommand	*msgcmd_ptr;
	UFSRVResult 	*res_ptr			= NULL;

	Session *sesn_ptr = ctx_sesn_ptr->sesn_ptr;

	msgcmd_ptr = data_msg_ptr->ufsrvcommand->msgcommand;

	if (unlikely(IS_EMPTY(msgcmd_ptr->intro))) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', o:'%p'}: ERROR: COMMAND CONTAINED NO INTRO RECORD...", __func__, pthread_self(), THREAD_CONTEXT_PTR, sesn_ptr);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}

	//"to" filed from incoming can be either type of HandleType
	IntroMessageRecord *record_ptr = msgcmd_ptr->intro;
	if (!IS_STR_LOADED(record_ptr->to)  || strlen(record_ptr->to) > CONFIG_MAX_NICKNAME_SIZE) {//convenient upper limit
    syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', o:'%p'}: ERROR: COMMAND CONTAINED INVALID HANDLE ID...", __func__, pthread_self(), THREAD_CONTEXT_PTR, sesn_ptr);

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}

  bool		lock_already_owned    = false;
  unsigned long sesn_call_flags	=	(CALL_FLAG_LOCK_SESSION|CALL_FLAG_LOCK_SESSION_BLOCKING|
                                     CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY| CALL_FLAG_HASH_USERNAME_LOCALLY|
                                     CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION|CALL_FLAG_REMOTE_SESSION);

//  GetSessionForThisUserByUserId(sesn_ptr, UfsrvUidGetSequenceId((UfsrvUid *)user_ptr->ufsrvuid.data), &lock_already_owned, sesn_call_flags);
  GetSessionFromUserHandle(sesn_ptr, record_ptr->to, &lock_already_owned, sesn_call_flags);
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
    RegisterUfsrvEvent(sesn_ptr, EVENT_TYPE_USER_INTRO, MESSAGE_COMMAND__COMMAND_TYPES__INTRO, NULL, &event);

    if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
      //this is the point where we actually formally capture a record for the attachment,previously uploaded by the user

      if (IS_PRESENT(record_ptr->avatar)) {
        _ProcessAvatarAttachment(sesn_ptr, record_ptr->avatar, &event);
      }

      if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
        InterBroadcastUserMessage(sesn_ptr, CLIENT_CTX_DATA(msgcmd_ptr), (FenceEvent *) &event, msgcmd_ptr->header->args);

        _MarshalIntroMessage(ctx_sesn_ptr, instance_sesn_ptr_target, wsm_ptr_received, data_msg_ptr, &event);

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

inline static UFSRVResult *_MarshalMessageReported (CommandBaseContext *cmd_base_ctx);
inline static UFSRVResult *_MarshalMessageEffect (CommandBaseContext *cmd_base_ctx);
inline static UFSRVResult *_MarshalMessageReaction (CommandBaseContext *cmd_base_ctx);
inline static UFSRVResult *_MarshalGuardianRequest (CommandBaseContext *cmd_base_ctx);
inline static UFSRVResult *_MarshalGuardianLink (CommandBaseContext *cmd_base_ctx);
inline static UFSRVResult *_MarshalGuardianUnLink (CommandBaseContext *cmd_base_ctx);

/**
 * @brief Flagged commands can only point to events of type MSGCMD_MESSAGE
 * @param ctx_sesn_ptr
 * @param wsm_ptr_received
 * @param data_msg_ptr
 * @param msg_descriptor_ptr_out
 * @return
 */
inline static UFSRVResult *
_UfsrvCommandControllerMessageReported (CommandBaseContext *cmd_base_ctx)
{
  MessageCommandContext *cmd_ctx_ptr = (MessageCommandContext *)cmd_base_ctx;
  MessageCommand	*msgcmd_ptr = cmd_base_ctx->data_msg_ptr_received->ufsrvcommand->msgcommand;

  if (IS_EMPTY(msgcmd_ptr->reported) || IS_EMPTY(msgcmd_ptr->reported[0])) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', o:'%p'}: ERROR: COMMAND CONTAINED INVALID REPORTED CONTENT RECORD...", __func__, pthread_self(), THREAD_CONTEXT_PTR, CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr));

    _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  return (IsUserAllowedToReportMessage(cmd_base_ctx, _MarshalMessageReported, CALLFLAGS_EMPTY));
}

#define _FIND_FENCE(fid) \
  unsigned long fence_call_flags_final = FENCE_CALLFLAG_SEARCH_BACKEND | \
  FENCE_CALLFLAG_HASH_FENCE_LOCALLY |   FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE | \
  FENCE_CALLFLAG_KEEP_FENCE_LOCKED | FENCE_CALLFLAG_LOCK_FENCE_BLOCKING; \
  \
  FindFenceById(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), fid, fence_call_flags_final); \
  InstanceHolderForFence *instance_f_ptr = SESSION_RESULT_USERDATA(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)); \
  \
  if (IS_EMPTY(instance_f_ptr)) { \
    if (SESSION_RESULT_TYPE_EQUAL(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), RESCODE_PROG_WONTLOCK)) { \
      _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_ERR, SESSION_RESULT_CODE(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr))) \
    } else {  \
        syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu'): COULD NOT FIND FENCE bid:'%lu'...", __func__, pthread_self(), SESSION_ID(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)), fid); \
        \
        _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_ERR, SESSION_RESULT_CODE(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr))) \
    } \
  } \
  \
  fence_lock_already_owned = SESSION_RESULT_TYPE_EQUAL(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), RESCODE_PROG_LOCKED_BY_THIS_THREAD);  \
  \
  f_ptr = FenceOffInstanceHolder(instance_f_ptr)


/**
 * @brief Currently only one reported message per command is processed. Reported message command will increment the fence eid.
 * User's eid won't be affected. Even though fence eid is incremented, current implementation does not lodge an event record for this. Only original
 * message's eid is being remembered.
 * @param cmd_base_ctx
 * @param command_marshaller
 * @param call_flags
 * @return
 */
UFSRVResult *
IsUserAllowedToReportMessage (CommandBaseContext *cmd_base_ctx, CommandMarshallerCallback command_marshaller, unsigned long call_flags)
{
  unsigned rescode = RESCODE_PROG_NULL_POINTER;
  bool fence_lock_already_owned = false;
  Fence *f_ptr = NULL;
  MessageCommandContext *cmd_ctx_ptr = (MessageCommandContext *) cmd_base_ctx;
  MessageCommand	*msgcmd_ptr = cmd_ctx_ptr->command_base_context.data_msg_ptr_received->ufsrvcommand->msgcommand;
  ReportedContentRecord *record_ptr = msgcmd_ptr->reported[0];

  if (record_ptr->gid > 0 && record_ptr->originator.len == 16 && IS_PRESENT(record_ptr->originator.data)) {
    UfsrvEventDescriptor event_descriptor = {0};
    unsigned long uid = UfsrvUidGetSequenceId((UfsrvUid *) record_ptr->originator.data);
    DbBackendGetEventDescriptorByGid((event_descriptor.gid=record_ptr->gid, &event_descriptor));
    if (THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA) {
      _FIND_FENCE(event_descriptor.ctx_id);
      //fence locked
      FenceEvent fence_event = {0};
      if (IS_EMPTY((RegisterFenceEvent(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), f_ptr, EVENT_TYPE_MSG_REPORTED, NULL, 0, &fence_event)))) {
        rescode = RESCODE_FENCE_EVENT_GENERATION; goto return_unlock_fence;
      }

      InstanceContextForFence fence_context = {.instance_f_ptr=instance_f_ptr, .f_ptr=f_ptr, .is_locked=true, .lock_already_owned=fence_lock_already_owned};
      cmd_ctx_ptr->command_base_context.event_ptr = (UfsrvEvent *)&fence_event;
      cmd_ctx_ptr->marshaller_context.ctx_f_ptr = &fence_context;

      if (DbBackendUpdateMessageStatus(event_descriptor.gid, uid, EVENT_STATUS_REPORTED) == H_OK) {
        DbBackendUpdateEventFlagger(event_descriptor.gid, uid, msgcmd_ptr->header->when);

        record_ptr->fid = FENCE_ID(f_ptr); record_ptr->has_fid = 1;
        InterBroadcastUserMessageReported((CommandBaseContext *)cmd_ctx_ptr, COMMAND_ARGS__ADDED);//update to COMMAND_ARGS__POSTED

        //todo use db transaction
        if (IS_PRESENT(command_marshaller)) {
          INVOKE_COMMAND_MARSHALLER(command_marshaller, cmd_base_ctx);
        }

        if (fence_context.is_locked && !fence_context.lock_already_owned) {
          FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)));
        }

        _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_SUCCESS, rescode)
      }
    } else {
      syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', o:'%p', gid:'%lu', orig:'%lu'}: ERROR: COMMAND CONTAINED INVALID EVENT...", __func__, pthread_self(), THREAD_CONTEXT_PTR, CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), msgcmd_ptr->header->gid, uid);
      goto return_error;
    }
  } else {
    syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', o:'%p', gid:'%lu'}: ERROR: COMMAND CONTAINED INVALID UFSRVUID...", __func__, pthread_self(), THREAD_CONTEXT_PTR, CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), msgcmd_ptr->header->gid);
    goto return_error;
  }

  return_unlock_fence:
  if (!fence_lock_already_owned)  FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)));

  return_error:
  _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_ERR, rescode)
}

static char *_FormatGuardianRecordSpecs (GuardianRecordDescriptor *descriptor_ptr);

/**
 * @brief Guardian Request requires initiation from within a private group. The group itself doe not define the relationship, though.
 * Events are registered against 'originator' when request is initiated and 'guardian' when originator when linked.
 * @param cmd_base_ctx
 * @return
 */
inline static UFSRVResult *
_UfsrvCommandControllerGuardianRequest (CommandBaseContext *cmd_base_ctx)
{
  MessageCommandContext *cmd_ctx_ptr = (MessageCommandContext *)cmd_base_ctx;
  MessageCommand	*msgcmd_ptr = cmd_base_ctx->data_msg_ptr_received->ufsrvcommand->msgcommand;

  if (unlikely(IS_EMPTY(msgcmd_ptr->guardian))) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: COMMAND CONTAINED NO GUARDIAN RECORD...", __func__, pthread_self(), CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr));

    _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  GuardianRecord *record_ptr = msgcmd_ptr->guardian;
  if (record_ptr->fid <= 0 || IS_EMPTY(record_ptr->guardian->ufsrvuid.data) || IS_EMPTY(record_ptr->originator->ufsrvuid.data)) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: COMMAND CONTAINED NO GUARDIAN RECORD SPECS...", __func__, pthread_self(), CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr));

    _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  if (!UfsrvUidIsEqual((const UfsrvUid *)record_ptr->originator->ufsrvuid.data, &SESSION_UFSRVUIDSTORE(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)))) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: GUARDIAN RECORD MIS SPECIFIED ORIGINATOR...", __func__, pthread_self(), CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr));

    _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  //todo check if private fence for two, check if a gurdian relationship exists already

  if (unlikely(msgcmd_ptr->n_messages <= 0)) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: COMMAND CONTAINED ZERO MESSAGE DEFINITION...", __func__, pthread_self(), CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr));

    _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  return (IsUserAllowedToRequestGuardian(cmd_base_ctx, _MarshalGuardianRequest, CALLFLAGS_EMPTY));
}

inline static UFSRVResult *
_UfsrvCommandControllerGuardianLink (CommandBaseContext *cmd_base_ctx)
{
  MessageCommandContext *cmd_ctx_ptr = (MessageCommandContext *)cmd_base_ctx;
  MessageCommand	*msgcmd_ptr = cmd_base_ctx->data_msg_ptr_received->ufsrvcommand->msgcommand;

  if (unlikely(IS_EMPTY(msgcmd_ptr->guardian))) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: COMMAND CONTAINED NO GUARDIAN RECORD...", __func__, pthread_self(), CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr));

    _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  GuardianRecord *record_ptr = msgcmd_ptr->guardian;
  if (record_ptr->fid <= 0 || IS_EMPTY(record_ptr->guardian->ufsrvuid.data) || IS_EMPTY(record_ptr->originator->ufsrvuid.data)) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: COMMAND CONTAINED NO GUARDIAN RECORD SPECS...", __func__, pthread_self(), CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr));

    _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  if (!UfsrvUidIsEqual((const UfsrvUid *)record_ptr->guardian->ufsrvuid.data, &SESSION_UFSRVUIDSTORE(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)))) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: GUARDIAN RECORD MIS SPECIFIED FOR GUARDIAN...", __func__, pthread_self(), CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr));

    _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  //todo check if private fence for two, check if a gurdian relationship exists already

  if (unlikely(IS_EMPTY(record_ptr->nonce))) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: COMMAND CONTAINED NO NONCE DEFINITION...", __func__, pthread_self(), CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr));

    _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  return (IsUserAllowedToLinkGuardian(cmd_base_ctx, _MarshalGuardianLink, CALLFLAGS_EMPTY));
}

inline static UFSRVResult *
_UfsrvCommandControllerGuardianUnlink (CommandBaseContext *cmd_base_ctx)
{
  MessageCommandContext *cmd_ctx_ptr = (MessageCommandContext *)cmd_base_ctx;
  MessageCommand	*msgcmd_ptr = cmd_base_ctx->data_msg_ptr_received->ufsrvcommand->msgcommand;

  if (unlikely(IS_EMPTY(msgcmd_ptr->guardian))) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: COMMAND CONTAINED NO GUARDIAN RECORD...", __func__, pthread_self(), CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr));

    _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  GuardianRecord *record_ptr = msgcmd_ptr->guardian;
  if (IS_EMPTY(record_ptr->guardian->ufsrvuid.data) || IS_EMPTY(record_ptr->originator->ufsrvuid.data)) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: COMMAND CONTAINED NO GUARDIAN RECORD SPECS...", __func__, pthread_self(), CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr));

    _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  if (!UfsrvUidIsEqual((const UfsrvUid *)record_ptr->guardian->ufsrvuid.data, &SESSION_UFSRVUIDSTORE(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)))) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', guardian_uid:'%lu'}: ERROR: GUARDIAN RECORD MIS SPECIFIED (guardian)...", __func__, pthread_self(), CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), UfsrvUidGetSequenceId((const UfsrvUid *)record_ptr->guardian->ufsrvuid.data));

    _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  return (IsUserAllowedToUnlinkGuardian(cmd_base_ctx, _MarshalGuardianUnLink, CALLFLAGS_EMPTY));
}

/**
 *
 * @param cmd_base_ctx
 * @param command_marshaller
 * @param call_flags
 * @return
 * @locks Fence *
 */
UFSRVResult *
IsUserAllowedToRequestGuardian (CommandBaseContext *cmd_base_ctx, CommandMarshallerCallback command_marshaller, unsigned long call_flags)
{
  unsigned rescode = RESCODE_PROG_NULL_POINTER;
  bool fence_lock_already_owned = false;
  MessageCommandContext *cmd_ctx_ptr = (MessageCommandContext *) cmd_base_ctx;
  MessageCommand	*msgcmd_ptr = cmd_ctx_ptr->command_base_context.data_msg_ptr_received->ufsrvcommand->msgcommand;

  GuardianRecordDescriptor guardian_descriptor = {.status=GUARDIAN_STATUS_REQUESTED, .guardian.uid=UfsrvUidGetSequenceId((const UfsrvUid *)msgcmd_ptr->guardian->guardian->ufsrvuid.data), .originator.uid=UfsrvUidGetSequenceId((const UfsrvUid *)msgcmd_ptr->guardian->originator->ufsrvuid.data)};
  DbBackendGetGuardianRecord(&guardian_descriptor);
  if (!THREAD_CONTEXT_UFSRV_RESULT_IS_EMPTYSET_BACKEND_DATA) {
    //record already exists
    unsigned long long timenow_millis = GetTimeNowInMillis();
    if (timenow_millis - guardian_descriptor.timestamp > CONFIGDEFAULT_GUARDIAN_NONCE_EXPIRY * 1000) {
      syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', time_now:'%llu', time_stored:'%llu', gid:'%lu'}: DELETING EXPIRED GUARDIAN REQUEST", __func__, pthread_self(), CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), timenow_millis, guardian_descriptor.timestamp, guardian_descriptor.gid);
      //todo send expiry error message

      DbBackendDeleteGuardianRecord(&guardian_descriptor);

    } else {
      syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', time_now:'%llu', time_stored:'%llu', gid:'%lu'}: GUARDIAN REQUEST STILL ACTIVE", __func__, pthread_self(), CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), timenow_millis, guardian_descriptor.timestamp, guardian_descriptor.gid);
      goto return_error;
    }
  }

  Fence *f_ptr = NULL;
  _FIND_FENCE(msgcmd_ptr->guardian->fid);

  //fence now locked

  UfsrvEvent event = {0};
  RegisterUfsrvEvent(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), EVENT_TYPE_USER_PREF, EVENT_TYPE_USER_GUARDIAN_REQUEST, NULL, &event);

  DbBackendInsertUfsrvEvent ((UfsrvEvent *)&event);

  guardian_descriptor.gid = event.gid;
  guardian_descriptor.timestamp = msgcmd_ptr->header->when;
  guardian_descriptor.status = GUARDIAN_STATUS_REQUESTED;
  guardian_descriptor.specs.specs_serialised = NULL;
  DbBackendInsertGuardianRecord(&guardian_descriptor, false);
  if (!THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA) {
    rescode = RESCODE_BACKEND_DATA;
    goto return_unlock_fence;
  }

  InstanceContextForFence fence_context = {.instance_f_ptr=instance_f_ptr, .f_ptr=f_ptr, .is_locked=true, .lock_already_owned=fence_lock_already_owned};
  cmd_ctx_ptr->command_base_context.event_ptr = &event;
  cmd_ctx_ptr->marshaller_context.ctx_f_ptr = &fence_context;

  if (IS_PRESENT(command_marshaller)) {
    INVOKE_COMMAND_MARSHALLER(command_marshaller, cmd_base_ctx);
  }

  if (fence_context.is_locked && !fence_context.lock_already_owned) {
    FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)));
  }

  InterBroadcastGuardianRequest((CommandBaseContext *)cmd_ctx_ptr, COMMAND_ARGS__ADDED);//update to COMMAND_ARGS__POSTED

  _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_SUCCESS, rescode)

  return_unlock_fence:
  if (!fence_lock_already_owned)  FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)));

  return_error:
  _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_ERR, rescode)
}

/**
 *
 * @param descriptor_ptr
 * @return formatted json
 * @dynamic_memory: EXPORTS Char *
 */
static char *
_FormatGuardianRecordSpecs (GuardianRecordDescriptor *descriptor_ptr)
{
  char *guardian_specs_serialised = mdsprintf("{\"event_types\": [{\"type\":%u, \"fid\":%lu}]}", 0, 0UL);
  return guardian_specs_serialised;
}

UFSRVResult *
IsUserAllowedToLinkGuardian (CommandBaseContext *cmd_base_ctx, CommandMarshallerCallback command_marshaller, unsigned long call_flags)
{
  unsigned rescode = RESCODE_PROG_NULL_POINTER;
  bool fence_lock_already_owned = false;
  MessageCommandContext *cmd_ctx_ptr = (MessageCommandContext *) cmd_base_ctx;
  MessageCommand	*msgcmd_ptr = cmd_ctx_ptr->command_base_context.data_msg_ptr_received->ufsrvcommand->msgcommand;

  unsigned long originator_uid = UfsrvUidGetSequenceId((const UfsrvUid *)msgcmd_ptr->guardian->originator->ufsrvuid.data),
                guardian_uid = UfsrvUidGetSequenceId((const UfsrvUid *)msgcmd_ptr->guardian->guardian->ufsrvuid.data);
  GuardianRecordDescriptor guardian_descriptor = {.status=GUARDIAN_STATUS_NONE, .guardian.uid=guardian_uid, .originator.uid=originator_uid};
  DbBackendGetGuardianRecord(&guardian_descriptor);
  if (THREAD_CONTEXT_UFSRV_RESULT_IS_EMPTYSET_BACKEND_DATA) {
    //request record should have already existed
    //todo return error?
  }

  if (!IsGuardianLinkNonceValid(msgcmd_ptr->guardian->nonce, UfsrvUidGetSequenceId((const UfsrvUid *)msgcmd_ptr->guardian->originator->ufsrvuid.data))) {
    goto return_error;
  }

  Fence *f_ptr = NULL;
  _FIND_FENCE(msgcmd_ptr->guardian->fid);

  //fence now locked

  UfsrvEvent event = {0};
  RegisterUfsrvEvent(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), EVENT_TYPE_USER_PREF, EVENT_TYPE_USER_GUARDIAN_LINK, NULL, &event);

  DbBackendInsertUfsrvEvent (&event);

  guardian_descriptor.status = GUARDIAN_STATUS_REQUESTED;
  DbBackendDeleteGuardianRecord (&guardian_descriptor);

  guardian_descriptor.gid = event.gid;
  guardian_descriptor.timestamp = msgcmd_ptr->header->when;
  guardian_descriptor.status = GUARDIAN_STATUS_LINKED;
  guardian_descriptor.specs.specs_serialised = _FormatGuardianRecordSpecs(&guardian_descriptor);
  DbBackendInsertGuardianRecord(&guardian_descriptor, false);
  if (!THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA) {
    rescode = RESCODE_BACKEND_DATA;
    free (guardian_descriptor.specs.specs_serialised);
    goto return_unlock_fence;
  }

  bool is_lock_already_owned = false;
  unsigned long sesn_call_flags = (CALL_FLAG_LOCK_SESSION|CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY|CALL_FLAG_HASH_USERNAME_LOCALLY|CALL_FLAG_REMOTE_SESSION);
  GetSessionForThisUserByUserId(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr),  originator_uid, &is_lock_already_owned, sesn_call_flags);
  if (SESSION_RESULT_TYPE_SUCCESS(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr))) {
    Session *sesn_ptr = SessionOffInstanceHolder((InstanceHolderForSession *)SESSION_RESULT_USERDATA(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)));
    ThreadContextTransferAccessContextForSession(sesn_ptr);
    SetGuardianFor(sesn_ptr, guardian_uid, PREFSTORE_EVERYWHERE);
    ThreadContextResetAccessContextForSession(sesn_ptr);

    if (!is_lock_already_owned) SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr, __func__);
  }

  InstanceContextForFence fence_context = {.instance_f_ptr=instance_f_ptr, .f_ptr=f_ptr, .is_locked=true, .lock_already_owned=fence_lock_already_owned};
  cmd_ctx_ptr->command_base_context.event_ptr = &event;
  cmd_ctx_ptr->marshaller_context.ctx_f_ptr = &fence_context;

  if (IS_PRESENT(command_marshaller)) {
    INVOKE_COMMAND_MARSHALLER(command_marshaller, cmd_base_ctx);
  }

  if (fence_context.is_locked && !fence_context.lock_already_owned) {
    FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)));
  }

  InterBroadcastGuardianRequest((CommandBaseContext *)cmd_ctx_ptr, COMMAND_ARGS__ADDED);//update to COMMAND_ARGS__POSTED

  free (guardian_descriptor.specs.specs_serialised);

  _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_SUCCESS, rescode)

  return_unlock_fence:
  if (!fence_lock_already_owned)  FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)));

  return_error:
  _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_ERR, rescode)
}

UFSRVResult *
IsUserAllowedToUnlinkGuardian (CommandBaseContext *cmd_base_ctx, CommandMarshallerCallback command_marshaller, unsigned long call_flags)
{
  unsigned rescode = RESCODE_PROG_NULL_POINTER;
  MessageCommandContext *cmd_ctx_ptr = (MessageCommandContext *) cmd_base_ctx;
  MessageCommand	*msgcmd_ptr = cmd_ctx_ptr->command_base_context.data_msg_ptr_received->ufsrvcommand->msgcommand;

  GuardianRecordDescriptor guardian_descriptor = {.status=GUARDIAN_STATUS_LINKED, .guardian.uid=UfsrvUidGetSequenceId((const UfsrvUid *)msgcmd_ptr->guardian->guardian->ufsrvuid.data), .originator.uid=UfsrvUidGetSequenceId((const UfsrvUid *)msgcmd_ptr->guardian->originator->ufsrvuid.data)};
  DbBackendGetGuardianRecord(&guardian_descriptor);
  if (THREAD_CONTEXT_UFSRV_RESULT_IS_EMPTYSET_BACKEND_DATA) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', guardian:'%lu', originator:'%lu'}: ERROR: NO GUARDIAN RECORD EXISTS...", __func__, pthread_self(), CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), guardian_descriptor.guardian.uid, guardian_descriptor.originator.uid);

    _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  unsigned long sesn_call_flags				=	(	CALL_FLAG_LOCK_SESSION|CALL_FLAG_LOCK_SESSION_BLOCKING|
                                             CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY| CALL_FLAG_HASH_USERNAME_LOCALLY|
                                             CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION|CALL_FLAG_REMOTE_SESSION);

  bool lock_already_owned = false;
  GetSessionForThisUserByUserId(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), guardian_descriptor.originator.uid, &lock_already_owned, sesn_call_flags);

  if (unlikely(IS_EMPTY((InstanceHolderForSession *)SESSION_RESULT_USERDATA(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)))))	{
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', guardian:'%lu', originator:'%lu'}: ERROR: COULD NOT INSTANTIATE ORIGINATOR SESSION", __func__, pthread_self(), CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), guardian_descriptor.guardian.uid, guardian_descriptor.originator.uid);

    _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  InstanceContextForSession instance_context = {(InstanceHolderForSession *)SESSION_RESULT_USERDATA(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)),
                                                 SessionOffInstanceHolder((InstanceHolderForSession *)SESSION_RESULT_USERDATA(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr))),
                                                 lock_already_owned,
                                                 true};
  //instance_sesn_ptr_originator LOCKED

  UfsrvEvent event = {0};
  RegisterUfsrvEvent(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), EVENT_TYPE_USER_PREF, EVENT_TYPE_USER_GUARDIAN_UNLINK, NULL, &event);

  DbBackendInsertUfsrvEvent(&event);

  guardian_descriptor.gid = event.gid;
  guardian_descriptor.timestamp = msgcmd_ptr->header->when;
  guardian_descriptor.status = GUARDIAN_STATUS_UNLINKED;
  guardian_descriptor.specs.specs_serialised = _FormatGuardianRecordSpecs(&guardian_descriptor);
  DbBackendInsertGuardianRecord(&guardian_descriptor, false);
  if (!THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA) {
    rescode = RESCODE_BACKEND_DATA;
    free (guardian_descriptor.specs.specs_serialised);
    goto return_unlock_session;
  }

  ThreadContextTransferAccessContextForSession(instance_context.sesn_ptr);
  SetGuardianFor(instance_context.sesn_ptr, 0, PREFSTORE_EVERYWHERE);
  ThreadContextResetAccessContextForSession(instance_context.sesn_ptr);

  if (!lock_already_owned) SessionUnLockCtx(THREAD_CONTEXT_PTR, instance_context.sesn_ptr, __func__);

  CMDCTX_MSG_TARGET_SESN(cmd_ctx_ptr).ctx_sesn_ptr = &instance_context;
  cmd_ctx_ptr->command_base_context.event_ptr = &event;
  cmd_ctx_ptr->marshaller_context.ctx_f_ptr = NULL;

  if (IS_PRESENT(command_marshaller)) {
    INVOKE_COMMAND_MARSHALLER(command_marshaller, cmd_base_ctx);
  }

  InterBroadcastGuardianRequest((CommandBaseContext *)cmd_ctx_ptr, COMMAND_ARGS__ADDED);//update to COMMAND_ARGS__POSTED

  _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_SUCCESS, rescode)

  return_unlock_session:
  if (!lock_already_owned)  SessionUnLockCtx(THREAD_CONTEXT_PTR, instance_context.sesn_ptr, __func__);

  return_error:
  _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_ERR, rescode)
}

inline static UFSRVResult *
_UfsrvCommandControllerMessageEffect (CommandBaseContext *cmd_base_ctx)
{
  MessageCommandContext *cmd_ctx_ptr = (MessageCommandContext *)cmd_base_ctx;
  MessageCommand	*msgcmd_ptr = cmd_base_ctx->data_msg_ptr_received->ufsrvcommand->msgcommand;

  if (IS_EMPTY(msgcmd_ptr->messages) || IS_EMPTY(msgcmd_ptr->messages[0])) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: COMMAND CONTAINED NO MESSAGE RECORD...", __func__, pthread_self(), CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr));

    _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  if (IS_EMPTY(msgcmd_ptr->fences) || IS_EMPTY(msgcmd_ptr->fences[0]) || msgcmd_ptr->fences[0]->fid == 0) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: COMMAND CONTAINED NO FENCE RECORD...", __func__, pthread_self(), CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr));

    _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  MessageRecord *record_ptr = msgcmd_ptr->messages[0];
  if (IS_EMPTY(record_ptr->effect) || !IS_STR_LOADED(record_ptr->message.data)) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: COMMAND CONTAINED EFFECT RECORD SPECS...", __func__, pthread_self(), CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr));

    _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  return (IsUserAllowedToSendMessageEffect(cmd_base_ctx, _MarshalMessageEffect, CALLFLAGS_EMPTY));
}

UFSRVResult *
IsUserAllowedToSendMessageEffect (CommandBaseContext *cmd_base_ctx, CommandMarshallerCallback command_marshaller, unsigned long call_flags)
{
  unsigned rescode = RESCODE_PROG_NULL_POINTER;
  MessageCommandContext *cmd_ctx_ptr = (MessageCommandContext *) cmd_base_ctx;
  MessageCommand	*msgcmd_ptr = cmd_ctx_ptr->command_base_context.data_msg_ptr_received->ufsrvcommand->msgcommand;

  unsigned long fid = msgcmd_ptr->fences[0]->fid;
  bool fence_lock_already_owned = false;
  Fence *f_ptr = NULL;
  _FIND_FENCE(fid);

  //fence now locked

  if (!(IsUserMemberOfThisFence(&SESSION_FENCE_LIST(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)), f_ptr, false))) {
    syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', bid:'%lu'): ERROR: USER IS NOT MEMBER OF FENCE", __func__, pthread_self(), CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), SESSION_ID(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)), fid);

    rescode = RESCODE_LOGIC_EMPTY_RESOURCE; goto return_unlock_fence;
  }

  UfsrvEvent event = {0};
  RegisterUfsrvEvent(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), EVENT_TYPE_FENCE_USR_MSG_EFFECT, 0, NULL, &event);

  DbBackendInsertUfsrvEvent (&event);

  InstanceContextForFence fence_context = {.instance_f_ptr=instance_f_ptr, .f_ptr=f_ptr, .is_locked=true, .lock_already_owned=fence_lock_already_owned};
  cmd_ctx_ptr->command_base_context.event_ptr = &event;
  cmd_ctx_ptr->marshaller_context.ctx_f_ptr = &fence_context;

  if (IS_PRESENT(command_marshaller)) {
    INVOKE_COMMAND_MARSHALLER(command_marshaller, cmd_base_ctx);
  }

  if (fence_context.is_locked && !fence_context.lock_already_owned) {
    FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)));
  }

//  InterBroadcastGuardianRequest((CommandBaseContext *)cmd_ctx_ptr, COMMAND_ARGS__ADDED);//update to COMMAND_ARGS__POSTED

  _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_SUCCESS, rescode)

  return_unlock_fence:
  if (!fence_lock_already_owned)  FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)));

  return_error:
  _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_ERR, rescode)
}

/**
 *
 * @param cmd_base_ctx
 * @return
 * @locked f_ptr
 * @unlocks f_ptr
 */
inline static UFSRVResult *
_MarshalMessageEffect (CommandBaseContext *cmd_base_ctx)
{
  MessageCommandContext *cmd_ctx_ptr = (MessageCommandContext *) cmd_base_ctx;
  MessageCommand	*msgcmd_ptr = CMDCTX_DATA_MESSAGE(cmd_ctx_ptr)->ufsrvcommand->msgcommand;

  _GENERATE_MESSAGECOMMAND_ENVELOPE_INITIALISATION();
  _PrepareMarshalMessageForUserMessage(&envelope_marshal, CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, CMDCTX_EVENT(cmd_ctx_ptr), CMDCTX_DATA_MESSAGE(cmd_ctx_ptr), MESSAGE_COMMAND__COMMAND_TYPES__EFFECT, COMMAND_ARGS__SYNCED);

  //eid will have picked up eid for fence
  message_command.fences = msgcmd_ptr->fences; message_command.n_fences = msgcmd_ptr->n_fences;
  message_command.messages = msgcmd_ptr->messages; message_command.n_messages = msgcmd_ptr->n_messages;

  FenceRawSessionList raw_session_list = {0};
  GetRawMemberUsersListForFence (CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), CMDCTX_MSG_FENCE_INSTANCE(cmd_ctx_ptr), FENCE_CALLFLAG_INCLUDE_REMOTE_SESSIONS, &raw_session_list);//no locking
  if (!CMDCTX_MSG_FENCE_LOCK_OWNED(cmd_ctx_ptr))	{
    FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, CMDCTX_MSG_FENCE(cmd_ctx_ptr), SESSION_RESULT_PTR(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)));
    CMDCTX_MSG_FENCE_LOCKED_STATE_SET_FALSE(cmd_ctx_ptr);
  }

  bool wont_send = false;
  if (raw_session_list.sessions_sz == 2) {
    envelope_marshal.header->args = COMMAND_ARGS__SYNCED;
    message_command.originator		=	MakeUserRecordFromSessionInProto(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), &user_record_originator, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF);

    for (size_t i = 0; i < raw_session_list.sessions_sz; i++) {
      Session *sesn_ptr_listed = SessionOffInstanceHolder(raw_session_list.sessions[i]);
      if (SESSION_ID(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)) == SESSION_ID(sesn_ptr_listed)) continue; //skip self

      if (IsUserOnShareListBlocked(sesn_ptr_listed, CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr))) {
        syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu', o_blocking:'%p', cid_blocked:'%lu'} ERROR: BLOCKED BY USER...", __func__, pthread_self(), CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), SESSION_ID(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)), sesn_ptr_listed, SESSION_ID(sesn_ptr_listed));
        //todo send error message;
        wont_send = true;
        break;
      }
      _MarshalUserMessageToUser(CMDCTX_SESN_CTX_ORIGINATOR(cmd_ctx_ptr), raw_session_list.sessions[i], CMDCTX_WSM(cmd_ctx_ptr), &command_envelope);
    }

    DestructFenceRawSessionList (&raw_session_list, false);

    if (!wont_send) {
      envelope_marshal.header->args = COMMAND_ARGS__ACCEPTED;
      message_command.originator = NULL;
      message_command.messages = NULL; message_command.n_messages = 0;
      _MarshalUserMessageToUser(CMDCTX_SESN_CTX_ORIGINATOR(cmd_ctx_ptr), NULL, CMDCTX_WSM(cmd_ctx_ptr), &command_envelope);
    }
  }

  return SESSION_RESULT_PTR(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr));
}

inline static UFSRVResult *
_UfsrvCommandControllerMessageReaction (CommandBaseContext *cmd_base_ctx)
{
  MessageCommandContext *cmd_ctx_ptr = (MessageCommandContext *)cmd_base_ctx;
  MessageCommand	*msgcmd_ptr = cmd_base_ctx->data_msg_ptr_received->ufsrvcommand->msgcommand;

   if (IS_EMPTY(msgcmd_ptr->reaction) || msgcmd_ptr->reaction->fid <= 0) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: COMMAND CONTAINED NO VALID REACTION RECORD...", __func__, pthread_self(), CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr));

    _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  return (IsUserAllowedToSendMessageReaction(cmd_base_ctx, _MarshalMessageReaction, CALLFLAGS_EMPTY));
}

UFSRVResult *
IsUserAllowedToSendMessageReaction (CommandBaseContext *cmd_base_ctx, CommandMarshallerCallback command_marshaller, unsigned long call_flags)
{
  unsigned rescode = RESCODE_PROG_NULL_POINTER;
  MessageCommandContext *cmd_ctx_ptr = (MessageCommandContext *) cmd_base_ctx;
  MessageCommand	*msgcmd_ptr = cmd_ctx_ptr->command_base_context.data_msg_ptr_received->ufsrvcommand->msgcommand;

  unsigned long fid = msgcmd_ptr->reaction->fid;
  bool fence_lock_already_owned = false;
  Fence *f_ptr = NULL;
  _FIND_FENCE(fid);

  //fence now locked

  if (!(IsUserMemberOfThisFence(&SESSION_FENCE_LIST(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)), f_ptr, false))) {
    syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', bid:'%lu'): ERROR: USER IS NOT MEMBER OF FENCE", __func__, pthread_self(), CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), SESSION_ID(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)), fid);

    rescode = RESCODE_LOGIC_EMPTY_RESOURCE; goto return_unlock_fence;
  }

  UfsrvEvent event = {0};
  RegisterUfsrvEvent(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), EVENT_TYPE_MSG_REACTION, 0, NULL, &event);

  DbBackendInsertUfsrvEvent (&event);

  InstanceContextForFence fence_context = {.instance_f_ptr=instance_f_ptr, .f_ptr=f_ptr, .is_locked=true, .lock_already_owned=fence_lock_already_owned};
  cmd_ctx_ptr->command_base_context.event_ptr = &event;
  cmd_ctx_ptr->marshaller_context.ctx_f_ptr = &fence_context;

  if (IS_PRESENT(command_marshaller)) {
    INVOKE_COMMAND_MARSHALLER(command_marshaller, cmd_base_ctx);
  }

  if (fence_context.is_locked && !fence_context.lock_already_owned) {
    FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)));
  }

//  InterBroadcastGuardianRequest((CommandBaseContext *)cmd_ctx_ptr, COMMAND_ARGS__ADDED);//update to COMMAND_ARGS__POSTED

  _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_SUCCESS, rescode)

  return_unlock_fence:
  if (!fence_lock_already_owned)  FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)));

  return_error:
  _RETURN_RESULT_SESN(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, RESULT_TYPE_ERR, rescode)
}

/**
 *
 * @param cmd_base_ctx
 * @return
 * @locked f_ptr
 * @unlocks f_ptr
 */
inline static UFSRVResult *
_MarshalMessageReaction (CommandBaseContext *cmd_base_ctx)
{
  MessageCommandContext *cmd_ctx_ptr = (MessageCommandContext *) cmd_base_ctx;
  MessageCommand	*msgcmd_ptr = CMDCTX_DATA_MESSAGE(cmd_ctx_ptr)->ufsrvcommand->msgcommand;

  _GENERATE_MESSAGECOMMAND_ENVELOPE_INITIALISATION();
  _PrepareMarshalMessageForUserMessage(&envelope_marshal, CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, CMDCTX_EVENT(cmd_ctx_ptr), CMDCTX_DATA_MESSAGE(cmd_ctx_ptr), MESSAGE_COMMAND__COMMAND_TYPES__REACTION, COMMAND_ARGS__SYNCED);

  //eid will have picked up eid for fence
  message_command.reaction = msgcmd_ptr->reaction;

  FenceRawSessionList raw_session_list = {0};
  GetRawMemberUsersListForFence (CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), CMDCTX_MSG_FENCE_INSTANCE(cmd_ctx_ptr), FENCE_CALLFLAG_INCLUDE_REMOTE_SESSIONS, &raw_session_list);//no locking
  if (!CMDCTX_MSG_FENCE_LOCK_OWNED(cmd_ctx_ptr))	{
    FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, CMDCTX_MSG_FENCE(cmd_ctx_ptr), SESSION_RESULT_PTR(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)));
    CMDCTX_MSG_FENCE_LOCKED_STATE_SET_FALSE(cmd_ctx_ptr);
  }

  bool wont_send = false;
  envelope_marshal.header->args = COMMAND_ARGS__SYNCED;
  message_command.originator		=	MakeUserRecordFromSessionInProto(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), &user_record_originator, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF);

  for (size_t i = 0; i < raw_session_list.sessions_sz; i++) {
    Session *sesn_ptr_listed = SessionOffInstanceHolder(raw_session_list.sessions[i]);
    if (SESSION_ID(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)) == SESSION_ID(sesn_ptr_listed)) continue; //skip self

    if (IsUserOnShareListBlocked(sesn_ptr_listed, CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr))) {
      syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu', o_blocking:'%p', cid_blocked:'%lu'} ERROR: BLOCKED BY USER...", __func__, pthread_self(), CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), SESSION_ID(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)), sesn_ptr_listed, SESSION_ID(sesn_ptr_listed));
      //todo send error message;
      wont_send = true;
      break;
    }
    _MarshalUserMessageToUser(CMDCTX_SESN_CTX_ORIGINATOR(cmd_ctx_ptr), raw_session_list.sessions[i], CMDCTX_WSM(cmd_ctx_ptr), &command_envelope);
  }

  DestructFenceRawSessionList (&raw_session_list, false);

  if (!wont_send) {
    envelope_marshal.header->args = COMMAND_ARGS__ACCEPTED;
    message_command.originator = NULL;
    message_command.messages = NULL; message_command.n_messages = 0;
    _MarshalUserMessageToUser(CMDCTX_SESN_CTX_ORIGINATOR(cmd_ctx_ptr), NULL, CMDCTX_WSM(cmd_ctx_ptr), &command_envelope);
  }

  return SESSION_RESULT_PTR(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr));
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
_MarshalIntroMessage(InstanceContextForSession *ctx_sesn_ptr, InstanceHolderForSession *instance_sesn_ptr_target, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received, UfsrvEvent *event_ptr)
{
  Session *sesn_ptr = SessionOffInstanceHolder(ctx_sesn_ptr->instance_sesn_ptr);

  _GENERATE_MESSAGECOMMAND_FOR_INTRO_ENVELOPE_INITIALISATION();
  _PrepareMarshalMessageForUserMessage(&envelope_marshal, sesn_ptr, CLIENT_CTX_DATA(SessionOffInstanceHolder(instance_sesn_ptr_target)), event_ptr, data_msg_ptr_received, MESSAGE_COMMAND__COMMAND_TYPES__INTRO, COMMAND_ARGS__ACCEPTED);

  MessageCommand		*msgcmd_ptr				= data_msg_ptr_received->ufsrvcommand->msgcommand;

  message_command.intro    = msgcmd_ptr->intro;

  _MarshalUserMessageToUser(ctx_sesn_ptr, NULL, wsm_ptr_received, &command_envelope);

  //only to target user
  message_command.header->args  = COMMAND_ARGS__SYNCED;
  message_command.originator    =	MakeUserRecordFromSessionInProto(sesn_ptr, &user_record_originator, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF);

  Session *sesn_ptr_target  = SessionOffInstanceHolder(instance_sesn_ptr_target);
//  intro_message.to          = msgcmd_ptr->intro->to; //no need for this
  intro_message.originator  = msgcmd_ptr->intro->originator;//todo: do we need this?
  intro_message.avatar      = msgcmd_ptr->intro->avatar;
  if (msgcmd_ptr->intro->has_msg) {//todo: check intro message length / size
    intro_message.msg.len   = msgcmd_ptr->intro->msg.len;
    intro_message.msg.data  = msgcmd_ptr->intro->msg.data;
    intro_message.has_msg   = 1;
  }
  if (msgcmd_ptr->intro->has_handle_type) {//for outbound, we indicate to received the handle type used. todo: unverified type
    intro_message.has_handle_type =   msgcmd_ptr->intro->has_handle_type;
    intro_message.handle_type     =   msgcmd_ptr->intro->handle_type;
  }

  //for outbound, we automatically include the originator's rego handle (or phone if signed up with e164)
  intro_message.handle  = SESSION_USERNAME(sesn_ptr);

  message_command.intro = &intro_message;

  _MarshalUserMessageToUser(ctx_sesn_ptr, instance_sesn_ptr_target, wsm_ptr_received, &command_envelope);

  return SESSION_RESULT_PTR(sesn_ptr);
}

inline static UFSRVResult *
_MarshalMessageReported (CommandBaseContext *cmd_base_ctx)
{
  MessageCommandContext *cmd_ctx_ptr = (MessageCommandContext *) cmd_base_ctx;
  MessageCommand	*msgcmd_ptr = CMDCTX_DATA_MESSAGE(cmd_ctx_ptr)->ufsrvcommand->msgcommand;

  _GENERATE_MESSAGECOMMAND_ENVELOPE_INITIALISATION();
  _PrepareMarshalMessageForUserMessage(&envelope_marshal, CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, CMDCTX_EVENT(cmd_ctx_ptr), CMDCTX_DATA_MESSAGE(cmd_ctx_ptr), MESSAGE_COMMAND__COMMAND_TYPES__FLAG, COMMAND_ARGS__ACCEPTED);

  //eid will have picked up eid for fence
  message_command.reported = msgcmd_ptr->reported;
  message_command.n_reported = msgcmd_ptr->n_reported;

  _MarshalUserMessageToUser(CMDCTX_SESN_CTX_ORIGINATOR(cmd_ctx_ptr), NULL, CMDCTX_WSM(cmd_ctx_ptr), &command_envelope);

  FenceRawSessionList raw_session_list = {0};
  GetRawMemberUsersListForFence (CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), CMDCTX_MSG_FENCE_INSTANCE(cmd_ctx_ptr), FENCE_CALLFLAG_INCLUDE_REMOTE_SESSIONS, &raw_session_list);//no locking
  if (!CMDCTX_MSG_FENCE_LOCK_OWNED(cmd_ctx_ptr))	{
    FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, CMDCTX_MSG_FENCE(cmd_ctx_ptr), SESSION_RESULT_PTR(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)));
    CMDCTX_MSG_FENCE_LOCKED_STATE_SET_FALSE(cmd_ctx_ptr);
  }

  if (raw_session_list.sessions_sz > 0) {
    envelope_marshal.header->args = COMMAND_ARGS__SYNCED;
    message_command.originator		=	MakeUserRecordFromSessionInProto(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), &user_record_originator, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF);

    for (size_t i = 0; i < raw_session_list.sessions_sz; i++) {
      Session *sesn_ptr_listed = SessionOffInstanceHolder(raw_session_list.sessions[i]);
      if (SESSION_ID(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)) == SESSION_ID(sesn_ptr_listed)) continue; //skip self

#if 0
//todo do we block originator if on blocked list of target user
      if (IsUserOnShareListBlocked(sesn_ptr_listed, CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr))) {
        syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu', o_blocking:'%p', cid_blocked:'%lu'} ERROR: BLOCKED BY USER...", __func__, pthread_self(), CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), SESSION_ID(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)), sesn_ptr_listed, SESSION_ID(sesn_ptr_listed));
        continue;
      }
#endif
      _MarshalUserMessageToUser(CMDCTX_SESN_CTX_ORIGINATOR(cmd_ctx_ptr), raw_session_list.sessions[i], CMDCTX_WSM(cmd_ctx_ptr), &command_envelope);
    }

    DestructFenceRawSessionList (&raw_session_list, false);
  }

  return SESSION_RESULT_PTR(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr));
}

#define _MARSHALL_GUARDIAN_REQUEST_ACCEPTED \
  UserRecord  *to_records[1]; \
  UserRecord  *to_record_ptr =	MakeUserRecordFromSessionInProto(SessionOffInstanceHolder(raw_session_list.sessions[i]), &user_record_originator, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF); \
  to_records[0]       = to_record_ptr; \
  message_command.to  = to_records; message_command.n_to = 1; \
  \
  envelope_marshal.header->args = COMMAND_ARGS__ACCEPTED; \
  _MarshalUserMessageToUser(CMDCTX_SESN_CTX_ORIGINATOR(cmd_ctx_ptr), NULL, CMDCTX_WSM(cmd_ctx_ptr), &command_envelope); \
  message_command.to = NULL; message_command.n_to = 0

inline static UFSRVResult *
_MarshalGuardianRequest (CommandBaseContext *cmd_base_ctx)
{
  MessageCommandContext *cmd_ctx_ptr = (MessageCommandContext *) cmd_base_ctx;
  MessageCommand	*msgcmd_ptr = CMDCTX_DATA_MESSAGE(cmd_ctx_ptr)->ufsrvcommand->msgcommand;

  _GENERATE_MESSAGECOMMAND_ENVELOPE_INITIALISATION();
  _PrepareMarshalMessageForUserMessage(&envelope_marshal, CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, CMDCTX_EVENT(cmd_ctx_ptr), CMDCTX_DATA_MESSAGE(cmd_ctx_ptr), msgcmd_ptr->header->command, COMMAND_ARGS__ACCEPTED);
  command_envelope.type     = _GetProtocolType(msgcmd_ptr); command_envelope.has_type = 1; //important as challenge is e2ee (only for initial request)
  message_command.guardian  = msgcmd_ptr->guardian;
  // see below where messages reassigned for target user, not originator

  FenceRawSessionList raw_session_list = {0};
  GetRawMemberUsersListForFence (CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), CMDCTX_MSG_FENCE_INSTANCE(cmd_ctx_ptr), FENCE_CALLFLAG_INCLUDE_REMOTE_SESSIONS, &raw_session_list);//no locking
  if (!CMDCTX_MSG_FENCE_LOCK_OWNED(cmd_ctx_ptr))	{
    FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, CMDCTX_MSG_FENCE(cmd_ctx_ptr), SESSION_RESULT_PTR(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)));
    CMDCTX_MSG_FENCE_LOCKED_STATE_SET_FALSE(cmd_ctx_ptr);
  }

  if (raw_session_list.sessions_sz == 2) {
    for (size_t i = 0; i < raw_session_list.sessions_sz; i++) {
      Session *sesn_ptr_listed = SessionOffInstanceHolder(raw_session_list.sessions[i]);
      if (SESSION_ID(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)) == SESSION_ID(sesn_ptr_listed)) {
        _MARSHALL_GUARDIAN_REQUEST_ACCEPTED;
        continue;
      }

      envelope_marshal.header->args = COMMAND_ARGS__SYNCED;
      message_command.originator		=	MakeUserRecordFromSessionInProto(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), &user_record_originator, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF);
      message_command.messages      = msgcmd_ptr->messages; message_command.n_messages = msgcmd_ptr->n_messages;

      _MarshalUserMessageToUser(CMDCTX_SESN_CTX_ORIGINATOR(cmd_ctx_ptr), raw_session_list.sessions[i], CMDCTX_WSM(cmd_ctx_ptr), &command_envelope);
    }

    DestructFenceRawSessionList (&raw_session_list, false);
  }

  return SESSION_RESULT_PTR(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr));
}

inline static UFSRVResult *
_MarshalGuardianLink (CommandBaseContext *cmd_base_ctx)
{
  MessageCommandContext *cmd_ctx_ptr = (MessageCommandContext *) cmd_base_ctx;
  MessageCommand	*msgcmd_ptr = CMDCTX_DATA_MESSAGE(cmd_ctx_ptr)->ufsrvcommand->msgcommand;

  _GENERATE_MESSAGECOMMAND_ENVELOPE_INITIALISATION();
  _PrepareMarshalMessageForUserMessage(&envelope_marshal, CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, CMDCTX_EVENT(cmd_ctx_ptr), CMDCTX_DATA_MESSAGE(cmd_ctx_ptr), msgcmd_ptr->header->command, COMMAND_ARGS__ACCEPTED);
  message_command.guardian  = msgcmd_ptr->guardian;

  FenceRawSessionList raw_session_list = {0};
  GetRawMemberUsersListForFence (CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), CMDCTX_MSG_FENCE_INSTANCE(cmd_ctx_ptr), FENCE_CALLFLAG_INCLUDE_REMOTE_SESSIONS, &raw_session_list);//no locking
  if (!CMDCTX_MSG_FENCE_LOCK_OWNED(cmd_ctx_ptr))	{
    FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, CMDCTX_MSG_FENCE(cmd_ctx_ptr), SESSION_RESULT_PTR(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)));
    CMDCTX_MSG_FENCE_LOCKED_STATE_SET_FALSE(cmd_ctx_ptr);
  }

  if (raw_session_list.sessions_sz == 2) {
    for (size_t i = 0; i < raw_session_list.sessions_sz; i++) {
      Session *sesn_ptr_listed = SessionOffInstanceHolder(raw_session_list.sessions[i]);
      if (SESSION_ID(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr)) == SESSION_ID(sesn_ptr_listed)) {
        envelope_marshal.header->args = COMMAND_ARGS__ACCEPTED;
        _MarshalUserMessageToUser(CMDCTX_SESN_CTX_ORIGINATOR(cmd_ctx_ptr), NULL, CMDCTX_WSM(cmd_ctx_ptr), &command_envelope);
        continue;
      }

      envelope_marshal.header->args = COMMAND_ARGS__SYNCED;
      message_command.originator		=	MakeUserRecordFromSessionInProto(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), &user_record_originator, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF);

      _MarshalUserMessageToUser(CMDCTX_SESN_CTX_ORIGINATOR(cmd_ctx_ptr), raw_session_list.sessions[i], CMDCTX_WSM(cmd_ctx_ptr), &command_envelope);
    }

    DestructFenceRawSessionList (&raw_session_list, false);
  }

  return SESSION_RESULT_PTR(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr));
}

inline static UFSRVResult *
_MarshalGuardianUnLink (CommandBaseContext *cmd_base_ctx)
{
  MessageCommandContext *cmd_ctx_ptr = (MessageCommandContext *) cmd_base_ctx;
  MessageCommand	*msgcmd_ptr = CMDCTX_DATA_MESSAGE(cmd_ctx_ptr)->ufsrvcommand->msgcommand;

  _GENERATE_MESSAGECOMMAND_ENVELOPE_INITIALISATION();
  _PrepareMarshalMessageForUserMessage(&envelope_marshal, CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), NULL, CMDCTX_EVENT(cmd_ctx_ptr), CMDCTX_DATA_MESSAGE(cmd_ctx_ptr), msgcmd_ptr->header->command, COMMAND_ARGS__ACCEPTED);

  message_command.guardian  = msgcmd_ptr->guardian;

  envelope_marshal.header->args = COMMAND_ARGS__ACCEPTED;
  _MarshalUserMessageToUser(CMDCTX_SESN_CTX_ORIGINATOR(cmd_ctx_ptr), NULL, CMDCTX_WSM(cmd_ctx_ptr), &command_envelope);

  envelope_marshal.header->args = COMMAND_ARGS__SYNCED;
  message_command.originator		=	MakeUserRecordFromSessionInProto(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr), &user_record_originator, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF);

  _MarshalUserMessageToUser(CMDCTX_SESN_CTX_ORIGINATOR(cmd_ctx_ptr), CMDCTX_MSG_TARGET_SESN_INSTANCE(cmd_ctx_ptr), CMDCTX_WSM(cmd_ctx_ptr), &command_envelope);

  return SESSION_RESULT_PTR(CMDCTX_SESN_ORIGINATOR(cmd_ctx_ptr));
}

/**
 * @brief Main marshaller for the regular user message command.
 * 	@locked f_ptr: RW
 * 	@unlocks f_ptr
 */
inline static UFSRVResult *
_MarshalMessageToFence (InstanceContextForSession *ctx_sesn_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr, InstanceContextForFence *ctx_f_ptr, FenceEvent *fence_event_ptr)
{
  Session *sesn_ptr = ctx_sesn_ptr->sesn_ptr;
  Fence *f_ptr = ctx_f_ptr->f_ptr;

	if (FENCE_SESSIONS_LIST_SIZE(f_ptr) <= 0) {
		syslog(LOG_NOTICE, "%s {pid:'%lu', o:'%p', fid:'%lu'} NOTICE: Fence has zero members: RETURNING... ", __func__, pthread_self(), sesn_ptr, FENCE_ID(f_ptr));
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_EMPTY_INVITATION_LIST)
	}

	UserRecord 				user_record_originator;
	FenceRecord       fence_record;
	FenceRecord				*fence_record_ptr	= &fence_record;
	Envelope 					command_envelope	= ENVELOPE__INIT;
	CommandHeader 		header						= COMMAND_HEADER__INIT;
	UfsrvCommandWire	ufsrv_command			= UFSRV_COMMAND_WIRE__INIT;
	MessageCommand 		message_command		= MESSAGE_COMMAND__INIT;
	MessageCommand		*msgcmd_ptr				= data_msg_ptr->ufsrvcommand->msgcommand;

	command_envelope.ufsrvcommand				=	&ufsrv_command;
	ufsrv_command.header								=	&header;
	message_command.header							=	&header;

	ufsrv_command.msgcommand						=	&message_command;
	ufsrv_command.ufsrvtype							=	UFSRV_COMMAND_WIRE__UFSRV_TYPE__UFSRV_MESSAGE;

  FenceEvent *fe_ptr = fence_event_ptr;
  header.eid = fe_ptr->eid; header.has_eid = 1;
  header.gid = fe_ptr->gid; header.has_gid = 1;

  command_envelope.sourceufsrvuid			=	"0";//ufsrv initiated origin
  command_envelope.timestamp	=	GetTimeNowInMillis(); command_envelope.has_timestamp = 1;
  command_envelope.type				= _GetProtocolType(msgcmd_ptr); command_envelope.has_type = 1;
  header.when									=	command_envelope.timestamp; header.has_when = 1;
  header.when_client					=	msgcmd_ptr->header->when; header.has_when_client = 1;//this the timestamp internal to the client (date_sent)

  if (SESSION_USERGUARDIAN_UID(ctx_sesn_ptr->sesn_ptr) > 0 && _GetProtocolType(msgcmd_ptr) != ENVELOPE__TYPE__CIPHERTEXT) {
      _MarshalMessageCommandSync(ctx_sesn_ptr, data_msg_ptr, &(WebSocketMessage){.request=NULL, .type=WEB_SOCKET_MESSAGE__TYPE__REQUEST}, &command_envelope);
  }

  header.command							=	MESSAGE_COMMAND__COMMAND_TYPES__SAY;
  header.args									=	COMMAND_ARGS__ACCEPTED; header.has_args = 1;

  fence_record_ptr										=	MakeFenceRecordInProtoAsIdentifier(sesn_ptr, f_ptr, &fence_record);

  FenceRecord *fence_records[1];
  fence_records[0]										=	fence_record_ptr;
  message_command.fences							=	fence_records;
  message_command.n_fences						=	1;

  //just enough context to pass back to originator
  _MarshalFenceMessageToUser(ctx_sesn_ptr, NULL,
                             IS_EMPTY(wsm_ptr_received)?(&(WebSocketMessage){.request=NULL, .type=WEB_SOCKET_MESSAGE__TYPE__REQUEST}):wsm_ptr_received,
                             FENCE_ID(f_ptr), &command_envelope);

	fence_record_ptr->expire_timer			=	FENCE_MSG_EXPIRY(f_ptr); fence_record_ptr->has_expire_timer = 1;

	message_command.originator					=	MakeUserRecordFromSessionInProto(sesn_ptr, &user_record_originator, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF);

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

  if (msgcmd_ptr->bodyranges != NULL) {
    message_command.bodyranges		=  msgcmd_ptr->bodyranges;
    message_command.n_bodyranges  =  msgcmd_ptr->n_bodyranges;
  }

  header.args									=	COMMAND_ARGS__SYNCED;
	delivery_mode_broadcast:
	if (F_ATTR_IS_SET(FENCE_ATTRIBUTES(f_ptr), F_ATTR_BROADCAST)) {
		InstanceHolderForSession *instance_sesn_ptr_fence_owner = GetSessionForFenceOwner(sesn_ptr, f_ptr);
		if (IS_PRESENT(instance_sesn_ptr_fence_owner)) {
      _MarshalFenceMessageToUser(ctx_sesn_ptr, instance_sesn_ptr_fence_owner,
                                 IS_EMPTY(wsm_ptr_received)?(&(WebSocketMessage){.request=NULL, .type=WEB_SOCKET_MESSAGE__TYPE__REQUEST}):wsm_ptr_received,
                                 FENCE_ID(f_ptr), &command_envelope);

			goto return_destruct_proto;
		}
	}

	FenceRawSessionList raw_session_list = {0};
	unsigned long fid_saved = FENCE_ID(f_ptr);
	GetRawMemberUsersListForFence (sesn_ptr, ctx_f_ptr->instance_f_ptr, FENCE_CALLFLAG_INCLUDE_REMOTE_SESSIONS, &raw_session_list);//no locking
	if (!ctx_f_ptr->lock_already_owned)	{
	  FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
	  ctx_f_ptr->is_locked = false;
	}

	if (raw_session_list.sessions_sz > 0) {
		for (size_t i=0; i<raw_session_list.sessions_sz; i++) {
      Session *sesn_ptr_listed = SessionOffInstanceHolder(raw_session_list.sessions[i]);
			if (SESSION_ID(sesn_ptr) == SESSION_ID(sesn_ptr_listed))	continue; //skip self

      if (!IsUserOnShareListBlocked(sesn_ptr_listed, sesn_ptr)) {
        _MarshalFenceMessageToUser(ctx_sesn_ptr, raw_session_list.sessions[i],
                                   IS_EMPTY(wsm_ptr_received)
                                   ? (&(WebSocketMessage) {.request=NULL, .type=WEB_SOCKET_MESSAGE__TYPE__REQUEST})
                                   : wsm_ptr_received,
                                   fid_saved, &command_envelope);
      } else {
#ifdef __UF_TESTING
        syslog(LOG_NOTICE, "%s {pid:'%lu', o:'%p', cid:'%lu', o_blocking:'%p', cid_blocked:'%lu'} ERROR: BLOCKED BY USER...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sesn_ptr_listed, SESSION_ID(sesn_ptr_listed));
#endif
        continue;
      }
		}
	}

	DestructFenceRawSessionList(&raw_session_list, false);

	return_destruct_proto:
	DestructFenceRecordsProto(fence_records, message_command.n_fences, false, false);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_UFSRV_INTERBROADCAST)

	return_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_UFSRV_INTERBROADCAST)
}

inline static UFSRVResult *
_MarshalFenceMessageToUser(InstanceContextForSession *ctx_sesn_ptr, InstanceHolderForSession *instance_sesn_ptr_target, WebSocketMessage *wsm_ptr_received, unsigned long fid, Envelope *command_envelope_ptr)
{
  Session *sesn_ptr = ctx_sesn_ptr->sesn_ptr;
  Session *sesn_ptr_target = IS_PRESENT(instance_sesn_ptr_target)?SessionOffInstanceHolder(instance_sesn_ptr_target):NULL;

	CommandHeader *command_header_ptr	=	command_envelope_ptr->ufsrvcommand->header;
	command_header_ptr->cid						=	SESSION_ID((sesn_ptr_target?sesn_ptr_target:sesn_ptr)); command_header_ptr->has_cid = 1;

	UfsrvCommandMarshallingDescriptor ufsrv_description = {command_header_ptr->eid, fid, command_header_ptr->when, &EnvelopeMetaData, command_envelope_ptr};

#ifdef __UF_TESTING
	syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', cid_target:'%lu' uname_target:'%s', fid:'%lu'} Sending Message to User ", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr),
				SESSION_ID((sesn_ptr_target?sesn_ptr_target:sesn_ptr)), SESSION_USERNAME((sesn_ptr_target?sesn_ptr_target:sesn_ptr)), fid);
#endif

  UfsrvCommandInvokeUserCommand(ctx_sesn_ptr,
                                (IS_PRESENT(instance_sesn_ptr_target) ? (&(InstanceContextForSession) {
                                        instance_sesn_ptr_target, sesn_ptr_target}) : NULL),
                                IS_EMPTY(wsm_ptr_received)?(&(WebSocketMessage){.request=NULL, .type=WEB_SOCKET_MESSAGE__TYPE__REQUEST}):wsm_ptr_received,
                                NULL, &ufsrv_description, uMSG_V1_IDX);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

/**
 *
 * @param ctx_sesn_ptr The originator in guradian-origination relationship
 * @param dm_ptr_received whole-of-DataMessage as sent by originator
 * @param wsm_ptr_received
 * @param command_envelope_ptr_prepared lightly populated by the caller, containing some reference attributes
 * @return
 */
static UFSRVResult *
_MarshalMessageCommandSync(InstanceContextForSession *ctx_sesn_ptr, DataMessage *dm_ptr_received, WebSocketMessage *wsm_ptr_received, Envelope *command_envelope_ptr_prepared)
{
  Session *sesn_ptr = ctx_sesn_ptr->sesn_ptr;
  Envelope 					command_envelope	= ENVELOPE__INIT;
  CommandHeader 		header						= COMMAND_HEADER__INIT;
  SyncCommand sync_command            = SYNC_COMMAND__INIT;
  UserRecord user_record_originator;
  UfsrvCommandWire	ufsrv_command			= UFSRV_COMMAND_WIRE__INIT;
  UfsrvCommandWire *command_wire_originator_list[1];

  unsigned long sesn_call_flags				=	(CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY| CALL_FLAG_HASH_USERNAME_LOCALLY| CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION|CALL_FLAG_REMOTE_SESSION);

  bool lock_already_owned = false;
  GetSessionForThisUserByUserId (ctx_sesn_ptr->sesn_ptr, SESSION_USERGUARDIAN_UID(ctx_sesn_ptr->sesn_ptr), &lock_already_owned, sesn_call_flags);
  InstanceHolderForSession *instance_sesn_ptr_guardian = (InstanceHolderForSession *)SESSION_RESULT_USERDATA(ctx_sesn_ptr->sesn_ptr);

  if (unlikely(IS_EMPTY(instance_sesn_ptr_guardian)))	goto return_error_unknown_uname;

  command_envelope.sourceufsrvuid = command_envelope_ptr_prepared->sourceufsrvuid;
  command_envelope.timestamp = command_envelope_ptr_prepared->timestamp; command_envelope.has_timestamp = 1;
  command_envelope.type = command_envelope_ptr_prepared->type; command_envelope.has_type = 1;
  command_envelope.ufsrvcommand = &ufsrv_command;

  ufsrv_command.ufsrvtype = UFSRV_COMMAND_WIRE__UFSRV_TYPE__UFSRV_SYNC;
  ufsrv_command.synccommand = &sync_command;

  sync_command.header = &header;
  header.when = dm_ptr_received->ufsrvcommand->msgcommand->header->when; header.has_when = 1;
  header.when_client = dm_ptr_received->ufsrvcommand->msgcommand->header->when_client; header.has_when_client = 1;

  sync_command.type = SYNC_COMMAND__COMMAND_TYPES__GUARDIAN_SYNC;
  sync_command.originator = MakeUserRecordFromSessionInProto(sesn_ptr, &user_record_originator, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF);
  sync_command.originator_command = command_wire_originator_list; sync_command.n_originator_command = 1;
  command_wire_originator_list[0] = dm_ptr_received->ufsrvcommand;

  UfsrvCommandMarshallingDescriptor ufsrv_description = {0, 0, header.when, &EnvelopeMetaData, &command_envelope};

  UfsrvCommandInvokeUserCommand(ctx_sesn_ptr,
                                &(InstanceContextForSession) {instance_sesn_ptr_guardian, SessionOffInstanceHolder(instance_sesn_ptr_guardian)},
                                wsm_ptr_received,
                                NULL, &ufsrv_description, uSYNC_V1_IDX);


  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

  return_error_unknown_uname:
  syslog(LOG_DEBUG, "%s {pid:'%lu', O:'%p', userid:'%lu'}: ERROR: COULD NOT RETRIEVE SESSION FOR USER", __func__, pthread_self(), ctx_sesn_ptr->sesn_ptr, SESSION_USERGUARDIAN_UID(ctx_sesn_ptr->sesn_ptr));
  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
}

inline static UFSRVResult *
_MarshalUserMessageToUser(InstanceContextForSession *ctx_sesn_ptr, InstanceHolderForSession *instance_sesn_ptr_target, WebSocketMessage *wsm_ptr_received, Envelope *command_envelope_ptr)
{
  Session *sesn_ptr = SessionOffInstanceHolder(ctx_sesn_ptr->instance_sesn_ptr);
  Session *sesn_ptr_target = IS_PRESENT(instance_sesn_ptr_target)?SessionOffInstanceHolder(instance_sesn_ptr_target):NULL;

  CommandHeader *command_header_ptr	=	command_envelope_ptr->ufsrvcommand->header;
  command_header_ptr->cid						=	SESSION_ID((sesn_ptr_target?sesn_ptr_target:sesn_ptr)); command_header_ptr->has_cid = 1;

  UfsrvCommandMarshallingDescriptor ufsrv_descpriptor = {command_header_ptr->eid, 0, command_header_ptr->when, &EnvelopeMetaData, command_envelope_ptr};

#ifdef __UF_TESTING
  syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', cid_target:'%lu' uname_target:'%s'} Sending UserMessage to User ", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr),
          SESSION_ID((sesn_ptr_target?sesn_ptr_target:sesn_ptr)), SESSION_USERNAME((sesn_ptr_target?sesn_ptr_target:sesn_ptr)));
#endif

  UfsrvCommandInvokeUserCommand(ctx_sesn_ptr,
                                (IS_PRESENT(instance_sesn_ptr_target) ? (&(InstanceContextForSession) {
                                        instance_sesn_ptr_target, sesn_ptr_target}) : NULL),
                                IS_EMPTY(wsm_ptr_received)?(&(WebSocketMessage){.request=NULL, .type=WEB_SOCKET_MESSAGE__TYPE__REQUEST}):wsm_ptr_received,
                                NULL, &ufsrv_descpriptor, uMSG_V1_IDX);

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

/**
 * @brief Check if shared contact is permitting sender to share their contact info
 * @param sesn_ptr the sender of the contact
 * @param contact_record_ptr
 */
static bool
_IsContactSharing(Session *sesn_ptr, UserContactRecord **contact_records_ptr)
{
  bool          is_allowed_status   = true;
  UserContactRecord *contact_record_ptr = contact_records_ptr[0];
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
_HandleMessageCommandError (InstanceHolderForSession *instance_sesn_ptr, ClientContextData *ctx_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr, int rescode, int command_type)
{
  Envelope 					command_envelope	= ENVELOPE__INIT;
  CommandHeader 		header						= COMMAND_HEADER__INIT;
  UfsrvCommandWire	ufsrv_command			= UFSRV_COMMAND_WIRE__INIT;
  MessageCommand 		message_command		= MESSAGE_COMMAND__INIT;

  Session *sesn_ptr                   = SessionOffInstanceHolder(instance_sesn_ptr);

  command_envelope.ufsrvcommand				=	&ufsrv_command;
  ufsrv_command.header								=	&header;
  message_command.header							=	&header;

  ufsrv_command.msgcommand						=	&message_command;
  ufsrv_command.ufsrvtype							=	UFSRV_COMMAND_WIRE__UFSRV_TYPE__UFSRV_MESSAGE;


  command_envelope.sourceufsrvuid			=	"0";
  command_envelope.timestamp					=	GetTimeNowInMillis(); command_envelope.has_timestamp = 1;

  header.when													=	command_envelope.timestamp; header.has_when		=	1;
  header.cid													=	SESSION_ID(sesn_ptr);				header.has_cid		=	1;

  _BuildErrorHeaderForMessageCommand (&header, data_msg_ptr->ufsrvcommand->msgcommand->header, rescode, command_type);

#ifdef __UF_TESTING
  syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', uid:'%lu', cid:'%lu', arg_error:'%d', rescode:'%d'}: Marshaling Error response message...", __func__, pthread_self(), sesn_ptr, SESSION_USERID(sesn_ptr), SESSION_ID(sesn_ptr), header.args_error, rescode);
#endif

  return (_MarshalCommandToUser(instance_sesn_ptr, NULL, wsm_ptr_received, &command_envelope,  uGETKEYS_V1_IDX));//TODO: temp use of uGETKEYS_V1
}

/**
 * 	@brief Generalised command sending
 */
inline static UFSRVResult *
_MarshalCommandToUser	(InstanceHolderForSession *instance_sesn_ptr, InstanceHolderForSession *instance_sesn_ptr_target, WebSocketMessage *wsm_ptr_received, Envelope *command_envelope_ptr, unsigned req_cmd_idx)
{
  CommandHeader *command_header_ptr	=	command_envelope_ptr->ufsrvcommand->msgcommand->header;

  UfsrvCommandMarshallingDescriptor ufsrv_descpription = {command_header_ptr->eid, 0, command_header_ptr->when, &EnvelopeMetaData, command_envelope_ptr};

  UfsrvCommandInvokeUserCommand(
          &(InstanceContextForSession) {instance_sesn_ptr, SessionOffInstanceHolder(instance_sesn_ptr)},
          &(InstanceContextForSession) {instance_sesn_ptr_target, SessionOffInstanceHolder(instance_sesn_ptr_target)},
          IS_EMPTY(wsm_ptr_received)?(&(WebSocketMessage){.request=NULL, .type=WEB_SOCKET_MESSAGE__TYPE__REQUEST}):wsm_ptr_received, NULL, &ufsrv_descpription, req_cmd_idx);

  _RETURN_RESULT_SESN(SessionOffInstanceHolder(instance_sesn_ptr), NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

#include <lzf/lzf.h>
/**
 *
 * @param ctx_sesn_ptr Sender's session
 * @param dm_ptr DataMessage sent by sender
 * @param msg_descriptor_ptr_out
 * @return Instated values
 * @dynamic_memory EXPORTS rawmsg
 */
static ParsedMessageDescriptor *
_ParsedMessageDescriptorForMessageCommand (InstanceContextForSession *ctx_sesn_ptr, DataMessage *dm_ptr, ParsedMessageDescriptor *msg_descriptor_ptr_out)
{
  MessageCommand  *cmd_ptr = dm_ptr->ufsrvcommand->msgcommand;
  msg_descriptor_ptr_out->msg_type = MSGCMD_MESSAGE;
  msg_descriptor_ptr_out->userid_from =  UfsrvUidGetSequenceId(&SESSION_UFSRVUIDSTORE(ctx_sesn_ptr->sesn_ptr));
  msg_descriptor_ptr_out->timestamp = cmd_ptr->header->when;
  if (msg_descriptor_ptr_out->eid == 0) msg_descriptor_ptr_out->eid = cmd_ptr->header->eid;
  if (msg_descriptor_ptr_out->gid == 0) msg_descriptor_ptr_out->eid = cmd_ptr->header->gid;
  msg_descriptor_ptr_out->fid = cmd_ptr->fences[0]->fid;

  size_t 	packed_sz		=	data_message__get_packed_size(dm_ptr);
  uint8_t packed_msg[packed_sz],
          packed_msg_compressed[packed_sz];

  data_message__pack (dm_ptr, packed_msg);
  size_t packed_compressed_sz = lzf_compress(packed_msg, packed_sz, packed_msg_compressed, packed_sz);

  if (packed_compressed_sz == 0) {
    syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu', eid:'%lu', fid:'%lu'} ERROR: COULD NOT COMPRESS MESSAGE", __func__, pthread_self(), ctx_sesn_ptr->sesn_ptr, SESSION_ID(ctx_sesn_ptr->sesn_ptr), msg_descriptor_ptr_out->eid, msg_descriptor_ptr_out->fid);

    return NULL;
  }

  msg_descriptor_ptr_out->rawmsg = (char *)base64_encode(packed_msg_compressed, packed_compressed_sz, NULL);

  return msg_descriptor_ptr_out;
}