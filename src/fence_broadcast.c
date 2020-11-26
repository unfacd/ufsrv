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
#include <ufsrv_core/fence/fence_state.h>
#include <ufsrv_core/fence/fence_protobuf.h>
#include <ufsrv_core/user/users_protobuf.h>
#include <nportredird.h>
#include <attachment_descriptor_type.h>
#include <fence_proto.h>
#include <ufsrv_core/fence/fence_permission.h>
#include <ufsrvwebsock/include/protocol_websocket_session.h>
#include <sessions_delegator_type.h>
#include <ufsrv_core/msgqueue_backend/ufsrvcmd_broadcast.h>
#include <fence_broadcast.h>
#include <command_controllers.h>
#include <ufsrv_core/msgqueue_backend/UfsrvMessageQueue.pb-c.h>
#include <hiredis.h>
#include <ufsrv_core/fence/fence_permission_type.h>
#include <ufsrvuid.h>

extern ufsrv 							*const masterptr;
extern SessionsDelegator 	*const sessions_delegator_ptr;
extern __thread ThreadContext ufsrv_thread_context;

/**
 * 	@brief: Main interface method for broadcasting backend data model state change for Fence display name attribute.
 * 	@
 */

struct BroadcastMessageEnvelopeForFence {
	MessageQueueMessage *msgqueue_msg;
	FenceCommand 			  *fence_command;
	CommandHeader 		  *header;
	FenceRecord				  *fence_record;
	FenceRecord 			  **fence_records;
	UfsrvUid            *uid_ptr;
};

typedef struct BroadcastMessageEnvelopeForFence BroadcastMessageEnvelopeForFence;

inline static void _PrepareInterBroadcastMessageForFence (BroadcastMessageEnvelopeForFence *envelope_ptr, Session *sesn_ptr, Fence *f_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg);
static inline UFSRVResult *_PrepareForInterBroadcastHandling (MessageQueueMessage *mqm_ptr, FenceSessionPair *, bool *fence_lock_state, UFSRVResult *res_ptr, int);
static UFSRVResult *_HandleInterBroadcastFenceJoin (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastFenceMake (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastFenceLeave (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastFenceName (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastFenceMaxMembers (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastFenceDeliveryMode (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastFenceAvatar (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastFenceMessageExpiry (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastFencePermission (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastFencePermissionListSemantics (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastFenceInviteCommand (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastFenceUninvite (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastFenceInvite (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastFenceDestruct (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
static UFSRVResult *_HandleInterBroadcastFenceReload (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags);
////// INTER \\\\\\

#define _GENERATE_ENVELOPE_INITIALISATION() \
	MessageQueueMessage 	msgqueue_msg				=	MESSAGE_QUEUE_MESSAGE__INIT;	\
	FenceCommand 					fence_command				=	FENCE_COMMAND__INIT;	\
	CommandHeader 				header							=	COMMAND_HEADER__INIT;	\
	FenceRecord						fence_record				=	FENCE_RECORD__INIT;	\
	FenceRecord 					*fence_records[1];	\
  UfsrvUid              ufsrvuid            = {0}; \
	\
	BroadcastMessageEnvelopeForFence	envelope_broadcast = {	\
				.msgqueue_msg				=	&msgqueue_msg,	\
				.fence_command			=	&fence_command,	\
				.header							=	&header,	\
				.fence_record				=	&fence_record,	\
				.fence_records			=	fence_records,	\
	      .uid_ptr            = &ufsrvuid \
	}

inline static void
_PrepareInterBroadcastMessageForFence (BroadcastMessageEnvelopeForFence *envelope_ptr, Session *sesn_ptr, Fence *f_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg)
{
//	message_queue_message__init(envelope_ptr->msgqueue_msg);
//	fence_command__init(envelope_ptr->fence_command)
//	command_header__init(envelope_ptr->header);
//	fence_record__init(envelope_ptr->fence_record);

	//consider using UfsrvMsgCommandType msgcmd_type for command_type
	envelope_ptr->msgqueue_msg->command_type				=	UFSRV_FENCE; envelope_ptr->msgqueue_msg->has_command_type = 1;
	envelope_ptr->msgqueue_msg->broadcast_semantics	=	MESSAGE_QUEUE_MESSAGE__BROADCAST_SEMANTICS__INTER; envelope_ptr->msgqueue_msg->has_broadcast_semantics	= 1;
	envelope_ptr->msgqueue_msg->fence								=	envelope_ptr->fence_command;
	envelope_ptr->fence_command->header							=	envelope_ptr->header;
	envelope_ptr->fence_command->fences							=	envelope_ptr->fence_records;
	envelope_ptr->fence_records[0]									=	envelope_ptr->fence_record;
	envelope_ptr->fence_command->n_fences						=	1;

	envelope_ptr->fence_record->fid									=	FENCE_ID(f_ptr);					envelope_ptr->fence_record->has_fid = 1;
	envelope_ptr->header->args											=	command_arg;							envelope_ptr->header->has_args = 1;

	if (IS_EMPTY(event_ptr))	return;

	envelope_ptr->header->when											=	event_ptr->when; 					envelope_ptr->header->has_when =1 ;
	envelope_ptr->header->eid												=	event_ptr->eid; 					envelope_ptr->header->has_eid = 1;
	envelope_ptr->header->cid												=	SESSION_ID(sesn_ptr); 		envelope_ptr->header->has_cid = 1;
	envelope_ptr->header->ufsrvuid.data							= SESSION_UFSRVUID(sesn_ptr); envelope_ptr->header->has_ufsrvuid = 1;
	envelope_ptr->header->ufsrvuid.len							=	CONFIG_MAX_UFSRV_ID_SZ;
  if (IS_PRESENT(GetUfsrvUid(sesn_ptr, FENCE_OWNER_UID(f_ptr), envelope_ptr->uid_ptr, false, NULL))) {
    MakeUfsrvUidInProto(envelope_ptr->uid_ptr, &(envelope_ptr->fence_record->owner_uid), true);
    envelope_ptr->fence_record->has_owner_uid = 1;
  }
	envelope_ptr->fence_record->fence_type					=	FENCE_ATTRIBUTES(f_ptr); 	envelope_ptr->fence_record->has_fence_type = 1;
	//be careful: for messages originating from users fence_type has its own enum values and not used a la 'f_ptr->attrs'
}

UFSRVResult *
InterBroadcastFenceMake (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg)
{
  _GENERATE_ENVELOPE_INITIALISATION();
	Fence *f_ptr	=	(Fence *)context_ptr;

	_PrepareInterBroadcastMessageForFence (&envelope_broadcast, sesn_ptr, f_ptr, event_ptr, command_arg);

	header.command										=	FENCE_COMMAND__COMMAND_TYPES__MAKE;

	//actual delta
	fence_record.fid								=	FENCE_ID(f_ptr);
	fence_record.cname							=	FENCE_CNAME(f_ptr);//by reference. DONT LOSE SCOPE

	return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg, UFSRV_FENCE));
}

UFSRVResult *
InterBroadcastFenceJoin (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg)
{
  _GENERATE_ENVELOPE_INITIALISATION();

  UserRecord		invited_by					=	USER_RECORD__INIT;

	Fence *f_ptr	=	(Fence *)context_ptr;

	_PrepareInterBroadcastMessageForFence (&envelope_broadcast, sesn_ptr, f_ptr, event_ptr, command_arg);

	header.command										=	FENCE_COMMAND__COMMAND_TYPES__JOIN;

	//actual delta
	fence_record.fid								=	FENCE_ID(f_ptr);
	fence_record.cname							=	FENCE_CNAME(f_ptr);//by reference. DONT LOSE SCOPE
	//fence_record.fence_type							=	FENCE_ATTRIBUTES(f_ptr);	fence_record.has_ftype=1; this is set in _PrepareInterBroadcastMessageForFence
	fence_command.invited_by				=	&invited_by;
	//TODO: invited by

	return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg, UFSRV_FENCE));
}

UFSRVResult *
InterBroadcastFenceLeave (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg)
{
//	MessageQueueMessage msgqueue_msg	=	MESSAGE_QUEUE_MESSAGE__INIT;
//	FenceCommand 	fence_command				=	FENCE_COMMAND__INIT;
//	CommandHeader header							=	COMMAND_HEADER__INIT;
//	FenceRecord		fence_record				=	FENCE_RECORD__INIT;
//	FenceRecord 	*fence_records[1];
//
//	BroadcastMessageEnvelopeForFence	envelope = {
//			.msgqueue_msg				=	&msgqueue_msg,
//			.fence_command			=	&fence_command,
//			.header							=	&header,
//			.fence_record				=	&fence_record,
//			.fence_records			=	fence_records
//	};

  _GENERATE_ENVELOPE_INITIALISATION();

	Fence *f_ptr	=	(Fence *)context_ptr;

	_PrepareInterBroadcastMessageForFence (&envelope_broadcast, sesn_ptr, f_ptr, event_ptr, command_arg);

	header.command										=	FENCE_COMMAND__COMMAND_TYPES__LEAVE;

	//actual delta
	fence_record.fid								=	FENCE_ID(f_ptr);
	fence_record.cname							=	FENCE_CNAME(f_ptr);//by reference. CONT LOSE SCOPE

	return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg, UFSRV_FENCE));
}

UFSRVResult *
InterBroadcastFenceInvite (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg)
{
	ContextDataFenceInvite *ctx_ptr_fence_invite	=	(ContextDataFenceInvite *)context_ptr;

	_GENERATE_ENVELOPE_INITIALISATION();

	_PrepareInterBroadcastMessageForFence (&envelope_broadcast, sesn_ptr, FENCESTATE_FENCE(ctx_ptr_fence_invite->fence_state_ptr), event_ptr, command_arg);

	header.command										=	FENCE_COMMAND__COMMAND_TYPES__INVITE;

	//actual delta
	UserRecord *user_records_invited[1];
	UserRecord	user_record_invited;

	user_records_invited[0]					=	&user_record_invited;
	fence_record.invited_members		=	user_records_invited;
	fence_record.n_invited_members	=	1;

	MakeUserRecordFromSessionInProto (ctx_ptr_fence_invite->sesn_ptr_invited, &user_record_invited, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF);
	user_record_invited.cid									=	SESSION_ID(ctx_ptr_fence_invite->sesn_ptr_invited); 		user_record_invited.has_cid	=	1;

	MakeUfsrvUidInProto(&SESSION_UFSRVUIDSTORE(sesn_ptr), &(fence_record.invited_by), true);
	fence_record.has_invited_by = 1;

	return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg, UFSRV_FENCE));
}

UFSRVResult *
InterBroadcastFenceDnameMessage (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg)
{
	_GENERATE_ENVELOPE_INITIALISATION();

	Fence *f_ptr	=	(Fence *)context_ptr;

	_PrepareInterBroadcastMessageForFence (&envelope_broadcast, sesn_ptr, f_ptr, event_ptr, command_arg);

	header.command										=	FENCE_COMMAND__COMMAND_TYPES__FNAME;

	//actual delta
	fence_record.fname								=	FENCE_DNAME(f_ptr);//by reference. DONT LOSE SCOPE

	return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg, UFSRV_FENCE));

#if 0
	//template for local static initialisation
	MessageQueueMessage msgqueue_msg	=	MESSAGE_QUEUE_MESSAGE__INIT;
	FenceCommand 	fence_command				=	FENCE_COMMAND__INIT;
	CommandHeader header							=	COMMAND_HEADER__INIT;
	FenceRecord		fence_record				=	FENCE_RECORD__INIT;
	FenceRecord 	*fence_records[1];

	msgqueue_msg.fence								=	&fence_command;
	fence_command.header							=	&header;
	fence_command.fences							=	fence_records;
	fence_records[0]									=	&fence_record;

	fence_command.n_fences						=	1;
	fence_record.fid									=	FENCE_ID(f_ptr); 	fence_record.has_fid=1;

	header.command										=	FENCE_COMMAND__COMMAND_TYPES__FNAME;
	header.command										=	command_arg;
	header.when												=	event_ptr->when; 	header.has_when=1;

	fence_command.eid									=	event_ptr->eid; fence_command.has_eid=1;

	//actual delta
	fence_record.fname								=	FENCE_DNAME(f_ptr);//by reference. CONT LOSE SCOPE

	return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg));
#endif
}

UFSRVResult *
InterBroadcastFenceAvatarMessage (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg)
{
//	MessageQueueMessage msgqueue_msg				=	MESSAGE_QUEUE_MESSAGE__INIT;
//	FenceCommand 				fence_command				=	FENCE_COMMAND__INIT;
//	CommandHeader 			header							=	COMMAND_HEADER__INIT;
//	FenceRecord					fence_record				=	FENCE_RECORD__INIT;
//	FenceRecord 				*fence_records[1];
//	AttachmentRecord		attachment_record;//this will be init'ed by MakeAttachmentRecordInProto()
//	AttachmentRecord		*attachment_records[1];
//
//	BroadcastMessageEnvelopeForFence	envelope = {
//			.msgqueue_msg				=	&msgqueue_msg,
//			.fence_command			=	&fence_command,
//			.header							=	&header,
//			.fence_record				=	&fence_record,
//			.fence_records			=	fence_records
//	};

  _GENERATE_ENVELOPE_INITIALISATION();

  AttachmentRecord		attachment_record;//this will be init'ed by MakeAttachmentRecordInProto()
	AttachmentRecord		*attachment_records[1];

	Fence *f_ptr																		=	(Fence *)((ContextDataPair *)context_ptr)->first;
	AttachmentDescriptor *attachment_descriptor_ptr	=	(AttachmentDescriptor *)((ContextDataPair *)context_ptr)->second;

	_PrepareInterBroadcastMessageForFence (&envelope_broadcast, sesn_ptr, f_ptr, event_ptr, command_arg);
	fence_command.attachments					=	attachment_records;
	fence_command.attachments[0]			=	&attachment_record;
	fence_command.n_attachments				=	1;

	MakeAttachmentRecordInProto (attachment_descriptor_ptr, &attachment_record, false);

	header.command										=	FENCE_COMMAND__COMMAND_TYPES__AVATAR;

	return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg, UFSRV_FENCE));
}

UFSRVResult *
InterBroadcastFenceMsgExpiry (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg)
{
	FenceStateDescriptor *fence_state_ptr	=	(FenceStateDescriptor *)((ContextDataPair *)context_ptr)->first;

	_GENERATE_ENVELOPE_INITIALISATION();

	_PrepareInterBroadcastMessageForFence (&envelope_broadcast, sesn_ptr, FENCESTATE_FENCE(fence_state_ptr), event_ptr, command_arg);

	header.command										=	FENCE_COMMAND__COMMAND_TYPES__EXPIRY;

	//actual delta
	fence_record.expire_timer	=	FENCE_MSG_EXPIRY(FENCESTATE_FENCE(fence_state_ptr)); fence_record.has_expire_timer = 1;

	return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg, UFSRV_FENCE));
}

UFSRVResult *
InterBroadcastFenceMaxMembers (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg)
{
	FenceStateDescriptor *fence_state_ptr	=	(FenceStateDescriptor *)((ContextDataPair *)context_ptr)->first;

	_GENERATE_ENVELOPE_INITIALISATION();

	_PrepareInterBroadcastMessageForFence (&envelope_broadcast, sesn_ptr, FENCESTATE_FENCE(fence_state_ptr), event_ptr, command_arg);

	header.command										=	FENCE_COMMAND__COMMAND_TYPES__MAXMEMBERS;

	//actual delta
	fence_record.maxmembers	=	FENCE_MAX_MEMBERS(FENCESTATE_FENCE(fence_state_ptr)); fence_record.has_maxmembers = 1;

	return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg, UFSRV_FENCE));
}

UFSRVResult *
InterBroadcastFenceDeliveryMode (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg)
{
  FenceStateDescriptor *fence_state_ptr	=	(FenceStateDescriptor *)((ContextDataPair *)context_ptr)->first;

  _GENERATE_ENVELOPE_INITIALISATION();

  _PrepareInterBroadcastMessageForFence (&envelope_broadcast, sesn_ptr, FENCESTATE_FENCE(fence_state_ptr), event_ptr, command_arg);

  header.command										=	FENCE_COMMAND__COMMAND_TYPES__DELIVERY_MODE;

  //actual delta
  MakeFenceDeliveryModeInProto (FENCESTATE_FENCE(fence_state_ptr), &fence_record);

  return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg, UFSRV_FENCE));
}

UFSRVResult *
InterBroadcastFencePermission (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg)
{
	Fence 					*f_ptr							=	((FencePermissionContextData *)context_ptr)->fence.f_ptr;
	Session 				*sesn_ptr_target		=	((FencePermissionContextData *)context_ptr)->sesn_ptr;
	FencePermission *permission_ptr			=	((FencePermissionContextData *)context_ptr)->permission_ptr;

	_GENERATE_ENVELOPE_INITIALISATION();

	_PrepareInterBroadcastMessageForFence (&envelope_broadcast, sesn_ptr, f_ptr, event_ptr, command_arg);

	header.command										=	FENCE_COMMAND__COMMAND_TYPES__PERMISSION;

	//actual delta
	UserRecord *user_records[1];
	UserRecord	user_record;
	FenceRecord__Permission	fence_permission = FENCE_RECORD__PERMISSION__INIT;

	user_records[0]											=	&user_record;
	MakeUserRecordFromSessionInProto (sesn_ptr_target, &user_record, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF);
	user_record.cid											=	SESSION_ID(sesn_ptr_target); 		user_record.has_cid	=	1;
	fence_permission.users							=	user_records;
	fence_permission.n_users						=	1;
	fence_permission.type								=	permission_ptr->type;//aligned with protobuf enum FENCE_RECORD__PERMISSION__TYPE__PRESENTATION;
	fence_command.type                  = permission_ptr->type; fence_command.has_type = 1;
	AssignFencePermissionForProto (permission_ptr, &fence_record, &fence_permission);

	return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg, UFSRV_FENCE));
}

UFSRVResult *
InterBroadcastFenceListSemantics (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg)
{
  Fence 					*f_ptr							=	((FencePermissionContextData *)context_ptr)->fence.f_ptr;
  Session 				*sesn_ptr_target		=	((FencePermissionContextData *)context_ptr)->sesn_ptr;
  FencePermission *permission_ptr			=	((FencePermissionContextData *)context_ptr)->permission_ptr;

  _GENERATE_ENVELOPE_INITIALISATION();

  _PrepareInterBroadcastMessageForFence (&envelope_broadcast, sesn_ptr, f_ptr, event_ptr, command_arg);

  header.command										=	FENCE_COMMAND__COMMAND_TYPES__PERMISSION_LIST_SEMANTICS;

  //actual delta
  FenceRecord__Permission	fence_permission = FENCE_RECORD__PERMISSION__INIT;

  fence_permission.type								=	permission_ptr->type;
  fence_permission.list_semantics     = permission_ptr->config.whitelist?FENCE_RECORD__PERMISSION__LIST_SEMANTICS__WHITELIST:FENCE_RECORD__PERMISSION__LIST_SEMANTICS__BLACKLIST;
  fence_permission.has_list_semantics = 1;

  AssignFencePermissionForProto (permission_ptr, &fence_record, &fence_permission);

  return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg, UFSRV_FENCE));
}

/**
 * 	@brief: This is internal server-to-server message and cannot originate from end user
 * 	@param event_ptr: must be set to NULL, since there is no event associated with this
 */
UFSRVResult *
InterBroadcastFenceDestruct (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg)
{
	_GENERATE_ENVELOPE_INITIALISATION();

	Fence *f_ptr	=	(Fence *)context_ptr;

	_PrepareInterBroadcastMessageForFence (&envelope_broadcast, sesn_ptr, f_ptr, event_ptr, command_arg);

	header.command										=	FENCE_COMMAND__COMMAND_TYPES__DESTRUCT;

	return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg, UFSRV_FENCE));
}

UFSRVResult *
InterBroadcastFenceReload (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg)
{
	_GENERATE_ENVELOPE_INITIALISATION();

	Fence *f_ptr	=	(Fence *)context_ptr;

	_PrepareInterBroadcastMessageForFence (&envelope_broadcast, sesn_ptr, f_ptr, event_ptr, command_arg);

	header.command										=	FENCE_COMMAND__COMMAND_TYPES__STATE;

	return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg, UFSRV_FENCE));
}

/**
 * 	@brief: Main handler for Fence INTER broadcast messages arriving via messagequeue. The handler will be run from UfsrvWorker context,
 * 	as opposed to SessionWorker one, therefore the affected user session must be loaded in ephemeral mode.
 * 	Prior to invoking this function a command-type specific verification will have taken place inside '_VerifyInterMessageQueueCommand()'
 *
 * 	@locks: Session *
 * 	@locks: Fence *
 * 	@unlocks Session *
 * 	@unlocks: Fence *
 * 	@worker: ufsrv
 */
int
HandleInterBroadcastForFence (MessageQueueMessage 		*mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	bool lock_already_owned									= false;
	int 										rescode					=	0;

	FenceSessionPair	fence_sesn_pair				=	{0};
	UFSRVResult 			result								=	{0};
	CommandHeader 		*command_header_ptr		=	mqm_ptr->fence->header;

	_PrepareForInterBroadcastHandling (mqm_ptr, &fence_sesn_pair, &lock_already_owned, &result, command_header_ptr->command);

	//on error, we only let base fence through because that has its own peculiar rules
	if (_RESULT_TYPE_ERROR(&result) &&
			!(_RESULT_CODE_EQUAL(&result, RESCODE_PROG_WONTLOCK)) &&
			!(fence_sesn_pair.fence_type == F_ATTR_BASEFENCE))	goto return_error_nonlocal_user;

	//
	//SESSION LOCKED, FENCE LOCKED, SESSION LOADED WITH ACCESS CONTEXT FROM UFSRVWORKER
	//

	switch (command_header_ptr->command)
	{
		case FENCE_COMMAND__COMMAND_TYPES__JOIN:
			_HandleInterBroadcastFenceJoin ((ClientContextData *)&fence_sesn_pair, mqm_ptr, &result, call_flags);
			break;

		case FENCE_COMMAND__COMMAND_TYPES__LEAVE:
			_HandleInterBroadcastFenceLeave ((ClientContextData *)&fence_sesn_pair, mqm_ptr, &result, call_flags);
			break;

		case FENCE_COMMAND__COMMAND_TYPES__MAKE:
			_HandleInterBroadcastFenceMake ((ClientContextData *)&fence_sesn_pair, mqm_ptr, &result, call_flags);
			break;

		case FENCE_COMMAND__COMMAND_TYPES__AVATAR:
			_HandleInterBroadcastFenceAvatar ((ClientContextData *)&fence_sesn_pair, mqm_ptr, &result, call_flags);
			break;

		case FENCE_COMMAND__COMMAND_TYPES__FNAME:
			_HandleInterBroadcastFenceName ((ClientContextData *)&fence_sesn_pair, mqm_ptr, &result, call_flags);
			break;

		case FENCE_COMMAND__COMMAND_TYPES__INVITE:
			_HandleInterBroadcastFenceInviteCommand ((ClientContextData *)&fence_sesn_pair, mqm_ptr, &result, call_flags);
			break;

		case FENCE_COMMAND__COMMAND_TYPES__DESTRUCT:
			_HandleInterBroadcastFenceDestruct ((ClientContextData *)&fence_sesn_pair, mqm_ptr, &result, call_flags);
			break;

		case FENCE_COMMAND__COMMAND_TYPES__STATE:
			_HandleInterBroadcastFenceReload ((ClientContextData *)&fence_sesn_pair, mqm_ptr, &result, call_flags);
			break;

		case FENCE_COMMAND__COMMAND_TYPES__EXPIRY:
			_HandleInterBroadcastFenceMessageExpiry ((ClientContextData *)&fence_sesn_pair, mqm_ptr, &result, call_flags);
			break;

		case FENCE_COMMAND__COMMAND_TYPES__PERMISSION:
			_HandleInterBroadcastFencePermission ((ClientContextData *)&fence_sesn_pair, mqm_ptr, &result, call_flags);
			break;

		case FENCE_COMMAND__COMMAND_TYPES__PERMISSION_LIST_SEMANTICS:
			_HandleInterBroadcastFencePermissionListSemantics ((ClientContextData *)&fence_sesn_pair, mqm_ptr, &result, call_flags);
			break;

		case FENCE_COMMAND__COMMAND_TYPES__MAXMEMBERS:
			_HandleInterBroadcastFenceMaxMembers ((ClientContextData *)&fence_sesn_pair, mqm_ptr, &result, call_flags);
			break;

    case FENCE_COMMAND__COMMAND_TYPES__DELIVERY_MODE:
      _HandleInterBroadcastFenceDeliveryMode ((ClientContextData *)&fence_sesn_pair, mqm_ptr, &result, call_flags);
      break;
	}

	return_success:
	if (IS_PRESENT(fence_sesn_pair.instance_f_ptr))	if (!lock_already_owned)	FenceEventsUnLockCtx (THREAD_CONTEXT_PTR, FenceOffInstanceHolder(fence_sesn_pair.instance_f_ptr), THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));
	if (IS_PRESENT(fence_sesn_pair.instance_sesn_ptr)) {
	  Session *sesn_ptr = SessionOffInstanceHolder(fence_sesn_pair.instance_sesn_ptr);
    SESSION_WHEN_SERVICED(sesn_ptr) = time(NULL);
		SessionUnLoadEphemeralMode(sesn_ptr);
		SessionUnLockCtx (THREAD_CONTEXT_PTR, sesn_ptr, __func__);
	}
	return rescode;

	return_error_nonlocal_user:
	rescode = -1;
	goto return_final;

	return_error_unknown_command:
	rescode=-1;

	return_final:
	return rescode;

}

static UFSRVResult *
_HandleInterBroadcastFenceJoin (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	FenceSessionPair *pair_ptr				=	(FenceSessionPair *)context_ptr;

	InstanceHolderForFenceStateDescriptor *instance_fence_state_ptr;
	instance_fence_state_ptr = AddUserToThisFenceListWithLinkback(pair_ptr->instance_sesn_ptr,
																										 pair_ptr->instance_f_ptr,
                                                     SESSION_FENCE_LIST_PTR(SessionOffInstanceHolder(pair_ptr->instance_sesn_ptr)),
																										 &((FenceOffInstanceHolder(pair_ptr->instance_f_ptr))->fence_user_sessions_list),
																										 EVENT_TYPE_FENCE_USER_JOINED,
																										 CALL_FLAG_FENCE_LIST_CHECK_DUP_SESSION|CALL_FLAG_SESSION_LIST_CHECK_DUP_FENCE);
	if (IS_PRESENT(instance_fence_state_ptr)) {
	  FenceStateDescriptor *fstate_ptr = FenceStateDescriptorOffInstanceHolder(instance_fence_state_ptr);
    (FenceOffInstanceHolder(fstate_ptr->instance_holder_fence))->fence_events.last_event_id = mqm_ptr->fence->header->eid;
		fstate_ptr->when_joined = mqm_ptr->fence->header->when;

		_RETURN_RESULT_RES (res_ptr, fstate_ptr, RESULT_TYPE_SUCCESS, RESCODE_FENCE_FENCE_MEMBERSHIP)
	}

	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_FENCE_MEMBERSHIP)
}

/**
 * 	@brief: INTER message signaling the creation of a new fence in the network. For user fence we should see owner userid.
 * 	For geoences, owner is always 0.
 */
static UFSRVResult *
_HandleInterBroadcastFenceMake (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	FenceSessionPair *pair_ptr = (FenceSessionPair *)context_ptr;
	//by this time the fence should have been created, hashed and its users instantiated
	//for geofence, there is no sesn_ptr

  (FenceOffInstanceHolder(pair_ptr->instance_f_ptr))->fence_events.last_event_id = mqm_ptr->fence->header->eid;

	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_FENCE_MEMBERSHIP)
}

static UFSRVResult *
_HandleInterBroadcastFenceLeave (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	FenceSessionPair *pair_ptr				=	(FenceSessionPair *)context_ptr;

	RemoveUserFromFence(pair_ptr->instance_sesn_ptr, FenceOffInstanceHolder(pair_ptr->instance_f_ptr), CALL_FLAG_DONT_BROADCAST_FENCE_EVENT);
  (FenceOffInstanceHolder(pair_ptr->instance_f_ptr))->fence_events.last_event_id=mqm_ptr->fence->header->eid;

	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_FENCE_MEMBERSHIP)
}

static UFSRVResult *
_HandleInterBroadcastFenceInviteCommand (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	switch (mqm_ptr->fence->header->args)
	{
		case COMMAND_ARGS__UNINVITED:
		return (_HandleInterBroadcastFenceUninvite (context_ptr, mqm_ptr, res_ptr, call_flags));

		case COMMAND_ARGS__INVITED:
			return (_HandleInterBroadcastFenceInvite (context_ptr, mqm_ptr, res_ptr, call_flags));
			break;

		default:
			break;
	}

	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_FENCE_MEMBERSHIP)
}

static UFSRVResult *
_HandleInterBroadcastFenceUninvite (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	FenceSessionPair *pair_ptr				=	(FenceSessionPair *)context_ptr;

  RemoveUserFromInvitedList(pair_ptr->instance_sesn_ptr, NULL, NULL, 0);
	if (mqm_ptr->fence->header->has_eid)	(FenceOffInstanceHolder(pair_ptr->instance_f_ptr))->fence_events.last_event_id = mqm_ptr->fence->header->eid;

	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_FENCE_MEMBERSHIP)
}

/**
 * 	@locks: sesn_ptr_invited
 * 	@unlocks: sesn_ptr_invited
 */
static UFSRVResult *
_HandleInterBroadcastFenceInvite (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
  if (mqm_ptr->fence->n_fences > 0 && IS_PRESENT(mqm_ptr->fence->fences) && IS_PRESENT(mqm_ptr->fence->fences[0])) {
    FenceSessionPair *pair_ptr = (FenceSessionPair *) context_ptr;
    Session *sesn_ptr_invited = NULL;
    Session *sesn_ptr_inviter = NULL;

    Session *sesn_ptr_ctx = SessionOffInstanceHolder(pair_ptr->instance_sesn_ptr);
    Fence *f_ptr_ctx = FenceOffInstanceHolder(pair_ptr->instance_f_ptr);
    FenceRecord *fence_record_ptr = mqm_ptr->fence->fences[0];

    if (memcmp(fence_record_ptr->invited_by.data, SESSION_UFSRVUID(sesn_ptr_ctx), CONFIG_MAX_UFSRV_ID_SZ) == 0) {
      sesn_ptr_inviter = SessionOffInstanceHolder(pair_ptr->instance_sesn_ptr);//already locked. Fetched based on header not invited_by field;
    } else {
      Session *sesn_ptr = SessionOffInstanceHolder(pair_ptr->instance_sesn_ptr);
      syslog(LOG_ERR,
             "%s {pid:'%lu', o:'%p', cid:'%lu', fid:'%lu', uid_thisuser:'%lu', uid_inviter:'%lu'}: NOTICE: NOT SUPPORTED: User who sent the invitation is not the same as this user",
             __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr),
             FENCE_ID(FenceOffInstanceHolder(pair_ptr->instance_f_ptr)), SESSION_USERID(sesn_ptr),
             UfsrvUidGetSequenceId((const UfsrvUid *) fence_record_ptr->invited_by.data));
      _RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_FENCE_MEMBERSHIP)
    }

    //yes the full catastrophe. We need the use due to association with the inviter
    bool lock_already_owned = false;
    unsigned long sesn_call_flags_invited = (CALL_FLAG_LOCK_SESSION | CALL_FLAG_LOCK_SESSION_BLOCKING |
                                             CALL_FLAG_HASH_SESSION_LOCALLY | CALL_FLAG_HASH_UID_LOCALLY |
                                             CALL_FLAG_HASH_USERNAME_LOCALLY |
                                             CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION | CALL_FLAG_REMOTE_SESSION);
    GetSessionForThisUserByUserId(sesn_ptr_ctx,
                                  UfsrvUidGetSequenceId((const UfsrvUid *) fence_record_ptr->invited_by.data),
                                  &lock_already_owned, sesn_call_flags_invited);
    InstanceHolderForSession *instance_sesn_ptr_invited = (InstanceHolderForSession *) SESSION_RESULT_USERDATA(sesn_ptr_ctx);

    if (IS_PRESENT(instance_sesn_ptr_invited)) {
      sesn_ptr_invited = SessionOffInstanceHolder(instance_sesn_ptr_invited);
      AddMemberToInvitedFenceList(instance_sesn_ptr_invited, pair_ptr->instance_f_ptr, sesn_ptr_inviter, CALLFLAGS_EMPTY);//no writeback

      if (mqm_ptr->fence->header->has_eid) f_ptr_ctx->fence_events.last_event_id = mqm_ptr->fence->header->eid;

      if (!lock_already_owned) SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_invited, __func__);

      _RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_FENCE_MEMBERSHIP)
    } else {
      return SESSION_RESULT_PTR(sesn_ptr_ctx);
    }
  } else {
    syslog(LOG_ERR, "%s {pid:'%lu', eid:'%lu', cid:'%lu'}: ERROR: FENCE RECORD MAY HAVE BEEN UNDEFINED", __func__, pthread_self(), mqm_ptr->fence->header->eid, mqm_ptr->fence->header->cid);

    _RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_MISSING_PARAM)
  }
}

static UFSRVResult *
_HandleInterBroadcastFenceName (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	FenceSessionPair *pair_ptr				=	(FenceSessionPair *)context_ptr;
  Fence *f_ptr = FenceOffInstanceHolder(pair_ptr->instance_f_ptr);

	UpdateFenceNameAssignment (NULL, pair_ptr->instance_f_ptr, mqm_ptr->fence->fences[0]->fname, NULL, true, 0);
	f_ptr->fence_events.last_event_id = mqm_ptr->fence->header->eid;

	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_FENCE_MEMBERSHIP)
}

static UFSRVResult *
_HandleInterBroadcastFenceMaxMembers (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	FenceSessionPair *pair_ptr				=	(FenceSessionPair *)context_ptr;
	Fence *f_ptr = FenceOffInstanceHolder(pair_ptr->instance_f_ptr);

	FENCE_MAX_MEMBERS(f_ptr) = mqm_ptr->fence->fences[0]->maxmembers;
	f_ptr->fence_events.last_event_id = mqm_ptr->fence->header->eid;

	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_FENCE_MEMBERSHIP)
}

static UFSRVResult *
_HandleInterBroadcastFenceDeliveryMode (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
  FenceSessionPair *pair_ptr				=	(FenceSessionPair *)context_ptr;

  if (mqm_ptr->fence->fences[0]->has_delivery_mode) {
    Fence *f_ptr = FenceOffInstanceHolder(pair_ptr->instance_f_ptr);
    UpdateFenceDeliveryModeAssignment(SessionOffInstanceHolder(pair_ptr->instance_sesn_ptr), f_ptr, mqm_ptr->fence->fences[0]->delivery_mode, CALLFLAGS_EMPTY);
    f_ptr->fence_events.last_event_id = mqm_ptr->fence->header->eid;

    _RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_FENCE_MEMBERSHIP)
  }

  syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', fo:'%p'}: ERROR: INTERBROADCAST FENCE SETTING UNSET", __func__, pthread_self(), SessionOffInstanceHolder(pair_ptr->instance_sesn_ptr), FenceOffInstanceHolder(pair_ptr->instance_f_ptr));
  _RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOGIC_EMPTY_RESOURCE)
}

static UFSRVResult *
_HandleInterBroadcastFenceAvatar (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	FenceSessionPair *pair_ptr				=	(FenceSessionPair *)context_ptr;

	if ((mqm_ptr->fence->n_attachments == 0) || (IS_EMPTY(mqm_ptr->fence->attachments)) || (IS_EMPTY(mqm_ptr->fence->attachments[0]))) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', n_attachments:'%lu'}: ERROR: DID NOT FIND ATTACHMENT RECORD", __func__, pthread_self(), mqm_ptr->fence->n_attachments);
		_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_FENCE_MEMBERSHIP)
	}

	Fence *f_ptr = FenceOffInstanceHolder(pair_ptr->instance_f_ptr);
	free (FENCE_AVATAR(f_ptr));
	FENCE_AVATAR(f_ptr) = strdup(mqm_ptr->fence->attachments[0]->id);

	f_ptr->fence_events.last_event_id = mqm_ptr->fence->header->eid;

	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_FENCE_MEMBERSHIP)
}

static UFSRVResult *
_HandleInterBroadcastFenceMessageExpiry (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	FenceSessionPair *pair_ptr				=	(FenceSessionPair *)context_ptr;

	if (!mqm_ptr->fence->fences[0]->has_expire_timer) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: ERROR: EXPIRY TIMER VALUE NOT SET", __func__, pthread_self(), SessionOffInstanceHolder(pair_ptr->instance_sesn_ptr), SESSION_ID(SessionOffInstanceHolder(pair_ptr->instance_sesn_ptr)));
		_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_EXPIRY)
	}

	Fence *f_ptr = FenceOffInstanceHolder(pair_ptr->instance_f_ptr);
	FENCE_MSG_EXPIRY(f_ptr) = mqm_ptr->fence->fences[0]->expire_timer;

	f_ptr->fence_events.last_event_id = mqm_ptr->fence->header->eid;

	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_EXPIRY)
}

/**
 * 	@locks: sesn_ptr_target
 * 	@unlocks: sesn_ptr_target
 */
static UFSRVResult *
_HandleInterBroadcastFencePermission (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	FenceSessionPair *pair_ptr												=	(FenceSessionPair *)context_ptr;
	FencePermission *permission_ptr										=	NULL;
	FenceRecord__Permission	*fence_record_permission	=	NULL;
	UserRecord							*user_record_ptr					=	NULL;

  Session               *sesn_ptr_ctx     = SessionOffInstanceHolder(pair_ptr->instance_sesn_ptr);
  Fence                 *f_ptr_ctx        = FenceOffInstanceHolder(pair_ptr->instance_f_ptr);

	if ((ValidateFencePermissionCommandFromProto(sesn_ptr_ctx, mqm_ptr->fence, f_ptr_ctx, &permission_ptr, &fence_record_permission)) != 0) {
		_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_PERMISSION)
	}

	UFSRVResult * (*permission_op_callback)(InstanceHolderForSession *, Fence *, FencePermission *, unsigned long, FenceEvent *);
	if (mqm_ptr->fence->header->args == COMMAND_ARGS__ADDED)	permission_op_callback = AddUserToFencePermissions;
	else if (mqm_ptr->fence->header->args == COMMAND_ARGS__DELETED)	permission_op_callback = RemoveUserFromFencePermissions;
	else {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', command_arg:'%d'}: ERROR: INVALID COMMAND ARG", __func__, pthread_self(), sesn_ptr_ctx, SESSION_ID(sesn_ptr_ctx), mqm_ptr->fence->header->args);
		_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_PERMISSION);
	}

	//yes the full catastrophe. We need the use due to association with the inviter
	bool		lock_already_owned = false;
	unsigned long sesn_call_flags_permission	=	(CALL_FLAG_LOCK_SESSION|CALL_FLAG_LOCK_SESSION_BLOCKING|
																							CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY| CALL_FLAG_HASH_USERNAME_LOCALLY|
																							CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION|CALL_FLAG_REMOTE_SESSION);
	GetSessionForThisUserByUserId(sesn_ptr_ctx, UfsrvUidGetSequenceId((const UfsrvUid *)fence_record_permission->users[0]->ufsrvuid.data), &lock_already_owned, sesn_call_flags_permission);
	InstanceHolderForSession *instance_sesn_ptr_target = (InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr_ctx);

	if (IS_PRESENT(instance_sesn_ptr_target)) {
	  Session *sesn_ptr_target = SessionOffInstanceHolder(instance_sesn_ptr_target);

		f_ptr_ctx->fence_events.last_event_id = mqm_ptr->fence->header->eid;

		(*permission_op_callback)(instance_sesn_ptr_target, f_ptr_ctx, permission_ptr, FENCE_CALLFLAG_EMPTY, NULL);
		if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_target, __func__);

		_RETURN_RESULT_RES (res_ptr, NULL, sesn_ptr_target->sservice.result.result_type, sesn_ptr_target->sservice.result.result_code)
	}

	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_PERMISSION)
}

static UFSRVResult *
_HandleInterBroadcastFencePermissionListSemantics (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	//todo: currently this mode is not supported. Can only be set once at fence creation time.
  _RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_PERMISSION);
}

/**
 * 	@brief: This is a server-to-server only command. At the receiving end of this broadcast the
 * 	only applicable action to clear local resident reference for the named fence.
 * 	We'd only land here if this ufsrv instance had the fence loaded in memory
 */
static UFSRVResult *
_HandleInterBroadcastFenceDestruct (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	FenceSessionPair *pair_ptr				=	(FenceSessionPair *)context_ptr;

	//since there is no session owner associated with this event, pair_ptr->session_ptr will be null, and fence won't be passed  here in
	//locked state by _PrepareForInterBroadcastHandling()
	FenceReturnToRecycler (pair_ptr->instance_f_ptr,
												(ContextData *)&((TypePoolContextDataFence){.is_fence_locked=false, .sesn_ptr=SessionOffInstanceHolder(pair_ptr->instance_sesn_ptr), .fence_data.instance_f_ptr=pair_ptr->instance_f_ptr}),
												FENCE_CALLFLAG_LOCK_FENCE);

	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
}

static UFSRVResult *
_HandleInterBroadcastFenceReload (ClientContextData *context_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	FenceSessionPair *pair_ptr				=	(FenceSessionPair *)context_ptr;

	//TODO: implement _HandleInterBroadcastFenceReload
	//since there is no session owner associated with this event, pair_ptr->session_ptr will be null, and fence won't passed to here in
	//locked state by _PrepareForInterBroadcastHandling()
//	FenceReturnToRecycler (pair_ptr->fence_ptr,
//												(ContextData *)&((TypePoolContextDataFence){.sesn_ptr=pair_ptr->session_ptr, .fence_data.f_ptr=pair_ptr->fence_ptr}),
//												FENCE_CALLFLAG_LOCK_FENCE);

	_RETURN_RESULT_RES (res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
}

/**
 * 	@brief: Helper routine to load a session for further INTER processing
 * 	@IMPORTANT: THIS LOADS backend access via ephemeral mode
 *
 * 	The logic is as follows:
 * 	1)Load fence locally:
 * 	1.1) fence local fails: load session locally
 * 	1.0) if geofence load from backend and return
 * 	1.1.1)session local success -> user we  know of joined a fence we don't know of
 * 													 -> backend-load Fence  (we'll retrieve full user list from loading fence in user list anyway, include ing this session)
 * 													 -> link up and update locally consistent with INTER semantics (may not be necessary as backend load will build the user list incuding this one)
 * 	1.1.2)session local fail -> user we don't know of joined a fence we don't know of -> exit
 *
 * 	1.2) fence local success:
 * 	1.2.0) if geo fence refresh from backend and return geofences dont have owners
 * 	1.2.1) load session locally:
 * 				success:
 * 				 				-> great known user + known fence
 * 								-> link up and update locally consistent with INTER semantics
 * 				fail: a user we dont know of JOINED a fence we know of
 * 								-> backend-load user sessionwith full list
 * 								-> link up and update locally consistent with INTER semantics (linkup may not be necessary because backend load will do that anyway)
 *
 *	@locks Session *, except when fence is geo type
 *	@locks Fence *
 */
static inline UFSRVResult *
_PrepareForInterBroadcastHandling (MessageQueueMessage *mqm_ptr, FenceSessionPair *fence_sesn_pair_ptr, bool *fence_lock_state, UFSRVResult *res_ptr, int command)
{
	Fence				*f_ptr;
	FenceRecord *fence_record_ptr	=	mqm_ptr->fence->fences[0];

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

		//shortcut for geofence make event, as they dont have user session associated with that event
		if (mqm_ptr->fence->fences[0]->owner_uid.len == CONFIG_MAX_UFSRV_ID_SZ && ((UfsrvUidGetSequenceId((const UfsrvUid *)mqm_ptr->fence->fences[0]->owner_uid.data) == 0) && (mqm_ptr->fence->fences[0]->has_owner_uid == 1)) &&
				(mqm_ptr->fence->header->command == FENCE_COMMAND__COMMAND_TYPES__MAKE))	goto return_existing_geofence;

		//>>>>> Fence locked

		if (mqm_ptr->fence->header->cid == 0)	goto return_unlock_fence;//no session associated with event

		Session                   *sesn_ptr_localuser;
		InstanceHolderForSession  *instance_sesn_ptr_localuser;

		if (IS_PRESENT((instance_sesn_ptr_localuser = LocallyLocateSessionById(mqm_ptr->fence->header->cid)))) {
		    sesn_ptr_localuser = SessionOffInstanceHolder(instance_sesn_ptr_localuser);
				SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_localuser, _LOCK_TRY_FLAG_FALSE, __func__);
				if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR)) {
          goto return_locked_session_error;
				}

				bool lock_already_owned = (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_BY_THIS_THREAD));

        SESSION_WHEN_SERVICE_STARTED(sesn_ptr_localuser) = time(NULL);
				SessionLoadEphemeralMode(sesn_ptr_localuser);
				fence_sesn_pair_ptr->instance_f_ptr = instance_f_ptr;
				fence_sesn_pair_ptr->instance_sesn_ptr = instance_sesn_ptr_localuser;
				fence_sesn_pair_ptr->lock_already_owned = lock_already_owned;
				fence_sesn_pair_ptr->fence_lock_already_owned = fence_lock_already_owned;
				fence_sesn_pair_ptr->flag_fence_local = fence_sesn_pair_ptr->flag_session_local = true;
				//both session/fence locked

				*fence_lock_state = fence_lock_already_owned;
				_RETURN_RESULT_RES(res_ptr, fence_sesn_pair_ptr, RESULT_TYPE_SUCCESS, RESCODE_USER_SESN_LOCAL)
    } else {
#define SESSION_CALL_FLAGS (CALL_FLAG_LOCK_SESSION|CALL_FLAG_HASH_SESSION_LOCALLY|					\
                          CALL_FLAG_HASH_UID_LOCALLY|CALL_FLAG_HASH_USERNAME_LOCALLY|			\
                          CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION|CALL_FLAG_REMOTE_SESSION)

      //given NULL session, load backend context from ufsrvworker's
      unsigned  long uid = UfsrvUidGetSequenceId((const UfsrvUid *) mqm_ptr->fence->header->ufsrvuid.data);
      if (IS_PRESENT((instance_sesn_ptr_localuser = SessionInstantiateFromBackend (NULL, uid, SESSION_CALL_FLAGS)))) {
        sesn_ptr_localuser = SessionOffInstanceHolder(instance_sesn_ptr_localuser);
        SESSION_WHEN_SERVICE_STARTED(sesn_ptr_localuser) = time(NULL);
        SessionLoadEphemeralMode(sesn_ptr_localuser);
        fence_sesn_pair_ptr->instance_f_ptr = instance_f_ptr;
        fence_sesn_pair_ptr->instance_sesn_ptr = instance_sesn_ptr_localuser;
        fence_sesn_pair_ptr->flag_fence_local = true;
        fence_sesn_pair_ptr->flag_session_local = false;
        fence_sesn_pair_ptr->fence_lock_already_owned = fence_lock_already_owned; //no need to set session lock state since it is backend instantiated and no prior lock could've existed
        //both session/fence locked

        *fence_lock_state = fence_lock_already_owned;
        _RETURN_RESULT_RES(res_ptr, fence_sesn_pair_ptr, RESULT_TYPE_SUCCESS, RESCODE_USER_SESN_LOCAL)
      }
      else goto return_unlock_fence;
    }
	} else { //1)fence not found locally 2)no locks instated so far
    //shortcut for geofence make event, as they dont have user session associated with that event
		if (mqm_ptr->fence->fences[0]->owner_uid.len == CONFIG_MAX_UFSRV_ID_SZ && ((UfsrvUidGetSequenceId((const UfsrvUid *)mqm_ptr->fence->fences[0]->owner_uid.data) == 0) && (mqm_ptr->fence->fences[0]->has_owner_uid == 1)) &&
				(mqm_ptr->fence->header->command == FENCE_COMMAND__COMMAND_TYPES__MAKE)) {
#define GEOFENCE_CALLFLAGS (FENCE_CALLFLAG_HASH_FENCE_LOCALLY|FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE|FENCE_CALLFLAG_KEEP_FENCE_LOCKED|FENCE_CALLFLAG_LOCK_FENCE_BLOCKING)
			Session *sesn_ptr_carrier = NULL;

			InstanceHolderForSession *instance_sesn_ptr_carrier = InstantiateCarrierSession (NULL, WORKERTYPE_UFSRVWORKER, SESSION_CALLFLAGS_EMPTY);
      sesn_ptr_carrier = SessionOffInstanceHolder(instance_sesn_ptr_carrier);

			GetCacheRecordForFence(sesn_ptr_carrier, UNSPECIFIED_FENCE_LISTTYPE, fence_record_ptr->fid, UNSPECIFIED_UID, &fence_lock_already_owned, GEOFENCE_CALLFLAGS);
      instance_f_ptr = (InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr_carrier);

			SessionReturnToRecycler (instance_sesn_ptr_carrier, (ContextData *)NULL, CALL_FLAG_CARRIER_INSTANCE);

			if (IS_PRESENT(instance_f_ptr))	{
			  f_ptr = FenceOffInstanceHolder(instance_f_ptr);
			  goto return_existing_backend_geofence;
			}
			else  goto return_geofence_not_found; //this a major error as fence should have existed in the backend for an INTER handling context
		}

    if (mqm_ptr->fence->header->cid == 0)	goto exit_error; //no session associated with event

    Session                   *sesn_ptr_localuser;
    InstanceHolderForSession  *instance_sesn_ptr_localuser;

    if (IS_PRESENT((instance_sesn_ptr_localuser = LocallyLocateSessionById(mqm_ptr->fence->header->cid)))) {
      sesn_ptr_localuser = SessionOffInstanceHolder(instance_sesn_ptr_localuser);

      SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_localuser, _LOCK_TRY_FLAG_FALSE, __func__);
      if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR)) goto return_unlock_fence;
      bool lock_already_owned = (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_BY_THIS_THREAD));

      InstanceHolderForSession *instance_sesn_ptr_carrier = InstantiateCarrierSession(NULL, WORKERTYPE_UFSRVWORKER, SESSION_CALLFLAGS_EMPTY);
      Session *sesn_ptr_carrier = SessionOffInstanceHolder(instance_sesn_ptr_carrier);

      GetCacheRecordForFence(sesn_ptr_carrier, 0, fence_record_ptr->fid, UNSPECIFIED_UID, &fence_lock_already_owned, GEOFENCE_CALLFLAGS);
      instance_f_ptr = (InstanceHolderForFence *) SESSION_RESULT_USERDATA(sesn_ptr_carrier);

      SessionReturnToRecycler(instance_sesn_ptr_carrier, (ContextData *) NULL, CALL_FLAG_CARRIER_INSTANCE);

      //x
      if (IS_PRESENT(instance_f_ptr)) {
        //>> FENCE LOCKED >>>>>

//      Session                   *sesn_ptr_localuser;
//      InstanceHolderForSession  *instance_sesn_ptr_localuser;
//
//			//plausible to assume session is now loaded locally if it did not previously exist
//			if (IS_PRESENT((instance_sesn_ptr_localuser = LocallyLocateSessionById(mqm_ptr->fence->header->cid)))) {
//			  sesn_ptr_localuser = SessionOffInstanceHolder(instance_sesn_ptr_localuser);
//
//				SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_localuser, _LOCK_TRY_FLAG_FALSE, __func__);
//				if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR)) goto return_unlock_fence;
//				bool lock_already_owned = (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_BY_THIS_THREAD));

        //>> SESSION/FENCE LOCKED >>>
        SESSION_WHEN_SERVICE_STARTED(sesn_ptr_localuser) = time(NULL);
        fence_sesn_pair_ptr->instance_f_ptr = instance_f_ptr;
        fence_sesn_pair_ptr->instance_sesn_ptr = instance_sesn_ptr_localuser;
        fence_sesn_pair_ptr->flag_fence_local = false;
        fence_sesn_pair_ptr->flag_session_local = true;
        fence_sesn_pair_ptr->lock_already_owned = lock_already_owned;
        fence_sesn_pair_ptr->fence_lock_already_owned = fence_lock_already_owned;
        *fence_lock_state = fence_lock_already_owned;//TODO: remove: not necessary anumore
        _RETURN_RESULT_RES(res_ptr, fence_sesn_pair_ptr, RESULT_TYPE_SUCCESS, RESCODE_USER_SESN_LOCAL)
//			} else {
//				//potentially a major stuff up
//				syslog(LOG_ERR, "%s {pid:'%lu', eid:'%lu', cid:'%lu', fid:'%lu'}: ERROR: COULD NOT LOCATE LOCAL SESSION FOLLOWING FENCE LOAD", __func__, pthread_self(), mqm_ptr->fence->header->eid, mqm_ptr->fence->header->cid, fence_record_ptr->fid);
//				goto return_unlock_fence;
//			}
      } else {
        syslog(LOG_ERR, "%s {pid:'%lu', eid:'%lu', cid:'%lu', fid:'%lu'}: ERROR: COULD NOT LOCATE FENCE...", __func__, pthread_self(), mqm_ptr->fence->header->eid, mqm_ptr->fence->header->cid, fence_record_ptr->fid);
        if (!lock_already_owned)  SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_localuser, __func__);
        goto exit_error;
      }
      //x
    } else {
      syslog(LOG_ERR, "%s {pid:'%lu', eid:'%lu', cid:'%lu', fid:'%lu'}: ERROR: COULD NOT LOCATE LOCAL SESSION", __func__, pthread_self(), mqm_ptr->fence->header->eid, mqm_ptr->fence->header->cid, fence_record_ptr->fid);
      goto exit_error;
    }
	}

	//fence locked
	return_existing_geofence:
	syslog (LOG_NOTICE, "%s {pid:'%lu', fid:'%lu'}: NOTICE: MAKE COMMAND FOR AN EXITING FENCE (REFRESH FROM BACKEND NOT IMPLEMENTED)", __func__, pthread_self(), FENCE_ID(f_ptr));
	fence_sesn_pair_ptr->instance_f_ptr = instance_f_ptr;
	fence_sesn_pair_ptr->instance_sesn_ptr = NULL;
	fence_sesn_pair_ptr->flag_fence_local = true; fence_sesn_pair_ptr->flag_session_local = false;
	fence_sesn_pair_ptr->fence_type = F_ATTR_BASEFENCE;
	fence_sesn_pair_ptr->fence_lock_already_owned = fence_lock_already_owned;
	*fence_lock_state = fence_lock_already_owned;
	_RETURN_RESULT_RES(res_ptr, fence_sesn_pair_ptr, RESULT_TYPE_SUCCESS, RESCODE_USER_SESN_LOCAL)

	//fence locked. ownership state transferred
	return_existing_backend_geofence:
	fence_sesn_pair_ptr->instance_f_ptr = instance_f_ptr;
	fence_sesn_pair_ptr->instance_sesn_ptr = NULL;
	fence_sesn_pair_ptr->flag_fence_local = false;
	fence_sesn_pair_ptr->flag_session_local = false;
	fence_sesn_pair_ptr->fence_type = F_ATTR_BASEFENCE;
	fence_sesn_pair_ptr->fence_lock_already_owned = fence_lock_already_owned;
	*fence_lock_state = fence_lock_already_owned;
	_RETURN_RESULT_RES(res_ptr, fence_sesn_pair_ptr, RESULT_TYPE_SUCCESS, RESCODE_USER_SESN_LOCAL)

	return_geofence_not_found:
#ifdef __UF_TESTING
	syslog (LOG_NOTICE, "%s {pid:'%lu', fid:'%lu'}: Could not find newly created geofence locally: instantiating one...", __func__, pthread_self(), fence_record_ptr->fid);
#endif
	fence_sesn_pair_ptr->instance_f_ptr = NULL;
	fence_sesn_pair_ptr->instance_sesn_ptr = NULL;
	fence_sesn_pair_ptr->flag_fence_local = fence_sesn_pair_ptr->flag_session_local = false;
	fence_sesn_pair_ptr->fence_type = F_ATTR_BASEFENCE;
	fence_sesn_pair_ptr->fence_lock_already_owned = fence_lock_already_owned;
	*fence_lock_state = fence_lock_already_owned;
	_RETURN_RESULT_RES(res_ptr, fence_sesn_pair_ptr, RESULT_TYPE_ERR, RESCODE_USER_SESN_LOCAL)

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
#undef	GEOFENCE_CALLFLAGS
}

///// END INTER	\\\\

/////// INTRA	\\\\\

int
HandleIntraBroadcastForFence (MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	int 								rc				=	0;

	long long timer_start = GetTimeNowInMicros(),
						timer_end;

  if (unlikely(mqm_ptr->has_ufsrvuid == 0)) goto return_error_undefined_ufsrvuid;

	if ((rc = VerifyFenceCommandFromUser(_WIRE_PROTOCOL_DATA(mqm_ptr->wire_data->ufsrvcommand->fencecommand))) < 0)	goto return_final;

  unsigned long userid = UfsrvUidGetSequenceId((const UfsrvUid *)(mqm_ptr->ufsrvuid.data));

	InstanceHolderForSession	*instance_sesn_ptr_carrier = InstantiateCarrierSession (NULL, WORKERTYPE_UFSRVWORKER, SESSION_CALLFLAGS_EMPTY);
	if (IS_EMPTY(instance_sesn_ptr_carrier))	{
	  rc = -4;
	  goto return_final;
	}

  Session				*sesn_ptr_carrier			= SessionOffInstanceHolder(instance_sesn_ptr_carrier);

  unsigned long sesn_call_flags				=	(	CALL_FLAG_LOCK_SESSION|CALL_FLAG_LOCK_SESSION_BLOCKING|
																					CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY| CALL_FLAG_HASH_USERNAME_LOCALLY|
																					CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION|CALL_FLAG_REMOTE_SESSION);
	bool lock_already_owned = false;
	GetSessionForThisUserByUserId (sesn_ptr_carrier, userid, &lock_already_owned, sesn_call_flags);
	InstanceHolderForSession	*instance_sesn_ptr_local_user = (InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr_carrier);

	if (unlikely(IS_EMPTY(instance_sesn_ptr_local_user)))	goto return_error_unknown_uname;

	//>>> sesn_ptr_local_user IS NOW LOCKED

	Session *sesn_ptr_local_user = SessionOffInstanceHolder(instance_sesn_ptr_local_user);

#ifdef __UF_TESTING
	FenceCommand 				*fcmd_ptr	= mqm_ptr->wire_data->ufsrvcommand->fencecommand;
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fid:'%lu', fname:'%s', fcname:'%s', userid:'%lu'}: FULLY CONSTRUCTED FENCE COMMAND.", __func__, pthread_self(),sesn_ptr_local_user, SESSION_ID(sesn_ptr_local_user), fcmd_ptr->fences[0]->fid, IS_STR_LOADED(fcmd_ptr->fences[0]->fname)?fcmd_ptr->fences[0]->fname:"*", IS_STR_LOADED(fcmd_ptr->fences[0]->cname)?fcmd_ptr->fences[0]->cname:"*", userid);
#endif

	{
    SESSION_WHEN_SERVICE_STARTED(sesn_ptr_local_user) = time(NULL);
		SessionLoadEphemeralMode(sesn_ptr_local_user);
		//>>>>>>>>><<<<<<<<<<
		CommandCallbackControllerFenceCommand (instance_sesn_ptr_local_user, &(WebSocketMessage){.type=WEB_SOCKET_MESSAGE__TYPE__REQUEST, .request=NULL}, mqm_ptr->wire_data);
		//>>>>>>>>><<<<<<<<<<

    SESSION_WHEN_SERVICED(sesn_ptr_local_user) = time(NULL);
		SessionUnLoadEphemeralMode(sesn_ptr_local_user);
		if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_local_user, __func__);
	}

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
	statsd_timing(pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_instrumentation_backend_key), "delegator.ufsrv.job.command.fence.elapsed_time", (timer_end-timer_start));
	return rc;

}

/**
 * 	@brief: Verify the fitness of the FenceCommand message in the context of on INTRA broadcast
 */
int
VerifyFenceCommandFromUser	(WireProtocolData *data_ptr)
{
	int rc = 1;
	FenceCommand *cmd_ptr = (FenceCommand *)data_ptr;

	if (unlikely(IS_EMPTY((cmd_ptr))))				goto return_error_fencecommand_missing;
	if (unlikely(IS_EMPTY(cmd_ptr->header)))	goto return_error_commandheader_missing;
	if (unlikely(cmd_ptr->n_fences < 1))				goto return_error_missing_fence_definition;
//	if (unlikely(mqm_ptr->has_ufsrvuid == 0))																					goto return_error_missing_ufrsvuid;

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

	return_error_missing_ufrsvuid:
	syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: UFSRVUID MISSING FROM MESSAGE", __func__, pthread_self());
	rc=-5;
	goto return_free;

	return_error_missing_fence_definition:
	syslog(LOG_DEBUG, "%s (pid:'%lu): ERROR: FENCE COMMAND DID NOT INCLUDE VALID FENCE DEFINITION", __func__, pthread_self());
	rc=-6;
	goto	return_free;

	return_free:
	return_final:
	return rc;

}

///////////////////
