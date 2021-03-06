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
#include <ufsrv_core/fence/fence_state.h>
#include <ufsrv_core/fence/fence_utils.h>
#include <fence_proto.h>
#include <ufsrv_core/user/user_backend.h>
#include <ufsrv_core/user/users_protobuf.h>
#include <ufsrvwebsock/include/protocol_websocket.h>
#include <ufsrvcmd_user_callbacks.h>
#include <ufsrvcmd_callbacks.h>
#include <ufsrv_core/msgqueue_backend/ufsrvcmd_broadcast.h>
#include <ufsrv_core/SignalService.pb-c.h>
#include <ufsrv_core/location/location.h>
#include <command_controllers.h>
#include <share_list.h>
#include <ufsrvuid.h>

extern ufsrv							*const masterptr;
extern __thread ThreadContext ufsrv_thread_context;

/**
 * 	@brief: ReceiptCommand is generated by the sender(sesn_ptr_originator) to acknowledge a prior event by another user
 * 	in the same fence (sesn_ptr_target)
 */
typedef struct ReceiptContext {
	InstanceHolderForFenceStateDescriptor *instance_fstate_ptr_target;
	InstanceHolderForSession 							*instance_sesn_ptr_originator, //user for whom receipt is sent (original sender) matches uid_originator in protobuf
												                *instance_sesn_ptr_sender;
	FenceEvent						*fence_event_ptr;
	unsigned long					**eids;//user can send many receipts for the same fence for the same target
}	ReceiptContext;

inline static UFSRVResult *_CommandControllerReceiptRead (InstanceContextForSession *, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
inline static UFSRVResult *_CommandControllerReceiptDelivery (InstanceContextForSession *, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);

inline static UFSRVResult *_MarshalReceiptForRead(InstanceHolderForSession *, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr_received, ReceiptContext *context_ptr);
static inline UFSRVResult *_MarshalReceiptForDelivery(InstanceHolderForSession *, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr_received, ReceiptContext *context_ptr);

static UFSRVResult *_HandleReceiptCommandError (InstanceHolderForSession *, FenceStateDescriptor *fence_state_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr_originator, int rescode, int command_type);
static void	_BuildErrorHeaderForReceiptCommand (CommandHeader *header_ptr, CommandHeader *header_ptr_originator, int errcode, int command_type);


UFSRVResult *IsUserAllowedToGenerateReceipt(InstanceHolderForSession *instance_sesn_ptr, unsigned long fid, unsigned long uid_origintor, ReceiptContext *, bool *fence_lock_state, unsigned long fence_call_flags);
UFSRVResult *IsUserAllowedToGenerateDeliveryReceipt (InstanceHolderForSession *instance_sesn_ptr_sender, unsigned long uid_origintor, ReceiptContext *context_ptr);

struct MarshalMessageEnvelopeForReceipt {
	UfsrvCommandWire		*ufsrv_command_wire;
	Envelope						*envelope;
	ReceiptCommand 			*receipt_command;
	CommandHeader 			*header;
	FenceRecord					*fence_record;
	UserRecord					*user_record_originator;
};
typedef struct MarshalMessageEnvelopeForReceipt MarshalMessageEnvelopeForReceipt;

#define _GENERATE_RECEIPT_COMMAND_ENVELOPE_INITIALISATION() \
	UfsrvCommandWire								ufsrv_command_wire	= UFSRV_COMMAND_WIRE__INIT;	\
	Envelope												command_envelope		=	ENVELOPE__INIT;	\
	ReceiptCommand 									receipt_command			=	RECEIPT_COMMAND__INIT;	\
	CommandHeader 									header							=	COMMAND_HEADER__INIT;	\
	\
	FenceRecord											fence_record;	\
	UserRecord											user_record_originator;	\
	\
	MarshalMessageEnvelopeForReceipt	envelope_marshal = {	\
			.ufsrv_command_wire	=	&ufsrv_command_wire,	\
			.envelope						=	&command_envelope,	\
			.receipt_command		=	&receipt_command,	\
			.header							=	&header,	\
			.fence_record				=	&fence_record,	\
			.user_record_originator	=	&user_record_originator	\
	}

#define _GENERATE_DELIVERY_RECEIPT_COMMAND_ENVELOPE_INITIALISATION() \
	UfsrvCommandWire								ufsrv_command_wire	= UFSRV_COMMAND_WIRE__INIT;	\
	Envelope												command_envelope		=	ENVELOPE__INIT;	\
	ReceiptCommand 									receipt_command			=	RECEIPT_COMMAND__INIT;	\
	CommandHeader 									header							=	COMMAND_HEADER__INIT;	\
	\
	UserRecord											user_record_originator;	\
	\
	MarshalMessageEnvelopeForReceipt	envelope_marshal = {	\
			.ufsrv_command_wire	=	&ufsrv_command_wire,	\
			.envelope						=	&command_envelope,	\
			.receipt_command		=	&receipt_command,	\
			.header							=	&header,	\
			.fence_record				=	NULL,	\
			.user_record_originator	=	&user_record_originator	\
	}

inline static void _PrepareMarshalMessageForReceipt (MarshalMessageEnvelopeForReceipt *envelope_ptr, Session *sesn_ptr, Fence *f_ptr, FenceEvent *event_ptr, DataMessage *data_msg_ptr_orig, enum _ReceiptCommand__CommandTypes, enum _CommandArgs command_arg);

inline static void
_PrepareMarshalMessageForReceipt (MarshalMessageEnvelopeForReceipt *envelope_ptr, Session *sesn_ptr, Fence *f_ptr, FenceEvent *event_ptr, DataMessage *data_msg_ptr_orig, enum _ReceiptCommand__CommandTypes command_type, enum _CommandArgs command_arg)
{
	envelope_ptr->envelope->ufsrvcommand								=	envelope_ptr->ufsrv_command_wire;

	envelope_ptr->envelope->ufsrvcommand->receiptcommand		=	envelope_ptr->receipt_command;
	envelope_ptr->envelope->ufsrvcommand->ufsrvtype			=	UFSRV_COMMAND_WIRE__UFSRV_TYPE__UFSRV_RECEIPT;
	envelope_ptr->envelope->ufsrvcommand->header				=	envelope_ptr->header;

	envelope_ptr->receipt_command->header									=	envelope_ptr->header;
	if (IS_PRESENT(f_ptr)) {
    envelope_ptr->receipt_command->fid      = envelope_ptr->fence_record->fid;
    envelope_ptr->receipt_command->has_fid  = 1;
    MakeFenceRecordInProtoAsIdentifier(sesn_ptr, f_ptr, envelope_ptr->fence_record);
  }

	envelope_ptr->envelope->sourceufsrvuid							=	"0";
	envelope_ptr->envelope->timestamp										=	GetTimeNowInMillis(); envelope_ptr->envelope->has_timestamp = 1;

	envelope_ptr->header->when													=	envelope_ptr->envelope->timestamp; 	envelope_ptr->header->has_when = 1;
	envelope_ptr->header->cid														=	SESSION_ID(sesn_ptr); 							envelope_ptr->header->has_cid = 1;
	envelope_ptr->header->command												=	command_type;
	envelope_ptr->header->args													=	command_arg;												envelope_ptr->header->has_args = 1;

	if (IS_PRESENT(event_ptr)) {
		envelope_ptr->header->when_eid										=	event_ptr->when; 					envelope_ptr->header->has_when_eid = 1;
		envelope_ptr->header->eid													=	event_ptr->eid; 					envelope_ptr->header->has_eid = 1;
	} else if IS_PRESENT(f_ptr) {
		envelope_ptr->header->eid													=	FENCE_LAST_EID(f_ptr); 					envelope_ptr->header->has_eid = 1;
	}

	if (IS_PRESENT(data_msg_ptr_orig)) {
		envelope_ptr->header->when_client								=	data_msg_ptr_orig->ufsrvcommand->receiptcommand->header->when;
		envelope_ptr->header->has_when_client						=	data_msg_ptr_orig->ufsrvcommand->receiptcommand->header->has_when_client = 1;
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
CommandCallbackControllerReceiptCommand (InstanceContextForSession *ctx_ptr_local_user, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr)
{
	CommandHeader *command_header = data_msg_ptr->ufsrvcommand->receiptcommand->header;

	if (unlikely(!IsProtoUfsrvUidDefined(&(data_msg_ptr->ufsrvcommand->receiptcommand->uid_originator)))) goto exit_ufsrvuid_error;

	switch (command_header->command)
	{
    case RECEIPT_COMMAND__COMMAND_TYPES__READ:
      _CommandControllerReceiptRead(ctx_ptr_local_user, NULL, data_msg_ptr);
      break;

    case RECEIPT_COMMAND__COMMAND_TYPES__DELIVERY:
      _CommandControllerReceiptDelivery(ctx_ptr_local_user, NULL, data_msg_ptr);
      break;

    default:
      syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', command:'%d'}: RECEIVED UNKNOWN RECEIPT COMMAND", __func__, pthread_self(), ctx_ptr_local_user->sesn_ptr, command_header->command);
	}

	exit_release:
	return SESSION_RESULT_PTR(ctx_ptr_local_user->sesn_ptr);

  exit_ufsrvuid_error:
  syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', command:'%d'): ERROR: UFSRVUID WAS NOT DEFINED ", __func__, pthread_self(), ctx_ptr_local_user->sesn_ptr, SESSION_ID(ctx_ptr_local_user->sesn_ptr), command_header->command);
  _RETURN_RESULT_SESN(ctx_ptr_local_user->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
}

/**
 * 	@brief: This function is designed to work with ephemeral sessions, not io sessions through the main loop.
 *
 *	@param sesn_ptr:	Target session loaded in ephemeral mode
 * 	@locked RW sesn_ptr: must be locked by the caller
 * 	@locks RW f_ptr: issues flags to cause locking
 * 	@unlocks f_ptr:
 */
inline static UFSRVResult *
_CommandControllerReceiptRead (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr)
{
	bool								fence_already_locked = false;
	ReceiptCommand			*recptcmd_ptr;
	FenceRecord 				*fence_record_ptr	= NULL;
	UserRecord					*user_record_to		=	NULL;
	ReceiptContext			receipt_context		=	{0};

	recptcmd_ptr = data_msg_ptr->ufsrvcommand->receiptcommand;

	if (recptcmd_ptr->fid > 0 && UfsrvUidGetSequenceId((const UfsrvUid *)recptcmd_ptr->uid_originator.data) > 0) {
		IsUserAllowedToGenerateReceipt(ctx_ptr->instance_sesn_ptr, recptcmd_ptr->fid, UfsrvUidGetSequenceId((const UfsrvUid *)recptcmd_ptr->uid_originator.data), &receipt_context, &fence_already_locked, FENCE_CALLFLAG_KEEP_FENCE_LOCKED);

		if (SESSION_RESULT_TYPE_ERROR(ctx_ptr->sesn_ptr)) {
			_HandleReceiptCommandError (ctx_ptr->instance_sesn_ptr, NULL, wsm_ptr_orig, data_msg_ptr, SESSION_RESULT_CODE(ctx_ptr->sesn_ptr), data_msg_ptr->ufsrvcommand->receiptcommand->header->command);

			_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
		}

    _MarshalReceiptForRead(ctx_ptr->instance_sesn_ptr, wsm_ptr_orig, data_msg_ptr, &receipt_context);
		if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(FenceStateDescriptorOffInstanceHolder(receipt_context.instance_fstate_ptr_target)), THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));

		return SESSION_RESULT_PTR(ctx_ptr->sesn_ptr);
	}

	_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
}

/**
 * 	@brief: .
 *
 * 	@param data_msg_ptr: is the original wire message sent by the client. We'll have to copy bits and pieces from  it for this transmission
 *  @locked f_ptr (as contained in FenceStateDescriptor in CallContext):
 *  @locked sesn_ptr (context_ptr->sesn_ptr->caller):
 *  @locked context_ptr->sesn_ptr->called
 *	@unlocks: none
 *  @dynamic_memory fence_records_ptr: array of FenceRecord initiated with dynamic values. Must be freed with DestructFenceRecordProto (FenceRecord **fence_records_ptr, unsigned count)
 */
inline static UFSRVResult *
_MarshalReceiptForRead(InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr_received, ReceiptContext *context_ptr)
{
	Fence *f_ptr=	FENCESTATE_FENCE(FenceStateDescriptorOffInstanceHolder(context_ptr->instance_fstate_ptr_target));

	_GENERATE_RECEIPT_COMMAND_ENVELOPE_INITIALISATION();

	Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	_PrepareMarshalMessageForReceipt (&envelope_marshal, SessionOffInstanceHolder(context_ptr->instance_sesn_ptr_originator), f_ptr, context_ptr->fence_event_ptr, NULL, RECEIPT_COMMAND__COMMAND_TYPES__READ, COMMAND_ARGS__SYNCED);
	receipt_command.type						=	data_msg_ptr_received->ufsrvcommand->receiptcommand->type; data_msg_ptr_received->ufsrvcommand->receiptcommand->has_type=1;
	receipt_command.eid							=	data_msg_ptr_received->ufsrvcommand->receiptcommand->eid;
	receipt_command.n_eid						=	data_msg_ptr_received->ufsrvcommand->receiptcommand->n_eid;
	receipt_command.fid							=	data_msg_ptr_received->ufsrvcommand->receiptcommand->fid; receipt_command.has_fid = data_msg_ptr_received->ufsrvcommand->receiptcommand->has_fid;
  MakeUfsrvUidInProto(&SESSION_UFSRVUIDSTORE(sesn_ptr), &(receipt_command.uid_originator), true);//don't reference data_msg_ptr_received->ufsrvcommand->receiptcommand->uid_originator;
	receipt_command.has_uid_originator = 1;
	receipt_command.timestamp				=	data_msg_ptr_received->ufsrvcommand->receiptcommand->timestamp;
	receipt_command.n_timestamp			=	data_msg_ptr_received->ufsrvcommand->receiptcommand->n_timestamp;

	size_t legacymessage_encoded_sz = data_message__get_packed_size(data_msg_ptr_received);
	uint8_t legacymessage_encoded[legacymessage_encoded_sz];
	data_message__pack(data_msg_ptr_received, legacymessage_encoded);
	command_envelope.legacymessage.data = legacymessage_encoded;
	command_envelope.legacymessage.len = legacymessage_encoded_sz;
	command_envelope.has_legacymessage = 1;

	command_envelope.sourcedevice = DEFAULT_DEVICE_ID; command_envelope.has_sourcedevice = 1;

	UfsrvCommandMarshallingDescriptor ufsrv_descpription={header.eid, FENCE_ID(f_ptr), header.when, &EnvelopeMetaData, &command_envelope};
  UfsrvCommandInvokeUserCommand(
          &(InstanceContextForSession) {instance_sesn_ptr, sesn_ptr},
          &(InstanceContextForSession) {context_ptr->instance_sesn_ptr_originator,
                                        SessionOffInstanceHolder(context_ptr->instance_sesn_ptr_originator)},
          wsm_ptr_orig, NULL, &ufsrv_descpription, uSETACCOUNT_ATTRS_V1_IDX);//todo: update command name

	DestructFenceRecordProto (&fence_record, false);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

inline static UFSRVResult *
_CommandControllerReceiptDelivery (InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr)
{
	ReceiptCommand			*recptcmd_ptr;
	ReceiptContext			receipt_context		=	{0};

	recptcmd_ptr  = data_msg_ptr->ufsrvcommand->receiptcommand;

	if  (UfsrvUidGetSequenceId((const UfsrvUid *)recptcmd_ptr->uid_originator.data) > 0) {
		IsUserAllowedToGenerateDeliveryReceipt(ctx_ptr->instance_sesn_ptr, UfsrvUidGetSequenceId((const UfsrvUid *)recptcmd_ptr->uid_originator.data), &receipt_context);
    if (SESSION_RESULT_TYPE_SUCCESS(ctx_ptr->sesn_ptr)) {
      _MarshalReceiptForDelivery(ctx_ptr->instance_sesn_ptr, wsm_ptr_orig, data_msg_ptr, &receipt_context);

      return SESSION_RESULT_PTR(ctx_ptr->sesn_ptr);
    }
	}

	_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
}

/**
 * 	@brief: Marshaled for delivery receipt to the user who originally sent the message (uid_originator). This user will be referenced in the receipt message generated
 * 	by the user who received the message and confirmed it its delivery by generating delivery receipt, refercing the original sender.
 * 	The server will on-send this receipt to the original sender, referencing this user as the originator, so the client can keep track of of who'd confirmed delivery of message.
 *
 * 	@param data_msg_ptr: is the original wire message sent by the client. We'll have to copy bits and pieces from  it for this transmission
 *  @locked f_ptr (as contained in FenceStateDescriptor in CallContext):
 *  @locked sesn_ptr (context_ptr->sesn_ptr->caller):
 *  @locked context_ptr->sesn_ptr->called
 *	@unlocks: none
 *  @dynamic_memory fence_records_ptr: array of FenceRecord initiated with dynamic values. Must be freed with DestructFenceRecordProto (FenceRecord **fence_records_ptr, unsigned count)
 */
inline static UFSRVResult *
_MarshalReceiptForDelivery (InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr_received, ReceiptContext *context_ptr)
{
  _GENERATE_DELIVERY_RECEIPT_COMMAND_ENVELOPE_INITIALISATION();
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

  _PrepareMarshalMessageForReceipt(&envelope_marshal, SessionOffInstanceHolder(context_ptr->instance_sesn_ptr_originator), NULL, context_ptr->fence_event_ptr, NULL, RECEIPT_COMMAND__COMMAND_TYPES__DELIVERY, COMMAND_ARGS__SYNCED);
  receipt_command.eid							   =	data_msg_ptr_received->ufsrvcommand->receiptcommand->eid;
  receipt_command.n_eid						   =	data_msg_ptr_received->ufsrvcommand->receiptcommand->n_eid;
  receipt_command.timestamp				   =	data_msg_ptr_received->ufsrvcommand->receiptcommand->timestamp;
  receipt_command.n_timestamp			   =	data_msg_ptr_received->ufsrvcommand->receiptcommand->n_timestamp;
  MakeUfsrvUidInProto(&SESSION_UFSRVUIDSTORE(sesn_ptr), &(receipt_command.uid_originator), true);//don't reference data_msg_ptr_received->ufsrvcommand->receiptcommand->uid_originator;
  receipt_command.has_uid_originator =  1;

  size_t legacymessage_encoded_sz = data_message__get_packed_size(data_msg_ptr_received);
  uint8_t legacymessage_encoded[legacymessage_encoded_sz];
  data_message__pack(data_msg_ptr_received, legacymessage_encoded);
  command_envelope.legacymessage.data = legacymessage_encoded;
  command_envelope.legacymessage.len = legacymessage_encoded_sz;
  command_envelope.has_legacymessage = 1;

  command_envelope.sourcedevice = DEFAULT_DEVICE_ID; command_envelope.has_sourcedevice = 1;

  UfsrvCommandMarshallingDescriptor ufsrv_descpription = {header.eid, 0, header.when, &EnvelopeMetaData, &command_envelope};
  UfsrvCommandInvokeUserCommand(
          &(InstanceContextForSession) {instance_sesn_ptr, sesn_ptr},
          &(InstanceContextForSession) {context_ptr->instance_sesn_ptr_originator,
                                        SessionOffInstanceHolder(context_ptr->instance_sesn_ptr_originator)},
          wsm_ptr_orig, NULL, &ufsrv_descpription, uSETACCOUNT_ATTRS_V1_IDX);//todo: update command name

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

/////////////////////////////////////////////

/**
 * 	@brief: Generalised command sending
 */
inline static UFSRVResult *
_MarshalCommandToUser	(InstanceHolderForSession *instance_sesn_ptr, InstanceHolderForSession *instance_sesn_ptr_target, Fence *f_ptr, WebSocketMessage *wsm_ptr_received, Envelope *command_envelope_ptr, unsigned req_cmd_idx)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
  Session *sesn_ptr_target = IS_PRESENT(instance_sesn_ptr_target)?SessionOffInstanceHolder(instance_sesn_ptr_target):NULL;

	CommandHeader *command_header_ptr	=	command_envelope_ptr->ufsrvcommand->header;

	UfsrvCommandMarshallingDescriptor ufsrv_descpription={command_header_ptr->eid, IS_PRESENT(f_ptr) ? FENCE_ID(f_ptr) : 0, command_header_ptr->when, &EnvelopeMetaData, command_envelope_ptr};

#ifdef __UF_TESTING
	syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', cid_target:'%lu', uname_target:'%s', fid:'%lu'} Marshaling command... ", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr),
				SESSION_ID((sesn_ptr_target?sesn_ptr_target:sesn_ptr)), SESSION_USERNAME((sesn_ptr_target?sesn_ptr_target:sesn_ptr)), IS_PRESENT(f_ptr)?FENCE_ID(f_ptr):0);
#endif

  UfsrvCommandInvokeUserCommand(&(InstanceContextForSession) {instance_sesn_ptr, sesn_ptr},
                                (IS_PRESENT(instance_sesn_ptr_target) ? (&(InstanceContextForSession) {
                                        instance_sesn_ptr_target, sesn_ptr_target}) : NULL),
                                wsm_ptr_received, NULL, &ufsrv_descpription, req_cmd_idx);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

/*
 * @param errcode: should reflect a UFSRVResult.rescode type
 * @param command_type: should reflect a protobif command type, or -1 to re use original
 *
 */
static void
_BuildErrorHeaderForReceiptCommand (CommandHeader *header_ptr, CommandHeader *header_ptr_originator, int errcode, int command_type)
{
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

	  case RESCODE_USER_SHARELIST_PRESENT:
      header_ptr->args_error	=	RECEIPT_COMMAND__ERRORS__NOT_ON_SHARELIST; 			header_ptr->has_args_error	=	1;
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
		case RESCODE_PROG_MISSING_PARAM:
			header_ptr->args_error	=	FENCE_COMMAND__ERRORS__MISSING_PARAMETER; 	header_ptr->has_args_error	=	1;
			header_ptr->args				=	COMMAND_ARGS__REJECTED;											header_ptr->has_args				=	1;
			break;

		default:
			goto exit_error;
	}

	if (command_type>0)		header_ptr->command	=	command_type;
	else									header_ptr->command	=	header_ptr_originator->command;//restore original command
	header_ptr->when_client	=	header_ptr_originator->when;							header_ptr->has_when_client=header_ptr_originator->has_when_client;
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
static UFSRVResult *
_HandleReceiptCommandError (InstanceHolderForSession *instance_sesn_ptr, FenceStateDescriptor *fence_state_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_originator, int rescode, int command_type)
{
	Envelope 					command_envelope	= ENVELOPE__INIT;
	CommandHeader 		header						= COMMAND_HEADER__INIT;
	UfsrvCommandWire	ufsrv_command			= UFSRV_COMMAND_WIRE__INIT;
	ReceiptCommand 		receipt_command		= RECEIPT_COMMAND__INIT;

	Session           *sesn_ptr         = SessionOffInstanceHolder(instance_sesn_ptr);

	command_envelope.ufsrvcommand				=	&ufsrv_command;
	ufsrv_command.header								=	&header;
	receipt_command.header							=	&header;

	ufsrv_command.receiptcommand				=	&receipt_command;
	ufsrv_command.ufsrvtype							=	UFSRV_COMMAND_WIRE__UFSRV_TYPE__UFSRV_RECEIPT;

	if (IS_PRESENT(fence_state_ptr)) {
		receipt_command.fid								=	 FENCE_ID(FENCESTATE_FENCE(fence_state_ptr));
		receipt_command.has_fid           = 1;
	} else {
    receipt_command.fid               = data_msg_ptr_originator->ufsrvcommand->receiptcommand->fid;
    receipt_command.has_fid           = data_msg_ptr_originator->ufsrvcommand->receiptcommand->has_fid;
	}

	command_envelope.sourceufsrvuid			=	"0";
	command_envelope.timestamp					=	GetTimeNowInMillis(); command_envelope.has_timestamp=1;

	header.when													=	command_envelope.timestamp; header.has_when		=	1;
	header.cid													=	SESSION_ID(sesn_ptr);				header.has_cid		=	1;

	_BuildErrorHeaderForReceiptCommand (&header, data_msg_ptr_originator->ufsrvcommand->receiptcommand->header, rescode, command_type);

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', uid:'%lu', cid:'%lu', arg_error:'%d', rescode:'%d'}: Marshaling Error response message...", __func__, pthread_self(), sesn_ptr, SESSION_USERID(sesn_ptr), SESSION_ID(sesn_ptr), header.args_error, rescode);
#endif

	return (_MarshalCommandToUser(instance_sesn_ptr, NULL,  IS_PRESENT(fence_state_ptr)?FENCESTATE_FENCE(fence_state_ptr):NULL, wsm_ptr_received, &command_envelope,  uSETACCOUNT_ATTRS_V1_IDX));

}

/**
 *  For a user(sender) to generate a receipt to another user(originator):
 *  1)sender musn't be on originator's blocked list, 2)originator must be on sender's sharelist for ReadReceipt
 *  Also, since ReadReceipts are bound to fences, both users need to be members of the given fence.
 *	@param sesn_ptr_sender: the user who is generating the Receipt
 * 	@locked sesn_ptr_sender
 * 	@locks f_ptr:
 * 	@locks sesn_ptr_originator: the user who sent the original message for which current receipt is being processed
 * 	@unlocks f_ptr: on error
 * 	@unlocks sesn_ptr_originator: on error or just before exit
 */
UFSRVResult *
IsUserAllowedToGenerateReceipt (InstanceHolderForSession *instance_sesn_ptr_sender, unsigned long fid, unsigned long uid_origintor, ReceiptContext *context_ptr, bool *fence_lock_state, unsigned long fence_call_flags)
{
	Fence			*f_ptr							    = NULL;
	Session 	*sesn_ptr_originator		=	NULL;

  bool		lock_already_owned = false;
  unsigned long sesn_call_flags	=	(CALL_FLAG_LOCK_SESSION|CALL_FLAG_LOCK_SESSION_BLOCKING|
                                     CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY| CALL_FLAG_HASH_USERNAME_LOCALLY|
                                     CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION|CALL_FLAG_REMOTE_SESSION);

  Session *sesn_ptr_sender = SessionOffInstanceHolder(instance_sesn_ptr_sender);

  GetSessionForThisUserByUserId(sesn_ptr_sender, uid_origintor, &lock_already_owned, sesn_call_flags);
  InstanceHolderForSession *instance_sesn_ptr_originator = (InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr_sender);

  if (unlikely(IS_EMPTY(instance_sesn_ptr_originator))) {
    _RETURN_RESULT_SESN(sesn_ptr_sender, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_DOESNT_EXIST)
  }

  //>>> Session for originator locked
  sesn_ptr_originator = SessionOffInstanceHolder(instance_sesn_ptr_originator);

  //todo: check for blocked

  if (!(*GetShareListPresenceChecker(SHARELIST_READ_RECEIPT))(sesn_ptr_sender, sesn_ptr_originator)) {
    if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_originator, __func__);
    _RETURN_RESULT_SESN(sesn_ptr_sender, NULL, RESULT_TYPE_ERR, RESCODE_USER_SHARELIST_PRESENT)
  }

	unsigned long fence_call_flags_final = FENCE_CALLFLAG_SEARCH_BACKEND|FENCE_CALLFLAG_HASH_FENCE_LOCALLY|FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE;

	if (fence_call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED)	fence_call_flags_final |= (FENCE_CALLFLAG_KEEP_FENCE_LOCKED|FENCE_CALLFLAG_LOCK_FENCE_BLOCKING);

	FindFenceById(sesn_ptr_sender, fid, fence_call_flags_final);
	InstanceHolderForFence *instance_f_ptr = (InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr_sender);

	if (IS_EMPTY(instance_f_ptr)) {
		if (SESSION_RESULT_CODE_EQUAL(sesn_ptr_sender, RESCODE_FENCE_DOESNT_EXIST)|| SESSION_RESULT_CODE_EQUAL(sesn_ptr_sender, RESCODE_BACKEND_RESOURCE_NULL)) {
      if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_originator, __func__);

			_RETURN_RESULT_SESN(sesn_ptr_sender, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_DOESNT_EXIST)
		}
		else 	SESSION_RETURN_RESULT(sesn_ptr_sender, NULL, RESULT_TYPE_ERR, SESSION_RESULT_CODE(sesn_ptr_sender))
	}

	bool fence_lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr_sender, RESCODE_PROG_LOCKED_BY_THIS_THREAD));

	f_ptr = FenceOffInstanceHolder(instance_f_ptr);

	//>>> Fence RW LOCKED

	InstanceHolderForFenceStateDescriptor *instance_fstate_ptr_sender;
  __unused InstanceHolderForFenceStateDescriptor *instance_fstate_ptr_originator;

	#define FLAG_FENCE_LOCK_FALSE false

	if (!IS_PRESENT((instance_fstate_ptr_sender = IsUserMemberOfThisFence(&(SESSION_FENCE_LIST(sesn_ptr_sender)), f_ptr, FLAG_FENCE_LOCK_FALSE)))) {
		if (!lock_already_owned)				SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_originator, __func__);
		if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr_sender));

		_RETURN_RESULT_SESN(sesn_ptr_sender, NULL, RESULT_TYPE_ERR, RESCODE_USER_FENCE_ALREADYIN)
	}

	if (!IS_PRESENT((instance_fstate_ptr_originator = IsUserMemberOfThisFence(&(SESSION_FENCE_LIST(sesn_ptr_originator)), f_ptr, FLAG_FENCE_LOCK_FALSE)))) {
		if (!lock_already_owned)				SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_originator, __func__);
		if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr_sender));

		_RETURN_RESULT_SESN(sesn_ptr_sender, NULL, RESULT_TYPE_ERR, RESCODE_USER_FENCE_ALREADYIN)
	}

	//TODO: check sesn_ptr_called prefs whilst session is locked allow/disallow event

  return_success:
  context_ptr->instance_fstate_ptr_target			=	instance_fstate_ptr_sender;
  context_ptr->instance_sesn_ptr_originator		=	instance_sesn_ptr_originator;
  context_ptr->instance_sesn_ptr_sender				=	instance_sesn_ptr_sender;

  if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_originator, __func__);

  *fence_lock_state = fence_lock_already_owned;

  _RETURN_RESULT_SESN(sesn_ptr_sender, context_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_RESOURCE_UPDATED)

}

/**
 *
 * @param instance_sesn_ptr_sender
 * @param uid_origintor this is the id of the sender, who originally sent the message.
 * @param context_ptr
 * @return
 */
UFSRVResult *
IsUserAllowedToGenerateDeliveryReceipt (InstanceHolderForSession *instance_sesn_ptr_sender, unsigned long uid_origintor, ReceiptContext *context_ptr)
{
  unsigned 	rescode;
  Fence			*f_ptr							    = NULL;
  Session 	*sesn_ptr_originator		=	NULL;
  Session   *sesn_ptr_sender = SessionOffInstanceHolder(instance_sesn_ptr_sender);

  bool		lock_already_owned    = false;
  unsigned long sesn_call_flags	=	(CALL_FLAG_LOCK_SESSION|CALL_FLAG_LOCK_SESSION_BLOCKING|
                                     CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY| CALL_FLAG_HASH_USERNAME_LOCALLY|
                                     CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION|CALL_FLAG_REMOTE_SESSION);
  GetSessionForThisUserByUserId(sesn_ptr_sender, uid_origintor, &lock_already_owned, sesn_call_flags);
  InstanceHolderForSession *instance_sesn_ptr_originator = (InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr_sender);

  if (unlikely(IS_EMPTY(instance_sesn_ptr_originator))) {
    _RETURN_RESULT_SESN(sesn_ptr_sender, NULL, RESULT_TYPE_ERR, RESCODE_USERINFO_UNKNOWN)
  }

  //>>> Session for called locked

  sesn_ptr_originator = SessionOffInstanceHolder(instance_sesn_ptr_originator);
  return_success:
  context_ptr->instance_sesn_ptr_originator		=	instance_sesn_ptr_originator;
  context_ptr->instance_sesn_ptr_sender				=	instance_sesn_ptr_sender;

  //no need to propagate lock at this stage, because UfsrvCommandMarshalTransmission will lock it prior to transmission
  if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_originator, __func__);

  _RETURN_RESULT_SESN(sesn_ptr_sender, context_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_RESOURCE_UPDATED)
}