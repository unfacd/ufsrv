/*
 * fence_command_controller.c
 *
 *  Created on: 25 Feb 2017
 *      Author: ayman
 */


#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <thread_context_type.h>
#include <misc.h>
#include <fence_state.h>
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
#include <call_broadcast.h>
#include <location.h>
#include <command_controllers.h>
#include <ufsrvuid.h>

extern ufsrv							*const masterptr;
extern __thread ThreadContext ufsrv_thread_context;

typedef struct CallContext {
	FenceStateDescriptor *fence_state_caller;
	FenceStateDescriptor *fence_state_called;
	Session 							*sesn_ptr_caller;
	Session 							*sesn_ptr_called;
	FenceEvent						*fence_event_ptr;
}	CallContext;

inline static UFSRVResult *_CommandControllerCallOffer (Session *sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
inline static UFSRVResult *_CommandControllerCallAnswer (Session *sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
inline static UFSRVResult *_CommandControllerCallHangUp (Session *sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);
inline static UFSRVResult *_CommandControllerCallIceUpdate (Session *sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr);

inline static UFSRVResult *_MarshalCallOffer (Session *sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr_received, CallContext *call_context_ptr);
static inline UFSRVResult *_MarshalCallAnswer(Session *sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr_received, CallContext *call_context_ptr);
static inline UFSRVResult *_MarshalCallHangUp(Session *sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr_received, CallContext *call_context_ptr);
static inline UFSRVResult *_MarshalCallIceUpdate(Session *sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr_received, CallContext *call_context_ptr);

static UFSRVResult *_HandleCallCommandError (Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, int rescode, int command_type);
static void	_BuildErrorHeaderForCallCommand (CommandHeader *header_ptr, CommandHeader *header_pyr_incoming, int errcode, int command_type);


UFSRVResult *IsUserAllowedToMakeCall(Session *sesn_ptr, unsigned long fid, const UfsrvUid *ufsrvuid, CallContext *, bool *fence_lock_state, unsigned long fence_call_flags);

struct MarshalMessageEnvelopeForCall {
	UfsrvCommandWire		*ufsrv_command_wire;
	Envelope						*envelope;
	CallCommand 				*call_command;
	CommandHeader 			*header;
	FenceRecord					*fence_record;
	UserRecord					*user_record_to;
	UserRecord					*user_record_originator;
};
typedef struct MarshalMessageEnvelopeForCall MarshalMessageEnvelopeForCall;



#define _GENERATE_CALL_COMMAND_ENVELOPE_INITIALISATION() \
	UfsrvCommandWire								ufsrv_command_wire	= UFSRV_COMMAND_WIRE__INIT;	\
	Envelope												command_envelope		=	ENVELOPE__INIT;	\
	CallCommand 										call_command				=	CALL_COMMAND__INIT;	\
	CommandHeader 									header							=	COMMAND_HEADER__INIT;	\
	\
	FenceRecord											fence_record;	\
	UserRecord											user_record_to;	\
	UserRecord											user_record_originator;	\
	\
	MarshalMessageEnvelopeForCall	envelope_marshal = {	\
			.ufsrv_command_wire	=	&ufsrv_command_wire,	\
			.envelope						=	&command_envelope,	\
			.call_command				=	&call_command,	\
			.header							=	&header,	\
			.fence_record				=	&fence_record,	\
			.user_record_to			=	&user_record_to,	\
			.user_record_originator	=	&user_record_originator	\
	}

inline static void _PrepareMarshalMessageForCall (MarshalMessageEnvelopeForCall *envelope_ptr, Session *sesn_ptr, Fence *f_ptr, FenceEvent *event_ptr, DataMessage *data_msg_ptr_orig, enum _CallCommand__CommandTypes, enum _CommandArgs command_arg);

inline static void
_PrepareMarshalMessageForCall (MarshalMessageEnvelopeForCall *envelope_ptr, Session *sesn_ptr, Fence *f_ptr, FenceEvent *event_ptr, DataMessage *data_msg_ptr_orig, enum _CallCommand__CommandTypes command_type, enum _CommandArgs command_arg)
{
	envelope_ptr->envelope->ufsrvcommand								=	envelope_ptr->ufsrv_command_wire;

	envelope_ptr->envelope->ufsrvcommand->callcommand		=	envelope_ptr->call_command;
	envelope_ptr->envelope->ufsrvcommand->ufsrvtype			=	UFSRV_COMMAND_WIRE__UFSRV_TYPE__UFSRV_CALL;
	envelope_ptr->envelope->ufsrvcommand->header				=	envelope_ptr->header;

	envelope_ptr->call_command->header									=	envelope_ptr->header;
	envelope_ptr->call_command->fence										=	envelope_ptr->fence_record;
	MakeFenceRecordInProtoAsIdentifier(sesn_ptr, f_ptr, envelope_ptr->fence_record);
	envelope_ptr->call_command->originator							=	envelope_ptr->user_record_originator; //initialised by user

	envelope_ptr->envelope->source											=	"0";
	envelope_ptr->envelope->timestamp										=	GetTimeNowInMillis(); envelope_ptr->envelope->has_timestamp=1;

	envelope_ptr->header->when													=	envelope_ptr->envelope->timestamp; 	envelope_ptr->header->has_when=1;
	envelope_ptr->header->cid														=	SESSION_ID(sesn_ptr); 							envelope_ptr->header->has_cid=1;
	envelope_ptr->header->command												=	command_type;
	envelope_ptr->header->args													=	command_arg;												envelope_ptr->header->has_args=1;

	if (IS_PRESENT(event_ptr))
	{
		envelope_ptr->header->when_eid										=	event_ptr->when; 					envelope_ptr->header->has_when_eid=1;
		envelope_ptr->header->eid													=	event_ptr->eid; 					envelope_ptr->header->has_eid=1;
	}
	else
	{
		envelope_ptr->header->eid													=	FENCE_LAST_EID(f_ptr); 					envelope_ptr->header->has_eid=1;
	}

	if (IS_PRESENT(data_msg_ptr_orig))
	{
		envelope_ptr->header->when_client								=	data_msg_ptr_orig->ufsrvcommand->callcommand->header->when;
		envelope_ptr->header->has_when_client						=	data_msg_ptr_orig->ufsrvcommand->callcommand->header->has_when_client=1;
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
CommandCallbackControllerCallCommand (Session *sesn_ptr_local_user, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, MessageQueueMsgPayload *mqp_ptr)
{
	CommandHeader *command_header=data_msg_ptr->ufsrvcommand->callcommand->header;

	switch (command_header->command)
	{

	case CALL_COMMAND__COMMAND_TYPES__OFFER:
		_CommandControllerCallOffer (sesn_ptr_local_user, NULL, data_msg_ptr);//fcmd_ptr);
		break;

	case CALL_COMMAND__COMMAND_TYPES__BUSY:
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', command:'%d'}: RECEIVED UNSUPPORTED CALL BUSY COMMAND", __func__, pthread_self(), sesn_ptr_local_user, command_header->command);
		//_CommandControllerCallBusy (sesn_ptr_local_user, NULL, data_msg_ptr);
		break;

	case CALL_COMMAND__COMMAND_TYPES__ANSWER:
		_CommandControllerCallAnswer (sesn_ptr_local_user, NULL, data_msg_ptr);
		break;

	case CALL_COMMAND__COMMAND_TYPES__HANGUP:
		_CommandControllerCallHangUp (sesn_ptr_local_user, NULL, data_msg_ptr);
		break;

	case CALL_COMMAND__COMMAND_TYPES__ICE_UPDATE:
		_CommandControllerCallIceUpdate (sesn_ptr_local_user, NULL, data_msg_ptr);
		break;

	default:
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', command:'%d'}: RECEIVED UKNOWN CALL COMMAND", __func__, pthread_self(), sesn_ptr_local_user, command_header->command);
	}

	exit_release:
	return SESSION_RESULT_PTR(sesn_ptr_local_user);

}


/**
 * 	@brief: All join command originating from client-side are passed through this we determine if fence is new or existing.
 * 	This function is designed to work with ephemeral sessions, not io sessions through the main loop.
 *
 *	@param sesn_ptr:	Target session loaded in ephemeral mode
 * 	@locked RW sesn_ptr: must be locked by the caller
 * 	@locks RW f_ptr: issues flags to cause locking
 * 	@unlocks f_ptr:
 */
inline static UFSRVResult *
_CommandControllerCallOffer (Session *sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr)
{
	bool								fence_already_locked = false;
	CallCommand					*ccmd_ptr;
	FenceRecord 				*fence_record_ptr	= NULL;
	UserRecord					*user_record_to		=	NULL;
	FenceEvent					fence_event				=	{0};
	CallContext					call_context			=	{.fence_event_ptr=&fence_event};

	ccmd_ptr=data_msg_ptr->ufsrvcommand->callcommand;
	if (unlikely(IS_EMPTY(ccmd_ptr->offer)))
	{
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', command:'%d'}: ERROR: RECEIVED EMPTY CALL OFFER COMMAND", __func__, pthread_self(), sesn_ptr, ccmd_ptr->header->command);
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);

	}

	user_record_to	=	ccmd_ptr->to[0];
	fence_record_ptr=ccmd_ptr->fence;

	if(fence_record_ptr->fid>0)	//possibly proposing to join an existing fence
	{
		//event incremented 1x for joining.  requesting fence be locked and returned in locked state
		IsUserAllowedToMakeCall(sesn_ptr, fence_record_ptr->fid, (const UfsrvUid *)user_record_to->ufsrvuid.data, &call_context, &fence_already_locked, FENCE_CALLFLAG_KEEP_FENCE_LOCKED);

		if (SESSION_RESULT_TYPE_ERROR(sesn_ptr)/* && SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST)*/)
		{
			_HandleCallCommandError (sesn_ptr, NULL, wsm_ptr_orig, data_msg_ptr, SESSION_RESULT_CODE(sesn_ptr), data_msg_ptr->ufsrvcommand->callcommand->header->command);

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
		}

		_MarshalCallOffer (sesn_ptr, wsm_ptr_orig, data_msg_ptr, &call_context);
		if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(call_context.fence_state_caller), THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));

		return SESSION_RESULT_PTR(sesn_ptr);
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
}


/**
 * 	@brief: Marshaled for new fence formation.
 *
 * 	@param data_msg_ptr: is the original wire message sent by the client. We'll have to copy bits and pieces from  it for this transmission
 *  @locked f_ptr (as contained in FenceStateDescriptor in CallContext):
 *  @locked sesn_ptr (context_ptr->sesn_ptr->caller):
 *  @locked context_ptr->sesn_ptr->called
 *	@unlocks: none
 *  @dynamic_memory fence_records_ptr: array of FenceRecord initiated with dynamic values. Must be freed with DestructFenceRecordProto (FenceRecord **fence_records_ptr, unsigned count)
 */
inline static UFSRVResult *
_MarshalCallOffer (Session *sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr_received, CallContext *context_ptr)
{
	Fence *f_ptr	=	FENCESTATE_FENCE(context_ptr->fence_state_caller);


	_GENERATE_CALL_COMMAND_ENVELOPE_INITIALISATION();

	_PrepareMarshalMessageForCall (&envelope_marshal, context_ptr->sesn_ptr_called, f_ptr, context_ptr->fence_event_ptr, NULL, CALL_COMMAND__COMMAND_TYPES__OFFER, COMMAND_ARGS__CREATED);
	//MakeFenceRecordInProtoAsIdentifier(sesn_ptr, f_ptr, &fence_record);
	call_command.originator		=	MakeUserRecordForSelfInProto (sesn_ptr, PROTO_USER_RECORD_MINIMAL);
	call_command.offer				=	data_msg_ptr_received->ufsrvcommand->callcommand->offer;

	size_t legacymessage_encoded_sz=data_message__get_packed_size(data_msg_ptr_received);
	uint8_t legacymessage_encoded[legacymessage_encoded_sz];
	data_message__pack(data_msg_ptr_received, legacymessage_encoded);
	command_envelope.legacymessage.data=legacymessage_encoded;
	command_envelope.legacymessage.len=legacymessage_encoded_sz;
	command_envelope.has_legacymessage=1;

	command_envelope.sourcedevice=1; command_envelope.has_sourcedevice=1;

	UfsrvCommandMarshallingDescription ufsrv_descpription={header.eid, FENCE_ID(f_ptr), header.when, &EnvelopeMetaData, &command_envelope};
	UfsrvCommandInvokeCommand (sesn_ptr, context_ptr->sesn_ptr_called, wsm_ptr_orig, NULL, &ufsrv_descpription, uSETKEYS_V1_IDX);

	DestructFenceRecordProto (&fence_record, false);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}


inline static UFSRVResult *
_CommandControllerCallAnswer (Session *sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr)
{
	bool								fence_already_locked = false;
	CallCommand					*ccmd_ptr;
	FenceRecord 				*fence_record_ptr	= NULL;
	UserRecord					*user_record_to		=	NULL;
	FenceEvent					fence_event				=	{0};
	CallContext					call_context			=	{.fence_event_ptr=&fence_event};

	ccmd_ptr=data_msg_ptr->ufsrvcommand->callcommand;
	if (unlikely(IS_EMPTY(ccmd_ptr->answer)))
	{
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', command:'%d'}: ERROR: RECEIVED EMPTY CALL ANSWER COMMAND", __func__, pthread_self(), sesn_ptr, ccmd_ptr->header->command);
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

	}

	user_record_to	=	ccmd_ptr->to[0];
	fence_record_ptr=ccmd_ptr->fence;

	if(fence_record_ptr->fid>0)	//possibly proposing to join an existing fence
	{
		//event incremented 1x for joining.  requesting fence be locked and returned in locked state
		IsUserAllowedToMakeCall(sesn_ptr, fence_record_ptr->fid, (const UfsrvUid *)user_record_to->ufsrvuid.data, &call_context, &fence_already_locked, FENCE_CALLFLAG_KEEP_FENCE_LOCKED);

		if (SESSION_RESULT_TYPE_ERROR(sesn_ptr)/* && SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST)*/)
		{
			_HandleCallCommandError (sesn_ptr, NULL, wsm_ptr_orig, data_msg_ptr, SESSION_RESULT_CODE(sesn_ptr), data_msg_ptr->ufsrvcommand->callcommand->header->command);

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
		}

		_MarshalCallAnswer (sesn_ptr, wsm_ptr_orig, data_msg_ptr, &call_context);
		if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(call_context.fence_state_caller), THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));

		return SESSION_RESULT_PTR(sesn_ptr);
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
}

/**
 * 	@brief: Marshaled for new fence formation.
 *
 * 	@param data_msg_ptr: is the original wire message sent by the client. We'll have to copy bits and pieces from  it for this transmission
 *  @locked f_ptr (as contained in FenceStateDescriptor in CallContext):
 *  @locked sesn_ptr (context_ptr->sesn_ptr->caller):
 *  @locked context_ptr->sesn_ptr->called
 *	@unlocks: none
 *  @dynamic_memory fence_records_ptr: array of FenceRecord initiated with dynamic values. Must be freed with DestructFenceRecordProto (FenceRecord **fence_records_ptr, unsigned count)
 */
inline static UFSRVResult *
_MarshalCallAnswer (Session *sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr_received, CallContext *context_ptr)
{
	Fence *f_ptr	=	FENCESTATE_FENCE(context_ptr->fence_state_caller);


	_GENERATE_CALL_COMMAND_ENVELOPE_INITIALISATION();

	_PrepareMarshalMessageForCall (&envelope_marshal, context_ptr->sesn_ptr_called, f_ptr, context_ptr->fence_event_ptr, NULL, CALL_COMMAND__COMMAND_TYPES__ANSWER, COMMAND_ARGS__CREATED);
//	MakeFenceRecordInProtoAsIdentifier(sesn_ptr, f_ptr, &fence_record);
	call_command.originator		=	MakeUserRecordForSelfInProto (sesn_ptr, PROTO_USER_RECORD_MINIMAL);
	call_command.answer				=	data_msg_ptr_received->ufsrvcommand->callcommand->answer;

	size_t legacymessage_encoded_sz=data_message__get_packed_size(data_msg_ptr_received);
	uint8_t legacymessage_encoded[legacymessage_encoded_sz];
	data_message__pack(data_msg_ptr_received, legacymessage_encoded);
	command_envelope.legacymessage.data=legacymessage_encoded;
	command_envelope.legacymessage.len=legacymessage_encoded_sz;
	command_envelope.has_legacymessage=1;

	command_envelope.sourcedevice=1; command_envelope.has_sourcedevice=1;

	UfsrvCommandMarshallingDescription ufsrv_descpription={header.eid, FENCE_ID(f_ptr), header.when, &EnvelopeMetaData, &command_envelope};
	UfsrvCommandInvokeCommand (sesn_ptr, context_ptr->sesn_ptr_called, wsm_ptr_orig, NULL, &ufsrv_descpription, uSETKEYS_V1_IDX);

	DestructFenceRecordProto (&fence_record, false);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}


inline static UFSRVResult *
_CommandControllerCallHangUp(Session *sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr)
{
	bool								fence_already_locked = false;
	CallCommand					*ccmd_ptr;
	FenceRecord 				*fence_record_ptr	= NULL;
	UserRecord					*user_record_to		=	NULL;
	FenceEvent					fence_event				=	{0};
	CallContext					call_context			=	{.fence_event_ptr=&fence_event};

	ccmd_ptr=data_msg_ptr->ufsrvcommand->callcommand;
	if (unlikely(IS_EMPTY(ccmd_ptr->hangup)))
	{
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', command:'%d'}: ERROR: RECEIVED EMPTY CALL HANGUP COMMAND", __func__, pthread_self(), sesn_ptr, ccmd_ptr->header->command);
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);

	}

	user_record_to	=	ccmd_ptr->to[0];
	fence_record_ptr=ccmd_ptr->fence;

	if(fence_record_ptr->fid>0)	//possibly proposing to join an existing fence
	{
		//event incremented 1x for joining.  requesting fence be locked and returned in locked state
		IsUserAllowedToMakeCall(sesn_ptr, fence_record_ptr->fid, (const UfsrvUid *)user_record_to->ufsrvuid.data, &call_context, &fence_already_locked, FENCE_CALLFLAG_KEEP_FENCE_LOCKED);

		if (SESSION_RESULT_TYPE_ERROR(sesn_ptr)/* && SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST)*/)
		{
			_HandleCallCommandError (sesn_ptr, NULL, wsm_ptr_orig, data_msg_ptr, SESSION_RESULT_CODE(sesn_ptr), data_msg_ptr->ufsrvcommand->callcommand->header->command);

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
		}

		_MarshalCallHangUp (sesn_ptr, wsm_ptr_orig, data_msg_ptr, &call_context);
		if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(call_context.fence_state_caller), THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));

		return SESSION_RESULT_PTR(sesn_ptr);
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
}

/**
 * 	@brief: Marshaled for new fence formation.
 *
 * 	@param data_msg_ptr: is the original wire message sent by the client. We'll have to copy bits and pieces from  it for this transmission
 *  @locked f_ptr (as contained in FenceStateDescriptor in CallContext):
 *  @locked sesn_ptr (context_ptr->sesn_ptr->caller):
 *  @locked context_ptr->sesn_ptr->called
 *	@unlocks: none
 *  @dynamic_memory fence_records_ptr: array of FenceRecord initiated with dynamic values. Must be freed with DestructFenceRecordProto (FenceRecord **fence_records_ptr, unsigned count)
 */
inline static UFSRVResult *
_MarshalCallHangUp (Session *sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr_received, CallContext *context_ptr)
{
	Fence *f_ptr	=	FENCESTATE_FENCE(context_ptr->fence_state_caller);


	_GENERATE_CALL_COMMAND_ENVELOPE_INITIALISATION();

	_PrepareMarshalMessageForCall (&envelope_marshal, context_ptr->sesn_ptr_called, f_ptr, context_ptr->fence_event_ptr, NULL, CALL_COMMAND__COMMAND_TYPES__HANGUP, COMMAND_ARGS__CREATED);
//	MakeFenceRecordInProtoAsIdentifier(sesn_ptr, f_ptr, &fence_record);
	call_command.originator		=	MakeUserRecordForSelfInProto (sesn_ptr, PROTO_USER_RECORD_MINIMAL);
	call_command.hangup				=	data_msg_ptr_received->ufsrvcommand->callcommand->hangup;

	size_t legacymessage_encoded_sz=data_message__get_packed_size(data_msg_ptr_received);
	uint8_t legacymessage_encoded[legacymessage_encoded_sz];
	data_message__pack(data_msg_ptr_received, legacymessage_encoded);
	command_envelope.legacymessage.data=legacymessage_encoded;
	command_envelope.legacymessage.len=legacymessage_encoded_sz;
	command_envelope.has_legacymessage=1;

	command_envelope.sourcedevice=1; command_envelope.has_sourcedevice=1;

	UfsrvCommandMarshallingDescription ufsrv_descpription={header.eid, FENCE_ID(f_ptr), header.when, &EnvelopeMetaData, &command_envelope};
	UfsrvCommandInvokeCommand (sesn_ptr, context_ptr->sesn_ptr_called, wsm_ptr_orig, NULL, &ufsrv_descpription, uSETKEYS_V1_IDX);

	DestructFenceRecordProto (&fence_record, false);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}


inline static UFSRVResult *
_CommandControllerCallIceUpdate(Session *sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr)
{
	bool								fence_already_locked = false;
	CallCommand					*ccmd_ptr;
	FenceRecord 				*fence_record_ptr	= NULL;
	UserRecord					*user_record_to		=	NULL;
	FenceEvent					fence_event				=	{0};
	CallContext					call_context			=	{.fence_event_ptr=&fence_event};

	ccmd_ptr=data_msg_ptr->ufsrvcommand->callcommand;
	if (unlikely(IS_EMPTY(ccmd_ptr->iceupdate)))
	{
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', command:'%d'}: ERROR: RECEIVED EMPTY CALL ICEUPDATE COMMAND", __func__, pthread_self(), sesn_ptr, ccmd_ptr->header->command);
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);

	}

	user_record_to	=	ccmd_ptr->to[0];
	fence_record_ptr=ccmd_ptr->fence;

	if(fence_record_ptr->fid>0)	//possibly proposing to join an existing fence
	{
		//event incremented 1x for joining.  requesting fence be locked and returned in locked state
		IsUserAllowedToMakeCall(sesn_ptr, fence_record_ptr->fid, (const UfsrvUid *)user_record_to->ufsrvuid.data, &call_context, &fence_already_locked, FENCE_CALLFLAG_KEEP_FENCE_LOCKED);

		if (SESSION_RESULT_TYPE_ERROR(sesn_ptr)/* && SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST)*/)
		{
			_HandleCallCommandError (sesn_ptr, NULL, wsm_ptr_orig, data_msg_ptr, SESSION_RESULT_CODE(sesn_ptr), data_msg_ptr->ufsrvcommand->callcommand->header->command);

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
		}

		_MarshalCallIceUpdate (sesn_ptr, wsm_ptr_orig, data_msg_ptr, &call_context);
		if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(call_context.fence_state_caller), THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));

		return SESSION_RESULT_PTR(sesn_ptr);
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
}

/**
 * 	@brief:
 *
 * 	@param data_msg_ptr: is the original wire message sent by the client. We'll have to copy bits and pieces from  it for this transmission
 *  @locked f_ptr (as contained in FenceStateDescriptor in CallContext):
 *  @locked sesn_ptr (context_ptr->sesn_ptr->caller):
 *  @locked context_ptr->sesn_ptr->called
 *	@unlocks: none
 *  @dynamic_memory fence_records_ptr: array of FenceRecord initiated with dynamic values. Must be freed with DestructFenceRecordProto (FenceRecord **fence_records_ptr, unsigned count)
 */
inline static UFSRVResult *
_MarshalCallIceUpdate (Session *sesn_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr_received, CallContext *context_ptr)
{
	Fence *f_ptr	=	FENCESTATE_FENCE(context_ptr->fence_state_caller);


	_GENERATE_CALL_COMMAND_ENVELOPE_INITIALISATION();

	_PrepareMarshalMessageForCall (&envelope_marshal, context_ptr->sesn_ptr_called, f_ptr, context_ptr->fence_event_ptr, NULL, CALL_COMMAND__COMMAND_TYPES__ICE_UPDATE, COMMAND_ARGS__CREATED);
//	MakeFenceRecordInProtoAsIdentifier(sesn_ptr, f_ptr, &fence_record);
	call_command.originator		=	MakeUserRecordForSelfInProto (sesn_ptr, PROTO_USER_RECORD_MINIMAL);
	call_command.iceupdate		=	data_msg_ptr_received->ufsrvcommand->callcommand->iceupdate;
	call_command.n_iceupdate	=	data_msg_ptr_received->ufsrvcommand->callcommand->n_iceupdate;

	size_t legacymessage_encoded_sz=data_message__get_packed_size(data_msg_ptr_received);
	uint8_t legacymessage_encoded[legacymessage_encoded_sz];
	data_message__pack(data_msg_ptr_received, legacymessage_encoded);
	command_envelope.legacymessage.data=legacymessage_encoded;
	command_envelope.legacymessage.len=legacymessage_encoded_sz;
	command_envelope.has_legacymessage=1;

	command_envelope.sourcedevice=1; command_envelope.has_sourcedevice=1;

	UfsrvCommandMarshallingDescription ufsrv_descpription={header.eid, FENCE_ID(f_ptr), header.when, &EnvelopeMetaData, &command_envelope};
	UfsrvCommandInvokeCommand (sesn_ptr, context_ptr->sesn_ptr_called, wsm_ptr_orig, NULL, &ufsrv_descpription, uSETKEYS_V1_IDX);

	DestructFenceRecordProto (&fence_record, false);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

/////////////////////////////////////////////


/**
 * 	@brief: Generalised command sending
 */
__unused inline static UFSRVResult *
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
_BuildErrorHeaderForCallCommand (CommandHeader *header_ptr, CommandHeader *header_ptr_incoming, int errcode, int command_type)
{
	switch (errcode)
	{
//		case RESCODE_FENCE_EXISTS:
//			header_ptr->args_error	=	FENCE_COMMAND__ERRORS__ALREADY_EXISTS; 	header_ptr->has_args_error	=	1;
//			header_ptr->args				=	COMMAND_ARGS__REJECTED;									header_ptr->has_args				=	1;
//			break;
//
//		case RESCODE_FENCE_FENCE_MEMBERSHIP:
//			header_ptr->args_error	=	FENCE_COMMAND__ERRORS__NOT_MEMBER; 			header_ptr->has_args_error	=	1;
//			header_ptr->args				=	COMMAND_ARGS__REJECTED;									header_ptr->has_args				=	1;
//			break;
//
//		case RESCODE_FENCE_OWNERSHIP:
//			header_ptr->args_error	=	FENCE_COMMAND__ERRORS__PERMISSIONS_ADMIN; 	header_ptr->has_args_error	=	1;
//			header_ptr->args				=	COMMAND_ARGS__REJECTED;											header_ptr->has_args				=	1;
//			break;
//
//		case RESCODE_FENCE_DOESNT_EXIST:
//			header_ptr->args_error	=	FENCE_COMMAND__ERRORS__GROUP_DOESNT_EXIST; 	header_ptr->has_args_error	=	1;
//			header_ptr->args				=	COMMAND_ARGS__REJECTED;											header_ptr->has_args				=	1;
//			break;
//
//			//command parameter empty, for example missing fence name
//		case RESCODE_PROG_MISSING_PARAM:
//			header_ptr->args_error	=	FENCE_COMMAND__ERRORS__MISSING_PARAMETER; 	header_ptr->has_args_error	=	1;
//			header_ptr->args				=	COMMAND_ARGS__REJECTED;											header_ptr->has_args				=	1;
//			break;

		default:
			goto exit_error;
	}

	if (command_type>0)		header_ptr->command	=	command_type;
	else									header_ptr->command	=	header_ptr_incoming->command;//restore original command
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
static UFSRVResult *
_HandleCallCommandError (Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, WebSocketMessage *wsm_ptr_orig, DataMessage *data_msg_ptr, int rescode, int command_type)
{
	Envelope 					command_envelope	= ENVELOPE__INIT;
	CommandHeader 		header						= COMMAND_HEADER__INIT;
	UfsrvCommandWire	ufsrv_command			= UFSRV_COMMAND_WIRE__INIT;
	CallCommand 			call_command			= CALL_COMMAND__INIT;

	command_envelope.ufsrvcommand				=	&ufsrv_command;
	ufsrv_command.header								=	&header;
	call_command.header									=	&header;

	ufsrv_command.callcommand						=	&call_command;
	ufsrv_command.ufsrvtype							=	UFSRV_COMMAND_WIRE__UFSRV_TYPE__UFSRV_CALL;

	FenceRecord	fence_record						= {0};

	call_command.fence									=	&fence_record;
	if (IS_PRESENT(fence_state_ptr))
	{
		MakeFenceRecordInProtoAsIdentifier(sesn_ptr, FENCESTATE_FENCE(fence_state_ptr), &fence_record);
		fence_record.fid									=	 FENCE_ID(FENCESTATE_FENCE(fence_state_ptr));
	}
	else
	{
		MakeFenceRecordInProtoAsIdentifierByParams (sesn_ptr, data_msg_ptr->ufsrvcommand->callcommand->fence->fid, &fence_record);
	}

	command_envelope.source							=	"0";
	command_envelope.timestamp					=	GetTimeNowInMillis(); command_envelope.has_timestamp=1;

	header.when													=	command_envelope.timestamp; header.has_when		=	1;
	header.cid													=	SESSION_ID(sesn_ptr);				header.has_cid		=	1;

	_BuildErrorHeaderForCallCommand (&header, data_msg_ptr->ufsrvcommand->callcommand->header, rescode, command_type);

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', uid:'%lu', cid:'%lu', arg_error:'%d', rescode:'%d'}: Marshaling Error response message...", __func__, pthread_self(), sesn_ptr, SESSION_USERID(sesn_ptr), SESSION_ID(sesn_ptr), header.args_error, rescode);
#endif

	return (_MarshalCommandToUser(sesn_ptr, NULL,  IS_PRESENT(fence_state_ptr)?FENCESTATE_FENCE(fence_state_ptr):NULL, &command_envelope,  uSETKEYS_V1_IDX));

}

/**
 *
 * 	@locked sesn_ptr_caller
 * 	@locks f_ptr:
 * 	@locks sesn_ptr_called:
 * 	@unlocks f_ptr: on error
 * 	@unlocks sesn_ptr_called: on error or just before exit
 */

UFSRVResult *
IsUserAllowedToMakeCall (Session *sesn_ptr_caller, unsigned long fid, const UfsrvUid *uid_ptr, CallContext *context_ptr, bool *fence_lock_state, unsigned long fence_call_flags)
{
	unsigned 	rescode;
	Fence			*f_ptr							= NULL;
	Session 	*sesn_ptr_called		=	NULL;
	unsigned long userid_called 	= UfsrvUidGetSequenceId(uid_ptr);

	unsigned long fence_call_flags_final = FENCE_CALLFLAG_SEARCH_BACKEND|FENCE_CALLFLAG_HASH_FENCE_LOCALLY|FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE;

	if (fence_call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED)	fence_call_flags_final |= (FENCE_CALLFLAG_KEEP_FENCE_LOCKED|FENCE_CALLFLAG_LOCK_FENCE_BLOCKING);

	FindFenceById(sesn_ptr_caller, fid, fence_call_flags_final);
  InstanceHolderForFence *instance_f_ptr = (InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr_caller);

	if (IS_EMPTY(instance_f_ptr)) {
		if (SESSION_RESULT_CODE_EQUAL(sesn_ptr_caller, RESCODE_FENCE_DOESNT_EXIST)||
				SESSION_RESULT_CODE_EQUAL(sesn_ptr_caller, RESCODE_BACKEND_RESOURCE_NULL)) {
			_RETURN_RESULT_SESN(sesn_ptr_caller, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_DOESNT_EXIST)
		}
		else 	SESSION_RETURN_RESULT(sesn_ptr_caller, NULL, RESULT_TYPE_ERR, SESSION_RESULT_CODE(sesn_ptr_caller))
	}

	bool fence_lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr_caller, RESCODE_PROG_LOCKED_THIS_THREAD));
  f_ptr = FenceOffInstanceHolder(instance_f_ptr);

	//>>> Fence RW LOCKED

	bool		lock_already_owned = false;
	unsigned long sesn_call_flags	=	(CALL_FLAG_LOCK_SESSION|CALL_FLAG_LOCK_SESSION_BLOCKING|
																		CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY| CALL_FLAG_HASH_USERNAME_LOCALLY|
																		CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION|CALL_FLAG_REMOTE_SESSION);
	GetSessionForThisUserByUserId(sesn_ptr_caller, userid_called, &lock_already_owned, sesn_call_flags);
	InstanceHolderForSession *instance_sesn_ptr_called = (InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr_caller);
  sesn_ptr_called = SessionOffInstanceHolder(instance_sesn_ptr_called);

	if (unlikely(IS_EMPTY(sesn_ptr_called))) {
		if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr_caller));
		_RETURN_RESULT_SESN(sesn_ptr_caller, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_DOESNT_EXIST)
	}

	//>>> Session for called locked

	InstanceHolderForFenceStateDescriptor *instance_fstate_ptr_caller;
  InstanceHolderForFenceStateDescriptor *instance_fstate_ptr_called;
	FenceStateDescriptor *fstate_ptr_called	=	NULL;
	FenceStateDescriptor *fstate_ptr_caller	=	NULL;
	#define FLAG_FENCE_LOCK_FALSE false

	if (!IS_PRESENT((instance_fstate_ptr_caller = IsUserMemberOfThisFence(&(SESSION_FENCE_LIST(sesn_ptr_caller)), f_ptr, FLAG_FENCE_LOCK_FALSE)))) {
		if (!lock_already_owned)				SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_called, __func__);
		if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr_caller));

		_RETURN_RESULT_SESN(sesn_ptr_caller, NULL, RESULT_TYPE_ERR, RESCODE_USER_FENCE_ALREADYIN)
	}

  fstate_ptr_caller = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr_caller);

	if (!IS_PRESENT((instance_fstate_ptr_called = IsUserMemberOfThisFence(&(SESSION_FENCE_LIST(sesn_ptr_called)), f_ptr, FLAG_FENCE_LOCK_FALSE)))) {
		if (!lock_already_owned)				SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_called, __func__);
		if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr_caller));

		_RETURN_RESULT_SESN(sesn_ptr_caller, NULL, RESULT_TYPE_ERR, RESCODE_USER_FENCE_ALREADYIN)
	}

  fstate_ptr_called = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr_called);

	//TODO: check sesn_ptr_called prefs whilst session is locked allow/disallow event

	FenceEvent *fence_event_ptr = RegisterFenceEvent (sesn_ptr_caller, FENCESTATE_FENCE(fstate_ptr_caller), EVENT_TYPE_CALL_OFFER,  NULL, FLAG_FENCE_LOCK_FALSE, context_ptr->fence_event_ptr);
	if (IS_PRESENT(fence_event_ptr)) {
		return_success:
		context_ptr->fence_state_called	=	fstate_ptr_called;
		context_ptr->fence_state_caller	=	fstate_ptr_caller;
		context_ptr->sesn_ptr_called		=	sesn_ptr_called;
		context_ptr->sesn_ptr_caller		=	sesn_ptr_caller;

//		InterBroadcastFenceAvatarMessage (sesn_ptr,
//																			&((ContextDataPair){(ClientContextData *)FENCESTATE_FENCE(fence_state_ptr), (ClientContextData *)&attachment_descriptor}),
//																			fence_event_ptr, COMMAND_ARGS__UPDATED);

		//no need to propagate lock at this stage, because UfsrvCommandMarshalTransmission will lock it prior to transmission
		if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_called, __func__);

		if (IS_PRESENT(fence_lock_state))	*fence_lock_state=fence_lock_already_owned;
		_RETURN_RESULT_SESN(sesn_ptr_caller, context_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_RESOURCE_UPDATED)
	}
	else	goto event_generation_error;


	event_generation_error:
	rescode = SESSION_RESULT_CODE(sesn_ptr_caller);
	goto exit_unlock;

	exit_unlock:
	if (!lock_already_owned)				SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_called, __func__);
	if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr_caller));
	_RETURN_RESULT_SESN(sesn_ptr_caller, NULL, RESULT_TYPE_ERR, rescode)

}
