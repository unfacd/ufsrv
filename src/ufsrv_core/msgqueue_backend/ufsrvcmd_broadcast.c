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
#include <nportredird.h>
#include <sessions_delegator_type.h>
#include <ufsrvuid.h>
#include <session.h>
#include <user/users_protobuf.h>
#include <ufsrv_core/SignalService.pb-c.h>
#include <msgqueue_backend/ufsrvcmd_broadcast.h>
#include <message.h>
#include <call_command_broadcast.h>
#include <receipt_broadcast.h>
#include <location_broadcast.h>
#include <message_command_broadcast.h>
#include <session_broadcast.h>
#include <fence_broadcast.h>
#include <state_command_broadcast.h>
#include <msgqueue_backend/ufsrvmsgqueue.h>
#include <command_controllers.h>
#include <msgqueue_backend/UfsrvMessageQueue.pb-c.h>

/**
 * 	System for handling "MessageQueue Broadcasts" arriving through the private pub/sub message bus which all instances subscribe and
 * 	publish to. There are well define channles (topics) which are currently in operation.
 * 	The main formating for expressing state information is the protobuf 'MessageQueueMessage' message.
 *
 * 	There are two types of broadcasts:
 * 	1)INTER: broadcasts between shared class of servers, for example the core ufsrv that implements websockets
 * 		1.1) These messages are mostly notifications about changes in backend data model
 * 		1.2) Maybe Triggered because the server have previously received an INTRA message from another class of servers
 * 		1.3) Receiving server should not update backend data model based on these broadcasts,but can update their local state
 * 		1.4) For each broadcast type there are two main handlers:
 * 				1) handler for when a such broadcast is received (_HandleInterBroadcastForUserMessage())
 * 				2) handler to send a broadcast (e.g BroadcastInterUserMessage())
 *		1.5) Expect to have an event id associated with the broadcast, signifying the actual change.
 *
 * 	2)INTRA: Broadcasts sent from out side the shared class, for example the stateless ufsrvapi
 * 		1.2)	Generally INTRA broadcasts are for named  targets ie. targeting a specific server instance
 * 		1.2.1)	Maybe due to load-balancing
 * 		1.2.2)	The named server owns a resource
 * 		1.3)	Generally indicate a state change/request/response from an endpoint user, which may or may not
 * 		 			cause a backend data model change
 *		1.4)	Untargeted servers should not respond. Instead, if applicable will receive an INTER broadcast from the targeted
 *					server after handling the original request.
 *		1.5) Expect to have an event id associated with the broadcast, signifying the actual change.
 *		1.6) Actual handling is dispatched to CommandController, which:
 *			1.6.1) Perform backend data model verification and change, including event generation
 *			1.6.2)Invoke InterBroadcast if relevant
 *		1.7)	Some INTRA broadcasts cause receivers to adopt INTER processing semantics in the sense that the backend model will have
 *		been already changed by the broadcaster (even though it is from different class eg stateless ufsrvapi). Most preference
 *		change requetes are handled by the ufsrvapi and therefore INTRA broadcasts merely reflect what changed
 */

extern ufsrv *const masterptr;
extern SessionsDelegator *const sessions_delegator_ptr;
extern __thread ThreadContext ufsrv_thread_context;

static inline enum MessageQueueVerificationCodes  _VerifyMessageQueueCommand (MessageQueueMsgPayload *mqp_ptr, MessageQueueMessage 	**mqm_ptr_out, unsigned long call_flags);
static inline enum MessageQueueVerificationCodes  _VerifyIntraMessageQueueCommand (MessageQueueMsgPayload *mqp_ptr, MessageQueueMessage 	**mqm_ptr_out, unsigned long call_flags);
static inline enum MessageQueueVerificationCodes  _VerifyInterMessageQueueCommand (MessageQueueMsgPayload *mqp_ptr, MessageQueueMessage 	**mqm_ptr_out, unsigned long call_flags);
static inline enum MessageQueueVerificationCodes _VerifyBroadcastTargeting (MessageQueueMessage *mqm_ptr, unsigned long call_flags);
static int _HandleStagedEncodedIntraMessage (redisReply *redis_ptr_staged_message, size_t reqid_target, bool *targetid_is_found);
static int _HandleInterBroadcast (MessageQueueMsgPayload *mqp_ptr, MessageQueueMessage *mqm_ptr);

#define DEFAULT_CALLFLAGS_VERFIER_INTRA (0)
#define DEFAULT_CALLFLAGS_VERFIER_INTER (MSGQUEFLAG_ALLOW_OTHER_TARGET)

//IMPORTANT KEEP THIS INLINE WITH enum UfsrvCmdTopicIds, ensuring symmetr line is maintained across the two types.
//There is a fixed conversion factor UFSRVCMDID_INTER_INTRA_CONVERSION_FACTOR define

static UfsrvCommandBroadcast ufsrvcmd_broadcasts[UFSRV_MAX_BROADCAST_ID] = {
		{UFSRV_SESSION, 				_INTERCOMMAND_SESSION, 		{DEFAULT_CALLFLAGS_VERFIER_INTER, HandleInterBroadcastForSession, 		  NULL, _VerifyInterMessageQueueCommand}		},
		{UFSRV_FENCE, 					_INTERCOMMAND_FENCE,			{DEFAULT_CALLFLAGS_VERFIER_INTER, HandleInterBroadcastForFence,				NULL, _VerifyInterMessageQueueCommand}		},
		{UFSRV_MSG,							_INTERCOMMAND_MSG,				{DEFAULT_CALLFLAGS_VERFIER_INTER, HandleInterBroadcastForUserMessage, (BroadcastPreHandler)PrepareForMessageCommandInterBroadcastHandling, _VerifyInterMessageQueueCommand}		},
		{UFSRV_LOC,							_INTERCOMMAND_LOC,				{DEFAULT_CALLFLAGS_VERFIER_INTER, HandleInterBroadcastForLocation,		NULL, _VerifyInterMessageQueueCommand}		},
		{UFSRV_USER,						_INTERCOMMAND_USER,				{DEFAULT_CALLFLAGS_VERFIER_INTER, HandleInterBroadcastForUser,				  NULL, _VerifyInterMessageQueueCommand}		},
		{UFSRV_CALL,						_INTERCOMMAND_CALL,				{0, 															NULL,																  NULL, NULL}																},
		{UFSRV_SYS,							_INTERCOMMAND_SYS,				{0, 															NULL,																NULL, NULL}																},
		{UFSRV_RECEIPT,					_INTERCOMMAND_RECEIPT,		{0, 															NULL,																NULL, NULL}																},
    {UFSRV_STATE,					_INTERCOMMAND_STATE,		    {DEFAULT_CALLFLAGS_VERFIER_INTER,NULL,			  NULL, NULL}																},
		{UFSRV_SYNC,						_INTERCOMMAND_SYNC,				{0, 															NULL,																  NULL, NULL}																},
//------------------------------------------- SYMMETRY LINE ------------------------------------------------------------//
		{UFSRV_INTRA_SESSION,		_INTRACOMMAND_SESSION,		{DEFAULT_CALLFLAGS_VERFIER_INTRA,	HandleIntraBroadcastForSession,			NULL, _VerifyIntraMessageQueueCommand}		},
		{UFSRV_INTRA_FENCE,			_INTRACOMMAND_FENCE,			{DEFAULT_CALLFLAGS_VERFIER_INTRA, HandleIntraBroadcastForFence,				NULL, _VerifyIntraMessageQueueCommand}		},
		{UFSRV_INTRA_MSG,				_INTRACOMMAND_MSG,				{DEFAULT_CALLFLAGS_VERFIER_INTRA, HandleIntraBroadcastForUserMessage,	NULL, _VerifyIntraMessageQueueCommand}		},
		{UFSRV_INTRA_LOC,				_INTRACOMMAND_LOC,				{DEFAULT_CALLFLAGS_VERFIER_INTRA,HandleIntraBroadcastForLocation,			NULL, _VerifyIntraMessageQueueCommand}		},
		{UFSRV_INTRA_USER,			_INTRACOMMAND_USER,				{DEFAULT_CALLFLAGS_VERFIER_INTRA, HandleIntraBroadcastForUser,				    NULL, _VerifyIntraMessageQueueCommand}		},
		{UFSRV_INTRA_CALL,			_INTRACOMMAND_CALL,				{DEFAULT_CALLFLAGS_VERFIER_INTRA, HandleIntraBroadcastForCall,			      NULL, _VerifyIntraMessageQueueCommand}		},
		{UFSRV_INTRA_RECEIPT,		_INTRACOMMAND_RECEIPT,		{DEFAULT_CALLFLAGS_VERFIER_INTRA, HandleIntraBroadcastForReceipt,			NULL, _VerifyIntraMessageQueueCommand}		},
    {UFSRV_INTRA_STATE,		_INTRACOMMAND_STATE,		    {DEFAULT_CALLFLAGS_VERFIER_INTRA, HandleIntraBroadcastForState,			  NULL, _VerifyIntraMessageQueueCommand}		},
		{UFSRV_INTRA_SYNC,			_INTRACOMMAND_SYNC,				{DEFAULT_CALLFLAGS_VERFIER_INTRA, NULL,			  NULL, NULL}		},
		{UFSRV_INTRA_SYS,				_INTRACOMMAND_SYS,				{0, 															NULL, NULL,																NULL}																},
};

static inline enum MessageQueueVerificationCodes
_VerifyBroadcastTargeting (MessageQueueMessage *mqm_ptr, unsigned long call_flags)
{
	if ((mqm_ptr->origin == masterptr->serverid) && !(call_flags&MSGQUEFLAG_ALLOW_SELF_PUBLISH)) {
#ifdef __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s {pid:'%lu' origin:'%d'}: BROADCAST FROM SELF: IGNORING.", __func__, pthread_self(), mqm_ptr->origin);
#endif
			return MSQQUE_SELFPUBLISHED;
	}

	if ((mqm_ptr->target_ufsrv != masterptr->serverid_by_user) && !(call_flags&MSGQUEFLAG_ALLOW_OTHER_TARGET)) {
#ifdef __UF_FULLDEBUG
				syslog(LOG_DEBUG, "%s {pid:'%lu' origin:'%d', target_ufsrv:'%d'}: BROADCAST FOR OTHER TARGET: IGNORING.", __func__, pthread_self(), mqm_ptr->origin, mqm_ptr->target_ufsrv);
#endif
		return MSGQUE_OTHER_TARGET;
	}

	return MSGQUE_SUCCESS;
}

/**
 * @WARNING: THIS USES 'COMPUTED GOTO' GCC required
 */
static inline enum MessageQueueVerificationCodes
_VerifyIntraMessageQueueCommand (MessageQueueMsgPayload *mqp_ptr, MessageQueueMessage 	**mqm_ptr_out, unsigned long call_flags)
{
	enum MessageQueueVerificationCodes resultcode;
	void *command_types [] = {&&session_cmd, &&fence_cmd, &&message_cmd, &&loc_cmd, &&user_cmd, &&call_cmd, &&receipt_cmd, &&sync_cmd, &&sys_cmd}; //ALIGN WITH enum UfsrvCmdTopicIds

	resultcode = _VerifyMessageQueueCommand (mqp_ptr, mqm_ptr_out, call_flags);
	if (resultcode == MSGQUE_SUCCESS) {
		MessageQueueMessage 	*mqm_ptr = *mqm_ptr_out;
		goto *command_types[mqm_ptr->command_type];

		session_cmd:
		if (unlikely(IS_EMPTY(mqm_ptr->session))) {
			syslog(LOG_DEBUG, "%s {pid:'%lu', payload_sz:'%lu'}: ERROR: UNPACKED MessageQueue DID NOT CONTAIN VALID SESSION PAYLOAD DATA", __func__, pthread_self(), mqp_ptr->payload_sz);
			return MSGQUE_EMPTY_WIREDATA;
		}
		return MSGQUE_SUCCESS;

		fence_cmd:
		message_cmd:
		user_cmd:
		call_cmd:
		receipt_cmd:
		sync_cmd:
		//currently this is not applicable for, otherwise valid, SessionMessage commands
		if (unlikely(IS_EMPTY(mqm_ptr->wire_data))) {
				syslog(LOG_DEBUG, "%s {pid:'%lu', payload_sz:'%lu'}: ERROR: UNPACKED MessageQueue DID NOT CONTAIN VALID WIRE PAYLOAD DATA", __func__, pthread_self(), mqp_ptr->payload_sz);
				return MSGQUE_EMPTY_WIREDATA;
		}

		if (unlikely((IS_EMPTY(mqm_ptr->wire_data->ufsrvcommand)))) {
			syslog(LOG_DEBUG, "%s {pid:'%lu', payload_sz:'%lu'}: ERROR: COULD NOT FIND UFSRV COMMAND IN UNPACKED MESAGEQUEUE", __func__, pthread_self(), mqp_ptr->payload_sz);
			return MSGQUE_EMPTY_COMMAND;
		}

		return MSGQUE_SUCCESS;

		loc_cmd:
		sys_cmd:
		return MSGQUE_UNKNOWN_COMMAND;
	}

	return MSGQUE_UNKNOWN_COMMAND;

}

static inline enum MessageQueueVerificationCodes
_VerifyInterMessageQueueCommand (MessageQueueMsgPayload *mqp_ptr, MessageQueueMessage 	**mqm_ptr_out, unsigned long call_flags)
{
	//we now get messagequeuemessage pre-unpacked for INTER broadcasts. Treatment for INTRA IS LSIGHTLY DIFFERENT as that is based on dequeueing staged message

	//enum MessageQueueVerificationCodes resultcode;
	void *command_types [] = {&&session_cmd, &&fence_cmd, &&message_cmd, &&location_cmd, &&user_cmd, &&system_cmd}; //ALIGN WITH enum UfsrvCmdTopicIds

	MessageQueueMessage 	*mqm_ptr = *mqm_ptr_out;
	goto *command_types[mqm_ptr->command_type];

	session_cmd:
	if (unlikely(IS_EMPTY(mqm_ptr->session))) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', payload_sz:'%lu'}: ERROR: UNPACKED MessageQueue DID NOT CONTAIN VALID SESSION PAYLOAD DATA", __func__, pthread_self(), mqp_ptr->payload_sz);
		return MSGQUE_EMPTY_WIREDATA;
	}

	if (unlikely(IS_EMPTY(mqm_ptr->session->header))) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', payload_sz:'%lu'}: ERROR: UNPACKED MessageQueue DID NOT CONTAIN VALID HEADER", __func__, pthread_self(), mqp_ptr->payload_sz);
		return MSGQUE_EMPTY_WIREDATA;
	}
	return MSGQUE_SUCCESS;

	fence_cmd:
	if (unlikely(IS_EMPTY(mqm_ptr->fence))) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', payload_sz:'%lu'}: ERROR: UNPACKED MessageQueue DID NOT CONTAIN VALID FENCE PAYLOAD DATA", __func__, pthread_self(), mqp_ptr->payload_sz);
		return MSGQUE_EMPTY_WIREDATA;
	}

	if (unlikely(IS_EMPTY(mqm_ptr->fence->header))) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', payload_sz:'%lu'}: ERROR: UNPACKED MessageQueue DID NOT CONTAIN VALID HEADER", __func__, pthread_self(), mqp_ptr->payload_sz);
		return MSGQUE_EMPTY_WIREDATA;
	}

	if (unlikely((mqm_ptr->fence->n_fences==0) || IS_EMPTY(mqm_ptr->fence->fences) || IS_EMPTY(mqm_ptr->fence->fences[0]))) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', payload_sz:'%lu', n_fences:'%lu'}: ERROR: COULD NOT FIND FENCE RECORD UNPACKED MESSAGEQUEUE", __func__, pthread_self(), mqp_ptr->payload_sz, mqm_ptr->fence->n_fences);
		return MSGQUE_EMPTY_COMMAND;
	}
	return MSGQUE_SUCCESS;

	message_cmd:
	if (unlikely(IS_EMPTY(mqm_ptr->message))) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', payload_sz:'%lu'}: ERROR: UNPACKED MessageQueue DID NOT CONTAIN VALID MESSAGE PAYLOAD DATA", __func__, pthread_self(), mqp_ptr->payload_sz);
		return MSGQUE_EMPTY_WIREDATA;
	}

	if (unlikely(IS_EMPTY(mqm_ptr->message->header))) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', payload_sz:'%lu'}: ERROR: UNPACKED MessageQueue DID NOT CONTAIN VALID HEADER", __func__, pthread_self(), mqp_ptr->payload_sz);
		return MSGQUE_EMPTY_WIREDATA;
	}

	return MSGQUE_SUCCESS;

	location_cmd:
	if (unlikely(IS_EMPTY(mqm_ptr->location))) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', payload_sz:'%lu'}: ERROR: UNPACKED MessageQueue DID NOT CONTAIN VALID LOCATION PAYLOAD DATA", __func__, pthread_self(), mqp_ptr->payload_sz);
		return MSGQUE_EMPTY_WIREDATA;
	}

	if (unlikely(IS_EMPTY(mqm_ptr->location->header))) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', payload_sz:'%lu'}: ERROR: UNPACKED MessageQueue DID NOT CONTAIN VALID HEADER", __func__, pthread_self(), mqp_ptr->payload_sz);
		return MSGQUE_EMPTY_WIREDATA;
	}

	return MSGQUE_SUCCESS;

	user_cmd:
	return MSGQUE_UNKNOWN_COMMAND;

	system_cmd:
	return MSGQUE_UNKNOWN_COMMAND;

}

/**
 * 	@brief: Default implementation for the verifier. Stops at ufsrvcommand level.
 * 	No targeting checks are performed, because that's now down earlier due to the semantics of the staging queue,
 * 	where messages are fetched FIFO style, which means in some cases, the targeting is overridden if a fetched message
 * 	was originally targeted at a different server (but yet hasn't been processed either due to timing or availability issues),
 * 	this server will still have to process it regardless.
 *
 * 	@dynamic_memory: unpacked message freed else where by the caller
 */
static inline enum MessageQueueVerificationCodes
_VerifyMessageQueueCommand (MessageQueueMsgPayload *mqp_ptr, MessageQueueMessage 	**mqm_ptr_out, unsigned long call_flags)
{
	MessageCommand 				*msgcmd_ptr	= NULL;
	MessageQueueMessage 	*mqm_ptr		= NULL;

	//Ufsrv instance targeting  check is done outside and _VerifyBroadcastTargeting (MessageQueueMessage *mqm_ptr, unsigned long call_flags)

	mqm_ptr = message_queue_message__unpack(NULL, mqp_ptr->payload_sz, mqp_ptr->payload);
	if (unlikely(IS_EMPTY(mqm_ptr))) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', payload_sz:'%lu'}: ERROR: COULD NOT UNPACK MessageQueue Message", __func__, pthread_self(), mqp_ptr->payload_sz);
		return MSGQUE_UNPACK_ERROR;
	}

	//>>>>> IMPORTANT DON'T REORDER NON TARGETING CHECKS BEFORE THIS COMMENT LINE <<<<<<<<<

	if (call_flags&MSGQUEFLAG_CHECK_RECEPIENT_UID) {

	}

	*mqm_ptr_out = mqm_ptr;

	return MSGQUE_SUCCESS;
}

/**
 * 	@brief: Process INTRA transmission for a staged message.
 * 	redis_ptr_staged_message is an array of [1]
 */
static int
_HandleStagedEncodedIntraMessage (redisReply *redis_ptr_staged_message, size_t reqid_target, bool *reqid_target_found)
{
	int 		rc	=	0;
	enum 		UfsrvCmdTopicIds 		command_type;
	char 		*marker,
					*reqid_str;
	size_t	chopped_bits_size;//how much we extracted so far from the staged message
	size_t 	reqid_parsed;
	UFSRVResult res	=	{0};

	if (!(IS_STR_LOADED(redis_ptr_staged_message->element[0]->str)))	goto return_error_empty_redis_string;

	//extract reqid
	marker				=	strchr (redis_ptr_staged_message->element[0]->str, ':');	*marker++ = '\0';
	reqid_parsed	=	strtoul(redis_ptr_staged_message->element[0]->str, NULL, 10);

	chopped_bits_size = strlen(redis_ptr_staged_message->element[0]->str) + 1;//+1 for the overwritten ':'

	//extract command/topic type
	unsigned char *command_type_str = (unsigned char *)strchr (marker, ':');	*command_type_str++ = '\0'; //this now holds the raw command payload in packed protobuffer
	command_type = strtoul(marker, NULL, 10);

	chopped_bits_size += strlen(marker) + 1;//+1 for the overwritten ':'

	//range should be in the upper end (INTER not INTRA) because it is type, not transmission channel
	if (unlikely(command_type > (UFSRV_MAX_BROADCAST_ID - UFSRVCMDID_INTER_INTRA_CONVERSION_FACTOR)))	goto return_error_invalid_commandtype;

	//types are stored in staging with INTER codes so we just pump them up with known fixed factor
	command_type += UFSRVCMDID_INTER_INTRA_CONVERSION_FACTOR;

	MessageQueueMsgPayload 	mqp_staged		=	{.payload=command_type_str, .payload_sz=((size_t)redis_ptr_staged_message->element[0]->len-chopped_bits_size)};
	MessageQueueMessage 		*mqm_ptr_staged	=	NULL;

	rc = ufsrvcmd_broadcasts[command_type].ops.broadcast_verifier(&mqp_staged, &mqm_ptr_staged, ufsrvcmd_broadcasts[command_type].ops.verifier_callflags);
	if (rc == MSGQUE_SUCCESS) {
		rc = ufsrvcmd_broadcasts[command_type].ops.broadcast_handler(mqm_ptr_staged, &res, 0);

		//lucky strike!
		if (reqid_target == reqid_parsed) {
			*reqid_target_found = true;
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s (pid:'%lu', channel_name:'%s', reqid_target:'%lu', reqid_processed:'%lu'): NOTICE: PROCESSED TARGET REQID", __func__,	pthread_self(), ufsrvcmd_broadcasts[command_type].topic_name, reqid_target, reqid_parsed);
#endif
		} else {
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s (pid:'%lu', channel_name:'%s', reqid_target:'%lu', reqid_processed:'%lu'): NOTICE: PROCESSED OTHER REQID", __func__,	pthread_self(), ufsrvcmd_broadcasts[command_type].topic_name, reqid_target, reqid_parsed);
#endif
		}

		message_queue_message__free_unpacked (mqm_ptr_staged, NULL);
		goto return_final;
	}
	else goto return_error_verification;

	return_error_empty_redis_string:
	syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: EMPTY REDIS STRING VALUE...", __func__, pthread_self());
	rc = -5;
	goto return_final;

	return_error_invalid_commandtype:
	syslog(LOG_DEBUG, "%s {pid:'%lu', command_type:'%d'}: ERROR: INVALID COMMAND TYPE...", __func__, pthread_self(), command_type);
	rc = -3;
	goto return_final;

	return_error_verification:
	syslog(LOG_ERR, "%s (pid:'%lu', channel_name:'%s', verification_rc:'%d'): ERROR: COMMAND VERIFICATION ", __func__,	pthread_self(), ufsrvcmd_broadcasts[command_type].topic_name, rc);
	if (IS_PRESENT(mqm_ptr_staged))	message_queue_message__free_unpacked (mqm_ptr_staged, NULL);
	goto return_final;

	return_final:
	return rc;

}

static int
_HandleInterBroadcast (MessageQueueMsgPayload *mqp_ptr, MessageQueueMessage *mqm_ptr)
{
	int						rc					=	0;
	long long 		timer_start	= GetTimeNowInMicros(),
								timer_end;
	UFSRVResult 	res					=	{0};

	rc = ufsrvcmd_broadcasts[mqm_ptr->command_type].ops.broadcast_verifier(mqp_ptr, &mqm_ptr, ufsrvcmd_broadcasts[mqm_ptr->command_type].ops.verifier_callflags);
	if (rc == MSGQUE_SUCCESS) {
		rc = ufsrvcmd_broadcasts[mqm_ptr->command_type].ops.broadcast_handler(mqm_ptr, &res, 0);
	}
	DestructMessageQueueMsgPayload(mqp_ptr, mqm_ptr, false);//object gets freed in

	timer_end = GetTimeNowInMicros();
	statsd_timing(pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_instrumentation_backend_key), "delegator.ufsrv.job.msgqueue.inter_broadcast_handler.elapsed_time", (timer_end-timer_start));

	return rc;

}

__attribute__((const)) MessageContextData *
WorkerThreadMessageQueueParserExtractArg (MessageQueueMsgPayload *msgqueue_payload_ptr)
{
	return ((ClientContextData *)msgqueue_payload_ptr);
}

/*
 * 	@brief: Main interface method for dispatching INCOMING MessageQueue broadcasts to respective handlers.
 * 	These broadcasts could be INTER or INTRA. Generally invoked from within a worker thread, eg. ufsrv worker.
 * 	MessageQueueMsgPayload is a local envelope constructed by the local MessageQueue Bus delegator as it listens for incoming
 * 	INTRA/INTER broadcasts and dispatches that to local workers. The envelope contents for INTRA is different from INTER. Invariably, the payload is enveloped
 * 	in 'MessageQueueMessage' which is the interchange format between broadcasters/receivers.
 *
 * 	Intra broadcasts have server target specified in them, which is loadbalanced by the broadcaster (ufsrvapi), not necessarily reflecting the server
 * 	instance which user has websock connection with. This allows other workers to back off.
 */
int WorkerThreadMsgQueueParserExecutor (MessageContextData *context_ptr)
{
	int 				rc = 0;
	enum MessageQueueVerificationCodes verify_return_code;
	UFSRVResult 				res				=	{0};
	MessageQueueMsgPayload *mqp_ptr	=	(MessageQueueMsgPayload *)context_ptr;
	MessageQueueMessage *mqm_ptr 	= NULL;

	if (unlikely((strcmp(mqp_ptr->verb, "message") != 0))) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', verb:'%s'}: UNKNOWN VERB: IGNORING.", __func__,pthread_self(), mqp_ptr->verb);

		goto return_final_no_timing;//could we still peek at the queue?
	}

	//unbolt it to get necessary meta data.. bit of double handling for INTRA message, because the same message is unpacked off the back of the staging
	mqm_ptr = message_queue_message__unpack(NULL, mqp_ptr->payload_sz, mqp_ptr->payload);
	if (unlikely(IS_EMPTY(mqm_ptr)))	goto return_error_upack_msgqueue;

	if (unlikely((mqm_ptr->command_type < 0) || (mqm_ptr->command_type > UFSRVCMDID_INTER_INTRA_CONVERSION_FACTOR - 1)))	goto return_error_wrong_command;

	inter_handler_block:
	if (mqm_ptr->has_broadcast_semantics &&
			(mqm_ptr->broadcast_semantics == MESSAGE_QUEUE_MESSAGE__BROADCAST_SEMANTICS__INTER)) {

		if ((_VerifyBroadcastTargeting(mqm_ptr, ufsrvcmd_broadcasts[mqm_ptr->command_type].ops.verifier_callflags)) != MSGQUE_SUCCESS)	goto return_final_no_timing;

		return (_HandleInterBroadcast(mqp_ptr, mqm_ptr));
	}

	intra_handler_block:
	if ((_VerifyBroadcastTargeting(mqm_ptr, ufsrvcmd_broadcasts[mqm_ptr->command_type + UFSRVCMDID_INTER_INTRA_CONVERSION_FACTOR].ops.verifier_callflags)) != MSGQUE_SUCCESS)	goto return_final_no_timing;

	long long 		timer_start	= GetTimeNowInMicros(),
								timer_end;

	bool 										reqid_target_found		=	false;
	size_t									processing_iterations	=	0;
	UfsrvInstanceDescriptor ufsrv_instance 				= {	.server_class			=	masterptr->server_class,
																										.ufsrv_geogroup		=	masterptr->ufsrv_geogroup,
																										.serverid					=	masterptr->serverid,
																										.serverid_by_user	=	masterptr->serverid_by_user,
																										.reqid						=	0//mqm_ptr->ufsrv_req_id
																									};
	InstanceHolderForSession 		*instance_sesn_ptr_carrier									=	InstantiateCarrierSession(NULL, WORKERTYPE_UFSRVWORKER, SESSION_CALLFLAGS_EMPTY);
	Session *sesn_ptr_carrier = SessionOffInstanceHolder(instance_sesn_ptr_carrier);
	redisReply 	*redis_ptr_staged_message					=	NULL;

	do {
		processing_iterations++;
		GetRemStagedMessageCacheRecordForIntraCommand (sesn_ptr_carrier,
																									 &((IncomingMessageDescriptor){.instance_descriptor_ptr=&ufsrv_instance}),
																									 NULL,
																									 MSGOPT_GET_REM_FIRST);

		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr_carrier)) {
			redis_ptr_staged_message = (redisReply *)SESSION_RESULT_USERDATA(sesn_ptr_carrier);
			if (unlikely(IS_EMPTY(redis_ptr_staged_message)))	goto return_empty_redis_reply; //this is no good? did we process the msg already

			//idx '0' is the array slot where the result of the 'GET' command is stored
			if ((redis_ptr_staged_message->element[0]->elements == 1) && IS_PRESENT(redis_ptr_staged_message->element[0]->element[0]->str)) {
				rc = _HandleStagedEncodedIntraMessage (redis_ptr_staged_message->element[0], mqm_ptr->ufsrv_req_id, &reqid_target_found);
				if (reqid_target_found) {
					goto return_deallocate_redis_reply;
				}

				freeReplyObject (redis_ptr_staged_message); redis_ptr_staged_message=NULL;
				//continue processing 'return_no_target_reqid' will catch target reqid was not found

			} else {
				//this poses a problem, because we dont know if this was our target reqid. So if we continue past it and there were many msgs in the queue
				//this thread will be taken up for far too long. Could also mean no more messages in the queue

				goto return_invalid_redis_reply;
			}
		}
		else	goto return_no_target_reqid;
	}
	while (true);

	//this will also catch intances where we processed some but did not hit target reqid
	return_no_target_reqid:
	if (!reqid_target_found)	syslog(LOG_ERR, "%s (pid:'%lu', channel_name:'%s', reqid_target:'%lu', iterations:'%lu'): NOTICE: COULD NOT FIND CORRESPONDING STORED STAGED MESSAGE", __func__,	pthread_self(), mqp_ptr->topic, mqm_ptr->ufsrv_req_id, processing_iterations);
	rc  = 0;
	goto return_empheral_session;

	return_error_upack_msgqueue:
	syslog(LOG_DEBUG, "%s {pid:'%lu', payload_sz:'%lu'}: ERROR: COULD NOT UNPACK MessageQueue Message", __func__, pthread_self(), mqp_ptr->payload_sz);
	rc = -2;
	goto return_final_no_timing;

	return_error_wrong_command:
	syslog(LOG_DEBUG, "%s {pid:'%lu', payload_sz:'%lu', command_type:'%d'}: ERROR: WRONG COMMAND TYPE", __func__, pthread_self(), mqp_ptr->payload_sz, mqm_ptr->command_type);
	rc = -3;
	goto return_final_no_timing;

	return_empty_redis_reply:
	syslog(LOG_ERR, "%s (pid:'%lu', channle_name:'%s', iteration:'%lu'): ERROR: REDIS REPLY EMPTY ", __func__,	pthread_self(), mqp_ptr->topic, processing_iterations);
	rc = -6;
	goto return_empheral_session;

	return_invalid_redis_reply:
	syslog(LOG_ERR, "%s (pid:'%lu', channle_name:'%s', iteration:'%lu'): ERROR: INVALID REDIS REPLY ", __func__,	pthread_self(), mqp_ptr->topic, processing_iterations);
	rc = -5;
	goto return_deallocate_redis_reply;

	return_deallocate_redis_reply:
	freeReplyObject (redis_ptr_staged_message);
	goto return_empheral_session;

	return_empheral_session:
	SessionReturnToRecycler (instance_sesn_ptr_carrier, NULL, 0);
	goto return_final;

	return_final_no_timing:
	DestructMessageQueueMsgPayload(mqp_ptr, mqm_ptr, false);//object gets freed in
	return rc;

	return_final:
	DestructMessageQueueMsgPayload(mqp_ptr, mqm_ptr, false);//object gets freed in
	timer_end = GetTimeNowInMicros();
	statsd_timing(pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_instrumentation_backend_key), "delegator.ufsrv.job.msgqueue.intra_broadcast_handler.elapsed_time", (timer_end-timer_start));
	return rc;

}

UfsrvCommandBroadcast *
GetBroadcastDescriptorByName (const char *topic)
{

	for (size_t i=0; i<UFSRV_MAX_BROADCAST_ID; i++)
	{
		//TODO: OPTIMISE:; use pre-computed hashes and build a symbol table

		if((strcmp(topic, ufsrvcmd_broadcasts[i].topic_name)==0))
		{
			return &ufsrvcmd_broadcasts[i];
		}
	}

	return &ufsrvcmd_broadcasts[UFSRV_MAX_BROADCAST_ID];

}

UfsrvCommandBroadcast *
GetBroadcastDescriptorByTopicId (enum UfsrvCmdTopicIds topic_id)
{
	if (topic_id<0 || topic_id>UFSRV_MAX_BROADCAST_ID-1)	return NULL;

	return &ufsrvcmd_broadcasts[topic_id];

}

/**
 * 	@brief: Main interface method for packaging/dispatching INTER broadcasts, previously fully formatted as
 * 	MessageQueueMessage message.
 * 	Typically invoked by handlers.
 */
UFSRVResult *
UfsrvInterBroadcastMessage (Session *sesn_ptr, MessageQueueMessage *msgqqueue_ptr, unsigned event_type)
{
	msgqqueue_ptr->origin							=	masterptr->serverid;

	UFSRVResult 					*res_ptr		=	NULL;
	MessageQueueBackend 	*mq_ptr			=	sesn_ptr->msgqueue_backend;
	redisReply 						*redis_ptr	=	NULL;

	size_t packed_sz = message_queue_message__get_packed_size(msgqqueue_ptr);
	uint8_t packed_msg[packed_sz];
	message_queue_message__pack (msgqqueue_ptr, packed_msg);

	switch (msgqqueue_ptr->command_type)
	{
		case UFSRV_FENCE:
			redis_ptr = (*mq_ptr->send_command)(sesn_ptr, REDIS_CMD_FENCE_PUBLISH_INTERMSG_P, packed_msg, packed_sz);
			break;

		case UFSRV_MSG:
			redis_ptr = (*mq_ptr->send_command)(sesn_ptr, REDIS_CMD_MSG_PUBLISH_INTERMSG_P, packed_msg, packed_sz);
			break;

		case UFSRV_SESSION:
			redis_ptr = (*mq_ptr->send_command)(sesn_ptr, REDIS_CMD_SESSION_PUBLISH_INTERMSG_P, packed_msg, packed_sz);
			break;

		case UFSRV_LOC:
			redis_ptr = (*mq_ptr->send_command)(sesn_ptr, REDIS_CMD_LOCATION_PUBLISH_INTERMSG_P, packed_msg, packed_sz);
			break;

		case UFSRV_USER:
			redis_ptr = (*mq_ptr->send_command)(sesn_ptr, REDIS_CMD_USER_PUBLISH_INTERMSG_P, packed_msg, packed_sz);
			break;

		case UFSRV_RECEIPT:
			redis_ptr = (*mq_ptr->send_command)(sesn_ptr, REDIS_CMD_RECEIPT_PUBLISH_INTERMSG_P, packed_msg, packed_sz);
			break;

		case UFSRV_SYNC:
			redis_ptr = (*mq_ptr->send_command)(sesn_ptr, REDIS_CMD_SYNC_PUBLISH_INTERMSG_P, packed_msg, packed_sz);
			break;

		case UFSRV_SYS:
		default:
				break;
	}

	if (IS_PRESENT(redis_ptr)) {
		if (unlikely((redis_ptr->type == REDIS_REPLY_ERROR))) {
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', origin:'%d', uname:'%s', error:'%s'}: ERROR: COULD NOT INTRA-PUBLISH MESSAGE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), masterptr->serverid, SESSION_USERNAME(sesn_ptr), redis_ptr->str);
			freeReplyObject(redis_ptr);

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
		}

		freeReplyObject(redis_ptr);
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
}

/**
 * 	@brief: Generic implementation that preloads session associated with the given incoming INTER broadcast.
 * 	@param res_ptr:	Must be allocated by user for status passing
 * 	@locks Session *: if found. Also, sessio loaded in ephemeral mode
 *
 */
UFSRVResult *
PrepareForInterBroadcastHandling (MessageQueueMessage *mqm_ptrr, CommandHeader *cmd_header_ptr, ClientContextData *context_ptr, UFSRVResult *res_ptr, int command, bool flag_local_only)
{
	Session 		*sesn_ptr_localuser;
  InstanceHolderForSession *instance_sesn_ptr_localuser;

	if (cmd_header_ptr->cid == 0)	goto return_no_session_defined;

	if (IS_PRESENT((instance_sesn_ptr_localuser = LocallyLocateSessionById(cmd_header_ptr->cid)))) {
	  sesn_ptr_localuser = SessionOffInstanceHolder(instance_sesn_ptr_localuser);

		SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_localuser, _LOCK_TRY_FLAG_FALSE, __func__);
		if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR)) {
			_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOGIC_CANTLOCK)
		}

		__unused bool lock_already_owned = (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_BY_THIS_THREAD));

		//SESSION locked
		//TODO: LOST SESSION LOCK STATE
		SESSION_WHEN_SERVICE_STARTED(sesn_ptr_localuser) = time(NULL);
		SessionLoadEphemeralMode(sesn_ptr_localuser);

		_RETURN_RESULT_RES(res_ptr, sesn_ptr_localuser, RESULT_TYPE_SUCCESS, RESCODE_USER_SESN_LOCAL)
	}

	if (IS_TRUE(flag_local_only))	goto 	return_no_local_session_found;

#define SESSION_CALL_FLAGS (CALL_FLAG_LOCK_SESSION|CALL_FLAG_HASH_SESSION_LOCALLY|					\
												CALL_FLAG_HASH_UID_LOCALLY|CALL_FLAG_HASH_USERNAME_LOCALLY|			\
												CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION|CALL_FLAG_REMOTE_SESSION)

	//given NULL session, load backend context from ufsrvworker's
  unsigned  long uid = UfsrvUidGetSequenceId((const UfsrvUid *) cmd_header_ptr->ufsrvuid.data);
	if (IS_PRESENT((instance_sesn_ptr_localuser = SessionInstantiateFromBackend(NULL, uid, SESSION_CALL_FLAGS)))) {
	  sesn_ptr_localuser = SessionOffInstanceHolder(instance_sesn_ptr_localuser);

		SESSION_WHEN_SERVICE_STARTED(sesn_ptr_localuser) = time(NULL);
		SessionLoadEphemeralMode(sesn_ptr_localuser);
		//SESSION locked
		_RETURN_RESULT_RES(res_ptr, sesn_ptr_localuser, RESULT_TYPE_SUCCESS, RESCODE_USER_SESN_LOCAL)
	}
	else goto return_error;

	return_no_session_defined:
	syslog(LOG_ERR, "%s {pid:'%lu'}: ERROR: HEADER COMMAND DID NOT INCLUDE A SESSION ID", __func__, pthread_self());
	goto return_error;

	return_no_local_session_found:
	goto return_error;

	return_error:
	_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_USER_SESN_LOCAL)

}
