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
#include <ufsrv_core/user/user_preferences.h>
#include <ufsrv_core/user/user_backend.h>
#include <ufsrv_core/user/users_protobuf.h>
#include <ufsrv_core/location/location.h>
#include <share_list.h>
#include <ufsrv_core/cache_backend/persistance.h>
#include <misc.h>
#include <net.h>
#include <nportredird.h>
#include <ufsrvwebsock/include/protocol_websocket_session.h>
#include <protocol_http.h>
#include <session_broadcast.h>
#include <sessions_delegator_type.h>
#include <ufsrv_core/msgqueue_backend/ufsrvcmd_broadcast.h>
#include <ufsrv_core/msgqueue_backend/UfsrvMessageQueue.pb-c.h>
#include <ufsrvuid.h>

#include <hiredis.h>

/**
 * 	@brief: Main interface method for broadcasting backend data model state change for Fence display name attribute.
 * 	@
 */

struct BroadcastMessageEnvelopeForSession {
	MessageQueueMessage 			*msgqueue_msg;
	FenceCommand 							*fence_command;
	SessionMessage						*session_message;
	SessionMessage__GeoFence	*session_messasage_geo;
	CommandHeader 						*header;
	FenceRecord								*fence_record;
	FenceRecord 							**fence_records;
};

typedef struct BroadcastMessageEnvelopeForSession BroadcastMessageEnvelopeForSession;

extern SessionsDelegator *const sessions_delegator_ptr;
extern __thread ThreadContext ufsrv_thread_context;

inline static void _PrepareInterBroadcastMessageForSession (BroadcastMessageEnvelopeForSession *envelope_ptr, Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg);
static UFSRVResult *_HandleInterBroadcastSessionStatus (MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr);
static UFSRVResult *_HandleInterBroadcastSessionConnected (MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr);
static UFSRVResult *_HandleInterBroadcastSessionSuspended (MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr);
static UFSRVResult *_HandleInterBroadcastSessionQuit (MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr);
static UFSRVResult *_HandleInterBroadcastSessionPreference (MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr);
static UFSRVResult *_HandleInterBroadcastSessionGeofenced (MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr);
static UFSRVResult *_HandleInterBroadcastSessionRebooted (MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr);
static inline UFSRVResult *_HandleIntraBroadcastForSession (InstanceHolderForSession *instance_sesn_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr);

//TODO: needs updating

#define _GENERATE_ENVELOPE_INITIALISATION() \
	MessageQueueMessage 			msgqueue_msg					=	MESSAGE_QUEUE_MESSAGE__INIT;	\
	FenceCommand 							fence_command					=	FENCE_COMMAND__INIT;	\
	CommandHeader 						header								=	COMMAND_HEADER__INIT;	\
	SessionMessage 						msgqueue_sesn_msg			=	SESSION_MESSAGE__INIT;	\
	SessionMessage__GeoFence	msgqueue_sesn_msg_geo	=	SESSION_MESSAGE__GEO_FENCE__INIT;	\
	\
	BroadcastMessageEnvelopeForSession	envelope_broadcast = {	\
				.msgqueue_msg				=	&msgqueue_msg,	\
				.fence_command			=	&fence_command,	\
				.header							=	&header,	\
				.fence_record				=	&fence_record,	\
				.fence_records			=	fence_records,	\
				.session_message		=	&msgqueue_sesn_msg,	\
				.session_messasage_geo	=	&msgqueue_sesn_msg_geo\
	}

#define _GENERATE_ENVELOPE_INITIALISATION_FOR_SESSION_STATUS() \
	MessageQueueMessage 			msgqueue_msg					=	MESSAGE_QUEUE_MESSAGE__INIT;	\
	CommandHeader 						header								=	COMMAND_HEADER__INIT;	\
	SessionMessage 						msgqueue_sesn_msg			=	SESSION_MESSAGE__INIT;	\
	\
	BroadcastMessageEnvelopeForSession	envelope_broadcast = {	\
				.msgqueue_msg				=	&msgqueue_msg,	\
				.header							=	&header,	\
				.session_message		=	&msgqueue_sesn_msg,	\
	}

//// INTER \\\\

/**
 * 	@WARNING: don't make too much assumptions around the completeness of the passed sesn_ptr, as it could be be mock one. Let the caller put
 * 	in more specific contextual stuff.
 */
inline static void
_PrepareInterBroadcastMessageForSession (BroadcastMessageEnvelopeForSession *envelope_ptr, Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg)
{
	envelope_ptr->msgqueue_msg->command_type					=	UFSRV_SESSION;	envelope_ptr->msgqueue_msg->has_command_type=1;
	envelope_ptr->msgqueue_msg->broadcast_semantics	=	MESSAGE_QUEUE_MESSAGE__BROADCAST_SEMANTICS__INTER; envelope_ptr->msgqueue_msg->has_broadcast_semantics	=1;
	envelope_ptr->msgqueue_msg->session								=	envelope_ptr->session_message;
	envelope_ptr->msgqueue_msg->session->header				=	envelope_ptr->header;
	envelope_ptr->msgqueue_msg->session->geo_fence		=	envelope_ptr->session_messasage_geo;

	envelope_ptr->header->args												=	command_arg;

	if (IS_PRESENT(event_ptr))
	{
		envelope_ptr->header->eid													=	event_ptr->eid; 					envelope_ptr->header->has_eid=1;
		envelope_ptr->header->when												=	event_ptr->when; 					envelope_ptr->header->has_when=1;
	}
	else
	{	envelope_ptr->header->when												=	GetTimeNowInMillis(); 	envelope_ptr->header->has_when=1;}

	envelope_ptr->header->cid													=	SESSION_ID(sesn_ptr); 		envelope_ptr->header->has_cid=1;
	MakeUfsrvUidInProto(&(SESSION_UFSRVUIDSTORE(sesn_ptr)), &(envelope_ptr->header->ufsrvuid), true); envelope_ptr->header->has_ufsrvuid=1;

}

/**
 * 	@brief: Main interface to INTER broadcast reassignment of user's current geofence.
 * 	@fence_event: None. This is a user session attribute. A join fence event would have triggered separately.
 */
UFSRVResult *
InterBroadcastSessionGeoFenced (Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg)
{

	MessageQueueMessage 			msgqueue_msg					=	MESSAGE_QUEUE_MESSAGE__INIT;
	CommandHeader							header								=	COMMAND_HEADER__INIT;
	SessionMessage 						msgqueue_sesn_msg			=	SESSION_MESSAGE__INIT;
	SessionMessage__GeoFence	msgqueue_sesn_msg_geo	=	SESSION_MESSAGE__GEO_FENCE__INIT;

	Fence *f_ptr_current,
				*f_ptr_past;

	f_ptr_current		=	(Fence *)((ContextDataPair *)context_ptr)->first;
	f_ptr_past			=	(Fence *)((ContextDataPair *)context_ptr)->second;

	BroadcastMessageEnvelopeForSession	envelope = {
				.msgqueue_msg						=	&msgqueue_msg,
				.fence_command					=	NULL,
				.session_message				=	&msgqueue_sesn_msg,
				.session_messasage_geo	=	&msgqueue_sesn_msg_geo,
				.header									=	&header,
				.fence_record						=	NULL,
				.fence_records					=	NULL
  };

	_PrepareInterBroadcastMessageForSession (&envelope, sesn_ptr, context_ptr, event_ptr, command_arg);

	//_GENERATE_ENVELOPE_INITIALISATION(); //replaces above

  MakeUfsrvUidInProto(&SESSION_UFSRVUIDSTORE(sesn_ptr), &(msgqueue_msg.ufsrvuid), true);
  msgqueue_msg.has_ufsrvuid = 1;
	msgqueue_sesn_msg.status					=	SESSION_MESSAGE__STATUS__GEOFENCED;

	//actual delta
	if (IS_PRESENT(f_ptr_current))	msgqueue_sesn_msg_geo.geofence_current=FENCE_ID(f_ptr_current);
	if (IS_PRESENT(f_ptr_past))			msgqueue_sesn_msg_geo.geofence_past		=FENCE_ID(f_ptr_past);

	return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg, msgqueue_msg.command_type));
}

UFSRVResult *
InterBroadcastSessionStatus (Session *sesn_ptr, ClientContextData *context_ptr, enum _SessionMessage__Status sesn_status, enum _CommandArgs command_arg)
{
	_GENERATE_ENVELOPE_INITIALISATION_FOR_SESSION_STATUS();

	_PrepareInterBroadcastMessageForSession (&envelope_broadcast, sesn_ptr, context_ptr, NULL, command_arg);

	msgqueue_msg.session->status			=	sesn_status;

	return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg, msgqueue_msg.command_type));
}

/**
 * 	@brief: Slight specialisation of the standard InterBroadcastSessionStatus, as we package more data into the message, which means
 * 	recipients won't ned to load from cache backend.
 */
UFSRVResult *
InterBroadcastSessionStatusRebooted (Session *sesn_ptr, ClientContextData *context_ptr, enum _SessionMessage__Status sesn_status, enum _CommandArgs command_arg)
{
	Session *sesn_ptr_rebooted 					=	(Session *)(context_ptr);	//could be the same reference as sesn_ptr

	_GENERATE_ENVELOPE_INITIALISATION_FOR_SESSION_STATUS();

	UserPreference user_pref_nick				=	USER_PREFERENCE__INIT;
	UserPreference *user_prefs[1];
	user_prefs[0]												=	&user_pref_nick;
	msgqueue_sesn_msg.prefs							=	user_prefs;
	msgqueue_sesn_msg.n_prefs							=	1;

	_PrepareInterBroadcastMessageForSession (&envelope_broadcast, sesn_ptr_rebooted, context_ptr, NULL, command_arg);

	msgqueue_msg.session->status			=	sesn_status;
	header.cookie											=	SESSION_COOKIE(sesn_ptr_rebooted);
	user_pref_nick.pref_id						=	USER_PREFS__NICKNAME;
	user_pref_nick.type								= PREFERENCE_TYPE__STR;
	user_pref_nick.values_str					=	SESSION_USERNICKNAME(sesn_ptr_rebooted);

	return (UfsrvInterBroadcastMessage(sesn_ptr, &msgqueue_msg, msgqueue_msg.command_type));
}

/**
 * 	@brief: TODO: TO BE PORTED TO PROTOBUF.
 */
int
HandleInterBroadcastForSession (MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	int 										rescode __unused;

	_HandleInterBroadcastSessionStatus (mqm_ptr, res_ptr);

	if (_RESULT_TYPE_SUCCESS(res_ptr))	goto return_success;

	return_error:
	return -1;

	return_success:
	return 0;

}

/**
 * 	@brief: Main handler for Session message command. This is designed to work from with ufsrvworker context. Whatever Session is loaded
 * 	within this context muts be setup in Ephemeral mode with SessionLoadEphemeralMode(sesn_ptr);
 */
static UFSRVResult *
_HandleInterBroadcastSessionStatus (MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr)
{
	switch (mqm_ptr->session->status)
	{
		case	SESSION_MESSAGE__STATUS__CONNECTED:
			return (_HandleInterBroadcastSessionConnected(mqm_ptr, res_ptr));

		case 	SESSION_MESSAGE__STATUS__SUSPENDED:
			return (_HandleInterBroadcastSessionSuspended(mqm_ptr, res_ptr));

		case  SESSION_MESSAGE__STATUS__QUIT:
			return (_HandleInterBroadcastSessionQuit(mqm_ptr, res_ptr));

		case  SESSION_MESSAGE__STATUS__HEARTBEAT:
		case 	SESSION_MESSAGE__STATUS__PREFERENCE:
			return (_HandleInterBroadcastSessionPreference (mqm_ptr, res_ptr));

		case 	SESSION_MESSAGE__STATUS__GEOFENCED:
			return (_HandleInterBroadcastSessionGeofenced (mqm_ptr, res_ptr));

		case SESSION_MESSAGE__STATUS__REBOOTED:
			return (_HandleInterBroadcastSessionRebooted(mqm_ptr, res_ptr));

		default:
			syslog(LOG_DEBUG, "%s {pid:'%lu', status:'%d'}: ERROR: UNKNOWN SESSION STATUS MESSAGE COMMAND", __func__, pthread_self(), mqm_ptr->session->status);

	}

	return res_ptr;
}

/*
 * 	@brief: Session is connected remotely with other server instance
 */
static UFSRVResult *
_HandleInterBroadcastSessionConnected (MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr)
{
	Session *sesn_ptr_localuser = NULL;
	InstanceHolderForSession *instance_sesn_ptr_localuser;

	if ((instance_sesn_ptr_localuser = LocallyLocateSessionById(mqm_ptr->session->target_session))) {
    sesn_ptr_localuser = SessionOffInstanceHolder(instance_sesn_ptr_localuser);

		SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_localuser, _LOCK_TRY_FLAG_FALSE, __func__);
		if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR)) {
			_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOGIC_CANTLOCK)
		}
		bool lock_already_owned = (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_BY_THIS_THREAD));

		SESSION_WHEN_SERVICE_STARTED(sesn_ptr_localuser) = time(NULL);
		//note no need to load session with EphemeralMode as we are not changing any backend state
		SESNSTATUS_SET(sesn_ptr_localuser->stat, SESNSTATUS_REMOTE_CONNECTED);
		SESNSTATUS_SET(sesn_ptr_localuser->stat, SESNSTATUS_REMOTE);
		SESNSTATUS_UNSET(sesn_ptr_localuser->stat, SESNSTATUS_CONNECTED);
		SESNSTATUS_UNSET(sesn_ptr_localuser->stat, SESNSTATUS_SUSPENDED);
		SESSION_WHEN_SERVICED(sesn_ptr_localuser) = time(NULL);
		if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_localuser, __func__);

		_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_USER_SESN_LOCAL)
	}

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s {pid:'%lu', cid_msgqueue:'%lu', status:'%d'}: NOTICE: SESSION IS NOT LOCAL...", __func__, pthread_self(), mqm_ptr->session->target_session, mqm_ptr->session->status);
#endif

	_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_USER_SESN_LOCAL)

}

static UFSRVResult *
_HandleInterBroadcastSessionSuspended (MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr)
{
	Session *sesn_ptr_localuser = NULL;
  InstanceHolderForSession *instance_sesn_ptr_localuser;

	if ((instance_sesn_ptr_localuser = LocallyLocateSessionById(mqm_ptr->session->target_session))) {
	  sesn_ptr_localuser = SessionOffInstanceHolder(instance_sesn_ptr_localuser);

		SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_localuser, _LOCK_TRY_FLAG_FALSE, __func__);
		if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR)) {
			_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOGIC_CANTLOCK)
		}

		bool lock_already_owned = (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_BY_THIS_THREAD));

		SESSION_WHEN_SERVICE_STARTED(sesn_ptr_localuser) = time(NULL);
		//note no need to load session with EphemeralMode as we are not changing any backend state
		SESNSTATUS_UNSET(sesn_ptr_localuser->stat, SESNSTATUS_REMOTE_CONNECTED);
		SESNSTATUS_SET(sesn_ptr_localuser->stat, SESNSTATUS_REMOTE);
		SESNSTATUS_UNSET(sesn_ptr_localuser->stat, SESNSTATUS_CONNECTED);
		SESNSTATUS_SET(sesn_ptr_localuser->stat, SESNSTATUS_SUSPENDED);
		SESSION_WHEN_SERVICED(sesn_ptr_localuser) = time(NULL);

		if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_localuser, __func__);

		_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_USER_SESN_LOCAL)
	}

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s {pid:'%lu', cid_msgqueue:'%lu', status:'%d'}: NOTICE: SESSION IS NOT LOCAL...", __func__, pthread_self(), mqm_ptr->session->target_session, mqm_ptr->session->status);
#endif

	_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_USER_SESN_LOCAL)

}

static UFSRVResult *
_HandleInterBroadcastSessionQuit (MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr)
{
	Session *sesn_ptr_localuser = NULL;
  InstanceHolderForSession *instance_sesn_ptr_localuser;

	if ((instance_sesn_ptr_localuser = LocallyLocateSessionById(mqm_ptr->session->target_session))) {
	  sesn_ptr_localuser = SessionOffInstanceHolder(instance_sesn_ptr_localuser);

		SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_localuser, _LOCK_TRY_FLAG_FALSE, __func__);
		if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR)) {
			_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOGIC_CANTLOCK)
		}

		bool lock_already_owned = (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_BY_THIS_THREAD));

		SESSION_WHEN_SERVICE_STARTED(sesn_ptr_localuser) = time(NULL);
		//note no need to load session with EphemeralMode as we are not changing any backend state
		SESNSTATUS_UNSET(sesn_ptr_localuser->stat, SESNSTATUS_REMOTE_CONNECTED);
		SESNSTATUS_SET(sesn_ptr_localuser->stat, SESNSTATUS_REMOTE);
		SESNSTATUS_UNSET(sesn_ptr_localuser->stat, SESNSTATUS_CONNECTED);
		SESNSTATUS_SET(sesn_ptr_localuser->stat, SESNSTATUS_QUIT);
		SESSION_WHEN_SERVICED(sesn_ptr_localuser) = time(NULL);
		if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_localuser, __func__);

		_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_USER_SESN_LOCAL)
	}

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s {pid:'%lu', cid_msgqueue:'%lu', status:'%d'}: NOTICE: SESSION IS NOT LOCAL...", __func__, pthread_self(), mqm_ptr->session->target_session, mqm_ptr->session->status);
#endif

	_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_USER_SESN_LOCAL)

}

/**
 * 	@brief: Main processor for pref changes communicated over the msgbus. At the moment it only handle one pref.
 */
static UFSRVResult *
_HandleInterBroadcastSessionPreference (MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr)
{
	Session *sesn_ptr_localuser = NULL;
  InstanceHolderForSession *instance_sesn_ptr_localuser;

	if (mqm_ptr->session->n_prefs == 0) {
		syslog(LOG_ERR, "%s {pid:'%lu', cid_msgqueue:'%lu', uid_msgqueue:'%lu'}: ERROR: NO PREFERENCES INCLUDED IN SESSION MSG", __func__, pthread_self(), mqm_ptr->session->target_session, UfsrvUidGetSequenceId((const UfsrvUid *)mqm_ptr->session->header->ufsrvuid.data));
		_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_MISSING_PARAM)
	}

	if ((instance_sesn_ptr_localuser = LocallyLocateSessionById(mqm_ptr->session->target_session))) {
    sesn_ptr_localuser = SessionOffInstanceHolder(instance_sesn_ptr_localuser);

		SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_localuser, _LOCK_TRY_FLAG_FALSE, __func__);
		if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR)) {
			_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOGIC_CANTLOCK)
		}
		bool lock_already_owned = (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_BY_THIS_THREAD));

		SESSION_WHEN_SERVICE_STARTED(sesn_ptr_localuser) = time(NULL);

		//static storage to capture the copying of information from SessionMessage to UserPreference
		UserPreferenceDescriptor				user_prefs_pool[mqm_ptr->session->n_prefs];
		UserPreferenceDescriptor				*user_prefs_ptr[mqm_ptr->session->n_prefs];
		for (size_t i=0; i<mqm_ptr->session->n_prefs; i++)	user_prefs_ptr[i] = (UserPreferenceDescriptor *)(user_prefs_pool + (i * sizeof(UserPreferenceDescriptor)));
		CollectionDescriptor						collection_prefs_result = {(collection_t **)user_prefs_ptr, mqm_ptr->session->n_prefs};

		SessionLoadEphemeralMode(sesn_ptr_localuser);
		LoadUserPreferenceBySessionMessageProto (mqm_ptr, &collection_prefs_result);

		//this is temporary, the entire collection must be considered not just the first element collection
		UfsrvEvent 				event = {0};
		SetUserPreferenceByDescriptor (sesn_ptr_localuser, (UserPreferenceDescriptor *)collection_prefs_result.collection[0], &event);

		SESSION_WHEN_SERVICED(sesn_ptr_localuser) = time(NULL);
		SessionUnLoadEphemeralMode(sesn_ptr_localuser);
		if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_localuser, __func__);

		_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_USER_SESN_LOCAL)
	}

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s {pid:'%lu', cid_msgqueue:'%lu', status:'%d'}: NOTICE: SESSION IS NOT LOCAL...", __func__, pthread_self(), mqm_ptr->session->target_session, mqm_ptr->session->status);
#endif

	_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_USER_SESN_LOCAL)

}

/**
 * 	@brief: Helper routine to processes inter-message command with user's change in geo-fence configuration.
 * 	@locks Session *: retrieved session
 * 	@unlocks Session *; previously retrieved Session
 */
static UFSRVResult *
_HandleInterBroadcastSessionGeofenced (MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr)
{
	Session *sesn_ptr_localuser = NULL;
  InstanceHolderForSession *instance_sesn_ptr_localuser;

	if ((instance_sesn_ptr_localuser = LocallyLocateSessionById(mqm_ptr->session->target_session))) {
    sesn_ptr_localuser = SessionOffInstanceHolder(instance_sesn_ptr_localuser);

    SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_localuser, _LOCK_TRY_FLAG_FALSE, __func__);
    if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR)) {
      _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOGIC_CANTLOCK);
    }
    bool lock_already_owned = (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_BY_THIS_THREAD));

    SESSION_WHEN_SERVICE_STARTED(sesn_ptr_localuser) = time(NULL);
    SessionLoadEphemeralMode(sesn_ptr_localuser);

    InstanceHolderForFence  *instance_f_ptr_current	=	NULL,
                            *instance_f_ptr_past		=	NULL;

    //not locking
    if (mqm_ptr->session->geo_fence->has_geofence_current) {
      FindFenceById(sesn_ptr_localuser, mqm_ptr->session->geo_fence->geofence_current, 0);
      instance_f_ptr_current = (InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr_localuser);
    }
    if (mqm_ptr->session->geo_fence->has_geofence_past) {
      FindFenceById(sesn_ptr_localuser, mqm_ptr->session->geo_fence->geofence_past, 0);
      instance_f_ptr_past = (InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr_localuser);
    }

    UpdateSessionGeoFenceData (sesn_ptr_localuser, instance_f_ptr_current, instance_f_ptr_past);

    SESSION_WHEN_SERVICED(sesn_ptr_localuser) = time(NULL);
    SessionUnLoadEphemeralMode(sesn_ptr_localuser);
    if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_localuser, __func__);

    _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_USER_SESN_LOCAL)

  }

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s {pid:'%lu', cid_msgqueue:'%lu', status:'%d'}: NOTICE: SESSION IS NOT LOCAL...", __func__, pthread_self(), mqm_ptr->session->target_session, mqm_ptr->session->status);
#endif

	_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_USER_SESN_LOCAL)

}

/**
 * 	@brief: Helper routine to processes inter-message command for rebooted Sessions, requiring reload of basic db data.
 * 	However, instead of contacting backends we rely on packaged data bundle. Only if session is cached locally.
 * 	@locks Session *: retrieved session
 * 	@unlocks Session *; previously retrieved Session
 */
static UFSRVResult *
_HandleInterBroadcastSessionRebooted (MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr)
{
	Session *sesn_ptr_localuser = NULL;
  InstanceHolderForSession *instance_sesn_ptr_localuser;

  if ((instance_sesn_ptr_localuser = LocallyLocateSessionById(mqm_ptr->session->target_session))) {
    sesn_ptr_localuser = SessionOffInstanceHolder(instance_sesn_ptr_localuser);

    SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_localuser, _LOCK_TRY_FLAG_FALSE, __func__);
    if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR)) {
      _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOGIC_CANTLOCK)
    }
    bool lock_already_owned = (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_BY_THIS_THREAD));

    SessionLoadEphemeralMode(sesn_ptr_localuser);

    SessionMessage 	*sesn_msg_ptr		=	mqm_ptr->session;

    if (IS_STR_LOADED(sesn_msg_ptr->header->cookie)) {
      size_t cookie_sz = strlen(sesn_msg_ptr->header->cookie);
      if (cookie_sz > CONFIG_MAX_COOKIE_SZ) {
        syslog(LOG_DEBUG, "%s {pid:'%lu', uid:'%lu', cookie_sz:'%lu'}: ERROR: COOKIE OVER SIZED...", __func__, pthread_self(), UfsrvUidGetSequenceId((const UfsrvUid *)sesn_msg_ptr->header->ufsrvuid.data), cookie_sz);
        _RETURN_RESULT_SESN(sesn_ptr_localuser, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
      }

      RemoveFromHash(&(sessions_delegator_ptr->hashed_cookies.hashtable), (void *) instance_sesn_ptr_localuser);
      memset (SESSION_COOKIE(sesn_ptr_localuser), 0, CONFIG_MAX_COOKIE_SZ + 1);
      memcpy (SESSION_COOKIE(sesn_ptr_localuser), sesn_msg_ptr->header->cookie, strlen(sesn_msg_ptr->header->cookie)); //already includes terminating null from memset

      if (!(AddToHash(&(sessions_delegator_ptr->hashed_cookies.hashtable), (void *)instance_sesn_ptr_localuser))) {
        //TODO: ERRO RECOVERY
      }
    }

    if (IS_STR_LOADED(sesn_msg_ptr->header->uname) && (strcasecmp(sesn_msg_ptr->header->uname, SESSION_USERNAME(sesn_ptr_localuser)) != 0)) {
#ifdef __UF_TESTING
      syslog(LOG_DEBUG, "%s {pid:'%lu', cid_local_user:'%lu', uid_msgqueue:'%lu', uname_old:'%s', uname_new:%s'}: NOTICE: USERNAME CHANGING...", __func__, pthread_self(), SESSION_ID(sesn_ptr_localuser), UfsrvUidGetSequenceId((const UfsrvUid *)mqm_ptr->session->header->ufsrvuid.data), SESSION_USERNAME(sesn_ptr_localuser), sesn_msg_ptr->header->uname);
#endif

      free (SESSION_USERNAME(sesn_ptr_localuser));
      SESSION_USERNAME(sesn_ptr_localuser) = strdup(sesn_msg_ptr->header->uname);
    }

    if (sesn_msg_ptr->n_prefs > 0) {
      UserPreference *user_pref_ptr	=	sesn_msg_ptr->prefs[0]; //TODO: currently limited to one pref, should be looped
      if (IS_STR_LOADED(user_pref_ptr->values_str)) {
        UserPreferenceDescriptor 	pref		=	{0};
        GetUserPreferenceNickname (sesn_ptr_localuser, PREF_NICKNAME, PREFSTORE_MEM, &pref);
        pref.value.pref_value_str = user_pref_ptr->values_str;
        SetUserPreferenceNickname(sesn_ptr_localuser, &pref, PREFSTORE_MEM, NULL);
      }
    } else {
#ifdef __UF_TESTING
      syslog(LOG_DEBUG, "%s {pid:'%lu', cid_localuser:'%lu', uid_msgqueue:'%lu'}: NOTICE: SESSION MESSAGE DID NOT CONTAIN PREFS", __func__, pthread_self(), SESSION_ID(sesn_ptr_localuser), UfsrvUidGetSequenceId((const UfsrvUid *)mqm_ptr->session->header->ufsrvuid.data));
#endif
    }

    ReloadCMToken(sesn_ptr_localuser, NULL);

    SessionUnLoadEphemeralMode(sesn_ptr_localuser);
    if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_localuser, __func__);

    _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_USER_SESN_LOCAL)

  }

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s {pid:'%lu', cid_msgqueue:'%lu', status:'%d'}: NOTICE: SESSION IS NOT LOCAL...", __func__, pthread_self(), mqm_ptr->session->target_session, mqm_ptr->session->status);
#endif

	_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_USER_SESN_LOCAL)

}

/////\\\\\\\


///// INTRA  \\\\


inline static int _VetrifySessionCommandForIntra	(WireProtocolData *);
inline static void _PrepareIntraBroadcastMessageForSession (BroadcastMessageEnvelopeForSession *envelope_ptr, Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg);
static UFSRVResult *_HandleIntraCommandForSessionRebooted (InstanceHolderForSession *instance_sesn_ptr, SessionMessage *sesn_msg_ptr);

//we may not implement this interface for INTRA Session commands, as the semantics are slightly different
__unused inline static void
_PrepareIntraBroadcastMessageForSession (BroadcastMessageEnvelopeForSession *envelope_ptr, Session *sesn_ptr, ClientContextData *context_ptr, FenceEvent *event_ptr, enum _CommandArgs command_arg)
{
	envelope_ptr->msgqueue_msg->command_type					=	UFSRV_SESSION;	envelope_ptr->msgqueue_msg->has_command_type=1;
	envelope_ptr->msgqueue_msg->broadcast_semantics		=	MESSAGE_QUEUE_MESSAGE__BROADCAST_SEMANTICS__INTRA; envelope_ptr->msgqueue_msg->has_broadcast_semantics	=1;
	envelope_ptr->msgqueue_msg->session								=	envelope_ptr->session_message;
	envelope_ptr->msgqueue_msg->session->header				=	envelope_ptr->header;
	envelope_ptr->msgqueue_msg->session->geo_fence		=	envelope_ptr->session_messasage_geo;

	envelope_ptr->header->args												=	command_arg;

	if (IS_PRESENT(event_ptr))
	{
		envelope_ptr->header->eid													=	event_ptr->eid; 					envelope_ptr->header->has_eid=1;
		envelope_ptr->header->when												=	event_ptr->when; 					envelope_ptr->header->has_when=1;
	}
	else
	{	envelope_ptr->header->when												=	GetTimeNowInMillis(); 	envelope_ptr->header->has_when=1;}

	envelope_ptr->header->cid													=	SESSION_ID(sesn_ptr); 		envelope_ptr->header->has_cid=1;
	MakeUfsrvUidInProto(&SESSION_UFSRVUIDSTORE(sesn_ptr), &(envelope_ptr->header->ufsrvuid), true); envelope_ptr->header->has_ufsrvuid = 1;

}

/**
 * 	@brief: Normally, Session commands are INTER type, but there are certain situations where non-stateful ufsrvapi needs to
 * 	drop some Session related commands for network-wide processing, such as invalidating sessions.
 */
UFSRVResult *
IntraBroadcastSessionStatusRebooted (Session *sesn_ptr, ClientContextData *context_ptr, enum _SessionMessage__Status sesn_status, enum _CommandArgs command_arg)
{
	SessionMessage session_msg				= SESSION_MESSAGE__INIT;
	CommandHeader		header						=	COMMAND_HEADER__INIT;

	AuthenticatedAccount *authacct_ptr=(AuthenticatedAccount *)context_ptr;

	//TODO we could transfer cookie as well
	session_msg.header								=	&header;
	header.ufsrvuid.data 							= authacct_ptr->ufsrvuid.data;
	header.ufsrvuid.len								=	CONFIG_MAX_UFSRV_ID_SZ; 							header.has_ufsrvuid = 1;
	header.when												=	time(NULL);														header.has_when=1;
	header.cookie											=	authacct_ptr->cookie; //by reference

	session_msg.target_session				= 0;
	session_msg.status								= SESSION_MESSAGE__STATUS__REBOOTED;

	return (UfsrvApiIntraBroadcastMessage (sesn_ptr, _WIRE_PROTOCOL_DATA((&session_msg)), MSGCMD_SESSION, INTRA_WITH_INTER_SEMANTICS, NULL));

}

/**
 * 	@brief: Main interface function for handling INTRA broadcasts for Session related commands
 * 	@worker: UfsrvWorker
 * 	@locks sesn_ptr_localuser: by instantiation
 * 	@unlocks sesn_ptr:
 */
int
HandleIntraBroadcastForSession (MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr, unsigned long call_flags)
{
	int									rc					= 0;
	MessageCommand 			*msgcmd_ptr	= NULL;

	long long timer_start						=	GetTimeNowInMicros();
	long long timer_end;

	if ((rc = _VetrifySessionCommandForIntra(mqm_ptr->session)) < 0)	goto return_final;

	InstanceHolderForSession				*instance_sesn_ptr_carrier			=	InstantiateCarrierSession (NULL, WORKERTYPE_UFSRVWORKER, SESSION_CALLFLAGS_EMPTY);
	if (IS_EMPTY(instance_sesn_ptr_carrier))	{
	  rc = -4;
	  goto return_final;
	}

	bool		lock_already_owned = false;
	unsigned long sesn_call_flags				=	(	CALL_FLAG_LOCK_SESSION|CALL_FLAG_LOCK_SESSION_BLOCKING|
																					CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY| CALL_FLAG_HASH_USERNAME_LOCALLY|
																					CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION|CALL_FLAG_REMOTE_SESSION);
	Session *sesn_ptr_carrier = SessionOffInstanceHolder(instance_sesn_ptr_carrier);

	GetSessionForThisUserByUserId (sesn_ptr_carrier, UfsrvUidGetSequenceId((const UfsrvUid *)mqm_ptr->session->header->ufsrvuid.data), &lock_already_owned, sesn_call_flags);
	InstanceHolderForSession *instance_sesn_ptr_local_user = (InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr_carrier);
	if (unlikely(IS_EMPTY(instance_sesn_ptr_local_user)))	goto return_error_unknown_uname;

	//>>> sesn_ptr_local_user IS NOW LOCKED

  Session 			*sesn_ptr_local_user = SessionOffInstanceHolder(instance_sesn_ptr_local_user);

	SESSION_WHEN_SERVICE_STARTED(sesn_ptr_local_user) = time(NULL);

	UFSRVResult *res_ptr_temp = _HandleIntraBroadcastForSession (instance_sesn_ptr_local_user, mqm_ptr, res_ptr);

	//IMPORTANT: DONT REFERENCE sesn_ptr_local_user if function returned RESULT_CODE_SESN_INVALIDATED

	if (_RESULT_TYPE_SUCCESS(res_ptr_temp))	rc = 0;
	else																		rc = -5;

	return_success:
	SESSION_WHEN_SERVICED(sesn_ptr_local_user) = time(NULL);
	if (!lock_already_owned && res_ptr_temp->result_code != RESULT_CODE_SESN_INVALIDATED)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_local_user, __func__);

	goto return_deallocate_carrier;

	return_error_unknown_uname:
	syslog(LOG_DEBUG, "%s {pid:'%lu', uid:'%lu'}: ERROR: COULD NOT RETRIEVE SESSION FOR USER", __func__, pthread_self(), UfsrvUidGetSequenceId((const UfsrvUid *)mqm_ptr->session->header->ufsrvuid.data));
	rc = -7;
	goto return_deallocate_carrier;

	return_deallocate_carrier:
	SessionReturnToRecycler (instance_sesn_ptr_carrier, (ContextData *)NULL, 0);

	return_final:
	timer_end = GetTimeNowInMicros();
	statsd_timing(pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_instrumentation_backend_key), "delegator.ufsrv.job.command.session.elapsed_time", (timer_end-timer_start));
	return rc;

}

/**
 * 	@brief: An IntraMessage for a user Session for which we hold a locally hashed session, not necessarily connected.
 * 	IntraMessages are intercepted by UfsrvWorkers,not SessionWorkers, so the Session needs to be loaded in Ephemeral mode
 * 	to provide necessary contexts.
 *
 * 	@param sesn_ptr: A local session, however, this session is not loaded through SessionWorker so it lacks backend contexts hence ephemeral mode
 * 	and may or may not be connected through to a live websocket. This session may or may not have existed before; ie it could have been just freshly
 * 	loaded from the cache backend and may not necessarily contain fresh cache db data such as nickname.
 *
 * 	@locked sesn_ptr: BY CALLER
 *	@unlocks sesn_ptr: (downstream when RESULT_CODE_SESN_INVALIDATED is returned successfully)
 *	@worker: UfsrvWorker
 */
static inline UFSRVResult *
_HandleIntraBroadcastForSession (InstanceHolderForSession *instance_sesn_ptr, MessageQueueMessage *mqm_ptr, UFSRVResult *res_ptr)
{
	UFSRVResult *res_ptr_local = _ufsrv_result_generic_error;
	Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	SessionLoadEphemeralMode(sesn_ptr);

	switch (mqm_ptr->session->status)
	{
	case SESSION_MESSAGE__STATUS__INVALIDTED:
		res_ptr_local = InvalidateLocalSessionReferenceFromProto (instance_sesn_ptr, mqm_ptr, CALLFLAGS_EMPTY);

		if ((_RESULT_TYPE_SUCCESS(res_ptr_local)) && (_RESULT_CODE_EQUAL(res_ptr_local, RESULT_CODE_SESN_INVALIDATED))) {
			//>>>> sesn_ptr NOW UNLOCKED and returned to recycler-> DONT REFRENCE IT IN THE CALLER
			*res_ptr = *res_ptr_local;
			goto return_final;
		}
		else	*res_ptr = *_ufsrv_result_generic_error;

		break;

	case SESSION_MESSAGE__STATUS__REBOOTED:
		_HandleIntraCommandForSessionRebooted (instance_sesn_ptr, mqm_ptr->session);
		break;

	case SESSION_MESSAGE__STATUS__PREFERENCE:
		HandleIntraCommandForSessionPreference (sesn_ptr, mqm_ptr->session);
		break;

	case  SESSION_MESSAGE__STATUS__HEARTBEAT:
		break;

	default:
		;
	}

	return_unload:
	SessionUnLoadEphemeralMode (sesn_ptr);

	return_final:
	return res_ptr;
}

/**
 * 	@brief: In this contex, a rebooted Session is session that is experienced a change in authentication cookie, most likely as a result or re-registration. Session id should
 * 	not have changed, but some other particulars may, such as cm token. Username should not have changed either.
 *
 * 	Rebooted sessions are reloaded from backend using essential data, which is then repackaged for INTER comms
 *
 * 	@locked sesn_ptr:
 */
static UFSRVResult *
_HandleIntraCommandForSessionRebooted (InstanceHolderForSession *instance_sesn_ptr, SessionMessage *sesn_msg_ptr)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

//TODO: 1)FORCE RELOAD OF SESSION FROM DB? UPDATED CACHE DB? INTERBROADCAST FOR OTHERS
	if (!IS_STR_LOADED(sesn_msg_ptr->header->cookie)) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', uid:'%lu'}: ERROR: COOKIE VALUE IS MISSING...", __func__, pthread_self(), UfsrvUidGetSequenceId((const UfsrvUid *)sesn_msg_ptr->header->ufsrvuid.data));
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}

  size_t cookie_sz = strlen(sesn_msg_ptr->header->cookie);
  if (cookie_sz > CONFIG_MAX_COOKIE_SZ) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', uid:'%lu', cookie_sz:'%lu'}: ERROR: COOKIE OVER SIZED...", __func__, pthread_self(), UfsrvUidGetSequenceId((const UfsrvUid *)sesn_msg_ptr->header->ufsrvuid.data), cookie_sz);
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

	syslog(LOG_DEBUG, "%s {pid:'%lu', uid:'%lu', cookie:'%s'}: Rebooting session...", __func__, pthread_self(), UfsrvUidGetSequenceId((const UfsrvUid *)sesn_msg_ptr->header->ufsrvuid.data), sesn_msg_ptr->header->cookie);

	AuthenticatedAccount 	authenticated_account = {0};

	//loads basic data from db backend
	DbValidateUserSignOnWithCookie(sesn_ptr, sesn_msg_ptr->header->cookie, &authenticated_account, NULL);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
	  char *old_cookie = NULL;

		if (strncmp(SESSION_COOKIE(sesn_ptr), sesn_msg_ptr->header->cookie, cookie_sz) != 0) {
		  old_cookie = strdupa(SESSION_COOKIE(sesn_ptr));

			RemoveFromHash(&(sessions_delegator_ptr->hashed_cookies.hashtable), (void *)instance_sesn_ptr);
			memset(SESSION_COOKIE(sesn_ptr), 0, CONFIG_MAX_COOKIE_SZ + 1);
			memcpy(SESSION_COOKIE(sesn_ptr), sesn_msg_ptr->header->cookie, CONFIG_MAX_COOKIE_SZ);//already includes terminating null from memset
			if (!(AddToHash(&(sessions_delegator_ptr->hashed_cookies.hashtable), (void *) instance_sesn_ptr))) {
				//TODO: ERROR RECOVERY
			}
		}
		if (IS_STR_LOADED(SESSION_USERNAME(sesn_ptr)))			{free (SESSION_USERNAME(sesn_ptr)); 		SESSION_USERNAME(sesn_ptr)			=	NULL;}
		if (IS_STR_LOADED(SESSION_USERNICKNAME(sesn_ptr)))	{free (SESSION_USERNICKNAME(sesn_ptr));	SESSION_USERNICKNAME(sesn_ptr)	=	NULL;}

		ReloadCMToken(sesn_ptr, NULL);

		TransferBasicSessionDbBackendData (sesn_ptr, &authenticated_account);
		RefreshBackendCacheForSession (sesn_ptr, old_cookie, CALL_FLAG_DONT_BROADCAST_SESSION_EVENT);
		InterBroadcastSessionStatusRebooted (sesn_ptr, sesn_ptr, SESSION_MESSAGE__STATUS__REBOOTED, 0);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

/**
 * 	@brief: Verify the fitness of the FenceCommand message in the context of on INTRA broadcast
 */
inline static int
_VetrifySessionCommandForIntra	(WireProtocolData *data_ptr)
{
	int rc = 0;
  SessionMessage *cmd_ptr = (SessionMessage *)data_ptr;

	if (unlikely(IS_EMPTY(cmd_ptr))) {
    syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: ERROR: COULD NOT FIND SESSIONMESSAGE IN UNPACKED MESAGEQUEUE", __func__, pthread_self());

    rc = -3;
    goto return_final;
}

	return_final:
	return rc;

}

/////
