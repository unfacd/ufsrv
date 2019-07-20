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
#include <utils.h>
#include <recycler.h>
#include <thread_context_type.h>
#include <net.h>
#include <recycler_type.h>
#include <session.h>
#include <session_service.h>
#include <share_list.h>
#include <delegator_session_worker_thread.h>
#include <session_broadcast.h>
#include <fence.h>
#include <location.h>
#include <nportredird.h>
#include <protocol.h>
#include <protocol_websocket_type.h>
#include <protocol_websocket_io.h>
#include <protocol_http_type.h>
#include <persistance.h>
#include <redis.h>
#include <dictionary.h>
#include <user_backend.h>
#include <sessions_delegator_type.h>
#include <command_controllers.h>
#include <fence_event_type.h>
#include <ufsrvuid.h>
#include <ufsrvcmd_user_callbacks.h>


//read-only pointer to statically allocated Protocols. Defined in protocol.c
extern const Protocol *const protocols_registry_ptr;
extern SessionsDelegator *const sessions_delegator_ptr;
extern __thread ThreadContext ufsrv_thread_context;
extern ufsrv *const masterptr;

static Session ufsrv_system_user={.session_id=1,
                                  .sservice.user.user_details.uid.data={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
                                  .sservice.user.user_details.user_name="1" };

static inline void *_s_DestructSocketMessageQueue (Session *, MessageQueue *);
static int _SessionSuspendSoft (InstanceHolderForSession *instance_sesn_ptr_target);
static inline UFSRVResult *_AuthenticateBrandNewSession (InstanceHolderForSession *instance_sesn_ptr);
static inline UFSRVResult *_AuthenticateUserIdHashedSession (InstanceHolderForSession *instance_sesn_ptr, InstanceHolderForSession *instance_sesn_ptr_uid_hashed, unsigned long);
static inline UFSRVResult *_AuthenticateDbBackendValidatedCookieSession (InstanceHolderForSession *instance_sesn_ptr, redisReply *redis_ptr, unsigned long);
static inline UFSRVResult *_InstateAuthenticatedNonLocalUser (InstanceHolderForSession *instance_sesn_ptr_transient, SocketMessage *sock_msg_ptr, redisReply *redis_ptr);
static inline UFSRVResult *_RefreshAuthenticatedLocalUser (InstanceHolderForSession *instance_sesn_ptr, InstanceHolderForSession *instance_sesn_ptr_hashed, SocketMessage *sock_msg_ptr, redisReply *redis_ptr);
static inline UFSRVResult *_InstateRemoteSessionAsConnected (InstanceHolderForSession *instance_sesn_ptr, InstanceHolderForSession *instance_sesn_ptr_hashed, redisReply *redis_ptr);
static inline UFSRVResult *_InstateSuspendedSessionAsConnected (InstanceHolderForSession *instance_sesn_ptr, InstanceHolderForSession *instace_sesn_ptr_hashed, SocketMessage *sock_msg_ptr);
static inline UFSRVResult *_DbBackendBootstrapIntoBrandNewSession (Session *sesn_ptr, bool);
static inline UFSRVResult  *_DbBackendVerifyAndInitialiseSession (InstanceHolderForSession *instance_sesn_ptr);
inline static UFSRVResult *_DiscoverSessionWhereabouts (InstanceHolderForSession *instance_sesn_ptr, unsigned long);
inline static UFSRVResult *_InstateUnconnectedSessionAsConnected (InstanceHolderForSession *instance_sesn_ptr_migrated, InstanceHolderForSession *instance_new_sesn_ptr, unsigned long call_flags, UFSRVResult *res_ptr_in);
static bool _SetupDataStructuresForBrandNewSession (InstanceHolderForSession *instance_sesn_ptr);

static UFSRVResult *_CacheBackendGetUfsrvUid (Session *sesn_ptr_this, unsigned long user_id, UFSRVResult *res_ptr_in);

static int TypePoolInitCallback_Session (ClientContextData *data_ptr, size_t oid);
static int TypePoolGetInitCallback_Session (InstanceHolder *data_ptr, ContextData *context_data, size_t oid, unsigned long call_flags);
static int TypePoolPutInitCallback_Session (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);
static char *TypePoolPrintCallback_Session (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);
static int TypePoolDestructCallback_Session (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);

//assigned when the typepool is initialised, holding meta data on the type under recycler management
static RecyclerPoolHandle *SessionTypePoolHandle;

static RecyclerPoolOps ops_session ={
		TypePoolInitCallback_Session,
		TypePoolGetInitCallback_Session,
		TypePoolPutInitCallback_Session,
		TypePoolPrintCallback_Session,
		TypePoolDestructCallback_Session
};

 /*
 ** Wrapped functions for export... -------------------------------------
 */

/**
 * 	@brief: User must load context s necessary, but this is not thread safe
 */
__attribute__ ((const)) Session *
GetUfsrvSystemUser (void)
{
	return &ufsrv_system_user;
}

/**
 * 	@brief A private copy of the Ufsrv System User, which means locking may not be necessary if underlying sesn_ptr is of one-off use
 * 	Always call ResetClonedUfsrvSystemUser() prior to sending to recycler.
 * 	@param sesn_call_flags only passed when recycler is invoked
 */
Session *
CloneUfsrvSystemUser (InstanceHolderForSession *instance_sesn_ptr_out, unsigned long sesn_call_flags)
{
	Session *sesn_ptr;
  InstanceHolder *instance_sesn_ptr = NULL;

	if (IS_PRESENT(instance_sesn_ptr_out))		instance_sesn_ptr = instance_sesn_ptr_out;
	else {
    instance_sesn_ptr = RecyclerGet(SessionPoolTypeNumber(), NULL, sesn_call_flags);
			if (unlikely(IS_EMPTY(instance_sesn_ptr)))	return NULL;
	}

	sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
	SESSION_ID(sesn_ptr)			=	ufsrv_system_user.session_id;
	memcpy(SESSION_UFSRVUID(sesn_ptr), ufsrv_system_user.sservice.user.user_details.uid.data, CONFIG_MAX_UFSRV_ID_SZ);
	SESSION_USERNAME(sesn_ptr) =	ufsrv_system_user.sservice.user.user_details.user_name;

	return sesn_ptr;
}

void
ResetClonedUfsrvSystemUser (Session *sesn_ptr, unsigned long sesn_call_flags)
{
	SESSION_USERNAME(sesn_ptr)=	NULL;
}

InstanceHolderForSession *
LocallyLocateSessionById (unsigned long session_id)
{
	if (session_id > 0) {
		return ((InstanceHolderForSession *)HashLookup(&(sessions_delegator_ptr->hashed_sessions.hashtable), (void *)&session_id, true));
	}

	return NULL;

}

InstanceHolderForSession *
LocallyLocateSessionByUserId(unsigned long user_id)
{
	if (user_id > 0) {
		return ((InstanceHolderForSession *)HashLookup(&(sessions_delegator_ptr->hashed_userids.hashtable), (void *)&user_id, true));
	}

	return NULL;

}

Session *
LocallyLocateSessionByUfsrvUid (const UfsrvUid *ui_ptr)
{
  unsigned long user_id = UfsrvUidGetSequenceId(ui_ptr);
  if (user_id > 0) {
    return ((Session *) HashLookup(&(sessions_delegator_ptr->hashed_userids.hashtable), (void *) &user_id, true));
  } else {
    syslog(LOG_DEBUG, "%s {pid:'%lu', id:'%lu'}: ERROR: UfsrvId contained undefined sequence id", __func__, pthread_self(), user_id);
  }

  return NULL;

}

#define _ALLOCATE_STORAGE_IF_NECESSARY \
  if (IS_EMPTY(uid_ptr_out)) {  \
    uid_ptr = calloc(1, sizeof(UfsrvUid));  \
  } else {  \
    uid_ptr = uid_ptr_out;  \
  }

/**
 * Return user id representation in UfrsvUid type. Returned value can be by-ref or by-value. by-ref requires the object to be hashed locally.
 * @param sesn_ptr_carrier
 * @param user_id
 * @param uid_ptr_out
 * @param flag_by_ref only honoured if Session is hashed locally., in which case no allocation is performed and uid_ptr_out is ignored
 * @param flag_is_local flag indicating if session was found locally. Helps with memory management
 * @return NULL on error, or UfsrvUid value (by value, or ref)
 */
UfsrvUid *
GetUfsrvUid (Session *sesn_ptr_carrier, unsigned long user_id, UfsrvUid *uid_ptr_out, bool flag_by_ref, bool *flag_is_local)
{
  UfsrvUid  *uid_ptr;
  InstanceHolderForSession *instance_sesn_ptr_local;

  if (likely(user_id > 0)) {
    instance_sesn_ptr_local = (InstanceHolder *) HashLookup(&(sessions_delegator_ptr->hashed_userids.hashtable), (void *) &user_id, true);
    if (IS_EMPTY((instance_sesn_ptr_local))) {
      _ALLOCATE_STORAGE_IF_NECESSARY

       if (IS_PRESENT(CacheBackendGetUfsrvUid(sesn_ptr_carrier, user_id, CALLFLAGS_EMPTY, uid_ptr))) {
         if (IS_PRESENT(flag_is_local)) {
           *flag_is_local = false;
         }

         return uid_ptr;
       } else {
         if (IS_EMPTY(uid_ptr_out)) {
           free (uid_ptr);
           goto return_error;
         }
       }
    } else {
      Session   *sesn_ptr_local = SessionOffInstanceHolder(instance_sesn_ptr_local);

      if (IS_PRESENT(flag_is_local)) {
        *flag_is_local = true;
      }

      if (flag_by_ref) {
        return &(SESSION_UFSRVUIDSTORE(sesn_ptr_local));
      }

      _ALLOCATE_STORAGE_IF_NECESSARY

      memcpy (uid_ptr->data, SESSION_UFSRVUID(sesn_ptr_local), CONFIG_MAX_UFSRV_ID_SZ);

      return uid_ptr;
    }
  }

  return_error:
  syslog(LOG_NOTICE, "%s {pid:'%lu', th_ctx:'%p'}: NOTICE: COULD NOT FIND USERID IN LOCALHASH '%lu'", __func__, pthread_self(), THREAD_CONTEXT_PTR, user_id);
  return NULL;
}

InstanceHolderForSession *
LocallyLocateSessionByUsername(const char *username)
{
	if (IS_STR_LOADED(username)) {
		return ((InstanceHolderForSession *)HashLookup(&(sessions_delegator_ptr->hashed_usernames.hashtable), (void *)username, true));
	}

	return NULL;
}

/**
* 	@brief: Soft suspension is the fist phase of cycling a Session out of service. Soft suspenssion keeps Sessions data structures intact for quick resumption
* 	but otherwise network access is completely unavailble.
* 	This function can be used by two types of threads: Session Worker threads and Ufsrv Worker threads. When sesn_ptr_this is NULL,
* 	the function is being invoked by a Ufsrv Worker.
*
* 	@param sesn_ptr_target: The Session that is target for Suspension
* 	@access_context: must be fully loaded
* 	@worker: Ufrsv or Session
*/
static int
_SessionSuspendSoft (InstanceHolderForSession *instance_sesn_ptr_target)
{
	redisReply							*redis_ptr;
	InstrumentationBackend	*instr_ptr __unused;
	PersistanceBackend			*pers_ptr;
	MessageQueueBackend			*mq_ptr	__unused;

	Session *sesn_ptr_target = SessionOffInstanceHolder(instance_sesn_ptr_target);
	SESNSTATUS_SET(sesn_ptr_target->stat, SESNSTATUS_SUSPENDED);
	SESNSTATUS_UNSET(sesn_ptr_target->stat, SESNSTATUS_CONNECTED);
	sesn_ptr_target->when_suspended = time(NULL);

	pers_ptr  =	sesn_ptr_target->persistance_backend;

	if (_PROTOCOL_CLLBACKS_RESET_SESSION(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr_target))))) {
		UFSRVResult *res_ptr = _PROTOCOL_CLLBACKS_RESET_SESSION_INVOKE(protocols_registry_ptr,
																PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr_target))),
																sesn_ptr_target, 0);//soft reset

		//TODO: OPTIMISE: keep separate caches per type.
		//At the moment the Protocol specific session needs to be recreated for each new request regardless of recycler origin
	}

	if (SESSION_SOCKETFD(sesn_ptr_target) > 0) {
		 shutdown (SESSION_SOCKETFD(sesn_ptr_target), SHUT_RDWR);
		 RemoveSessionToMonitoredWorkEvents(instance_sesn_ptr_target); //this seems to be necessary as under some conditions we get events for recycled objects
		 close (SESSION_SOCKETFD(sesn_ptr_target));//this will automatically remove from monitored events
	}

	SESSION_SOCKETFD(sesn_ptr_target) = -1;

	if (sesn_ptr_target->persistance_backend) {

		if (_PROTOCOL_CTL_PUB_SESSION_TRANSITIONS(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr_target))))) {
			if ((redis_ptr = (*pers_ptr->send_command)(sesn_ptr_target, REDIS_CMD_USER_SESSION_STATUS_SUSPEND, SESSION_USERID(sesn_ptr_target), sesn_ptr_target->when_suspended)))
				freeReplyObject(redis_ptr);

			InterBroadcastSessionStatus (sesn_ptr_target, NULL, SESSION_MESSAGE__STATUS__SUSPENDED, 0);
		}
	} else {
		_LOGD(LOGSTR_NULL_PARAM, __func__, pthread_self(), RESCODE_PROG_MISSING_PARAM, "PersistanceBackend *");
	}

	return 1;

}

/**
 * 	@brief: Pure data oriented reset
 * 	TODO: This is to be used above in SuspendHard to consolidate all data ops in one place
 */
void
ResetSessionData (InstanceHolderForSession *instance_sesn_ptr_target)
{
  Session *sesn_ptr_target = SessionOffInstanceHolder(instance_sesn_ptr_target);

	memset(SESSION_COOKIE(sesn_ptr_target), 0, CONFIG_MAX_COOKIE_SZ+1);

	ResetSessionService(instance_sesn_ptr_target, 0);

	_s_DestructSocketMessageQueue (sesn_ptr_target, &(sesn_ptr_target->message_queue_in));
	_s_DestructSocketMessageQueue (sesn_ptr_target, &(sesn_ptr_target->message_queue_out));

	DestructSocketMessage (&(sesn_ptr_target->ssptr->socket_msg));
	DestructSocketMessage (&(sesn_ptr_target->ssptr->socket_msg_out));

	SessionResetTransferAccessContext(sesn_ptr_target);

	memset (&sesn_ptr_target->ssptr->protocol_header, 0, sizeof(ProtocolHeaderWebsocket));
	memset (sesn_ptr_target->ssptr, 0, sizeof(Socket));

	if (sesn_ptr_target->dsptr) memset (sesn_ptr_target->dsptr, 0, sizeof(Socket));

	memset(SESSION_UFSRVUID(sesn_ptr_target), 0, CONFIG_MAX_UFSRV_ID_SZ);
	SESSION_USERID_TEMP(sesn_ptr_target)	=	0;
	SESSION_ID(sesn_ptr_target)		      	=	0;
	sesn_ptr_target->stat						      =	0;
}

/**
 * 	@brief: Suspend a fully connected session.
 * 	The session is cached locally with cookie hash, uid hash and session hash.
 * 	Suspension will close live socket associated with Session.
 * 	Soft suspend changes the logical state of the session to SUSPENDED and shuts down network related space
 * 	Hard suspend (with recycle flag) completely destroys the Session and attaches it to the recycler pool for future use.
 */
int
SuspendSession (InstanceHolderForSession *instance_sesn_ptr, unsigned recycle_flag)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	if (recycle_flag == SOFT_SUSPENSE) {
		if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_SUSPENDED)) {
			syslog(LOG_DEBUG, LOGSTR_INCONSISTENT_STATE, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), RESCODE_PROG_INCONSISTENT_STATE, "Session already suspended (proceeding anyway).");
		}

    return (_SessionSuspendSoft(instance_sesn_ptr));
	}

#ifdef __UF_TESTING
	_LOGD(LOGSTR_FUNC_ENTERY, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), "HARD SUSPEND");
#endif

	if (recycle_flag == HARD_SUSPENSE) {
		//just in case no soft suspend wasdone
		if (!(SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_SUSPENDED))) {
#ifdef __UF_TESTING
			syslog (LOG_DEBUG, "%s (pid;'%lu' o:'%p'): NOTICE: HARD SUSPEND REQUEST WITHOUT PRIOR SOFT", __func__, pthread_self(), sesn_ptr);
#endif
			_SessionSuspendSoft(instance_sesn_ptr);
		}

		//invoke lifecycle callback for session reset (soft, recycler based)
		if (_PROTOCOL_CLLBACKS_RESET_SESSION(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))))) {
			UFSRVResult *res_ptr = _PROTOCOL_CLLBACKS_RESET_SESSION_INVOKE(protocols_registry_ptr,
																	PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))),
																	sesn_ptr, 1);//hard reset

			//TODO: OPTIMISE: keep separate caches per type.
			//At the moment the Protocol specific session needs to be recreated for each new request regardless of recycler origin
			if (SESSION_PROTOCOLSESSION(sesn_ptr)) {
				free(SESSION_PROTOCOLSESSION(sesn_ptr));
				SESSION_PROTOCOLSESSION(sesn_ptr) = NULL;
			}
		}

		redisReply *redis_ptr;

		if (SESSION_ID(sesn_ptr) > 0) {
			RemoveFromHash(SESNDELEGATE_SESSIONCACHE(sessions_delegator_ptr), (void *) (InstanceHolderForSession *)instance_sesn_ptr);
		}

		if (SESSION_USERID(sesn_ptr) > 0) {
			RemoveFromHash(SESNDELEGATE_USERIDCACHE(sessions_delegator_ptr), (void *) (InstanceHolderForSession *)instance_sesn_ptr);
		}

		RemoveFromHash(SESNDELEGATE_USERNAMECACHE(sessions_delegator_ptr), (void *) (InstanceHolderForSession *)instance_sesn_ptr);

		RemoveFromHash(SESNDELEGATE_COOKIECACHE(sessions_delegator_ptr), (void *) (InstanceHolderForSession *)instance_sesn_ptr);

		if ((SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_AUTHENTICATED)) && !(SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_REMOTE))) {
			if (_PROTOCOL_CTL_PUB_SESSION_TRANSITIONS(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))))) {
				if ((redis_ptr = (*sesn_ptr->persistance_backend->send_command)(sesn_ptr, REDIS_CMD_USER_SESSION_STATUS_SET, SESSION_USERID(sesn_ptr), 0)))	freeReplyObject(redis_ptr);

				if ((redis_ptr = (*sesn_ptr->persistance_backend->send_command)(sesn_ptr, REDIS_CMD_COOKIE_SESSION_DEL, SESSION_COOKIE(sesn_ptr))))	freeReplyObject(redis_ptr);

				InterBroadcastSessionStatus (sesn_ptr, NULL, SESSION_MESSAGE__STATUS__QUIT, 0);
			}
		}

		sesn_ptr->stat = 0;
		memset(SESSION_COOKIE(sesn_ptr), 0, CONFIG_MAX_COOKIE_SZ + 1);

		ResetSessionService(instance_sesn_ptr, 0); //only if session_servicee is !NULL

		_s_DestructSocketMessageQueue (sesn_ptr, &(sesn_ptr->message_queue_in));
		_s_DestructSocketMessageQueue (sesn_ptr, &(sesn_ptr->message_queue_out));

		DestructSocketMessage (&(sesn_ptr->ssptr->socket_msg));
		DestructSocketMessage (&(sesn_ptr->ssptr->socket_msg_out));

		sesn_ptr->persistance_backend = NULL;

		memset (&sesn_ptr->ssptr->protocol_header, 0, sizeof(ProtocolHeaderWebsocket));
		memset (sesn_ptr->ssptr, 0, sizeof(Socket));

    memset(SESSION_UFSRVUID(sesn_ptr), 0, CONFIG_MAX_UFSRV_ID_SZ);
		SESSION_USERID_TEMP(sesn_ptr) = 0;
		SESSION_ID(sesn_ptr)          = 0;

		if (sesn_ptr->dsptr) memset (sesn_ptr->dsptr, 0, sizeof(Socket));
	}

	return 1;

}

#define _RECOVERY_BLOCK \
		 /*backend cookie hash is not affected as it has not been touched at this point*/\
		 new_sptr = sesn_ptr_transient->ssptr;\
		 sesn_ptr_transient->ssptr = sesn_ptr_migrated->ssptr; \
		 sesn_ptr_migrated->ssptr = new_sptr;	\
		 	 	 	 	 	 	 	 	 	\
		 SESNSTATUS_UNSET(sesn_ptr_transient->stat, SESNSTATUS_SUSPENDED);\
		 AddSessionToMonitoredWorkEvents (instance_sesn_ptr_transient);\
		 \
		 if (!lock_already_owned)	SessionUnLockCtx (THREAD_CONTEXT_PTR, sesn_ptr_migrated, __func__);


/**
 * 	@brief:
 * 	Fetch INDIVIDUAL raw session  cache record from redis backend, returning. user responsible for freeing redis reply
 *
 * 	@param sesn_ptr_this: Assumed a locked carrier session as we only need uid to service this request. Can be NULL.
 *
 * 	@worker: ufsrv and session if sesn_ptr_this is provided, otherwise ufsrvworker's is used
 *
 *	@access_context: must be full loaded
 * 	@locks: NONE
 *
 * 	@blocks: redis write
 *
 * 	@dynamic_memory redisReply: EXPORTS which the caller is responsible for freeing
 * 	(IMPORTANT: ONLY WHEN RESULT_TYPE_SUCCESS and RESCODE_BACKEND_DATA are returned together)
 *
 */
UFSRVResult *
CacheBackendGetRawSessionRecord(Session *sesn_ptr_this, unsigned long user_id, unsigned long call_flags,
                                UFSRVResult *res_ptr_in)
{
	UFSRVResult *res_ptr;

	if (!res_ptr_in)	res_ptr = &(sesn_ptr_this->sservice.result);
	else							res_ptr = res_ptr_in;

	if (user_id > 0) {
		PersistanceBackend 	*pers_ptr		= sesn_ptr_this->persistance_backend;
		redisReply 					*redis_ptr	=	NULL;

		redis_ptr = (*pers_ptr->send_command)(sesn_ptr_this, REDIS_CMD_USER_SESSION_RECORD_GET_ALL, user_id);

		if (IS_EMPTY(redis_ptr)) {
			syslog(LOG_DEBUG, "%s: ERROR COULD NOT GET REDIS RESPONSE for UID '%lu'", __func__, user_id);

			_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_BACKENDERR, RESCODE_BACKEND_CONNECTION)
		}

		if (redis_ptr->type == REDIS_REPLY_ERROR) {
		   syslog(LOG_DEBUG, "%s {pid:'%lu'}: REDIS_REPLY_ERROR COULD NOT GET REDIS RESPONSE for UID '%lu'", __func__, pthread_self(), user_id);

		   freeReplyObject(redis_ptr);

		   _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_BACKENDERR, RESCODE_BACKEND_DATA);;
		}

		//empty set, technically not error
		if (redis_ptr->type == REDIS_REPLY_NIL) {
		   syslog(LOG_DEBUG, "%s {pid:'%lu'}: COULD NOT RETRIEVE RECORD FOR UID '%lu'",  __func__, pthread_self(), user_id);

		   freeReplyObject(redis_ptr);//

		   _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA_EMPTYSET)
		}

		//this is necessary because the HMGET command will return a empty named array
	   if (!(redis_ptr->element[0]->str)) {
		   syslog(LOG_DEBUG, "%s {pid:'%lu', uid:'%lu', err:'%s', type:'%d', elements:'%lu'}: ERROR: EMPTY SET FOR UID",  __func__, pthread_self(), user_id, redis_ptr->str, redis_ptr->type, redis_ptr->elements);

		   freeReplyObject(redis_ptr);

		   _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_BACKENDERR, RESCODE_BACKEND_DATA)
	   }

		_RETURN_RESULT_RES(res_ptr, redis_ptr,  RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
	}

	_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

static UFSRVResult *
_CacheBackendGetUfsrvUid (Session *sesn_ptr_this, unsigned long user_id, UFSRVResult *res_ptr_in)
{
  UFSRVResult *res_ptr;

  if (!res_ptr_in)	res_ptr = &(sesn_ptr_this->sservice.result);
  else							res_ptr = res_ptr_in;

  if (likely(user_id>0)) {
    PersistanceBackend 	*pers_ptr		= sesn_ptr_this->persistance_backend;
    redisReply 					*redis_ptr	=	NULL;

    redis_ptr=(*pers_ptr->send_command)(sesn_ptr_this, REDIS_CMD_USER_GET_UFSRVUID, user_id);

    if (IS_EMPTY(redis_ptr)) {
      syslog(LOG_DEBUG, "%s: ERROR COULD NOT GET REDIS RESPONSE for UID '%lu'", __func__, user_id);

      _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_BACKENDERR, RESCODE_BACKEND_CONNECTION);
    }

    if (redis_ptr->type == REDIS_REPLY_ERROR) {
      syslog(LOG_DEBUG, "%s {pid:'%lu'}: REDIS_REPLY_ERROR COULD NOT GET REDIS RESPONSE for UID '%lu'", __func__, pthread_self(), user_id);

      freeReplyObject(redis_ptr);

      _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_BACKENDERR, RESCODE_BACKEND_DATA);;
    }

    //empty set, technically not error
    if (redis_ptr->type == REDIS_REPLY_NIL) {
      syslog(LOG_DEBUG, "%s {pid:'%lu'}: COULD NOT RETRIEVE RECORD FOR UID '%lu'",  __func__, pthread_self(), user_id);

      freeReplyObject(redis_ptr);//

      _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA_EMPTYSET);
    }

    //this is necessary because the HMGET command will return a empty named array
    if (!(redis_ptr->element[0]->str))
    {
      syslog(LOG_DEBUG, "%s {pid:'%lu', uid:'%lu', err:'%s', type:'%d'}: ERROR: EMPTY SET FOR UID",  __func__, pthread_self(), user_id, redis_ptr->str, redis_ptr->type);

      freeReplyObject(redis_ptr);

      _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_BACKENDERR, RESCODE_BACKEND_DATA);
    }

    _RETURN_RESULT_RES(res_ptr, redis_ptr,  RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);
  }

  _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);

}

UfsrvUid *
CacheBackendGetUfsrvUid (Session *sesn_ptr_this, unsigned long user_id, unsigned long sesn_call_flags, UfsrvUid *uid_ptr_out)
{
  UFSRVResult res = {0};
  UfsrvUid *uid_ptr;

  if (IS_PRESENT(uid_ptr_out)) {
    uid_ptr = uid_ptr_out;
  } else {
    uid_ptr = calloc(1, sizeof(UfsrvUid));
  }

  UFSRVResult *res_ptr = _CacheBackendGetUfsrvUid(sesn_ptr_this, user_id, &res);
  if (res_ptr->result_type==RESULT_TYPE_SUCCESS && (res_ptr->result_code==RESCODE_BACKEND_DATA))
  {
//    if (user_id!=301&&user_id!=305)
//    {//temporary block remove after cachevackend uids are updated
//      DbBackendUfsrvUidDescriptor uid_descriptor = {0};
//      redisReply 					*redis_ptr = (redisReply *)res_ptr->result_user_data;
//      DbAccountGetUserId(sesn_ptr_this, redis_ptr->element[REDIS_KEY_USER_USER_NAME]->str, &uid_descriptor);
//      if (SESSION_RESULT_CODE_EQUAL(sesn_ptr_this, RESCODE_BACKEND_DATA)) {
//        CacheBackendsUpdateForUfsrvUid (sesn_ptr_this, uid_descriptor.sequence_id, (const UfsrvUid *)&(uid_descriptor.ufsrvid));
////        user_id = uid_descriptor.sequence_id;
////          memcpy (ufsrvuid.data, uid_descriptor.ufsrvid, CONFIG_MAX_UFSRV_ID_SZ);
//      }
//    }
    redisReply *redis_ptr = ((redisReply *) res_ptr->result_user_data);
    memcpy(uid_ptr->data, redis_ptr->element[0]->str, CONFIG_MAX_UFSRV_ID_SZ);
    freeReplyObject(redis_ptr);

    return uid_ptr;
  } else {
    if (IS_EMPTY(uid_ptr_out)) {
      free (uid_ptr);
    }
  }

  return NULL;
}

/**
 * 	@brief:
 * 	Fetch a raw session record from the backend using provided cookie.
 * 	via a call to SessionGetFromBackendRaw(), which the user responsible for freeing redis reply.
 * 	Redis reply instantiaed here is destoryed here as well, once the session id is extacted from it and fed into the contained function.
 *
 * 	@param sesn_ptr_this: current connected session which is servicing request
 *
 * 	@param session_cookie: cookie value
 *
 * 	@worker_thread: ufsrv and session
 *
 * 	@locks: NONE
 *
 * 	@blocks: redis write
 *
 * 	@dynamic_memory:
 * 	creates redisReply * which is is freed here
 *
 * 	@dynamic_memory redisReply: EXPORTS via  proxy function which must be freed by the caler
 * 	(IMPORTANT: ONLY WHEN RESULT_TYPE_SUCCESS and RESCODE_BACKEND_DATA are returned together)
 *
 *	@returns RESCODE_BACKEND_DATA: with success
 *
 *	@worker: Session Worker, Ufsrv Worker
 *
 *	TODO: OPTIMISATION: Write lua script to avoid two calls to backend
 */
UFSRVResult *
CacheBackendGetRawSessionRecordByCookie(Session *sesn_ptr_this, const char *session_cookie, unsigned long call_flags, UFSRVResult *res_ptr_in)
{
	UFSRVResult			*res_ptr;
	PersistanceBackend	*pers_ptr;
	redisReply			*redis_ptr;

	pers_ptr = sesn_ptr_this->persistance_backend;

	if (!res_ptr_in)	res_ptr = &(sesn_ptr_this->sservice.result);
	else	res_ptr = res_ptr_in;

	if (!(redis_ptr = (*pers_ptr->send_command)(sesn_ptr_this, REDIS_CMD_COOKIE_SESSION_GET, session_cookie))) {
		syslog(LOG_DEBUG, "%s: ERROR COULD NOT GET REDIS RESPONSE for cookie:'%s'", __func__, session_cookie);

		_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_BACKENDERR, RESCODE_BACKEND_CONNECTION)
	}

	if (redis_ptr->type == REDIS_REPLY_ERROR) {
	   syslog(LOG_DEBUG, "%s: REDIS_REPLY_ERROR COULD NOT GET REDIS RESPONSE for cookie '%s'", __func__, session_cookie);

	   freeReplyObject(redis_ptr);

	   _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_BACKENDERR, RESCODE_BACKEND_DATA)
	}

	//empty set, technically not error
	if (redis_ptr->type == REDIS_REPLY_NIL) {
	   syslog(LOG_DEBUG, "%s: COULD NOT RETRIEVE SESSION ID FOR COOKIE '%s'",  __func__, session_cookie);

	   freeReplyObject(redis_ptr);//

	   _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA_EMPTYSET)
	}

	//cid:uid
	char *user_id_str = strrchr(redis_ptr->str, ':');
	if (user_id_str) {
		*user_id_str = '\0';
		user_id_str++;
	} else {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', }: ERROR PARSING VALUE OF COOKIE:%%session_cookie: USER ID WAS NOT ENCODED: str:'%s'", __func__, pthread_self(), sesn_ptr_this, SESSION_ID(sesn_ptr_this), redis_ptr->str);

		 freeReplyObject(redis_ptr);

		_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_BACKENDERR, RESCODE_BACKEND_DATA)
	}

	unsigned long userid = strtoul(user_id_str, NULL, 10);

	freeReplyObject(redis_ptr);

	return (CacheBackendGetRawSessionRecord(sesn_ptr_this, userid, call_flags, res_ptr_in));

}

/**
 * 	@brief: Given a username return a Session representation for them. The Session can an actual active one or just a dead data carrier
 * 	.Search is performed locally, redis backend and finally db.
 *
 *	@param sesn_ptr_carrier: no relation to session being fetched. Should have full access context
 * 	@callflag CALL_FLAG_LOCK_SESSION: locks session before returning
 *
 * 	@locks Session: if CALL_FLAG_LOCK_SESSION is set
 */
UFSRVResult *
GetSessionForThisUser (Session *sesn_ptr_carrier, const char *username, bool *lock_state, unsigned long call_flags)
{
	Session *sesn_ptr_other_user = NULL;

	InstanceHolderForSession *instance_sesn_ptr_other_user = LocallyLocateSessionByUsername(username);

	if (IS_PRESENT(instance_sesn_ptr_other_user)) {
	  sesn_ptr_other_user = SessionOffInstanceHolder(instance_sesn_ptr_other_user);

		int res_code = RESCODE_PROG_LOCKED;

		if (call_flags&CALL_FLAG_LOCK_SESSION) {
			if (!(call_flags&CALL_FLAG_LOCK_SESSION_BLOCKING)) 	SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_other_user, _LOCK_TRY_FLAG_TRUE, __func__);
			else 																								SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_other_user, _LOCK_TRY_FLAG_FALSE, __func__);

			if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_SUCCESS)) {
				if (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_THIS_THREAD)) res_code = RESCODE_PROG_LOCKED_THIS_THREAD;
			}
			else {_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, RESCODE_PROG_WONTLOCK)
			}
		}

		if (SESNSTATUS_IS_SET(sesn_ptr_other_user->stat, SESNSTATUS_FENCELIST_LAZY)) {
			SessionTransferAccessContext (sesn_ptr_carrier, sesn_ptr_other_user, false);
			InstateFenceListsForUser (instance_sesn_ptr_other_user, SESSION_CALLFLAGS_EMPTY, ALL_FENCE_TYPES, true);
		}

		if (IS_PRESENT(lock_state))	*lock_state = (res_code==RESCODE_PROG_LOCKED_THIS_THREAD?true:false);
		_RETURN_RESULT_SESN(sesn_ptr_carrier, sesn_ptr_other_user, RESULT_TYPE_SUCCESS, SESSION_RESULT_CODE(sesn_ptr_carrier))
	}

	DbBackendUfsrvUidDescriptor uid_descriptor = {0};
  DbAccountGetUserId(sesn_ptr_carrier, username, &uid_descriptor);
	if (!SESSION_RESULT_CODE_EQUAL(sesn_ptr_carrier, RESCODE_BACKEND_DATA)) {
		_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
	}

	UFSRVResult *res_ptr_aux = FindSessionForUserLocalOrBackend (sesn_ptr_carrier, 0, uid_descriptor.sequence_id, CALL_FLAG_SEARCH_BACKEND);

	if (_RESULT_CODE_EQUAL(res_ptr_aux, RESCODE_USER_ONLINE)) {
    sesn_ptr_other_user = (Session *)_RESULT_USERDATA(res_ptr_aux);

		int res_code = RESCODE_PROG_LOCKED;
		//local instance
		if (call_flags&CALL_FLAG_LOCK_SESSION) {
			if (!(call_flags&CALL_FLAG_LOCK_SESSION_BLOCKING)) 	SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_other_user, _LOCK_TRY_FLAG_TRUE, __func__);
			else 																								SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_other_user, _LOCK_TRY_FLAG_FALSE, __func__);//<

			if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT.res_ptr, RESULT_TYPE_SUCCESS)) {
				if (_RESULT_CODE_EQUAL(THREAD_CONTEXT.res_ptr, RESCODE_PROG_LOCKED_THIS_THREAD)) res_code = RESCODE_PROG_LOCKED_THIS_THREAD;
			}
			else {_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, RESCODE_PROG_WONTLOCK)}
		}

		if (IS_PRESENT(lock_state))	*lock_state = (res_code == RESCODE_PROG_LOCKED_THIS_THREAD?true:false);
		_RETURN_RESULT_SESN(sesn_ptr_carrier, sesn_ptr_other_user, RESULT_TYPE_SUCCESS, SESSION_RESULT_CODE(sesn_ptr_carrier))
	} else if (_RESULT_CODE_EQUAL(res_ptr_aux, RESCODE_USER_BACKEND)) {
		//session instance found in the backend: instantiate one locally
		redisReply *redis_ptr = (redisReply *)res_ptr_aux->result_user_data;

		if ((instance_sesn_ptr_other_user = CacheBackendInstantiateRawSessionRecord(sesn_ptr_carrier, redis_ptr,
                                                                                call_flags |
                                                                                CALL_FLAG_LOAD_DB_BACKEND_FOR_SESSION,
                                                                                NULL)))  {//recycler instance
		  sesn_ptr_other_user = SessionOffInstanceHolder(instance_sesn_ptr_other_user);
			syslog(LOG_DEBUG, LOGSTR_SESSION_SUCCESS_MIGRATED, __func__, pthread_self(), sesn_ptr_carrier, sesn_ptr_other_user, SESSION_ID(sesn_ptr_other_user), LOGCODE_SESSION_SUCCESS_MIGRATED);
		} else {
			syslog(LOG_DEBUG, LOGSTR_SESSION_ERROR_MIGRATED, __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), LOGCODE_SESSION_ERROR_MIGRATED);

			freeReplyObject(redis_ptr);

			_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
		}

		freeReplyObject(redis_ptr);

		//TODO: pass local session_lcoked_flag variable instead of reading sesn resocde
//		return sesn_ptr_other_user;//session can be locked depending on flag which we passed on
		if (SESSION_RESULT_CODE(sesn_ptr_other_user) == RESCODE_PROG_LOCKED_THIS_THREAD) if (IS_PRESENT(lock_state))	*lock_state = true;
		_RETURN_RESULT_SESN(sesn_ptr_carrier, sesn_ptr_other_user, RESULT_TYPE_SUCCESS, SESSION_RESULT_CODE(sesn_ptr_carrier))//session can be locked depending on flag which we passed on
	}

	_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
}

/**
 * 	@brief: Given a user id return a Session representation for them. The Session can an actual active one or juts a dead data carrier
 * 	.Search is performed locally, redis backend and finally db.
 *  @return InstanceHolderForSession
 * 	@call_flag CALL_FLAG_REBOOT_SESSION: source session from db first and propogate
 * 	@locks: sesn_ptr_other_user
 */
UFSRVResult *
GetSessionForThisUserByUserId (Session *sesn_ptr, unsigned long uid, bool *lock_state, unsigned long call_flags)
{
	bool lock_already_owned 			= false;
	Session *sesn_ptr_other_user	=	NULL;

	if (uid <= 0)	{_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)}

	InstanceHolderForSession *instance_sesn_ptr_other_user = LocallyLocateSessionByUserId(uid);

	if (IS_PRESENT(instance_sesn_ptr_other_user)) {
	  sesn_ptr_other_user = SessionOffInstanceHolder(instance_sesn_ptr_other_user);

		//bingo...
		if (call_flags&CALL_FLAG_LOCK_SESSION) {
			if (!(call_flags&CALL_FLAG_LOCK_SESSION_BLOCKING)) 	SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_other_user, _LOCK_TRY_FLAG_TRUE, __func__);
			else 																								SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_other_user, _LOCK_TRY_FLAG_FALSE, __func__);

			if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR)) {
				_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_WONTLOCK)
			}

			lock_already_owned = (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_THIS_THREAD));
		}

		//TODO: recovery from fence loading errors
		if (call_flags&CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION && SESNSTATUS_IS_SET(sesn_ptr_other_user->stat, SESNSTATUS_FENCELIST_LAZY)) {
			SessionTransferAccessContext (sesn_ptr, sesn_ptr_other_user, false);
			InstateFenceListsForUser (instance_sesn_ptr_other_user, SESSION_CALLFLAGS_EMPTY, ALL_FENCE_TYPES, true);
		}

		if (IS_PRESENT(lock_state))	*lock_state = lock_already_owned;
		_RETURN_RESULT_SESN(sesn_ptr, instance_sesn_ptr_other_user, RESULT_TYPE_SUCCESS, RESCODE_PROG_RESOURCE_CACHED)
	}

	UFSRVResult *res_ptr_aux = FindSessionForUserLocalOrBackend (sesn_ptr, 0, uid, CALL_FLAG_SEARCH_BACKEND);

	if (_RESULT_CODE_EQUAL(res_ptr_aux, RESCODE_USER_ONLINE)) {
		//local instance
		instance_sesn_ptr_other_user = (InstanceHolderForSession *)_RESULT_USERDATA(res_ptr_aux);
    sesn_ptr_other_user = SessionOffInstanceHolder(instance_sesn_ptr_other_user);

		if (call_flags&CALL_FLAG_LOCK_SESSION) {
			if (!(call_flags&CALL_FLAG_LOCK_SESSION_BLOCKING)) 	SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_other_user, _LOCK_TRY_FLAG_TRUE, __func__);
			else 																								SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_other_user, _LOCK_TRY_FLAG_FALSE, __func__);

			if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR)) {
				_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_WONTLOCK)
			}

			lock_already_owned = (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_THIS_THREAD));
		}

		if (call_flags&CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION && SESNSTATUS_IS_SET(sesn_ptr_other_user->stat, SESNSTATUS_FENCELIST_LAZY)) {
			SessionTransferAccessContext (sesn_ptr, sesn_ptr_other_user, false);
			InstateFenceListsForUser (instance_sesn_ptr_other_user, SESSION_CALLFLAGS_EMPTY, ALL_FENCES, true);
		}

		if (IS_PRESENT(lock_state))	*lock_state = lock_already_owned;
		_RETURN_RESULT_SESN(sesn_ptr, instance_sesn_ptr_other_user, RESULT_TYPE_SUCCESS, RESCODE_USER_ONLINE)
	}
	else
	if (_RESULT_CODE_EQUAL(res_ptr_aux, RESCODE_USER_BACKEND)) {
		//session instance found in the backend: instantiate one locally
		redisReply *redis_ptr = (redisReply *)res_ptr_aux->result_user_data;

		if ((instance_sesn_ptr_other_user = CacheBackendInstantiateRawSessionRecord(sesn_ptr, redis_ptr, call_flags |
                                                                                                     CALL_FLAG_LOAD_DB_BACKEND_FOR_SESSION,
                                                                                NULL))) {
		  sesn_ptr_other_user = SessionOffInstanceHolder(instance_sesn_ptr_other_user);
			syslog(LOG_DEBUG, LOGSTR_SESSION_SUCCESS_MIGRATED, __func__, pthread_self(), sesn_ptr, sesn_ptr_other_user, SESSION_ID(sesn_ptr_other_user), LOGCODE_SESSION_SUCCESS_MIGRATED);
		} else {
			syslog(LOG_DEBUG, LOGSTR_SESSION_ERROR_MIGRATED, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), LOGCODE_SESSION_ERROR_MIGRATED);

			freeReplyObject(redis_ptr);

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
		}

		freeReplyObject(redis_ptr);

		if (IS_PRESENT(lock_state))	*lock_state = false; //we certainly own this lock (if lock was requested anyway)

		_RETURN_RESULT_SESN(sesn_ptr, instance_sesn_ptr_other_user, RESULT_TYPE_SUCCESS, SESSION_RESULT_CODE(sesn_ptr))
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
}

/**
 * 	@brief: wrapper function to instantiate Session from backend.
 * 	USE WITH CAUTION AS IT PULLS IN AN INSTANCE FROM THE RECYLER. MAKE SURE THE SESSION DOES NOT HAVE LOCAL REPRESENTATION
 * 	OF ANY SORT: CONNECTED OR REMOTE
 *
 * 	@IMPORTANT: if sesn_ptr_this is NULL the backend context will be loaded from a UFSRV WORKER  NOT SESSION WORKER
 *
 */
inline InstanceHolderForSession *
SessionInstantiateFromBackend (Session *sesn_ptr_this, unsigned long user_id, unsigned long sesn_call_flags)
{
	UFSRVResult res;

	UFSRVResult *res_ptr = CacheBackendGetRawSessionRecord(sesn_ptr_this, user_id, 0, &res);//user ufsrv worker context
   if (RESULT_IS_SUCCESS_WITH_BACKEND_DATA(res_ptr)) {
	   redisReply *redis_ptr_user = ((redisReply *)res_ptr->result_user_data);
	   InstanceHolderForSession *instance_sesn_ptr_remote = CacheBackendInstantiateRawSessionRecord(sesn_ptr_this,
                                                                                                  redis_ptr_user,
                                                                                                  sesn_call_flags |
                                                                                                  CALL_FLAG_LOAD_DB_BACKEND_FOR_SESSION,
                                                                                                  NULL);

	   freeReplyObject(redis_ptr_user);

	   if (IS_PRESENT(instance_sesn_ptr_remote)) return instance_sesn_ptr_remote;
   }

   return NULL;
}

/**
 * @brief populate the Session object with attributes stored in the CacheBackend redisReplybackend object.
 * If no Session is provided a new one in created/recycler and returned.
 * This function does not change the core status of the session, it just populates data for further
 * processing up stream. Therefore no msgqueue broadcasting is performed,because we are mirroring the state of an already existing object.
 *
 * If HASHLOCALLy flag is set, InstantiateSession will hash the new session for session and uid depending on flag
 *
 *	DOES NOT PERFORM ANY VALIDATION: user must ensure session and uid are not in hash already.
 *
 *	DOES NOT SET BACKEND ACCESS POINTERS, only model data.
 *
 * 	@return populated session or NULL if unable to process
 *
 *	@param call_flags:
 * 	CALL_FLAG_REMOTE_SESSION
 * 	CALL_FLAG_HASH_SESSION_LOCALLY
 * 	CALL_FLAG_LOCK_SESSION
 * 	CALL_FLAG_HASH_UID_LOCALLY
 * 	CALL_FLAG_HASH_USERNAME_LOCALLY
 * 	CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION
 * 	CALL_FLAG_SNAPSHOT_INSTANCE: instance is purely for data representation. No locking no hashing etc...
 *
 *	@locks sens_ptr: if CALL_FLAG_LOCK_SESSION is passed
 *
 * 	@param sesn_ptr_in:
 * 	user supplied Session object to populate into
 *
 * 	@param sesn_ptr_this:
 * 	NO ASSUMPTION SHOULD BE MADE AS TO WHETHER THIS SESSION AND THE SESSION BEING BUILT ARE RELATED> THIS MAYBE A CARRIER SESSION ONLY
 * 	if FLAG_TRANSFER_DBDATA is setcopy key db data across.
 * 	The connected Session instance being serviced by a session worker. If NULL can mean servicing thread is ufsrv worker
 * 	or function used in a utilitarian way by another function. ALWAYS check for sesn_ptr_this before using it.
 * 	IF NULL BACKEND ACCESS CONTEXT WILL BE LOADED FROM UFSRVWORKER.
 *
 * 	@dynamic_memory: some session fields are malloc'ed
 * 	@dynamic_memory: not responsible for the redis_ptr. Caller  frees.
 *
 */
InstanceHolderForSession *
CacheBackendInstantiateRawSessionRecord(Session *sesn_ptr_this, redisReply *redis_ptr, unsigned long sesn_call_flags, InstanceHolderForSession *instance_sesn_ptr_out)
{
	Session *sesn_ptr	= NULL;
	InstanceHolderForSession *instance_sesn_ptr = NULL;

	if (IS_EMPTY(instance_sesn_ptr_out)) {
    instance_sesn_ptr = RecyclerGet(SessionPoolTypeNumber(), NULL, ((sesn_call_flags&CALL_FLAG_SNAPSHOT_INSTANCE)?CALL_FLAG_SNAPSHOT_INSTANCE:CALLFLAGS_EMPTY));//don't create Session hash
		if (unlikely(IS_EMPTY(instance_sesn_ptr))) {
			syslog(LOG_DEBUG, LOGSTR_INCONSISTENT_STATE, __func__, pthread_self(), sesn_ptr_this?sesn_ptr_this:0, sesn_ptr_this?SESSION_ID(sesn_ptr_this):0UL, LOGCODE_PROTO_INCONSISTENT_STATE, "Could not get Session *");

			return NULL;
		}
		sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
	} else {
		sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr_out);
		if (sesn_call_flags&CALL_FLAG_SNAPSHOT_INSTANCE)	SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_SNAPSHOT);
    instance_sesn_ptr = instance_sesn_ptr_out;
	}

	int res_code = RESCODE_PROG_LOCKED;
	if (sesn_call_flags&CALL_FLAG_LOCK_SESSION) {
		if (!(sesn_call_flags&CALL_FLAG_LOCK_SESSION_BLOCKING)) 	SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr, _LOCK_TRY_FLAG_TRUE, __func__);
		else 																											SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr, _LOCK_TRY_FLAG_FALSE, __func__);

		if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_SUCCESS)) {
			if (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_THIS_THREAD)) res_code = RESCODE_PROG_LOCKED_THIS_THREAD;
		} else {
			if (IS_EMPTY(instance_sesn_ptr_out)) SessionReturnToRecycler (instance_sesn_ptr, (ContextData *)NULL, ((sesn_call_flags&CALL_FLAG_SNAPSHOT_INSTANCE)?CALL_FLAG_SNAPSHOT_INSTANCE:0));
			return NULL;
		}
	}

	///>>> SESSION LOCKED if requested <<<<

	if (sesn_call_flags&CALL_FLAG_LOAD_DB_BACKEND_FOR_SESSION) {
    memcpy(SESSION_UFSRVUID(sesn_ptr), redis_ptr->element[REDIS_KEY_USER_UID]->str, CONFIG_MAX_UFSRV_ID_SZ);
    SESSION_USERID_TEMP(sesn_ptr) = UfsrvUidGetSequenceId(&SESSION_UFSRVUIDSTORE(sesn_ptr));
		_DbBackendBootstrapIntoBrandNewSession(sesn_ptr, true);
		if (SESSION_RESULT_TYPE_ERROR(sesn_ptr)) {
			goto exit_with_session_unlock;
		}
	}

	SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_UNDERCONSTRUCTION);

	//RECORD FOR UID '312' on SERVER '292141944' with CID 'sid' STATUS '1454125207'
	//only set it if remote is not requested: they have two different semantics
	if (!SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_SNAPSHOT))	if (!(sesn_call_flags&CALL_FLAG_REMOTE_SESSION))	SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_MIGRATED);

	if (sesn_call_flags&CALL_FLAG_REMOTE_SESSION)	SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_REMOTE);

	{//begin session population block
		sesn_ptr->session_id = strtoul(redis_ptr->element[REDIS_KEY_USER_CID]->str, NULL, 10);
		if (sesn_call_flags&CALL_FLAG_HASH_SESSION_LOCALLY) {
			if (!(AddToHash(&(sessions_delegator_ptr->hashed_sessions.hashtable), (void *)instance_sesn_ptr))) {
				//goto session_hash_error;
				goto exit_with_session_unlock;//we barely touched it
			}
		}

		//session objectified, locked, session-hashed,
    if (!(sesn_call_flags&CALL_FLAG_LOAD_DB_BACKEND_FOR_SESSION)) {
      memcpy(SESSION_UFSRVUID(sesn_ptr), redis_ptr->element[REDIS_KEY_USER_UID]->str, CONFIG_MAX_UFSRV_ID_SZ);
      SESSION_USERID_TEMP(sesn_ptr) = UfsrvUidGetSequenceId(&SESSION_UFSRVUIDSTORE(sesn_ptr));
    }
		if (sesn_call_flags&CALL_FLAG_HASH_UID_LOCALLY) {
			if (!(AddToHash(&(sessions_delegator_ptr->hashed_userids.hashtable), (void *)instance_sesn_ptr))) {
				goto uid_hash_error;
			}
		}

    SESSION_EID(sesn_ptr) = strtoul(redis_ptr->element[REDIS_KEY_USER_EVENT_COUNTER]->str, NULL, 10);

		//session objectified, locked, session-hashed, uid-hashed
		SESSION_USERNAME(sesn_ptr) = strdup(redis_ptr->element[REDIS_KEY_USER_USER_NAME]->str);
		if (sesn_call_flags&CALL_FLAG_HASH_USERNAME_LOCALLY) {
			if (!(AddToHash(&(sessions_delegator_ptr->hashed_usernames.hashtable), (void *)instance_sesn_ptr))) {
				goto username_hash_error;
			}
		}

		if (redis_ptr->element[REDIS_KEY_USER_PROFILE_KEY]->len == CONFIG_USER_PROFILEKEY_MAX_SIZE) {
			memcpy(SESSION_USER_PROFILE_KEY(sesn_ptr), redis_ptr->element[REDIS_KEY_USER_PROFILE_KEY]->str, CONFIG_USER_PROFILEKEY_MAX_SIZE);
		}

		//this is unassigned placeholder
		//SESSION_WHEN(sesn_ptr)					=strtoul(redis_ptr->element[REDIS_KEY_USER_WHEN]->str, NULL, 10);
		SESSION_WHEN_SERVICED(sesn_ptr)	= strtoul(redis_ptr->element[REDIS_KEY_USER_WHEN_SERVICED]->str, NULL, 10);
		SESSION_WHEN_SUSPENDED(sesn_ptr) = strtoul(redis_ptr->element[REDIS_KEY_USER_WHEN_SUSPENDED]->str, NULL, 10);

		SESSION_UFSRV_GEOGROUP(sesn_ptr) = strtoul(redis_ptr->element[REDIS_KEY_USER_GEOGROUP]->str, NULL, 10);

		memcpy(SESSION_HADDRESS(sesn_ptr), redis_ptr->element[REDIS_KEY_USER_HADDRESS]->str,
				redis_ptr->element[REDIS_KEY_USER_HADDRESS]->len + 1 > MAXHOSTLEN?MAXHOSTLEN:redis_ptr->element[REDIS_KEY_USER_HADDRESS]->len + 1);

		if ((sesn_call_flags&CALL_FLAG_TRANSFER_DB_USERDATA) && !IS_EMPTY(SESSION_USERNICKNAME(sesn_ptr_this))) {
			SESSION_USERNICKNAME(sesn_ptr) = SESSION_USERNICKNAME(sesn_ptr_this);//transfer by reference
			SESSION_USERNICKNAME(sesn_ptr_this) = NULL;
		} else	if (!IS_EMPTY(redis_ptr->element[REDIS_KEY_USER_NICKNAME]->str))	{
				SESSION_USERNICKNAME(sesn_ptr) = strdup(redis_ptr->element[REDIS_KEY_USER_NICKNAME]->str);//direct assignment is OK as it comes from trusted source
			}

		//TODO: CHECK FOR MEMORY OVERRUN
		memcpy (SESSION_COOKIE(sesn_ptr), redis_ptr->element[REDIS_KEY_USER_COOKIE]->str, strlen(redis_ptr->element[REDIS_KEY_USER_COOKIE]->str)+1);

		//TODO: FIX status and use bit defined sesn_ptr->stat
		unsigned sesn_stat = strtoul(redis_ptr->element[REDIS_KEY_USER_STATUS]->str, NULL, 10);
		switch (sesn_stat)
		{
      case 1:
        if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_REMOTE))	SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_REMOTE_CONNECTED);
        //otherwise for migrated session we only set to connected once Socket correctly swapped over in Unsuspend
      break;

      case 2:
        SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_SUSPENDED);
      break;

		}

		if (IS_PRESENT(redis_ptr->element[REDIS_KEY_USER_BASELOC]->str) && (*redis_ptr->element[REDIS_KEY_USER_BASELOC]->str != '*')) {
			UpdateBaseLocAssignment (sesn_ptr, (const char *)redis_ptr->element[REDIS_KEY_USER_BASELOC]->str, 0);
		}

		if (IS_PRESENT(redis_ptr->element[REDIS_KEY_HOME_BASELOC]->str) && (*redis_ptr->element[REDIS_KEY_HOME_BASELOC]->str != '*')) {
			UpdateHomeBaseLocAssignment (sesn_ptr, (const char *)redis_ptr->element[REDIS_KEY_USER_BASELOC]->str, 0);
		}

		if (IS_PRESENT(redis_ptr->element[REDIS_KEY_LOCATION_USER]->str) && (*redis_ptr->element[REDIS_KEY_LOCATION_USER]->str != '*')) {
      if ((ParseCacheBackendStoredLocationDescription(SESSION_ULOCATION_BYUSER_PTR(sesn_ptr), redis_ptr->element[REDIS_KEY_LOCATION_USER]->str, false)) == 0) {
        SESSION_ULOCATION_BYUSER_INITIALISED(sesn_ptr) = 1; //TODO: this is effectively last known value
      }
    }

		if (IS_PRESENT(redis_ptr->element[REDIS_KEY_LOCATION_SERVER]->str) && (*redis_ptr->element[REDIS_KEY_LOCATION_SERVER]->str != '*')) {
      if ((ParseCacheBackendStoredLocationDescription(SESSION_ULOCATION_BYSERVER_PTR(sesn_ptr),
                                                      redis_ptr->element[REDIS_KEY_LOCATION_SERVER]->str, false)) == 0) {
        SESSION_ULOCATION_BYSERVER_INITIALISED(sesn_ptr) = 1; //TODO: this is effectively last known value
      }
    }

		//IMPORTANT OBSERVE THE ORDER OF THE EXIT LABLES BELOW WITH RESPECT TO THE ORDERING OF HASH INVOCATIONS

		//session objectified, locked, session-hashed, uid-hashed, uname-hashed, all dynamic memory fields setup
		SessionTransferAccessContext(sesn_ptr_this, sesn_ptr, (IS_PRESENT(sesn_ptr_this)?0:1));//if sesn_ptr_this is NULL access context is loaded from ufsrvworker

		unsigned long sesn_call_flags_final = 0;

		if (sesn_call_flags&CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION) {
			//we want full fence list for this session + for each session full list of session
			int failed_lists = InstateFenceListsForUser (instance_sesn_ptr, sesn_call_flags_final, (MEMBER_FENCE|INVITED_FENCE), true);
			if (failed_lists != 0)	goto fence_attachment_error;
		} else {
			SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_FENCELIST_LAZY);
#ifdef __UF_TESTING
			syslog(LOG_DEBUG, "%s: {pid:'%lu', o:'%p', uname:'%s'} Fences Lists LAZILY initialised for user...", __func__, pthread_self(), sesn_ptr, SESSION_USERNAME(sesn_ptr));
#endif
		}

		//TODO: we need this info but too expensive for ufsrvapi, unless fence pointer is changed to logical fid
		if (!(SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_SNAPSHOT))) {
			UpdateSessionGeoFenceDataByFid (sesn_ptr, strtoul(redis_ptr->element[REDIS_KEY_CURRENT_GEOFENCE]->str?:"0", NULL, 10),
																							strtoul(redis_ptr->element[REDIS_KEY_PAST_GEOFENCE]->str?:"0", NULL, 10));
		}

		CacheBackendLoadUserPreferencesBoolean (sesn_ptr);

		if (IS_PRESENT(redis_ptr->element[REDIS_KEY_USER_AVATAR]->str) && (*redis_ptr->element[REDIS_KEY_USER_AVATAR]->str!='*')) {
      if (!IS_EMPTY(SESSION_USERAVATAR(sesn_ptr))) {
        free(SESSION_USERAVATAR(sesn_ptr));
      }
      SESSION_USERAVATAR(sesn_ptr) = strdup(redis_ptr->element[REDIS_KEY_USER_AVATAR]->str);
    }

//		LoadShareLists (sesn_ptr);//REMINDER: THIS IS CURRENLY LAZILY INITIALISED PER LIST TO PRESERVE MEMORY

		SESNSTATUS_UNSET(sesn_ptr->stat, SESNSTATUS_UNDERCONSTRUCTION);

	}//end population block

	exit_success:
	SESSION_RESULT_CODE(sesn_ptr) = res_code;
	return instance_sesn_ptr;

	//long march to recovery....originally used ClearLocalSessionCache (sesn_ptr_this, sesn_ptr, 0);

	fence_attachment_error:
	if (sesn_call_flags&CALL_FLAG_HASH_USERNAME_LOCALLY)	RemoveFromHash(&(sessions_delegator_ptr->hashed_usernames.hashtable), (void *) instance_sesn_ptr);
	//add dynamic memory fields if any

	username_hash_error:
	if (sesn_call_flags&CALL_FLAG_HASH_UID_LOCALLY)	RemoveFromHash(&(sessions_delegator_ptr->hashed_userids.hashtable), (void *) instance_sesn_ptr);
	free(SESSION_USERNAME(sesn_ptr));

	uid_hash_error:
	SESSION_USERID_TEMP(sesn_ptr) = 0;
	if (sesn_call_flags&CALL_FLAG_HASH_SESSION_LOCALLY)	RemoveFromHash(&(sessions_delegator_ptr->hashed_sessions.hashtable), (void *) instance_sesn_ptr);
	SESSION_ID(sesn_ptr) = 0;

	exit_with_session_unlock:
	if (sesn_call_flags&CALL_FLAG_LOCK_SESSION)	if (res_code == RESCODE_PROG_LOCKED)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr, __func__);//only unlock if we owned the lock
	sesn_ptr->stat = 0;
	SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_RECYCLED);
	SessionReturnToRecycler (instance_sesn_ptr, (ContextData *)NULL, 0);

	return NULL;

}

/**
 * 	@brief: Light instantiation user Session, mostly used for so-called incognito session; ie session that has local scope
 * 	and not hashed anywhere.
 *
 * 	@pram sesn_ptr_carrier:	justa carrier Session for backend access and logging
 * 	@param sesn_ptr_in: is passed, this instance will hold the processed Session data, otherwise TypePoll is used.
 * 	@param redis_ptr: the raw redis record for the Session
 *
 */
InstanceHolder *
SessionLightlyInstantiateFromBackendRaw (Session *sesn_ptr_carrier, InstanceHolder *instance_holder_ptr_out, redisReply *redis_ptr, unsigned long sesn_call_flags)
{
	if (unlikely(IS_EMPTY(redis_ptr))) {
		syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Missing 'redisReply *'");

		return NULL;
	}

	Session *sesn_ptr	= NULL;
	Socket 	*ssptr		= NULL;
  InstanceHolder *instance_sesn_ptr = NULL;

	if (IS_EMPTY(instance_holder_ptr_out)) {
    instance_sesn_ptr = RecyclerGet(SessionPoolTypeNumber(), NULL, CALLFLAGS_EMPTY);//don't create Session hash
		if (unlikely(IS_EMPTY(instance_sesn_ptr))) {
			syslog(LOG_DEBUG, LOGSTR_INCONSISTENT_STATE, __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), LOGCODE_PROTO_INCONSISTENT_STATE, "Could not get Session *");

			return NULL;
		}
	} else {
    instance_sesn_ptr = instance_holder_ptr_out;
	}

	sesn_ptr = GetInstance(instance_sesn_ptr);

	bool lock_already_owned = false;

	if (sesn_call_flags&CALL_FLAG_LOCK_SESSION) {
		SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr, _LOCK_TRY_FLAG_TRUE, __func__);
		if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR)) {
			if (IS_EMPTY(instance_holder_ptr_out))  SessionReturnToRecycler (instance_sesn_ptr, (ContextData *)NULL, CALLFLAGS_EMPTY);

			return NULL;
		}

		lock_already_owned = (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_THIS_THREAD));
	}

	///>>> SESSION LOCKED <<<<

	SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_UNDERCONSTRUCTION);

	//RECORD FOR UID '312' on SERVER '292141944' with CID 'sid' STATUS '1454125207'
	//only set it if remote is not requested: they have two different semantics
	if (!(sesn_call_flags&CALL_FLAG_REMOTE_SESSION))	SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_MIGRATED);

	if (sesn_call_flags&CALL_FLAG_REMOTE_SESSION)	SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_REMOTE);

	{//begin session population block
		sesn_ptr->session_id = strtoul(redis_ptr->element[REDIS_KEY_USER_CID]->str, NULL, 10);
		if (sesn_call_flags&CALL_FLAG_HASH_SESSION_LOCALLY) {
			if (!(AddToHash(&(sessions_delegator_ptr->hashed_sessions.hashtable), (void *)instance_sesn_ptr))) {
				//goto session_hash_error;
				goto exit_with_session_unlock;//we barely touched it
			}
		}

		//session objectified, locked, session-hashed,
		memcpy(SESSION_UFSRVUID(sesn_ptr), (UfsrvUid *)redis_ptr->element[REDIS_KEY_USER_UID]->str, CONFIG_MAX_UFSRV_ID_SZ);
		SESSION_USERID_TEMP(sesn_ptr) = UfsrvUidGetSequenceId(&SESSION_UFSRVUIDSTORE(sesn_ptr));
		if (sesn_call_flags&CALL_FLAG_HASH_UID_LOCALLY) {
			if (!(AddToHash(&(sessions_delegator_ptr->hashed_userids.hashtable), (void *)instance_sesn_ptr))) {
				goto uid_hash_error;
			}
		}

		//session objectified, locked, session-hashed, uid-hashed
		SESSION_USERNAME(sesn_ptr) = strdup(redis_ptr->element[REDIS_KEY_USER_USER_NAME]->str);
		if (sesn_call_flags&CALL_FLAG_HASH_USERNAME_LOCALLY) {
			if (!(AddToHash(&(sessions_delegator_ptr->hashed_usernames.hashtable), (void *)instance_sesn_ptr))) {
				goto username_hash_error;
			}
		}

		//TODO: CHECK FOR MEMORY OVERRUN
		if (!IS_EMPTY(redis_ptr->element[REDIS_KEY_USER_COOKIE]->str))
		memcpy (SESSION_COOKIE(sesn_ptr), redis_ptr->element[REDIS_KEY_USER_COOKIE]->str, strlen(redis_ptr->element[REDIS_KEY_USER_COOKIE]->str) +1 );//CONFIG_MAX_COOKIE_SZ


		//session objectified, locked, session-hashed, uid-hashed, uname-hashed, all dynamic memory fields setup
		if (sesn_call_flags&CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION) {
			//we want full fence list for this session + for each session full list of session
			SessionTransferAccessContext (sesn_ptr_carrier, sesn_ptr, 0);
			if ((InstateFenceListsForUser(instance_sesn_ptr, SESSION_CALLFLAGS_EMPTY, MEMBER_FENCE, true)) != 0)	goto fence_attachment_error;
		} else {
			SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_FENCELIST_LAZY);
		}

		SESNSTATUS_UNSET(sesn_ptr->stat, SESNSTATUS_UNDERCONSTRUCTION);

	}//end population block

	exit_success:
#ifdef __UF_FULLDEBUG
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:%lu): SUCCESSFULLY instantiated BACKEND Session (o:'%p', cid:'%lu' uid:'%lu)", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_USERID(sesn_ptr));
#endif

	//TODO: LOST SESSION LOCK STATE
	return instance_sesn_ptr;

	//long march to recovery....originally used ClearLocalSessionCache (sesn_ptr_this, sesn_ptr, 0);

	fence_attachment_error:
	if (sesn_call_flags&CALL_FLAG_HASH_USERNAME_LOCALLY)	RemoveFromHash(&(sessions_delegator_ptr->hashed_usernames.hashtable), (void *) instance_sesn_ptr);
	//add dynamic memory fields if any

	username_hash_error:
	if (sesn_call_flags&CALL_FLAG_HASH_UID_LOCALLY)	RemoveFromHash(&(sessions_delegator_ptr->hashed_userids.hashtable), (void *) instance_sesn_ptr);
	free(SESSION_USERNAME(sesn_ptr));

	uid_hash_error:
	SESSION_USERID_TEMP(sesn_ptr) = 0;
	if (sesn_call_flags&CALL_FLAG_HASH_SESSION_LOCALLY)	RemoveFromHash(&(sessions_delegator_ptr->hashed_sessions.hashtable), (void *) instance_sesn_ptr);
	SESSION_ID(sesn_ptr) = 0;

	exit_with_session_unlock:
	if (sesn_call_flags&CALL_FLAG_LOCK_SESSION)	if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr, __func__);
	sesn_ptr->stat = 0;
	SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_RECYCLED);
	if (IS_EMPTY(instance_holder_ptr_out))  SessionReturnToRecycler (instance_sesn_ptr, (ContextData *)NULL, CALLFLAGS_EMPTY);

	return NULL;

}

 /*
 ** End of export functions... --------------------------------------------
 */

 /*
	-called from wrapper.AnswerTelnetConnectio()
	-instantiate new session object
	-attach to Session master List
	-attach to it vrious Socket pointers
	-on success return newly created session
*/

/**
 *  @this function is not thread-safe, as it uses the masterptr->persistance_backend handle which is not protected.
 *   It is supposed to be called from the main listener thread.
 *   based on http://engineering.intenthq.com/2015/03/icicle-distributed-id-generation-with-redis-lua/
 *   /usr/local/redis/3.2.5/redis-cli -p 19705  SCRIPT LOAD "$(cat /opt/redis/redis_id_generation.lua)"
 */
inline unsigned long
GenerateSessionId (void)
{
#if 1
	unsigned long id = 0;

	#define LOGICAL_SHARD_ID_BITS 10
	#define SEQUENCE_BITS 12

	#define TIMESTAMP_SHIFT  (SEQUENCE_BITS + LOGICAL_SHARD_ID_BITS)
	#define LOGICAL_SHARD_ID_SHIFT  SEQUENCE_BITS

	// These three bitopped constants are also used as bit masks for the maximum value of the data they represent.
	#define MAX_SEQUENCE  ()~(-1 << SEQUENCE_BITS))//4095
	#define MAX_LOGICAL_SHARD_ID  (~(-1 << LOGICAL_SHARD_ID_BITS))//1023
	#define MIN_LOGICAL_SHARD_ID  1

	#define CUSTOM_EPOCH_IN_MILLIS  1401277473000UL//Wed, 28 May 2014 11:44:33 GMT
	#define MILLIS_IN_ONE_MICRO_SEC	1000UL
	#define MICROS_IN_ONE_SEC 1000000UL

	#define MAX_BATCH_SIZE  (MAX_SEQUENCE + 1)

	 ///opt/redis/redis-cli -p 19705 EVALSHA 21bee0f6116c759cc9fd0407658f4ec88cf0a60e 4 4095 1 1023 1 <---1 is batch size)
	redisReply *redis_ptr=(*masterptr->persistance_backend->send_command_sessionless)
								(masterptr->persistance_backend, "EVALSHA %s 4 %d %d %d %d",
										REDIS_SCRIPT_SHA1_UNIQUE_ID, 4095, 1, 1023, 1);//REDIS_SCRIPT_SHA1_UNIQUE_ID

	if (unlikely((redis_ptr==NULL)))	goto final_return_id;

	if (unlikely((redis_ptr->type==REDIS_REPLY_ERROR)))
	{
	   syslog(LOG_DEBUG, "%s (pid:'%lu', err:'%d', errstr'%s'): REDIS_REPLY_ERROR COULD NOT GET REDIS RESPONSE", __func__, pthread_self(), ((redisContext *)masterptr->persistance_backend->persistance_agent)->err, ((redisContext *)masterptr->persistance_backend->persistance_agent)->errstr);
	   goto final_return;
	}

	if (unlikely(redis_ptr->type==REDIS_REPLY_NIL))
	{
	   syslog(LOG_DEBUG, "%s (pid='%lu'): COULD NOT RETRIEVE RECORD.",  __func__, pthread_self());
	   goto final_return;
	}

	//TODO: NOTICE: this should correspond with the fields returned by the lua script
	#define _REDIS_UID_FIELDS_COUNT	5

	if (redis_ptr->elements!=_REDIS_UID_FIELDS_COUNT)//emty set
	{
	   syslog(LOG_DEBUG, "%s (pid='%lu'): COULD NOT RETRIEVE RECORD: received empty set, or incomplete set: '%lu'", __func__, pthread_self(), redis_ptr->elements);
	   goto final_return;
	}

	#undef _REDIS_UID_FIELDS_COUNT

	/*return {
  start_sequence,
  end_sequence, -- Doesn't need conversion, the result of INCR or the variable set is always a number.
  logical_shard_id,
  tonumber(time[1]),
  tonumber(time[2])
  1) (integer) 10
2) (integer) 10
3) (integer) 1
4) (integer) 1454571918 //seconds
5) (integer) 826746	//micro seconds in the current second
184 467 440 737 095 516 15 max unsigned 64bit
184 351 241 100 538 716 40

}*/

		unsigned long sequence=redis_ptr->element[0]->integer;
		//((1454624775UL * MICROS_IN_ONE_SEC ) + 593028UL)/MILLIS_IN_ONE_MICRO_SEC;
		unsigned long timestamp=((redis_ptr->element[3]->integer*MICROS_IN_ONE_SEC) + redis_ptr->element[4]->integer)/MILLIS_IN_ONE_MICRO_SEC;

		unsigned shard_id = redis_ptr->element[2]->integer;

		//validateLogicalShardId(logicalShardId);

		  // The purpose of this is to get a 64-bit ID of the following
		  // format:
		  //
		  //  ABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBCCCCCCCCCCDDDDDDDDDDDD
		  //
		  // Where:
		  //   * A is the reserved signed bit .
		  //   * B is the timestamp in milliseconds since custom epoch bits, 41 in total.
		  //   * C is the logical shard ID, 10 bits in total.
		  //   * D is the sequence, 12 bits in total.

		  id = ((timestamp - CUSTOM_EPOCH_IN_MILLIS) << TIMESTAMP_SHIFT)|
						(shard_id << LOGICAL_SHARD_ID_SHIFT)|
						sequence;

		  final_return:
		  freeReplyObject(redis_ptr);

#ifdef __UF_FULLDEBUG
		  syslog(LOG_DEBUG, LOGSTR_SESSION_DISTRIBUTED_ID_GENERATED, __func__, GET_BITS_IN_BETWEEN(id, 22, 63), GET_BITS_IN_BETWEEN(id, 12, 22), GET_N_BITS_FROM_REAR(id, 12), id, LOGCODE_SESSION_DISTRIBUTED_ID_GENERATED);
#endif

		  final_return_id:
		  return id;
#endif

}

unsigned long
GenerateSessionIdLocally (void)
{
	return (abs((unsigned long)(rand()*rand())<< 1));

}

/**
 * 	@brief: Primary interface for adding a new session to the framework. It checks the cache and instantiate from heas as neceassry.
 *
 *	@param protocol_id: >=0 initiate protocla specific initialisation. Pass '-1' to skip that.
 *
 *	@param call_flags CALL_FLAG_HASH_SESSION_LOCALLY: hash the session
 */

#if 0 //TODO finalise implementation
Session *SessionGet (int protocol_id, unsigned call_flags)
{

   Session sesnptr=(Session *)FetchRecycledObject();

   if (!sesnptr)//we new Session allocation
   {
	   //TODO increment miss counter
	   Socket *ssptr;
	   xmalloc(ssptr, (sizeof(Socket)));
	   memset (ssptr, 0, sizeof(Socket));

	   if (!(sesnptr=InstantiateSession(ssptr, dsptr, call_flags, masterptr->main_listener_protoid)))//thread-safe only called from this thread
		{
		   close (nsocket);//close (ssptr->sock);
		   free (ssptr);

		   return 0;
		}
   }
   else
   {
	   //re-assign relevant values to recycled session so we can use it
	   sesnptr->session_id=GenerateSessionId();

	   //reassign protocol as a reminder for future multi
	   SESSION_PROTOCOLTYPE(sesnptr)=(ProtocolTypeData *)&protocols_registry_ptr[masterptr->main_listener_protoid];

	   //invoke lifecycle callback for session initialisation (soft, recycler based)
		if (_PROTOCOL_CLLBACKS_INIT_SESSION(protocols_registry_ptr, masterptr->main_listener_protoid))
		{
#define SESSION_RECYCLERINSTANCE	1 //recycler instance
			_PROTOCOL_CLLBACKS_INIT_SESSION_INVOKE(protocols_registry_ptr, masterptr->main_listener_protoid,
													sesnptr, SESSION_RECYCLERINSTANCE);
#undef	SESSION_RECYCLERINSTANCE
		}

	   if (!(AddToHash(&(sessions_delegator_ptr->hashed_sessions.hashtable), (void *)sesnptr)))
	   {
		   //TODO: push back to recycler
		   return 0;
	   }

   }//Recycler instance

}
#endif


/**
 * param protocol_id: >=0 protocol id which can be used as index. If -1 no protocol is associated with this session
 */
Session *
InstantiateSession (Socket *ssptr, Socket *dsptr, unsigned call_flags, int protocol_id)
{
	Session *sesn_ptr;

	sesn_ptr = calloc(1, sizeof(Session));

	if ((sesn_ptr->session_id = GenerateSessionId()) == 0)	goto final_clean_up;

	SetShareListTypes (sesn_ptr);

	if (!CreateSessionService(sesn_ptr)) {
		syslog(LOG_ERR, "%s (pid:'%lu'): ERROR: COULD NOT CREATE SESSION SERVICE...", __func__, pthread_self());

		goto final_clean_up;
	}

	pthread_rwlockattr_init(&(sesn_ptr->session_events.rwattr));
	int rc = pthread_rwlock_init(&(sesn_ptr->session_events.rwlock), &(sesn_ptr->session_events.rwattr));//==0 on success
	if (rc == 0) {
		sesn_ptr->session_id = GenerateSessionId();

		if (ssptr) {
			//TODO: consider using local variable
			pthread_mutexattr_t attr;

			//Note: using adaptive mutex changes the error reporting behaviour in lock/unlock it would appears multipe locks acquired at the same time
			pthread_mutexattr_init(&(sesn_ptr->message_queue_in.mutex_attr));
			pthread_mutexattr_settype(&(sesn_ptr->message_queue_in.mutex_attr), PTHREAD_MUTEX_ADAPTIVE_NP);//PTHREAD_MUTEX_ERRORCHECK);

			if ((pthread_mutex_init (&(sesn_ptr->message_queue_in.mutex), 	&(sesn_ptr->message_queue_in.mutex_attr))) != 0) {
				syslog(LOG_ERR, "%s (pid:'%lu', errno:'%d'): ERROR: COULD NOT INITIALISE MUTEX FOR INCOMING SOCKETMESSAGE QUEUE...", __func__, pthread_self(), errno);
				pthread_mutexattr_destroy(&(sesn_ptr->message_queue_in.mutex_attr));

				goto final_clean_up;
			}

			pthread_mutexattr_destroy(&(sesn_ptr->message_queue_in.mutex_attr));

			///////////////

			pthread_mutexattr_init(&(sesn_ptr->message_queue_out.mutex_attr));
			pthread_mutexattr_settype(&(sesn_ptr->message_queue_out.mutex_attr), PTHREAD_MUTEX_ADAPTIVE_NP);//PTHREAD_MUTEX_ERRORCHECK);

			if ((pthread_mutex_init (&(sesn_ptr->message_queue_out.mutex), 	&(sesn_ptr->message_queue_out.mutex_attr))) != 0) {
				syslog(LOG_ERR, "%s (pid:'%lu' errno:'%d'): ERROR: COULD NOT INITIALISE MUTEX FOR OUTGOING SOCKETMESSAGE QUEUE...", __func__, pthread_self(), errno);
				pthread_mutexattr_destroy(&(sesn_ptr->message_queue_out.mutex_attr));

				goto final_clean_up;
			}

			pthread_mutexattr_destroy(&(sesn_ptr->message_queue_out.mutex_attr));

			sesn_ptr->ssptr = ssptr;
		}

		if (dsptr)	sesn_ptr->dsptr = dsptr;


		//invoke protocol session specific initialisation for this session
    if (protocol_id >= 0) {
      //1) assign static protocol type data
      SESSION_PROTOCOLTYPE(sesn_ptr) = (ProtocolTypeData *)ProtocolGet(protocol_id);
      //TODO: this is to be phased out infavour of protocol_type_data
      sesn_ptr->protocol_registry = (void *)&protocols_registry_ptr[protocol_id];

      //2)assign dynamic protocol type session data (per session)
      if (_PROTOCOL_CLLBACKS_INIT_SESSION(protocols_registry_ptr, protocol_id)) {
#define SESSION_RECYCLERINSTANCE	0
        _PROTOCOL_CLLBACKS_INIT_SESSION_INVOKE(protocols_registry_ptr, protocol_id, sesn_ptr, SESSION_RECYCLERINSTANCE);
#undef	SESSION_RECYCLERINSTANCE
      }
    }

    //Should not do this, as instance is not recycler managed and has for Sessions requires InstanceHolder type
//		if (call_flags&CALL_FLAG_HASH_SESSION_LOCALLY) {
//			if (!(AddToHash(&(sessions_delegator_ptr->hashed_sessions.hashtable), (void *)sesn_ptr))) {
//				goto mutex_clean_up;
//			}
//		}

		return (Session *)sesn_ptr;
	} else {
		char error_str[250];
		strerror_r(errno, error_str, 250);

		syslog(LOG_ERR, "%s (pid:'%lu'): ERROR (errno='%d' str='%s'): COULD NOT INITIALISE MUTEX", __func__, pthread_self(), errno, error_str);

		goto final_clean_up;
	}

	mutex_clean_up:
	pthread_rwlockattr_destroy(&(sesn_ptr->session_events.rwattr));
	pthread_mutexattr_destroy(&(sesn_ptr->message_queue_in.mutex_attr));
	pthread_mutexattr_destroy(&(sesn_ptr->message_queue_out.mutex_attr));

	pthread_rwlock_destroy(&(sesn_ptr->session_events.rwlock));
	pthread_mutex_destroy(&(sesn_ptr->message_queue_in.mutex));
	pthread_mutex_destroy(&(sesn_ptr->message_queue_out.mutex));
	//TODO: CLEAN UP PROTOCOL INIT

	goto final_clean_up;

	//
	final_clean_up:
	free (sesn_ptr);

	return NULL;

}  /**/

 /**
 * param protocol_id: >=0 protocol id which can be used as index. If -1 no protocol is associated with this session
 * This is more pool aware version of the function above.
 */
int
InstantiateSession2 (Session **sesn_ptr_in, unsigned long call_flags, int protocol_id)
{
	Session *sesn_ptr = NULL;

	if (sesn_ptr_in)	sesn_ptr = *sesn_ptr_in;
	else {
		sesn_ptr = calloc(1, sizeof(Session));
		*sesn_ptr_in  = sesn_ptr;
	}

	if (call_flags&CALL_FLAG_HASH_SESSION_LOCALLY) {
		if ((sesn_ptr->session_id = GenerateSessionId()) == 0) {
			if (IS_EMPTY(sesn_ptr_in))	free (sesn_ptr);
			return 0;
		}
	}

	SetShareListTypes (sesn_ptr);

	if (!CreateSessionService(sesn_ptr)) {
		syslog(LOG_ERR, "%s (pid:'%lu'): ERROR: COULD NOT CREATE SESSION SERVICE...", __func__, pthread_self());

		goto final_clean_up;
	}

	pthread_rwlockattr_init(&(sesn_ptr->session_events.rwattr));
	int rc = pthread_rwlock_init(&(sesn_ptr->session_events.rwlock), &(sesn_ptr->session_events.rwattr));//==0 on success

	if (unlikely(rc != 0)) {
		char error_str[MBUF] = {0};
		char *er;
		er = strerror_r(errno, error_str, MBUF);

		syslog(LOG_ERR, "%s {pid:'%lu', errno:'%d' error:'%s'}: ERROR: COULD NOT INITIALISE MUTEX",	__func__, pthread_self(), errno, er);

		goto final_clean_up;
	}

	if (true) {
		//TODO: consider using local variable
		pthread_mutexattr_t attr;

		//Note: using adaptive mutex changes the error reporting behaviour in lock/unlock it would appears multipe locks acquired at the same time
		pthread_mutexattr_init(&(sesn_ptr->message_queue_in.mutex_attr));
		pthread_mutexattr_settype(&(sesn_ptr->message_queue_in.mutex_attr), PTHREAD_MUTEX_ADAPTIVE_NP);//PTHREAD_MUTEX_ERRORCHECK);

		if ((pthread_mutex_init (&(sesn_ptr->message_queue_in.mutex), 	&(sesn_ptr->message_queue_in.mutex_attr)))!=0) {
			syslog(LOG_ERR, "%s (pid:'%lu', errno:'%d'): ERROR: COULD NOT INITIALISE MUTEX FOR INCOMING SOCKETMESSAGE QUEUE...", __func__, pthread_self(), errno);
			pthread_mutexattr_destroy(&(sesn_ptr->message_queue_in.mutex_attr));

			goto final_clean_up;
		}

		pthread_mutexattr_destroy(&(sesn_ptr->message_queue_in.mutex_attr));

		///////////////

		pthread_mutexattr_init(&(sesn_ptr->message_queue_out.mutex_attr));
		pthread_mutexattr_settype(&(sesn_ptr->message_queue_out.mutex_attr), PTHREAD_MUTEX_ADAPTIVE_NP);//PTHREAD_MUTEX_ERRORCHECK);

		if ((pthread_mutex_init (&(sesn_ptr->message_queue_out.mutex), 	&(sesn_ptr->message_queue_out.mutex_attr)))!=0) {
			syslog(LOG_ERR, "%s (pid:'%lu' errno:'%d'): ERROR: COULD NOT INITIALISE MUTEX FOR OUTGOING SOCKETMESSAGE QUEUE...", __func__, pthread_self(), errno);
			pthread_mutexattr_destroy(&(sesn_ptr->message_queue_out.mutex_attr));

			goto final_clean_up;
		}

		pthread_mutexattr_destroy(&(sesn_ptr->message_queue_out.mutex_attr));

		sesn_ptr->ssptr = calloc(1, sizeof(Socket));
	}


	//invoke protocol session specific initialisation for this session
  if (protocol_id >= 0) {
    //1) assign static protocol type data
    SESSION_PROTOCOLTYPE(sesn_ptr) = (ProtocolTypeData *)ProtocolGet(protocol_id);
    //TODO: this is to be phased out in favour of protocol_type_data
    sesn_ptr->protocol_registry = (void *)&protocols_registry_ptr[protocol_id];

    //2)assign dynamic protocol type session data (per session)
    if (_PROTOCOL_CLLBACKS_INIT_SESSION(protocols_registry_ptr, protocol_id)) {
#define SESSION_RECYCLERINSTANCE	0
      _PROTOCOL_CLLBACKS_INIT_SESSION_INVOKE(protocols_registry_ptr, protocol_id, sesn_ptr, SESSION_RECYCLERINSTANCE);
#undef	SESSION_RECYCLERINSTANCE
    }
  }

  //Shouldn't do this, as we need and InstanceHolder type. hashing should be done at Get init level
//	if (call_flags&CALL_FLAG_HASH_SESSION_LOCALLY) {
//		if (!(AddToHash(&(sessions_delegator_ptr->hashed_sessions.hashtable), (void *)sesn_ptr))) {
//			//TODO: CLEANUP: FREE object and mutextes
//			goto mutex_clean_up;
//		}
//	}

	return 0;//success

	mutex_clean_up:
	pthread_rwlockattr_destroy(&(sesn_ptr->session_events.rwattr));
	pthread_mutexattr_destroy(&(sesn_ptr->message_queue_in.mutex_attr));
	pthread_mutexattr_destroy(&(sesn_ptr->message_queue_out.mutex_attr));

	pthread_rwlock_destroy(&(sesn_ptr->session_events.rwlock));
	pthread_mutex_destroy(&(sesn_ptr->message_queue_in.mutex));
	pthread_mutex_destroy(&(sesn_ptr->message_queue_out.mutex));

	//this was allocated in tandem with mutex
	free(sesn_ptr->ssptr);
	//TODO: CLEAN UP PROTOCOL INIT

	goto final_clean_up;

	//
	final_clean_up:
	if (!sesn_ptr_in)	free (sesn_ptr);

	return 1;

}  /**/

/**
 * 	@brief: Carrier sessions are anonymous sessions not associated with real users, or visible in system hashes, primarily used to drive functions
 * 	that required a session with backend access context.
 */
InstanceHolderForSession *
InstantiateCarrierSession (InstanceHolderForSession *instance_sesn_ptr_out, enum WorkerType worker, unsigned long sesn_call_flags)
{
	Session *sesn_ptr;
	InstanceHolder *instance_sesn_ptr = NULL;

	if (IS_PRESENT(instance_sesn_ptr_out)){
	  instance_sesn_ptr = instance_sesn_ptr_out;
	} else {
    instance_sesn_ptr = (InstanceHolderForSession *)RecyclerGet(SessionPoolTypeNumber(), NULL, CALL_FLAG_CARRIER_INSTANCE|sesn_call_flags);
    if (unlikely(IS_EMPTY(instance_sesn_ptr)))	return NULL;
	}

	sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
	SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_CARRIER);

	switch (worker)
	{
		case WORKERTYPE_UFSRVWORKER:
			SessionLoadEphemeralMode (sesn_ptr);
			return instance_sesn_ptr;
		case WORKERTYPE_SESSIONWORKER:
			//TODO: implement transfer of current thread's backend access context to new session
			return instance_sesn_ptr;
	}

	return NULL;
}

//
//@brief deallocate MessageQueue
//
static inline void *
_s_DestructSocketMessageQueue (Session *sesn_ptr, MessageQueue *msg_que_ptr)
{
	if (msg_que_ptr->queue.nEntries==0) return NULL;

	syslog(LOG_DEBUG, "DestructSocketMessageQueue (pid:'%lu' cid:'%lu'): DESTRUCTING Queue (msg count='%lu')...",
			pthread_self(), sesn_ptr->session_id, msg_que_ptr->queue.nEntries);

	QueueEntry *qe_ptr=NULL;
	while (msg_que_ptr->queue.nEntries!=0)
	{
		//1)Retrieve carrier object
		qe_ptr=deQueue(&(msg_que_ptr->queue));

		DestructSocketMessage ((SocketMessage *)qe_ptr->whatever);

		free (qe_ptr->whatever);
		free(qe_ptr);
	}

	syslog(LOG_DEBUG, "DestructSocketMessageQueue (pid:'%lu' cid:'%lu'): DESTRUCTED Queue (msg count='%lu')...",
				pthread_self(), sesn_ptr->session_id, msg_que_ptr->queue.nEntries);

	return sesn_ptr;

}

inline void
DestructSocketMessage (SocketMessage *sock_msg_ptr)
{
  if (sock_msg_ptr->processed_msg_size > 0)	free(sock_msg_ptr->_processed_msg);
  if (sock_msg_ptr->raw_msg_size > 0) free(sock_msg_ptr->_raw_msg);
  if (sock_msg_ptr->holding_buffer_msg_size > 0) free(sock_msg_ptr->holding_buffer);

  memset (sock_msg_ptr, 0, sizeof(SocketMessage));

}

/**
 * 	@brief: Helper function to ease Sessions through final stage of being let through
 *
 * 	@locked sesn_ptr_backend: in main loop
 * 	@unlocks: None
 * 	@locks: None
 *
 * 	@call_flags CALL_FLAG_SUSSPEND_SESSION: suspend session on error
 */
UFSRVResult *
HandleSessionReturnHandshake (InstanceHolderForSession *instance_sesn_ptr, SocketMessage *sock_msg_ptr, unsigned long sesn_call_flags)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	///>>>>> sesn_ptr_backend IS NOW LOCKED. sesn_ptr returned to pool <<<<<<<<<<<<<

	//user good to roll off: acknowledge the connection by replying in WS protocol
	UFSRVResult *res_ptr_aux;
	res_ptr_aux = ProcessOutgoingWsHandshake(sesn_ptr, sock_msg_ptr);

	switch (_RESULT_TYPE(res_ptr_aux))
	{
		case RESULT_TYPE_ERR:
			if (_RESULT_CODE(res_ptr_aux) == RESCODE_IO_CONNECTIONCLOSED) {
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p' cid:'%lu'):  COULD NOT HANDSHAKE: connection closed", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
			} else if (_RESULT_CODE(res_ptr_aux) == RESCODE_PROTOCOL_WSHANDSHAKE) {
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p' cid:'%lu'):  COULD NOT HANDSHAKE: parsing error", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
			}

      statsd_gauge_inc(sesn_ptr->instrumentation_backend, "worker.work.handshake_failed", 1);

			if (CALLGFLAG_IS_SET(sesn_call_flags, CALL_FLAG_SUSSPEND_SESSION))	SuspendSession(instance_sesn_ptr, SOFT_SUSPENSE);

			_RETURN_RESULT_SESN(sesn_ptr, instance_sesn_ptr, RESULT_TYPE_ERR, RESCODE_PROTOCOL_WSHANDSHAKE)
	}

	exit_success:
		_RETURN_RESULT_SESN(sesn_ptr, instance_sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_PROTOCOL_WSHANDSHAKE)
}

///////// START STATE \\\\\\

/**
 * 	@brief:
 * 	This is the main entry point for users that presents with a cookie which is not cached locally, or at the cache backend.
 * 	For example, brand new users, or users that have had their session invalidated.  The key to unlocking this user
 * 	is identifying their UID.
 * 	All return functions funnel back into here, before returning to the main loop.
 * 	Also, all SuspendSession resulting from errors is localised here in one spot--Save for situations where that is not possible.
 *
 *	Care must be taken when loading session data from cache backend as it maybe stale, especially if user re-registered, for example nominated
 *	new nickname.
 *
 * 	Successful Sessions will all have performed return handshake
 *
 * 	@param sesn_ptr_transient: This is a transient Session: ie it's only been hadshaked one-way incoming. This function processes authentication
 * 	upto postHandShake  protocol callback which should be invoked by the caller
 */
inline UFSRVResult *
AuthenticateForNonCookieHashedSession (InstanceHolderForSession *instance_sesn_ptr_transient)
{
	__unused unsigned long	session_id_invoked;
	Session 		*sesn_ptr_processed = NULL,
	            *sesn_ptr_transient = SessionOffInstanceHolder(instance_sesn_ptr_transient);
	InstanceHolderForSession *instance_sesn_ptr_processed;

	//remember current session in case we get a swap
	session_id_invoked = SESSION_ID(sesn_ptr_transient);

	UFSRVResult *res_ptr = _DbBackendVerifyAndInitialiseSession(instance_sesn_ptr_transient);

	if (_RESULT_TYPE_SUCCESS(res_ptr)) {
		switch (res_ptr->result_code) {
			case RESCODE_USER_INSTATED:
				//local unconnected session was instated as connected. we have a different session object
				instance_sesn_ptr_processed = (InstanceHolderForSession *)res_ptr->result_user_data; break;

			case RESCODE_USER_MIGRATED:
				//new session was migrated from the backend
        instance_sesn_ptr_processed = (InstanceHolderForSession *)res_ptr->result_user_data; break;

			case RESULT_CODE_USER_AUTHENTICATION:
				//brand new user session
        instance_sesn_ptr_processed = (InstanceHolderForSession *)res_ptr->result_user_data; break;
		}

		//suspend on error
		sesn_ptr_processed = SessionOffInstanceHolder(instance_sesn_ptr_processed);
		UFSRVResult *res_ptr_error = HandleSessionReturnHandshake(instance_sesn_ptr_processed, NULL, CALL_FLAG_SUSSPEND_SESSION);
		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr_processed)) {
			_RETURN_RESULT_SESN(sesn_ptr_processed, instance_sesn_ptr_processed, RESULT_TYPE_SUCCESS, RESULT_CODE_USER_INITIALISED);
		}
		else return res_ptr_error;//session suspended
	}
	else if (_RESULT_TYPE_ERROR(res_ptr)) {
		UFSRVResult temp_res,
                *temp_res_ptr;

		temp_res_ptr = &temp_res;
		*temp_res_ptr = *res_ptr;

		SuspendSession (instance_sesn_ptr_transient, SOFT_SUSPENSE);//this may invoke routines that modify desired res_ptr result returned above

		*res_ptr = *temp_res_ptr;

		if (_RESULT_CODE_EQUAL(res_ptr, RESULT_CODE_USER_AUTHENTICATION)) {
#ifdef __UF_TESTING
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: Setting SESNSTATUS_DEFERRED_RECYCLE flag...", __func__, pthread_self(), sesn_ptr_transient);
#endif
			SESNSTATUS_SET(sesn_ptr_transient->stat, SESNSTATUS_DEFERRED_RECYCLE);
		}
	}

	//contains error of sorts
	return res_ptr;

}

/**
 * 	@brief: Load current session worker thread's access context
 */
inline  void
LoadSessionWorkerAccessContext (Session *sesn_ptr)
{
	sesn_ptr->persistance_backend			=	pthread_getspecific(masterptr->threads_subsystem.ufsrv_data_key);
	sesn_ptr->instrumentation_backend	=	pthread_getspecific(masterptr->threads_subsystem.ufsrv_instrumentation_backend_key);
	sesn_ptr->msgqueue_backend				=	pthread_getspecific(masterptr->threads_subsystem.ufsrv_msgqueue_pub_key);
	sesn_ptr->usrmsg_cachebackend			=	pthread_getspecific(masterptr->threads_subsystem.ufsrv_usrmsg_key);
	sesn_ptr->fence_cachebackend			=	pthread_getspecific(masterptr->threads_subsystem.ufsrv_fence_key);
	sesn_ptr->db_backend							=	pthread_getspecific(masterptr->threads_subsystem.ufsrv_db_backend_key);
	sesn_ptr->thread_ctx_ptr					= pthread_getspecific(masterptr->threads_subsystem.ufsrv_thread_context_key);

}

/**
 * 	@brief: Main interface for loading session with basic db backend data. also known as rebooting session.
 * 	User must ensure session's is dealocated of any previous values.
 */
void
TransferBasicSessionDbBackendData (Session *sesn_ptr, AuthenticatedAccount *authacct_ptr)
{
	SESSION_USERID_TEMP(sesn_ptr)			= authacct_ptr->userid;
	memcpy (SESSION_UFSRVUID(sesn_ptr), authacct_ptr->ufsrvuid.data, CONFIG_MAX_UFSRV_ID_SZ);
	if (IS_STR_LOADED(SESSION_USERNAME(sesn_ptr)))	free (SESSION_USERNAME(sesn_ptr));
	SESSION_USERNAME(sesn_ptr)				=	authacct_ptr->username; //@dynamic_memory: transfered reference
	if (IS_STR_LOADED(SESSION_USERNICKNAME(sesn_ptr)))	free (SESSION_USERNICKNAME(sesn_ptr));
	SESSION_USERNICKNAME(sesn_ptr)		=	authacct_ptr->nickname;	//@dynamic_memory: transfered reference
	SESSION_DEVICEID(sesn_ptr)				=	authacct_ptr->device_id;
	SESSION_UFSRV_GEOGROUP(sesn_ptr)	=	authacct_ptr->ufsrv_geogroup;

	//TODO: append with more

}

/**
 * 	@brief: Main interface for loading session with basic db backend data.
 * 	This list may expand into the future. Must ensure any hashing dependencies are seloved here, eg userid is hashed against Session instance
 * 	etc...
 * 	@param sesn_ptr_source: session containing desired basic data. No assumptions should be made about connectedness; treat as data store.
 * 	@locked sesn_ptr_target:
 */
void
TransferBasicSessionDbBackendDataFromSession (Session *sesn_ptr_target, Session *sesn_ptr_source)
{
//	if (SESSION_USERID(sesn_ptr_target)!=SESSION_USERID(sesn_ptr_source)) {
  if (!UfsrvUidIsEqual(&SESSION_UFSRVUIDSTORE(sesn_ptr_target), &SESSION_UFSRVUIDSTORE(sesn_ptr_source)))  {
		//TODO: update hash although this is unlikely event as userid dont change
		SESSION_USERID_TEMP(sesn_ptr_target)=SESSION_USERID_TEMP(sesn_ptr_source);
		memcpy (SESSION_UFSRVUID(sesn_ptr_target), SESSION_UFSRVUID(sesn_ptr_source), CONFIG_MAX_UFSRV_ID_SZ);
	}

	if (IS_STR_LOADED(SESSION_USERNAME(sesn_ptr_source))) {
    if (strcmp(SESSION_USERNAME(sesn_ptr_source), SESSION_USERNAME(sesn_ptr_target)) != 0) {
      if (IS_STR_LOADED(SESSION_USERNAME(sesn_ptr_target))) free(SESSION_USERNAME(sesn_ptr_target));
      SESSION_USERNAME(sesn_ptr_target) = SESSION_USERNAME(sesn_ptr_source); //@dynamic_memory: transfered reference
      SESSION_USERNAME(sesn_ptr_source) = NULL;
    }
  }

	//nickname always loaded with a value, default '*' for unset
	if (IS_STR_LOADED(SESSION_USERNICKNAME(sesn_ptr_source))) {
    if (strcmp(SESSION_USERNICKNAME(sesn_ptr_source), SESSION_USERNICKNAME(sesn_ptr_target)) != 0) {
      if (IS_STR_LOADED(SESSION_USERNICKNAME(sesn_ptr_target))) free(SESSION_USERNICKNAME(sesn_ptr_target));
      SESSION_USERNICKNAME(sesn_ptr_target) = SESSION_USERNICKNAME(
              sesn_ptr_source);  //@dynamic_memory: transfered reference
      SESSION_USERNICKNAME(sesn_ptr_source) = NULL;
    }
  }

	SESSION_DEVICEID(sesn_ptr_target)				=	SESSION_DEVICEID(sesn_ptr_source);
	SESSION_UFSRV_GEOGROUP(sesn_ptr_target)	=	SESSION_UFSRV_GEOGROUP(sesn_ptr_source);

	//TODO: append with more

}

/**
 * 	@brief: This is called in the context of initialising new users for whom we could not locate an  existing session
 * 	purely based on cookie, because we did not have that in local/backend hash tables. So we need to use a more identifying attribute, namely
 * 	userid. This attribute will unlock the user's presence across the whole network.
 *
 * 	Where Session's cookie is invalid we terminate user and direct them to re-authenticate, which will have the effect of issuing
 * 	new cookie associated with this account (username/password authentication needed), which will see us land here again.
 *
 * 	@param sesn_ptr_transient: currently connected session in transient mode. Only handshaked one-way incoming
 *
 * 	@return RESCODE_USER_AUTHCOOKIE: On Success, the cookie belongs to an authenticated account
 */
static inline UFSRVResult  *
_DbBackendVerifyAndInitialiseSession (InstanceHolderForSession *instance_sesn_ptr_transient)
{
	AuthenticatedAccount 	authenticated_account = {0};
  Session *sesn_ptr_transient = SessionOffInstanceHolder(instance_sesn_ptr_transient);

	//lets make sure we are supposed to be talking to this fellow. We should hold a cookie of sorts if legit user
	UFSRVResult *res_ptr = DbValidateUserSignOnWithCookie(sesn_ptr_transient, SESSION_COOKIE(sesn_ptr_transient), &authenticated_account, NULL);
	if (!_RESULT_TYPE_SUCCESS(res_ptr)) {
		syslog(LOG_DEBUG, LOGSTR_ACCOUNT_INVALID_SIGNON_COOKIE, __func__, pthread_self(), sesn_ptr_transient, SESSION_ID(sesn_ptr_transient), SESSION_COOKIE(sesn_ptr_transient), LOGCODE_ACCOUNT_INVALID_SIGNON_COOKIE);

		ProcessOutgoingWsHandshake(sesn_ptr_transient, NULL);
    UfsrvCommandInvokeCommand (sesn_ptr_transient, NULL, NULL, NULL, NULL, uACCOUNT_VERIFIED_V1_IDX);

    _RETURN_RESULT_SESN(sesn_ptr_transient, instance_sesn_ptr_transient, RESULT_TYPE_ERR, RESULT_CODE_USER_AUTHENTICATION);
	}

	//TODO: check for RESCODE_ACCOUNT_DISABLED, as account maybe disabled even if AUTHCOOKIE is valid

	//User's cookie is a valid one.
	//Bootstrap basic account info into Session, bearing in mind the user may still exist somewhere based on uid just retrieved
	//so keep Session population light-on because if we later on uncovered a local Session, we'll refresh it and reuse it
	//and this transient Session will be ditched

	//IMPORTANT: data transfered maybe lost because this session is still in transient mode, it may or may not have a local hashed seession
	//if it has a local session we need to on-transfer this data to that session hence CALL_FLAG_TRANSFER_DB_USERDATA below
	TransferBasicSessionDbBackendData (sesn_ptr_transient, &authenticated_account); //cookie is locally hashed for transient. must be removed on success

	return (_DiscoverSessionWhereabouts(instance_sesn_ptr_transient, CALL_FLAG_TRANSFER_DB_USERDATA));

}

/**
* 	@brief: This function tries to resolve the presence of a given user who's got a valid signon cookie, for which we did not
* 	have a local cookie hash. The cookie has been validated with the backend, so it may have a session associated with it somewhere.
* 	We also loaded basic account information, userid, username...
*
*	There are several categories of Sessions that can be uncovered:
*
*	LOCAL hashed:
*	A remote Session(belongs to a user connected on another remote ufsrv) won't have a local cookie hash, but we will have its
*	userid hashed against the Session
*
*	BACKEND ONLINE:
*	User is connected on on another server with status 1
*
*	BACKEND OFFLINE:
*	User had a (now inactive) session on another server
*
*	@param sesn_ptr_transient: connected Session in transient state (oneway handshaked, not fully authenticated), BUT HAS BASIC INFO LOADED FROM DB BACKEND
 *	and cookie locally hashed
*	@call_flag: CALL_FLAG_TRANSFER_DB_USERDATA: session contains fresh basic data sourced from db backend for reuse
*	@locks: None
*
*	@locked sesn_ptr: locked by the main loop
*
*/
 inline static UFSRVResult *
_DiscoverSessionWhereabouts (InstanceHolderForSession *instance_sesn_ptr_transient, unsigned long sesn_call_flags)
{
   Session *sesn_ptr_transient = SessionOffInstanceHolder(instance_sesn_ptr_transient);

	//this maybe a throw away data in case of existing session, as we'll reload from backend if record exists
	//there, but we don't know at this stage: we have to do full initialisation

	//start check for users presence locally and network based on USERID
	UFSRVResult *res_ptr_aux = FindSessionForUserLocalOrBackend (sesn_ptr_transient, 0, SESSION_USERID(sesn_ptr_transient), CALL_FLAG_SEARCH_BACKEND);

	if (res_ptr_aux->result_type == RESULT_TYPE_SUCCESS &&  res_ptr_aux->result_code == RESCODE_USER_ONLINE) {
		//found local hash for this Session based on UID. This could be a remote session. We now turn it into live
		return (_AuthenticateUserIdHashedSession (instance_sesn_ptr_transient, (InstanceHolderForSession *)res_ptr_aux->result_user_data, sesn_call_flags));
	} else if (res_ptr_aux->result_type == RESULT_TYPE_SUCCESS && res_ptr_aux->result_code == RESCODE_USER_BACKEND) {
		//with this flag only cache backend data is returned. To fully instantiate a session, db backend must be loaded first
		return (_AuthenticateDbBackendValidatedCookieSession(instance_sesn_ptr_transient, (redisReply *)res_ptr_aux->result_user_data, sesn_call_flags));
	} else {
		//SPANKING BRAND NEW USER SESSION, eg new registration, or old record was completely deleted...
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, LOGSTR_SESSION_NOTONLINE_INITIALISING, __func__, pthread_self(), sesn_ptr_transient, SESSION_ID(sesn_ptr_transient), LOGCODE_SESSION_NOTONLINE_INITIALISING);
#endif
	}

	return (_AuthenticateBrandNewSession(instance_sesn_ptr_transient));

}

 /**
  * 	@brief: A session which has its userid hashed locally, but its cookie isn't. This is a termination function and is invoked
  * 	in the context of authenticating incoming user session under specific lifecycle stages.
  * 	Session has only been handshaked one-way incoming.
  *
  * 	Under current implementation the only context under which this is possible if the Session is Remote type OR a scenario
  * 	where a user re-registered/acquired new sign-on cookie for which we have no record and the user previously happened to
  * 	be connected to this instance. In that case when the user connects again with new cookie, his new cookie won't hash
  * 	but his userid will, uncovering previous session with old cookie. In this case the user isn't Remote.
  * 	Otherwise we should check for data integrity issues.
  *
  * 	IMPORTANT: We dont check if the Session exists anywhere on the network: as the user is connecting with this server
  * 	once that is broadcasted, if the user existed anywhere else, it will be disconnected by that server as a result of
  * 	the broadcast.
  *
  *	IMPORTANT: the hashed session gets recycled by SessionInstantiateFromBackendRaw() on failure. so no recovery needed here.
  *
  * 	@param sesn_ptr_transient: current connected session in transient state, one-way handshaked incoming
  * 	@param sesn_ptr_uid_hashed: locally hashed user session on userid key, presumably belonging to the same connected sesn_ptr
  *
  *		@locked sesn_ptr: by the main loop
  *
  *		@call_flags:	CALL_FLAG_TRANSFER_DB_USERDATA
  *
  *		@locks sesn_ptr_ui_hashed: Not directly, but downstream by InstateUnconnectedSession()
  * 	@returns
  *
  */
 static inline UFSRVResult *
_AuthenticateUserIdHashedSession (InstanceHolderForSession *instance_sesn_ptr_transient, InstanceHolderForSession *instance_sesn_ptr_uid_hashed, unsigned long sesn_call_flags)
 {
  unsigned long	call_flags_unconnected = sesn_call_flags|CALL_FLAG_SWAP_COOKIE|CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND;//this will cause the cookie to be hashed
  Session *sesn_ptr_uid_hashed = SessionOffInstanceHolder(instance_sesn_ptr_uid_hashed);
   Session *sesn_ptr_transient = SessionOffInstanceHolder(instance_sesn_ptr_transient);

 	//TODO: this condition may need to be revisited as it may not be always true
 	if (SESNSTATUS_IS_SET(sesn_ptr_uid_hashed->stat, SESNSTATUS_REMOTE)) {
 		 return (InstateUnconnectedSession (instance_sesn_ptr_uid_hashed, instance_sesn_ptr_transient, call_flags_unconnected));
 	 } else {
 		 //At this stage we do no different, just mark out rge condition. just noise
 		 syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', o_uid_hashed:'%p', cid:'%lu', uid:'%lu', uid_uid_hashed:'%lu'}: NOTICE: FOUND NON COOKIE-HASED SESSION, UID-HASHED BUT NOT REMOTE: Maybe new signon cookie from a previously connected session",__func__, pthread_self(),
            sesn_ptr_transient, sesn_ptr_uid_hashed, SESSION_ID(sesn_ptr_transient), SESSION_USERID(sesn_ptr_transient), SESSION_USERID(sesn_ptr_uid_hashed));
 		return (InstateUnconnectedSession (instance_sesn_ptr_uid_hashed, instance_sesn_ptr_transient, call_flags_unconnected));
 	 }

 	 _RETURN_RESULT_SESN(sesn_ptr_transient, instance_sesn_ptr_transient, RESULT_TYPE_ERR, RESCODE_USER_INSTATED)

 }

 /**
  * 	@brief:	Found a user, who has valid cookie on the DbBackend only and a UID:<userid> CacheBackend record, for which this instance
  * 	doesn't hold a local Session.
  * 	The Session will be migrated and instantiated locally. This is a special case. Most likely user re-registered, or has been asked to re-sign on.
  *		NOTE: we want to keep fresh data sourced from Db hence CALL_FLAG_TRANSFER_DB_USERDATA flag.
  *   IMPORTANT: There is a danger multiple sessions are instantiated for the same userid, because cookie hash has is the only place that uniquely identifies this user.
  *              so searching locally for this user by sessionid or userid will fail to surface it until 'InstateUnconnectedSession' is called. Threrfore DO NOT instantiate
  *              full fence list for this user until after it is fully hashed.
  *		IMPORTANT: the remote session gets recycled by SessionInstantiateFromBackendRaw() on failure. so no recovery needed here.
  *
  * 	@param sesn_ptr: current connected Session in transient state. This session will be recycled upon success
  * 	@param redis_prt: the raw redis record for the remote session
  *
  * 	@locked sesn_ptr: in main loop
  * 	@unlocks: none directly, but sesn_ptr should be unlocked if successful
  * 			all locking/unlocking logic is in InstateUnconnectedSessionAsConnected()
  * 	@locks: none directly, but the returned remote session should be in locked state
  */
static inline UFSRVResult *
_AuthenticateDbBackendValidatedCookieSession (InstanceHolderForSession *instance_sesn_ptr_transient, redisReply *redis_ptr, unsigned long sesn_call_flags)
 {
 	//connected remote session instance found in the backend: instantiate one locally
 	//this could be hoax, as the server may have crashed before updating the true value

 	Session *sesn_ptr_migrated	= NULL;
   Session *sesn_ptr_transient = SessionOffInstanceHolder(instance_sesn_ptr_transient);
 	InstanceHolderForSession *instance_sesn_ptr_migrated;

 	//DON'T LOCK MIGRATED SESSION  THAT GETS AUTOMATICALLY DONE IN InstateUnconnectedSession()
 	//DON'T flag CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION. See IMPORTANT note above
 	if ((instance_sesn_ptr_migrated = CacheBackendInstantiateRawSessionRecord(sesn_ptr_transient, redis_ptr,
                                                                            (CALL_FLAG_TRANSFER_DB_USERDATA |
                                                                             CALL_FLAG_LOAD_DB_BACKEND_FOR_SESSION),
                                                                            NULL))) {
 	  sesn_ptr_migrated = SessionOffInstanceHolder(instance_sesn_ptr_migrated);
 		unsigned long sesn_call_flags = (CALL_FLAG_SWAP_COOKIE|CALL_FLAG_HASH_USERNAME_LOCALLY|
 																		CALL_FLAG_HASH_UID_LOCALLY|CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION|
																		CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND);

 		//locks unconnected session
 		UFSRVResult *res_ptr = InstateUnconnectedSession (instance_sesn_ptr_migrated, instance_sesn_ptr_transient, sesn_call_flags);

 		if (res_ptr->result_type == RESULT_TYPE_SUCCESS) {
 #ifdef __UF_TESTING
 		syslog(LOG_DEBUG, LOGSTR_SESSION_SUCCESS_MIGRATED, __func__, pthread_self(), sesn_ptr_transient, sesn_ptr_migrated, SESSION_ID(sesn_ptr_migrated), LOGCODE_SESSION_SUCCESS_MIGRATED);
 #endif

 			freeReplyObject(redis_ptr);

      //we want full fence list for this session + for each session full list of session
#define ABORT_ON_FAILURE true
      int failed_lists = InstateFenceListsForUser (instance_sesn_ptr_migrated, SESSION_CALLFLAGS_EMPTY, (MEMBER_FENCE|INVITED_FENCE), ABORT_ON_FAILURE);
      if (failed_lists != 0) {
        ClearLocalSessionCache(instance_sesn_ptr_migrated, CALL_FLAG_DONT_BROADCAST_FENCE_EVENT);
        _RETURN_RESULT_SESN(sesn_ptr_transient, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_SESSION_INTEGRITY);
      }
#undef ABORT_ON_FAILURE

 			_RETURN_RESULT_SESN(sesn_ptr_migrated, instance_sesn_ptr_migrated, RESULT_TYPE_SUCCESS, RESCODE_USER_MIGRATED)
 		} else {
 			syslog(LOG_DEBUG, LOGSTR_SESSION_ERROR_MIGRATED, __func__, pthread_self(), sesn_ptr_transient, SESSION_ID(sesn_ptr_transient), LOGCODE_SESSION_ERROR_MIGRATED);

 			freeReplyObject(redis_ptr);

 			return res_ptr;
 		}
 	}

 	freeReplyObject(redis_ptr);

 	_RETURN_RESULT_SESN(sesn_ptr_transient, NULL, RESULT_TYPE_ERR, RESCODE_USERINFO_BAKENDERR)

 }

 /**
  * 	@brief: A user session that's never connected with us before, and no prior presence could be found for it anywhere on the network
  * 	so we launch them into the system and have them fully setup.
  *
  * 	Connection has only been one-way handshaked incoming and with, has not been hashed, and its backend cache record not written out yet.
  *
  * 	@param sesn_ptr_transient: current connected Session in transient state.
  *
  * 	@locked sesn_ptr_transient: by the main loop
  */
static inline UFSRVResult *
_AuthenticateBrandNewSession (InstanceHolderForSession *instance_sesn_ptr_transient)
 {
   Session *sesn_ptr_transient = SessionOffInstanceHolder(instance_sesn_ptr_transient);

	_DbBackendBootstrapIntoBrandNewSession (sesn_ptr_transient, true);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr_transient)) {
		if (!_SetupDataStructuresForBrandNewSession(instance_sesn_ptr_transient))	goto exit_error;

		RefreshBackendCacheForSession (sesn_ptr_transient, NULL, CALLFLAGS_EMPTY);
		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr_transient)) {
      SESNSTATUS_SET(SESSION_STATUS(sesn_ptr_transient), SESNSTATUS_AUTHENTICATED);
      SESNSTATUS_UNSET(SESSION_STATUS(sesn_ptr_transient), SESNSTATUS_TRANSIENT);

			_RETURN_RESULT_SESN(sesn_ptr_transient, instance_sesn_ptr_transient, RESULT_TYPE_SUCCESS, RESULT_CODE_USER_AUTHENTICATION)
		}
	}

 	exit_error:

 	_RETURN_RESULT_SESN(sesn_ptr_transient, instance_sesn_ptr_transient, RESULT_TYPE_ERR, RESULT_CODE_USER_AUTHENTICATION)

 }

static bool
_SetupDataStructuresForBrandNewSession (InstanceHolderForSession *instance_sesn_ptr)
 {
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

   if (!SESNSTATUS_IS_SET(SESSION_STATUS(sesn_ptr), SESNSTATUS_TRANSIENT)) {
     if (!(AddToHash(&(sessions_delegator_ptr->hashed_cookies.hashtable), (void *) instance_sesn_ptr))) {
       return false;
     }
   }

 	if (!(AddToHash(&(sessions_delegator_ptr->hashed_usernames.hashtable), (void *)instance_sesn_ptr))) {
 		goto error_remove_cookies_hash;
 	}

 	if (!(AddToHash(&(sessions_delegator_ptr->hashed_userids.hashtable), (void *)instance_sesn_ptr))) {
 		goto error_remove_username_hash;
 	}

 	return true;

 	error_remove_username_hash:
 	RemoveFromHash(SESNDELEGATE_USERNAMECACHE(sessions_delegator_ptr), (void *) instance_sesn_ptr);

 	error_remove_cookies_hash:
 	RemoveFromHash(SESNDELEGATE_COOKIECACHE(sessions_delegator_ptr), (void *) instance_sesn_ptr);

 	return false;

 }

///////// END STATE \\\\\\

/**
 * @param sesn_ptr: Most likely this session is freshly instantiated
 * @param flag_auth_data_loaded: session carries fresh db backend authentication data
 *
 * @dynamic_memory jobj_account: IMPORTS json object which is free'd locally
 * @dynamic_memory: Allocates a number of buffers which stay on for the lifetime of the Session and get free at Session reset
 */
static UFSRVResult *
_DbBackendBootstrapIntoBrandNewSession (Session *sesn_ptr_transient, bool flag_auth_data_loaded)
{
	const char				  *scratch;
	struct json_object	*jobj_account	= NULL;

	jobj_account=DbGetAccountInJsonByUserId (sesn_ptr_transient, SESSION_USERID(sesn_ptr_transient));

	if (unlikely(IS_EMPTY(jobj_account)))	_RETURN_RESULT_SESN(sesn_ptr_transient, NULL, RESULT_TYPE_ERR, RESULT_CODE_USER_INITIALISED);

	json_object *jobj_userprefs = NULL;
	DbBackendGetUserPrefs (sesn_ptr_transient, SESSION_USERID(sesn_ptr_transient));
  if (SESSION_RESULT_IS_SUCCESS_WITH_BACKEND_DATA(sesn_ptr_transient))  {
		jobj_userprefs=(json_object *)SESSION_RESULT_USERDATA(sesn_ptr_transient);
		GenerateUserPrefsFromStorage (sesn_ptr_transient, jobj_userprefs);
		json_object_put(jobj_userprefs);
	}

	//this is first tier data that get fetched as a matter of DbBackend authentication, so we keep it
	if (!flag_auth_data_loaded) {
		//geogroup allocation

		//add more if applicable
	}

  scratch = GetAccountAttributeForCloudMessaging (jobj_account, AUTHENTICATED_DEVICE);
	if (IS_STR_LOADED(scratch))	SESSION_CMTOKEN(sesn_ptr_transient) = strdup(scratch);

	//Add more fields...

	json_object_put(jobj_account);

	_RETURN_RESULT_SESN(sesn_ptr_transient, sesn_ptr_transient, RESULT_TYPE_SUCCESS, RESULT_CODE_USER_INITIALISED);

}

////////// START STATE \\\\\\\

/**
 * 	@brief	Given a user session found through backend cookie hash (ie do not have a local cookie hash),
 * 	process the semantics around allowing the user through.
 * 	The user could still be known to us (through uid hash eg), but pure cookie hash lookup did not uncover them.
 *	This function processes two states: user has known presence (could be locally connected or remote), or none.
 *
 * 	@successful_exit: user authenticated
 *
 * 	@param	sesn_ptr_transient:	current connected session in transient state
 * 	@param	res_ptr:	Raw redis record of the user UID:%uid
 * 	@dynamic_memory: raw redi_ptr is passed through the data object of res_ptr, whihc must be freed here
 *
 * 	@locked sesn_ptr in main loop
 */
UFSRVResult *
AuthenticateForBackendCookieHashedSession (InstanceHolderForSession *instance_sesn_ptr_transient, UFSRVResult *res_ptr, SocketMessage *sock_msg_ptr)
{
	Session *sesn_ptr_backend     = NULL,
          *sesn_ptr_ui_hashed   = NULL,
          *sesn_ptr_sesn_hashed = NULL;

  Session *sesn_ptr_transient = SessionOffInstanceHolder(instance_sesn_ptr_transient);
	redisReply *redis_ptr = (redisReply *)res_ptr->result_user_data;

	int						status_network	= atoi(redis_ptr->element[REDIS_KEY_USER_STATUS]->str);
	int 					server_id				= atoi(redis_ptr->element[REDIS_KEY_USER_SID]->str);
	unsigned long session_id			= strtoul(redis_ptr->element[REDIS_KEY_USER_CID]->str, NULL, 10);
	UfsrvUid			*uid_ptr				= (UfsrvUid *)redis_ptr->element[REDIS_KEY_USER_UID]->str;
	unsigned long	user_id					= UfsrvUidGetSequenceId(uid_ptr);

	//check for the presence of session locally, potentially as an old, stale session, or REMOTE
	InstanceHolderForSession *instance_sesn_ptr_backend     = NULL;
	InstanceHolderForSession *instance_sesn_ptr_sesn_hashed = LocallyLocateSessionById(session_id);
	InstanceHolderForSession *instance_sesn_ptr_ui_hashed		= LocallyLocateSessionByUserId(user_id);

	{//this is just mostly diagnostics
		if (!(IS_EMPTY(instance_sesn_ptr_sesn_hashed)) && !(IS_EMPTY(instance_sesn_ptr_ui_hashed))) {
      sesn_ptr_sesn_hashed = SessionOffInstanceHolder(instance_sesn_ptr_sesn_hashed);
      sesn_ptr_ui_hashed = SessionOffInstanceHolder(instance_sesn_ptr_ui_hashed);

			if (sesn_ptr_sesn_hashed != sesn_ptr_ui_hashed) {
				//this is a major inconsistency in the system
				syslog(LOG_ERR, "%s (pid:'%lu', o:'%p', o_uid:'%p', o_hashed:'%p'): CRITICAL: FOUND DIFFERING LOCAL SESSION REFERENCE IN BOTH SESSION AND USERID HASHES: ui_cid:'%lu' ui_userid:'%lu' sesn_cid:'%lu sesn_userid:'%lu'", __func__, pthread_self(),
               sesn_ptr_transient, sesn_ptr_ui_hashed, sesn_ptr_sesn_hashed, SESSION_ID(sesn_ptr_ui_hashed), SESSION_USERID(sesn_ptr_ui_hashed), SESSION_ID(sesn_ptr_sesn_hashed), SESSION_USERID(sesn_ptr_sesn_hashed));

				//TODO: kill both sessions
			} else {//we could use either
				instance_sesn_ptr_backend = instance_sesn_ptr_sesn_hashed;
				sesn_ptr_backend = SessionOffInstanceHolder(instance_sesn_ptr_backend);
#ifdef __UF_TESTING
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p'): FOUND LOCAL SESSION REFERENCE IN BOTH SESSION AND USERID HASHES: cid:'%lu'", __func__, pthread_self(), sesn_ptr_transient, session_id);
#endif
			}
		} else if (!IS_EMPTY(instance_sesn_ptr_ui_hashed)) {
		  instance_sesn_ptr_backend = instance_sesn_ptr_sesn_hashed;
			sesn_ptr_backend = SessionOffInstanceHolder(instance_sesn_ptr_backend);
#ifdef __UF_TESTING
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', o_backend:'%p'): FOUND LOCAL SESSION REFERENCE IN USERID HASH: cid:'%lu'", __func__, pthread_self(), sesn_ptr_transient, sesn_ptr_backend, SESSION_ID(sesn_ptr_backend));
#endif
		} else if (!IS_EMPTY(instance_sesn_ptr_sesn_hashed)) {
			instance_sesn_ptr_backend = instance_sesn_ptr_sesn_hashed;
			sesn_ptr_backend = SessionOffInstanceHolder(instance_sesn_ptr_backend);
#ifdef __UF_TESTING
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', o_backend:'%p'): FOUND LOCAL SESSION REFERENCE IN SESSION HASH: cid:'%lu'", __func__, pthread_self(), sesn_ptr_transient, sesn_ptr_backend, SESSION_ID(sesn_ptr_backend));
#endif
		} else {
			//cookie is related to another Session id in the backend We only know of its id, so we'll instantiate it from backend
			syslog(LOG_DEBUG, LOGSTR_TSWORKER_BACKEND_INSTANTIATE, __func__, pthread_self(), sesn_ptr_transient, SESSION_ID(sesn_ptr_transient), session_id, LOGCODE_TSWORKER_BACKEND_INSTANTIATE, "Session with Backend-verified cookie not in local hash");
			instance_sesn_ptr_backend = NULL;
			sesn_ptr_backend = NULL;
		}
	}

	if (IS_EMPTY(sesn_ptr_backend)) {
		//rebuild the object since we have no prior data on it
    SESSION_USERID_TEMP(sesn_ptr_transient) = user_id;
		//TODO: SHOULDN'T this be handled same as new user initialisation?
		UFSRVResult *res_ptr = _InstateAuthenticatedNonLocalUser(instance_sesn_ptr_transient, sock_msg_ptr, redis_ptr);
		int rescode = _RESULT_CODE(res_ptr);

		if (_RESULT_TYPE_ERROR(res_ptr)) {
			InstanceHolderForSession *instance_sesn_ptr_processed = (InstanceHolderForSession *)res_ptr->result_user_data;
			Session *sesn_ptr_processed = SessionOffInstanceHolder(instance_sesn_ptr_processed);

			if (!IS_EMPTY(instance_sesn_ptr_processed))	{
			  SuspendSession (instance_sesn_ptr_processed, SOFT_SUSPENSE);
			  if (sesn_ptr_processed == sesn_ptr_transient) {
          RemoveFromHash(&(sessions_delegator_ptr->hashed_cookies.hashtable), (void *)instance_sesn_ptr_transient);
			  }
			}

      _RETURN_RESULT_SESN(sesn_ptr_processed, instance_sesn_ptr_processed, RESULT_TYPE_ERR, rescode)
		}

    return  res_ptr;
	} else {
		//refresh user session from newly fetched backend data
		UFSRVResult *res_ptr = _RefreshAuthenticatedLocalUser(instance_sesn_ptr_transient, instance_sesn_ptr_backend, sock_msg_ptr, redis_ptr);
    int rescode = _RESULT_CODE(res_ptr);

		if (_RESULT_TYPE_ERROR(res_ptr)) {
			InstanceHolderForSession *instance_sesn_ptr_processed = (InstanceHolderForSession *)res_ptr->result_user_data;
			Session *sesn_ptr_processed = SessionOffInstanceHolder(instance_sesn_ptr_processed);
			if (!IS_EMPTY(instance_sesn_ptr_processed))	{
			  SuspendSession (instance_sesn_ptr_processed, SOFT_SUSPENSE);
        if (sesn_ptr_processed == sesn_ptr_transient) {
          RemoveFromHash(&(sessions_delegator_ptr->hashed_cookies.hashtable), (void *)instance_sesn_ptr_transient);
        }
			}
      _RETURN_RESULT_SESN(sesn_ptr_processed, instance_sesn_ptr_processed, RESULT_TYPE_ERR, rescode)
		}

		return res_ptr;
	}

}

/**
 * 	@brief: This is a termination function. Process a connecting  user that is on the network (valid cookie on the backend),
 * 	 but for which we didn't have a local authenticated session instance.
 *
 * 	So we go ahead and instantiate a new local authenticated Session, and populate it with raw backend data supplied.
 * 	The user is then handshaked and allowed through.
 *
 * 	@param sesn_ptr_transient: current connected session for the named user, whose Session is about to be instated locally. This session
 * 	instance will be returned to the pool and new one created.
 *
 *	@locks sesn_ptr_backend: newly instated Session. Gets unlocked in the main loop
 *	@unlocks sesn_ptr: the current connected session is unlocked upon successful instatment of sesn_ptr_backend
 *
 * 	@dynamic_memory redisReply *: IMPORTED and freed locally, regardless of outcome
 *
 */
static inline UFSRVResult *
_InstateAuthenticatedNonLocalUser (InstanceHolderForSession *instance_sesn_ptr_transient, SocketMessage *sock_msg_ptr, redisReply *redis_ptr)
{
	Session *sesn_ptr_backend = NULL;
	InstanceHolderForSession *instance_sesn_ptr_backend;

	Session *sesn_ptr_transient = SessionOffInstanceHolder(instance_sesn_ptr_transient);

	//DOES NOT LOCK sesn_ptr_backend
	unsigned long sesn_call_flags = (CALL_FLAG_LOCK_SESSION| CALL_FLAG_HASH_SESSION_LOCALLY| CALL_FLAG_LOAD_DB_BACKEND_FOR_SESSION| CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION);
	if ((instance_sesn_ptr_backend = CacheBackendInstantiateRawSessionRecord(sesn_ptr_transient, redis_ptr, sesn_call_flags, NULL))) {
    sesn_ptr_backend = SessionOffInstanceHolder(instance_sesn_ptr_backend);
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p' cid:'%lu'): SESSION (o_migrated:'%p', cid_migrated:'%lu') WAS MIGRATED FROM BACKEND", __func__,
			pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sesn_ptr_backend, SESSION_ID(sesn_ptr_backend));
#endif
	} else {
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR: COULD NOT INSTANTIATE SESSION FROM BACKEND OBJECT: TERMINATING USER...", __func__, pthread_self(), sesn_ptr_transient, SESSION_ID(sesn_ptr_transient));

		freeReplyObject(redis_ptr);
     //suspend? or leave for upstream
		_RETURN_RESULT_SESN(sesn_ptr_transient, instance_sesn_ptr_transient, RESULT_TYPE_ERR, RESCODE_USERINFO_BAKENDERR)
	}

	//no more use for this because we have now refreshed the session
	freeReplyObject(redis_ptr);

	//CacheBackendInstantiateRawSessionRecord will have instated cookie value, so we need to hash (not CALL_FLAG_SWAP_COOKIE)
	//LOCKS sesn_ptr_backend. sesn_ptr_transient is  RETURNED TO THE POOL cannot be referenced anymore
	sesn_call_flags = CALL_FLAG_DONT_LOCK_SESSION|CALL_FLAG_HASH_UID_LOCALLY|CALL_FLAG_HASH_USERNAME_LOCALLY|CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND;
	UFSRVResult *res_ptr_error = InstateUnconnectedSession (instance_sesn_ptr_backend, instance_sesn_ptr_transient, sesn_call_flags);//event broadcasted

	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr_backend)) {
		//happy end
		UFSRVResult *res_ptr_error = HandleSessionReturnHandshake (instance_sesn_ptr_backend, sock_msg_ptr, CALL_FLAG_SUSSPEND_SESSION);

		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr_backend)) { //todo: this is confusing; clean up and user res_ptr_error
			_RETURN_RESULT_SESN(sesn_ptr_backend, instance_sesn_ptr_backend, RESULT_TYPE_SUCCESS, RESULT_CODE_USER_INITIALISED);
		}

		return res_ptr_error;
	}

	//error of some sort
	return res_ptr_error;

}

/**
 * 	@brief: This is a termination function. Process a connecting  user for whom we have a Session loaded:
 * 	1)Turn Session to a connected local session
 * 	2)associate this connected user with it
 * 	3)get rid of the transient Session through which the user is coming.
 *
 * 	Due to existing reference counting on this Session we CANNOT instantiate a new local authenticated Session, just reuse currently loaded Session.
 * 	The user is then handshaked and allowed through.
 *
 * 	@param sesn_ptr: current connected  transient session for the named user, whose _HASHED_ Session is about to be refreshed locally.
 * 	 This transient session instance will be returned to the pool and the hashed one use moving forward.
 * 	@param sesn_ptr_hashed: currently instantiated, non-connected Session for the user.
 *
 *	@locks sesn_ptr_: newly instated Session. Gets unlocked in the main loop
 *	@unlocks sesn_ptr: the current connected session is unlocked upon successful instatment of sesn_ptr_backend
 *
 * 	@dynamic_memory redisReply *: IMPORTED and freed locally, regardless of outcome
 *
 */
static inline UFSRVResult *
_RefreshAuthenticatedLocalUser (InstanceHolderForSession *instance_sesn_ptr_transient, InstanceHolderForSession *instance_sesn_ptr_hashed, SocketMessage *sock_msg_ptr, redisReply *redis_ptr)
{
  Session *sesn_ptr_transient = SessionOffInstanceHolder(instance_sesn_ptr_transient),
          *sesn_ptr_hashed    = SessionOffInstanceHolder(instance_sesn_ptr_hashed);

	//DOES NOT LOCK sesn_ptr_hashed. All we do is data population from backend record --> sesn_ptr_hashed
	//THIS IS WRONG: RESPECT REFRENCE COUNTING
  if (SESSION_EID(sesn_ptr_transient) != SESSION_EID(sesn_ptr_hashed)) {
    syslog(LOG_NOTICE, "%s (pid:'%lu', o:'%p', cid:'%lu', eid:'%lu', o_hashed:'%p', cid_hashed:'%lu', eid_hashed:'%lu'): EVENT IDs don't match: reloading session from backend record...", __func__, pthread_self(), sesn_ptr_transient, SESSION_ID(sesn_ptr_transient), SESSION_EID(sesn_ptr_transient), sesn_ptr_hashed, SESSION_ID(sesn_ptr_hashed), SESSION_EID(sesn_ptr_hashed));
    if (!(CacheBackendInstantiateRawSessionRecord(sesn_ptr_transient, redis_ptr, CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION, instance_sesn_ptr_hashed)))
      goto _exit_refresh_failed;
  }

	freeReplyObject(redis_ptr);

	/*
	 * CALL_FLAG_SWAP_COOKIE: because we are not sure if sesn_ptr_hashed was connected before so just update cookie as well
	 *	we are not hashing session because id wouldn't have changed, not its underlying Session object
	 *	LOCKS sesn_ptr_hashed. sesn_ptr is  RETURNED TO THE POOL cannot be referenced anymore
	 */
	unsigned call_flags_sesn = CALL_FLAG_HASH_UID_LOCALLY|CALL_FLAG_HASH_USERNAME_LOCALLY|CALL_FLAG_SWAP_COOKIE|CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND;
	UFSRVResult *res_ptr_error = InstateUnconnectedSession (instance_sesn_ptr_hashed, instance_sesn_ptr_transient, call_flags_sesn);

	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr_hashed)) {
		UFSRVResult *res_ptr_error = HandleSessionReturnHandshake (instance_sesn_ptr_hashed, sock_msg_ptr, CALL_FLAG_SUSSPEND_SESSION);

		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr_hashed)) {
			_RETURN_RESULT_SESN(sesn_ptr_hashed, instance_sesn_ptr_hashed, RESULT_TYPE_SUCCESS, RESULT_CODE_USER_INITIALISED)
		}

		return res_ptr_error;
	} else {
		return res_ptr_error;
	}

	_exit_refresh_failed:
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', o_hashed:'%p', cid_hashed:'%lu'): ERROR: COULD NOT REFRESH SESSION FROM BACKEND OBJECT: TERMINATING USER...", __func__, pthread_self(), sesn_ptr_transient, SESSION_ID(sesn_ptr_transient), sesn_ptr_hashed, SESSION_ID(sesn_ptr_hashed));

	freeReplyObject(redis_ptr);

	//TODO: terminate user, but we need a protocol message to inform them of the reason. Hashed instance remains where it was
	_RETURN_RESULT_SESN(sesn_ptr_transient, instance_sesn_ptr_transient, RESULT_TYPE_ERR, RESCODE_USERINFO_BAKENDERR)

}
///////// END STATE \\\\\


////// START AuthenticateForCookieHashedSession STATE \\\\\\

/**
 * 	@brief:
* 	Given a locally cookies-hashed user session, process the semantics around allowing the user through.
* 	The current connected session sesn_ptr is in transient state: oneway handshaked and not fully authenticated yet.
 *
 * 	Locally hashed session will be compared with backend cached instance if the origin of the backend is not current sever and local hashed fails the the REMOTE
 * 	test then that points to an inconsistency. local hashed will be destroyed and a new one recreated from backend.
 *
 * 	@param	sesn_ptr:	connected session in transient state
 *
 * 	@param	sesn_ptr_hashed: Session belonging to the same user found under cookie key
 *
 *	@locked sesn_ptr: in main loop
 * 	@locks sesn_ptr_hashed:
 * 	@unlocks sesn_ptr_hashed: backend instantiated instance if the local one failed
 *	@unlocks sesn_ptr: upon successful instateent of hashed session
 *
 * 	@dynamic_memory sesn_ptr_hashed: instantiated form backend cache to replace locally hashed instance in case of processing issues
 *
 * 	@dynamic_memory redis_ptr: instantiated via @SessionGetFromBackendRaw and freed
 *
 * 	@worker_thread: session worker
 *
 */
UFSRVResult *
AuthenticateForCookieHashedSession (InstanceHolderForSession *instance_sesn_ptr_transient, InstanceHolderForSession *instance_sesn_ptr_hashed, SocketMessage *sock_msg_ptr)
{
	Session     *sesn_ptr_hashed    = SessionOffInstanceHolder(instance_sesn_ptr_hashed);
  Session     *sesn_ptr_transient = SessionOffInstanceHolder(instance_sesn_ptr_transient);
	UFSRVResult	*res_ptr;

	//todo: no lock on sesn_ptr_hashed so this read is technically ripe for race condition. Relying on the atomicity of 64bit read off
	if (SESNSTATUS_IS_SET(SESSION_STATUS(sesn_ptr_hashed), SESNSTATUS_TRANSIENT)) {
    syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', o_hashed:'%p', cid:'%lu', cid_hashed:'%lu'): ERROR: THIS COOKIE BELONGS TO TRANSIENT SESSION: TERMINATING THIS INCOMING CONNECTION...", __func__, pthread_self(), sesn_ptr_transient, sesn_ptr_hashed, SESSION_ID(sesn_ptr_transient), SESSION_ID(sesn_ptr_hashed));

    _RETURN_RESULT_SESN(sesn_ptr_transient, instance_sesn_ptr_transient, RESULT_TYPE_ERR, RESCODE_USER_LOGINREJECTED)
	}

	SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_hashed, _LOCK_TRY_FLAG_TRUE, __func__);
	if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR)) {
		if (time(NULL) - SESSION_WHEN_SERVICE_STARTED(sesn_ptr_hashed) > CONFIG_SESSION_INSERVICE_MAX_TIMEOUT) {
			syslog(LOG_DEBUG, "%s (pid:'%lu',o:'%p', o_hashed:'%p', cid:'%lu'): ERROR: SESSION cid:'%lu' MAY NOT BE ABLE TO BE RECOVERED: SESSION WILL BE FORCIBLY DESTROYED AND SESSION RECREATED",
				__func__, pthread_self(), sesn_ptr_transient, sesn_ptr_hashed, SESSION_ID(sesn_ptr_transient), SESSION_ID(sesn_ptr_hashed));

			//GET THIS SESSION OUT OF CIRCULATION...
			//TODO: possible dangling mutex object due to inability to unlock
			//TODO: Should this be picked by the periodic CheckSessionIdle? the problem we can re-initalise client if it has trace in the system we must clean up first
			ClearLocalSessionCache (instance_sesn_ptr_hashed, CALL_FLAGS_KILL_SESSION|CALL_FLAG_DONT_BROADCAST_FENCE_EVENT|CALL_FLAG_TRANSFER_SESSION_ACCESS_CONTEXT);//don't unlock because of lock issues above just leave it dangling for now

			//causes caller to send session through to normal full initialisation as cookie based processing failed
			_RETURN_RESULT_SESN(sesn_ptr_transient, instance_sesn_ptr_transient, RESULT_TYPE_ERR, RESCODE_USER_SESN_KILLED)
		}

		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', o_hashed:'%p', cid:'%lu', cid_hashed:'%lu'): ERROR: THIS COOKIE BELONGS TO AN ACTIVE SESSION/OR IS IN-SERVICE: TERMINATING THIS INCOMING CONNECTION...", __func__, pthread_self(), sesn_ptr_transient, sesn_ptr_hashed, SESSION_ID(sesn_ptr_transient), SESSION_ID(sesn_ptr_hashed));

		_RETURN_RESULT_SESN(sesn_ptr_transient, instance_sesn_ptr_transient, RESULT_TYPE_ERR, RESCODE_USER_LOGINREJECTED)
	}

	bool lock_already_owned = (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_THIS_THREAD));

	//>>>>>>>>> sesion_ptr_hashed IS NOW LOCKED <<<<<<<<<<<<<<<<

	//the locally hashed session is still marked as connected. The client may have just disconncted/reconnected and we weren't
	//notified in time by the OS, otherwise it may be double signon: same cookie used for simultaneous connections
	if (sesn_ptr_hashed->stat&SESNSTATUS_CONNECTED) {
		SessionTransferAccessContext(sesn_ptr_transient, sesn_ptr_hashed, false);

		//A proxy  may still hang on to the connection, even though the client s coming off a fresh connection. Perhaps safer to terminate
		//the connected
		if ((IsSocketAlive(SESSION_SOCKETFD(sesn_ptr_hashed))) == 0) {
#if __UF_TESTING
			syslog(LOG_NOTICE, "%s (pid:'%lu', o:'%p', cid:'%lu'): WARNING: DOUBLE SIGNON ATTEMPT: HASHED SESSION IS CONNECTED AND WITH LIVE SOCKET (o_hashed:'%p', cid_hashed:'%lu', socketfd:'%d'): SUSPENDING HASHED SESSION...",
				__func__, pthread_self(), sesn_ptr_transient, SESSION_ID(sesn_ptr_transient), sesn_ptr_hashed, SESSION_ID(sesn_ptr_hashed), SESSION_SOCKETFD(sesn_ptr_hashed));
#endif

			SuspendSession (instance_sesn_ptr_hashed, SOFT_SUSPENSE);
			goto _instate_suspended_session;

			//TODO: OR we just leave it where it is and Send protocol message for double connection
			//_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_USER_AUTHENTICATED)
		} else {
			//TODO: check for idle time and if long reinstate the session instead proceeding with the current connection
#if __UF_TESTING
			syslog(LOG_NOTICE, "%s (pid:'%lu', o:'%p', cid:'%lu'): WARNING: DOUBLE SIGNON ATTEMPT: HASHED SESSION HAS CONNECTED FLAG SET BUT HAS NO LIVE SOCKET (o:'%p', cid:'%lu', socketfd:'%d'): CLEARING HASHED SESSION...",
				__func__, pthread_self(), sesn_ptr_transient, SESSION_ID(sesn_ptr_transient), sesn_ptr_hashed, SESSION_ID(sesn_ptr_hashed), SESSION_SOCKETFD(sesn_ptr_hashed));
#endif
			//reset it to a sound baseline, before we attempt to reinstate it below
			SuspendSession (instance_sesn_ptr_hashed, SOFT_SUSPENSE);
		}
	}

	res_ptr = CacheBackendGetRawSessionRecord(sesn_ptr_transient, SESSION_USERID(sesn_ptr_hashed), CALLFLAGS_EMPTY, &(sesn_ptr_transient->sservice.result));

	if (_RESULT_TYPE_SUCCESS(res_ptr)) {
		if (_RESULT_CODE_EQUAL(res_ptr, RESCODE_BACKEND_DATA)) {
			if (SESNSTATUS_IS_SET(sesn_ptr_hashed->stat, SESNSTATUS_REMOTE))
				return (_InstateRemoteSessionAsConnected (instance_sesn_ptr_transient, instance_sesn_ptr_hashed, (redisReply *)res_ptr->result_user_data));
		} else if (_RESULT_CODE_EQUAL(res_ptr, RESCODE_BACKEND_DATA_EMPTYSET)) {
			syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p' cid:'%lu'): POSSIBLE CACHING ISSUES: USER LOCAL COOKIE-HASHED, BUT DOESN'T HAVE CACHE BACKEND STATE INFO (BRAND NEW USER?): ALLOWING...", __func__, pthread_self(), sesn_ptr_transient, SESSION_ID(sesn_ptr_transient));

			//CONTINUE THROUGH TO process_locally_hashed_user
		}
	} else {
		//abandon mission. There is no raw redisReply to free
		syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p', o_hashed:'%p', cid:'%lu'): ERROR: COULD NOT DETERMINE USER NETWORK STATUS: SUSPENDING SESSION...", __func__, pthread_self(), sesn_ptr_transient, sesn_ptr_hashed, SESSION_ID(sesn_ptr_transient));

		SuspendSession(instance_sesn_ptr_transient, SOFT_SUSPENSE);

		if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_hashed, __func__);

		_RETURN_RESULT_SESN(sesn_ptr_transient, instance_sesn_ptr_transient, RESULT_TYPE_ERR, RESCODE_USER_LOGINREJECTED)
	}

	freeReplyObject((redisReply *)res_ptr->result_user_data);

	_instate_suspended_session:
	return (_InstateSuspendedSessionAsConnected(instance_sesn_ptr_transient, instance_sesn_ptr_hashed, sock_msg_ptr));

}

/**
 *	@brief: Promote remote session from Remote state to local Connected.
 *
 *	@param sesn_ptr_transient: connected session in transient state
 *	@param	sesn_ptr_hashed: typically hashed session in Remote state
 *	@param redis_ptr: raw session record from cache backend
 *
 *	@locked sesn_ptr: in main loop
 *	@locked sesn_ptr_hashed: in caller's environment. Which subsequently unlocked here afterbeind reset for rebuild from backend record
 *	@locks sesn_ptr_hashed: after being rebuilt from backend record
 *
 *	@dynamic_memory redisReply: IMPORTED and FREED locally
 *
 */
static inline UFSRVResult *
_InstateRemoteSessionAsConnected (InstanceHolderForSession *instance_sesn_ptr_transient, InstanceHolderForSession *instance_sesn_ptr_hashed, redisReply *redis_ptr)
{
	int status_network  = atoi(redis_ptr->element[REDIS_KEY_USER_STATUS]->str);
	int server_id       = atoi(redis_ptr->element[REDIS_KEY_USER_SID]->str);
  unsigned long eid   = strtoul(redis_ptr->element[REDIS_KEY_USER_EVENT_COUNTER]->str, NULL, 10);

  Session *sesn_ptr_transient = SessionOffInstanceHolder(instance_sesn_ptr_transient),
          *sesn_ptr_hashed    = SessionOffInstanceHolder(instance_sesn_ptr_hashed) ;

	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): FOUND COOKIE HASHED SESSION (cid_hashed:'%lu', o_hashed:'%p', sid:'%d' status:'%d', eid_hashed:'%lu', eid_backend:'%lu') WITH REMOTE FLAG: REBUILDING SESSION FROM BACKEND (ONLY IF EIDS ARE DIFFERENT)...",
		__func__, pthread_self(), sesn_ptr_transient, SESSION_ID(sesn_ptr_transient), SESSION_ID(sesn_ptr_hashed), sesn_ptr_hashed, server_id, status_network, SESSION_EID(sesn_ptr_hashed), eid);

	__unused Session *sesn_ptr_new = NULL;
	InstanceHolderForSession *instance_sesn_ptr_new;

	if (eid != SESSION_EID(sesn_ptr_hashed)) {
		//abandon original hashed session, backend copy remains intact. we now lost sesn_ptr_hash + unlocked
		//TODO: RESET LIFECYCLE MISSING inside ClearLocal.. although logical Session is not destroyed this just a reference to it

		ClearLocalSessionCache(instance_sesn_ptr_hashed, CALL_FLAG_UNLOCK_SESSION | CALL_FLAG_DONT_BROADCAST_FENCE_EVENT | CALL_FLAG_TRANSFER_SESSION_ACCESS_CONTEXT);

		//>>>>>>>>> session_ptr_hashed IS NOW UNLOCKED and INSIDE RECYCLER<<<<<<<<<<<<<<<<

		//rebuild object from backend cache and fully setup locally
		//LOCKS sesn_ptr_hashed
		unsigned long sesn_call_flags = CALL_FLAG_LOCK_SESSION | CALL_FLAG_HASH_SESSION_LOCALLY | CALL_FLAG_HASH_UID_LOCALLY | CALL_FLAG_HASH_USERNAME_LOCALLY | CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION;
		instance_sesn_ptr_new = CacheBackendInstantiateRawSessionRecord(sesn_ptr_transient, redis_ptr, sesn_call_flags, NULL);
		sesn_ptr_new = SessionOffInstanceHolder(instance_sesn_ptr_new);
	} else {
	  instance_sesn_ptr_new = instance_sesn_ptr_hashed;
	  sesn_ptr_new = sesn_ptr_hashed;
	}
	//>>>>>>>>> sesion_ptr_new IS NOW LOCKED <<<<<<<<<<<<<<<<

	freeReplyObject(redis_ptr);

	UFSRVResult *res_ptr = InstateUnconnectedSession(instance_sesn_ptr_new, instance_sesn_ptr_transient, CALL_FLAG_DONT_LOCK_SESSION|CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND);
	InstanceHolderForSession *instance_sesn_ptr_processed = (InstanceHolderForSession *)res_ptr->result_user_data;
  Session *sesn_ptr_processed = SessionOffInstanceHolder(instance_sesn_ptr_new);

	if (res_ptr->result_type == RESULT_TYPE_SUCCESS) {
		UFSRVResult *res_ptr_error = HandleSessionReturnHandshake (instance_sesn_ptr_processed, NULL, CALL_FLAG_SUSSPEND_SESSION);

		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr_processed)) {
			_RETURN_RESULT_SESN(sesn_ptr_processed, instance_sesn_ptr_processed, RESULT_TYPE_SUCCESS, RESULT_CODE_USER_INITIALISED)
		}
		else return res_ptr_error;//session suspended
	} else if (res_ptr->result_type == RESULT_TYPE_ERR) {
		InstanceHolderForSession *instance_sesn_ptr_processed = (InstanceHolderForSession *)res_ptr->result_user_data;
		if (!IS_EMPTY(instance_sesn_ptr_processed))	SuspendSession(instance_sesn_ptr_processed, SOFT_SUSPENSE);
	}

	return res_ptr;//whatever in it... can contain generic error

}

/**
 * 	@brief: Instates a locally hashed session which is currently in suspended state as a fully fledged connected session.
 *
 * 	@param sesn_ptr: connected session in transient state
 * 	@param sesn_ptr_hashed: Suspended session, most likely retrieved from hash and previously was connected
 *
 * 	@locked sesn_ptr: in main loop
 * 	@locked sesn_ptr_hashed: by the caller
 * 	@unocks sesn_ptr: upon successful instatement of suspended session
 */
static inline UFSRVResult *
_InstateSuspendedSessionAsConnected (InstanceHolderForSession *instance_sesn_ptr_transient, InstanceHolderForSession *instance_sesn_ptr_hashed, SocketMessage *sock_msg_ptr)
{
  Session     *sesn_ptr_hashed = SessionOffInstanceHolder(instance_sesn_ptr_hashed);
  Session     *sesn_ptr_transient = SessionOffInstanceHolder(instance_sesn_ptr_transient);

	unsigned long	sesn_call_flags = CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND|CALL_FLAG_DONT_LOCK_SESSION;//since it is already locked by the caller
	UFSRVResult		*res_ptr = InstateUnconnectedSession (instance_sesn_ptr_hashed, instance_sesn_ptr_transient, sesn_call_flags);

	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr_hashed)) {
		UFSRVResult *res_ptr_error = HandleSessionReturnHandshake (instance_sesn_ptr_hashed, sock_msg_ptr, CALL_FLAG_SUSSPEND_SESSION);

		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr_hashed)) {
			_RETURN_RESULT_SESN(sesn_ptr_hashed, instance_sesn_ptr_hashed, RESULT_TYPE_SUCCESS, RESULT_CODE_USER_INITIALISED)
		}

		return res_ptr_error;
	} else {
		if (!(IS_EMPTY(_RESULT_USERDATA(res_ptr)))) {
			SuspendSession(((InstanceHolderForSession *)_RESULT_USERDATA(res_ptr)), SOFT_SUSPENSE);
		}

		return res_ptr;
	}

}

////// END AuthenticateForCookieHashedSession STATE \\\\\\\\\


/**
 * 	@brief:	Helper function to carry out common steps for transforming an unconnected Session into a connected one, using he context of transient
 * 	connected Session.
 * 	Instating can be destructive and recovery may not be possible for the the transient Session, in which case user's
 * 	Session gets terminated.
 *
 * 	This function finalises the Session setup all the way up to return handshake Post.
 *
 *	IMPORTANT: this take care of destroying the passed unconnected object in case of failure. So callers don't need to worry about that.
 *
 * 	@call_flags:non interpreted locally
 *
 *	@locks: non directly. All locking logic is in InstateUnconnectedSessionAsConnected()
 *	@locked sesn_ptr_connected: by caller
 *
 */
UFSRVResult *
InstateUnconnectedSession (InstanceHolderForSession *instance_sesn_ptr_unconnected, InstanceHolderForSession *instance_sesn_ptr_transient, unsigned long sesn_call_flags)
{
	UFSRVResult res = {0};
  Session     *sesn_ptr_unconnected = SessionOffInstanceHolder(instance_sesn_ptr_unconnected);
  Session     *sesn_ptr_transient   = SessionOffInstanceHolder(instance_sesn_ptr_transient);

	_InstateUnconnectedSessionAsConnected (instance_sesn_ptr_unconnected, instance_sesn_ptr_transient, sesn_call_flags, &res);

	if (res.result_type == RESULT_TYPE_SUCCESS) {
		 //we lost sesn_ptr_transient: we now have a different Session object
		 InstanceHolderForSession *instance_sesn_ptr_instated = (InstanceHolderForSession *)res.result_user_data;

		_RETURN_RESULT_SESN(SessionOffInstanceHolder(instance_sesn_ptr_instated), instance_sesn_ptr_instated, RESULT_TYPE_SUCCESS, RESCODE_USER_INSTATED)
	} else if (res.result_type == RESULT_TYPE_ERR) {
		Session		*sesn_ptr_returned = NULL;
    InstanceHolderForSession *instance_sesn_ptr_returned = NULL;

		if (res.result_code == RESCODE_IO_POLLERROR) {
			//this should be sesn_ptr_transient returned back to us
			instance_sesn_ptr_returned  = (InstanceHolderForSession *)res.result_user_data;
			sesn_ptr_returned           = SessionOffInstanceHolder(instance_sesn_ptr_returned);

			syslog(LOG_NOTICE, "%s (pid:'%lu', o:'%p', cid:'%lu, , o_unconnected:'%p', cid_unconnected:'%lu'): ERROR: COULD NOT INSTATE NEW BACKEND SESSION...", __func__,  pthread_self(), sesn_ptr_returned, SESSION_ID(sesn_ptr_returned), sesn_ptr_unconnected, SESSION_ID(sesn_ptr_unconnected));

			//this will butcher the session back into recycler
			ClearLocalSessionCache(instance_sesn_ptr_unconnected, CALL_FLAG_DONT_BROADCAST_FENCE_EVENT|CALL_FLAG_TRANSFER_SESSION_ACCESS_CONTEXT);

			_RETURN_RESULT_SESN(sesn_ptr_returned, instance_sesn_ptr_returned, RESULT_TYPE_ERR, RESCODE_IO_SESSIONSTATE)
		} else if (res.result_code == RESCODE_PROG_HASHED || res.result_code == RESCODE_PROG_LOCKED) {
			//sesn_ptr_connected is still recoverable. this should be sesn_ptr_transient returned back to us
			instance_sesn_ptr_returned = (InstanceHolderForSession *)res.result_user_data;
			if (!IS_EMPTY(instance_sesn_ptr_returned)) {
			  sesn_ptr_returned = SessionOffInstanceHolder(instance_sesn_ptr_returned);
				syslog(LOG_NOTICE, "%s (pid:'%lu', o:'%p, cid:'%lu', o_unconnected:'%p', cid_inconnected:'%lu'): ERROR: COULD NOT INSTATE UNCONNECTED SESSION", __func__,  pthread_self(), sesn_ptr_returned, SESSION_ID(sesn_ptr_returned), sesn_ptr_unconnected, SESSION_ID(sesn_ptr_unconnected));

				//this will butcher the session out of circulation
				ClearLocalSessionCache(instance_sesn_ptr_unconnected, CALL_FLAG_DONT_BROADCAST_FENCE_EVENT|CALL_FLAGS_KILL_SESSION|CALL_FLAG_TRANSFER_SESSION_ACCESS_CONTEXT);

				_RETURN_RESULT_SESN(sesn_ptr_returned, instance_sesn_ptr_returned, RESULT_TYPE_ERR, RESCODE_IO_SESSIONSTATE)
			} else {
				//IMPORTANT WE LOST CONNECTED
				//WE HAVE LOST ACCESS TO sesn_ptr_connected it is in recycler now... we have to dispose of sesn_ptr_unconnected
				//NOTICE INVALID ACCESS TO SESN_PTR WE JUST DO IT FOR DEBUGGING AS THEY ARE POOLED NOT FREED
				syslog(LOG_ERR, "%s (pid:'%lu', o:'%p', o_backend:'%p'): SEVERE ERROR: COULD NOT INSTATE BACKEND SESSION: LOST CURRENT CONNECTED USER..", __func__,  pthread_self(), sesn_ptr_transient, sesn_ptr_unconnected);

				ClearLocalSessionCache(instance_sesn_ptr_unconnected, CALL_FLAG_DONT_BROADCAST_FENCE_EVENT|CALL_FLAG_TRANSFER_SESSION_ACCESS_CONTEXT);

				//since we dont have a return session object to carry the error message anymore
				return _ufsrv_result_generic_error;
			}
		} else {
			//NOTICE INVALID REFERENCE TO sesn_ptr: we just doit for debugging to report on object address
			syslog(LOG_ERR, "%s (pid:'%lu', o:'%p', cid:'%lu): SEVERE ERROR: CONFUSED STATE: COULD NOT INSTATE NEW BACKEND SESSION...", __func__, pthread_self(), sesn_ptr_transient, SESSION_ID(sesn_ptr_transient));

			ClearLocalSessionCache(instance_sesn_ptr_unconnected, CALL_FLAG_DONT_BROADCAST_FENCE_EVENT|CALL_FLAG_TRANSFER_SESSION_ACCESS_CONTEXT);
		}

		//statsd_inc(sesn_ptr->instrumentation_backend, "worker.work.handshake_failed", 1.0);
	}

	_RETURN_RESULT_SESN(sesn_ptr_transient, instance_sesn_ptr_transient, RESULT_TYPE_ERR, RESCODE_USER_INSTATED)
}

/**
 * 	@brief:	This function turns an instantiated, unconnected Session into a fully fledged connected session.
 * 	The Session may have been previously connected, migrated, or remote.
 *
 * 	IMPORTANT: We don't touch fence-session relationships, so reference counting is not affected.
 * 	IMPORTANT: This does not populate regular account data
 *
 * 	A connected Session is a Session for which we hold a live socket.
 * 	The session may have been a remote Session.
 *
 * 	@locked new_sesn_ptr: the transient Session is locked by main loop
 * 	@locked sesn_ptr_migrated: can belocked in the presense of CALL_FLAG_DONT_LOCK_SESSION
 * 	@unlocks ses_sesn_pt: after successful processing
 * 	@locks sesn_ptr_migrated: unless CALL_FLAG_DONT_LOCK_SESSION is flagged
 *
 * 	@call_flag CALL_FLAG_WRITEBACK_FENCE_DATA_TO_BACKEND: update backend record
 * 	@call_flag CALL_FLAG_DONT_LOCK_SESSION: the sesn_ptr_migrated is assumed locked by the caller, so it won't be locked here
 * 	@call_flag CALL_FLAG_TRANSFER_DB_USERDATA: new/transient session has fresh Basic Session Data which must be transferred to migrated
 *
 *
 */
static inline UFSRVResult *						/*orig, local						                               new, transient state*/
_InstateUnconnectedSessionAsConnected (InstanceHolderForSession *instance_sesn_ptr_migrated, InstanceHolderForSession *instance_sesn_ptr_transient, unsigned long call_flags, UFSRVResult *res_ptr_in)
{
  Session     *sesn_ptr_migrated = SessionOffInstanceHolder(instance_sesn_ptr_migrated);
  Session     *sesn_ptr_transient = SessionOffInstanceHolder(instance_sesn_ptr_transient);

#ifdef __UF_TESTING
	 syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): INSTATING: (cid_migrated:'%lu' o_migrated:'%p', socket_fd:'%d')", __func__, pthread_self(),  sesn_ptr_transient, SESSION_ID(sesn_ptr_transient), SESSION_ID(sesn_ptr_migrated), sesn_ptr_migrated, SESSION_SOCKETFD(sesn_ptr_migrated));
#endif

	 //note try lock is on
	if (!(call_flags&CALL_FLAG_DONT_LOCK_SESSION)) {
		SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_migrated, _LOCK_TRY_FLAG_TRUE, __func__);
		if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR)) {
			_RETURN_RESULT_RES(res_ptr_in, sesn_ptr_transient, RESULT_TYPE_ERR, RESCODE_PROG_LOCKED) //will cause hashed object to be killed
		}
	}

	 bool lock_already_owned = (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_THIS_THREAD));
	 Socket *new_sptr;
	 redisReply *redis_ptr;

	 RemoveSessionToMonitoredWorkEvents (instance_sesn_ptr_transient); //remove association new socket<->new Session in epoll and stop monitoring socket

	 new_sptr = sesn_ptr_transient->ssptr;//live socket we need it
  sesn_ptr_transient->ssptr = sesn_ptr_migrated->ssptr; //this is a throw away socket

	 sesn_ptr_migrated->ssptr = new_sptr;//hijack new Socket, allowing us to create new association between new socket <->orig Session

	 //TODO: WE AUTOMATICALLY GET THE NEWSOCKET ADDRESS, BUT WE LOSE MSGQUEUE FOR EXISTING SCOKETIT MAY HAVE ENTRIES IN IT

	 SessionTransferAccessContext (sesn_ptr_transient,  sesn_ptr_migrated, false);

	 if (call_flags&CALL_FLAG_TRANSFER_DB_USERDATA) {
		 TransferBasicSessionDbBackendDataFromSession(sesn_ptr_migrated, sesn_ptr_transient);//this is destructive to sesn_ptr_transient as those fields will be nulled out

#ifdef __UF_TESTING
		 syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', uid_transferred:'%lu', uname_transferred:'%s', nickname_transferred:'%s'}: Transferred Basic Session Data from transient session...", __func__, pthread_self(), sesn_ptr_transient, SESSION_ID(sesn_ptr_transient), SESSION_USERID(sesn_ptr_transient), SESSION_USERNAME(sesn_ptr_transient), SESSION_USERNICKNAME(sesn_ptr_transient));
#endif
	 }

	 if (AddSessionToMonitoredWorkEvents(instance_sesn_ptr_migrated)) {
		 sesn_ptr_migrated->event_descriptor = sesn_ptr_transient->event_descriptor; //reassign the network event

		 //both sessions are in suspend and has session id hash. orig has cookie hash. new session has cookie hash if swap flag is set
		 //at this point we may receive network events, but the main loop will ignore t due to suspend flag

		 if (call_flags&CALL_FLAG_SWAP_COOKIE) {
#ifdef __UF_TESTING
			 syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): SWAPPING CONNECTED TRANSIENT cookie:'%s' INTO MIGRATED cookie:'%s'...", __func__, pthread_self(), SESSION_ID(sesn_ptr_transient), SESSION_COOKIE(sesn_ptr_transient), SESSION_COOKIE(sesn_ptr_migrated));
#endif

			 //0)this was set at request initialisation to block repeated incoming requests against the same cookie
			 RemoveFromHash(&(sessions_delegator_ptr->hashed_cookies.hashtable), (void *)instance_sesn_ptr_transient);
			 //1)remove old cookie associated with migrated session: both local and backend
			 RemoveFromHash(&(sessions_delegator_ptr->hashed_cookies.hashtable), (void *)instance_sesn_ptr_migrated);

			 //This hash may not be in the backend just yet
      redis_ptr = (*sesn_ptr_migrated->persistance_backend->send_command)(sesn_ptr_migrated, REDIS_CMD_COOKIE_SESSION_DEL, SESSION_COOKIE(sesn_ptr_migrated));
      if (IS_PRESENT(redis_ptr)) freeReplyObject(redis_ptr);

			 //2) shift cookie across
			 memcpy(SESSION_COOKIE(sesn_ptr_migrated), SESSION_COOKIE(sesn_ptr_transient), strlen(sesn_ptr_transient->session_cookie) + 1);

			 //3) update local hash new cookie against migrated session, because they are different object instances
			 if (!(AddToHash(&(sessions_delegator_ptr->hashed_cookies.hashtable), (void *)instance_sesn_ptr_migrated))) {
				 //TODO: MORE RECOVERY FOR SWAP OPTION
				 RemoveSessionToMonitoredWorkEvents(instance_sesn_ptr_migrated);
				 //undo everything and re-engage new_sesn_ptr
				 _RECOVERY_BLOCK
				 _RETURN_RESULT_RES(res_ptr_in, instance_sesn_ptr_transient, RESULT_TYPE_ERR, RESCODE_PROG_HASHED)
			 }

			 //4)backend update for migrated happens below
		 } else {
       RemoveFromHash(&(sessions_delegator_ptr->hashed_cookies.hashtable), (void *)instance_sesn_ptr_transient); //was set at request initialisation
			 //cookie backend update for migrated happens below
			 if (!(AddToHash(&(sessions_delegator_ptr->hashed_cookies.hashtable), (void *)instance_sesn_ptr_migrated))) {
				 RemoveSessionToMonitoredWorkEvents(instance_sesn_ptr_migrated);
				 //undo everything and re-engage new_sesn_ptr
         AddToHash(&(sessions_delegator_ptr->hashed_cookies.hashtable), (void *)instance_sesn_ptr_transient);
				 _RECOVERY_BLOCK
				 _RETURN_RESULT_RES(res_ptr_in, instance_sesn_ptr_transient, RESULT_TYPE_ERR, RESCODE_PROG_HASHED)
			 }
		 }

		 //status so far:
		 //cookie for migrated locally hashed. if swap cookie was on: cookie for connected us shifted and hash updated accordingly
		 //no backend update except for del of connected hash if swap was on

		 //SESNSTATUS_HANDSHAKEDis originally set in ProcessOutgoingWsHandshake for non migrated sessions
		 sesn_ptr_migrated->stat |= SESNSTATUS_HANDSHAKED;
		 sesn_ptr_migrated->stat |= SESNSTATUS_AUTHENTICATED;
		 sesn_ptr_migrated->stat |= SESNSTATUS_CONNECTED;

		 {//start reset new session as we no longer need that
			 //this will trigger a broadcast and update the corresponding UID:xxx status, which is not desirable,
			 //but we restore it with the update below
			 if (SuspendSession(instance_sesn_ptr_transient, SOFT_SUSPENSE)) {
				 SESNSTATUS_SET(sesn_ptr_transient->stat, SESNSTATUS_DEFERRED_RECYCLE);
				SessionUnLockCtx (THREAD_CONTEXT_PTR, sesn_ptr_transient, __func__);//lock should be owned by this thread
			 } else {
				 syslog(LOG_ERR, "%s (pid:'%lu', o_new:'%p', o_migrated:'%p', cid_new:'%lu'): ERROR: COULD NOT SUSPEND CONNECTED SESSION (cid:'%lu'): KILLING SESSION AND CONTINUING WITH MIGRATED cid_migrated:'%lu'",
					 __func__, pthread_self(), sesn_ptr_transient, sesn_ptr_migrated, SESSION_ID(sesn_ptr_transient), SESSION_ID(sesn_ptr_transient), SESSION_ID(sesn_ptr_migrated));

				 //this is a faulty object we ought to flush it out of the system and continue with migrated session.CALL_FLAG_TRANSFER_SESSION_ACCESS_CONTEXT passed just in case
				 ClearLocalSessionCache(instance_sesn_ptr_transient, CALL_FLAG_UNLOCK_SESSION|CALL_FLAGS_KILL_SESSION|CALL_FLAG_DONT_BROADCAST_FENCE_EVENT|CALL_FLAG_TRANSFER_SESSION_ACCESS_CONTEXT);
			 }

			 //controls flow naturally wth migrated session
		 }//end reset transient session

		 //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		 //DON't USE SESN_PTR_TRANSIENT beyond this point either recycled or killed
		 //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

		 //CALL_FLAG_SWAP_COOKIE forces a cookie hash so no need to do it again
		 if ((call_flags&CALL_FLAG_HASH_SESSION_LOCALLY) && !(call_flags&CALL_FLAG_SWAP_COOKIE)) {
			 if (!(AddToHash(&(sessions_delegator_ptr->hashed_sessions.hashtable), (void *)instance_sesn_ptr_migrated))) {
				 RemoveFromHash(&(sessions_delegator_ptr->hashed_cookies.hashtable), (void *) instance_sesn_ptr_migrated);

				 RemoveSessionToMonitoredWorkEvents (instance_sesn_ptr_migrated);

				 //we cannot recover sesn_ptr_new so we must wrap up the whole lot and get the user to reconnect
				 //ask the calling environment to kill migrated it is of no use
				 _RETURN_RESULT_RES(res_ptr_in, NULL, RESULT_TYPE_ERR, RESCODE_PROG_HASHED) //note NULL is RETURNED
			 }
		 }

		 if (call_flags&CALL_FLAG_HASH_USERNAME_LOCALLY) {
			 if (!(AddToHash(&(sessions_delegator_ptr->hashed_usernames.hashtable), (void *)instance_sesn_ptr_migrated))) {
				 RemoveFromHash(&(sessions_delegator_ptr->hashed_cookies.hashtable), (void *) instance_sesn_ptr_migrated);
				 RemoveFromHash(&(sessions_delegator_ptr->hashed_sessions.hashtable), (void *) instance_sesn_ptr_migrated);

				 RemoveSessionToMonitoredWorkEvents (instance_sesn_ptr_migrated);

				 _RETURN_RESULT_RES(res_ptr_in, NULL, RESULT_TYPE_ERR, RESCODE_PROG_HASHED)
			 }
		 }

		 if (call_flags&CALL_FLAG_HASH_UID_LOCALLY) {
			 if (!(AddToHash(&(sessions_delegator_ptr->hashed_userids.hashtable), (void *)instance_sesn_ptr_migrated))) {
				 RemoveFromHash(&(sessions_delegator_ptr->hashed_cookies.hashtable), (void *) instance_sesn_ptr_migrated);
				 RemoveFromHash(&(sessions_delegator_ptr->hashed_sessions.hashtable), (void *) instance_sesn_ptr_migrated);
				 RemoveFromHash(&(sessions_delegator_ptr->hashed_usernames.hashtable), (void *) instance_sesn_ptr_migrated);

				 RemoveSessionToMonitoredWorkEvents (instance_sesn_ptr_migrated);

				 _RETURN_RESULT_RES(res_ptr_in, NULL, RESULT_TYPE_ERR, RESCODE_PROG_HASHED)
			 }
		 }

		 SESNSTATUS_SET(sesn_ptr_migrated->stat, SESNSTATUS_INSERVICE);

		 SESSION_WHEN_SERVICE_STARTED(sesn_ptr_migrated) = SESSION_WHEN_SERVICE_STARTED(sesn_ptr_transient);

		 SESNSTATUS_UNSET(sesn_ptr_migrated->stat, SESNSTATUS_SUSPENDED);
     SESNSTATUS_UNSET(sesn_ptr_migrated->stat, SESNSTATUS_TRANSIENT);
		 SESNSTATUS_UNSET(sesn_ptr_migrated->stat, SESNSTATUS_IDLED);
		 SESNSTATUS_SET(sesn_ptr_migrated->stat, SESNSTATUS_CONNECTED);
		 SESNSTATUS_UNSET(sesn_ptr_migrated->stat, SESNSTATUS_MIGRATED);
		 SESNSTATUS_UNSET(sesn_ptr_migrated->stat, SESNSTATUS_REMOTE);
		 SESNSTATUS_UNSET(sesn_ptr_migrated->stat, SESNSTATUS_REMOTE_CONNECTED);
		 SESNSTATUS_UNSET(sesn_ptr_migrated->stat, SESNSTATUS_IOERROR);

		 if (CALLGFLAG_IS_SET(call_flags, CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND)) {
			 UFSRVResult *res_ptr = RefreshBackendCacheForSession (sesn_ptr_migrated, NULL, CALL_FLAG_DONT_BROADCAST_SESSION_EVENT); //because we testing for it below
			 if (_RESULT_TYPE_ERROR(res_ptr)) {
         RemoveFromHash(&(sessions_delegator_ptr->hashed_cookies.hashtable), (void *) instance_sesn_ptr_migrated);
         RemoveFromHash(&(sessions_delegator_ptr->hashed_sessions.hashtable), (void *) instance_sesn_ptr_migrated);
         RemoveFromHash(&(sessions_delegator_ptr->hashed_usernames.hashtable), (void *) instance_sesn_ptr_migrated);
         RemoveFromHash(&(sessions_delegator_ptr->hashed_userids.hashtable), (void *) instance_sesn_ptr_migrated);

         RemoveSessionToMonitoredWorkEvents (instance_sesn_ptr_migrated);

         _RETURN_RESULT_RES(res_ptr_in, NULL, RESULT_TYPE_ERR, res_ptr->result_code)
			 }
		 }

		 //by default event is broadcasted unless CALL_FLAG_DONT_BROADCAST_SESSION_EVENT is passed
		 if (!(CALLGFLAG_IS_SET(call_flags, CALL_FLAG_DONT_BROADCAST_SESSION_EVENT))) {
			 if (_PROTOCOL_CTL_PUB_SESSION_TRANSITIONS(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr_migrated))))) {
				 InterBroadcastSessionStatus (sesn_ptr_migrated, NULL, SESSION_MESSAGE__STATUS__CONNECTED, 0);
			 }
		 }

		 //statsd_inc(sesn_ptr_migrated->instrumentation_backend, "sessions.resumed", 1.0);

		 //success

		 //return sesn_ptr_migrated;//sesn state: locked
		 _RETURN_RESULT_RES(res_ptr_in, instance_sesn_ptr_migrated, RESULT_TYPE_SUCCESS, RESCODE_USER_INSTATED)
	 } else {
		 syslog(LOG_ERR, "%s (pid:'%lu' o:'%p', cid:'%lu'): SEVERE ERROR: COULD NOT POLL NEWLY UNSUSPENDED ORIG SESSION(cid:'%lu', o:'%p'): RESTORING NEW SESSION(cid='%lu')...",
			 __func__, pthread_self(), sesn_ptr_transient, SESSION_ID(sesn_ptr_transient), SESSION_ID(sesn_ptr_migrated), sesn_ptr_migrated, SESSION_ID(sesn_ptr_transient));

		 connected_session_recovery:

		 //restore transient session
		 //backend cookie hash is not affected as it has not been touched at this this pony
		 new_sptr = sesn_ptr_transient->ssptr;	//orig' original socket
     sesn_ptr_transient->ssptr = sesn_ptr_migrated->ssptr; 	//this new original socket
		 sesn_ptr_migrated->ssptr = new_sptr;	//orig gets its original socket

		 //new_sesn_ptr->ssptr=orig_sesn_ptr->ssptr;
		 SESNSTATUS_UNSET(sesn_ptr_transient->stat, SESNSTATUS_SUSPENDED);
		 AddSessionToMonitoredWorkEvents (instance_sesn_ptr_transient);

		 //we did not succeed so unlock the original nd restore it to original condition
		 //caller will unlock new
		 //>>>>>>>>>>>>>>>>>>>>>>>
		 if (!(call_flags&CALL_FLAG_DONT_LOCK_SESSION)) SessionUnLockCtx (THREAD_CONTEXT_PTR, sesn_ptr_migrated, __func__);
		 //>>>>>>>>>>>>>>>>>>>>>>>

		 //instruct the user to reauthenticate
		 //returning environment must manage migrated session reclamation
		 _RETURN_RESULT_RES(res_ptr_in, instance_sesn_ptr_transient, RESULT_TYPE_ERR, RESCODE_IO_POLLERROR)

		 //no change in state sesn_ptr_transient remains locked. up to calling environment to unlock
	 }

	 _RETURN_RESULT_RES(res_ptr_in, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

/**
 * 	@brief this a pure local event with no network wide ramification. We clear local resources associated with a session, could be because the user
 * 	is present on another server. Very similar to Suspend, with slightly simpler semantics, because this is primarily used with non connected, carrier Session objects
 *
 *	IMPORTANT: THIS DOES NOT RESPECT CURRENT REFERENCE COUNTING BETWEEN SESSIONS/FENCES
 *
 *	@param sesn_ptr_target: target session to be cleared. Could be remote, non-connected session.
 *
 *	@param sesn_ptr_this:	A connected session
 *
 * 	@call_flag CALL_FLAG_UNLOCK_SESSION: user supplied a locked session, so we unlock
 * 	@call_flag CALL_FLAG_REMOTE_SESSION: this is a snappy action, turn the Session into a Remote type
 * 	@call_flag CALL_FLAGS_KILL_SESSION: Session permanently destructed and not available for future work
 * 	@call_flag CALL_FLAG_DONT_BROADCAST_FENCE_EVENT: the event is broadcasted. sesn_ptr_this must be NON NULL
 * 	@call_flag CALL_FLAG_TRANSFER_SESSION_ACCESS_CONTEXT: use current's thread access context
 *
 *	@locks: None
 *	@unlock sesn_ptr_target: if flag is set
 *	@access_context sesn_ptr_target:	must be fuly loaded, as it can be called from ufsrv worker and may not be connected
 * 	@worker_thread: session works, ufsrv worker (no sesn_ptr_this)
 */
int
ClearLocalSessionCache (InstanceHolderForSession *instance_sesn_ptr_target, unsigned long sesn_call_flags)
 {
 	 if (IS_PRESENT(instance_sesn_ptr_target)) {
     Session *sesn_ptr_target = SessionOffInstanceHolder(instance_sesn_ptr_target);

 		if (sesn_ptr_target->ssptr) {
			if (sesn_ptr_target->ssptr->sock > 0)	close (sesn_ptr_target->ssptr->sock);//this will automatically remove from monitored events

			sesn_ptr_target->ssptr->sock = -1;
		}

 		if (sesn_call_flags&CALL_FLAG_TRANSFER_SESSION_ACCESS_CONTEXT) 	LoadSessionWorkerAccessContext(sesn_ptr_target);

 		if (sesn_call_flags&CALL_FLAG_REMOTE_SESSION) {
			//turn target session into a remote one. Now that we did the socket check above, all remaining to be done is state manipulator
			syslog(LOG_DEBUG, "%s (pid:'%lu', o_target:'%p', cid_target:'%lu'): CONVERTING SESSION TO A REMOTE INSTANCE...", __func__, pthread_self(), sesn_ptr_target, SESSION_ID(sesn_ptr_target));

			SESNSTATUS_UNSET(sesn_ptr_target->stat, SESNSTATUS_CONNECTED);
			SESNSTATUS_UNSET(sesn_ptr_target->stat, SESNSTATUS_SUSPENDED);
			SESNSTATUS_SET(sesn_ptr_target->stat, SESNSTATUS_REMOTE_CONNECTED);
			SESNSTATUS_SET(sesn_ptr_target->stat, SESNSTATUS_REMOTE);

			return 1;
		}

		//spray and pray...
		if (SESSION_ID(sesn_ptr_target) > 0)			RemoveFromHash(&(sessions_delegator_ptr->hashed_sessions.hashtable), (void *) (InstanceHolderForSession *)instance_sesn_ptr_target);
		if (SESSION_USERID(sesn_ptr_target) > 0)	RemoveFromHash(&(sessions_delegator_ptr->hashed_userids.hashtable), (void *) (InstanceHolderForSession *)instance_sesn_ptr_target);
		if (SESSION_USERNAME(sesn_ptr_target))	RemoveFromHash(&(sessions_delegator_ptr->hashed_usernames.hashtable), (void *) (InstanceHolderForSession *)instance_sesn_ptr_target);

		RemoveFromHash(&(sessions_delegator_ptr->hashed_cookies.hashtable), (void *) (InstanceHolderForSession *)instance_sesn_ptr_target);

		sesn_ptr_target->stat = 0;

		//SessionService
		unsigned cflags = 0;
		if (sesn_call_flags&CALL_FLAG_DONT_BROADCAST_FENCE_EVENT) cflags |= CALL_FLAG_DONT_BROADCAST_FENCE_EVENT;
		ResetSessionService(instance_sesn_ptr_target, cflags); //only if session_servicee is !NULL

		_s_DestructSocketMessageQueue (sesn_ptr_target, &(sesn_ptr_target->message_queue_in));
		_s_DestructSocketMessageQueue (sesn_ptr_target, &(sesn_ptr_target->message_queue_out));

		DestructSocketMessage (&(sesn_ptr_target->ssptr->socket_msg));
		DestructSocketMessage (&(sesn_ptr_target->ssptr->socket_msg_out));

		memset (&sesn_ptr_target->ssptr->protocol_header, 0, sizeof(ProtocolHeaderWebsocket));
		memset (sesn_ptr_target->ssptr, 0, sizeof(Socket));

		if (sesn_ptr_target->dsptr) memset (sesn_ptr_target->dsptr, 0, sizeof(Socket));

		//TODO: to widen the application of this function, reset User as well

#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s (pid:'%lu', o_target:'%p'): Recycling Session (cid:%lu' socketfd:'%d')...", __func__, pthread_self(), sesn_ptr_target, SESSION_ID(sesn_ptr_target), SESSION_SOCKETFD(sesn_ptr_target));
#endif

		if (sesn_call_flags&CALL_FLAG_UNLOCK_SESSION) {
			SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_target, __func__);
		}

		//TODO: FAULTY: THIS NEEDS TO BE ALIGNED WITH TYPE POOL: THIS WILL CAUSE FUTURE USER TO FAIL
		if (sesn_call_flags&CALL_FLAGS_KILL_SESSION) {
			SESNSTATUS_SET(sesn_ptr_target->stat, SESNSTATUS_FAULTY);
			DestructSessionService (instance_sesn_ptr_target, sesn_call_flags&CALL_FLAG_DONT_BROADCAST_FENCE_EVENT?CALL_FLAG_DONT_BROADCAST_FENCE_EVENT:0);
		} else {
			SESNSTATUS_SET(sesn_ptr_target->stat, SESNSTATUS_RECYCLED);
		}

		SessionReturnToRecycler (instance_sesn_ptr_target, (ContextData *)NULL, CALLFLAGS_EMPTY);

		return 1;
 	 }

 	 return 0;

 }

UFSRVResult *
CacheBackendUpdateCookie (Session *sesn_ptr, const char *old_cookie)
{
  PersistanceBackend		*sesn_backend_ptr	=	SESSION_SESSION_BACKEND(sesn_ptr);
#define COMMANDSET_WITH_OLD_COOKIE_SIZE     4
#define COMMANDSET_WITHOUT_OLD_COOKIE_SIZE  3

  (*sesn_backend_ptr->send_command_multi)(sesn_ptr,	"MULTI");
  (*sesn_backend_ptr->send_command_multi)(sesn_ptr,	REDIS_CMD_COOKIE_SESSION_SET, SESSION_COOKIE(sesn_ptr), SESSION_ID(sesn_ptr), SESSION_USERID(sesn_ptr));
  if (IS_PRESENT(old_cookie)) (*sesn_backend_ptr->send_command_multi)(sesn_ptr,	REDIS_CMD_COOKIE_SESSION_DEL, old_cookie);
  (*sesn_backend_ptr->send_command_multi)(sesn_ptr,	"EXEC");

  size_t				actually_processed	=	IS_PRESENT(old_cookie)?COMMANDSET_WITH_OLD_COOKIE_SIZE:COMMANDSET_WITHOUT_OLD_COOKIE_SIZE;
  size_t				commands_successful	=	actually_processed;
  redisReply		*replies[actually_processed];
  memset (replies, 0, sizeof(replies));

  for (size_t i=0; i<actually_processed; i++) {
    if ((RedisGetReply(sesn_ptr, sesn_backend_ptr, (void *)&replies[i])) != REDIS_OK) {
      commands_successful--;

      if ((replies[i] != NULL)) {
        syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', idx:'%lu'): ERROR PROCESSING MULTI SET COMMAND. ERROR: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i, replies[i]->str);
      } else {
        syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', i:'%lu'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i);
      }
    }
  }//for

  //diagnostics
  if (commands_successful!=actually_processed) {
    for (size_t i=0; i<actually_processed; i++)	if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)
  }

  //verification block
  {
#define EXEC_COMMAND_IDX (actually_processed-1)

    for (size_t i=0; i<actually_processed-1; i++)	if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);

    if (unlikely(IS_EMPTY(replies[EXEC_COMMAND_IDX]))) {//idx for EXEC, which is last
      syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR: REDIS TRANSACTION ERROR: NULL COMMAND ARRAY RESPONSE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

      _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)
    }

    if (replies[EXEC_COMMAND_IDX]->elements==actually_processed-2) {
      //these should be contextual to the actual return codes for the above commands
      bool is_error = false;
      if (!(strcmp(replies[EXEC_COMMAND_IDX]->element[0]->str, "OK") == 0)) {
        syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', error:'%s'): ERROR: SET COOKIE:<> Failed", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), replies[EXEC_COMMAND_IDX]->element[0]->str);
        is_error = true;
      }

      freeReplyObject(replies[EXEC_COMMAND_IDX]);

      if (is_error) _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
    } else {
      //only remaining element is at EXEC_COMMAND_IDX
      syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', dispatched:'%lu', received:'%lu'): ERROR: REDIS TRANSACTION ERROR: DISPATCHED/RECEIVED COMMANDS COUNT MISMATCH", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), actually_processed-2, replies[EXEC_COMMAND_IDX]->elements);
      if (IS_PRESENT(replies[EXEC_COMMAND_IDX]))	freeReplyObject(replies[EXEC_COMMAND_IDX]);

      _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)
    }
  }

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)

#undef EXEC_COMMAND_IDX

}

/**
 * 	call_flags CALL_FLAG_DONT_BROADCAST_SESSION_EVENT: if set, the sesseion refresh event won't be broadcast to the queue
 */
UFSRVResult *
RefreshBackendCacheForSession (Session *sesn_ptr, const char *old_cookie, unsigned long sesn_call_flags)
{
  CacheBackendUpdateCookie(sesn_ptr, old_cookie);
  if (SESSION_RESULT_TYPE_ERROR(sesn_ptr)) {
    return SESSION_RESULT_PTR(sesn_ptr);
  }

  redisReply *redis_ptr = (*sesn_ptr->persistance_backend->send_command)(sesn_ptr, REDIS_CMD_USERNAME_UID_SET, SESSION_USERNAME(sesn_ptr), SESSION_USERID(sesn_ptr));

	if (redis_ptr) freeReplyObject(redis_ptr);

#if 0
	//potential optimisation...
	struct RedisCommandArgument {
		unsigned char **argument;
		size_t *argument_sz;
	};//32

	unsigned char *session_record_set_all_args[32]={
			"HMSET",
			NULL,//UID:%lu
			"cid",
			NULL, //cid value %lu
			"sid",
			NULL, //sid %d value
			"uid"
			NULL, //uid value %lu
			"when",
			NULL, //when value %lu
	};
	size_t session_record_set_all_sz[32]={
			5,//MSET
			0,//UID:%lu
			3,//cid
			0,//cid value %lu
			3,//"sid"
			0,//sid value %d
			3, "uid"
			0, //uid value %lu
			4, //when
			0,//when value
	};
	cmdlen = redisFormatCommandArgv(&outbuf, 32/*argc*/, session_record_set_all_args, session_record_set_all_sz);
	//"HMSET UID:%lu cid %lu sid %d uid %lu when %lu haddress %s hport %lu status 1 when_serviced %lu when_suspended %lu when_resumed %lu uname %s cookie %s creqid %lu sreqid %lu lseen_eids %s"
#endif

	size_t baseloc_by_user_sz		=	SizeofLocationDescription (SESSION_ULOCATION_BYUSER_PTR(sesn_ptr));
	size_t baseloc_by_server_sz	=	SizeofLocationDescription (SESSION_ULOCATION_BYSERVER_PTR(sesn_ptr));

	char baseloc_by_user[baseloc_by_user_sz]; 		baseloc_by_user[0] = '\0';
	char baseloc_by_server[baseloc_by_server_sz];	baseloc_by_server[0] = '\0';

	FormatCacheBackendLocationFieldValue ((const LocationDescription *)SESSION_ULOCATION_BYUSER_PTR(sesn_ptr), &((BufferDescriptor){baseloc_by_user, 0, baseloc_by_user_sz}));
	FormatCacheBackendLocationFieldValue ((const LocationDescription *)SESSION_ULOCATION_BYSERVER_PTR(sesn_ptr), &((BufferDescriptor){baseloc_by_server, 0, baseloc_by_server_sz}));

	redis_ptr = (*sesn_ptr->persistance_backend->send_command)(sesn_ptr, REDIS_CMD_USER_SESSION_RECORD_SET_ALL,
                                                              SESSION_USERID(sesn_ptr),
                                                              SESSION_ID(sesn_ptr),
                                                              masterptr->serverid,
                                                              //sesn_ptr->sservice.user.user_details.user_id,
                                                              SESSION_UFSRVUID(sesn_ptr), CONFIG_MAX_UFSRV_ID_SZ,
                                                              SESSION_USER_PROFILE_KEY(sesn_ptr), (size_t)CONFIG_USER_PROFILEKEY_MAX_SIZE,
                                                              0,//this slot is unused: old 'when' value
                                                              sesn_ptr->ssptr->haddress,
                                                              (IS_STR_LOADED(SESSION_BASELOC(sesn_ptr))?SESSION_BASELOC(sesn_ptr):CONFIG_DEFAULT_PREFS_STRING_VALUE),
                                                              sesn_ptr->when_serviced_start,
                                                              sesn_ptr->when_suspended,
                                                              0,//this slot is unused: old 'resumed' value
                                                              SESSION_USERNAME(sesn_ptr),
                                                              SESSION_COOKIE(sesn_ptr),
                                                              SESSION_UFSRV_GEOGROUP(sesn_ptr),
                                                              SESSION_EID(sesn_ptr),
                                                              (SESSION_USERNICKNAME(sesn_ptr)?SESSION_USERNICKNAME(sesn_ptr):CONFIG_DEFAULT_PREFS_STRING_VALUE),
                                                              (IS_PRESENT(SESSION_GEOFENCE_CURRENT_INSTANCE(sesn_ptr))?FENCE_ID(SESSION_GEOFENCE_CURRENT(sesn_ptr)):0),
                                                              (IS_PRESENT(SESSION_GEOFENCE_LAST_INSTANCE(sesn_ptr))?FENCE_ID(SESSION_GEOFENCE_LAST(sesn_ptr)):0),
                                                              (*baseloc_by_user?baseloc_by_user:CONFIG_DEFAULT_PREFS_STRING_VALUE),
                                                              (*baseloc_by_server?baseloc_by_server:CONFIG_DEFAULT_PREFS_STRING_VALUE),
                                                              (IS_STR_LOADED(SESSION_HOMEBASELOC(sesn_ptr))?SESSION_HOMEBASELOC(sesn_ptr):CONFIG_DEFAULT_PREFS_STRING_VALUE),
                                                              (IS_STR_LOADED(SESSION_USERAVATAR(sesn_ptr))?SESSION_USERAVATAR(sesn_ptr):CONFIG_DEFAULT_PREFS_STRING_VALUE)
                                                              );

	if (redis_ptr) freeReplyObject(redis_ptr);

	BackendCacheStoreBooleanUserPreferences (sesn_ptr);

	//sharelists are done lazily and on-demand

	if (!(sesn_call_flags&CALL_FLAG_DONT_BROADCAST_SESSION_EVENT)) {
		if (_PROTOCOL_CTL_PUB_SESSION_TRANSITIONS(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))))) {
			InterBroadcastSessionStatus (sesn_ptr, NULL, SESSION_MESSAGE__STATUS__CONNECTED, 0);
		}
	}

	_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESULT_CODE_USER_INITIALISED)

}

static UfsrvEvent *_CreateSessionEvent (Session *sesn_ptr, int eid_in, UfsrvEvent *event_ptr_out);
static unsigned long _GenerateSessionEventId (Session *sesn_ptr);

UFSRVResult *
RegisterSessionEvent (Session *sesn_ptr, EnumEventType event_type, unsigned event_instance_type, void *event_payload, UfsrvEvent *event_ptr_out)
{
	UfsrvEvent *event_ptr = NULL;

	event_ptr = _CreateSessionEvent (sesn_ptr, 0, event_ptr_out);

	if (unlikely(IS_EMPTY(event_ptr)))	{_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)}

	event_ptr->event_type		= event_type;
	event_ptr->instance_type= event_instance_type;
	event_ptr->event_payload= event_payload;

#ifdef __UF_FULLDEBUG
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', eid:'%lu'}: SessionEvent: Added..", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), event_ptr->eid);
#endif

	_RETURN_RESULT_SESN(sesn_ptr, event_ptr, RESULT_TYPE_SUCCESS, RESCODE_PROG_RESOURCE_CACHED)

}

/**
* 	/brief create individual, unattached FenceEvent.
* 	/lock	caller must specifiy lock condition
*/
static UfsrvEvent *
_CreateSessionEvent (Session *sesn_ptr, int eid_in, UfsrvEvent *event_ptr_out)
{
	UfsrvEvent *event_ptr = NULL;
	if (IS_PRESENT(event_ptr_out))	event_ptr = event_ptr_out;
	else														event_ptr = malloc(sizeof(UfsrvEvent));

	//generate at the backend
	if (eid_in==0) {
		event_ptr->eid=_GenerateSessionEventId (sesn_ptr);
		if (event_ptr->eid<=0) {
			syslog(LOG_INFO, LOGSTR_SESSION_EVENET_ID_ERROR_BACKEND, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), event_ptr->eid,  LOGCODE_SESSION_EVENET_ID_ERROR_BACKEND);
			if (!IS_PRESENT(event_ptr_out))	free (event_ptr);

			return NULL;
		}
	}
	else 						event_ptr->eid=eid_in;

	event_ptr->when				=	time(NULL);
	event_ptr->ufsrv_event.session_event.session_id	=	SESSION_ID(sesn_ptr);

	return event_ptr;

}

static unsigned long
_GenerateSessionEventId (Session *sesn_ptr)
{
	extern SessionsDelegator *const sessions_delegator_ptr;

	PersistanceBackend	*pers_ptr;
	redisReply					*redis_ptr;

	pers_ptr=sesn_ptr->persistance_backend;

	char command_buf[MBUF]={0};
	snprintf (command_buf, MBUF, REDIS_CMD_SESSION_INC_EVENT_COUNTER, SESSION_USERID(sesn_ptr));
	if (!(redis_ptr=(*pers_ptr->send_command)(sesn_ptr, command_buf))) {
		syslog(LOG_DEBUG, "%s: ERROR COULD NOT INC EVENTS COUNTER for UID:'%lu': BACKEND CONNECTIVITY ERROR", __func__, SESSION_USERID(sesn_ptr));

		return 0;
	}

	if (redis_ptr->type==REDIS_REPLY_ERROR) {
		syslog(LOG_DEBUG, "%s: ERROR COULD NOT INC EVENTS CUNTER for UID:'%lu': REPLY ERROR '%s'", __func__, SESSION_USERID(sesn_ptr), redis_ptr->str);

		freeReplyObject(redis_ptr);

		return 0;
	}

	if (redis_ptr->type == REDIS_REPLY_NIL) {
		syslog(LOG_DEBUG, "%s: ERROR COULD NOT INC EVENTS CUNTER for UID:'%lu': REPLY NIL '%s'", __func__, SESSION_USERID(sesn_ptr), redis_ptr->str);

		freeReplyObject(redis_ptr);

		return 0;
	}

	long long ev_counter=redis_ptr->integer;

	freeReplyObject(redis_ptr);

	SESSION_EID(sesn_ptr)=(unsigned long)ev_counter;

	return (unsigned long)ev_counter;

}

/**
 * 	@brief:
 * 	This is called in a specific context whereby a network broadcast by ANOTHER ORIGIN on user session arrived. The broadcast carries update
 * 	on the status of the Session. This function determines if session is hashed locally
 * 	and if yes compare with supplied status.
 *	If found hashed locally, the session could be connected or remote.
 *
 *	@param status: status of session as supplied in the broadcast
 *
 *	@returns RESCODE_IO_NOTCACHED: session unknown to this server and not in local cache
 *	@return RESCODE_USER_SESN_LOCAL:RESULT_TYPE_SUCCESS: session is known/hashed locally. could be remote or connected
 *	@return RESCODE_IO_CACHEINVALIDATED: local connected user whose local status was not inline with broadcast so local cash was cleared
 *	@return RESCODE_IO_CONNECTED: user session is local and connected and is ACTIVE
 *	@returns RESCODE_LOGIC_CANTLOCK: could not lock session
 *
 * 	@lock:
 * 	 locks session and returns it in locked state. caller responsibility to unlock
 *
 * 	@worker_thread: ufsrv worker. don't user sesn_ptr_this
 */
UFSRVResult  *
IsSessionLocalAndCompareStatus (unsigned long session_id, unsigned status, unsigned call_flags, UFSRVResult *res_ptr)
{
#if 0
	//THIS IS NOT RELEVANT UNDER NEW IMPLEMENTATION> KEEP AROUND FOR REFERENCE
	Session *sesn_ptr;
	//unsigned long session_id;

	//ession_id=session_id_in;
	if ((sesn_ptr=LocateSessionById(session_id)))
	{
		if ((SessionLockRW(sesn_ptr, 0))!=0)//blocking lock
		{
			if (res_ptr)
			{
				_RETURN_RESULT_RES(res_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_LOGIC_CANTLOCK);
			}

			_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_USER_SESN_LOCAL);
		}

		//>>>>>>>>>> SESSION LOCKED

		if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_REMOTE))
		{
			syslog(LOG_DEBUG, "%s (pid:'%lu'): SESSION cid='%lu' IS REMOTE", __func__, pthread_self(), session_id);

			switch(status)
			{
				case 0://user is signed off on server of origin
					syslog(LOG_DEBUG, "%s (pid:'%lu'): REMOTE SESSION cid:'%lu' SIGNED OFF ON ORIGIN: REMOVING LOCALY and NOTIFYING", __func__, pthread_self(), session_id);
					SESNSTATUS_UNSET(sesn_ptr->stat, SESNSTATUS_REMOTE_CONNECTED);
					//we clear it off in checkidle time
					//ClearLocalSessionCache (NULL, sesn_ptr);
						//TODO: check fences and updated to other users
						//goto clear session off below
				break;

				case 1://active
					syslog(LOG_DEBUG, "%s (pid:'%lu'): REMOTE SESSION cid:'%lu' HAS CONNECTED", __func__, pthread_self(), session_id);

					SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_REMOTE_CONNECTED);
					SESNSTATUS_UNSET(sesn_ptr->stat, SESNSTATUS_SUSPENDED);
					//TODO: notify
				break;

				case 2://suspended
					syslog(LOG_DEBUG, "%s (pid:'%lu'): REMOTE SESSION cid:'%lu' SUSPENDED", __func__, pthread_self(), session_id);
					SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_SUSPENDED);
					SESNSTATUS_UNSET(sesn_ptr->stat, SESNSTATUS_REMOTE_CONNECTED);
					//TODO: notify and update
				break;
			}//switch

			if (call_flags&CALL_FLAG_UNLOCK_SESSION)	SessionUnLock(sesn_ptr);

			_RETURN_RESULT_RES(res_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_USER_SESN_LOCAL);
		}
		else
		{//supposedly locally connected user. can be problematic
			switch (status)
			{
				case 0:
					//user signed off on another server and is known locally
					if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_CONNECTED))//user active locally
					{
						//network inconsistency: other servers my act upon this false 0 signal
						syslog(LOG_DEBUG, "%s (pid:'%lu'): SESSION cid:'%lu' signed off on REMOTE SERVER BUT IS ACTIVE LOCALLY", __func__, pthread_self(), session_id);

						if (call_flags&CALL_FLAG_UNLOCK_SESSION)	SessionUnLock(sesn_ptr);

						_RETURN_RESULT_RES(res_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_IO_CONNECTED);
					}
					else
					{
						syslog(LOG_DEBUG, "%s (pid:'%lu'): SESSION cid:'%lu': INVALIDATING CACHE LOCALLY", __func__, pthread_self(), session_id);
						//TODO: check fences and updated to other users
						//goto clear session off below
					}
				break;

				case 1://active
					//we lost this guy he is on another ufsrv: remove from local cache
					syslog(LOG_DEBUG, "%s (pid:'%lu'): SESSION cid:'%lu' MIGRATED: INVALIDATING LOCALLY", __func__, pthread_self(), session_id);

					//check for double login
					if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_CONNECTED))
					{
						//this is not fool proof as we may have lost the guy, but underlying network did not propogate that yet
						if ((sesn_ptr->ssptr->sock>0)&&(IsSocketAlive(sesn_ptr->ssptr->sock)==0))
						{
							syslog(LOG_DEBUG, "%s (pid:'%lu'): SESSION cid:'%lu' MULTIPLE LOGINS: DISCONNECTING LOCAL", __func__, pthread_self(), session_id);

							//TODO: we cant issue MarshalServiceCommandToClient from ufsrv worker yet
							//UfsrvLoginVerificationMessage (NULL, sesn_ptr, NULL, LVMSG_MULTIPLELOGIN_REJECT);//inform user

							//now quietly disconnect the user from network POV post switch block
							ClearLocalSessionCache (NULL, sesn_ptr, CALL_FLAG_REMOTE_SESSION);

							if (call_flags&CALL_FLAG_UNLOCK_SESSION)	SessionUnLock(sesn_ptr);

							_RETURN_RESULT_RES(res_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_IO_CACHEINVALIDATED);
						}
						else
						{
							syslog(LOG_DEBUG, "%s (pid:'%lu'): INCONSISTANCY: SESSION cid:'%lu' MIGRATED AND MARKED LOCALLY CONNECTED BUT SOCKET IS DISCONNECTED", __func__, pthread_self(), session_id);
						}
					}
				break;

				case 2://suspended
					syslog(LOG_DEBUG, "%s (pid:'%lu'): SESSION cid:'%lu' SUSPENDED ON REMOTE SEREVR: INVALIDATING LOCALLY", __func__, pthread_self(), session_id);
				break;
			}//switch

			//finished_processing_local_hashed_sesseion:

			ClearLocalSessionCache (NULL, sesn_ptr, CALL_FLAG_UNLOCK_SESSION|CALL_FLAG_DONT_BROADCAST_FENCE_EVENT);//we lost this session now dont reference after this point

			_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_IO_CACHEINVALIDATED);
		}//LOCAL session

		if (call_flags&CALL_FLAG_UNLOCK_SESSION)	SessionUnLock(sesn_ptr);

		_RETURN_RESULT_RES(res_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_IO_CACHEINVALIDATED);
	}
	else
	{
		syslog(LOG_DEBUG, "%s (pid:'%lu'): UNKNOWN SESSION cid:'%lu' NOT IN LOCAL CACHE: REPORTING ON STATUS...", __func__, pthread_self(), session_id);

		switch (status)
		{
			case 0://user is signed off on another server

				syslog(LOG_DEBUG, "%s (pid:'%lu'): UKNOWN SESSION 'cid=%lu': SIGNED OFF REMOTELY", __func__, pthread_self(), session_id);
				//TODO: due to random events for disconnection we always verify against backend
				//FetchUserNetworkState (Session *sesn_ptr, unsigned long user_id);

				//TODO: check affected fences/notify lists
			break;

			case 1://active
				syslog(LOG_DEBUG, "%s (pid:'%lu'): UNKNOWN SESSION '%lu' LOGGED ON REMOTELY", __func__, pthread_self(), session_id);
				//TODO: check affected fences/notify lists
			break;

			case 2://suspended
				syslog(LOG_DEBUG, "%s (pid:'%lu'): UNKNOWN SESSION '%lu' SUSPENDED REMOTELY", __func__, pthread_self(), session_id);
				//TODO: check affected fences/notify lists
			break;
		}//switch

		_RETURN_RESULT_RES(res_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_IO_NOTCACHED);
	}
#endif
	_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);

}

/**
 * 	@brief Loads the session context with all backend access pointers
 * 	This is designed to work with UfsrvWorker threads, ie non SessionWorkers.
 *
 * 	@locked sesn_ptr: must be locked in the calling environment
 */
inline int
SessionLoadEphemeralMode (Session *sesn_ptr)
{
	ThreadContext						*thread_ctx_ptr;
	PersistanceBackend 			*pers_ptr;
	UserMessageCacheBackend *usrmsg_cachbackend_ptr;
	FenceCacheBackend 			*fence_cachbackend_ptr;
	MessageQueueBackend 		*mq_ptr;
	InstrumentationBackend 	*inst_ptr;
	struct _h_connection 		*db_backend;

	thread_ctx_ptr				=pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_thread_context_key);
	inst_ptr							=pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_instrumentation_backend_key);
	pers_ptr							=pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.worker_persistance_key);
	mq_ptr								=pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_msgqueue_pub_key);
	usrmsg_cachbackend_ptr=pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.worker_usrmsg_cachebackend_key);
	fence_cachbackend_ptr	=pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.worker_fence_cachebackend_key);
	db_backend						=pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_db_backend_key);

	sesn_ptr->thread_ctx_ptr					=thread_ctx_ptr;
	sesn_ptr->instrumentation_backend	=inst_ptr;
	sesn_ptr->persistance_backend			=pers_ptr;
	sesn_ptr->msgqueue_backend				=mq_ptr;
	sesn_ptr->usrmsg_cachebackend			=usrmsg_cachbackend_ptr;
	sesn_ptr->fence_cachebackend			=fence_cachbackend_ptr;
	sesn_ptr->db_backend							=db_backend;

	SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_EPHEMERAL);

	return 0;

}

inline int
SessionLoadEphemeralModeWithDescriptor (Session *sesn_ptr, EphemeralModeDescription *ephm_mode_ptr)
{
	sesn_ptr->thread_ctx_ptr					=ephm_mode_ptr->thread_ctx_ptr;
	sesn_ptr->instrumentation_backend	=ephm_mode_ptr->inst_ptr;
	sesn_ptr->persistance_backend			=ephm_mode_ptr->pers_ptr;
	sesn_ptr->msgqueue_backend				=ephm_mode_ptr->mq_ptr;
	sesn_ptr->usrmsg_cachebackend			=ephm_mode_ptr->usrmsg_cachbackend_ptr;
	sesn_ptr->fence_cachebackend			=ephm_mode_ptr->fence_cachbackend_ptr;
	sesn_ptr->db_backend							=ephm_mode_ptr->db_backend;

	SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_EPHEMERAL);

	return 0;
}

inline int
SessionUnLoadEphemeralMode (Session *sesn_ptr)
{
	if	(unlikely(sesn_ptr==NULL))	return -1;

	sesn_ptr->thread_ctx_ptr					=NULL;
	sesn_ptr->instrumentation_backend	=NULL;
	sesn_ptr->persistance_backend			=NULL;
	sesn_ptr->usrmsg_cachebackend			=NULL;
	sesn_ptr->fence_cachebackend			=NULL;
	sesn_ptr->msgqueue_backend				=NULL;
	sesn_ptr->db_backend							=NULL;

	SESNSTATUS_UNSET(sesn_ptr->stat, SESNSTATUS_EPHEMERAL);

	return 0;

}

inline HttpRequestContext *
GetHttpRequestContext(Session *sesn_ptr)
{
 return (pthread_getspecific(masterptr->threads_subsystem.ufsrv_http_request_context_key));
}

inline HttpRequestContext *
GetHttpRequestContextUfsrvWorker(Session *sesn_ptr)
{
 return (pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_http_request_context_key));
}

static inline UFSRVResult *_InvokeLifecycleCallbackServiceTimeout (Session *sesn_ptr, time_t now, unsigned long call_flags);

static inline UFSRVResult *
_InvokeLifecycleCallbackServiceTimeout (Session *sesn_ptr, time_t now, unsigned long call_flags)
{
	UFSRVResult *res_ptr;

	if (_PROTOCOL_CLLBACKS_SERVICE_TIMEOUT(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr)))))
	{
		res_ptr=_PROTOCOL_CLLBACKS_SERVICE_TIMEOUT_INVOKE(protocols_registry_ptr,
											PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))),
											sesn_ptr, now, call_flags);
	}

	exit_success:
	return res_ptr;
}

__attribute__ ((const)) ScheduledJobType *
GetScheduledJobTypeForSessionTimeout (void)
{
	static ScheduledJobType job_type_session_timeout={
			.type_name				=	"Session Timeout",
			.type_id					=	0,//gets assigned by type registry
			.frequecy_mode		=	PERIODIC,
			.concurrency_mode	=	SINGLE_INSTANCE,
			.frequency				=	_CONFIGDEFAULT_SESSION_TIMEOUT_CHECK_FREQUENCY, //1min
			.job_ops					=	{
					.callback_on_compare_keys	= (CallbackOnCompareKeys)TimeValueComparator,
					.callback_on_error				=	NULL,
					.callback_on_run					=	(CallbackOnRun)CheckSessionIdleTime
			}
	};

	return &job_type_session_timeout;

}

/**
 * 	@brief: Since this job type does not allow concurrent scheduling, ie one job of this type can ever exist in the scheduler
 * 	we can get away with allocating a single static reference.
 */
ScheduledJob *
GetScheduledJobForSessionTimeout (void)
{
	static ScheduledJob job_session_timeout;

	job_session_timeout.job_type_ptr=GetScheduledJobTypeForSessionTimeout();

	return &job_session_timeout;
}

//This is thread-safe as it is only accessed one thread at a time.
static size_t	_store_sz = _CONFIGDEFAULT_HASHTABLE_SZ * 2;
static InstanceHolderForSession	*_LocalSessionStore[_CONFIGDEFAULT_HASHTABLE_SZ * 2];
static atomic_bool isCheckSessionIdelTimeRunning = ATOMIC_VAR_INIT(false);

bool IsCheckSessionIdelTimeRunning ()
{
	return (atomic_load_explicit(&isCheckSessionIdelTimeRunning, memory_order_acquire));

}

/*
 * You don't need atomic_thread_fence() here because your critical sections start with acquire and end with release semantics.
 * Hence, reads within your critical sections can not be reordered prior to the acquire and writes post the release.
 * And this is why volatile is unnecessary here as well.
 * http://stackoverflow.com/questions/19689872/c11-memory-fence-usage
 */
int
CheckSessionIdleTime (void *arg)
{
	bool expected_running_is_false = false;
	if( !atomic_compare_exchange_strong_explicit(&isCheckSessionIdelTimeRunning, &expected_running_is_false, true, memory_order_acq_rel/*memory_order_acquire*/, memory_order_relaxed)) {
		syslog(LOG_DEBUG, LOGSTR_UFSRVWORKER_ONETHREADONLY, __func__, pthread_self(), LOGCODE_UFSRVWORKER_ONETHREADONLY, "CheckSessionIdleTime");
		//statsd_inc(pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_instrumentation_backend_key), "worker.ufsrv.job.idletime.busy", 1.0);
		return 0;
	}

	int			i;
	int			numResults = 0;
	bool		is_using_local_store = false;
	InstanceHolderForSession **current_sessions;
	HashTable	*hash = &(sessions_delegator_ptr->hashed_sessions.hashtable);

		//TODO: this a giant locking space as we are locking the entire sessions table. won't scale with many sessions. FIX.
		if ((HashTable_RdLock(hash, 1)) != 0) {
				numResults =- 1;
				goto return_with_value;
		}

		UfsrvConfigRegisterUfsrverActivity (pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.worker_persistance_key), time(NULL));

		syslog(LOG_DEBUG, LOGSTR_CACHE_SIZE, __func__, pthread_self(), HASHTABLE_ENTRIES(hash), HASHTABLE_SIZE(hash), LOGCODE_CACHE_SIZE_SESSION, HASHTABLE_NAME(hash));

		statsd_gauge(pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_instrumentation_backend_key), "worker.ufsrv.job.idletime.sessions_global_size", (ssize_t)HASHTABLE_ENTRIES(hash));

		long long timer_start = GetTimeNowInMicros();

		if (HASHTABLE_SIZE(hash) == 0 || HASHTABLE_ENTRIES(hash) == 0) {
			HashTable_UnLock(hash);
#if __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s (pid:'%lu'): NO SESSIONS FOUND: RETURNING...", __func__, pthread_self(), LOGCODE_CACHE_EMPTY);
#endif

			numResults = 0;//return 0;
			goto return_with_value;
		}

		//mutate table so as not to hold it locked for too long
		if (HASHTABLE_ENTRIES(hash)<_store_sz) {
			current_sessions = _LocalSessionStore;
			is_using_local_store = true;
		} else {
			current_sessions = malloc((HASHTABLE_ENTRIES(hash) + 1) * sizeof(InstanceHolderForSession *));
			*(current_sessions + HASHTABLE_ENTRIES(hash)) = NULL; //terminate last entry for safety
		}

#if __UF_FULLDEBUG
		syslog(LOG_DEBUG, LOGSTR_CACHE_SIZE,
				__func__, pthread_self(), hash->fNumEntries, hash->fTableSize, LOGCODE_CACHE_SIZE_SESSION, hash->table_name);
#endif

		for (i=0; i<HASHTABLE_SIZE(hash); i++) {
			if (hash->fTable[i] != NULL) {
				if (numResults + 1 > HASHTABLE_ENTRIES(hash)) {
					syslog(LOG_ERR, LOGSTR_CACH_INCONSIZE, __func__, pthread_self(), numResults+1, HASHTABLE_ENTRIES(hash), LOGCODE_CACHE_INCONSISTENT_SIZE, HASHTABLE_NAME(hash));
					break;
				}

				//this is being over defensive: although we don't hold a lock on the Session, only this is the only likely thread
				//that actually can send it to recycler, causing it to be invalidated between now and until we acquire the lock below
				//IMPORTANT: proto_http_service_timeout_callback checks for refcount==2 due to this increase. Adjust accordingly to '1' if this increase is removed in the future
				SessionIncrementReference((InstanceHolderForSession *)hash->fTable[i], 1);

				*(current_sessions+(numResults++)) = (InstanceHolderForSession *)hash->fTable[i];
			}
		}
		HashTable_UnLock(hash);

		syslog(LOG_DEBUG, LOGSTR_CACHE_EXTRACTEDSET, __func__, pthread_self(), numResults, LOGCODE_CACHE_EXTRACTEDSET_SIZE, HASHTABLE_NAME(hash));

		if (numResults != HASHTABLE_ENTRIES(hash)) {
			syslog(LOG_ERR, "%s (pid:'%lu'): ERROR: DISCREPANCY between SCANNED '%d' and ACTUAL '%lu' SESSIONS.", __func__, pthread_self(), numResults, HASHTABLE_ENTRIES(hash));
		}

		{
			int								result_code;
			time_t						now	= time(NULL);
			Session						*sesn_ptr;
			EphemeralModeDescription	ephemeral_mode_descriptor;

			//once only init
			ephemeral_mode_descriptor.thread_ctx_ptr				=	pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_thread_context_key);
			ephemeral_mode_descriptor.inst_ptr							=	pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_instrumentation_backend_key);
			ephemeral_mode_descriptor.pers_ptr							=	pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.worker_persistance_key);
			ephemeral_mode_descriptor.mq_ptr								=	pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_msgqueue_pub_key);
			ephemeral_mode_descriptor.usrmsg_cachbackend_ptr=	pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.worker_usrmsg_cachebackend_key);
			ephemeral_mode_descriptor.fence_cachbackend_ptr	=	pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.worker_fence_cachebackend_key);
			ephemeral_mode_descriptor.db_backend						=	pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_db_backend_key);

			//bool recycle_flag=false;
			statsd_gauge(pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_instrumentation_backend_key), "worker.ufsrv.job.idletime.sessions_collection_size", numResults);

			bool    lock_already_owned			= false;

			for (i=0; i<numResults; i++) {
				InstanceHolderForSession *instance_sesn_ptr = *(current_sessions + i);
        Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

				if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_RECYCLED)) {
					//this indicates a session that was meant to be recycled, but has unresolved reference count
					syslog(LOG_ERR, "%s (pid:'%lu', o:'%p', cid:'%lu'): NOTICE: FOUND A SESSION WITH UNRESOLVED REFCOUNT", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
					SessionDecrementReference(instance_sesn_ptr, 1);
					SessionReturnToRecycler (instance_sesn_ptr, (ContextData *)NULL, CALLFLAGS_EMPTY);
					continue;
				}

				SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr, _LOCK_TRY_FLAG_TRUE, __func__);
				if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR)) {
					//TODO: USE ATOMICS FOR THIS
					if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_IOERROR))/*this is only set for local connected sessions*/ {
						syslog(LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu'}: NOTICE: FOUND A LOCKEDSESNSTATUS_IOERROR TAGGED SESSION:...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
					}

					SessionDecrementReference(instance_sesn_ptr, 1);

					continue;//ignore session

						//TODO: this is problematic as a session could be in service and just tagged itself with IO error
						//a better check routine is required
//					//TODO: USE ATOMICS FOR THIS
//					if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_IOERROR))//this is only set for local connected sessions
//					{
//						syslog(LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu'}: NOTICE: FOUND A LOCKED AND FAULTY SESSION: KILLING SESSION...",
//							__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
//
//						SessionDecrementReference(sesn_ptr, 1);
//
//						//we don't broadcast event: deal with it at data structure local level
//						ClearLocalSessionCache(sesn_ptr, CALL_FLAGS_KILL_SESSION|CALL_FLAG_TRANSFER_WORKER_ACCESS_CONTEXT);//we dont unlock, broadcast
//					}
//					else
//					{
//						SessionDecrementReference(sesn_ptr, 1);
//
//						continue;//ignore session
//					}
				}

				//>>>> SESSION NOW LOCKED

				lock_already_owned = (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_THIS_THREAD));

				SessionLoadEphemeralModeWithDescriptor(sesn_ptr, &ephemeral_mode_descriptor);

				if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_DEFERRED_RECYCLE) && SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_SUSPENDED)) {
#ifdef __UF_TESTING
					syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: Found a Session with SESNSTATUS_DEFERRED_RECYCLE flag...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
#endif

					if (SuspendSession (instance_sesn_ptr, HARD_SUSPENSE)) {
						result_code = RESULT_CODE_SESN_HARDSPENDED;
						goto unlock_session;
					} else {
						//TODO: this ends up in limbo we got to kill it
						SessionDecrementReference(instance_sesn_ptr, 1);
						if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr, __func__);
						continue;
					}
				}

				_InvokeLifecycleCallbackServiceTimeout (sesn_ptr, now, 0);

				result_code = SESSION_RESULT_CODE(sesn_ptr); //grab it whilst the session is still locked

				//>>>>>>>>>>>>>>>>>>>>>>>
				unlock_session:
				SessionUnLoadEphemeralMode(sesn_ptr);
				if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr, __func__);

				//TODO: should this be place before unlocking Session? probably not, because if it is dereferenced
				//it becomes available immdiately, so it must be in unlocked state
				SessionDecrementReference(instance_sesn_ptr, 1);

				if (result_code == RESULT_CODE_SESN_HARDSPENDED)/*session out of circulation*/ {
					SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_RECYCLED);
					SessionReturnToRecycler (instance_sesn_ptr, (ContextData *)NULL, 0);
				}
				//>>>>>>>>>>>>>>>>>>>>>>>

			}//for
		}

		if (!is_using_local_store)	free (current_sessions);

		//statsd_gauge(pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_instrumentation_backend_key), "worker.ufsrv.job.idletime.sessions_collection_size", 0);

		return_with_value:
		atomic_store_explicit(&isCheckSessionIdelTimeRunning, false, memory_order_release);
		long long timer_end=GetTimeNowInMicros();
		//syslog(LOG_DEBUG, "start_timer: %lld. end_timer: %lld", timer_start, timer_end);
		statsd_timing(pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_instrumentation_backend_key), "worker.ufsrv.job.idletime.elapsed_time", (timer_end-timer_start));
		return numResults;

}

/**
 * 	@brief: "constructor" type intialiser for newly instantiated objects just before attaching them to the recycler.
 * 	One off for the object's lifetime.
 *
 */
static int
TypePoolInitCallback_Session (ClientContextData *data_ptr, size_t oid)
{
	Session *sesn_ptr = (Session *)data_ptr;

	return (InstantiateSession2(&sesn_ptr, CALLFLAGS_EMPTY, masterptr->main_listener_protoid));

}

void
InitSessionRecyclerTypePool ()
{
	SessionTypePoolHandle = RecyclerInitTypePool ("Session", sizeof(Session), _CONF_SESNMEMSPECS_ALLOC_GROUP_SZ(masterptr), &ops_session);

}

/**
 * @brief: initialiser Each time the object is fetched from the recycler. On error, the data is automatically pushed back to the recycler.
 * and the original caller of RecyclerGet() gets NULL back.
 *
 * @param call_flags: passed down from the client through the lifecycle manager
 */
static int
TypePoolGetInitCallback_Session (InstanceHolder *data_ptr, ContextData *context_data, size_t oid, unsigned long call_flags)
{
  Session *sesn_ptr = SessionOffInstanceHolder((InstanceHolderForSession *)data_ptr);

	if (!(call_flags&CALL_FLAG_INSTANTIATE_FROM_SYSTEM_USER)) {
		if ((sesn_ptr->session_id = GenerateSessionId()) == 0)	return 1;//object queued back automatically
	} else CloneUfsrvSystemUser((InstanceHolderForSession *)data_ptr, SESSION_CALLFLAGS_EMPTY);

	//re-assign relevant values to recycled session so we can use it
	SESNSTATUS_UNSET(sesn_ptr->stat, SESNSTATUS_RECYCLED);

	if (unlikely(call_flags&CALL_FLAG_CARRIER_INSTANCE)) {
		SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_CARRIER);
		return 0;
	}

	if (call_flags&CALL_FLAG_SNAPSHOT_INSTANCE)	SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_SNAPSHOT);

	LoadDefaultUserPreferences (sesn_ptr);

	SESSION_SOCKETBLOCKSZ(sesn_ptr) = masterptr->buffer_size;//set default read block size

	//reassign protocol as a reminder for future multi
	SESSION_PROTOCOLTYPE(sesn_ptr) = (ProtocolTypeData *)&protocols_registry_ptr[masterptr->main_listener_protoid];

	//invoke lifecycle callback for session initialisation (soft, recycler based)
	if (_PROTOCOL_CLLBACKS_INIT_SESSION(protocols_registry_ptr, masterptr->main_listener_protoid)) {
	#define SESSION_RECYCLERINSTANCE	1 //recycler instance
		_PROTOCOL_CLLBACKS_INIT_SESSION_INVOKE(protocols_registry_ptr, masterptr->main_listener_protoid,
												sesn_ptr, SESSION_RECYCLERINSTANCE);
	#undef	SESSION_RECYCLERINSTANCE
	}

	if (call_flags&CALL_FLAG_HASH_SESSION_LOCALLY) {
		if (!(AddToHash(&(sessions_delegator_ptr->hashed_sessions.hashtable), (void *)(InstanceHolderForSession *)data_ptr))) {
			SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_RECYCLED);

			return 1;//object queued back automatically
		}
	}

	return 0;//success

}

/**
 * @brief: initialiser Each time the object is pushed back into the recycler.
 */
static int
TypePoolPutInitCallback_Session (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
  Session *sesn_ptr = SessionOffInstanceHolder((InstanceHolderForSession *)data_ptr);
	sesn_ptr->stat = 0;
	SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_RECYCLED);

	if (call_flags&CALL_FLAG_HASH_SESSION_LOCALLY) {
		RemoveFromHash(&(sessions_delegator_ptr->hashed_sessions.hashtable), (void *) (InstanceHolderForSession *)data_ptr);
	}

	return 0;//success

}

/**
 * @brief: initialiser Each time the object is pushed back into the recycler.
 */
static char *
TypePoolPrintCallback_Session (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
  Session *sesn_ptr = SessionOffInstanceHolder((InstanceHolderForSession *)data_ptr);

	return 0;//success

}

/**
 * @brief:
 */
static int
TypePoolDestructCallback_Session (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
  Session *sesn_ptr = SessionOffInstanceHolder((InstanceHolderForSession *)data_ptr);

	return 0;//success

}

void
SessionIncrementReference (InstanceHolderForSession *instance_sesn_ptr, int multiples)
{
	RecyclerTypeReferenced (1, (RecyclerClientData *)instance_sesn_ptr, multiples);
}

void
SessionIncrementReferenceByOne (InstanceHolderForSession *instance_sesn_ptr)
{
  RecyclerTypeReferenced (1, (RecyclerClientData *)instance_sesn_ptr, 1);
}

void
SessionDecrementReference (InstanceHolderForSession *instance_sesn_ptr, int multiples)
{
	RecyclerTypeUnReferenced (1, (RecyclerClientData *)instance_sesn_ptr, multiples);
}

void
SessionDecrementReferenceByOne (InstanceHolderForSession *instance_sesn_ptr)
{
  RecyclerTypeUnReferenced (1, (RecyclerClientData *)instance_sesn_ptr, 1);
}

size_t
SessionGetReferenceCount (InstanceHolderForSession *instance_sesn_ptr)
{
	return RecyclerTypeGetReferenceCount (SessionPoolTypeNumber(), (RecyclerClientData *)instance_sesn_ptr);
}

int
SessionReturnToRecycler (InstanceHolderForSession *instance_sesn_ptr, ContextData *ctx_data_ptr, unsigned long call_flags)
{
	int rc = RecyclerPut(SessionPoolTypeNumber(), instance_sesn_ptr, (ContextData *)ctx_data_ptr, call_flags);
	if (rc == -3) {
	  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
		if (_PROTOCOL_CLLBACKS_RECYCLER_ERROR(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))))) {
			UFSRVResult *res_ptr=_PROTOCOL_CLLBACKS_RECYCLER_ERROR_INVOKE(protocols_registry_ptr,
								PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))),
								sesn_ptr, CALLFLAGS_EMPTY);
		}
	}

	return rc;

}

__pure unsigned  SessionPoolTypeNumber()
{
	return SessionTypePoolHandle->type;
}
