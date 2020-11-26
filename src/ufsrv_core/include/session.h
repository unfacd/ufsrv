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

#ifndef SESSION_H
# define SESSION_H

#include <uflib/adt/adt_queue.h>
#include <uflib/adt/adt_linkedlist.h>
#include <session_type.h>
#include <sessions_delegator_type.h>
#include <sockets.h>
#include <hashtable.h>
#include <misc.h>//thread errors prnt
#include <ufsrv_core/msgqueue_backend/UfsrvMessageQueue.pb-c.h>
#include <ufsrv_core/instrumentation/instrumentation_backend.h>
#include <ufsrv_core/user/user_backend.h>
#include <http_request_context_type.h>
#include <ufsrv_core/cache_backend/persistance_type.h>
#include <ufsrv_core/msgqueue_backend/ufsrvmsgqueue_type.h>
#include <ufsrv_core/fence/fence_type.h>
#include <pthread.h>
#include <thread_context_type.h>
#include <thread_utils.h>
#include <hiredis.h>
#include <uflib/db/db_sql.h>
#include <uflib/scheduled_jobs/scheduled_jobs.h>
#include <ufsrvuid_type.h>

#include <recycler/recycler_type.h>

//function call flags
#define CALLFLAG_SET(x,y)			(x|=y)
#define CALLFLAG_UNSET(x,y)			(x&=~y)
#define CALLGFLAG_IS_SET(x,y)		(x&y)

#define SESSION_CALLFLAGS_EMPTY											0
#define CALL_FLAG_LOCK_SESSION											(0x1UL<<1UL)
#define CALL_FLAG_HASH_SESSION_LOCALLY							(0x1UL<<2UL)
#define CALL_FLAG_REMOTE_SESSION										(0x1UL<<3UL)//set it as remote session
#define CALL_FLAG_SUSSPEND_SESSION									(0x1UL<<4UL)
#define CALL_FLAG_WRITEBACK_FENCE_DATA_TO_BACKEND		(0x1UL<<5UL)//includes msgqueue broadcast
#define CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND	(0x1UL<<6UL)
#define CALL_FLAG_SNAPSHOT_INSTANCE									(0x1UL<<7UL)
#define CALL_FLAG_SEARCH_BACKEND										(0x1UL<<8UL)
#define CALL_FLAG_HASH_UID_LOCALLY									(0x1UL<<9UL)
#define CALL_FLAG_SEARCH_LOCAL											(0x1UL<<10UL) //local hash
#define CALL_FLAG_UNLOCK_SESSION										(0x1UL<<11UL)
#define CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION			(0x1UL<<12UL)//build user's  list of fences
#define CALL_FLAG_SESSION_FENCE_APPEND							(0x1UL<<13UL)//append to existing user fence list, ensuring no duplication
#define CALL_FLAG_SESSION_FENCE_REBUILD							(0x1UL<<14UL)//rebuild user fence list
#define CALL_FLAG_CARRIER_INSTANCE									(0x1UL<<15UL)//
#define CALL_FLAG_FENCE_LIST_CHECK_DUP_SESSION			(0x1UL<<16UL)//check if session is in Fence Session list
#define CALL_FLAG_SESSION_LIST_CHECK_DUP_FENCE			(0x1UL<<17UL)//check if fence is in Session fence list
#define CALL_FLAG_DONT_LOCK_SESSION									(0x1UL<<18UL)
#define CALL_FLAG_SESSION_LIST_INCLUDE_REMOTE				(0x1UL<<19UL)//whci compliling sessions list from fence, include remote sessions
#define CALL_FLAGS_KILL_SESSION											(0x1UL<<20UL)//dont' send session into recycler: release all memory associated with it
#define CALL_FLAG_SWAP_COOKIE												(0x1UL<<21UL)
#define CALL_FLAG_DONT_BROADCAST_FENCE_EVENT				(0x1UL<<22UL)//announce fence event trough msgqueue, but not write back
#define CALL_FLAG_BROADCAST_SESSION_EVENT						(0x1UL<<23UL)//
#define CALL_FLAG_DONT_BROADCAST_SESSION_EVENT			(0x1UL<<24UL)//
#define CALL_FLAG_USER_AUTHENTICATED								(0x1UL<<25UL)//user already (password)authenticated
#define CALL_FLAG_USER_SIGNON												(0x1UL<<26UL)//sign user on
#define CALL_FLAG_HASH_USERNAME_LOCALLY							(0x1UL<<27UL)
#define CALL_FLAG_SELF_DESTRUCT											(0x1UL<<28UL)
#define CALL_FLAG_LOCTION_BY_USER										(0x1UL<<29UL)
#define CALL_FLAG_LOCTION_BY_SERVER									(0x1UL<<30UL)
#define CALL_FLAG_TRANSFER_DB_USERDATA							(0x1UL<<31UL)//session hold freshly sourced DB data
#define CALL_FLAG_REBOOT_SESSION										(0x1UL<<32UL)//for session provider: load session data from db backend and propogate up
#define CALL_FLAG_DUP_SESSION_DATA									(0x1UL<<33UL)//duplicate dynamic data as opposed to copying by reference
#define CALL_FLAG_LOCK_SESSION_BLOCKING							(0x1UL<<34UL)//lock session and block if necessary
#define CALL_FLAG_TRANSFER_SESSION_ACCESS_CONTEXT		(0x1UL<<35UL)
#define CALL_FLAG_TRANSFER_WORKER_ACCESS_CONTEXT		(0x1UL<<36UL)
#define CALL_FLAG_INSTANTIATE_FROM_SYSTEM_USER			(0x1UL<<37UL)//when instantiating a session, assume the singular identity of ufsrv system user
#define CALL_FLAG_LOAD_DB_BACKEND_FOR_SESSION				(0x1UL<<38UL)//load user's data from db backend

//profile_key not in use and can be reassigned
enum REDIS_UID_FIELDS {
REDIS_KEY_USER_SID=0, 					REDIS_KEY_USER_CID,
REDIS_KEY_USER_STATUS, 					REDIS_KEY_USER_UID,
REDIS_KEY_USER_USER_NAME, 			REDIS_KEY_USER_PROFILE_KEY,
REDIS_KEY_USER_HADDRESS, 				REDIS_KEY_USER_BASELOC,
REDIS_KEY_USER_WHEN,						REDIS_KEY_USER_WHEN_SERVICED,
REDIS_KEY_USER_WHEN_SUSPENDED, 	REDIS_KEY_USER_WHEN_RESUMED,
REDIS_KEY_USER_COOKIE, 					REDIS_KEY_USER_GEOGROUP,
REDIS_KEY_USER_EVENT_COUNTER,   REDIS_KEY_USER_NICKNAME,
REDIS_KEY_CURRENT_GEOFENCE, 		REDIS_KEY_PAST_GEOFENCE,
REDIS_KEY_LOCATION_USER,				REDIS_KEY_LOCATION_SERVER,
REDIS_KEY_HOME_BASELOC,					REDIS_KEY_USER_AVATAR,
REDIS_KEY_GUARDIAN_ID,
REDIS_KEY_MAX
};

#define REDIS_CMD_USER_SESSION_RECORD_SET_ALL	"HMSET UID:%lu cid %lu sid %d uid %b profile_key %b when %lu haddress %s baseloc %s status 1 when_serviced %lu when_suspended %lu when_resumed %lu uname %s cookie %s geogroup %d events_counter %lu nickname %s geofid_current %lu geofid_past %lu location_byu %s location_bys %s home_baseloc %s avatar %s guardian_uid %lu"

//#define REDIS_CMD_FULL_USER_SESSION_RECORD_GET	"HVALS UID:%lu"
//keep fields indexed inline with enum REDIS_UID_FIELDS
#define REDIS_CMD_USER_SESSION_RECORD_GET_ALL	"HMGET UID:%lu sid cid status uid uname profile_key haddress baseloc when when_serviced when_suspended when_resumed cookie geogroup events_counter nickname geofid_current geofid_past location_byu location_bys home_baseloc avatar guardian_uid"

#define REDIS_CMD_USER_SESSION_RECORD_DEL_ALL "DEL UID:%lu"

#define REDIS_CMD_USER_SESSION_SERVICE_TIMING_GET	"HMGET UID:%lu uid status when_serviced when_suspended"

#define REDIS_CMD_USER_GET_UFSRVUID	"HMGET UID:%lu uid"
#define REDIS_CMD_USER_SESSION_UFSRVUID_SET "HSET UID:%lu uid %b"

#define REDIS_CMD_USER_SESSION_STATUS_SET "HSET UID:%lu status %d"
#define REDIS_CMD_USER_SESSION_STATUS_SUSPEND "HMSET UID:%lu status 2 when_suspended %lu"
#define REDIS_CMD_USER_SESSION_PROFILE_KEY_SET "HSET UID:%lu profile_key %b"
#define REDIS_CMD_SESSION_PUBLISH_MSG "PUBLISH UFSRV:SESSION %s"

//%scookie %cid. Setting the same key again will override with new value cid:uid
#define REDIS_CMD_COOKIE_SESSION_SET "SET COOKIE:%s %lu:%lu"


//HSET USERNAME_TO_USERID <username> <userid>
#define REDIS_CMD_USERNAME_UID_SET "HSET USERNAME_TO_USERID %s %lu"
//#define REDIS_CMD_USERNAME_UID_DEL "HDEL USERNAME_TO_USERID %s"

//#define REDIS_CMD_USERNAME_USERID_MAPPING_SET "HSET USERNAME_TO_USERID %s %lu"
#define REDIS_CMD_USERNAME_USERID_MAPPING_GET "HGET USERNAME_TO_USERID %s"
#define REDIS_CMD_USERNAME_USERID_MAPPING_DEL "HDEL USERNAME_TO_USERID %s"

#define REDIS_CMD_COOKIE_SESSION_GET "GET COOKIE:%s"

#define REDIS_CMD_COOKIE_SESSION_DEL "DEL COOKIE:%s"

#define REDIS_CMD_SESSION_INC_EVENT_COUNTER	"HINCRBY UID:%lu events_counter 1"
#define REDIS_CMD_SESSION_EVENT_COUNTER_GET	"HGET BID:%lu events_counter"

//geo fences
#define REDIS_CMD_USER_GEOFIDS_GET	"HMGET UID:%lu geofid_current geofid_past"
#define REDIS_CMD_USER_GEOFIDS_SET "HMSET UID:%lu geofid_current %lu geofid_past %lu"

//GEOHASH <%long> <%lat> <%uid>:<0>: last colon is empty placeholder
//
#define REDIS_CMD_USER_GEOHASH_ADD "GEOADD USERS_GEO %f %f %lu:%d:"

#define REDIS_CMD_USER_LOCATION_SET	"HMSET UID:%lu %s %s"
//-------------


//<uid> <bitoffset:[0...n>0]> <value:0|1>
//in redis offset 0 starts at the right most end
//refere to enum UserPrefsOffsets "user_type.h", which provides user-friendly name inline with actual offsets
//also, refer to macro SESSION_USERPREF_ONOFF(x, y, z)
#define REDIS_CMD_USERPREF_ONOFF 			"SETBIT USER_PREFS_ONOFF:%lu %d %d"
#define REDIS_CMD_USERPREF_ONOFF_ON 	"SETBIT USER_PREFS_ONOFF:%lu %d 1"
#define REDIS_CMD_USERPREF_ONOFF_OFF 	"SETBIT USER_PREFS_ONOFF:%lu %d 0"
#define REDIS_CMD_USERPREF_ONOFF_GET 	"GETBIT USER_PREFS_ONOFF:%lu %d"
#define REDIS_CMD_USERPREF_GETALL			"GETRANGE USER_PREFS_ONOFF:%lu 0 -1"
#define REDIS_CMD_USERPREF_REMALL			"DEL USER_PREFS_ONOFF:%lu"
#define REDIS_CMD_USERPREF_GETRANGE		"GETRANGE USER_PREFS_ONOFF:%lu %d %d"
//<uid> <byte-offset> <vlue>
#define REDIS_CMD_USERPREF_SETRANGE		"SETRANGE USER_PREFS_ONOFF:%lu %d %s"

enum {//protocol types
  PROTO_TYPE_WEBSOCKET=0, PROTO_TYPE_RAW
};

#define SOFT_SUSPENSE 0
#define HARD_SUSPENSE 1

inline static Session *
SessionOffInstanceHolder(InstanceHolderForSession *instance_holder_ptr) {
  return (Session *)GetInstance(instance_holder_ptr);
}

Session *GetUfsrvSystemUser (void);
Session * CloneUfsrvSystemUser (InstanceHolderForSession *instance_sesn_ptr_out, unsigned long sesn_call_flags);
void ResetClonedUfsrvSystemUser (Session *sesn_ptr, unsigned long sesn_call_flags);
void *FetchRecycledObject(void);

unsigned long GenerateSessionId (void);
unsigned long GenerateSessionIdLocally (void);
Session *SessionGet (int protocol_id, unsigned call_flas);
int CreateSessionsDelegatorThread (void);
Session *InstantiateSession (Socket *, Socket *, unsigned, int protocol_type);
int InstantiateSession2 (Session **sesn_ptr_in, unsigned long call_flags, int protocol_id);
InstanceHolderForSession *InstantiateCarrierSession (InstanceHolderForSession *sesn_ptr_out, enum WorkerType worker, unsigned long);
int SuspendSession (InstanceHolderForSession *, unsigned);
UFSRVResult *InstateUnconnectedSession (InstanceHolderForSession *sesn_ptr_connected, InstanceHolderForSession *sesn_ptr_unconnected, unsigned long sesn_call_flags);
UFSRVResult *HandleSessionReturnHandshake (InstanceHolderForSession *instance_sesn_ptr_backend, SocketMessage *sock_msg_ptr, unsigned long sesn_call_flags);

UfsrvUid *GetUfsrvUid(Session *sesn_ptr, unsigned long user_id, UfsrvUid *uid_ptr_out, bool flag_by_ref, bool *flag_is_local);
InstanceHolderForSession *LocallyLocateSessionByUserId(unsigned long user_id);
InstanceHolderForSession *LocallyLocateSessionByUfsrvUid (const UfsrvUid *ui_ptr);
InstanceHolderForSession *LocallyLocateSessionByUsername(const char *username);
InstanceHolderForSession *LocallyLocateSessionById(unsigned long);
void DestructSocketMessage (SocketMessage *sock_msg_ptr);

int CheckSessionIdleTime (void *);
bool IsCheckSessionIdelTimeRunning ();

UFSRVResult *GetSessionForThisUser (Session *sesn_ptr, const char *username, bool *lock_state, unsigned long call_flags);
UFSRVResult *GetSessionForThisUserByUserId (Session *sesn_ptr, unsigned long uid, bool *lock_state, unsigned long call_flags);
InstanceHolderForSession *SessionInstantiateFromBackend (Session *sesn_ptr_this, unsigned long user_id, unsigned long call_flags);
UFSRVResult *CacheBackendGetRawSessionRecordByCookie(const char *session_cookie, unsigned long call_flags);
InstanceHolderForSession *CacheBackendInstantiateRawSessionRecord(Session *sesn_ptr_this, redisReply *redis_ptr, unsigned long sesn_call_flags, InstanceHolderForSession *instance_sesn_ptr_out);
InstanceHolder *SessionLightlyInstantiateFromBackendRaw (Session *sesn_ptr_this, InstanceHolder *, redisReply *redis_ptr, unsigned long sesn_call_flags);
Session *InstantiateFromBackendRaw (Session *sesn_ptr_this, Session *sesn_ptr_in, redisReply *redis_ptr, unsigned long sesn_call_flags);
UFSRVResult *CacheBackendGetRawSessionRecord(unsigned long user_id, unsigned long call_flags, UFSRVResult *res_ptr_in);
UfsrvUid *CacheBackendGetUfsrvUid (Session *sesn_ptr_this, unsigned long user_id, unsigned long sesn_call_flags, UfsrvUid *uid_ptr_out);

UFSRVResult *IsSessionLocalAndCompareStatus (unsigned long session_id, unsigned status, unsigned unlock_flag, UFSRVResult *res_ptr);
UFSRVResult *AuthenticateForNonCookieHashedSession (InstanceHolderForSession *instance_sesn_ptr);
UFSRVResult *AuthenticateForBackendCookieHashedSession (InstanceHolderForSession *sesn_ptr, UFSRVResult *res_ptr, SocketMessage *sock_msg_ptr);
UFSRVResult *AuthenticateForCookieHashedSession (InstanceHolderForSession *instance_sesn_ptr_transient, InstanceHolderForSession *instance_sesn_ptr_hashed, SocketMessage *sock_msg_ptr);
void TransferBasicSessionDbBackendData (Session *sesn_ptr, AuthenticatedAccount *authacct_ptr);
void LoadSessionWorkerAccessContext (Session *sesn_ptr);
void TransferBasicSessionDbBackendDataFromSession (Session *sesn_ptr_target, Session *sesn_ptr_source);
int ClearLocalSessionCache (InstanceHolderForSession *instance_sesn_ptr_target, unsigned long sesn_call_flags);
void ResetSessionData (InstanceHolderForSession *instance_sesn_ptr_target);
UFSRVResult *RefreshBackendCacheForSession (Session *sesn_ptr, const char *old_cookie, unsigned long sesn_call_flags);
UFSRVResult *CacheBackendUpdateCookie (Session *sesn_ptr, const char *old_cookie);
int SessionReturnToRecycler (InstanceHolderForSession *instance_sesn_ptr, ContextData *ctx_data_ptr, unsigned long call_falgs);
size_t SessionGetReferenceCount (InstanceHolderForSession *instance_sesn_ptr);
void SessionIncrementReference (InstanceHolderForSession *instance_sesn_ptr, int multiples);
void SessionDecrementReference (InstanceHolderForSession *instance_sesn_ptr, int multiples);
void SessionDecrementReferenceByOne (InstanceHolderForSession *instance_sesn_ptr);
void SessionIncrementReferenceByOne (InstanceHolderForSession *instance_sesn_ptr);
void InitSessionRecyclerTypePool ();
unsigned SessionPoolTypeNumber();

int SessionLoadEphemeralMode (Session *sesn_ptr);
int SessionUnLoadEphemeralMode (Session *sesn_ptr);
int SessionLoadEphemeralModeWithDescriptor (Session *sesn_ptr, EphemeralModeDescription *);
void ThreadContextTransferAccessContextForSession (Session *sesn_ptr);
void ThreadContextResetAccessContextForSession (Session *sesn_ptr);

UFSRVResult *RegisterUfsrvEvent (Session *sesn_ptr, EnumEventType event_type, unsigned event_instance_type, void *event_payload, UfsrvEvent *event_ptr_out);

HttpRequestContext *GetHttpRequestContext(Session *sesn_ptr);
HttpRequestContext *GetHttpRequestContextUfsrvWorker(Session *sesn_ptr);

ScheduledJobType *GetScheduledJobTypeForSessionTimeout (void);
ScheduledJob *GetScheduledJobForSessionTimeout (void);

  static inline bool
  IsSessionConnected (Session *sesn_ptr, time_t time_now)
  {
    return ((SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_CONNECTED)) && (time_now-sesn_ptr->when_serviced_end>_CONFIGDEFAULT_IDLETIME_THRESHOLD));
  }

  /**
  * 	@brief: Load session context for a given carrier source:
  * 	if session is present use that, otherwise load from ufsrvworker, but only if the flag is set, to trap corruption
  */
  static inline void
  SessionTransferAccessContext (Session *sesn_ptr_source, Session *sesn_ptr_target, bool flag_ufsrvworker)
  {
    if (IS_PRESENT(sesn_ptr_source)) {
      sesn_ptr_target->thread_ctx_ptr						=	sesn_ptr_source->thread_ctx_ptr;
      sesn_ptr_target->instrumentation_backend	=	sesn_ptr_source->instrumentation_backend;
      sesn_ptr_target->persistance_backend			=	sesn_ptr_source->persistance_backend;
      sesn_ptr_target->msgqueue_backend					=	sesn_ptr_source->msgqueue_backend;
      sesn_ptr_target->db_backend								=	sesn_ptr_source->db_backend;
      sesn_ptr_target->usrmsg_cachebackend			=	sesn_ptr_source->usrmsg_cachebackend;
      sesn_ptr_target->fence_cachebackend				=	sesn_ptr_source->fence_cachebackend;
    } else	if (flag_ufsrvworker) {
      SessionLoadEphemeralMode (sesn_ptr_target);
    } else {
      syslog(LOG_ERR, "%s {pid:'%lu'}: ERROR COULD NOT FIND CARRIER FOR ACCESS CONTEXT", __func__, pthread_self());
    }
  }

  static inline void
  SessionResetTransferAccessContext (Session *sesn_ptr_from)
  {
    sesn_ptr_from->thread_ctx_ptr						=	NULL;
    sesn_ptr_from->persistance_backend			=	NULL;
    sesn_ptr_from->instrumentation_backend	=	NULL;
    sesn_ptr_from->db_backend								=	NULL;
    sesn_ptr_from->msgqueue_backend					=	NULL;
    sesn_ptr_from->usrmsg_cachebackend			=	NULL;
    sesn_ptr_from->fence_cachebackend				=	NULL;
  }

  /* @return: the state is returned on the thread's own UFSRvresul*/
  static inline UFSRVResult *
  SessionLockRDCtx (ThreadContext *thread_ctx_ptr, Session *sesn_ptr, int try_flag)
  {
    int lock_state;
    UFSRVResult *res_ptr;

    if (likely(IS_PRESENT(thread_ctx_ptr))) {
      res_ptr = thread_ctx_ptr->res_ptr;

      if (IsObjectInLockedObjectsStore(thread_ctx_ptr->ht_ptr, sesn_ptr)) {
        lock_state = 0;
        syslog(LOG_DEBUG, "%s {pid:'%lu', cid:'%lu', o:'%p, ctx:'%p', try:'%i'}: NOTICE: NOT LOCKING: ALREADY IN STORE", __func__, pthread_self(), SESSION_ID(sesn_ptr), sesn_ptr, IS_PRESENT(thread_ctx_ptr)?thread_ctx_ptr:0, try_flag);
        goto return_already_locked_by_this_thread;
      }
    } else res_ptr = SESSION_RESULT_PTR(sesn_ptr);

    if (try_flag) {
      lock_state = pthread_rwlock_tryrdlock(&(sesn_ptr->session_events.rwlock));
      if (lock_state == 0) {
        syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu', o:'%p', ctx:'%p', lock:50:1 ): SUCCESS: TRY-READ lock for Session events acquired...", __func__, pthread_self(), SESSION_ID(sesn_ptr), sesn_ptr, IS_PRESENT(thread_ctx_ptr)?thread_ctx_ptr:0);
        if (IS_PRESENT(thread_ctx_ptr)) PutIntoLockedObjectsStore (thread_ctx_ptr->ht_ptr, (void *)sesn_ptr);
        goto return_locked;
      } else {
        char *err_str = thread_error(errno);
        syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu', o:'%p', ctx:'%p'): ERROR: COULD NOT acquire TRY-READ lock for Session events (errno='%d'):  '%s'", __func__, pthread_self(), SESSION_ID(sesn_ptr), sesn_ptr, IS_PRESENT(thread_ctx_ptr)?thread_ctx_ptr:0, errno, err_str);free(err_str);
      }
    } else {
      lock_state = pthread_rwlock_rdlock(&(sesn_ptr->session_events.rwlock));
      if (lock_state == 0) {
        syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu', o:'%p, ctx:'%p', lock:50:1 ): SUCCESS: READ lock for Session events acquired...", __func__, pthread_self(), SESSION_ID(sesn_ptr), sesn_ptr, IS_PRESENT(thread_ctx_ptr)?thread_ctx_ptr:0);
        if (likely(IS_PRESENT(thread_ctx_ptr))) PutIntoLockedObjectsStore (thread_ctx_ptr->ht_ptr, (void *)sesn_ptr);
        goto return_locked;
      } else {
        char *err_str = thread_error(errno);
        syslog(LOG_DEBUG, "%s (pid='%lu' cid='%lu' o='%p): ERROR: COULD NOT acquire READ lock for Session events (errno='%d'):  '%s'", __func__, pthread_self(), SESSION_ID(sesn_ptr), sesn_ptr, errno, err_str);free(err_str);
      }
    }

    return_wont_lock:
    _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_WONTLOCK)

    return_locked:
    _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_LOCKED)

    return_already_locked_by_this_thread:
    _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_LOCKED_BY_THIS_THREAD)

  }

  static inline UFSRVResult *
  SessionLockRWCtx (ThreadContext *thread_ctx_ptr, Session *sesn_ptr, int try_flag, const char *func)
  {
    int lock_state;
    UFSRVResult *res_ptr;

    if (likely(IS_PRESENT(thread_ctx_ptr))) {
      res_ptr = thread_ctx_ptr->res_ptr;

      if (IsObjectInLockedObjectsStore(thread_ctx_ptr->ht_ptr, sesn_ptr)) {
        lock_state = 0;
        syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu', o:'%p, ctx:'%p', try:'%i', func:'%s'): NOTICE: NOT LOCKING: ALREADY IN STORE", __func__, pthread_self(), SESSION_ID(sesn_ptr), sesn_ptr, thread_ctx_ptr, try_flag, func);
        goto return_already_locked_by_this_thread;
      }
    } else res_ptr = SESSION_RESULT_PTR(sesn_ptr);

    if (try_flag) {
      lock_state = pthread_rwlock_trywrlock(&(sesn_ptr->session_events.rwlock));
      if (lock_state == 0) {
  #ifdef __UF_FULLDEBUG
        syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu' o:'%p', ctx:'%p', try:1, func:'%s'): SUCCESS: TRY-WRITE/READ lock for Session events acquired...", __func__, pthread_self(), SESSION_ID(sesn_ptr), sesn_ptr, IS_PRESENT(thread_ctx_ptr)?thread_ctx_ptr:0, func);
  #endif
        if (likely(IS_PRESENT(thread_ctx_ptr))) PutIntoLockedObjectsStore (thread_ctx_ptr->ht_ptr, (void *)sesn_ptr);

        goto return_locked;
      } else {
        char *err_str=thread_error_wrlock(errno);
        syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu', o:'%p', ctx:'%p', try:1, func:'%s'): ERROR: COULD NOT acquire TRY-WRITE/READ lock for Session events (errno='%d'): '%s'", __func__, pthread_self(), SESSION_ID(sesn_ptr), sesn_ptr, IS_PRESENT(thread_ctx_ptr)?thread_ctx_ptr:0, func, errno, err_str); free(err_str);
      }
    } else {
      lock_state = pthread_rwlock_wrlock(&(sesn_ptr->session_events.rwlock));
      if (lock_state == 0) {
  #ifdef __UF_FULLDEBUG
        syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu', o:'%p', ctx:'%p', func:'%s'): SUCCESS: WRITE/READ lock for Session events acquired...", __func__, pthread_self(), SESSION_ID(sesn_ptr), sesn_ptr, IS_PRESENT(thread_ctx_ptr)?thread_ctx_ptr:0, func);
  #endif
        if (IS_PRESENT(thread_ctx_ptr)) PutIntoLockedObjectsStore (thread_ctx_ptr->ht_ptr, (void *)sesn_ptr);

        goto return_locked;
      } else {
        char *err_str = thread_error_wrlock(errno);
        syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu', o:'%p', ctx:'%p', func:'%s'): ERROR: COULD NOT acquire WRITE/READ lock for Session events (errno='%d'): '%s'",
            __func__, pthread_self(), SESSION_ID(sesn_ptr), sesn_ptr, IS_PRESENT(thread_ctx_ptr)?thread_ctx_ptr:0, func, errno, err_str); free(err_str);
      }
  }

  return_wont_lock:
  _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_WONTLOCK)

  return_locked:
  _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_LOCKED)

  return_already_locked_by_this_thread:
  _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_LOCKED_BY_THIS_THREAD)

  }

  static inline UFSRVResult *
  SessionUnLockCtx (ThreadContext *thread_ctx_ptr, Session *sesn_ptr, const char *func)
  {
     UFSRVResult *res_ptr;

    if (IS_PRESENT(thread_ctx_ptr)) res_ptr = thread_ctx_ptr->res_ptr;
    else 														res_ptr = SESSION_RESULT_PTR(sesn_ptr);

    int lock_state = pthread_rwlock_unlock(&(sesn_ptr->session_events.rwlock));
    if (lock_state == 0) {
  #ifdef __UF_FULLDEBUG
      syslog(LOG_DEBUG, "SessionUnLock: (pid:'%lu', cid:'%lu', o:'%p', ctx:'%p', func:'%s): SUCCESS: RELEASED WRITE/READ lock for Session events...", pthread_self(), SESSION_ID(sesn_ptr), sesn_ptr, IS_PRESENT(thread_ctx_ptr)?thread_ctx_ptr:0, func);
  #endif
      if (IS_PRESENT(thread_ctx_ptr)) RemoveFromLockedObjectsStore(thread_ctx_ptr->ht_ptr, (void *)sesn_ptr);
      _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_LOCKED)
    } else {
      char *err_str = thread_error(errno);
      syslog(LOG_DEBUG, "SessionUnLock: (pid:'%lu', cid:'%lu', o:'%p', ctx:'%p', func:'%s'): ERROR: COULD NOT RELEASE WRITE/READ lock for Session events (errno='%d'): '%s'", pthread_self(), SESSION_ID(sesn_ptr), sesn_ptr, IS_PRESENT(thread_ctx_ptr)?thread_ctx_ptr:0, func, errno, err_str); free(err_str);
    }

    _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_WONTLOCK)

  }

//----------------------------

  static  inline int MessageQueueLock (Session *sesn_ptr, MessageQueue *msg_que_ptr, int try_flag)
  {
    int lock_state;

    if (try_flag) {
      lock_state = pthread_mutex_trylock(&(msg_que_ptr->mutex));

      if (lock_state == 0) {
  #ifdef __UF_FULLDEBUG
        syslog(LOG_DEBUG, "%s: {pid'%lu', th_ctx:'%lu', cid:'%lu'  o:'%p'}: SUCCESS: MUTEX TRY-LOCK for MessageQueue events acquired...", __func__, pthread_self(), THREAD_CONTEXT_PTR, SESSION_ID(sesn_ptr), sesn_ptr);
  #endif
      } else {
        char *err_str = thread_error(errno);
        syslog(LOG_DEBUG, "%s: {pid'%lu', th_ctx:'%lu', cid:'%lu'  o:'%p'}: ERROR: COULD NOT acquire MUTEX lock for MessageQueue (errno='%d'):  '%s'", __func__, pthread_self(), 0UL, SESSION_ID(sesn_ptr), sesn_ptr, errno, err_str); free(err_str);
      }
    } else {
      lock_state = pthread_mutex_lock(&(msg_que_ptr->mutex));
      if (lock_state == 0) {
  #ifdef __UF_FULLDEBUG
        syslog(LOG_DEBUG, "%s: {pid'%lu', th_ctx:'%lu', cid:'%lu'  o:'%p'}: SUCCESS:  MUTEX lock for MessageQueue acquired...", __func__, pthread_self(), THREAD_CONTEXT_PTR, SESSION_ID(sesn_ptr), sesn_ptr);
  #endif
      } else {
        char *err_str = thread_error(errno);
        syslog(LOG_DEBUG, "%s: {pid'%lu', th_ctx:'%lu', cid:'%lu'  o:'%p'}: ERROR: COULD NOT acquire MUTEX lock for MessageQueue (errno='%d'): '%s'", __func__, pthread_self(), 0UL, SESSION_ID(sesn_ptr), sesn_ptr, errno, err_str); free(err_str);
      }
    }

    return lock_state;

  }

  static inline int MessageQueueUnLock (Session *sesn_ptr, MessageQueue *msg_que_ptr)
  {
    int lock_state = pthread_mutex_unlock(&(msg_que_ptr->mutex));
    if (lock_state == 0) {
  #ifdef __UF_FULLDEBUG
      syslog(LOG_DEBUG, "%s: {pid'%lu', th_ctx:'%lu', cid:'%lu'  o:'%p'}: SUCCESS: RELEASED MUTEX lock for MessageQueue...", __func__, pthread_self(), THREAD_CONTEXT_PTR, SESSION_ID(sesn_ptr), sesn_ptr);
  #endif
    } else {
      char *err_str = thread_error(errno);
      syslog(LOG_DEBUG, "%s: {pid'%lu', th_ctx:'%lu', cid:'%lu', o:'%p'}: ERROR: COULD NOT RELEASE MUTEX lock for MessageQueue (errno='%d'):  '%s'", __func__, pthread_self(), 0UL, SESSION_ID(sesn_ptr), sesn_ptr, errno, err_str); free(err_str);
    }

    return lock_state;

  }

  static inline bool IsSessionListInitialisedFences (Session *sesn_ptr) {
    return SESSION_LISTS_INIT_STATE_FENCES(sesn_ptr);
  }

  static inline bool IsSessionListInitialisedProfile(Session *sesn_ptr) {
    return SESSION_LISTS_INIT_STATE_PROFILE(sesn_ptr);
  }

  static inline bool IsSessionListInitialisedLocation (Session *sesn_ptr) {
    return SESSION_LISTS_INIT_STATE_LOCATION(sesn_ptr);
  }

  static inline bool IsSessionListInitialisedNetstate (Session *sesn_ptr) {
    return SESSION_LISTS_INIT_STATE_NETSTATE(sesn_ptr);
  }

  static inline bool IsSessionListInitialisedContacts (Session *sesn_ptr) {
    return SESSION_LISTS_INIT_STATE_CONTACTS(sesn_ptr);
  }

#endif