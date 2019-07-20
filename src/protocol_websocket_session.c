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
#include <net.h>
#include <recycler_type.h>
#include <session.h>
#include <session_service.h>
#include <session_broadcast.h>
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
#include <protocol_websocket_session.h>
#include <ufsrvuid.h>

extern ufsrv *const							 	masterptr;
extern SessionsDelegator *const 	sessions_delegator_ptr;
extern __thread ThreadContext ufsrv_thread_context;


/**
 * 	@brief: Clear the cache associated with an invalid userid. No network-wide broadcast is performed
 * 	because of the invalidity of theSession.
 *
 *	@param sesn_ptr_carrier: just a carrier Session not target for operation
 *	@param sesn_ptr_invalid: session containin the target invalid uid
 */
UFSRVResult *
ClearBackendCacheForInvalidUserId (Session *sesn_ptr_carrier, Session *sesn_ptr_invalid, Fence *f_ptr, unsigned long call_flags)
{
	size_t				actually_processed=0;
	PersistanceBackend	*pers_ptr=NULL;

	pers_ptr=sesn_ptr_carrier->persistance_backend;

	(*pers_ptr->send_command_multi)(sesn_ptr_carrier, "MULTI");

	(*pers_ptr->send_command_multi)(sesn_ptr_carrier,  REDIS_CMD_COOKIE_SESSION_DEL, SESSION_COOKIE(sesn_ptr_invalid));

	(*pers_ptr->send_command_multi)(sesn_ptr_carrier, REDIS_CMD_USERNAME_USERID_MAPPING_DEL, SESSION_USERNAME(sesn_ptr_invalid));

	(*pers_ptr->send_command_multi)(sesn_ptr_carrier, REDIS_CMD_USER_SESSION_RECORD_DEL_ALL, SESSION_USERID(sesn_ptr_invalid));

	(*pers_ptr->send_command_multi)(sesn_ptr_carrier, REDIS_CMD_USER_FENCE_LIST_REM_ALL, SESSION_USERID(sesn_ptr_invalid));

	(*pers_ptr->send_command_multi)(sesn_ptr_carrier, REDIS_CMD_NICKNAMES_DIRECTORY_DEL, SESSION_USERNICKNAME(sesn_ptr_invalid)?SESSION_USERNICKNAME(sesn_ptr_invalid):"");

	(*pers_ptr->send_command_multi)(sesn_ptr_carrier, REDIS_CMD_FENCE_USERS_LIST_REM, FENCE_ID(f_ptr), SESSION_USERID(sesn_ptr_invalid));

	(*pers_ptr->send_command_multi)(sesn_ptr_carrier, REDIS_CMD_INVITED_USERS_FOR_FERNCE_REM, FENCE_ID(f_ptr), SESSION_USERID(sesn_ptr_invalid));

	//TODO: THIS NEEDS INVITED BY value. currently set to 0. this command will fail
	(*pers_ptr->send_command_multi)(sesn_ptr_carrier, REDIS_CMD_INVITED_FENCES_FOR_USER_REM, SESSION_USERID(sesn_ptr_invalid), FENCE_ID(f_ptr), 0);

	(*pers_ptr->send_command_multi)(sesn_ptr_carrier, REDIS_CMD_MY_FENCE_INVITED_USERS_REM_ALL, SESSION_USERID(sesn_ptr_invalid));

	//TODO: ADD preferences to cleard UID
	(*pers_ptr->send_command_multi)(sesn_ptr_carrier, "EXEC");
	actually_processed = 11;

	size_t 		i;
	redisReply	*replies[actually_processed];

	//TODO: we need error recover for intermediate errors
	for (i=0; i<actually_processed; i++) {
		if ((RedisGetReply(sesn_ptr_carrier, pers_ptr, (void*)&replies[i]) != REDIS_OK)) {
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', cmd_idx:'%lu', uid_invalid:'%lu'}: ERROR: REDIS COMMAND IN MULTI SET FAILED", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), i, SESSION_USERID(sesn_ptr_invalid));

			if ((replies[i] != NULL) && (replies[i]->type != REDIS_REPLY_NIL)) {
				//syslog (LOG_DEBUG, LOGSTR_BACKENDCACHE_SHARED_CONTACTS, __func__, SESSION_PID(sesn_ptr), sesn_ptr, i, replies[i]->str, LOGCODE_BACKENDCACHE_SHARED_CONTACTS_HIT, "Found shared contact token");
			}
		}

		if (!IS_EMPTY(replies[i]))	freeReplyObject(replies[i]);
	}//for

	_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)

}

/**
 * 	@brief: This is a referenced userid, but for which there is no valid userbackend record, so no Session container
 * 	could be built for it
 *
 */
UFSRVResult *
ClearBackendCacheForSessionlessInvalidUserId (Session *sesn_ptr_carrier, unsigned long userid, unsigned long sesn_call_flags, unsigned long fence_call_flags)
{
	//check _ClearInvalidUserId, which RELIES ON STATUS BEING SET TO 0
	//check ClearBackendCacheForInvalidUserId
	if (!IsUserCloudRegistered (sesn_ptr_carrier, GetHttpRequestContext(sesn_ptr_carrier)))
	{
		//check cache backend for cookie based on uid and check if cookie can be signed on -> user may have unregistered but they are coming back. Also check for freshness
		//get all fences ->remove reciprocally
		//get all invited fences ->remove reciprocally
		//duplicate some of the del operations from ClearBackendCacheForInvalidUserId()
	}

	_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);
}

/**
 * 	@brief: Invalidating a session is a terminal action, whereby a session is withdrawn from the system and all associated fences
 * 	are disengaged. The Session could be in any mode: remote, connected etc...
 * 	We propagate the event to all fences accordingly  for which we hold connected sessions
 *
 * 	@locked sesn_ptr: by the caller environment
 * 	@unlocks sesn_ptr: as we are in the process of destorying the Session, we ough to unlock it
 *
 */
#if 0
inline static UFSRVResult *
_InvalidateLocalSessionReference (Session sesn_ptr, unsigned long call_flags)
{

	time_t time_now=time(NULL);

	ListEntry *eptr;
	for (eptr=SESSION_FENCE_LIST(sesn_ptr).head; eptr; eptr=eptr->next)
	{
		FenceStateDescriptor *fence_state_descriptor_ptr=(FenceStateDescriptor *)eptr->whatever;
		//FENCESTATE_FENCE(fence_state_descriptor);
		if (IsSessionConnected(sesn_ptr_aux, time_now))
		{

		}
	}
}
#endif

/**
 * 	@brief: entry point into session invalidation based on Intra SessionMessage, specifying a collection of fences affected
 * 	Upon successfull processing sesn_ptr will be sent to recycler. When processing through this proto, we'd be responding to a
 * 	an IntraMessage. In this instance the api backend will have taken care of invalidating the backend cache for this Session.
 * 	So we purely perform local invalidation.
 *
 * 	@sesn_ptr: Session loaded in ephemeral mode. Could be connected or remote.
 *	@access_context: lready loaded emphemeral
 *	@locking: sesn_ptr and fences must be locked
 * 	@locked sesn_ptr: by the caller
 * 	@locks f_ptr: each retrieved Fence is locked whilst being operated on
 * 	@unlocks f_ptr: each retrieved Fence that was previously locked whilst being operated on gets unlockd
 *
 * 	@worker: UfsrvWorker
 */
UFSRVResult *
InvalidateLocalSessionReferenceFromProto (InstanceHolderForSession *instance_sesn_ptr, MessageQueueMessage *mqm_ptr, unsigned long call_flags)
{
	time_t 			time_now		= time(NULL);
	SessionMessage	*session_msg	= mqm_ptr->session;
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', fences_sz:'%lu'}: Invalidating Session",__func__, pthread_self(), sesn_ptr, session_msg->n_fences);

	if (session_msg->n_fences > 0) {
		size_t i = 0;
		for (; i<session_msg->n_fences; i++) {
			FindFenceById(sesn_ptr, mqm_ptr->session->fences[i]->fid, 0);
			InstanceHolder *instance_f_ptr_hashed = (InstanceHolder *)SESSION_RESULT_USERDATA(sesn_ptr);
			if (!(IS_EMPTY(instance_f_ptr_hashed))) {
			  Fence *f_ptr_hashed = FenceOffInstanceHolder(instance_f_ptr_hashed);

				FenceEventsLockRWCtx(THREAD_CONTEXT_PTR, f_ptr_hashed, _LOCK_TRY_FLAG_FALSE, SESSION_RESULT_PTR(sesn_ptr), __func__);
				if (SESSION_RESULT_TYPE_EQUAL(sesn_ptr, RESULT_TYPE_ERR)) continue;//lock error: this would indicate broader problem
				bool lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_PROG_LOCKED_THIS_THREAD));

				Fence									*f_ptr_sesn_list	__attribute__((unused));
				InstanceHolderForFenceStateDescriptor *instance_fstate_ptr;

        instance_fstate_ptr = IsUserMemberOfThisFence(&(SESSION_FENCE_LIST(sesn_ptr)), f_ptr_hashed, false/*LOCK_FLAG*/);
				if (IS_EMPTY(instance_fstate_ptr)) {
					syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', fo:'%p', fid:'%lu'}: ERROR: INCONSISTENT FENCE STATE: FENCE NOT FOUND IN SESSION LIST",__func__, pthread_self(), sesn_ptr, f_ptr_hashed, mqm_ptr->session->fences[i]->fid);
					//continue; //we still need to remove the session from Fences list and self-heal
				}

				RemoveUserFromFence (instance_sesn_ptr, f_ptr_hashed, CALL_FLAG_DONT_BROADCAST_FENCE_EVENT);//prevents generation of eid +broadcast
				f_ptr_hashed->fence_events.last_event_id = mqm_ptr->session->fences[i]->eid;
				MarshalFenceStateSyncForLeave (sesn_ptr, sesn_ptr, f_ptr_hashed, NULL, LT_SESSION_INVALIDATED);

				if (!lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr_hashed, SESSION_RESULT_PTR(sesn_ptr));
			} else {
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', fid:'%lu'}: ERROR: INCONSISTENT FENCE STATE: FENCENOT FOUND IN HASH",__func__, pthread_self(), sesn_ptr, mqm_ptr->session->fences[i]->fid);
			}
		}
	} else {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: NOTICE: FENCE LIST WAS EMPTY",__func__, pthread_self(), sesn_ptr);
	}

	if (session_msg->n_fences_invited > 0) {
		size_t i = 0;
		for (; i<session_msg->n_fences_invited; i++) {
			FindFenceById(sesn_ptr, mqm_ptr->session->fences_invited[i]->fid, 0);
      InstanceHolderForFence *instance_f_ptr_hashed = (InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr);

			if (!(IS_EMPTY(instance_f_ptr_hashed))) {
				Fence									*f_ptr_sesn_list __attribute__ ((unused));
//				FenceStateDescriptor	*f_state_ptr;

				Fence *f_ptr_hashed = FenceOffInstanceHolder(instance_f_ptr_hashed);

				FenceEventsLockRWCtx(THREAD_CONTEXT_PTR, f_ptr_hashed, _LOCK_TRY_FLAG_FALSE, SESSION_RESULT_PTR(sesn_ptr), __func__);
				bool lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_PROG_LOCKED_THIS_THREAD));

				if (SESSION_RESULT_TYPE_EQUAL(sesn_ptr, RESULT_TYPE_ERR)) continue; //lock error: this would indicate broader problem

				InstanceHolderForFenceStateDescriptor *instance_fstate_ptr = IsUserMemberOfThisFence(&(SESSION_FENCE_LIST(sesn_ptr)), f_ptr_hashed, 0);
				if (IS_EMPTY(instance_fstate_ptr)) {
					syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', fo:'%p', fid:'%lu'}: ERROR: INCONSISTENT INVITED FENCE STATE: FENCE NOT FOUND IN SESSION LIST",__func__, pthread_self(), sesn_ptr, f_ptr_hashed, mqm_ptr->session->fences_invited[i]->fid);
					//continue; //we still need to remove the session from Fences list and selfheal
				}

				RemoveUserFromFence (instance_sesn_ptr, f_ptr_hashed, CALL_FLAG_DONT_BROADCAST_FENCE_EVENT);//prevents generation of eid +broadcast
				f_ptr_hashed->fence_events.last_event_id = mqm_ptr->session->fences_invited[i]->eid;
				MarshalFenceStateSyncForLeave (sesn_ptr, sesn_ptr, f_ptr_hashed, NULL, 0);

				if (!lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr_hashed, SESSION_RESULT_PTR(sesn_ptr));
			} else {
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', fid:'%lu'}: ERROR: INCONSISTENT INVITED FENCE STATE: FENCENOT FOUND IN HASH",__func__, pthread_self(), sesn_ptr, mqm_ptr->session->fences_invited[i]->fid);
			}
		}
	} else {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: NOTICE: INVITE LIST WAS EMPTY",__func__, pthread_self(), sesn_ptr);
	}

	//sesn_ptr already loaded in ephemeral mode with access context no need for CALL_FLAG_TRANSFER_WORKER_ACCESS_CONTEXT
	ClearLocalSessionCache (instance_sesn_ptr, CALL_FLAG_DONT_BROADCAST_FENCE_EVENT|CALL_FLAG_UNLOCK_SESSION);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESULT_CODE_SESN_INVALIDATED)
}

/**
 *	@brief: Main interface point for changing backend data model for geofence join attribute for user.The actual join event has its
 *	andler and broadcast. This only pdates the session attribute that remembers current/past geo fence
 */
UFSRVResult *
UpdateBackendSessionGeoJoinData (Session *sesn_ptr, Fence *f_ptr_current, Fence *f_ptr_past)
{
	int 								rescode = RESCODE_PROG_NULL_POINTER;
	PersistanceBackend 	*pers_ptr;
	redisReply 					*redis_ptr = NULL;

  pers_ptr = sesn_ptr->persistance_backend;

  if (!(redis_ptr = (*pers_ptr->send_command)(sesn_ptr, REDIS_CMD_USER_GEOFIDS_SET, SESSION_USERID(sesn_ptr), IS_PRESENT(f_ptr_current)?FENCE_ID(f_ptr_current):0, IS_PRESENT(f_ptr_past)?FENCE_ID(f_ptr_past):0)))	goto return_redis_error;

  if (redis_ptr->type == REDIS_REPLY_ERROR)	goto return_redis_error;

  return	(InterBroadcastSessionGeoFenced(sesn_ptr,
                                          (ClientContextData *)(&((ContextDataPair){.first=f_ptr_current, .second=f_ptr_past})),
                                          &((FenceEvent) {.eid=0, .when=time(NULL)}),
                                          COMMAND_ARGS__UPDATED));

  return_redis_error:
  if (IS_EMPTY(redis_ptr)) {
   syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
  }

  if (redis_ptr->type == REDIS_REPLY_ERROR) {
   syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu', fid_current:'%lu', fid_past:'%lu'}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), IS_PRESENT(f_ptr_current)?FENCE_ID(f_ptr_current):0, IS_PRESENT(f_ptr_past)?FENCE_ID(f_ptr_past):0, redis_ptr->str);
   freeReplyObject(redis_ptr);
   rescode = RESCODE_BACKEND_DATA;

   goto return_error;
  }

  return_error:
  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)

}

