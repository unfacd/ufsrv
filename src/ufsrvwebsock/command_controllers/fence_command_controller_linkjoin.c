/**
* Copyright (C) 2015-2025 unfacd works
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

/**
* @file fence_command_controller_linkjoin.c
* @brief Command controller for link joining fences.
 *
 * Link joining a fence via a url link (or QR) has three distinct states:
 * 1) User activating the link generates ADDED command argument
 * 2)Admin approving the join generates ACCEPTED command argument. User still has has to join
 * 3)Admin rejecting the join generated REJECTED command argument.
*/

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include "fence_command_controller.h"
#include <fence_command_controller_linkjoin.h>
#include <include/thread_context_type.h>
#include <ufsrvmsg_core/fence/fence.h>
#include <ufsrvmsg_core/fence/fence_proto.h>
#include <ufsrvmsg_core/fence/fence_permission.h>
#include <ufsrvmsg_core/user/users_protobuf.h>
#include <uflib/recycler/recycler.h>
#include <ufsrvwebsock/include/protocol_websocket.h>
#include <ufsrvmsg_core/SignalService.pb-c.h>
#include <include/command_controllers.h>
#include <uflib/ufsrvuid.h>
#include <ufsrvwebsock/include/ufsrvcmd_user_callbacks.h>
#include <fence_broadcast.h>
#include <broadcast_context_data_fence_linkjoin.h>

#include <ufsrvmsg_core/fence/fence_cachbackend_commands_ literal.h>

extern ufsrv							*const masterptr;
extern __thread ThreadContext ufsrv_thread_context;

typedef struct FenceLinkJoinCommandExecutorContext {
    InstanceContextForSession  *ctx_ptr_originator;
    Envelope  *envelope;
    WebSocketMessage *wsm_ptr_received;
    InstanceHolderForFence *f_ptr_instance;
} FenceLinkJoinCommandExecutorContext;

static InstanceHolderForFence *_GetSessionForOriginator(Session *sesn_ptr_carrier, const UfsrvUid *ufsrv_uid_originator, bool *is_already_locked_session);
static UFSRVResult *_IsUserAllowedToLinkJoinFence(Session *sesn_ptr, unsigned long fid, bool *fence_lock_state, unsigned long fence_call_flags);
static UFSRVResult *_IsUserAllowedToAdminActionLinkJoinFence(Session *sesn_ptr, InstanceHolderForSession *sesn_ptr_originator_instance, unsigned long fid, bool *fence_lock_state, unsigned long fence_call_flags);
static UFSRVResult *_CommandControllerFenceLinkJoinAdded(InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received);
static UFSRVResult *_CommandControllerAdminActionFenceLinkJoin(InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received, int command_arg);
static UFSRVResult * _CacheBackendUpdateFenceLinkJoinAdded(unsigned long user_id, Fence *f_ptr);
static UFSRVResult *_CacheBackendUpdateFenceLinkJoinRemoved(unsigned long user_id, Fence *f_ptr);
static UFSRVResult *_WireMarshalFenceLinkJoinToUser(FenceLinkJoinCommandExecutorContext *ctx_ptr, ClientContextData *ctx_data_ptr);
static UFSRVResult *_MarshalFenceLinkJoinCommand(InstanceContextForSession *ctx_ptr, InstanceContextForSession *ctx_ptr_originator, InstanceHolderForFence *instance_f_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received, int command_arg, unsigned call_flags);

UFSRVResult *
CommandControllerFenceLinkJoin(InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received)
{
  UFSRVResult 					*res_ptr	=	NULL;

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

  switch (data_msg_ptr_received->ufsrvcommand->fencecommand->header->args)
  {
    case COMMAND_ARGS__ADDED://user requesting to join (via a link)
      res_ptr = _CommandControllerFenceLinkJoinAdded(instance_sesn_ptr, wsm_ptr_received, data_msg_ptr_received);
      break;

    case COMMAND_ARGS__ACCEPTED://admin accepted link join request
      res_ptr = _CommandControllerAdminActionFenceLinkJoin(instance_sesn_ptr, wsm_ptr_received, data_msg_ptr_received, COMMAND_ARGS__ACCEPTED);
      break;

    case COMMAND_ARGS__REJECTED://admin rejected link join request
      res_ptr = _CommandControllerAdminActionFenceLinkJoin(instance_sesn_ptr, wsm_ptr_received, data_msg_ptr_received, COMMAND_ARGS__REJECTED);
      break;

    default:
      syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', arg:'%d'}: ERROR: UNKNOWN FENCE LINK_JOIN COMMAND ARG...", __func__, pthread_self(), sesn_ptr, data_msg_ptr_received->ufsrvcommand->fencecommand->header->args);
  }

  exit_final:
  if (IS_EMPTY(res_ptr))	goto exit_catch_all; //this catches the default case
  return res_ptr;

  exit_catch_all:
  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

/**
 * @brief Instantiate a session object for user.
 * @param sesn_ptr_carrier carrier session for access to some context data (to be phased out, relying only on thread context)
 * @param ufsrv_uid_originator Identifying \ref UfsrvUid for user
 * @param is_already_locked_session flag to manage lock state for session
 * @return \ref InstanceHolderForSession *
 */
static InstanceHolderForFence *
_GetSessionForOriginator(Session *sesn_ptr_carrier, const UfsrvUid *ufsrv_uid_originator, bool *is_already_locked_session)
{
  unsigned long sesn_call_flags	=	(CALL_FLAG_LOCK_SESSION|CALL_FLAG_LOCK_SESSION_BLOCKING|
                                     CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY| CALL_FLAG_HASH_USERNAME_LOCALLY|
                                     CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION|CALL_FLAG_REMOTE_SESSION);

  unsigned long user_id_originator = UfsrvUidGetSequenceId(ufsrv_uid_originator);
  GetSessionForThisUserByUserId(sesn_ptr_carrier, user_id_originator, is_already_locked_session, sesn_call_flags);
  return (InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr_carrier);
}

/**
 * 	@brief Check if user has the permissions to request a fence link-join.
 * 	@param sesn_ptr The user who issued the request
 * 	@originator The user who issued the request
 * 	@locked sesn_ptr: by caller
 * 	@locks f_ptr: by downstream functions and remains locked after this function exists if FENCE_CALLFLAG_KEEP_FENCE_LOCKED is set
 * 	@return \ref InstanceHolderForFence on success. Success return indicates the intent to change the state of the data model. RESULT_TYPE_SUCCESS if 1) the user is not member, yet the owner
 * 	2)requires authorisation 3)the state of no other restrictions, so user can be made to direct-join.
 */
static UFSRVResult *
_IsUserAllowedToLinkJoinFence(Session *sesn_ptr, unsigned long fid, bool *fence_lock_state, unsigned long fence_call_flags)
{
  bool lock_already_owned = false;
  unsigned 	fence_call_flags_final;
  unsigned	rescode;
  InstanceHolderForFence *instance_f_ptr = NULL;

  fence_call_flags_final = FENCE_CALLFLAG_SEARCH_BACKEND|FENCE_CALLFLAG_HASH_FENCE_LOCALLY|FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE;
  if (fence_call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED)	fence_call_flags_final |= (FENCE_CALLFLAG_KEEP_FENCE_LOCKED|FENCE_CALLFLAG_LOCK_FENCE_BLOCKING);

  FindFenceById(sesn_ptr, fid,	fence_call_flags_final);
  instance_f_ptr = (InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr);

  if (IS_EMPTY(instance_f_ptr)) {
#ifdef __UF_TESTING
    syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', fid:'%lu'}: COULD NOT LOCATE FENCE", __func__, pthread_self(), sesn_ptr, fid);
#endif

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_DOESNT_EXIST)
  }

  *fence_lock_state = lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_PROG_LOCKED_BY_THIS_THREAD));
  Fence *f_ptr = FenceOffInstanceHolder(instance_f_ptr);

  //FENCE NOW LOCKED if FENCE_CALLFLAG_KEEP_FENCE_LOCKED was set

  rescode = RESCODE_FENCE_BANNED_LIST;
  if (IsUserOnFenceBannedList(f_ptr, SESSION_USERID(sesn_ptr))) {
    //todo Issue a state sync for this user, as client might be out of sync.
#ifdef __UF_TESTING
    syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', userid:'%lu', fid:'%lu'}: JoinRequest COMMAND IGNORED: USER BANNED", __func__, pthread_self(), sesn_ptr, SESSION_USERID(sesn_ptr), fid);
#endif
    goto exit_error;
  }

  bool isFenceOwner = IsFenceOwnedByUser(sesn_ptr, f_ptr);

  if (isFenceOwner) {
    //todo: just join the,
    rescode = RESCODE_FENCE_OWNERSHIP;
    goto exit_success;
  }

  rescode = RESCODE_FENCE_MEMBERSHIP;
  InstanceHolderForFenceStateDescriptor *instance_fstate_ptr = IsUserMemberOfThisFence(SESSION_FENCE_LIST_PTR(sesn_ptr), f_ptr, 0/*DONT_LOCK*/);
  if (IS_PRESENT(instance_fstate_ptr)) {
    //todo Issue a state sync for this user, as client might be out of sync.
    goto exit_error;
  }

  rescode = RESCODE_FENCE_JOIN_LINKJOIN_LIST;
  if (IsUserOnFenceLinkJoinList(f_ptr, SESSION_USERID(sesn_ptr))) {
    //todo Issue a state sync for this user, as client might be out of sync.
#ifdef __UF_TESTING
    syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', userid:'%lu', fid:'%lu'}: JoinRequest COMMAND IGNORED: USER ALREADY ON LIST", __func__, pthread_self(), sesn_ptr, SESSION_USERID(sesn_ptr), fid);
#endif
    goto exit_error;
  }

  rescode = RESCODE_FENCE_PERMISSION;
  if (!IsFencePermissionWhiteListSemantics(FENCE_PERMISSIONS_MEMBERSHIP_PTR(f_ptr))) {
#ifdef __UF_TESTING
    syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', userid:'%lu', fid:'%lu'}: JoinRequest COMMAND: AUTHORISATION REQUIRED", __func__, pthread_self(), sesn_ptr, SESSION_USERID(sesn_ptr), fid);
#endif
    goto exit_success;
  }

  goto exit_success;

  exit_success:
  if (!(fence_call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED))	if (!lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
  _RETURN_RESULT_SESN(sesn_ptr, instance_f_ptr, RESULT_TYPE_SUCCESS, rescode)

  exit_error:
  if (!(fence_call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED))	if (!lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
  _RETURN_RESULT_SESN(sesn_ptr, instance_f_ptr, RESULT_TYPE_ERR, rescode)
}

/**
 * 	@brief Check if current user has the admin right permission to take an admin action, such as accepting or rejecting a linkjoin request.
 *
 * 	@param sesn_ptr the current (admin) user, authorising the acceptance command
 * 	@param sesn_ptr_originator the initial user who requested the linkjoin
 * 	@locked sesn_ptr: by caller
 * 	@locked sesn_ptr_originator
 * 	@locks f_ptr: by downstream functions and remains locked after this function exists if FENCE_CALLFLAG_KEEP_FENCE_LOCKED is set
 * 	@return \ref InstanceHolderForFence on success. A success return indicates the intent to change the state of the data model. RESULT_TYPE_SUCCESS if 1) the user is not member, yet the owner
 * 	2)requires authorisation 3)the state of no other restrictions, so user can be made to direct-join.
 */
static UFSRVResult *
_IsUserAllowedToAdminActionLinkJoinFence(Session *sesn_ptr, InstanceHolderForSession *sesn_ptr_originator_instance, unsigned long fid, bool *fence_lock_state, unsigned long call_flags_fence)
{
  bool lock_already_owned = false;
  unsigned	rescode;
  InstanceHolderForFence *instance_f_ptr = NULL;
  Session *sesn_ptr_originator = SessionOffInstanceHolder(sesn_ptr_originator_instance);

  unsigned 	call_flags_fence_finding;
  call_flags_fence_finding = FENCE_CALLFLAG_SEARCH_BACKEND|FENCE_CALLFLAG_HASH_FENCE_LOCALLY|FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE;
  if (call_flags_fence&FENCE_CALLFLAG_KEEP_FENCE_LOCKED)	call_flags_fence_finding |= (FENCE_CALLFLAG_KEEP_FENCE_LOCKED|FENCE_CALLFLAG_LOCK_FENCE_BLOCKING);

  FindFenceById(sesn_ptr, fid, call_flags_fence_finding);

  if (IS_EMPTY((instance_f_ptr = (InstanceHolderForFence *) SESSION_RESULT_USERDATA(sesn_ptr)))) {
#ifdef __UF_TESTING
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', fid:'%lu'}: COULD NOT LOCATE FENCE", __func__, pthread_self(), sesn_ptr, fid);
#endif

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_DOESNT_EXIST)
  }

  *fence_lock_state = lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_PROG_LOCKED_BY_THIS_THREAD));
  Fence *f_ptr = FenceOffInstanceHolder(instance_f_ptr);

  //FENCE NOW LOCKED if FENCE_CALLFLAG_KEEP_FENCE_LOCKED was set

  bool isFenceOwner = IsFenceOwnedByUser(sesn_ptr, f_ptr);

  rescode = RESCODE_FENCE_PERMISSION;
  if (!IsUserWithPermission(sesn_ptr, f_ptr, FENCE_PERMISSIONS_MEMBERSHIP_PTR(f_ptr)) && !isFenceOwner) {
#ifdef __UF_TESTING
    syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', userid:'%lu', fid:'%lu'}: USER DOESN'T HAVE SUFFICIENT AUTHORISATION RIGHT OR BLACKLISTED", __func__, pthread_self(), sesn_ptr, SESSION_USERID(sesn_ptr), fid);
#endif
    goto exit_error;
  }

  rescode = RESCODE_FENCE_BANNED_LIST;
  if (IsUserOnFenceBannedList(f_ptr, SESSION_USERID(sesn_ptr_originator))) {
    //todo Issue a state sync for this user, as client might be out of sync.
#ifdef __UF_TESTING
    syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', userid:'%lu', fid:'%lu'}: JoinRequest COMMAND IGNORED: USER BANNED", __func__, pthread_self(), sesn_ptr, SESSION_USERID(sesn_ptr), fid);
#endif
    goto exit_error;
  }

  rescode = RESCODE_USER_FENCE_ALREADYIN;
  InstanceHolderForFenceStateDescriptor *instance_fstate_ptr = IsUserMemberOfThisFence(SESSION_FENCE_LIST_PTR(sesn_ptr_originator), f_ptr, 0/*DONT_LOCK*/);
  if (IS_PRESENT(instance_fstate_ptr)) {
    //todo Issue a state sync for this user, as client might be out of sync.
    goto exit_error;
  }

  rescode = RESCODE_FENCE_JOIN_LINKJOIN_LIST;
  if (IsUserOnFenceLinkJoinList(f_ptr, SESSION_USERID(sesn_ptr_originator))) {
    goto exit_success;
  }

#ifdef __UF_TESTING
  syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', userid_originator:'%lu', fid:'%lu'}: USER NOT ON FENCE'S LINKJOIN LIST....", __func__, pthread_self(), sesn_ptr, SESSION_USERID(sesn_ptr_originator), fid);
#endif

  exit_error:
  if (!(call_flags_fence&FENCE_CALLFLAG_KEEP_FENCE_LOCKED))	if (!lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
  _RETURN_RESULT_SESN(sesn_ptr, instance_f_ptr, RESULT_TYPE_ERR, rescode)

  exit_success:
  if (!(call_flags_fence&FENCE_CALLFLAG_KEEP_FENCE_LOCKED))	if (!lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
  _RETURN_RESULT_SESN(sesn_ptr, instance_f_ptr, RESULT_TYPE_SUCCESS, rescode)

}

/**
 * @brief Process a linkjoin request for a user (who added themselves to the linkjoin request list) asking to join a fence via a link.
 * @originator user issuing a linkjoin ADDED message
 * @session originator
 *
 * @param instance_sesn_ptr
 * @return
 */
static UFSRVResult *
_CommandControllerFenceLinkJoinAdded(InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received) {
  bool is_already_locked_fence = false;
  InstanceHolderForFenceStateDescriptor *instance_fstate_ptr;
  FenceCommand *fence_cmd_ptr = data_msg_ptr_received->ufsrvcommand->fencecommand;

#define _FENCE_CALL_FLAGS_STATESYNC  (FENCE_CALLFLAG_KEEP_FENCE_LOCKED)

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
  InstanceHolderForFence *f_ptr_instance = NULL;
  Fence *f_ptr = NULL;

  //locks by default
  _IsUserAllowedToLinkJoinFence(sesn_ptr, fence_cmd_ptr->fences[0]->fid, &is_already_locked_fence, _FENCE_CALL_FLAGS_STATESYNC);
  int rescode = SESSION_RESULT_CODE(sesn_ptr);
  if (SESSION_RESULT_TYPE_ERROR(sesn_ptr)) {
    //FENCE LOCKED...
    if (!SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST)) {
      f_ptr_instance = SESSION_RESULT_USERDATA(sesn_ptr); f_ptr = FenceOffInstanceHolder(f_ptr_instance);

      switch (rescode) {
        case RESCODE_FENCE_MEMBERSHIP: //user already a member
        case RESCODE_FENCE_JOIN_LINKJOIN_LIST: //user already on the list; perhaps pending authorization, or clicking multiple time on fence join link
        case RESCODE_FENCE_BANNED_LIST: //user banned anyway
          HandleFenceCommandError(&(InstanceContextForSession){instance_sesn_ptr, sesn_ptr}, NULL, wsm_ptr_received, data_msg_ptr_received, rescode, fence_cmd_ptr->header->command, NULL);
        break;
      }

      if (!is_already_locked_fence)  FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
      _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)
    }

    //fence doesn't exist
    HandleFenceCommandError(&(InstanceContextForSession){instance_sesn_ptr, sesn_ptr}, NULL, wsm_ptr_received, data_msg_ptr_received, rescode, fence_cmd_ptr->header->command, NULL);
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)
  }

  //FENCE LOCKED...
  //User either needs authorisation, or is joined straight
  f_ptr_instance = SESSION_RESULT_USERDATA(sesn_ptr); f_ptr = FenceOffInstanceHolder(f_ptr_instance);

  //request needs to be authorised. Inform authorising users
  if (rescode == RESCODE_FENCE_PERMISSION) {
    FenceEvent fence_event = {0};
    if (IS_EMPTY((RegisterFenceEvent(f_ptr, EVENT_TYPE_LINKJOIN_ADDED, NULL, 0/*LOCK_FLAG*/, &fence_event)))) {
      THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_FENCE_EVENT_GENERATION)
    }
    fence_event.originator_ptr = &SESSION_UFSRVUIDSTORE(sesn_ptr);
    fence_event.session_id = SESSION_ID(sesn_ptr);
    AddThisToList(FENCE_LINK_JOINING_USER_SESSIONS_LIST_PTR(f_ptr), CLIENT_CTX_DATA(instance_sesn_ptr));
    SessionIncrementReference(instance_sesn_ptr, 1);
    _CacheBackendUpdateFenceLinkJoinAdded(SESSION_USERID(sesn_ptr), f_ptr);
    DbBackendInsertUfsrvEvent((UfsrvEvent *)&fence_event);

    BroadcastContextDataFenceLinkJoin broadcast_data = {.sesn_ptr_join_linking=sesn_ptr, .f_ptr=f_ptr};
    InterBroadcastFenceLinkJoin(sesn_ptr, (ClientContextData *)&broadcast_data, &fence_event, COMMAND_ARGS__ADDED);
  } else {
    //join user straight
  }

  _MarshalFenceLinkJoinCommand(&(InstanceContextForSession){instance_sesn_ptr, sesn_ptr}, NULL, f_ptr_instance, wsm_ptr_received, data_msg_ptr_received, COMMAND_ARGS__ADDED, CALLFLAGS_EMPTY);

  if (!is_already_locked_fence)  FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));

  return_success:
  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

#undef _FENCE_CALL_FLAGS_STATESYNC
}

#include <utils_nonce.h>
static UFSRVResult *_ProcessAdminActionFenceLinkJoin(InstanceHolderForSession *instance_sesn_ptr, InstanceContextForSession *sesn_ptr_instance_originator_ctx, InstanceContextForFence *f_ptr_instance_ctx, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received, int command_arg);
static UFSRVResult *_ProcessFenceLinkJoiningJoinActionAccepted(InstanceHolderForSession *instance_sesn_ptr, InstanceContextForSession *sesn_ptr_instance_originator_ctx, InstanceContextForFence *f_ptr_instance_ctx, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received, int command_arg);
static UFSRVResult *_ProcessFenceLinkJoiningJoinActionRejected(InstanceHolderForSession *instance_sesn_ptr, InstanceContextForSession *sesn_ptr_instance_originator_ctx, InstanceContextForFence *f_ptr_instance_ctx, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received, int command_arg);
static UFSRVResult *_MarshalFenceLinkJoinAdminActionCommand(InstanceContextForSession *ctx_ptr, InstanceContextForSession *ctx_ptr_originator, InstanceHolderForFence *instance_f_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received, char *linkjoin_nonce, int command_arg, unsigned call_flags);
static char *_GenerateLinkJoiningNonce(Session *sesn_ptr, Session *sesn_ptr_linking, Fence *f_ptr);
static bool _IsLinkJoinNonceValid(Session *sesn_ptr_linking, Fence *f_ptr, const char *nonce);

/**
* @brief A user who is authorised to admit a linkjoing user issued an action.
*  such as accepting or rejecting a previously requested linkjoin.
*
* @originator The user who previously issued a linkjoin request message
* @session Authorising user who issued the admin action
* @param instance_sesn_ptr as per session description
* @return
*/
static UFSRVResult *
_CommandControllerAdminActionFenceLinkJoin(InstanceHolderForSession *instance_sesn_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received, int command_arg) {
  int rescode = RESCODE_PROG_NULL_POINTER;
  bool is_already_locked_fence = false;
  InstanceHolderForFenceStateDescriptor *instance_fstate_ptr;
  FenceCommand *fence_cmd_ptr = data_msg_ptr_received->ufsrvcommand->fencecommand;

#define _FENCE_CALL_FLAGS_STATESYNC  (FENCE_CALLFLAG_KEEP_FENCE_LOCKED)

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

  bool is_already_locked_session = false;
  InstanceHolderForSession *sesn_ptr_instance_originator = _GetSessionForOriginator(sesn_ptr, (const UfsrvUid *)fence_cmd_ptr->originator->ufsrvuid.data, &is_already_locked_session);
  if (IS_EMPTY(sesn_ptr_instance_originator)) {
    THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_PROG_MISSING_PARAM)
  }

  //SESSION sesn_ptr_originator locked

  Session *sesn_ptr_originator = SessionOffInstanceHolder(sesn_ptr_instance_originator);
  InstanceHolderForFence *f_ptr_instance = NULL;
  Fence *f_ptr = NULL;
  _IsUserAllowedToAdminActionLinkJoinFence(sesn_ptr, sesn_ptr_instance_originator, fence_cmd_ptr->fences[0]->fid, &is_already_locked_fence, _FENCE_CALL_FLAGS_STATESYNC);
  rescode = SESSION_RESULT_CODE(sesn_ptr);
  if (SESSION_RESULT_TYPE_ERROR(sesn_ptr)) {
    //FENCE LOCKED in this scope...
    if (!SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST)) {
      f_ptr_instance = SESSION_RESULT_USERDATA(sesn_ptr); f_ptr = FenceOffInstanceHolder(f_ptr_instance);

      switch (rescode) {
        case RESCODE_FENCE_MEMBERSHIP: //user was not on linkjoin list
        case RESCODE_FENCE_JOIN_LINKJOIN_LIST: //user already on the list; perhaps pending authorization, or clicking multiple time on fence join link
        case RESCODE_FENCE_BANNED_LIST: //user banned from fence
        case RESCODE_FENCE_PERMISSION: //authorising user doesn't have enough persmissions
        case RESCODE_USER_FENCE_ALREADYIN://user already a member
          HandleFenceCommandError(&(InstanceContextForSession){instance_sesn_ptr, sesn_ptr}, NULL, wsm_ptr_received, data_msg_ptr_received, rescode, fence_cmd_ptr->header->command, NULL);
          break;
      }

      if (!is_already_locked_session)   SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_originator, __func__ );
      if (!is_already_locked_fence)     FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
      THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, rescode)
    }

    //RESCODE_FENCE_DOESNT_EXIST
    if (!is_already_locked_session)  SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_originator, __func__ );
    THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_FENCE_DOESNT_EXIST)
  }

  //FENCE LOCKED...

  _ProcessAdminActionFenceLinkJoin(instance_sesn_ptr,
                                   &(InstanceContextForSession) {sesn_ptr_instance_originator, sesn_ptr_originator, is_already_locked_session, true}, &(InstanceContextForFence) {f_ptr_instance, FenceOffInstanceHolder(f_ptr_instance), is_already_locked_fence, true},
                                   wsm_ptr_received, data_msg_ptr_received, command_arg);

  if (!is_already_locked_session) SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_originator, __func__ );
  if (!is_already_locked_fence)   FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));

  //todo trap error return

  THREAD_CONTEXT_RETURN_RESULT_SUCCESS(NULL, RESCODE_PROG_NULL_POINTER)

 /* //User either needs authorisation, or is joined straight
  f_ptr_instance = SESSION_RESULT_USERDATA(sesn_ptr); f_ptr = FenceOffInstanceHolder(f_ptr_instance);

  //user doesn't have permission to issue acceptance for linkjoin
  FenceEvent fence_event = {0};
  if (IS_EMPTY((RegisterFenceEvent(f_ptr, command_arg == COMMAND_ARGS__ACCEPTED? EVENT_TYPE_FENCE_JOIN_REQUEST_ACCEPTED : EVENT_TYPE_FENCE_JOIN_REQUEST_REJECTED, NULL, 0*//*LOCK_FLAG*//*, &fence_event)))) {
    rescode =  RESCODE_FENCE_EVENT_GENERATION;
    goto return_error;
  }

  fence_event.originator_ptr = &SESSION_UFSRVUIDSTORE(sesn_ptr);
  fence_event.session_id = SESSION_ID(sesn_ptr);
  RemoveThisFromList(FENCE_LINK_JOINING_USER_SESSIONS_LIST_PTR(f_ptr), CLIENT_CTX_DATA(sesn_ptr_instance_originator));
  SessionDecrementReference(sesn_ptr_instance_originator, 1);
  _CacheBackendUpdateFenceLinkJoinRemoved(SESSION_USERID(sesn_ptr_originator), f_ptr);
  DbBackendInsertUfsrvEvent((UfsrvEvent *)&fence_event);
  BroadcastContextDataFenceLinkJoin broadcast_data = {.sesn_ptr_join_linking=sesn_ptr_originator, .f_ptr=f_ptr};
  InterBroadcastFenceLinkJoin(sesn_ptr, (ClientContextData *)&broadcast_data, &fence_event, command_arg);

  _MarshalFenceLinkJoinAdminActionCommand(&(InstanceContextForSession) {instance_sesn_ptr, sesn_ptr}, &(InstanceContextForSession) {sesn_ptr_instance_originator, sesn_ptr_originator}, f_ptr_instance, wsm_ptr_received, data_msg_ptr_received, command_arg, CALLFLAGS_EMPTY);

  if (!is_already_locked_session) SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_originator, __func__ );
  if (!is_already_locked_fence)      FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));

  return_success:
  THREAD_CONTEXT_RETURN_RESULT_SUCCESS(NULL, RESCODE_PROG_NULL_POINTER)

  return_error:
  if (!is_already_locked_session)   SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_originator, __func__ );
  if (!is_already_locked_fence)     FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
  THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, rescode)*/

#undef _FENCE_CALL_FLAGS_STATESYNC
}

/**
 * @brief Helper function to interpret linkjoin admin action which is currently either to accept or reject a user's request linkjoin.
 * @param sesn_ptr_instance_originator User who requested to linkjoin
 * @locked sesn_ptr_instance_originator
 * @locked f_ptr_instance
 * @unlocks None
 * @return
 */
static UFSRVResult *
_ProcessAdminActionFenceLinkJoin(InstanceHolderForSession *instance_sesn_ptr, InstanceContextForSession *sesn_ptr_instance_originator_ctx, InstanceContextForFence *f_ptr_instance_ctx, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received, int command_arg)
{
  if (command_arg == COMMAND_ARGS__ACCEPTED) {
    return _ProcessFenceLinkJoiningJoinActionAccepted(instance_sesn_ptr, sesn_ptr_instance_originator_ctx, f_ptr_instance_ctx, wsm_ptr_received, data_msg_ptr_received, command_arg);
  }
  if (command_arg == COMMAND_ARGS__REJECTED) {
    return _ProcessFenceLinkJoiningJoinActionRejected(instance_sesn_ptr, sesn_ptr_instance_originator_ctx, f_ptr_instance_ctx, wsm_ptr_received, data_msg_ptr_received, command_arg);
  }

  return_success:
  THREAD_CONTEXT_RETURN_RESULT_SUCCESS(NULL, RESCODE_PROG_NULL_POINTER)

}

/**
 * @brief linkjoin admin accepted linkjoining user requesting to join. User will be sent a linkjoin nonce to join with.
 * User will only be removed from linkjoin lists (both in-memory and cachebackend) after joining.
 * @param instance_sesn_ptr
 * @param sesn_ptr_instance_originator_ctx session representing the user linkjoining
 * @param command_arg
 * @return
 */
static UFSRVResult *
_ProcessFenceLinkJoiningJoinActionAccepted(InstanceHolderForSession *instance_sesn_ptr, InstanceContextForSession *sesn_ptr_instance_originator_ctx, InstanceContextForFence *f_ptr_instance_ctx, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received, int command_arg)
{
  int rescode;
  Fence *f_ptr = FenceOffInstanceHolder(f_ptr_instance_ctx->instance_f_ptr);
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
  Session *sesn_ptr_originator = SessionOffInstanceHolder(sesn_ptr_instance_originator_ctx->instance_sesn_ptr);

  //user doesn't have permission to issue acceptance for linkjoin

  char *linkjoin_nonce = _GenerateLinkJoiningNonce(sesn_ptr, sesn_ptr_originator, f_ptr);
  if (!IS_STR_LOADED(linkjoin_nonce)) {
    rescode =  RESCODE_FENCE_LINKJOIN_NONCE;
    THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, rescode)
  }

  //todo is this necessary? no data sets have changed
  FenceEvent fence_event = {0};
  if (IS_EMPTY((RegisterFenceEvent(f_ptr, EVENT_TYPE_LINKJOIN_ACCEPTED, NULL, 0/*LOCK_FLAG*/, &fence_event)))) {
    rescode =  RESCODE_FENCE_EVENT_GENERATION;

    free(linkjoin_nonce);

    THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, rescode)
  }

  fence_event.originator_ptr = &SESSION_UFSRVUIDSTORE(sesn_ptr);
  fence_event.session_id = SESSION_ID(sesn_ptr);
  DbBackendInsertUfsrvEvent((UfsrvEvent *)&fence_event);
  BroadcastContextDataFenceLinkJoin broadcast_data = {.sesn_ptr_join_linking=sesn_ptr_originator, .f_ptr=f_ptr};
  InterBroadcastFenceLinkJoin(sesn_ptr, (ClientContextData *)&broadcast_data, &fence_event, command_arg);

  _MarshalFenceLinkJoinAdminActionCommand(&(InstanceContextForSession) {instance_sesn_ptr, sesn_ptr}, &(InstanceContextForSession) {sesn_ptr_instance_originator_ctx->instance_sesn_ptr, sesn_ptr_originator}, f_ptr_instance_ctx->instance_f_ptr, wsm_ptr_received, data_msg_ptr_received, linkjoin_nonce, command_arg, CALLFLAGS_EMPTY);

  free(linkjoin_nonce);

  return_success:
  THREAD_CONTEXT_RETURN_RESULT_SUCCESS(NULL, RESCODE_PROG_NULL_POINTER)

}

/**
 * @brief linkjoin admin rejected linkjoining user request to join.
 * @param instance_sesn_ptr
 * @param sesn_ptr_instance_originator_ctx session representing the user linkjoining
 * @param command_arg
 * @return
 */
static UFSRVResult *
_ProcessFenceLinkJoiningJoinActionRejected(InstanceHolderForSession *instance_sesn_ptr, InstanceContextForSession *sesn_ptr_instance_originator_ctx, InstanceContextForFence *f_ptr_instance_ctx, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received, int command_arg)
{
  int rescode;
  Fence *f_ptr = FenceOffInstanceHolder(f_ptr_instance_ctx->instance_f_ptr);
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
  Session *sesn_ptr_originator = SessionOffInstanceHolder(sesn_ptr_instance_originator_ctx->instance_sesn_ptr);

  FenceEvent fence_event = {0};
  if (IS_EMPTY((RegisterFenceEvent(f_ptr, EVENT_TYPE_LINKJOIN_REJECTED, NULL, 0/*LOCK_FLAG*/, &fence_event)))) {
    THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_FENCE_EVENT_GENERATION)
  }

  fence_event.originator_ptr = &SESSION_UFSRVUIDSTORE(sesn_ptr);
  fence_event.session_id = SESSION_ID(sesn_ptr);
  RemoveThisFromList(FENCE_LINK_JOINING_USER_SESSIONS_LIST_PTR(f_ptr), CLIENT_CTX_DATA(instance_sesn_ptr));
  SessionDecrementReference(instance_sesn_ptr, 1);
  _CacheBackendUpdateFenceLinkJoinRemoved(SESSION_USERID(sesn_ptr), f_ptr);
  DbBackendInsertUfsrvEvent((UfsrvEvent *)&fence_event);
  BroadcastContextDataFenceLinkJoin broadcast_data = {.sesn_ptr_join_linking=sesn_ptr, .f_ptr=f_ptr};
  InterBroadcastFenceLinkJoin(sesn_ptr, (ClientContextData *)&broadcast_data, &fence_event, COMMAND_ARGS__REJECTED);

  _MarshalFenceLinkJoinAdminActionCommand(&(InstanceContextForSession) {instance_sesn_ptr, sesn_ptr}, &(InstanceContextForSession) {sesn_ptr_instance_originator_ctx->instance_sesn_ptr, sesn_ptr_originator}, f_ptr_instance_ctx->instance_f_ptr, wsm_ptr_received, data_msg_ptr_received, NULL, command_arg, CALLFLAGS_EMPTY);

  return_success:
  THREAD_CONTEXT_RETURN_RESULT_SUCCESS(NULL, RESCODE_PROG_NULL_POINTER)

}

/**
 * @brief Tidy up after a linkjoining user actually joined the group.
 * @param sesn_ptr
 * @param f_ptr
 * @param linkjoin_nonce nonce that was created when linkjoin request was made
 * @return
 */
UFSRVResult *
ProcessLinkJoinUserActionJoined(InstanceHolderForSession *instance_sesn_ptr, Fence *f_ptr, const char *linkjoin_nonce)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
  if (_IsLinkJoinNonceValid(sesn_ptr, f_ptr, linkjoin_nonce)) {
    FenceEvent fence_event = {0};
    if (IS_EMPTY((RegisterFenceEvent(f_ptr, EVENT_TYPE_LINKJOIN_JOINED, NULL, 0/*LOCK_FLAG*/, &fence_event)))) {
      THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_FENCE_EVENT_GENERATION)
    }

    fence_event.originator_ptr = &SESSION_UFSRVUIDSTORE(sesn_ptr);
    fence_event.session_id = SESSION_ID(sesn_ptr);
    RemoveThisFromList(FENCE_LINK_JOINING_USER_SESSIONS_LIST_PTR(f_ptr), CLIENT_CTX_DATA(instance_sesn_ptr));
    SessionDecrementReference(instance_sesn_ptr, 1);
    _CacheBackendUpdateFenceLinkJoinRemoved(SESSION_USERID(sesn_ptr), f_ptr);
    DbBackendInsertUfsrvEvent((UfsrvEvent *)&fence_event);
    BroadcastContextDataFenceLinkJoin broadcast_data = {.sesn_ptr_join_linking=sesn_ptr, .f_ptr=f_ptr};
    InterBroadcastFenceLinkJoin(sesn_ptr, (ClientContextData *)&broadcast_data, &fence_event, COMMAND_ARGS__ACCEPTED);
    THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_FENCE_LINKJOIN_NONCE)
  }

  THREAD_CONTEXT_RETURN_RESULT_SUCCESS(NULL, RESCODE_FENCE_LINKJOIN_NONCE)
}

/**
 * @brief drop a nonce (with a TTL) for a user who's been linkjoin request has been accepted. User must provide the nonce when joining.
 * @param sesn_ptr
 * @param sesn_ptr_linking user who's linkjoining
 * @param f_ptr fence impacted
 * @return generated nonce or NULL
 * @dynamic_memory EXPORT char * (from BackEndGenerateNonce())
 */
static char *
_GenerateLinkJoiningNonce(Session *sesn_ptr, Session *sesn_ptr_linking, Fence *f_ptr)
{
  char *linkjoin_nonce_value;
  char *linkjoin_nonce = NULL;

  asprintf(&linkjoin_nonce_value, "%lu:%lu", FENCE_ID(f_ptr), UfsrvUidGetSequenceId(&(SESSION_UFSRVUIDSTORE(sesn_ptr_linking))));

  if (IS_STR_LOADED(linkjoin_nonce_value)) {
    linkjoin_nonce = BackEndGenerateNonce(sesn_ptr, CONFIGDEFAULT_LINKJOIN_NONCE_EXPIRY, CONFIGDEFAULT_LINKJOIN_NONCE_PREFIX, linkjoin_nonce_value);
  } else {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', uname:'%s', fid:'%lu'}: ERROR: COULD NOT GENERATE LinkJoin nonce value path...", __func__, pthread_self(), sesn_ptr, SESSION_USERNAME(sesn_ptr), FENCE_ID(f_ptr));
  }

  free(linkjoin_nonce_value);
  return linkjoin_nonce;

}

static bool
_IsLinkJoinNonceValid(Session *sesn_ptr_linking, Fence *f_ptr, const char *linkjoin_nonce)
{
  bool is_linkjoin_nonce_valid = false;
  char *redis_command_with_nonce = NULL;
  redisReply *redis_ptr = NULL;

  asprintf(&redis_command_with_nonce, "GET %s:%s", CONFIGDEFAULT_LINKJOIN_NONCE_PREFIX, linkjoin_nonce);

  if (IS_PRESENT(redis_command_with_nonce)) {
    PersistanceBackend *pers_ptr = THREAD_CONTEXT_SESSION_CACHEBACKEND;

    if (!(redis_ptr = (*pers_ptr->send_command)(NULL, redis_command_with_nonce))) {
      syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p' nonce:'%s'): ERROR COULD NOT GET NONCE: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr_linking, linkjoin_nonce);

      free(redis_command_with_nonce);
      return is_linkjoin_nonce_valid;
    }

    free(redis_command_with_nonce);

    //region success block
    if (redis_ptr->type == REDIS_REPLY_STRING) {
#ifdef __UF_FULLDEBUG
      syslog(LOG_DEBUG, "%s {pid:'%lu' o:'%p', path:'%s'}: SUCCESS NONCE:'%s' RECEIVED. Stored value:'%s'", __func__, pthread_self(), sesn_ptr, path, nonce, redis_ptr->str);
#endif

      char *linkjoin_nonce_value;
      asprintf(&linkjoin_nonce_value, "%lu:%lu", FENCE_ID(f_ptr), UfsrvUidGetSequenceId(&(SESSION_UFSRVUIDSTORE(sesn_ptr_linking))));
      if (IS_PRESENT(linkjoin_nonce_value)) {
        if (strcmp(linkjoin_nonce_value, redis_ptr->str) == 0) {
          is_linkjoin_nonce_valid = true;
        }

        free(linkjoin_nonce_value);
      }

      goto get_out;
    }
    //endregion

    if (redis_ptr->type == REDIS_REPLY_ERROR) {
      syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p'): ERROR COULD NOT GET NONCE: REPLY ERROR '%s'", __func__, pthread_self(), sesn_ptr_linking, redis_ptr->str);

      goto get_out;
    }

    if (redis_ptr->type == REDIS_REPLY_NIL) {
      syslog(LOG_DEBUG, "%s(pid:'%lu' o:'%p'): ERROR COULD NOT GET STORED NONCE: REPLY NIL '%s'", __func__, pthread_self(), sesn_ptr_linking, redis_ptr->str);

      goto get_out;
    }
  }

  get_out:
  if (!IS_EMPTY(redis_ptr)) freeReplyObject(redis_ptr);
  return is_linkjoin_nonce_valid;
}

/**
 * @brief Remove user from linkjoin cache backend list.
 * @param fe_ptr_provided user allocated events structure
 * @return
 */
static UFSRVResult *
_CacheBackendUpdateFenceLinkJoinAdded(unsigned long user_id, Fence *f_ptr)
{
  PersistanceBackend 	*pers_ptr						= THREAD_CONTEXT_SESSION_CACHEBACKEND;
  redisReply 					*redis_ptr					= NULL;
  time_t              time_now            = time(NULL);

  redis_ptr  = (*pers_ptr->send_command)(NULL, REDIS_CMD_LINKJOINING_USERS_FOR_FERNCE_ADD, FENCE_ID(f_ptr), time_now, user_id);
  if (IS_PRESENT(redis_ptr))	freeReplyObject(redis_ptr);
  else {
    THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_BACKEND_CONNECTION)
  }

  THREAD_CONTEXT_RETURN_RESULT_SUCCESS(NULL, RESCODE_BACKEND_COMMAND)
}

/**
 * @brief Remove user from linkjoin cache backend list
 * @param fe_ptr_provided user allocated events structure
 * @return
 */
static UFSRVResult *
_CacheBackendUpdateFenceLinkJoinRemoved(unsigned long user_id, Fence *f_ptr)
{
  PersistanceBackend 	*pers_ptr						= THREAD_CONTEXT_SESSION_CACHEBACKEND;
  redisReply 					*redis_ptr					= NULL;
  time_t              time_now            = time(NULL);

  redis_ptr  = (*pers_ptr->send_command)(NULL, REDIS_CMD_LINKJOINING_USERS_FOR_FERNCE_REM, FENCE_ID(f_ptr), user_id);
  if (IS_PRESENT(redis_ptr))	freeReplyObject(redis_ptr);
  else {
    THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_BACKEND_CONNECTION)
  }

  THREAD_CONTEXT_RETURN_RESULT_SUCCESS(NULL, RESCODE_BACKEND_COMMAND)
}

/**
 * @brief Wire admin-actioned linkjoin command, currently either accepted or rejected.
 * @param ctx_ptr The admin user handling the command
 * @param ctx_ptr_originator The initial requesting user
 * @param command_arg Type of action currently only \ref _CommandArgs.COMMAND_ARGS__ACCEPTED and _CommandArgs.COMMAND_ARGS__REJECTED
 * @param call_flags
 * @return
 */
static UFSRVResult *
_MarshalFenceLinkJoinAdminActionCommand(InstanceContextForSession *ctx_ptr, InstanceContextForSession *ctx_ptr_originator, InstanceHolderForFence *instance_f_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received, char *linkjoin_nonce, int command_arg, unsigned call_flags)
{
#pragma region allocation_block_for__MarshalFenceLinkJoinCAcceptedCommand
  Session *sesn_ptr = ctx_ptr->sesn_ptr;
  Fence *f_ptr      = FenceOffInstanceHolder(instance_f_ptr);

  Envelope 					command_envelope= ENVELOPE__INIT;
  CommandHeader 		header					=	COMMAND_HEADER__INIT;
  UfsrvCommandWire	ufsrv_command		= UFSRV_COMMAND_WIRE__INIT;
  FenceCommand 			fence_command		= FENCE_COMMAND__INIT;

  //plumb in static elements
  command_envelope.ufsrvcommand = &ufsrv_command;
  ufsrv_command.header = &header; fence_command.header = &header;

  //plumb in FenceRecords array
  FenceRecord *fence_records[1];
  FenceRecord fence_record = {0};
  ufsrv_command.fencecommand	=	&fence_command;
  ufsrv_command.ufsrvtype			=	UFSRV_COMMAND_WIRE__UFSRV_TYPE__UFSRV_FENCE;

  ProvideFenceRecordInProtoAsIdentifier(ctx_ptr->sesn_ptr, f_ptr, &fence_record, true);
  if (IS_STR_LOADED(linkjoin_nonce))  fence_record.description = linkjoin_nonce;

  fence_records[0]							=	&fence_record;
  fence_command.fences					=	fence_records;
  fence_command.n_fences				=	1;

  command_envelope.sourceufsrvuid				=	"0";
  command_envelope.sourcedevice	=	1; command_envelope.has_sourcedevice = 1;
  command_envelope.timestamp		=	GetTimeNowInMillis(); command_envelope.has_timestamp = 1;

  header.cid			=	SESSION_ID(sesn_ptr); header.has_cid = 1;
  header.when			=	command_envelope.timestamp; header.has_when = 1;
  header.command	=	FENCE_COMMAND__COMMAND_TYPES__LINKJOIN;
  header.args		  =	command_arg; header.has_args = 1;

  if (IS_PRESENT(data_msg_ptr_received) && IS_PRESENT(data_msg_ptr_received->ufsrvcommand->fencecommand)) {
    header.when_client	=	data_msg_ptr_received->ufsrvcommand->fencecommand->header->when; header.has_when_client	= 1;
    header.args_client  = data_msg_ptr_received->ufsrvcommand->fencecommand->header->args_client; header.has_args_client = 1;
  }

  UFSRVResult *res_ptr = NULL;
  UserRecord user_record_originator = {0};
  UserRecord user_record_authoriser = {0};
#pragma endregion

   //let the initial originator know their linkjoining request was accepted/rejected by admin. Keep originator undefined.
   fence_command.authoriser	= ProvideUserRecordFromSessionInProto(ctx_ptr->sesn_ptr, &user_record_authoriser, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF);
   res_ptr = WireMarshalFenceCommandToUser(ctx_ptr_originator, NULL, f_ptr, wsm_ptr_received, &command_envelope,  uFENCE_V1_IDX);

   //set originator to initial requesting user and keep authoriser, as other admins may want to know who authorised the join
   fence_command.originator	= ProvideUserRecordFromSessionInProto(ctx_ptr_originator->sesn_ptr, &user_record_originator, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF);
  FenceLinkJoinCommandExecutorContext  ctx = {ctx_ptr, &command_envelope, wsm_ptr_received, instance_f_ptr};
  size_t marshalled = InvokeFencePermissionListIteratorExecutor(FENCE_PERMISSIONS_MEMBERSHIP_PTR(f_ptr), (CallbackExecutor)_WireMarshalFenceLinkJoinToUser, CLIENT_CTX_DATA(&ctx), true);
  if (marshalled == 0) {
    //the approving admin was not on that permission list (could be fence owner who doesn't need to be there technically speaking
   res_ptr = WireMarshalFenceCommandToUser(ctx_ptr, NULL, f_ptr, wsm_ptr_received, &command_envelope,  uFENCE_V1_IDX);
  }

  free(fence_record.cname);

  return res_ptr;

}

/**
 * @brief Prepare for wire marshalling outcome of linkjoin command processing back to users.
 * @param ctx_ptr the user session which sent the command
 * @param ctx_ptr_originator if applicable, the initial originator of the command which maybe a target for a special response message
 * @param call_flags
 * @return
 */
static UFSRVResult *
_MarshalFenceLinkJoinCommand(InstanceContextForSession *ctx_ptr, InstanceContextForSession *ctx_ptr_originator, InstanceHolderForFence *instance_f_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received, int command_arg, unsigned call_flags)
{
#pragma region allocation_flock_for__MarshalFenceLinkJoinCommand
  Session *sesn_ptr = ctx_ptr->sesn_ptr;
  Fence *f_ptr = FenceOffInstanceHolder(instance_f_ptr);

  Envelope 					command_envelope= ENVELOPE__INIT;
  CommandHeader 		header					=	COMMAND_HEADER__INIT;
  UfsrvCommandWire	ufsrv_command		= UFSRV_COMMAND_WIRE__INIT;
  FenceCommand 			fence_command		= FENCE_COMMAND__INIT;

  //plumb in static elements
  command_envelope.ufsrvcommand = &ufsrv_command;
  ufsrv_command.header = &header; fence_command.header = &header;

  //plumb in FenceRecords array
  FenceRecord *fence_records[1];
  FenceRecord fence_record = {0};
  ufsrv_command.fencecommand	=	&fence_command;
  ufsrv_command.ufsrvtype			=	UFSRV_COMMAND_WIRE__UFSRV_TYPE__UFSRV_FENCE;

  ProvideFenceRecordInProtoAsIdentifier(ctx_ptr->sesn_ptr, f_ptr, &fence_record, true);
  fence_records[0]							=	&fence_record;
  fence_command.fences					=	fence_records;
  fence_command.n_fences				=	1;

  command_envelope.sourceufsrvuid				=	"0";
  command_envelope.sourcedevice	=	1; command_envelope.has_sourcedevice = 1;
  command_envelope.timestamp		=	GetTimeNowInMillis(); command_envelope.has_timestamp = 1;

  header.cid			=	SESSION_ID(sesn_ptr); header.has_cid = 1;
  header.when			=	command_envelope.timestamp; header.has_when = 1;
  header.command	=	FENCE_COMMAND__COMMAND_TYPES__LINKJOIN;
  header.args		  =	command_arg; header.has_args = 1;

  if (IS_PRESENT(data_msg_ptr_received) && IS_PRESENT(data_msg_ptr_received->ufsrvcommand->fencecommand)) {
    header.when_client =	data_msg_ptr_received->ufsrvcommand->fencecommand->header->when; header.has_when_client	= 1;
    header.args_client = data_msg_ptr_received->ufsrvcommand->fencecommand->header->args_client; header.has_args_client = 1;
  }

  UFSRVResult *res_ptr;
  UserRecord user_record_originator;
#pragma endregion

  fence_command.originator	= ProvideUserRecordFromSessionInProto(sesn_ptr, &user_record_originator, PROTO_USER_RECORD_MINIMAL, PROTO_USER_RECORD_BYREF);

  //acknowledge user request
  res_ptr = WireMarshalFenceCommandToUser(ctx_ptr, NULL, f_ptr, wsm_ptr_received, &command_envelope,  uFENCE_V1_IDX);

  FenceLinkJoinCommandExecutorContext  ctx = {ctx_ptr, &command_envelope, wsm_ptr_received, instance_f_ptr};
  size_t marshalled = InvokeFencePermissionListIteratorExecutor(FENCE_PERMISSIONS_MEMBERSHIP_PTR(f_ptr), (CallbackExecutor)_WireMarshalFenceLinkJoinToUser, CLIENT_CTX_DATA(&ctx), true);
  if (marshalled == 0) {
    bool lock_already_owned = false;
    InstanceHolderForSession *instance_sesn_ptr_fence_owner = GetSessionForFenceOwner(sesn_ptr, FENCE_OWNER_UID(f_ptr), &lock_already_owned);
    if (IS_PRESENT(instance_sesn_ptr_fence_owner)) {
      WireMarshalFenceCommandToUser(ctx_ptr, &(InstanceContextForSession){instance_sesn_ptr_fence_owner, SessionOffInstanceHolder(instance_sesn_ptr_fence_owner)}, f_ptr, wsm_ptr_received, &command_envelope,  uFENCE_V1_IDX);
      if (!lock_already_owned) SessionUnLockCtx(THREAD_CONTEXT_PTR, SessionOffInstanceHolder(instance_sesn_ptr_fence_owner), __func__ );
    }
  }

  free(fence_record.cname);

  return res_ptr;

}

/**
 * 	@brief: designed to be called back from the hashtable iterator for each user who is member of a given permission ACL
 * 	@param ctx_ptr Context data provided by the originating caller (which invoked the iterator)
 * 	@param ctx_data_ptr Data item provided through a serial iteration on the hashmap
 */
static UFSRVResult *
_WireMarshalFenceLinkJoinToUser(FenceLinkJoinCommandExecutorContext *ctx_ptr, ClientContextData *ctx_data_ptr)
{
  Session *sesn_ptr_target = SessionOffInstanceHolder((InstanceHolderForSession *)ctx_data_ptr);
  //don't send to self as this user is acknowledged separately
  if (memcmp(SESSION_UFSRVUID(sesn_ptr_target), SESSION_UFSRVUID(ctx_ptr->ctx_ptr_originator->sesn_ptr), CONFIG_MAX_UFSRV_ID_SZ) == 0)	goto return_success;

  ctx_ptr->envelope->ufsrvcommand->usercommand->header->cid = SESSION_ID(sesn_ptr_target);
  WireMarshalFenceCommandToUser(ctx_ptr->ctx_ptr_originator, &(InstanceContextForSession){(InstanceHolderForSession *)ctx_data_ptr, sesn_ptr_target, false, false}, FenceOffInstanceHolder(ctx_ptr->f_ptr_instance), ctx_ptr->wsm_ptr_received, ctx_ptr->envelope,  uFENCE_V1_IDX);

  return_success:
  _RETURN_RESULT_SESN(ctx_ptr->ctx_ptr_originator->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
}

