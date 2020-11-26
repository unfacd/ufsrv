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
#include <hashtable.h>
#include <recycler/instance_type.h>
#include <utils_crypto.h>
#include <utils_str.h>
#include <fence.h>
#include <ufsrv_core/fence/fence_utils.h>
#include <ufsrv_core/fence/fence_state.h>
#include <fence_proto.h>
#include <ufsrv_core/fence/fence_permission.h>
#include <uflib/scheduled_jobs/scheduled_jobs.h>
#include <attachments.h>
#include <fence_broadcast.h>
#include <http_request_context_type.h>
#include <ufsrv_core/location/location.h>
#include <ufsrv_core/cache_backend/persistance.h>
#include <misc.h>
#include <net.h>
#include <recycler/instances_list.h>
#include <nportredird.h>
#include <ufsrvwebsock/include/protocol_websocket.h>
#include <ufsrvwebsock/include/protocol_websocket_session.h>
#include <sessions_delegator_type.h>
#include <recycler/recycler.h>
#include <ufsrv_core/user/user_backend.h>
#include <thread_utils.h>
#include <command_controllers.h>
#include <ufsrv_core/msgqueue_backend/UfsrvMessageQueue.pb-c.h>
#include <ufsrvuid.h>
#include <include/fence.h>

//type recycler pool for Fence
/////>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

static RecyclerPoolHandle *FencePoolHandle;

static int	TypePoolInitCallback_Fence (ClientContextData *data_ptr, size_t oid);
static int	TypePoolGetInitCallback_Fence (InstanceHolder *data_ptr, ContextData *context_data, size_t oid, unsigned long call_flags);
static int	TypePoolPutInitCallback_Fence (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);
static char	*TypePoolPrintCallback_Fence (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);
static int	TypePoolDestructCallback_Fence (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);

static RecyclerPoolOps ops_fence = {
		TypePoolInitCallback_Fence,
		TypePoolGetInitCallback_Fence,
		TypePoolPutInitCallback_Fence,
		TypePoolPrintCallback_Fence,
		TypePoolDestructCallback_Fence
};

//////>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

//type recycler pool for FenceStateDescriptor
/////>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

//assigned when the typepool is initialised
static RecyclerPoolHandle *FenceStateDescriptorPoolHandle;

static int	TypePoolInitCallback_FenceStateDescriptor (ClientContextData *data_ptr, size_t oid);
static int	TypePoolGetInitCallback_FenceStateDescriptor (InstanceHolder *data_ptr, ContextData *context_data, size_t oid, unsigned long call_flags);
static int	TypePoolPutInitCallback_FenceStateDescriptor (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);
static char	*TypePoolPrintCallback_FenceStateDescriptor (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);
static int	TypePoolDestructCallback_FenceStateDescriptor (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);

static RecyclerPoolOps ops_fence_state_descriptor = {
		TypePoolInitCallback_FenceStateDescriptor,
		TypePoolGetInitCallback_FenceStateDescriptor,
		TypePoolPutInitCallback_FenceStateDescriptor,
		TypePoolPrintCallback_FenceStateDescriptor,
		TypePoolDestructCallback_FenceStateDescriptor
};

/////>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>


extern SessionsDelegator *const sessions_delegator_ptr;
extern __thread ThreadContext ufsrv_thread_context;
extern ufsrv *const masterptr;

static HashTable FenceRegistryIdHashTable;

static HashTable FenceRegistryCanonicalNameHashTable;


static size_t _CrossCheckInvitedListsForUser (InstanceHolderForSession *instance_sesn_ptr);
inline static Fence *_PopulateFenceData (Fence *f_ptr, Session *sesn_ptr, LocationDescription *, const char *fence_banner, char *userfence_canonical_name_in, bool);
inline static void _DePopulateFenceData (Fence *f_ptr, unsigned long call_flags);
inline static void _DestructFenceLocationDescription (FenceLocationDescription *location_ptr);
static inline UFSRVResult *_CheckForDuplicateUsername (Session *sesn_ptr, Fence *f_ptr, redisReply *current_user, redisReply **processed_users_collection, size_t collection_sz);

// ---START LOCKING--------------------

 inline UFSRVResult *
 FenceEventsLockRDCtx (ThreadContext *thread_ctx_ptr, Fence *f_ptr, int try_flag, UFSRVResult *res_ptr, const char *func)
 {
 	int lock_state;

 	if (IS_PRESENT(thread_ctx_ptr)) {
		if (IsObjectInLockedObjectsStore(thread_ctx_ptr->ht_ptr, f_ptr)) {
			lock_state = 0;
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', ctx:'%p, try:'%i', func:'%s'): NOTICE: NOT LOCKING: ALREADY IN STORE", __func__, pthread_self(), f_ptr, thread_ctx_ptr, try_flag, func);
			goto return_already_locked_by_this_thread;
		}
	}

 	if (try_flag) {//The calling thread acquires the read lock if a writer does not hold the lock and there are no writers blocked on the lock.
 		lock_state = pthread_rwlock_tryrdlock(&(f_ptr->fence_events.rwlock));
 		if (lock_state == 0) {
#ifdef __UF_FULLDEBUG
 			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', ctx:'%p, try:'1', func:'%s'): SUCCESS: TRY-READ lock for Fence events acquired...",__func__, pthread_self(), f_ptr, IS_PRESENT(thread_ctx_ptr)?thread_ctx_ptr:0, func);
#endif
 			goto return_locked;
 		} else {
 			char *err_str = thread_error(errno);
 			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', ctx:'%p', try:'1', func:'%s'): ERROR: COULD NOT acquire TRY-READ lock for Fence events (errno='%d'): '%s'", __func__, pthread_self(), f_ptr, IS_PRESENT(thread_ctx_ptr)?thread_ctx_ptr:0, func, errno, err_str);
 			free(err_str);
 		}
 	} else {
 		lock_state = pthread_rwlock_rdlock(&(f_ptr->fence_events.rwlock));
 		if (lock_state == 0) {
#ifdef __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', ctx:'%p', func:'%s'): SUCCESS: READ lock for Fence events acquired...", __func__, pthread_self(), f_ptr, IS_PRESENT(thread_ctx_ptr)?thread_ctx_ptr:0, func);
#endif
			goto return_locked;
		} else {
 			char *err_str = thread_error(errno);
 			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', ctx:'%p', func:'%s'): ERROR: COULD NOT acquire READ lock for Fence events (errno='%d'): '%s'", __func__, pthread_self(), f_ptr, IS_PRESENT(thread_ctx_ptr)?thread_ctx_ptr:0, func, errno, err_str);
 			free(err_str);
 		}
 	}

 	return_wont_lock:
	_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_WONTLOCK)

	return_locked:
	if (IS_PRESENT(thread_ctx_ptr)) PutIntoLockedObjectsStore (thread_ctx_ptr->ht_ptr, (void *)f_ptr);
	_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_LOCKED)

	return_already_locked_by_this_thread:
	_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_LOCKED_BY_THIS_THREAD)

 }

inline UFSRVResult *
FenceEventsLockRWCtx (ThreadContext *thread_ctx_ptr, Fence *f_ptr, int try_flag, UFSRVResult *res_ptr, const char *func)
{
	int lock_state;

	if (IS_PRESENT(thread_ctx_ptr)) {
		if (IsObjectInLockedObjectsStore(thread_ctx_ptr->ht_ptr, f_ptr)) {
			lock_state = 0;
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', ctx:'%p', try:'%i', func:'%s'): NOTICE: NOT LOCKING: ALREADY IN STORE", __func__, pthread_self(),  f_ptr, IS_PRESENT(thread_ctx_ptr)?thread_ctx_ptr:0, try_flag, func);
			goto return_already_locked_by_this_thread;
		}
	}

	if (try_flag) {
		lock_state = pthread_rwlock_trywrlock(&(f_ptr->fence_events.rwlock));
		if (lock_state == 0) {
#ifdef __UF_FULLDEBUG
      syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', ctx:'%p', try:'1', func:'%s'): SUCCESS: TRY-WRITE/READ lock for Fence events acquired...", __func__, pthread_self(), f_ptr, IS_PRESENT(thread_ctx_ptr)?thread_ctx_ptr:0, func);
#endif
			goto return_locked;
		} else {
			char *err_str = thread_error(errno);
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', ctx:'%p', try:'1', func:'%s'): ERROR: COULD NOT acquire TRY-WRITE/READ lock for Fence events (errno='%d'): '%s'", __func__, pthread_self(),  f_ptr, IS_PRESENT(thread_ctx_ptr)?thread_ctx_ptr:0, func, errno, err_str);
			free(err_str);
		}
	} else {
		lock_state = pthread_rwlock_wrlock(&(f_ptr->fence_events.rwlock));
		if (lock_state == 0) {
#ifdef __UF_FULLDEBUG
      syslog (LOG_DEBUG, "%s (pid:'%lu', o:'%p', ctx:'%p', func:'%s'): SUCCESS: WRITE/READ lock for Fence events acquired...",__func__, pthread_self(), f_ptr, IS_PRESENT(thread_ctx_ptr)?thread_ctx_ptr:0, func);
#endif
			goto return_locked;
		} else {
			char *err_str = thread_error(errno);
			syslog (LOG_DEBUG, "%s (pid:'%lu', o:'%p', ctx:'%p', func:'%s'): ERROR: COULD NOT acquire WRITE/READ lock for Fence events (errno='%d'): '%s'", __func__, pthread_self(), f_ptr, IS_PRESENT(thread_ctx_ptr)?thread_ctx_ptr:0, func, errno, err_str);
			free (err_str);
		}
	}

	return_wont_lock:
	_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_WONTLOCK)

	return_locked:
	if (IS_PRESENT(thread_ctx_ptr)) PutIntoLockedObjectsStore (thread_ctx_ptr->ht_ptr, (void *)f_ptr);
	_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_LOCKED)

	return_already_locked_by_this_thread:
	_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_LOCKED_BY_THIS_THREAD)

}

inline UFSRVResult *
FenceEventsUnLockCtx (ThreadContext *thread_ctx_ptr, Fence *f_ptr, UFSRVResult *res_ptr)
{
	int lock_state = pthread_rwlock_unlock(&(f_ptr->fence_events.rwlock));
	if (lock_state == 0) {
#ifdef __UF_FULLDEBUG
    syslog(LOG_DEBUG, "%s: (pid:'%lu', o:'%p', ctx:'%p'): SUCCESS: RELEASED WRITE/READ lock for Fence events...", __func__, pthread_self(), f_ptr, IS_PRESENT(thread_ctx_ptr)?thread_ctx_ptr:0);
#endif
		if (IS_PRESENT(thread_ctx_ptr)) RemoveFromLockedObjectsStore (thread_ctx_ptr->ht_ptr, (void *)f_ptr);
		_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_LOCKED)
	} else {
		char *err_str = thread_error(errno);
		syslog(LOG_DEBUG, "%s: (pid:'%lu', o:'%p', ctx:'%p'): ERROR: COULD NOT RELEASE WRITE/READ lock for Fence events (errno='%d'): '%s'", __func__, pthread_self(),  f_ptr, IS_PRESENT(thread_ctx_ptr)?thread_ctx_ptr:0, errno, err_str); free(err_str);
	}

	_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_WONTLOCK)

}

//---END LOCKING-------------------------

//static entity at the base of the Base Fence Registry.
Fence *broadcast_fence_ptr;

inline static InstanceHolderForFenceStateDescriptor *_FindFenceInUserListByID (const List *const, unsigned long);//const unsigned long);
inline static Fence *_FindFenceInUserListByCanonicalName (const List *const lst_ptr, const char *fence_canonical_name);
static unsigned _CheckIntraBaseFencesAndAdd (Session *, const LocationDescription *, unsigned long);
static bool _IsBaseLocValid (Session *, const char *);
static char *_MakeCanonicalFenceName(LocationDescription *, unsigned long, const char *, unsigned, char *);

static UFSRVResult *_ProcessUserAllowedToJoinFence(InstanceHolderForSession *instance_sesn_ptr, InstanceHolderForFence *instance_f_ptr, unsigned long call_flags);

static void SummariseFenceConfiguration (List *, const char *) __attribute__((unused));

static inline void _ClearInvalidUserId (Session *sesn_ptr_carrier, Fence *, redisReply *redis_ptr_invalid);
static inline bool _ExtractUserIdUserNameFromListCacheRecord (char *raw_cache_field, PairOfUserIdUserName *pair);
inline static Fence *_InstateUsersListCacheRecordsForFence (Session *sesn_ptr_carrier, List *fence_user_list_ptr, EnumFenceCollectionType user_fence_list_type, InstanceHolderForFence *instance_f_ptr, CollectionDescriptorPair *collection_pair_ptr/*redisReply **sesn_ptr_list, size_t list_count*/, unsigned call_flags);
static inline FenceRawSessionList *_ConstructRawUsersListForFence (Session *sesn_ptr, Fence *f_ptr, List *fence_user_list_ptr, unsigned long fence_call_flags, FenceRawSessionList *raw_sesn_list_ptr);
static inline int _CrossCheckFenceInSessionFenceListByFenceId (Session *sesn_ptr, List *sesn_fence_ist_ptr, unsigned long fence_id);
static inline int _CrossCheckSessionInFenceUserListByUserId (Fence *f_ptr, List *fence_user_list_ptr, unsigned long user_id);

#ifdef _LOCAL_FENCE_EVENT_QUEUE
static void * _DestructFenceMessageQueue (Fence *);
static void *_m_AddMessageToFenceQueue (SessionService *, Fence *, Message *const);
#endif

static inline size_t _CleanUpFaultyUserEntriesForFence (Session *sesn_ptr, Fence *f_ptr, unsigned long userid_loaded_for, CollectionDescriptor *collection_ptr,  EnumFenceCollectionType list_type);
static Fence *_RemoveUserFromUserFenceAndUnlinkUser(Fence *, InstanceHolderForSession *, bool);
static Fence *_RemoveUserFromBaseFenceAndUnlinkUser(Fence *, InstanceHolderForSession *, bool);
static Fence *_RemoveUserFromBaseFence (InstanceHolderForSession *, Fence *, unsigned long);//unsigned long);
static Fence *_RemoveUserFromUserFence (InstanceHolderForSession *, Fence *, unsigned long);//unsigned long);
static inline InstanceHolderForFenceStateDescriptor * _RemoveFenceFromList (List *, unsigned long);
inline static unsigned _CrossCheckUserInFenceAndFenceInUser(Fence *, Session *);
inline static void _DestructUserFence (Session *sesn_ptr, InstanceContextForFence *, unsigned long);

//-----------------------------------------------------------

void
InitialiseMaserFenceRegistries (void)
{
  if (HashTableLockingInstantiate(&(FenceRegistryIdHashTable), (offsetof(Fence, fence_id)), sizeof(unsigned long), HASH_ITEM_NOT_PTR_TYPE, "FenceRegistry", (ItemExtractor)GetClientContextData)) {
    syslog(LOG_INFO, "%s: SUCCESS: FenceRegistryId HashTable Instantiated: key_offset: '%ld'. key_size: '%ld'", __func__, FenceRegistryIdHashTable.fKeyOffset, FenceRegistryIdHashTable.fKeySize);
  } else {
    syslog(LOG_ERR, "%s: ERROR (errno: '%d'): COULD NOT INITIALISE FenceRegistryId HashTable: TERMINATING...", __func__, errno);

    exit(-1);
  }

  if (HashTableLockingInstantiate(&(FenceRegistryCanonicalNameHashTable), (offsetof(Fence, fence_location.canonical_name)), KEY_SIZE_ZERO, HASH_ITEM_IS_PTR_TYPE, "FenceRegistryCanonicalName", (ItemExtractor)GetClientContextData)) {
    syslog(LOG_INFO, "%s: SUCCESS: FenceRegistryCanonicalName HashTable Instantiated: key_offset: '%ld'. key_size: '%ld'", __func__, FenceRegistryIdHashTable.fKeyOffset, FenceRegistryIdHashTable.fKeySize);
  } else {
    syslog(LOG_ERR, "%s: ERROR (errno: '%d'): COULD NOT INITIALISE FenceRegistryCanonicalName HashTable: TERMINATING...", __func__, errno);

    exit(-1);
  }

	Fence *f_ptr = NULL;

	InstanceHolder *instance_holder_ptr = RecyclerGet(FencePoolTypeNumber(), (ContextData *)NULL, FENCE_CALLFLAG_BASEFENCE);/*won't generate id*/
	if (unlikely(IS_EMPTY(instance_holder_ptr))) {
		syslog(LOG_DEBUG, "%s: Failed to create Broadcast Fence. Aborting", __func__);
		exit (-1);
	}

	f_ptr = GetInstance(instance_holder_ptr);

	f_ptr->fence_location.display_banner_name	=	strdup("broadcast");
	f_ptr->fence_location.canonical_name			=	strdup("unfacd Broadcast Fence");
	f_ptr->when																=	time(NULL);
	f_ptr->fence_id														=	1;

	broadcast_fence_ptr												=	f_ptr;

	syslog(LOG_DEBUG, "%s: Global Broadcast Fence '%s' successfully created...", __func__, f_ptr->fence_location.display_banner_name );

	return;

}

/**
 * 	@brief: Main interface for checking whether a user is permitted to change a fence state. Normally used for pre-screening
 * 	requests coming down the wire. As it currently stands, user has to be a member of the fence to begin with, hence why on
 * 	success the FenceStateDescripror is returned.
 *
 *	@returns NULL, RESULT_TYPE_ERR: if fence doesn't exist
 *	@returns Fence:, RESULT_TYPE_ERR:	if either membership or ownership fails
 *	@returns InstanceHolderForFenceStateDescriptor: if either membership or ownership succeeded
 *
 * 	@locked sesn_ptr: by caller
 * 	@locks f_ptr: by downstream functions and remains locked after this function exists if FENCE_CALLFLAG_KEEP_FENCE_LOCKED is set
 */
UFSRVResult *
IsUserAllowedToChangeFence (Session *sesn_ptr, unsigned long fid, const char *cname, bool *fence_lock_state, unsigned long fence_call_flags)
{
	bool lock_already_owned = false;
	unsigned 	fence_call_flags_final;
	unsigned	rescode;
	Fence 		*f_ptr;
  InstanceHolderForFence *instance_f_ptr = NULL;

	fence_call_flags_final = FENCE_CALLFLAG_SEARCH_BACKEND|FENCE_CALLFLAG_HASH_FENCE_LOCALLY|FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE;
	if (fence_call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED)	fence_call_flags_final |= (FENCE_CALLFLAG_KEEP_FENCE_LOCKED|FENCE_CALLFLAG_LOCK_FENCE_BLOCKING);

	if (fid > 0) {
		FindFenceById (sesn_ptr, fid,	fence_call_flags_final);
    instance_f_ptr = (InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr);
		lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_PROG_LOCKED_BY_THIS_THREAD));
	} else if	(IS_STR_LOADED(cname)) {
		FindFenceByCanonicalName (sesn_ptr, cname, &lock_already_owned, fence_call_flags_final);
    instance_f_ptr = (InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr);
	}

	if (IS_EMPTY(instance_f_ptr)) {
#ifdef __UF_TESTING
		syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', uname:'%s', fid:'%lu'}: FenceStateSync COMMAND IGNORED: COULD NOT LOCATE FENCE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_USERNAME(sesn_ptr), fid);
#endif

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_DOESNT_EXIST)
	}

	f_ptr = FenceOffInstanceHolder(instance_f_ptr);

	//FENCE NOW LOCKED if FENCE_CALLFLAG_KEEP_FENCE_LOCKED was set

	rescode = RESCODE_FENCE_FENCE_MEMBERSHIP;
	InstanceHolderForFenceStateDescriptor *instance_fstate_ptr = IsUserMemberOfThisFence (SESSION_FENCE_LIST_PTR(sesn_ptr), f_ptr, 0/*DONT_LOCK*/);
	if (IS_EMPTY(instance_fstate_ptr))  goto exit_error;

	if (fence_call_flags&FENCE_CALLFLAG_CHECK_FENCEOWNERSHIP) {
		rescode = RESCODE_FENCE_OWNERSHIP;
		if (IsFenceOwnedByUser(sesn_ptr, f_ptr))	goto exit_success;
		else																			goto exit_error;
	}

	//TODO: LOST state of lock_already_owned due to rescode assignment? Is still the case?

	exit_success:
	if (!(fence_call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED))	if (!lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
	if (likely(IS_PRESENT(fence_lock_state)))	*fence_lock_state = lock_already_owned;
	_RETURN_RESULT_SESN(sesn_ptr, instance_fstate_ptr, RESULT_TYPE_SUCCESS, rescode)

	exit_error:
	if (!(fence_call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED))	if (!lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
	if (likely(IS_PRESENT(fence_lock_state)))	*fence_lock_state = lock_already_owned;

	if (rescode == RESCODE_FENCE_OWNERSHIP) { //note we return fence state if error was related to ownership
		_RETURN_RESULT_SESN(sesn_ptr, instance_fstate_ptr, RESULT_TYPE_ERR, rescode)
	} else {
		_RETURN_RESULT_SESN(sesn_ptr, instance_f_ptr, RESULT_TYPE_ERR, rescode)
	}
}

/**
 * 	@brief: General population routine for newly created fences. These reflect values that are user-settable
 */
void
UpdateFenceAssignments (Session *sesn_ptr, Fence *f_ptr_processed, ClientContextData *context_ptr)
{
	FenceRecord *fence_record_ptr	=	(FenceRecord *)context_ptr;

	if (fence_record_ptr->has_fence_type)			UpdateFenceTypeAssignment (sesn_ptr, f_ptr_processed, fence_record_ptr->fence_type, 0);
	if (fence_record_ptr->has_privacy_mode)		UpdateFencePrivacyModeAssignment (sesn_ptr, f_ptr_processed, fence_record_ptr->privacy_mode, 0);
	if (fence_record_ptr->has_delivery_mode)	UpdateFenceDeliveryModeAssignment (sesn_ptr, f_ptr_processed, fence_record_ptr->delivery_mode, 0);
	if (fence_record_ptr->has_join_mode)			UpdateFenceJoinModeAssignment (sesn_ptr, f_ptr_processed, fence_record_ptr->join_mode, 0);
	if (fence_record_ptr->has_maxmembers)			UpdateFenceMaxUsersAssignment (sesn_ptr, f_ptr_processed, fence_record_ptr->maxmembers, 0);
	if (IS_PRESENT(fence_record_ptr->avatar))	UpdateFenceAvatarAssignment (sesn_ptr, f_ptr_processed, fence_record_ptr->avatar, 0);

	bool list_semantic;//false indicates the default "blacklisting"

	if (IS_PRESENT(fence_record_ptr->presentation) && fence_record_ptr->presentation->has_list_semantics)
	{
		list_semantic=(fence_record_ptr->presentation->list_semantics==FENCE_RECORD__PERMISSION__LIST_SEMANTICS__WHITELIST)?true:false;
    UpdateFencePermissionListSemanticAssignment(sesn_ptr, f_ptr_processed,
                                                FENCE_PERMISSIONS_PRESENTATION_PTR(f_ptr_processed), list_semantic,
                                                FENCE_CALLFLAG_EMPTY, NULL);
	}

	if (IS_PRESENT(fence_record_ptr->membership) && fence_record_ptr->presentation->has_list_semantics)
	{
		list_semantic=(fence_record_ptr->membership->list_semantics==FENCE_RECORD__PERMISSION__LIST_SEMANTICS__WHITELIST)?true:false;
    UpdateFencePermissionListSemanticAssignment(sesn_ptr, f_ptr_processed,
                                                FENCE_PERMISSIONS_MEMBERSHIP_PTR(f_ptr_processed), list_semantic,
                                                FENCE_CALLFLAG_EMPTY, NULL);
	}

	if (IS_PRESENT(fence_record_ptr->messaging) && fence_record_ptr->presentation->has_list_semantics)
	{
		list_semantic=(fence_record_ptr->messaging->list_semantics==FENCE_RECORD__PERMISSION__LIST_SEMANTICS__WHITELIST)?true:false;
    UpdateFencePermissionListSemanticAssignment(sesn_ptr, f_ptr_processed,
                                                FENCE_PERMISSIONS_MESSAGING_PTR(f_ptr_processed), list_semantic,
                                                FENCE_CALLFLAG_EMPTY, NULL);
	}

	if (IS_PRESENT(fence_record_ptr->attaching) && fence_record_ptr->presentation->has_list_semantics)
	{
		list_semantic=(fence_record_ptr->attaching->list_semantics==FENCE_RECORD__PERMISSION__LIST_SEMANTICS__WHITELIST)?true:false;
    UpdateFencePermissionListSemanticAssignment(sesn_ptr, f_ptr_processed,
                                                FENCE_PERMISSIONS_ATTACHING_PTR(f_ptr_processed), list_semantic,
                                                FENCE_CALLFLAG_EMPTY, NULL);
	}

	if (IS_PRESENT(fence_record_ptr->calling) && fence_record_ptr->presentation->has_list_semantics)
	{
		list_semantic=(fence_record_ptr->calling->list_semantics==FENCE_RECORD__PERMISSION__LIST_SEMANTICS__WHITELIST)?true:false;
    UpdateFencePermissionListSemanticAssignment(sesn_ptr, f_ptr_processed,
                                                FENCE_PERMISSIONS_CALLING_PTR(f_ptr_processed), list_semantic,
                                                FENCE_CALLFLAG_EMPTY, NULL);
	}

}

/**
 * 	@brief: this is designed to assign avatar as part of the fence creation process. It doesnt generate events, or broadcast
 * 	that specific event.
 * 	Check IsUserAllowedToChangeFenceAvatar() for similar treatment but in the context of update event.
 * 	@flags:
 * 	FENCE_CALLFLAG_WRITEBACK_DATA_TO_BACKEND:
 * 	@locked sesn_ptr:
 * 	@locked RW f_ptr:
 */
UFSRVResult *
UpdateFenceAvatarAssignment (Session *sesn_ptr, Fence *f_ptr, AttachmentRecord *record_ptr, unsigned long fence_call_flags)
{

	if (strlen(record_ptr->id)>CONFIG_MAX_FAVATAR_SIZE)
	{
#ifdef __UF_TESTING
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fo:'%p', fid:'%lu'}: ERROR: ATTACHMENT ID TOO LONG", __func__, pthread_self(), sesn_ptr,  SESSION_ID(sesn_ptr), f_ptr, FENCE_ID(f_ptr));
#endif
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_NAMING);
	}

	AttachmentDescriptor attachment_descriptor_out = {0};
	if (IS_PRESENT(GetAttachmentDescriptorEphemeral(sesn_ptr, record_ptr->id, false, &attachment_descriptor_out))) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fo:'%p', fid:'%lu', blocb_id:'%s'}: ERROR: ATTACHMENT ID ALREADY EXISTS", __func__, pthread_self(), sesn_ptr,  SESSION_ID(sesn_ptr), f_ptr, FENCE_ID(f_ptr),  record_ptr->id);
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOGIC_IDENTICAL_RESOURCE);
	}

	if (AttachmentDescriptorGetFromProto(sesn_ptr, record_ptr, 0/*eid*/, &attachment_descriptor_out, true/*encode_key*/)) {
		DbAttachmentStore (sesn_ptr, &attachment_descriptor_out, FENCE_ID(f_ptr), 1);//ufsrv instance doesn't currently support lru-caching attachments

		//this should be removed, because at fence creation time there is no fence cache record yet
		if (fence_call_flags&FENCE_CALLFLAG_WRITEBACK_DATA_TO_BACKEND) {
			CacheBackendSetFenceAttribute(sesn_ptr, FENCE_ID(f_ptr), "avatar", attachment_descriptor_out.id);
		}

    if (unlikely(SESSION_RESULT_TYPE_ERROR(sesn_ptr)))	{_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);}//todo: delete db backend record for attachment??

    //update memory store
    if (IS_STR_LOADED(FENCE_AVATAR(f_ptr)))	free (FENCE_AVATAR(f_ptr));
    FENCE_AVATAR(f_ptr)=strdup(attachment_descriptor_out.id);

		AttachmentDescriptorDestruct(&attachment_descriptor_out, true, false);
	}
	else {_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);}

	exit_success:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_DATA_UPDATED);
}

/**
 * 	@brief: Localises the process for updating memory-resident data model for fence cname
 * 	param flag_build_cname: if true, cname_new should passed as NULL
 * 	@param cname_new: preallocated, except when flag_build_cname is set
 * 	@locked f_ptr:
 * 	@dynamic_memory EXPORTS/IMPORTS:
 * 	@dynamic_memory:	DEALLOCATES previously allocated strings for fence names
 */
bool
UpdateFenceNameAssignment (Session *sesn_ptr, InstanceHolderForFence *instance_f_ptr, const char *fname_new, char *cname_new, bool flag_build_cname, unsigned long fence_call_flags)
{
	char *cname_new_final = NULL;
	Fence *f_ptr = FenceOffInstanceHolder(instance_f_ptr);

	if (flag_build_cname) {
		asprintf(&cname_new_final, "%s%s", FENCE_BASELOC(f_ptr), fname_new);
	}
	else	cname_new_final = cname_new;

	free	(FENCE_DNAME(f_ptr));
	FENCE_DNAME(f_ptr) = strdup(fname_new);

	RemoveFromHash(&FenceRegistryCanonicalNameHashTable, (void *)(InstanceHolderForFence *)instance_f_ptr);
	free (FENCE_CNAME(f_ptr));

	FENCE_CNAME(f_ptr)=cname_new_final;
	if ((AddToHash(&FenceRegistryCanonicalNameHashTable, (void *)(InstanceHolderForFence *)instance_f_ptr)) != NULL) {
		return true;
	}

	//this is of course a breach in data space as we are no longer are able to lookup new hash, even though it is present on the fence
	syslog(LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu', fo:'%p', fid:'%lu'} ERROR: DATA SPACE IMBALANCE: COULD NOT HASH FCNAME", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), f_ptr, FENCE_ID(f_ptr));

	return false;

}

/**
 *	@locked f_ptr:
 *	@locked sesn_ptr:
 *	@unlocks: none
 */
UFSRVResult *
UpdateFenceTypeAssignment (Session *sesn_ptr, Fence *f_ptr, FenceRecord__FenceType fence_type, unsigned long fence_call_flags)
{
	switch (fence_type)
	{
		case FENCE_RECORD__FENCE_TYPE__GEO:
			F_ATTR_SET(f_ptr->attrs, F_ATTR_BASEFENCE);
			break;

		case FENCE_RECORD__FENCE_TYPE__USER:
			F_ATTR_SET(f_ptr->attrs, F_ATTR_USERFENCE);
			break;

		default:
			syslog(LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu', fo:'%p', fid:'%lu', fence_type:'%d'} ERROR: UNKNOWN FENCE TYPE SEPCIFIED: DEFAULTING TO USERFENCE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), f_ptr, FENCE_ID(f_ptr), fence_type);
			F_ATTR_SET(f_ptr->attrs, F_ATTR_USERFENCE);
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_UKNOWN_TYPE);
	}

	if (fence_call_flags&FENCE_CALLFLAG_WRITEBACK_DATA_TO_BACKEND)
	{
			//TODO: also implement INTERBROADCAST
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_DATA_UPDATED);
}

UFSRVResult *
UpdateFenceMaxUsersAssignment (Session *sesn_ptr, Fence *f_ptr, int maxusers, unsigned long fence_call_flags)
{

	FENCE_MAX_MEMBERS(f_ptr)=maxusers;

	if (fence_call_flags&FENCE_CALLFLAG_WRITEBACK_DATA_TO_BACKEND)
	{
			//TODO: also implement INTERBROADCAST
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_DATA_UPDATED);
}

UFSRVResult *
UpdateFencePrivacyModeAssignment (Session *sesn_ptr, Fence *f_ptr, FenceRecord__PrivacyMode privacy_mode, unsigned long fence_call_flags)
{
	switch (privacy_mode)
	{
		case FENCE_RECORD__PRIVACY_MODE__PRIVATE:
			F_ATTR_SET(f_ptr->attrs, F_ATTR_PRIVATE);
			break;

		case FENCE_RECORD__PRIVACY_MODE__PUBLIC:
			F_ATTR_SET(f_ptr->attrs, F_ATTR_PUBLIC);
			break;

		default:
			syslog(LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu', fo:'%p', fid:'%lu', fence_type:'%d'} ERROR: UNKNOWN FENCE PRIVACY MODE SEPCIFIED: DEFAULTING TO PUBLIC", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), f_ptr, FENCE_ID(f_ptr), privacy_mode);
			F_ATTR_SET(f_ptr->attrs, F_ATTR_PUBLIC);
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_UKNOWN_TYPE);
	}

	if (fence_call_flags&FENCE_CALLFLAG_WRITEBACK_DATA_TO_BACKEND)
	{
			//TODO: also implement INTERBROADCAST
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_DATA_UPDATED);
}

//todo:  also see SetFenceDeliveryModeFromProto (uint64_t *setting, FenceRecord__DeliveryMode delivery_mode)
UFSRVResult *
UpdateFenceDeliveryModeAssignment (Session *sesn_ptr, Fence *f_ptr, FenceRecord__DeliveryMode delivery_mode, unsigned long fence_call_flags)
{
	switch (delivery_mode)
	{
		case FENCE_RECORD__DELIVERY_MODE__BROADCAST:
			F_ATTR_SET(f_ptr->attrs, F_ATTR_BROADCAST);

			F_ATTR_UNSET(f_ptr->attrs, F_ATTR_BROADCAST_ONEWAY);
			F_ATTR_UNSET(f_ptr->attrs, F_ATTR_MANY_TO_MANY);
			break;

		case FENCE_RECORD__DELIVERY_MODE__BROADCAST_ONEWAY:
			F_ATTR_SET(f_ptr->attrs, F_ATTR_BROADCAST_ONEWAY);

			F_ATTR_UNSET(f_ptr->attrs, F_ATTR_BROADCAST);
			F_ATTR_UNSET(f_ptr->attrs, F_ATTR_MANY_TO_MANY);
			break;

		case FENCE_RECORD__DELIVERY_MODE__MANY:
			F_ATTR_SET(f_ptr->attrs, F_ATTR_MANY_TO_MANY);

			F_ATTR_UNSET(f_ptr->attrs, F_ATTR_BROADCAST);
			F_ATTR_UNSET(f_ptr->attrs, F_ATTR_BROADCAST_ONEWAY);
			break;

		default:
			syslog(LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu', fo:'%p', fid:'%lu', fence_type:'%d'} ERROR: UNKNOWN FENCE DELIVERY MODE SEPCIFIED: DEFAULTING TO MANY_TO_MANY", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), f_ptr, FENCE_ID(f_ptr), delivery_mode);
			F_ATTR_SET(f_ptr->attrs, F_ATTR_MANY_TO_MANY);
			F_ATTR_UNSET(f_ptr->attrs, F_ATTR_BROADCAST);
			F_ATTR_UNSET(f_ptr->attrs, F_ATTR_BROADCAST_ONEWAY);
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_UKNOWN_TYPE);
	}

	if (fence_call_flags&FENCE_CALLFLAG_WRITEBACK_DATA_TO_BACKEND)
	{
			//TODO: also implement INTERBROADCAST <- currently done in IsUserAllowedTo....
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_DATA_UPDATED);
}

UFSRVResult *
UpdateFenceJoinModeAssignment (Session *sesn_ptr, Fence *f_ptr, FenceRecord__JoinMode join_mode, unsigned long fence_call_flags)
{
	switch (join_mode)
	{
		case FENCE_RECORD__JOIN_MODE__OPEN:
			F_ATTR_SET(f_ptr->attrs, F_ATTR_JOINMODE_OPEN);
			break;

		case FENCE_RECORD__JOIN_MODE__INVITE:
			F_ATTR_SET(f_ptr->attrs, F_ATTR_JOINMODE_INVITE_ONLY);
			break;

		case FENCE_RECORD__JOIN_MODE__OPEN_WITH_KEY:
			F_ATTR_SET(f_ptr->attrs, F_ATTR_JOINMODE_OPEN|F_ATTR_JOINMODE_KEY);
			break;

		case FENCE_RECORD__JOIN_MODE__INVITE_WITH_KEY:
			F_ATTR_SET(f_ptr->attrs, F_ATTR_JOINMODE_INVITE_ONLY|F_ATTR_JOINMODE_KEY);
			break;

		default:
			syslog(LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu', fo:'%p', fid:'%lu', fence_type:'%d'} ERROR: UNKNOWN FENCE JOIN MODE SEPCIFIED: DEFAULTING TO OPEN", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), f_ptr, FENCE_ID(f_ptr), join_mode);
			F_ATTR_SET(f_ptr->attrs, F_ATTR_JOINMODE_OPEN);
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_UKNOWN_TYPE);
	}

	if (fence_call_flags&FENCE_CALLFLAG_WRITEBACK_DATA_TO_BACKEND)
	{
			//TODO: also implement INTERBROADCAST
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_DATA_UPDATED);
}

/**
 * 	@brief: Main interface function for changing fence display name across all model stores
 * 	@dynamic_memory cname_new: INSTANTIATED and used by reference when successful, otherwise deallocated
 * 	@locked sesn_ptr: by caller
 * 	@locks Fence *: if FENCE_CALLFLAG_LOCK_FENCE is set
 * 	@unlocks Fence *: UNLESS  FENCE_CALLFLAG_KEEP_FENCE_LOCKED IS SET
 */
UFSRVResult *
IsUserAllowedToChangeFenceName (Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, const char *fname_new, unsigned long fence_call_flags, FenceEvent *fence_event_ptr_out)
{
	unsigned rescode;

	if (fence_call_flags&FENCE_CALLFLAG_LOCK_FENCE) {
		FenceEventsLockRWCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fence_state_ptr), _LOCK_TRY_FLAG_FALSE, SESSION_RESULT_PTR(sesn_ptr), __func__);
		if (SESSION_RESULT_TYPE_EQUAL(sesn_ptr, RESULT_TYPE_ERR))	goto exit_lock_error;
	}

	bool fence_lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_PROG_LOCKED_BY_THIS_THREAD));

	if ((strcasecmp(fname_new, FENCE_DNAME(FENCESTATE_FENCE(fence_state_ptr))) == 0))	goto exit_fname_identical;

	CheckFenceNameForValidity(sesn_ptr, FENCESTATE_FENCE(fence_state_ptr), fname_new);

	if (unlikely(SESSION_RESULT_TYPE_ERROR(sesn_ptr)))	goto exit_naming_error;

	FenceEvent *fence_event_ptr = RegisterFenceEvent(sesn_ptr, FENCESTATE_FENCE(fence_state_ptr), EVENT_TYPE_FENCE_DNAME,  NULL, 0/*LOCK_FLAG*/, fence_event_ptr_out);
	if (IS_PRESENT(fence_event_ptr)) {
#define REDIS_COMMAND_ARGV_SIZE 	6 //first 2 are for command and arg then for each attr/value pair
#define REDIS_COMMAND_ATTR_SIZE 	2
#define REDIS_COMMAND_VALUE_SIZE 	2

					char 	*cname_new;
		const char 	*attributes[REDIS_COMMAND_ATTR_SIZE] __unused, //fixed elements in redis
								*values[REDIS_COMMAND_VALUE_SIZE] __unused;		//actual new values

		const char	*combined[REDIS_COMMAND_ARGV_SIZE];		//actual storage pool for all the elements and values converted to str
		size_t 			combined_len[REDIS_COMMAND_ARGV_SIZE]	=	{0};	//actual storage pool for len of each converted str

		CollectionDescriptorPair collection_argv_argvlen	=	{
				.first={(collection_t **)combined, 			REDIS_COMMAND_ARGV_SIZE},
				.second={(collection_t **)combined_len, REDIS_COMMAND_ARGV_SIZE}
		};

		asprintf(&cname_new, "%s%s", FENCE_BASELOC(FENCESTATE_FENCE(fence_state_ptr)), fname_new);

		attributes[0]="dname"; 		attributes[1] = "cname";
		values[0]		= fname_new;	values[1]		=	cname_new;

		CacheBackendUpdateFenceRegistry (sesn_ptr, FENCESTATE_FENCE(fence_state_ptr), fname_new, cname_new);
//Currently not in use because the above function takes care of all relevant cachebackend updates as one transaction
//so this is hold over just to demo how to use the CacheBackendSetFenceAttributesByCollection function as it has useful technique
//		CacheBackendSetFenceAttributesByCollection(sesn_ptr, FENCE_ID(FENCESTATE_FENCE(fence_state_ptr)),
//																							&((CollectionDescriptor){(collection_t **)attributes, REDIS_COMMAND_ATTR_SIZE}),
//																							&((CollectionDescriptor){(collection_t**)values, 			REDIS_COMMAND_VALUE_SIZE}),
//																							&collection_argv_argvlen);

		if (unlikely(SESSION_RESULT_TYPE_ERROR(sesn_ptr)))	{free (cname_new);	goto exit_backend_update_error;}

		exit_success:
		//update memory store. note the 'false' flag -> 'cname_new' ownership transferred, fname_new will be duplicated
		UpdateFenceNameAssignment (sesn_ptr, FENCESTATE_INSTANCE_HOLDER(fence_state_ptr), fname_new, cname_new, false, CALLFLAGS_EMPTY);

    DbBackendInsertUfsrvEvent ((UfsrvEvent *)fence_event_ptr);

		//TODO: we my need to have a flag on this in case we dont want to broadcast
		InterBroadcastFenceDnameMessage (sesn_ptr, (ClientContextData *)FENCESTATE_FENCE(fence_state_ptr), fence_event_ptr, COMMAND_ARGS__UPDATED);

		if (fence_call_flags&FENCE_CALLFLAG_LOCK_FENCE) {
			if (!(fence_call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED))	if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fence_state_ptr), SESSION_RESULT_PTR(sesn_ptr));
		}

		//TODO: LOST LOCK OWNERSHIP
		_RETURN_RESULT_SESN(sesn_ptr, fence_event_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_RESOURCE_UPDATED)
	}
	else	goto event_generation_error;


	exit_backend_update_error:
	rescode=SESSION_RESULT_CODE(sesn_ptr);
	goto exit_unlock;

	event_generation_error:
	rescode = SESSION_RESULT_CODE(sesn_ptr);
	goto exit_unlock;

	exit_naming_error:
	rescode = SESSION_RESULT_CODE(sesn_ptr);
	goto exit_unlock;

	exit_fname_identical:
	rescode = RESCODE_FENCE_IDENTICAL;
	goto exit_unlock;

	exit_unlock:
	if (fence_call_flags&FENCE_CALLFLAG_LOCK_FENCE) {
		if (!(fence_call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED))	if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fence_state_ptr), SESSION_RESULT_PTR(sesn_ptr));
	}
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)

	exit_lock_error:
	rescode = SESSION_RESULT_CODE(sesn_ptr);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)

#undef REDIS_COMMAND_ARGV_SIZE
}

/**
 * 	@brief: Main interface function for changing fence avatar across all model stores.
 * 	Check UpdateFenceAvatarAssignment()which is invoked at fence creation time.
 * 	TODO: refactor UpdateFenceAvatarAssignment() so they are invoked from one function
 * 	TODO: Try and move away from exposing DataMessage at this level
 * 	@locked sesn_ptr: by caller
 * 	@locks Fence *: if FENCE_CALLFLAG_LOCK_FENCE is set
 * 	@unlocks Fence *: UNLESS FENCE_CALLFLAG_KEEP_FENCE_LOCKED IS SET. Done regardless of error.
 */
UFSRVResult *
IsUserAllowedToChangeFenceAvatar (Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, DataMessage *data_msg_ptr, unsigned long fence_call_flags, FenceEvent *fence_event_ptr_out)
{
	unsigned 							rescode;
	AttachmentDescriptor 	attachment_descriptor_out	=	{0};

	if (fence_call_flags&FENCE_CALLFLAG_LOCK_FENCE) {
		FenceEventsLockRWCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fence_state_ptr), _LOCK_TRY_FLAG_FALSE, SESSION_RESULT_PTR(sesn_ptr), __func__);
		if (SESSION_RESULT_TYPE_EQUAL(sesn_ptr, RESULT_TYPE_ERR))	goto exit_lock_error;
	}

	bool fence_lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_PROG_LOCKED_BY_THIS_THREAD));

	CheckAvatarForValidityFromProto (sesn_ptr, FENCESTATE_FENCE(fence_state_ptr), data_msg_ptr);

	if (unlikely(SESSION_RESULT_TYPE_ERROR(sesn_ptr)))	goto exit_validity_error;

	AttachmentPointer 		*attachment_ptr				=	data_msg_ptr->group->avatar;

	if (IS_PRESENT(GetAttachmentDescriptorEphemeral(sesn_ptr, attachment_ptr->ufid, false, &attachment_descriptor_out))) goto exit_already_exists_error;

	if (TEMPAttachmentDescriptorGetFromProto(sesn_ptr, attachment_ptr, 0/*eid*/, &attachment_descriptor_out, true/*encode_key*/)) {
		DbAttachmentStore(sesn_ptr, &attachment_descriptor_out, FENCE_ID(FENCESTATE_FENCE(fence_state_ptr)), 1);//ufsrv instance doesn't currently support lru-caching attachments
	}
	else goto exit_data_error;

	FenceEvent *fence_event_ptr = RegisterFenceEvent(sesn_ptr, FENCESTATE_FENCE(fence_state_ptr), EVENT_TYPE_FENCE_AVATAR,  NULL, 0/*LOCK_FLAG*/, fence_event_ptr_out);
	if (IS_PRESENT(fence_event_ptr)) {
		CacheBackendSetFenceAttribute(sesn_ptr, FENCE_ID(FENCESTATE_FENCE(fence_state_ptr)), "avatar", attachment_descriptor_out.id);

		if (unlikely(SESSION_RESULT_TYPE_ERROR(sesn_ptr)))	goto exit_backend_update_error;

    DbBackendInsertUfsrvEvent ((UfsrvEvent *)fence_event_ptr);

		exit_success:
		//update memory store
		if (IS_STR_LOADED(FENCE_AVATAR(FENCESTATE_FENCE(fence_state_ptr))))	free(FENCE_AVATAR(FENCESTATE_FENCE(fence_state_ptr)));
		FENCE_AVATAR(FENCESTATE_FENCE(fence_state_ptr)) = strdup(attachment_descriptor_out.id);

		InterBroadcastFenceAvatarMessage (sesn_ptr,
																			&((ContextDataPair){(ClientContextData *)FENCESTATE_FENCE(fence_state_ptr), (ClientContextData *)&attachment_descriptor_out}),
																			fence_event_ptr, COMMAND_ARGS__UPDATED);

		if (fence_call_flags&FENCE_CALLFLAG_LOCK_FENCE) {
			if (!(fence_call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED))	if (!fence_lock_already_owned) FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fence_state_ptr), SESSION_RESULT_PTR(sesn_ptr));
		}

		//TODO: LOST LOCK OWNERSHIP
		_RETURN_RESULT_SESN(sesn_ptr, fence_event_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_RESOURCE_UPDATED)
	} else	goto event_generation_error;


	exit_backend_update_error:
	rescode=SESSION_RESULT_CODE(sesn_ptr);
	goto exit_unlock;

	event_generation_error:
	rescode=SESSION_RESULT_CODE(sesn_ptr);
	goto exit_unlock;

	exit_naming_error:
	rescode=SESSION_RESULT_CODE(sesn_ptr);
	goto exit_unlock;

	exit_already_exists_error:
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', blocb_id:'%s'}: ERROR: ATTACHMENT ID ALREADY EXISTS", __func__, pthread_self(), sesn_ptr,  attachment_ptr->ufid);
	rescode=RESCODE_LOGIC_IDENTICAL_RESOURCE;
	goto exit_unlock;

	exit_data_error:
	rescode=RESCODE_PROG_INCONSISTENT_DATA;
	goto exit_unlock;

	exit_validity_error:
	rescode=SESSION_RESULT_CODE(sesn_ptr);
	goto exit_unlock;

	exit_unlock:
	if (fence_call_flags&FENCE_CALLFLAG_LOCK_FENCE) {
		if (!(fence_call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED))	if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fence_state_ptr), SESSION_RESULT_PTR(sesn_ptr));
	}
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)

	exit_lock_error:
	rescode=SESSION_RESULT_CODE(sesn_ptr);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)

}

/**
 * 	@brief: Main interface function for changing fence message expiry across all model stores.
 * 	@locked sesn_ptr: by caller
 * 	@locks Fence *: if FENCE_CALLFLAG_LOCK_FENCE is set
 * 	@unlocks Fence *: UNLESS FENCE_CALLFLAG_KEEP_FENCE_LOCKED IS SET. Done regardless of error.
 */
UFSRVResult *
IsUserAllowedToChangeFenceMessageExpiry (Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, time_t msg_expiry_in_seconds, unsigned long fence_call_flags, FenceEvent *fence_event_ptr_out)
{
	unsigned 							rescode;

	if (fence_call_flags&FENCE_CALLFLAG_LOCK_FENCE) {
		FenceEventsLockRWCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fence_state_ptr), _LOCK_TRY_FLAG_FALSE, SESSION_RESULT_PTR(sesn_ptr), __func__);
		if (SESSION_RESULT_TYPE_EQUAL(sesn_ptr, RESULT_TYPE_ERR))	goto exit_lock_error;
	}

	bool fence_lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_PROG_LOCKED_BY_THIS_THREAD));

	FenceEvent *fence_event_ptr = RegisterFenceEvent(sesn_ptr, FENCESTATE_FENCE(fence_state_ptr), EVENT_TYPE_FENCE_EXPIRY,  NULL, 0/*LOCK_FLAG*/, fence_event_ptr_out);
	if (IS_PRESENT(fence_event_ptr)) {
		char msg_expiry[sizeof(UINT64_LONGEST_STR)+2] = {0};
		ultoa(msg_expiry_in_seconds, msg_expiry, 10);

		CacheBackendSetFenceAttribute(sesn_ptr, FENCE_ID(FENCESTATE_FENCE(fence_state_ptr)), "expiry", msg_expiry);

		if (unlikely(SESSION_RESULT_TYPE_ERROR(sesn_ptr)))	goto exit_backend_update_error;

		exit_success:
		//update memory store
		FENCE_MSG_EXPIRY(FENCESTATE_FENCE(fence_state_ptr)) = msg_expiry_in_seconds;
    DbBackendInsertUfsrvEvent ((UfsrvEvent *)fence_event_ptr);
		InterBroadcastFenceMsgExpiry (sesn_ptr,
																	&((ContextDataPair){(ClientContextData *)fence_state_ptr, (ClientContextData *)NULL}),
																	fence_event_ptr, COMMAND_ARGS__UPDATED);

		if (fence_call_flags&FENCE_CALLFLAG_LOCK_FENCE) {
			if (!(fence_call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED))	if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fence_state_ptr), SESSION_RESULT_PTR(sesn_ptr));
		}

		//TODO: LOST LOCK OWNERSHIP
		_RETURN_RESULT_SESN(sesn_ptr, fence_event_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_RESOURCE_UPDATED)
	}
	else	goto event_generation_error;

	exit_backend_update_error:
	rescode=SESSION_RESULT_CODE(sesn_ptr);
	goto exit_unlock;

	event_generation_error:
	rescode=SESSION_RESULT_CODE(sesn_ptr);
	goto exit_unlock;

	exit_naming_error:
	rescode=SESSION_RESULT_CODE(sesn_ptr);
	goto exit_unlock;

	exit_validity_error:
	rescode=SESSION_RESULT_CODE(sesn_ptr);
	goto exit_unlock;

	exit_unlock:
	if (fence_call_flags&FENCE_CALLFLAG_LOCK_FENCE)
	{
		if (!(fence_call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED))	if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(fence_state_ptr), SESSION_RESULT_PTR(sesn_ptr));
	}
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)

	exit_lock_error:
	rescode=SESSION_RESULT_CODE(sesn_ptr);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)

}

/**
 * 	@brief: Resolve rules around user's ability to receive invitation to join a Geofence.
 * 	@param sesn_ptr_inviter: Could be another user, or a system user. Call flag will spcify
 * 	@param sesn_ptr: invited user
 *
 * 	@locked sesn_ptr: must be locked by the user
 * 	@locks f_ptr:
 * 	@unlocks fptr:
 *
 *	@returns Fence *:
 *
 * 	@call_flag FENCE_CALLFLAG_ROAMING_GEOFENCE: Operation as a result or roaming changes. Inviter is ufsrvsystem user
 */
UFSRVResult *
IsUserAllowedGeoFenceInvite(InstanceHolderForSession *instance_sesn_ptr, Session *sesn_ptr_inviter, unsigned long fence_call_flags)
{
	bool 				fence_already_locked			=	false;
	Fence				*f_ptr										= NULL;
	InstanceHolderForFence *instance_f_ptr    = NULL;
	UFSRVResult *res_ptr									=	NULL;

	Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	////create Intra fences as necessary
	_CheckIntraBaseFencesAndAdd(sesn_ptr, &(sesn_ptr->sservice.user.user_details.user_location), 0);

	size_t cname_sz = SizeofCanonicalFenceName(sesn_ptr, NULL);
	char canonical_fence_name[cname_sz]; memset (canonical_fence_name, 0, sizeof(canonical_fence_name));

	_MakeCanonicalFenceName(&(sesn_ptr->sservice.user.user_details.user_location), SESSION_USERID(sesn_ptr), NULL, USER_ATTRIBUTE_IS_SET(sesn_ptr, USERATTRIBUTE_DEFINES_USERZONE), canonical_fence_name);

	//only local search, as _CheckIntraBaseFencesAndAdd should have added fences as necessary
	if ((instance_f_ptr = FindBaseFenceByCanonicalName(sesn_ptr, canonical_fence_name, &fence_already_locked, FENCE_CALLFLAG_KEEP_FENCE_LOCKED))) {
		if ((fence_call_flags&FENCE_CALLFLAG_ROAMING_GEOFENCE))	SessionTransferAccessContext (sesn_ptr, sesn_ptr_inviter, 0);
		f_ptr = FenceOffInstanceHolder(instance_f_ptr);
		res_ptr = AddMemberToInvitedFenceList (instance_sesn_ptr, instance_f_ptr, sesn_ptr_inviter, FENCE_CALLFLAG_WRITEBACK_DATA_TO_BACKEND);
		if (_RESULT_TYPE_SUCCESS(res_ptr)) {
			unsigned long invited_eids[1];
			CollectionDescriptor invited_eids_collection = {(collection_t **)invited_eids, 1};
			invited_eids[0] = (uintptr_t)_RESULT_USERDATA(res_ptr);

			res_ptr = MarshalFenceInvitation(&(InstanceContextForSession){instance_sesn_ptr, sesn_ptr}, instance_f_ptr, &((WebSocketMessage){{0}}), NULL, &invited_eids_collection, NULL, 0);

			if ((fence_call_flags&FENCE_CALLFLAG_ROAMING_GEOFENCE))	SessionResetTransferAccessContext (sesn_ptr_inviter);

			if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));

			if (_RESULT_TYPE_SUCCESS(res_ptr)) {_RETURN_RESULT_SESN(sesn_ptr, instance_f_ptr, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);}
			else goto exit_error;
		}

		if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
	}

	exit_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

/**
 * 	@brief: Scans the location's geo. components (country, etc...) and infers if new base fences are to be added to the network.
 * 	This designed to work in response to location changes reported by user.
 * 	Current implementation joins user automatically to the lowest locality component, including all necessary fence creation.
 *
 * 	@locks RW f_ptr: For each fence that corresponds with a given location component
 * 	@unlocks f_ptr:
 *
 * 	@dynamic_memory: IMPORTS a 'char *' canonical_fence_name which is freed herein
 *
 * 	@returns RESCODE_USER_FENCE_JOINED: when a user is joined to fence
 * 	@returns FenceStatedescriptor * where user was joined, or already in
 */
UFSRVResult *
IsUserAllowedToJoinGeoFence (InstanceHolderForSession *instance_sesn_ptr, LocationDescription *ld_ptr)
{
	unsigned count_of_new_base_fences = 0;

	Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	////create Intra fences as necessary
	count_of_new_base_fences = _CheckIntraBaseFencesAndAdd(sesn_ptr, ld_ptr, 0);

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): CREATED '%u' new IntraBaseFence", __func__, pthread_self(), sesn_ptr->session_id, count_of_new_base_fences );
#endif

	bool 				fence_already_locked			=	false;
	size_t cname_sz = SizeofCanonicalFenceName(sesn_ptr, NULL);
	char canonical_fence_name[cname_sz]; memset (canonical_fence_name, 0, sizeof(canonical_fence_name));

	Fence	*f_ptr								        = NULL;
  InstanceHolder  *instance_f_ptr = NULL,
                  *instance_fstate_ptr = NULL;

	_MakeCanonicalFenceName(ld_ptr, SESSION_USERID(sesn_ptr), NULL, USER_ATTRIBUTE_IS_SET(sesn_ptr, USERATTRIBUTE_DEFINES_USERZONE), canonical_fence_name);

	//only local search
	if ((instance_f_ptr = FindBaseFenceByCanonicalName(sesn_ptr, canonical_fence_name, &fence_already_locked, FENCE_CALLFLAG_KEEP_FENCE_LOCKED))) {
		f_ptr = (Fence *)GetInstance(instance_f_ptr);

		UFSRVResult *res_ptr = _ProcessUserAllowedToJoinFence(instance_sesn_ptr, instance_f_ptr, FENCE_CALLFLAG_JOIN);

		//in case of logical error, we take care of unlocking
		if (_RESULT_TYPE_ERROR(res_ptr) && _RESULT_CODE_EQUAL(res_ptr, RESCODE_PROG_NULL_POINTER))	goto exit_no_result;

		HandleJoinFence (&(InstanceContextForSession){instance_sesn_ptr, sesn_ptr}, (InstanceHolderForFenceStateDescriptor *)_RESULT_USERDATA(res_ptr), &(WebSocketMessage){.type=WEB_SOCKET_MESSAGE__TYPE__REQUEST, .request=NULL}, NULL, JT_GEO_BASED, res_ptr);
		if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_USER_FENCE_ALREADYIN) || SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_USER_FENCE_JOINED)) {
      instance_fstate_ptr = (InstanceHolder *) SESSION_RESULT_USERDATA(sesn_ptr);
      f_ptr = FENCESTATE_FENCE(((FenceStateDescriptor *)GetInstance(instance_fstate_ptr)));
    }
		else
		  f_ptr = (Fence *)SESSION_RESULT_USERDATA(sesn_ptr);

		if (IS_PRESENT(f_ptr) && !fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));
		return SESSION_RESULT_PTR(sesn_ptr);

		exit_no_result:
		if (!fence_already_locked)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_NOOP, RESCODE_PROG_NULL_POINTER)
	}

	//NOT RELEVANT ANYMORE //brand new base Fence. rare condition as intra above catches most
	syslog(LOG_ERR, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR: FindBaseFenceByCanonicalName() returned NULL: something is seriously wrong", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

/**
 * 	@brief: Main entry point for joining users into EXISTING fences. invoked in the context of a given id supplied by user.
 * 	Caller must pass FENCE_CALLFLAG_JOIN in order to actually join.

 *	@param sesn_ptr: The user for whom command is being executed
 *  @return InstanceHolder of type FenceStateDescriptor
 * 	@call_flags FENCE_CALLFLAG_JOIN: the context of the request is user join

 * 	@locks RW f_ptr: if FENCE_CALLFLAG_JOIN is passed we lock the fence
 * 	@unlocks f_ptr: unless FENCE_CALLFLAG_KEEP_FENCE_LOCKED is passed, unless RESCODE_PROG_NULL_POINTER is returned
 * 	@locked sesn_ptr: must be locked in the caller's environment
 */
UFSRVResult *
IsUserAllowedToJoinFenceById(InstanceHolderForSession *instance_sesn_ptr, const unsigned long fence_id, unsigned long call_flags, bool *fence_lock_state)
{
	unsigned long	fence_call_flags_final	= 0;
	Fence			*f_ptr											= NULL;

	fence_call_flags_final = FENCE_CALLFLAG_SEARCH_BACKEND|FENCE_CALLFLAG_HASH_FENCE_LOCALLY|FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE;
	if (call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED)	fence_call_flags_final |= (FENCE_CALLFLAG_KEEP_FENCE_LOCKED|FENCE_CALLFLAG_LOCK_FENCE_BLOCKING);

	Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	FindFenceById(sesn_ptr, fence_id, fence_call_flags_final);
  InstanceHolderForFence *instance_f_ptr = SESSION_RESULT_USERDATA(sesn_ptr);

	if (IS_EMPTY((instance_f_ptr))) {
		if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST)|| SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_RESOURCE_NULL)) {
#ifdef __UF_TESTING
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', fid:'%lu'): COULD NOT FIND FENCE...",		__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), fence_id);
#endif
			SESSION_RETURN_RESULT(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_DOESNT_EXIST)
		}
		else 	{SESSION_RETURN_RESULT(sesn_ptr, NULL, RESULT_TYPE_ERR, SESSION_RESULT_CODE(sesn_ptr))}
	}

  bool fence_lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_PROG_LOCKED_BY_THIS_THREAD));
  f_ptr = FenceOffInstanceHolder(instance_f_ptr);

	//>>> Fence RW LOCKED

	UFSRVResult *res_ptr = _ProcessUserAllowedToJoinFence(instance_sesn_ptr, instance_f_ptr, call_flags);

	//in case of logical error, we take care of unlocking
	if (res_ptr->result_code == RESCODE_PROG_NULL_POINTER)	{
		if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
	} else {
		if (!(call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED))	if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
		if (likely(IS_PRESENT(fence_lock_state)))	*fence_lock_state = fence_lock_already_owned;
	}

	return res_ptr;

}

/**
 * 	@brief: Main interface function for changing fence message expiry across all model stores.
 * 	@locked sesn_ptr: by caller
 * 	@locks Fence *: by caller
 * 	@unlocks None
 */
UFSRVResult *
IsUserAllowedToChangeFenceMaxMembers (Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, int32_t maxmembers, unsigned long fence_call_flags, FenceEvent *fence_event_ptr_out)
{
	unsigned 							rescode;

	FenceEvent *fence_event_ptr = RegisterFenceEvent(sesn_ptr, FENCESTATE_FENCE(fence_state_ptr), EVENT_TYPE_FENCE_MAXMEMBERS,  NULL, 0/*LOCK_FLAG*/, fence_event_ptr_out);
	if (IS_PRESENT(fence_event_ptr)) {
		char maxmembers_setting[sizeof(UINT64_LONGEST_STR)+2] = {0};
		ultoa(maxmembers, maxmembers_setting, 10);

		CacheBackendSetFenceAttribute(sesn_ptr, FENCE_ID(FENCESTATE_FENCE(fence_state_ptr)), "maxusers", maxmembers_setting);

		if (unlikely(SESSION_RESULT_TYPE_ERROR(sesn_ptr)))	goto exit_backend_update_error;

		exit_success:
		FENCE_MAX_MEMBERS(FENCESTATE_FENCE(fence_state_ptr)) = maxmembers;
    DbBackendInsertUfsrvEvent ((UfsrvEvent *)fence_event_ptr);
		InterBroadcastFenceMaxMembers (sesn_ptr,
																	&((ContextDataPair){(ClientContextData *)fence_state_ptr, (ClientContextData *)NULL}),
																	fence_event_ptr, COMMAND_ARGS__UPDATED);

		_RETURN_RESULT_SESN(sesn_ptr, fence_event_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_RESOURCE_UPDATED)
	}
	else	goto event_generation_error;

	exit_backend_update_error:
	rescode=SESSION_RESULT_CODE(sesn_ptr);
	goto exit_error;

	event_generation_error:
	rescode=SESSION_RESULT_CODE(sesn_ptr);
	goto exit_error;

	exit_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)

}

UFSRVResult *
IsUserAllowedToChangeFenceDeliveryMode (Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, int delivery_mode, unsigned long fence_call_flags, FenceEvent *fence_event_ptr_out)
{
	unsigned 							rescode;

	if (isFenceDeliveryModelEquals(FENCESTATE_FENCE(fence_state_ptr), (FenceRecord__DeliveryMode) delivery_mode)) {
		goto exit_same_delivery_mode;
	}

	FenceEvent *fence_event_ptr = RegisterFenceEvent(sesn_ptr, FENCESTATE_FENCE(fence_state_ptr), EVENT_TYPE_FENCE_DELIVERY_MODE,  NULL, 0/*LOCK_FLAG*/, fence_event_ptr_out);
	if (IS_PRESENT(fence_event_ptr)) {
		char attributes_setting[sizeof(UINT64_LONGEST_STR)+2] = {0};
		uint64_t attributes = FENCE_ATTRIBUTES(FENCESTATE_FENCE(fence_state_ptr));
		SetFenceDeliveryModeFromProto (&attributes, (FenceRecord__DeliveryMode) delivery_mode);

		ultoa(attributes, attributes_setting, 10);

		CacheBackendSetFenceAttribute(sesn_ptr, FENCE_ID(FENCESTATE_FENCE(fence_state_ptr)), "type", attributes_setting);

		if (unlikely(SESSION_RESULT_TYPE_ERROR(sesn_ptr)))	goto exit_backend_update_error;

		exit_success:
    DbBackendInsertUfsrvEvent ((UfsrvEvent *)fence_event_ptr);
		UpdateFenceDeliveryModeAssignment (sesn_ptr, FENCESTATE_FENCE(fence_state_ptr), delivery_mode, CALLFLAGS_EMPTY);

		InterBroadcastFenceDeliveryMode(sesn_ptr,
																	 &((ContextDataPair){(ClientContextData *)fence_state_ptr, (ClientContextData *)NULL}),
																	 fence_event_ptr, COMMAND_ARGS__UPDATED);

		_RETURN_RESULT_SESN(sesn_ptr, fence_event_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_RESOURCE_UPDATED)
	}
	else	goto event_generation_error;

	exit_same_delivery_mode:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOGIC_IDENTICAL_RESOURCE)

	exit_backend_update_error:
	rescode=SESSION_RESULT_CODE(sesn_ptr);
	goto exit_error;

	event_generation_error:
	rescode=SESSION_RESULT_CODE(sesn_ptr);
	goto exit_error;

	exit_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)

}

/**
 * 	@brief: This interprets the result code from a previous join request and marshals the enduser related  response. All model data
 * 	will have been changed by now.  Each result code carries a different meaning so data will be overloaded as necessary.
 *	@param fence_state_ptr: Fence must be wrapped in this, even if there no actual join involved The meaning will be taken from rescode
 * 	@param res_ptr: contains the outcome of a previous test on user's eligibility to joining given fence
 * 	@locked: Fence *: must be locked by the caller, except where res_ptr indicates certain errors
 * 	@unlocks Fence *:
 * 	@returns FenceStateDescriptor *, but can also return Fence *. see context below
 */
UFSRVResult *
HandleJoinFence (InstanceContextForSession *ctx_ptr, InstanceHolderForFenceStateDescriptor *instance_fstate_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received, EnumFenceJoinType join_type, UFSRVResult *res_ptr)
{
	//>>>>>>>>f_ptr MAY BE LOCKED depending on return value on success only <<<<<<<<<<<
	FenceStateDescriptor *fstate_ptr = (FenceStateDescriptor *)GetInstance(instance_fstate_ptr);
	Fence *f_ptr = FENCESTATE_FENCE(fstate_ptr);
	Session *sesn_ptr = ctx_ptr->sesn_ptr;

	switch (res_ptr->result_code)
	{
		case RESCODE_USER_FENCE_FULL:
			_RETURN_RESULT_SESN(sesn_ptr, f_ptr, RESULT_TYPE_NOOP, RESCODE_USER_FENCE_FULL)

			//invite only + user not on invite list
		case RESCODE_FENCE_INVITATION_LIST:
			_RETURN_RESULT_SESN(sesn_ptr, f_ptr, RESULT_TYPE_ERR, RESCODE_FENCE_INVITATION_LIST)

		case RESCODE_USER_FENCE_WRITEOFF:
			_RETURN_RESULT_SESN(sesn_ptr, f_ptr, RESULT_TYPE_NOOP, RESCODE_USER_FENCE_WRITEOFF)

		case RESCODE_USER_FENCE_LOCATION:
			_RETURN_RESULT_SESN(sesn_ptr, f_ptr, RESULT_TYPE_NOOP, RESCODE_USER_FENCE_LOCATION)

		case RESCODE_USER_FENCE_KEY:
			_RETURN_RESULT_SESN(sesn_ptr, f_ptr, RESULT_TYPE_NOOP, RESCODE_USER_FENCE_KEY)

		case RESCODE_USER_FENCE_CANJOIN:
			//TODO: fence_state_ptr is actually the Fence * here... check return
			_RETURN_RESULT_SESN(sesn_ptr, (Fence *)res_ptr->result_user_data, RESULT_TYPE_NOOP, RESCODE_USER_FENCE_CANJOIN)

		case RESCODE_USER_FENCE_ALREADYIN:
				//this could be because the fence's SessionList was pre-loaded from  the backend. We just reannounce that to members
				//no further local state mods are done
#ifdef __UF_TESTING
				syslog (LOG_DEBUG, "%s (pid:'%lu', cid:'%lu', sesn_fence_list_sz:'%d', fence_ulist_sz:'%d'): WARNING: DOUBLE JOIN: 'uid:'%lu' IS ALREADY IN 'bid:%lu'",
					__func__, pthread_self(), SESSION_ID(sesn_ptr), SESSION_FENCE_LIST_SIZE(sesn_ptr), FENCE_SESSIONS_LIST_SIZE(f_ptr), SESSION_USERID(sesn_ptr), FENCE_ID(f_ptr));
#endif

				//TODO: given the potential for state being out for sync for others, we should send fence state synch to the whole fence, not just this user
				MarshalFenceStateSync (ctx_ptr, fstate_ptr, wsm_ptr_received, NULL, CALLFLAGS_EMPTY);

				_RETURN_RESULT_SESN(sesn_ptr, instance_fstate_ptr, RESULT_TYPE_ERR, RESCODE_USER_FENCE_ALREADYIN)

		case RESCODE_USER_FENCE_JOINED:
			if (_RESULT_TYPE_SUCCESS(res_ptr)) {
				//this is the ideal case
#ifdef __UF_TESTING
				syslog (LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): SUCCESS: Joining 'uid='%lu' into 'bid=%lu'", __func__, pthread_self(), SESSION_ID(sesn_ptr), UfsrvUidGetSequenceId(&SESSION_UFSRVUIDSTORE(sesn_ptr)), FENCE_ID(f_ptr));
#endif

				//set a copy aside, otherwise it gets overwritten by subsequent invocations on the Session
				//Fence *f_ptr_processed=(Fence *)_RESULT_USERDATA(res_ptr);
				UFSRVResult res = {.result_user_data=f_ptr, .result_code=res_ptr->result_code, .result_type=res_ptr->result_type};

				if (join_type == JT_GEO_BASED)						MarshalGeoFenceJoinToUser (ctx_ptr, NULL, fstate_ptr,   &((WebSocketMessage){0}), 0);
				else if (join_type == JT_USER_INITIATED)	MarshalFenceJoinToUser (ctx_ptr, fstate_ptr, &((WebSocketMessage){.type=WEB_SOCKET_MESSAGE__TYPE__RESPONSE}),  data_msg_ptr_received);
				else if (join_type == JT_INVITED)					MarshalFenceJoinInvitedToUser (ctx_ptr, fstate_ptr, &((WebSocketMessage){0}),  data_msg_ptr_received);
				MarshalFenceStateSyncForJoin (ctx_ptr, sesn_ptr, FENCESTATE_INSTANCE_HOLDER(fstate_ptr), 0);

				_RETURN_RESULT_SESN(sesn_ptr, instance_fstate_ptr, RESULT_TYPE_SUCCESS, RESCODE_USER_FENCE_JOINED)
			} else {
				//TODO: unsupported condition
				//fence should not need unlocking under error condition
				_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_USER_FENCE_JOINED)
			}
		break;

		case RESCODE_LOGIC_EMPTY_RESOURCE:
		default:

			//fence should be unlocked/or could not be fetched as this is an error condition, for which the
			//called function automatically unlocks if applicable

			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', fo:'%p', fid:'%lu'):  INVALID RESCODE JOIN REQUEST...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), f_ptr, FENCE_ID(f_ptr));
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

/**
 * 	@brief: main  entry point for joining users into EXISTING fences. invoked in the context of a given id supplied by user.
 * 	Caller must pass FENCE_CALLFLAG_JOIN in order to actually join.
 * 	@return InstanceHolder of type FenceStateDescriptor
 * 	@call_flags: FENCE_CALLFLAG_KEEP_FENCE_LOCKED
 * 	@locks RW f_ptr: indirectly via flags
 * 	@unlocks f_ptr: unless FENCE_CALLFLAG_KEEP_FENCE_LOCKED is set by caller
 */
UFSRVResult *
IsUserAllowedToJoinFenceByCanonicalName(InstanceHolderForSession *instance_sesn_ptr_this, const char *fence_canonical_name, unsigned long call_flags)
{
	bool fence_locked_already = false;
	Session *sesn_ptr_this = SessionOffInstanceHolder(instance_sesn_ptr_this);
	SessionService *ss_ptr = &(sesn_ptr_this->sservice);

	//this will lock fence but doesn't  return it in locked state unless KEE_LOCKED flag is set
	InstanceHolderForFence *instance_f_ptr = FindUserFenceByCanonicalName(sesn_ptr_this, fence_canonical_name, &fence_locked_already, FENCE_CALLFLAG_KEEP_FENCE_LOCKED|FENCE_CALLFLAG_HASH_FENCE_LOCALLY|FENCE_CALLFLAG_SEARCH_BACKEND|FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE);
	if (IS_EMPTY(instance_f_ptr)) {
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s (pid='%lu' cid='%lu'): ERROR: COULD FIND FENCE for canonical name '%s'", __func__, pthread_self(), sesn_ptr_this->session_id, fence_canonical_name);
#endif
		_RETURN_RESULT(ss_ptr, NULL, RESULT_TYPE_NOOP, RESCODE_PROG_NULL_POINTER)
	}

  Fence *f_ptr = FenceOffInstanceHolder(instance_f_ptr);
	//f_ptr RW LOCKED

	UFSRVResult *res_ptr = _ProcessUserAllowedToJoinFence(instance_sesn_ptr_this, instance_f_ptr, call_flags);

	//in case of logical error, we take care of unlocking
	if (res_ptr->result_code == RESCODE_PROG_NULL_POINTER) {
		if (!fence_locked_already) FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr_this));
	} else {
		if (!(call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED))	if (!fence_locked_already)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr_this));
	}

	return res_ptr; //todo: fence already-locked state lost

}

/**
 * 	@brief: Resolves rules around user's ability to join an existing fence. Works with two frontend functions above.
 * 	All joins must funnel through this.
 *
 * 	@call_flags FENCE_CALLFLAG_JOIN: we proceed to join the user if allowed so
 *
 *	@returns InstanceHolder of type FenceStateDescripto with rescode RESCODE_USER_FENCE_JOINED and RESCODE_USER_FENCE_ALREADYIN
 *	@returns Fence   with rescode RESCODE_USER_FENCE_CANJOIN
 *
 * 	@locks: NONE
 * 	@unlocks: NONE
 * 	@locked sesn_ptr: must be locked by the caller.
 * 	@locked RW f_ptr: must be locked by the caller.
 */
static UFSRVResult *
_ProcessUserAllowedToJoinFence(InstanceHolderForSession *instance_sesn_ptr, InstanceHolderForFence *instance_f_ptr, unsigned long call_flags)
{
  InstanceHolderForFenceStateDescriptor *instance_fstate_ptr   = NULL;
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
  Fence *f_ptr = FenceOffInstanceHolder(instance_f_ptr);

#define FLAG_FENCE_LOCK_FALSE false

	if (IS_PRESENT((instance_fstate_ptr = IsUserMemberOfThisFence(&(SESSION_FENCE_LIST(sesn_ptr)), f_ptr, FLAG_FENCE_LOCK_FALSE)))) {
		//Extra integrity check
		if (FindUserInFenceSessionListByID(&FENCE_USER_SESSION_LIST(f_ptr), f_ptr, SESSION_ID(sesn_ptr))) {
			_RETURN_RESULT_SESN(sesn_ptr, instance_fstate_ptr, RESULT_TYPE_ERR, RESCODE_USER_FENCE_ALREADYIN)
		} else {
			syslog (LOG_DEBUG, LOGSTR_FENCE_MISSING_SESSION, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), f_ptr, FENCE_ID(f_ptr), LOGCODE_FENCE_MISSING_SESSION); //data integrity issue
			_RETURN_RESULT_SESN(sesn_ptr, instance_f_ptr, RESULT_TYPE_ERR, RESCODE_FENCE_SESSION_INTEGRITY)
		}
	}

	if (FindUserInFenceSessionListByID(&FENCE_USER_SESSION_LIST(f_ptr), f_ptr, SESSION_ID(sesn_ptr))) {
		syslog (LOG_DEBUG, LOGSTR_SESSION_MISSING_FENCE, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), f_ptr, FENCE_ID(f_ptr), LOGCODE_SESSION_MISSING_FENCE);
		_RETURN_RESULT_SESN(sesn_ptr, instance_f_ptr, RESULT_TYPE_ERR, RESCODE_SESSION_FENCE_INTEGRITY)
	}

	//general case for invite only
	if (FENCE_IS_INVITE_ONLY(f_ptr) && !IsUserOnFenceInvitedList (f_ptr, SESSION_USERID(sesn_ptr))) {
    if (FENCE_OWNER_UID(f_ptr) == SESSION_USERID(sesn_ptr) && !FENCE_HAS_REACHED_MAX_MEMBERS_SIZE(f_ptr)) {
#ifdef __UF_TESTING
      syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fid:'%lu'}: FENCE INVITE-ONLY: ALLOWING OWNER BACK IN", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), FENCE_ID(f_ptr));
#endif

      goto allow_user_join;
    }

#ifdef __UF_TESTING
	syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fid:'%lu'}: FENCE INVITE-ONLY: USER NOT ON INVITED LIST.", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), FENCE_ID(f_ptr));
#endif
			_RETURN_RESULT_SESN(sesn_ptr, f_ptr, RESULT_TYPE_ERR, RESCODE_FENCE_INVITATION_LIST)
	}

	if (FENCE_HAS_MAX_MEMBERS_SIZE_SET(f_ptr)) {
		if (FENCE_HAS_REACHED_MAX_MEMBERS_SIZE(f_ptr)) {
#ifdef __UF_TESTING
		syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', fid:'%lu'}: REACHED MAXIMUM USER COUNT: configured max users: '%lu'. Current user count: '%d'", __func__, pthread_self(), sesn_ptr, FENCE_ID(f_ptr), f_ptr->max_users, f_ptr->fence_user_sessions_list.nEntries);
#endif

			_RETURN_RESULT_SESN(sesn_ptr, f_ptr, RESULT_TYPE_ERR, RESCODE_USER_FENCE_FULL)
		}
	}

	//second check based on WriteoffList
	{
#if 0
		//not implemented yet
		_RETURN_RESULT_SESN(sesn_ptr, f_ptr, RESULT_TYPE_ERR, RESCODE_USER_FENCE_WRITEOFF);
#endif
	}

	//third check on locality test
	{
#if 0
		//not implemented yet
		_RETURN_RESULT_SESN(sesn_ptr, f_ptr, RESULT_TYPE_ERR, RESCODE_USER_FENCE_LOCATION);
#endif
	}

  allow_user_join:
  if (call_flags&FENCE_CALLFLAG_JOIN) {
    InstanceHolder *instance_fstate_ptr = AddUserToThisFenceListWithLinkback(instance_sesn_ptr, instance_f_ptr, SESSION_FENCE_LIST_PTR(sesn_ptr), &(f_ptr->fence_user_sessions_list),  EVENT_TYPE_FENCE_USER_JOINED, CALL_FLAG_WRITEBACK_FENCE_DATA_TO_BACKEND);
    FenceStateDescriptor *fstate_ptr = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);

    RemoveUserFromInvitedList(instance_sesn_ptr, fstate_ptr,
                              &((FenceEvent) {.event_type=EVENT_TYPE_FENCE_USER_INVITED_JOINED}),
                              FENCE_CALLFLAG_WRITEBACK_DATA_TO_BACKEND | FENCE_CALLFLAG_TRANSFER_INVITE_CONTEXT);

    _RETURN_RESULT_SESN(sesn_ptr, instance_fstate_ptr, RESULT_TYPE_SUCCESS, RESCODE_USER_FENCE_JOINED)
  } else {
    _RETURN_RESULT_SESN(sesn_ptr, f_ptr, RESULT_TYPE_SUCCESS, RESCODE_USER_FENCE_CANJOIN)
  }

#undef FLAG_FENCE_LOCK_FALSE
}

/**
 * 	This is a generalised implementation of AddUserToExistingFenceAndLinkToUser(Fence *f_ptr, Session *sesn_ptr, unsigned call_flags)
 *
 * 	@brief: establish two-way link between a user-fence list. User-Session Fences have many lists, but they all have the same semantics
 * 	IMPORTANT NO integrity check is done if user is already in Fence. This should be done in the calling environment.
*
*	@param call_flags:
*	CALL_FLAG_WRITEBACK_FENCE_DATA_TO_BACKEND update backend and broadcast event through msgqueue
*
*	@locks: None directly, but locks associated with getting type instances from the type pool are engaged
*	@locked sesn_ptr: must be locked in the caller's environment
*	@locked RW f_ptr: must be locked in the caller's environment
*	@unlocks: None.
*
*	@blocks_on: None
*
*	@dynamic_memory: Implicitly creates ListEntry * in both Session and Fence which are freed else where as part of removing user from fence
*
*	@call_flags CALL_FLAG_SESSION_LIST_CHECK_DUP_FENCE: checks for the existence of the Fence in the user's Session
*	@call_flags CALL_FLAG_FENCE_LIST_CHECK_DUP_SESSION: checks for the existence of user session in Fence's list
*	@call_flags CALL_FLAG_WRITEBACK_FENCE_DATA_TO_BACKEND: update and broadcast the event across the network
*
 */
InstanceHolderForFenceStateDescriptor *
AddUserToThisFenceListWithLinkback(InstanceHolderForSession *instance_sesn_ptr, InstanceHolderForFence *instance_f_ptr, List *user_fence_list_ptr, List *fence_user_list_ptr,  int event_type, unsigned call_flags)
{
	//integrity check
	Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
	Fence *f_ptr = FenceOffInstanceHolder(instance_f_ptr);

	if (call_flags&CALL_FLAG_FENCE_LIST_CHECK_DUP_SESSION) {
		if (_CrossCheckSessionInFenceUserListByUserId(f_ptr, fence_user_list_ptr, SESSION_USERID(sesn_ptr))) {
			syslog(LOG_NOTICE, "%s {pid:'%lu', o:'%p', cid:'%lu', fo:'%p', fid:'%lu'}: DUPLICATE: CROSS CHECKING SESSION IN FENCE LIST FOUND SESSION: RETURNING INSTANCE FROM user_fence_list", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), f_ptr, FENCE_ID(f_ptr));

			return (FindFenceStateInSessionFenceListByFenceId(sesn_ptr, user_fence_list_ptr, FENCE_ID(f_ptr)));
		}
	}

	//integrity check
	if (call_flags&CALL_FLAG_SESSION_LIST_CHECK_DUP_FENCE) {
		if (_CrossCheckFenceInSessionFenceListByFenceId (sesn_ptr, user_fence_list_ptr, FENCE_ID(f_ptr))) {
			syslog(LOG_NOTICE, "%s (pid:'%lu' o:'%p', cid:'%lu', fo:'%p', fid:'%lu'): DUPLICATE: CROSS CHECKING FENCE IN SESSION LIST FOUND FENCE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), f_ptr, FENCE_ID(f_ptr));

			return NULL;
		}
	}

	InstanceHolder *instance_fstate_ptr = RecyclerGet(FenceStateDescriptorPoolTypeNumber(), (ContextData *)instance_f_ptr, CALLFLAGS_EMPTY);
	if (unlikely(IS_EMPTY(instance_fstate_ptr))) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fo:'%p', fid:'%lu'}: ERROR: COULD NOT ALLOCATE FenceStateDescriptor type", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), f_ptr, FENCE_ID(f_ptr));

		return NULL;
	}

  FenceStateDescriptor *fence_state_ptr = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
  fence_state_ptr->instance_holder_fence = instance_f_ptr; //no need as it is done at GetInit by RecyclerGet()

	//preserve invited-by on this fence
  InstanceHolder *instance_fstate_ptr_invite = IsUserMemberOfThisFence(SESSION_INVITED_FENCE_LIST_PTR(sesn_ptr), f_ptr, false/*FLAG_FENCE_LOCK_FALSE*/);
	if (IS_PRESENT(instance_fstate_ptr_invite)) {
    FenceStateDescriptor *fstate_ptr_invite = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr_invite);
    memcpy (&(fence_state_ptr->invited_by), &(fstate_ptr_invite->invited_by), sizeof(UfsrvUid));
    fence_state_ptr->when_invited = fstate_ptr_invite->when_invited;
  }

	//2)link this Fence to User's List of Fences
	//fence is added by a proxy. The same fence can be in multiple instances of FenceStates across many users.
	//References are incremented every time a fence is referenced like this
	//The fence instance will live on for as long as it is referenced in a user's session list, until they explicitly leave
	//or inactivity rules are breached
	AddThisToList (user_fence_list_ptr, instance_fstate_ptr);
	FenceIncrementReference(instance_f_ptr, 1);

	//3)add this Session to Fence's List
	AddThisToList (fence_user_list_ptr, CLIENT_CTX_DATA(instance_sesn_ptr));
	SessionIncrementReference (instance_sesn_ptr, 1);

	if (call_flags&CALL_FLAG_WRITEBACK_FENCE_DATA_TO_BACKEND) {
		//TODO: this doesn't work with INVITED EVENT; has to be invoked seperately by the caller
		UpdateBackendFenceData (sesn_ptr, f_ptr, (void *)fence_state_ptr, event_type, &((FenceEvent){}));
	}

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', fo:'%p'}: SUCCESS: LINKED (uid:'%lu' fence_count:'%d') to (fid:'%lu' user_count:'%d')...", __func__, pthread_self(), sesn_ptr, f_ptr, SESSION_USERID(sesn_ptr), user_fence_list_ptr->nEntries, FENCE_ID(f_ptr), fence_user_list_ptr->nEntries);
#endif

	return instance_fstate_ptr;

}

/**
 * 	@brief:	Main entry point for making _user fence_ : no other function should be called before this one.
 * 	If fence already exists drops user in, otherwise it creates new one.
 * 	we allow fence name collisions as it is up to the user to decide how they want to live with that
 * 	@return InstanceHolderForFenceStateDescriptor when fenced JOINED, MADE, or ALREADY_IN
 * 	@return InstanceHolderForFence
 *
 * 	@call_flags FENCE_CALLFLAG_KEEP_FENCE_LOCKED:  return the fence in locked state for both new and existing fences.
 * 	@call_flags: FENCE_CALLFLAG_JOIN: the context of the request is a user joining/making fence. Affects locking mode.
 *
 * 	@locks WR f_ptr: As a side effect of of searching for Fence *.
 * 	@unlocks f_ptr: unless  FENCE_CALLFLAG_KEEP_FENCE_LOCKED is passed. ALSO automatically unlocks it if some logical/structural error with Fence *
 *
*/
UFSRVResult *
IsUserAllowedToMakeUserFence (InstanceHolderForSession *instance_sesn_ptr, const char *fence_banner, const char *baseloc_prefix, FenceContextDescriptor *fence_context_ptr, bool *fence_lock_state, unsigned long call_flags)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	if (!IS_STR_LOADED(fence_banner)) {
	  syslog (LOG_ERR, "%s: ERROR: INVALID fence_banner parameter", __func__);

	  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}

	//TODO: we risk invoking this function yet another time in the else block as we create a new fence as part of new fence instantiation
	//better we pass the canonical name, along with display name

	size_t cname_sz = SizeofCanonicalFenceName(sesn_ptr, fence_banner);
	if (unlikely(cname_sz == 0)) {
		syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', uid:'%lu', baseloc:'%s'}: ERROR: COULD NOT ESTABLISH CNAME SIZE", __func__, pthread_self(), sesn_ptr, SESSION_USERID(sesn_ptr), SESSION_BASELOC(sesn_ptr));

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}

	char userfence_canonical_name[cname_sz]; memset (userfence_canonical_name, 0, sizeof(userfence_canonical_name));

	if (IS_STR_LOADED(baseloc_prefix)) {
	  if(_IsBaseLocValid(sesn_ptr, baseloc_prefix)) {
		  sprintf(userfence_canonical_name, "%s%s", SESSION_SERVICE(sesn_ptr)->user.user_details.baseloc_prefix, fence_banner);
	  } else {
	  	LocationDescription *ld_ptr = GetLocationDescription (sesn_ptr);
		  _MakeCanonicalFenceName(ld_ptr, SESSION_USERID(sesn_ptr), fence_banner, USER_ATTRIBUTE_IS_SET(sesn_ptr, USERATTRIBUTE_DEFINES_USERZONE), userfence_canonical_name);
	  }
	} else {
		LocationDescription *ld_ptr = GetLocationDescription (sesn_ptr);
	  _MakeCanonicalFenceName(ld_ptr, SESSION_USERID(sesn_ptr), fence_banner, USER_ATTRIBUTE_IS_SET(sesn_ptr, USERATTRIBUTE_DEFINES_USERZONE), userfence_canonical_name);
	}

	bool fence_already_locked = false;
	unsigned long fence_call_options = FENCE_CALLFLAG_KEEP_FENCE_LOCKED|FENCE_CALLFLAG_HASH_FENCE_LOCALLY|FENCE_CALLFLAG_SEARCH_BACKEND|FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE;
	InstanceHolderForFence *instance_f_ptr = NULL;

  //this will lock fence but doesn't  return it in locked state unless KEEP_LOCKED flag is set
	if ((instance_f_ptr = FindUserFenceByCanonicalName(sesn_ptr, userfence_canonical_name, &fence_already_locked, fence_call_options))) {
    Fence *f_ptr = FenceOffInstanceHolder(instance_f_ptr);

    UFSRVResult *res_ptr = _ProcessUserAllowedToJoinFence(instance_sesn_ptr, instance_f_ptr, call_flags);

		if (IS_PRESENT(fence_lock_state))	*fence_lock_state = fence_already_locked;

		switch (res_ptr->result_code)
		{
			case RESCODE_USER_FENCE_FULL:
				if (!(call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED))	if (!fence_already_locked) FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
				SESSION_RETURN_RESULT(sesn_ptr, instance_f_ptr, RESULT_TYPE_ERR, RESCODE_USER_FENCE_FULL)

			case RESCODE_USER_FENCE_ALREADYIN:
			  //this returns fstate_ptr
				if (!(call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED))	if (!fence_already_locked) FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
				SESSION_RETURN_RESULT(sesn_ptr, _RESULT_USERDATA(res_ptr), RESULT_TYPE_ERR, RESCODE_USER_FENCE_ALREADYIN)

			case RESCODE_USER_FENCE_WRITEOFF://user on writeoff list
				if (!(call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED))	if (!fence_already_locked) FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
				SESSION_RETURN_RESULT(sesn_ptr, instance_f_ptr, RESULT_TYPE_ERR, RESCODE_USER_FENCE_WRITEOFF)

			case RESCODE_USER_FENCE_LOCATION:
				if (!(call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED))	if (!fence_already_locked) FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
				SESSION_RETURN_RESULT(sesn_ptr, instance_f_ptr, RESULT_TYPE_ERR, RESCODE_USER_FENCE_LOCATION)

			case RESCODE_USER_FENCE_KEY:
				if (!(call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED))	if (!fence_already_locked) FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
				SESSION_RETURN_RESULT(sesn_ptr, instance_f_ptr, RESULT_TYPE_ERR, RESCODE_USER_FENCE_KEY)

			case RESCODE_USER_FENCE_JOINED:
				//this is ideal case
				syslog (LOG_DEBUG, "%s: SUCESS: FOUND EXISTING Fence with the same name: fcname='%s': DROPPING  user in..", __func__, FENCE_CNAME(f_ptr));

				if (!(call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED))	if (!fence_already_locked) FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
        InstanceHolderForFenceStateDescriptor *instance_fstate_ptr = _RESULT_USERDATA(res_ptr);
				SESSION_RETURN_RESULT(sesn_ptr, instance_fstate_ptr, RESULT_TYPE_SUCCESS, RESCODE_USER_FENCE_JOINED)

			default:
				//for this kind of unknown errors we unlock automatically
				if (fence_already_locked) FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
				SESSION_RETURN_RESULT(sesn_ptr, instance_f_ptr, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
		}
	} else {
			//NO FENCE LOCK YET
		  //passing canonical_name will bypass the invocation of _f_MakeCanonicalFenceName: we shouldn't double handle
			//this is a RW locking function
			InstanceHolderForFenceStateDescriptor *instance_fstate_ptr = CreateUserFenceAndLinkToUser(instance_sesn_ptr, fence_banner, userfence_canonical_name, fence_context_ptr, call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED?FENCE_CALLFLAG_KEEP_FENCE_LOCKED:0);
		  if (IS_PRESENT(instance_fstate_ptr)) {
		    FenceStateDescriptor *fstate_ptr = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
        Fence *f_ptr = FenceOffInstanceHolder(FENCESTATE_INSTANCE_HOLDER(fstate_ptr));
		  	//note the fence is fresh out of recycler so no check for lock already exists test
			  if (!(call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED))	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));

			  if (IS_PRESENT(fence_lock_state))	*fence_lock_state = false;//not relevant

			  SESSION_RETURN_RESULT(sesn_ptr, instance_fstate_ptr, RESULT_TYPE_SUCCESS, RESCODE_USER_FENCE_MADE)
		  } else {
			  syslog (LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR: COULD NOT CREATE NEW UserFence fcname='%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), userfence_canonical_name);
			  //terminates below no f_ptr to unlock
		  }
	}

	SESSION_RETURN_RESULT(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

/**
 * 	@brief: Check if  the user-provided baseloc is valid, based on current known location.
 * 	Also, check if the localisation tokens are structured correctly.
 * 	template: 'x:y:z:user:'
 * 	variations: 'x::::', ':::user:', etc...
 * 	baseloc prefix should include the full qualified base(i.e. each zone suffixed by ':') less the terminating fence name
 */
static inline bool
_IsBaseLocValid (Session *sesn_ptr, const char *baseloc)

{
#define Z1_COUNTRY	0
#define Z2_ADMINA		1
#define	Z3_LOCALITY	2
#define Z4_USER			3
	User *u_ptr	=	&(sesn_ptr->sservice.user);

	if (unlikely(IS_EMPTY(u_ptr) || IS_EMPTY(baseloc)))	return false;

	if (IS_STR_LOADED(u_ptr->user_details.baseloc_prefix)) {
		if((strcmp(u_ptr->user_details.baseloc_prefix, baseloc))==0) return true;
	}

	if (IS_STR_LOADED(u_ptr->user_details.home_baseloc_prefix)) {
		if((strcmp(u_ptr->user_details.home_baseloc_prefix, baseloc))==0) return true;
	}

	int iterations=0;
	char *start, *aux;
	char *zones[4]={0};
	char *baseloc_copy=strdupa(baseloc);
	start=baseloc_copy;

	while (iterations++<4) {
		if((aux=strchr(start, ':'))) {
			*aux='\0'; zones[iterations-1]=start;
			aux++;
			start=aux;
			continue;
		}

		break;
	}

	//253 3846 129
	if (iterations-1!=4) {
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s {uname:'%s', token_sz:'%d'}: Wrong number of tokens...", __func__, u_ptr->user_details.user_name, iterations-1);
#endif
		return false;
	}

#ifdef __UF_TESTING
	  syslog(LOG_DEBUG, "%s {uname:'%s', country:'%s', admin:'%s', locality:'%s', user:'%s'}: Toknised baseloc...", __func__, u_ptr->user_details.user_name, zones[0]?zones[0]:"", zones[1]?zones[1]:"", zones[2]?zones[2]:"", zones[3]?zones[3]:"");
#endif

	  LocationDescription *ld_ptr=NULL;
	  if (u_ptr->user_details.user_location_initialised) ld_ptr=&u_ptr->user_details.user_location;
	  else
	  if (u_ptr->user_details.user_location_by_server_initialised) ld_ptr=&u_ptr->user_details.user_location_by_server;

	  if (!ld_ptr) {
		  syslog(LOG_DEBUG, "%s {uname:'%s'}: ERROR: COULD NOT NOT FIND VALID LOCATION DESCRIPTION DEFINED FOR USER ", __func__, u_ptr->user_details.user_name);

		  return false;
	  }


	  //don't allow empty country zone, although technically this is correct condition, meaning global scope
	  if((*zones[Z1_COUNTRY]==0)||(strcmp(zones[Z1_COUNTRY], ld_ptr->country)!=0)) {
		  syslog(LOG_INFO, "%s: INVALID COUNTRY assignment in baseloc: '%s'. LocationDescription contains: '%s'",   __func__, zones[Z1_COUNTRY], ld_ptr->country);

		  return false;
	  }


	  if ((*zones[Z4_USER])) {// && strtoul(zones[Z4_USER], NULL, 10)!=u_ptr->user_details.user_id)
	  	unsigned long selfzoned_uid=strtoul(zones[Z4_USER], NULL, 10);
	  	if (selfzoned_uid!=0 && selfzoned_uid!=UfsrvUidGetSequenceId(&(u_ptr->user_details.uid))) {
	  		syslog(LOG_INFO, "%s: INVALID USER assignment in self-zoned baseloc: '%s'", __func__, zones[Z4_USER]);

	  		return false;
	  	}
	  }

	  UpdateBaseLocAssignment (sesn_ptr, baseloc, CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND|CALL_FLAG_BROADCAST_SESSION_EVENT);

	  return true;

}

char *
MakeCanonicalFenceName(Session *sesn_ptr, const char *fdname, unsigned  flag_selfzoned, char *cname_out)
{
	return (_MakeCanonicalFenceName(&(sesn_ptr->sservice.user.user_details.user_location), SESSION_USERID(sesn_ptr), fdname, flag_selfzoned, cname_out));
}

/**
 * 	@brief: Calculate maximum possible string size to house fully loaded canonical fence name. Location information
 * 	is based on Session. Also, caters for self-zoned possibility. We over overshoot slightly.
 */
__attribute__ ((const)) size_t
SizeofCanonicalFenceName (Session *sesn_ptr, const char *fdname)
{
	const LocationDescription *ld_ptr=SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_initialised?
			  &(SESSION_SERVICE(sesn_ptr)->user.user_details.user_location):
			  &(SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_by_server);

  size_t len  = strlen(IS_STR_LOADED(ld_ptr->country)?ld_ptr->country:"") +
                strlen(IS_STR_LOADED(ld_ptr->admin_area)?ld_ptr->admin_area:"") +
                strlen(IS_STR_LOADED(ld_ptr->locality)?ld_ptr->locality:"") +
                sizeof(UINT64_LONGEST_STR) + 4 + 1; //uid + 4 for ':' + for null

  if (IS_PRESENT(fdname))	len+=strlen(fdname);

  return len;
}

/**
 * 	@brief:	produces final fully qualified user fence name, incorporating all known location information.
 * 	if userfence_banner is null it only create baseloc_prefix value.
 *	This is intended for USER FENCE only, but it dovetails with _f_CheckIntraBaseFencesAndAdd which handles BaseFences.
 *
 * 	@dynamic_memory: EXPORTS char * which the user must free
 */
static inline char *
_MakeCanonicalFenceName(LocationDescription *ld_ptr, unsigned long userid, const char *userfence_banner, unsigned  flag_selfzoned, char *cname_out)
{
	if (!IS_STR_LOADED(ld_ptr->country)) {
		syslog(LOG_ERR, "%s {pid:'%lu'}: WILL NOT create a canonical for NoCountryDefined: '%s'", __func__, pthread_self(), userfence_banner);
		return NULL;
	}

	char *canonical_name  =NULL;

	if (IS_PRESENT(cname_out)) {
		canonical_name=cname_out;
		sprintf(canonical_name, "%s:%s:%s:%lu:%s",
						ld_ptr->country?ld_ptr->country:"",
						ld_ptr->admin_area?ld_ptr->admin_area:"",
						ld_ptr->locality?ld_ptr->locality:"",
						flag_selfzoned?userid:0,
						userfence_banner?userfence_banner:"");
	} else {
    asprintf(&canonical_name, "%s:%s:%s:%lu:%s",
                        ld_ptr->country?ld_ptr->country:"",
                        ld_ptr->admin_area?ld_ptr->admin_area:"",
                        ld_ptr->locality?ld_ptr->locality:"",
                        flag_selfzoned?userid:0,
                        userfence_banner?userfence_banner:"");
	}

	if (canonical_name) {
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s {pid:'%lu'}: Produced: '%s'", __func__, pthread_self(), canonical_name);
#endif
	} else syslog(LOG_DEBUG, "%s {pid:'%lu'}: ERROR: COUD NOT PRODUCE CANONICL NAME: '%s'", __func__, pthread_self(), userfence_banner);

	return canonical_name;

}

static inline void	_UpdateLocationIfDifferent (FenceLocationDescription *location_ptr_target, FenceLocationDescription *location_ptr_source);

static inline void
_UpdateLocationIfDifferent (FenceLocationDescription *location_ptr_target, FenceLocationDescription *location_ptr_source)
{
	if (IS_STR_LOADED(location_ptr_target->display_banner_name)) {
		if (!(strcasecmp(location_ptr_target->display_banner_name, location_ptr_source->display_banner_name) == 0)) {
			free (location_ptr_target->display_banner_name);
			location_ptr_target->display_banner_name = strdup(location_ptr_source->display_banner_name);
		}
	}
	else location_ptr_target->display_banner_name = strdup(location_ptr_source->display_banner_name);

	if (IS_STR_LOADED(location_ptr_target->canonical_name)) {
		if (!(strcasecmp(location_ptr_target->canonical_name, location_ptr_source->canonical_name) == 0)) {
			free (location_ptr_target->canonical_name);
			location_ptr_target->canonical_name = strdup(location_ptr_source->canonical_name);
		}
	} else location_ptr_target->canonical_name = strdup (location_ptr_source->canonical_name);

	if (IS_STR_LOADED(location_ptr_target->base_location)) {
		if (!(strcasecmp(location_ptr_target->base_location, location_ptr_source->base_location) == 0)) {
			free (location_ptr_target->base_location);
			location_ptr_target->base_location = strdup(location_ptr_source->base_location);
		}
	} else location_ptr_target->base_location = strdup(location_ptr_source->base_location);

}

/**
 *	@brief: Works for Network BaseFences, no user defined fence name, as opposed to MakeFenceByCanonicalName, unrolls the canonical name and creates
 *	BaseFences for the locations bits that are known. Follows the naming rules used in MakeCanonicalFenceName.
 *	For basefence the selfzone is always empty.
 *
 *	@param ld_ptr: Denotes user's location description (as opposed to fence's)
 *
 *	@returns: the number of intra fences created as an outcome of parsing the components of user'slocation
 *
 * 	@locks: NONE
 */
static unsigned
_CheckIntraBaseFencesAndAdd (Session *sesn_ptr, const LocationDescription *ld_ptr, unsigned long add_flag)
{
	bool  fence_already_locked			= false;
	unsigned int				counter			= 0;
	HttpRequestContext	*http_ptr		=	GetHttpRequestContext(sesn_ptr);

	if (IS_STR_LOADED(ld_ptr->country)) {
		char *cn_country	= NULL;
		Fence *f_ptr		  = NULL;
    InstanceHolder *instance_holder_ptr;

		asprintf(&cn_country, "%s:::0:", ld_ptr->country);

		//country
    instance_holder_ptr = FindBaseFenceByCanonicalName(sesn_ptr, cn_country, &fence_already_locked, FENCE_CALLFLAG_SEARCH_BACKEND|FENCE_CALLFLAG_KEEP_FENCE_LOCKED);
		if (IS_EMPTY(instance_holder_ptr)) {
			instance_holder_ptr = RecyclerGet(FencePoolTypeNumber(), (ContextData *)sesn_ptr, FENCE_CALLFLAG_BASEFENCE|FENCE_CALLFLAG_GENERATE_ID|FENCE_CALLFLAG_LOCK_FENCE);
			if (unlikely(IS_EMPTY(instance_holder_ptr))) {
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', name:'%s'}: ERROR: COULD NOT GET FENCE TYPE INSTANCE...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), cn_country);
				free (cn_country);

				return 0;
			}

			//fence locked
			f_ptr = FenceOffInstanceHolder(instance_holder_ptr);

			counter++;
			_UpdateLocationIfDifferent (&f_ptr->fence_location,
																	&((FenceLocationDescription){.display_banner_name=ld_ptr->country, .canonical_name=cn_country, .base_location=cn_country}));

			if (!(AddToHash(&FenceRegistryCanonicalNameHashTable, instance_holder_ptr))) goto exit_error_country;
			if (!(AddToHash(&FenceRegistryIdHashTable, instance_holder_ptr))) {
				RemoveFromHash(&FenceRegistryCanonicalNameHashTable, instance_holder_ptr);

				exit_error_country:
				_DestructFenceLocationDescription(&(f_ptr->fence_location));
				free(cn_country);
				RecyclerPut(FencePoolTypeNumber(), instance_holder_ptr, (ContextData *)NULL, FENCE_CALLFLAG_UNLOCK_FENCE);
				return 0;
			}

			GeocodeLocation (sesn_ptr, http_ptr, &(f_ptr->fence_location.fence_location), f_ptr->fence_location.display_banner_name);

			UpdateBackendFenceData (sesn_ptr, f_ptr, NULL, EVENT_TYPE_FENCE_CREATED, &((FenceEvent){}));
		}

		//fence locked
		free (cn_country); cn_country = NULL;
		f_ptr = FenceOffInstanceHolder(instance_holder_ptr);
		SESSION_BASEFENCE_LOCAL(sesn_ptr) = FENCE_ID(f_ptr);//gets overwritten successively down to the most specific
    if (!fence_already_locked)  FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));
    fence_already_locked = false;

    //......................................................................................
		if (IS_STR_LOADED(ld_ptr->admin_area)) { //'country:admin_area'
			char *cn_country_admin_area = NULL;

			asprintf(&cn_country_admin_area, "%s:%s::0:", ld_ptr->country, ld_ptr->admin_area);

      instance_holder_ptr = FindBaseFenceByCanonicalName(sesn_ptr, cn_country_admin_area, &fence_already_locked, FENCE_CALLFLAG_SEARCH_BACKEND|FENCE_CALLFLAG_KEEP_FENCE_LOCKED);
			if (IS_EMPTY(instance_holder_ptr)) {
        instance_holder_ptr = RecyclerGet(FencePoolTypeNumber(), (ContextData *)sesn_ptr, FENCE_CALLFLAG_BASEFENCE|FENCE_CALLFLAG_GENERATE_ID|FENCE_CALLFLAG_LOCK_FENCE);
				if (unlikely(IS_EMPTY(instance_holder_ptr))) {
					syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', name:'%s'}: ERROR: COULD NOT GET FENCE TYPE INSTANCE...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), cn_country_admin_area);
					free (cn_country_admin_area);

					return 0;
				}

        f_ptr = FenceOffInstanceHolder(instance_holder_ptr);

				_UpdateLocationIfDifferent (&f_ptr->fence_location,
																		&((FenceLocationDescription){.display_banner_name=ld_ptr->admin_area, .canonical_name=cn_country_admin_area, .base_location=cn_country_admin_area}));

				if (!(AddToHash(&FenceRegistryCanonicalNameHashTable, instance_holder_ptr))) goto exit_error_country_admina_area;
				if (!(AddToHash(&FenceRegistryIdHashTable, instance_holder_ptr))) {
					RemoveFromHash(&FenceRegistryCanonicalNameHashTable, instance_holder_ptr);

					exit_error_country_admina_area:
					_DestructFenceLocationDescription(&(f_ptr->fence_location));
					free(cn_country_admin_area);
					RecyclerPut(FencePoolTypeNumber(), instance_holder_ptr, (ContextData *)NULL, FENCE_CALLFLAG_UNLOCK_FENCE);

					return 0;
				}

				char *s = NULL;
				asprintf(&s, "%s,%s", ld_ptr->country, f_ptr->fence_location.display_banner_name);
				GeocodeLocation (sesn_ptr, http_ptr, &(f_ptr->fence_location.fence_location), s); free(s);

				UpdateBackendFenceData (sesn_ptr, f_ptr, NULL, EVENT_TYPE_FENCE_CREATED, &((FenceEvent){}));

				counter++;
			}

			free(cn_country_admin_area); cn_country_admin_area = NULL;
			f_ptr = FenceOffInstanceHolder(instance_holder_ptr);
			SESSION_BASEFENCE_LOCAL(sesn_ptr) = FENCE_ID(f_ptr);
      if (!fence_already_locked)  FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));
      fence_already_locked = false;

      //................................................................................................
			if (IS_STR_LOADED(ld_ptr->locality)) {//ideal case: all components defined
			//country:admin_area:locality
				char *cn_country_admin_area_locality = NULL;

				asprintf(&cn_country_admin_area_locality, "%s:%s:%s:0:", ld_ptr->country, ld_ptr->admin_area, ld_ptr->locality);

        instance_holder_ptr = FindBaseFenceByCanonicalName(sesn_ptr, cn_country_admin_area_locality, &fence_already_locked, FENCE_CALLFLAG_SEARCH_BACKEND|FENCE_CALLFLAG_KEEP_FENCE_LOCKED);
				if (IS_EMPTY(instance_holder_ptr)) {
					instance_holder_ptr = RecyclerGet(FencePoolTypeNumber(), (ContextData *)sesn_ptr, FENCE_CALLFLAG_BASEFENCE|FENCE_CALLFLAG_GENERATE_ID|FENCE_CALLFLAG_LOCK_FENCE);
					if (unlikely(IS_EMPTY(instance_holder_ptr))) {
						syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', name:'%s'}: ERROR: COULD NOT GET FENCE TYPE INSTANCE...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), cn_country_admin_area_locality);
						free (cn_country_admin_area_locality);

						return 0;
					}

					//fence locked
          f_ptr = FenceOffInstanceHolder(instance_holder_ptr);

					_UpdateLocationIfDifferent (&f_ptr->fence_location,
																			&((FenceLocationDescription){.display_banner_name=ld_ptr->locality, .canonical_name=cn_country_admin_area_locality, .base_location=cn_country_admin_area_locality}));

					if (!(AddToHash(&FenceRegistryCanonicalNameHashTable, instance_holder_ptr))) goto exit_error_country_admina_area_local;
					if (!(AddToHash(&FenceRegistryIdHashTable, instance_holder_ptr))) {
						RemoveFromHash(&FenceRegistryCanonicalNameHashTable, instance_holder_ptr);

						exit_error_country_admina_area_local:
						_DestructFenceLocationDescription(&(f_ptr->fence_location));
						free(cn_country_admin_area_locality);
						RecyclerPut(FencePoolTypeNumber(), instance_holder_ptr, (ContextData *)NULL, CALLFLAGS_EMPTY|FENCE_CALLFLAG_UNLOCK_FENCE);

						return 0;
					}

					char *s = NULL;
					asprintf(&s, "%s,%s,%s", ld_ptr->country, ld_ptr->admin_area, ld_ptr->locality);
					GeocodeLocation (sesn_ptr, http_ptr, &(f_ptr->fence_location.fence_location), s); free(s);

					UpdateBackendFenceData (sesn_ptr, f_ptr, NULL, EVENT_TYPE_FENCE_CREATED, &((FenceEvent){}));

					counter++;
					free(cn_country_admin_area_locality); cn_country_admin_area_locality = NULL;
				}

				//fence locked
				f_ptr = FenceOffInstanceHolder(instance_holder_ptr);
				SESSION_BASEFENCE_LOCAL(sesn_ptr) = FENCE_ID(f_ptr);

        if (!fence_already_locked)  FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));
        fence_already_locked = false;
			} else {
			  //country:admin_area:NO_locality
			//circular logic this is covered in the parent case
			}
		} else {
		  //country:NO_admin_area
			if (IS_STR_LOADED(ld_ptr->locality)) {//TODO: we should not allow this at client side
			//country:NO_admin_area:locality
				char *cn_s = NULL;

				asprintf(&cn_s, "%s::%s:0:", ld_ptr->country, ld_ptr->locality);//note display name collision with above

        instance_holder_ptr = FindBaseFenceByCanonicalName(sesn_ptr, cn_s, &fence_already_locked, FENCE_CALLFLAG_SEARCH_BACKEND|FENCE_CALLFLAG_KEEP_FENCE_LOCKED);
				if (IS_EMPTY(instance_holder_ptr)) {
					instance_holder_ptr = RecyclerGet(FencePoolTypeNumber(), (ContextData *)sesn_ptr, FENCE_CALLFLAG_BASEFENCE|FENCE_CALLFLAG_GENERATE_ID|FENCE_CALLFLAG_LOCK_FENCE);
					if (unlikely(IS_EMPTY(instance_holder_ptr))) {
						syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', name:'%s'}: ERROR: COULD NOT GET FENCE TYPE INSTANCE...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), cn_s);
						free (cn_s);

						return 0;
					}

					//fence locked
          f_ptr = FenceOffInstanceHolder(instance_holder_ptr);

					_UpdateLocationIfDifferent (&f_ptr->fence_location,
																			&((FenceLocationDescription){.display_banner_name=ld_ptr->locality, .canonical_name=cn_s, .base_location=cn_s}));

					if (!(AddToHash(&FenceRegistryCanonicalNameHashTable, instance_holder_ptr))) goto exit_error_cn_s;
					if (!(AddToHash(&FenceRegistryIdHashTable, instance_holder_ptr))) {
						//TODO: free f_ptr and dealocate
						RemoveFromHash(&FenceRegistryCanonicalNameHashTable, (void *) instance_holder_ptr);

						exit_error_cn_s:
						_DestructFenceLocationDescription(&(f_ptr->fence_location));
						free(cn_s);
						RecyclerPut(FencePoolTypeNumber(), instance_holder_ptr, (ContextData *)NULL, FENCE_CALLFLAG_UNLOCK_FENCE);

						return 0;
					}

					char *s = NULL;
					asprintf(&s, "%s,%s", ld_ptr->country, ld_ptr->locality);
					GeocodeLocation (sesn_ptr, http_ptr, &(f_ptr->fence_location.fence_location), s); free(s);

					UpdateBackendFenceData (sesn_ptr, f_ptr, NULL, EVENT_TYPE_FENCE_CREATED, &((FenceEvent){}));

					counter++;
				}

				free(cn_s); cn_s = NULL;
				f_ptr = FenceOffInstanceHolder(instance_holder_ptr);
				SESSION_BASEFENCE_LOCAL(sesn_ptr) = FENCE_ID(f_ptr);

        if (!fence_already_locked)  FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));
        fence_already_locked = false;
			} else {
				//country_NO_admin_area:NO_locality
				//circular logic back top most case
				//char *cn_s=asprintf("%s::", ld_ptr->country);
			}
		}
	} else {//no country no go
	//if (ld_ptr->admin_area&&strlen(ld_ptr->admin_area)>0)//no country no go
		//dont allow for "nocountry:admin:locality type"
		syslog(LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu'}: WILL NOT create a BaseFence for NoCountryDefined", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

	}

	return counter;

}

//-------------------------- ADD ROUTINES ------------------------

/**
 *
 * @brief: Main entry point for creating new, fully linked up user fences. Contrasts with AddtoExistingFence.
 * IMPORTANT: if using userfence_canonical_name_in must be previously malloced in the calling environment
 * future version should allow passing in of LocationDescription object
 *
 * @param userfence_canonical_name_in: constructed value. A local copy must be made
 *
 * @locks RW f_ptr: newly created f_ptr returned in locked state
 * @locks: indirectly locks associated with type pool are locked/unlocked as instances are fetched from the pool
 * @locked sesn_ptr: must be locked by the caller
 * @call_flags FENCE_CALLFLAG_KEEP_FENCE_LOCKED:	This function can leave the lock on the fence open if so instructed. It only does that if the outcome
 * 										of the operation was successful.
 * @dynamic_memory userfence_canonical_name_in: creates heap copy if successful
 */
InstanceHolderForFenceStateDescriptor *
CreateUserFenceAndLinkToUser (InstanceHolderForSession *instance_sesn_ptr, const char *fence_banner, char *userfence_canonical_name_in, FenceContextDescriptor *fence_context, unsigned long call_flags)
{
	Fence *f_ptr;
	Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	if (!IS_STR_LOADED(fence_banner)) {
		syslog (LOG_DEBUG, "%s: ERROR: INVALID fence_banner parameter", __func__);
		return NULL;
	}

	if (!IS_STR_LOADED(userfence_canonical_name_in)) {
		syslog (LOG_DEBUG, "%s: ERROR: INVALID userfence_canonical_name_in parameter", __func__);
		return NULL;
	}

	InstanceHolderForFence *instance_fptr = (InstanceHolderForFence *)RecyclerGet(FencePoolTypeNumber(), (ContextData *)sesn_ptr, FENCE_CALLFLAG_USERFENCE|FENCE_CALLFLAG_GENERATE_ID);

	if (unlikely(IS_EMPTY(instance_fptr)))	return NULL;

	f_ptr = FenceOffInstanceHolder(instance_fptr);

	//TODO: this would be a major stuffup... as fence would have been in the pool before being unlocked
	FenceEventsLockRWCtx(THREAD_CONTEXT_PTR, f_ptr, _LOCK_TRY_FLAG_TRUE, SESSION_RESULT_PTR(sesn_ptr), __func__);

	if (SESSION_RESULT_TYPE_EQUAL(sesn_ptr, RESULT_TYPE_ERR)) {
		syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu', cname:'%s'}: ERROR: FETCHED LOCKED FENCE FROM POOL", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), userfence_canonical_name_in);
		RecyclerPut(FencePoolTypeNumber(), instance_fptr, (ContextData *)NULL, CALLFLAGS_EMPTY);
		return NULL;
	}

	//not useful? just come out of recycler...
	bool fence_lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_PROG_LOCKED_BY_THIS_THREAD));

	_PopulateFenceData (f_ptr, sesn_ptr, NULL, fence_banner, userfence_canonical_name_in, true);

	if (!(AddToHash(&FenceRegistryCanonicalNameHashTable, instance_fptr))) {
		_DePopulateFenceData (f_ptr, CALLFLAGS_EMPTY);

		if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));

		RecyclerPut(FencePoolTypeNumber(), instance_fptr, (ContextData *)NULL, CALLFLAGS_EMPTY);

		return NULL;
	}

	if (!(AddToHash(&FenceRegistryIdHashTable, instance_fptr))) {
		RemoveFromHash(&FenceRegistryCanonicalNameHashTable, (void *) instance_fptr);

		_DePopulateFenceData (f_ptr, CALLFLAGS_EMPTY);

		if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));

		RecyclerPut(FencePoolTypeNumber(), instance_fptr, (ContextData *)NULL, CALLFLAGS_EMPTY);

		return NULL;
	}

	if (IS_PRESENT(fence_context))	fence_context->callbacks.callback_update_fence(fence_context->sesn_ptr, f_ptr, fence_context->context_ptr);

	UpdateBackendFenceData (sesn_ptr, f_ptr, NULL, EVENT_TYPE_FENCE_CREATED, &((FenceEvent){}));

	//>>>>>>>>>>>> Fence fully setup
	unsigned cflags = (CALL_FLAG_FENCE_LIST_CHECK_DUP_SESSION	|
										CALL_FLAG_SESSION_LIST_CHECK_DUP_FENCE	|
										CALL_FLAG_WRITEBACK_FENCE_DATA_TO_BACKEND);

	InstanceHolderForFenceStateDescriptor *instance_fstate_ptr = AddUserToThisFenceListWithLinkback(instance_sesn_ptr, instance_fptr, SESSION_FENCE_LIST_PTR(sesn_ptr), &(f_ptr->fence_user_sessions_list),  EVENT_TYPE_FENCE_USER_JOINED, cflags);
	if (IS_EMPTY(instance_fstate_ptr)) {
		RemoveFromHash(&FenceRegistryCanonicalNameHashTable, (void *)instance_fptr);
		RemoveFromHash(&FenceRegistryIdHashTable, (void *)instance_fptr);
		_DePopulateFenceData (f_ptr, call_flags);

		if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));

		RecyclerPut(FencePoolTypeNumber(), instance_fptr, (ContextData *)NULL, 0);

		return NULL;
	}

	F_ATTR_UNSET(f_ptr->attrs, F_ATTR_SESSNLIST_LAZY);
	F_ATTR_UNSET(f_ptr->attrs, F_ATTR_DIRTY);

	//success. We only look at this flag if operation was successful
	if (!(call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED)) {
		if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
	}
	//else Fence returned locked to the caller

	return instance_fstate_ptr;

}

/**
 * 	@brief:	Populate the Fence in the context of the Session owner sesn_ptr who created the fence (if location_ptr is NULL),
 * 	eg. it inherits its location attributes.
 * 	@param location_ptr:	Location descriptor touse forthe fence, could be the Session's or some other designation (not implemented well)
 * 	@userfence_canonical_name_in
 *
 * 	@dynamic_memory userfence_canonical_name_in: this is a reference to previously constructed local copy. Must be allocated on the heap.
 *
 */
inline static Fence *
_PopulateFenceData (Fence *f_ptr, Session *sesn_ptr, LocationDescription *location_ptr, const char *fence_banner, char *userfence_canonical_name_in, bool flag_fuzz_location)
{
	LocationDescription *ld_ptr=NULL;
	SessionService 		*ss_ptr=&(sesn_ptr->sservice);
	static LocationDescription location_descriptor_fallback={
			.longitude=0.0,
			.latitude=0.0,
			.locality="_locality_",
			.admin_area="_adminarea_",
			.country="_country_",
			.selfzone="0"
	};

	if (IS_PRESENT(location_ptr))	ld_ptr=location_ptr;
	else
	{
		//use Session's location, or fallback
		 ld_ptr=ss_ptr->user.user_details.user_location_initialised?
					 (&ss_ptr->user.user_details.user_location):(ss_ptr->user.user_details.user_location_by_server_initialised?
							 (&(ss_ptr->user.user_details.user_location_by_server)):(&location_descriptor_fallback));
	}

	 char *userfence_canonical_name=NULL;
	 if (userfence_canonical_name_in)
	 {
		userfence_canonical_name=strdup(userfence_canonical_name_in);//previously dynamically allocated and safe to use
	 }
	 else
	 {
		 //resolved above
		 //ld_ptr=ss_ptr->user.user_details.user_location_initialised?
			// (&ss_ptr->user.user_details.user_location):(&ss_ptr->user.user_details.user_location_by_server);

		 //this is specific to user fences, which limits the utility of this function
		 userfence_canonical_name=_MakeCanonicalFenceName(ld_ptr, SESSION_USERID(sesn_ptr), fence_banner, USER_ATTRIBUTE_IS_SET(sesn_ptr, USERATTRIBUTE_DEFINES_USERZONE), NULL);
	 }

	 //we should not need to strdup if we invoked MakeCanonicalFenceName
	 f_ptr->fence_location.canonical_name				=	userfence_canonical_name;
	 f_ptr->fence_location.display_banner_name	=	strdup(fence_banner);
	 FENCE_OWNER_UID(f_ptr)											=	UfsrvUidGetSequenceId(&(ss_ptr->user.user_details.uid));
	 {
		 int len=strlen(f_ptr->fence_location.canonical_name);//xxx:yyy:zzz
		 int len2=strlen(f_ptr->fence_location.display_banner_name);//zzz
		 int len3=len-len2;//11-3=8

		 f_ptr->fence_location.base_location=malloc(len3+1);//9 extra for null
		 memcpy(f_ptr->fence_location.base_location, f_ptr->fence_location.canonical_name, len3);
		 *(f_ptr->fence_location.base_location+(len3))=0;

#ifdef __UF_FULLDEBUG
		 syslog(LOG_DEBUG, "%s: BASELOC IS: '%s'", __func__, f_ptr->fence_location.base_location);
#endif
	 }

	 f_ptr->fence_location.fence_location.latitude	=	ld_ptr->latitude;
	 f_ptr->fence_location.fence_location.longitude	=	ld_ptr->longitude;

	 if (flag_fuzz_location) _FuzzGeoLocationByCoords (&FENCE_LONGITUDE(f_ptr), &FENCE_LATITUDE(f_ptr), _CONFIGDEFAULT_GEOLOC_FUZZFACTOR);

	 //TODO: populate the rest from ld_ptr

	 return f_ptr;
}

LocationDescription *
MapFenceLocationDescription (const Fence *f_ptr, char *canonical_name_buffer, LocationDescription *location_ptr_out)
{
	//country:admin:locality:username-self_zone:dname
	char *walker,
				*orig=canonical_name_buffer;

	if ((walker=strchr(orig, ':')))
	{
		*walker++='\0';
		location_ptr_out->country=orig;
		orig=walker;

		if ((walker=strchr(orig, ':')))
		{
			*walker++='\0';
			location_ptr_out->admin_area=orig;
			orig=walker;

			if ((walker=strchr(orig, ':')))
			{
				*walker++='\0';
				location_ptr_out->locality=orig;
				orig=walker;

				if ((walker=strchr(orig, ':')))
				{
					*walker++='\0';
					location_ptr_out->selfzone=orig;
					orig=walker;

					return location_ptr_out;
				}
			}
		}
	}

	return NULL;
}

/**
 * 	@brief: This is responsible for updating the model, generating eids
 * 	Source invited users list from give protobuf data. As it originates from the user, this is always reflects the outcome
 * 	of either add/remove/etc  for users on the list
 * 	@locked: fence_events lock must be in place
 * 	@locks: Session * for invited users
 */
CollectionDescriptor *
AddToFenceInvitedListFromProtoRecord (InstanceHolderForSession *instance_sesn_ptr, InstanceHolderForFence *instance_f_ptr, UserRecord **user_records, size_t invited_members_sz, CollectionDescriptorPair *invited_collections_for_result, bool flag_exclude_self)
{
	if (invited_members_sz < 1)	return NULL;

	size_t								processed													= 0;
	unsigned long 				sesn_call_flags										= 0;
	UserRecord 						*invited_user_record_ptr					= NULL;
	Session 							*sesn_ptr_invited									= NULL;
	CollectionDescriptor 	*invited_events_collection_ptr		= NULL;
	CollectionDescriptor 	*unprocessed_uids_collection_ptr	= NULL;
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
  Fence *f_ptr = FenceOffInstanceHolder(instance_f_ptr);

	sesn_call_flags=(CALL_FLAG_LOCK_SESSION|CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY|CALL_FLAG_HASH_USERNAME_LOCALLY|
										CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION|CALL_FLAG_REMOTE_SESSION);

	invited_events_collection_ptr		=	&(invited_collections_for_result->first);
	unprocessed_uids_collection_ptr	=	&(invited_collections_for_result->second);

	for (size_t i=0; i<invited_members_sz; i++) {
		invited_user_record_ptr = user_records[i];

		unsigned long userid_invited = UfsrvUidGetSequenceId((const UfsrvUid *)invited_user_record_ptr->ufsrvuid.data);
		assert(userid_invited > 0);

		if (userid_invited == SESSION_USERID(sesn_ptr))	if (flag_exclude_self)	continue;

		bool lock_already_owned = false;
		GetSessionForThisUserByUserId(sesn_ptr, userid_invited, &lock_already_owned, sesn_call_flags);
		if (SESSION_RESULT_TYPE_ERROR(sesn_ptr)) {
		  continue;
		}

		InstanceHolderForSession *instance_sesn_ptr_invited = (InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr);
    sesn_ptr_invited = SessionOffInstanceHolder(instance_sesn_ptr_invited);

		//>>>>>>> SESSION LOCKED
		if (unlikely(IS_EMPTY(sesn_ptr_invited))) {
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fid:'%lu', uid_invited:'%lu'}: ERROR: COULD NOT RETRIEVE SESSION FOR INVITED USER", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), FENCE_ID(f_ptr), userid_invited);
			continue;
		}

		if (!IsUserOnFenceInvitedList(f_ptr, SESSION_USERID(sesn_ptr_invited))) {
			FenceEvent fence_event = {0};

			InstanceHolderForFenceStateDescriptor *instance_fstate_ptr = RecyclerGet(FenceStateDescriptorPoolTypeNumber(), (ContextData *)instance_f_ptr, CALLFLAGS_EMPTY);
			if (unlikely(IS_EMPTY(instance_fstate_ptr))) {
				if (IS_PRESENT(sesn_ptr_invited))	if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_invited, __func__);
				continue;
			}

      FenceStateDescriptor *fence_descriptor = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);

			FENCESTATE_INSTANCE_HOLDER(fence_descriptor)  =	instance_f_ptr;
			memcpy(fence_descriptor->invited_by.data, SESSION_UFSRVUID(sesn_ptr), CONFIG_MAX_UFSRV_ID_SZ);

			FenceEvent *fe_ev = UpdateBackendFenceInvitedData(sesn_ptr, sesn_ptr_invited, fence_descriptor, EVENT_TYPE_FENCE_USER_INVITED, &fence_event);
			if (IS_PRESENT(fe_ev)) {
				AddThisToList (SESSION_INVITED_FENCE_LIST_PTR(sesn_ptr_invited), instance_fstate_ptr);
				FenceIncrementReference(fence_descriptor->instance_holder_fence, 1);

				AddThisToList(&f_ptr->fence_user_sessions_invited_list, CLIENT_CTX_DATA(instance_sesn_ptr_invited));
				SessionIncrementReference(instance_sesn_ptr_invited, 1);

				//note the use of array index 'i'. failed events will have eid as '0', but overall we maintain index consistency between array and invitation list provided by user
				((unsigned long *)invited_events_collection_ptr->collection)[i] = fe_ev->eid;
        fence_descriptor->when_invited = fe_ev->when;
				processed++;
			} else {
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fid:'%lu', uid_invited:'%lu'}: ERROR: COULD NOT RETRIEVE FENCE EVENT FOR INVITED USER", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), FENCE_ID(f_ptr), SESSION_USERID(sesn_ptr_invited));
				FenceStateDescriptorReturnToRecycler(instance_fstate_ptr, NULL, 0);
				//TODO: what do we do with the generated event? should mark it as failed
			}
		} else if (IS_PRESENT(unprocessed_uids_collection_ptr))	{
			((unsigned long *)unprocessed_uids_collection_ptr->collection)[i] = userid_invited;
			unprocessed_uids_collection_ptr->collection_sz++;
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fid:'%lu', uid_invited:'%lu'}: ERROR: USER ALREADY ON LIST: COULD NOT ADD USER TO INVITE LIST", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), FENCE_ID(f_ptr), userid_invited);
		}

		if (sesn_ptr_invited != NULL)	if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_invited, __func__);
	}//for

	invited_events_collection_ptr->collection_sz = processed;//caller will check if processed less than provided list

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cname:'%s', recved_list_sz:'%lu', processed_list_sz:'%lu'}: Fence Invitaion List: processed", __func__, pthread_self(), sesn_ptr, FENCE_CNAME(f_ptr), invited_members_sz, processed);
#endif

	return invited_events_collection_ptr;
}

/**
 * 	@brief: Add singular user to Invite list.
 *
 * 	@param sesn_ptr_inviter: can be regular user of ufsrv system user
 * 	@returns: event_id
 * 	@locked sesn_ptr_invited: must be locked by the caller
 * 	@locked sesn_ptr_inviter:	must be locked by the caller
 * 	@locked f_ptr:
 *
 */
UFSRVResult *
AddMemberToInvitedFenceList (InstanceHolderForSession *instance_sesn_ptr_invited, InstanceHolderForFence *instance_f_ptr, Session *sesn_ptr_inviter, unsigned long fence_call_flags)
{
  Session *sesn_ptr_invited = SessionOffInstanceHolder(instance_sesn_ptr_invited);
  Fence *f_ptr = FenceOffInstanceHolder(instance_f_ptr);

	if (!IsUserOnFenceInvitedList(f_ptr, SESSION_USERID(sesn_ptr_invited))) {
		FenceEvent fence_event	=	{0};
		FenceEvent *fe_ev				= NULL;

		 InstanceHolderForFenceStateDescriptor *instance_fstate_ptr = RecyclerGet(FenceStateDescriptorPoolTypeNumber(), (ContextData *)instance_f_ptr, CALLFLAGS_EMPTY);
		if (unlikely(IS_EMPTY(instance_fstate_ptr))) {
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fid:'%lu'}: ERROR: COULD NOT ALLOCATE FenceStateDescriptor type", __func__, pthread_self(), sesn_ptr_invited, SESSION_ID(sesn_ptr_invited), FENCE_ID(f_ptr));
			_RETURN_RESULT_SESN(sesn_ptr_invited, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)
		}

    FenceStateDescriptor *fstate_ptr = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);

		FENCESTATE_INSTANCE_HOLDER(fstate_ptr)  =	instance_f_ptr;
		fstate_ptr->when_invited      =	time(NULL);
    memcpy (fstate_ptr->invited_by.data, SESSION_UFSRVUID(sesn_ptr_inviter), CONFIG_MAX_UFSRV_ID_SZ);

		if (fence_call_flags&FENCE_CALLFLAG_WRITEBACK_DATA_TO_BACKEND) {
			if (IS_PRESENT(fe_ev)) { //todo: event is unassigned
				AddThisToList (SESSION_INVITED_FENCE_LIST_PTR(sesn_ptr_invited), instance_fstate_ptr);
				FenceIncrementReference(instance_fstate_ptr, 1);

        AddThisToList (&f_ptr->fence_user_sessions_invited_list, CLIENT_CTX_DATA(instance_sesn_ptr_invited));
				SessionIncrementReference (instance_sesn_ptr_invited, 1);

				_RETURN_RESULT_SESN(sesn_ptr_invited, (void *) (uintptr_t) fe_ev->eid, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
			} else {
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fid:'%lu', uid_invited:'%lu'}: ERROR: COULD NOT RETRIEVE FENCE EVENT FOR INVITED USER", __func__, pthread_self(), sesn_ptr_invited, SESSION_ID(sesn_ptr_invited), FENCE_ID(f_ptr), SESSION_USERID(sesn_ptr_invited));
				FenceStateDescriptorReturnToRecycler (instance_fstate_ptr, NULL, 0);
				//TODO: what do we do with the generated event? should mark it as failed
			}
		} else {
			AddThisToList (SESSION_INVITED_FENCE_LIST_PTR(sesn_ptr_invited), instance_fstate_ptr);
			FenceIncrementReference(instance_f_ptr, 1);

      AddThisToList (&f_ptr->fence_user_sessions_invited_list, CLIENT_CTX_DATA(instance_sesn_ptr_invited));
			SessionIncrementReference (instance_sesn_ptr_invited, 1);

			_RETURN_RESULT_SESN(sesn_ptr_invited, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
		}
	}

	_RETURN_RESULT_SESN(sesn_ptr_invited, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)
}

//--------------------- END OF ADD ROUTINES ----------------------------------


// ------------------- REMOVE & DESTRUCT ROUTINES -------------------------------------

/**
 * 	@brief:
 * 	Frontline line function removes individual named fence from Session's fence list
 *
 */
int
FenceRemoveUserByFenceId (Session *sesn_ptr_this, Session *sesn_ptr_target, unsigned long fence_id)
{
#if 0
	//require work to function properly

	if (fence_id<=0)
	{
		syslog(LOG_ERR, "%s (pid:'%lu' cid:'%lu'): INVALID fence_id parameter passed: RETURNING", __func__, pthread_self(), SESSION_ID(sesn_ptr_target));

		return -2;
	}

	//FENCE_CALLFLAG_SEARCH_BACKEND unset. We only remove if user is local to this server
	Fence *f_ptr_hash=FindFenceById(NULL, fence_id, 0);
	if (!f_ptr_hash)
	{
		syslog(LOG_DEBUG, "%s (pid:'%lu' cid='%lu'): ERROR: COULD NOT FIND fence_id: '%lu' in Hash.", __func__, pthread_self(), SESSION_ID(sesn_ptr_target), fence_id);

		return -3;
	}

	return (RemoveUserFromFence(sesn_ptr_this, sesn_ptr_target, f_ptr_hash, 0));
#endif

	return 0;
}

/**
 * 	@brief: Clears Session instance only and doesn't touch referencial links related to Fences at system level, as this is
 * 	an isolated instance with its own copy of the relationships.
 * 	This is useful when the session was created as a snapshot and not actual live one.
 */
unsigned
RemoveUserFromAllFencesSessionInstanceOnly (Session *sesn_ptr, unsigned long call_flags)
{
	Fence 					*f_ptr		=	NULL;
	ListEntry 			*eptr			=	NULL;

	//NEVER USE FOR LOOP CONSTRUCT FOR ITERATION
	FenceStateDescriptor	*fence_state_descriptor = NULL;

	while (SESSION_FENCE_LIST_SIZE(sesn_ptr) != 0) {
		eptr = SESSION_FENCE_LIST(sesn_ptr).head;
		if (IS_PRESENT(eptr)) {
      InstanceHolderForFenceStateDescriptor *instance_fstate_ptr = (InstanceHolderForFenceStateDescriptor *)eptr->whatever;
			fence_state_descriptor = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
			f_ptr = FENCESTATE_FENCE(fence_state_descriptor);
			RemoveFenceFromSessionFenceList (SESSION_FENCE_LIST_PTR(sesn_ptr), f_ptr);
			FenceDecrementReference (FENCESTATE_INSTANCE_HOLDER(fence_state_descriptor), 1);
			//kill both
      RecyclerPut(FencePoolTypeNumber(), (RecyclerClientData *)FENCESTATE_INSTANCE_HOLDER(fence_state_descriptor), (ContextData *)NULL, CALLFLAGS_EMPTY);
			RecyclerPut(FenceStateDescriptorPoolTypeNumber(), instance_fstate_ptr, (ContextData *)NULL, CALLFLAGS_EMPTY);
		}
	}

	while (SESSION_INVITED_FENCE_LIST_SIZE(sesn_ptr) != 0) {
		eptr = SESSION_INVITED_FENCE_LIST(sesn_ptr).head;
		if (IS_PRESENT(eptr)) {
      InstanceHolderForFenceStateDescriptor *instance_fstate_ptr = (InstanceHolderForFenceStateDescriptor *)eptr->whatever;
			fence_state_descriptor = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
			f_ptr = FENCESTATE_FENCE(fence_state_descriptor);
			RemoveFenceFromSessionInvitedFenceList (SESSION_INVITED_FENCE_LIST_PTR(sesn_ptr), FENCE_ID(f_ptr));
			FenceDecrementReference (FENCESTATE_INSTANCE_HOLDER(fence_state_descriptor), 1);
			//kill both
      RecyclerPut(FencePoolTypeNumber(), (RecyclerClientData *)FENCESTATE_INSTANCE_HOLDER(fence_state_descriptor), (ContextData *)NULL, CALLFLAGS_EMPTY);
			RecyclerPut(FenceStateDescriptorPoolTypeNumber(), (RecyclerClientData *)instance_fstate_ptr, (ContextData *)NULL, CALLFLAGS_EMPTY);
		}
	}

	return 1;//all good

}

//
//export function
//destructive
//all fences
//can be used when a user quit or I/O exception
//>>>>> LOCKS f_ptr <<<<<<
//session must be locked
// session for sesn_ptr_target can be different from sesn_ptr_this. For example connected session is used to kill a remote session
//
/*	@brief: this can be called from
 * 	@param sesn_ptr_target: must have full access context.
 * 	@worker: ufsrv, session
 */
unsigned
RemoveUserFromAllFences (InstanceHolderForSession *instance_sesn_ptr_target, unsigned long call_flags)
{
	//we approach it from the User's fence list (which is hybrid User and Base) instead of Searching the
	//Master Registeries for the User: both should
	//yield the same effect due to stringent referencial data integrity checks throughout

	Fence *f_ptr			=	NULL;
	ListEntry *eptr		=	NULL;
	Session *sesn_ptr_target = SessionOffInstanceHolder(instance_sesn_ptr_target);
	SessionService *ss_ptr  = SESSION_SERVICE(sesn_ptr_target);
	int error = 0;

	//NEVER USE FOR LOOP CONSTRUCT FOR ITERATION
	Queue 					tmp_que;
	FenceStateDescriptor	*fence_state_descriptor = NULL;
	InstanceHolderForFenceStateDescriptor *instance_fstate_ptr;

	size_t list_count = SESSION_FENCE_LIST_SIZE(sesn_ptr_target);//prevent going on endless loop where one of the feneces could not be unlocked
	while (SESSION_FENCE_LIST_SIZE(sesn_ptr_target) != 0 && list_count--) {
		eptr = SESSION_FENCE_LIST(sesn_ptr_target).head;
		if (IS_PRESENT(eptr)) {
			fence_state_descriptor = FenceStateDescriptorOffInstanceHolder((InstanceHolderForFenceStateDescriptor *)eptr->whatever);
			f_ptr = FENCESTATE_FENCE(fence_state_descriptor);

			FenceEventsLockRWCtx(THREAD_CONTEXT_PTR, f_ptr, _LOCK_TRY_FLAG_TRUE, SESSION_RESULT_PTR(sesn_ptr_target), __func__);
			if (SESSION_RESULT_TYPE_EQUAL(sesn_ptr_target, RESULT_TYPE_ERR)) {
				error++;
				//TODO: POP the fence off forcibly from user session this can cause endless loop if a fence is locked
				continue;
			}

			bool fence_lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr_target, RESCODE_PROG_LOCKED_BY_THIS_THREAD));

			if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_BASEFENCE)) {
#ifdef __UF_FULLDEBUG
				syslog (LOG_DEBUG, "%s: REMOVING (cid='%lu' uname='%s' fence_count='%d') from BaseFence (bid='%lu fcname='%s' user_count='%d')...",
									 __func__, sesn_ptr->session_id,
									 ss_ptr->user.user_details.user_name, SESSION_FENCE_LIST_SIZE(sesn_ptr_target),
									 f_ptr->fence_id, f_ptr->fence_location.canonical_name, f_ptr->fence_user_sessions_list.nEntries);
#endif

				_RemoveUserFromBaseFence(instance_sesn_ptr_target, f_ptr, call_flags);
			} else if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_USERFENCE)) {
#ifdef __UF_FULLDEBUG
				syslog (LOG_DEBUG, "%s: REMOVING (cid='%lu' uname='%s' fence_count='%d') from UserFence (bid='%lu fcname='%s' user_count='%d')...",
										 __func__, sesn_ptr->session_id,
										 ss_ptr->user.user_details.user_name, SESSION_FENCE_LIST_SIZE(sesn_ptr_target),
										 f_ptr->fence_id, f_ptr->fence_location.canonical_name, f_ptr->fence_user_sessions_list.nEntries);
#endif

				_RemoveUserFromUserFence(instance_sesn_ptr_target, f_ptr, call_flags);
			} else {
				//this is a truly sad condition... something is screwed up
#ifdef __UF_TESTING
				syslog (LOG_INFO, "%s: ERROR: COULD NOT DETERMINE FENCE TYPE  (fid='%lu fcname='%s' user_count='%d') FOR (cid='%lu' uname='%s' fence_count='%d')...",
						__func__, f_ptr->fence_id, f_ptr->fence_location.canonical_name, f_ptr->fence_user_sessions_list.nEntries,
						SESSION_ID(sesn_ptr_target),
						ss_ptr->user.user_details.user_name, SESSION_FENCE_LIST_SIZE(sesn_ptr_target));
#endif
				error++;
			}

			if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr_target));
		}
	}//while

	if (error) {
		syslog (LOG_INFO, "%s: ERROR (error_count='%d'): SOME FENCES HAD UNKNOWN TYPE OR COULD NOT BE LOCKED...  (o:'%p', cid:'%lu', fence_count:'%d')...", __func__, error, sesn_ptr_target, SESSION_ID(sesn_ptr_target), SESSION_FENCE_LIST_SIZE(sesn_ptr_target));

		return 0;
	}

	return 1;//all good

}

/**
 * 	@brief: Remove user from a Fence based on  fenceid

 * 	@locks f_ptr_in: NONE
 * 	@unlocks f_ptr_in
 * 	@locked RW f_ptr: must be locked by the caller
 * 	@locked RW sesn_ptr_target: must be locked by the caller nd fully loaded with context

 * 	@call_flag CALL_FLAG_DONT_BROADCAST_FENCE_EVENT: if not present, the event will be broadcasted Remote Sessions may set that.
 * 	@call_flag FENCE_CALLFLAG_ROAMING_GEOFENCE: if not present, update the update this property of and broadcast backend change

 * 	@returns: on success the eventid>0
 */
inline unsigned long
RemoveUserFromFence (InstanceHolderForSession *instance_sesn_ptr_target, Fence *f_ptr_in, unsigned long call_flags)
{
	Fence									*f_ptr						= NULL;
	FenceStateDescriptor 	*fence_state_ptr	=	NULL;
	ListEntry							*eptr							= NULL;

	Session *sesn_ptr_target                = SessionOffInstanceHolder(instance_sesn_ptr_target);
	SessionService				*ss_ptr						= &(sesn_ptr_target->sservice);

	//this is integrity check could be relaxed in the future
  InstanceHolderForFenceStateDescriptor *instance_fstate_ptr = _FindFenceInUserListByID(SESSION_FENCE_LIST_PTR(sesn_ptr_target), FENCE_ID(f_ptr_in));
	if (IS_PRESENT(instance_fstate_ptr)) {
	  fence_state_ptr = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);

    if (IS_PRESENT((f_ptr = FENCESTATE_FENCE(fence_state_ptr))) &&
        IS_PRESENT(FindUserInFenceSessionListByID(&FENCE_USER_SESSION_LIST(f_ptr_in), f_ptr_in, SESSION_ID(sesn_ptr_target)))) {

      if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_BASEFENCE)) {
#ifdef __UF_TESTING
        syslog(LOG_DEBUG,
               "%s: REMOVING (cid:'%lu' uname:'%s' fence_count:'%d') from BaseFence (bid='%lu fcname='%s' user_count='%d')...",
               __func__,
               SESSION_ID(sesn_ptr_target), SESSION_USERNAME(sesn_ptr_target),
               SESSION_FENCE_LIST_SIZE(sesn_ptr_target),
               FENCE_ID(f_ptr), FENCE_CNAME(f_ptr), FENCE_USER_SESSION_LIST_SIZE(f_ptr));
#endif
        _RemoveUserFromBaseFence(instance_sesn_ptr_target, f_ptr, call_flags);

        //
        if (!(call_flags & FENCE_CALLFLAG_ROAMING_GEOFENCE)) {
          if (IS_PRESENT(SESSION_GEOFENCE_CURRENT_INSTANCE(sesn_ptr_target)) &&
              FENCE_ID(f_ptr_in) == FENCE_ID(SESSION_GEOFENCE_CURRENT(sesn_ptr_target))) {
            FenceDecrementReference(SESSION_GEOFENCE_CURRENT_INSTANCE(sesn_ptr_target), 1);
            SESSION_GEOFENCE_CURRENT_INSTANCE(sesn_ptr_target) = NULL;

            if (!(call_flags & CALL_FLAG_DONT_BROADCAST_FENCE_EVENT))
              UpdateBackendSessionGeoJoinData(sesn_ptr_target, NULL, IS_PRESENT(SESSION_GEOFENCE_LAST_INSTANCE(sesn_ptr_target))?SESSION_GEOFENCE_LAST(sesn_ptr_target):NULL);
          }
        }

        return f_ptr->fence_events.last_event_id;//success case
      } else if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_USERFENCE)) {
#ifdef __UF_TESTING
        syslog(LOG_DEBUG,
               "%s: REMOVING (cid:'%lu' uname:'%s' fence_count:'%d') from UserFence (bid='%lu fcname='%s' user_count='%d')...",
               __func__,
               SESSION_ID(sesn_ptr_target),
               SESSION_USERNAME(sesn_ptr_target), SESSION_FENCE_LIST_SIZE(sesn_ptr_target),
               FENCE_ID(f_ptr), FENCE_CNAME(f_ptr), f_ptr->fence_user_sessions_list.nEntries);
#endif

        _RemoveUserFromUserFence(instance_sesn_ptr_target, f_ptr, call_flags);//mark for destruction if count is zero

        return f_ptr->fence_events.last_event_id;//success case
      } else {
        //this is a truly sad condition... something is screwed up
        syslog(LOG_ERR,
               "%s: ERROR: COULD NOT DETERMINE FENCE TYPE  (bid:'%lu fcname:'%s' user_count:'%d') FOR (cid='%lu' uname='%s' fence_count='%d')...",
               __func__,
               f_ptr->fence_id, f_ptr->fence_location.canonical_name, f_ptr->fence_user_sessions_list.nEntries,
               SESSION_ID(sesn_ptr_target), SESSION_USERNAME(sesn_ptr_target),
               SESSION_FENCE_LIST_SIZE(sesn_ptr_target));
      }

    } else goto return_error_not_found;
  } else {
	  goto return_error_not_found;
	}

	return 0;

  return_error_not_found:
  syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', fo:'%p', cid:'%lu', bid:'%lu', uname:'%s', user_fence_count:'%d', fence_user_count:'%d'}: DATA SYNC ERROR: COULD NOT REMOVE UserFence: NOT IN USER'S FENCE LIST...", __func__,
          pthread_self(), sesn_ptr_target, f_ptr_in, SESSION_ID(sesn_ptr_target),
          FENCE_ID(f_ptr_in),
          SESSION_USERNAME(sesn_ptr_target), SESSION_FENCE_LIST_SIZE(sesn_ptr_target), f_ptr_in->fence_user_sessions_list.nEntries);

  return 0;

}

#define USER_FENCE_LIST			(0x1U<<1U) //requires key but otherwise visible
#define FENCE_USER_LIST			(0x1U<<2U)

//
//this a high level removal routine, employing lower level helper routines defined below
//Remove user from ONE UserFence and unlinks as necessary
//Fence will be destroyed if fence stickiness rule is not satisfied. Destruction happens in another helper routine
//SessionService and User are not touched
//a mirror call is required for BaseFences.
//can be used in a loop to iterate over all user fences. perhaps not efficient, but safe and predictable

//
/**
 * 	@brief: A highlevel removal routine for removing and unlinking users from user fence
 * 	@locked f_ptr: must be in RW locked
 * 	@locked sesn_ptr:
 * 	@call_flag CALL_FLAG_DONT_BROADCAST_FENCE_EVENT: if not present, the event will be broadcasted
 */
static Fence *
_RemoveUserFromUserFence (InstanceHolderForSession *instance_sesn_ptr, Fence *f_ptr, unsigned long call_flags)
{
	unsigned score = 0;
	Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	//integrity check: is this user member of the fence
	if ((score = _CrossCheckUserInFenceAndFenceInUser(f_ptr, sesn_ptr))) {
		FenceEvent fence_event = {0};

		if ((score&USER_FENCE_LIST) && (score&FENCE_USER_LIST)) {
		  InstanceHolderForFenceStateDescriptor *instance_fstate_ptr;
			FenceStateDescriptor *fence_state_ptr_leaving	=	NULL;
			FenceStateDescriptor	fence_state_for_invited_by_only = {0};

			instance_fstate_ptr = IsUserMemberOfThisFence(SESSION_INVITED_FENCE_LIST_PTR(sesn_ptr), f_ptr, false/*FLAG_FENCE_LOCK_FALSE*/);

			if (IS_PRESENT(instance_fstate_ptr)) {
        //we need this value to remove record bewe lose the stateahead of updating the backend
        fence_state_ptr_leaving = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
        fence_state_for_invited_by_only.invited_by = fence_state_ptr_leaving->invited_by;
      }
#if 0
			//is the user owns the user fence
			if (f_ptr->fence_owner_id==ss_ptr->user.user_details.id)
			{
				//TODO: OK we are not processing this condition at this stage
				syslog(LOG_INFO, "%s: Fence owner is leaving", __func__);
			}
#endif
			if (f_ptr->fence_user_sessions_list.nEntries == 1) {
			 //OK last user in Fence we'll destruct the fence unless sticky
				//if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_STICKY))//AA 0810
				{//sticky bit is on we'll leave the fence up, but stil unlink user
					syslog(LOG_DEBUG, "%s: STICKY BIT IS ON: Fence owner is leaving: user count will drop to zero.", __func__);
					_RemoveUserFromUserFenceAndUnlinkUser(f_ptr, instance_sesn_ptr, false/*dangling_session*/);
				}
			} else {//more users remaining in the fence we just unlink user
				_RemoveUserFromUserFenceAndUnlinkUser(f_ptr, instance_sesn_ptr, false/*dangling_session*/);
			}

			if (!(call_flags&CALL_FLAG_DONT_BROADCAST_FENCE_EVENT)) {
				if (unlikely(IS_EMPTY(UpdateBackendFenceData (sesn_ptr, f_ptr, &fence_state_for_invited_by_only, EVENT_TYPE_FENCE_USER_PARTED, &((FenceEvent){})))))
					return NULL;
			}

			return f_ptr;
		} else {//one of the bits is unset
			syslog(LOG_DEBUG, "%s {pid:'%lu'}: one bit is unset", __func__, pthread_self());

			return NULL;
		}
	} else {
		syslog(LOG_DEBUG, "%s {pid:'%lu'}: COULD NOT find user", __func__, pthread_self());

		return NULL;
	}

}

/**
 * 	@brief: A highlevel removal routine for removing user from base fence. base fences are never destroyed.
 * 	@locked f_ptr: must be in RW locked
 * 	@locked sesn_ptr: target session. Must be fully loaded
 * 	@call_flag CALL_FLAG_DONT_BROADCAST_FENCE_EVENT: if not present, the event will be broadcasted
 */
inline static Fence *
_RemoveUserFromBaseFence (InstanceHolderForSession *instance_sesn_ptr, Fence *f_ptr, unsigned long call_flags)
{
	unsigned score = 0;
	Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	//integrity check: is this user member of the fence
	if ((score = _CrossCheckUserInFenceAndFenceInUser(f_ptr, sesn_ptr))) {
		FenceEvent *fe_ptr;

		if ((score&USER_FENCE_LIST) && (score&FENCE_USER_LIST)) {//both bits are set
			FenceStateDescriptor *fence_state_ptr_leaving	=	NULL;
			InstanceHolderForFenceStateDescriptor *instance_fstate_ptr;
			FenceStateDescriptor	fence_state_for_invited_by_only = {0};

			instance_fstate_ptr = IsUserMemberOfThisFence(SESSION_INVITED_FENCE_LIST_PTR(sesn_ptr), f_ptr, false/*FLAG_FENCE_LOCK_FALSE*/);
			if (IS_PRESENT(instance_fstate_ptr)) {
        fence_state_ptr_leaving = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
        //we need this value to remove record bewe lose the stateahead of updating the backend, ALTHOUGH FOR BASEFENCE VALUE IS ALWAY 0
        fence_state_for_invited_by_only.invited_by = fence_state_ptr_leaving->invited_by;
      }

			if (!(call_flags&CALL_FLAG_DONT_BROADCAST_FENCE_EVENT)) {
				FenceEvent fence_event = {0};
				//for remote sessions the above flag prohibits generations of fence event. We also
				//prohibit netwrk broadcast for the same reason below.
				//this function require connected session to intercat with backends and remote sessions dont have that
				FenceEvent *fe_ptr = RegisterFenceEvent(sesn_ptr, f_ptr, EVENT_TYPE_FENCE_USER_PARTED,  NULL, 0/*LOCK_FLAG*/, &fence_event);

				if (unlikely(IS_EMPTY(fe_ptr)))	return NULL;

        DbBackendInsertUfsrvEvent ((UfsrvEvent *)fe_ptr);
			}
#if 0
			//is the user owns the user fence
			if (f_ptr->fence_owner_id==ss_ptr->user.user_details.id)
			{
				//TODO: OK we are not processing this condition at this stage
				syslog(LOG_DEBUG, "%s: Fence owner is leaving", __func__);
			}
#endif
			if (f_ptr->fence_user_sessions_list.nEntries == 1) {//OK last user in Fence is leaving, but unlike UserFence we never destruct upon this condition
#ifdef __UF_TESTING
				syslog(LOG_DEBUG, "%s: BaseFence count will drop to zero.", __func__);
#endif
				_RemoveUserFromBaseFenceAndUnlinkUser(f_ptr, instance_sesn_ptr, false/*dangling_session*/);
			} else {//more users remaining in the fence we just unlink user
				_RemoveUserFromBaseFenceAndUnlinkUser(f_ptr, instance_sesn_ptr, false/*dangling_session*/);
			}

			if (!(call_flags&CALL_FLAG_DONT_BROADCAST_FENCE_EVENT)) {
				//no need for explicit FenceEvent object
				UpdateBackendFenceData (sesn_ptr, f_ptr, &fence_state_for_invited_by_only, EVENT_TYPE_FENCE_USER_PARTED, &((FenceEvent){}));
			}

			return f_ptr;
		} else {//one of the bits is unset
			syslog(LOG_DEBUG, "%s: one bit is unset", __func__);
			return NULL;
		}
	}//find user
	else {//user was not found
		syslog(LOG_DEBUG, "%s (pid:'%lu'): COULD NOT find user", __func__, pthread_self());

		return NULL;
	}

}

/**
 * 	@param sesn_ptr: Fully loaded Session in connected or Emphemeral mode which is target for removal
 * 	@param fence_state_joined: Fence to which user has invitation
 * 	@param fence_call_flags CALL_FLAG_WRITEBACK_FENCE_DATA_TO_BACKEND:
* 	@param fence_call_flags FENCE_CALLFLAG_TRANSFER_INVITE_CONTEXT: indicates invited fence is becoming a joined so need invite context transfered
 * 	@locked sesn_ptr_this, sesn_ptr_target: must be locked by the caller
 * 	@locked f_ptr: must be locked in the caller's environment
 * 	@returns: success is where the fence has been removed 2x therefore returning 2. 0 empty list. <0 error
 *
 * 	@worker: ufsrv, io
 */
int
RemoveUserFromInvitedList(InstanceHolderForSession *instance_sesn_ptr, FenceStateDescriptor *fence_state_joined, FenceEvent *fe_ptr_out, unsigned long fence_call_flags)
{
	int		rc			= 0;
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
	Fence *f_ptr = FenceOffInstanceHolder(fence_state_joined->instance_holder_fence);

	if (FENCE_INVITED_LIST_EMPTY(f_ptr)) {
		return rc;
	}

	//1) remove fence reference from Session's invite list (referenced as FenceStateDescriptor)
  InstanceHolderForFenceStateDescriptor *instance_fstate_ptr = RemoveFenceFromSessionInvitedFenceList (SESSION_INVITED_FENCE_LIST_PTR(sesn_ptr), FENCE_ID(f_ptr));

	if (IS_PRESENT(instance_fstate_ptr)) {
    FenceStateDescriptor *fence_state_descriptor = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', fid:'%lu', invite_list_sz:'%u'} Fence removed from Session's InviteList...", __func__, pthread_self(), sesn_ptr, FENCE_ID(f_ptr), SESSION_INVITED_FENCE_LIST_SIZE(sesn_ptr));
#endif

	//2)remove session from Fence's invite list
		if (RemoveThisFromList(&(FENCE_INVITED_USER_SESSIONS_LIST(f_ptr)), instance_sesn_ptr)) {
			SessionDecrementReference (instance_sesn_ptr, 1);
			rc++;
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', fid:'%lu', invite_list_sz:'%u'} Session removed from Fences's InviteList...", __func__, pthread_self(), sesn_ptr, FENCE_ID(f_ptr), FENCE_INVITED_USER_SESSIONS_LIST_SIZE(f_ptr));
#endif
		}

		if (fence_call_flags&FENCE_CALLFLAG_TRANSFER_INVITE_CONTEXT) {
			memcpy(&(fence_state_joined->invited_by), &(fence_state_descriptor->invited_by), sizeof(UfsrvUid));
			fence_state_joined->when_invited = fence_state_descriptor->when_invited;
		}

		if (fence_call_flags&FENCE_CALLFLAG_WRITEBACK_DATA_TO_BACKEND) {
			UpdateBackendFenceInvitedData(NULL/*inviter*/, sesn_ptr/*invited*/, fence_state_descriptor, fe_ptr_out->event_type, fe_ptr_out);
		}

		FenceDecrementReference(fence_state_joined->instance_holder_fence, 1);
		RecyclerPut(FenceStateDescriptorPoolTypeNumber(), (RecyclerClientData *)instance_fstate_ptr, (ContextData *)NULL, CALLFLAGS_EMPTY);
		rc++;

		return rc;
	}

	syslog(LOG_ERR, "%s {pid:'%lu', o:'%p', fo:'%p'}: FAILED TO ACQUIRE A VALID FenceStateDescriptor..", __func__, pthread_self(), sesn_ptr, f_ptr);

	return 0;
}

/**
 * 	@brief: Remove all users in Invited List conducting full network ceremonies
 * 	@locked f_ptr:
 *
 * 	@returns: number of unsuccessful processed users, otherwise success is 0
 */
size_t
NetworkRemoveUsersFromInviteList (InstanceContextForSession *ctx_ptr_carrier, InstanceHolderForFence *instance_f_ptr)
{
	size_t 		dangling_users_counter = 0;
	ListEntry *eptr;
	Session *sesn_ptr_invited;

	Fence *f_ptr = FenceOffInstanceHolder(instance_f_ptr);

	while (!FENCE_INVITED_LIST_EMPTY(f_ptr)) {
		if ((eptr = f_ptr->fence_user_sessions_invited_list.head)) {
			sesn_ptr_invited = SessionOffInstanceHolder((InstanceHolderForSession *) eptr->whatever);
			SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_invited, _LOCK_TRY_FLAG_TRUE, __func__);
			if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR)) {
				dangling_users_counter++;
				continue;
			}

			bool lock_already_owned = (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_BY_THIS_THREAD));
			FenceEvent 	fence_event = {0};	fence_event.event_type=EVENT_TYPE_FENCE_USER_UNINVITED;
			SessionTransferAccessContext(ctx_ptr_carrier->sesn_ptr, sesn_ptr_invited, false);
      RemoveUserFromInvitedList((InstanceHolderForSession *) eptr->whatever, &((FenceStateDescriptor) {.instance_holder_fence=instance_f_ptr}), &fence_event, FENCE_CALLFLAG_WRITEBACK_DATA_TO_BACKEND);

			if (!lock_already_owned)	{
				SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_invited, __func__);
			}

			//dont lock sesn_ptr_invited, as it gets locked downstream at marshaling
			MarshalFenceUnInvitedToUser(ctx_ptr_carrier, &(InstanceContextForSession){(InstanceHolderForSession *) eptr->whatever, sesn_ptr_invited}, f_ptr, &fence_event, SESSION_CALLFLAGS_EMPTY);
		}
	}

	return dangling_users_counter;
}

inline static void
_DestructUserFenceSnapshot (Session *sesn_ptr, Fence *f_ptr, unsigned long call_flags);

/**
 * 	@brief: In snapshot mode, we dont connect users
 */
inline static void
_DestructUserFenceSnapshot (Session *sesn_ptr, Fence *f_ptr, unsigned long call_flags)
{
//	if (IS_PRESENT(FENCE_CNAME(f_ptr)))	 free (FENCE_CNAME(f_ptr));
//	f_ptr->attrs		=	0;
//	FENCE_ID(f_ptr)	=	0;
	_DePopulateFenceData (f_ptr, 0);

	return;
}

//#if 1
//
//destructive: all resources associated with _a Fence_ are removed and completely unlinked.
//DO NOT CALL ON A LOOP WITH  ListEntry->next s you'd be shooting yourself in the foot as you cycle through loop iteration
//because the structure of the list will have changed
//assumes USers are in Fence and will loop unlink destruct each
//user service routines to unlink
//
/**
 * 	@brief: This is designed to work with the type pool, being invoked from PUT and DESTRUCT callbacks. It will need a
 * 	slight adaptation to operate as a standalone.
 *
 * 	@sesn_ptr: the session owner, who is (most likely) in the Fence's user session list
 * 	@brief: Deep destructor: all resources associated with Fence are removed, especially if SELF_DESTRUCT is SET
 * 	@locks f_ptr: if FENCE_CALLFLAG_LOCK_FENCE is set
 * 	@unlocks f_ptr: unless FENCE_CALLFLAG_KEEP_FENCE_LOCKED is set
 * 	@locked sesn_ptr: must be locked in the calling environment
 */
inline static void
_DestructUserFence (Session *sesn_ptr, InstanceContextForFence *instance_ctx_ptr, unsigned long call_flags)
{
	if ((call_flags&FENCE_CALLFLAG_SNAPSHOT_INSTANCE) ||	(F_ATTR_IS_SET(instance_ctx_ptr->f_ptr->attrs, F_ATTR_SNAPSHOT)))	return (_DestructUserFenceSnapshot(sesn_ptr, instance_ctx_ptr->f_ptr, call_flags));

	bool fence_lock_already_owned = false;

	if (call_flags&FENCE_CALLFLAG_LOCK_FENCE) {
		FenceEventsLockRWCtx(THREAD_CONTEXT_PTR, instance_ctx_ptr->f_ptr, _LOCK_TRY_FLAG_FALSE, SESSION_RESULT_PTR(sesn_ptr), __func__);

		if (SESSION_RESULT_TYPE_EQUAL(sesn_ptr, RESULT_TYPE_ERR)) return;

		fence_lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_PROG_LOCKED_BY_THIS_THREAD));
	}

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s: {pid:'%lu', fo:'%p', bid:'%lu', fcname: '%s'} has (user_count='%d') Sessions...", __func__, pthread_self(), instance_ctx_ptr->f_ptr, instance_ctx_ptr->f_ptr->fence_id, instance_ctx_ptr->f_ptr->fence_location.canonical_name, instance_ctx_ptr->f_ptr->fence_user_sessions_list.nEntries);
#endif

	ListEntry *eptr = NULL;

	bool		dangling_session_status	=	false;
	bool    lock_already_owned			= false;
	Session *sesn_ptr_other_user		=	NULL;
	InstanceHolderForSession *instance_sesn_ptr_other_user;

	while (instance_ctx_ptr->f_ptr->fence_user_sessions_list.nEntries != 0) {
		if ((eptr = instance_ctx_ptr->f_ptr->fence_user_sessions_list.head)) {
			sesn_ptr_other_user = SessionOffInstanceHolder((InstanceHolderForSession *)eptr->whatever);

			//since sesn_ptr is already locked, we skip it
			if (NOT_TRUE(SESSION_ID(sesn_ptr) == (SESSION_ID(sesn_ptr_other_user)))) {
				SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_other_user, _LOCK_TRY_FLAG_TRUE, __func__);
				if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR)) {
					//lock failed: Session will still be removed from theFence's List but Fence will remain on the user's List of fences, although marked as dangling
					dangling_session_status = true;
				}
			}

			lock_already_owned = (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_BY_THIS_THREAD));

			_RemoveUserFromUserFenceAndUnlinkUser(instance_ctx_ptr->f_ptr, (InstanceHolderForSession *)eptr->whatever, dangling_session_status);

			if (NOT_TRUE(SESSION_ID(sesn_ptr) == (SESSION_ID(sesn_ptr_other_user)))) {
				if (!lock_already_owned)	SessionUnLockCtx (THREAD_CONTEXT_PTR, sesn_ptr_other_user, __func__);
			}

			dangling_session_status = false;
		}
	}//while

	//TODO: do the same for invited list/blocked

	RemoveFromHash(&FenceRegistryIdHashTable, (void *)instance_ctx_ptr->instance_f_ptr);
	RemoveFromHash(&FenceRegistryCanonicalNameHashTable, (void *) instance_ctx_ptr->instance_f_ptr);

	ResetFencePermissions (instance_ctx_ptr->f_ptr);

	_DePopulateFenceData (instance_ctx_ptr->f_ptr, call_flags);

	if ((call_flags&FENCE_CALLFLAG_LOCK_FENCE) && !(call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED)) {
		if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, instance_ctx_ptr->f_ptr, SESSION_RESULT_PTR(sesn_ptr));
	}

	//TODO: LOST LOCK OWNERSHIP remove FENCE_CALLFLAG_KEEP_FENCE_LOCKED

	if (unlikely(call_flags&FENCE_CALLFLAG_SELF_DESTRUCT)) {
		pthread_rwlockattr_destroy (&(instance_ctx_ptr->f_ptr->fence_events.rwattr));

		free(instance_ctx_ptr->f_ptr);
	} else {
		//TODO: this cannot be called, because this is function is callback handler for put
		//RecyclerPut(FencePoolTypeNumber(), (RecyclerClientData *)f_ptr, (ContextData *)NULL, 0);
	}

}

/**
 * 	@brief:	Resets some of the data structure associated with a Fence in a way that suitable for reuse in the Recycler. This doesn't clean up the Fence-Session linking
 *
 * 	@locked f_ptr: must be locked in the calling environment
 */
inline static void
_DePopulateFenceData (Fence *f_ptr, unsigned long call_flags)
{
	_DestructFenceLocationDescription (&(f_ptr->fence_location));

	f_ptr->when					=0;
	f_ptr->time_to_live	=0;
	f_ptr->fence_id			=0;
	f_ptr->attrs				=0;
	f_ptr->max_users		=0;
	f_ptr->owner_uid		=0;

	if (IS_PRESENT(FENCE_AVATAR(f_ptr)))	{free (FENCE_AVATAR(f_ptr)); FENCE_AVATAR(f_ptr)=NULL;}

}

inline static void
_DestructFenceLocationDescription (FenceLocationDescription *location_ptr)
{
	if (!IS_EMPTY(location_ptr->canonical_name)) 			{free(location_ptr->canonical_name); location_ptr->canonical_name=NULL;}
	if (!IS_EMPTY(location_ptr->display_banner_name))	{free(location_ptr->display_banner_name); location_ptr->display_banner_name=NULL;}
	if (!IS_EMPTY(location_ptr->banner_name))					{free(location_ptr->banner_name); location_ptr->banner_name=NULL;}
	if (!IS_EMPTY(location_ptr->base_location))				{free(location_ptr->base_location); location_ptr->base_location=NULL;}

	DestructLocationDescription (&(location_ptr->fence_location));
}

/**
 * 	@brief: non destructive removal of referenced Fence and Session entities from each other
 * 	@locked: both Fence andSession must be locked by the caller
 * 	@locks: Directly done: bu decrementing refrences locks type recycler resources associated with Fence and Session
 */
inline static Fence *
_RemoveUserFromBaseFenceAndUnlinkUser(Fence *f_ptr, InstanceHolderForSession *instance_sesn_ptr, bool dangling_session_status)
{
	return _RemoveUserFromUserFenceAndUnlinkUser(f_ptr, instance_sesn_ptr, dangling_session_status);

}

/**
 * 	@brief: This is here for semantical clarity only.
 */
InstanceHolderForFenceStateDescriptor *
RemoveFenceFromSessionInvitedFenceList (List *sesn_fence_list, unsigned long fid)
{
	return _RemoveFenceFromList (sesn_fence_list, fid);
}

/**
 * 	@brief: Unlinks Fence from User's session list Pure data manipulation.
 */
InstanceHolderForFenceStateDescriptor *
RemoveFenceFromSessionFenceList (List *sesn_fence_list, Fence *f_ptr)
{
	return _RemoveFenceFromList (sesn_fence_list, FENCE_ID(f_ptr));
}

/**
 * 	@brief: introspects into the Session's FenceStateDescriptor List to find/remove the underlying Fence. This is necessary because
 * 	 FenceStateDescriptor is not exported and would be double handling to do it through the standard opaque 'RemoveThisFromList'
 */
static inline InstanceHolderForFenceStateDescriptor *
_RemoveFenceFromList (List *sesn_fence_list, unsigned long fid)
{
	int 		found	= 0;
	ListEntry	*lptr	= NULL,
				    *prev	= NULL;
	FenceStateDescriptor *fence_state_descriptor	= NULL;
  InstanceHolderForFenceStateDescriptor *instance_fstate_ptr = NULL;

	lptr = sesn_fence_list->head;

	while ((lptr!=NULL) && (!found)) {
    instance_fstate_ptr = (InstanceHolder *)lptr->whatever;
		fence_state_descriptor = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);

		if (FENCE_ID(FENCESTATE_FENCE(fence_state_descriptor)) == fid) {
			found = 1;
		} else {
			prev = lptr;
			lptr = lptr->next;
		}
	}

	if (!found)  return NULL;

	if ((prev == NULL)) {
		sesn_fence_list->head = lptr->next;
	} else if ((lptr->next == NULL)) {
		sesn_fence_list->tail = prev;
		sesn_fence_list->tail->next = NULL;
	} else {
		prev->next = lptr->next;
	}

	sesn_fence_list->nEntries--;

	memset (lptr, 0, sizeof(ListEntry));
	free (lptr);

	return instance_fstate_ptr;

}

/**
 * 	@brief: non destructive removal of referenced Fence and Session entities from each other
 * 	@param dangling_session: session has not been able to be locked so we only remove it from the fence's list
 * 	@locked: both Fence andSession must be locked by the caller
 * 	@locks: Directly done: but decrementing refrences locks type recycler resources associated with Fence and Session
 */
inline static Fence *
_RemoveUserFromUserFenceAndUnlinkUser(Fence *f_ptr, InstanceHolderForSession *instance_sesn_ptr, bool dangling_session)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
	SessionService *ss_ptr = SESSION_SERVICE(sesn_ptr);

	//TODO: this should be done somewhere else
	//if we are unlinking the user's baseloc fence, that's no longer valid relationship as we are removing the Fence
	if (ss_ptr->user.user_details.base_fence_local_id == FENCE_ID(f_ptr))	ss_ptr->user.user_details.base_fence_local_id = 0;

	if (IS_FALSE(dangling_session)) {
    InstanceHolderForFenceStateDescriptor *instance_fstate_ptr = RemoveFenceFromSessionFenceList (SESSION_FENCE_LIST_PTR(sesn_ptr), f_ptr);
		FenceStateDescriptor *fence_state_descriptor = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
		if (IS_PRESENT(fence_state_descriptor)) {
			FenceDecrementReference (fence_state_descriptor->instance_holder_fence, 1);
			RecyclerPut(FenceStateDescriptorPoolTypeNumber(), instance_fstate_ptr, (ContextData *)NULL, 0);
		}
	} else {
		//TODO
		//we can't remove it from the Session because we couldn't lock it so we may atomically mark  it as Fence statedescription as dangling
	}

	//do locking at higher level
	RemoveThisFromList (&(f_ptr->fence_user_sessions_list), instance_sesn_ptr);
	SessionDecrementReference (instance_sesn_ptr, 1);

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s (pid:'%lu', cid_removed:'%lu', uid_removed:'%lu' fence_count='%d'): SUCCESS: REMOVED  from (bid='%lu' user_count='%d')", __func__, pthread_self(), SESSION_ID(sesn_ptr),
		UfsrvUidGetSequenceId(&(ss_ptr->user.user_details.uid)), SESSION_FENCE_LIST_SIZE(sesn_ptr),
		FENCE_ID(f_ptr), f_ptr->fence_user_sessions_list.nEntries);
#endif

	return f_ptr;

}

// ---------- --------------- END OF REMOVE ROUTINES ---------------------


//
//essentially we should be able to cross reference the user across the fence and fence across the user
//ONE USER_FENCE at a time
//can be used in a loop to iterate over all FENCE-USER twins
//works for both USerFence and BAseFence
//important data integrity check
//bits are set to indicate status of linking
//f_ptr and session must be locked in the calling environment
//
inline static unsigned
_CrossCheckUserInFenceAndFenceInUser(Fence *f_ptr, Session *sesn_ptr)
{
	unsigned 	score	= 0x1;
	ListEntry 	*eptr	= NULL;
  InstanceHolderForSession *instance_sesn_ptr;

   //first check user in Fence's List
   for (eptr=f_ptr->fence_user_sessions_list.head; eptr; eptr=eptr->next) {
     Session *sesn_ptr_from_list = SessionOffInstanceHolder((InstanceHolder *)eptr->whatever);
	   if (SESSION_ID(sesn_ptr_from_list) == SESSION_ID(sesn_ptr)) {
		   score |= FENCE_USER_LIST;
		   break;
	   }
   }

   FenceStateDescriptor *fence_state_descriptor	= NULL;

   //second check fence in Users's List
   for (eptr=SESSION_FENCE_LIST(sesn_ptr).head; eptr; eptr=eptr->next) {

	   fence_state_descriptor = FenceStateDescriptorOffInstanceHolder((InstanceHolder *)eptr->whatever);
	   if (FENCE_ID(FENCESTATE_FENCE(fence_state_descriptor)) == FENCE_ID(f_ptr)) {
		   score |= USER_FENCE_LIST;
		   break;
	   }
   }

   return score;

}

/**
 * @brief: This is a data integrity check for invite lists that is performed after Session's been loaded from cachebackend.
 * @param sesn_ptr
 * @return how many list elements that were affected.
 * @locked sesn_ptr by caller
 * @locks f_ptr
 * @unlocks f_ptr
 */
static size_t
_CrossCheckInvitedListsForUser (InstanceHolderForSession *instance_sesn_ptr)
{
  size_t processed = 0;
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

  if (SESSION_FENCE_LIST_SIZE(sesn_ptr) > 0 && SESSION_INVITED_FENCE_LIST_SIZE(sesn_ptr) > 0) {
    ListEntry *eptr = NULL;
    ListEntry *eptr_invited = NULL;
    FenceStateDescriptor *fence_state_descriptor = NULL;
    FenceStateDescriptor *fence_state_descriptor_invited = NULL;

    FenceStateDescriptor *rouge_fences[SESSION_FENCE_LIST_SIZE(sesn_ptr)];
    memset(rouge_fences, 0, sizeof(rouge_fences));

    size_t idx = 0;
    for (eptr = SESSION_FENCE_LIST(sesn_ptr).head; eptr; eptr = eptr->next) {
      fence_state_descriptor = FenceStateDescriptorOffInstanceHolder((InstanceHolderForFenceStateDescriptor *) eptr->whatever);

      for (eptr_invited = SESSION_INVITED_FENCE_LIST(sesn_ptr).head; eptr_invited; eptr_invited = eptr_invited->next) {
        fence_state_descriptor_invited = FenceStateDescriptorOffInstanceHolder((InstanceHolderForFenceStateDescriptor *) eptr_invited->whatever);
        if (FENCE_ID(FENCESTATE_FENCE(fence_state_descriptor)) == FENCE_ID(FENCESTATE_FENCE(fence_state_descriptor_invited))) {
          rouge_fences[idx++] = fence_state_descriptor_invited;
        }
      }
    }

    size_t idx_processed = idx;
    bool fence_lock_already_owned;

    idx = 0;
    while (idx++ < idx_processed) {
      FenceEvent fence_event = {.event_type=EVENT_TYPE_FENCE_USER_LIST_CORRECTED};

      FenceEventsLockRWCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(rouge_fences[idx]), _LOCK_TRY_FLAG_FALSE, THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), __func__);

      if (THREAD_CONTEXT_UFSRV_RESULT_TYPE_ERR) continue;

      syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p, o:'%p', fo:'%p', fid:'%lu'}: ERROR: DATA INTEGRITY: FENCE ON INVITE LIST, BUT USER ALREADY JOINED ", __func__, pthread_self(), THREAD_CONTEXT_PTR, sesn_ptr, rouge_fences[idx], FENCE_ID(FENCESTATE_FENCE(rouge_fences[idx])));

      fence_lock_already_owned = THREAD_CONTEXT_UFSRV_RESULT_CODE_EQUAL(ufsrv_thread_context, RESCODE_PROG_LOCKED_BY_THIS_THREAD);
      RemoveUserFromInvitedList(instance_sesn_ptr, rouge_fences[idx], &fence_event, FENCE_CALLFLAG_WRITEBACK_DATA_TO_BACKEND);
      if (!fence_lock_already_owned)  FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FENCESTATE_FENCE(rouge_fences[idx]), THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));
    }

    return idx_processed;
  }

  return processed;
}


/**
 *	@brief Using the Fences's Sessions List check for the presence of the given session. As opposed to "_f_CrossCheckUserInFenceAndFenceInUser()", which
 *	performs pointer comparison, this function uses the logical session_id value, which is more correct in handling remote sessions.
 *	Another function IsUserMemberOfThisFence() uses the Session's fence's list.
 *
 *	@locked: f_ptr must be locked in caller environment
 *
 *	@blocks_on: NONE
 *
 *	@dynamic_memory: NONE
 */
inline int
CrossCheckSessionInFenceBySessionId (Fence *f_ptr, unsigned long session_id)
{
   ListEntry *eptr = NULL;

   for (eptr=f_ptr->fence_user_sessions_list.head; eptr; eptr=eptr->next) {

	   if (SESSION_ID(SessionOffInstanceHolder((InstanceHolderForSession *)eptr->whatever)) == session_id) {
		   return 1;
	   }
   }

   return 0;

}

/**
 * 	This is generalised implementation of CrossCheckSessionInFenceBySessionId (Fence *f_ptr, unsigned long session_id)
 *	@brief Using the Fences's provided user List check for the presence of the given session. As opposed to "_f_CrossCheckUserInFenceAndFenceInUser()", which
 *	performs pointer comparison, this function uses the logical user_id value, which is more correct in handling remote sessions.
 *	Another function IsUserMemberOfThisFence() uses the Session's fence's list.
 *
 *	@locked: f_ptr must be locked in caller environment
 *
 *	@blocks_on: NONE
 *
 *	@dynamic_memory: NONE
 */
static inline int
_CrossCheckSessionInFenceUserListByUserId (Fence *f_ptr, List *fence_user_list_ptr, unsigned long user_id)
{
  ListEntry *eptr = NULL;
  InstanceHolder *instance_holder_ptr = NULL;

  for (eptr=fence_user_list_ptr->head; eptr; eptr=eptr->next) {
    instance_holder_ptr = (InstanceHolder *)eptr->whatever;
    if (SESSION_USERID(((Session *)GetInstance(instance_holder_ptr))) == user_id) {
     return 1;
    }
  }

return 0;

}

/**
 *	@brief Using the Session;s Fences List check for the presence of the given fence. As opposed to "_f_CrossCheckUserInFenceAndFenceInUser()", which
 *	performs pointer comparison, this function uses the logical fence_id value, which is more correct in handling remote sessions.
 *	Another comparable function IsUserMemberOfThisFence().
 *
 *	@locked sesn_ptr: must be locked in caller environment
 *	@locks: None
 *	@blocks_on: NONE
 *
 *	@dynamic_memory: NONE
 */
inline int
CrossCheckFenceInSessionByFenceId (Session *sesn_ptr, unsigned long fence_id)
{
   ListEntry *eptr;
   FenceStateDescriptor *fence_descriptor;

   for (eptr=SESSION_FENCE_LIST(sesn_ptr).head; eptr; eptr=eptr->next) {
	   fence_descriptor = FenceStateDescriptorOffInstanceHolder((InstanceHolderForFenceStateDescriptor *)(eptr->whatever));
	   if (FENCESTATE_FENCE(fence_descriptor)->fence_id == fence_id) {
		   return 1;
	   }
   }

   return 0;

}

/**
 * This is a generalisation of CrossCheckFenceInSessionByFenceId (Session *sesn_ptr, unsigned long fence_id)
 *	@brief Using the provided Session's Fences List check for the presence of the given fence. As opposed to "_f_CrossCheckUserInFenceAndFenceInUser()", which
 *	performs pointer comparison, this function uses the logical fence_id value, which is more correct in handling remote sessions.
 *	Another comparable function IsUserMemberOfThisFence().
 *
 *	@locked sesn_ptr: must be locked in caller environment
 *	@locks: None
 *	@blocks_on: NONE
 *
 *	@dynamic_memory: NONE
 */
static inline int
_CrossCheckFenceInSessionFenceListByFenceId (Session *sesn_ptr, List *sesn_fence_ist_ptr, unsigned long fence_id)
{
   ListEntry *eptr;
   FenceStateDescriptor *fence_descriptor_ptr;

   for (eptr=sesn_fence_ist_ptr->head; eptr; eptr=eptr->next) {
	   fence_descriptor_ptr = (FenceStateDescriptor *)GetInstance(((InstanceHolder *)eptr->whatever));
	   if (FENCESTATE_FENCE(fence_descriptor_ptr)->fence_id == fence_id) {
		   return 1;
	   }
   }

   return 0;

}

inline InstanceHolderForFenceStateDescriptor *
FindFenceStateInSessionFenceListByFenceId (Session *sesn_ptr, List *sesn_fence_ist_ptr, unsigned long fence_id)
{
   ListEntry *eptr;
   FenceStateDescriptor *fence_descriptor;

   for (eptr=sesn_fence_ist_ptr->head; eptr; eptr=eptr->next) {
     fence_descriptor = FenceStateDescriptorOffInstanceHolder((InstanceHolder *)eptr->whatever);
	   if (FENCESTATE_FENCE(fence_descriptor)->fence_id == fence_id) {
		   return (InstanceHolderForFenceStateDescriptor *)eptr->whatever;
	   }
   }

   return NULL;

}

inline static void _JsonFormatFenceTypeSpecs (const Fence *f_ptr, json_object *jobj);

struct json_object *
JsonFormatFenceForDbBackend(Session *sesn_ptr_carrier, Fence *f_ptr, enum DigestMode digest_mode, unsigned long fence_call_flags)
{
	bool 			fence_lock_already_owned	=	false;
	bool    	is_uid_hashed_locally 		= false;
	char 		  uid_encoded[CONFIG_MAX_UFSRV_ID_ENCODED_SZ+1] = {0};
	UfsrvUid	uid = {0};

	if (fence_call_flags&FENCE_CALLFLAG_LOCK_FENCE)
	{
		FenceEventsLockRDCtx(THREAD_CONTEXT_PTR, f_ptr, _LOCK_TRY_FLAG_TRUE, THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), __func__);

		if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR))	return NULL;

		fence_lock_already_owned=(_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_BY_THIS_THREAD));
	}

	struct json_object *jobj=json_object_new_object();
	if (IS_STR_LOADED(FENCE_DNAME(f_ptr)))		json_object_object_add (jobj,"fname", 		json_object_new_string(FENCE_DNAME(f_ptr)));
	json_object_object_add (jobj,"fid", 			json_object_new_int64(FENCE_ID(f_ptr)));
	json_object_object_add (jobj,"eid", 			json_object_new_int64(f_ptr->fence_events.last_event_id));
	if (FENCE_OWNER_UID(f_ptr)!=1) {
		UfsrvUid *uid_ptr = GetUfsrvUid(sesn_ptr_carrier, FENCE_OWNER_UID(f_ptr), &uid, true, NULL);
		if (IS_PRESENT(uid_ptr)) {
      UfsrvUidConvertSerialise(uid_ptr, uid_encoded);
			json_object_object_add(jobj, "owner_ufsrvid", json_object_new_string(uid_encoded));
		}
	} else {
		json_object_object_add(jobj, "owner_ufsrvuid", json_object_new_string(UFSRV_SYSTEMUSER_UID));
	}
//	todo: enable
//	_JsonFormatFenceTypeSpecs (f_ptr, jobj);

	if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_BASEFENCE))	json_object_object_add (jobj,"type", 			json_object_new_int(FENCE_RECORD__FENCE_TYPE__GEO));
	else 																								json_object_object_add (jobj,"type", 			json_object_new_int(FENCE_RECORD__FENCE_TYPE__USER));

	if	(F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_PRIVATE))		json_object_object_add (jobj,"privacy_mode", 			json_object_new_int(FENCE_RECORD__PRIVACY_MODE__PRIVATE));
	else	json_object_object_add (jobj,"privacy_mode", 			json_object_new_int(FENCE_RECORD__PRIVACY_MODE__PUBLIC));

	if	(F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_BROADCAST))		json_object_object_add (jobj,"delivery_mode", 			json_object_new_int(FENCE_RECORD__DELIVERY_MODE__BROADCAST));
	else if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_BROADCAST_ONEWAY))	json_object_object_add (jobj,"delivery_mode", 			json_object_new_int(FENCE_RECORD__DELIVERY_MODE__BROADCAST_ONEWAY));
	else json_object_object_add (jobj,"delivery_mode", 			json_object_new_int(FENCE_RECORD__DELIVERY_MODE__MANY)); //defaults to F_ATTR_MANY_TO_MANY

	if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_JOINMODE_OPEN))
	{
		if (!F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_JOINMODE_KEY))	json_object_object_add (jobj,"join_mode", json_object_new_int(FENCE_RECORD__JOIN_MODE__OPEN));
		else json_object_object_add (jobj,"join_mode", json_object_new_int(FENCE_RECORD__JOIN_MODE__OPEN_WITH_KEY));
	}
	else if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_JOINMODE_INVITE_ONLY))
	{
		if (!F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_JOINMODE_KEY))	json_object_object_add (jobj,"join_mode", json_object_new_int(FENCE_RECORD__JOIN_MODE__INVITE));
		else json_object_object_add (jobj,"join_mode", json_object_new_int(FENCE_RECORD__JOIN_MODE__INVITE_WITH_KEY));
	}
	else	json_object_object_add (jobj,"join_mode", json_object_new_int(FENCE_RECORD__JOIN_MODE__OPEN)); //defaults to open


	if (IS_STR_LOADED(FENCE_CNAME(f_ptr)))		json_object_object_add (jobj,"fcname", 		json_object_new_string(FENCE_CNAME(f_ptr)));

	json_object_object_add (jobj,"msg_expiry", 		json_object_new_int64(FENCE_MSG_EXPIRY(f_ptr)));

	if (digest_mode==DIGESTMODE_BRIEF) goto record_ready;//digest mode

	{
		//add more attributes for full
		if (IS_STR_LOADED(FENCE_BASELOC(f_ptr)))		json_object_object_add (jobj,"baseloc", 		json_object_new_string(FENCE_BASELOC(f_ptr)));
		if (IS_STR_LOADED(FENCE_AVATAR(f_ptr)))		json_object_object_add (jobj,"avatar", 		json_object_new_string(FENCE_AVATAR(f_ptr)));
		if (IS_STR_LOADED(FENCE_BNAME(f_ptr)))		json_object_object_add (jobj,"bname", 		json_object_new_string(FENCE_BNAME(f_ptr)));
		json_object_object_add (jobj,"when_created", 		json_object_new_int64(FENCE_WHEN_CREATED(f_ptr)));
		json_object_object_add (jobj,"when_modified", 		json_object_new_int64(FENCE_WHEN_MODIFIED(f_ptr)));
		json_object_object_add (jobj,"max_members", 		json_object_new_int(FENCE_MAX_MEMBERS(f_ptr)));
		json_object_object_add (jobj,"ttl", 		json_object_new_int64(FENCE_TTL(f_ptr)));
		json_object_object_add (jobj,"longitude", 		json_object_new_double(FENCE_LONGITUDE(f_ptr)));
		json_object_object_add (jobj,"latitude", 		json_object_new_double(FENCE_LATITUDE(f_ptr)));
	}

	record_ready:
	if (fence_call_flags&FENCE_CALLFLAG_LOCK_FENCE) {
		if (!fence_lock_already_owned) FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));
	}

	return jobj;

}

inline static void
_JsonFormatFenceTypeSpecs (const Fence *f_ptr, json_object *jobj)
{
	if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_BASEFENCE))	json_object_object_add (jobj,"type", 			json_object_new_int(FENCE_RECORD__FENCE_TYPE__GEO));
	else 																								json_object_object_add (jobj,"type", 			json_object_new_int(FENCE_RECORD__FENCE_TYPE__USER));

	if	(F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_PRIVATE))		json_object_object_add (jobj,"privacy_mode", 			json_object_new_int(FENCE_RECORD__PRIVACY_MODE__PRIVATE));
	else	json_object_object_add (jobj,"privacy_mode", 			json_object_new_int(FENCE_RECORD__PRIVACY_MODE__PUBLIC));

	if	(F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_BROADCAST))		json_object_object_add (jobj,"delivery_mode", 			json_object_new_int(FENCE_RECORD__DELIVERY_MODE__BROADCAST));
	else if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_BROADCAST_ONEWAY))	json_object_object_add (jobj,"delivery_mode", 			json_object_new_int(FENCE_RECORD__DELIVERY_MODE__BROADCAST_ONEWAY));
	else json_object_object_add (jobj,"delivery_mode", 			json_object_new_int(FENCE_RECORD__DELIVERY_MODE__MANY)); //defaults to F_ATTR_MANY_TO_MANY

	if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_JOINMODE_OPEN))
	{
		if (!F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_JOINMODE_KEY))	json_object_object_add (jobj,"join_mode", json_object_new_int(FENCE_RECORD__JOIN_MODE__OPEN));
		else json_object_object_add (jobj,"join_mode", json_object_new_int(FENCE_RECORD__JOIN_MODE__OPEN_WITH_KEY));
	}
	else if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_JOINMODE_INVITE_ONLY))
	{
		if (!F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_JOINMODE_KEY))	json_object_object_add (jobj,"join_mode", json_object_new_int(FENCE_RECORD__JOIN_MODE__INVITE));
		else json_object_object_add (jobj,"join_mode", json_object_new_int(FENCE_RECORD__JOIN_MODE__INVITE_WITH_KEY));
	}
	else	json_object_object_add (jobj,"join_mode", json_object_new_int(FENCE_RECORD__JOIN_MODE__OPEN)); //defaults to open

}

/**
 *  @param mode: 1 digest,2full
 *
 *  @dynamic_memory: EXPORTS josn_object tree (array) which the user must free
 *  @locks: locks Fences in user's list in iteratios
 *  @unlocks: unlocks fenceslocked within itreation
 *  @locked: Session must be locked by the calling environment
 */
struct json_object *
JsonFormatSessionFenceList (Session *sesn_ptr, enum DigestMode digest_mode)
{
  if (SESSION_FENCE_LIST_SIZE(sesn_ptr) == 0) {
   syslog(LOG_DEBUG, "%s {pid:'%lu' o:'%p', cid:'%lu'}: COULD NOT MAKE FENCE LIST FOR SESSION: No Fences found in Session", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

   return NULL;
  }

  bool fence_lock_already_owned = false;
  Fence 				*f_ptr	= NULL;
  ListEntry		*eptr		= NULL;
  json_object	*jarray	= NULL;
  json_object	*jobj		= NULL;
  FenceStateDescriptor	*fence_state_descriptor	= NULL;

  char 		  uid_encoded[CONFIG_MAX_UFSRV_ID_ENCODED_SZ+1] = {0};
  UfsrvUid	uid 																					= {0};

   jarray = json_object_new_array();

   for (eptr=SESSION_FENCE_LIST(sesn_ptr).head; eptr; eptr=eptr->next) {
	   fence_state_descriptor = FenceStateDescriptorOffInstanceHolder((InstanceHolderForFenceStateDescriptor *)eptr->whatever);
	   f_ptr = FENCESTATE_FENCE(fence_state_descriptor);

	   FenceEventsLockRDCtx(THREAD_CONTEXT_PTR, f_ptr, _LOCK_TRY_FLAG_TRUE, SESSION_RESULT_PTR(sesn_ptr), __func__);

		 if (SESSION_RESULT_TYPE_EQUAL(sesn_ptr, RESULT_TYPE_ERR))	continue;

		 fence_lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_PROG_LOCKED_BY_THIS_THREAD));

		jobj = json_object_new_object();
		json_object_object_add (jobj,"userCount",	json_object_new_int(FENCE_USERS_COUNT(f_ptr)));
		if (IS_STR_LOADED(FENCE_DNAME(f_ptr)))		json_object_object_add (jobj,"fname", 		json_object_new_string(FENCE_DNAME(f_ptr)));
		json_object_object_add (jobj,"fid", 			json_object_new_int64(FENCE_ID(f_ptr)));
		json_object_object_add (jobj,"eid", 			json_object_new_int64(f_ptr->fence_events.last_event_id));

		if (FENCE_OWNER_UID(f_ptr) != 1) {
			UfsrvUid *uid_ptr = GetUfsrvUid(sesn_ptr, FENCE_OWNER_UID(f_ptr), &uid, true, NULL);
			if (IS_PRESENT(uid_ptr)) {
        UfsrvUidConvertSerialise(uid_ptr, uid_encoded);
				json_object_object_add(jobj, "owner_ufsrvuid", json_object_new_string(uid_encoded));
			}
		} else {
			json_object_object_add(jobj, "owner_ufsrvuid", json_object_new_string(UFSRV_SYSTEMUSER_UID));
		}

		json_object_object_add (jobj,"msg_expiry", 		json_object_new_int64(FENCE_MSG_EXPIRY(f_ptr)));

		if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_BASEFENCE))	json_object_object_add (jobj,"type", 			json_object_new_int(FENCE_RECORD__FENCE_TYPE__GEO));
		else 																								json_object_object_add (jobj,"type", 			json_object_new_int(FENCE_RECORD__FENCE_TYPE__USER));

		if	(F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_PRIVATE))		json_object_object_add (jobj,"privacy_mode", 			json_object_new_int(FENCE_RECORD__PRIVACY_MODE__PRIVATE));
		else	json_object_object_add (jobj,"privacy_mode", 			json_object_new_int(FENCE_RECORD__PRIVACY_MODE__PUBLIC));

		if	(F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_BROADCAST))		json_object_object_add (jobj,"delivery_mode", 			json_object_new_int(FENCE_RECORD__DELIVERY_MODE__BROADCAST));
		else if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_BROADCAST_ONEWAY))	json_object_object_add (jobj,"delivery_mode", 			json_object_new_int(FENCE_RECORD__DELIVERY_MODE__BROADCAST_ONEWAY));
		else json_object_object_add (jobj,"delivery_mode", 			json_object_new_int(FENCE_RECORD__DELIVERY_MODE__MANY)); //defaults to F_ATTR_MANY_TO_MANY

		if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_JOINMODE_OPEN)) {
			if (!F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_JOINMODE_KEY))	json_object_object_add (jobj,"join_mode", json_object_new_int(FENCE_RECORD__JOIN_MODE__OPEN));
			else json_object_object_add (jobj,"join_mode", json_object_new_int(FENCE_RECORD__JOIN_MODE__OPEN_WITH_KEY));
		} else if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_JOINMODE_INVITE_ONLY)) {
			if (!F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_JOINMODE_KEY))	json_object_object_add (jobj,"join_mode", json_object_new_int(FENCE_RECORD__JOIN_MODE__INVITE));
			else json_object_object_add (jobj,"join_mode", json_object_new_int(FENCE_RECORD__JOIN_MODE__INVITE_WITH_KEY));
		} else	json_object_object_add (jobj,"join_mode", json_object_new_int(FENCE_RECORD__JOIN_MODE__OPEN)); //defaults to open


		if (IS_STR_LOADED(FENCE_CNAME(f_ptr)))		json_object_object_add (jobj,"fcname", 		json_object_new_string(FENCE_CNAME(f_ptr)));

		//todo: disable this, as fence statesync contains protobuf representation of this data
    struct json_object *jobj_array_prefs = JsonFormatFenceUserPreferences (sesn_ptr, fence_state_descriptor);
    if (IS_PRESENT(jobj_array_prefs)) json_object_object_add (jobj, "fence_preferences", jobj_array_prefs);

     struct json_object *jobj_array_fence_permissions = JsonFormatFencePermissions (sesn_ptr, f_ptr);
     if (IS_PRESENT(jobj_array_prefs)) json_object_object_add (jobj, "fence_permissions", jobj_array_fence_permissions);

		if (digest_mode == DIGESTMODE_BRIEF) goto record_ready;

		{
			//add more attributes for full
		}

		record_ready:
		if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));

		json_object_array_add(jarray, jobj);
	}

   //edge case where we originally had one fence but we could not lock it, so we end up with zero size array
   if (json_object_array_length(jarray) == 0) {
	   json_object_put(jarray);

	   return NULL;
   }

   return jarray;

}

/**
 *  @param mode: 1 digest, 2full
 *
 *  @dynamic_memory: EXPORTS josn_object tree (array) which the user must free
 *  @locks: locks Fences in user's list in iteratios
 *  @unlocks: unlocks fenceslocked within itreation
 *  @locked: Session must be locked by the calling environment
 */
struct json_object *
JsonFormatSessionInvitedFenceList (Session *sesn_ptr, enum DigestMode digest_mode)
{

   if (SESSION_INVITED_FENCE_LIST_SIZE(sesn_ptr)==0) {
#ifdef __UF_FULLDEBUG
	   syslog(LOG_DEBUG, "%s {pid:'%lu' o:'%p', cid:'%lu'}: COULD NOT MAKE INVITED FENCE LIST FOR SESSION: No Fences found in Session", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
#endif
	   return NULL;
   }

   bool									fence_lock_already_owned = false;
   Fence 								*f_ptr									= NULL;
   ListEntry						*eptr										= NULL;
   FenceStateDescriptor	*fstate_ptr             = NULL;
   struct json_object		*jarray									= NULL;
   struct json_object		*jobj										= NULL;
   char invited_by[CONFIG_MAX_UFSRV_ID_ENCODED_SZ+1];


   jarray = json_object_new_array();

   for (eptr=SESSION_INVITED_FENCE_LIST(sesn_ptr).head; eptr; eptr=eptr->next) {
     fstate_ptr = FenceStateDescriptorOffInstanceHolder((InstanceHolderForFenceStateDescriptor *)eptr->whatever);
	   f_ptr = FenceOffInstanceHolder(FENCESTATE_INSTANCE_HOLDER(fstate_ptr));

	   FenceEventsLockRDCtx(THREAD_CONTEXT_PTR, f_ptr, _LOCK_TRY_FLAG_TRUE, SESSION_RESULT_PTR(sesn_ptr), __func__);

		 if (SESSION_RESULT_TYPE_EQUAL(sesn_ptr, RESULT_TYPE_ERR))	continue;

		 fence_lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_PROG_LOCKED_BY_THIS_THREAD));

		//TODO: We can probably get away without locking f we dont include userCount, fname, fcname
		jobj=json_object_new_object();
		json_object_object_add (jobj,"userCount",			json_object_new_int(FENCE_USERS_COUNT(f_ptr)));
		if (IS_STR_LOADED(FENCE_DNAME(f_ptr)))				json_object_object_add (jobj,"fname", 				json_object_new_string(FENCE_DNAME(f_ptr)));
		json_object_object_add (jobj,"fid", 					json_object_new_int64(FENCE_ID(f_ptr)));
		if (IS_STR_LOADED(FENCE_CNAME(f_ptr)))				json_object_object_add (jobj,"fcname", 				json_object_new_string(FENCE_CNAME(f_ptr)));

		memset (invited_by, '\0', CONFIG_MAX_UFSRV_ID_ENCODED_SZ+1);
     UfsrvUidConvertSerialise(&(fstate_ptr->invited_by), invited_by);

    json_object_object_add (jobj,"invited_by",		json_object_new_string(invited_by));
		json_object_object_add (jobj,"invited_when",	json_object_new_int64(fstate_ptr->when_invited));

		_JsonFormatFenceTypeSpecs (f_ptr, jobj);

		if (digest_mode == DIGESTMODE_BRIEF) goto record_ready;//digest mode

		{
			//add more attributes for full
		}

		record_ready:
		if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));

		json_object_array_add(jarray, jobj);
	}

   //edge case where we originally had one fence but we could not lock it, so we end up with zero size array
   if (json_object_array_length(jarray) == 0) {
	   json_object_put(jarray);

	   return NULL;
   }

   return jarray;

}

/**
 * 	@brief: Generically constructs a UsersList from sessions attached to a given fence.
 * 	@refcount: Increment refcount for Session * if included in the returned collection
 *	@param sesn_ptr: the session context under which request is being made
 * 	@dynamic_memory: EXPORTS dynamically created array which the user must deallocate
 * 	@returns: raw session references
 *
 * 	@locked f_ptr: must be locked by the caller
 */
static inline FenceRawSessionList *
_ConstructRawUsersListForFence (Session *sesn_ptr, Fence *f_ptr, List *fence_user_list_ptr, unsigned long fence_call_flags, FenceRawSessionList *raw_sesn_list_ptr)
{
	//just to gurad against this  being used as a general utility: request has to be associted with a serverd Session
	if (unlikely(IS_EMPTY(sesn_ptr)))						return NULL;
	if (unlikely(IS_EMPTY(raw_sesn_list_ptr)))	return NULL;

	if (fence_user_list_ptr->nEntries == 0) {
		raw_sesn_list_ptr->sessions_sz = 0;
		return raw_sesn_list_ptr;
	}

	raw_sesn_list_ptr->sessions = calloc(fence_user_list_ptr->nEntries, sizeof(InstanceHolderForSession *));

	size_t		i			=	0;
	ListEntry	*eptr	= NULL;

	for (eptr=fence_user_list_ptr->head; eptr; eptr=eptr->next) {
	   InstanceHolderForSession *instance_sesn_ptr_aux = (InstanceHolderForSession *)eptr->whatever;
     Session *sesn_ptr_aux = SessionOffInstanceHolder(instance_sesn_ptr_aux);
	   if (SESNSTATUS_IS_SET(sesn_ptr_aux->stat, SESNSTATUS_REMOTE)) {
		   if (!(fence_call_flags&FENCE_CALLFLAG_INCLUDE_REMOTE_SESSIONS)) {
#ifdef __UF_FULLDEBUG
			   syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', fo:'%p', fid:'%lu', o_remote:'%p', cid_remote:'%lu'}: FOUND REMOTE SESSION: IGNORING...", __func__, pthread_self(),
		   			sesn_ptr, f_ptr, FENCE_ID(f_ptr), sesn_ptr_aux, SESSION_ID(sesn_ptr_aux), f_ptr);
#endif
			   continue;
		   }

		   //else control flows below to fill attributes
	   }

	   raw_sesn_list_ptr->sessions[i++] = instance_sesn_ptr_aux;
	   SessionIncrementReference (instance_sesn_ptr_aux, 1);
	}

	raw_sesn_list_ptr->sessions_sz = i;

	return raw_sesn_list_ptr;

}

InstanceHolderForSession *
GetSessionForFenceOwner (Session *sesn_ptr, Fence *f_ptr)
{
  if (unlikely(FENCE_USERS_COUNT(f_ptr) == 0)) {
    return NULL;
  }

  bool		lock_already_owned = false;
  unsigned long sesn_call_flags	=	(/*CALL_FLAG_LOCK_SESSION|*/CALL_FLAG_LOCK_SESSION_BLOCKING|
                                     CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY| CALL_FLAG_HASH_USERNAME_LOCALLY|
                                     CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION|CALL_FLAG_REMOTE_SESSION);
  GetSessionForThisUserByUserId(sesn_ptr, FENCE_OWNER_UID(f_ptr), NULL, sesn_call_flags);

  if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))  return (InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr);

  return NULL;
}

/**
 * 	@locked f_ptr: must be locked by the caller, or here with the FENCE_CALLFLAG_LOCK_FENCE callflag
 *
 * 	@call_fag FENCE_CALLFLAG_INCLUDE_REMOTE_SESSIONS:
 * 	@call_flag FENCE_CALLFLAG_LOCK_FENCE:
 * 	@call_flag FENCE_CALLFLAG_KEEP_FENCE_LOCKED: Only considered if FENCE_CALLFLAG_LOCK_FENCE was flagged as well
 *
 *	@refcount: Increments refcount for Session *
 *
 * 	@return NULL: on error. Zero members is not an error list is still returned
 * 	@return FenceRawSessionList *: containing zero or more elements...
 *
 * 	@worker: sesnworker
 */
FenceRawSessionList *
GetRawMemberUsersListForFence  (Session *sesn_ptr, InstanceHolderForFence *instance_f_ptr, unsigned long fence_call_flags, FenceRawSessionList *raw_sesn_list_ptr_in)
{
  Fence *f_ptr = FenceOffInstanceHolder(instance_f_ptr);

	//TODO: change FenceRawList to CollectionDescriptor type
	if (fence_call_flags&FENCE_CALLFLAG_LOCK_FENCE) {
		FenceEventsLockRWCtx(THREAD_CONTEXT_PTR, f_ptr, _LOCK_TRY_FLAG_FALSE, SESSION_RESULT_PTR(sesn_ptr), __func__);

		if (SESSION_RESULT_TYPE_EQUAL(sesn_ptr, RESULT_TYPE_ERR))	return NULL;
	}

	bool fence_lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_PROG_LOCKED_BY_THIS_THREAD));

	FenceRawSessionList *raw_sesn_list_ptr = NULL;

	if (IS_EMPTY(raw_sesn_list_ptr_in))	raw_sesn_list_ptr = calloc(1, sizeof(FenceRawSessionList));
	else																raw_sesn_list_ptr = raw_sesn_list_ptr_in;

	if (unlikely(FENCE_USERS_COUNT(f_ptr) == 0))	{raw_sesn_list_ptr->sessions = NULL;	raw_sesn_list_ptr->sessions_sz = 0; goto exit_unlock;}

	//won't load from cache backend unless F_ATTR_DIRTY || F_ATTR_SESSNLIST_LAZY set
	GetMembersListCacheRecordForFence(sesn_ptr, instance_f_ptr, UNSPECIFIED_UID, UNSPECIFIED_FENCE_LISTTYPE, UNSPECIFIED_FENCE_LISTTYPE, FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE);
	if (SESSION_RESULT_TYPE_EQUAL(sesn_ptr, RESULT_TYPE_ERR)) {
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', fo:'%p', bid:'%lu', fence_members_sz:'%d'}: ERROR: COULD NOT LOAD FENCE'S USERS LIST", __func__, pthread_self(), sesn_ptr, f_ptr, FENCE_ID(f_ptr), FENCE_USERS_COUNT(f_ptr));
#endif

		raw_sesn_list_ptr->sessions = NULL;
		raw_sesn_list_ptr->sessions_sz = 0;

		goto exit_error;
	}

	if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET)) {
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', fo:'%p', bid:'%lu', fence_members_sz:'%d'}: NOTICE: COULD NOT LOAD FENCE'S USERS LIST: ZERO MEMBERS", __func__, pthread_self(), sesn_ptr, f_ptr, FENCE_ID(f_ptr), FENCE_USERS_COUNT(f_ptr));
#endif

		raw_sesn_list_ptr->sessions = NULL;
		raw_sesn_list_ptr->sessions_sz = 0;

		goto exit_unlock;
	}

	_ConstructRawUsersListForFence (sesn_ptr, f_ptr, &(f_ptr->fence_user_sessions_list), fence_call_flags, raw_sesn_list_ptr);

	exit_unlock:
	if (fence_call_flags&FENCE_CALLFLAG_LOCK_FENCE && !fence_lock_already_owned) {
		FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
	}

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', fo:'%p', fid:'%lu', members_sz:'%lu'}: Finished Session list construction for Fence", __func__, pthread_self(), sesn_ptr, f_ptr, FENCE_ID(f_ptr), raw_sesn_list_ptr->sessions_sz);
#endif

	return raw_sesn_list_ptr;

	exit_error:
	if (IS_EMPTY(raw_sesn_list_ptr_in))	free(raw_sesn_list_ptr);
	if (fence_call_flags&FENCE_CALLFLAG_LOCK_FENCE && !fence_lock_already_owned) {
		FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
	}

	return NULL;

}

/**
 * 	@locked f_ptr: must be locked by the caller, or here with the FENCE_CALLFLAG_LOCK_FENCE callflag
 *
 * 	@call_fag FENCE_CALLFLAG_INCLUDE_REMOTE_SESSIONS:
 * 	@call_flag FENCE_CALLFLAG_LOCK_FENCE:
 * 	@call_flag FENCE_CALLFLAG_KEEP_FENCE_LOCKED: Only considered if FENCE_CALLFLAG_LOCK_FENCE was flagged as well
 *
 *	@refcount: Increments refcount for Session *
 *
 * 	@return NULL: on error. Zero members is not an error list is still returned
 * 	@return FenceRawSessionList *: containing zero or more elements...
 *
 * 	@worker: sesnworker
 */
FenceRawSessionList *
GetRawInvitedUsersListForFence  (Session *sesn_ptr, InstanceHolderForFence *instance_f_ptr, unsigned long fence_call_flags, FenceRawSessionList *raw_sesn_list_ptr_in)
{
	//TODO: change FenceRawList to CollectionDescriptor type
	Fence *f_ptr = FenceOffInstanceHolder(instance_f_ptr);

	if (fence_call_flags&FENCE_CALLFLAG_LOCK_FENCE) {
		FenceEventsLockRWCtx(THREAD_CONTEXT_PTR, f_ptr, _LOCK_TRY_FLAG_FALSE, SESSION_RESULT_PTR(sesn_ptr), __func__);

		if (SESSION_RESULT_TYPE_EQUAL(sesn_ptr, RESULT_TYPE_ERR))	return NULL;
	}

	bool fence_lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_PROG_LOCKED_BY_THIS_THREAD));

	FenceRawSessionList *raw_sesn_list_ptr = NULL;

	if (IS_EMPTY(raw_sesn_list_ptr_in))	raw_sesn_list_ptr = calloc(1, sizeof(FenceRawSessionList));
	else																raw_sesn_list_ptr = raw_sesn_list_ptr_in;

	if (unlikely(FENCE_USERS_COUNT(f_ptr) == 0))	goto exit_unlock;

	//won't load from cache backend unless F_ATTR_DIRTY || F_ATTR_SESSNLIST_LAZY set
	GetInvitedMembersListCacheRecordForFence(sesn_ptr, instance_f_ptr, 0, UNSPECIFIED_FENCE_LISTTYPE, UNSPECIFIED_FENCE_LISTTYPE, FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE);
	if (SESSION_RESULT_TYPE_ERROR(sesn_ptr)) {
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', fo:'%p', bid:'%lu', members_sz:'%d'}: ERROR: COULD NOT LOAD FENCE'S SESSION LISTFENCE", __func__, pthread_self(), sesn_ptr, f_ptr, FENCE_ID(f_ptr), FENCE_USERS_COUNT(f_ptr));
#endif

		goto exit_error;
	}

	if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET)) {
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', fo:'%p', bid:'%lu', members_sz:'%d'}: NOTICE: COULD NOT LOAD FENCE'S SESSION LISTFENCE: ZERO MEMBERS", __func__, pthread_self(), sesn_ptr, f_ptr, FENCE_ID(f_ptr), FENCE_USERS_COUNT(f_ptr));
#endif

		return raw_sesn_list_ptr;
	}

	//increments refcount for Session. You must destruct this with DestructFenceRawSessionList()
	_ConstructRawUsersListForFence (sesn_ptr, f_ptr, &(f_ptr->fence_user_sessions_invited_list), fence_call_flags, raw_sesn_list_ptr);

//TODO: LOST FENCE LOCK OWNERSHIP
	exit_unlock:
	if ((fence_call_flags&FENCE_CALLFLAG_LOCK_FENCE) && !(fence_call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED)) {
		if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
	}

#ifdef __UF_TETING
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', fo:'%p', fid:'%lu', members_sz:'%lu'}: Finished Session list construction for Fence", __func__, pthread_self(), sesn_ptr, f_ptr, FENCE_ID(f_ptr), raw_sesn_list_ptr->sessions_sz);
#endif

	return raw_sesn_list_ptr;

	exit_error:
	if (IS_EMPTY(raw_sesn_list_ptr_in))	free(raw_sesn_list_ptr);
	if ((fence_call_flags&FENCE_CALLFLAG_LOCK_FENCE) && !(fence_call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED)) {
		if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
	}
	return NULL;

}

void
DestructFenceRawSessionList (FenceRawSessionList *raw_sesn_list_ptr, bool self_destruct)
{
	if (unlikely(IS_EMPTY(raw_sesn_list_ptr)))	return;

	if (!IS_EMPTY(raw_sesn_list_ptr->sessions)) {
		if (raw_sesn_list_ptr->sessions_sz>0) {
			size_t i=0;
			for (; i<raw_sesn_list_ptr->sessions_sz; i++) {
				SessionDecrementReference(raw_sesn_list_ptr->sessions[i], 1);
			}
		}

		free (raw_sesn_list_ptr->sessions);
	}

	if (self_destruct)	free (raw_sesn_list_ptr);
}

// START START CACHE RECORD AND USERLIST FOR FENCE \\\\\

static inline void _CacheRecordPopulateFence (Fence *f_ptr, redisReply *redis_ptr);
static inline UFSRVResult *_CacheBackendGetCacheRecordForFence (unsigned long fence_id);

/**
 * 	@brief: Pupulate fence's fields from raw cache record
 */
static inline void
_CacheRecordPopulateFence (Fence *f_ptr, redisReply *redis_ptr)
{
	f_ptr->fence_id																	=	strtoul(redis_ptr->element[REDIS_KEY_FENCE_ID]->str, NULL, 10);
  f_ptr->attrs																		=	strtoul(redis_ptr->element[REDIS_KEY_FENCE_TYPE]->str, NULL, 10);
	f_ptr->when																			=	strtoul(redis_ptr->element[REDIS_KEY_FENCE_WHEN_CREATED]->str, NULL, 10);
	FENCE_OWNER_UID(f_ptr)													=	strtoul(redis_ptr->element[REDIS_KEY_FENCE_USERID]->str, NULL, 10);
	f_ptr->fence_location.base_location							=	strdup(redis_ptr->element[REDIS_KEY_FENCE_BASELOC]->str);
	f_ptr->fence_location.canonical_name						=	strdup(redis_ptr->element[REDIS_KEY_FENCE_CNAME]->str);
	f_ptr->fence_location.display_banner_name				=	strdup(redis_ptr->element[REDIS_KEY_FENCE_DNAME]->str);
	f_ptr->fence_location.banner_name								=	strdup(redis_ptr->element[REDIS_KEY_FENCE_BNAME]->str);
	f_ptr->fence_location.fence_location.longitude	=	strtof(redis_ptr->element[REDIS_KEY_FENCE_LONG]->str, NULL);
	f_ptr->fence_location.fence_location.latitude		=	strtof(redis_ptr->element[REDIS_KEY_FENCE_LAT]->str, NULL);
	f_ptr->max_users																=	strtoul(redis_ptr->element[REDIS_KEY_MAXUSERS]->str, NULL, 10);
	f_ptr->time_to_live															=	strtoul(redis_ptr->element[REDIS_KEY_TTL]->str, NULL, 10);
	f_ptr->fence_events.last_event_id								=	strtoul(redis_ptr->element[REDIS_KEY_EVENT_COUNTER]->str, NULL, 10);

	if (redis_ptr->element[REDIS_KEY_FENCE_AVATAR]->str && *redis_ptr->element[REDIS_KEY_EVENT_COUNTER]->str!='*')
		FENCE_AVATAR(f_ptr)														=	strdup(redis_ptr->element[REDIS_KEY_FENCE_AVATAR]->str);

	if (redis_ptr->element[REDIS_KEY_FENCE_MSGEXPIRY]->str)	FENCE_MSG_EXPIRY(f_ptr)=strtoul(redis_ptr->element[REDIS_KEY_FENCE_MSGEXPIRY]->str, NULL, 10);

	if (redis_ptr->element[REDIS_KEY_LIST_SEMANTICS]->str)	MapListSemantics (f_ptr, (int)strtoul(redis_ptr->element[REDIS_KEY_LIST_SEMANTICS]->str, NULL, 10));
}

/**
 * 	@dynamic_memory redisReply *: EXPORTS
 */
static inline UFSRVResult *
_CacheBackendGetCacheRecordForFence (unsigned long fence_id)
{
	int rescode	=	RESCODE_BACKEND_DATA;
	PersistanceBackend 	*pers_ptr;
	redisReply					*redis_ptr;

	pers_ptr = THREAD_CONTEXT_FENCE_CACHEBACKEND;//sesn_ptr->fence_cachebackend;
	if (IS_EMPTY((redis_ptr = (*pers_ptr->send_command)(NULL, pers_ptr, REDIS_CMD_FENCE_RECORD_GET_ALL, fence_id))))	{rescode = RESCODE_BACKEND_CONNECTION;	goto return_connection_error;}

	if (redis_ptr->type == REDIS_REPLY_ERROR)	goto return_reply_error;
	if (redis_ptr->type == REDIS_REPLY_NIL)		goto return_nil_error;
	if (!(redis_ptr->element[0]->str))			goto return_empty_set; //HMGET command will still return empty array

	 return_success:
//	 _RETURN_RESULT_SESN(sesn_ptr, redis_ptr, RESULT_TYPE_SUCCESS, rescode);
	 THREAD_CONTEXT_RETURN_RESULT_SUCCESS(redis_ptr, rescode);

	 return_empty_set:
	 rescode = RESCODE_BACKEND_DATA_EMPTYSET;
	 syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', fid;'%lu'}: ERROR: EMPTY SET.",  __func__, pthread_self(), THREAD_CONTEXT_PTR, fence_id);
	 goto return_error;

	 return_nil_error:
	 syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', fid;'%lu'}: ERROR: NIL SET",  __func__, pthread_self(), THREAD_CONTEXT_PTR, fence_id);
	 goto return_error;

	 return_reply_error:
	 rescode = RESCODE_BACKEND_COMMAND;
	 syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', fid:'%lu', error:'%s'}: ERROR: COMMAND ERROR.", __func__, pthread_self(), THREAD_CONTEXT_PTR, fence_id, redis_ptr->str);
	 goto return_error;

	 return_error:
	 freeReplyObject(redis_ptr);
//	 _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)
  THREAD_CONTEXT_RETURN_RESULT_SUCCESS(NULL, rescode);

	 return_connection_error:
	 syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p'}: ERROR RESPONSE for fence_id '%lu'", __func__, pthread_self(), THREAD_CONTEXT_PTR, fence_id);
//	 _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)
  THREAD_CONTEXT_RETURN_RESULT_SUCCESS(NULL, rescode);
}

/**
 *	@brief Retrieve and build a Fence object from its cache backend record.
 *	@param sesn_ptr_this can be NULL if no lock is installed on Fence
 *	@param uid user id to look up when loading fence lists, typically the requesting session. Only when FENCE_CALLFLAG_ABORT_RECORD_IF_USER_NOT_MEMBER is passed.
 *	empty value set to '0'.
 *  @returns InstanceHolderForFence
 *	@call_flag FENCE_CALLFLAG_HASH_FENCE_LOCALLY:
 *	@call_flag FENCE_CALLFLAG_KEEP_FENCE_LOCKED: only honored if HASH_LOCALLY is set
 *	@call_flag FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE:
 *	@call_flag FENCE_CALLFLAG_ABORT_RECORD_IF_USER_NOT_MEMBER: stop loading the fence record if user in the provided session was not on members list.
 *	Currently this test only works if the fence had zero members in it. We don't checked for named users in fences list.
 *
 *	@locks f_ptr:
 *	Fence RW events. If FENCE_CALLFLAG_KEEP_FENCE_LOCKED  we let the calling environment to unlock the fence.
 *	@unlocks f_ptr: if hash local and FENCE_CALLFLAG_KEEP_FENCE_LOCKED is NOT set
 *
 *	@worker: sesn_worker
 *
 */
UFSRVResult *//CALL_FLAG_HASH_SESSION_LOCALLY
GetCacheRecordForFence (Session *sesn_ptr_this, EnumFenceCollectionType list_type_context, unsigned long fence_id, unsigned long uid, bool *fence_lock_state, unsigned long call_flags)
{
	Fence 							*f_ptr = NULL;
	InstanceHolderForFence  *instance_f_ptr = NULL;

	_CacheBackendGetCacheRecordForFence(fence_id);
	if (!THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA)	goto return_error_null;
	redisReply 	*redis_ptr	=	(redisReply *)THREAD_CONTEXT_UFSRV_RESULT_USERDATA;

	unsigned fence_attrs = strtoul(redis_ptr->element[REDIS_KEY_FENCE_TYPE]->str, NULL, 10);
	if (F_ATTR_IS_SET(fence_attrs, F_ATTR_BASEFENCE)) {
    instance_f_ptr = RecyclerGet(FencePoolTypeNumber(), (ContextData *)NULL, FENCE_CALLFLAG_BASEFENCE);/*won't generate id*/
	} else if (F_ATTR_IS_SET(fence_attrs, F_ATTR_USERFENCE)) {
    instance_f_ptr = RecyclerGet(FencePoolTypeNumber(), (ContextData *)NULL, FENCE_CALLFLAG_USERFENCE);/*won't generate id*/
	}

	if (unlikely(IS_EMPTY(instance_f_ptr)))	goto return_error;

	f_ptr = FenceOffInstanceHolder(instance_f_ptr);

	//Do it early as there is no point in loading the fence for the user if he is not on its list

	bool fence_lock_already_owned = false;

	if (call_flags&FENCE_CALLFLAG_HASH_FENCE_LOCALLY) {
		FenceEventsLockRWCtx(THREAD_CONTEXT_PTR, f_ptr, _LOCK_TRY_FLAG_FALSE, THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), __func__);
		if (THREAD_CONTEXT_UFSRV_RESULT_TYPE_ERR)	goto return_error;

		fence_lock_already_owned = (THREAD_CONTEXT_UFSRV_RESULT_CODE_EQUAL(THREAD_CONTEXT, RESCODE_PROG_LOCKED_BY_THIS_THREAD));

		_CacheRecordPopulateFence(f_ptr, redis_ptr);

		if (!(AddToHash(&FenceRegistryCanonicalNameHashTable, instance_f_ptr))) goto return_error_unlock;
		if (!(AddToHash(&FenceRegistryIdHashTable, instance_f_ptr))) {
			//TODO: reset and deallocate f_ptr object
			RemoveFromHash(&FenceRegistryCanonicalNameHashTable, (void *) instance_f_ptr);

			goto return_error_unlock;
		}
	} else {
		_CacheRecordPopulateFence(f_ptr, redis_ptr);
	}

	 if (call_flags&FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE) {
		 F_ATTR_SET(f_ptr->attrs, F_ATTR_DIRTY);

		 if (call_flags&FENCE_CALLFLAG_ABORT_RECORD_IF_USER_NOT_MEMBER) {
			 GetMembersListCacheRecordForFence(sesn_ptr_this, instance_f_ptr, uid, MEMBER_FENCES, list_type_context, FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE|FENCE_CALLFLAG_ABORT_RECORD_IF_USER_NOT_MEMBER);
		 } else {
			 GetMembersListCacheRecordForFence(sesn_ptr_this, instance_f_ptr, UNSPECIFIED_UID, MEMBER_FENCES, list_type_context, FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE);
		 }

     if (SESSION_RESULT_TYPE_ERROR(sesn_ptr_this) ||
         (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr_this) && SESSION_RESULT_CODE_EQUAL(sesn_ptr_this, RESCODE_BACKEND_DATA_EMPTYSET))) {
       if ((call_flags&FENCE_CALLFLAG_ABORT_RECORD_IF_USER_NOT_MEMBER) && (list_type_context == MEMBER_FENCES))	goto return_error;
     }

		 unsigned long fence_call_flags_invited = FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE;

		 F_ATTR_SET(f_ptr->attrs, F_ATTR_DIRTY);
		 if (call_flags&FENCE_CALLFLAG_ABORT_RECORD_IF_USER_NOT_MEMBER) {
			 fence_call_flags_invited |= FENCE_CALLFLAG_ABORT_RECORD_IF_USER_NOT_MEMBER;
			 GetInvitedMembersListCacheRecordForFence(sesn_ptr_this,  instance_f_ptr, uid, INVITED_FENCES, list_type_context, fence_call_flags_invited);
		 } else {
			 GetInvitedMembersListCacheRecordForFence(sesn_ptr_this,  instance_f_ptr, 0, INVITED_FENCES, list_type_context, fence_call_flags_invited);
		 }

		 if (SESSION_RESULT_TYPE_ERROR(sesn_ptr_this) ||
				 (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr_this) && SESSION_RESULT_CODE_EQUAL(sesn_ptr_this, RESCODE_BACKEND_DATA_EMPTYSET))) {
			 if ((call_flags&FENCE_CALLFLAG_ABORT_RECORD_IF_USER_NOT_MEMBER) && (list_type_context == INVITED_FENCES))	goto return_error;
		 }

		 //more lists.....

		 F_ATTR_UNSET(f_ptr->attrs, F_ATTR_DIRTY);
	 }
	 else	F_ATTR_SET(f_ptr->attrs, F_ATTR_SESSNLIST_LAZY); //load list on demand

	 freeReplyObject(redis_ptr);

	 if (call_flags&FENCE_CALLFLAG_HASH_FENCE_LOCALLY) {
		 if (!(call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED)) {//not transferring lock ownership
			 if (!fence_lock_already_owned) {
         FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));
       }

			 if (IS_PRESENT(fence_lock_state))	*fence_lock_state = fence_lock_already_owned;
			 _RETURN_RESULT_SESN(sesn_ptr_this, instance_f_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
		 }

		 if (IS_PRESENT(fence_lock_state))	*fence_lock_state = fence_lock_already_owned;
		 _RETURN_RESULT_SESN(sesn_ptr_this, instance_f_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
	 } else {
		 //lock never obtained
		 _RETURN_RESULT_SESN(sesn_ptr_this, instance_f_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
	 }

	return_error:
	if (IS_PRESENT(f_ptr)) FenceReturnToRecycler(instance_f_ptr, NULL, CALLFLAGS_EMPTY);
	freeReplyObject(redis_ptr);
	goto return_error_null;

	return_error_unlock:
	if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));
	FenceReturnToRecycler(instance_f_ptr, NULL, CALLFLAGS_EMPTY);
	freeReplyObject(redis_ptr);

	return_error_null:
	_RETURN_RESULT_SESN(sesn_ptr_this, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

UFSRVResult *
CacheBackendGetFencesListSize (Session *sesn_ptr, unsigned long userid)
{
	if (unlikely(IS_EMPTY(sesn_ptr)))
	{
		syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Session *");
		return _ufsrv_result_generic_error;
	}

	unsigned 						rescode			=	RESCODE_BACKEND_DATA;
	PersistanceBackend	*pers_ptr		=	sesn_ptr->persistance_backend;
	redisReply 					*redis_ptr	=	NULL;

	if (!(redis_ptr=(*pers_ptr->send_command)(sesn_ptr, REDIS_CMD_USER_FENCE_LIST_SIZE, userid)))	goto return_redis_error;

	if (redis_ptr->type==REDIS_REPLY_INTEGER)
	{
		size_t fences_list_sz=(size_t)redis_ptr->integer; //shouldn't have problems with negative as we dont store them in this context
		freeReplyObject(redis_ptr);

		if (fences_list_sz < CONFIG_MAX_FENCELIST_SZ){_RETURN_RESULT_SESN(sesn_ptr, (void *) (uintptr_t) fences_list_sz, RESULT_TYPE_SUCCESS, rescode);}
		else
		{
			syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu', _fenceslist_sz:'%lu'}: ERROR: FENCE LIST SIZE EXCEEED MAX...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), fences_list_sz);
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_INCONSISTENT_STATE);
		}
	}

	if (redis_ptr->type==REDIS_REPLY_ERROR)	goto return_redis_error;
	if (redis_ptr->type==REDIS_REPLY_NIL)		goto return_redis_error;

	return_redis_error:
	if (IS_EMPTY(redis_ptr))
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	 _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);
	}
	if (redis_ptr->type==REDIS_REPLY_ERROR)
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), redis_ptr->str);
	 rescode=RESCODE_BACKEND_DATA; goto return_error;
	}
	if (redis_ptr->type==REDIS_REPLY_NIL)
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: NIL SET",  __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	 rescode=RESCODE_BACKEND_DATA; goto return_error;
	}

	return_error:
	freeReplyObject(redis_ptr);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

}

/**
 * 	@brief: Get the number of fences for which user is invited
 */
UFSRVResult *
CacheBackendGetUserFencesInviteListSize (Session *sesn_ptr, unsigned long uid)
{
	if (unlikely(IS_EMPTY(sesn_ptr)))
	{
		syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Session *");
		return _ufsrv_result_generic_error;
	}

	unsigned 						rescode			=	RESCODE_BACKEND_DATA;
	PersistanceBackend	*pers_ptr		=	sesn_ptr->persistance_backend;
	redisReply 					*redis_ptr	=	NULL;

	if (!(redis_ptr=(*pers_ptr->send_command)(sesn_ptr, REDIS_CMD_INVITED_FENCES_FOR_USER_LIST_SIZE, uid)))	goto return_redis_error;

	if (redis_ptr->type==REDIS_REPLY_INTEGER)
	{
		size_t fences_list_sz=(size_t)redis_ptr->integer; //shouldn't have problems with negative as we dont store them in this context
		freeReplyObject(redis_ptr);

		if (fences_list_sz < CONFIG_MAX_FENCELIST_SZ){_RETURN_RESULT_SESN(sesn_ptr, (void *) (uintptr_t) fences_list_sz, RESULT_TYPE_SUCCESS, rescode);}
		else
		{
			syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu', _fenceslist_sz:'%lu'}: ERROR: FENCE LIST SIZE EXCEEED MAX...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), fences_list_sz);
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_INCONSISTENT_STATE);
		}
	}

	if (redis_ptr->type==REDIS_REPLY_ERROR)	goto return_redis_error;
	if (redis_ptr->type==REDIS_REPLY_NIL)		goto return_redis_error;

	return_redis_error:
	if (IS_EMPTY(redis_ptr))
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	 _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);
	}
	if (redis_ptr->type==REDIS_REPLY_ERROR)
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), redis_ptr->str);
	 rescode=RESCODE_BACKEND_DATA; goto return_error;
	}
	if (redis_ptr->type==REDIS_REPLY_NIL)
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: NIL SET",  __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	 rescode=RESCODE_BACKEND_DATA; goto return_error;
	}

	return_error:
	freeReplyObject(redis_ptr);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

}

/**
 * 	@brief: return the number of invitees for a fence using backend cache source.
 */
UFSRVResult *
CacheBackendGetFenceInviteListSize (Session *sesn_ptr, Fence *f_ptr)
{
	if (unlikely(IS_EMPTY(sesn_ptr)))
	{
		syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Session *");
		return _ufsrv_result_generic_error;
	}

	if (unlikely(IS_EMPTY(f_ptr)))
	{
		syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Fence *");
		return _ufsrv_result_generic_error;
	}

	unsigned 						rescode			=	RESCODE_BACKEND_DATA;
	PersistanceBackend	*pers_ptr		=	sesn_ptr->persistance_backend;
	redisReply 					*redis_ptr	=	NULL;

	if (!(redis_ptr=(*pers_ptr->send_command)(sesn_ptr, REDIS_CMD_INVITED_USERS_FOR_FERNCE_LIST_SIZE, FENCE_ID(f_ptr))))	goto return_redis_error;

	if (redis_ptr->type==REDIS_REPLY_INTEGER)
	{
		size_t fences_list_sz=(size_t)redis_ptr->integer; //shouldn't have problems with negative as we dont store them in this context
		freeReplyObject(redis_ptr);

		_RETURN_RESULT_SESN(sesn_ptr, (void *) (uintptr_t) fences_list_sz, RESULT_TYPE_SUCCESS, rescode);
	}

	if (redis_ptr->type==REDIS_REPLY_ERROR)	goto return_redis_error;
	if (redis_ptr->type==REDIS_REPLY_NIL)		goto return_redis_error;

	return_redis_error:
	if (IS_EMPTY(redis_ptr))
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	 _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);
	}
	if (redis_ptr->type==REDIS_REPLY_ERROR)
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), redis_ptr->str);
	 rescode=RESCODE_BACKEND_DATA; goto return_error;
	}
	if (redis_ptr->type==REDIS_REPLY_NIL)
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: NIL SET",  __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	 rescode=RESCODE_BACKEND_DATA; goto return_error;
	}

	return_error:
	freeReplyObject(redis_ptr);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

}

static char *_BuildAttributesValuesString (CollectionDescriptor *collection_attributes, CollectionDescriptor *collection_values, CollectionDescriptorPair *collection_argv_argvlen);

/**
 * 	@dynamic_memory char *: allocate a one chunk  memory pool to carve out the individual argv elements. User must free.
 */
static char *
_BuildAttributesValuesString (CollectionDescriptor *collection_attributes, CollectionDescriptor *collection_values, CollectionDescriptorPair *collection_argv_argvlen)
{
#define REDIS_COMMAND_OFFSET	2 //the first two slots are for redis command and its length
#define PAIR_FACTOR						2	//well pair means '2'
	if (collection_attributes->collection_sz!=collection_values->collection_sz)	return NULL;

	size_t total_sz=0;
	size_t len_attributes[collection_attributes->collection_sz],
					len_values[collection_values->collection_sz];

	//process the elements that we know of already: attribute names and their values
	for (size_t i=0; i<collection_attributes->collection_sz; i++)
	{
		len_attributes[i]	=	strlen((char *)collection_attributes->collection[i]); total_sz+=len_attributes[i];
		len_values[i]			=	strlen((char *)collection_values->collection[i]);	total_sz+=len_values[i];
	}

	total_sz+=(collection_values->collection_sz+1); //for nulls


	char 		*built_str	=	calloc(total_sz, sizeof(char));
	char		*walker			=	built_str;

	for (size_t i=1; i<=collection_attributes->collection_sz; i++)//we skipped the [0] & [1] which holds the actual comand/arg + len
	{
		collection_argv_argvlen->first.collection[(i*PAIR_FACTOR)]			=	(collection_t *)(const char *)collection_attributes->collection[i-1];
		collection_argv_argvlen->second.collection[(i*PAIR_FACTOR)]			=	(collection_t *)(const size_t)len_attributes[i-1];

		collection_argv_argvlen->first.collection[(i*PAIR_FACTOR)+1]	=	(collection_t *)(const char *)collection_values->collection[i-1];
		collection_argv_argvlen->second.collection[(i*PAIR_FACTOR)+1]	=	(collection_t *)(const size_t)len_values[i-1];
	}

//
//	char 		*built_str	=	calloc(total_sz, sizeof(char));
//	char		*walker			=	built_str;
//
//	for (size_t i=(0+REDIS_COMMAND_OFFSET); i<collection_attributes->collection_sz; i++)
//	{
//		collection_combined->collection[i]			=	(collection_t *)walker;
//		collection_combined_len->collection[i]	=	(collection_t *)len_attributes[i]+len_values[i]+1;//+1 for space
//
//		sprintf (walker, "%s %s", (char *)collection_attributes->collection[i], (char *)collection_values->collection[i]);
//		walker+=(len_attributes[i]+len_values[i]+2);//+2 advance beyon the null
//	}

	return built_str;
}

UFSRVResult *
CacheBackendSetFenceAttributesByCollection (Session *sesn_ptr, unsigned long fence_id, CollectionDescriptor *collection_attributes, CollectionDescriptor *collection_values, CollectionDescriptorPair *collection_argv_argvlen)// *collection_combined, CollectionDescriptor *collection_combined_len)
{
#define REDIS_COMMAND_IDX 		0
#define REDIS_COMMAND_ARG_IDX 1

	unsigned 						rescode			=	RESCODE_BACKEND_DATA;
	char								redis_cmdarg[sizeof(UINT64_LONGEST_STR)+sizeof("BID:")+1];
	PersistanceBackend	*pers_ptr		=	sesn_ptr->fence_cachebackend;//persistance_backend;
	redisReply 					*redis_ptr	=	NULL;

	char *built_str=_BuildAttributesValuesString (collection_attributes, collection_values, collection_argv_argvlen);

	collection_argv_argvlen->first.collection[REDIS_COMMAND_IDX]		=	(collection_t *)(const char *)"HMSET";
	collection_argv_argvlen->second.collection[REDIS_COMMAND_IDX]		=	(collection_t *)(const size_t)5;

	snprintf(redis_cmdarg, (sizeof(UINT64_LONGEST_STR)+sizeof("BID:")+1), "BID:%lu", fence_id);
	collection_argv_argvlen->first.collection[REDIS_COMMAND_ARG_IDX]		=	(collection_t *)(const char *)redis_cmdarg;
	collection_argv_argvlen->second.collection[REDIS_COMMAND_ARG_IDX]		=	(collection_t *)(const size_t)strlen(redis_cmdarg);

	if (!(redis_ptr=RedisSendCommandWithCollection(sesn_ptr, pers_ptr, collection_argv_argvlen)))	goto return_redis_error;

	if (redis_ptr->type==REDIS_REPLY_STATUS && (strcasecmp(redis_ptr->str, "OK")==0))
	{
		return_success:
		free (built_str);
		freeReplyObject(redis_ptr);
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, rescode);
	}

	if (redis_ptr->type==REDIS_REPLY_ERROR)	goto return_redis_error;
	if (redis_ptr->type==REDIS_REPLY_NIL)		goto return_redis_error;

	return_redis_error:
	free (built_str);
	if (IS_EMPTY(redis_ptr))
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	 _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);
	}

	if (redis_ptr->type==REDIS_REPLY_ERROR)
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), redis_ptr->str);
	 rescode=RESCODE_BACKEND_DATA; goto return_error;
	}
	if (redis_ptr->type==REDIS_REPLY_NIL)
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: NIL SET",  __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	 rescode=RESCODE_BACKEND_DATA; goto return_error;
	}

	return_error:
	freeReplyObject(redis_ptr);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

}

/**
 * 	@brief: Set a single value for  fence
 */
UFSRVResult *
CacheBackendSetFenceAttribute (Session *sesn_ptr, unsigned long fence_id, const char *attribute_name, const char *attribute_value)
{
	if (unlikely(IS_EMPTY(sesn_ptr)))
	{
		syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Session *");
		return _ufsrv_result_generic_error;
	}

	unsigned 						rescode			=	RESCODE_BACKEND_DATA;
	PersistanceBackend	*pers_ptr		=	sesn_ptr->fence_cachebackend;
	redisReply 					*redis_ptr	=	NULL;

	if (!(redis_ptr=(*pers_ptr->send_command)(sesn_ptr, SESSION_FENCE_CACHEBACKEND(sesn_ptr), REDIS_CMD_FENCE_RECORD_SET_ATTRIBUTE, fence_id, attribute_name, attribute_value)))	goto return_redis_error;

	if (redis_ptr->type==REDIS_REPLY_STATUS && (strcasecmp(redis_ptr->str, "OK")==0))
	{
		return_success:
		freeReplyObject(redis_ptr);
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, rescode);
	}

	if (redis_ptr->type==REDIS_REPLY_ERROR)	goto return_redis_error;
	if (redis_ptr->type==REDIS_REPLY_NIL)		goto return_redis_error;

	return_redis_error:
	if (IS_EMPTY(redis_ptr))
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	 _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);
	}

	if (redis_ptr->type==REDIS_REPLY_ERROR)
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), redis_ptr->str);
	 rescode=RESCODE_BACKEND_DATA; goto return_error;
	}
	if (redis_ptr->type==REDIS_REPLY_NIL)
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: NIL SET",  __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	 rescode=RESCODE_BACKEND_DATA; goto return_error;
	}

	return_error:
	freeReplyObject(redis_ptr);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

}

UFSRVResult *
CacheBackendSetFenceAttributeBinary (Session *sesn_ptr, unsigned long fence_id, const char *attribute_name, BufferDescriptor *buffer_attribute_value)
{
	if (unlikely(IS_EMPTY(sesn_ptr)))
	{
		syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Session *");
		return _ufsrv_result_generic_error;
	}

	unsigned 						rescode			=	RESCODE_BACKEND_DATA;
	PersistanceBackend	*pers_ptr		=	sesn_ptr->fence_cachebackend;//persistance_backend;
	redisReply 					*redis_ptr	=	NULL;

	if (!(redis_ptr=(*pers_ptr->send_command)(sesn_ptr, SESSION_FENCE_CACHEBACKEND(sesn_ptr), REDIS_CMD_FENCE_RECORD_SET_ATTRIBUTE_BINARY, fence_id, attribute_name, buffer_attribute_value->data, buffer_attribute_value->size)))	goto return_redis_error;

	if (redis_ptr->type==REDIS_REPLY_STATUS && (strcasecmp(redis_ptr->str, "OK")==0))
	{
		return_success:
		freeReplyObject(redis_ptr);
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, rescode);
	}

	if (redis_ptr->type==REDIS_REPLY_ERROR)	goto return_redis_error;
	if (redis_ptr->type==REDIS_REPLY_NIL)		goto return_redis_error;

	return_redis_error:
	if (IS_EMPTY(redis_ptr))
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	 _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);
	}

	if (redis_ptr->type==REDIS_REPLY_ERROR)
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), redis_ptr->str);
	 rescode=RESCODE_BACKEND_DATA; goto return_error;
	}
	if (redis_ptr->type==REDIS_REPLY_NIL)
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: NIL SET",  __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	 rescode=RESCODE_BACKEND_DATA; goto return_error;
	}

	return_error:
	freeReplyObject(redis_ptr);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

}

/**
 * 	@brief: Get a single value for  fence
 * 	@dynamic_memory redis_ptr: EXPORTS
 */
UFSRVResult *
CacheBackendGetFenceAttribute (Session *sesn_ptr, unsigned long fence_id, const char *attribute_name)
{
	unsigned 						rescode			=	RESCODE_BACKEND_DATA;
	PersistanceBackend	*pers_ptr		=	sesn_ptr->fence_cachebackend;//persistance_backend;
	redisReply 					*redis_ptr	=	NULL;

	if (!(redis_ptr=(*pers_ptr->send_command)(sesn_ptr, SESSION_FENCE_CACHEBACKEND(sesn_ptr), REDIS_CMD_FENCE_RECORD_GET_ATTRIBUTE, fence_id, attribute_name)))	goto return_redis_error;

	if (redis_ptr->type==REDIS_REPLY_ARRAY && (redis_ptr->elements>0))
	{
		_RETURN_RESULT_SESN(sesn_ptr, redis_ptr, RESULT_TYPE_ERR, rescode);
	}

	if (redis_ptr->type==REDIS_REPLY_ERROR)	goto return_redis_error;
	if (redis_ptr->type==REDIS_REPLY_NIL)		goto return_redis_error;

	return_redis_error:
	if (IS_EMPTY(redis_ptr))
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	 _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);
	}

	if (redis_ptr->type==REDIS_REPLY_ERROR)
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), redis_ptr->str);
	 rescode=RESCODE_BACKEND_DATA; goto return_error;
	}
	if (redis_ptr->type==REDIS_REPLY_NIL)
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: NIL SET",  __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	 rescode=RESCODE_BACKEND_DATA; goto return_error;
	}

	return_error:
	freeReplyObject(redis_ptr);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

}

/**
 * 	@brief: Cache backend query function, returning raw ids for a given fence user's membership
 * 	@dynamic_memroy: EXPORTS redis_ptr
 */
UFSRVResult *
CacheBackendGetUserIdsCacheRecordForFence (unsigned long fid)
{
	PersistanceBackend	*pers_ptr = THREAD_CONTEXT_PERSISTANCE_CACHEBACKEND(THREAD_CONTEXT);

	redisReply *redis_ptr;

  if (!(redis_ptr = (*pers_ptr->send_command)(NO_SESSION, REDIS_CMD_FENCE_USERS_LIST_GET, fid))) {
     syslog(LOG_DEBUG, "%s (pid:'%lu) ERROR RESPONSE for bid:'%lu': ZRANGE MEMBER_USERS_FOR_FENCE:%lu", __func__, pthread_self(), fid, fid);

     THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_BACKEND_CONNECTION)
  }

   if (redis_ptr->type == REDIS_REPLY_ERROR) {
     syslog(LOG_DEBUG, "%s (pid:'%lu'): ERROR: REDIS RESULT SET for RESPONSE for fid:'%lu'. Error: '%s'",  __func__, pthread_self(), fid, redis_ptr->str);

     goto return_error;
   }
   if (redis_ptr->type == REDIS_REPLY_NIL) {
     syslog(LOG_DEBUG, "%s (pid:'%lu'): ERROR: EMPTY SET FOR fid:'%lu'",  __func__, pthread_self(), fid);
     goto return_error;
   }

   if (redis_ptr->elements > 0) {
     THREAD_CONTEXT_RETURN_RESULT_SUCCESS(redis_ptr, RESCODE_BACKEND_DATA)
   } else {
     freeReplyObject(redis_ptr);
     THREAD_CONTEXT_RETURN_RESULT_SUCCESS(NULL, RESCODE_BACKEND_DATA_EMPTYSET)
   }

	 return_error:
	 freeReplyObject(redis_ptr);
  THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_BACKEND_DATA)

}

/**
 *	@brief: Scan the returned raw userids for the matching session owner
 */
bool
IsUserIdInCacheRecordForFence (Session *sesn_ptr,  unsigned long fid)
{
	CacheBackendGetUserIdsCacheRecordForFence(fid);
	if (THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA) {
		bool				return_value = false;
		redisReply *redis_ptr = (redisReply 	*)THREAD_CONTEXT_UFSRV_RESULT_USERDATA;

		for (size_t i=0; i < redis_ptr->elements; ++i) {
			unsigned long 	user_id		= strtoul(redis_ptr->element[i]->str, NULL, 10);
			if (user_id == SESSION_USERID(sesn_ptr)) {
				return_value = true;
				break;
			}
		}

		freeReplyObject(redis_ptr);
		return return_value;
	 }

	return false;
}

/**
 * 	@brief: Resolve link-back integrity issues for Fence/Session memberships. It is assumed at least one part of the relationship is
 * 	established. The caller must request sync from connected clients if necessary.
 * 	@locked sesn_ptr:
 * 	@locked f_ptr:
 */
UFSRVResult *
RepairFenceMembershipForUser (InstanceHolderForSession *instance_sesn_ptr, InstanceHolderForFence *instance_f_ptr, EnumImpairedFenceMembershipType impairment_type)
{
	bool is_not_impaired;
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
  Fence *f_ptr = FenceOffInstanceHolder(instance_f_ptr);

	if (impairment_type == ImpairedFenceMembershipFence) {
		//fence's memory store did not contain reference session: refer back to CacheBackend for Fence and retrieve list of session ids for its members
		is_not_impaired = IsUserIdInCacheRecordForFence (sesn_ptr,  FENCE_ID(f_ptr));
		if (is_not_impaired) {
			AddThisToList (FENCE_SESSIONS_LIST_PTR(f_ptr), CLIENT_CTX_DATA(instance_sesn_ptr));
			SessionIncrementReference (instance_sesn_ptr, 1);

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_SESSION_INTEGRITY)
		}
	} else if (impairment_type == ImpairedFenceMembershipSession) {
		unsigned long uid_inviter = 0;

		//session's memory store did not contain reference to fence: refer back to CacheBack end for Session and retrieve list of fence ids this user is memer of
		is_not_impaired = IsFenceIdInCacheRecordForUser(SESSION_USERID(sesn_ptr), FENCE_ID(f_ptr), &uid_inviter);
		if (is_not_impaired) {
			InstanceHolder *instance_holder_ptr = RecyclerGet(FenceStateDescriptorPoolTypeNumber(), (ContextData *)instance_f_ptr, CALLFLAGS_EMPTY);
			if (unlikely(IS_EMPTY(instance_holder_ptr))) goto return_allocation_error;

      FenceStateDescriptor *fence_state_ptr = GetInstance(instance_holder_ptr);
      GetUfsrvUid(sesn_ptr, uid_inviter, &(fence_state_ptr->invited_by), false, NULL);

			AddThisToList (SESSION_FENCE_LIST_PTR(sesn_ptr), instance_holder_ptr);
			FenceIncrementReference(instance_holder_ptr, 1);

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_SESSION_FENCE_INTEGRITY)

		}
	} else goto return_error;

	return_allocation_error:
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fo:'%p', fid:'%lu'}: ERROR: COULD NOT ALLOCATE FenceStateDescriptr type", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), f_ptr, FENCE_ID(f_ptr));
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_LIST_SELFLOADED);

	return_error:
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fo:'%p', fid:'%lu', type:'%i'}: ERROR: COULD NOT determine impairment type", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), f_ptr, FENCE_ID(f_ptr), impairment_type);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_INCONSISTENT_STATE);

}

/**
 * 	@brief: retrieve a given Fence's users member list and build/initialise it into Fence's Session list
 * 	FenceGetUserListFromBackend -> LOOP( _RetrieveSessionRecordFromRawBackend)
 * 									 -> FenceAttachRawSessionsList
 *
 * 	@WARNING: Fence MAY NOT BE POPULATED DONT ASSUME ANYTHING ABOUT FENEC DATA EXCEPT ID AND WHETHET DIRT FLAG IS SET
 * 	TODO: refactor so the session creation happens here
 *
 *	@param userid_loaded_for: where fence is being loaded for a specific user and if flag FENCE_CALLFLAG_ABORT_RECORD_IF_USER_NOT_MEMBER is present: abort loading if fence user list doess dnot contain user
 *	@param list_type_context: context information indicating which fence list type the provided fence was loaded from, for example this fence
 *	could have been originally referenced in users invited tyle fence list. This helps with ABORTING callflag
 * 	@call_flag CALL_FLAG_ATTACH_USER_LIST_TO_FENCE:
 *
 * 	@locks: none
 *
 * 	@locked f_ptr: must be locked in the calling environment
 * 	@locked sesn_ptr_target: must be locked in the calling environment
 *
 * 	@dynamic_memory redis_ptr: Redis reply is created and destroyed
 * 	@dynamic_memory sesn_ptr_list: redisReply **sesn_ptr_list array of redis replys created and destroyed

 *	@call_flag: FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE
 *	@call_flag FENCE_CALLFLAG_ABORT_RECORD_IF_USER_NOT_MEMBER: if present, the userid_loaded_for param can used to decided whether to contiue with loading fence
 *
 * 	@worker_thread: session worker, ufsrv worker
 */
UFSRVResult *
GetMembersListCacheRecordForFence (Session *sesn_ptr_target,  InstanceHolderForFence *instance_f_ptr, unsigned long userid_loaded_for, EnumFenceCollectionType list_type_target, EnumFenceCollectionType list_type_context, unsigned long fence_call_flags)
{
  Fence *f_ptr = FenceOffInstanceHolder(instance_f_ptr);

	//we need at least one of these to be set to proceed...
	if (!(F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_DIRTY)) && !(F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_SESSNLIST_LAZY))) {
#ifdef __UF_TESTING
		 syslog(LOG_DEBUG, "%s (pid:'%lu, th_ctx:'%p', fo:'%p', fid:'%lu') NOT FETCHING SESSION LIST FOR FENCE (lazy:'%d', dirty:'%d')", __func__, pthread_self(), THREAD_CONTEXT_PTR, f_ptr, FENCE_ID(f_ptr), F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_SESSNLIST_LAZY), F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_DIRTY));
#endif

		_RETURN_RESULT_SESN(sesn_ptr_target, f_ptr, RESULT_TYPE_SUCCESS, RESCODE_FENCE_LIST_SELFLOADED)
	}

	redisReply 	*redis_ptr;
	CacheBackendGetUserIdsCacheRecordForFence(FENCE_ID(f_ptr));//TODO: this backend loading is heavy handed

	if (THREAD_CONTEXT_UFSRV_RESULT_TYPE_SUCCESS) {
		if (THREAD_CONTEXT_UFSRV_RESULT_CODE_EQUAL(THREAD_CONTEXT, RESCODE_BACKEND_DATA_EMPTYSET))	_RETURN_RESULT_SESN(sesn_ptr_target, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA_EMPTYSET)

		redis_ptr = (redisReply 	*)THREAD_CONTEXT_UFSRV_RESULT_USERDATA;
	} else	_RETURN_RESULT_SESN(sesn_ptr_target, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)

	{
	 //>> we now have a list of UID's

#ifdef __UF_TESTING
	   syslog(LOG_DEBUG, "%s {pid:'%lu, th_ctx:'%p', fo:'%p', fid:'%lu'}: RESULT: Fence contains (%lu) users in it", __func__, pthread_self(), THREAD_CONTEXT_PTR, f_ptr, FENCE_ID(f_ptr), redis_ptr->elements);
#endif

	   bool 					userid_found						=	false;
	   size_t					userids_preprocessed_sz	=	redis_ptr->elements;
	   unsigned long 	userids_preprocessed[userids_preprocessed_sz]; //TODO: warning: stackoverflow

	   memset (userids_preprocessed, 0, sizeof(userids_preprocessed));

		 for (size_t i=0; i < userids_preprocessed_sz; ++i) {
			 userids_preprocessed[i] = strtoul(redis_ptr->element[i]->str, NULL, 10);
			 if (fence_call_flags&FENCE_CALLFLAG_ABORT_RECORD_IF_USER_NOT_MEMBER) if (userids_preprocessed[i] == userid_loaded_for)	userid_found = true;
		 }

		 //where user was'nt found we want to continue process if the fence for which we are processing the user list was being loaded into
		 //the missing user; ie there is a referential problem: if I was loading the invited fences list for user and this fence was referenced
		 //that list we should see the user referenced here
		 if (!userid_found && (fence_call_flags&FENCE_CALLFLAG_ABORT_RECORD_IF_USER_NOT_MEMBER) && (list_type_target == list_type_context)) {
			 syslog(LOG_DEBUG, "%s {pid:'%lu, th_ctx:'%p', fo:'%p', fid:'%lu', userid_loadedfor:'%lu'}: ERROR: REFERENTIAL ERROR: FENCE MEMBERS LIST DOESNNT REFER TO USER BEING LOADED FOR", __func__, pthread_self(), THREAD_CONTEXT_PTR, f_ptr, FENCE_ID(f_ptr), userid_loaded_for);
			 freeReplyObject(redis_ptr);

			 _RETURN_RESULT_SESN(sesn_ptr_target, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_FENCE_MEMBERSHIP)
		 }

	   size_t				i, success_counter = 0;
	   redisReply		*redis_ptr_session_records[userids_preprocessed_sz];

	   for (i=0; i < userids_preprocessed_sz; ++i)	redis_ptr_session_records[i] = NULL;

	   //retrieve the raw user cache record for each uid and index it into list
	   for (i=0; i < userids_preprocessed_sz; ++i) {
		   unsigned long 	user_id		=  	userids_preprocessed[i];
		   CacheBackendGetRawSessionRecord(user_id, CALLFLAGS_EMPTY, THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));

		   if (THREAD_CONTEXT_UFSRV_RESULT_TYPE_SUCCESS) {
			   redisReply *redis_ptr_user = (redisReply *)THREAD_CONTEXT_UFSRV_RESULT_USERDATA;
			   *(redis_ptr_session_records + success_counter++) = redis_ptr_user;
		   } else {
			   //TODO: this a stale UID which must be cleansed. First check in the DbBackend if the user has uninstalled. perhaps log it in a list for out of band processing?
			   syslog(LOG_DEBUG, "%s (pid:'%lu', th_ctx:'%p', fo:'%p', fid:'%lu', uid:'%lu'): ERROR: FOUND POTENTIALLY STALE UID --> TODO: IMPELMENT CLEANSING", __func__, pthread_self(), THREAD_CONTEXT_PTR, f_ptr, FENCE_ID(f_ptr), user_id);

			   //TODO: implement fully.. currently an anchor point and must check the db backend
			   ClearBackendCacheForSessionlessInvalidUserId(user_id, CALLFLAGS_EMPTY, CALLFLAGS_EMPTY);
		   }
	   }

	   //we now have a list of user record each entry represented by raw redisReply *
	   if (success_counter) {
	  	 __unused size_t users_removed = 0;
       //filter out user's who don't reference this Fence in their Fence list...
       CollectionDescriptor collection_users				={.collection=(collection_t **)redis_ptr_session_records, success_counter};
       users_removed = _CleanUpFaultyUserEntriesForFence(sesn_ptr_target, f_ptr, userid_loaded_for, &collection_users,  MEMBER_FENCES);

		   if (fence_call_flags&FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE) {
		  	 //IMPORTANT: THIS DOES NOT LOAD FENCE LIST FOR SESSION; instead LAZY flag will be set
		  	 CollectionDescriptorPair collection_pair				={.first={(collection_t **)redis_ptr_session_records, success_counter}, .second={0}};
		  	 _InstateUsersListCacheRecordsForFence(sesn_ptr_target, &(f_ptr->fence_user_sessions_list), MEMBER_FENCES, instance_f_ptr,  &collection_pair, CALL_FLAG_REMOTE_SESSION);

			   //we are not writing back fence data or broadcasting users/sessions in this list
		   }
	   }

	   if (success_counter < userids_preprocessed_sz) {
		   syslog(LOG_DEBUG, "%s (pid:'%lu', th_ctx:'%p', fo:'%p'): ERROR: Received '%lu' elements: BUT ONLY PROCESED '%lu' WITH SUCCESS...", __func__, pthread_self(), THREAD_CONTEXT_PTR, f_ptr, redis_ptr->elements, success_counter);
	   }

	   good_finish:
	   for (i=0; i < success_counter; ++i)	 if (IS_PRESENT(redis_ptr_session_records[i]))	freeReplyObject(redis_ptr_session_records[i]);

	   freeReplyObject(redis_ptr);

	   _RETURN_RESULT_SESN(sesn_ptr_target, f_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
	}//redis block

	return_error:
	freeReplyObject(redis_ptr);
	_RETURN_RESULT_SESN(sesn_ptr_target, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)

	return_error_unlock:
	freeReplyObject(redis_ptr);
	_RETURN_RESULT_SESN(sesn_ptr_target, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)

}

/**
 * 	@brief: retrieve a given Fence's invited users member list and build/initialise it into Fence's Session list
 * 	FenceGetUserListFromBackend -> LOOP( _RetrieveSessionRecordFromRawBackend)
 * 									 -> FenceAttachRawSessionsList
 * 	TODO: refactor so the session creation happens here
 *
 * 	@WARNING: Fence MAY NOT BE POPULATED DONT ASSUME ANYTHING ABOUT FENEC DATA EXCEPT ID AND WHETHET DIRT FLAG IS SET
 *
 *	@param sesn_ptr: must have full backend access context
 *
 * 	@call_flag CALL_FLAG_ATTACH_USER_LIST_TO_FENCE:
 *
 * 	@locks: none
 *
 * 	@locked f_ptr: must be locked in the calling environment
 * 	@locked sesn_ptr: must be locked in the calling environment
 *
 * 	@dynamic_memory redis_ptr: Redis reply is created and destroyed
 * 	@dynamic_memory sesn_ptr_list: redisReply **sesn_ptr_list array of redis replys created and destroyed

 *	@call_flag: FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE
 *
 * 	@worker_thread: session worker, ufsrv worker
 */
UFSRVResult *
GetInvitedMembersListCacheRecordForFence (Session *sesn_ptr,  InstanceHolderForFence *instance_f_ptr, unsigned long userid_loaded_for, EnumFenceCollectionType list_type_target, EnumFenceCollectionType list_type_context, unsigned long fence_call_flags)
{
  Fence *f_ptr = FenceOffInstanceHolder(instance_f_ptr);

	//we need at lease one of these to be set to proceed...
	if (!(F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_DIRTY)) && !(F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_SESSNLIST_LAZY))) {
#ifdef __UF_TESTING
		 syslog(LOG_DEBUG, "%s (pid:'%lu, o:'%p', fo:'%p', fid:'%lu') NOT FETCHING SESSION LIST FOR FENCE (lazy:'%d', dirty:'%d')", __func__, pthread_self(), sesn_ptr, f_ptr, FENCE_ID(f_ptr), F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_SESSNLIST_LAZY), F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_DIRTY));
#endif

		 _RETURN_RESULT_SESN(sesn_ptr, f_ptr, RESULT_TYPE_SUCCESS, RESCODE_FENCE_LIST_SELFLOADED)
	}

	int									rescode;
	PersistanceBackend	*pers_ptr		=	sesn_ptr->persistance_backend;
	redisReply 					*redis_ptr	=	NULL;

#if 1
	//returns list of userids
	if (!(redis_ptr = (*pers_ptr->send_command)(sesn_ptr, REDIS_CMD_INVITED_USERS_FOR_FERNCE_GET_ALL, FENCE_ID(f_ptr))))	goto return_redis_error;
	if (redis_ptr->type == REDIS_REPLY_ERROR)	goto return_redis_error;
	if (redis_ptr->type == REDIS_REPLY_NIL)		goto return_redis_error;
  if (redis_ptr->elements == 0) {
#ifdef __UF_FULLDEBUG
 	 syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p, fo:'%p', fid:'%lu'): NOTICE: EMPTY SET FOR FENCE",  __func__, pthread_self(), sesn_ptr, f_ptr, FENCE_ID(f_ptr));
#endif

 	 _RETURN_RESULT_SESN(sesn_ptr, f_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA_EMPTYSET)
  }
#endif

	   //we now have a list of UID's
#ifdef __UF_TESTING
   syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', fo:'%p', fid:'%lu'}: RESULT: Fence contains (%lu) invited users in it", __func__, pthread_self(), sesn_ptr, f_ptr, FENCE_ID(f_ptr), redis_ptr->elements);
#endif

   {//block necessary because of variable sized array. Cannot exit with goto from this block
		 bool 					userid_found						=	false;
		 size_t					userids_preprocessed_sz	=	redis_ptr->elements;
		 PairOfUserIdUserName	uids_unames_preprocessed[userids_preprocessed_sz];

		 memset (uids_unames_preprocessed, 0, sizeof(uids_unames_preprocessed));

		 for (size_t i=0; i < userids_preprocessed_sz; ++i) {
			 if (NOT_TRUE(_ExtractUserIdUserNameFromListCacheRecord(redis_ptr->element[i]->str, &uids_unames_preprocessed[i]))) {
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', idx:'%lu', field(maybe modified):'%s'): ERROR: COULD NOT PARSE FIELD", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i, redis_ptr->element[i]->str);
				continue;
			 }

			 if (fence_call_flags&FENCE_CALLFLAG_ABORT_RECORD_IF_USER_NOT_MEMBER) if (uids_unames_preprocessed[i].uid==userid_loaded_for)	userid_found=true;
		 }

		 //where user wasnt found we want to continue process if the fence for which we are processing the user list was being loaded into
		 //the missing user; ie there is a referential problem: if I was loading the invited fences list for user and this fence was referenced
		 //that list we should see the user referenced here
		 if (!userid_found && (fence_call_flags&FENCE_CALLFLAG_ABORT_RECORD_IF_USER_NOT_MEMBER) && (list_type_target == list_type_context)) {
			 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', fo:'%p', fid:'%lu', userid_loadedfor:'%lu'}: ERROR: REFERENTIAL ERROR: FENCE MEMBERS LIST DOESNNT REFER TO USER BEING LOADED FOR", __func__, pthread_self(), sesn_ptr, f_ptr, FENCE_ID(f_ptr), userid_loaded_for);
			 freeReplyObject(redis_ptr);

			 _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_FENCE_MEMBERSHIP)
		 }

		 //retrieve the raw user cache record for each uid and index it into list
		 //IMPORTANT: we are loading temporary session regardless if the users exists locally in order to perform data integrity check
		 //on members reflected in the returned cache backend.It is expensive.
		 size_t				success_counter =	0;
		 PairOfUserIdUserName			*uids_unames_processed[userids_preprocessed_sz];//filtered out list based on successfully fetched user records
		 redisReply								*redis_ptr_session_records[userids_preprocessed_sz];

		 memset (uids_unames_processed, 0, sizeof(uids_unames_processed));
		 memset (redis_ptr_session_records, 0, sizeof(redis_ptr_session_records));

		 for (size_t i=0; i < userids_preprocessed_sz; ++i) {
			 unsigned long 	user_id		= uids_unames_preprocessed[i].uid;
			 CacheBackendGetRawSessionRecord(user_id, CALLFLAGS_EMPTY, THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));

			 if (THREAD_CONTEXT_UFSRV_RESULT_TYPE_SUCCESS) {
				 redisReply *redis_ptr_user = (redisReply *)THREAD_CONTEXT_UFSRV_RESULT_USERDATA;
				 *(uids_unames_processed + success_counter) = &uids_unames_preprocessed[i];
				 *(redis_ptr_session_records + success_counter++) = redis_ptr_user;
			 } else {
				 //TODO: this a stale UID which must cleanse. perhaps log it in a list for out of band processing?
				 syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', fo:'%p', fid:'%lu', uid:'%lu'): ERROR: FOUND POTENTIALLY STALE UID --> TODO: IMPELMENT CLEANSING", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), f_ptr, FENCE_ID(f_ptr), user_id);
			 }
		 }

		 //we now have a list of user record each entry represented by raw redisReply *
		 if (success_counter) {
			 if (fence_call_flags&FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE) {
				 CollectionDescriptorPair collection_pair				={ .first={(collection_t **)redis_ptr_session_records, success_counter},
						 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 .second={(collection_t **)uids_unames_processed, success_counter}};
				 _InstateUsersListCacheRecordsForFence (sesn_ptr, &(f_ptr->fence_user_sessions_invited_list), INVITED_FENCES, instance_f_ptr, &collection_pair, CALL_FLAG_REMOTE_SESSION);
				 //we are not writing back fence data or broadcasting users/sessions in this list
			 }
		 }

		 if (success_counter < redis_ptr->elements) {
			 syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', fo:'%p'): ERROR: Received '%lu' elements: BUT ONLY PROCESED '%lu' WITH SUCCESS...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), f_ptr, redis_ptr->elements, success_counter);
		 }

		 good_finish:
		 for (size_t i=0; i < success_counter; ++i)	 freeReplyObject(redis_ptr_session_records[i]);
		 freeReplyObject(redis_ptr);

		 _RETURN_RESULT_SESN(sesn_ptr, f_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
   }

   return_redis_error:
   if (IS_EMPTY(redis_ptr)) {
	   syslog(LOG_DEBUG, "%s (pid:'%lu, o:'%p', cid:'%lu', fo:'%p', fid:'%lu') ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), f_ptr, FENCE_ID(f_ptr));_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION);
   }
   if (redis_ptr->type == REDIS_REPLY_ERROR) {
	   syslog(LOG_DEBUG, "%s (pid:'%lu, o:'%p', cid:'%lu', fo:'%p', fid:'%lu'): ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), f_ptr, FENCE_ID(f_ptr), redis_ptr->str);
	   rescode = RESCODE_BACKEND_DATA; goto return_error;
   }
   if (redis_ptr->type == REDIS_REPLY_NIL) {
	   syslog(LOG_DEBUG, "%s (pid:'%lu, o:'%p', cid:'%lu', fo:'%p', fid:'%lu': ERROR: NIL SET FOR FENCE",  __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), f_ptr, FENCE_ID(f_ptr));
	   rescode = RESCODE_BACKEND_DATA; goto return_error;
   }

   return_error:
   freeReplyObject(redis_ptr);
   _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)

}

/**
 * 	@brief for each (redis-raw) user session record contained in the list:
 * 	1)instatiate a remote type session 2)attach it to the Fences Session list.
 * 	Designed to work within FenceGetUserListFromBackend()
 *
 *	@param sesn_ptr_carrier: mostly functions as carrier Session, but it also reflects the current user Session for whom list is
 *	being processed, especially when check for uid invalidity is performed
 *
 *	@param collection_pair_ptr: Contains the actual list of raw records. Additionally, collection_pair_ptr.second may contain additional
 *	indexed records list depending on context
 *
 *	DOESN NOT RESET FENCE USER LIST BEFORE ADDING, but no duplicates are allowed in user or fence list as they are cross checked
 *	@dynamic_memory: Caller is responsible for deallocating 'redisReplay **'
 *
 *	@locked f_ptr *: must locked by the caller
 *
 *	@worker: session worker, ufsrv worker
 */
inline static Fence *
_InstateUsersListCacheRecordsForFence (Session *sesn_ptr_target, List *fence_user_list_ptr, EnumFenceCollectionType user_fence_list_type, InstanceHolderForFence *instance_f_ptr, CollectionDescriptorPair *collection_pair_ptr, unsigned call_flags)
{
	size_t i = 0;

	const unsigned		writeback_flag	= (call_flags&CALL_FLAG_WRITEBACK_FENCE_DATA_TO_BACKEND)?CALL_FLAG_WRITEBACK_FENCE_DATA_TO_BACKEND:0;
	unsigned					instan_flags		= 0;
	redisReply 				**redis_ptr_session_records 	= (redisReply **)collection_pair_ptr->first.collection;
	ClientContextData **contex_records 							= collection_pair_ptr->second.collection;
	size_t 						list_count										=	collection_pair_ptr->first.collection_sz;
	redisReply				*processed_users[list_count];
	UfsrvUid					*uid_ptr;

	Fence *f_ptr = FenceOffInstanceHolder(instance_f_ptr);

	for (; i<list_count; i++)	processed_users[i] = NULL;

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s: {pid:'%lu', o:'%p', cid:'%lu', fo:'%p', fid:'%lu'}: Attaching '%lu' Users to Fence", __func__, pthread_self(), sesn_ptr_target, SESSION_ID(sesn_ptr_target), f_ptr, FENCE_ID(f_ptr), list_count);
#endif

	instan_flags |= call_flags&CALL_FLAG_REMOTE_SESSION?CALL_FLAG_REMOTE_SESSION:0;
	instan_flags |= (CALL_FLAG_LOCK_SESSION|CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY|CALL_FLAG_HASH_USERNAME_LOCALLY);//no CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION

	for (i=0; i<list_count; i++) {
		redisReply *redis_ptr = *(redis_ptr_session_records + i);

		if (IS_EMPTY(redis_ptr)) {
			syslog(LOG_DEBUG, "%s: {pid:'%lu', o:'%p', cid:'%lu', fo:'%p', fid:'%lu'}: ERROR: User at index '%lu' is NULL: RECIEVED '%lu' elements to attach to FENCE", __func__, pthread_self(), sesn_ptr_target, SESSION_ID(sesn_ptr_target), f_ptr, FENCE_ID(f_ptr), i, list_count);

			processed_users[i] = NULL;
			continue;
		}

		//IMPORTANT RELIES ON STATUS BEING SET TO 0
		if ((strtoul(redis_ptr->element[REDIS_KEY_USER_STATUS]->str, NULL, 10)) == 0) {
			const char *username_invalid=(!IS_EMPTY(redis_ptr->element[REDIS_KEY_USER_USER_NAME]->str))?redis_ptr->element[REDIS_KEY_USER_USER_NAME]->str:"";
			uid_ptr											=(!IS_EMPTY(redis_ptr->element[REDIS_KEY_USER_UID]->str) && *(redis_ptr->element[REDIS_KEY_USER_UID]->str)!=0)?
																		(UfsrvUid *)redis_ptr->element[REDIS_KEY_USER_UID]->str:NULL;
//			const char *uid_invalid		=(!IS_EMPTY(redis_ptr->element[REDIS_KEY_USER_UID]->str))?redis_ptr->element[REDIS_KEY_USER_UID]->str:"";

			syslog(LOG_NOTICE, "%s: {pid:'%lu', o:'%p', cid:'%lu', fo:'%p', fid:'%lu', unamed_invalid:'%s', uid_ptr:'%p'}: WARNING: ENTIRE USER CACHEBACKEND RECORD WILL BE BLOWN OFF: User at index '%lu' is NULL: RECIEVED '%lu' elements to attach to FENCE", __func__, pthread_self(), sesn_ptr_target, SESSION_ID(sesn_ptr_target), f_ptr, FENCE_ID(f_ptr), username_invalid, uid_ptr, i, list_count);

			_ClearInvalidUserId(sesn_ptr_target, f_ptr, redis_ptr);

			continue;
		}

		//ensure the user is not in this list twice
		_CheckForDuplicateUsername(sesn_ptr_target, f_ptr, redis_ptr, processed_users, i + 1);

		if (unlikely(SESSION_RESULT_TYPE_ERROR(sesn_ptr_target))) {
			redisReply *redis_ptr_invalid = SESSION_RESULT_USERDATA(sesn_ptr_target);

			if (!(IS_EMPTY(redis_ptr_invalid))) {
				UfsrvUid *uid_ptr_invalid	=	(UfsrvUid *)redis_ptr_invalid->element[REDIS_KEY_USER_UID]->str;
				unsigned long userid_invalid = UfsrvUidGetSequenceId(uid_ptr_invalid);

				//some other dude with invalid userid
				if (SESSION_USERID(sesn_ptr_target) != userid_invalid) {
					_ClearInvalidUserId(sesn_ptr_target, f_ptr, redis_ptr_invalid);

					continue;//process next user
				} else {
					//kind of impossible?
					syslog(LOG_ERR, "%s: (pid:'%lu', o:'%p', cid:'%lu', uid_invalid:'%lu', fid:'%lu', fo:'%p'): SEVERE ERROR: CURRENT CONNECTED USER REPORTED WITH INVALID UID", __func__, pthread_self(), sesn_ptr_target, SESSION_ID(sesn_ptr_target), userid_invalid,  FENCE_ID(f_ptr), f_ptr);
					return NULL;
				}
			}

			if (IS_EMPTY(redis_ptr_invalid)) {
				//both userids share the same username
				syslog(LOG_ERR, "%s: (pid:'%lu', o:'%p', cid:'%lu', uid:'%lu', uname:'%s', fid:'%lu', fo:'%p'): SEVERE ERROR: TWO USERIDs SHARE THE SAME USERNAME...", __func__, pthread_self(), sesn_ptr_target, SESSION_ID(sesn_ptr_target), SESSION_USERID(sesn_ptr_target),  SESSION_USERNAME(sesn_ptr_target), FENCE_ID(f_ptr), f_ptr);
				return NULL;
			}
		}

		if (IS_EMPTY(redis_ptr->element[REDIS_KEY_USER_UID]->str) || *(redis_ptr->element[REDIS_KEY_USER_UID]->str) == 0 || IS_EMPTY(redis_ptr->element[REDIS_KEY_USER_USER_NAME]->str)) {
			if (!IS_EMPTY(redis_ptr->element[REDIS_KEY_USER_USER_NAME]->str))	processed_users[i] = redis_ptr;
			else processed_users[i] = NULL;

			syslog(LOG_DEBUG, "%s: (pid:'%lu', o:'%p', cid:'%lu'): ERROR: ELEMENT at index '%lu' HAS NULL UID OR USERNAME 'bid='%lu'", __func__, pthread_self(), sesn_ptr_target, SESSION_ID(sesn_ptr_target), i, FENCE_ID(f_ptr));

			continue;
		}

		if (UfsrvUidIsEqual(&SESSION_UFSRVUIDSTORE(sesn_ptr_target), (UfsrvUid *)redis_ptr->element[REDIS_KEY_USER_UID]->str)) {
			//session id sould be the same too as UID:%uid record will have been updated before this call after authentication
			//OK this is me: this potentially belongs to stale old entry, maybe server crashed and did not updated properly
			//since we'll be added properly to this fence (not s a remote session) we can ignore this reference

			processed_users[i] = redis_ptr;

			continue;
		}

		//at this stage we don't know which of these sessions are local
		//TODO: NOTICE: for the same session id and different session pointer the has WILL SUCCEDE as the same is will hash to the same slot number,
		//but due to collision one will be incremented: so we have one id, two session objects. We must ensure the id is not in the hash before adding

		//check for existence in local hash
		bool lock_already_owned = false;
		InstanceHolderForSession  *instance_sesn_ptr_remote;
    Session						        *sesn_ptr_remote;

		if ((instance_sesn_ptr_remote = LocallyLocateSessionById(strtoul(redis_ptr->element[REDIS_KEY_USER_CID]->str, NULL, 10)))) {
#ifdef __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s: (pid='%lu'): FOUND USER IN SESSION HASH (cid='%s') (LOCAL OR REMOTE): NOT INSTANTIATING SESSION", __func__, pthread_self(), redis_ptr->element[REDIS_KEY_USER_CID]->str);
#endif
      sesn_ptr_remote = SessionOffInstanceHolder(instance_sesn_ptr_remote);

			SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_remote, _LOCK_TRY_FLAG_TRUE, __func__);
			if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR)) {
				processed_users[i] = NULL;

				continue;
			}

			lock_already_owned = _RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_BY_THIS_THREAD);
		} else {
      if ((instance_sesn_ptr_remote = CacheBackendInstantiateRawSessionRecord(sesn_ptr_target, redis_ptr,
                                                                              instan_flags |
                                                                              CALL_FLAG_LOAD_DB_BACKEND_FOR_SESSION,
                                                                              NULL))) {
        sesn_ptr_remote = SessionOffInstanceHolder(instance_sesn_ptr_remote);
      } else {
        sesn_ptr_remote = NULL;
      }
		}

		if (!IS_EMPTY(sesn_ptr_remote)) {
			processed_users[i] = redis_ptr;
		} else {
			//could be because it is a duplicate local session, because hash will refuse rehahshing that
			syslog(LOG_DEBUG, "%s: (pid:'%lu', o:'%p', cid:'%lu'): ERROR: COULD NOT INSTANTIATE REMOTE SESSION: 'cid_redis='%s' to Fence: 'bid='%lu'",	__func__, pthread_self(), sesn_ptr_target, SESSION_ID(sesn_ptr_target), redis_ptr->element[REDIS_KEY_USER_CID]->str, FENCE_ID(f_ptr));

			processed_users[i] = NULL;

			continue; //process next record in list
		}

    InstanceHolderForFenceStateDescriptor *instance_fstate_ptr;
    FenceStateDescriptor *fstate_ptr;

    List *user_fence_list_ptr = _GetUserListByFenceCollectionType(sesn_ptr_remote, user_fence_list_type);
    instance_fstate_ptr = AddUserToThisFenceListWithLinkback(instance_sesn_ptr_remote, instance_f_ptr, user_fence_list_ptr, fence_user_list_ptr,  0/*event_type*/, writeback_flag|CALL_FLAG_FENCE_LIST_CHECK_DUP_SESSION|CALL_FLAG_SESSION_LIST_CHECK_DUP_FENCE);
    fstate_ptr = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);

    FenceListTypeDescriptor *list_descriptor_ptr = GetFenceListTypeDescriptor (user_fence_list_type);
    if (IS_PRESENT(list_descriptor_ptr->type_ops.user_attached_callback))	(*list_descriptor_ptr->type_ops.user_attached_callback)(sesn_ptr_remote, fstate_ptr, *(contex_records + i));

    if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_remote, __func__);

	}

	F_ATTR_UNSET(f_ptr->attrs, F_ATTR_SESSNLIST_LAZY);
	F_ATTR_UNSET(f_ptr->attrs, F_ATTR_DIRTY);

	return f_ptr;

}

/**
 * 	@brief: helper function to detect if raw cache records list of users contain the a specific user. This is extra safety check to
 * 	detect at "run-time" if the list being processed contains the same user twice.
 *
 * 	@returns if returned userdata is NULL and rescode is  RESCODE_USER_INVALID_UID that indicates both uids are invalid, because
 * 	we detected two uids sharing the same username
 */
static inline UFSRVResult *
_CheckForDuplicateUsername (Session *sesn_ptr_carrier, Fence *f_ptr, redisReply *current_user, redisReply **processed_users_collection, size_t collection_sz)
{
	size_t idx=0;

	for (; idx<collection_sz; idx++)
	{
		if (IS_EMPTY(processed_users_collection[idx]))	continue;

//		if ((strcasecmp(current_user->element[REDIS_KEY_USER_USER_NAME]->str, processed_users_collection[idx]->element[REDIS_KEY_USER_USER_NAME]->str)==0))
		if ((memcmp(current_user->element[REDIS_KEY_USER_UID]->str, processed_users_collection[idx]->element[REDIS_KEY_USER_UID]->str, CONFIG_MAX_UFSRV_ID_SZ)==0)) {
			syslog(LOG_ERR, "%s: (pid='%lu', o:'%p', fid:'%lu', fo:'%p', uname:'%s', uid_redis:'%p', cid_redis:'%s'): ERROR: DUPLICATE USERNAME IN FENCE LIST", __func__,
					pthread_self(), sesn_ptr_carrier, FENCE_ID(f_ptr), f_ptr, current_user->element[REDIS_KEY_USER_USER_NAME]->str, processed_users_collection[idx]->element[REDIS_KEY_USER_UID]->str, processed_users_collection[idx]->element[REDIS_KEY_USER_CID]->str);

			bool				userid_current_valid		= false,
									userid_processed_valid	= false;
			unsigned		userid_current_rescode		__attribute__((unused)),
									userid_processed_rescode	__attribute__((unused)); //use to check for returned errors

			unsigned long	userid_current	=UfsrvUidGetSequenceId((UfsrvUid *)current_user->element[REDIS_KEY_USER_UID]->str);
			unsigned long	userid_processed=UfsrvUidGetSequenceId((UfsrvUid *)processed_users_collection[idx]->element[REDIS_KEY_USER_UID]->str);

			DbValidateUserId (sesn_ptr_carrier, userid_current);
			if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr_carrier))	userid_current_valid=true;
			userid_current_rescode=SESSION_RESULT_CODE(sesn_ptr_carrier);

			DbValidateUserId (sesn_ptr_carrier, userid_processed);
			if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr_carrier))	userid_processed_valid=true;
			userid_processed_rescode=SESSION_RESULT_CODE(sesn_ptr_carrier);

			if (userid_current_valid && userid_processed_valid) {
				syslog(LOG_ERR, "%s: (pid:'%lu', o:'%p', fid:'%lu', fo:'%p', uid_current:'%lu', uid_processed:'%lu'): ERROR: FOUND TWO VALID UIDs WITH THE SAME USERNAME", __func__,
							pthread_self(), sesn_ptr_carrier, FENCE_ID(f_ptr), f_ptr, userid_current, userid_processed);

				_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, RESCODE_USER_INVALID_UID);
			}

			if (userid_current_valid) {
				syslog(LOG_ERR, "%s: (pid:'%lu', o:'%p', fid:'%lu', fo:'%p', uid_current:'%lu', uid_invalid:'%lu'): ERROR: FOUND INVALID UID", __func__,
											pthread_self(), sesn_ptr_carrier, FENCE_ID(f_ptr), f_ptr, userid_current, userid_processed);

				_RETURN_RESULT_SESN(sesn_ptr_carrier, processed_users_collection[idx], RESULT_TYPE_ERR, RESCODE_USER_INVALID_UID);
			}

			if (userid_processed_valid) {
				syslog(LOG_ERR, "%s: (pid:'%lu', o:'%p', fid:'%lu', fo:'%p', uid_processed:'%lu', uid_invalid:'%lu'): ERROR: CURRENT UID  INVALID UID", __func__,
											pthread_self(), sesn_ptr_carrier, FENCE_ID(f_ptr), f_ptr, userid_processed, userid_current);

				_RETURN_RESULT_SESN(sesn_ptr_carrier, current_user, RESULT_TYPE_ERR, RESCODE_USER_INVALID_UID);
			}
		}
	}

	//all erroneous exit points are inlined above
	_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);
}

/**
 * 	@brief helper function to remove invalid uids discovered during fence user list loading.
 * 	Session is loaded "incognito", not leaving any trace in hashes
 *
 * 	@param sesn_ptr: just a carrier session, not target for operation
 * 	@param:redis_ptr_invalid: raw redis record containing the invalid userid
 *
 * 	@type_pool: instantiates and returns temporary Session
 * 	@ref_count: does not increment
 *
 * 	@worker: session worker,ufsrv worker
 */
static inline void
_ClearInvalidUserId (Session *sesn_ptr_carrier, Fence *f_ptr, redisReply *redis_ptr_invalid)
{
	//todo: this can prove problematic as clearing cache entries require more data about the user and fence state for exampel invited by
	InstanceHolderForSession *instance_sesn_ptr_invalid = SessionLightlyInstantiateFromBackendRaw (sesn_ptr_carrier, NULL, redis_ptr_invalid, CALLFLAGS_EMPTY);
	if (!IS_EMPTY(instance_sesn_ptr_invalid)) {
		ClearBackendCacheForInvalidUserId (sesn_ptr_carrier, SessionOffInstanceHolder(instance_sesn_ptr_invalid), f_ptr, CALLFLAGS_EMPTY);
		SessionReturnToRecycler (instance_sesn_ptr_invalid, (ContextData *)NULL, CALLFLAGS_EMPTY);
	}

}

/**
 * @brief: helper routine
 * 	@ALREAT: modifies passed string
 */
static inline bool
_ExtractUserIdUserNameFromListCacheRecord (char *raw_cache_field, PairOfUserIdUserName *pair)
{
	//"276:+61412345678:1234", includes extra field at the end(inviter uid)
	char *uid_str=raw_cache_field;
	char *uid_by=strrchr(uid_str, ':'); *uid_by='\0'; uid_by++;
	char *uname=strchr(uid_str, ':');
	if (IS_PRESENT(uname))
	{
		*uname='\0';
		pair->uname=++uname;
		pair->uid=strtoul(uid_str, NULL, 10);
		pair->aux=uid_by;

		return true;
	}

	return false;
}

//END BUILD USER LIST FOR FENCE

// -------------------------- FIND AND FETCH ROUTINES ------------------------------
#if 1

/**
 *  @returns InstanceHolderForFence
 * 	@locks RW Fence *:  WHEN  the flag HASH_LOCALLY is set OR when the fence is hashed locally and FENCE_CALLFLAG_KEEP_FENCE_LOCKED was set
 * 	@unlocks Fence *: UNLESS (FENCE_CALLFLAG_HASH_FENCE_LOCALLY|
 *
 * 	@call_flag FENCE_CALLFLAG_SEARCH_BACKEND: if local search find none backend will be searched
 * 	@call_flag FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE: SET BY DEFAULT
 * 	@call_flag FENCE_CALLFLAG_HASH_FENCE_LOCALLY: SET BY DEFULT
 * 	@call_flag FENCE_CALLFLAG_KEEP_FENCE_LOCKED: Fence returned in locked state. In case of backend search works in combination with FENCE_CALLFLAG_HASH_FENCE_LOCALLY
 * 	@call_flag	FENCE_CALLFLAG_SNAPSHOT_INSTANCE: Used in conjunction with BACKEND, restricting the amount of data populated for the Fence. User
 * 	must return the instance back to recycler
 *
 */
UFSRVResult *
FindFenceByCanonicalName (Session *sesn_ptr_this, const char *fence_canonical_name, bool *fence_lock_state, unsigned long fence_call_flags)
{
	Fence 							*f_ptr		= NULL;
  InstanceHolderForFence *instance_f_ptr = NULL;
	PersistanceBackend	*pers_ptr	= NULL;

  instance_f_ptr = (InstanceHolderForFence *)HashLookup(&FenceRegistryCanonicalNameHashTable, (void *)fence_canonical_name, true);

	if (!IS_EMPTY(instance_f_ptr)) {
	  f_ptr = FenceOffInstanceHolder(instance_f_ptr);
		if (fence_call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED) {
			FenceEventsLockRWCtx(THREAD_CONTEXT_PTR, f_ptr, _LOCK_TRY_FLAG_FALSE, SESSION_RESULT_PTR(sesn_ptr_this), __func__);
			if (likely(IS_PRESENT(fence_lock_state)))	*fence_lock_state = (SESSION_RESULT_CODE_EQUAL(sesn_ptr_this, RESCODE_PROG_LOCKED_BY_THIS_THREAD));
		}

		SESSION_RETURN_RESULT(sesn_ptr_this, instance_f_ptr, RESULT_TYPE_SUCCESS, RESCODE_PROG_RESOURCE_CACHED)
	}

	if ((IS_EMPTY(f_ptr)) && (!(fence_call_flags&FENCE_CALLFLAG_SEARCH_BACKEND)))	{SESSION_RETURN_RESULT(sesn_ptr_this, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)}

	pers_ptr = sesn_ptr_this->fence_cachebackend;

	redisReply *redis_ptr;
	bool fence_lock_already_owned = false;

  if (!(redis_ptr = (*pers_ptr->send_command)(sesn_ptr_this, SESSION_FENCE_CACHEBACKEND(sesn_ptr_this), REDIS_CMD_MATCHING_FENCES_GET, fence_canonical_name, fence_canonical_name))) {
    syslog(LOG_DEBUG, "%s: ERROR RESPONSE for baseloc '%s' " REDIS_CMD_MATCHING_FENCES_GET, __func__, fence_canonical_name, fence_canonical_name, fence_canonical_name);
    SESSION_RETURN_RESULT(sesn_ptr_this, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
  }

  if (redis_ptr->type == REDIS_REPLY_ERROR) {
    syslog(LOG_DEBUG, "%s: ERROR: REDIS RESULTSET for baseloc '%s'. Error: '%s'", __func__, fence_canonical_name, redis_ptr->str);
    SESSION_RETURN_RESULT(sesn_ptr_this, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
  }

  if (redis_ptr->type == REDIS_REPLY_NIL) {
    syslog(LOG_DEBUG, "%s: ERROR: EMPTY SET FOR BASELOC '%s'",  __func__, fence_canonical_name);
    SESSION_RETURN_RESULT(sesn_ptr_this, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_RESOURCE_NULL)
  }
#endif

#ifdef __UF_FULLDEBUG
   syslog(LOG_DEBUG, "%s (pid:'%lu'): RESULT: Received (%lu) elements", __func__, pthread_self(), redis_ptr->elements);
#endif
   int i, j = 0;

   for (i=0; i < redis_ptr->elements; ++i) {
     char *fence_id_str = strrchr(redis_ptr->element[i]->str, ':');
     *fence_id_str = '\0'; fence_id_str++;

     if ((strcasecmp(redis_ptr->element[i]->str, fence_canonical_name) == 0)) {
       if (fence_call_flags&FENCE_CALLFLAG_SNAPSHOT_INSTANCE) {
         instance_f_ptr = FenceGetInstance (NULL, FENCE_CALLFLAG_USERFENCE|FENCE_CALLFLAG_SNAPSHOT_INSTANCE);
         if (unlikely(IS_EMPTY(instance_f_ptr))) {
           freeReplyObject(redis_ptr);
           SESSION_RETURN_RESULT(sesn_ptr_this, NULL, RESULT_TYPE_ERR, RESCODE_PROG_INCONSISTENT_STATE)
         }

         f_ptr = FenceOffInstanceHolder(instance_f_ptr);

         FENCE_ID(f_ptr) = strtoul(fence_id_str, NULL, 10);
         goto return_success;
       } else {
         unsigned long fence_call_flags_final = FENCE_CALLFLAG_HASH_FENCE_LOCALLY|FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE;

         if (fence_call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED)	fence_call_flags_final |= FENCE_CALLFLAG_KEEP_FENCE_LOCKED;

         GetCacheRecordForFence(sesn_ptr_this, UNSPECIFIED_FENCE_LISTTYPE, strtoul(fence_id_str, NULL, 10), UNSPECIFIED_UID, &fence_lock_already_owned, fence_call_flags_final);

         instance_f_ptr = (InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr_this);

         if (IS_PRESENT(instance_f_ptr))	goto return_success;
       }
     }
   }

   //we did not find it
  freeReplyObject(redis_ptr);

  syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p'): COULD NOT FIND Fence '%s' ", __func__, pthread_self(), sesn_ptr_this, fence_canonical_name);

  SESSION_RETURN_RESULT(sesn_ptr_this, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

  return_success:
  freeReplyObject(redis_ptr);
  if (IS_PRESENT(fence_lock_state))	*fence_lock_state = fence_lock_already_owned;
  SESSION_RETURN_RESULT(sesn_ptr_this, instance_f_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA) //fence returned in RW locked state if FENCE_CALLFLAG_KEEP_FENCE_LOCKED set

}

/**
 *
 * 	@locks f_ptr: RW LOCKED downstream if HASH_LOCALLY|KEEP LOCKED ARE set
 * 	@unlocks f_ptr: returned unlocked if fence was not of BaseFence type and keeplocked was set
 * 	@locked sesn_ptr_this:
 * 	@call_flag
 */
InstanceHolder *
FindBaseFenceByCanonicalName (Session *sesn_ptr, const char *fence_canonical_name, bool *fence_already_locked, unsigned long fence_call_flags)
{
	Fence *f_ptr = NULL;

	FindFenceByCanonicalName (sesn_ptr, fence_canonical_name, fence_already_locked, fence_call_flags);
	InstanceHolder *instance_holder_ptr = SESSION_RESULT_USERDATA(sesn_ptr);

	if (IS_EMPTY(instance_holder_ptr))	return NULL;

	f_ptr = FenceOffInstanceHolder(instance_holder_ptr);

	if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_BASEFENCE)) {
		return instance_holder_ptr;
	} else {
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu' o:'%p'}: FENCE '%s' IS NOT OF BASE TYPE", __func__, pthread_self(), sesn_ptr, FENCE_CNAME(f_ptr));
#endif

		//since the retrieval function  above is oblivion to fence type if these two flags are set it will return a locked fence
		//but since our client is only interested in type specific fence, we transparently unlock on their behalf, because the retrieval
		//has essentially failed from their perspective, hence NULL return--they have no way of unlocking a NULL reference!
		if (((fence_call_flags&FENCE_CALLFLAG_HASH_FENCE_LOCALLY) && (fence_call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED)) || (fence_call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED))
			if (!(*fence_already_locked))	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));

		return NULL;
	}

	return NULL;

}

//
//Searches Hash. Canonical names only apply to network created base fences
//>>RD LOCKS
//
/**
 * 	locks: None, unless fence was fetched from backend and the flags HASH_LOCALLY|FENCE_CALLFLAG_KEEP_FENCE_LOCKED were set
 * 			which has the effect of returning the fence locked state
 */
InstanceHolderForFence *
FindUserFenceByCanonicalName (Session *sesn_ptr, const char *fence_canonical_name, bool *fence_already_locked, unsigned long fence_call_flags)
{
	Fence *f_ptr = NULL;

	FindFenceByCanonicalName (sesn_ptr, fence_canonical_name, fence_already_locked, fence_call_flags);
	InstanceHolderForFence *instance_f_ptr = SESSION_RESULT_USERDATA(sesn_ptr);

	if (IS_EMPTY(instance_f_ptr))	return NULL;

	f_ptr = FenceOffInstanceHolder(instance_f_ptr);

	if (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_USERFENCE)) {
		return instance_f_ptr;
	} else {
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu' o:'%p'}: FENCE '%s' IS NOT OF USER TYPE", __func__, pthread_self(), sesn_ptr, FENCE_CNAME(f_ptr));
#endif

		//since the retrieval function is oblivion to fence type if these two flags are set it will return a locked fence
		//but since our client is only interested in type specific fence, we transparently unlock on their behalf, because the retrieval
		//has essentially failed from their perspective, hence NULL return
		if (((fence_call_flags&FENCE_CALLFLAG_HASH_FENCE_LOCALLY) && (fence_call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED)) || (fence_call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED))
			if (!(*fence_already_locked))	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));

		return NULL;
	}

}

/**
 * 	@brief: Searches based on fence id. Relays all call_flags.
 * 	@returns InstanceHolderForFence
 * 	@locks: None directly
 * 	@locked Session
 * 	@call_flag FENCE_CALLFLAG_SEARCH_BACKEND: if fence is not found locally, perform search on backend
 * 	@call_flag FENCE_CALLFLAG_KEEP_FENCE_LOCKED: for backend search works when hash-locally is set
 */
UFSRVResult *
FindFenceById (Session *sesn_ptr, const unsigned long fence_id, unsigned long fence_call_flags)
{
	int 	res_code 	= RESCODE_PROG_LOCKED;
	ThreadContext *thread_ctx_ptr;
	UFSRVResult 	*res_ptr;

	if (IS_EMPTY(sesn_ptr)) {
		thread_ctx_ptr  = THREAD_CONTEXT_PTR;
		res_ptr         = THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT);
	} else {
		thread_ctx_ptr = THREAD_CONTEXT_PTR;
		res_ptr        =  SESSION_RESULT_PTR(sesn_ptr);
	}

	InstanceHolderForFence *instance_f_ptr = (InstanceHolder *)HashLookup(&FenceRegistryIdHashTable, (void *)&fence_id, true);

	if (!IS_EMPTY(instance_f_ptr)) {
    Fence *f_ptr = FenceOffInstanceHolder(instance_f_ptr);

		if (fence_call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED) {
			if (!(fence_call_flags&FENCE_CALLFLAG_LOCK_FENCE_BLOCKING))	FenceEventsLockRWCtx(thread_ctx_ptr, f_ptr, 1, res_ptr, __func__);
			else 																												FenceEventsLockRWCtx(thread_ctx_ptr, f_ptr, 0, res_ptr, __func__);

			if (_RESULT_TYPE_EQUAL(res_ptr, RESULT_TYPE_SUCCESS)) {
				if (_RESULT_CODE_EQUAL(res_ptr, RESCODE_PROG_LOCKED_BY_THIS_THREAD)) res_code = RESCODE_PROG_LOCKED_BY_THIS_THREAD;
			} else	{_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_WONTLOCK)}
		}

		return_success:
		_RETURN_RESULT_RES(res_ptr, instance_f_ptr, RESULT_TYPE_SUCCESS, res_code)
	}

	if (IS_EMPTY(instance_f_ptr) && !(fence_call_flags&FENCE_CALLFLAG_SEARCH_BACKEND)) {_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_DOESNT_EXIST)}

	//this honours FENCE_CALLFLAG_KEEP_FENCE_LOCKED
	bool fence_lock_already_owned = false;
	GetCacheRecordForFence(sesn_ptr, UNSPECIFIED_FENCE_LISTTYPE, fence_id, SESSION_USERID(sesn_ptr), &fence_lock_already_owned, fence_call_flags);

	instance_f_ptr = SESSION_RESULT_USERDATA(sesn_ptr);

	if (IS_EMPTY(instance_f_ptr))	{_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_RESOURCE_NULL)}

	return_backend_success:
	_RETURN_RESULT_RES(res_ptr, instance_f_ptr, RESULT_TYPE_SUCCESS, fence_lock_already_owned ? RESCODE_PROG_LOCKED_BY_THIS_THREAD : RESCODE_BACKEND_DATA)

}

/**
 * 	@brief: just a decorator function.
 *
 * 	@locks: NONE
 * 	@locked: NONE
 */
Fence *
IsUserMemberOfFenceByCanonicalName (const List *const lst_ptr, const char *fence_canonical_name)

{
	return (_FindFenceInUserListByCanonicalName(lst_ptr, fence_canonical_name));

}

/**
 * 	@brief: Frontend function performs local fence search to find the Fence * to use for searching Session's list
 * 	@returns InstanceHolderForFenceStateDescriptor
 * 	@locks RD Fence *: if flagged
 */
InstanceHolderForFenceStateDescriptor *
IsUserMemberOfFenceById (const List *const lst_ptr_sesn, const unsigned long fence_id, bool lock_flag)
{
	if (unlikely(fence_id <= 0)) {
		syslog(LOG_ERR, "%s (pid:'%lu', fid:'%lu'): INVALID fence_id parameter <=0 ", __func__, pthread_self(), fence_id);
		return NULL;
	}

	if (lst_ptr_sesn->nEntries == 0) {
		return NULL;
	}

	UFSRVResult *res_ptr = FindFenceById(NULL, fence_id, CALLFLAGS_EMPTY);//local search only
  InstanceHolderForFence *instance_f_ptr = (InstanceHolderForFence *)_RESULT_USERDATA(res_ptr);

	if (IS_PRESENT(instance_f_ptr)) {
	  Fence *f_ptr_hash = FenceOffInstanceHolder(instance_f_ptr);
		InstanceHolderForFenceStateDescriptor *instance_fstate_ptr	=	IsUserMemberOfThisFence (lst_ptr_sesn, f_ptr_hash, lock_flag);
		if (IS_PRESENT(instance_fstate_ptr))		return instance_fstate_ptr;
		else																  return NULL;
	}
	else return NULL;

}

/*
 * 	@brief: Searches Session's FenceList for instance of supplied fence id
 * 	@returns InstanceHolderForFenceStateDescriptor
 *	@locks f_ptr: RD locked  unless the lock_flag is off
 *	@unlocks f_ptr: if lock_flag was on
 *	@locked Session *: underlying Session must be locked by callerto prevent changes to the list being searched
 *
 *	//TODO: IS this RD LOCK  USELESS in this context?
 */
InstanceHolderForFenceStateDescriptor *
IsUserMemberOfThisFence (const List *const lst_ptr_sesn, Fence *f_ptr, bool lock_flag)
{
	if (lst_ptr_sesn->nEntries == 0) {
		return NULL;
	}

	InstanceHolderForFenceStateDescriptor        *instance_fstate_ptr    = NULL;

	if (lock_flag) {
		FenceEventsLockRDCtx(THREAD_CONTEXT_PTR, f_ptr, _LOCK_TRY_FLAG_FALSE, THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), __func__);
		if (_RESULT_CODE_EQUAL(ufsrv_thread_context.res_ptr, RESCODE_PROG_WONTLOCK))	return NULL;

		bool lock_already_owned = (_RESULT_CODE_EQUAL(ufsrv_thread_context.res_ptr, RESCODE_PROG_LOCKED_BY_THIS_THREAD));

    instance_fstate_ptr = _FindFenceInUserListByID(lst_ptr_sesn, FENCE_ID(f_ptr));

		if (!lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));

		return instance_fstate_ptr;
	} else {
    instance_fstate_ptr = _FindFenceInUserListByID(lst_ptr_sesn, FENCE_ID(f_ptr));

		return instance_fstate_ptr;
	}

}

//
//searches in any List, but it designed to be used in searching Session's list of fences.
//looks up immutable field fence_id so there is no need to lock f_ptr
//user list is on average of small size
//Fence LOCKED at higher level
//SESSION MUST BE LOCKED
//
inline static InstanceHolderForFenceStateDescriptor *
_FindFenceInUserListByID (const List *const lst_ptr_sesn, unsigned long fid)
{
	ListEntry							*eptr										= NULL;
	FenceStateDescriptor	*fence_state_descriptor	= NULL;
	InstanceHolderForFenceStateDescriptor *instance_fstate_ptr    = NULL;

	for (eptr=lst_ptr_sesn->head; eptr; eptr=eptr->next) {
    instance_fstate_ptr = (InstanceHolder *)eptr->whatever;
		fence_state_descriptor = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
	   if (FENCESTATE_FENCE(fence_state_descriptor)->fence_id == fid) {
		   return instance_fstate_ptr;
		}
	}

	return NULL;

}

/**
 * 	@brief: Searches the Sessions' FenceList for instance of the given fence cname. It does extra integrity check by also
 * 	fetching the hashed instance of theFence and compares it with what's found in the user's list.
 *
 * 	@locks: NONE
 * 	@locked sesn_ptr: assumed locked by the caller
 */
 //TODO Phase out _FindFenceInUserListByCanonicalName?
inline static Fence *
_FindFenceInUserListByCanonicalName (const List *const lst_ptr, const char *fence_canonical_name)

{
	ListEntry				*eptr 					= NULL;
	FenceStateDescriptor	*fence_state_descriptor	= NULL;

	if (lst_ptr->nEntries == 0 || !fence_canonical_name)
	{
		syslog(LOG_ERR, "%s  (pid:'%lu'): INVALID canonical name parameter was passed or List entries = 0 ", __func__, pthread_self());

		return (Fence *)NULL;
	}

	//TODO: this needs to be protected by read lock
	Fence *f_ptr_hash = NULL;
	{
		f_ptr_hash = (Fence *)HashLookup(&FenceRegistryCanonicalNameHashTable, (void *)fence_canonical_name, true);

		for (eptr=lst_ptr->head; eptr; eptr=eptr->next)
		{
			fence_state_descriptor=(FenceStateDescriptor *)eptr->whatever;

		   if (strncasecmp(fence_canonical_name, FENCESTATE_FENCE(fence_state_descriptor)->fence_location.canonical_name, strlen(FENCESTATE_FENCE(fence_state_descriptor)->fence_location.canonical_name))==0)
			{
			   //cross check with hash
			   if (f_ptr_hash && (strncasecmp(fence_canonical_name, f_ptr_hash->fence_location.canonical_name, strlen(f_ptr_hash->fence_location.canonical_name))==0))
			   {
				   syslog(LOG_ERR, "%s (pid:'%lu'): SUCCESS: FOUND USER in bid='%lu' fcname='%s'", __func__, pthread_self(), f_ptr_hash->fence_id, f_ptr_hash->fence_location.canonical_name);

				   return f_ptr_hash;
			   }
			   else
			   {
				   syslog(LOG_ERR, "%s (pid:'%lu', cname:'%s'): SEVERE ERROR: FOUND FENCE IN USER'S SESSION'S FENCE-LIST BUT NOT IN HASH)", __func__, pthread_self(), fence_canonical_name);
				   return NULL;
			   }
			}
		}
	}


	//not found
	return NULL;

}

/**
 * 	@brief: Search Fence's userlist for the occurrence of a give session id.
 * 	@param lst_ptr_sesn: any list that hold Sessions entities
 * 	@param f_ptr: reference to actual fence entity
 * 	@returns: InstanceHolderForSession
 * 	@locked f_ptr:
 *
 */
inline InstanceHolderForSession *
FindUserInFenceSessionListByID (const List *const lst_ptr_sesn, Fence *f_ptr, unsigned long cid)
{
	ListEntry							*eptr										= NULL;
	InstanceHolderForSession *instance_sesn_ptr;
	Session 							*sesn_ptr_in_list;

	for (eptr=lst_ptr_sesn->head; eptr; eptr=eptr->next) {
    instance_sesn_ptr = (InstanceHolderForSession *)eptr->whatever;
    sesn_ptr_in_list = SessionOffInstanceHolder(instance_sesn_ptr);
		if (SESSION_ID(sesn_ptr_in_list) == cid)	return instance_sesn_ptr;
	}

#ifdef __UF_TESTING
		   syslog(LOG_DEBUG, "%s (pid:'%lu', of:'%p', fid:'%lu', cid:'%lu'): COULD NOT FIND Session in Fence List", __func__, pthread_self(), f_ptr, FENCE_ID(f_ptr), cid);
#endif

	return NULL;

}

/**
 *
 *	@locked RD|RW f_ptr:
 */
bool
IsUserOnFenceInvitedList (Fence *f_ptr, unsigned long uid)
{
  ListEntry *eptr;
  Session *sesn_ptr;

  for (eptr=f_ptr->fence_user_sessions_invited_list.head; eptr; eptr=eptr->next) {
    sesn_ptr = SessionOffInstanceHolder((InstanceHolderForSession *) eptr->whatever);

    if (SESSION_USERID(sesn_ptr) == uid) {
#ifdef __UF_TESTING
      syslog(LOG_DEBUG, "%s {pid:'%lu', uid:'%lu', cname:'%s', invitation_list_sz:'%d'}: User already on Fence's invitation list", __func__, pthread_self(), uid, FENCE_CNAME(f_ptr), f_ptr->fence_user_sessions_invited_list.nEntries);
#endif
      return true;
    }
  }

return false;

}
// -------------------------- END OF FIND ROUTINES ------------------


//------------------ MESSAGE QUEUE ROUTINES --------------------------

/**
 * 	If called from within session worker thread sesn_ptr_this==sesn_ptr_target and should use backend context from session
 * 	if called from within ufsrv worker thread sesn_ptr_this==NULL and should user backend context from ufsrv worker
 *	As this can be called from session of ufsrv worker, sesn_ptr must have access context loaded
 *	@param fe_ptr_out: must be allocated by caller
 *
 * 	@locked: both session and fence events must be locked
 * 	TODO: OPTIMISE: remove conditionals and add add event type callbacks
 */
FenceEvent *
UpdateBackendFenceData (Session *sesn_ptr_target, Fence *f_ptr, void *user_dat, unsigned event_type, FenceEvent *fe_ptr_out)
{
	FenceEvent 					*fe_ptr							=	NULL;
	PersistanceBackend 	*pers_ptr						= sesn_ptr_target->persistance_backend;
	FenceCacheBackend		*fence_backend_ptr	=	sesn_ptr_target->fence_cachebackend;
	redisReply 					*redis_ptr					= NULL;

	if (event_type == EVENT_TYPE_FENCE_CREATED) {
		if (IS_EMPTY((fe_ptr = RegisterFenceEvent(sesn_ptr_target, f_ptr, event_type,  NULL, 0/*LOCK_FLAG*/, fe_ptr_out)))) {
			return NULL;
		}

		CacheBackendAddFenceRecord (sesn_ptr_target, f_ptr, FENCE_CALLFLAG_EMPTY);

    DbBackendInsertUfsrvEvent ((UfsrvEvent *)fe_ptr);

    //Add detailed event entry
    //TODO: this should be more loged to db backend. No value in keepoing this memory resident
//    redis_ptr = (*pers_ptr->send_command)(sesn_ptr_target, REDIS_CMD_FENCE_EVENTS,
//                                                        FENCE_ID(f_ptr), 1UL,
//                                                        1UL, masterptr->serverid,
//                                                        SESSION_ID(sesn_ptr_target), time(NULL),
//                                                        SESSION_ID(sesn_ptr_target), FENCE_ID(f_ptr),
//                                                        event_type, "event");
//
//    if (redis_ptr)	freeReplyObject(redis_ptr);

    //avoid race condition between fence creation and user joining, as both are broadcast at nearly the same time, causing INETER processing race conditions
		if (false) InterBroadcastFenceMake (sesn_ptr_target, (ClientContextData *)f_ptr, fe_ptr, 0/*enum _CommandArgs*/);

		return fe_ptr;

	} else if (event_type == EVENT_TYPE_FENCE_DESTROYED) {
	  //todo implement EVENT_TYPE_FENCE_DESTROYED
	} else if (event_type == EVENT_TYPE_FENCE_USER_JOINED) {
		fe_ptr = RegisterFenceEvent (sesn_ptr_target, f_ptr, event_type,  NULL, 0/*LOCK_FLAG*/, fe_ptr_out);

		if (unlikely(IS_EMPTY(fe_ptr)))		return NULL;

		FenceStateDescriptor *fence_state_ptr_invite	=	(FenceStateDescriptor *)user_dat;
		//fence_state_ptr_invite=IsUserMemberOfThisFence(SESSION_INVITED_FENCE_LIST_PTR(sesn_ptr_target), f_ptr, false/*FLAG_FENCE_LOCK_FALSE*/);

		//ZADD  FUSERS:<bid>  timestamp> <uid>
		redis_ptr  = (*pers_ptr->send_command)(sesn_ptr_target, REDIS_CMD_FENCE_USER_RECORD, FENCE_ID(f_ptr), time(NULL), SESSION_USERID(sesn_ptr_target));
		if (redis_ptr)	freeReplyObject(redis_ptr);

		unsigned long uid_invited_by = IS_PRESENT(fence_state_ptr_invite)?UfsrvUidGetSequenceId(&(fence_state_ptr_invite->invited_by))
																																	 :(F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_BASEFENCE)?1:0);
		redis_ptr = (*pers_ptr->send_command)(sesn_ptr_target, REDIS_CMD_USER_FENCE_LIST_ADD, SESSION_USERID(sesn_ptr_target), time(NULL), FENCE_ID(f_ptr), uid_invited_by);
		if (redis_ptr)	freeReplyObject(redis_ptr);

		//TODO: store in db backend
		//HMSET FEV:%lu:%lu sid %lu cid %lu when %lu oid %lu tid %lu evt %d ev %s
//		redis_ptr = (*pers_ptr->send_command)(sesn_ptr_target, REDIS_CMD_FENCE_EVENTS,
//																												FENCE_ID(f_ptr),
//																												fe_ptr->eid,
//																												fe_ptr->eid,
//																												masterptr->serverid,
//																												SESSION_ID(sesn_ptr_target),
//																												time(NULL),
//																												SESSION_ID(sesn_ptr_target),
//																												FENCE_ID(f_ptr),
//																												event_type,
//																												"event");
//
//		if (redis_ptr)	freeReplyObject(redis_ptr);

    DbBackendInsertUfsrvEvent ((UfsrvEvent *)fe_ptr);

		InterBroadcastFenceJoin (sesn_ptr_target, (ClientContextData *)f_ptr, fe_ptr, 0/*enum _CommandArgs*/);

		return fe_ptr;

	} else if (event_type == EVENT_TYPE_FENCE_USER_PARTED) {
		FenceStateDescriptor *fence_state_for_invited_by_only	=	(FenceStateDescriptor *)user_dat;
		redisReply *redis_ptr;
    redis_ptr = (*pers_ptr->send_command)(sesn_ptr_target, REDIS_CMD_FENCE_USERS_LIST_REM, FENCE_ID(f_ptr), SESSION_USERID(sesn_ptr_target));

    if (redis_ptr)	freeReplyObject(redis_ptr);

    //REDIS_CMD_USER_FENCE_REM
    redis_ptr=(*pers_ptr->send_command)(sesn_ptr_target, REDIS_CMD_USER_FENCE_LIST_REM, SESSION_USERID(sesn_ptr_target), FENCE_ID(f_ptr), UfsrvUidGetSequenceId(&(fence_state_for_invited_by_only->invited_by)));

    if (redis_ptr)	freeReplyObject(redis_ptr);

		//this generates event data
		fe_ptr = BackendUpdateFenceEvent (sesn_ptr_target, &((FenceIdentifier){0, f_ptr}), fe_ptr_out, event_type);
		InterBroadcastFenceLeave (sesn_ptr_target, (ClientContextData *)f_ptr, fe_ptr, 0/*enum _CommandArgs*/);

		return fe_ptr;
	} else if (event_type == EVENT_TYPE_FENCE_MEMBERSHIP_REPAIRED) {
		if (IS_EMPTY((fe_ptr = RegisterFenceEvent(sesn_ptr_target, f_ptr, event_type,  NULL, 0/*LOCK_FLAG*/, fe_ptr_out)))) {
			return NULL;
		}

		redis_ptr = (*pers_ptr->send_command)(sesn_ptr_target, REDIS_CMD_FENCE_USERS_LIST_REM, FENCE_ID(f_ptr), (unsigned long)user_dat);

		if (IS_PRESENT(redis_ptr)) {
			freeReplyObject(redis_ptr);
      DbBackendInsertUfsrvEvent ((UfsrvEvent *)fe_ptr);
			InterBroadcastFenceReload (sesn_ptr_target, (ClientContextData *)f_ptr, fe_ptr, COMMAND_ARGS__RESYNC);

			return fe_ptr;
		} else return NULL;
	} else {
		syslog(LOG_DEBUG, "%s {pid:'%lu', cid:'%lu', fid:'%lu', event_type:'%d'}: WARNING: Unknown event type",	__func__, pthread_self(), SESSION_ID(sesn_ptr_target), FENCE_ID(f_ptr), event_type);
		return NULL;
	}

	return fe_ptr;

}

/**
 * 	@brief: for each invited user we generate a corresponding unique network wide event.
 * 	Not all event types require generation of event id
 */
FenceEvent *
UpdateBackendFenceInvitedData (Session *sesn_ptr_inviter, Session *sesn_ptr_invited, FenceStateDescriptor *fstate_ptr, unsigned event_type, FenceEvent *fe_ptr_out)
{
	Session			*sesn_ptr;
	Fence				*f_ptr		= FenceOffInstanceHolder(fstate_ptr->instance_holder_fence);
	FenceEvent	*fe_ptr		= NULL;

	time_t							time_now;
	PersistanceBackend 	*pers_ptr;
	MessageQueueBackend *mq_ptr __unused;

	//user is being sent a join invitation
	if (event_type == EVENT_TYPE_FENCE_USER_INVITED) {
		sesn_ptr											= sesn_ptr_inviter;
		pers_ptr											= sesn_ptr->persistance_backend;
		mq_ptr												= sesn_ptr->msgqueue_backend;

		if (IS_PRESENT(fe_ptr_out))	fe_ptr = fe_ptr_out;
		else												fe_ptr = calloc (1, sizeof(FenceEvent));

		fe_ptr = RegisterFenceEvent(sesn_ptr, f_ptr, event_type,  NULL, 0/*LOCK_FLAG*/, fe_ptr);

		if (unlikely(IS_EMPTY(fe_ptr))) {
			if (IS_EMPTY(fe_ptr_out))	free(fe_ptr);
			return NULL;
		}

		time_now = fe_ptr->when;

#ifdef __UF_TESTING
			syslog(LOG_DEBUG, "%s {pid:'%lu', cid:'%lu', target_fid:'%lu', eid:'%lu'}: FenceInvited Event ID: Generated", __func__, pthread_self(), fe_ptr->session_id, fe_ptr->target_id, fe_ptr->eid);
#endif

		(*pers_ptr->send_command_multi)(sesn_ptr, "MULTI");

		(*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_INVITED_FENCES_FOR_USER_ADD, SESSION_USERID(sesn_ptr_invited), time_now, FENCE_ID(f_ptr), SESSION_USERID(sesn_ptr_inviter));

		(*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_INVITED_USERS_FOR_FERNCE_ADD, FENCE_ID(f_ptr), time_now,  SESSION_USERID(sesn_ptr_invited), SESSION_USERNAME(sesn_ptr_invited), SESSION_USERID(sesn_ptr_inviter));

		(*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_MY_FENCE_INVITED_USERS_ADD, SESSION_USERID(sesn_ptr_inviter), time_now, FENCE_ID(f_ptr), SESSION_USERID(sesn_ptr_invited));

//		(*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_FENCE_EVENTS, FENCE_ID(f_ptr), fe_ptr->eid, fe_ptr->eid, masterptr->serverid, SESSION_USERID(sesn_ptr_invited), time_now, SESSION_USERID(sesn_ptr_inviter), FENCE_ID(f_ptr), event_type, "event");

		(*pers_ptr->send_command_multi)(sesn_ptr, "EXEC");

		size_t 		i,
					    actually_processed = 5;
		redisReply	*replies[actually_processed];

		//TODO: we need error recover for intermediate errors
		for (i=0; i<actually_processed; i++) {
			if ((RedisGetReply(sesn_ptr, pers_ptr, (void*)&replies[i]) != REDIS_OK)) {
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', cmd_idx:'%lu', uid_invalid:'%lu'}: ERROR: REDIS COMMAND IN MULTI SET FAILED", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i, SESSION_USERID(sesn_ptr));

				if ((replies[i] != NULL) && (replies[i]->type != REDIS_REPLY_NIL)) {
					//syslog (LOG_DEBUG, LOGSTR_BACKENDCACHE_SHARED_CONTACTS, __func__, pthread_self(), sesn_ptr, i, replies[i]->str, LOGCODE_BACKENDCACHE_SHARED_CONTACTS_HIT, "Found shared contact token");
				}
			}

			if (!IS_EMPTY(replies[i]))	freeReplyObject(replies[i]);
		}//for

    DbBackendInsertUfsrvEvent((UfsrvEvent *)fe_ptr);

		fence_join_event_broadcast:
    InterBroadcastFenceInvite(sesn_ptr,
                              (ClientContextData *)(&((ContextDataFenceInvite){sesn_ptr_inviter, sesn_ptr_invited, fstate_ptr})),
                              fe_ptr,
                              COMMAND_ARGS__INVITED);

		return fe_ptr;
	}
	else//user being removed from the invite list
	if (event_type == EVENT_TYPE_FENCE_USER_UNINVITED || event_type == EVENT_TYPE_FENCE_USER_INVITEREJECTED  || EVENT_TYPE_FENCE_USER_LIST_CORRECTED) {
		sesn_ptr											= sesn_ptr_invited;//note using -> invited
		pers_ptr											= sesn_ptr->persistance_backend;
		mq_ptr												= sesn_ptr->msgqueue_backend;

		if (IS_PRESENT(fe_ptr_out))	fe_ptr = fe_ptr_out;
		else												fe_ptr = calloc(1, sizeof(FenceEvent));

		fe_ptr = RegisterFenceEvent(sesn_ptr, f_ptr, event_type,  NULL, 0/*LOCK_FLAG*/, fe_ptr);

		if (unlikely(IS_EMPTY(fe_ptr))) {
			if (IS_EMPTY(fe_ptr_out))	free(fe_ptr);
			return NULL;
		}

		time_now = fe_ptr->when;

    unsigned long userid_invited_by = UfsrvUidGetSequenceId(&(fstate_ptr->invited_by));

    //IMPORTANT sesn_ptr_inviter IS NULL in this context. fstate_ptr->invited_by conains its uid
		(*pers_ptr->send_command_multi)(sesn_ptr, "MULTI");

		//remove fence from user's list of invited for which it was invited
		(*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_INVITED_FENCES_FOR_USER_REM, SESSION_USERID(sesn_ptr_invited), FENCE_ID(f_ptr), userid_invited_by);

		//remove user from fences list of invited users
		(*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_INVITED_USERS_FOR_FERNCE_REM, FENCE_ID(f_ptr), SESSION_USERID(sesn_ptr_invited), SESSION_USERNAME(sesn_ptr_invited), userid_invited_by);

		//remove user from original inviter's list of ser it previously invited
		(*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_MY_FENCE_INVITED_USERS_REM, userid_invited_by, FENCE_ID(f_ptr), SESSION_USERID(sesn_ptr_invited));

		(*pers_ptr->send_command_multi)(sesn_ptr, "EXEC");

		size_t 			i,
										actually_processed = 5;
		redisReply	*replies[actually_processed];

		//TODO: we need error recover for intermediate errors
		for (i=0; i<actually_processed; i++) {
			if ((RedisGetReply(sesn_ptr, pers_ptr, (void*)&replies[i]) != REDIS_OK)) {
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', cmd_idx:'%lu', uid_invalid:'%lu'}: ERROR: REDIS COMMAND IN MULTI SET FAILED", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i, SESSION_USERID(sesn_ptr));

				if ((replies[i] != NULL) && (replies[i]->type != REDIS_REPLY_NIL)) {
					//syslog (LOG_DEBUG, LOGSTR_BACKENDCACHE_SHARED_CONTACTS, __func__, pthread_self(), sesn_ptr, i, replies[i]->str, LOGCODE_BACKENDCACHE_SHARED_CONTACTS_HIT, "Found shared contact token");
				}
			}

			if (!IS_EMPTY(replies[i]))	freeReplyObject(replies[i]);
		}//for

    DbBackendInsertUfsrvEvent ((UfsrvEvent *)fe_ptr);

		fence_uninvite_event_broadcast:
    InterBroadcastFenceInvite(sesn_ptr,
                              (ClientContextData *)(&((ContextDataFenceInvite){sesn_ptr_inviter, sesn_ptr_invited, fstate_ptr})),
                              fe_ptr,
                              event_type==EVENT_TYPE_FENCE_USER_UNINVITED?COMMAND_ARGS__UNINVITED:COMMAND_ARGS__REJECTED);

	}
	else//user accepted and joined based on prior invitation. We dont generate eid for this, as actual user join will have covered it
	if (event_type == EVENT_TYPE_FENCE_USER_INVITED_JOINED) {
		sesn_ptr											= sesn_ptr_invited;//note invited
		pers_ptr											= sesn_ptr->persistance_backend;
		mq_ptr												= sesn_ptr->msgqueue_backend;

		unsigned long userid_invited_by = UfsrvUidGetSequenceId(&(fstate_ptr->invited_by));

		//IMPORTANT sesn_ptr_inviter IS NULL in this context. fstate_ptr->invited_by conains its uid
		(*pers_ptr->send_command_multi)(sesn_ptr, "MULTI");

		//remove fence from user's list of invited for which it was invited
		(*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_INVITED_FENCES_FOR_USER_REM, SESSION_USERID(sesn_ptr_invited), FENCE_ID(f_ptr), userid_invited_by);

		//remove user from fences list of invited users
		(*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_INVITED_USERS_FOR_FERNCE_REM, FENCE_ID(f_ptr), SESSION_USERID(sesn_ptr_invited), SESSION_USERNAME(sesn_ptr_invited), userid_invited_by);

		//TODO: cannot execute this now as we dont have access to the inviter: enablewhen ready -> INCREASE ACTUALLY_PROCESSED TO 5
		//remove user from original inviter's list of ser it previously invited
		(*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_MY_FENCE_INVITED_USERS_REM, userid_invited_by, FENCE_ID(f_ptr), SESSION_USERID(sesn_ptr_invited));

		(*pers_ptr->send_command_multi)(sesn_ptr, "EXEC");

		size_t 			i,
								actually_processed=5;
		redisReply	*replies[actually_processed];

		//TODO: we need error recover for intermediate errors
		for (i=0; i<actually_processed; i++) {
			if ((RedisGetReply(sesn_ptr, pers_ptr, (void*)&replies[i]) != REDIS_OK)) {
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', cmd_idx:'%lu', uid_invalid:'%lu'}: ERROR: REDIS COMMAND IN MULTI SET FAILED", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i, SESSION_USERID(sesn_ptr));

				if ((replies[i] != NULL) && (replies[i]->type != REDIS_REPLY_NIL)) {
					//syslog (LOG_DEBUG, LOGSTR_BACKENDCACHE_SHARED_CONTACTS, __func__, pthread_self(), sesn_ptr, i, replies[i]->str, LOGCODE_BACKENDCACHE_SHARED_CONTACTS_HIT, "Found shared contact token");
				}
			}

			if (!IS_EMPTY(replies[i]))	freeReplyObject(replies[i]);
		}//for

		return NULL;//we dont perform broadcast for that, as the actual join event will cover that off
	} else {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o_inviter:'%p', o_invited:'%p', type:'%d'} Unsupported type received", __func__, pthread_self(), sesn_ptr_inviter?:NULL,sesn_ptr_invited?:NULL, event_type);
	}

	return NULL;

}

//-------------------------- END OF MESSAGE QUEUE ROUTINES ------


//-------------- START backend fence instantiation FOR USER ---//
#if 1
static UFSRVResult *_GetFencesListCacheRecordForUser (Session *sesn_ptr_this, unsigned long call_flags, UFSRVResult *res_ptr_in);
static UFSRVResult * _GetFencesListCacheRecordForUserId (unsigned long uid, unsigned long call_flags, UFSRVResult *res_ptr_in);
static UFSRVResult *_InstateFencesListCacheRecordForUser (InstanceHolderForSession *instance_sesn_ptr_this, redisReply *redis_ptr_list, EnumFenceCollectionType, unsigned long sesn_call_flags, unsigned long fence_call_flags, UFSRVResult *res_ptr);
static inline FenceStateDescriptor *_InstateFenceIntoSessionFromCacheRecord (InstanceHolderForSession *instance_sesn_ptr, EnumFenceCollectionType list_type, unsigned long score, unsigned long fence_id, const char *uid_by, unsigned long fence_call_flags);
static inline FenceStateDescriptor *_InstateFenceForSnapshotSession (InstanceHolderForSession *instance_sesn_ptr, EnumFenceCollectionType list_type, unsigned long fence_id, const char *uid_by);
static UFSRVResult *_GetInvitedFencesListCacheRecordForUser (Session *sesn_ptr, unsigned long call_flags, UFSRVResult *res_ptr_in);
static UFSRVResult *_GetInvitedFencesListCacheRecordForUserWithScores (Session *sesn_ptr,  unsigned long call_flags, UFSRVResult *res_ptr_in);


/**
 * 	@brief Wrapper function for building a sessions's fence list
 * 	@param sesn_ptr: Must have full backend access context
 */
Session *
InstateMembersFenceListForUser (InstanceHolderForSession *instance_sesn_ptr, unsigned long sesn_call_flags, unsigned long fence_call_flags)
{
	UFSRVResult res;
	Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	_GetFencesListCacheRecordForUser(sesn_ptr, SESSION_CALLFLAGS_EMPTY, &res);
	if (res.result_type == RESULT_TYPE_SUCCESS && res.result_code == RESCODE_BACKEND_DATA) {
		redisReply *redis_ptr = ((redisReply *)(res.result_user_data));

		_InstateFencesListCacheRecordForUser(instance_sesn_ptr, redis_ptr, MEMBER_FENCES, sesn_call_flags, fence_call_flags, &res);
		if (res.result_type == RESULT_TYPE_SUCCESS) {
			freeReplyObject(redis_ptr);

			return sesn_ptr;
		}

		freeReplyObject(redis_ptr);
	} else {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o_target:'%p', cid_target:'%lu'}: ERROR: COULD NOT INSTANTIATE FENCE LIST FOR SESSION", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

		return NULL;
	}

	return NULL;

}

/**
 * 	@brief:
 * 	Wrapper function for building a sessions's invited-for fence list
 * 	@param fence_call_flags FENCE_CALLFLAG_FENCE_LIST_WITH_SCORES: retrieve additional context information
 * 	@param sesn_ptr: Must have full backend access context
 */
Session *
InstateInvitedFenceListForUser (InstanceHolderForSession *instance_sesn_ptr, unsigned long sesn_call_flags, unsigned long fence_call_flags)
{
	UFSRVResult res;
	Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	//<fid:cname>
	if (fence_call_flags&FENCE_CALLFLAG_FENCE_LIST_WITH_SCORES)
	_GetInvitedFencesListCacheRecordForUserWithScores(sesn_ptr, CALLFLAGS_EMPTY, &res);
	else
		_GetInvitedFencesListCacheRecordForUser(sesn_ptr, 0/*call_flags*/, &res);

	if (res.result_type == RESULT_TYPE_SUCCESS) {
		redisReply *redis_ptr = ((redisReply *)(res.result_user_data));

		_InstateFencesListCacheRecordForUser (instance_sesn_ptr, redis_ptr, INVITED_FENCES, sesn_call_flags, fence_call_flags, &res);
		if (res.result_type == RESULT_TYPE_SUCCESS) {
			freeReplyObject(redis_ptr);

			return sesn_ptr;
		}

		freeReplyObject(redis_ptr);
	} else {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o_target:'%p', cid_target:'%lu'}: ERROR: COULD NOT INSTANTIATE FENCE LIST FOR SESSION", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

		return NULL;
	}

	return NULL;

}

void
DestructFenceCollection (CollectionDescriptor *fence_collection_ptr, bool flag_self_destruct)
{
	if(!(IS_EMPTY(fence_collection_ptr)))
	{
		if (!(IS_EMPTY(fence_collection_ptr->collection))) free (fence_collection_ptr->collection);

		if (flag_self_destruct)
		{
			free (fence_collection_ptr);
			fence_collection_ptr=NULL;
		}

	}
}

/**
 * @brief: Primary point for fully loading user fences to session. Typically, invoked when SESNSTATUS_FENCELIST_LAZY
 * flag is set on Session.
 *	@param sesn_ptr: As this session may not always be a connected one, FULL ACCESS CONTEXT must be loaded for it by teh caller
 * 	@param list_types_encoded: uses EnumFenceCollectionType
 */
int
InstateFenceListsForUser (InstanceHolderForSession *instance_sesn_ptr, unsigned long sesn_call_flags, FenceTypes fence_type, bool flag_abort_on_failure)
{
	unsigned int failed_lists = 0;

		//we want full fence list for this session + for each session full list of session
	if (fence_type&MEMBER_FENCE) {
		if (!(InstateMembersFenceListForUser(instance_sesn_ptr, sesn_call_flags, FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE|FENCE_CALLFLAG_ABORT_RECORD_IF_USER_NOT_MEMBER))) {
			failed_lists |= (MEMBER_FENCE);
			if (flag_abort_on_failure)	return failed_lists;
		}
	}

	if (fence_type&INVITED_FENCE) {
		if (!(InstateInvitedFenceListForUser(instance_sesn_ptr, sesn_call_flags, FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE|FENCE_CALLFLAG_FENCE_LIST_WITH_SCORES|FENCE_CALLFLAG_ABORT_RECORD_IF_USER_NOT_MEMBER))) {
			failed_lists |= (INVITED_FENCE);
			if (flag_abort_on_failure)	return failed_lists;
		}
	}

	_CrossCheckInvitedListsForUser(instance_sesn_ptr);

	return failed_lists;
}

/**
 * 	@brief: Queries the backend cache and retrieves the desired fence category as a Collection of fence ids.
 *
 * 	@sesn_ptr:	target user session. Must have full access context. Could be ephemeral, connected, or carriered
 *
 * 	@dynamic_memory redisReply *: IMPORTS when _GetFenceListFromBackendRaw() returns success, even if list is empty.
 * 	must be deallocated here.
 *
 * 	@dynamic_memory CollectionDescriptor *: EXPORTS if the value of 'fence_collection_ptr_in *' is NULL,
 * 	in which case the caller must deallocate
 *
 * 	@dynamic_memory CollectionDescriptor:collection_t: EXPORTS the actual collection
 *
 * 	@returns CollectionDescriptor *: which could user allocated/provided.
 * 	@return NULL: on empty set.
 */
CollectionDescriptor *
GetFenceCollectionForUser (Session *sesn_ptr, CollectionDescriptor *fence_collection_ptr_in, CollectionDescriptor *overflow_collection_ptr_in, EnumFenceCollectionType collection_type)
{
	UFSRVResult						res;
	CollectionDescriptor	*fence_collection_ptr			=	NULL;
	CollectionDescriptor	*overflow_collection_ptr	=	NULL;

	switch (collection_type)
	{
	case MEMBER_FENCES:
		_GetFencesListCacheRecordForUser (sesn_ptr, 0/*call_flags*/, &res);
		break;

	case INVITED_FENCES:
		_GetInvitedFencesListCacheRecordForUser (sesn_ptr, 0/*call_flags*/, &res);
		break;

	case BLOCKED_FENCES:
	case LIKED_FENCES:
	case FAVED_FENCES:
	default:
		return NULL;

	}

	if ((res.result_type == RESULT_TYPE_SUCCESS) && !(IS_EMPTY(res.result_user_data))) {
		if (res.result_code == RESCODE_BACKEND_DATA_EMPTYSET) {
			return NULL;//fence_collection_ptr;
		}

		if 		(!IS_EMPTY(fence_collection_ptr_in))	fence_collection_ptr = fence_collection_ptr_in;
		else																				fence_collection_ptr = calloc(1, sizeof(CollectionDescriptor));

		size_t			i = 0,
								processed = 0;
		char				*bid_str,
								*uid_inviter;
		redisReply	*redis_ptr_list	=	((redisReply *)(res.result_user_data));

		fence_collection_ptr->collection=calloc(redis_ptr_list->elements, sizeof(unsigned long));
		unsigned long *fence_ids		=	(unsigned long *)fence_collection_ptr->collection;
		unsigned long *by_ids				=	NULL;

		//this holds the reminder of raw data fter it is stripped of fenceid. Mostly *_by type information reflecting userid
		//TODO: impelemnt this as context with callback
		if (IS_PRESENT(overflow_collection_ptr_in))	{
			overflow_collection_ptr	=	overflow_collection_ptr_in;
			overflow_collection_ptr	=	calloc(redis_ptr_list->elements, sizeof(unsigned long));
			by_ids									=	(unsigned long *)overflow_collection_ptr->collection;
		}

		for (; i < redis_ptr_list->elements; ++i) {
			//"1804689344:1234"
			if (IS_STR_LOADED(uid_inviter=strrchr(redis_ptr_list->element[i]->str, ':'))) {
				*uid_inviter='\0';	uid_inviter++;
				fence_ids[processed]=strtoul(redis_ptr_list->element[i]->str, NULL, 10);
				if (IS_PRESENT(by_ids))	by_ids[processed]=strtoul(uid_inviter, NULL, 10);
				processed++;
			} else {
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p',  cid:'%lu'): ERROR: COULD NOT EXTRACT BID UID value from redis set '%s': ignoring...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), redis_ptr_list->element[i]->str);
				continue;
			}

#if 0
			//"1804689344:Australia:New South Wales:Auburn:1234"
			bid_str=redis_ptr_list->element[i]->str;
			uid_inviter=strrchr (bid_str, ':'); *uid_inviter='\0'; uid_inviter++;
			fence_cname=strchr(bid_str, ':');
			if (fence_cname)
			{
				*fence_cname='\0';
				fence_cname++;
				fence_ids[processed++]=strtoul(bid_str, NULL, 10);

#ifdef __UF_TESTING
				syslog(LOG_DEBUG, "%s (pid='%lu', cid='%lu'): BACKEND RESULTSET CONTAINs FENCE: bid='%lu' CNAME: '%s' ", __func__, pthread_self(), SESSION_ID(sesn_ptr), fence_ids[processed-1], fence_cname);
#endif
			}
			else
			{
				syslog(LOG_DEBUG, "%s (pid='%lu' cid='%lu'): ERROR: COULD NOT EXTRACT BID UID value from redis set '%s': ignoring...", __func__, pthread_self(), SESSION_ID(sesn_ptr), redis_ptr_list->element[i]->str);
				continue;
			}
#endif
		}//for

		fence_collection_ptr->collection_sz = processed;
		if (IS_PRESENT(by_ids))	overflow_collection_ptr->collection_sz = processed;

		freeReplyObject(redis_ptr_list);

		return fence_collection_ptr;
	} else {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: COULD NOT RETRIEVE RAW FENCE LIST...", __func__, pthread_self(), sesn_ptr);
	}

	return NULL;
}

/**
 *	@brief: Scan the returned raw fenceids in users raw Session CacheRecord  for the matching fid
 *	@para uid_inviter: returnthe inviter value if present
 *	@locks: none
 *	@locked sesn_ptr_carrier: could be locked if belongs to a real user
 *	@unlocks: none
 */
bool
IsFenceIdInCacheRecordForUser (unsigned long uid, unsigned long fid, unsigned long *uid_inviter)
{
	bool				return_value = false;
	redisReply *redis_ptr		=	NULL;

	_GetFencesListCacheRecordForUserId(uid, FENCE_CALLFLAG_EMPTY, NULL);

	if (THREAD_CONTEXT_UFSRV_RESULT_TYPE_SUCCESS) {
		redis_ptr = (redisReply *)THREAD_CONTEXT_UFSRV_RESULT_USERDATA;

		if (THREAD_CONTEXT_UFSRV_RESULT_CODE_EQUAL(THREAD_CONTEXT, RESCODE_BACKEND_DATA)) {
			size_t i = 0;
			unsigned long fid_processed;
			char *uid_inviter_processed;

			for (; i < redis_ptr->elements; ++i) {
				//"1804689344:1234"
				if (IS_STR_LOADED(uid_inviter_processed=strrchr(redis_ptr->element[i]->str, ':'))) {
					*uid_inviter_processed = '\0';	uid_inviter_processed++;
					fid_processed = strtoul(redis_ptr->element[i]->str, NULL, 10);
					if (fid == fid_processed) {
						return_value = true;
						if (IS_PRESENT(uid_inviter))	*uid_inviter = strtoul(uid_inviter_processed, NULL, 10);
						goto return_success;
					}
				} else {
					syslog(LOG_DEBUG, "%s (pid:'%lu', th_ctx:'%p', uid:'%lu', bid:'%lu'): ERROR: COULD NOT EXTRACT BID UID value from redis set(%s): ignoring...", __func__, pthread_self(), THREAD_CONTEXT_PTR, uid, fid, redis_ptr->element[i]->str);
				}
			}
	  }

		goto return_success;
	 }

	return false;

	return_success:
	if (IS_PRESENT(redis_ptr))  freeReplyObject(redis_ptr);
	return return_value;

}

/**
 * 	@brief:
 * 	Retrieve the user's list of fences from the backend in raw redis format.
 *
 * 	@param sesn_ptr_this:
 * 	current session being serviced or NULL if called from within ufrsv worker
 *
 * 	@param sesn_ptr_target:
 * 	session for which list is built, could be teh same as sesn_ptr_this
 *
 * 	@returns:
 * 	UFSRVResult * with res_ptr->userdata set to the resulting redisReply.
 *
 * 	@dynamic_memory:
 * 	user must free returned redisReply object
 *
 *	@locks: none as no local objects are manipulated
 *
 *	@call_flags: NONE
 */
static UFSRVResult *
_GetFencesListCacheRecordForUser (Session *sesn_ptr,  unsigned long call_flags, UFSRVResult *res_ptr_in)
{
	return _GetFencesListCacheRecordForUserId(SESSION_USERID(sesn_ptr), call_flags, res_ptr_in);

}

static UFSRVResult *
_GetFencesListCacheRecordForUserId (unsigned long uid, unsigned long call_flags, UFSRVResult *res_ptr_in)
{
	PersistanceBackend	*pers_ptr = THREAD_CONTEXT_PERSISTANCE_CACHEBACKEND(THREAD_CONTEXT);
	redisReply					*redis_ptr;
	UFSRVResult					*res_ptr;

	if (!res_ptr_in)	res_ptr = THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT);
	else							res_ptr = res_ptr_in;

	if (!(redis_ptr = (*pers_ptr->send_command)(NO_SESSION, REDIS_CMD_USER_FENCE_LIST_GET_ALL, uid))) {
		syslog(LOG_DEBUG, "%s: ERROR COULD NOT GET REDIS RESPONSE for CID '%lu'", __func__, uid);
		_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_BACKENDERR, RESCODE_BACKEND_CONNECTION)
	}

	if (redis_ptr->type == REDIS_REPLY_ERROR) {
	   syslog(LOG_DEBUG, "%s: REDIS_REPLY_ERROR COULD NOT GET REDIS RESPONSE for CID '%lu'", __func__, uid);

	   freeReplyObject(redis_ptr);

	   _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)
	}

	if (redis_ptr->type == REDIS_REPLY_NIL || redis_ptr->elements == 0) {
#ifdef __UF_TESTING
	   syslog(LOG_DEBUG, "%s {pid:'%lu', th_ctx:'%p', uid:'%lu'}: COULD NOT RETRIEVE RECORD: EMPTY SET",  __func__, pthread_self(), THREAD_CONTEXT_PTR, uid);
#endif

    freeReplyObject(redis_ptr);

	   _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA_EMPTYSET)
	}

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s (pid:'%lu'): UID '%lu': FOUND '%lu' fences", __func__, pthread_self(), uid, redis_ptr->elements);
#endif

	_RETURN_RESULT_RES(res_ptr, redis_ptr,  RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)

}

/**
 * 	@brief:
 * 	Retrieve the user's list of fences from the backend in raw redis format.
 *
 * 	@param sesn_ptr_this:
 * 	current session being serviced or NULL if called from within ufrsv worker
 *
 * 	@param sesn_ptr_target:
 * 	session for which list is built, could be teh same as sesn_ptr_this
 *
 * 	@returns:
 * 	UFSRVResult * with res_ptr->userdata set to the resulting redisReply.
 *
 * 	@dynamic_memory redisReply *: EXPORTS
 * 	user must free returned redisReply object
 *
 *	@locks: none as no local objects are manipulated
 *
 *	@call_flags: NONE
 */
static UFSRVResult *
_GetInvitedFencesListCacheRecordForUser (Session *sesn_ptr,  unsigned long call_flags, UFSRVResult *res_ptr_in)

{
	if (unlikely(IS_EMPTY(sesn_ptr)))
	{
		if (IS_PRESENT(res_ptr_in))	_RETURN_RESULT_RES(res_ptr_in, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)
		else						return _ufsrv_result_generic_error;
	}

	UFSRVResult 		*res_ptr;
	PersistanceBackend 	*pers_ptr=sesn_ptr->persistance_backend;
	redisReply 			*redis_ptr;

	if (!res_ptr_in)	res_ptr=&(sesn_ptr->sservice.result);
	else				res_ptr=res_ptr_in;

	if (!(redis_ptr=(*pers_ptr->send_command)(sesn_ptr, REDIS_CMD_INVITED_FENCES_FOR_USER_GET_ALL, SESSION_USERID(sesn_ptr))))
	{
		syslog(LOG_DEBUG, "%s: ERROR COULD NOT GET REDIS RESPONSE for CID '%lu'", __func__, SESSION_USERID(sesn_ptr));
		_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_BACKENDERR, RESCODE_BACKEND_CONNECTION);
	}

	if (redis_ptr->type==REDIS_REPLY_ERROR)
	{
	   syslog(LOG_DEBUG, "%s: REDIS_REPLY_ERROR COULD NOT GET REDIS RESPONSE for CID '%lu'", __func__, SESSION_USERID(sesn_ptr));

	   freeReplyObject(redis_ptr);

	   _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_BACKENDERR, RESCODE_BACKEND_DATA);;
	}

	if ((redis_ptr->type==REDIS_REPLY_NIL) || (redis_ptr->elements==0))
	{
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', uid:'%lu'}: COULD NOT RETRIEVE RECORD: EMPTY SET",  __func__, pthread_self(), sesn_ptr, SESSION_USERID(sesn_ptr));
#endif

	   _RETURN_RESULT_RES(res_ptr, redis_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA_EMPTYSET);
	}

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p'): UID '%lu': FOUND '%lu' fences", __func__, pthread_self(), sesn_ptr, SESSION_USERID(sesn_ptr), redis_ptr->elements);
#endif

	_RETURN_RESULT_RES(res_ptr, redis_ptr,  RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);

}

/**
 * 	@brief:
 *
 * 	Similra to its cousine _GetInvitedFencesListCacheRecordForUserWithScores(), except it also retrieve
 * 	the user's list of fences from the backend in raw redis format, including original score values, which
 * 	translate to 'invited when timestamp' value for each fence.
 *
 */
static UFSRVResult *
_GetInvitedFencesListCacheRecordForUserWithScores (Session *sesn_ptr,  unsigned long call_flags, UFSRVResult *res_ptr_in)
{
	UFSRVResult 				*res_ptr;
	PersistanceBackend 	*pers_ptr=sesn_ptr->persistance_backend;
	redisReply 					*redis_ptr;

	if (!res_ptr_in)	res_ptr=&(sesn_ptr->sservice.result);
	else				res_ptr=res_ptr_in;

	if (!(redis_ptr=(*pers_ptr->send_command)(sesn_ptr, REDIS_CMD_INVITED_FENCES_FOR_USER_GET_ALL_WITHSCORES, SESSION_USERID(sesn_ptr)))) {
		syslog(LOG_DEBUG, "%s: ERROR COULD NOT GET REDIS RESPONSE for CID '%lu'", __func__, SESSION_USERID(sesn_ptr));
		_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_BACKENDERR, RESCODE_BACKEND_CONNECTION);
	}

	if (redis_ptr->type==REDIS_REPLY_ERROR) {
	   syslog(LOG_DEBUG, "%s: REDIS_REPLY_ERROR COULD NOT GET REDIS RESPONSE for CID '%lu'", __func__, SESSION_USERID(sesn_ptr));

	   freeReplyObject(redis_ptr);

	   _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_BACKENDERR, RESCODE_BACKEND_DATA);;
	}

	if ((redis_ptr->type==REDIS_REPLY_NIL) || (redis_ptr->elements==0)) {
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', uid:'%lu'}: COULD NOT RETRIEVE RECORD: EMPTY SET",  __func__, pthread_self(), sesn_ptr, SESSION_USERID(sesn_ptr));
#endif

	   _RETURN_RESULT_RES(res_ptr, redis_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA_EMPTYSET);
	}

#ifdef __UF_FULLDEBUG
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p'): UID '%lu': FOUND '%lu' fences", __func__, pthread_self(), sesn_ptr, SESSION_USERID(sesn_ptr), redis_ptr->elements);
#endif

	_RETURN_RESULT_RES(res_ptr, redis_ptr,  RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);

}

static inline void	_BuildFenceListWithScores (InstanceHolderForSession *instance_sesn_ptr, redisReply *redis_ptr_list, EnumFenceCollectionType list_type, unsigned long fence_call_flags);
static inline void	_BuildFenceList (InstanceHolderForSession *instance_sesn_ptr, redisReply *redis_ptr_list, EnumFenceCollectionType list_type, unsigned long fence_call_flags);
static inline void _CleanUpFaultyFenceEntriesForUser (Session *sesn_ptr, CollectionDescriptor *collection_ptr, size_t resultset_sz,  EnumFenceCollectionType list_type);


/**
 * 	@brief: Helper class to iterate over raw fence list for a user. This's strictly a utility class.
 * 	@param redis_ptr_list: raw redis collection in the form of "<fid>:<uid_invited_by>" which originates from
 * 	user's fences store. We should be able to detect data referential issues and recover from that if the target fence did not contain
 * 	the user in fences user's store and delete that fence from user's collection.
 * 	@locked: None
 */
static inline void
_BuildFenceList (InstanceHolderForSession *instance_sesn_ptr, redisReply *redis_ptr_list, EnumFenceCollectionType list_type, unsigned long fence_call_flags)
{
	int 						i								=	0;
	size_t          raw_records_sz	= 0;
	unsigned long		fence_id;
	char 						*uid_by;
	char 						*raw_records[redis_ptr_list->elements]; memset (raw_records, 0, sizeof(raw_records)); //TODO: warning: stackoverflow

	Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	for (; i < redis_ptr_list->elements; ++i) {
		//"1804689344:1234"
		raw_records[i]	=	strdupa(redis_ptr_list->element[i]->str);

		if (IS_STR_LOADED(uid_by = strrchr(redis_ptr_list->element[i]->str, ':'))) {
			*uid_by = '\0';	uid_by++;
			fence_id = strtoul(redis_ptr_list->element[i]->str, NULL, 10);
#ifdef __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p',  cid:'%lu'): BACKEND RESULTSET CONTAINs FENCE: fid:'%lu' uid_inviter:'%s", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), fence_id, uid_by);
#endif
		} else {
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p',  cid:'%lu'): ERROR: COULD NOT EXTRACT BID UID value from redis set '%s': ignoring...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), redis_ptr_list->element[i]->str);
			continue;
		}

		if (!(SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_SNAPSHOT))) {
			if (IS_PRESENT(_InstateFenceIntoSessionFromCacheRecord (instance_sesn_ptr, list_type, 0/*score*/, fence_id, uid_by, fence_call_flags)))	raw_records[i]	= NULL;
			else raw_records_sz++;
		} else {
			_InstateFenceForSnapshotSession (instance_sesn_ptr, list_type, fence_id, uid_by);
		}
	}

	_CleanUpFaultyFenceEntriesForUser (sesn_ptr, &((CollectionDescriptor){.collection=(collection_t **)raw_records, .collection_sz=redis_ptr_list->elements}), raw_records_sz, list_type);
}

/**
 * 	@brief: Helper class to iterate over raw fence list, containing SCORES info for a user.
 * 	This strictly utility class.
 */
static inline void
_BuildFenceListWithScores (InstanceHolderForSession *instance_sesn_ptr, redisReply *redis_ptr_list, EnumFenceCollectionType list_type, unsigned long fence_call_flags)
{
	size_t          raw_records_sz  =       0;
	unsigned long		fence_id,
									score;
	char 						*uid_by;
	char 						*raw_records[redis_ptr_list->elements / 2]; memset (raw_records, 0, sizeof(raw_records)); // elements/2 because list contain scores as well as useful payload
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	for (size_t i=0; i < redis_ptr_list->elements; i+=2) {
		score	=	strtoul(redis_ptr_list->element[i+1]->str, NULL, 10);//score at odd idx
		raw_records[i/2]	=	strdupa(redis_ptr_list->element[i]->str); //this is the payload always at even index

		//"1804689344:1234"
		if (IS_STR_LOADED(uid_by = strrchr(redis_ptr_list->element[i]->str, ':'))) {
			*uid_by = '\0';
			uid_by++;
			fence_id = strtoul(redis_ptr_list->element[i]->str, NULL, 10);
		} else {
			raw_records_sz++;
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p',  cid:'%lu', list_type:'%d'): ERROR: COULD NOT EXTRACT BID UID value from redis set '%s': ignoring...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), list_type, redis_ptr_list->element[i]->str);

			continue;
		}

		if (!(SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_SNAPSHOT))) {
			//_InstateFenceForSession (sesn_ptr, list_type, score, fence_id, uid_by, fence_call_flags);
			if (IS_PRESENT(_InstateFenceIntoSessionFromCacheRecord(instance_sesn_ptr, list_type, score, fence_id, uid_by, fence_call_flags)))	raw_records[i/2]	= NULL;
			else raw_records_sz++;
		} else {
			_InstateFenceForSnapshotSession (instance_sesn_ptr, list_type, fence_id,  uid_by);
		}
	}

	_CleanUpFaultyFenceEntriesForUser (sesn_ptr, &((CollectionDescriptor){.collection=(collection_t **)raw_records, .collection_sz=redis_ptr_list->elements/2}), raw_records_sz, list_type);

}

/**
 *      @brief: This is very specific clean up function used to resolve referencial user-fence integrity issues as seen from the
 *      Fences side; ie: the Fence's members List contained a reference to a user who did not reference that fence on its Fence List.
 *      @param sesn_ptr Current session under processing
 *      @param collection_ptr: collection of userids
 *
 *      @param raw_records_collection: The collection may contain less items than indicated by resultset_sz. Always check for payload.
 *
 *      @returns: how many users who did not reference the fence
 *      @locked f_ptr:
 *      @locked sesn_ptr:
 *
 */
static inline size_t
_CleanUpFaultyUserEntriesForFence (Session *sesn_ptr, Fence *f_ptr, unsigned long userid_loaded_for, CollectionDescriptor *collection_ptr,  EnumFenceCollectionType list_type)
{
	size_t 	removed_users_sz = 0;

	if (collection_ptr->collection_sz > 0) {
		if (list_type == MEMBER_FENCES) {
			for (size_t i=0; i<collection_ptr->collection_sz; i++) {
				redisReply *redis_ptr_user = (redisReply *)collection_ptr->collection[i];
				unsigned long uid = UfsrvUidGetSequenceId((UfsrvUid *)redis_ptr_user->element[REDIS_KEY_USER_UID]->str);

				if (!IsFenceIdInCacheRecordForUser(uid, FENCE_ID(f_ptr), NULL)) {
					//user doesn't have fence in its List of fences: so we remove this user from the Fences Members list
					redisReply 					*redis_ptr;
					PersistanceBackend 	*pers_ptr						= THREAD_CONTEXT_PERSISTANCE_CACHEBACKEND(THREAD_CONTEXT);

					if (unlikely(IS_EMPTY(UpdateBackendFenceData(sesn_ptr, f_ptr, (void *)uid, EVENT_TYPE_FENCE_MEMBERSHIP_REPAIRED, &((FenceEvent){})))))
										continue;

						//TODO: inter broadcast invalidate event (should happen in UpdateBackendFenceData())

						syslog (LOG_NOTICE, "%s (pid:'%lu', th_ctx:'%p', uid:'%lu, fid:'%lu'): FOUND USER THAT DID NOT REFERENCE FENCE IN ITS LIST: DELETEING...", __func__, pthread_self(), THREAD_CONTEXT_PTR, uid, FENCE_ID(f_ptr));

						Session *sesn_ptr_removed;
						InstanceHolderForSession *instance_sesn_ptr_removed;
						bool 		dangling_session 					= false;
						bool 		lock_already_owned 				= false;

						//update memory store for both direction, although it is likely the user doesn't have the fence on its list
						if (uid == userid_loaded_for){// && SESSION_USERID(sesn_ptr_carrier) == uid) {
							//already locked. Unlikely scenario???
							InstanceHolderForSession *instance_sesn_ptr_this_user = LocallyLocateSessionByUserId(uid);
							_RemoveUserFromUserFenceAndUnlinkUser(f_ptr, instance_sesn_ptr_this_user, false);
						} else {
							instance_sesn_ptr_removed = LocallyLocateSessionByUserId(uid);
							if (IS_PRESENT(instance_sesn_ptr_removed)) {
							  sesn_ptr_removed = SessionOffInstanceHolder(instance_sesn_ptr_removed);

								SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_removed, _LOCK_TRY_FLAG_FALSE, __func__);
								if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_SUCCESS)) {
									if (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_BY_THIS_THREAD)) lock_already_owned = true;
								} else	{
									dangling_session = true;//lock failed
								}

								_RemoveUserFromUserFenceAndUnlinkUser(f_ptr, instance_sesn_ptr_removed, dangling_session);

								if (!dangling_session && !lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_removed, __func__);
								dangling_session = false;
								lock_already_owned = false;
							} else {
								//this is tolerable, as we may not have session for that user locally
								syslog (LOG_NOTICE, "%s (pid:'%lu', th_ctx:'%p' uid:'%lu, fid:'%lu'): FOUND USER THAT DID NOT REFERENCE FENCE IN ITS LIST: BUT NO LOCAL SESSION FOR THIS FOUND", __func__, pthread_self(), THREAD_CONTEXT_PTR, uid, FENCE_ID(f_ptr));
							}
						}

						//remove record from received collection so called doesn;t process for this user, even though we may not have been able to successfull update memory store
						removed_users_sz++;
						collection_ptr->collection[i] = NULL;
						freeReplyObject(redis_ptr_user);
				}
			}
		} else if (list_type == INVITED_FENCES) {
			//TODO: implement _CleanUpFaultyUserEntriesForFence for other fence membership types
			syslog(LOG_DEBUG, "%s (pid:'%lu', th_ctx:'%p', fid:'%lu'): WARNING: NOT IMPLEMENTED...", __func__, pthread_self(), THREAD_CONTEXT_PTR, FENCE_ID(f_ptr));
		}

	}//end if

	return removed_users_sz;

}

/**
 *      @brief: This is very specific clean up function used to resolve referencial user-fence integrity issues as seen from the
 *      User side; ie: the user's Fence List contained a reference to a Fence where that fenece did not have the user on its Members List.
 *
 *      @param raw_records_collection: The collection may contain less items than indicated by resultset_sz. Always check for payload.
 *
 */
static inline void
_CleanUpFaultyFenceEntriesForUser (Session *sesn_ptr, CollectionDescriptor *collection_ptr, size_t resultset_sz,  EnumFenceCollectionType list_type)//, char **raw_records_collection, size_t collection_sz, EnumFenceCollectionType list_type)
{
	if (resultset_sz > 0) {
		const char *prebuilt_command_template = NULL;

		if 			(list_type == MEMBER_FENCES)        prebuilt_command_template  =  REDIS_CMD_USER_FENCE_LIST_REM_PREBUILT;
		else if (list_type == INVITED_FENCES)       prebuilt_command_template  =  REDIS_CMD_INVITED_FENCES_FOR_USER_REM_PREBUILT;
		else return;

		size_t	actually_processed      	= collection_ptr->collection_sz+2;
		char    **raw_records_collection	=	(char **)collection_ptr->collection;
		PersistanceBackend      *pers_ptr	=	sesn_ptr->persistance_backend;

		(*pers_ptr->send_command_multi)(sesn_ptr, "MULTI");
		for (size_t i=0; i<collection_ptr->collection_sz; i++) {
			if (IS_PRESENT(raw_records_collection[i])) {
				(*pers_ptr->send_command_multi)(sesn_ptr, prebuilt_command_template, SESSION_USERID(sesn_ptr), raw_records_collection[i]);
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', collection_sz:'%lu', resultset_sz:'%lu', arg:'%s'): ERROR: User's Fences List contained referential errors (user wasn't referenced)...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), collection_ptr->collection_sz, resultset_sz, raw_records_collection[i]);
			}
			else actually_processed--;
		}
		(*pers_ptr->send_command_multi)(sesn_ptr, "EXEC");

		size_t          commands_successful     =       actually_processed;
		redisReply      *replies[actually_processed];

		memset (replies, 0, sizeof(replies));

		for (size_t i=0; i<actually_processed; i++) {
			if ((RedisGetReply(sesn_ptr, pers_ptr, (void *)&replies[i])) != REDIS_OK) {
				commands_successful--;

				if ((replies[i] != NULL)) {
					syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', idex:'%lu'): ERROR PROCESSING MULTI SET COMMAND. ERROR: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i, replies[i]->str);
				} else {
					syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', i:'%lu'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i);
				}
			}
		}

    //diagnostics
    if (commands_successful != actually_processed) {
			for (size_t i=0; i<actually_processed; i++)     if (IS_PRESENT(replies[i]))     freeReplyObject(replies[i]);

			return;
    }

    //verification block
    {
			//we only want to keep the last one which contains array of redisReply * corresponding with the number of commands issued, less exec/multi
			//the rest will return value of type REDIS_REPLY_STATUS
#define EXEC_COOMAND_IDX actually_processed-1

			for (size_t i=0; i<EXEC_COOMAND_IDX; i++)   if (IS_PRESENT(replies[i]))     freeReplyObject(replies[i]);

			if (IS_EMPTY(replies[EXEC_COOMAND_IDX])) {//idx for EXEC, which is last
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR: REDIS TRANSCTION ERROR: NULL COMMAND ARRAY RESPONSE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

				return;
			}

			if (replies[EXEC_COOMAND_IDX]->elements == actually_processed - 2) {
				for (size_t i=0; i<replies[EXEC_COOMAND_IDX]->elements; i++) {
					redisReply *reply = replies[EXEC_COOMAND_IDX]->element[i];
					//TODO: CHECK CODE
				}
			} else {
				//Only remaining element is EXEC
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', dispatched:'%lu', received:'%lu'): ERROR: REDIS TRANSCTION ERROR: DISPATCHED/RECEIVED COMMANDS COUNT MISMATCH", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), actually_processed-2, replies[EXEC_COOMAND_IDX]->elements);
			}

			if (IS_PRESENT(replies[EXEC_COOMAND_IDX]))      freeReplyObject(replies[EXEC_COOMAND_IDX]);
		}
	}

}

/**
 * 	@brief:
 * 	In the context of initialising a User: Retrieve the user's list of fences from the backend previously returned in list
 * 	(output of REDIS_CMD_USER_FENCE_LIST_GET_ALL %bid:%uid) and build it into User's Session
 * 	We don't change the core state of the session we just reflect what is already in the backend, update local cache. Therefore,
 * 	no msgqueue broadcast is performed.
 *
 * 	@param redis_ptr:
 * 	Raw redis record reply, containing list of fences in the form: '%bid:%uid'. List type is indicated by list_type
 *
 * 	@param fence_call_flag FENCE_CALLFLAG_FENCE_LIST_WITH_SCORES:
 * 	@param call_flag:
 * 	(NOT IMPLEMENTED)CALL_FLAG_SESSION_FENCE_APPEND	append to existing user fence list
 *
 *	@param call_flag:
 * 	(NOT IMLEMENTED)CALL_FLAG_SESSION_FENCE_REBUILD	rebuild user fence list freeing all memory associated with old list, but dont remove fences from rego
 *
 * 	@dynamic_memory: caller must free IMPORTED redisReply instance
 *
 *	@locks: RW each fence in the list as the fence's list is updated to remove user session from it
 */
static UFSRVResult *
_InstateFencesListCacheRecordForUser (InstanceHolderForSession *instance_sesn_ptr, redisReply *redis_ptr_list, EnumFenceCollectionType list_type, unsigned long sesn_call_flags, unsigned long fence_call_flags, UFSRVResult *res_ptr_in)
{
	Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
	UFSRVResult			*res_ptr = NULL;

	if (IS_EMPTY(res_ptr_in))	res_ptr = SESSION_RESULT_PTR(sesn_ptr);
	else											res_ptr = res_ptr_in;

	//SESSION LOCKED (if flag set)

	if (SESSION_FENCE_LIST_COUNT(sesn_ptr) > 0) {
		if (sesn_call_flags&CALL_FLAG_SESSION_FENCE_REBUILD) {
			//free existing list
#ifdef __UF_TESTING
			syslog(LOG_DEBUG, "%s (cid='%lu'): SESSION CONTAINS '%d' IVITED-FOR FENCES: releasing before rebuilding...(NOT IMPLEMENTED)", __func__, SESSION_ID(sesn_ptr), SESSION_FENCE_LIST_COUNT(sesn_ptr));
#endif
			//no state change is intended therefore no msgqueue broadcast is necessary: we are just rebuilding internal data structure to
			//mirror established state in backend
			//RemoveUserFromFence
		}
	}

#ifdef __UF_FULLDEBUG
	syslog(LOG_DEBUG, "%s {pid:'%lu' o:'%p', cid:'%lu', list_sz:'%lu'}: Fence CacheRecord from CacheBackend", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), redis_ptr_list->elements);
#endif

	if (redis_ptr_list->elements > 0) {
		if (fence_call_flags&FENCE_CALLFLAG_FENCE_LIST_WITH_SCORES) {
			_BuildFenceListWithScores(instance_sesn_ptr, redis_ptr_list, list_type, fence_call_flags);
		} else {
			_BuildFenceList(instance_sesn_ptr, redis_ptr_list, list_type, fence_call_flags);
		}
	}

	SESNSTATUS_UNSET(sesn_ptr->stat, SESNSTATUS_FENCELIST_LAZY);

	_RETURN_RESULT_RES(res_ptr, sesn_ptr,  RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)

}

/**
 * 	@brief: Helper routine to instate and connect individual fence into a given session in the context of previously freshly retrieved
 * 	cache fence backend records of type list_type, eg. invited. the key point is we should not load the fence if it did not
 * 	have the user in it. Hence, why we need to keep the context of what list_type we are working with, because this function works
 * 	with multiple fence types (especially downstream). As a side effect of loading the fence, we'l be loading various other fence lists
 * 	it should not be an error if the user was not on members list if the context of the fence load was invited list.
 * 	the above rules only apply if FENCE_CALLFLAG_ABORT_RECORD_IF_USER_NOT_MEMBER was set.
 * 	@param score: If available that will have been retrieved from the backend and is interpreted relative to list context
 *	@fence_call_flag FENCE_CALLFLAG_ABORT_RECORD_IF_USER_NOT_MEMBER:
 * 	@locks RW f_ptr: where found
 * 	@unlocks f_ptr: where previously found
 */
static inline FenceStateDescriptor *
_InstateFenceIntoSessionFromCacheRecord (InstanceHolderForSession *instance_sesn_ptr, EnumFenceCollectionType list_type, unsigned long score, unsigned long fence_id, const char *uid_by, unsigned long fence_call_flags)
{
	bool		lock_already_owned 				= false,
					fence_lock_already_owned 	= false;
	Fence 	*f_ptr_hashed;
	Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	FindFenceById(sesn_ptr, fence_id, CALLFLAGS_EMPTY);//local search only
	InstanceHolder *instance_f_ptr_hashed = (InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr);

	if (IS_PRESENT(instance_f_ptr_hashed)) {
	  f_ptr_hashed = FenceOffInstanceHolder(instance_f_ptr_hashed);
		FenceEventsLockRWCtx(THREAD_CONTEXT_PTR, f_ptr_hashed, _LOCK_TRY_FLAG_FALSE, SESSION_RESULT_PTR(sesn_ptr), __func__);
		if (SESSION_RESULT_TYPE_EQUAL(sesn_ptr, RESULT_TYPE_ERR))	return NULL;
		fence_lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_PROG_LOCKED_BY_THIS_THREAD));
	} else {
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s (pid'%lu', o:'%p', cid:%lu', list_type:'%d'): COULD NOT FIND  FENCE bid='%lu' LOCALLY: RETRIEVING FROM BACKEND", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), list_type, fence_id);
#endif

		unsigned fence_call_flags_final = 0;

		fence_call_flags_final = (FENCE_CALLFLAG_HASH_FENCE_LOCALLY|FENCE_CALLFLAG_KEEP_FENCE_LOCKED|FENCE_CALLFLAG_LOCK_FENCE_BLOCKING);
		if (fence_call_flags&FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE)				fence_call_flags_final |= FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE;
		if (fence_call_flags&FENCE_CALLFLAG_ABORT_RECORD_IF_USER_NOT_MEMBER)	fence_call_flags_final |= FENCE_CALLFLAG_ABORT_RECORD_IF_USER_NOT_MEMBER;


		//we request to keep fence locked upon return
		//CALL_FLAG_ATTACH_USER_LIST_TO_FENCE does not add this user to list. we do it here
		GetCacheRecordForFence(sesn_ptr, list_type, fence_id, SESSION_USERID(sesn_ptr), &fence_lock_already_owned, fence_call_flags_final);
    instance_f_ptr_hashed = (InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr);

		if (IS_EMPTY(instance_f_ptr_hashed)) {
			syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p', cid:'%lu', fid:'%lu', list_type:'%d'): ERROR COULD NOT INSTATE FENCE RECORD FROM BACKEND: MEMBRS LIST COULD HAVE BEEN EMPTY", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), fence_id, list_type);

			return NULL;
		}
	}

	f_ptr_hashed = FenceOffInstanceHolder(instance_f_ptr_hashed);

	//OK we now have a locked fence instance in the local cache. add and cross link this session<->fence
#define BACKEND_WRITEBACK 0
	//no write back because we are reflecting an already existing backend state
	//AddUserToExistingFenceAndLinkToUser(f_ptr_hashed, sesn_ptr, CALL_FLAG_FENCE_LIST_CHECK_DUP_SESSION|CALL_FLAG_SESSION_LIST_CHECK_DUP_FENCE);//BACKEND_WRITEBACK);

	List				 					*user_fence_list_ptr,
												*fence_user_list_ptr;
	FenceStateDescriptor	*f_state_ptr = NULL;
	InstanceHolderForFenceStateDescriptor *instance_fstate_ptr = NULL;

	switch (list_type)
	{
    case MEMBER_FENCES:
      user_fence_list_ptr = SESSION_FENCE_LIST_PTR(sesn_ptr);
      fence_user_list_ptr = &(f_ptr_hashed->fence_user_sessions_list);
      instance_fstate_ptr = AddUserToThisFenceListWithLinkback(instance_sesn_ptr, instance_f_ptr_hashed, user_fence_list_ptr, fence_user_list_ptr, 0/*event_type*/, CALL_FLAG_FENCE_LIST_CHECK_DUP_SESSION|CALL_FLAG_SESSION_LIST_CHECK_DUP_FENCE);
      if (IS_PRESENT(instance_fstate_ptr)) {
        f_state_ptr = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
        InitialiseFenceUserPreferences (&((PairedSessionFenceState){f_state_ptr, sesn_ptr}));
        GetUfsrvUid(sesn_ptr, strtoll(uid_by, NULL, 10), &(f_state_ptr->invited_by), false, NULL);
      }
      //f_state_ptr->when_joined=time(NULL);
      break;

    case INVITED_FENCES:
      user_fence_list_ptr = SESSION_INVITED_FENCE_LIST_PTR(sesn_ptr);
      fence_user_list_ptr = &(f_ptr_hashed->fence_user_sessions_invited_list);
      instance_fstate_ptr = AddUserToThisFenceListWithLinkback(instance_sesn_ptr, instance_f_ptr_hashed, user_fence_list_ptr, fence_user_list_ptr,  0, CALL_FLAG_FENCE_LIST_CHECK_DUP_SESSION|CALL_FLAG_SESSION_LIST_CHECK_DUP_FENCE);
      if (IS_PRESENT(instance_fstate_ptr)) {
        f_state_ptr = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
        GetUfsrvUid(sesn_ptr, strtoll(uid_by, NULL, 10), &(f_state_ptr->invited_by), false, NULL);
        //InitialiseFenceUserPreferences (&((PairedSessionFenceState){f_state_ptr, sesn_ptr})); //only di=o it when user actually joined
        f_state_ptr->when_invited = score;
      }
      break;

    default:
      ;
	}

#undef BACKEND_WRITEBACK

	if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr_hashed, SESSION_RESULT_PTR(sesn_ptr));

	return f_state_ptr;
}

/**
 * 	@brief: Instate Fence for snapshot session (not hashed, locked, etc...). In this context we only one-way link Session <- Fence with
 * 	light-on fenece data. This should be paired with ResetSessionData(), which has test for SNAPSHOT session type and knows how
 * 	to clean what's being instated here.
 * 	@return InstanceHolderForFenceStateDescriptor
 */
static inline FenceStateDescriptor *
_InstateFenceForSnapshotSession (InstanceHolderForSession *instance_sesn_ptr, EnumFenceCollectionType list_type,  unsigned long fence_id,  const char *uid_by)
{
	List				 					*user_fence_list_ptr;
	Fence									*f_ptr;
	FenceStateDescriptor	*fstate_ptr;

	Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	GetCacheRecordForFence(sesn_ptr, list_type, fence_id, UNSPECIFIED_UID, NULL, FENCE_CALLFLAG_EMPTY);
  InstanceHolderForFence *instance_f_ptr = SESSION_RESULT_USERDATA(sesn_ptr);
	if (unlikely(IS_EMPTY(instance_f_ptr)))	return NULL;

	InstanceHolderForFenceStateDescriptor *instance_fstate_ptr = FenceStateDescriptorGetInstance((ContextData *)instance_f_ptr, FENCE_CALLFLAG_EMPTY);
	if (unlikely(IS_EMPTY(instance_fstate_ptr))) {
		FenceReturnToRecycler(instance_f_ptr, NULL, 0);
		return NULL;
	}

	f_ptr = FenceOffInstanceHolder(instance_f_ptr);
	fstate_ptr = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);

	F_ATTR_SET(f_ptr->attrs, F_ATTR_SNAPSHOT);
	F_ATTR_SET(f_ptr->attrs, F_ATTR_USERFENCE);

  GetUfsrvUid(sesn_ptr, strtoll(uid_by, NULL, 10), &(fstate_ptr->invited_by), false, NULL);

	switch (list_type)
	{
	case MEMBER_FENCES:
		user_fence_list_ptr = SESSION_FENCE_LIST_PTR(sesn_ptr);

		AddThisToList (user_fence_list_ptr, instance_fstate_ptr);
		FenceIncrementReference(instance_f_ptr, 1);

		InitialiseFenceUserPreferences (&((PairedSessionFenceState){fstate_ptr, sesn_ptr}));

		//f_state_ptr->when_joined=time(NULL);
		return fstate_ptr;

	case INVITED_FENCES:
		user_fence_list_ptr = SESSION_INVITED_FENCE_LIST_PTR(sesn_ptr);
		AddThisToList (user_fence_list_ptr, instance_fstate_ptr);
		FenceIncrementReference(instance_f_ptr, 1);

		return fstate_ptr;

	case BLOCKED_FENCES:
		//user_fence_list_ptr=&(sesn_ptr->sservice.session_user_blocked_fence_list);
		break;

	default:
		;
	}

	FenceStateDescriptorReturnToRecycler(instance_fstate_ptr, (ContextData *)f_ptr, 0);

	return NULL;

}

#endif
//-------------- END backend fence instantiation FOR USER ---//

__attribute__ ((const)) bool
IsGeoFence (const Fence *f_ptr)
{
	return (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_BASEFENCE));
}

__attribute__ ((const)) bool
IsUserFence (const Fence *f_ptr)
{
	return (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_USERFENCE));
}

__attribute__ ((const)) bool
IsFenceSticky (const Fence *f_ptr)
{
	return (F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_STICKY));
}

__attribute__ ((const)) bool
IsFenceReferencedByUsers (InstanceHolderForFence *instance_f_ptr)
{
	size_t refcount_fence = RecyclerTypeGetReferenceCount(FencePoolTypeNumber(), instance_f_ptr);
	return (refcount_fence > 2);

}

//practically owner left, but fence has invitees who have not accepted invitation
__attribute__ ((const)) bool
IsFenceReferencedByInviteMembersOnly (const Fence *f_ptr)
{
	return (!F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_DIRTY) 					&&
					!F_ATTR_IS_SET(f_ptr->attrs, F_ATTR_SESSNLIST_LAZY) &&
					FENCE_SESSIONS_LIST_SIZE(f_ptr)==0 									&&
					FENCE_INVITED_LIST_SIZE(f_ptr)>0);
}

__pure bool
IsFenceOwnedByUser (Session *sesn_ptr, Fence *f_ptr)
{
	if (SESSION_USERID(sesn_ptr) == FENCE_OWNER_UID(f_ptr))	return true;

	return false;
}


static UFSRVResult * _HandleOrphanGeoFenceCandidate (InstanceContextForSession *ctx_ptr_carrier, InstanceHolderForFence *, bool fence_lock_already_owned);
static UFSRVResult * _HandleOrphanUserFenceCandidate (InstanceContextForSession *ctx_ptr_carrier, InstanceHolderForFence *, bool fence_lock_already_owned);
static UFSRVResult *_HandleOrphanUserFenceWithInvitedMembers (InstanceContextForSession *ctx_ptr_carrier, InstanceHolderForFence *, bool fence_alreadyLocked);

/**
 * 	@locked f_ptr:
 * 	@unlocks f_ptr: f_ptr lock transferred to the destroying method
 */
static UFSRVResult *
_HandleOrphanGeoFenceCandidate (InstanceContextForSession *ctx_ptr_carrier, InstanceHolderForFence *instance_f_ptr, bool fence_lock_already_owned)
{
  Session *sesn_ptr_carrier = ctx_ptr_carrier->sesn_ptr;

	if (IsFenceReferencedByUsers(instance_f_ptr))	goto return_no_action;

	//this is invokes _DestructUserFence
	int rc = FenceReturnToRecycler(instance_f_ptr,
																(ContextData *)&((TypePoolContextDataFence){.is_fence_locked=fence_lock_already_owned, .sesn_ptr=sesn_ptr_carrier, .fence_data.instance_f_ptr=instance_f_ptr}),
																FENCE_CALLFLAG_WRITEBACK_TO_DBBACKEND|FENCE_CALLFLAG_UNLOCK_FENCE);

	if (likely(rc == 0))	_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_DESTRUCTED);

	return_no_action:
	_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

/**
 * @param sesn_ptr_carrier: this is ufsrv system user preloaded with access context
 * @locked sesn_ptr_carrier:
 * @locked f_ptr:
 * @unlocks f_ptr: f_ptr lock transferred to the destroying method
 */
static UFSRVResult *
_HandleOrphanUserFenceCandidate (InstanceContextForSession *ctx_ptr_carrier, InstanceHolderForFence *instance_f_ptr, bool fence_lock_already_owned)
{
  Fence *f_ptr = FenceOffInstanceHolder(instance_f_ptr);

	if (IsFenceReferencedByInviteMembersOnly(f_ptr)) {
		return (_HandleOrphanUserFenceWithInvitedMembers (ctx_ptr_carrier, instance_f_ptr, fence_lock_already_owned));
	}

	Session *sesn_ptr_carrier = ctx_ptr_carrier->sesn_ptr;

	if (IsFenceReferencedByUsers(instance_f_ptr))	goto return_no_action;
	if (IsFenceSticky(f_ptr))							goto return_no_action;

	//this invokes _DestructUserFence
	unsigned long fence_call_flags = FENCE_CALLFLAG_EVICT_FROM_CACHEBACKEND|FENCE_CALLFLAG_UNLOCK_FENCE;

	int rc = FenceReturnToRecycler (instance_f_ptr,
																(ContextData *)&((TypePoolContextDataFence){.is_fence_locked=fence_lock_already_owned, .sesn_ptr=sesn_ptr_carrier, .fence_data.instance_f_ptr=instance_f_ptr}),
																fence_call_flags);

	if (likely(rc == 0))	_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_DESTRUCTED)

	return_no_action:
	_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
}

/**
 * 	@locks sesn_ptr_invited:
 * 	@unlocks sesn_ptr_invited: but this gets locked again downstream at marshaling
 * 	@unlocks f_ptr: f_ptr lock transferred to the destroying method
 */
static UFSRVResult *
_HandleOrphanUserFenceWithInvitedMembers (InstanceContextForSession *ctx_ptr_carrier, InstanceHolderForFence *instance_f_ptr, bool fence_lock_already_owned)
{
	size_t 			dangling_users_counter  = 0;

	dangling_users_counter = NetworkRemoveUsersFromInviteList (ctx_ptr_carrier, instance_f_ptr);

	Session *sesn_ptr_carrier = ctx_ptr_carrier->sesn_ptr;

	//this invokes _DestructUserFence
	if (dangling_users_counter == 0) {
		FenceReturnToRecycler (instance_f_ptr,
													 (ContextData *)&((TypePoolContextDataFence){.is_fence_locked=fence_lock_already_owned, .sesn_ptr=sesn_ptr_carrier, .fence_data.instance_f_ptr=instance_f_ptr}),
													 FENCE_CALLFLAG_EVICT_FROM_CACHEBACKEND|FENCE_CALLFLAG_UNLOCK_FENCE);
		_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_DESTRUCTED)
	}

	_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
}

static ScheduledJobType * _GetScheduledJobTypeForOrphanedFences (void);

void
InitialiseScheduledJobTypeForOrphanedFences (void)
{
	RegisterScheduledJobType (GetScheduledJobsStore(), _GetScheduledJobTypeForOrphanedFences());
	AddScheduledJob (GetScheduledJobsStore(), GetScheduledJobForOrphanedFences());
}

__attribute__ ((const)) static ScheduledJobType *
_GetScheduledJobTypeForOrphanedFences (void)
{
	static ScheduledJobType job_type_session_timeout={
			.type_name				=	"Orphaned Fences",
			.type_id					=	0,//gets assigned by type registry
			.frequecy_mode		=	PERIODIC,
			.concurrency_mode	=	SINGLE_INSTANCE,
			.frequency				=	_CONFIGDEFAULT_FENCE_ORPHANED_CHECK_FREQUENCY, //5min
			.job_ops					=	{
					.callback_on_compare_keys	= (CallbackOnCompareKeys)TimeValueComparator,
					.callback_on_error				=	NULL,
					.callback_on_run					=	(CallbackOnRun)CheckOrphanedFences
			}
	};

	return &job_type_session_timeout;

}


/**
 * 	@brief: Since this job type does not allow concurrent scheduling, ie one job of this type can ever exist in the scheduler
 * 	we can get away with allocating a single static reference.
 */
ScheduledJob *
GetScheduledJobForOrphanedFences (void)
{
	static ScheduledJob job_orpahned_fences;

	job_orpahned_fences.job_type_ptr = _GetScheduledJobTypeForOrphanedFences();

	return &job_orpahned_fences;
}

//This is thread-safe as it is only accessed one thread at a time.
static size_t	_store_sz = _CONFIGDEFAULT_HASHTABLE_SZ*2;
static InstanceHolderForFence	*_LocalFencesStore[_CONFIGDEFAULT_HASHTABLE_SZ*2];
static atomic_bool isCheckOrphanedFencesRunning = ATOMIC_VAR_INIT(false);


/*
 * You don't need atomic_thread_fence() here because your critical sections start with acquire and end with release semantics.
 * Hence, reads within your critical sections can not be reordered prior to the acquire and writes post the release.
 * And this is why volatile is unnecessary here as well.
 */
int
CheckOrphanedFences (void *arg)
{
	bool expected_running_is_false = false;

	if (!atomic_compare_exchange_strong_explicit(&isCheckOrphanedFencesRunning, &expected_running_is_false, true, memory_order_acq_rel, memory_order_relaxed)) {
		syslog(LOG_DEBUG, LOGSTR_UFSRVWORKER_ONETHREADONLY, __func__, pthread_self(), LOGCODE_UFSRVWORKER_ONETHREADONLY, "CheckOrphanedFences");
		return 0;
	}

	size_t	  i;
	int				numResults          = 0;
	bool			is_using_local_store= false;
	InstanceHolderForFence  **current_fences    = NULL;
	HashTable               *hash = &(FenceRegistryIdHashTable);

	if ((HashTable_RdLock(hash, 1)) != 0) {
		numResults = -1;
		goto return_with_value;
	}

	syslog(LOG_DEBUG, LOGSTR_CACHE_SIZE, __func__, pthread_self(), HASHTABLE_ENTRIES(hash), HASHTABLE_SIZE(hash), LOGCODE_CACHE_SIZE_SESSION, HASHTABLE_NAME(hash));

	statsd_gauge(pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_instrumentation_backend_key), "worker.ufsrv.job.orphaned_fences.fences_global_size", (ssize_t)HASHTABLE_ENTRIES(hash));

	long long timer_start = GetTimeNowInMicros();

  UfsrvConfigRegisterUfsrverActivity(pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.worker_persistance_key), time(NULL));

	if (HASHTABLE_SIZE(hash) == 0 || HASHTABLE_ENTRIES(hash) == 0) {
		HashTable_UnLock(hash);

		numResults = 0;
		goto return_with_value;
	}

	//mutate table so as not to hold it locked for too long
	if (HASHTABLE_ENTRIES(hash) < _store_sz) {
		current_fences = _LocalFencesStore;
		is_using_local_store = true;
	} else {
		current_fences = malloc((HASHTABLE_ENTRIES(hash) + 1) * sizeof(Fence *));
		*(current_fences + HASHTABLE_ENTRIES(hash)) = NULL; //terminate last entry for safety
	}

	for (i=0; i<HASHTABLE_SIZE(hash); i++) {
		if (hash->fTable[i] != NULL) {
			if (numResults + 1 > HASHTABLE_ENTRIES(hash)) {
				syslog(LOG_ERR, LOGSTR_CACH_INCONSIZE, __func__, pthread_self(), numResults+1, HASHTABLE_ENTRIES(hash), LOGCODE_CACHE_INCONSISTENT_SIZE, HASHTABLE_NAME(hash));
				break;
			}

			FenceIncrementReference((InstanceHolderForFence *)hash->fTable[i], 1);

			*(current_fences + (numResults++)) = (InstanceHolderForFence *)hash->fTable[i];
		}
	}

	HashTable_UnLock(hash);

	syslog(LOG_DEBUG, LOGSTR_CACHE_EXTRACTEDSET, __func__, pthread_self(), numResults, LOGCODE_CACHE_EXTRACTEDSET_SIZE, HASHTABLE_NAME(hash));

	if (numResults != HASHTABLE_ENTRIES(hash)) {
		syslog(LOG_ERR, "%s (pid:'%lu'): ERROR: DISCREPANCY between SCANNED '%d' and ACTUAL '%lu' FENCES.", __func__, pthread_self(), numResults, HASHTABLE_ENTRIES(hash));
	}

	//pool based allocation
	InstanceHolderForSession	*instance_sesn_ptr_carrier =	InstantiateCarrierSession(NULL, WORKERTYPE_UFSRVWORKER, CALL_FLAG_INSTANTIATE_FROM_SYSTEM_USER);
	if (IS_EMPTY(instance_sesn_ptr_carrier)) {
		syslog(LOG_ERR, "%s (pid:'%lu'): SEVERE ERROR: RECYCLER RETURNED NULL CARRIER SESSION OBJECT.", __func__, pthread_self());
		numResults = -2;
		goto return_with_value;
	}

  Session	*sesn_ptr_carrier = SessionOffInstanceHolder(instance_sesn_ptr_carrier);
	{
		int								result_code 				__unused;
		time_t						now								= time(NULL);

		//bool recycle_flag=false;
		statsd_gauge(pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_instrumentation_backend_key), "worker.ufsrv.job.orphaned_fences.fences_collection_size", numResults);

		bool fence_lock_already_owned = false;

		for (i=0; i<numResults; i++) {
			InstanceHolderForFence *instance_f_ptr = *(current_fences + i);
			Fence *f_ptr = FenceOffInstanceHolder(instance_f_ptr);

			if (IS_EMPTY(f_ptr)) {
        syslog(LOG_ERR, "%s (pid:'%lu', fo_instance:'%p', idx:'%lu'): !!!SEVERE ERROR: INSTANCE HOLDER CONTAINED NULL FENCE INSTANCE REFERENCE", __func__, pthread_self(), instance_f_ptr, i);
        FenceDecrementReference(instance_f_ptr, 1);
        continue;
			}

			FenceEventsLockRWCtx(THREAD_CONTEXT_PTR, f_ptr, _LOCK_TRY_FLAG_TRUE, THREAD_CONTEXT_UFSRV_RESULT(ufsrv_thread_context), __func__);
			if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(ufsrv_thread_context), RESULT_TYPE_ERR)) {
			  FenceDecrementReference(instance_f_ptr, 1);
				continue;
			}

			fence_lock_already_owned = (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(ufsrv_thread_context), RESCODE_PROG_LOCKED_BY_THIS_THREAD));
			//>>>> FENCE NOW LOCKED

			//DO STUFF....
      FenceDecrementReference(instance_f_ptr, 1);
			InstanceContextForSession instance_ctx = {instance_sesn_ptr_carrier, sesn_ptr_carrier};
			if (IsGeoFence(f_ptr))	_HandleOrphanGeoFenceCandidate (&instance_ctx, instance_f_ptr, fence_lock_already_owned);
			else 										_HandleOrphanUserFenceCandidate (&instance_ctx, instance_f_ptr, fence_lock_already_owned);

			result_code = SESSION_RESULT_CODE(sesn_ptr_carrier); //grab it whilst the session is still locked

			//>>>>>>>>>>>>>>>>>>>>>>>
			unlock_fence:
			if (result_code != RESCODE_FENCE_DESTRUCTED) {
				if (!fence_lock_already_owned)	FenceEventsUnLockCtx (THREAD_CONTEXT_PTR, f_ptr, THREAD_CONTEXT_UFSRV_RESULT(ufsrv_thread_context));//didn't get into recycler
			}
			//>>>>>>>>>>>>>>>>>>>>>>>
		}
	}

	if (!is_using_local_store)	free (current_fences);

	//statsd_gauge(pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_instrumentation_backend_key), "worker.ufsrv.job.orphaned_fences.fences_collection_size", 0);

	return_deallocate_carrier:
	SessionUnLoadEphemeralMode(sesn_ptr_carrier);
	ResetClonedUfsrvSystemUser (sesn_ptr_carrier, SESSION_CALLFLAGS_EMPTY);
	SessionReturnToRecycler (instance_sesn_ptr_carrier, (ContextData *)NULL, 0);

	return_with_value:
  if (!is_using_local_store)  {
    free (current_fences);
  }
	atomic_store_explicit(&isCheckOrphanedFencesRunning, false, memory_order_release);
	long long timer_end=GetTimeNowInMicros();

	statsd_timing(pthread_getspecific(sessions_delegator_ptr->ufsrv_thread_pool.ufsrv_instrumentation_backend_key), "worker.ufsrv.job.orphaned_fences.elapsed_time", (timer_end-timer_start));

	return numResults;

}

static void _AssignFenceListTypeForInvited (Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, ClientContextData *context_ptr);

static void
_AssignFenceListTypeForInvited (Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, ClientContextData *context_ptr)
{
	PairOfUserIdUserName *pair_ptr=(PairOfUserIdUserName *)context_ptr;
  GetUfsrvUid(sesn_ptr, strtoul(pair_ptr->aux, NULL, 10), &(fence_state_ptr->invited_by), false, NULL);
//	fence_state_ptr->when_invited=pair_ptr->
}

__attribute__((const)) FenceListTypeDescriptor *
GetFenceListTypeDescriptor (EnumFenceCollectionType list_type)
{
	static FenceListTypeDescriptor fence_list_types[] = {
			{0, 							{NULL}},
			{MEMBER_FENCES, 	{NULL}},
			{INVITED_FENCES, 	{_AssignFenceListTypeForInvited}},
			{BLOCKED_FENCES, 	{NULL}},
			{LIKED_FENCES, 		{NULL}},
			{FAVED_FENCES, 		{NULL}},
			{LIKED_FENCES, 		{NULL}},

	};

	if (list_type>=MEMBER_FENCES && list_type < ALL_FENCES)	return &fence_list_types[list_type];

	return NULL;
}

//----------- Recycer Type Pool Fence---- //
void InitFenceRecyclerTypePool ()
{
	#define _THIS_FENCE_EXPANSION_THRESHOLD (1024*10)
	FencePoolHandle = RecyclerInitTypePool("Fence", sizeof(Fence), _CONF_SESNMEMSPECS_ALLOC_GROUPS(masterptr),
                                         _THIS_FENCE_EXPANSION_THRESHOLD/*_CONF_SESNMEMSPECS_ALLOC_GROUP_SZ(masterptr)*/,
                                         &ops_fence);

	syslog(LOG_INFO, "%s: Initialised TypePool: '%s'. TypeNumber:'%d', Block Size:'%lu'", __func__, FencePoolHandle->type_name, FencePoolHandle->type, FencePoolHandle->blocksz);
}

/**
 * 	@brief: "constructor" type intialiser for newly instantiated objects just before attaching them to the recycler.
 * 	One off for the object's lifetime. No InstanceHolder ref yet.
 *
 */
static int
TypePoolInitCallback_Fence (ClientContextData *data_ptr, size_t oid)
{
	Fence *f_ptr = (Fence *)data_ptr;

	pthread_rwlockattr_init(&(f_ptr->fence_events.rwattr));

	int rc = pthread_rwlock_init(&(f_ptr->fence_events.rwlock), &(f_ptr->fence_events.rwattr));//==0 on success

	if (unlikely(rc != 0)) {
		char error_str[250] = {0};
		strerror_r(errno, error_str, 250);

		syslog(LOG_ERR, "%s: ERROR: (pid:'%lu', errno: '%d', error:'%s'): COULD NOT INITIALISE fence_events.rwlock...", __func__, pthread_self(), errno, error_str);

		return 1;//this will return NULL fence to the caller
	}

	InitialiseFencePermissionsTypes (f_ptr);
	InitialiseFencePermissionsSpecs (f_ptr);

	return 0;//success
}

/**
 * 	@param ContextData: whatever  context data we might have passed to the recycler when we issued Get In this instance Fence *
 */
static int
TypePoolGetInitCallback_Fence (InstanceHolder *data_ptr, ContextData *context_data, size_t oid, unsigned long call_flags)
{
  Fence *f_ptr = FenceOffInstanceHolder((InstanceHolderForFence *)data_ptr);

	if (call_flags&FENCE_CALLFLAG_GENERATE_ID) {
		Session *sesn_ptr = (Session *)context_data;
		if ((FENCE_ID(f_ptr) = GenerateCacheBackendId (SESSION_FENCE_CACHEBACKEND(sesn_ptr))) <= 0) {
			syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu', id:'%lu} ERROR: COULD NOT ALLOCATE FENCE ID", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), FENCE_ID(f_ptr));
			return -1;
		}

		f_ptr->when = time(NULL);
	}

	if (call_flags&FENCE_CALLFLAG_SNAPSHOT_INSTANCE)	F_ATTR_SET(f_ptr->attrs, F_ATTR_SNAPSHOT);

	if (call_flags&FENCE_CALLFLAG_LOCK_FENCE) {
		FenceEventsLockRWCtx(THREAD_CONTEXT_PTR, f_ptr, _LOCK_TRY_FLAG_FALSE, THREAD_CONTEXT_UFSRV_RESULT(ufsrv_thread_context), __func__);
		if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(ufsrv_thread_context), RESULT_TYPE_ERR))	return 0;
	}

	if (call_flags&FENCE_CALLFLAG_BASEFENCE) {
		F_ATTR_SET(f_ptr->attrs, F_ATTR_BASEFENCE);
		FENCE_OWNER_UID(f_ptr)=CONFIG_UFSRV_UID;
	} else if (call_flags&FENCE_CALLFLAG_USERFENCE) {
		F_ATTR_SET(f_ptr->attrs, F_ATTR_USERFENCE);

		//now done lazily
//		if (!InitialiseFencePermissions(f_ptr))
//		{
//			if (call_flags&FENCE_CALLFLAG_LOCK_FENCE) FenceEventsUnLock(f_ptr);
//
//			syslog(LOG_ERR, "%s: ERROR: (pid:'%lu'): COULD NOT INITIALISE FENCE PERMISSION", __func__, pthread_self());
//
//			return -1;//this will return NULL fence to the caller
//		}
	}

	//this will cause it to be fully fetched from backend
	F_ATTR_SET(f_ptr->attrs, F_ATTR_DIRTY);

	return 0;//success
}

/**
 * 	@param ContextData: whatever  context data we might have passed to the recycler when we issued Put. In this instance Fence *
 */
static int
TypePoolPutInitCallback_Fence (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
	//perhaps early in the initialisation we failed so there nothing to destruct
	if (IS_EMPTY(context_data))	return 0;

  Fence *f_ptr = FenceOffInstanceHolder((InstanceHolderForFence *)data_ptr);
	TypePoolContextDataFence *data = (TypePoolContextDataFence *)context_data;

	if (call_flags&FENCE_CALLFLAG_WRITEBACK_TO_DBBACKEND) {
		struct json_object 	*jobj_fence	= JsonFormatFenceForDbBackend(data->sesn_ptr, f_ptr, DIGESTMODE_FULL, 0/*lock*/);
		const char 					*jstr_fence	=	json_object_to_json_string(jobj_fence);

		DbBackendInsertFenceRecord (data->sesn_ptr, FENCE_ID(f_ptr), jstr_fence);
		json_object_put (jobj_fence);
	}

	if (call_flags&FENCE_CALLFLAG_EVICT_FROM_CACHEBACKEND) {
		CacheBackendRemCacheRecordForFence (data->sesn_ptr, f_ptr);
		InterBroadcastFenceDestruct (data->sesn_ptr, f_ptr, NULL, 0);
	}

//	_DestructUserFence (data->sesn_ptr, data->fence_data.instance_f_ptr, call_flags);
  _DestructUserFence (data->sesn_ptr,
                      &((InstanceContextForFence){data->fence_data.instance_f_ptr, FenceOffInstanceHolder(data->fence_data.instance_f_ptr)}),
                      call_flags);

	//not relevant to check if lock owned already
	//note: if FENCE_CALLFLAG_LOCK was passed, _Destruct takes care of unlocking
	if (call_flags&FENCE_CALLFLAG_UNLOCK_FENCE) {
		FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));
	}

	return 0;//success
}

static char *
TypePoolPrintCallback_Fence (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
	Fence *f_ptr = FenceOffInstanceHolder((InstanceHolderForFence *)data_ptr);

	return NULL;
}

static int
TypePoolDestructCallback_Fence (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
	if (IS_EMPTY(context_data))	return 0;

	TypePoolContextDataFence *data = (TypePoolContextDataFence *)context_data;

	_DestructUserFence (data->sesn_ptr,
                      &((InstanceContextForFence){data->fence_data.instance_f_ptr, FenceOffInstanceHolder(data->fence_data.instance_f_ptr)}),
                      call_flags);//expecting CALL_FLAG_SELF_DESTRUCT

	//not relevant to check if lock owned already
	//note: if FENCE_CALLFLAG_LOCK was passed, _Destruct takes care of unlocking
	if (call_flags&FENCE_CALLFLAG_UNLOCK_FENCE) {
		FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, FenceOffInstanceHolder(data->fence_data.instance_f_ptr), THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));
	}

	return 0;//success

}

/**
 * @brief Retrieve a fresh instance from the recycler
 * @param ctx_data_ptr Context data to be passed to the init function for Get
 * @param call_flags
 * @return
 */
InstanceHolderForFence *
FenceGetInstance (ContextData *ctx_data_ptr, unsigned long call_flags)
{
	InstanceHolderForFence *instance_f_ptr = RecyclerGet(FencePoolTypeNumber(), ctx_data_ptr, call_flags);
	if (unlikely(IS_EMPTY(instance_f_ptr)))	goto return_error;

	return instance_f_ptr;

	return_error:
	syslog(LOG_DEBUG, LOGSTR_INCONSISTENT_STATE, __func__, pthread_self(), (void *)0, 0UL, LOGCODE_PROTO_INCONSISTENT_STATE, "Could not get Fence instance");
	return NULL;

}

int
FenceReturnToRecycler (InstanceHolderForFence *instance_f_ptr, ContextData *ctx_data_ptr, unsigned long call_flags)
{
	return RecyclerPut(FencePoolTypeNumber(), instance_f_ptr, (ContextData *)ctx_data_ptr, call_flags);
}

void
FenceIncrementReference (InstanceHolderForFence *instance_f_ptr, int multiples)
{
	RecyclerTypeReferenced (FencePoolTypeNumber(), (RecyclerClientData *)instance_f_ptr, multiples);
#ifdef __UF_TESTING
			syslog(LOG_DEBUG, "%s: {pid:'%lu', fo:'%p'} ...", __func__, pthread_self(), instance_f_ptr);
#endif
}

void
FenceDecrementReference (InstanceHolderForFence *instance_f_ptr, int multiples)
{
	RecyclerTypeUnReferenced (FencePoolTypeNumber(), (RecyclerClientData *)instance_f_ptr, multiples);
#ifdef __UF_TESTING
			syslog(LOG_DEBUG, "%s: {pid:'%lu', fo:'%p'} ...", __func__, pthread_self(), instance_f_ptr);
#endif
}

__pure inline unsigned
FencePoolTypeNumber()
{
	return FencePoolHandle->type;
}

////end typePool Fence /////////////////////


//----------- Recycer Type Pool FenceState ---- //
void InitFenceStateDescriptorRecyclerTypePool ()
{
	#define _THIS_EXPANSION_THRESHOLD (1024*100)
	FenceStateDescriptorPoolHandle = RecyclerInitTypePool("FenceStateDescriptor", sizeof(FenceStateDescriptor), _CONF_SESNMEMSPECS_ALLOC_GROUPS(masterptr),
                                                        _THIS_EXPANSION_THRESHOLD/*_CONF_SESNMEMSPECS_ALLOC_GROUP_SZ(masterptr)*/,
                                                        &ops_fence_state_descriptor);

	syslog(LOG_INFO, "%s: Initialised TypePool: '%s'. TypeNumber:'%d', Block Size:'%lu'", __func__, FenceStateDescriptorPoolHandle->type_name, FenceStateDescriptorPoolHandle->type, FenceStateDescriptorPoolHandle->blocksz);
}

/**
 * 	@brief: "constructor" type intialiser for newly instantiated objects just before attaching them to the recycler.
 * 	One off for the object's lifetime. No InstanceHolder ref yet.
 *
 */
static int
TypePoolInitCallback_FenceStateDescriptor (ClientContextData *data_ptr, size_t oid)
{
  FenceStateDescriptor *fstate_ptr =(FenceStateDescriptor *)data_ptr;

	return 0;//success
}

/**
 * 	@param ContextData: whatever  context data we might have passed to the recycler when we issued Get().
 */
static int
TypePoolGetInitCallback_FenceStateDescriptor (InstanceHolderForFenceStateDescriptor *data_ptr, ContextData *context_data, size_t oid, unsigned long call_flags)
{
  FenceStateDescriptor *fstate_ptr = FenceStateDescriptorOffInstanceHolder((InstanceHolderForFenceStateDescriptor *)data_ptr);
	InstanceHolderForFence *instance_f_ptr = (InstanceHolderForFence *)context_data;

	fstate_ptr->instance_holder_fence = instance_f_ptr;

	return 0;//success
}

/**
 * 	@param ContextData: whatever  context data we might havepassed to the recycler when we issued Put In this instance Fence *
 */
static int
TypePoolPutInitCallback_FenceStateDescriptor (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
  FenceStateDescriptor *fstate_ptr = FenceStateDescriptorOffInstanceHolder((InstanceHolderForFenceStateDescriptor *)data_ptr);
	Fence *f_ptr=(Fence *)context_data;

	return 0;//success
}

static char *
TypePoolPrintCallback_FenceStateDescriptor (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
	FenceStateDescriptor *fstate_ptr = FenceStateDescriptorOffInstanceHolder((InstanceHolderForFenceStateDescriptor *)data_ptr);

	return NULL;
}

static int
TypePoolDestructCallback_FenceStateDescriptor (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
  FenceStateDescriptor *fstate_ptr = FenceStateDescriptorOffInstanceHolder((InstanceHolderForFenceStateDescriptor *)data_ptr);

	return 0;//success

}

void
FenceStateDescriptorIncrementReference (FenceStateDescriptor *descriptor_ptr, int multiples)
{
	RecyclerTypeReferenced (2, (RecyclerClientData *)descriptor_ptr, multiples);
}

void
FenceStateDescriptorDecrementReference (FenceStateDescriptor *descriptor_ptr, int multiples)
{
	RecyclerTypeUnReferenced (2, (RecyclerClientData *)descriptor_ptr, multiples);
}

inline unsigned
FenceStateDescriptorPoolTypeNumber()
{
	return FenceStateDescriptorPoolHandle->type;
}

/**
 * @brief Retrive a fresh instance from the recycler
 * @param ctx_data_ptr Context data to be passed to the initi function for Get
 * @param call_flags
 * @return
 */
InstanceHolderForFenceStateDescriptor *
FenceStateDescriptorGetInstance (ContextData *ctx_data_ptr, unsigned long call_flags)
{
	InstanceHolderForFenceStateDescriptor *instance_fstate_ptr = (InstanceHolderForFenceStateDescriptor *)RecyclerGet(FenceStateDescriptorPoolTypeNumber(), ctx_data_ptr, call_flags);
	if (unlikely(IS_EMPTY(instance_fstate_ptr)))	goto return_error;

	return instance_fstate_ptr;

	return_error:
	syslog(LOG_DEBUG, LOGSTR_INCONSISTENT_STATE, __func__, pthread_self(), (void *)0, 0UL, LOGCODE_PROTO_INCONSISTENT_STATE, "Could not get FenceStateDescriptor instance");
	return NULL;

}

int
FenceStateDescriptorReturnToRecycler (InstanceHolder *instance_older_ptr, ContextData *ctx_data_ptr, unsigned long call_flags)
{
	return RecyclerPut(FenceStateDescriptorPoolTypeNumber(), instance_older_ptr, (ContextData *)ctx_data_ptr, call_flags);
}
////end typePool  /////////////////////

void
SummariseUserFenceConfiguration (void)
{
	//MASTER_USER_FENCE_RDLOCK(SummariseUserFenceConfiguration);
	//SummariseFenceConfiguration (master_fence_registry_ptr, "UserFence");
	//MASTER_USER_FENCE_RWUNLOCK(SummariseUserFenceConfiguration);
}

void
SummariseBaseFenceConfiguration (void)
{
	//MASTER_BASE_FENCE_RDLOCK(SummariseBaseFenceConfiguration);
	//SummariseFenceConfiguration (master_base_fence_registry_ptr, "BaseFence");
	//MASTER_BASE_FENCE_RWUNLOCK(SummariseBaseFenceConfiguration);
}

//cross referenced reporting of users and fencesto check on the referencial integrity of lists across the network
static void SummariseFenceConfiguration (List *lst_ptr, const char *label)
{
	ListEntry *eptr;
	Fence *f_ptr;

	if (lst_ptr->nEntries == 0) {
		syslog (LOG_INFO, "%s: List has empty Fences in it '%d'", label, lst_ptr->nEntries);
		return;
	}

	syslog (LOG_INFO, ":::- Summary of %s Configuration Network wide -:::", label);
	syslog (LOG_INFO, "%s: List has '%d' Fences in it:", label, lst_ptr->nEntries);

	for (eptr=lst_ptr->head; eptr; eptr=eptr->next)
	{
	 f_ptr=(Fence *)eptr->whatever;
	 syslog (LOG_INFO, "%s: Fence: '%s'. ID: '%lu'. Number of Users: '%u' ",
			 label, f_ptr->fence_location.canonical_name, f_ptr->fence_id, f_ptr->fence_user_sessions_list.nEntries );
	 {//block1: fence list of users
		 ListEntry *eptr2;
		 SessionService *ss_ptr;
		 Session *sesn_ptr;
		 for (eptr2=f_ptr->fence_user_sessions_list.head; eptr2; eptr2=eptr2->next)
		 {
			 sesn_ptr=SessionOffInstanceHolder((InstanceHolderForSession *)eptr2->whatever);
			 ss_ptr=&(sesn_ptr->sservice);
			 syslog (LOG_INFO, "`-- User name: '%s'. User's Fence count: '%u'",
					 ss_ptr->user.user_details.user_name, SESSION_FENCE_LIST_SIZE(sesn_ptr));
			 {//block2 user list of fences
				 ListEntry *eptr3;
				 Fence *f_ptr2;
				 for (eptr3=SESSION_FENCE_LIST(sesn_ptr).head; eptr3; eptr3=eptr3->next)
				 {
					 f_ptr2=FenceOffInstanceHolder(FenceStateDescriptorOffInstanceHolder(((InstanceHolderForFenceStateDescriptor *)(eptr3->whatever)))->instance_holder_fence);
					 syslog (LOG_INFO, "`---- Fence: '%s'. Fence's User count: '%u' ",
							 f_ptr2->fence_location.canonical_name, f_ptr2->fence_user_sessions_list.nEntries);
				 }

			 }//block2

		 }
	 }//block 1

	}

}
