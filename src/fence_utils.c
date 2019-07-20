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
#include <utils_crypto.h>
#include <fence.h>
#include <fence_utils.h>
#include <fence_state.h>
#include <fence_permission.h>
#include <fence_proto.h>
#include <attachments.h>
#include <http_request_context_type.h>
#include <location.h>
#include <persistance.h>
#include <misc.h>
#include <nportredird.h>
#include <protocol_websocket.h>
#include <protocol_websocket_session.h>
#include <sessions_delegator_type.h>
#include <user_backend.h>
#include <command_controllers.h>
#include <UfsrvMessageQueue.pb-c.h>
#include <SignalService.pb-c.h>
#include <utf8proc.h>

extern __thread ThreadContext ufsrv_thread_context;

static UFSRVResult * _CacheBackendSearchFenceNameIndex (Session *sesn_ptr_carrier, const char *search_text, size_t count);

/**
 * 	@brief A quick a snappy way to check for existence of a given fence
 * 	@return RESULT_TYPE_SUCCESS with fid
 */
UFSRVResult *
CheckFenceNameForValidity (Session *sesn_ptr, Fence *f_ptr, const char *fname_new)
{
	if (strlen(fname_new) > CONFIG_MAX_FENCE_NAME_SIZE)	{_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_NAMING)}

	size_t cname_new_sz = strlen(FENCE_BASELOC(f_ptr))+strlen(fname_new)+1;
	char cname_new[cname_new_sz];
	snprintf(cname_new, cname_new_sz, "%s%s", FENCE_BASELOC(f_ptr), fname_new);
#define _FENCE_SEARCH_FLAGS (FENCE_CALLFLAG_SEARCH_BACKEND|FENCE_CALLFLAG_SNAPSHOT_INSTANCE)

	FindFenceByCanonicalName (sesn_ptr, (const char *)cname_new, NULL, _FENCE_SEARCH_FLAGS);
  InstanceHolder *instance_holder_ptr = SESSION_RESULT_USERDATA(sesn_ptr);
	if (IS_PRESENT(instance_holder_ptr)) {
	  Fence *f_ptr_found = (Fence *)GetInstance(instance_holder_ptr);
		unsigned long fid_found = FENCE_ID(f_ptr_found);
		if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA))  FenceReturnToRecycler(instance_holder_ptr, NULL, CALLFLAGS_EMPTY);

		_RETURN_RESULT_SESN(sesn_ptr, (uintptr_t)(void *)fid_found, RESULT_TYPE_ERR, RESCODE_FENCE_EXISTS)
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

#undef _FENCE_SEARCH_FLAGS
}

/**
 * 	@brief: this is all-in one cachback end fix for when updating fence name
 * 	@locked RD f_ptr: Although that can be relaxed the the old value is passed independently of the fence container object
 */
UFSRVResult *
CacheBackendUpdateFenceRegistry (Session *sesn_ptr, Fence *f_ptr, const char *fname_new, const char *cname_new)
{
	unsigned char 			*name_folded		=	NULL;
	PersistanceBackend	*pers_ptr=sesn_ptr->fence_cachebackend;

	utf8proc_map((const unsigned char *)FENCE_DNAME(f_ptr), 0, &name_folded, UTF8PROC_CASEFOLD | UTF8PROC_DECOMPOSE | UTF8PROC_NULLTERM);

	(*pers_ptr->send_command_multi)(sesn_ptr, SESSION_FENCE_CACHEBACKEND(sesn_ptr), "MULTI");
	(*pers_ptr->send_command_multi)(sesn_ptr, SESSION_FENCE_CACHEBACKEND(sesn_ptr), REDIS_CMD_GLOBAL_FENCE_REGO_REM, FENCE_CNAME(f_ptr), FENCE_ID(f_ptr));
	(*pers_ptr->send_command_multi)(sesn_ptr, SESSION_FENCE_CACHEBACKEND(sesn_ptr), REDIS_CMD_GLOBAL_FENCE_REGO_ADD, cname_new, FENCE_ID(f_ptr));
	(*pers_ptr->send_command_multi)(sesn_ptr, SESSION_FENCE_CACHEBACKEND(sesn_ptr), REDIS_CMD_FENCE_RECORDSET_NAME, FENCE_ID(f_ptr), fname_new, cname_new);
	(*pers_ptr->send_command_multi)(sesn_ptr, SESSION_FENCE_CACHEBACKEND(sesn_ptr), REDIS_CMD_GLOBAL_FENCE_NAMEINDEX_REM, name_folded, FENCE_ID(f_ptr), FENCE_CNAME(f_ptr), FENCE_LONGITUDE(f_ptr), FENCE_LATITUDE(f_ptr));
	free (name_folded);
	utf8proc_map((const unsigned char *)fname_new, 0, &name_folded, UTF8PROC_CASEFOLD | UTF8PROC_DECOMPOSE | UTF8PROC_NULLTERM);
	(*pers_ptr->send_command_multi)(sesn_ptr, 	SESSION_FENCE_CACHEBACKEND(sesn_ptr), REDIS_CMD_GLOBAL_FENCE_NAMEINDEX_ADD, name_folded, FENCE_ID(f_ptr), FENCE_CNAME(f_ptr), FENCE_LONGITUDE(f_ptr), FENCE_LATITUDE(f_ptr));
	free (name_folded);

	(*pers_ptr->send_command_multi)(sesn_ptr, SESSION_FENCE_CACHEBACKEND(sesn_ptr), "EXEC");

	size_t				i;
	size_t				actually_processed	=	7;
	size_t				commands_successful	=	actually_processed;
	redisReply		*replies[actually_processed];

	for (i=0; i<actually_processed; i++)
	{
		if ((RedisGetReply(sesn_ptr, pers_ptr, (void *)&replies[i])) != REDIS_OK)
		{
			commands_successful--;

			if ((replies[i] != NULL))
			{
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', idex:'%lu'): ERROR PROCESSING MULTI SET COMMAND. ERROR: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i, replies[i]->str);
			}
			else
			{
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', i:'%lu'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i);
			}
		}
	}//for

	//diagnostics
	if (commands_successful!=actually_processed)
	{
		for (i=0; i<actually_processed; i++)	if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
	}

	//verification block
	{
//the results are stored at last index EXEC_COMMAND_IDX: array corresponding with command-set size less MULTI/EXEC. Other idx locations are of reply type REDIS_REPLY_STATUS
#define EXEC_COMMAND_IDX actually_processed-1

		for (i=0; i<EXEC_COMMAND_IDX; i++)	if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);

		if (unlikely(IS_EMPTY(replies[EXEC_COMMAND_IDX])))//idx for EXEC, which is last
		{
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR: REDIS TRANSCTION ERROR: NULL COMMAND ARRAY RESPONSE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
		}

		if (replies[EXEC_COMMAND_IDX]->elements==actually_processed-2)
		{
			if (!(replies[EXEC_COMMAND_IDX]->element[0]->integer==1))	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', error:'%s'): ERROR: ZREM Failed", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), replies[EXEC_COMMAND_IDX]->element[0]->str);
			if (!(replies[EXEC_COMMAND_IDX]->element[1]->integer==1))	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', error:'%s'): ERROR: ZADD Failed", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), replies[EXEC_COMMAND_IDX]->element[1]->str);
			if (!(strcmp(replies[EXEC_COMMAND_IDX]->element[2]->str, "OK")==0))	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', error:'%s'): ERROR: HMSET Failed", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), replies[EXEC_COMMAND_IDX]->element[2]->str);

//			for (i=0; i<replies[EXEC_COMMAND_IDX]->elements; i++)
//			{
//				redisReply *redis_ptr_reply=replies[EXEC_COMMAND_IDX]->element[i];
//				//TODO: check the return value
//			}

			freeReplyObject(replies[EXEC_COMMAND_IDX]);
		}
		else
		{
			//Only remaining element is EXEC
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', dispatched:'%lu', received:'%lu', error:'%s'): ERROR: REDIS TRANSCTION ERROR: DISPATCHED/RECEIVED COMMANDS COUNT MISMATCH", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), actually_processed-2, replies[EXEC_COMMAND_IDX]->elements, replies[EXEC_COMMAND_IDX]->str);
			if (IS_PRESENT(replies[EXEC_COMMAND_IDX]))	freeReplyObject(replies[EXEC_COMMAND_IDX]);

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
		}
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);

#undef EXEC_COMMAND_IDX

}

/**
 * 	@brief: Main interface for adding new new fence record.
 */
UFSRVResult *
CacheBackendAddFenceRecord (Session *sesn_ptr, Fence *f_ptr, unsigned long fence_call_flags)
{
	FenceCacheBackend		*fence_backend_ptr	=	sesn_ptr->fence_cachebackend;
	unsigned char 			*name_folded		=	NULL;

	int									list_semantics	=	0;
	char 								*cname_scratch_buffer	=	strdupa(FENCE_CNAME(f_ptr));
	LocationDescription fence_location 				= {0};
	MapFenceLocationDescription (f_ptr, cname_scratch_buffer, &fence_location);

	list_semantics = FormatListSemanticsForPersistance(f_ptr);
	size_t commandset_size	=	10;

	(*fence_backend_ptr->send_command_multi)(sesn_ptr, SESSION_FENCE_CACHEBACKEND(sesn_ptr), "MULTI");
	(*fence_backend_ptr->send_command_multi)(sesn_ptr, 	SESSION_FENCE_CACHEBACKEND(sesn_ptr), REDIS_CMD_GLOBAL_FENCE_REGO_ADD, FENCE_CNAME(f_ptr), FENCE_ID(f_ptr));
	(*fence_backend_ptr->send_command_multi)(sesn_ptr, 	SESSION_FENCE_CACHEBACKEND(sesn_ptr), REDIS_CMD_FENCE_RECORD_SET_ALL,
																											FENCE_ID(f_ptr),
																											FENCE_ID(f_ptr),
																											f_ptr->attrs,
																											f_ptr->when,
																											FENCE_OWNER_UID(f_ptr),
																											f_ptr->fence_location.base_location,
																											f_ptr->fence_location.canonical_name,
																											f_ptr->fence_location.display_banner_name,
																											f_ptr->fence_location.base_location,//f_ptr->fence_location.banner_name,
																											/*"fence banner",*/
																											f_ptr->fence_location.fence_location.longitude,
																											f_ptr->fence_location.fence_location.latitude,
																											f_ptr->max_users,
																											f_ptr->time_to_live,
																											1UL,//event counter starts at 1 to mark the creation event. No explicit FenceEvent *
																											IS_PRESENT(f_ptr->avatar)?f_ptr->avatar:CONFIG_DEFAULT_PREFS_STRING_VALUE,
																											FENCE_MSG_EXPIRY(f_ptr),
																											list_semantics);

	////<%component>:<fid>>:<baseloc>:<longit>:<lat>
	if (*fence_location.country)		{
		utf8proc_map((const unsigned char *)fence_location.country, 0, &name_folded, UTF8PROC_CASEFOLD | UTF8PROC_DECOMPOSE | UTF8PROC_NULLTERM);
		(*fence_backend_ptr->send_command_multi)(sesn_ptr, 	SESSION_FENCE_CACHEBACKEND(sesn_ptr), REDIS_CMD_GLOBAL_FENCE_NAMEINDEX_ADD, name_folded, FENCE_ID(f_ptr), FENCE_CNAME(f_ptr), FENCE_LONGITUDE(f_ptr), FENCE_LATITUDE(f_ptr));
		free	(name_folded);
	} else commandset_size--;

	if (*fence_location.admin_area)	{
		utf8proc_map((const unsigned char *)fence_location.admin_area, 0, &name_folded, UTF8PROC_CASEFOLD | UTF8PROC_DECOMPOSE | UTF8PROC_NULLTERM);
		(*fence_backend_ptr->send_command_multi)(sesn_ptr, 	SESSION_FENCE_CACHEBACKEND(sesn_ptr), REDIS_CMD_GLOBAL_FENCE_NAMEINDEX_ADD, name_folded, FENCE_ID(f_ptr), FENCE_CNAME(f_ptr), FENCE_LONGITUDE(f_ptr), FENCE_LATITUDE(f_ptr));
		free (name_folded);
	} else commandset_size--;

	if (*fence_location.locality)		{
		utf8proc_map((const unsigned char *)fence_location.locality, 0, &name_folded, UTF8PROC_CASEFOLD | UTF8PROC_DECOMPOSE | UTF8PROC_NULLTERM);
		(*fence_backend_ptr->send_command_multi)(sesn_ptr, 	SESSION_FENCE_CACHEBACKEND(sesn_ptr), REDIS_CMD_GLOBAL_FENCE_NAMEINDEX_ADD, name_folded, FENCE_ID(f_ptr), FENCE_CNAME(f_ptr), FENCE_LONGITUDE(f_ptr), FENCE_LATITUDE(f_ptr));
		free (name_folded);
	} else commandset_size--;

	if (*fence_location.selfzone)		{
		(*fence_backend_ptr->send_command_multi)(sesn_ptr, 	SESSION_FENCE_CACHEBACKEND(sesn_ptr), REDIS_CMD_GLOBAL_FENCE_NAMEINDEX_SELZONE_ADD, SESSION_USERID(sesn_ptr), FENCE_ID(f_ptr), FENCE_CNAME(f_ptr), FENCE_LONGITUDE(f_ptr), FENCE_LATITUDE(f_ptr));
	} else commandset_size--;

	if (true)												{
		utf8proc_map((const unsigned char *)FENCE_DNAME(f_ptr), 0, &name_folded, UTF8PROC_CASEFOLD | UTF8PROC_DECOMPOSE | UTF8PROC_NULLTERM);
		(*fence_backend_ptr->send_command_multi)(sesn_ptr, 	SESSION_FENCE_CACHEBACKEND(sesn_ptr), REDIS_CMD_GLOBAL_FENCE_NAMEINDEX_ADD, name_folded, FENCE_ID(f_ptr), FENCE_CNAME(f_ptr), FENCE_LONGITUDE(f_ptr), FENCE_LATITUDE(f_ptr));
		free (name_folded);
	} else commandset_size--;

	(*fence_backend_ptr->send_command_multi)(sesn_ptr, 	SESSION_FENCE_CACHEBACKEND(sesn_ptr), REDIS_CMD_FENCE_GEOHASH_ADD, FENCE_LONGITUDE(f_ptr), FENCE_LATITUDE(f_ptr), FENCE_ID(f_ptr), GetFenceNetworkType(f_ptr));

	(*fence_backend_ptr->send_command_multi)(sesn_ptr, SESSION_FENCE_CACHEBACKEND(sesn_ptr), "EXEC");


	size_t				actually_processed	=	commandset_size;
	size_t				commands_successful	=	actually_processed;
	redisReply		*replies[actually_processed];
	memset (replies, 0, sizeof(replies));

	for (size_t i=0; i<actually_processed; i++)
	{
		if ((RedisGetReply(sesn_ptr, fence_backend_ptr, (void *)&replies[i])) != REDIS_OK)
		{
			commands_successful--;

			if ((replies[i] != NULL))
			{
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', idx:'%lu'): ERROR PROCESSING MULTI SET COMMAND. ERROR: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i, replies[i]->str);
			}
			else
			{
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', i:'%lu'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i);
			}
		}
	}//for

	//diagnostics
	if (commands_successful!=actually_processed)
	{
		for (size_t i=0; i<actually_processed; i++)	if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
	}

	//verification block
	{
//the results are stored at last index EXEC_COMMAND_IDX: array corresponding with command-set size less MULTI/EXEC. Other idx locations are of reply type REDIS_REPLY_STATUS
#define EXEC_COMMAND_IDX actually_processed-1

		for (size_t i=0; i<actually_processed-1; i++)	if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);

		if (unlikely(IS_EMPTY(replies[EXEC_COMMAND_IDX])))//idx for EXEC, which is last
		{
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR: REDIS TRANSCTION ERROR: NULL COMMAND ARRAY RESPONSE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
		}

		if (replies[EXEC_COMMAND_IDX]->elements==actually_processed-2)
		{
			//these should be contextual to the actual return codes for the above commands
			if (replies[EXEC_COMMAND_IDX]->element[0]->integer!=1)	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', integer:'%llu', error:'%s'): ERROR: ZADD Failed", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), replies[EXEC_COMMAND_IDX]->element[0]->integer, replies[EXEC_COMMAND_IDX]->element[0]->str);
			if (!(strcmp(replies[EXEC_COMMAND_IDX]->element[1]->str, "OK")==0))	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', error:'%s'): ERROR: HMSET Failed", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), replies[EXEC_COMMAND_IDX]->element[1]->str);
			if (replies[EXEC_COMMAND_IDX]->element[2]->integer!=1)	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', integer:'%llu', error:'%s'): ERROR: GEOADD Failed", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), replies[EXEC_COMMAND_IDX]->element[2]->integer, replies[EXEC_COMMAND_IDX]->element[2]->str);

			freeReplyObject(replies[EXEC_COMMAND_IDX]);
		}
		else
		{
			//only remaining element is at EXEC_COMMAND_IDX
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', dispatched:'%lu', received:'%lu'): ERROR: REDIS TRANSCTION ERROR: DISPATCHED/RECEIVED COMMANDS COUNT MISMATCH", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), actually_processed-2, replies[EXEC_COMMAND_IDX]->elements);
			if (IS_PRESENT(replies[EXEC_COMMAND_IDX]))	freeReplyObject(replies[EXEC_COMMAND_IDX]);

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
		}
	}


	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);

#undef EXEC_COMMAND_IDX

}

static inline UFSRVResult *_ResetMemberFencesForUser (InstanceHolderForSession *instance_sesn_ptr, unsigned long fence_call_flags);
static inline UFSRVResult *_ResetInvitedFencesForUser (InstanceHolderForSession *instance_sesn_ptr, unsigned long fence_call_flags);

/**
 * 	@brief: the main interface for removing user from fence with proper network-wide semantics
 * 	@locked sesn_ptr
 * 	@locked f_ptr
 */
UFSRVResult *
NetworkRemoveUserFromFence (InstanceHolderForSession *instance_sesn_ptr, Fence *f_ptr, CommandContextData *context_ptr, EnumFenceLeaveType leave_type, unsigned long call_flags_fence)
{
	unsigned long eid;
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	if ((eid = RemoveUserFromFence(instance_sesn_ptr, f_ptr, call_flags_fence)) != 0) {
		MarshalFenceStateSyncForLeave (sesn_ptr, sesn_ptr, f_ptr, (DataMessage *)context_ptr, leave_type);
		return SESSION_RESULT_PTR(sesn_ptr);
	} else {
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', fo:'%p', cid:'%lu', cname:'%s'): COULD NOT complete user removal from fence", __func__, pthread_self(), sesn_ptr, f_ptr, SESSION_ID(sesn_ptr), FENCE_CNAME(f_ptr));
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_FENCE_MEMBERSHIP);
}

/**
 * 	@brief: the main interface for removing user from invited fence with proper network-wide semantics
 * 	@locked sesn_ptr
 * 	@locked f_ptr
 */
UFSRVResult *
NetworkRemoveUserFromInvitedFence (InstanceHolderForSession *instance_sesn_ptr, Fence *f_ptr, CommandContextData *context_ptr, EnumFenceLeaveType leave_type, unsigned long call_flags_fence)
{
	unsigned long eid;
	InstanceHolderForFenceStateDescriptor *instance_fstate_ptr;
	Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	if (IS_PRESENT((instance_fstate_ptr = IsUserMemberOfThisFence (SESSION_INVITED_FENCE_LIST_PTR(sesn_ptr), f_ptr, false)))) {
		FenceEvent fence_event = {0};	fence_event.event_type = EVENT_TYPE_FENCE_USER_INVITEREJECTED;

    RemoveUserFromInvitedList(instance_sesn_ptr, FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr), &fence_event, FENCE_CALLFLAG_WRITEBACK_DATA_TO_BACKEND);
		//TODO if  inviter is still on fence  marshal event
		//MarshalFenceStateSyncForLeave (sesn_ptr, sesn_ptr, f_ptr, (DataMessage *)context_ptr, leave_type);
		return SESSION_RESULT_PTR(sesn_ptr);
	} else {
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', fo:'%p', cid:'%lu', list_sz:'%u'): COULD NOT REMOVE USER FROM INVITED LIST: NOT MEMBER", __func__, pthread_self(), sesn_ptr, f_ptr, SESSION_ID(sesn_ptr), SESSION_INVITED_FENCE_LIST_SIZE(sesn_ptr));
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_FENCE_MEMBERSHIP)
}

static UFSRVResult *_CacheBackendCleanUpStaleMemberFenceRecordsForUser (Session *sesn_ptr_carrier, unsigned long userid, CollectionDescriptor *collection_ptr, CollectionDescriptor *by_collection_ptr, unsigned long call_flags_fence);

/**
 * @brief: List processed is based on freshly fetched cachbackend record, but member-comparison is based on memory-loaded fence membership, with
 * the option of loading from caches backend where fence instance is not already loaded. However, existing fences are not reloaded.
 * This limits this function to stateful instances only.
 * 	@stack_overflow: watch out for VLA objects...
 * 	@dynamic_memory fence_collection.collection_t: IMPORTS and DEALLOCATES
 * 	@dynamic_memory byids_collection.collection_t: IMPORTS and DEALLOCATES
 */
static inline UFSRVResult *
_ResetMemberFencesForUser (InstanceHolderForSession *instance_sesn_ptr, unsigned long fence_call_flags)
{
	CollectionDescriptor	fence_collection = {0};
	CollectionDescriptor	byids_collection = {0};
	CollectionDescriptor	*fence_collection_ptr __attribute__((unused));

	Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	fence_collection_ptr = GetFenceCollectionForUser (sesn_ptr, &fence_collection, &byids_collection, MEMBER_FENCES);

	size_t			i;
	unsigned long	*fence_ids = (unsigned long *)fence_collection.collection;
	unsigned long	*fence_byids = (unsigned long *)byids_collection.collection;

	if (fence_collection.collection_sz == 0) {
		//no need as we get no allocation upon empty set
		//if (!(IS_EMPTY(fence_collection_ptr)))	DestructFenceCollection (&fence_collection, false);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EMPTYSET)
	}

	unsigned long fence_call_flags_search =	FENCE_CALLFLAG_SEARCH_BACKEND|FENCE_CALLFLAG_HASH_FENCE_LOCALLY|
																					FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE|FENCE_CALLFLAG_KEEP_FENCE_LOCKED|FENCE_CALLFLAG_LOCK_FENCE_BLOCKING;

	size_t				fence_ids_orphaned_counter	=	0,
								fences_stale_counter				=	0;

	unsigned long fence_ids_orphaned[fence_collection.collection_sz];//fences for which no entity can be loaded
	unsigned long fences_ids_stale[fence_collection.collection_sz];	//fence standalone entity exists, but not on user's list
	unsigned long fence_byids_stale[fence_collection.collection_sz];	//fence standalone entity exists, but not on user's list

	CollectionDescriptor	fence_ids_orphaned_collection = {.collection=(collection_t **)fence_ids_orphaned, .collection_sz=0};
	CollectionDescriptor	fence_ids_stale_collection 		= {.collection=(collection_t **)fences_ids_stale, .collection_sz=0};
	CollectionDescriptor	fence_byids_collection 				= {.collection=(collection_t **)fence_byids_stale, .collection_sz=0};

	memset (fence_ids_orphaned, 0, sizeof fence_ids_orphaned);
	memset(fences_ids_stale, 0, sizeof fences_ids_stale);
	memset(fence_byids_stale, 0, sizeof fence_byids_stale);

	Fence *f_ptr;
	InstanceHolderForFence *instance_f_ptr;

	for (i=0; i<fence_collection.collection_sz; i++) {
			FindFenceById(sesn_ptr, fence_ids[i], fence_call_flags_search);//blocking lock
    instance_f_ptr = (InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr);
			bool fence_lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_PROG_LOCKED_THIS_THREAD));

			if (unlikely(IS_EMPTY(instance_f_ptr))) {
				//only do this if fence not found. Error could be related to locking, but that is not treated
				if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST)|| SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_RESOURCE_NULL)) {
					fence_ids_orphaned[fence_ids_orphaned_counter++]	=	fence_ids[i];
					continue;
				} else {
					syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu', uid:'%lu', fid:'%lu'}: LOCKING ERROR: COULD NOT LOAD FENCE REFERENCED IN USER'S MEMBERS LIST: NOT ADDING TO ORPHAN LIST", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_USERID(sesn_ptr), fence_ids[i]);
				}
			}

		//>>> FENCE SHOULD BE IN RW LOCKED STATE
		f_ptr = FenceOffInstanceHolder(instance_f_ptr);

		NetworkRemoveUserFromFence (instance_sesn_ptr, f_ptr, NULL, LT_USER_INITIATED, CALLFLAGS_EMPTY);
		if (SESSION_RESULT_TYPE_ERROR(sesn_ptr)) {
			fences_ids_stale[fences_stale_counter]	=	FENCE_ID(f_ptr);
			fence_byids_stale[fences_stale_counter]	=	fence_byids[i];
			fences_stale_counter++;
		}

		if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
	}

	fence_ids_orphaned_collection.collection_sz	=	fence_ids_orphaned_counter;
	if (fence_ids_orphaned_collection.collection_sz > 0) {
		//TODO: clean orphan backend entry
		syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu', uid:'%lu', count:'%lu'}: DATA ERROR: CLEANING ORPHANED FENCE IDS: NOT IMPLEMENTED", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_USERID(sesn_ptr), fence_ids_orphaned_collection.collection_sz);
	}

	fence_ids_stale_collection.collection_sz	=	fences_stale_counter;
	fence_byids_collection.collection_sz			=	fences_stale_counter;
	if (fence_ids_stale_collection.collection_sz > 0) {
		//TODO: clean BACKEND collection for user  UF:<uid>
		syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu', uid:'%lu', count:'%lu'}: DATA ERROR: CLEANING STALE FENCE COLLECTION", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_USERID(sesn_ptr), fence_ids_stale_collection.collection_sz);

		_CacheBackendCleanUpStaleMemberFenceRecordsForUser (sesn_ptr, SESSION_USERID(sesn_ptr), &fence_ids_stale_collection, &fence_byids_collection, FENCE_CALLFLAG_EMPTY);
	}

	DestructFenceCollection (&fence_collection, false);
	DestructFenceCollection (&byids_collection, false);

	return SESSION_RESULT_PTR(sesn_ptr);
}

/**
 * 	@brief: This performs cache backend cleanup, whilst catering for a specific usecase whereby the cachebackend has fence entries for user under UF:<uid>, but those fences have no
 * 	reciprocal relationships with the user, mostly based on memory based assessment. So, we go ahead and clean up those cachebackend entries
 * 	@param  collection_ptr: collection of fence ids
 */
static UFSRVResult *
_CacheBackendCleanUpStaleMemberFenceRecordsForUser (Session *sesn_ptr_carrier, unsigned long userid, CollectionDescriptor *fence_ids_collection_ptr, CollectionDescriptor *byids_collection_ptr, unsigned long call_flags_fence)
{
	PersistanceBackend	*pers_ptr		=	sesn_ptr_carrier->persistance_backend;
	unsigned long 			*fence_ids	= (unsigned long *)fence_ids_collection_ptr->collection_sz;
	unsigned long 			*byids			= (unsigned long *)byids_collection_ptr->collection_sz;
#define COMANDSET_PER_USER	2

	(*pers_ptr->send_command_multi)(sesn_ptr_carrier, "MULTI");

	for (size_t i =0; i<fence_ids_collection_ptr->collection_sz; i++)
	{
		(*pers_ptr->send_command_multi)(sesn_ptr_carrier,  REDIS_CMD_FENCE_USERS_LIST_REM, fence_ids[i], userid);
		(*pers_ptr->send_command_multi)(sesn_ptr_carrier,  REDIS_CMD_USER_FENCE_LIST_REM, fence_ids[i], userid, byids[i]);
	}

	(*pers_ptr->send_command_multi)(sesn_ptr_carrier,  "EXEC");

	size_t				i;
	size_t				actually_processed	=	COMANDSET_PER_USER*fence_ids_collection_ptr->collection_sz + 2;
	size_t				commands_successful	=	actually_processed;
	redisReply		*replies[actually_processed];

	for (i=0; i<actually_processed; i++)
	{
		if ((RedisGetReply(sesn_ptr_carrier, pers_ptr, (void *)&replies[i])) != REDIS_OK)
		{
			commands_successful--;

			if ((replies[i] != NULL))
			{
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', idex:'%lu'): ERROR PROCESSING MULTI SET COMMAND. ERROR: '%s'", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), i, replies[i]->str);
			}
			else
			{
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', i:'%lu'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), i);
			}
		}
	}//for

	//diagnostics
	if (commands_successful!=actually_processed)
	{
		for (i=0; i<actually_processed; i++)	if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);

		_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
	}

	//verification block
	{
//the results are stored at last index EXEC_COMMAND_IDX: array corresponding with command-set size less MULTI/EXEC. Other idx locations are of reply type REDIS_REPLY_STATUS
#define EXEC_COMMAND_IDX actually_processed-1

		for (i=0; i<EXEC_COMMAND_IDX; i++)	if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);

		if (unlikely(IS_EMPTY(replies[EXEC_COMMAND_IDX])))//idx for EXEC, which is last
		{
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR: REDIS TRANSCTION ERROR: NULL COMMAND ARRAY RESPONSE", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier));

			_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
		}

		if (replies[EXEC_COMMAND_IDX]->elements==actually_processed-2)
		{
			for (i=0; i<replies[EXEC_COMMAND_IDX]->elements; i++)
			{
				redisReply *redis_ptr_reply=replies[EXEC_COMMAND_IDX]->element[i];
				if (!(replies[EXEC_COMMAND_IDX]->element[0]->integer==1))	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', fid:'%lu', idx:'%lu', error:'%s'): ERROR: ZREM Failed", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), fence_ids[i], i, replies[EXEC_COMMAND_IDX]->element[0]->str);
			}

			freeReplyObject(replies[EXEC_COMMAND_IDX]);
		}
		else
		{
			//Only remaining element is EXEC
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', dispatched:'%lu', received:'%lu', error:'%s'): ERROR: REDIS TRANSCTION ERROR: DISPATCHED/RECEIVED COMMANDS COUNT MISMATCH", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), actually_processed-2, replies[EXEC_COMMAND_IDX]->elements, replies[EXEC_COMMAND_IDX]->str);
			if (IS_PRESENT(replies[EXEC_COMMAND_IDX]))	freeReplyObject(replies[EXEC_COMMAND_IDX]);

			_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
		}
	}

	_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);

#undef EXEC_COMMAND_IDX
#undef COMANDSET_PER_USER
}

static inline UFSRVResult *
_ResetInvitedFencesForUser (InstanceHolderForSession *instance_sesn_ptr, unsigned long fence_call_flags)
{
	CollectionDescriptor	fence_collection = {0};
	CollectionDescriptor	*fence_collection_ptr __attribute__((unused));

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	fence_collection_ptr = GetFenceCollectionForUser (sesn_ptr, &fence_collection, NULL, INVITED_FENCES);

	size_t			i;
	unsigned long	*fence_ids = (unsigned long *)fence_collection.collection;

	if (fence_collection.collection_sz == 0) {
		//no need as we get no allocation upon empty set
		//if (!(IS_EMPTY(fence_collection_ptr)))	DestructFenceCollection (&fence_collection, false);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EMPTYSET);
	}

	unsigned long fence_call_flags_search =	FENCE_CALLFLAG_SEARCH_BACKEND|FENCE_CALLFLAG_HASH_FENCE_LOCALLY|
																		      FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE|FENCE_CALLFLAG_KEEP_FENCE_LOCKED|FENCE_CALLFLAG_LOCK_FENCE_BLOCKING;

	size_t				fence_ids_orphaned_counter	=	0;
	unsigned long fence_ids_orphaned[fence_collection.collection_sz];
	CollectionDescriptor	fence_ids_orphaned_collection = {.collection=(collection_t **)fence_ids_orphaned, .collection_sz=0};

	size_t				sesn_fence_list_orphaned_counter	=	0;
	unsigned long sesn_fence_list_ids_orphaned[fence_collection.collection_sz];
	CollectionDescriptor	sesn_fence_list_ids_orphaned_collection = {.collection=(collection_t **)sesn_fence_list_ids_orphaned, .collection_sz=0};

	Fence *f_ptr;
	FenceStateDescriptor *fence_state_ptr;
  InstanceHolderForFence *instance_f_ptr;
  InstanceHolderForFenceStateDescriptor *instance_fstate_ptr;

	for (i=0; i<fence_collection.collection_sz; i++) {
		FindFenceById (sesn_ptr, fence_ids[i], fence_call_flags_search);//blocking lock requested
    instance_f_ptr = (InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr);
		bool lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_PROG_LOCKED_THIS_THREAD));

		if (unlikely(IS_EMPTY(instance_f_ptr))) {
			//only do this if fence not found. Error could be related to locking, but that is not treated
			if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_FENCE_DOESNT_EXIST) || SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_RESOURCE_NULL)) {
				fence_ids_orphaned[fence_ids_orphaned_counter++]	=	fence_ids[i];

				continue;
			} else {
				syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu', uid:'%lu', fid:'%lu'}: LOCKING ERROR: COULD NOT LOAD FENCE REFERENCED IN USER'S MEMBERS LIST: NOT ADDING TO ORPHAN LIST", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_USERID(sesn_ptr), fence_ids[i]);
			}
		}

		//>>> FENCE SHOULD BE IN RW LOCKED STATE

		f_ptr = FenceOffInstanceHolder(instance_f_ptr);

		if (!IS_PRESENT((instance_fstate_ptr = FindFenceStateInSessionFenceListByFenceId(sesn_ptr, SESSION_INVITED_FENCE_LIST_PTR(sesn_ptr), FENCE_ID(f_ptr))))) {
#ifdef __UF_TESTING
			syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu', uid:'%lu', fid:'%lu'}: DATA ERROR: COULD NOT LOAD FENCE STATE REFERENCED IN USER'S MEMBERS LIST", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_USERID(sesn_ptr), fence_ids[i]);
#endif
			sesn_fence_list_ids_orphaned[sesn_fence_list_orphaned_counter++]	=	fence_ids[i];

			if (!lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));

			continue;
		}

		fence_state_ptr = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
		assert (f_ptr == FENCESTATE_FENCE(fence_state_ptr));

		//this draws an event, unlike when uninvited due to fence fence being joined
		FenceEvent fence_event = {0};	fence_event.event_type = EVENT_TYPE_FENCE_USER_UNINVITED;

    RemoveUserFromInvitedList(instance_sesn_ptr, fence_state_ptr, &fence_event, FENCE_CALLFLAG_WRITEBACK_DATA_TO_BACKEND);
		if (!lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
	}

	fence_ids_orphaned_collection.collection_sz						=	fence_ids_orphaned_counter;
	sesn_fence_list_ids_orphaned_collection.collection_sz	=	sesn_fence_list_orphaned_counter;

	if (fence_ids_orphaned_collection.collection_sz > 0) {
		//TODO: clean orphan backend entry
		syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu', uid:'%lu', list_sz:'%lu'}: DATA ERRORS: COULD NOT LOAD FENCES FROM REGISTRY: CLEANUP NOT IMPLEMENTED", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_USERID(sesn_ptr), fence_ids_orphaned_collection.collection_sz);
	}

	if (sesn_fence_list_ids_orphaned_collection.collection_sz > 0) {
		//TODO: clean orphan backend entry
		syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu', uid:'%lu', list_sz:'%lu'}: DATA ERRORS: COULD NOT LOAD FENCE STATES REFERENCED IN USER'S MEMBERS LIST: CLEANUP NOT IMPLEMENTED", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_USERID(sesn_ptr), sesn_fence_list_ids_orphaned_collection.collection_sz);
	}

	DestructFenceCollection (&fence_collection, false);

	return SESSION_RESULT_PTR(sesn_ptr);
}

/**
 * 	@brief: Main interface for reseting user's fence membership with full network visibility, as if the user initiated the command.
 * 	To ensure proper clean up, the backend is queried first and locall memory resident is cross checked at the end.
 */
UFSRVResult *
ResetFencesForUser (InstanceHolderForSession *instance_sesn_ptr, EnumFenceCollectionType collection_type)
{
	switch (collection_type)
	{
	case MEMBER_FENCES:
		return _ResetMemberFencesForUser (instance_sesn_ptr, 0);

	case INVITED_FENCES:
		return _ResetInvitedFencesForUser (instance_sesn_ptr, 0);

	case BLOCKED_FENCES:
	case LIKED_FENCES:
	case FAVED_FENCES:
	case ALL_FENCES:
	default:
		break;
	}

	return SESSION_RESULT_PTR(SessionOffInstanceHolder(instance_sesn_ptr));
}

static UFSRVResult *_CacheBackendGetFencesNearByIndex (Session *sesn_ptr_carrier, float longitude, float latitude, size_t radius, size_t count);
static UFSRVResult *_CacheBackendGetFencesNearByIndexRecords (Session *sesn_ptr, redisReply *redis_ptr);
static inline char * _ParseFenceIdValue (char *raw_record);

//"376530017196179457:2:"
static inline char *
_ParseFenceIdValue (char *raw_record)
{
	char *marker	=	 NULL;
	if (IS_PRESENT((marker=strchr(raw_record, ':'))))	{
		*marker='\0';
		marker=raw_record;
	}

	return marker;
}

/**
 * @return redisReply *: contains array of unparsed fence records, each of which is an array corresponding with individual record fields
 * 												IMPORTANT: must check for null entries in the list.
 * @dynamic_memory: EXPORTS 'redisReply *'. USER MUST DEALLOCATE
 */
UFSRVResult *
GetFencesNearByIndexRecords (Session *sesn_ptr_carrier, float longitude, float latitude, size_t radius, size_t count)
{
	_CacheBackendGetFencesNearByIndex (sesn_ptr_carrier, longitude, latitude, radius, count);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr_carrier))	return _CacheBackendGetFencesNearByIndexRecords (sesn_ptr_carrier, (redisReply *)SESSION_RESULT_USERDATA(sesn_ptr_carrier));

	return SESSION_RESULT_PTR(sesn_ptr_carrier);

}

/**
 * 	@IMPORTANT: we are not using local fence cache for this as we don't want inflate the size of the internal cache, so we return raw record to the user
 * 	redis_ptr: contains array of unparsed GEO records, each of which is an array corresponding with individual record fields
 * 	@dynamic_memory: EXPORTS redisReply * USER MUST DEALLOCATE
 * 	@dynamic_memory: DEALLOCATES provided redis_ptr
 */
static UFSRVResult *
_CacheBackendGetFencesNearByIndexRecords (Session *sesn_ptr, redisReply *redis_ptr)
{
	size_t 								valid_fids_sz;
	FenceCacheBackend			*fence_backend_ptr	=	SESSION_FENCE_CACHEBACKEND(sesn_ptr);

	if ((valid_fids_sz=redis_ptr->elements)==0)	{
		freeReplyObject(redis_ptr);
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EMPTYSET);
	}

	//TODO: do we actually need a transaction for this? if you remove it, remove '+ 2' from 'actually_processed' below
	(*fence_backend_ptr->send_command_multi)(sesn_ptr, SESSION_FENCE_CACHEBACKEND(sesn_ptr), "MULTI");

	for (size_t i=0; i<redis_ptr->elements; i++)
	{
		const char 		*fid_str	=	_ParseFenceIdValue(redis_ptr->element[i]->str);
		unsigned long fid;

		if (IS_STR_LOADED(fid_str) && ((fid=strtoul(fid_str, NULL, 10))>0))
					(*fence_backend_ptr->send_command_multi)(sesn_ptr, 	SESSION_FENCE_CACHEBACKEND(sesn_ptr), REDIS_CMD_FENCE_RECORD_GET_ALL, fid);
		else	valid_fids_sz--;
	}

	(*fence_backend_ptr->send_command_multi)(sesn_ptr, SESSION_FENCE_CACHEBACKEND(sesn_ptr), "EXEC");

	size_t				actually_processed	=	valid_fids_sz + 2;// +2 for MULTI/EXEC
	size_t				commands_successful	=	actually_processed;
	redisReply		*replies[actually_processed];

	memset (replies, 0, sizeof(replies));

	for (size_t i=0; i<actually_processed; i++)
	{
		if ((RedisGetReply(sesn_ptr, fence_backend_ptr, (void *)&replies[i])) != REDIS_OK)
		{
			commands_successful--;

			if ((replies[i] != NULL))
			{
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', idx:'%lu'): ERROR PROCESSING MULTI SET COMMAND. ERROR: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i, replies[i]->str);
			}
			else
			{
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', i:'%lu'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i);
			}
		}
	}//for

	//diagnostics
	if (commands_successful!=actually_processed)
	{
		for (size_t i=0; i<actually_processed; i++)	if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);

		freeReplyObject(redis_ptr);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
	}

	//verification block
	{
#define EXEC_COMMAND_IDX actually_processed-1

		for (size_t i=0; i<actually_processed-1; i++)	if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);

		if (unlikely(IS_EMPTY(replies[EXEC_COMMAND_IDX])))//idx for EXEC, which is last
		{
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR: REDIS TRANSCTION ERROR: NULL COMMAND ARRAY RESPONSE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

			freeReplyObject(redis_ptr);

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
		}

		if (replies[EXEC_COMMAND_IDX]->elements==actually_processed-2)
		{
			for (size_t i=0; i<replies[EXEC_COMMAND_IDX]->elements; i++)
			{
				if (IS_EMPTY(replies[EXEC_COMMAND_IDX]->element[i]->element[0]->str) || (replies[EXEC_COMMAND_IDX]->element[i]->type!=REDIS_REPLY_ARRAY))
				{
					syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', idx:'%lu', error:'%s'): ERROR: HMGET COMMAND FAILED", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i, replies[EXEC_COMMAND_IDX]->element[i]->str);
					freeReplyObject(replies[EXEC_COMMAND_IDX]->element[i]);
					replies[EXEC_COMMAND_IDX]->element[i]=NULL;
				}
			}
		}
		else
		{
			//only remaining element is at EXEC_COMMAND_IDX
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', dispatched:'%lu', received:'%lu'): ERROR: REDIS TRANSCTION ERROR: DISPATCHED/RECEIVED COMMANDS COUNT MISMATCH", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), actually_processed-2, replies[EXEC_COMMAND_IDX]->elements);
			if (IS_PRESENT(replies[EXEC_COMMAND_IDX]))	freeReplyObject(replies[EXEC_COMMAND_IDX]);

			freeReplyObject(redis_ptr);

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
		}
	}


	freeReplyObject(redis_ptr);

	_RETURN_RESULT_SESN(sesn_ptr, replies[EXEC_COMMAND_IDX], RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);

#undef EXEC_COMMAND_IDX

}

/**
 * 	@returns redisReply *: containing unparsed records. No check is performed on setsize being zero
 * 	@dynamic_memory: EXPORTS redisReply * WHICH MUST BE DEALLOCATED BY USER
 */
static UFSRVResult *
_CacheBackendGetFencesNearByIndex (Session *sesn_ptr_carrier, float longitude, float latitude, size_t radius, size_t count)
{
	int rescode	=	RESCODE_BACKEND_CONNECTION;

	FenceCacheBackend		*pers_ptr					=	SESSION_FENCE_CACHEBACKEND(sesn_ptr_carrier);
	redisReply 					*redis_ptr				=	NULL;

	//this command will return "" string if set does not exist, ie does not communicate error in that sense
	if (count>0)	{
		if (!(redis_ptr=(*pers_ptr->send_command)(sesn_ptr_carrier, SESSION_FENCE_CACHEBACKEND(sesn_ptr_carrier), REDIS_CMD_FENCE_NEARBY_LOC_GET_WITH_COUNT, longitude, latitude, radius, count)))	goto return_redis_error;
	}
	else{
		if (!(redis_ptr=(*pers_ptr->send_command)(sesn_ptr_carrier, SESSION_FENCE_CACHEBACKEND(sesn_ptr_carrier), REDIS_CMD_FENCE_NEARBY_LOC_GET, longitude, latitude, radius)))	goto return_redis_error;
	}

	if (redis_ptr->type==REDIS_REPLY_ARRAY)
	{
		_RETURN_RESULT_SESN(sesn_ptr_carrier, redis_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);
	}

	if (redis_ptr->type==REDIS_REPLY_ERROR)	goto return_redis_error;
	if (redis_ptr->type==REDIS_REPLY_NIL)		goto return_redis_error;

	return_redis_error:
	if (IS_EMPTY(redis_ptr))
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier));
	 goto return_error;
	}
	if (redis_ptr->type==REDIS_REPLY_ERROR)
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), redis_ptr->str);
	 rescode=RESCODE_BACKEND_DATA; goto return_error_deallocate;
	}
	if (redis_ptr->type==REDIS_REPLY_NIL)
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: NIL SET",  __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier));
	 rescode=RESCODE_BACKEND_DATA; goto return_error_deallocate;
	}

	return_error_deallocate:
	freeReplyObject(redis_ptr);

	return_error:
	_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, rescode);

}

static UFSRVResult *
_CacheBackendSearchFenceNameIndex (Session *sesn_ptr_carrier, const char *search_text, size_t count)
{
	int rescode	=	RESCODE_BACKEND_CONNECTION;

	//utf8proc_uint8_t 		*normalised_search_text	=	utf8proc_NFD((const utf8proc_uint8_t *)search_text);
	unsigned char *search_text_folded;
	utf8proc_map((const unsigned char *)search_text/*normalised_search_text*/, 0, &search_text_folded, UTF8PROC_CASEFOLD | UTF8PROC_DECOMPOSE | UTF8PROC_NULLTERM);
	FenceCacheBackend		*pers_ptr								=	SESSION_FENCE_CACHEBACKEND(sesn_ptr_carrier);
	redisReply 					*redis_ptr							=	NULL;

	//this command will return "" string if set does not exist, ie does not communicate error in that sense
	if (count>0)	{
		if (!(redis_ptr=(*pers_ptr->send_command)(sesn_ptr_carrier, SESSION_FENCE_CACHEBACKEND(sesn_ptr_carrier), REDIS_CMD_GLOBAL_FENCE_NAMEINDEX_GET_WITHLIMIT, search_text_folded, search_text_folded, 0, count)))	goto return_redis_error;
	}
	else {
		if (!(redis_ptr=(*pers_ptr->send_command)(sesn_ptr_carrier, SESSION_FENCE_CACHEBACKEND(sesn_ptr_carrier), REDIS_CMD_GLOBAL_FENCE_NAMEINDEX_GET, search_text_folded, search_text_folded)))	goto return_redis_error;
	}

	if (redis_ptr->type==REDIS_REPLY_ARRAY)
	{
//		free(normalised_search_text);
		free(search_text_folded);
		_RETURN_RESULT_SESN(sesn_ptr_carrier, redis_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);
	}

	if (redis_ptr->type==REDIS_REPLY_ERROR)	goto return_redis_error;
	if (redis_ptr->type==REDIS_REPLY_NIL)		goto return_redis_error;

	return_redis_error:
	if (IS_EMPTY(redis_ptr))
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier));
	 goto return_error;
	}
	if (redis_ptr->type==REDIS_REPLY_ERROR)
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), redis_ptr->str);
	 rescode=RESCODE_BACKEND_DATA; goto return_error_deallocate;
	}
	if (redis_ptr->type==REDIS_REPLY_NIL)
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: NIL SET",  __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier));
	 rescode=RESCODE_BACKEND_DATA; goto return_error_deallocate;
	}

	return_error_deallocate:
//	free (normalised_search_text);
	free (search_text_folded);
	freeReplyObject(redis_ptr);

	return_error:
	_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, rescode);

}

/**
 * "ZADD" "FENCES_NAMEINDEX" "0" "Woronora:379423644163506195:Australia:New South Wales:Woronora:::151.035393:-34.026777"
 */
UFSRVResult *
SearchMatchingFencesWithRawResultsPacked (Session *sesn_ptr_carrier, const char *search_text, size_t count, BufferDescriptor *buffer_descriptor_ptr_out)
{
	redisReply *redis_ptr = NULL;

	_CacheBackendSearchFenceNameIndex (sesn_ptr_carrier, search_text, count);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr_carrier))	redis_ptr=SESSION_RESULT_USERDATA(sesn_ptr_carrier);
	if (IS_PRESENT(redis_ptr))
	{
		if (redis_ptr->elements==0)
		{
			freeReplyObject (redis_ptr);
			_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA_EMPTYSET);
		}

		FencesSearch 										search_result=FENCES_SEARCH__INIT;
		FencesSearch__RawResultRecord 	*raw_records_ptr[redis_ptr->elements];
		FencesSearch__RawResultRecord		raw_records[redis_ptr->elements];

		memset (raw_records, 0, sizeof raw_records);
		search_result.raw_results				=	raw_records_ptr;
		search_result.n_raw_results			=	redis_ptr->elements;

		for (size_t i=0; i<redis_ptr->elements; i++)
		{
			raw_records_ptr[i]					=	&raw_records[i];
			fences_search__raw_result_record__init(raw_records_ptr[i]);

			raw_records[i].raw_payload 	= redis_ptr->element[i]->str;
		}

		buffer_descriptor_ptr_out->size			=	fences_search__get_packed_size(&search_result);
		buffer_descriptor_ptr_out->data			=	calloc(1, buffer_descriptor_ptr_out->size);
		fences_search__pack (&search_result, (unsigned char *)buffer_descriptor_ptr_out->data);
		buffer_descriptor_ptr_out->size_max	=	redis_ptr->elements;

		freeReplyObject (redis_ptr);

		_RETURN_RESULT_SESN(sesn_ptr_carrier, buffer_descriptor_ptr_out, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);
	}

	return_no_results:
	return SESSION_RESULT_PTR(sesn_ptr_carrier);
}

/**
 * 	@brief: This is specifically handles fence avatars, which currently uses AttachmentPointer as opposed to AttachmentRecord.
 * 	When successfull, a permanent record is created in the DbBackend. This does not utilise lru.
 * 	@locked sesn_ptr:
 * 	@locked RW f_ptr:
 */
UFSRVResult *
CheckAvatarForValidityFromProto (Session *sesn_ptr, Fence *f_ptr, DataMessage *data_msg_ptr)
{
	GroupContext 					*gctx_ptr							=	data_msg_ptr->group;
	FenceCommand 					*fcmd_ptr							=	data_msg_ptr->ufsrvcommand->fencecommand;
	AttachmentPointer 		*attachment_ptr				=	NULL;

	if (!(IS_EMPTY(fcmd_ptr)))
	{
		if (data_msg_ptr->n_attachments)
		{
			attachment_ptr=data_msg_ptr->attachments[0];
#ifdef __UF_TESTING
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', group_name:'%s' attachment_id:'%s', content_type:'%s' thumbnail:'%d' key:'%d'}: RECIEVED ATTACHMENT", __func__, pthread_self(), sesn_ptr,  fcmd_ptr->fences[0]->fname, attachment_ptr->ufid, attachment_ptr->contenttype, attachment_ptr->has_thumbnail, attachment_ptr->has_key);
#endif
		}

		if (IS_PRESENT(gctx_ptr->avatar))
		{
			attachment_ptr=gctx_ptr->avatar;
#ifdef __UF_TESTING
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', group_name:'%s' attachment_id:'%s', content_type:'%s' thumbnail:'%d' key:'%d'}: RECIEVED GROUP AVATAR", __func__, pthread_self(), sesn_ptr,  fcmd_ptr->fences[0]->fname, attachment_ptr->ufid, attachment_ptr->contenttype, attachment_ptr->has_thumbnail, attachment_ptr->has_key);
#endif
			if (strlen(attachment_ptr->ufid)>CONFIG_MAX_FAVATAR_SIZE)	{_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_NAMING);}

			if (IS_STR_LOADED(FENCE_AVATAR(f_ptr)))	if ((strcasecmp(FENCE_AVATAR(f_ptr), attachment_ptr->ufid)==0)) {_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOGIC_IDENTICAL_RESOURCE);}

			return_success:
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);
		}
	}

	exit_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);

}

/**
 * 	@brief: retrieve descriptor based on provided id. Designed to be used with ufsrv and therefore bypasses the lru stuff
 */
AttachmentDescriptor *
GetAttachmentDescriptorEphemeral (Session *sesn_ptr, const char *blob_id, bool flag_fully_populate, AttachmentDescriptor *attch_ptr_out)
{
	if (unlikely(IS_EMPTY(blob_id)))	return NULL;

	AttachmentDescriptor *attch_ptr	=	NULL;
	if (IS_PRESENT(attch_ptr_out))	attch_ptr=attch_ptr_out;
	else														attch_ptr=calloc(1, sizeof(AttachmentDescriptor));

	DbGetAttachmentDescriptor (sesn_ptr, blob_id, flag_fully_populate, attch_ptr);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
		return_success:
		return attch_ptr;
	}

	if (!IS_PRESENT(attch_ptr_out)) free (attch_ptr);

	return NULL;

}

/**
 * 	@brief: Main interface function for evicting complete records-set for a given fence
 *
 */
UFSRVResult *
CacheBackendRemCacheRecordForFence (Session *sesn_ptr, Fence *f_ptr)
{
	unsigned char 						*name_folded		=	NULL;
	PersistanceBackend				*pers_ptr				=	sesn_ptr->fence_cachebackend;
	size_t 										commandset_size	=	10;
//	FenceLocationDescription	fence_location	=	FENCE_LOCATION(f_ptr);
	char 											*cname_scratch_buffer	=	strdupa(FENCE_CNAME(f_ptr));
	LocationDescription 			fence_location 				= {0};
	MapFenceLocationDescription (f_ptr, cname_scratch_buffer, &fence_location);

	utf8proc_map((const unsigned char *)FENCE_DNAME(f_ptr), 0, &name_folded, UTF8PROC_CASEFOLD | UTF8PROC_DECOMPOSE | UTF8PROC_NULLTERM);

	(*pers_ptr->send_command_multi)(sesn_ptr, SESSION_FENCE_CACHEBACKEND(sesn_ptr), "MULTI");
	(*pers_ptr->send_command_multi)(sesn_ptr, SESSION_FENCE_CACHEBACKEND(sesn_ptr), REDIS_CMD_GLOBAL_FENCE_REGO_REM, FENCE_CNAME(f_ptr), FENCE_ID(f_ptr));
	(*pers_ptr->send_command_multi)(sesn_ptr, SESSION_FENCE_CACHEBACKEND(sesn_ptr), REDIS_CMD_FENCE_GEOHASH_REM, FENCE_ID(f_ptr), GetFenceNetworkType(f_ptr));
	(*pers_ptr->send_command_multi)(sesn_ptr, SESSION_FENCE_CACHEBACKEND(sesn_ptr), REDIS_CMD_FENCE_RECORD_REM, FENCE_ID(f_ptr));

	if (*fence_location.country)		{
			utf8proc_map((const unsigned char *)fence_location.country, 0, &name_folded, UTF8PROC_CASEFOLD | UTF8PROC_DECOMPOSE | UTF8PROC_NULLTERM);
			(*pers_ptr->send_command_multi)(sesn_ptr, 	SESSION_FENCE_CACHEBACKEND(sesn_ptr), REDIS_CMD_GLOBAL_FENCE_NAMEINDEX_REM, name_folded, FENCE_ID(f_ptr), FENCE_CNAME(f_ptr), FENCE_LONGITUDE(f_ptr), FENCE_LATITUDE(f_ptr));
			free	(name_folded);
		} else commandset_size--;

		if (*fence_location.admin_area)	{
			utf8proc_map((const unsigned char *)fence_location.admin_area, 0, &name_folded, UTF8PROC_CASEFOLD | UTF8PROC_DECOMPOSE | UTF8PROC_NULLTERM);
			(*pers_ptr->send_command_multi)(sesn_ptr, 	SESSION_FENCE_CACHEBACKEND(sesn_ptr), REDIS_CMD_GLOBAL_FENCE_NAMEINDEX_REM, name_folded, FENCE_ID(f_ptr), FENCE_CNAME(f_ptr), FENCE_LONGITUDE(f_ptr), FENCE_LATITUDE(f_ptr));
			free (name_folded);
		} else commandset_size--;

		if (*fence_location.locality)		{
			utf8proc_map((const unsigned char *)fence_location.locality, 0, &name_folded, UTF8PROC_CASEFOLD | UTF8PROC_DECOMPOSE | UTF8PROC_NULLTERM);
			(*pers_ptr->send_command_multi)(sesn_ptr, 	SESSION_FENCE_CACHEBACKEND(sesn_ptr), REDIS_CMD_GLOBAL_FENCE_NAMEINDEX_REM, name_folded, FENCE_ID(f_ptr), FENCE_CNAME(f_ptr), FENCE_LONGITUDE(f_ptr), FENCE_LATITUDE(f_ptr));
			free (name_folded);
		} else commandset_size--;

		if (*fence_location.selfzone)		{
			(*pers_ptr->send_command_multi)(sesn_ptr, 	SESSION_FENCE_CACHEBACKEND(sesn_ptr), REDIS_CMD_GLOBAL_FENCE_NAMEINDEX_SELFZONE_REM, SESSION_USERID(sesn_ptr), FENCE_ID(f_ptr), FENCE_CNAME(f_ptr), FENCE_LONGITUDE(f_ptr), FENCE_LATITUDE(f_ptr));
		} else commandset_size--;

		if (true)												{
			utf8proc_map((const unsigned char *)FENCE_DNAME(f_ptr), 0, &name_folded, UTF8PROC_CASEFOLD | UTF8PROC_DECOMPOSE | UTF8PROC_NULLTERM);
			(*pers_ptr->send_command_multi)(sesn_ptr, 	SESSION_FENCE_CACHEBACKEND(sesn_ptr), REDIS_CMD_GLOBAL_FENCE_NAMEINDEX_REM, name_folded, FENCE_ID(f_ptr), FENCE_CNAME(f_ptr), FENCE_LONGITUDE(f_ptr), FENCE_LATITUDE(f_ptr));
			free (name_folded);
		} else commandset_size--;


	(*pers_ptr->send_command_multi)(sesn_ptr, SESSION_FENCE_CACHEBACKEND(sesn_ptr), "EXEC");

	size_t				i;
	size_t				actually_processed	=	commandset_size;
	size_t				commands_successful	=	actually_processed;
	redisReply		*replies[actually_processed];

	for (i=0; i<actually_processed; i++)
	{
		if ((RedisGetReply(sesn_ptr, pers_ptr, (void *)&replies[i])) != REDIS_OK)
		{
			commands_successful--;

			if ((replies[i] != NULL))
			{
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', idex:'%lu'): ERROR PROCESSING MULTI SET COMMAND. ERROR: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i, replies[i]->str);
			}
			else
			{
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', i:'%lu'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i);
			}
		}
	}//for

	//diagnostics
	if (commands_successful != actually_processed)
	{
		for (i=0; i<actually_processed; i++)	if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)
	}

	//verification block
	{
//the results are stored at last index EXEC_COMMAND_IDX: array corresponding with command-set size less MULTI/EXEC. Other idx locations are of reply type REDIS_REPLY_STATUS
#define EXEC_COMMAND_IDX actually_processed-1

		for (i=0; i<EXEC_COMMAND_IDX; i++)	if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);

		if (unlikely(IS_EMPTY(replies[EXEC_COMMAND_IDX])))//idx for EXEC, which is last
		{
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR: REDIS TRANSCTION ERROR: NULL COMMAND ARRAY RESPONSE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)
		}

		if (replies[EXEC_COMMAND_IDX]->elements == actually_processed-2)
		{
//			if (!(replies[EXEC_COMMAND_IDX]->element[0]->integer==1))	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', error:'%s'): ERROR: ZREM Failed", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), replies[EXEC_COMMAND_IDX]->element[0]->str);
//			if (!(replies[EXEC_COMMAND_IDX]->element[1]->integer==1))	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', error:'%s'): ERROR: ZADD Failed", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), replies[EXEC_COMMAND_IDX]->element[1]->str);
//			if (!(strcmp(replies[EXEC_COMMAND_IDX]->element[2]->str, "OK")==0))	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', error:'%s'): ERROR: HMSET Failed", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), replies[EXEC_COMMAND_IDX]->element[2]->str);

			freeReplyObject(replies[EXEC_COMMAND_IDX]);
		}
		else
		{
			//Only remaining element is EXEC
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', dispatched:'%lu', received:'%lu', error:'%s'): ERROR: REDIS TRANSCTION ERROR: DISPATCHED/RECEIVED COMMANDS COUNT MISMATCH", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), actually_processed-2, replies[EXEC_COMMAND_IDX]->elements, replies[EXEC_COMMAND_IDX]->str);
			if (IS_PRESENT(replies[EXEC_COMMAND_IDX]))	freeReplyObject(replies[EXEC_COMMAND_IDX]);

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)
		}
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)

#undef EXEC_COMMAND_IDX

}

//DB

/**
 * 	@returns: 0 on success
 */
int
DbBackendInsertFenceRecord (Session *sesn_ptr_carrier, unsigned long fid, const char *jstr_fence)
{
#define SQL_INSERT_NEW_FENCE "INSERT INTO fences (fid, data) VALUES ('%lu', '%s') ON DUPLICATE KEY UPDATE data = '%s'"

	char *sql_query_str;
	sql_query_str = mdsprintf(SQL_INSERT_NEW_FENCE, fid, jstr_fence, jstr_fence);

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu'): GENERATED SQL QUERY: '%s'", __func__, pthread_self(), SESSION_ID(sesn_ptr_carrier), sql_query_str);
#endif
	int sql_result = h_query_insert(sesn_ptr_carrier->db_backend, sql_query_str);

	if (sql_result != H_OK)
	{
		syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu'): ERROR: COULD EXEUTE QUERY: '%s'", __func__, pthread_self(), SESSION_ID(sesn_ptr_carrier), sql_query_str);
	}

	free (sql_query_str);

	return sql_result;

#undef SQL_INSERT_NEW_FENCE
}

//end DB

/**
 *	@brief: This method traverses the provided list of user sessions and collect single instance of each session found. This
 *	is used to build up a set of single occurances of users from across many lists. The example below traverses user's
 *	fences list and collect all users, removing duplicate (same user on multiple fences in the list)
 *	 \code{.c}
 *	for (eptr=SESSION_FENCE_LIST(sesn_ptr).head; eptr; eptr=eptr->next) {
 * 		FetchUsersList(sesn_ptr, FENCE_SESSIONS_LIST_PTR(FENCESTATE_FENCE(fence_state_ptr)), &ht);
 *  }
 *  \endcode
 *
 *	@sessions_list_ptr: Standard linked list of sessions or other objects.
 *	@param  ht_ptr: user-provided hash store of found objects. Only single instance of each object allowed
 */
void
FetchUsersList (Session *sesn_ptr, List *sessions_list_ptr, HopscotchHashtableConfigurable *ht_ptr)
{
	ListEntry *eptr;

	for (eptr=sessions_list_ptr->head; eptr; eptr=eptr->next) {
		if (hopscotch_lookup_configurable(ht_ptr, eptr->whatever)) continue;
		if (unlikely((hopscotch_insert_configurable(ht_ptr, (uint8_t *)eptr->whatever))!=0)) {
			syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', o_user:'%p'} ERROR: COULD NOT ADD USER ", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), eptr->whatever);
		}
	}

}
