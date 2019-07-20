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
#include <fence_state.h>
#include <user_preferences.h>
#include <user_broadcast.h>
#include <users_proto.h>
#include <share_list.h>
#include <location.h>
#include <persistance.h>
#include <misc.h>
#include <net.h>
#include <nportredird.h>
#include <protocol_websocket_session.h>
#include <protocol_http.h>
#include <sessions_delegator_type.h>
#include <UfsrvMessageQueue.pb-c.h>
#include <hiredis.h>
#include <user_preference_descriptor_type.h>
#include <ufsrvuid.h>

static UserPreferenceDescriptor *_SetFenceUserPreferenceBoolean(PairedSessionFenceState *paired_ptr,
																																UserPreferenceDescriptor *pref_ptr_in,
																																PrefsStore pref_store, UfsrvEvent *event_ptr);
static UserPreferenceDescriptor *_GetFenceUserPreferenceBoolean (PairedSessionFenceState *paired_ptr,  UserPreferenceDescriptor *pref_ptr_in, PrefsStore pref_store, UserPreferenceDescriptor *pref_ptr_out);
static UserPreferenceDescriptor *_SetLocalFenceUserPreferenceBoolean (PairedSessionFenceState *paired_ptr, UserPreferenceDescriptor *pref_ptr_in);
static UserPreferenceDescriptor *_PrefValidateGeneric (PairedSessionFenceState *paired_ptr, UserPreferenceDescriptor *pref_ptr);
static inline bool	_GetBooleanPrefByOffeset (FenceStateDescriptor *fence_state_ptr, FenceUserPrefsOffsets pref_offset);
static inline void	_SetBooleanPrefByOffeset (FenceStateDescriptor *fence_state_ptr, FenceUserPrefsOffsets pref_offset, bool value);
static inline void 	_CacheBackendRecordReadOffPreferenceValue (redisReply *redis_ptr, UserPreferenceDescriptor *pref_ptr);
static struct json_object *_JsonFormatFenceUserPreferences (Session *sesn_ptr, PairedFencePrefCollections *fence_pref_collections_pair);
static UFSRVResult *_IntraBroadcastForSessionFenceUserPrefs (PairedSessionFenceState *paired_ptr, CollectionDescriptor *pref_collection_ptr);
static UFSRVResult *_HandleIntraMessageCommandForFenceUserPrefs (Session *sesn_ptr, SessionMessage *sesn_msg_ptr);
static inline UFSRVResult *_ProcessIntraMessageCommandForFenceUserPref (Session *sesn_ptr, FenceUserPreference *sesn_msg_pref_ptr, SessionMessage *sesn_msg_ptr);
extern ufsrv							*const masterptr;

static const UserPreferenceOps prefs_ops_table[] ={
		{(UserPreferenceOpSet)_SetFenceUserPreferenceBoolean, (UserPreferenceOpGet)_GetFenceUserPreferenceBoolean, (UserPreferenceOpSetLocal)_SetLocalFenceUserPreferenceBoolean},
		{NULL, NULL, NULL											},
		{NULL, NULL, NULL											},
		{NULL, NULL, NULL											},
		{NULL, NULL, NULL											},
		{NULL, NULL, NULL											},//invalid
};

//This needs to be kept in sync with enum FenceUserPrefsOffsets{} and bitfields defined in struct FenceUserPrefsBoolean in fence_state_descriptor_type.h
//AND redis HGETALL macro "REDIS_CMD_FENCE_USERPREF_GET_ALL"
//slots 0-63 reserved for bools, organised in 8 groups of bytes. redis fetches by byte ranges, hence this supporting scheme
//id should be aligned with enum FenceUserPrefsOffsets
static const UserPreferenceDescriptor fence_prefs_table[] = {
		{.pref_id=PREF_STICKY_GEOGROUP, .pref_name="sticky_geogroup", 	.pref_value_type=PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)_PrefValidateGeneric,  NULL, .pref_ops=&prefs_ops_table[0]},
		{.pref_id=PREF_PROFILE_SHARING, .pref_name="profile_sharing", 	.pref_value_type=PREFVALUETYPE_BOOL, 		.value={0}, (UserPreferenceValidate)_PrefValidateGeneric,  NULL, .pref_ops=&prefs_ops_table[0]},
		{.pref_id=0,										.pref_name="", 									.pref_value_type=PREFVALUETYPE_INVALID, .value={0}, NULL,  	 																			 NULL, .pref_ops=NULL}
};

//typedef UFSRVResult * (*)(ClientContextData *, CommandContextData *);
static UserPreferences user_fence_prefs_table={
		.prefs_table_sz=sizeof(fence_prefs_table)/sizeof(UserPreferenceDescriptor),
		.prefs_table=(UserPreferenceDescriptor **)fence_prefs_table,
		.type_ops={
				.intra_msg_handler=(UFSRVResult * (*)(ClientContextData *, CommandContextData *))_HandleIntraMessageCommandForFenceUserPrefs
		}
};

void
RegisterFenceUserPreferencesSource (void)
{
  RegisterUserPreferenceSource(&user_fence_prefs_table, PREFTYPE_FENCEUSER, user_fence_prefs_table.prefs_table_sz);

}

/**
 * 	@brief: This is necessary, because Fence is referenced almost everywhere for a given user, instead of FenceStateDescriptor, so we
 * 	need this front method to retrieve the state object and wrap it
 */
bool
IsStickyGeogroupForFenceSet (Session *sesn_ptr, Fence *f_ptr)
{
	InstanceHolderForFenceStateDescriptor *instance_fstate_ptr = FindFenceStateInSessionFenceListByFenceId(sesn_ptr, &SESSION_FENCE_LIST(sesn_ptr), FENCE_ID(f_ptr));
	if (IS_PRESENT(instance_fstate_ptr)) {
		return (IsFenceUserPreferenceSet(&((PairedSessionFenceState){FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr), sesn_ptr}), (UserPrefOffset) PREF_STICKY_GEOGROUP));
	}

	return false;
}

bool
IsProfileSharingForFenceSet (Session *sesn_ptr, Fence *f_ptr)
{
  InstanceHolderForFenceStateDescriptor *instance_fstate_ptr = FindFenceStateInSessionFenceListByFenceId(sesn_ptr, &SESSION_FENCE_LIST(sesn_ptr), FENCE_ID(f_ptr));
  if (IS_PRESENT(instance_fstate_ptr)) {
    return (IsFenceUserPreferenceSet(&((PairedSessionFenceState){FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr), sesn_ptr}), (UserPrefOffset) PREF_PROFILE_SHARING));
  }

  return false;
}

bool
IsFenceUserPreferenceSet (PairedSessionFenceState *paired_ptr, UserPrefOffset offset)
{
	return _GetBooleanPrefByOffeset (paired_ptr->fence_state_ptr, offset);
}

/**
 * 	@brief: Convenient frontend function, returning a copy of the pref descriptor, with basic descriptor specs preloaded, except for actual value
 * 	@param pref_ptr_out: User must provide storage for returned copy
 */
UserPreferenceDescriptor *
GetFenceUserPreferenceDescriptorByName (const char *pref_name, UserPreferenceDescriptor *pref_ptr_out)
{
	return (GetUserPreferenceDescriptorByName (&user_fence_prefs_table, pref_name, pref_ptr_out));
}

UserPreferenceDescriptor *
GetFenceUserPreferenceDescriptorById (const UserPrefsOffsets pref_offset, UserPreferenceDescriptor *pref_ptr_out)
{
	return (GetUserPreferenceDescriptorById (&user_fence_prefs_table, pref_offset, pref_ptr_out));
}

/**
 * 	@brief: Initialise user's in-memory fence preferences. This is designed to be invoked when a fence is
 * 	loaded from the cachebackend for the user.
 */
UFSRVResult *
InitialiseFenceUserPreferences (PairedSessionFenceState *paired_ptr)
{
	Session *sesn_ptr	=	paired_ptr->session_ptr;
	Fence 	*f_ptr		=	FenceOffInstanceHolder(paired_ptr->fence_state_ptr->instance_holder_fence);

	CacheBackendGetAllFenceUserPreferencesRecord (paired_ptr, SESSION_USERID(sesn_ptr), FENCE_ID(f_ptr));
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
		UserPreferenceDescriptor 	pref				=	{0};
		redisReply 								*redis_ptr	=	(redisReply *)SESSION_RESULT_USERDATA(sesn_ptr);

		for (size_t i=0; i<redis_ptr->elements; i++) {//must be fully aligned with pref_table order
			if (GetUserPreferenceDescriptorById (&user_fence_prefs_table, (UserPrefsOffsets)i, &pref)) {
				//TODO: this needs to work for types other than bools
				unsigned long bool_value=IS_STR_LOADED(redis_ptr->element[i]->str)?strtoul(redis_ptr->element[i]->str, NULL, 10):0;
				_SetBooleanPrefByOffeset (paired_ptr->fence_state_ptr, (FenceUserPrefsOffsets)i, bool_value);
			}
		}
	}

	_RETURN_RESULT_SESN(paired_ptr->session_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)
}

/**
 * 	@dynamic_memory redisReply *: EXPORTS
 */
UFSRVResult *
CacheBackendSetFenceUserPreferenceRecord (PairedSessionFenceState *paired_ptr, unsigned long userid, unsigned long fid, UserPreferenceDescriptor *pref_ptr)
{
	int rescode;

	Session							*sesn_ptr		=	paired_ptr->session_ptr;
	PersistanceBackend	*pers_ptr		=	sesn_ptr->persistance_backend;
	redisReply 					*redis_ptr	=	NULL;

	if (!(redis_ptr=(*pers_ptr->send_command)(sesn_ptr, REDIS_CMD_FENCE_USERPREF_X_SET, userid, fid, pref_ptr->pref_name, pref_ptr->value.pref_value_bool)))	goto return_redis_error;

	if ((redis_ptr->type==REDIS_REPLY_STATUS) && (strcasecmp(redis_ptr->str, "OK")==0))
	{
		_RETURN_RESULT_SESN(sesn_ptr, redis_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);
	}

	if (redis_ptr->type==REDIS_REPLY_ERROR)	goto return_redis_error;
	if (redis_ptr->type==REDIS_REPLY_NIL)		goto return_redis_error;

	return_redis_error:
	if (IS_EMPTY(redis_ptr))
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
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
 * 	@dynamic_memory redisReply *: EXPORTS
 */
UFSRVResult *
CacheBackendGetFenceUserPreferenceRecord (PairedSessionFenceState *paired_ptr, unsigned long userid, unsigned long fid, UserPreferenceDescriptor *pref_ptr)
{
	int rescode;

	PersistanceBackend	*pers_ptr		=	paired_ptr->session_ptr->persistance_backend;
	redisReply 					*redis_ptr	=	NULL;

	//this command will return "" string if set does not exist, ie does not communicate error in that sense
	if (!(redis_ptr=(*pers_ptr->send_command)(paired_ptr->session_ptr, REDIS_CMD_FENCE_USERPREF_X_GET, userid, fid, pref_ptr->pref_name)))	goto return_redis_error;

	if (redis_ptr->type==REDIS_REPLY_ARRAY)
	{
		_RETURN_RESULT_SESN(paired_ptr->session_ptr, redis_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);
	}

	if (redis_ptr->type==REDIS_REPLY_ERROR)	goto return_redis_error;
	if (redis_ptr->type==REDIS_REPLY_NIL)		goto return_redis_error;

	return_redis_error:
	if (IS_EMPTY(redis_ptr))
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), paired_ptr->session_ptr, SESSION_ID(paired_ptr->session_ptr));
	}
	if (redis_ptr->type==REDIS_REPLY_ERROR)
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), paired_ptr->session_ptr, SESSION_ID(paired_ptr->session_ptr), redis_ptr->str);
	 rescode=RESCODE_BACKEND_DATA; goto return_error;
	}
	if (redis_ptr->type==REDIS_REPLY_NIL)
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: NIL SET",  __func__, pthread_self(), paired_ptr->session_ptr, SESSION_ID(paired_ptr->session_ptr));
	 rescode=RESCODE_BACKEND_DATA; goto return_error;
	}

	return_error:
	freeReplyObject(redis_ptr);
	_RETURN_RESULT_SESN(paired_ptr->session_ptr, NULL, RESULT_TYPE_ERR, rescode);

}

/**
 * 	@brief: Return the full FenceUserPreference set for a given fence
 * 	@dynamic_memory redisReply *: EXPORTS
 */
UFSRVResult *
CacheBackendGetAllFenceUserPreferencesRecord (PairedSessionFenceState *paired_ptr, unsigned long userid, unsigned long fid)
{
	int rescode	=	RESCODE_BACKEND_CONNECTION;

	PersistanceBackend	*pers_ptr		=	paired_ptr->session_ptr->persistance_backend;
	redisReply 					*redis_ptr	=	NULL;

	//this command will return "" string if set does not exist, ie does not communicate error in that sense
	if (!(redis_ptr=(*pers_ptr->send_command)(paired_ptr->session_ptr, REDIS_CMD_FENCE_USERPREF_GET_ALL, userid, fid)))	goto return_redis_error;

	if (redis_ptr->type==REDIS_REPLY_ARRAY)
	{
		_RETURN_RESULT_SESN(paired_ptr->session_ptr, redis_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);
	}

	if (redis_ptr->type==REDIS_REPLY_ERROR)	goto return_redis_error;
	if (redis_ptr->type==REDIS_REPLY_NIL)		goto return_redis_error;

	return_redis_error:
	if (IS_EMPTY(redis_ptr))
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), paired_ptr->session_ptr, SESSION_ID(paired_ptr->session_ptr));
	 goto return_error;
	}
	if (redis_ptr->type==REDIS_REPLY_ERROR)
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), paired_ptr->session_ptr, SESSION_ID(paired_ptr->session_ptr), redis_ptr->str);
	 rescode=RESCODE_BACKEND_DATA; goto return_error_deallocate;
	}
	if (redis_ptr->type==REDIS_REPLY_NIL)
	{
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: NIL SET",  __func__, pthread_self(), paired_ptr->session_ptr, SESSION_ID(paired_ptr->session_ptr));
	 rescode=RESCODE_BACKEND_DATA; goto return_error_deallocate;
	}

	return_error_deallocate:
	freeReplyObject(redis_ptr);

	return_error:
	_RETURN_RESULT_SESN(paired_ptr->session_ptr, NULL, RESULT_TYPE_ERR, rescode);

}

/**
 * 	@brief: return collection of the full cacherecord FenceUserPreference set for each fence of which the user is member
 * 	@dynamic_memory redisReply *: EXPORTS
 * 	@dynamic_memory CollectionDescriptor *: IMPORTS/EXPORTS for Fences
 * 	@dynamic_memory CollectionDescriptor *: EXPORTS for prefs if not preallocated
 *
 */
UFSRVResult *
CacheBackendGetAllFenceUserPreferencesRecords (Session *sesn_ptr, unsigned long userid, PairedFencePrefCollections *collection_pair_ptr)//CollectionDescriptor *collection_ptr_in)
{
	CollectionDescriptor 	fences_collection	=	{0};

	if (IS_EMPTY(GetFenceCollectionForUser (sesn_ptr, &fences_collection, NULL, MEMBER_FENCES)))
	{
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
	}

	size_t							i;
	unsigned long				*fence_ids=(unsigned long *)fences_collection.collection;
	PersistanceBackend	*pers_ptr=sesn_ptr->persistance_backend;

	(*pers_ptr->send_command_multi)(sesn_ptr, "MULTI");
	for (i=0; i<fences_collection.collection_sz; i++) {
		(*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_FENCE_USERPREF_GET_ALL, userid, fence_ids[i]);

#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', fid:'%lu', idx:'%lu'}: Processing FenceCollection item...", __func__, pthread_self(), sesn_ptr, fence_ids[i], i);
#endif
	}
	(*pers_ptr->send_command_multi)(sesn_ptr, "EXEC");


	size_t								actually_processed=fences_collection.collection_sz+2;
	CollectionDescriptor 	*collection_ptr;
	redisReply						*replies[actually_processed];

	if (IS_PRESENT(collection_pair_ptr->collection_prefs))	collection_ptr=collection_pair_ptr->collection_prefs;
	else {
		collection_ptr=calloc(1, sizeof(redisReply *));
		collection_ptr->collection=calloc(actually_processed-1, sizeof(void *));//-1 instead of -2 as we need to retain a reference to EXEC reply object to delete later. we dont care about MULTI/EXEC
		collection_pair_ptr->collection_prefs=collection_ptr;
	}

	size_t				commands_successful	=	actually_processed;

	for (i=0; i<actually_processed; i++) {
		if ((RedisGetReply(sesn_ptr, pers_ptr, (void *)&replies[i])) != REDIS_OK) {
			commands_successful--;

			if ((replies[i] != NULL)) {
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', uid:'%lu', idex:'%lu'): ERROR PROCESSING MULTI SET COMMAND. ERROR: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), userid, i, replies[i]->str);
			} else {
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', i:'%lu'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i);
			}
		}
	}//for

	//diagnostics
	if (commands_successful!=actually_processed) {
		for (i=0; i<actually_processed; i++)	if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);

		DestructFenceCollection (&fences_collection, false);
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
	}

	//verification block
	{
		//we only want to keep the last one which contains array of redisReply * corresponding with the number of commands issued, less exec/multi
		//the rest will return value of type REDIS_REPLY_STATUS
#define EXEC_COOMAND_IDX actually_processed-1

		for (i=0; i<actually_processed-1; i++)	if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);

		if (IS_EMPTY(replies[EXEC_COOMAND_IDX])) {//idx for EXEC, which is last
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', userid:'%lu'): ERROR: REDIS TRANSCTION ERROR: NULL COMMAND ARRAY RESPONSE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), userid);

			DestructFenceCollection (&fences_collection, false);
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
		}

		if (replies[EXEC_COOMAND_IDX]->elements==actually_processed-2) {
			//dont use index 0 or free hereafter
			replies[0]=NULL;

			for (i=0; i<replies[EXEC_COOMAND_IDX]->elements; i++) {
				collection_ptr->collection[i]=replies[EXEC_COOMAND_IDX]->element[i];
			}

			collection_ptr->collection[replies[EXEC_COOMAND_IDX]->elements]=replies[EXEC_COOMAND_IDX];//we need to retain this in order to free the replyobject later
			collection_ptr->collection_sz=replies[EXEC_COOMAND_IDX]->elements;//actually extra "hidden" index exists for the redisReply object from EXEC
		} else {
			//Only remaining element is EXEC
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', dispatched:'%lu', received:'%lu', userid:'%lu'): ERROR: REDIS TRANSCTION ERROR: DISPATCHED/RECEIVED COMMANDS COUNT MISMATCH", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), actually_processed-2, replies[EXEC_COOMAND_IDX]->elements, userid);
			if (IS_PRESENT(replies[EXEC_COOMAND_IDX]))	freeReplyObject(replies[EXEC_COOMAND_IDX]);

			DestructFenceCollection (&fences_collection, false);
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
		}
	}


	//DestructFenceCollection (&fences_collection, false);
	collection_pair_ptr->collection_fences->collection		=	fences_collection.collection;
	collection_pair_ptr->collection_fences->collection_sz	=	fences_collection.collection_sz;

	_RETURN_RESULT_SESN(sesn_ptr, collection_pair_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);

#undef EXEC_COOMAND_IDX

}

/**
 * 	@brief:	Return a FenceUserPreference for user in json, as currently stored in cache backend. More suited to ufsrvapi stateless interaction.
 * 	TODO: expand to read off other store types (mem, db)
 */
__attribute__((unused)) struct json_object *
CacheBackendGetFenceUserPreferenceByJson (PairedSessionFenceState *paired_ptr, unsigned long userid, unsigned long fid, UserPreferenceDescriptor *pref_ptr)
{
	UFSRVResult *res_ptr=CacheBackendGetFenceUserPreferenceRecord (paired_ptr, userid, fid, pref_ptr);

	if (_RESULT_TYPE_SUCCESS(res_ptr))
	{
		_CacheBackendRecordReadOffPreferenceValue ((redisReply *)_RESULT_USERDATA(res_ptr), pref_ptr);

		return (JsonFormatUserPreference(pref_ptr));
	}

	return NULL;
}

/**
 * 	@brief:	Return a FenceUserPreference for user in json, as currently stored in cache backend. More suited to ufsrvapi stateless interaction.
 * 	TODO: expand to read off other store types (mem, db)
 */
__attribute__ ((unused)) struct json_object *
CacheBackendSetFenceUserPreferenceByJson (PairedSessionFenceState *paired_ptr, unsigned long userid, unsigned long fid, UserPreferenceDescriptor *pref_ptr)
{
	if (IS_PRESENT(pref_ptr->pref_validate))	(*pref_ptr->pref_validate)((ClientContextData *)paired_ptr, pref_ptr);

	UFSRVResult *res_ptr=CacheBackendSetFenceUserPreferenceRecord (paired_ptr, userid, fid, pref_ptr);

	if (_RESULT_TYPE_SUCCESS(res_ptr))
	{
		freeReplyObject((redisReply *)_RESULT_USERDATA(res_ptr));

		return (JsonFormatUserPreference(pref_ptr));
	}

	return NULL;
}

/**
 * 	@brief: Helper method to format json reply for a given fence based on its cacherecord
 * 	@returns: json array containing all prefs for the fence as stored in the cache backend
 */
static struct json_object *
_JsonFormatFenceUserPreferenceByCacheRecord (Session *sesn_ptr, redisReply *redis_ptr)
{
					UserPreferenceDescriptor pref;
	struct 	json_object	*jarray	= json_object_new_array();
	struct 	json_object	*jobj		= NULL;

	for (size_t i=0; i<user_fence_prefs_table.prefs_table_sz; i++)
	{
		if (GetUserPreferenceDescriptorById (&user_fence_prefs_table, (UserPrefsOffsets)i, &pref))
		{
			bool pref_value;

			if (IS_STR_LOADED(redis_ptr->element[i]->str))	pref.value.pref_value_bool=strtoul(redis_ptr->element[i]->str, NULL, 10);
			else	pref.value.pref_value_bool=0;

			jobj=JsonFormatUserPreference (&pref);
			json_object_array_add(jarray, jobj);
		}
	}

	return jarray;
}

/**
 * 	@brief: Helper method to format json reply
 * 	@returns: json array containing all fences of which current user is member. Each element of the array is
 * 	an array of prefs
 * 	@dynamic_memory json_object *: EXPORTS. root element to be deallocated is jarray_fences
 */
static struct json_object *
_JsonFormatFenceUserPreferences (Session *sesn_ptr, PairedFencePrefCollections *fence_pref_collections_pair)
{
	CollectionDescriptor *fences_collection	=	fence_pref_collections_pair->collection_fences;
	CollectionDescriptor *prefs_collection	=	fence_pref_collections_pair->collection_prefs;

	if (prefs_collection->collection_sz>0 && fences_collection->collection_sz>0)
	{
		unsigned long				*fence_ids=(unsigned long *)fences_collection->collection;
		struct json_object	*jarray_fences						= json_object_new_array();
		struct json_object	*jobj_fence_prefs_array,
												*jobj_fence;

		for (size_t i=0; i<prefs_collection->collection_sz; i++)
		{
			jobj_fence=json_object_new_object();

			json_object_object_add (jobj_fence, "fid", 		json_object_new_int64(fence_ids[i]));
			jobj_fence_prefs_array=_JsonFormatFenceUserPreferenceByCacheRecord (sesn_ptr, (redisReply *)prefs_collection->collection[i]);
			json_object_object_add(jobj_fence,"fence_preferences", jobj_fence_prefs_array);

			json_object_array_add(jarray_fences, jobj_fence);
		}

		return jarray_fences;
	}

	return NULL;
}

/**
 *  Load FenceUserPreferences given a memory committed Fence object (contrast with CacheRecord above)
 * @dynamic_memory: Exports json_object *
 */
json_object *JsonFormatFenceUserPreferences (Session *sesn_ptr, const FenceStateDescriptor *fstate_ptr)
{
	UserPreferenceDescriptor pref;
	struct 	json_object	*jarray	= json_object_new_array();
	struct 	json_object	*jobj		= NULL;

	GetUserPreferenceDescriptorById (&user_fence_prefs_table, (UserPrefsOffsets)PREF_STICKY_GEOGROUP, &pref);
	pref.value.pref_value_bool = IS_SET_FENCE_USERPREF(fstate_ptr, sticky_geogroup);
	jobj=JsonFormatUserPreference (&pref);
	json_object_array_add(jarray, jobj);

	memset (&pref, 0, sizeof(pref));
	GetUserPreferenceDescriptorById (&user_fence_prefs_table, (UserPrefsOffsets)PREF_PROFILE_SHARING, &pref);
	pref.value.pref_value_bool = IS_SET_FENCE_USERPREF(fstate_ptr, profile_sharing);
	jobj=JsonFormatUserPreference (&pref);
	json_object_array_add(jarray, jobj);

	return jarray;
}

/**
 * 	@dynamic_memory redisReply *: IMPROTS AND DEALLOCATES originating from previous query
 * 	@dynamic_memory collection **: IMPORTS from &(fence_pref_collections_pair.collection_fences)
 *
 */
struct json_object *
CacheBackendGetAllFenceUserPreferencesByJson (Session *sesn_ptr, unsigned long userid)
{
	size_t fences_list_sz=0;

	CacheBackendGetFencesListSize (sesn_ptr, SESSION_USERID(sesn_ptr));

	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))	fences_list_sz=(uintptr_t)SESSION_RESULT_USERDATA(sesn_ptr);
	if (fences_list_sz>0)
	{
		PairedFencePrefCollections	fence_pref_collections_pair={0};
		CollectionDescriptor 	prefs_collection	=	{0},
													fences_collection	=	{0};//no need to pre-allocate for collection_t ** as we get that automatically, which is subsequently freed below
		collection_t 					*collection[fences_list_sz+1];//we need to add extra one to retain actual redisReply object for memory reclamation
		memset (collection, 0, sizeof collection);

		prefs_collection.collection=collection;
		fence_pref_collections_pair.collection_prefs=&prefs_collection;
		fence_pref_collections_pair.collection_fences=&fences_collection;

		CacheBackendGetAllFenceUserPreferencesRecords (sesn_ptr, userid, &fence_pref_collections_pair);
		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))
		{
			struct json_object *jarray_fences=_JsonFormatFenceUserPreferences (sesn_ptr, &fence_pref_collections_pair);

			DestructFenceCollection (&fences_collection, false);
			freeReplyObject((redisReply *)prefs_collection.collection[prefs_collection.collection_sz]);//retained in the last "hidden" element

			return jarray_fences;
		}
	}
	else
	{
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: Fences List size was zero..", __func__, pthread_self(), sesn_ptr);
#endif
	}

	return NULL;
}

/**
 * 	@brief: main interface function for storing boolean types.
 * 	This can be called from ufsrvapi, in which case the INTRA broadcast will have to be proceeded with INTER semantics by the recievers,
 * 	meaning the backend model will have already been modified.
 * 	@warning: This function is part of lifecycle, as callback (*pref_ptr->pref_validate) must be invoked first, which's what SetUserPreference() does.
 * 	@param pref_store: where to store the value: memory, cached, persisted. IMPORTANT: writes automatically cascades through  from high(mem)->low(persisted)
 * 	@param pref_ptr_in: User supplied with preloaded with descriptor data and desired value
 */
static UserPreferenceDescriptor *
_SetFenceUserPreferenceBoolean(PairedSessionFenceState *paired_ptr, UserPreferenceDescriptor *pref_ptr_in, PrefsStore pref_store, UfsrvEvent *event_ptr)
{
	if (pref_ptr_in->pref_id<0 || pref_ptr_in->pref_id>=FPREF_LAST_ALIGNMENT)	return NULL;

	_SetBooleanPrefByOffeset (paired_ptr->fence_state_ptr, pref_ptr_in->pref_id, pref_ptr_in->value.pref_value_bool);

	RegisterSessionEvent (paired_ptr->session_ptr, EVENT_TYPE_SESSION, 0, NULL, event_ptr); //todo: set session event instance type

	if (SESSION_RESULT_TYPE_SUCCESS(paired_ptr->session_ptr)) {
		//DbBackendStoreUserPrefs (sesn_ptr, SESSION_USERID(sesn_ptr));

		CacheBackendSetFenceUserPreferenceRecord(paired_ptr, SESSION_USERID(paired_ptr->session_ptr), FENCE_ID(FenceOffInstanceHolder(paired_ptr->fence_state_ptr->instance_holder_fence)), pref_ptr_in);

		if (SESSION_RESULT_TYPE_SUCCESS(paired_ptr->session_ptr)) {
			redisReply *redis_ptr = (redisReply *) SESSION_RESULT_USERDATA(paired_ptr->session_ptr);

			{
				UserPreferenceDescriptor *prefs_collection[1];
				prefs_collection[0] = pref_ptr_in;
				FenceStateDescriptor *fences_descriptors_collection[1];
				fences_descriptors_collection[0] = paired_ptr->fence_state_ptr;
				PairedFencePrefCollections collections = {
								&(CollectionDescriptor) {(collection_t **) fences_descriptors_collection, 1},
								&(CollectionDescriptor) {(collection_t **) prefs_collection, 1}
				};
				InterBroadcastUserMessageFenceUserPrefs(paired_ptr->session_ptr, &collections, event_ptr, 0);
				//this is old semantics for user prefs set via direct POST. Kept for reference
//			_IntraBroadcastForSessionFenceUserPrefs (paired_ptr, &((CollectionDescriptor){(collection_t **)prefs_collection, 1}));
			}

#ifdef __UF_TESTING
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', pref_name:'%s', pref_value:'%lu'}: Set user preference...", __func__, pthread_self(), paired_ptr->session_ptr, pref_ptr_in->pref_name, pref_ptr_in->pref_id);
#endif

			freeReplyObject(redis_ptr);

			return pref_ptr_in;
		}
	}

	return NULL;
}

/**
 * 	@brief: Designed as callback handler for updating in-memory value only. Chiefly as a result of intra-msg
 */
static UserPreferenceDescriptor *
_SetLocalFenceUserPreferenceBoolean (PairedSessionFenceState *paired_ptr, UserPreferenceDescriptor *pref_ptr_in)
{
	if (pref_ptr_in->pref_id<0 || pref_ptr_in->pref_id>=FPREF_LAST_ALIGNMENT)	return NULL;

	_SetBooleanPrefByOffeset (paired_ptr->fence_state_ptr, pref_ptr_in->pref_id, pref_ptr_in->value.pref_value_bool);

	return pref_ptr_in;
}

/**
 * 	@brief: get interface function for getting boolean type pref values
 * 	@param pref_offset: pref id as defined by its offset in the master prefs table
 * 	@param pref_store: which store to get the value from: memory, cached (redis), persisted(db)
 */
static UserPreferenceDescriptor *
_GetFenceUserPreferenceBoolean (PairedSessionFenceState *paired_ptr,  UserPreferenceDescriptor *pref_ptr_in, PrefsStore pref_store, UserPreferenceDescriptor *pref_ptr_out)
{
	Session 									*sesn_ptr = paired_ptr->session_ptr;
	FenceStateDescriptor 			*fence_state_ptr = paired_ptr->fence_state_ptr;

	switch (pref_store)
	{
		case PREFSTORE_MEM:
			pref_ptr_in->value.pref_value_bool	=	_GetBooleanPrefByOffeset (paired_ptr->fence_state_ptr, pref_ptr_in->pref_id);
			return pref_ptr_in;

		default:
			CacheBackendGetFenceUserPreferenceRecord (paired_ptr, SESSION_USERID(sesn_ptr), FENCE_ID(FenceOffInstanceHolder(fence_state_ptr->instance_holder_fence)), pref_ptr_in);

			if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
				_CacheBackendRecordReadOffPreferenceValue ((redisReply *)SESSION_RESULT_USERDATA(sesn_ptr), pref_ptr_in);
				return pref_ptr_in;
			}
	}

	return NULL;
}

/**
 * 	@brief: Utility function to isolate the redis readoff operations
 * 	@param pref_ptr: User-supplied and already preloaded with pref descriptor data
 */
static inline void
_CacheBackendRecordReadOffPreferenceValue (redisReply *redis_ptr, UserPreferenceDescriptor *pref_ptr)
{
	const char *value=IS_STR_LOADED(redis_ptr->element[0]->str)?redis_ptr->element[0]->str:"0";

	pref_ptr->value.pref_value_bool= strtoul(value, NULL, 10);

	freeReplyObject(redis_ptr);
}

/**
 * 	@brief: callback. Commits changes to memory, ahead of committing to cache and db backends
 */
static UserPreferenceDescriptor *
_PrefValidateGeneric (PairedSessionFenceState *paired_ptr, UserPreferenceDescriptor *pref_ptr)
{
//
//	switch (pref_ptr->pref_id)
//	{
//		case 	PREF_RM_WANDERER:
//			if (pref_ptr->value.pref_value_bool==1)
//			{
//				SetBooleanPrefById (sesn_ptr, PREF_RM_CONQUERER, false);
//				SetBooleanPrefById (sesn_ptr, PREF_RM_JOURNALER, false);
//			}
//			break;
//
//	}

	return pref_ptr;
}

/**
 * 	@brief: get the pref value for a user based on given bitfield offset
 */
static inline bool
_GetBooleanPrefByOffeset (FenceStateDescriptor *fence_state_ptr, FenceUserPrefsOffsets pref_offset)
{
	const struct FenceUserPrefsBooleanStorage pref_storage={.on_off=fence_state_ptr->user_preferences.booleans};

	return (bool)(pref_storage.storage & (1<<(pref_offset)));

}

/**
 * 	@brief: set the pref value for a user based on given bitfield offset
 * 	Similar to //SESSION_USERPREF_ONOFF_SET(sesn_ptr, roaming_mode, 1);
 * 	except it is dynamic, offset based as opposed to field-name based, which relies on preprocessor magic
 */
/*__attribute__((const))*/ static inline void
_SetBooleanPrefByOffeset (FenceStateDescriptor *fence_state_ptr, FenceUserPrefsOffsets pref_offset, bool value)
{
	struct FenceUserPrefsBooleanStorage pref_storage={.on_off=fence_state_ptr->user_preferences.booleans};

	 //pref_storage.storage ^= (-value ^ pref_storage.storage) & (1UL << pref_offset);
	 //canonical method
	 if (value==1) 	pref_storage.storage |= (1UL<<(pref_offset));
	 else  					pref_storage.storage &= ~(1UL<<(pref_offset));

	 fence_state_ptr->user_preferences.booleans=pref_storage.on_off;
}

/**
 * 	@brief: Helper function to process individual prefs for fence user
 * 	@locked sesn_ptr: By the caller
 */
static inline UFSRVResult *
_ProcessIntraMessageCommandForFenceUserPref (Session *sesn_ptr, FenceUserPreference *sesn_msg_pref_ptr, SessionMessage *sesn_msg_ptr)
{
	InstanceHolderForFenceStateDescriptor *instance_fstate_ptr;

	if (IS_EMPTY((instance_fstate_ptr = IsUserMemberOfFenceById(&SESSION_FENCE_LIST(sesn_ptr), sesn_msg_ptr->fences[0]->fid, false)))) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fid:'%lu'}: ERROR: COULD NOT RETRIEVE VALID FENCE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr),sesn_msg_ptr->fences[0]->fid);
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}

  FenceStateDescriptor *fence_state_ptr = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
	UserPreferenceDescriptor 				pref = {0};

	if (GetUserPreferenceDescriptorById (&user_fence_prefs_table, sesn_msg_pref_ptr->pref_id, &pref)) {
		SetPrefValueByTypeFromIntraSessionMessage ((UserPreference *)sesn_msg_pref_ptr, &pref);//simple value transfer, adapting from wire format
		if (!(SetLocalUserPreference (&((PairedSessionFenceState){fence_state_ptr, sesn_ptr}), &pref, true))) {
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fid:'%lu', pref_name:'%s'}: ERROR: COULD NOT SET FENCE USER PREF", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sesn_msg_ptr->fences[0]->fid, sesn_msg_pref_ptr->pref_name);
			//continue
		}
	} else {
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
}

UFSRVResult *
IsUserAllowedToChangeFenceUserPrefProfileSharing(Session *sesn_ptr, FenceUserPreference *sesn_msg_pref_ptr, DataMessage *data_msg_ptr_received, UfsrvEvent *event_ptr, CallbackCommandMarshaller command_marshaller)
{
	InstanceHolderForFenceStateDescriptor *instance_fstate_ptr;
	UserCommand 					*command_ptr	=	data_msg_ptr_received->ufsrvcommand->usercommand;

	if (IS_EMPTY((instance_fstate_ptr = IsUserMemberOfFenceById(&SESSION_FENCE_LIST(sesn_ptr), command_ptr->fences[0]->fid, false)))) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fid:'%lu'}: ERROR: COULD NOT RETRIEVE VALID FENCE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), command_ptr->fences[0]->fid);
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_FENCE_MEMBERSHIP);
	}

  FenceStateDescriptor 	*fence_state_ptr = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
	UserPreferenceDescriptor 				pref = {0};

	if (GetUserPreferenceDescriptorById (&user_fence_prefs_table, sesn_msg_pref_ptr->pref_id, &pref)) {
		pref.value.pref_value_bool = sesn_msg_pref_ptr->values_int;
		if (IS_PRESENT((*pref.pref_ops->pref_set)(&((PairedSessionFenceState){fence_state_ptr, sesn_ptr}), &pref, PREFSTORE_EVERYWHERE, event_ptr))) {
		  if (IS_PRESENT(command_marshaller)) {
        ShareListContextData share_list_ctx = {sesn_ptr, NULL, NULL, NULL, data_msg_ptr_received, false, false, fence_state_ptr};
        INVOKE_COMMAND_MARSHALLER(command_marshaller, sesn_ptr, ctx_ptr, data_msg_ptr_received, event_ptr);
		  }
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
		}
	}

	return_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
}

UFSRVResult *
IsUserAllowedToChangeFenceUserPrefStickyGeoGroup (Session *sesn_ptr, FenceUserPreference *sesn_msg_pref_ptr,  DataMessage *data_msg_ptr_recieved, unsigned long sesn_call_flags)
{
  InstanceHolderForFenceStateDescriptor *instance_fstate_ptr;

	UserCommand 					*command_ptr	=	data_msg_ptr_recieved->ufsrvcommand->usercommand;

	if (IS_EMPTY((instance_fstate_ptr = IsUserMemberOfFenceById(&SESSION_FENCE_LIST(sesn_ptr), command_ptr->fences[0]->fid, false)))) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fid:'%lu'}: ERROR: COULD NOT RETRIEVE VALID FENCE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), command_ptr->fences[0]->fid);
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_FENCE_MEMBERSHIP);
	}

  FenceStateDescriptor 	*fence_state_ptr = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
	UserPreferenceDescriptor 				pref = {0};

	//delete old
//	//if (GetUserPreferenceDescriptorByName(&user_prefs_table, sesn_msg_pref_ptr->pref_name, &pref))
//	if (GetUserPreferenceDescriptorById (&user_prefs_table, sesn_msg_pref_ptr->pref_id, &pref))
//	{
//		SetPrefValueByTypeFromIntraSessionMessage ((UserPreference *)sesn_msg_pref_ptr, &pref);//simple value transfer, adapting from wire format
//		if (!(SetLocalUserPreference (&((PairedSessionFenceState){fence_state_ptr, sesn_ptr}), &pref, true)))
//		{
//			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fid:'%lu', pref_name:'%s'}: ERROR: COULD NOT SET FENCE USER PREF", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), command_ptr->fences[0]->fid, sesn_msg_pref_ptr->pref_name);
//			//continue
//		}
//	}
//	else
//	{
//		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);
//
//	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
}

/**
 * 	@brief: Process collection of Fences and their associated prefs. This is in response to intra-updates through the msgqueue bus.
 * 	So we only update the memory-resident part. See comments below re the need to treat this INTRA broadcast with INTER
 * 	semantics.
 *
 * 	@locked RW sesn_ptr: by the caller
 */
static UFSRVResult *
_HandleIntraMessageCommandForFenceUserPrefs (Session *sesn_ptr, SessionMessage *sesn_msg_ptr)
{
	size_t							  erroneous_prefs_sz	=	0;
	FenceUserPreference 	*erroneous_prefs[sesn_msg_ptr->n_fence_prefs] __attribute__((unused));

	for (size_t i=0; i<sesn_msg_ptr->n_fence_prefs; i++)
	{
		FenceUserPreference *fence_pref_ptr=sesn_msg_ptr->fence_prefs[i];
		_ProcessIntraMessageCommandForFenceUserPref (sesn_ptr, fence_pref_ptr, sesn_msg_ptr);
		if (SESSION_RESULT_TYPE_ERROR(sesn_ptr)) {
			erroneous_prefs[i]=fence_pref_ptr;
			erroneous_prefs_sz++;
		}
	}

	if (erroneous_prefs_sz>0)	{_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);
}

/**
 * @brief: Main interface for broadcasting user preference change for a given fence.
 * Only use if the backend data model is being changed by a server residing outside the stateful ufsrv class. Otherwise
 * use regular INTER broadcast. AS SUCH this is currently designed to be invoked from ufsrvapi, because the prefs api is oblivion
 * to server processing environmentand POST requests will be executed against the data backend model in order to acknowledge the request
 * properly. Therefore this broadcast and "after-the-fact" from the point of view of the ufsrv class servers and will treat it with INTER
 * semantics. In turn ufsrv should not invoke an INTER broadcast when it receives this.
 * Also, this broadcast need not be target at a named instance: all servers must that have this user/fence must updated their
 * local data model.
 *
 * changed on stateless api calls. This broadcast should beregarded as INTRA_WITH_INTER_SEMANTICS
 *
 * 	@param pref_collection_ptr: collection of UserPreferenceDescriptor * containing pref values to encode
 */
__unused static UFSRVResult *
_IntraBroadcastForSessionFenceUserPrefs (PairedSessionFenceState *paired_ptr, CollectionDescriptor *pref_collection_ptr)
{
	Session *sesn_ptr = paired_ptr->session_ptr;

	if (IS_PRESENT(pref_collection_ptr) && (pref_collection_ptr->collection_sz>0))
	{
		CollectionDescriptor collection_prefs		=	{0};
		CollectionDescriptor collection_fences	=	{0};

		//mempool for the collection of prefs
		UserPreference pref_descriptor_mempool[pref_collection_ptr->collection_sz];
		UserPreference *pref_descriptor_ptrs[pref_collection_ptr->collection_sz];

		for (size_t i=0; i<pref_collection_ptr->collection_sz; i++)
					pref_descriptor_ptrs[i] = (UserPreference *)(pref_descriptor_mempool + (i * sizeof(UserPreference)));

		collection_prefs.collection_sz = pref_collection_ptr->collection_sz;
		collection_prefs.collection		 = (collection_t **)pref_descriptor_ptrs;

		if (IS_EMPTY(MakeSessionMessageUserPreferenceInProto (sesn_ptr, pref_collection_ptr, &collection_prefs))) {
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: ERROR: received zero size Prefs collection", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
		}

		//mempool for the fences (only one at a time in this context, but multi is possible)
		FenceUserPreference fpref_descriptor_mempool[1];//one fence
		FenceUserPreference *fpref_descriptor_ptrs[1];
		fpref_descriptor_ptrs[0] = (FenceUserPreference *)(fpref_descriptor_mempool + 0);

		FenceRecord fence_mempool[1];//one fence
		FenceRecord *fence_collection[1];
		fence_collection[0] = (FenceRecord *)(fence_mempool + 0);

		//connect the prefs prepared above
		fence_user_preference__init(&fpref_descriptor_mempool[0]);
		fence_record__init(&fence_mempool[0]);
		fence_mempool[0].fid			=	FENCE_ID(FenceOffInstanceHolder(paired_ptr->fence_state_ptr->instance_holder_fence));
//		fpref_descriptor_mempool[0].fence_prefs		=	(UserPreference **)collection_prefs.collection;
//		fpref_descriptor_mempool[0].n_prefs	=	collection_prefs.collection_sz;

		collection_fences.collection_sz=1;//pref_collection_ptr->collection_sz;
		collection_fences.collection		=(collection_t **)fpref_descriptor_ptrs;

		SessionMessage msgqueue_sesn_msg	=	SESSION_MESSAGE__INIT;
		CommandHeader		header						=	COMMAND_HEADER__INIT;

		msgqueue_sesn_msg.header					=	&header;
		MakeUfsrvUidInProto(&SESSION_UFSRVUIDSTORE(sesn_ptr), &(header.ufsrvuid), true);
		header.has_ufsrvuid=1;
		header.when												=	time(NULL);								header.has_when=1;

		msgqueue_sesn_msg.fences					=	fence_collection;
		msgqueue_sesn_msg.n_fences					=	1;
		msgqueue_sesn_msg.fence_prefs			=	(FenceUserPreference **)collection_fences.collection;
		msgqueue_sesn_msg.n_fence_prefs		=	collection_fences.collection_sz;
		msgqueue_sesn_msg.status					=	SESSION_MESSAGE__STATUS__PREFERENCE;

	#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', origin:'%d', uname:'%s'}: Publishing intra-Session-pref message...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), masterptr->serverid, SESSION_USERNAME(sesn_ptr));
	#endif

		UfsrvApiIntraBroadcastMessage (sesn_ptr, _WIRE_PROTOCOL_DATA((&msgqueue_sesn_msg)), MSGCMD_SESSION, INTRA_WITH_INTER_SEMANTICS, NULL);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);

	}//if

	return _ufsrv_result_generic_error;

}
