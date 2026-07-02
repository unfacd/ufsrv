/**
 * Copyright (C) 2015-2024 unfacd works
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
#include <share_list.h>
#include <uflib/recycler/recycler.h>
#include <session.h>
#include <ufsrv_core/cache_backend/redis.h>
#include <user_broadcast.h>
#include <uflib/ufsrvuid.h>

extern __thread ThreadContext ufsrv_thread_context;

static UFSRVResult *_CacheBackendAddToShareList(Session *sesn_ptr, ShareList *shlist_ptr, unsigned long item_id);
static UFSRVResult *_CacheBackendRemoveFromShareList(Session *sesn_ptr, ShareList *shlist_ptr, unsigned long item_id);

//align index with enum EnumShareListType
static ShareListTypeOps sharelist_types[] = {
		{hopscotch_init_with_offset, IsUserOnShareListProfile,          IsShareLisInitialisedProfile,         SetShareListInitialisedProfile      },
		{hopscotch_init_with_offset, IsUserOnShareListLocation,         IsShareLisInitialisedLocation,        SetShareListInitialisedLocation     },
    {hopscotch_init_with_offset, IsUserOnShareListContacts,         IsShareLisInitialisedContacts,        SetShareListInitialisedContacts     },
    {hopscotch_init_with_offset, IsUserOnShareListNetstate,         IsShareLisInitialisedNetstate,        SetShareListInitialisedNetstate     },
		{NULL, NULL, NULL, NULL },//FRIENDS
    {hopscotch_init_with_offset, IsUserOnShareListBlocked,          IsShareLisInitialisedBlocked,         SetShareListInitialisedBlocked      },
    {hopscotch_init_with_offset, IsUserOnShareListReadReceipt,      IsShareLisInitialisedReadReceipt,     SetShareListInitialisedReadReceipt  },
    {hopscotch_init_with_offset, IsUserOnShareListTypingIndicator,  IsShareLisInitialisedActivityState,   SetShareListInitialisedActivityState},
    {hopscotch_init,            (bool(*)())IsFenceOnShareListBlockedFence,IsShareLisInitialisedBlockedFence,    SetShareListInitialisedBlockedFence  }
};

__attribute__ ((pure)) ShareListCheckerCallBack
GetShareListPresenceChecker(enum EnumShareListType type)
{
	return 	sharelist_types[type].presence_checker_callback;
}

__attribute__ ((pure)) ShareListInitialisationCheckerCallBack
GetShareListInitialisationChecker(enum EnumShareListType type)
{
	return 	sharelist_types[type].initialisation_checker_callBack;
}

__attribute__ ((pure)) ShareListInitialisationSetterCallBack
GetShareListInitialisationSetter(enum EnumShareListType type)
{
	return 	sharelist_types[type].initialisation_setter_callBack;
}

__attribute__ ((pure)) ShareListInitialiserCallback
GetShareListInitialiser(enum EnumShareListType type)
{
  return 	sharelist_types[type].initialiser_callback;
}

static ClientContextData *
_ShareListItemExtractorCallback(ItemContainer *item_container_ptr)
{
  return GetClientContextData((InstanceHolder *)item_container_ptr);
}

void SetShareListTypes(Session *sesn_ptr)
{
	SESSION_USERPREF_SHLIST_PROFILE(sesn_ptr).list_type           = SHARELIST_PROFILE;
  SESSION_USERPREF_SHLIST_PROFILE(sesn_ptr).share_direction     = SHARELIST_DIR_RECIPRICAL;

	SESSION_USERPREF_SHLIST_LOCATION(sesn_ptr).list_type          = SHARELIST_LOCATION;
  SESSION_USERPREF_SHLIST_LOCATION(sesn_ptr).share_direction    = SHARELIST_DIR_RECIPRICAL;

	SESSION_USERPREF_SHLIST_NETSTATE(sesn_ptr).list_type          = SHARELIST_NETSTATE;
  SESSION_USERPREF_SHLIST_NETSTATE(sesn_ptr).share_direction    = SHARELIST_DIR_RECIPRICAL;

  SESSION_USERPREF_SHLIST_CONTACTS(sesn_ptr).list_type          = SHARELIST_CONTACT;
  SESSION_USERPREF_SHLIST_CONTACTS(sesn_ptr).share_direction    = SHARELIST_DIR_RECIPRICAL;

  SESSION_USERPREF_SHLIST_BLOCKED(sesn_ptr).list_type           = SHARELIST_BLOCKED;
  SESSION_USERPREF_SHLIST_BLOCKED(sesn_ptr).share_direction     = SHARELIST_DIR_RECIPRICAL;

  SESSION_USERPREF_SHLIST_READ_RECEIPT(sesn_ptr).list_type      = SHARELIST_READ_RECEIPT;
  SESSION_USERPREF_SHLIST_READ_RECEIPT(sesn_ptr).share_direction=SHARELIST_DIR_RECIPRICAL;

  SESSION_USERPREF_SHLIST_ACTIVITY_STATE(sesn_ptr).list_type    = SHARELIST_ACTIVITY_STATE;
  SESSION_USERPREF_SHLIST_ACTIVITY_STATE(sesn_ptr).share_direction    = SHARELIST_DIR_RECIPRICAL;

  SESSION_USERPREF_SHLIST_BLOCKED_FENCE(sesn_ptr).list_type     = SHARELIST_BLOCKED_FENCE;
  SESSION_USERPREF_SHLIST_BLOCKED_FENCE(sesn_ptr).share_direction     = SHARELIST_DIR_SHARING;

}

/**
 *	@dynamic_memory: EXPORTS redis_ptr
 *
 */
UFSRVResult *
CacheBackendGetShareList(ShareList *shlist_ptr, unsigned long userid)
{
	unsigned 						rescode		=	RESCODE_BACKEND_DATA;
	PersistanceBackend	*pers_ptr	=	THREAD_CONTEXT_PERSISTANCE_CACHEBACKEND(THREAD_CONTEXT);
	redisReply 					*redis_ptr;

	if (!(redis_ptr = (*pers_ptr->send_command)(NULL, REDIS_CMD_SHARELIST_GETALL, shlist_ptr->list_type, userid))) goto return_redis_error;

	if (redis_ptr->type == REDIS_REPLY_ERROR)	goto return_redis_error;
	if (redis_ptr->type == REDIS_REPLY_NIL)		goto return_redis_error;

	if (redis_ptr->elements > 0) {
    THREAD_CONTEXT_RETURN_RESULT_SUCCESS(redis_ptr, RESCODE_BACKEND_DATA);
	} else {
	#ifdef __UF_FULLDEBUG
	 syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p, list:'%i'): NOTICE: EMPTY SET FOR ShareList",  __func__, pthread_self(), sesn_ptr, shlist_ptr->list_type);
	#endif

	 freeReplyObject(redis_ptr);
    THREAD_CONTEXT_RETURN_RESULT_SUCCESS(NULL, RESCODE_BACKEND_DATA_EMPTYSET);
	}

	return_redis_error:
	if (IS_EMPTY(redis_ptr)) {
	 syslog(LOG_DEBUG, "%s {pid:'%lu, uid:'%lu'}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), userid);
    THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, rescode);

	}
	if (redis_ptr->type == REDIS_REPLY_ERROR) {
	 syslog(LOG_DEBUG, "%s {pid:'%lu, uid:'%lu'}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), userid, redis_ptr->str);
	 rescode = RESCODE_BACKEND_DATA; goto return_error;
	}
	if (redis_ptr->type == REDIS_REPLY_NIL) {
	 syslog(LOG_DEBUG, "%s {pid:'%lu, uid:'%lu'}: ERROR: NIL SET",  __func__, pthread_self(), userid);
	 rescode = RESCODE_BACKEND_DATA; goto return_error;
	}

	return_error:
	freeReplyObject(redis_ptr);
  THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, rescode);

}

/**
 * 	Entries formatted as %uid:%list_enum
 *	@dynamic_memroy: EXPORTS redis_ptr
 *
 */
UFSRVResult *
CacheBackendGetSharedList(Session *sesn_ptr)
{
	unsigned 						rescode		=	RESCODE_BACKEND_DATA;
	PersistanceBackend	*pers_ptr	=	THREAD_CONTEXT_PERSISTANCE_CACHEBACKEND(ufsrv_thread_context);
	redisReply 					*redis_ptr;

	if (!(redis_ptr = (*pers_ptr->send_command)(sesn_ptr, REDIS_CMD_SHAREDLIST_GETALL, SESSION_USERID(sesn_ptr)))) goto return_redis_error;

	if (redis_ptr->type == REDIS_REPLY_ERROR)	goto return_redis_error;
	if (redis_ptr->type == REDIS_REPLY_NIL)		goto return_redis_error;


	if (redis_ptr->elements > 0) {
		_RETURN_RESULT_SESN(sesn_ptr, redis_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);
	} else {
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p): NOTICE: EMPTY SET FOR SharedList",  __func__, pthread_self(), sesn_ptr);
#endif

		freeReplyObject(redis_ptr);
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA_EMPTYSET);
	}

	return_redis_error:
	if (IS_EMPTY(redis_ptr)) {
		syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);
	}
	if (redis_ptr->type == REDIS_REPLY_ERROR) {
		syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), redis_ptr->str);
		rescode=RESCODE_BACKEND_DATA; goto return_error;
	}
	if (redis_ptr->type == REDIS_REPLY_NIL) {
		syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: NIL SET",  __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
		rescode = RESCODE_BACKEND_DATA; goto return_error;
	}

	return_error:
	freeReplyObject(redis_ptr);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

}

UFSRVResult *
CacheBackendGetShareListSize(Session *sesn_ptr, ShareList *shlist_ptr)
{
	unsigned 						rescode			=	RESCODE_BACKEND_DATA;
	PersistanceBackend	*pers_ptr		=	THREAD_CONTEXT_PERSISTANCE_CACHEBACKEND(ufsrv_thread_context);
	redisReply 					*redis_ptr	=	NULL;

	if (!(redis_ptr=(*pers_ptr->send_command)(sesn_ptr, REDIS_CMD_SHARELIST_SIZE, shlist_ptr->list_type, SESSION_USERID(sesn_ptr))))	goto return_redis_error;

	if (redis_ptr->type == REDIS_REPLY_INTEGER) {
		size_t share_list_sz = (size_t)redis_ptr->integer; //shouldn't have problems with negative as we dont store them in this context
		freeReplyObject(redis_ptr);

		_RETURN_RESULT_SESN(sesn_ptr, (void *) (uintptr_t) share_list_sz, RESULT_TYPE_SUCCESS, rescode);
	}

	if (redis_ptr->type == REDIS_REPLY_ERROR)	goto return_redis_error;
	if (redis_ptr->type == REDIS_REPLY_NIL)		goto return_redis_error;

	return_redis_error:
	if (IS_EMPTY(redis_ptr)) {
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	 _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);
	}
	if (redis_ptr->type == REDIS_REPLY_ERROR) {
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), redis_ptr->str);
	 rescode = RESCODE_BACKEND_DATA; goto return_error;
	}
	if (redis_ptr->type == REDIS_REPLY_NIL) {
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: NIL SET",  __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	 rescode = RESCODE_BACKEND_DATA; goto return_error;
	}

	return_error:
	freeReplyObject(redis_ptr);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode);

}

/**
 * @brief Check if a user is in a sharelist based on backend cache check.
 * @param shlist_ptr Sharelist for identifying type
 * @param userid_host the owner of the sharelist to be checked
 * @return
 */
UFSRVResult *
CacheBackendGetShareListAndCheckUser(const ShareList *shlist_ptr, unsigned long userid_host, unsigned long userid_to_check)
{
  CacheBackendGetShareList((ShareList *)shlist_ptr, userid_host);

  redisReply *redis_ptr;

  if (THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA) {
    redis_ptr = (redisReply *) THREAD_CONTEXT_UFSRV_RESULT_USERDATA;

    for (size_t i = 0; i < redis_ptr->elements; ++i) {
      unsigned long userid_fetched = strtoul(redis_ptr->element[i]->str, NULL, 10);
      if (userid_fetched == userid_to_check)  goto return_found;
    }
  } else {
    redis_ptr = THREAD_CONTEXT_UFSRV_RESULT_USERDATA;
    goto return_not_found;
  }

  return_not_found:
  if (IS_PRESENT(redis_ptr))  freeReplyObject(redis_ptr); //redis object could be found if empty backend and no error
  THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_BACKEND_DATA_EMPTYSET)

  return_found:
  freeReplyObject(redis_ptr);
  THREAD_CONTEXT_RETURN_RESULT_SUCCESS(NULL, RESCODE_BACKEND_DATA)

}

/**
 * 	@brief: Load fresh list from the backend. This only storage-allocates/initialises the sharelist if the backend contained entries
 *
 */
UFSRVResult *
InstateShareListForUsers(Session *sesn_ptr, ShareList *shlist_ptr, bool flag_init)
{
	CacheBackendGetShareList(shlist_ptr, SESSION_USERID(sesn_ptr));

	unsigned rescode = RESCODE_PROG_NULL_POINTER;
	if (THREAD_CONTEXT_UFSRV_RESULT_TYPE_SUCCESS) {
		if (!THREAD_CONTEXT_UFSRV_RESULT_CODE_EQUAL_(RESCODE_BACKEND_DATA_EMPTYSET)) {
			unsigned long instan_flags	= (CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY|CALL_FLAG_HASH_USERNAME_LOCALLY);//no CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION
			InstanceHolderForSession *instance_sesn_ptr_member;
			redisReply 		*redis_ptr		= (redisReply *)THREAD_CONTEXT_UFSRV_RESULT_USERDATA;

			rescode = THREAD_CONTEXT_UFSRV_RESULT_CODE_;
			if (flag_init)	{
				InitialiseShareListStorage(shlist_ptr);
				(*GetShareListInitialisationSetter(shlist_ptr->list_type))(sesn_ptr, true);
			}

			for (size_t i=0; i < redis_ptr->elements; ++i) {
				unsigned long 	user_id		= strtoul(redis_ptr->element[i]->str, NULL, 10);
				GetSessionForThisUserByUserId(sesn_ptr, user_id, NULL/*lock_state*/, instan_flags);
				instance_sesn_ptr_member = (InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr);
				if (IS_PRESENT(instance_sesn_ptr_member)) {
					if ((hopscotch_insert_with_offset(&(shlist_ptr->hashtable), _ShareListItemExtractorCallback, (void *) instance_sesn_ptr_member, CONFIG_FENCE_PERMISSIONS_KEYOFFSET(Session, sservice.user.user_details.user_id))) == 0) {
            SessionIncrementReference(instance_sesn_ptr_member, 1);
					}
				}
			}

			freeReplyObject(redis_ptr);
		} else {
			//empty set
			rescode = RESCODE_BACKEND_DATA_EMPTYSET; //we still return success on emptyset
		}

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, rescode)
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)
}

/**
 * @brief Generalised form of sharelist loading with no user semantics implied as per @ref InstateShareListForUsers.
 * @param sesn_ptr User @ref Session corresponding with user for which @ref ShareList is being instated
 * @param shlist_ptr Pre-allocated, uninstated @ref ShareList type
 * @param flag_init if set initialise storage
 * @return
 */
UFSRVResult *
InstateShareListForItems(Session *sesn_ptr, ShareList *shlist_ptr, bool flag_init)
{
  CacheBackendGetShareList(shlist_ptr, SESSION_USERID(sesn_ptr));

  unsigned rescode = RESCODE_PROG_NULL_POINTER;
  if (THREAD_CONTEXT_UFSRV_RESULT_TYPE_SUCCESS) {
    if (!THREAD_CONTEXT_UFSRV_RESULT_CODE_EQUAL_(RESCODE_BACKEND_DATA_EMPTYSET)) {
      redisReply 		*redis_ptr		= (redisReply *)THREAD_CONTEXT_UFSRV_RESULT_USERDATA;

      rescode = THREAD_CONTEXT_UFSRV_RESULT_CODE_;
      if (flag_init)	{
        InitialiseShareListStorage(shlist_ptr);
        (*GetShareListInitialisationSetter(shlist_ptr->list_type))(sesn_ptr, true);
      }

      for (size_t i=0; i < redis_ptr->elements; ++i) {
        unsigned long 	item_id		= strtoul(redis_ptr->element[i]->str, NULL, 10);
        if ((hopscotch_insert(&(shlist_ptr->hashtable), item_id, (void *)item_id)) == 0) {
          //noop
        }
      }

      freeReplyObject(redis_ptr);
    } else {
      //empty set
      rescode = RESCODE_BACKEND_DATA_EMPTYSET; //we still return success on emptyset
    }

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, rescode)
  }

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)
}

/**
 * Loads and initialises sharelist even if backend is empty.
 * @param sesn_ptr Session context for the sharelist
 * @param shlist_ptr sharelist to be initialised
 * @param is_force_initialise Also initialise on error
 * @return
 */
UFSRVResult *
LoadInitialiseShareListForUsersIfNecessary(Session *sesn_ptr, ShareList *shlist_ptr)
{
	if (!(*GetShareListInitialisationChecker(shlist_ptr->list_type))(sesn_ptr)) {
    InstateShareListForUsers(sesn_ptr, shlist_ptr, true);
		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
			if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET))	{
				InitialiseShareListStorage(shlist_ptr);
				(*GetShareListInitialisationSetter(shlist_ptr->list_type))(sesn_ptr, true);
			}

			goto return_sharelist_initialised;
		}	else {
			//don't initialise on backend error
			return SESSION_RESULT_PTR(sesn_ptr);
		}
	}

	return_sharelist_initialised:
	return SESSION_RESULT_PTR(sesn_ptr);
}

UFSRVResult *
LoadInitialiseShareListForItemsIfNecessary(Session *sesn_ptr, ShareList *shlist_ptr)
{
  if (!(*GetShareListInitialisationChecker(shlist_ptr->list_type))(sesn_ptr)) {
    InstateShareListForItems(sesn_ptr, shlist_ptr, true);
    if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
      if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET))	{
        InitialiseShareListStorage(shlist_ptr);
        (*GetShareListInitialisationSetter(shlist_ptr->list_type))(sesn_ptr, true);
      }

      goto return_sharelist_initialised;
    }	else {
      //don't initialise on backend error
      return SESSION_RESULT_PTR(sesn_ptr);
    }
  }

  return_sharelist_initialised:
  return SESSION_RESULT_PTR(sesn_ptr);
}

/**
 * 	@brief This method doesn't perform any allocation/initialisation check on the ShareList. Use specialised methods, such as:
 * 	IsUserOnShareListProfile()
 */
bool
IsUserOnShareListProvided(Session *sesn_ptr_target, ShareList *shlist_ptr)
{
	unsigned long userid = UfsrvUidGetSequenceId(&SESSION_UFSRVUIDSTORE(sesn_ptr_target));

	return (hopscotch_lookup_with_offset(&(shlist_ptr->hashtable), _ShareListItemExtractorCallback, (uint8_t *) &userid,
                                       CONFIG_FENCE_PERMISSIONS_KEYOFFSET(Session, sservice.user.user_details.user_id)) != NULL);
}

/**
 * 	@brief Generalised item look up (as opposed to specialised session id lookup) This method doesn't perform any allocation/initialisation check on the ShareList. Use specialised methods, such as:
 * 	IsUserOnShareListProfile()
 * 	@param item pass pointer to the first byte
 */
bool
IsItemOnShareListProvided(ShareList *shlist_ptr, ShareListItemKeyStoreValue *shlist_item)
{
  return (hopscotch_lookup(&(shlist_ptr->hashtable), shlist_item->key_value) != NULL);
}

/**
 * Iterates the given sharelist and invoke the callback on each item found on the sharelist.
 * User's responsibility to arrange for initialisation.
 * @param shlist_ptr sharelist
 * @param executor user-supplied callback
 * @param ctx_ptr user-supplied data context passed as parameter into the callback
 */
void
InvokeShareListIteratorExecutor(Session *sesn_ptr, ShareList *shlist_ptr, CallbackExecutor executor, ClientContextData *ctx_data_ptr, bool is_initialise)
{
	if (is_initialise) {
    LoadInitialiseShareListForUsersIfNecessary(sesn_ptr, shlist_ptr);
	}

  hopscotch_iterator_executor_with_offset(&(shlist_ptr->hashtable), executor, ctx_data_ptr);
}

/**
 *	@param sesn_ptr: the session to be added to the ShareList, indexed by the hash of its uid
 */
UFSRVResult *
AddUserToShareList(Session *sesn_ptr, ShareList *shlist_ptr, InstanceHolderForSession *instance_sesn_ptr_target, unsigned long sesn_call_flags)
{
  Session *sesn_ptr_target = SessionOffInstanceHolder(instance_sesn_ptr_target);

	if ((*GetShareListPresenceChecker(shlist_ptr->list_type))(sesn_ptr, sesn_ptr_target))	goto return_success_already_in;

	//The above will not initialise storage if backend did not contain any users. This is to economise on memory allocation at the expense of repeated calls to the backend
	if (!(*GetShareListInitialisationChecker(shlist_ptr->list_type))(sesn_ptr)) {
		InitialiseShareListStorage(shlist_ptr);
		(*GetShareListInitialisationSetter(shlist_ptr->list_type))(sesn_ptr, true);
	}

	if ((hopscotch_insert_with_offset(&(shlist_ptr->hashtable), _ShareListItemExtractorCallback,
                                    (void *) instance_sesn_ptr_target,
                                    CONFIG_FENCE_PERMISSIONS_KEYOFFSET(Session, sservice.user.user_details.user_id))) == 0) {
		if (sesn_call_flags&CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND) {
			_CacheBackendAddToShareList(sesn_ptr, shlist_ptr, SESSION_USERID(sesn_ptr_target));
			if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
        SessionIncrementReference(instance_sesn_ptr_target, 1);
				goto return_success;
			} else {
				unsigned long userid = UfsrvUidGetSequenceId(&SESSION_UFSRVUIDSTORE(sesn_ptr_target));
        hopscotch_remove_with_offset(&(shlist_ptr->hashtable), _ShareListItemExtractorCallback, (uint8_t *) &userid,
                                     CONFIG_FENCE_PERMISSIONS_KEYOFFSET(Session, sservice.user.user_details.user_id));
				goto return_error;
			}
		}

		//this is case for INTER commands, where only internal state is affected
		goto return_success;
	}

	return_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_INCONSISTENT_STATE)

	return_success:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_PERMISSION_MEMBERSHIP)

	return_success_already_in:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_USER_SHARELIST_PRESENT)

}

UFSRVResult *
AddItemToShareList(Session *sesn_ptr, ShareList *shlist_ptr, ShareListItemKeyStoreValue *shlist_item, unsigned long sesn_call_flags)
{
  if ((*GetShareListPresenceChecker(shlist_ptr->list_type))(sesn_ptr, (Session *)(uint64_t)shlist_item->key_value))	goto return_success_already_in;

  //The above will not initialise storage if backend did not contain any users. This is to economise on memory allocation at the expense of repeated calls to the backend
  if (!(*GetShareListInitialisationChecker(shlist_ptr->list_type))(sesn_ptr)) {
    InitialiseShareListStorage(shlist_ptr);
    (*GetShareListInitialisationSetter(shlist_ptr->list_type))(sesn_ptr, true);
  }

  if ((hopscotch_insert(&(shlist_ptr->hashtable), shlist_item->key_value, (void *)shlist_item->store_value)) == 0) {
    if (sesn_call_flags&CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND) {
      _CacheBackendAddToShareList(sesn_ptr, shlist_ptr, shlist_item->key_value);
      if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
        goto return_success;
      } else {
        hopscotch_remove(&(shlist_ptr->hashtable), shlist_item->key_value);
        goto return_error;
      }
    }

    //this is case for INTER commands, where only internal state is affected
    goto return_success;
  }

  return_error:
  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_INCONSISTENT_STATE)

  return_success:
  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_PERMISSION_MEMBERSHIP)

  return_success_already_in:
  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_USER_SHARELIST_PRESENT)

}

/**
 *	@param sesn_ptr: user owning the Sharelist
 * 	@param sesn_ptr_target: user to be removed from share list
 * 	@return if the list does not contain the user a RESULT_TYPE_ERR is flagged and error arg set to RESCODE_USER_SHARELIST_PRESENT
 * 	this behaviour is inconsistent with RemoveUserToShareList, which returns RESULT_TYPE_SUCCESS / RESCODE_USER_SHARELIST_PRESENT if user already on the share list
 */
UFSRVResult *
RemoveUserFromShareList(Session *sesn_ptr, ShareList *shlist_ptr, InstanceHolderForSession *instance_sesn_ptr_target, unsigned long sesn_call_flags)
{
  Session *sesn_ptr_target = SessionOffInstanceHolder(instance_sesn_ptr_target);

	//catch both cases where allocated list did not have the user OR if list is backend empty and hence not initialised
	if (!((*GetShareListPresenceChecker(shlist_ptr->list_type))(sesn_ptr, sesn_ptr_target)))	goto return_error_membership;

  //The above will not initialise storage if backend did not contain any users. This is to economise on memory allocation at the expense of repeated calls to the backend
  if (!(*GetShareListInitialisationChecker(shlist_ptr->list_type))(sesn_ptr)) {
    InitialiseShareListStorage(shlist_ptr);
    (*GetShareListInitialisationSetter(shlist_ptr->list_type))(sesn_ptr, true);
  }

	if (sesn_call_flags&CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND) {
		_CacheBackendRemoveFromShareList(sesn_ptr, shlist_ptr, SESSION_USERID(sesn_ptr_target));
		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
			InstanceHolderForSession *instance_sesn_ptr_removed;
			unsigned long userid	=	UfsrvUidGetSequenceId(&SESSION_UFSRVUIDSTORE(sesn_ptr_target));

			if (IS_PRESENT((instance_sesn_ptr_removed = hopscotch_remove_with_offset(&(shlist_ptr->hashtable), _ShareListItemExtractorCallback, (uint8_t *) &userid, CONFIG_FENCE_PERMISSIONS_KEYOFFSET(Session, sservice.user.user_details.user_id))))) {
        SessionDecrementReference(instance_sesn_ptr_removed, 1);

				goto return_success;
			}
		}

		goto return_error;
	} else {
		InstanceHolderForSession *instance_sesn_ptr_removed;
		unsigned long userid	=	UfsrvUidGetSequenceId(&SESSION_UFSRVUIDSTORE(sesn_ptr_target));

		if (IS_PRESENT((instance_sesn_ptr_removed = hopscotch_remove_with_offset(&(shlist_ptr->hashtable), _ShareListItemExtractorCallback, (uint8_t *) &userid, CONFIG_FENCE_PERMISSIONS_KEYOFFSET(Session, sservice.user.user_details.user_id))))) {
      SessionDecrementReference(instance_sesn_ptr_removed, 1);

			goto return_success;
		}
		else goto return_error;
	}

	return_error_membership:
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_USER_SHARELIST_PRESENT);

	return_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_INCONSISTENT_STATE);

	return_success:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_PERMISSION_MEMBERSHIP);

}

/**
 * @brief generalised item removal
 * @param sesn_ptr User session with sharelist to be removed from
 * @param shlist_ptr target share list
 * @param item_descriptor item to be removed
 * @param sesn_call_flags
 * @return
 */
UFSRVResult *
RemoveItemFromShareList(Session *sesn_ptr, ShareList *shlist_ptr, ShareListItemKeyStoreValue *shlist_item, unsigned long sesn_call_flags)
{
  //catch both cases where allocated list did not have the item OR if list is backend empty and hence not initialised
  if (!((*GetShareListPresenceChecker(shlist_ptr->list_type))(sesn_ptr, (Session *)(uint64_t)shlist_item->key_value)))	goto return_error_membership;

  //The above will not initialise storage if backend did not contain any users. This is to economise on memory allocation at the expense of repeated calls to the backend
  if (!(*GetShareListInitialisationChecker(shlist_ptr->list_type))(sesn_ptr)) {
    InitialiseShareListStorage(shlist_ptr);
    (*GetShareListInitialisationSetter(shlist_ptr->list_type))(sesn_ptr, true);
  }

  if (sesn_call_flags&CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND) {
    _CacheBackendRemoveFromShareList(sesn_ptr, shlist_ptr, shlist_item->store_value);
    if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {

      //returned value should match item_descriptor->store_value
      if (IS_PRESENT((hopscotch_remove(&shlist_ptr->hashtable, shlist_item->key_value)))) {
        goto return_success;
      }
    }

    goto return_error;
  } else {
    if (IS_PRESENT((hopscotch_remove(&shlist_ptr->hashtable, shlist_item->key_value)))) {
      goto return_success;
    }
    else goto return_error;
  }

  return_error_membership:
  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_USER_SHARELIST_PRESENT);

  return_error:
  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_INCONSISTENT_STATE);

  return_success:
  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_FENCE_PERMISSION_MEMBERSHIP);

}

HopscotchHashtable *
InitialiseShareListStorage(ShareList *shlist_ptr)
{
  return (*GetShareListInitialiser(shlist_ptr->list_type))(&(shlist_ptr->hashtable), CONFIG_FENCE_PERMISSIONS_PFACTOR);
//	return hopscotch_init_with_offset(&(shlist_ptr->hashtable), CONFIG_FENCE_PERMISSIONS_PFACTOR);
}

/**
 * @brief post list item removal op on removed item
 * @param shlist_ptr
 * @param finaliser callback issued on removed item in unextracted state
 */
void DestructShareListStorage(ShareList *shlist_ptr, CallbackFinaliser finaliser)
{
  if (!IS_EMPTY(finaliser)) {
    hopscotch_iterator_finaliser(&(shlist_ptr->hashtable), finaliser);
  }

	hopscotch_release(&(shlist_ptr->hashtable));
}

/**
 * 	@brief: main entry point for loading sharelists as part of Session instantiation. Lists Should be in an uninitialised state.
 */
void LoadShareLists(Session *sesn_ptr)
{
  InstateShareListForUsers(sesn_ptr, SESSION_USERPREF_SHLIST_PROFILE_PTR(sesn_ptr), INIT_FLAG_TRUE);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr) && !SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET))	SESSION_LISTS_INIT_STATE_PROFILE(sesn_ptr) = true;

  InstateShareListForUsers(sesn_ptr, SESSION_USERPREF_SHLIST_LOCATION_PTR(sesn_ptr), INIT_FLAG_TRUE);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr) && !SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET))	SESSION_LISTS_INIT_STATE_LOCATION(sesn_ptr) = true;

  InstateShareListForUsers(sesn_ptr, SESSION_USERPREF_SHLIST_NETSTATE_PTR(sesn_ptr), INIT_FLAG_TRUE);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr) && !SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET))	SESSION_LISTS_INIT_STATE_NETSTATE(sesn_ptr) = true;

  InstateShareListForUsers(sesn_ptr, SESSION_USERPREF_SHLIST_CONTACTS_PTR(sesn_ptr), INIT_FLAG_TRUE);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr) && !SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET))	SESSION_LISTS_INIT_STATE_CONTACTS(sesn_ptr) = true;

  InstateShareListForUsers(sesn_ptr, SESSION_USERPREF_SHLIST_BLOCKED_PTR(sesn_ptr), INIT_FLAG_TRUE);
  if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr) && !SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET))	SESSION_LISTS_INIT_STATE_BLOCKED(sesn_ptr) = true;

  InstateShareListForUsers(sesn_ptr, SESSION_USERPREF_SHLIST_READ_RECEIPT_PTR(sesn_ptr), INIT_FLAG_TRUE);
  if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr) && !SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET))	SESSION_LISTS_INIT_STATE_READ_RECEIPT(sesn_ptr) = true;

  InstateShareListForUsers(sesn_ptr, SESSION_USERPREF_SHLIST_ACTIVITY_STATE_PTR(sesn_ptr), INIT_FLAG_TRUE);
  if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr) && !SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET))	SESSION_LISTS_INIT_STATE_ACTIVITY_STATE(sesn_ptr) = true;

  InstateShareListForItems(sesn_ptr, SESSION_USERPREF_SHLIST_BLOCKED_FENCE_PTR(sesn_ptr), INIT_FLAG_TRUE);
  if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr) && !SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET))	SESSION_LISTS_INIT_STATE_BLOCKED_FENCE(sesn_ptr)=true;
}

void DestructShareLists(Session *sesn_ptr)
{
	if (IsHopscotchHashtableAllocated (&(SESSION_USERPREF_SHLIST_PROFILE(sesn_ptr).hashtable)))		{
		DestructShareListStorage(SESSION_USERPREF_SHLIST_PROFILE_PTR(sesn_ptr), (CallbackFinaliser )SessionDecrementReferenceByOne);
		SESSION_LISTS_INIT_STATE_PROFILE(sesn_ptr)=false;
	}
	if (IsHopscotchHashtableAllocated (&(SESSION_USERPREF_SHLIST_LOCATION(sesn_ptr).hashtable)))	{
		DestructShareListStorage(SESSION_USERPREF_SHLIST_LOCATION_PTR(sesn_ptr), (CallbackFinaliser )SessionDecrementReferenceByOne);
		SESSION_LISTS_INIT_STATE_LOCATION(sesn_ptr)=false;
	}
	if (IsHopscotchHashtableAllocated (&(SESSION_USERPREF_SHLIST_NETSTATE(sesn_ptr).hashtable)))	{
		DestructShareListStorage(SESSION_USERPREF_SHLIST_NETSTATE_PTR(sesn_ptr), (CallbackFinaliser )SessionDecrementReferenceByOne);
		SESSION_LISTS_INIT_STATE_NETSTATE(sesn_ptr)=false;
	}
	if (IsHopscotchHashtableAllocated (&(SESSION_USERPREF_SHLIST_CONTACTS(sesn_ptr).hashtable)))		{
    DestructShareListStorage(SESSION_USERPREF_SHLIST_CONTACTS_PTR(sesn_ptr), (CallbackFinaliser )SessionDecrementReferenceByOne);
	  SESSION_LISTS_INIT_STATE_CONTACTS(sesn_ptr)=false;
  }
  if (IsHopscotchHashtableAllocated (&(SESSION_USERPREF_SHLIST_BLOCKED(sesn_ptr).hashtable)))		{
    DestructShareListStorage(SESSION_USERPREF_SHLIST_BLOCKED_PTR(sesn_ptr), (CallbackFinaliser )SessionDecrementReferenceByOne);
    SESSION_LISTS_INIT_STATE_BLOCKED(sesn_ptr)=false;
  }

  if (IsHopscotchHashtableAllocated (&(SESSION_USERPREF_SHLIST_READ_RECEIPT(sesn_ptr).hashtable)))	{
    DestructShareListStorage(SESSION_USERPREF_SHLIST_READ_RECEIPT_PTR(sesn_ptr), (CallbackFinaliser )SessionDecrementReferenceByOne);
    SESSION_LISTS_INIT_STATE_READ_RECEIPT(sesn_ptr)=false;
  }

  if (IsHopscotchHashtableAllocated (&(SESSION_USERPREF_SHLIST_ACTIVITY_STATE(sesn_ptr).hashtable)))	{
    DestructShareListStorage(SESSION_USERPREF_SHLIST_ACTIVITY_STATE_PTR(sesn_ptr), (CallbackFinaliser )SessionDecrementReferenceByOne);
    SESSION_LISTS_INIT_STATE_ACTIVITY_STATE(sesn_ptr)=false;
  }
}

static UFSRVResult *
_CacheBackendAddToShareList(Session *sesn_ptr, ShareList *shlist_ptr, unsigned long item_key)
{
	unsigned 						rescode			=	RESCODE_BACKEND_DATA;
	PersistanceBackend	*pers_ptr		=	THREAD_CONTEXT_PERSISTANCE_CACHEBACKEND(ufsrv_thread_context);

  (*pers_ptr->send_command_multi)(sesn_ptr, "MULTI");
	(*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_SHARELIST_ADD, shlist_ptr->list_type, SESSION_USERID(sesn_ptr), time(NULL), item_key);
  (*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_SHAREDLIST_ADD, item_key, SESSION_USERID(sesn_ptr), shlist_ptr->list_type);
  (*pers_ptr->send_command_multi)(sesn_ptr,	"EXEC");

#define COMMANDSET_SIZE	4
  size_t				actually_processed	=	COMMANDSET_SIZE;
  size_t				commands_successful	=	actually_processed;
  redisReply		*replies[actually_processed];
  memset (replies, 0, sizeof(replies));

  for (size_t i=0; i<actually_processed; i++) {
    if ((RedisGetReply(sesn_ptr, pers_ptr, (void *)&replies[i])) != REDIS_OK) {
      commands_successful--;

      if ((replies[i] != NULL)) {
        syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', idx:'%lu'): ERROR PROCESSING MULTI SET COMMAND. ERROR: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i, replies[i]->str);
      } else {
        syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', i:'%lu'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i);
      }
    }
  }

  //diagnostics
  if (commands_successful != actually_processed) {
    for (size_t i=0; i<actually_processed; i++)	if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
  }

  //verification block
#define EXEC_COMMAND_IDX (actually_processed - 1)

  //drain responses upto EXEC index
  for (size_t i=0; i<actually_processed-1; i++)	if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);

  if (unlikely(IS_EMPTY(replies[EXEC_COMMAND_IDX]))) {//idx for EXEC, which is last
    syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR: REDIS TRANSCTION ERROR: NULL COMMAND ARRAY RESPONSE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
  }

  if (replies[EXEC_COMMAND_IDX]->elements == actually_processed - 2) {
    bool is_error = false;
    //these should be contextual to the actual return codes for the above commands
    if (replies[EXEC_COMMAND_IDX]->element[0]->type != REDIS_REPLY_INTEGER) {
      syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', error:'%s'): ERROR: REDIS_CMD_SHARELIST_ADD Failed", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), replies[EXEC_COMMAND_IDX]->element[0]->str);
      is_error = true;
    }
    if (replies[EXEC_COMMAND_IDX]->element[1]->type != REDIS_REPLY_INTEGER)	{
      syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', error:'%s'): ERROR: REDIS_CMD_SHAREDLIST_ADD Failed", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), replies[EXEC_COMMAND_IDX]->element[1]->str);
      is_error = true;
    }

    freeReplyObject(replies[EXEC_COMMAND_IDX]);
    if (is_error) _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
  } else {
    //only remaining element is at EXEC_COMMAND_IDX
    syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', dispatched:'%lu', received:'%lu'): ERROR: REDIS TRANSCTION ERROR: DISPATCHED/RECEIVED COMMANDS COUNT MISMATCH", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), actually_processed-2, replies[EXEC_COMMAND_IDX]->elements);
    if (IS_PRESENT(replies[EXEC_COMMAND_IDX]))	freeReplyObject(replies[EXEC_COMMAND_IDX]);

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
  }

		return_success:
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, rescode);

#undef COMMANDSET_SIZE
#undef EXEC_COMMAND_IDX
}

UFSRVResult *
_CacheBackendRemoveFromShareList(Session *sesn_ptr, ShareList *shlist_ptr, unsigned long item_id)
{
	unsigned 						rescode			=	RESCODE_BACKEND_DATA;
	PersistanceBackend	*pers_ptr		=	THREAD_CONTEXT_PERSISTANCE_CACHEBACKEND(ufsrv_thread_context);
	redisReply 					*redis_ptr	=	NULL;

	(*pers_ptr->send_command_multi)(sesn_ptr, "MULTI");
	(*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_SHARELIST_REM, shlist_ptr->list_type, SESSION_USERID(sesn_ptr), item_id);
	(*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_SHAREDLIST_REM, item_id, SESSION_USERID(sesn_ptr), shlist_ptr->list_type);
	(*pers_ptr->send_command_multi)(sesn_ptr,	"EXEC");

#define COMMANDSET_SIZE	4
	size_t				actually_processed	=	COMMANDSET_SIZE;
	size_t				commands_successful	=	actually_processed;
	redisReply		*replies[actually_processed];
	memset(replies, 0, sizeof(replies));

	for (size_t i=0; i<actually_processed; i++) {
		if ((RedisGetReply(sesn_ptr, pers_ptr, (void *)&replies[i])) != REDIS_OK) {
			commands_successful--;

			if ((replies[i] != NULL)) {
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', idx:'%lu'): ERROR PROCESSING MULTI SET COMMAND. ERROR: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i, replies[i]->str);
			} else {
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', i:'%lu'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i);
			}
		}
	}//for

	//diagnostics
	if (commands_successful != actually_processed) {
		for (size_t i=0; i<actually_processed; i++)	if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
	}

	//verification block
#define EXEC_COMMAND_IDX (actually_processed - 1)

	//drain responses upto EXEC index
	for (size_t i=0; i<actually_processed-1; i++)	if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);

	if (unlikely(IS_EMPTY(replies[EXEC_COMMAND_IDX]))) {//idx for EXEC, which is last
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR: REDIS TRANSACTION ERROR: NULL COMMAND ARRAY RESPONSE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
	}

	if (replies[EXEC_COMMAND_IDX]->elements == actually_processed - 2) {
		bool is_error = false;
		//these should be contextual to the actual return codes for the above commands
		if (replies[EXEC_COMMAND_IDX]->element[0]->type != REDIS_REPLY_INTEGER) {
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', error:'%s'): ERROR: REDIS_CMD_SHARELIST_REM Failed", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), replies[EXEC_COMMAND_IDX]->element[0]->str);
			is_error = true;
		}
		if (replies[EXEC_COMMAND_IDX]->element[1]->type != REDIS_REPLY_INTEGER)	{
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', error:'%s'): ERROR: REDIS_CMD_SHAREDLIST_REM Failed", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), replies[EXEC_COMMAND_IDX]->element[1]->str);
			is_error = true;
		}

		freeReplyObject(replies[EXEC_COMMAND_IDX]);
		if (is_error) _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
	} else {
		//only remaining element is at EXEC_COMMAND_IDX
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', dispatched:'%lu', received:'%lu'): ERROR: REDIS TRANSCTION ERROR: DISPATCHED/RECEIVED COMMANDS COUNT MISMATCH", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), actually_processed-2, replies[EXEC_COMMAND_IDX]->elements);
		if (IS_PRESENT(replies[EXEC_COMMAND_IDX]))	freeReplyObject(replies[EXEC_COMMAND_IDX]);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
	}

	return_success:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, rescode);

#undef COMMANDSET_SIZE
#undef EXEC_COMMAND_IDX

}

/**
 * @brief Delete all sharing lists asociated with this user at the cache backend.
 * @param sesn_ptr Session representing user
 */
UFSRVResult *
CacheBackendClearSessionSharingLists(Session *sesn_ptr, __unused unsigned long call_flags)
{
  size_t				actually_processed;
  PersistanceBackend	*pers_ptr = sesn_ptr->persistance_backend;

  (*pers_ptr->send_command_multi)(sesn_ptr, "MULTI");
  (*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_SHARELIST_REM_ALL, SHARELIST_PROFILE, SESSION_USERID(sesn_ptr));
  (*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_SHARELIST_REM_ALL, SHARELIST_LOCATION, SESSION_USERID(sesn_ptr));
  (*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_SHARELIST_REM_ALL, SHARELIST_CONTACT, SESSION_USERID(sesn_ptr));
  (*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_SHARELIST_REM_ALL, SHARELIST_NETSTATE, SESSION_USERID(sesn_ptr));
//  (*pers_ptr->send_command_multi)(sesn_ptr,  REDIS_CMD_SHARELIST_REM_ALL, SHARELIST_FRIENDS, SESSION_USERID(sesn_ptr)); //remember to increase actually_processed by 1 if uncommented
  (*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_SHARELIST_REM_ALL, SHARELIST_BLOCKED, SESSION_USERID(sesn_ptr));
  (*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_SHARELIST_REM_ALL, SHARELIST_READ_RECEIPT, SESSION_USERID(sesn_ptr));
  (*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_SHARELIST_REM_ALL, SHARELIST_ACTIVITY_STATE, SESSION_USERID(sesn_ptr));
  (*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_SHARELIST_REM_ALL, SHARELIST_BLOCKED_FENCE, SESSION_USERID(sesn_ptr));

  (*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_SHAREDLIST_REM_ALL, SESSION_USERID(sesn_ptr)); ////todo 10/2/25 devops: should retrieve the list of users and for each user issue: "ZREM SHL_%i:%lu(userid retrieved) %lu(this user id)"

  (*pers_ptr->send_command_multi)(sesn_ptr, "EXEC");
  actually_processed = 11;

  size_t 		i;
  redisReply	**replies;

  replies = calloc(actually_processed, sizeof(redisReply *));
  //TODO: we need error recover for intermediate errors
  for (i=0; i<actually_processed; i++) {
    if ((RedisGetReply(sesn_ptr, pers_ptr, (void *)&replies[i]) != REDIS_OK)) {
      syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cmd_idx:'%lu'}: ERROR: REDIS COMMAND IN MULTI SET FAILED", __func__, pthread_self(), sesn_ptr, i);

      if ((replies[i] != NULL) && (replies[i]->type != REDIS_REPLY_NIL)) {
        syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', sharelist_idx:'%lu'): ERROR: Sharing list deletion failed: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i, replies[i]->element[1]->str);
      }
    }

    if (!IS_EMPTY(replies[i]))	freeReplyObject(replies[i]);
  }

  free(replies);

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);

}