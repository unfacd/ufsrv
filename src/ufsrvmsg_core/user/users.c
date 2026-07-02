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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <ufsrvmsg_core/user/users.h>
#include <ufsrvmsg_core/user/user_preferences.h>
#include <ufsrvmsg_core/user/user_backend.h>
#include <session_cachebackend.h>
#include <share_list.h>
#include <user_broadcast.h>
#include <fence/fence.h>
#include <ufsrv_core/cache_backend/persistance.h>
#include <location/location.h>
#include <ufsrvmsg_core/fence/fence_utils.h>
#include <attachments.h>
#include <ufsrvmsg_core/user/user_preference_descriptor_type.h>
#include <uflib/ufsrvuid.h>
#include <message.h>
#include <ufsrvmsg_core/user/user_type.h>
#include <uflib/recycler/instance_type.h>
#include <uflib/utils_str.h>
#include <include/guardian_record_descriptor.h>
#include <ufsrvmsg_core/user/user_profile.h>
#include <utils_db_account.h>
#include <uflib/recycler/recycler.h>
#include <fence/fence_state.h>
#include <json_attribute_names_fence.h>

extern ufsrv							*const masterptr;
extern __thread ThreadContext ufsrv_thread_context;

static pthread_rwlock_t       master_user_registry_rwlock;

static void _SetBooleanPrefByOffset(Session *sesn_ptr, UserPrefsOffsets pref_offset, bool value);
static bool	_GetBooleanPrefByOffset(Session *sesn_ptr, UserPrefsOffsets pref_offset);
static UserPreferenceDescriptor *_SetLocalUserPreferenceBoolean(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in);
static UFSRVResult *_CacheBackendGetRawSessionRecordByUserId(unsigned long user_id, unsigned call_flags);

static UserPreferenceDescriptor * _PrefValidateNickname(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr);
static UserPreferenceDescriptor * _SetLocalUserPreferenceNickname(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in);

static UserPreferenceDescriptor * _PrefValidateAvatar(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr);
static UserPreferenceDescriptor * _SetLocalUserPreferenceAvatar(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in);

static UserPreferenceDescriptor * _PrefValidateE164Number(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr);
static UserPreferenceDescriptor * _SetLocalUserPreferenceE164Number(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in);

static UserPreferenceDescriptor *_PrefValidateUnsolicitedContactAction(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr);
static UserPreferenceDescriptor *_PrefValidateGuardianUid(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr);
static UserPreferenceDescriptor *_SetLocalGuardianUid(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in);
static UserPreferenceDescriptor *_GetLocalGuardianUid(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in);

static UserPreferenceDescriptor *_PrefValidateGeolocTrigger(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr);
static UserPreferenceDescriptor *_PrefValidateBaselocZone(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr);
static UserPreferenceDescriptor *_PrefValidateHomebaseGeoLoc(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr);
static UserPreferenceDescriptor *_SetLocalGeolocTrigger(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in);
static UserPreferenceDescriptor *_GetLocalGeolocTrigger(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in);
static UserPreferenceDescriptor *_SetLocalBaselocZone(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in);
static UserPreferenceDescriptor *_GetLocalBaselocZone(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in);
static UserPreferenceDescriptor *_SetLocalHomebaseLoc(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in);
static UserPreferenceDescriptor *_GetLocalHomebaseLoc(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in);

unsigned CompareUserId(void *, unsigned long);

/**
 *	This is not doing anything at the moment with this mutex
 */
void InitialiseMasterUserRegistry(void)
{
	int init_state = pthread_rwlock_init(&master_user_registry_rwlock, NULL);
	if (init_state == 0)	syslog(LOG_INFO, "%s: SUCCESS: Master user registry initialised(NOT IN USE)", __func__);
	else {
		syslog(LOG_INFO, "%s: ERROR: COULD NOT initialise Master user registry: exiting...",__func__);
		_exit(-1);
	}

}

/**
 * @brief: Based on session_id and user_id the function checks if the user has a record in the local hash tables: hashed_sessions and hashed_userid. If session is provided
 * as a validation the provided user_id is checked with the one present in the retrieved session.
 * If no session is provided, the user_id is used for local hashtable lookup. If found the data field of the returned UFSRVResult will contain
 * SessionService pointer. No validation is provided on the status of the session.
 * If lookup fails and offline flag is turned on, a redis backend lookup is performed.
 *
 *	@paramsesn_ptr_carrier: carrier session not necessarily related to the user being lookup.
 *
 * @dynamic_memory redisReply *: EXPORT IF RESCODE_USER_BACKEND IS RETURNED )via  _CacheBackendGetRawSessionRecordByUserId())
 *
 * @return InstanceHolderForSession
 * @return RESCODE_USER_ONLINE: on success with data field set to retrieved session from local hash
 * @return  RESCODE_USER_BACKEND: on success with data field set to raw redis_ptr containing backend session information for the user
 * @return RESCODE_USER_NOTONLINE: if user could not be looked up, but not as a result of error. This is also returned (as ERR) if record existed in
 *																	CacheBackend, but its status was set to '0', indicating a potentially stale/invalidated record
 * @locks: NONE
 */
UFSRVResult *
FindSessionForUserLocalOrBackend(Session *sesn_ptr_carrier, unsigned long session_id, unsigned long user_id, unsigned call_flags)
{
	if (session_id > 0 && user_id > 0) {
	  Session *sesn_ptr_aux;
    InstanceHolderForSession *instance_sesn_ptr_aux = LocallyLocateSessionById(session_id);
		if (IS_PRESENT(instance_sesn_ptr_aux)) {
		  sesn_ptr_aux = SessionOffInstanceHolder(instance_sesn_ptr_aux);

			if (SESSION_USERID(sesn_ptr_aux) == user_id) { /*extra check*/
#ifdef __UF_TESTING
				if (SESNSTATUS_IS_SET(sesn_ptr_aux->stat, SESNSTATUS_REMOTE)) {
					syslog(LOG_DEBUG, "%s : FOUND REMOTE LOCALLY SESSION-HASHED cid:'%lu' uid:'%lu'", __func__, SESSION_ID(sesn_ptr_aux), SESSION_USERID(sesn_ptr_aux));
				}
#endif
				_RETURN_RESULT_SESN(sesn_ptr_carrier, instance_sesn_ptr_aux, RESULT_TYPE_SUCCESS, RESCODE_USER_ONLINE)
			}
		}
	} else if (user_id > 0) {
	  //session_id was <0 we search across online registry. this is what clients send us only uid
		InstanceHolderForSession *instance_sesn_ptr_other_user = LocallyLocateSessionByUserId(user_id);
		if (IS_PRESENT(instance_sesn_ptr_other_user)) {
		  Session *sesn_ptr_other_user = SessionOffInstanceHolder(instance_sesn_ptr_other_user);

#pragma region session_diagnostics
#ifdef __UF_TESTING
			if (SESNSTATUS_IS_SET(sesn_ptr_other_user->stat, SESNSTATUS_SUSPENDED))/*diagnostic only*/ {
				syslog(LOG_DEBUG, "%s {pid:'%lu'}: FOUND SUSPENDED SESSION USING USERID: '%lu'. SUSPENDED SESSION: '%lu'" , __func__, pthread_self(), user_id, sesn_ptr_other_user->session_id);
			}

			if (SESNSTATUS_IS_SET(sesn_ptr_other_user->stat, SESNSTATUS_REMOTE)) {
				syslog(LOG_DEBUG, "%s {pid:'%lu'}: FOUND REMOTE LOCALLY SESSION-HASHED cid:'%lu' uid:'%lu'", __func__, pthread_self(), SESSION_ID(sesn_ptr_other_user), SESSION_USERID(sesn_ptr_other_user));
			}
#endif
#pragma endregion

			_RETURN_RESULT_SESN(sesn_ptr_carrier, instance_sesn_ptr_other_user, RESULT_TYPE_SUCCESS, RESCODE_USER_ONLINE)
		} else if (call_flags&CALL_FLAG_SEARCH_BACKEND) {
#ifdef __UF_TESTING
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', uid_supplied:'%lu'}: Could not locate Session locally using UID: Searching CacheBackend...", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), user_id);
#endif

			return (_CacheBackendGetRawSessionRecordByUserId(user_id, call_flags)); //this returns redisReply * and RESCODE_USER_BACKEND
		} else {
#ifdef __UF_TESTING
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', uid_supplied:'%lu'}: COULD NOT locate session locally using supplied userid and CacheBackend search wasn't flagged.", __func__, pthread_self(), sesn_ptr_carrier, SESSION_ID(sesn_ptr_carrier), user_id);
#endif
			_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, RESCODE_USER_NOTONLINE)
		}
	} else {
		syslog(LOG_DEBUG, "%s {pid:'%lu'}: session id AND uid were zero: uid: '%lu'. cid='%lu'", __func__, pthread_self(), user_id, session_id); //some validation errors
	}

	_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL,  RESULT_TYPE_NOOP, RESCODE_PROG_NULL_POINTER)

}

/**
 * @brief Searches the CacheBackend for a record of the user's session, whilst verifying if the status field is marked active (other than 0).
 *  0 mostly indicates stale session data.
 *  This is a legacy method which maybe phased out.
 *  IMPORTANT: SESSION IS NOT LOADED WITH DB BACKEND PERSISTED DATA, OR PREFERENCES. Should be paired with CacheBackendInstantiateSessionRecord()
 *
 * @success_case
 * user record found in the backend with status other than '0' ie. 'QUIT'
 *
 * 	@return UFSRVResult from THREAD_CONTEXT with the data field set to the redis_ptr object containing the raw redis record.
 *
 *  @dynamic_memory redis_ptr: EXPORTS ONLY IF RESCODE_USER_BACKEND IS THE RESULT CODE VALUE
 */
UFSRVResult *
_CacheBackendGetRawSessionRecordByUserId(unsigned long user_id, unsigned call_flags)
{
	if (likely(user_id > 0)) {
    CacheBackendGetRawSessionRecordByUserId(user_id, call_flags, THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));

		if (THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA) {
			redisReply *redis_ptr = (redisReply *)THREAD_CONTEXT_UFSRV_RESULT_USERDATA;

			if ((atoi(redis_ptr->element[REDIS_KEY_USER_STATUS]->str)) == 0) {
#ifdef __UF_TESTING
				syslog(LOG_DEBUG, "%s (pid:'%lu', th_ctx:'%p', uid:'%lu'): RECORD FOR USER IS OF STATUS '0'. RECORD WILL BE OVERRIDEN",  __func__, pthread_self(), THREAD_CONTEXT_PTR, user_id);
#endif
				freeReplyObject(redis_ptr);

				THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_USER_NOTONLINE)//aka QUIT)
			}

      THREAD_CONTEXT_RETURN_RESULT_SUCCESS(redis_ptr, RESCODE_USER_BACKEND)//online via backend verification
		}
	}

	return_error:
  THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_PROG_NULL_POINTER)

}

//used as comparator
//used in callback context within an iterator: currently used to iterate through Sessions and compare user id
unsigned CompareUserId(void *ss_ptr, unsigned long user_id)
{
 if (UfsrvUidGetSequenceId(&((SessionService *)ss_ptr)->user.user_details.uid) == user_id)  return 1;
 else return 0;

}

UFSRVResult *
CacheBackendsUpdateForUfsrvUid(Session *sesn_ptr_carrier, unsigned long userid, const UfsrvUid *uid_ptr)
{
  redisReply *redis_ptr;
  if ((redis_ptr = (*sesn_ptr_carrier->persistance_backend->send_command)(sesn_ptr_carrier, REDIS_CMD_USER_SESSION_UFSRVUID_SET, userid, uid_ptr->data, CONFIG_MAX_UFSRV_ID_SZ))) {
    freeReplyObject(redis_ptr);
    _RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
  } else {
    _RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

}

int
LoadDefaultUserPreferences(Session *sesn_ptr)
{
	SESSION_USERPREF_ONOFF_SET(sesn_ptr, roaming_mode, 1);
	SESSION_USERPREF_ONOFF_SET(sesn_ptr, roaming_mode_wanderer, 1);

	return 1;
}

void
ResetUser(InstanceHolderForSession *instance_sesn_ptr_target, unsigned call_flags)
{
  Session *sesn_ptr_target = SessionOffInstanceHolder(instance_sesn_ptr_target);
	SessionService *ss_ptr = SESSION_SERVICE(sesn_ptr_target);

	if (SESNSTATUS_IS_SET(sesn_ptr_target->stat, SESNSTATUS_SNAPSHOT))	RemoveUserFromAllFencesSessionInstanceOnly (sesn_ptr_target, call_flags);
	else																																RemoveUserFromAllFences(instance_sesn_ptr_target, call_flags);

	if (ss_ptr->user.user_details.user_name) 	free(ss_ptr->user.user_details.user_name);
	if (ss_ptr->user.user_details.password)		free(ss_ptr->user.user_details.password);
	if (IS_PRESENT(SESSION_CMTOKEN(sesn_ptr_target))) free(SESSION_CMTOKEN(sesn_ptr_target));
	SESSION_CMTOKEN(sesn_ptr_target) = NULL;

	memset(SESSION_USER_PROFILE_KEY(sesn_ptr_target), '\0', CONFIG_USER_PROFILEKEY_MAX_SIZE);

	ResetUserPreferences(sesn_ptr_target);
	DestructShareLists(sesn_ptr_target);
	DestructLocationDescription(&(ss_ptr->user.user_details.user_location));
	DestructLocationDescription(&(ss_ptr->user.user_details.user_location_by_server));

	memset(&(ss_ptr->user), 0, sizeof(User));

	LoadDefaultUserPreferences(sesn_ptr_target);

}

/**
 * @brief This will nullify the cmtoken if it cannot be reloaded from the backend.
 * @param sesn_ptr
 * @param cm_token_provided Use this token instead of querying the backend
 */
void
ReloadCMToken(Session *sesn_ptr, const char *cm_token_provided)
{
  char *cm_token = NULL;

  if (IS_STR_LOADED(cm_token_provided)) {
    cm_token = strdup(cm_token_provided);
  } else {
    cm_token = DbGetGcmId(sesn_ptr, &(SESSION_UFSRVUIDSTORE(sesn_ptr)), DEFAULT_DEVICE_ID);
  }

  //todo: check for equality and abandon

  if (IS_PRESENT(cm_token)) {
    if (IS_PRESENT(SESSION_CMTOKEN(sesn_ptr))) {
      memset(SESSION_CMTOKEN(sesn_ptr), 0, strlen(SESSION_CMTOKEN(sesn_ptr)));
      free(SESSION_CMTOKEN(sesn_ptr));
    }

    SESSION_CMTOKEN(sesn_ptr) = cm_token;
  } else {
    if (IS_PRESENT(SESSION_CMTOKEN(sesn_ptr))) {
      memset(SESSION_CMTOKEN(sesn_ptr), 0, strlen(SESSION_CMTOKEN(sesn_ptr)));
      free(SESSION_CMTOKEN(sesn_ptr));
    }

    SESSION_CMTOKEN(sesn_ptr) = NULL;
  }

}

//just basic multiples manipulation to get which multiples of 8-bit group (RangeGroup) this pref belongs in
__attribute__((pure)) static inline size_t
_GetBitFieldRangeGroup(UserPrefsOffsets pref)
{
	int r = pref % REDIS_BITFIELDS_ALIGNMENT_FACTOR;
	//return r? (pref+(REDIS_BITFIELDS_ALIGNMENT_FACTOR - r))/8 : pref/8;
	return  (pref + (REDIS_BITFIELDS_ALIGNMENT_FACTOR - r)) / 8;
	//0%8=0		0+(8-0)=8		8/8=1
	//1%8=1, 	1+(8-1)=8, 	8/8=1
	//6%8=6, 	6+(8-6)=8,		8/8=1
	//7%8=7,	7+(8-7)=8,	8/8=1

	//8%8=0,	8+(8-0)=16, 16/8=2
	//9%8=1, 	9+(8-1)=16, 	16/8=2

}

static UFSRVResult *_HandleIntraMessageCommandForUserPrefs(Session *sesn_ptr, SessionMessage *sesn_msg_ptr);
static UFSRVResult *_ProcessIntraMessageCommandForUserPref(Session *sesn_ptr, UserPreference *sesn_msg_pref_ptr);

typedef ClientContextData * (*PreferenceValueFormatter)(ClientContextData *, UserPreferenceDescriptor *, ClientContextData *, PrefsStore);

#include <user/data/data_UserPreferenceDescriptor.h>

static UserPreferences user_prefs_table = {
		.prefs_table_sz=sizeof(prefs_table)/sizeof(UserPreferenceDescriptor),
		.prefs_table=(UserPreferenceDescriptor **)prefs_table,
		.type_ops={
				.intra_msg_handler=(UFSRVResult * (*)(ClientContextData *, CommandContextData *))_HandleIntraMessageCommandForUserPrefs
		}
};

/**
 * @brief Generic extractor for objects enclosed in InstanceHolder
 * @param item_container_ptr item stored in sharelist in its native format (ie requring extraction)
 */
ClientContextData *
ShareListItemExtractorCallback(ItemContainer *item_container_ptr)
{
  return GetClientContextData((InstanceHolder *)item_container_ptr);
}

/**
 * @brief return a statically allocated type defining a generalised ShareListItemDescriptor configuration for items stored
 * in ShareLists. Not thread safe and user should not attempt to reassign values.
 */
ShareListItemDescriptor *const
ProvideDefaultShareListItemDescriptor(void)
{
  static ShareListItemDescriptor default_sharelist_item_descriptor = {
          .size = sizeof(unsigned long),
          .key_offset = CONFIG_FENCE_PERMISSIONS_KEYOFFSET(Session, sservice.user.user_details.user_id),
          .extractor_callback = ShareListItemExtractorCallback
  };

  return &default_sharelist_item_descriptor;
}

/**
 * @brief return a statically allocated type defining a generalised ShareListItemDescriptor configuration for items stored
 * in ShareLists for BlockedFence. Not thread safe and user should not attempt to reassign values.
 */
ShareListItemDescriptor *const
ProvideDefaultShareListItemDescriptorForBlockedFence(void)
{
  static ShareListItemDescriptor default_sharelist_item_descriptor = {
          .size = sizeof(unsigned long),
          .key_offset = 0,
          .extractor_callback = NULL
  };

  return &default_sharelist_item_descriptor;
}

/**
 * 	@brief: Currently two type of preferences are managed: Session user preferences and Fence user preferences.
 * 	For convenience, one master registry of prefs provide singular interface.
 *
 */
void
RegisterUserPreferencesSource(void)
{
  RegisterUserPreferenceSource(&user_prefs_table, PREFTYPE_USER, user_prefs_table.prefs_table_sz);

}

/**
 * 	@param pref: represents absolute offset but we map it map back to the corresponding index of 8-bit long groups: pref=2 -> group 1
 * 	pref=9 -> group 2. These groups correspond with the ranges as expected by redis. For each group redis returns an 8-bit representation of the group.
 * 	to fetch the first group; ie preferences 0-7 we specify range 0 0. For the first two groups: 0 1. For the second group 1 1 etc...
 *
 * 	We then have to remap the absolute pref value to the sacled down set: if pref was 9, and the range was 1 1, the corresponding bit in that
 * 	group of 8-bit is 1(second bit position) r2-r1 9-(8)+1
 */
UserPreferenceDescriptor *
GetUserPreferenceByRange(Session *sesn_ptr, UserPrefsOffsets pref, UserPreferenceDescriptor *pref_ptr_out)
{
	if (pref < 0 || pref >= PREF_LAST_ALIGNMENT)	return NULL;

	UserPreferenceDescriptor *pref_ptr = NULL;

	if (IS_PRESENT(pref_ptr_out))	pref_ptr = pref_ptr_out;
	else													pref_ptr = calloc(1, sizeof(UserPreferenceDescriptor));

	size_t bit_group = _GetBitFieldRangeGroup(pref) - 1;//adjust for redis range, which starts at 0

	CacheBackendGetUserPreferenceRecordByRange(SESSION_USERID(sesn_ptr), bit_group, bit_group);

	if (THREAD_CONTEXT_UFSRV_RESULT_TYPE_SUCCESS) {
    redisReply *redis_ptr = (redisReply *)THREAD_CONTEXT_UFSRV_RESULT_USERDATA;
		char byte = (*redis_ptr->str);

		//pref_ptr->value.pref_value_bool= ((byte & (1 <<(7-(pref%REDIS_BITFIELDS_ALIGNMENT_FACTOR)))) >> (7-(pref%REDIS_BITFIELDS_ALIGNMENT_FACTOR)));//redis stores bits on the right side, so we have to flip around the order
		pref_ptr->value.pref_value_bool = (bool)(byte & (1 << (7 - (pref % REDIS_BITFIELDS_ALIGNMENT_FACTOR))));//simpler 7 comes from: REDIS_BITFIELDS_ALIGNMENT_FACTOR-1
		//(( byte & (1 <<(7-2)) ) >> (7-2))//for single byte

		pref_ptr->pref_value_type = GetPrefValueTypeByIndex(pref);
		pref_ptr->pref_name       = GetPrefNameByIndex (pref);

		freeReplyObject(redis_ptr);

		return pref_ptr;
	}

	return NULL;
}

/**
 * 	Load into user session's whatever is stored by way of boolean preferences for the user in the cache backend.
 * 	we do assignment bit-by-bit, there is a probably a simpler way to do it by ramming the bytes into the prefs structure
 * 	but the redis getrange command returns str which needs to be parsed byte-by-byte and juggled around as per below
 * 	@param sesn_ptr: must be the target Session with full context
 */
void *
CacheBackendLoadUserPreferencesBoolean(Session *sesn_ptr)
{
	union grouper_loader {
		char 					bitgroups[8];
		unsigned long loader;
	};

	CacheBackendGetUserPreferenceRecordByRange(SESSION_USERID(sesn_ptr), 0, 7);//we support max of 8-byte groups for booleans

  if (THREAD_CONTEXT_UFSRV_RESULT_TYPE_SUCCESS) {
		unsigned long prefs_packed	=	0;
    redisReply *redis_ptr = (redisReply *)THREAD_CONTEXT_UFSRV_RESULT_USERDATA;

		memcpy((void *)&prefs_packed, (void *)redis_ptr->str, redis_ptr->len * sizeof(char));

		union grouper_loader grouper	={0};
		grouper.loader								=prefs_packed;

		for (size_t i=0; i<8; i++) {//8 bytes
			char byte = grouper.bitgroups[i];
			for (size_t j=0; j<8; j++) {//8 bits
				bool pref_value = (bool)(byte & (1 << (7 - (((8 * i) + j) % REDIS_BITFIELDS_ALIGNMENT_FACTOR))));//8*i to maintain the offset across loop rollings and prevent it from rolling over
				_SetBooleanPrefByOffset(sesn_ptr, (8 * i) + j, pref_value);
			}
		}

		freeReplyObject(redis_ptr);

	}

	return NULL;
}

/**
 * 	@brief get interface function for getting boolean type pref values
 * 	@param pref_offset: pref id as defined by its offset in the master prefs table
 * 	@param pref_store: which store to get the value from: memory, cached (redis), persisted(db)
 */
UserPreferenceDescriptor *
GetUserPreferenceBoolean(Session *sesn_ptr, UserPrefsOffsets pref_offset, PrefsStore pref_store, UserPreferenceDescriptor *pref_ptr_out)
{
	if ((pref_offset < 0) || (pref_offset >= PREF_LAST_ALIGNMENT))	return NULL;

	UserPreferenceDescriptor *pref_ptr = NULL;

	if (IS_PRESENT(pref_ptr_out))	pref_ptr  = pref_ptr_out;
	else													pref_ptr  = calloc(1, sizeof(UserPreferenceDescriptor));

  pref_ptr->pref_id								=	pref_offset;

	switch (pref_store)
	{
		case PREFSTORE_MEM:
			pref_ptr->value.pref_value_bool	=_GetBooleanPrefByOffset(sesn_ptr, pref_offset);
			pref_ptr->pref_value_type				=	GetPrefValueTypeByIndex(pref_offset);
			pref_ptr->pref_name							=	GetPrefNameByIndex(pref_offset);
			return pref_ptr;

		default:
			CacheBackendGetUserPreferenceRecordBoolean(sesn_ptr, SESSION_USERID(sesn_ptr), pref_offset);

			if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
				redisReply *redis_ptr = (redisReply *)SESSION_RESULT_USERDATA(sesn_ptr);
				pref_ptr->value.pref_value_bool = redis_ptr->integer;

				pref_ptr->pref_value_type	=	GetPrefValueTypeByIndex(pref_offset);
				pref_ptr->pref_name				=	GetPrefNameByIndex(pref_offset);

				freeReplyObject(redis_ptr);

				return pref_ptr;
			}
	}

	return NULL;
}

/**
 * 	@brief set the pref value for a user based on given bitfield offset
 * 	Similar to //SESSION_USERPREF_ONOFF_SET(sesn_ptr, roaming_mode, 1);
 * 	except it is dynamic, offset based as opposed to field-name based, which relies on preprocessor magic
 */
/*__attribute__((const))*/ static void
_SetBooleanPrefByOffset(Session *sesn_ptr, UserPrefsOffsets pref_offset, bool value)
{
	struct UserPrefsBooleanStorage pref_storage={.on_off=sesn_ptr->sservice.user.user_details.user_preferences.on_off};

	 //pref_storage.storage ^= (-value ^ pref_storage.storage) & (1UL << pref_offset);
	 //canonical method
	 if (value == 1) 	pref_storage.storage |= (1UL << (pref_offset));
	 else  					  pref_storage.storage &= ~(1UL << (pref_offset));

	 sesn_ptr->sservice.user.user_details.user_preferences.on_off = pref_storage.on_off;

}

void
SetBooleanPrefById(Session *sesn_ptr, UserPrefsOffsets pref_offset, bool value)
{
	_SetBooleanPrefByOffset(sesn_ptr, pref_offset, value);
}

/**
 * 	@brief get the pref value for a user based on given bitfield offset
 */
static inline bool
_GetBooleanPrefByOffset(Session *sesn_ptr, UserPrefsOffsets pref_offset)
{
	const struct UserPrefsBooleanStorage pref_storage = {.on_off=sesn_ptr->sservice.user.user_details.user_preferences.on_off};

	return (bool)(pref_storage.storage & (1 << (pref_offset)));

}

/**
 * 	@brief get the pref value for a user based on given bitfield offset
 */
__attribute__((const, unused)) static bool
_GetBooleanPrefByDuelOffset(Session *sesn_ptr, UserPrefsOffsets pref_offset1, UserPrefsOffsets pref_offset2)
{
	struct UserPrefsBooleanStorage pref_storage = {.on_off=sesn_ptr->sservice.user.user_details.user_preferences.on_off};

	return (bool)(pref_storage.storage & (1 << pref_offset1)) && (bool)(pref_storage.storage & (1 << pref_offset2));

}

/**
 * 	@brief Key entry point for setting user preference. basically dispatches processing based on pref type
 * 	@param sesn_ptr target session. must be fully loaded with context
 * 	@param pref_ptr descriptor for the pref undergoing change
 * 	TODO: ADAPT IT FOR COLLECTION NOT JUST SINGLE PREF
 * 	TODO: ADATPT IT TO USE OPS
 *
 */
UserPreferenceDescriptor *
SetUserPreferenceByDescriptor(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr, UfsrvEvent *event_ptr)
{
	if (unlikely(IS_EMPTY(sesn_ptr)))	return NULL;
	if (unlikely(IS_EMPTY(pref_ptr)))	return NULL;

	//todo: replace below with return ((*pref_ptr->pref_ops->pref_set)(sesn_ptr, pref_ptr, PREFSTORE_MEM, event_ptr));

	switch (pref_ptr->pref_value_type)
	{
		case	PREFVALUETYPE_BOOL:
			return (SetUserPreferenceBoolean (sesn_ptr, pref_ptr, PREFSTORE_MEM, event_ptr));

		case	PREFVALUETYPE_INT:
		case	PREFVALUETYPE_INT_MULTI:

		case PREFVALUETYPE_STR:
			return ((*pref_ptr->pref_ops->pref_set)(sesn_ptr, pref_ptr, PREFSTORE_MEM, event_ptr));

		case PREFVALUETYPE_STR_MULTI:

		default:;
	}

	return NULL;

}

/**
 * 	TODO: remove 'case' and ADAPT TO USE OPS instead of explicit switch/case
 */
UserPreferenceDescriptor *
SetUserPreferenceByName(Session *sesn_ptr, const char *pref_name, const char *pref_value, UfsrvEvent *event_ptr)
{
	const UserPrefsOffsets pref_id = GetPrefIndexByName(pref_name);
	const UserPreferenceDescriptor *pref_descriptor_meta_ptr = GetPrefDescriptorById(pref_id);

	if (unlikely(IS_EMPTY(pref_descriptor_meta_ptr)))		return NULL;

	switch (pref_descriptor_meta_ptr->pref_value_type)
	{
		case	PREFVALUETYPE_BOOL:
			return(SetUserPreferenceBoolean(sesn_ptr, &((UserPreferenceDescriptor){.pref_id=pref_id, .pref_name=pref_descriptor_meta_ptr->pref_name, .value.pref_value_bool=strtol(pref_value, NULL, 10)}), PREFSTORE_MEM, event_ptr));

		case PREFVALUETYPE_STR:
			return ((*pref_descriptor_meta_ptr->pref_ops->pref_set)(sesn_ptr, &((UserPreferenceDescriptor){.pref_id=pref_id, .pref_name=pref_descriptor_meta_ptr->pref_name, .value.pref_value_str=(char *)pref_value}), PREFSTORE_MEM, event_ptr));

		case PREFVALUETYPE_INT:
		case PREFVALUETYPE_INT_MULTI:
		case PREFVALUETYPE_STR_MULTI:
		default:
			return NULL;//TODO: IMPELEMNT OTHER TYPES
	}
}

/**
 * 	@brief: main interface function for storing boolean types.
 * 	This particular state can be invoked from a stateless ufsrvapi, Thsi function needs to be able to determine when an INTRA vs INTER
 * 	broadcast is needed, because it can be invoked from ufsrvapi directly, in which case ufsrv will simply process that with INTER semantics
 * 	@param pref_store: where to store the value: memory, cached, persisted. IMPORTANT: writes automatically cascades through  from high(mem)->low(persisted)
 */
UserPreferenceDescriptor *
SetUserPreferenceBoolean(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in, PrefsStore pref_store, UfsrvEvent *event_ptr)
{
	if (pref_ptr_in->pref_id < 0 || pref_ptr_in->pref_id >= PREF_LAST_ALIGNMENT)	return NULL;

	UserPreferenceDescriptor *pref_ptr = NULL;

	//todo: may not always be set, but is required when setting DB json payload (which is no longer a valid way of setting pref)
	if (!IS_STR_LOADED(pref_ptr_in->pref_name)) {
		const UserPreferenceDescriptor *prefdef_ptr = GetPrefDescriptorById (pref_ptr_in->pref_id);
		pref_ptr_in->pref_name =	prefdef_ptr->pref_name;
	}

	if (likely(GetPrefValueTypeByIndex(pref_ptr_in->pref_id) == PREFVALUETYPE_BOOL)) {
		{
			const UserPreferenceDescriptor *prefdef_ptr = GetPrefDescriptorById (pref_ptr_in->pref_id);
			if (IS_PRESENT(prefdef_ptr) && IS_PRESENT(prefdef_ptr->pref_validate))	(*prefdef_ptr->pref_validate)(sesn_ptr, pref_ptr_in);
		}

		//todo: for consistency, use pref callback for local setting
		_SetBooleanPrefByOffset(sesn_ptr, pref_ptr_in->pref_id, pref_ptr_in->value.pref_value_bool);

    RegisterUfsrvEvent(sesn_ptr, EVENT_TYPE_USER_PREF, 0, NULL, event_ptr); //todo: set session event instance type
		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
			DbAccountUserDataUpdatePreference(sesn_ptr, pref_ptr_in, SESSION_USERID(sesn_ptr));

			BackendCacheStoreBooleanUserPreferences(sesn_ptr);

			if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
				redisReply *redis_ptr = (redisReply *) SESSION_RESULT_USERDATA(sesn_ptr); //redis returns old value

				InterBroadcastUserMessageUserPrefsBoolean(sesn_ptr, CLIENT_CTX_DATA(pref_ptr_in), event_ptr, pref_ptr_in->value.pref_value_bool?COMMAND_ARGS__SET:COMMAND_ARGS__UNSET);

#ifdef __UF_TESTING
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', pref_name:'%s', pref_value_previous:'%llu'}: Set user preference...", __func__, pthread_self(), sesn_ptr, GetPrefNameByIndex(pref_ptr_in->pref_id), redis_ptr->integer);
#endif

				freeReplyObject(redis_ptr);

				return pref_ptr_in;
			}
		} else {
			//todo: restore old pref value and return error msg to user
			syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu', pref_offset:'%lu'}: ERROR: COULD NOT SET PREF...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), pref_ptr_in->pref_id);
		}
	}
	else
	{
		 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu', pref_offset:'%lu'}: ERROR: TYPE VALUE IS NOT BOOL...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), pref_ptr_in->pref_id);
	}

	return NULL;
}

/**
 * 	@brief Designed as callback handler for updating in-memory value only. Chiefly as a result of intra-msg
 */
static UserPreferenceDescriptor *
_SetLocalUserPreferenceBoolean(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in)
{
	if (pref_ptr_in->pref_id < 0 || pref_ptr_in->pref_id >= PREF_LAST_ALIGNMENT)	return NULL;

	_SetBooleanPrefByOffset(sesn_ptr, pref_ptr_in->pref_id, pref_ptr_in->value.pref_value_bool);

	return pref_ptr_in;
}

/**
 * 	@brief Store the current boolean prefs set in to redis backend.
 */
UFSRVResult *
BackendCacheStoreBooleanUserPreferences(Session *sesn_ptr)
{
	union grouper_loader{
		unsigned char 							bitgroups[8];
		UserPrefsBoolean 	loader;
		unsigned long			storage;
	};

	union grouper_loader grouper	={0};
	grouper.loader								=sesn_ptr->sservice.user.user_details.user_preferences.on_off;

#ifdef __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu'): PREFS BINARY STORAGE BEFORE:'0x%lx'", __func__, pthread_self(), SESSION_ID(sesn_ptr), grouper.storage);
#endif

		for (size_t i=0; i<sizeof(unsigned long); i++) {
			grouper.bitgroups[i] = (grouper.bitgroups[i] * 0x0202020202ULL & 0x010884422010ULL) % 1023; //reverse bits on the byte
		}

#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu'): PREFS STRING STORAGE:'0x%x 0x%x 0x%x 0x%x'", __func__, pthread_self(), SESSION_ID(sesn_ptr), grouper.bitgroups[0], grouper.bitgroups[1], grouper.bitgroups[2], grouper.bitgroups[3]);
#endif

		return (CacheBackendSetBooleanUserPreferenceRecordByRange(sesn_ptr, SESSION_USERID(sesn_ptr),  grouper.bitgroups, 0, 8));

#if 0
	union grouper_loader{
		char 					bitgroups[8];
		UserPrefsBoolean loader;//unsigned long loader;

	};

	union grouper_loader grouper	={0};
	grouper.loader								=sesn_ptr->sservice.user.user_details.user_preferences.on_off;





#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu'): PREFS STRING STORAGE:'%*.8s'", __func__, pthread_self(), SESSION_ID(sesn_ptr), 8, grouper.bitgroups);
#endif

		return (CacheBackendSetBooleanUserPreferenceRecordByRange (sesn_ptr, SESSION_USERID(sesn_ptr),  grouper.bitgroups, 0, 8));
#endif
}

//REDIS_CMD_USERPREF_SETRANGE
UFSRVResult *
CacheBackendSetBooleanUserPreferenceRecordByRange(Session *sesn_ptr, unsigned long userid, unsigned char *value, size_t byte_offset, size_t bytes_sz)
{
	int rescode = RESCODE_PROG_NULL_POINTER;

	PersistanceBackend	*pers_ptr		=	THREAD_CONTEXT_PERSISTANCE_CACHEBACKEND(ufsrv_thread_context);;
	redisReply 					*redis_ptr	=	NULL;

	//this command will return "" string if set does not exist, ie does not communicate error in that sense
	if (!(redis_ptr=(*pers_ptr->send_command)(sesn_ptr, REDIS_CMD_USERPREF_SETRANGE, userid, byte_offset, value)))	goto return_redis_error;

	if (redis_ptr->type == REDIS_REPLY_INTEGER) {
		_RETURN_RESULT_SESN(sesn_ptr, redis_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
	}

	if (redis_ptr->type == REDIS_REPLY_ERROR)	goto return_redis_error;
	if (redis_ptr->type == REDIS_REPLY_NIL)		goto return_redis_error;

	return_redis_error:
	if (IS_EMPTY(redis_ptr)) {
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
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
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)

}

/**
 * 	@brief: Generic string based pref setter that automatically updates both, db and cache backends. If value of pref is NULL, corresponding target values are deleted
 */
UserPreferenceDescriptor *
SetUserPreferenceString(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in, PrefsStore pref_store, UfsrvEvent *event_ptr)
{
	const UserPreferenceDescriptor *prefdef_ptr = GetPrefDescriptorById (pref_ptr_in->pref_id);
  if (IS_PRESENT(prefdef_ptr) && IS_PRESENT(prefdef_ptr->pref_validate)) {
    if (IS_EMPTY((*prefdef_ptr->pref_validate)(sesn_ptr, pref_ptr_in))) return NULL;
  }

  if (IS_PRESENT(prefdef_ptr->pref_ops->pref_set_local)) {
    (*prefdef_ptr->pref_ops->pref_set_local)(sesn_ptr, pref_ptr_in);
  }
	if (pref_store == PREFSTORE_MEM)	return pref_ptr_in;

  RegisterUfsrvEvent(sesn_ptr, EVENT_TYPE_USER_PREF, 0, NULL, event_ptr); //todo: set session event instance type

  if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
    if (pref_store == PREFSTORE_PERSISTED) {
      DbAccountUserDataUpdatePreference(sesn_ptr, pref_ptr_in, SESSION_USERID(sesn_ptr));
    } else if (pref_store == PREFSTORE_CACHED) {
      CacheBackendSetSessionAttribute(sesn_ptr, SESSION_USERID(sesn_ptr), pref_ptr_in->pref_name, pref_ptr_in->value.pref_value_str);
    } else if (pref_store == PREFSTORE_EVERYWHERE) {
      DbAccountUserDataUpdatePreference(sesn_ptr, pref_ptr_in, SESSION_USERID(sesn_ptr));
      CacheBackendSetSessionAttribute(sesn_ptr, SESSION_USERID(sesn_ptr), pref_ptr_in->pref_name, pref_ptr_in->value.pref_value_str);
    }

    if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
#ifdef __UF_FULLDEBUG
      syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', pref_name:'%s', pref_value_new:'%s'}: Set user preference...", __func__, pthread_self(), sesn_ptr, GetPrefNameByIndex(pref_ptr_in->pref_id), pref_ptr_in->value.pref_value_str);
#endif

      return pref_ptr_in;
    }
  }

  //todo: we should rollback the memory stored value set earlier for preference
	return NULL;
}

/**
 * 	@brief: get interface function for getting string type pref values
 * 	@param pref_offset: pref id as defined by its offset in the master prefs table
 * 	@param pref_store: which store to get the value from: memory, cached (redis), persisted(db)
 * 	@param pref_ptr_out Holder of returned preference value. If pre-allocated, must be fully loaded
 * 	@dynamic_memory EXPORTS UserPreferenceDescriptor *' unless preallocated
 * 	@dynamic_memory: EXPORTS char * as stored in preference
 */
UserPreferenceDescriptor *
GetUserPreferenceString(Session *sesn_ptr, UserPrefsOffsets pref_offset, PrefsStore pref_store, UserPreferenceDescriptor *pref_ptr_out)
{
  UserPreferenceDescriptor *pref_ptr = NULL;
  UfsrvUid *uid_ptr = &SESSION_UFSRVUIDSTORE(sesn_ptr);

  if (IS_PRESENT(pref_ptr_out))	pref_ptr = pref_ptr_out;
  else {
    pref_ptr = calloc(1, sizeof(UserPreferenceDescriptor));
  }

  const UserPreferenceDescriptor *prefdef_ptr = GetPrefDescriptorById(pref_offset);
  pref_ptr->pref_value_type				=	prefdef_ptr->pref_value_type;//GetPrefValueTypeByIndex(pref_offset);
  pref_ptr->pref_name							=	prefdef_ptr->pref_name;//GetPrefNameByIndex(pref_offset);
  pref_ptr->pref_id								=	pref_offset;

  switch (pref_store)
  {
    case PREFSTORE_MEM:
      if (IS_PRESENT(prefdef_ptr->pref_ops->pref_get_local)) {
        return (*prefdef_ptr->pref_ops->pref_get_local)(sesn_ptr, pref_ptr);
      }

      return NULL;

    case PREFSTORE_CACHED:
      CacheBackendGetSessionAttribute(UfsrvUidGetSequenceId(uid_ptr), pref_ptr->pref_name);
      if (RESULT_IS_SUCCESS_WITH_BACKEND_DATA_THCTX) {
        redisReply *redis_ptr = (redisReply *)RESULT_USERDATA_THCTX;
        pref_ptr->value.pref_value_str = strdup(redis_ptr->str);

        freeReplyObject(redis_ptr);

        return pref_ptr;
      }
      break;

    case PREFSTORE_PERSISTED:
    __attribute__((fallthrough));
    default:
      DbAccountDataUserAttributeGetText(UfsrvUidGetSequenceId(uid_ptr), pref_ptr->pref_name);
      if (RESULT_IS_SUCCESS_WITH_BACKEND_DATA_THCTX) {
        pref_ptr->value.pref_value_str = (char *)RESULT_USERDATA_THCTX;

        return pref_ptr;
      }
  }

  return NULL;
}

/**
 * 	@brief: Generic integer based pref setter that automatically updates both, db and cache backends. If value of pref is NULL, corresponding target values are deleted
 */
UserPreferenceDescriptor *
SetUserPreferenceInteger(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in, PrefsStore pref_store, UfsrvEvent *event_ptr)
{
  const UserPreferenceDescriptor *prefdef_ptr = GetPrefDescriptorById(pref_ptr_in->pref_id);
  if (IS_PRESENT(prefdef_ptr)) {
    pref_ptr_in->pref_name = prefdef_ptr->pref_name;
    pref_ptr_in->pref_value_type = prefdef_ptr->pref_value_type;

    if (IS_PRESENT(prefdef_ptr->pref_validate)) {
      if (IS_EMPTY((*prefdef_ptr->pref_validate)(sesn_ptr, pref_ptr_in))) return NULL;
    }

    if (IS_PRESENT(prefdef_ptr->pref_ops->pref_set_local)) {
      (*prefdef_ptr->pref_ops->pref_set_local)(sesn_ptr, pref_ptr_in);
    }

    if (pref_store == PREFSTORE_MEM) return pref_ptr_in;

    if (IS_PRESENT(event_ptr))
      RegisterUfsrvEvent(sesn_ptr, EVENT_TYPE_USER_PREF, 0, NULL, event_ptr); //todo: set session event instance type

    if (IS_PRESENT(event_ptr) && SESSION_RESULT_TYPE_ERROR(sesn_ptr)) {
      //todo: we should rollback the memory stored value set earlier for preference
      return NULL;
    }

    if (pref_store == PREFSTORE_PERSISTED) {
      DbAccountUserDataUpdatePreference(sesn_ptr, pref_ptr_in, SESSION_USERID(sesn_ptr));
    } else if  (pref_store == PREFSTORE_CACHED) {
      CacheBackendSetSessionAttribute(sesn_ptr, SESSION_USERID(sesn_ptr), pref_ptr_in->pref_name, STRINGIFY_PARAMETER("%lu", pref_ptr_in->value.pref_value_int));
    } else if (pref_store == PREFSTORE_EVERYWHERE) {
      DbAccountUserDataUpdatePreference(sesn_ptr, pref_ptr_in, SESSION_USERID(sesn_ptr));
      CacheBackendSetSessionAttribute(sesn_ptr, SESSION_USERID(sesn_ptr), pref_ptr_in->pref_name, STRINGIFY_PARAMETER("%lu", pref_ptr_in->value.pref_value_int));
    }

    if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
#ifdef __UF_FULLDEBUG
      syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', pref_name:'%s', pref_value_new:'%s'}: Set user preference...", __func__, pthread_self(), sesn_ptr, GetPrefNameByIndex(pref_ptr_in->pref_id), pref_ptr_in->value.pref_value_str);
#endif

      return pref_ptr_in;
    }
  }

  return NULL;
}

/**
 * 	@brief get interface function for getting integer type pref values
 * 	@param pref_offset pref id as defined by its offset in the master prefs table
 * 	@param pref_store which store to get the value from: memory, cached (redis), persisted(db)
 * 	@param pref_ptr_out Holder of returned preference value. If pre-allocated, must be fully loaded
 * 	@dynamic_memory EXPORTS UserPreferenceDescriptor *' unless preallocated
 */
UserPreferenceDescriptor *
GetUserPreferenceInteger(Session *sesn_ptr, UserPrefsOffsets pref_offset, PrefsStore pref_store, UserPreferenceDescriptor *pref_ptr_out)
{
  UserPreferenceDescriptor *pref_ptr = NULL;
  UfsrvUid *uid_ptr = &SESSION_UFSRVUIDSTORE(sesn_ptr);

  if (IS_PRESENT(pref_ptr_out))	pref_ptr = pref_ptr_out;
  else {
    pref_ptr = calloc(1, sizeof(UserPreferenceDescriptor));
  }

  const UserPreferenceDescriptor *prefdef_ptr = GetPrefDescriptorById(pref_offset);
  pref_ptr->pref_value_type				=	prefdef_ptr->pref_value_type;//GetPrefValueTypeByIndex(pref_offset);
  pref_ptr->pref_name							=	prefdef_ptr->pref_name;//GetPrefNameByIndex(pref_offset);
  pref_ptr->pref_id								=	pref_offset;

  switch (pref_store)
  {
    case PREFSTORE_MEM:
      if (IS_PRESENT(prefdef_ptr->pref_ops->pref_get_local)) {
        return (*prefdef_ptr->pref_ops->pref_get_local)(CLIENT_CTX_DATA(sesn_ptr), pref_ptr);
      }

      return NULL;

    case PREFSTORE_CACHED:
      CacheBackendGetSessionAttribute(UfsrvUidGetSequenceId(uid_ptr), pref_ptr->pref_name);
      if (RESULT_IS_SUCCESS_WITH_BACKEND_DATA_THCTX) {
        redisReply *redis_ptr = (redisReply *)RESULT_USERDATA_THCTX;
        pref_ptr->value.pref_value_int = strtoul(redis_ptr->str, NULL, 10);

        freeReplyObject(redis_ptr);

        return pref_ptr;
      }

      break;

    case PREFSTORE_PERSISTED:
    __attribute__((fallthrough));
    default:
      DbAccountDataUserAttributeGetText(UfsrvUidGetSequenceId(uid_ptr), pref_ptr->pref_name);
      if (RESULT_IS_SUCCESS_WITH_BACKEND_DATA_THCTX) {
        pref_ptr->value.pref_value_int = strtoul((const char *)RESULT_USERDATA_THCTX, NULL, 10);
        free(RESULT_USERDATA_THCTX);

        return pref_ptr;
      }
  }

  return NULL;
}

//NICKNAME

/**
 * 	@brief: main interface function for changing nicknames across all data stores.
 * 	This particular state can be invoked from a stateless ufsrvapi, This function needs to be able to determine when an INTRA vs INTER
 * 	broadcast is needed, because it can be invoked from ufsrvapi directly, in which case ufsrv will simply process that with INTER semantics
 * 	@param pref_store: where to store the value: memory, cached, persisted. IMPORTANT: writes automatically cascades through  from high(mem)->low(persisted)
 */
UserPreferenceDescriptor *
SetUserPreferenceNickname(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in, PrefsStore pref_store, UfsrvEvent *event_ptr)
{
  char *nickname_to_be_deleted = NULL;
  if (IS_STR_LOADED(SESSION_USERNICKNAME(sesn_ptr))) nickname_to_be_deleted = strdupa(SESSION_USERNICKNAME(sesn_ptr));

	if (IS_PRESENT(SetUserPreferenceString(sesn_ptr, pref_ptr_in, pref_store, event_ptr))) {
		if (IS_STR_LOADED(pref_ptr_in->value.pref_value_str))  BackendDirectoryNicknameSet(sesn_ptr, pref_ptr_in->value.pref_value_str);//todo: cache backend error recovery
    BackendDirectoryNicknameDel(sesn_ptr, nickname_to_be_deleted);

		return pref_ptr_in;
	}

	return NULL;
}

/**
 * 	@brief: Designed as callback handler for updating in-memory value only. Chiefly, as a result of intra-msg
 * 	@dynamic_memory pref_ptr_in->value: retained from previous allocation
 */
static UserPreferenceDescriptor *
_SetLocalUserPreferenceNickname(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in)
{
  if (IS_STR_LOADED(SESSION_USERNICKNAME(sesn_ptr)))	free(SESSION_USERNICKNAME(sesn_ptr));

  if (IS_STR_LOADED(pref_ptr_in->value.pref_value_str)) SESSION_USERNICKNAME(sesn_ptr) = strdup(pref_ptr_in->value.pref_value_str);
  else LOAD_NULL(SESSION_USERNICKNAME(sesn_ptr));

	return pref_ptr_in;
}

/**
 * 	@brief: Retrieve currently assigned nickname value for user. Option to use memory based (currently loaded) vs backend
 * 	@param pref_offset: pref id as defined by its offset in the master prefs table
 * 	@param pref_store: which store to get the value from: memory, cached (redis), persisted(db)
 */
UserPreferenceDescriptor *
GetUserPreferenceNickname(Session *sesn_ptr, UserPrefsOffsets pref_offset, PrefsStore pref_store, UserPreferenceDescriptor *pref_ptr_out, char *name_override)
{
	UserPreferenceDescriptor *pref_ptr = NULL;

	if (IS_PRESENT(pref_ptr_out))	pref_ptr = pref_ptr_out;
	else													pref_ptr = calloc(1, sizeof(UserPreferenceDescriptor));

	pref_ptr->pref_value_type				=	GetPrefValueTypeByIndex(pref_offset);
	pref_ptr->pref_name							=	GetPrefNameByIndex(pref_offset);
	pref_ptr->pref_id								=	pref_offset;

	switch (pref_store)
	{
		case PREFSTORE_MEM:
			pref_ptr->value.pref_value_str	= IS_STR_LOADED(name_override)? name_override : SESSION_USERNICKNAME(sesn_ptr);

			return pref_ptr;

		default:
			//todo: update to use nickname aware cachback end or db backend value
			//CacheBackendGetUserPreferenceRecordBoolean (sesn_ptr, SESSION_USERID(sesn_ptr), pref_offset);

			if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
				redisReply *redis_ptr = (redisReply *)SESSION_RESULT_USERDATA(sesn_ptr);
				pref_ptr->value.pref_value_bool = redis_ptr->integer;

				freeReplyObject(redis_ptr);

				return pref_ptr;
			}
	}

	return NULL;
}

/**
 * 	@brief: callback. Commits changes to memory, ahead of committing to cache and db backends
 */
static UserPreferenceDescriptor *
_PrefValidateNickname(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr)
{
  if (IS_STR_LOADED(pref_ptr->value.pref_value_str)) {
    if ((strlen(pref_ptr->value.pref_value_str)) > CONFIG_MAX_NICKNAME_SIZE) goto return_error;

    if (IS_STR_LOADED(SESSION_USERNICKNAME(sesn_ptr))) {
      if (strcasecmp(pref_ptr->value.pref_value_str, SESSION_USERNICKNAME(sesn_ptr)) == 0) goto return_error;
    }
  }

	return pref_ptr;

	return_error:
	return NULL;

}
//

//AVATAR

/**
 * 	@brief: Designed as callback handler for updating in-memory value only. Chiefly as a result of intra-msg
 * 	@dynamic_memory pref_ptr_in->value: retained from previous allocation
 */
static UserPreferenceDescriptor *
_SetLocalUserPreferenceAvatar(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in)
{
  if (IS_STR_LOADED(SESSION_USERAVATAR(sesn_ptr)))	free(SESSION_USERAVATAR(sesn_ptr));

  if (IS_STR_LOADED(pref_ptr_in->value.pref_value_str))  SESSION_USERAVATAR(sesn_ptr) = strdup(pref_ptr_in->value.pref_value_str);
  else LOAD_NULL(SESSION_USERAVATAR(sesn_ptr));

	return pref_ptr_in;
}

/**
 * 	@brief: get interface function for getting boolean type pref values
 * 	@param pref_offset: pref id as defined by its offset in the master prefs table
 * 	@param pref_store: which store to get the value from: memory, cached (redis), persisted(db)
 */
UserPreferenceDescriptor *
GetUserPreferenceAvatar(Session *sesn_ptr, UserPrefsOffsets pref_offset, PrefsStore pref_store, UserPreferenceDescriptor *pref_ptr_out)
{
	UserPreferenceDescriptor *pref_ptr=NULL;

	if (IS_PRESENT(pref_ptr_out))	pref_ptr=pref_ptr_out;
	else													pref_ptr=calloc(1, sizeof(UserPreferenceDescriptor));

	pref_ptr->pref_value_type				=	GetPrefValueTypeByIndex(pref_offset);
	pref_ptr->pref_name							=	GetPrefNameByIndex (pref_offset);
	pref_ptr->pref_id								=	pref_offset;

	switch (pref_store)
	{
		case PREFSTORE_MEM:
			pref_ptr->value.pref_value_str	= SESSION_USERAVATAR(sesn_ptr);

			return pref_ptr;

		case PREFSTORE_CACHED:
		case PREFSTORE_PERSISTED:
		default:
			//todo: update to use avatar aware cachback end or db backend value
			//CacheBackendGetUserPreferenceRecordBoolean (sesn_ptr, SESSION_USERID(sesn_ptr), pref_offset);

			if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
				redisReply *redis_ptr = (redisReply *)SESSION_RESULT_USERDATA(sesn_ptr);
				pref_ptr->value.pref_value_bool = redis_ptr->integer;

				freeReplyObject(redis_ptr);

				return pref_ptr;
			}
	}

	return NULL;
}

/**
 * 	@brief: callback. Commits changes to memory, ahead of committing to cache and db backends
 */
static UserPreferenceDescriptor *
_PrefValidateAvatar(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr)
{
	//TODO: check for stored value in Attachments
	//	if ((strlen((char *)pref_ptr->value.pref_value_str))>CONFIG_MAX_NICKNAME_SIZE) goto return_error;//max 20 letters
//
//	if (IS_STR_LOADED(sesn_ptr->sservice.user.user_details.user_preferences.nickname)) {
//		if (strcasecmp((char *)pref_ptr->value.pref_value_str, sesn_ptr->sservice.user.user_details.user_preferences.nickname)==0)	goto return_error;
//	}

	return pref_ptr;

	return_error:
	return NULL;

}

//

/**
 * NOT IMPLEMENTED
 * 	@brief: Generic pref setter for sharelists
 */
UserPreferenceDescriptor *
SetUserPreferenceShareList(ClientContextData *ctx_ptr, UserPreferenceDescriptor *pref_ptr_in, PrefsStore pref_store, UserPreferenceDescriptor *pref_ptr_out)
{
	UserPreferenceDescriptor *pref_ptr		=	NULL;
//	ShareListContextData *shlist_ctx_ptr	= (ShareListContextData *)ctx_ptr;
//
//	const UserPreferenceDescriptor *prefdef_ptr=GetPrefDescriptorById (pref_ptr_in->pref_id);
//	{
//		if (IS_PRESENT(prefdef_ptr) && IS_PRESENT(prefdef_ptr->pref_validate)) {
//			if (IS_EMPTY((*prefdef_ptr->pref_validate)(ctx_ptr, pref_ptr_in))) return NULL;
//		}
//	}
//
//	(*prefdef_ptr->pref_ops->pref_set_local)(ctx_ptr, pref_ptr_in);
//	if (pref_store==PREFSTORE_MEM)	return pref_ptr;
//
//	DbAccountUserDataUpdatePreference (sesn_ptr,  pref_ptr_in, SESSION_USERID(sesn_ptr));
//
//	CacheBackendSetSessionAttribute (sesn_ptr, SESSION_USERID(sesn_ptr), pref_ptr_in->pref_name+(sizeof(CONFIG_PREFERENCE_PREFIX)-1), pref_ptr_in->value.pref_value_str);
//
//	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))
//	{
//#ifdef __UF_TESTING
//		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', pref_name:'%s', pref_value_new:'%s'}: Set user preference...", __func__, pthread_self(), sesn_ptr, GetPrefNameByIndex (pref_ptr_in->pref_id), SESSION_USERNICKNAME(sesn_ptr));
//#endif

//		return pref_ptr;
//	}

	return NULL;
}

UserPreferenceDescriptor *
GetUserPreferenceShareList(Session *sesn_ptr, UserPrefsOffsets pref_offset, PrefsStore pref_store, UserPreferenceDescriptor *pref_ptr_out)
{
	UserPreferenceDescriptor *pref_ptr = NULL;

	if (IS_PRESENT(pref_ptr_out))	pref_ptr = pref_ptr_out;
	else													pref_ptr = calloc(1, sizeof(UserPreferenceDescriptor));

	if ((pref_ptr->pref_value_type = GetPrefValueTypeByIndex(pref_offset)) == PREFVALUETYPE_INVALID) {
		if (IS_EMPTY(pref_ptr_out))	free(pref_ptr);

		return NULL;
	}

	pref_ptr->pref_name							=	GetPrefNameByIndex(pref_offset);
	pref_ptr->pref_id								=	pref_offset;

	switch (pref_store)
	{
		case PREFSTORE_MEM://todo currently not implemented
//			pref_ptr->value.pref_value_blob	= SESSION_USERPREF_SHLIST_PROFILE_PTR(sesn_ptr); //we don't retain a value for key
			return pref_ptr;

		default:
			//todo: update to use avatar aware cachback end or db backend value
			//CacheBackendGetUserPreferenceRecordBoolean (sesn_ptr, SESSION_USERID(sesn_ptr), pref_offset);

			if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
				redisReply *redis_ptr = (redisReply *)SESSION_RESULT_USERDATA(sesn_ptr);
				pref_ptr->value.pref_value_bool = redis_ptr->integer;

				freeReplyObject(redis_ptr);

				return pref_ptr;
			}
	}

	return NULL;
}
//

//E164NUMBER

/**
 * 	@brief: Designed as callback handler for updating in-memory value only. Chiefly as a result of intra-msg
 * 	@dynamic_memory pref_ptr_in->value: retained from previous allocation
 */
static UserPreferenceDescriptor *
_SetLocalUserPreferenceE164Number(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in)
{
	if (IS_STR_LOADED(sesn_ptr->sservice.user.user_details.user_preferences.e164number))	free (sesn_ptr->sservice.user.user_details.user_preferences.e164number);

	sesn_ptr->sservice.user.user_details.user_preferences.e164number = strdup(pref_ptr_in->value.pref_value_str);

	return pref_ptr_in;
}

/**
 * 	@brief: get interface function for getting boolean type pref values
 * 	@param pref_offset: pref id as defined by its offset in the master prefs table
 * 	@param pref_store: which store to get the value from: memory, cached (redis), persisted(db)
 * 	@dynamic_memory: PASSES downstream allocated 'char *'
 */
UserPreferenceDescriptor *
GetUserPreferenceE164Number(Session *sesn_ptr, UserPrefsOffsets pref_offset, PrefsStore pref_store, UserPreferenceDescriptor *pref_ptr_out)
{
	UserPreferenceDescriptor *pref_ptr=NULL;

	if (IS_PRESENT(pref_ptr_out))	pref_ptr=pref_ptr_out;
	else													pref_ptr=calloc(1, sizeof(UserPreferenceDescriptor));

	pref_ptr->pref_value_type				=	GetPrefValueTypeByIndex(pref_offset);
	pref_ptr->pref_name							=	GetPrefNameByIndex (pref_offset);
	pref_ptr->pref_id								=	pref_offset;

	switch (pref_store)
	{
		case PREFSTORE_MEM:
			pref_ptr->value.pref_value_str = sesn_ptr->sservice.user.user_details.user_preferences.e164number;

			return pref_ptr;

		PREFSTORE_PERSISTED:
		default:
			DbAccountGetE164Number(sesn_ptr, UfsrvUidGetSequenceId(&(SESSION_UFSRVUIDSTORE(sesn_ptr))));
			if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
				pref_ptr->value.pref_value_str = (char *) SESSION_RESULT_USERDATA(sesn_ptr);
			} else pref_ptr->value.pref_value_str	=	NULL;
	}

	return NULL;
}

//Currently this is only persisted in the backends, not in memory
enum UnsolicitedContactAction
GetUserPreferenceUnsolicitedContactAction(Session *sesn_ptr, PrefsStore pref_store)
{
  UserPreferenceDescriptor pref = {0};
  if (IS_PRESENT(GetUserPreferenceInteger(sesn_ptr, PREF_UNSOLICITED_CONTACT, pref_store, &pref))) {
    return (enum UnsolicitedContactAction)pref.value.pref_value_int;
  }

  return ACTION_BLOCK;
}

/**
 * @locked sesn_ptr_for
 */
UFSRVResult *
SetGuardianFor(Session *sesn_ptr_for, unsigned long guardian_uid, PrefsStore pref_store)
{
  UserPreferenceDescriptor pref_descriptor;
  const UserPreferenceDescriptor *prefdef_ptr = GetPrefDescriptorById(PREF_GUARDIAN_UID);
  if (IS_PRESENT((*prefdef_ptr->pref_ops->pref_set)(sesn_ptr_for, &((UserPreferenceDescriptor){.pref_id=PREF_GUARDIAN_UID, .value.pref_value_int=guardian_uid}), pref_store, EMPTY_EVENT))) {
    _RETURN_RESULT_SESN(sesn_ptr_for, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);
  }

  _RETURN_RESULT_SESN(sesn_ptr_for, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
}

unsigned long
GetGuardianUId(Session *sesn_ptr, PrefsStore pref_store)
{
  UserPreferenceDescriptor pref = {0};
  if (IS_PRESENT(GetUserPreferenceInteger(sesn_ptr, PREF_GUARDIAN_UID, pref_store, &pref))) {
    return pref.value.pref_value_int;
  }

  return 0;
}

static UserPreferenceDescriptor *
_SetLocalGuardianUid(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in)
{
  SESSION_USERGUARDIAN_UID(sesn_ptr) = pref_ptr_in->value.pref_value_int;

  return pref_ptr_in;
}

static UserPreferenceDescriptor *
_GetLocalGuardianUid(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in)
{
  pref_ptr_in->value.pref_value_int =  SESSION_USERGUARDIAN_UID(sesn_ptr);

  return pref_ptr_in;
}

InstanceContextForSession *
GetGuardianSession(Session *sesn_ptr, PrefsStore pref_store, bool is_locked, InstanceContextForSession *instance_sesn_ptr_out)
{
  UserPreferenceDescriptor pref = {0};
  if (IS_PRESENT(GetUserPreferenceInteger(sesn_ptr, PREF_GUARDIAN_UID, pref_store, &pref))) {
    bool is_lock_already_owned = false;
    unsigned long sesn_call_flags=(CALL_FLAG_HASH_SESSION_LOCALLY|CALL_FLAG_HASH_UID_LOCALLY|CALL_FLAG_HASH_USERNAME_LOCALLY|CALL_FLAG_REMOTE_SESSION);
    if (is_locked) sesn_call_flags |= CALL_FLAG_LOCK_SESSION;
    GetSessionForThisUserByUserId(sesn_ptr, pref.value.pref_value_int, &is_lock_already_owned, sesn_call_flags);
    if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
      instance_sesn_ptr_out->instance_sesn_ptr = (InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr);
      instance_sesn_ptr_out->sesn_ptr = SessionOffInstanceHolder((InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr));
      instance_sesn_ptr_out->lock_already_owned = is_lock_already_owned;
      instance_sesn_ptr_out->is_locked = is_locked;
    }
  }

  return NULL;
}

/**
 * 	@brief: callback. Commits changes to memory, ahead of committing to cache and db backends
 */
static UserPreferenceDescriptor *
_PrefValidateE164Number(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr)
{
	if (strlen(pref_ptr->value.pref_value_str) > CONFIG_E164_NUMBER_SZ_MAX) goto return_error;

	if (IS_STR_LOADED(sesn_ptr->sservice.user.user_details.user_preferences.e164number)) {
		if (strcasecmp(pref_ptr->value.pref_value_str, sesn_ptr->sservice.user.user_details.user_preferences.e164number)==0)	goto return_error;
	}

	return pref_ptr;

	return_error:
	return NULL;

}

static UserPreferenceDescriptor *
_PrefValidateGeolocTrigger(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr)
{
  if (pref_ptr->value.pref_value_int < 0 || pref_ptr->value.pref_value_int > GEOLOC_TRIGGER_NOT_VALID - 1) goto return_error;

  return pref_ptr;

  return_error:
  return NULL;

}

/**
 * Only loads from user's memory based session
 */
enum GeoLocRoamingTrigger
GetUserPrefGeolocRoamingTrigger(Session *sesn_ptr)
{
  UserPreferenceDescriptor pref = {0};
  GetUserPreferenceInteger(sesn_ptr, PREF_GEOLOC_TRIGGER, PREFSTORE_MEM, &pref);

  return (enum GeoLocRoamingTrigger)pref.value.pref_value_int;
}

bool
IsUserBaseLocSelfZoned(Session * _Nonnull sesn_ptr)
{
  return GetUserPrefBaselocAnchorZone(sesn_ptr) == BASELOC_ZONE_SELFZONE_EXCLUSIVE;
}

/**
 * Only loads from user's memory based session
 */
enum BaseLocAnchorZones
GetUserPrefBaselocAnchorZone(Session *sesn_ptr)
{
  UserPreferenceDescriptor pref = {0};
  GetUserPreferenceInteger(sesn_ptr, PREF_BASELOC_ANCHOR_ZONE, PREFSTORE_MEM, &pref);

  return (enum BaseLocAnchorZones)pref.value.pref_value_int;
}

static UserPreferenceDescriptor *
_SetLocalGeolocTrigger(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in)
{
  SESSION_USERPREF_GEOLOC_TRIGGER(sesn_ptr) = pref_ptr_in->value.pref_value_int;

  return pref_ptr_in;
}

static UserPreferenceDescriptor *
_GetLocalGeolocTrigger(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in)
{
  pref_ptr_in->value.pref_value_int =  SESSION_USERPREF_GEOLOC_TRIGGER(sesn_ptr);

  return pref_ptr_in;
}

static UserPreferenceDescriptor *
_PrefValidateBaselocZone(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr)
{
  if (pref_ptr->value.pref_value_int < 0 || pref_ptr->value.pref_value_int > BASELOC_ZONE_NOT_VALID - 1) goto return_error;

  return pref_ptr;

  return_error:
  return NULL;

}

/**
 * Value comes in as 'lat,long:country:region:area:zone:'
 * @param sesn_ptr
 * @param pref_ptr
 * @return
 */
static UserPreferenceDescriptor *
_PrefValidateHomebaseGeoLoc(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr)
{
  if (strlen(pref_ptr->value.pref_value_str) > (UINT64_LONGEST_STR_SZ * 3) + CONFIG_DEFAULT_GEOLOC_MAX_SZ + 3) {// + 3 = ',', ':' + NULL
    return NULL;
  }

  LocationDescription location = {0};
  if (IS_PRESENT(ProvideLocationDescriptionFromSerialised(strdupa(pref_ptr->value
                                                                          .pref_value_str), &location, false))) { //focuses on lat/long only
    if (location.longitude == 0.0f || location.latitude == 0.0) goto return_error;
  }

  return pref_ptr;

  return_error:
  return NULL;

}
static UserPreferenceDescriptor *
_SetLocalBaselocZone(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in)
{
  SESSION_USERPREF_BASELOC_ZONE(sesn_ptr) = pref_ptr_in->value.pref_value_int;

  return pref_ptr_in;
}

static UserPreferenceDescriptor *
_GetLocalBaselocZone(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in)
{
  pref_ptr_in->value.pref_value_int =  SESSION_USERPREF_BASELOC_ZONE(sesn_ptr);

  return pref_ptr_in;
}

__unused static UserPreferenceDescriptor *
_SetLocalHomebaseLoc(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in)
{
  if (IS_STR_LOADED(SESSION_USERPREF_HOMEBASE_GEOLOC(sesn_ptr)))	free(SESSION_USERPREF_HOMEBASE_GEOLOC(sesn_ptr));

  if (IS_STR_LOADED(pref_ptr_in->value.pref_value_str)) SESSION_USERPREF_HOMEBASE_GEOLOC(sesn_ptr) = strdup(pref_ptr_in->value.pref_value_str);
  else LOAD_NULL(SESSION_USERPREF_HOMEBASE_GEOLOC(sesn_ptr));

  return pref_ptr_in;
}

__unused static UserPreferenceDescriptor *
_GetLocalHomebaseLoc(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in)
{
  pref_ptr_in->value.pref_value_str =  SESSION_USERPREF_HOMEBASE_GEOLOC(sesn_ptr);

  return pref_ptr_in;
}
//

static UserPreferenceDescriptor *
_PrefValidateUnsolicitedContactAction(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr)
{
  if ((pref_ptr->value.pref_value_int > ACTION_ALLOW) || (pref_ptr->value.pref_value_int < ACTION_BLOCK)) goto return_error;

  return pref_ptr;

  return_error:
  return NULL;

}

static UserPreferenceDescriptor *
_PrefValidateGuardianUid(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr)
{
  if (pref_ptr->value.pref_value_int < 0) goto return_error;

  return pref_ptr;

  return_error:
  return NULL;

}

//quick and dirty
UserPrefsOffsets
GetPrefIndexByName(const char *pref_name)
{
	static size_t prefs_table_sz = sizeof(prefs_table) / sizeof(UserPreferenceDescriptor);

	for (size_t i=0; i<prefs_table_sz-1; i++) {
		if (strcmp(prefs_table[i].pref_name, pref_name) == 0)	return i;
	}

	return PREF_LAST_ALIGNMENT;
}

__attribute__((pure)) const char *
GetPrefNameByIndex(UserPrefsOffsets pref_offset)
{
	if (pref_offset < 0 || pref_offset >= PREF_LAST_ALIGNMENT)	return NULL;
	return prefs_table[pref_offset].pref_name;
}

/**
 *  @brief: High level routine for interfacing the Prefs metedata table
 */
PrefValueType
GetPrefValueTypeByName(const char *pref_name)
{
	static size_t prefs_table_sz = sizeof(prefs_table) / sizeof(UserPreferenceDescriptor);

	for (size_t i=0; i<prefs_table_sz-1; i++) {
		if (strcmp(prefs_table[i].pref_name, pref_name) == 0)	return prefs_table[i].pref_value_type;
	}

	return PREFVALUETYPE_INVALID;
}

/**
 *  @brief: High level routine for interfacing the Prefs metedata table
 */
const UserPreferenceDescriptor *
GetPrefDescriptorByName(const char *pref_name)
{
	static size_t prefs_table_sz = sizeof(prefs_table)/sizeof(UserPreferenceDescriptor);

	for (size_t i=0; i<prefs_table_sz-1; i++) {
		if (strcmp(prefs_table[i].pref_name, pref_name) == 0) {
			const UserPreferenceDescriptor *pref_descriptor = &prefs_table[i];
			return pref_descriptor;
		}
	}

	return NULL;
}

/**
 *  @brief: High level routine for interfacing the Prefs metedata table
 */
__pure const UserPreferenceDescriptor *
GetPrefDescriptorById(const UserPrefsOffsets pref_offset)
{
	static size_t prefs_table_sz = sizeof(prefs_table) / sizeof(UserPreferenceDescriptor);

	if ((pref_offset >= 0 ) && (pref_offset < prefs_table_sz - 1)) {
		const UserPreferenceDescriptor *pref_descriptor = &prefs_table[pref_offset];
		return pref_descriptor;
	}

	return NULL;
}

PrefValueType
GetPrefValueTypeByIndex(UserPrefsOffsets pref_offset)
{
	if (pref_offset < 0 || pref_offset >= PREF_LAST_ALIGNMENT)	return PREFVALUETYPE_INVALID;
	return prefs_table[pref_offset].pref_value_type;
}

/**
 * 	@brief: return the string representation of boolean prefs stored at key starting from offset.
 * 	should not be used to fetch data about user.
 * 	@dynamic_memory redisReply *: EXPORTS
 */
UFSRVResult *
CacheBackendGetUserPreferenceRecordByRange(unsigned long userid, int range1, int range2)
{
	int rescode = RESCODE_PROG_NULL_POINTER;

	PersistanceBackend	*pers_ptr		=  THREAD_CONTEXT_PERSISTANCE_CACHEBACKEND(THREAD_CONTEXT);
	redisReply 					*redis_ptr	=	NULL;

	//this command will return "" string if set does not exist, ie does not communicate error in that sense
	if (!(redis_ptr = (*pers_ptr->send_command)(NO_SESSION, REDIS_CMD_USERPREF_GETRANGE, userid, range1, range2)))	goto return_redis_error;

	if (redis_ptr->type == REDIS_REPLY_STRING) {
    THREAD_CONTEXT_RETURN_RESULT_SUCCESS(redis_ptr, RESCODE_BACKEND_DATA)
	}

	if (redis_ptr->type == REDIS_REPLY_ERROR)	goto return_redis_error;
	if (redis_ptr->type == REDIS_REPLY_NIL)		goto return_redis_error;

	return_redis_error:
	if (IS_EMPTY(redis_ptr)) {
	 syslog(LOG_DEBUG, "%s {pid:'%lu, th_ctx:'%p', uid:'%lu'}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), THREAD_CONTEXT_PTR, userid);
	 rescode = RESCODE_BACKEND_DATA;
	 goto return_final;
	}
	if (redis_ptr->type == REDIS_REPLY_ERROR) {
	 syslog(LOG_DEBUG, "%s {pid:'%lu, th_ctx:'%p', uid:'%lu'}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), THREAD_CONTEXT_PTR, userid, redis_ptr->str);
	 rescode = RESCODE_BACKEND_DATA;
	 goto return_free;
	}
	if (redis_ptr->type == REDIS_REPLY_NIL) {
	 syslog(LOG_DEBUG, "%s {pid:'%lu, th_ctx:'%p', uid:'%lu'}: ERROR: NIL SET",  __func__, pthread_self(), THREAD_CONTEXT_PTR, userid);
	 rescode = RESCODE_BACKEND_DATA;
	 goto return_free;
	}

	return_free:
	freeReplyObject(redis_ptr);

	return_final:
  THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, rescode)

}

/**
 * 	@dynamic_memory redisReply *: EXPORTS
 */
UFSRVResult *
CacheBackendGetUserPreferenceRecordBoolean(Session *sesn_ptr, unsigned long userid, size_t pref_offset)
{
	int rescode = RESCODE_PROG_NULL_POINTER;

	PersistanceBackend	*pers_ptr		=	sesn_ptr->persistance_backend;
	redisReply 					*redis_ptr	=	NULL;

	//this command will return "" string if set does not exist, ie does not communicate error in that sense
	if (!(redis_ptr = (*pers_ptr->send_command)(sesn_ptr, REDIS_CMD_USERPREF_ONOFF_GET, userid, pref_offset)))	goto return_redis_error;

	if (redis_ptr->type == REDIS_REPLY_INTEGER) {
		_RETURN_RESULT_SESN(sesn_ptr, redis_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
	}

	if (redis_ptr->type == REDIS_REPLY_ERROR)	goto return_redis_error;
	if (redis_ptr->type == REDIS_REPLY_NIL)		goto return_redis_error;

	return_redis_error:
	if (IS_EMPTY(redis_ptr)) {
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	}
	if (redis_ptr->type == REDIS_REPLY_ERROR) {
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), redis_ptr->str);
	 rescode = RESCODE_BACKEND_DATA;
	 goto return_error;
	}
	if (redis_ptr->type == REDIS_REPLY_NIL) {
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: NIL SET",  __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	 rescode = RESCODE_BACKEND_DATA;
	 goto return_error;
	}

	return_error:
	freeReplyObject(redis_ptr);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)

}

/**
 * 	@dynamic_memory redisReply *: EXPORTS
 */
UFSRVResult *
CacheBackendSetUserPreferenceRecord(Session *sesn_ptr, unsigned long userid, size_t pref_offset, bool pref_value)
{
	int rescode = RESCODE_PROG_NULL_POINTER;

	PersistanceBackend	*pers_ptr		=	sesn_ptr->persistance_backend;
	redisReply 					*redis_ptr	=	NULL;

	if (!(redis_ptr = (*pers_ptr->send_command)(sesn_ptr, REDIS_CMD_USERPREF_ONOFF, userid, pref_offset, pref_value)))	goto return_redis_error;

	if (redis_ptr->type == REDIS_REPLY_INTEGER) {
		_RETURN_RESULT_SESN(sesn_ptr, redis_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
	}

	if (redis_ptr->type == REDIS_REPLY_ERROR)	goto return_redis_error;
	if (redis_ptr->type == REDIS_REPLY_NIL)		goto return_redis_error;

	return_redis_error:
	if (IS_EMPTY(redis_ptr)) {
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: CACHE BACKEND: NO REPLY RECEIVED...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	}
	if (redis_ptr->type == REDIS_REPLY_ERROR) {
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: REDIS RESULTSET. Error: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), redis_ptr->str);
	 rescode = RESCODE_BACKEND_DATA;
	 goto return_error;
	}
	if (redis_ptr->type == REDIS_REPLY_NIL) {
	 syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid:'%lu'}: ERROR: NIL SET",  __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	 rescode = RESCODE_BACKEND_DATA;
	 goto return_error;
	}

	return_error:
	freeReplyObject(redis_ptr);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)

}

/**
 * @brief: packs the boolean prefs in the way stored in redis, so when read from db it can be stored  as is redis
 */
unsigned long
GenerateUserPrefsBooleanForStorage(Session *sesn_ptr)
{
	UserPrefsBooleanStorage prefs_storage = {0};
	prefs_storage.on_off = sesn_ptr->sservice.user.user_details.user_preferences.on_off;

#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu'): PREFS BINARY STORAGE BEFORE:'0x%lx'", __func__, pthread_self(), SESSION_ID(sesn_ptr), prefs_storage.storage);
#endif

	unsigned char bitgroups8[sizeof(unsigned long)]={0};

	memcpy((void *)&bitgroups8, (void *)&prefs_storage.storage, sizeof(unsigned long));

	for (size_t i=0; i<sizeof(unsigned long); i++)
	{
		//bitgroups8[i]= (bitgroups8[i] >> 3) | (bitgroups8[i]<< (sizeof(char)*8-3));//flip bits arounds
		bitgroups8[i]= (bitgroups8[i] * 0x0202020202ULL & 0x010884422010ULL) % 1023;//reverse the bits on the byte
	}

	memcpy((void *)&prefs_storage.storage, (void *)&bitgroups8, sizeof(unsigned long));//TODO: perhaps do it in cleaner, more platform neutral way
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu'): PREFS BINARY STORAGE AFTER:'0x%lx'", __func__, pthread_self(), SESSION_ID(sesn_ptr), prefs_storage.storage);
#endif

	return prefs_storage.storage;

}

static void _PopulateUserPrefsBooleanFromRawJson(Session *sesn_ptr, json_object *jobj_userprefs);
static void _PopulateUserPrefsFromRawJson(Session *sesn_ptr, json_object *jobj_userprefs);

static void
_PopulateUserPrefsBooleanFromRawJson(Session *sesn_ptr, json_object *jobj_userprefs)
{
  GenerateUserPrefsBooleanFromStorage(sesn_ptr, json_object_get_int64(json__get(jobj_userprefs, ACCOUNT_JSONATTR_PREFS_BOOL)));
}

void
GenerateUserPrefsBooleanFromStorage(Session *sesn_ptr, unsigned long stored_value)
{
  UserPrefsBooleanStorage prefs_storage = {0};
  prefs_storage.storage = stored_value;

#ifdef __UF_FULLDEBUG
  syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu'): PREFS BINARY DB STORAGE:'0x%lx'", __func__, pthread_self(), SESSION_ID(sesn_ptr), prefs_storage.storage);
#endif

  unsigned char bitgroups8[sizeof(unsigned long)] = {0};

  memcpy((void *)&bitgroups8, (void *)&prefs_storage.storage, sizeof(unsigned long));

  for (size_t i=0; i<sizeof(unsigned long); i++) {
    bitgroups8[i] = (bitgroups8[i] * 0x0202020202ULL & 0x010884422010ULL) % 1023;//reverse the bits on the byte
  }

  memcpy((void *)&prefs_storage.storage, (void *)&bitgroups8, sizeof(unsigned long));

#ifdef __UF_FULLDEBUG
  syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu'): PREFS BINARY STORAGE AFTER:'0x%lx'", __func__, pthread_self(), SESSION_ID(sesn_ptr), prefs_storage.storage);
#endif

  sesn_ptr->sservice.user.user_details.user_preferences.on_off = prefs_storage.on_off;

}

/**
 * 	@brief: load user prefs other than booleans into Session
 */
static void
_PopulateUserPrefsFromRawJson(Session *sesn_ptr, json_object *jobj_userprefs)
{
	const UserPreferenceDescriptor *prefdef_ptr;

	const char *user_pref = json_object_get_string(json__get(jobj_userprefs, ACCOUNT_JSONATTR_NICKNAME));
	if (IS_STR_LOADED(user_pref) && !(strcmp(user_pref, CONFIG_DEFAULT_PREFS_STRING_VALUE) == 0)) {
		prefdef_ptr = GetPrefDescriptorById(PREF_NICKNAME);
		(*prefdef_ptr->pref_ops->pref_set_local)(sesn_ptr, &((UserPreferenceDescriptor){.pref_id=PREF_NICKNAME, .value.pref_value_str=(char *)user_pref}));
	}

	user_pref = json_object_get_string(json__get(jobj_userprefs, ACCOUNT_JSONATTR_AVATAR));
	if (IS_STR_LOADED(user_pref) && !(strcmp(user_pref, CONFIG_DEFAULT_PREFS_STRING_VALUE) == 0)) {
		prefdef_ptr = GetPrefDescriptorById(PREF_AVATAR);
		(*prefdef_ptr->pref_ops->pref_set_local)(sesn_ptr, &((UserPreferenceDescriptor){.pref_id=PREF_AVATAR, .value.pref_value_str=(char *)user_pref}));
	}

  user_pref = json_object_get_string(json__get(jobj_userprefs, ACCOUNT_JSONATTR_E164NUMBER));
  if (IS_STR_LOADED(user_pref) && !(strcmp(user_pref, CONFIG_DEFAULT_PREFS_STRING_VALUE) == 0)) {
    prefdef_ptr = GetPrefDescriptorById(PREF_E164NUMBER);
    (*prefdef_ptr->pref_ops->pref_set_local)(sesn_ptr, &((UserPreferenceDescriptor){.pref_id=PREF_E164NUMBER, .value.pref_value_str=(char *)user_pref}));
  }

  user_pref = json_object_get_string(json__get(jobj_userprefs, ACCOUNT_JSONATTR_GUARDIAN_UID));
  if (IS_STR_LOADED(user_pref)) {
    prefdef_ptr = GetPrefDescriptorById(PREF_GUARDIAN_UID);
    (*prefdef_ptr->pref_ops->pref_set_local)(sesn_ptr, &((UserPreferenceDescriptor){.pref_id=PREF_GUARDIAN_UID, .value.pref_value_int=strtoul(user_pref, NULL, 10)}));
  }

  enum GeoLocRoamingTrigger geoloc_trigger = json_object_get_int(json__get(jobj_userprefs, ACCOUNT_JSONATTR_GEOLOC_TRIGGER));
  prefdef_ptr = GetPrefDescriptorById(PREF_GEOLOC_TRIGGER);
  (*prefdef_ptr->pref_ops->pref_set_local)(sesn_ptr, &((UserPreferenceDescriptor){.pref_id=PREF_GEOLOC_TRIGGER, .value.pref_value_int=geoloc_trigger}));

  enum BaseLocAnchorZones baseloc_zone = json_object_get_int(json__get(jobj_userprefs, ACCOUNT_JSONATTR_BASELOC_ZONE));
  prefdef_ptr = GetPrefDescriptorById(PREF_BASELOC_ANCHOR_ZONE);
  (*prefdef_ptr->pref_ops->pref_set_local)(sesn_ptr, &((UserPreferenceDescriptor){.pref_id=PREF_BASELOC_ANCHOR_ZONE, .value.pref_value_int=baseloc_zone}));

  user_pref = json_object_get_string(json__get(jobj_userprefs, ACCOUNT_JSONATTR_HOMEBASE_GEOLOC));
  if (IS_STR_LOADED(user_pref) && !(strcmp(user_pref, CONFIG_DEFAULT_PREFS_STRING_VALUE) == 0)) {
    prefdef_ptr = GetPrefDescriptorById(PREF_HOMEBASE_GEOLOC);
    (*prefdef_ptr->pref_ops->pref_set_local)(sesn_ptr, &((UserPreferenceDescriptor){.pref_id=PREF_HOMEBASE_GEOLOC, .value.pref_value_str=(char *)user_pref}));
  }

  	//TODO: add more memory kept prefs below

}

/**
 * 	@brief: Re-enact db stored user boolean prefs into user Session
 */
void
PopulateUserPrefsFromRawJson(Session *sesn_ptr, json_object *jobj_userprefs)
{
  _PopulateUserPrefsBooleanFromRawJson(sesn_ptr, jobj_userprefs);
  _PopulateUserPrefsFromRawJson(sesn_ptr, jobj_userprefs);

}

/**
 * 	@brief: Used in the context of resetting session
 */
void
ResetUserPreferences(Session *sesn_ptr)
{
	UserPrefsBooleanStorage storage = {.storage=64UL};
  SESSION_USERBOOLPREFS(sesn_ptr) = storage.on_off;

	if (IS_STR_LOADED(SESSION_USERNICKNAME(sesn_ptr))) {
		free(SESSION_USERNICKNAME(sesn_ptr));
		LOAD_NULL(SESSION_USERNICKNAME(sesn_ptr));
	}

	if (IS_STR_LOADED(SESSION_USERAVATAR(sesn_ptr))) {
			free(SESSION_USERAVATAR(sesn_ptr));
			LOAD_NULL(SESSION_USERAVATAR(sesn_ptr));
	}

  if (IS_STR_LOADED(SESSION_USERE164NUMBER(sesn_ptr))) {
    free(SESSION_USERE164NUMBER(sesn_ptr));
    LOAD_NULL(SESSION_USERE164NUMBER(sesn_ptr));
  }

  if (IS_STR_LOADED(SESSION_USERPREF_HOMEBASE_GEOLOC(sesn_ptr))) {
    free(SESSION_USERPREF_HOMEBASE_GEOLOC(sesn_ptr));
    LOAD_NULL(SESSION_USERPREF_HOMEBASE_GEOLOC(sesn_ptr));
  }

  SESSION_USERPREF_BASELOC_ZONE(sesn_ptr) = BASELOC_ZONE_UNDEFINED;
  SESSION_USERPREF_GEOLOC_TRIGGER(sesn_ptr) = GEOLOC_TRIGGER_UNDEFINED;

  SESSION_USERGUARDIAN_UID(sesn_ptr) = 0;

  //unsolicited contact not memory-kept

	//Add more memory kept prefs below
}

/**
 * @brief: returns all user prefs stored the DB backend using JSON
 * 	@dynamic_memory json_object *: EXPORTS
 */
UFSRVResult *
DbBackendGetUserPrefs(Session *sesn_ptr, unsigned long userid)
{
#define SQL_GET_ACCOUNT_DATA "SELECT data_user FROM accounts WHERE id = %lu" // {"prefs_bool": 192, ...}
#define SQL_GET_ACCOUNT_DATA_USERNAME "SELECT data_user FROM accounts WHERE number = '%s'" // {"prefs_bool": 192, ...}
		int 	rescode;
		char 	*sql_query_str;
		struct _h_result result;

		if (userid > 0) {
      sql_query_str = mdsprintf(SQL_GET_ACCOUNT_DATA, userid);
    } else {
      sql_query_str = mdsprintf(SQL_GET_ACCOUNT_DATA_USERNAME, SESSION_USERNAME(sesn_ptr));
		}

#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (cid='%lu'): GENERATED SQL QUERY: '%s'", __func__, SESSION_ID(sesn_ptr), sql_query_str);
#endif

		int sql_result = h_query_select(THREAD_CONTEXT_DB_BACKEND, sql_query_str, &result);

		if (sql_result != H_OK)		goto return_db_error;
		if (result.nb_rows == 0)	goto return_empty_set;
		if (IS_EMPTY(((struct _h_type_blob *)result.data[0][0].t_data)))	goto return_db_empty_jsonstr;

		const char *account_data_json_str = strndupa((char *)(((struct _h_type_blob *)result.data[0][0].t_data)->value), ((struct _h_type_blob *)result.data[0][0].t_data)->length);
		size_t 			jsonstr_sz = strlen(account_data_json_str);

		if (unlikely(jsonstr_sz == 0))	goto return_db_empty_jsonstr;

#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:%p', cid:'%lu'): RETRIEVED JSON ACCOUNT DATA: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), account_data_json_str);
#endif
		enum 		json_tokener_error jerr;
		struct 	json_object 	*jobj_account=NULL;
		struct 	json_tokener 	*jtok;
		{
			jtok = json_tokener_new();

			do {
				jobj_account = json_tokener_parse_ex(jtok, account_data_json_str, strlen(account_data_json_str));
			} while ((jerr = json_tokener_get_error(jtok)) == json_tokener_continue);

			if (jerr != json_tokener_success)	goto return_error_json_tokniser;

			return_success:
			json_tokener_free(jtok);
			h_clean_result(&result);
			free(sql_query_str);
			_RETURN_RESULT_SESN(sesn_ptr, jobj_account, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
		}

		return_error_json_tokniser:
		syslog(LOG_NOTICE, "%s (pid:'%lu' cid:'%lu'): JSON tokeniser Error: '%s'. Terminating.", __func__, pthread_self(), sesn_ptr->session_id, json_tokener_error_desc(jerr));
		rescode = RESCODE_PROG_JSON_PARSER;
		goto return_free_json_tokeniser;

		return_db_empty_jsonstr:
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR: DB JSON COLUMN NULL OR STRING SIZE ZERO", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
		rescode = RESCODE_BACKEND_RESOURCE_NULL;
		goto return_free_sql_handle;

		return_empty_set:
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR: COULD FIND CORRESPONDING DB RECORD", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
#endif
		rescode = RESCODE_BACKEND_DATA_EMPTYSET;
		goto return_free_sql_handle;

		return_db_error:
		syslog(LOG_DEBUG, "%s (cid='%lu'): ERROR: COULD EXEUTE QUERY: '%s'", __func__, SESSION_ID(sesn_ptr), sql_query_str);
		rescode = RESCODE_BACKEND_CONNECTION;
		goto return_free;

		return_free_json_tokeniser:
		json_tokener_free(jtok);
    if (IS_PRESENT(jobj_account)) json_object_put(jobj_account);

		return_free_sql_handle:
		h_clean_result(&result);

		return_free:
		free (sql_query_str);

		return_error:
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)

#undef SQL_GET_ACCOUNT_DATA
#undef SQL_GET_ACCOUNT_DATA_USERNAME
#undef SQL_GET_ACCOUNT_DATA

}

static UFSRVResult *
_ProcessIntraMessageCommandForUserPref(Session *sesn_ptr, UserPreference *sesn_msg_pref_ptr)
{
	UserPreferenceDescriptor 				pref={0};

	//if (GetUserPreferenceDescriptorByName(&user_prefs_table, sesn_msg_pref_ptr->pref_name, &pref))
	if (GetUserPreferenceDescriptorById(&user_prefs_table, AS_USER_PREFS_OFFSETS(sesn_msg_pref_ptr->pref_id), &pref)) {
		SetPrefValueByTypeFromIntraSessionMessage(sesn_msg_pref_ptr, &pref);//simple value transfer, adapting from wire format
		if (!(SetLocalUserPreference(sesn_ptr, &pref, true))) {
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', pref_name:'%s'}: ERROR: COULD NOT SET FENCE USER PREF", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr),  sesn_msg_pref_ptr->pref_name);
		} else {
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
		}
	}

	//TODO: COMMUNICATE ERROR BACK to user via WS

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
}

static UFSRVResult *
_HandleIntraMessageCommandForUserPrefs(Session *sesn_ptr, SessionMessage *sesn_msg_ptr)
{
	for (size_t i=0; i<sesn_msg_ptr->n_prefs; i++) {
		UserPreference *sesn_msg_pref_ptr = sesn_msg_ptr->prefs[i];
		_ProcessIntraMessageCommandForUserPref(sesn_ptr, sesn_msg_pref_ptr);
	}

	return &(sesn_ptr->sservice.result);
}


/**
 * Generic processor for integer based user pref values. @note this only persists to the db backend, not cache
 * @param ctx_ptr context specific data holder
 * @param value_provided integer value to be updated
 * @param event_ptr pre-generated event descriptor
 * @return
 */
UFSRVResult *
IsUserAllowedToChangeUserPrefInteger(InstanceContextForSession *ctx_ptr, int prefid_provided, int64_t value_provided, unsigned long sesn_call_flags, UfsrvEvent *event_ptr)
{
  UserPreferenceDescriptor 	pref	=	{0};
  GetUserPreferenceInteger(ctx_ptr->sesn_ptr, (UserPrefsOffsets)prefid_provided, PREFSTORE_MEM, &pref);

  if (value_provided == pref.value.pref_value_int) {
    _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOGIC_IDENTICAL_RESOURCE);
  }

  pref.value.pref_value_int = value_provided;
  if (SetUserPreferenceInteger(ctx_ptr->sesn_ptr, &pref, PREFSTORE_PERSISTED, event_ptr)) {
    if (SESSION_RESULT_TYPE_SUCCESS(ctx_ptr->sesn_ptr)) {
      if (likely(sesn_call_flags&CALL_FLAG_BROADCAST_SESSION_EVENT)) {
        InterBroadcastUserMessageUserPrefsInteger(ctx_ptr->sesn_ptr, CLIENT_CTX_DATA(&pref), event_ptr, COMMAND_ARGS__UPDATED);
        _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_UFSRV_INTERBROADCAST)
      }
    }
  }

  return SESSION_RESULT_PTR(ctx_ptr->sesn_ptr); //captures error from last invocation. Can also capture success
}

/**
 * Generic processor for single string value based user prefs. @note this only persists to the db backend, not cache
 * @param ctx_ptr context specific data holder
 * @param value_provided string value to be updated
 * @param event_ptr pre-generated event descriptor
 * @return
 */
UFSRVResult *
IsUserAllowedToChangeUserPrefString(InstanceContextForSession *ctx_ptr, int prefid_provided, char *value_provided, unsigned long sesn_call_flags, UfsrvEvent *event_ptr)
{
  UserPreferenceDescriptor 	pref	=	{0};
  GetUserPreferenceString(ctx_ptr->sesn_ptr, (UserPrefsOffsets)prefid_provided, PREFSTORE_MEM, &pref);

  if (IS_PRESENT(pref.value.pref_value_str) && strcasecmp(value_provided, pref.value.pref_value_str) == 0) {
    _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOGIC_IDENTICAL_RESOURCE);
  }

  pref.value.pref_value_str = value_provided;
  if (SetUserPreferenceString(ctx_ptr->sesn_ptr, &pref, PREFSTORE_PERSISTED, event_ptr)) {
    if (SESSION_RESULT_TYPE_SUCCESS(ctx_ptr->sesn_ptr)) {
      if (likely(sesn_call_flags&CALL_FLAG_BROADCAST_SESSION_EVENT)) {
        InterBroadcastUserMessageUserPrefsInteger(ctx_ptr->sesn_ptr, CLIENT_CTX_DATA(&pref), event_ptr, COMMAND_ARGS__UPDATED);
        _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_UFSRV_INTERBROADCAST)
      }
    }
  }

  return SESSION_RESULT_PTR(ctx_ptr->sesn_ptr); //captures error from last invocation. Can also capture success
}

UFSRVResult *
IsUserAllowedToChangeUserPrefGroupRoaming(InstanceContextForSession *ctx_ptr, UserPreference *pref_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_ptr_received, UfsrvEvent *event_ptr, unsigned long sesn_call_flags) {
  UserCommand 					    *command_ptr	=	data_msg_ptr_received->ufsrvcommand->usercommand;
  UserPreferenceDescriptor 	pref          = {0};

  if (GetUserPreferenceDescriptorById(&user_prefs_table, AS_USER_PREFS_OFFSETS(pref_ptr->pref_id), &pref)) {
    pref.value.pref_value_bool = pref_ptr->values_int;
    if (IS_PRESENT((*pref.pref_ops->pref_set)(ctx_ptr->sesn_ptr, &pref, PREFSTORE_EVERYWHERE, event_ptr))) {
      ShareListContextData share_list_ctx = {ctx_ptr->sesn_ptr, NULL, NULL, &pref, data_msg_ptr_received, false, false};

      MarshalUserPrefGroupRoaming(ctx_ptr, CLIENT_CTX_DATA(&share_list_ctx), wsm_ptr_received, data_msg_ptr_received, SESSION_CALLFLAGS_EMPTY, event_ptr);
      _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
    }
  }

  return_error:
  _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
}

/**
 * 	@dynamic_memory nickname_new: IMPORTS AND RETAINS previously allocated string
 * 	This should align with the validation function for nickname _PrefValidateNickname()
 */
UFSRVResult *
IsUserAllowedToChangeNickname(InstanceContextForSession *ctx_ptr, const char *nickname_new, unsigned long sesn_call_flags, UfsrvEvent *event_ptr)
{
  AccountNicknameValidateForUniqueness(ctx_ptr->sesn_ptr, &(SESSION_UFSRVUIDSTORE(ctx_ptr->sesn_ptr)), nickname_new);
  if (SESSION_RESULT_TYPE_SUCCESS(ctx_ptr->sesn_ptr) && SESSION_RESULT_CODE_EQUAL(ctx_ptr->sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET)) {
    UserPreferenceDescriptor 	pref	=	{0};

		GetUserPreferenceNickname(ctx_ptr->sesn_ptr, PREF_NICKNAME, PREFSTORE_MEM, &pref, _EMPTY_STR);
    pref.value.pref_value_str = (char *)nickname_new;

    if (SetUserPreferenceNickname(ctx_ptr->sesn_ptr, &pref, PREFSTORE_EVERYWHERE, event_ptr)) {
      if (SESSION_RESULT_TYPE_SUCCESS(ctx_ptr->sesn_ptr)) {
        if (likely(sesn_call_flags&CALL_FLAG_BROADCAST_SESSION_EVENT)) {
          InterBroadcastUserNicknameMessage(ctx_ptr->sesn_ptr, CLIENT_CTX_DATA(nickname_new), event_ptr, COMMAND_ARGS__UPDATED);
          _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_UFSRV_INTERBROADCAST)
        }
      }
    }
  }

	return SESSION_RESULT_PTR(ctx_ptr->sesn_ptr); //captures error from last invocation. Can also capture success
}

UFSRVResult *
IsUserAllowedToDeleteNickname(InstanceContextForSession *ctx_ptr, const char *nickname_new, unsigned long sesn_call_flags, UfsrvEvent *event_ptr)
{
	UserPreferenceDescriptor 	pref	=	{0};
	GetUserPreferenceNickname(ctx_ptr->sesn_ptr, PREF_NICKNAME, PREFSTORE_MEM, &pref, CONFIG_DEFAULT_PREFS_STRING_VALUE);

		if (SetUserPreferenceNickname(ctx_ptr->sesn_ptr, &pref, PREFSTORE_EVERYWHERE, event_ptr)) {
			if (SESSION_RESULT_TYPE_SUCCESS(ctx_ptr->sesn_ptr)) {
				if (likely(sesn_call_flags&CALL_FLAG_BROADCAST_SESSION_EVENT)) {
					InterBroadcastUserNicknameMessage(ctx_ptr->sesn_ptr, CLIENT_CTX_DATA(nickname_new), event_ptr, COMMAND_ARGS__DELETED);
					_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_UFSRV_INTERBROADCAST)
				}
			}
		}

	return SESSION_RESULT_PTR(ctx_ptr->sesn_ptr); //captures error from last invocation. Can also capture success
}

/**
 * 	@dynamic_memory nickname_new: IMPORTS AND RETAINS previously allocated string
 * 	This should align with the validation function for nickname _PrefValidateNickname()
 */
UFSRVResult *
IsUserAllowedToChangeAvatar(InstanceContextForSession *ctx_ptr, const char *avatar_id, AttachmentRecord *attachment_record, unsigned long sesn_call_flags, UfsrvEvent *event_ptr)
{
	UserPreferenceDescriptor 	pref												=	{0};
	AttachmentDescriptor 			attachment_descriptor_out 	= {0};
	Session                   *sesn_ptr                   = ctx_ptr->sesn_ptr;

	if (IS_PRESENT(attachment_record)) {
    if (IS_PRESENT(GetAttachmentDescriptorEphemeral(ctx_ptr->sesn_ptr, avatar_id, false, &attachment_descriptor_out)))
      goto exit_already_exist_error;

    if (AttachmentDescriptorGetFromProto(sesn_ptr, attachment_record, 0, &attachment_descriptor_out, true)) {
      DbAttachmentStore(sesn_ptr, &attachment_descriptor_out, SESSION_USERID(sesn_ptr), 1);//false: ufsrv instance doesn't currently support lru-caching attachments
      AttachmentDescriptorDestruct(&attachment_descriptor_out, true, false);
    } else {_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER) }
  }

	GetUserPreferenceAvatar(sesn_ptr, PREF_AVATAR, PREFSTORE_MEM, &pref);
	pref.value.pref_value_str = (char *)avatar_id;

#define FLGA_STORE_IF_VALID	0 //if set to 1, test for RESCODE_BACKEND_DATA_SETCREATED not RESCODE_BACKEND_DATA_EMPTYSET

	if (SetUserPreferenceString(sesn_ptr, &pref, PREFSTORE_EVERYWHERE, event_ptr)) {
		//TODO: INTER marshal nick change event a
		InterBroadcastUserAvatarMessage(sesn_ptr, CLIENT_CTX_DATA(avatar_id), event_ptr, COMMAND_ARGS__UPDATED);
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_UFSRV_INTERBROADCAST)
	}

	exit_already_exist_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EXISTINGSET)
}

static UFSRVResult *_CacheBackendUpdateForProfileKey(Session *sesn_ptr, const unsigned char *profile_key);

__unused static UFSRVResult *
_CacheBackendUpdateForProfileKey(Session *sesn_ptr, const unsigned char *profile_key)
{
  unsigned char key_b64encoded[GetBase64BufferAllocationSize(CONFIG_USER_PROFILEKEY_MAX_SIZE)];
  memset(key_b64encoded, 0, sizeof(key_b64encoded));
  base64_encode(profile_key, CONFIG_USER_PROFILEKEY_MAX_SIZE, key_b64encoded);
  DbBackendSetProfileKey(sesn_ptr, (const char *)key_b64encoded);

  if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
    redisReply *redis_ptr = NULL;
    memcpy(SESSION_USER_PROFILE_KEY(sesn_ptr), profile_key, CONFIG_USER_PROFILEKEY_MAX_SIZE);
    if ((redis_ptr = (*sesn_ptr->persistance_backend->send_command)(sesn_ptr, REDIS_CMD_USER_SESSION_PROFILE_KEY_SET, SESSION_USERID(sesn_ptr), SESSION_USER_PROFILE_KEY(sesn_ptr), CONFIG_USER_PROFILEKEY_MAX_SIZE))) {
      freeReplyObject(redis_ptr);
      _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
    } else {
      memset(SESSION_USER_PROFILE_KEY(sesn_ptr), '\0', CONFIG_USER_PROFILEKEY_MAX_SIZE);
      _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
    }
  } else {
    return SESSION_RESULT_PTR(sesn_ptr); //error
  }
}

/**
 * Add/remove a target-user to this session user's sharelist. Thereby, this user is sharing their profile with the target-user. This doesn't automatically share target-user's
 * profile with this session user.
 * Under this scenario two acknowledgement messages are sent: one to the originator (called sharing) and another one to the target user (called shared)
 */
UFSRVResult *
IsUserAllowedToShareProfile(InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_received, UfsrvEvent *event_ptr, unsigned long sesn_call_flags)
{
	UserPreferenceDescriptor 	pref	=	{0};
	UserCommand *usercommand			=	data_msg_received->ufsrvcommand->usercommand;
	UserPreference *user_command_prefs 	=	usercommand->prefs[0];
	unsigned command_arg 				= usercommand->header->args;

	Session *sesn_ptr                   = ctx_ptr->sesn_ptr;

	//TODO: IS THIS NECESSARY? previously, we didnt retrieve key from Session, as we didnt store it
	//bad pref_id I
	if (IS_EMPTY(GetUserPreferenceShareList(sesn_ptr, (UserPrefsOffsets) user_command_prefs->pref_id, PREFSTORE_MEM, &pref))) {
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}

	if (user_command_prefs->vaues_blob.len != CONFIG_USER_PROFILEKEY_MAX_SIZE || IS_EMPTY(user_command_prefs->vaues_blob.data)) {
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_USERCMD_MISSING_PARAM)
	}
	__unused Session 		*sesn_ptr_target;
	InstanceHolderForSession *instance_sesn_ptr_target;
	UserRecord 	*user_record_ptr;

	if (usercommand->n_target_list > 0) {
		for (size_t i = 0; i < usercommand->n_target_list; i++) {
			user_record_ptr = usercommand->target_list[i];
			if (unlikely(IS_EMPTY(user_record_ptr)))	continue;
      if (unlikely(UfsrvUidIsEqual((const UfsrvUid *)user_record_ptr->ufsrvuid.data, &SESSION_UFSRVUIDSTORE(sesn_ptr))))	continue; //same user

			GetSessionForThisUserByUserId(sesn_ptr, UfsrvUidGetSequenceId((const UfsrvUid *)user_record_ptr->ufsrvuid.data), NULL, SESSION_CALLFLAGS_EMPTY); //not locking CALL_FLAG_LOCK_SESSION
			if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
			  instance_sesn_ptr_target = (InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr);
			  sesn_ptr_target = SessionOffInstanceHolder(instance_sesn_ptr_target);
			}
			else continue;

			//sesn_ptr_target NOT LOCKED

			switch (command_arg)
			{
        case COMMAND_ARGS__DELETED:
          RemoveUserFromShareList(sesn_ptr, SESSION_USERPREF_SHLIST_PROFILE_PTR(sesn_ptr), instance_sesn_ptr_target, CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND);
          break;

        case COMMAND_ARGS__ADDED:
          AddUserToShareList(sesn_ptr, SESSION_USERPREF_SHLIST_PROFILE_PTR(sesn_ptr), instance_sesn_ptr_target, CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND);
          break;

        default:
          _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
			}

			if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
        if (!SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_USER_SHARELIST_PRESENT)) {
          ShareListContextData share_list_ctx = {sesn_ptr, instance_sesn_ptr_target,
                                                 SESSION_USERPREF_SHLIST_PROFILE_PTR(sesn_ptr), &pref,
                                                 data_msg_received, false, false};

          RegisterUfsrvEvent(sesn_ptr, EVENT_TYPE_USER_PROFILE_SHARE, 0, NULL, event_ptr); //todo: set session event instance type

          if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
            MarshalUserPrefProfile(ctx_ptr, CLIENT_CTX_DATA((&share_list_ctx)), wsm_ptr_received, data_msg_received, event_ptr);

            InterBroadcastUserShareListMessage(sesn_ptr, CLIENT_CTX_DATA((&share_list_ctx)), event_ptr, command_arg);

            _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_UFSRV_INTERBROADCAST)//todo: we exiting the loop (probably OK because list should not contain more than one
          }
        } else {
          //todo: return indicator of prior presence: ACCEPTED_NOOP
        }
			}
		}
	}

	return SESSION_RESULT_PTR(sesn_ptr); //captures error from AddUserToShareList()/etc..
}

/**
 * @brief Check if a target user (by their userid) is present on a given ShareList for a source user.
 * @param sesn_ptr_target Target session to check for presence on source ShareList. Must be locked by caller.
 * @param uid_source userid for for which to load the ShareList for checking
 * @param shlist_type ShareList type
 * @param call_flags Session loading flag. If empty, Session loaded will be locked and unlocked
 * @return
 * @locked: Session * for source userid
 */
__attribute__ ((nonnull(1), access (read_write, 1))) bool
IsUserOnShareList(Session *sesn_ptr_target, size_t uid_source, EnumShareListType shlist_type, unsigned long call_flags)
{
  unsigned long sesn_call_flags = CALLFLAGS_EMPTY;
  if (call_flags == CALLFLAGS_EMPTY) {
    sesn_call_flags = (CALL_FLAG_LOCK_SESSION | CALL_FLAG_LOCK_SESSION_BLOCKING |
                       CALL_FLAG_HASH_SESSION_LOCALLY | CALL_FLAG_HASH_UID_LOCALLY | CALL_FLAG_HASH_USERNAME_LOCALLY |
                       CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION | CALL_FLAG_REMOTE_SESSION);
  }

  bool lock_already_owned = false;
  GetSessionForThisUserByUserId(sesn_ptr_target, uid_source, &lock_already_owned, sesn_call_flags);
  InstanceHolderForSession *instance_sesn_ptr_source = (InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr_target);

  if (unlikely(IS_EMPTY(instance_sesn_ptr_source)))	goto return_error_unknown_uid;

  Session *sesn_ptr_source = SessionOffInstanceHolder(instance_sesn_ptr_source);

  static void *sharelist_types [] = {
                &&SHARELIST_PROFILE,
                &&SHARELIST_LOCATION,
                &&SHARELIST_CONTACT,
                &&SHARELIST_NETSTATE,
                &&SHARELIST_FRIENDS,
                &&SHARELIST_BLOCKED,
                &&SHARELIST_READ_RECEIPT,
                &&SHARELIST_ACTIVITY_STATE,
                &&SHARELIST_BLOCKED_FENCE
  }; //ALIGN WITH EnumShareListType

  bool IsOnSharelist = false;
  __unused ShareList *share_list_ptr = NULL;
  goto *sharelist_types[shlist_type];

  SHARELIST_PROFILE:
  share_list_ptr = SESSION_USERPREF_SHLIST_PROFILE_PTR(sesn_ptr_source); goto lookup_sharelist;

  SHARELIST_LOCATION:
  share_list_ptr = SESSION_USERPREF_SHLIST_LOCATION_PTR(sesn_ptr_source); goto lookup_sharelist;

  SHARELIST_CONTACT:
  share_list_ptr = SESSION_USERPREF_SHLIST_CONTACTS_PTR(sesn_ptr_source); goto lookup_sharelist;

  SHARELIST_NETSTATE:
  share_list_ptr = SESSION_USERPREF_SHLIST_NETSTATE_PTR(sesn_ptr_source); goto lookup_sharelist;

  SHARELIST_FRIENDS:
  goto return_error_unknown_uid;

  SHARELIST_BLOCKED:
  share_list_ptr = SESSION_USERPREF_SHLIST_BLOCKED_PTR(sesn_ptr_source); goto lookup_sharelist;

  SHARELIST_READ_RECEIPT:
  share_list_ptr = SESSION_USERPREF_SHLIST_READ_RECEIPT_PTR(sesn_ptr_source); goto lookup_sharelist;

  SHARELIST_ACTIVITY_STATE:
  share_list_ptr = SESSION_USERPREF_SHLIST_ACTIVITY_STATE_PTR(sesn_ptr_source); goto lookup_sharelist;

  SHARELIST_BLOCKED_FENCE:
  share_list_ptr = SESSION_USERPREF_SHLIST_BLOCKED_FENCE_PTR(sesn_ptr_source); goto lookup_sharelist;

  lookup_sharelist:
  IsOnSharelist = (*GetShareListPresenceChecker(shlist_type))(sesn_ptr_source, sesn_ptr_target);

  unlock_session:
  if (!lock_already_owned)	SessionUnLockCtx(THREAD_CONTEXT_PTR, sesn_ptr_source, __func__);

  return IsOnSharelist;

  return_error_unknown_uid:
  return false;

}

/**
 * 	@brief: Performs lazy initialisation of sharelist. List will only be allocated and marked as initialised if backend had data stored for it.
 * 	This will result in repeated calls to backend over successive lookup calls.
 * 	todo: this policy should be revisited, as what matters is that at least one backend lookup has been performed. If the list is empty that just
 * 	reflects the state of the actual list as seen by the backend.
 * 	@param sesn_ptr Source session to look up ShareList from
 * 	@param sesn_ptr_target Target session to be looked up on Sharelist
 */
__attribute__ ((nonnull(1, 2), access (read_write, 1), access (read_only, 2))) bool
IsUserOnShareListProfile(Session *sesn_ptr, Session *sesn_ptr_target)
{
	if (!IsShareLisInitialisedProfile(sesn_ptr)) {
    InstateShareListForUsers(sesn_ptr, SESSION_USERPREF_SHLIST_PROFILE_PTR(sesn_ptr), INIT_FLAG_TRUE);
		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
			if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET))	return false;
			else 																																		goto check_initialised_list;//user could be in instated list
		}

		//fallback on error
		return false;
	}

	check_initialised_list:
	return IsUserOnShareListProvided(sesn_ptr_target, SESSION_USERPREF_SHLIST_PROFILE_PTR(sesn_ptr));
}

/**
 * 	@brief: Perform lazy initialisation of sharelist. List will only be allocated and marked as initialised if backend had data stored for it.
 * 	This will result in repeated calls to backend over successive lookup calls.
 */
__attribute__ ((nonnull(1, 2), access (read_write, 1), access (read_only, 2))) bool
IsUserOnShareListNetstate(Session *sesn_ptr, Session *sesn_ptr_target)
{
  if (!IsShareLisInitialisedNetstate(sesn_ptr)) {
    InstateShareListForUsers(sesn_ptr, SESSION_USERPREF_SHLIST_NETSTATE_PTR(sesn_ptr), INIT_FLAG_TRUE);
    if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
      if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET))	return false;
      else 																																		goto check_initialised_list;//user could be in instated list
    }

    //fallback on error
    return false;
  }

  check_initialised_list:
  return IsUserOnShareListProvided(sesn_ptr_target, SESSION_USERPREF_SHLIST_NETSTATE_PTR(sesn_ptr));
}

/**
 * 	@brief: Perform lazy initialisation of sharelist. List will only be allocated and marked as initialised if backend had data stored for it.
 * 	This will result in repeated calls to backend over successive lookup calls.
 */
__attribute__ ((nonnull(1, 2), access (read_write, 1), access (read_only, 2))) bool
IsUserOnShareListLocation(Session *sesn_ptr, Session *sesn_ptr_target)
{
  if (!IsShareLisInitialisedLocation(sesn_ptr)) {
    InstateShareListForUsers(sesn_ptr, SESSION_USERPREF_SHLIST_LOCATION_PTR(sesn_ptr), INIT_FLAG_TRUE);
    if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
      if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET))	return false;
      else 																																		goto check_initialised_list;//user could be in instated list
    }

    //fallback on error
    return false;
  }

  check_initialised_list:
  return IsUserOnShareListProvided(sesn_ptr_target, SESSION_USERPREF_SHLIST_LOCATION_PTR(sesn_ptr));
}

/**
 * @brief Check if a given target user is allow to receive read-receipts from another user
 * @param sesn_ptr User who's List is to be check
 * @param sesn_ptr_target User who is being checked
 * @return true if user is allowed to received read-receipts
 */
__attribute__ ((nonnull(1, 2), access (read_write, 1), access (read_only, 2))) bool
IsUserOnShareListReadReceipt(Session *sesn_ptr, Session *sesn_ptr_target)
{
  if (!IsShareLisInitialisedReadReceipt(sesn_ptr)) {
    InstateShareListForUsers(sesn_ptr, SESSION_USERPREF_SHLIST_READ_RECEIPT_PTR(sesn_ptr), INIT_FLAG_TRUE);
    if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
      if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET))	return false;
      else 																																		goto check_initialised_list;//user could be in instated list
    }

    //fallback on error
    return false;
  }

  check_initialised_list:
  return IsUserOnShareListProvided(sesn_ptr_target, SESSION_USERPREF_SHLIST_READ_RECEIPT_PTR(sesn_ptr));
}

/**
 * @brief Check if a given target user is allowed to see typing events of another user
 * @param sesn_ptr User who's List is to be check
 * @param sesn_ptr_target User who is being checked
 * @return true if user is allowed to see typing events
 */
__attribute__ ((nonnull(1, 2), access (read_write, 1), access (read_only, 2))) bool
IsUserOnShareListTypingIndicator(Session *sesn_ptr, Session *sesn_ptr_target)
{
  if (!IsShareLisInitialisedActivityState(sesn_ptr)) {
    InstateShareListForUsers(sesn_ptr, SESSION_USERPREF_SHLIST_ACTIVITY_STATE_PTR(sesn_ptr), INIT_FLAG_TRUE);
    if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
      if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET))	return false;
      else 																																		goto check_initialised_list;//user could be in instated list
    }

    //fallback on error
    return false;
  }

  check_initialised_list:
  return IsUserOnShareListProvided(sesn_ptr_target, SESSION_USERPREF_SHLIST_ACTIVITY_STATE_PTR(sesn_ptr));
}

/**
 * @brief Check if a given target user is on the "Blocked List" of another user
 * @param sesn_ptr User who's List is to be check
 * @param sesn_ptr_target User who is being checked
 * @return true if user is on list
 */
__attribute__ ((nonnull(1, 2), access (read_write, 1), access (read_only, 2))) bool
IsUserOnShareListBlocked(Session *sesn_ptr, Session *sesn_ptr_target)
{
  if (!IsShareLisInitialisedBlocked(sesn_ptr)) {
    InstateShareListForUsers(sesn_ptr, SESSION_USERPREF_SHLIST_BLOCKED_PTR(sesn_ptr), INIT_FLAG_TRUE);
    if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
      if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET))	return false;
      else 																																		goto check_initialised_list;//user could be in instated list
    }

    //fallback on error
    return false;
  }

  check_initialised_list:
  return IsUserOnShareListProvided(sesn_ptr_target, SESSION_USERPREF_SHLIST_BLOCKED_PTR(sesn_ptr));
}

/**
 * @brief Check if @param sesn_ptr_target is on the Contacts sharelist of @param sesn_ptr
 * @param sesn_ptr
 * @param sesn_ptr_target
 * @return
 */
bool
IsUserOnShareListContacts(Session *sesn_ptr, Session *sesn_ptr_target)
{
  if (!IsShareLisInitialisedContacts(sesn_ptr)) {
    InstateShareListForUsers(sesn_ptr, SESSION_USERPREF_SHLIST_CONTACTS_PTR(sesn_ptr), INIT_FLAG_TRUE);
    if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
      if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET))	return false;
      else 																																		goto check_initialised_list;//user could be in instated list
    }

    //fallback on error
    return false;
  }

  check_initialised_list:
  return IsUserOnShareListProvided(sesn_ptr_target, SESSION_USERPREF_SHLIST_CONTACTS_PTR(sesn_ptr));
}

/**
 * @brief Check if @param sesn_ptr_target is on the Contacts sharelist of @param sesn_ptr
 * @param sesn_ptr
 * @param fid fence id as an identifying key
 * @return
 */
bool
IsFenceOnShareListBlockedFence(Session *sesn_ptr, uint64_t fid)
{
  if (!IsShareLisInitialisedBlockedFence(sesn_ptr)) {
    InstateShareListForItems(sesn_ptr, SESSION_USERPREF_SHLIST_BLOCKED_FENCE_PTR(sesn_ptr), INIT_FLAG_TRUE);
    if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
      if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET))	return false;
      else 																																		goto check_initialised_list;//user could be in instated list
    }

    //fallback on error
    return false;
  }

  ShareListItemKeyStoreValue share_list_item = {.key_value=fid, .item_descriptor=ProvideDefaultShareListItemDescriptorForBlockedFence()};
  check_initialised_list:
  return IsItemOnShareListProvided(SESSION_USERPREF_SHLIST_BLOCKED_FENCE_PTR(sesn_ptr), &share_list_item);
}

UFSRVResult *
IsUserAllowedToShareNetstate(InstanceContextForSession *ctx_ptr, WebSocketMessage *wsm_ptr_received, DataMessage *data_msg_received, UfsrvEvent *event_ptr, unsigned long sesn_call_flags)
{
  UserPreferenceDescriptor 	pref			=	{0};
  UserCommand *usercommand						=	data_msg_received->ufsrvcommand->usercommand;
  UserPreference *user_command_prefs 	=	usercommand->prefs[0];
  unsigned command_arg 								= usercommand->header->args;

  Session *sesn_ptr                   = ctx_ptr->sesn_ptr;

  //TODO: IS THIS NECESSARY?
  //bad pref_id I
  if (IS_EMPTY(GetUserPreferenceShareList(sesn_ptr, (UserPrefsOffsets) user_command_prefs->pref_id, PREFSTORE_MEM, &pref))) {
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  __unused Session 		*sesn_ptr_target;
  InstanceHolderForSession *instance_sesn_ptr_target;
  UserRecord 	*user_record_ptr;

  if (usercommand->n_target_list > 0) {
    for (size_t i = 0; i < usercommand->n_target_list; i++) {
      user_record_ptr = usercommand->target_list[i];
      if (unlikely(IS_EMPTY(user_record_ptr)))	continue;
      if (unlikely(UfsrvUidIsEqual((const UfsrvUid *)user_record_ptr->ufsrvuid.data, &SESSION_UFSRVUIDSTORE(sesn_ptr))))	continue; //same user

      GetSessionForThisUserByUserId (sesn_ptr, UfsrvUidGetSequenceId((const UfsrvUid *)user_record_ptr->ufsrvuid.data), NULL, SESSION_CALLFLAGS_EMPTY); //not locking CALL_FLAG_LOCK_SESSION
      if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
        instance_sesn_ptr_target = (InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr);
        sesn_ptr_target = SessionOffInstanceHolder(instance_sesn_ptr_target);
      }
      else continue;

      //sesn_ptr_target NOT LOCKED

      switch (command_arg)
      {
        case COMMAND_ARGS__DELETED: //user removed
					RemoveUserFromShareList(sesn_ptr, SESSION_USERPREF_SHLIST_NETSTATE_PTR(sesn_ptr), instance_sesn_ptr_target, CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND);
          break;

        case COMMAND_ARGS__ADDED:
					AddUserToShareList(sesn_ptr, SESSION_USERPREF_SHLIST_NETSTATE_PTR(sesn_ptr), instance_sesn_ptr_target, CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND);
          break;

        default:
        _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

      }

      if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
      	if (!SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_USER_SHARELIST_PRESENT)) {
					ShareListContextData share_list_ctx = {sesn_ptr, instance_sesn_ptr_target, SESSION_USERPREF_SHLIST_NETSTATE_PTR(sesn_ptr), &pref, data_msg_received, false, false};

          RegisterUfsrvEvent(sesn_ptr, EVENT_TYPE_USER_NETSTATE_SHARE, 0, NULL, event_ptr); //todo: set session event instance type

					if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
						MarshalUserPrefNetstate(ctx_ptr, CLIENT_CTX_DATA((&share_list_ctx)), wsm_ptr_received, data_msg_received, 0, event_ptr);

						InterBroadcastUserShareListMessage(sesn_ptr, CLIENT_CTX_DATA((&share_list_ctx)), event_ptr, command_arg);

						_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_UFSRV_INTERBROADCAST)//todo: we exiting the loop (probably OK because list should not contain more than one
					}
				} else {
      		//todo: return indicator of prior presence: ACCEPTED_NOOP
      	}
      }
    }
  }

  return SESSION_RESULT_PTR(sesn_ptr); //captures error from AddUserToShareList()/etc..
}

UFSRVResult *
IsUserAllowedToShareReadReceipt(InstanceContextForSession *ctx_ptr, DataMessage *data_msg_received, UfsrvEvent *event_ptr, unsigned long sesn_call_flags)
{
  UserPreferenceDescriptor 	pref			=	{0};
  UserCommand *usercommand						=	data_msg_received->ufsrvcommand->usercommand;
  UserPreference *user_command_prefs 	=	usercommand->prefs[0];
  unsigned command_arg 								= usercommand->header->args;

  Session *sesn_ptr                   = ctx_ptr->sesn_ptr;

  //TODO: IS THIS NECESSARY?
  //bad pref_id I
  if (IS_EMPTY(GetUserPreferenceShareList(sesn_ptr, (UserPrefsOffsets) user_command_prefs->pref_id, PREFSTORE_MEM, &pref))) {
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  __unused Session 		*sesn_ptr_target;
  InstanceHolderForSession *instance_sesn_ptr_target;
  UserRecord 	*user_record_ptr;

  if (usercommand->n_target_list > 0) {
    for (size_t i = 0; i < usercommand->n_target_list; i++) {
      user_record_ptr = usercommand->target_list[i];
      if (unlikely(IS_EMPTY(user_record_ptr)))	continue;
      if (unlikely(UfsrvUidIsEqual((const UfsrvUid *)user_record_ptr->ufsrvuid.data, &SESSION_UFSRVUIDSTORE(sesn_ptr))))	continue; //same user

      GetSessionForThisUserByUserId (sesn_ptr, UfsrvUidGetSequenceId((const UfsrvUid *)user_record_ptr->ufsrvuid.data), NULL, SESSION_CALLFLAGS_EMPTY); //not locking CALL_FLAG_LOCK_SESSION
      if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
        instance_sesn_ptr_target = (InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr);
        sesn_ptr_target = SessionOffInstanceHolder(instance_sesn_ptr_target);
      }
      else continue;

      //sesn_ptr_target NOT LOCKED

      switch (command_arg)
      {
        case COMMAND_ARGS__DELETED: //user removed
          RemoveUserFromShareList(sesn_ptr, SESSION_USERPREF_SHLIST_READ_RECEIPT_PTR(sesn_ptr), instance_sesn_ptr_target, CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND);
          break;

        case COMMAND_ARGS__ADDED:
          AddUserToShareList(sesn_ptr, SESSION_USERPREF_SHLIST_READ_RECEIPT_PTR(sesn_ptr), instance_sesn_ptr_target, CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND);
          break;

        default:
        _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

      }

      if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
        if (!SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_USER_SHARELIST_PRESENT)) {
          ShareListContextData share_list_ctx = {sesn_ptr, instance_sesn_ptr_target, SESSION_USERPREF_SHLIST_READ_RECEIPT_PTR(sesn_ptr), &pref, data_msg_received, false, false};

          RegisterUfsrvEvent(sesn_ptr, EVENT_TYPE_USER_READ_RECEIPT, 0, NULL, event_ptr); //todo: set session event instance type

          if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
            MarshalUserPrefShareList(ctx_ptr, CLIENT_CTX_DATA((&share_list_ctx)), data_msg_received, NULL, event_ptr);

            InterBroadcastUserShareListMessage(sesn_ptr, CLIENT_CTX_DATA((&share_list_ctx)), event_ptr, command_arg);

            _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_UFSRV_INTERBROADCAST)//todo: we exiting the loop (probably OK because list should not contain more than one
          }
        } else {
          //todo: return indicator of prior presence: ACCEPTED_NOOP
        }
      }
    }
  }

  return SESSION_RESULT_PTR(sesn_ptr); //captures error from AddUserToShareList()/etc..
}

UFSRVResult *
IsUserAllowedToShareBlocked(InstanceContextForSession *ctx_ptr, DataMessage *data_msg_received, WebSocketMessage *wsm_ptr_received, UfsrvEvent *event_ptr, CallbackCommandMarshaller command_marshaller, unsigned long sesn_call_flags)
{
  UserPreferenceDescriptor 	pref			=	{0};
  UserCommand *usercommand						=	data_msg_received->ufsrvcommand->usercommand;
  UserPreference *user_command_prefs 	=	usercommand->prefs[0];
  unsigned command_arg 								= usercommand->header->args;

  Session *sesn_ptr                   = ctx_ptr->sesn_ptr;

  //TODO: IS THIS NECESSARY?
  //bad pref_id I
  if (IS_EMPTY(GetUserPreferenceShareList(sesn_ptr, (UserPrefsOffsets) user_command_prefs->pref_id, PREFSTORE_MEM, &pref))) {
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  __unused Session 		*sesn_ptr_target;
  InstanceHolderForSession *instance_sesn_ptr_target;
  UserRecord 	*user_record_ptr;

  if (usercommand->n_target_list > 0) {
    for (size_t i = 0; i < usercommand->n_target_list; i++) {
      user_record_ptr = usercommand->target_list[i];
      if (unlikely(IS_EMPTY(user_record_ptr)))	continue;
      if (unlikely(UfsrvUidIsEqual((const UfsrvUid *)user_record_ptr->ufsrvuid.data, &SESSION_UFSRVUIDSTORE(sesn_ptr))))	continue; //same user

      GetSessionForThisUserByUserId (sesn_ptr, UfsrvUidGetSequenceId((const UfsrvUid *)user_record_ptr->ufsrvuid.data), NULL, SESSION_CALLFLAGS_EMPTY); //not locking CALL_FLAG_LOCK_SESSION
      if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
        instance_sesn_ptr_target = (InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr);
        sesn_ptr_target = SessionOffInstanceHolder(instance_sesn_ptr_target);
      }
      else continue;

      //sesn_ptr_target NOT LOCKED

      switch (command_arg)
      {
        case COMMAND_ARGS__DELETED: //user removed
          RemoveUserFromShareList(sesn_ptr, SESSION_USERPREF_SHLIST_BLOCKED_PTR(sesn_ptr), instance_sesn_ptr_target, CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND);
          break;

        case COMMAND_ARGS__ADDED:
          AddUserToShareList(sesn_ptr, SESSION_USERPREF_SHLIST_BLOCKED_PTR(sesn_ptr), instance_sesn_ptr_target, CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND);
          break;

        default:
        _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

      }

      if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
        if (!SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_USER_SHARELIST_PRESENT)) {
          RegisterUfsrvEvent(sesn_ptr, EVENT_TYPE_USER_BLOCK, 0, NULL, event_ptr); //todo: set session event instance type

          if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
            ShareListContextData share_list_ctx = {sesn_ptr, instance_sesn_ptr_target,
                                                   SESSION_USERPREF_SHLIST_BLOCKED_PTR(sesn_ptr), &pref,
                                                   data_msg_received, false, false};
            InterBroadcastUserShareListMessage(sesn_ptr, CLIENT_CTX_DATA((&share_list_ctx)), event_ptr, command_arg);
            if (IS_PRESENT(command_marshaller)) {
              _INVOKE_COMMAND_MARSHALLER(command_marshaller, ctx_ptr, &share_list_ctx, data_msg_received, wsm_ptr_received, event_ptr);
            }

            _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_UFSRV_INTERBROADCAST)//todo: we exiting the loop (probably OK because list should not contain more than one
          }
        } else {
          //todo: return indicator of prior presence: ACCEPTED_NOOP
        }
      }
    }
  }

  return SESSION_RESULT_PTR(sesn_ptr); //captures error from AddUserToShareList()/etc..
}

static UFSRVResult *_RemoveFenceFromInvitedListIfNecessary(InstanceContextForSession *sesn_context, InstanceContextForFence *fence_context, DataMessage *data_msg_received, WebSocketMessage *wsm_ptr_received);
/**
 * @brief Check if user has the right context in place to block a fence. No prior invitation is assumed, but the invitation list will be checked and
 * user removed if successful.
 * @warning only processes the first fence in the provided collection.
 * @param ctx_ptr @ref InstanceContextForSession for the requesting user
 * @param data_msg_received @ref DataMessage provided by the requesting user
 * @param wsm_ptr_received @ref WebSocketMessage only provided if message arrived via WebSocket pipe
 * @param event_ptr @ref UfsrvEvent optionally pre-allocated by the caller
 * @param command_marshaller @ref CallbackCommandMarshaller what command response marshaller to user in responding to user
 * @param sesn_call_flags
 * @return
 * @locked WR sesn_ptr by caller
 * @locks WR f_ptr
 * @unlocks f_ptr
 */
UFSRVResult *
IsUserAllowedToShareBlockedFence(InstanceContextForSession *ctx_ptr, DataMessage *data_msg_received, WebSocketMessage *wsm_ptr_received, UfsrvEvent *event_ptr, CallbackCommandMarshaller command_marshaller, unsigned long sesn_call_flags)
{
  UserPreferenceDescriptor 	pref			=	{0};
  UserCommand *usercommand						=	data_msg_received->ufsrvcommand->usercommand;
  UserPreference *user_command_prefs 	=	usercommand->prefs[0];
  unsigned command_arg 								= usercommand->header->args;

  Session *sesn_ptr                   = ctx_ptr->sesn_ptr;

  //quick validation for bad pref_id
  if (IS_EMPTY(GetUserPreferenceShareList(sesn_ptr, (UserPrefsOffsets) user_command_prefs->pref_id, PREFSTORE_MEM, &pref))) {
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  unsigned long fid = 0;
  FenceRecord 	*fence_record_ptr;

  if (usercommand->n_fences_blocked > 0) {
    for (size_t i = 0; i < usercommand->n_fences_blocked; i++) {
      fence_record_ptr = usercommand->fences_blocked[i];
      if (unlikely(IS_EMPTY(fence_record_ptr)))	continue;

      fid = fence_record_ptr->fid;

      bool lock_already_owned = false;
      unsigned 	fence_call_flags_final;
      Fence 		*f_ptr;
      InstanceHolderForFence *instance_f_ptr = NULL;

      fence_call_flags_final = FENCE_CALLFLAG_SEARCH_BACKEND|FENCE_CALLFLAG_HASH_FENCE_LOCALLY|FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE;
      fence_call_flags_final |= (FENCE_CALLFLAG_KEEP_FENCE_LOCKED|FENCE_CALLFLAG_LOCK_FENCE_BLOCKING);

      if (fid > 0) {
        FindFenceById(sesn_ptr, fid,	fence_call_flags_final);
        instance_f_ptr = (InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr);
        lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_PROG_LOCKED_BY_THIS_THREAD));
      } else  {
        _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_MISSING_PARAM)
      }

      if (unlikely(IS_EMPTY(instance_f_ptr))) {
#ifdef __UF_TESTING
        syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', uname:'%s', fid:'%lu'}: COMMAND IGNORED: COULD NOT LOCATE FENCE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_USERNAME(sesn_ptr), fid);
#endif

        _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_DOESNT_EXIST)
      }

      f_ptr = FenceOffInstanceHolder(instance_f_ptr);

      //FENCE NOW WR LOCKED


      ShareListItemKeyStoreValue share_list_item = {.key_value=fid, .store_value=fence_record_ptr->fid, .item_descriptor=(ShareListItemDescriptor *)ProvideDefaultShareListItemDescriptorForBlockedFence()};
      switch (command_arg)
      {
        case COMMAND_ARGS__DELETED: //user removed
          RemoveItemFromShareList(sesn_ptr, SESSION_USERPREF_SHLIST_BLOCKED_FENCE_PTR(sesn_ptr), &share_list_item, CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND);
          break;

        case COMMAND_ARGS__ADDED:
          AddItemToShareList(sesn_ptr, SESSION_USERPREF_SHLIST_BLOCKED_FENCE_PTR(sesn_ptr), &share_list_item, CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND);
          break;

        default:
          if (!lock_already_owned)  FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
        _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

      }

      if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
        if (!SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_USER_SHARELIST_PRESENT)) {
          RegisterUfsrvEvent(sesn_ptr, EVENT_TYPE_USER_BLOCKED_FENCE, 0, NULL, event_ptr); //todo: set session event instance type

          if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
            ShareListContextData share_list_ctx = {sesn_ptr, NULL,
                                                   SESSION_USERPREF_SHLIST_BLOCKED_FENCE_PTR(sesn_ptr), &pref,
                                                   data_msg_received, false, false, .key_store_value=&(ShareListItemKeyStoreValue){.key_value=fence_record_ptr->fid}};
            InterBroadcastUserShareListMessage(sesn_ptr, CLIENT_CTX_DATA((&share_list_ctx)), event_ptr, command_arg);
            if (IS_PRESENT(command_marshaller)) {
              (*command_marshaller)(ctx_ptr, CLIENT_CTX_DATA((&share_list_ctx)), data_msg_received, wsm_ptr_received, event_ptr);
            }
          }
        } else {
          //todo: return indicator of prior presence: ACCEPTED_NOOP
          if (!lock_already_owned)  FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
          return SESSION_RESULT_PTR(sesn_ptr);
        }

        //todo we are not checking for the success f teh marshallling above
        if (command_arg == COMMAND_ARGS__ADDED) {
          InstanceContextForFence instance_ctx_fence = {.f_ptr=f_ptr, .instance_f_ptr=instance_f_ptr, .is_locked=true, .lock_already_owned=lock_already_owned};
          _RemoveFenceFromInvitedListIfNecessary(ctx_ptr, &instance_ctx_fence, data_msg_received, wsm_ptr_received);
          if (instance_ctx_fence.is_locked && !instance_ctx_fence.lock_already_owned)  FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
        } else {
          if (!lock_already_owned)  FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
          _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_UFSRV_INTERBROADCAST)//todo: we exiting the loop (probably OK because list should not contain more than one
        }
      } else {
        if (!lock_already_owned)  FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, SESSION_RESULT_PTR(sesn_ptr));
      }
    }
  }

  return SESSION_RESULT_PTR(sesn_ptr); //captures error from AddUserToShareList()/etc..
}

/**
 * @locks NONE
 * @unlocks NONE
 */
static UFSRVResult *
_RemoveFenceFromInvitedListIfNecessary(InstanceContextForSession *instance_sesn_ctx, InstanceContextForFence *instance_fence_ctx, DataMessage *data_msg_received, WebSocketMessage *wsm_ptr_received)
{
  Session *sesn_ptr = instance_sesn_ctx->sesn_ptr;
  Fence   *f_ptr    = instance_fence_ctx->f_ptr;
  InstanceHolderForFenceStateDescriptor *instance_fstate_ptr;

  if (IS_PRESENT((instance_fstate_ptr = IsUserMemberOfThisFence(SESSION_INVITED_FENCE_LIST_PTR(sesn_ptr), f_ptr, false)))) {

    FenceStateDescriptor *fstate_ptr = FenceStateDescriptorOffInstanceHolder(instance_fstate_ptr);
    UfsrvUid uid_invited_by = {0};
    memcpy(&uid_invited_by, &(fstate_ptr->invited_by), sizeof(UfsrvUid));

    FenceEvent fence_event = {0};
    fence_event.event_type = EVENT_TYPE_FENCE_USER_BLOCKED;
    RemoveUserFromInvitedList(instance_sesn_ctx->instance_sesn_ptr, fstate_ptr, &fence_event, FENCE_CALLFLAG_WRITEBACK_DATA_TO_BACKEND);

    MarshalFenceInvitationBlocked(instance_sesn_ctx, fstate_ptr, instance_fence_ctx, &uid_invited_by, &fence_event, wsm_ptr_received, data_msg_received, 0);

    return SESSION_RESULT_PTR(sesn_ptr);
  }

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESULT_TYPE_SUCCESS_NOOP)

}

UFSRVResult *
IsUserAllowedToShareContacts(InstanceContextForSession *ctx_ptr, DataMessage *data_msg_received, WebSocketMessage *wsm_ptr_received, UfsrvEvent *event_ptr, CallbackCommandMarshaller command_marshaller, unsigned long sesn_call_flags)
{
  UserPreferenceDescriptor 	pref			=	{0};
  UserCommand *usercommand						=	data_msg_received->ufsrvcommand->usercommand;
  UserPreference *user_command_prefs 	=	usercommand->prefs[0];
  unsigned command_arg 								= usercommand->header->args;

  Session *sesn_ptr                   = ctx_ptr->sesn_ptr;

  //TODO: IS THIS NECESSARY?
  //bad pref_id I
  if (IS_EMPTY(GetUserPreferenceShareList(sesn_ptr, (UserPrefsOffsets) user_command_prefs->pref_id, PREFSTORE_MEM, &pref))) {
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
  }

  __unused Session 		*sesn_ptr_target;
  InstanceHolderForSession *instance_sesn_ptr_target;
  UserRecord 	*user_record_ptr;

  if (usercommand->n_target_list > 0) {
    for (size_t i = 0; i < usercommand->n_target_list; i++) {
      user_record_ptr = usercommand->target_list[i];
      if (unlikely(IS_EMPTY(user_record_ptr)))	continue;
      if (unlikely(UfsrvUidIsEqual((const UfsrvUid *)user_record_ptr->ufsrvuid.data, &SESSION_UFSRVUIDSTORE(sesn_ptr))))	continue; //same user

      GetSessionForThisUserByUserId (sesn_ptr, UfsrvUidGetSequenceId((const UfsrvUid *)user_record_ptr->ufsrvuid.data), NULL, SESSION_CALLFLAGS_EMPTY); //not locking CALL_FLAG_LOCK_SESSION
      if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
        instance_sesn_ptr_target = (InstanceHolderForSession *)SESSION_RESULT_USERDATA(sesn_ptr);
        sesn_ptr_target = SessionOffInstanceHolder(instance_sesn_ptr_target);
      }
      else continue;

      //sesn_ptr_target NOT LOCKED

      switch (command_arg)
      {
        case COMMAND_ARGS__DELETED: //user removed
          RemoveUserFromShareList(sesn_ptr, SESSION_USERPREF_SHLIST_CONTACTS_PTR(sesn_ptr), instance_sesn_ptr_target, CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND);
          break;

        case COMMAND_ARGS__ADDED:
          AddUserToShareList(sesn_ptr, SESSION_USERPREF_SHLIST_CONTACTS_PTR(sesn_ptr), instance_sesn_ptr_target, CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND);
          break;

        default:
        _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

      }

      if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
        if (!SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_USER_SHARELIST_PRESENT)) {
          RegisterUfsrvEvent(sesn_ptr, EVENT_TYPE_USER_SHARE_CONTACT, 0, NULL, event_ptr); //todo: set session event instance type

          if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
            ShareListContextData share_list_ctx = {sesn_ptr, instance_sesn_ptr_target,
                                                   SESSION_USERPREF_SHLIST_CONTACTS_PTR(sesn_ptr), &pref,
                                                   data_msg_received, false, false};
            InterBroadcastUserShareListMessage(sesn_ptr, CLIENT_CTX_DATA((&share_list_ctx)), event_ptr, command_arg);
            if (IS_PRESENT(command_marshaller)) {
              _INVOKE_COMMAND_MARSHALLER(command_marshaller, ctx_ptr, &share_list_ctx, data_msg_received, wsm_ptr_received, event_ptr);
            }

            _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_UFSRV_INTERBROADCAST)//todo: we exiting the loop (probably OK because list should not contain more than one
          }
        } else {
          //todo: return indicator of prior presence: ACCEPTED_NOOP
        }
      }
    }
  }

  return SESSION_RESULT_PTR(sesn_ptr); //captures error from AddUserToShareList()/etc..
}

UFSRVResult *
IsUserAllowedToChangeUnsolicitedContactAction(InstanceContextForSession *ctx_ptr, UserPreference *pref_ptr, DataMessage *data_msg_ptr_recieved, WebSocketMessage *wsm_ptr_received, UfsrvEvent *event_ptr, CallbackCommandMarshaller command_marshaller, unsigned long sesn_call_flags)
{
  __unused UserCommand 					    *command_ptr	=	data_msg_ptr_recieved->ufsrvcommand->usercommand;
  UserPreferenceDescriptor 	pref          = {0};
  Session                   *sesn_ptr     = ctx_ptr->sesn_ptr;

  if (GetUserPreferenceDescriptorById(&user_prefs_table, AS_USER_PREFS_OFFSETS(pref_ptr->pref_id), &pref)) {
    pref.value.pref_value_int = pref_ptr->values_int;
    if (IS_PRESENT((*pref.pref_ops->pref_set)(sesn_ptr, &pref, PREFSTORE_EVERYWHERE, event_ptr))) {
      ShareListContextData share_list_ctx = {sesn_ptr, NULL, NULL, &pref, data_msg_ptr_recieved, false, false};

      if (IS_PRESENT(command_marshaller)) {
        _INVOKE_COMMAND_MARSHALLER(command_marshaller, ctx_ptr, &share_list_ctx, data_msg_ptr_recieved, wsm_ptr_received, event_ptr);
      }

      return SESSION_RESULT_PTR(sesn_ptr);
    }
  }

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
}

/**
 * @brief Working from a variety of potential unique ids: return a Session object.
 * @param sesn_ptr_carrier
 * @param handle representation for user ids: if prefixed with '@' denotes nickname. If prefixed with '+' denotes an e61 number (not supported). One last check on email before
 *  standard decoded ufsrvuid is assumed.
 * @param lock_already_owned
 * @param callflags
 * @return Session *
 * @warning No check is done on @param handle
 */
UFSRVResult *
GetSessionFromUserHandle(Session *sesn_ptr_carrier, const char *handle, bool *lock_already_owned, unsigned long callflags)
{
  unsigned long userid = 0;

  if (*handle == '@') {
    const char *nickname = handle + 1;
    if (*nickname == '\0') return NULL;
    BackendDirectoryNicknameGet(sesn_ptr_carrier, nickname);
    if (SESSION_RESULT_IS_SUCCESS_WITH_BACKEND_DATA(sesn_ptr_carrier))  userid = (unsigned long)SESSION_RESULT_USERDATA(sesn_ptr_carrier);
  } else if (*handle == '+') {
    goto return_error; //todo: support e164 lookups
  } else if (IsEmailAddressValid(handle, CONFIG_EMAIL_ADDRESS_SZ_MAX)) {
    DbGetUserByUsername(handle, CALLFLAGS_EMPTY);
    if (THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA) {
      AuthenticatedAccount *authacct_ptr = THREAD_CONTEXT_UFSRV_RESULT_USERDATA;
      userid = authacct_ptr->userid;
      free(authacct_ptr);
    }
  } else {
    userid = UfsrvUidGetSequenceIdFromEncoded(handle);
  }

  if (userid > 0) {
    GetSessionForThisUserByUserId(sesn_ptr_carrier, userid, lock_already_owned, callflags);
    return SESSION_RESULT_PTR(sesn_ptr_carrier);
  }

  return_error:
  syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', handle:'%s'}: ERROR: INVALID UFSRV HANDLE", __func__, pthread_self(), sesn_ptr_carrier, handle);
  _RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
}

struct json_object *
JsonFormatStateSyncForSessionState(Session *sesn_ptr,  enum SessionState session_state, struct json_object *jobj_out) {
  char uid_encoded[CONFIG_MAX_UFSRV_ID_ENCODED_SZ + 1] = {0};

  struct json_object *jobj;
  if (IS_PRESENT(jobj_out)) jobj = jobj_out;
  else                      jobj = json_object_new_object();

  UfsrvUidConvertSerialise(&SESSION_UFSRVUIDSTORE(sesn_ptr), uid_encoded);

  json_object_object_add(jobj, ACCOUNT_JSONATTR_SESSION_STATE, json_object_new_int(session_state));
  json_object_object_add(jobj, ACCOUNT_JSONATTR_UFSRVUID, json_object_new_string(uid_encoded));
  if (IS_STR_LOADED(SESSION_COOKIE(sesn_ptr))) json_object_object_add (jobj, ACCOUNT_JSONATTR_COOKIE, json_object_new_string(SESSION_COOKIE(sesn_ptr)));

  return jobj;
}

#include <donations/utils_donations.h>

struct json_object *
JsonFormatStateSync(Session *sesn_ptr, enum DigestMode digest_mode, bool reload_flag, struct json_object *jobj_out)
{
  char 		      uid_encoded[CONFIG_MAX_UFSRV_ID_ENCODED_SZ+1] = {0};
	Session       *sesn_ptr_reloaded;
	InstanceHolderForSession *instance_sesn_ptr_reloaded;

	if (reload_flag) {
    if ((instance_sesn_ptr_reloaded = SessionInstantiateFromCacheBackendWithDbFallback(sesn_ptr, &SESSION_UFSRVUIDSTORE(sesn_ptr), CALL_FLAG_SNAPSHOT_INSTANCE | CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION))) {
      sesn_ptr_reloaded = SessionOffInstanceHolder(instance_sesn_ptr_reloaded);
    } else sesn_ptr_reloaded = NULL;
  }
	else 							sesn_ptr_reloaded	=	sesn_ptr;

	if (unlikely(IS_EMPTY(sesn_ptr_reloaded)))	return NULL;

	struct	json_object	*jobj;
	if (IS_PRESENT(jobj_out))	jobj = jobj_out;
	else											jobj = json_object_new_object();

  UfsrvUidConvertSerialise(&SESSION_UFSRVUIDSTORE(sesn_ptr_reloaded), uid_encoded);
	const char					*nickname						= IS_EMPTY(SESSION_USERNICKNAME(sesn_ptr_reloaded)) ? "" : SESSION_USERNICKNAME(sesn_ptr_reloaded);
	json_object	*jobj_fences_array					= JsonFormatSessionFenceList(sesn_ptr_reloaded, digest_mode);
	json_object	*jobj_invited_fences_array	= JsonFormatSessionInvitedToFenceList(sesn_ptr_reloaded, digest_mode);
  json_object	*jobj_linkjoin_requested_array	= JsonFormatSessionLinkJoinRequestedFenceList(sesn_ptr_reloaded, digest_mode);
	json_object *jobj_location							= JsonFormatUserLocation(sesn_ptr_reloaded, NULL);
	json_object *jobj_array_user_prefs      = JsonFormatUserPreferences(sesn_ptr_reloaded, PREFTYPE_USER, DIGESTMODE_FULL, NULL);
	json_object *jobj_array_shared_lists    = JsonValueFormatForSharedLists(sesn_ptr_reloaded, NULL);
	json_object *jobj_array_guardians       = NULL;//JsonValueFormatForGuardians(sesn_ptr_reloaded, &(CollectionDescriptor){0});
  json_object *jobj_donations             = JsonFormatUserDonations(sesn_ptr_reloaded);
//  json_object *jobs_subscription          = //not available yet client will fetch separately via api

	json_object_object_add(jobj, ACCOUNT_JSONATTR_ACCOUNT_STATE, json_object_new_boolean(1));
	json_object_object_add(jobj, ACCOUNT_JSONATTR_UFSRVUID, json_object_new_string(uid_encoded));
  json_object_object_add(jobj, ACCOUNT_JSONATTR_EID, json_object_new_int64(SESSION_EID(sesn_ptr_reloaded)));
	json_object_object_add(jobj, ACCOUNT_JSONATTR_USERNAME, json_object_new_string(SESSION_USERNAME(sesn_ptr_reloaded)));
	json_object_object_add(jobj, ACCOUNT_JSONATTR_NICKNAME, json_object_new_string(nickname));

	ProfileKeyStore store_key = {0};
	DbBackendGetProfileKey(&(SESSION_UFSRVUIDSTORE(sesn_ptr_reloaded)), KEY_B64_SERIALISED, &store_key);
  if (IS_STR_LOADED(store_key.serialised)) {
    json_object_object_add(jobj, ACCOUNT_JSONATTR_PROFILE_KEY, json_object_new_string(store_key.serialised));
    memset(&store_key, 0, sizeof(struct ProfileKeyStore));
  }

  if (IS_PRESENT(jobj_donations)) {
    json_object_object_add(jobj, ACCOUNT_JSONATTR_DONATIONS, jobj_donations);
  }

  json_object_object_add(jobj, "cid", json_object_new_int64(SESSION_ID(sesn_ptr_reloaded)));
	json_object_object_add(jobj, "sid", json_object_new_string(masterptr->server_descriptive_name));
	json_object_object_add(jobj, "queue_size", json_object_new_int64(GetMessageQueueSize(sesn_ptr_reloaded)));
	json_object_object_add(jobj, "invited_list_size", json_object_new_int64(SESSION_INVITED_FENCE_LIST_SIZE(sesn_ptr_reloaded)));

	if (IS_PRESENT(jobj_array_user_prefs)) {
    json_object_object_add(jobj, "user_prefs", jobj_array_user_prefs);
	}

	if (IS_PRESENT(jobj_array_shared_lists)) {
		json_object_object_add(jobj, "shared_lists", jobj_array_shared_lists);
	}

	if (IS_PRESENT(jobj_array_guardians)) {
    json_object_object_add(jobj, "guardians", jobj_array_guardians);
	}

	if (jobj_fences_array) {
		json_object_object_add(jobj, FENCE_JSONATTR_FENCES, jobj_fences_array);
	}

	if (IS_PRESENT(jobj_invited_fences_array)) {
		json_object_object_add(jobj, FENCE_JSONATTR_FENCES_INVITED, jobj_invited_fences_array);
	}

	if (jobj_location) {
		json_object_object_add(jobj, "location", jobj_location);
	}

	if (reload_flag) {
		ResetSessionData(instance_sesn_ptr_reloaded);
		SessionReturnToRecycler(instance_sesn_ptr_reloaded, NULL, 0);
	}

	return jobj;
}

size_t
GetMessageQueueSize(Session *sesn_ptr)
{
  size_t queue_sz = 0;
	GetStageMessageCacheBackendListSize(sesn_ptr, SESSION_USERID_TEMP(sesn_ptr));
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))	queue_sz = (uintptr_t)SESSION_RESULT_USERDATA(sesn_ptr);

  return queue_sz;
}

/**
 * @brief Read-only, zero'ed out profile key storage buffer.
 *
 * Use to test is a given profilekey have been initialised (e.g by doing a memcmp()), or load a profile key with zero value.
 * @return read-only empty buffer.
 */
unsigned char *
GetEmptyProfile()
{
  static unsigned char empty_profile[CONFIG_USER_PROFILEKEY_MAX_SIZE] = {0};

  return empty_profile;
}

bool
IsProfileKeyLoaded(const Session *sesn_ptr)
{
  if (memcmp(SESSION_USER_PROFILE_KEY(sesn_ptr), GetEmptyProfile(), CONFIG_USER_PROFILEKEY_MAX_SIZE) != 0) {
    return true;
  }

  return false;
}

bool
IsProfileKeyLoadedAndEncode(Session *sesn_ptr_reloaded, void(^on_encoded)(unsigned  char *))
{
  unsigned char *profile_key_provided = SESSION_USER_PROFILE_KEY(sesn_ptr_reloaded);
  if (memcmp(profile_key_provided, GetEmptyProfile(), CONFIG_USER_PROFILEKEY_MAX_SIZE) != 0) {
    unsigned char profile_key_encoded[GetBase64BufferAllocationSize(CONFIG_USER_PROFILEKEY_MAX_SIZE)];
    memset(profile_key_encoded, 0, sizeof(profile_key_encoded));
    base64_encode(profile_key_provided, CONFIG_USER_PROFILEKEY_MAX_SIZE, profile_key_encoded);
    on_encoded(profile_key_encoded);
    return true;
  } else {
      ProfileKeyStore  key_store = {0};
      DbBackendGetProfileKey(&(SESSION_UFSRVUIDSTORE(sesn_ptr_reloaded)), KEY_B64_SERIALISED, &key_store);
      if (IS_STR_LOADED(key_store.serialised)) {
        on_encoded((unsigned char *)key_store.serialised);
        memset(&key_store, 0, sizeof(ProfileKeyStore));
        return true;
      }
  }

  return false;
}

static void
_LoadUuidForJsonFormatting(Session *sesn_ptr, json_object *jobj)
{
  DbOpDescriptor dbop_descriptor = {0};
  Uuid           uuid            = {0};

  if (IS_PRESENT(GetUuid(SESSION_USERNAME(sesn_ptr), &uuid, &dbop_descriptor))) {
    json_object_object_add(jobj, ACCOUNT_JSONATTR_UUID, json_object_new_string(uuid.serialised.by_ref));
    DBOP_DESCRIPTOR_INVOKE_RESULT_FINALISER(&dbop_descriptor);
  }

}

static json_object *
_JsonFormatSystemUserProfile(json_object *jobj_out)
{
  struct	json_object	*jobj;
  if (IS_PRESENT(jobj_out))	jobj = jobj_out;
  else											jobj = json_object_new_object();

  json_object_object_add(jobj, ACCOUNT_JSONATTR_UFSRVUID, json_object_new_string(UFSRV_SYSTEMUSER_UID));
  json_object_object_add(jobj, ACCOUNT_JSONATTR_NICKNAME, json_object_new_string("unfacd"));
  json_object_object_add(jobj, ACCOUNT_JSONATTR_UUID, json_object_new_string("00000000-0000-0000-0000-000000000000"));
  json_object_object_add(jobj, ACCOUNT_JSONATTR_USERNAME, json_object_new_string("0@unfa.cd"));

  return jobj;
}

/**
 * 	@brief This is basic profile information for a given user provided to current session holder. Profile information is
 * 	only passed if the given user has "shared" their profile with current session holder.
 * 	@param sesn_ptr Currently this represents the session that's initiated the request. This is needed to check if the profile can be shared with the initiating user.
 * 	@param ufsrvuid[in] Raw ufsrvuid for user for which profile is being assembled.  (this may replace userid_to_profile in the future)
 * 	@param userid_to_profile Sequence user id for user for which profile is being assembled.
 * 	@param jobj_out[out] Optionally, user-allocated json object to format data into
 * 	@param reload_flag load the session for the provided userid
 * 	@dynamic_memory EXPORTS json_object if 'jobj_out' is NULL
 */
struct json_object *
JsonFormatUserProfile(Session *sesn_ptr, const UfsrvUidSequenceIdPair *ufsrvuid_pair, enum DigestMode digest_mode, bool reload_flag, struct json_object *jobj_out)
{
  bool is_profile_shared = false;
  unsigned long userid_to_be_checked = SESSION_USERID(sesn_ptr);
  unsigned long userid_to_profile = ufsrvuid_pair->uid;
	Session *sesn_ptr_reloaded;
  InstanceHolderForSession *instance_sesn_ptr_reloaded = NULL;

  if (ufsrvuid_pair->uid == 0) {
    return _JsonFormatSystemUserProfile(jobj_out);
  }

	if (reload_flag)	{
    if (IS_PRESENT(ufsrvuid_pair->ufsrvuid)) {
      instance_sesn_ptr_reloaded	= SessionInstantiateFromCacheBackendWithDbFallback(NO_SESSION, ufsrvuid_pair->ufsrvuid, CALL_FLAG_SNAPSHOT_INSTANCE | CALL_FLAG_ATTACH_FENCE_LIST_TO_SESSION | CALL_FLAG_LOAD_DB_BACKEND_FOR_SESSION);
    } else {
      instance_sesn_ptr_reloaded = DbBackendGetAccountForSessionByUserId(ufsrvuid_pair->uid, &(DbOpDescriptor){0});
    }
    if (IS_PRESENT(instance_sesn_ptr_reloaded)) {
	    sesn_ptr_reloaded = SessionOffInstanceHolder(instance_sesn_ptr_reloaded);
	  } else sesn_ptr_reloaded = NULL;
	} else	sesn_ptr_reloaded	=	sesn_ptr;

	if (IS_EMPTY(sesn_ptr_reloaded))	return NULL;

	if (userid_to_profile != userid_to_be_checked) {
    CacheBackendGetShareListAndCheckUser((const ShareList *) SESSION_USERPREF_SHLIST_PROFILE_PTR(sesn_ptr), userid_to_profile, userid_to_be_checked);
		if (THREAD_CONTEXT_UFSRV_RESULT_TYPE_SUCCESS)	is_profile_shared = true;
	} else is_profile_shared = true; //showing for self

	struct	json_object	*jobj;
	if (IS_PRESENT(jobj_out))	jobj = jobj_out;
	else											jobj = json_object_new_object();

	if (is_profile_shared) {
	  if (!IS_EMPTY(SESSION_USERNICKNAME(sesn_ptr_reloaded))) json_object_object_add(jobj, ACCOUNT_JSONATTR_NICKNAME, json_object_new_string(SESSION_USERNICKNAME(sesn_ptr_reloaded)));

    if (!IS_EMPTY(SESSION_USERAVATAR(sesn_ptr_reloaded))) json_object_object_add(jobj, ACCOUNT_JSONATTR_AVATAR, json_object_new_string(SESSION_USERAVATAR(sesn_ptr_reloaded)));

    //This function can be called from ufsrvapi, so instantiating from cache backend doesn't load profile key for user.
    bool is_profile_key_decoded = IsProfileKeyLoadedAndEncode(sesn_ptr_reloaded, ^(unsigned char *profile_key_encoded) {
                                                                json_object_object_add(jobj, ACCOUNT_JSONATTR_PROFILE_KEY, json_object_new_string((char *) profile_key_encoded));
                                                              });

		if (!IS_EMPTY(SESSION_USERE164NUMBER(sesn_ptr_reloaded))) json_object_object_add(jobj, ACCOUNT_JSONATTR_E164NUMBER, json_object_new_string(SESSION_USERE164NUMBER(sesn_ptr_reloaded)));

    json_object_object_add(jobj, ACCOUNT_JSONATTR_USERNAME, json_object_new_string(SESSION_USERNAME(sesn_ptr_reloaded)));
	}

//	const char 					*home_baseloc				=	IS_STR_LOADED(SESSION_USERPREF_HOMEBASE_GEOLOC(sesn_ptr_reloaded))? SESSION_USERPREF_HOMEBASE_GEOLOC(sesn_ptr_reloaded) : "";
	char 					      uid_encoded[CONFIG_MAX_UFSRV_ID_ENCODED_SZ + 1] = {0};
//	struct	json_object	*jobj_fences_array	= JsonFormatSessionFenceList (sesn_ptr_reloaded, digest_mode);
//	struct	json_object	*jobj_invited_fences_array	= JsonFormatSessionInvitedToFenceList (sesn_ptr_reloaded, digest_mode);
//	struct	json_object *jobj_location			= JsonFormatUserLocation(sesn_ptr_reloaded, NULL);

  UfsrvUidConvertSerialise(&SESSION_UFSRVUIDSTORE(sesn_ptr_reloaded), uid_encoded);
	json_object_object_add(jobj, ACCOUNT_JSONATTR_UFSRVUID, json_object_new_string(uid_encoded));//old "userid"
  _LoadUuidForJsonFormatting(sesn_ptr_reloaded, jobj);
  json_object_object_add(jobj, ACCOUNT_JSONATTR_EID, json_object_new_int64(SESSION_EID(sesn_ptr_reloaded)));

  UFSRVResult *res_ptr = DbAccountIdentityKeyGet(ufsrvuid_pair, 0);
  if (_RESULT_TYPE_SUCCESS(res_ptr)) {
    json_object_object_add(jobj, ACCOUNT_JSONATTR_IDENTITY_KEY2, json_object_new_string(((char *)_RESULT_USERDATA(res_ptr))));
    free(_RESULT_USERDATA(res_ptr));
  }

	if (digest_mode == DIGESTMODE_CONTACTS_SHARING) {
		const char *e164number = IS_EMPTY(SESSION_USERE164NUMBER(sesn_ptr_reloaded))? "" : SESSION_USERE164NUMBER(sesn_ptr_reloaded);
		json_object_object_add(jobj, ACCOUNT_JSONATTR_E164NUMBER, json_object_new_string(e164number));

		goto return_finalise;
	}

//	json_object_object_add (jobj,"location", json_object_new_string(home_baseloc));

//	if (jobj_fences_array)
//	{
//		json_object_object_add(jobj,"fences", jobj_fences_array);
//	}
//
//	if (IS_PRESENT(jobj_invited_fences_array))
//	{
//		json_object_object_add(jobj,"fences_invited", jobj_invited_fences_array);
//	}

//	if (jobj_location)
//	{
//		json_object_object_add(jobj,"location", jobj_location);
//	}

	return_finalise:
	if (reload_flag) {
		ResetSessionData(instance_sesn_ptr_reloaded);
		SessionReturnToRecycler(instance_sesn_ptr_reloaded, NULL, 0);
	}

	return jobj;
}

json_object *
JsonValueFormatForRoamingMode(Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out, PrefsStore prefs_store)
{
  json_object	*jobj;
  if (IS_PRESENT(jobj_out))	jobj = jobj_out;
  else											jobj = json_object_new_object();

  UserPreferenceDescriptor pref = {.pref_id=preference_descriptor->pref_id, .pref_name=preference_descriptor->pref_name};

  if (SESSION_USERPREF_ONOFF_GET(sesn_ptr, roaming_mode)) {
    if (SESSION_USERPREF_ONOFF_GET(sesn_ptr, roaming_mode_wanderer)) {
      pref.value.pref_value_int = PREF_RM_WANDERER;
    } else	if (SESSION_USERPREF_ONOFF_GET(sesn_ptr, roaming_mode_conqueror)) {
      pref.value.pref_value_int = USER_PREFS__RM_CONQUERER;
    } else 	if	(SESSION_USERPREF_ONOFF_GET(sesn_ptr, roaming_mode_journaler)) {
      pref.value.pref_value_int = PREF_RM_JOURNALER;
    }

    return PreferenceIntegerJsonValueFormatter(&pref, jobj);
  } else {
    pref.value.pref_value_int=0;
    return PreferenceIntegerJsonValueFormatter(&pref, jobj);
  }

}

/**
 * @dynamic_memory SESSION_USERAVATAR(sesn_ptr) is passed by reference, hence session must be locked
 * @dynamic_memory jobj_out exported if none is provided
 * @locked sesn_ptr
 * @return formatted json object
 */
json_object *
JsonValueFormatForUserAvatar(Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out, PrefsStore prefs_store)
{
  if (!IS_STR_LOADED(SESSION_USERAVATAR(sesn_ptr))) return NULL;

  json_object	*jobj;
  if (IS_PRESENT(jobj_out))	jobj = jobj_out;
  else											jobj = json_object_new_object();

  UserPreferenceDescriptor pref = {.pref_id=preference_descriptor->pref_id, .pref_name=preference_descriptor->pref_name};
  pref.value.pref_value_str = SESSION_USERAVATAR(sesn_ptr);

	return PreferenceStringJsonValueFormatter(&pref, jobj);

}

json_object *
JsonValueFormatForE164Number(Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out, PrefsStore prefs_store)
{
  if (!IS_STR_LOADED(SESSION_USERE164NUMBER(sesn_ptr))) return NULL;

  json_object	*jobj;
  if (IS_PRESENT(jobj_out))	jobj = jobj_out;
  else											jobj = json_object_new_object();

  UserPreferenceDescriptor pref = {.pref_id=preference_descriptor->pref_id, .pref_name = preference_descriptor->pref_name};
  pref.value.pref_value_str = SESSION_USERE164NUMBER(sesn_ptr);

  return PreferenceStringJsonValueFormatter(&pref, jobj);

}

json_object *
JsonValueFormatForHomebaseGeoLoc(Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out, PrefsStore prefs_store)
{
  return JsonValueFormatForGenericString(sesn_ptr, preference_descriptor, jobj_out, PREFSTORE_MEM);

}

static UFSRVResult *_AddSharedUser(ClientContextData *ctx_ptr, ClientContextData  *userid_container);
static UFSRVResult *_AddSharedBlockedFence(ClientContextData *ctx_ptr, ClientContextData  *userid_container);

/**
 *
 * @return pre-built json array as per formatting below
 * @dynamic_memory exports json_object if not preallocated
 * @dynamic_memory deallocates imported redis result object
 */
json_object *
JsonValueFormatForSharedLists(Session *sesn_ptr, json_object *jobj_out) {
  CacheBackendGetSharedList(sesn_ptr);
  if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
    char 		      uid_encoded[CONFIG_MAX_UFSRV_ID_ENCODED_SZ+1];
    UFSRVResult   *res_ptr;
    json_object	  *jobj_array   = NULL;
    redisReply 		*redis_ptr		= (redisReply *)SESSION_RESULT_USERDATA(sesn_ptr);

    if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA)) {
			if (IS_PRESENT(jobj_out)) jobj_array = jobj_out;
			else                      jobj_array = json_object_new_array();

			for (size_t i = 0; i < redis_ptr->elements; ++i) {
			  bool    is_uid_hashed_locally = false;
				char    *list_type_str;
				UfsrvUid uid;

				if (IS_STR_LOADED((list_type_str = strchr(redis_ptr->element[i]->str, ':')))) {
					*list_type_str++ = '\0';
					unsigned long user_id = strtoul(redis_ptr->element[i]->str, NULL, 10);
					UfsrvUid *uid_ptr     = GetUfsrvUid(user_id, &uid, true, &is_uid_hashed_locally);

					if (IS_PRESENT(uid_ptr)) {
            struct json_object *jobj = json_object_new_object();
            memset (uid_encoded, 0, sizeof(uid_encoded));
            UfsrvUidConvertSerialise(uid_ptr, uid_encoded);
            json_object_object_add(jobj, ACCOUNT_JSONATTR_UFSRVUID, json_object_new_string(uid_encoded));
            res_ptr = CacheBackendGetSessionAttribute(user_id, ACCOUNT_JSONATTR_EVENTS_COUNTER);

            unsigned long eid = -1;
            if (RESULT_IS_SUCCESS_WITH_BACKEND_DATA(res_ptr)) {
              char *eid_stored = ((redisReply *)_RESULT_USERDATA(res_ptr))->str;
              if (IS_STR_LOADED(eid_stored)) eid = strtoul(eid_stored, NULL, 10);

              freeReplyObject((redisReply *)_RESULT_USERDATA(res_ptr));
            }
            json_object_object_add(jobj, ACCOUNT_JSONATTR_EID, json_object_new_int64(eid));

            json_object_object_add(jobj, ACCOUNT_JSONATTR_TYPE, json_object_new_int(atoi(list_type_str)));
            json_object_array_add(jobj_array, jobj);
          }
				}
			}

			freeReplyObject(redis_ptr);
		}

		//this may also be RESCODE_BACKEND_DATA_EMPTYSET
    return jobj_array;
  }

  //error
  return NULL;
}

json_object *
JsonValueFormatForGuardians(Session *sesn_ptr, CollectionDescriptor *collection_ptr_out)
{
  GuardianRecordDescriptor guardian_descriptor = {.guardian.uid=SESSION_USERID(sesn_ptr), .status=GUARDIAN_STATUS_LINKED};
  DbBackendGetGuardianRecords(&guardian_descriptor, collection_ptr_out);

  json_object	  *jobj_array   = NULL;
  GuardianRecordDescriptor *descriptor_ptr;
  if (collection_ptr_out->collection_sz > 0) {
    char 		      uid_encoded[CONFIG_MAX_UFSRV_ID_ENCODED_SZ+1];
    UfsrvUid      uid;
    GuardianRecordDescriptor **descriptor_list = (GuardianRecordDescriptor **)collection_ptr_out->collection;

    jobj_array = json_object_new_array();

    for (size_t i = 0; i < collection_ptr_out->collection_sz; ++i) {
      descriptor_ptr    = (GuardianRecordDescriptor *)(descriptor_list + (i * sizeof(GuardianRecordDescriptor)));
      UfsrvUid *uid_ptr = GetUfsrvUid(descriptor_ptr->originator.uid, &uid, true, NULL);

      if (IS_PRESENT(uid_ptr)) {
        struct json_object *jobj = json_object_new_object();
        memset (uid_encoded, 0, sizeof(uid_encoded));
        UfsrvUidConvertSerialise(uid_ptr, uid_encoded);
        json_object_object_add(jobj, "ufsrvuid", json_object_new_string(uid_encoded));
        json_object_object_add(jobj, "status", json_object_new_int(descriptor_ptr->status));
        json_object_array_add(jobj_array, jobj);
      }
    }

#if __VALGRIND_DRD
    VALGRIND_DESTROY_MEMPOOL(collection_ptr_out->collection);
#endif

    free (collection_ptr_out->collection);

    return jobj_array;
  }

  return NULL;
}

json_object *
JsonValueFormatForProfileShare(Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out, PrefsStore prefs_store) {
	json_object	*jobj_array;

	if (!IsShareLisInitialisedProfile(sesn_ptr)) {
    InstateShareListForUsers(sesn_ptr, SESSION_USERPREF_SHLIST_PROFILE_PTR(sesn_ptr), INIT_FLAG_TRUE);
		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
			if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET)) return NULL;//empty list
			else goto format_initialised_list;//user could be in instated list
		}

		//fallback on error
		return NULL;
	}

	format_initialised_list:
	if (IS_PRESENT(jobj_out))	jobj_array = jobj_out;
	else											jobj_array = json_object_new_array();

  hopscotch_iterator_executor_with_offset(SESSION_USERPREF_SHLIST_PROFILE_PTR(sesn_ptr).hashtable, (CallbackExecutor) _AddSharedUser, CLIENT_CTX_DATA(jobj_array));

	UserPreferenceDescriptor pref = {.pref_id=preference_descriptor->pref_id, .pref_name=preference_descriptor->pref_name};
	return PreferenceListJsonValueFormatter(&pref, jobj_array);
}

json_object *
JsonValueFormatForLocationShare(Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out, PrefsStore prefs_store) {
	json_object	*jobj_array;

	if (!IsShareLisInitialisedLocation(sesn_ptr)) {
    InstateShareListForUsers(sesn_ptr, SESSION_USERPREF_SHLIST_LOCATION_PTR(sesn_ptr), INIT_FLAG_TRUE);
		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
			if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET)) return NULL;//empty list
			else goto format_initialised_list;//user could be in instated list
		}

		//fallback on error
		return NULL;
	}

	format_initialised_list:
	if (IS_PRESENT(jobj_out))	jobj_array=jobj_out;
	else											jobj_array=json_object_new_array();

  hopscotch_iterator_executor_with_offset(SESSION_USERPREF_SHLIST_LOCATION_PTR(sesn_ptr).hashtable, (CallbackExecutor) _AddSharedUser, CLIENT_CTX_DATA(jobj_array));

	UserPreferenceDescriptor pref = {.pref_id=preference_descriptor->pref_id, .pref_name=preference_descriptor->pref_name};
	return PreferenceListJsonValueFormatter(&pref, jobj_array);
}

json_object *
JsonValueFormatForNetstateShare(Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out, PrefsStore prefs_store) {
	json_object	*jobj_array;

	if (!IsShareLisInitialisedNetstate(sesn_ptr)) {
    InstateShareListForUsers(sesn_ptr, SESSION_USERPREF_SHLIST_NETSTATE_PTR(sesn_ptr), INIT_FLAG_TRUE);
		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
			if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET)) return NULL;//empty list
			else goto format_initialised_list;//user could be in instated list
		}

		//fallback on error
		return NULL;
	}

	format_initialised_list:
	if (IS_PRESENT(jobj_out))	jobj_array=jobj_out;
	else											jobj_array=json_object_new_array();

  hopscotch_iterator_executor_with_offset(SESSION_USERPREF_SHLIST_NETSTATE_PTR(sesn_ptr).hashtable, (CallbackExecutor) _AddSharedUser, CLIENT_CTX_DATA(jobj_array));

	UserPreferenceDescriptor pref = {.pref_id=preference_descriptor->pref_id, .pref_name=preference_descriptor->pref_name};
	return PreferenceListJsonValueFormatter(&pref, jobj_array);
}

json_object *
JsonValueFormatForReadReceiptShare(Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out, PrefsStore prefs_store) {
  json_object	*jobj_array;

  if (!IsShareLisInitialisedReadReceipt(sesn_ptr)) {
    InstateShareListForUsers(sesn_ptr, SESSION_USERPREF_SHLIST_READ_RECEIPT_PTR(sesn_ptr), INIT_FLAG_TRUE);
    if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
      if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET)) return NULL;//empty list
      else goto format_initialised_list;//user could be in instated list
    }

    //fallback on error
    return NULL;
  }

  format_initialised_list:
  if (IS_PRESENT(jobj_out))	jobj_array=jobj_out;
  else											jobj_array=json_object_new_array();

  hopscotch_iterator_executor_with_offset(SESSION_USERPREF_SHLIST_READ_RECEIPT_PTR(sesn_ptr).hashtable, (CallbackExecutor) _AddSharedUser, CLIENT_CTX_DATA(jobj_array));

  UserPreferenceDescriptor pref = {.pref_id=preference_descriptor->pref_id, .pref_name=preference_descriptor->pref_name};
  return PreferenceListJsonValueFormatter(&pref, jobj_array);
}

json_object *
JsonValueFormatForBlockedShare(Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out, PrefsStore prefs_store) {
  json_object	*jobj_array;

  if (!IsShareLisInitialisedBlocked(sesn_ptr)) {
    InstateShareListForUsers(sesn_ptr, SESSION_USERPREF_SHLIST_BLOCKED_PTR(sesn_ptr), INIT_FLAG_TRUE);
    if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
      if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET)) return NULL;//empty list
      else goto format_initialised_list;//user could be in instated list
    }

    //fallback on error
    return NULL;
  }

  format_initialised_list:
  if (IS_PRESENT(jobj_out))	jobj_array = jobj_out;
  else											jobj_array = json_object_new_array();

  hopscotch_iterator_executor_with_offset(SESSION_USERPREF_SHLIST_BLOCKED_PTR(sesn_ptr).hashtable, (CallbackExecutor) _AddSharedUser, CLIENT_CTX_DATA(jobj_array));

  UserPreferenceDescriptor pref = {.pref_id=preference_descriptor->pref_id, .pref_name=preference_descriptor->pref_name};
  return PreferenceListJsonValueFormatter(&pref, jobj_array);
}

json_object *
JsonValueFormatForContactsShare(Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out, PrefsStore prefs_store) {
  json_object	*jobj_array;

  if (!IsShareLisInitialisedContacts(sesn_ptr)) {
    InstateShareListForUsers(sesn_ptr, SESSION_USERPREF_SHLIST_CONTACTS_PTR(sesn_ptr), INIT_FLAG_TRUE);
    if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
      if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET)) return NULL;//empty list
      else goto format_initialised_list;//user could be in instated list
    }

    //fallback on error
    return NULL;
  }

  format_initialised_list:
  if (IS_PRESENT(jobj_out))	jobj_array = jobj_out;
  else											jobj_array = json_object_new_array();

  hopscotch_iterator_executor_with_offset(SESSION_USERPREF_SHLIST_CONTACTS_PTR(sesn_ptr).hashtable, (CallbackExecutor) _AddSharedUser, CLIENT_CTX_DATA(jobj_array));

  UserPreferenceDescriptor pref = {.pref_id=preference_descriptor->pref_id, .pref_name=preference_descriptor->pref_name};
  return PreferenceListJsonValueFormatter(&pref, jobj_array);
}

json_object *
JsonValueFormatForBlockedFenceShare(Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out, PrefsStore prefs_store) {
  json_object	*jobj_array;

  if (!IsShareLisInitialisedBlockedFence(sesn_ptr)) {
    InstateShareListForItems(sesn_ptr, SESSION_USERPREF_SHLIST_BLOCKED_FENCE_PTR(sesn_ptr), INIT_FLAG_TRUE);
    if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
      if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET)) return NULL;//empty list
      else goto format_initialised_list;//user could be in instated list
    }

    //fallback on error
    return NULL;
  }

  format_initialised_list:
  if (IS_PRESENT(jobj_out))	jobj_array = jobj_out;
  else											jobj_array = json_object_new_array();

  hopscotch_iterator_executor(SESSION_USERPREF_SHLIST_BLOCKED_FENCE_PTR(sesn_ptr).hashtable, (CallbackExecutor)_AddSharedBlockedFence, CLIENT_CTX_DATA(jobj_array));

  UserPreferenceDescriptor pref = {.pref_id=preference_descriptor->pref_id, .pref_name=preference_descriptor->pref_name};
  return PreferenceListJsonValueFormatter(&pref, jobj_array);
}

/**
 *  Callback for adding users to formatted json array representing users on a shared list
 * @param ctx_ptr context object created by caller: json array
 * @param userid_container the payload reprsenting user session retrieved from shared list
 * @return allocate json object
 */
static UFSRVResult *
_AddSharedUser(ClientContextData *ctx_ptr, ClientContextData  *userid_container)
{
	Session *sesn_ptr 			= SessionOffInstanceHolder(userid_container);
	json_object *jobj_array = (json_object *)ctx_ptr;

	if (IS_PRESENT(sesn_ptr)) {
	  char ufsrvuid_encoded[CONFIG_MAX_UFSRV_ID_ENCODED_SZ + 1] = {0};
    UfsrvUidConvertSerialise((const UfsrvUid *) &SESSION_UFSRVUIDSTORE(sesn_ptr), ufsrvuid_encoded);
		json_object_array_add(jobj_array, json_object_new_string(ufsrvuid_encoded));
		_RETURN_RESULT_SESN(sesn_ptr, jobj_array, RESULT_TYPE_SUCCESS, RECODE_NONE)
	}

	_RETURN_RESULT_SESN(sesn_ptr, jobj_array, RESULT_TYPE_ERR, RECODE_NONE)
}

/**
 *  Callback for adding blocked fences to formatted json array representing users on a shared list
 * @param ctx_ptr context object created by caller: json array
 * @param fid_container the payload representing fid retrieved from shared list
 * @return allocate json object
 */
static UFSRVResult *
_AddSharedBlockedFence(ClientContextData *ctx_ptr, ClientContextData  *fid_container)
{
  unsigned long fid = (unsigned long)fid_container;
  json_object *jobj_array = (json_object *)ctx_ptr;

  json_object_array_add(jobj_array, json_object_new_int64(fid));

  return ProvideSuccessResult();
}