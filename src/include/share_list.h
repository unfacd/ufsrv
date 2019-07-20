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

#ifndef SRC_INCLUDE_SHARE_LIST_H_
#define SRC_INCLUDE_SHARE_LIST_H_

#include <share_list_type.h>
#include <fence_state_descriptor_type.h>
#include <session_type.h>
#include <ufsrvresult_type.h>
#include <user_preference_descriptor_type.h>
#include <SignalService.pb-c.h>

typedef struct ShareListContextData {
		Session *sesn_ptr;
		InstanceHolderForSession *instance_sesn_ptr_target;
		ShareList *shlist_ptr;
		const UserPreferenceDescriptor *pref_descriptor_ptr;
		DataMessage *data_msg_received;
		bool 	lock_already_owned_sesn,
					lock_already_owned_sesn_target;
		FenceStateDescriptor			*fstate_ptr;
		bool											lock_already_owned_fence;
} ShareListContextData;

typedef bool (*ShareListCheckerCallBack) (Session *sesn_ptr, Session *sesn_ptr_target);
typedef bool (*ShareListInitialisationCheckerCallBack) (const Session *sesn_ptr);
typedef void (*ShareListInitialisationSetterCallBack) (Session *sesn_ptr, bool value);

typedef struct ShareListTypeOps {
  ShareListCheckerCallBack                presence_checker_callback;
  ShareListInitialisationCheckerCallBack  initialisation_checker_callBack;
  ShareListInitialisationSetterCallBack   initialisation_setter_callBack;
} ShareListTypeOps;


//This sharelist stores users with permission as added by this sharelist owner (sharing semantics). This's distinct from other
//share list containing users who added this user on their permission for a given sharelist type (shared semantics)
//list type enum, uid, timestamp, uid(of allowed user)
#define SHARELIST_ADD "ZADD SHL_%i:%lu %lu %lu"

//list type enum, uid, uid(of allowed user)
#define SHARELIST_REM "ZREM SHL_%i:%lu %lu"

#define SHARELIST_GETALL "ZRANGE SHL_%i:%lu 0 -1"

#define SHARELIST_SIZE "ZCARD SHL_%i:%lu"

//As per the comment above, this the shared list, which contains all users who shared their permissions with this
//users. unlike sharing this list contains all sharelist types. It is not loaded into Sessions memory.
//%uid, %uid_other, %type_enum
#define SHAREDLIST_ADD "ZADD SHDL_%lu 0 %lu:%i"
#define SHAREDLIST_REM "ZREM SHDL_%lu %lu:%i"
#define SHAREDLIST_GETALL "ZRANGE SHDL_%lu 0 -1"

ShareListCheckerCallBack GetShareListPresenceChecker (enum EnumShareListType type);
ShareListInitialisationCheckerCallBack GetShareListInitialisationChecker (enum EnumShareListType type);
ShareListInitialisationSetterCallBack GetShareListInitialisationSetter (enum EnumShareListType type);

void SetShareListTypes (Session *sesn_ptr);
HopscotchHashtable *InitialiseShareListStorage(ShareList *shlist_ptr);
void LoadShareLists (Session *sesn_ptr);
void DestructShareLists (Session *sesn_ptr);
void DestructShareListStorage(ShareList *shlist_ptr, CallbackFinaliser);
UFSRVResult *CacheBackendGetShareList (Session *sesn_ptr,  ShareList *shlist_ptr);
UFSRVResult *CacheBackendGetSharedList (Session *sesn_ptr);
UFSRVResult *CacheBackendGetShareListSize (Session *sesn_ptr, ShareList *shlist_ptr);
UFSRVResult *InstateShareList (Session *sesn_ptr, ShareList *shlist_ptr, bool);
UFSRVResult *LoadInitialiseShareListIfNecessary(Session *sesn_ptr, ShareList *shlist_ptr);
bool IsUserOnShareList (Session *sesn_ptr, ShareList *shlist_ptr);
UFSRVResult *
AddUserToShareList(Session *sesn_ptr, ShareList *shlist_ptr, InstanceHolderForSession *instance_sesn_ptr_target, unsigned long sesn_call_flags);
UFSRVResult *RemoveUserFromShareList(Session *sesn_ptr, ShareList *shlist_ptr, InstanceHolderForSession *sesn_ptr_target, unsigned long sesn_call_flags);
void InvokeShareListIteratorExecutor (Session *sesn_ptr, ShareList *shlist_ptr, CallbackExecutor executor, ClientContextData *ctx_ptr, bool is_initialise);


inline static bool IsShareLisInitialisedProfile (const Session *sesn_ptr) {return SESSION_LISTS_INIT_STATE_PROFILE(sesn_ptr);}
inline static bool IsShareLisInitialisedLocation (const Session *sesn_ptr) {return SESSION_LISTS_INIT_STATE_LOCATION(sesn_ptr);}
inline static bool IsShareLisInitialisedNetstate (const Session *sesn_ptr) {return SESSION_LISTS_INIT_STATE_NETSTATE(sesn_ptr);}
inline static bool IsShareLisInitialisedContacts (const Session *sesn_ptr) {return SESSION_LISTS_INIT_STATE_CONTACTS(sesn_ptr);}
inline static bool IsShareLisInitialisedReadReceipt(const Session *sesn_ptr) {return SESSION_LISTS_INIT_STATE_READ_RECEIPT(sesn_ptr);}
inline static bool IsShareLisInitialisedActivityState(const Session *sesn_ptr) {return SESSION_LISTS_INIT_STATE_ACTIVITY_STATE(sesn_ptr);}
inline static bool IsShareLisInitialisedBlocked (const Session *sesn_ptr) {return SESSION_LISTS_INIT_STATE_BLOCKED(sesn_ptr);}

inline static void SetShareListInitialisedProfile(Session *sesn_ptr, bool value) {SESSION_LISTS_INIT_STATE_PROFILE(sesn_ptr)=value;}
inline static void SetShareListInitialisedLocation(Session *sesn_ptr, bool value) {SESSION_LISTS_INIT_STATE_LOCATION(sesn_ptr)=value;}
inline static void SetShareListInitialisedNetstate (Session *sesn_ptr, bool value) {SESSION_LISTS_INIT_STATE_NETSTATE(sesn_ptr)=value;}
inline static void SetShareListInitialisedContacts (Session *sesn_ptr, bool value) {SESSION_LISTS_INIT_STATE_CONTACTS(sesn_ptr)=value;}
inline static void SetShareListInitialisedReadReceipt(Session *sesn_ptr, bool value) {SESSION_LISTS_INIT_STATE_READ_RECEIPT(sesn_ptr)=value;}
inline static void SetShareListInitialisedActivityState(Session *sesn_ptr, bool value) {SESSION_LISTS_INIT_STATE_ACTIVITY_STATE(sesn_ptr)=value;}
inline static void SetShareListInitialisedBlocked (Session *sesn_ptr, bool value) {SESSION_LISTS_INIT_STATE_BLOCKED(sesn_ptr)=value;}

#endif /* SRC_INCLUDE_SHARE_LIST_H_ */
