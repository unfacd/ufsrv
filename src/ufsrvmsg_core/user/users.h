/**
 * Copyright (C) 2015-2022 unfacd works
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

#ifndef INCLUDE_USERS_H_
#define INCLUDE_USERS_H_

#include <uflib/adt/adt_linkedlist.h>
#include <share_list_item_descriptor.h>
#include <uflib/recycler/instance_type.h>
#include <ufsrvmsg_core/location/location_type.h>
#include <ufsrvmsg_core/fence/fence_type.h>
#include <digest_mode_enum.h>
#include <json/json.h>
#include <ufsrvmsg_core/user/user_type.h>
#include <session_type.h>
 #include <ufsrvmsg_core/user/user_preference_descriptor_type.h>
#include <ufsrvmsg_core/SignalService.pb-c.h>
#include <uflib/ufsrvuid_type.h>
#include <command_controllers.h>

#define USER_DETAILS(x) 	(x)->user_details

#define NORMALISE_PREFNAME(x) (x + (sizeof(CONFIG_PREFERENCE_PREFIX) - 1))

UFSRVResult *FindSessionForUserLocalOrBackend(Session *, unsigned long session_id, unsigned long user_id, unsigned offline_flag);
UFSRVResult *CacheBackendsUpdateForUfsrvUid(Session *sesn_ptr_carrier, unsigned long userid, const UfsrvUid *uid_ptr);
void ResetUser(InstanceHolderForSession *, unsigned);
void ReloadCMToken(Session *sesn_ptr, const char *cm_token_provided);

void InitialiseMasterUserRegistry(void);

ClientContextData *ShareListItemExtractorCallback(ItemContainer *item_container_ptr);
ShareListItemDescriptor *const ProvideDefaultShareListItemDescriptor(void);
ShareListItemDescriptor *const ProvideDefaultShareListItemDescriptorForBlockedFence(void);

void RegisterUserPreferencesSource(void);
UFSRVResult *DbBackendGetUserPrefs(Session *sesn_ptr, unsigned long userid);
void ResetUserPreferences(Session *sesn_ptr);
void PopulateUserPrefsFromRawJson(Session *sesn_ptr, json_object *jobj_userprefs);
void SetBooleanPrefById(Session *sesn_ptr, UserPrefsOffsets pref_offset, bool value);
UserPrefsOffsets 	GetPrefIndexByName(const char *pref_name);
PrefValueType			GetPrefValueTypeByIndex(UserPrefsOffsets pref_offset);
const UserPreferenceDescriptor *GetPrefDescriptorById(const UserPrefsOffsets pref_offset);
const char *			GetPrefNameByIndex(UserPrefsOffsets pref_offset);
int LoadDefaultUserPreferences(Session *sesn_ptr);
void *CacheBackendLoadUserPreferencesBoolean(Session *sesn_ptr);
UFSRVResult *BackendCacheStoreBooleanUserPreferences(Session *sesn_ptr);
UserPreferenceDescriptor *GetUserPreferenceByRange(Session *sesn_ptr, UserPrefsOffsets pref, UserPreferenceDescriptor *);
UserPreferenceDescriptor *GetUserPreferenceBoolean(Session *sesn_ptr, UserPrefsOffsets pref, PrefsStore pref_store, UserPreferenceDescriptor *);
UserPreferenceDescriptor *SetUserPreferenceBoolean(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in, PrefsStore, UfsrvEvent *event_ptr);
UserPreferenceDescriptor *SetUserPreferenceByDescriptor(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr, UfsrvEvent *event_ptr);
UserPreferenceDescriptor *SetUserPreferenceString(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in, PrefsStore pref_store, UfsrvEvent *event_ptr);
UserPreferenceDescriptor *GetUserPreferenceString(Session *sesn_ptr, UserPrefsOffsets pref_offset, PrefsStore pref_store, UserPreferenceDescriptor *pref_ptr_out);
UserPreferenceDescriptor *SetUserPreferenceInteger(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in, PrefsStore pref_store, UfsrvEvent *event_ptr);
UserPreferenceDescriptor *GetUserPreferenceInteger(Session *sesn_ptr, UserPrefsOffsets pref_offset, PrefsStore pref_store, UserPreferenceDescriptor *pref_ptr_out);
UFSRVResult *CacheBackendGetUserPreferenceRecordByRange(unsigned long userid, int range1, int range2);
UFSRVResult *CacheBackendSetBooleanUserPreferenceRecordByRange(Session *sesn_ptr, unsigned long userid, unsigned char *value, size_t byte_offset, size_t);
UFSRVResult *CacheBackendGetUserPreferenceRecordBoolean(Session *sesn_ptr, unsigned long userid, size_t pref_offset);

size_t GetMessageQueueSize(Session *sesn_ptr);
bool IsProfileKeyLoaded(const Session *sesn_ptr);
bool IsProfileKeyLoadedAndEncode(Session *sesn_ptr_reloaded, void(^on_encoded)(unsigned  char *));
unsigned char *GetEmptyProfile();

struct json_object *JsonFormatStateSyncForSessionState(Session *sesn_ptr,  enum SessionState session_state, struct json_object *jobj_out);
json_object *JsonFormatStateSync(Session *sesn_ptr, enum DigestMode digest_mode, bool, struct json_object *jobj_out);
json_object *JsonFormatUserProfile(Session *sesn_ptr, const UfsrvUidSequenceIdPair *ufsrvuid_pair, enum DigestMode digest_mode, bool reload_flag, struct json_object *jobj_out);
json_object *JsonValueFormatForRoamingMode(Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out, PrefsStore prefs_store);
json_object *
JsonValueFormatForUserAvatar(Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out, PrefsStore prefs_store);
json_object *JsonValueFormatForE164Number(Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out, PrefsStore prefs_store);
json_object *JsonValueFormatForHomebaseGeoLoc(Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out, PrefsStore prefs_store);
json_object *JsonValueFormatForSharedLists(Session *sesn_ptr, json_object *jobj_out);
json_object *JsonValueFormatForGuardians(Session *sesn_ptr, CollectionDescriptor *collection_ptr_out);
json_object *JsonValueFormatForProfileShare(Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out, PrefsStore prefs_store);
json_object *JsonValueFormatForLocationShare(Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out, PrefsStore prefs_store);
json_object *JsonValueFormatForNetstateShare(Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out, PrefsStore prefs_store);
json_object *JsonValueFormatForReadReceiptShare(Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out, PrefsStore prefs_store);
json_object *JsonValueFormatForContactsShare(Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out, PrefsStore prefs_store);
json_object *JsonValueFormatForBlockedShare(Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out, PrefsStore prefs_store);
json_object *JsonValueFormatForBlockedFenceShare(Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out, PrefsStore prefs_store);

UFSRVResult *IsUserAllowedToChangeUserPrefInteger(InstanceContextForSession *ctx_ptr, int prefid_provided, int64_t value_provided, unsigned long sesn_call_flags, UfsrvEvent *event_ptr);
UFSRVResult *IsUserAllowedToChangeUserPrefString(InstanceContextForSession *ctx_ptr, int prefid_provided, char *value_provided, unsigned long sesn_call_flags, UfsrvEvent *event_ptr);
UFSRVResult *IsUserAllowedToChangeUserPrefGroupRoaming(InstanceContextForSession *ctx_ptr, UserPreference *sesn_msg_pref_ptr, WebSocketMessage *, DataMessage *data_msg_ptr_received, UfsrvEvent *event_ptr, unsigned long sesn_call_flags);
UFSRVResult *IsUserAllowedToChangeNickname(InstanceContextForSession *, const char *nickname, unsigned long call_flags, UfsrvEvent *event_ptr);
UFSRVResult *IsUserAllowedToDeleteNickname(InstanceContextForSession *, const char *nickname, unsigned long call_flags, UfsrvEvent *event_ptr);
UFSRVResult *IsUserAllowedToChangeAvatar(InstanceContextForSession *ctx_ptr, const char *avatar_id, AttachmentRecord *, unsigned long call_flags, UfsrvEvent *event_ptr);
bool IsUserOnShareListProfile(Session *sesn_ptr, Session *sesn_ptr_target) __attribute__((nonnull));
bool IsUserOnShareListNetstate(Session *sesn_ptr, Session *sesn_ptr_target) __attribute__((nonnull));
bool IsUserOnShareListLocation(Session *sesn_ptr, Session *sesn_ptr_target) __attribute__((nonnull));
bool IsUserOnShareListReadReceipt(Session *sesn_ptr, Session *sesn_ptr_target) __attribute__((nonnull));
bool IsUserOnShareListTypingIndicator(Session *sesn_ptr, Session *sesn_ptr_target) __attribute__((nonnull));
bool IsUserOnShareListBlocked(Session *sesn_ptr, Session *sesn_ptr_target) __attribute__((nonnull));
bool IsUserOnShareListContacts(Session *sesn_ptr, Session *sesn_ptr_target) __attribute__((nonnull));
bool IsFenceOnShareListBlockedFence(Session *sesn_ptr, uint64_t fid) __attribute__((nonnull));;
bool IsUserOnShareList(Session *sesn_ptr_target, size_t uid_source, EnumShareListType shlist_type, unsigned long call_flags);
UFSRVResult *IsUserAllowedToShareProfile(InstanceContextForSession *ctx_ptr, WebSocketMessage *, DataMessage *data_msg_received, UfsrvEvent *event_ptr, unsigned long sesn_call_flags);
UFSRVResult *IsUserAllowedToShareNetstate(InstanceContextForSession *ctx_ptr, WebSocketMessage *, DataMessage *data_msg_received, UfsrvEvent *event_ptr, unsigned long sesn_call_flags);
UFSRVResult *IsUserAllowedToShareReadReceipt(InstanceContextForSession *ctx_ptr, DataMessage *data_msg_received, UfsrvEvent *event_ptr, unsigned long sesn_call_flags);
UFSRVResult *IsUserAllowedToShareBlocked(InstanceContextForSession *ctx_ptr, DataMessage *data_msg_received, WebSocketMessage *wsm_ptr_received, UfsrvEvent *event_ptr, CallbackCommandMarshaller command_marshaller, unsigned long sesn_call_flags);
UFSRVResult *IsUserAllowedToShareBlockedFence(InstanceContextForSession *ctx_ptr, DataMessage *data_msg_received, WebSocketMessage *wsm_ptr_received, UfsrvEvent *event_ptr, CallbackCommandMarshaller command_marshaller, unsigned long sesn_call_flags);
UFSRVResult *IsUserAllowedToShareContacts(InstanceContextForSession *ctx_ptr, DataMessage *data_msg_received, WebSocketMessage *, UfsrvEvent *event_ptr, CallbackCommandMarshaller command_marshaller, unsigned long sesn_call_flags);
UFSRVResult *IsUserAllowedToChangeUnsolicitedContactAction(InstanceContextForSession *ctx_ptr, UserPreference *pref_ptr, DataMessage *data_msg_ptr_received, WebSocketMessage *wsm_ptr_received, UfsrvEvent *event_ptr, CallbackCommandMarshaller command_marshaller, unsigned long sesn_call_flags);
unsigned long GenerateUserPrefsBooleanForStorage(Session *sesn_ptr) __attribute__((nonnull));
void GenerateUserPrefsBooleanFromStorage(Session *sesn_ptr, unsigned long stored_value);
UserPreferenceDescriptor *SetUserPreferenceNickname(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in, PrefsStore, UfsrvEvent *event_ptr);
UserPreferenceDescriptor *GetUserPreferenceNickname(Session *sesn_ptr, UserPrefsOffsets pref_offset, PrefsStore pref_store, UserPreferenceDescriptor *pref_ptr_out, char *name_override);
UserPreferenceDescriptor *GetUserPreferenceAvatar(Session *sesn_ptr, UserPrefsOffsets pref_offset, PrefsStore pref_store, UserPreferenceDescriptor *pref_ptr_out);
UserPreferenceDescriptor *GetUserPreferenceE164Number(Session *sesn_ptr, UserPrefsOffsets pref_offset, PrefsStore pref_store, UserPreferenceDescriptor *pref_ptr_out);
enum UnsolicitedContactAction GetUserPreferenceUnsolicitedContactAction(Session *sesn_ptr, PrefsStore pref_store);
unsigned long GetGuardianUId(Session *sesn_ptr, PrefsStore pref_store);
UFSRVResult *SetGuardianFor(Session *sesn_ptr, unsigned long for_uid, PrefsStore pref_store);
InstanceContextForSession *GetGuardianSession(Session *, PrefsStore pref_store, bool is_locked, InstanceContextForSession *instance_sesn_ptr_out);
enum GeoLocRoamingTrigger GetUserPrefGeolocRoamingTrigger(Session *sesn_ptr);
enum BaseLocAnchorZones GetUserPrefBaselocAnchorZone(Session *sesn_ptr);
bool IsUserBaseLocSelfZoned(Session * _Nonnull sesn_ptr);

UserPreferenceDescriptor *SetUserPreferenceShareList(ClientContextData *ctx_ptr, UserPreferenceDescriptor *pref_ptr_in, PrefsStore pref_store, UserPreferenceDescriptor *pref_ptr_out);
UserPreferenceDescriptor *GetUserPreferenceShareList(Session *sesn_ptr, UserPrefsOffsets pref_offset, PrefsStore pref_store, UserPreferenceDescriptor *pref_ptr_out);

UFSRVResult *GetSessionFromUserHandle(Session *sesn_ptr_carrier, const char *handle, bool *lock_already_owned, unsigned long callflags);

//return values
enum {
	LOCATION_STATE_UNCHANGED=1, LOCATION_STATE_CHANGED, LOCATION_STATE_INITIALISED, LOCATION_STATE_UNINITIALISED, LOCATION_STATE_ERROR
};


#endif /* INCLUDE_USERS_H_ */
