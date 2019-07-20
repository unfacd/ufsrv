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

#ifndef INCLUDE_USERS_H_
#define INCLUDE_USERS_H_

#include <list.h>
#include <instance_type.h>
#include <location_type.h>
#include <fence_type.h>
#include <json/json.h>
#include <user_type.h>
#include <session_type.h>
#include <user_preference_descriptor_type.h>
#include <SignalService.pb-c.h>
#include <ufsrvuid_type.h>
#include <command_controllers.h>

#define USER_DETAILS(x) 	(x)->user_details

#define NORMALISE_PREFNAME(x) (x + (sizeof(CONFIG_PREFERENCE_PREFIX) - 1))

UFSRVResult *FindSessionForUserLocalOrBackend (Session *, unsigned long session_id, unsigned long user_id, unsigned offline_flag);
UFSRVResult *CacheBackendsUpdateForUfsrvUid (Session *sesn_ptr_carrier, unsigned long userid, const UfsrvUid *uid_ptr);
void ResetUser (InstanceHolderForSession *, unsigned);
void ReloadCMToken (Session *sesn_ptr, const char *cm_token_provided);

void InitialiseMasterUserRegistry (void);

void RegisterUserPreferencesSource (void);
UFSRVResult *DbBackendGetUserPrefs (Session *sesn_ptr, unsigned long userid);
void ResetUserPreferences (Session *sesn_ptr);
void GenerateUserPrefsFromStorage (Session *sesn_ptr, json_object *jobj_userprefs);
void SetBooleanPrefById (Session *sesn_ptr, UserPrefsOffsets pref_offset, bool value);
UserPrefsOffsets 	GetPrefIndexByName (const char *pref_name);
PrefValueType			GetPrefValueTypeByIndex (UserPrefsOffsets pref_offset);
const UserPreferenceDescriptor *GetPrefDescriptorById (const UserPrefsOffsets pref_offset);
const char *			GetPrefNameByIndex (UserPrefsOffsets pref_offset);
int LoadDefaultUserPreferences (Session *sesn_ptr);
void *CacheBackendLoadUserPreferencesBoolean (Session *sesn_ptr);
UFSRVResult *BackendCacheStoreBooleanUserPreferences (Session *sesn_ptr);
UserPreferenceDescriptor *GetUserPreferenceByRange (Session *sesn_ptr, UserPrefsOffsets pref, UserPreferenceDescriptor *);
UserPreferenceDescriptor *GetUserPreferenceBoolean (Session *sesn_ptr, UserPrefsOffsets pref, PrefsStore pref_store, UserPreferenceDescriptor *);
UserPreferenceDescriptor *SetUserPreferenceBoolean(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in, PrefsStore, UfsrvEvent *event_ptr);
UserPreferenceDescriptor *SetUserPreferenceByDescriptor(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr, UfsrvEvent *event_ptr);
UserPreferenceDescriptor *SetUserPreferenceString(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in, PrefsStore pref_store, UfsrvEvent *event_ptr);
UserPreferenceDescriptor *GetUserPreferenceString (UfsrvUid *uid_ptr, UserPrefsOffsets pref_offset, PrefsStore pref_store, UserPreferenceDescriptor *pref_ptr_out);
UserPreferenceDescriptor *SetUserPreferenceInteger (Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in, PrefsStore pref_store, UfsrvEvent *event_ptr);
UserPreferenceDescriptor *GetUserPreferenceInteger (UfsrvUid *uid_ptr, UserPrefsOffsets pref_offset, PrefsStore pref_store, UserPreferenceDescriptor *pref_ptr_out);
UFSRVResult *CacheBackendGetUserPreferenceRecordByRange (Session *sesn_ptr, unsigned long userid, int range1, int range2);
UFSRVResult *CacheBackendSetBooleanUserPreferenceRecordByRange (Session *sesn_ptr, unsigned long userid, unsigned char *value, size_t byte_offset, size_t);
UFSRVResult *CacheBackendGetUserPreferenceRecordBoolean (Session *sesn_ptr, unsigned long userid, size_t pref_offset);

size_t GetMessageQueueSize (Session *sesn_ptr);

struct json_object *JsonFormatStateSyncForSessionState (Session *sesn_ptr,  enum SessionState session_state, struct json_object *jobj_out);
json_object *JsonFormatStateSync (Session *sesn_ptr, enum DigestMode digest_mode, bool, struct json_object *jobj_out);
json_object *JsonFormatUserProfile (Session *sesn_ptr, unsigned long userid, enum DigestMode digest_mode, bool reload_flag, struct json_object *jobj_out);
json_object *JsonValueFormatForRoamingMode (Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out);
json_object *JsonValueFormatForUserAvatar (Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out);
json_object *JsonValueFormatForE164Number (Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out);
json_object *JsonValueFormatForSharedLists(Session *sesn_ptr, json_object *jobj_out);
json_object *JsonValueFormatForProfileShare (Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out);
json_object *JsonValueFormatForLocationShare (Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out);
json_object *JsonValueFormatForNetstateShare (Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out);
json_object *JsonValueFormatForReadReceiptShare(Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out);
json_object *JsonValueFormatForContactsShare(Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out);
json_object *JsonValueFormatForBlockedShare(Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out);

UFSRVResult *IsUserAllowedToChangeUserPrefGroupRoaming(Session *sesn_ptr, UserPreference *sesn_msg_pref_ptr, DataMessage *data_msg_ptr_recieved, UfsrvEvent *event_ptr, unsigned long sesn_call_flags);
UFSRVResult *IsUserAllowedToChangeNickname (Session *sesn_ptr, const char *nickname, unsigned long call_flags, UfsrvEvent *event_ptr);
UFSRVResult *IsUserAllowedToChangeAvatar (Session *sesn_ptr, const char *avatar_id, AttachmentRecord *, unsigned long call_flags, UfsrvEvent *event_ptr);
bool IsUserOnShareListProfile (Session *sesn_ptr, Session *sesn_ptr_target) __attribute__((nonnull));
bool IsUserOnShareListNetstate (Session *sesn_ptr, Session *sesn_ptr_target) __attribute__((nonnull));
bool IsUserOnShareListLocation (Session *sesn_ptr, Session *sesn_ptr_target) __attribute__((nonnull));
bool IsUserOnShareListReadReceipt (Session *sesn_ptr, Session *sesn_ptr_target) __attribute__((nonnull));
bool IsUserOnShareListTypingIndicator (Session *sesn_ptr, Session *sesn_ptr_target) __attribute__((nonnull));
bool IsUserOnShareListBlocked (Session *sesn_ptr, Session *sesn_ptr_target) __attribute__((nonnull));
bool IsUserOnShareListContacts (Session *sesn_ptr, Session *sesn_ptr_target) __attribute__((nonnull));
UFSRVResult *IsUserAllowedToShareProfile(Session *sesn_ptr, DataMessage *data_msg_received, UfsrvEvent *event_ptr, unsigned long sesn_call_flags);
UFSRVResult *IsUserAllowedToShareNetstate(Session *sesn_ptr, DataMessage *data_msg_received, UfsrvEvent *event_ptr, unsigned long sesn_call_flags);
UFSRVResult *IsUserAllowedToShareReadReceipt (Session *sesn_ptr, DataMessage *data_msg_received, UfsrvEvent *event_ptr, unsigned long sesn_call_flags);
UFSRVResult *IsUserAllowedToShareBlocked (Session *sesn_ptr, DataMessage *data_msg_received, UfsrvEvent *event_ptr, CallbackCommandMarshaller command_marshaller, unsigned long sesn_call_flags);
UFSRVResult *IsUserAllowedToShareContacts (Session *sesn_ptr, DataMessage *data_msg_received, UfsrvEvent *event_ptr, CallbackCommandMarshaller command_marshaller, unsigned long sesn_call_flags);
UFSRVResult *IsUserAllowedToChangeUnsolicitedContactAction (Session *sesn_ptr, UserPreference *pref_ptr, DataMessage *data_msg_ptr_recieved, UfsrvEvent *event_ptr, CallbackCommandMarshaller command_marshaller, unsigned long sesn_call_flags);
unsigned long GenerateUserPrefsBooleanForStorage (Session *sesn_ptr) __attribute__((nonnull));

UserPreferenceDescriptor *SetUserPreferenceNickname(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr_in, PrefsStore, UfsrvEvent *event_ptr);
UserPreferenceDescriptor *GetUserPreferenceNickname (Session *sesn_ptr, UserPrefsOffsets pref_offset, PrefsStore pref_store, UserPreferenceDescriptor *pref_ptr_out);
UserPreferenceDescriptor *GetUserPreferenceAvatar (Session *sesn_ptr, UserPrefsOffsets pref_offset, PrefsStore pref_store, UserPreferenceDescriptor *pref_ptr_out);
UserPreferenceDescriptor *GetUserPreferenceE164Number (Session *sesn_ptr, UserPrefsOffsets pref_offset, PrefsStore pref_store, UserPreferenceDescriptor *pref_ptr_out);
enum UnsolicitedContactAction GetUserPreferenceUnsolicitedContactAction (Session *sesn_ptr, PrefsStore pref_store);

UserPreferenceDescriptor *SetUserPreferenceShareList (ClientContextData *ctx_ptr, UserPreferenceDescriptor *pref_ptr_in, PrefsStore pref_store, UserPreferenceDescriptor *pref_ptr_out);
UserPreferenceDescriptor *GetUserPreferenceShareList(Session *sesn_ptr, UserPrefsOffsets pref_offset, PrefsStore pref_store, UserPreferenceDescriptor *pref_ptr_out);

//return values
enum {
	LOCATION_STATE_UNCHANGED=1, LOCATION_STATE_CHANGED, LOCATION_STATE_INITIALISED, LOCATION_STATE_UNINITIALISED, LOCATION_STATE_ERROR
};


#endif /* INCLUDE_USERS_H_ */
