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

#ifndef SRC_INCLUDE_USER_PREFERENCES_H_
#define SRC_INCLUDE_USER_PREFERENCES_H_

#include <json/json.h>
#include <user_preferences_type.h>
#include <session_type.h>
#include <utils.h>
#include <ufsrvresult_type.h>
#include <UfsrvMessageQueue.pb-c.h>

void RegisterUserPreferenceSource(UserPreferences *prefs_table, enum PrefType, size_t size);
UserPreferences *GetUserPreferencesSource (enum PrefType pref_type);
UserPreferencesRegistry const *GetUserPreferencesMasterRegistry (enum PrefType pref_type);
UserPreferenceDescriptor *ValidateUserPreference (ClientContextData *ctx_ptr, UserPreferenceDescriptor *pref_ptr);
UserPreferenceDescriptor *GetUserPreference (ClientContextData *ctx_ptr,  UserPreferenceDescriptor *pref_ptr, PrefsStore pref_store);
UserPreferenceDescriptor *SetUserPreference(ClientContextData *ctx_ptr, UserPreferenceDescriptor *pref_ptr,
                                            PrefsStore pref_store, UfsrvEvent *event_ptr);
UserPreferenceDescriptor *SetLocalUserPreference (ClientContextData *ctx_ptr, UserPreferenceDescriptor 	*pref_ptr, bool flag_validate);
UserPreferenceDescriptor *GetUserPreferenceDescriptorByName  (UserPreferences *prefs_table_ptr, const char *pref_name, UserPreferenceDescriptor *pref_ptr_out);
UserPreferenceDescriptor *GetUserPreferenceDescriptorById (UserPreferences *prefs_table_ptr, const UserPrefsOffsets pref_offset, UserPreferenceDescriptor *pref_ptr_out);
UFSRVResult *InterBroadcastForSessionPreferences (Session *sesn_ptr, CollectionDescriptor *pref_collection_ptr);
UFSRVResult *IntraBroadcastForSessionPreferences (Session *sesn_ptr, CollectionDescriptor *pref_collection_ptr);
UFSRVResult *HandleIntraCommandForSessionPreference (Session *sesn_ptr, SessionMessage *sesn_msg_ptr);
void SetPrefValueByTypeFromIntraSessionMessage (UserPreference *sesn_msg_pref_ptr, UserPreferenceDescriptor *pref_ptr);
struct json_object *JsonFormatUserPreference (UserPreferenceDescriptor *pref_ptr);
json_object *PreferenceBooleanJsonValueFormatter (UserPreferenceDescriptor *pref_descriptor, json_object *jobj_out);
json_object *PreferenceIntegerJsonValueFormatter (UserPreferenceDescriptor *pref_descriptor, json_object *jobj_out);
json_object *JsonValueFormatForGenericInteger (Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out);
json_object *PreferenceStringJsonValueFormatter (UserPreferenceDescriptor *pref_descriptor, json_object *jobj_out);
json_object *PreferenceListJsonValueFormatter(UserPreferenceDescriptor *pref_descriptor, json_object *jobj_out);
json_object *JsonFormatUserPreferences (Session *sesn_ptr, enum PrefType pref_type, enum DigestMode digest_mode, json_object *jobj_out);

#endif /* SRC_INCLUDE_USER_PREFERENCES_H_ */
