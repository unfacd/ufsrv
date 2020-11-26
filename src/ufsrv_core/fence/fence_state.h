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

#ifndef SRC_INCLUDE_FENCE_STATE_H_
#define SRC_INCLUDE_FENCE_STATE_H_

#include <recycler/instance_type.h>
#include <ufsrv_core/fence/fence_state_descriptor_type.h>
 #include <ufsrv_core/user/user_preference_descriptor_type.h>
#include <ufsrv_core/user/user_preferences_type.h>
#include <ufsrv_core/fence/fence_type.h>
#include <session_type.h>
#include <command_controllers.h>
#include <ufsrv_core/SignalService.pb-c.h>
#include <json/json.h>

typedef enum FenceUserPrefsOffsets{
	PREF_STICKY_GEOGROUP	=	0,
	PREF_PROFILE_SHARING	=	1,
	FPREF_LAST_ALIGNMENT,//to get alignment when reading from redis
} FenceUserPrefsOffsets;

//convenient type to contextually pair related Session/Fence grouping
typedef struct PairedSessionFenceState {
	FenceStateDescriptor 	*fence_state_ptr;
	Session								*session_ptr;
} PairedSessionFenceState;

//convinient type to facilitate processing of contexually related fences and their corresponding prefs
struct PairedFencePrefCollections {
	CollectionDescriptor 	*collection_fences; //or Fence OR FenceStateDescriptor
	CollectionDescriptor	*collection_prefs;
};

typedef struct  PairedFencePrefCollections  PairedFencePrefCollections;

//FENCE_USERPREFS:<%uid>:%<fid> sticky_geogroups <1|0>
//for each fence which the user is member of, user-specific prefs can be set
#define REDIS_CMD_FENCE_USERPREF_GET_ALL "HMGET FENCE_USERPREFS:%lu:%lu sticky_geogroup profile_sharing"
#define REDIS_CMD_FENCE_USERPREF_X_SET "HMSET FENCE_USERPREFS:%lu:%lu %s %d"
#define REDIS_CMD_FENCE_USERPREF_X_GET "HMGET FENCE_USERPREFS:%lu:%lu %s"

void RegisterFenceUserPreferencesSource (void);
bool IsFenceUserPreferenceSet (PairedSessionFenceState *paired_ptr, UserPrefOffset offset);
bool IsStickyGeogroupForFenceSet (Session *sesn_ptr, Fence *f_ptr);
bool IsProfileSharingForFenceSet (Session *sesn_ptr, Fence *f_ptr);
json_object *_JsonFormatFenceUserPreference (UserPreferenceDescriptor *pref_ptr);
UserPreferenceDescriptor *GetFenceUserPreferenceDescriptorByName (const char *pref_name, UserPreferenceDescriptor *pref_ptr_out);
UserPreferenceDescriptor *GetFenceUserPreferenceDescriptorById (const UserPrefsOffsets pref_offset, UserPreferenceDescriptor *pref_ptr_out);
UFSRVResult *InitialiseFenceUserPreferences (PairedSessionFenceState *paired_ptr);
UFSRVResult *CacheBackendSetFenceUserPreferenceRecord (PairedSessionFenceState *paired_ptr, unsigned long userid, unsigned long fid, UserPreferenceDescriptor *pref_ptr);
UFSRVResult *CacheBackendGetFenceUserPreferenceRecord (PairedSessionFenceState *paired_ptr, unsigned long userid, unsigned long fid, UserPreferenceDescriptor *pref_ptr);
UFSRVResult *CacheBackendGetAllFenceUserPreferencesRecord (PairedSessionFenceState *paired_ptr, unsigned long userid, unsigned long fid);
UFSRVResult *CacheBackendGetAllFenceUserPreferencesRecords (Session *, unsigned long userid, PairedFencePrefCollections *collection_pair_ptr);
json_object *CacheBackendGetFenceUserPreferenceByJson (PairedSessionFenceState *paired_ptr, unsigned long userid, unsigned long fid, UserPreferenceDescriptor *pref_ptr);
json_object *CacheBackendSetFenceUserPreferenceByJson (PairedSessionFenceState *paired_ptr, unsigned long userid, unsigned long fid, UserPreferenceDescriptor *pref_ptr);
json_object *CacheBackendGetAllFenceUserPreferencesByJson (Session *sesn_ptr, unsigned long userid);
UFSRVResult *BroadcastIntraSessionMessageFenceUserPrefs (PairedSessionFenceState *paired_ptr, CollectionDescriptor *pref_collection_ptr);
json_object *JsonFormatFenceUserPreferences (Session *sesn_ptr, const FenceStateDescriptor *fstate_ptr);
UFSRVResult *IsUserAllowedToChangeFenceUserPrefProfileSharing(InstanceContextForSession *, FenceUserPreference *sesn_msg_pref_ptr, DataMessage *data_msg_ptr_received, UfsrvEvent *event_ptr, CallbackCommandMarshaller );
UFSRVResult *IsUserAllowedToChangeFenceUserPrefStickyGeoGroup (Session *sesn_ptr, FenceUserPreference *sesn_msg_pref_ptr, DataMessage *data_msg_ptr_received, unsigned long sesn_call_flags);

inline static FenceStateDescriptor *
FenceStateDescriptorOffInstanceHolder(InstanceHolderForFenceStateDescriptor *instance_holder_ptr) {
  return (FenceStateDescriptor *)GetInstance(instance_holder_ptr);
}

#endif /* SRC_INCLUDE_FENCE_STATE_H_ */
