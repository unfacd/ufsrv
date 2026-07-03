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

#ifndef FENCE_H
# define FENCE_H

#include <thread_context_type.h>
#include <ufsrvmsg_core/fence/fence_context_descriptor_type.h>
#include <ufsrvmsg_core/fence/fence_enums_type.h>
#include <ufsrvmsg_core/fence/pair_of_userid_user_name_type.h>
#include <ufsrvmsg_core/fence/fencelist_type_descriptor_type.h>
#include <ufsrv_core/cache_backend/persistance_type.h>
#include <uflib/recycler/instance_type.h>
#include <digest_mode_enum.h>
#include <misc.h>
#include <uflib/utils.h>
#include <ufsrvmsg_core/fence/fence_type.h>
#include <uflib/adt/adt_linkedlist.h>
#include <session_type.h>
#include <uflib/adt/adt_queue.h>
#include <ufsrvmsg_core/location/location_type.h>
#include <ufsrvmsg_core/user/users.h>
#include <json/json.h>
#include <ufsrvwebsock/include/protocol_websocket.h>//WireProtocolData
#include <ufsrvmsg_core/SignalService.pb-c.h>//proto
#include <message_type.h>
#include <ufsrvresult_type.h>
#include <ufsrvmsg_core/fence/fence_state_descriptor_type.h>
#include <sessions_delegator_type.h>
#include <uflib/scheduled_jobs/scheduled_jobs_type.h>
#include <zkgroup_utils/zkgroup_masterkey_type.h>

typedef struct PairOfFenceIdFenceCname {
	unsigned long 	fid;
	char *			fcname;
} PairOfFenceIdFenceCname;

typedef struct ListPreProcessor {
  uintptr_t target;
  struct {
    bool (*matcher)(uintptr_t src, uintptr_t target);
    bool (*on_matched)();

  } callbacks;
} ListPreProcessor;

#define FENCE_CALLFLAG_EMPTY											0
#define FENCE_CALLFLAG_GENERATE_ID								(0x1U << 1U)
#define FENCE_CALLFLAG_LOCK_FENCE									(0x1U << 2U)
#define FENCE_CALLFLAG_KEEP_FENCE_LOCKED					(0x1U << 3U)//instructs the current lock owner to leave it locked
#define FENCE_CALLFLAG_UNLOCK_FENCE								(0x1U << 4U)
#define FENCE_CALLFLAG_SELF_DESTRUCT							(0x1U << 5U)
#define FENCE_CALLFLAG_BASEFENCE									(0x1U << 6U)//aka geofence
#define FENCE_CALLFLAG_USERFENCE									(0x1U << 7U)
#define FENCE_CALLFLAG_JOIN												(0x1U << 8U)
#define	FENCE_CALLFLAG_JOIN_LINKJOIN      		    (0x1U << 30U)
#define FENCE_CALLFLAG_SEARCH_BACKEND							(0x1U << 9U)
#define FENCE_CALLFLAG_HASH_FENCE_LOCALLY					(0x1U << 10U)
#define FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE	(0x1U << 11U)
#define	FENCE_CALLFLAG_INCLUDE_REMOTE_SESSIONS		(0x1U << 12U)
#define	FENCE_CALLFLAG_ROAMING_GEOFENCE						(0x1U << 13U)//geofence related operation
#define	FENCE_CALLFLAG_SNAPSHOT_INSTANCE					(0x1U << 14U)//unmanaged,pure data representtaion
#define	FENCE_CALLFLAG_CHECK_FENCEOWNERSHIP				(0x1U << 15U)//is user owner of fence
#define	FENCE_CALLFLAG_FENCE_LIST_WITH_SCORES			(0x1U << 16U)//raw fences list contains score information, nut just serial list of fences
#define	FENCE_CALLFLAG_TRANSFER_INVITE_CONTEXT		(0x1U << 17U)//transfer relevant invite spepcif info from a given fence stored in in invite list
#define	FENCE_CALLFLAG_MARSHAL_COMMAND_ERROR			(0x1U << 18U)//marshal error to user
#define FENCE_CALLFLAG_WRITEBACK_DATA_TO_BACKEND	(0x1U << 19U)
#define FENCE_CALLFLAG_ABORT_RECORD_IF_USER_NOT_MEMBER	(0x1U << 20U)
#define FENCE_CALLFLAG_EVICT_FROM_CACHEBACKEND		(0x1U << 21U)//deleter cachebackend record
#define FENCE_CALLFLAG_WRITEBACK_TO_DBBACKEND			(0x1U << 22U)
#define FENCE_CALLFLAG_LOCK_FENCE_BLOCKING				(0x1U << 23U) //using blocking mode as opposed tro try-mode
#define	FENCE_CALLFLAG_CHECK_PERM_PRESENTATION		(0x1U << 24U)//presentation membership
#define	FENCE_CALLFLAG_CHECK_PERM_MEMBERSHIP		  (0x1U << 25U)
#define	FENCE_CALLFLAG_CHECK_PERM_MESSAGING		    (0x1U << 246)
#define	FENCE_CALLFLAG_CHECK_PERM_ATTACHING		    (0x1U << 27U)
#define	FENCE_CALLFLAG_CHECK_PERM_CALLING   		  (0x1U << 28U)
#define	FENCE_CALLFLAG_CHECK_PERMESSIONS  		    (0x1U << 29U)//indicates some fence permissions are to be checked
//next      		    (0x1U << 31U)


#define FENCECMND_JOIN		"JOIN"
#define FENCECMND_LEAVE		"LEAVE"
#define FENCECMND_UPDATE	"UPDATE"

//IMPORTANT ordinal order should match the positional order in the command REDIS_CMD_FENCE_RECORD_GET_ALL below
enum {
	REDIS_KEY_FENCE_ID=0,REDIS_KEY_FENCE_TYPE, REDIS_KEY_FENCE_WHEN_CREATED, REDIS_KEY_FENCE_USERID, REDIS_KEY_FENCE_BASELOC,
	REDIS_KEY_FENCE_CNAME, REDIS_KEY_FENCE_DNAME, REDIS_KEY_FENCE_BNAME, REDIS_KEY_FENCE_LONG, REDIS_KEY_FENCE_LAT,
	REDIS_KEY_MAXUSERS, REDIS_KEY_TTL, REDIS_KEY_EVENT_COUNTER, REDIS_KEY_FENCE_AVATAR, REDIS_KEY_FENCE_MSGEXPIRY,
	REDIS_KEY_LIST_SEMANTICS, REDIS_KEY_FENCE_KEY,

	_REDIS_KEY_FENCE_SETSIZE
};


/**
 * Fence attributes loaded int \ref Fence.attrs
 */
//privacy mode
#define F_ATTR_PRIVATE					(0x1U<<1U) //
#define F_ATTR_PUBLIC						(0x1U<<6U)//defalt if not set

//delivery modes
#define F_ATTR_BROADCAST				(0x1U<<5U)
#define F_ATTR_BROADCAST_ONEWAY	(0x1U<<8U)
#define F_ATTR_MANY_TO_MANY			(0x1U<<13U) //default if not set

//fence type
#define F_ATTR_BASEFENCE				(0x1U<<4U) //also known as GEO
#define F_ATTR_USERFENCE				(0x1U<<7U)//normal channel style

#define F_ATTR_GUARDIANFENCE		(0x1<<2)

//visibility modes
#define F_ATTR_VISIBLE					(0x1U<<3U) //default if not set
#define F_ATTR_HIDDEN						(0x1U<<14U)

#define F_ATTR_SESSNLIST_LAZY		(0x1U<<9U)//A fence has been instantiated from backend without its full session list so it is being being on demand
#define F_ATTR_DIRTY						(0x1U<<10U)//A fence has been updated by another server instance and has not been reloaded locally
#define F_ATTR_STICKY						(0x1U<<11U)
#define F_ATTR_SNAPSHOT					(0x1U<<12U)

//join mode
#define F_ATTR_JOINMODE_INVITE_ONLY			(0x1U<<15U)
#define F_ATTR_JOINMODE_OPEN						(0x1U<<16U)	//default
#define F_ATTR_JOINMODE_KEY							(0x1U<<17U)
#define F_ATTR_TIMED						        (0x1U<<18U)
//19

#define F_ATTR_IS_SET(x, y)		(x&y)
#define F_ATTR_SET(x,y)				(x|=(y))
#define F_ATTR_UNSET(x,y)			(x&=~(y))

UFSRVResult *FenceEventsLockRDCtx(ThreadContext *thread_ctx_ptr, Fence *f_ptr, int try_flag, UFSRVResult *res_ptr, const char *);
UFSRVResult *FenceEventsLockRWCtx(ThreadContext *thread_ctx_ptr, Fence *f_ptr, int try_flag, UFSRVResult *res_ptr, const char *func);
UFSRVResult *FenceEventsUnLockCtx(ThreadContext *thread_ctx_ptr, Fence *f_ptr, UFSRVResult *res_ptr);

UFSRVResult *RepairFenceMembershipForUser(InstanceHolderForSession *instance_sesn_ptr, InstanceHolderForFence *instance_f_ptr, EnumImpairedFenceMembershipType impairment_type);
bool IsFenceIdInCacheRecordForUser(unsigned long uid, unsigned long fid, unsigned long *uid_inviter);
bool IsUserIdInCacheRecordForFence(Session *sesn_ptr,  unsigned long fid);

UFSRVResult *IsUserAllowedToChangeFence(Session *sesn_ptr, unsigned long fid, const char *cname, bool *fence_lock_state, unsigned long fence_call_flags);
UFSRVResult *IsUserAllowedToRejectFence(Session *sesn_ptr, unsigned long fid, const char *cname, bool *fence_lock_state, unsigned long fence_call_flags);
UFSRVResult *IsUserAllowedToRemoveInvitedUser(Session *sesn_ptr, unsigned long fid, InstanceContextForFence *, ContextData *ctx_data, unsigned long fence_call_flags);
UFSRVResult *IsUserAllowedToChangeFenceName(Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, const char *fname_new, unsigned long fence_call_flags, FenceEvent *fence_event_ptr_out);
UFSRVResult *IsUserAllowedToChangeFenceDescription(Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, const char *description_new, unsigned long fence_call_flags, FenceEvent *fence_event_ptr_out);
void UpdateFenceAssignments(Session *sesn_ptr, Fence *f_ptr_processed, ClientContextData *context_ptr);
UFSRVResult *UpdateFenceAvatarAssignment(Session *sesn_ptr, Fence *f_ptr, AttachmentRecord *record_ptr, unsigned long fence_call_flags);
bool UpdateFenceNameAssignment(Session *, InstanceHolderForFence *instance_f_ptr, const char *fname_new, char *cname_new, bool flag_build_cname, unsigned long);
bool UpdateFenceDescriptionAssignment(Session *sesn_ptr, InstanceHolderForFence *instance_f_ptr, const char *description_new, unsigned long fence_call_flags);
UFSRVResult *UpdateFenceKeyAssignment(Fence *f_ptr, ZKGroupMasterKey *group_key, unsigned long fence_call_flags);
UFSRVResult *UpdateFenceTypeAssignment(Session *sesn_ptr, Fence *f_ptr, FenceRecord__FenceType fence_type, unsigned long fence_call_flags);
UFSRVResult *UpdateFenceMaxUsersAssignment(Session *sesn_ptr, Fence *f_ptr, int maxusers, unsigned long fence_call_flags);
UFSRVResult *UpdateFencePrivacyModeAssignment(Session *sesn_ptr, Fence *f_ptr, FenceRecord__PrivacyMode privacy_mode, unsigned long fence_call_flags);
UFSRVResult *UpdateFenceDeliveryModeAssignment(Session *sesn_ptr, Fence *f_ptr, FenceRecord__DeliveryMode delivery_mode, unsigned long fence_call_flags);
UFSRVResult *IsUserAllowedToChangeFenceAvatar(Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, DataMessage *data_msg_ptr, unsigned long fence_call_flags, FenceEvent *fence_event_ptr_out);
UFSRVResult *IsUserAllowedToChangeFenceMessageExpiry(Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, time_t msg_expiry_in_seconds, unsigned long fence_call_flags, FenceEvent *fence_event_ptr_out);
UFSRVResult *UpdateFenceJoinModeAssignment(Session *sesn_ptr, Fence *f_ptr, FenceRecord__JoinMode join_mode, unsigned long fence_call_flags);
UFSRVResult  *CacheBackendUpdateFenceKey(Fence *f_ptr, ZKGroupMasterKey *fence_key);
const unsigned char *ProvideEmptyFenceKey();
bool IsFenceKeyEmpty(const unsigned char *fence_key);
ZKGroupMasterKey *EncodeFenceKey(const unsigned char *fence_key, ZKGroupMasterKey *buffer_provided);

char *MakeCanonicalFenceName(Session *sesn_ptr, const char *fdname, unsigned  flag_selfzoned, char *);
LocationDescription *MapFenceLocationDescription(const Fence *f_ptr, char *canonical_name_buffer, LocationDescription *location_ptr_out);
size_t SizeofCanonicalFenceName(Session *sesn_ptr, const char *fdname);
UFSRVResult *IsUserAllowedToJoinGeoFence(InstanceHolderForSession *, LocationDescription *);
UFSRVResult *
IsUserAllowedGeoFenceInvite(InstanceHolderForSession *instance_sesn_ptr, LocationDescription *location_description_ptr,
                            Session *sesn_ptr_inviter, unsigned long fence_call_flags);
void InitialiseMaserFenceRegistries(void);
void SummariseUserFenceConfiguration(void);
void SummariseBaseFenceConfiguration(void);
UFSRVResult *
IsUserAllowedToJoinFenceById(InstanceHolderForSession *, const unsigned long, const char *linkjoin_nonce, unsigned long,
                             bool *fence_lock_state);
UFSRVResult *HandleJoinFence(InstanceContextForSession *, InstanceHolderForFenceStateDescriptor *, WebSocketMessage *, DataMessage *data_msg_ptr, EnumFenceJoinType join_type, UFSRVResult *res_ptr);
UFSRVResult *IsUserAllowedToJoinFenceByCanonicalName(InstanceHolderForSession *, const char *, unsigned long);

UFSRVResult *IsUserAllowedToChangeFenceMaxMembers(Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, int32_t maxmembers, unsigned long fence_call_flags, FenceEvent *fence_event_ptr_out);
UFSRVResult *IsUserAllowedToChangeFenceDeliveryMode(Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, int delivery_mode, unsigned long fence_call_flags, FenceEvent *fence_event_ptr_out);

struct json_object *JsonFormatSessionFenceList(Session *, enum DigestMode);
struct json_object *JsonFormatSessionInvitedToFenceList(Session *sesn_ptr, enum DigestMode digest_mode);
struct json_object *JsonFormatSessionLinkJoinRequestedFenceList(Session *sesn_ptr, enum DigestMode digest_mode);
struct json_object *JsonFormatFenceForDbBackend(Session *sesn_ptr_carrier, Fence *f_ptr, enum DigestMode digest_mode, unsigned long fence_call_flags);

void DestructFenceRawSessionList(FenceRawSessionList *raw_sesn_list_ptr, bool self_destruct);
InstanceHolderForSession *GetSessionForFenceOwnerNonBlocking(Session *sesn_ptr, unsigned long fence_owner_userid);
InstanceHolderForSession *GetSessionForFenceOwner(Session *sesn_ptr, unsigned long fence_owner_userid, bool *lock_state);
FenceRawSessionList *GetRawMemberUsersListForFence(Session *sesn_ptr, InstanceHolderForFence *instance_f_ptr, unsigned long fence_call_flags, FenceRawSessionList *raw_sesn_list_ptr_in);
FenceRawSessionList *GetRawInvitedUsersListForFence(Session *sesn_ptr, InstanceContextForFence *instance_fence_ctx, unsigned long fence_call_flags, FenceRawSessionList *raw_sesn_list_ptr_in);

int FenceRemoveUserByFenceId(Session *sesn_ptr_this, Session *sesn_ptr, unsigned long fence_id);
unsigned RemoveUserFromAllFences(InstanceHolderForSession *, unsigned long);
unsigned RemoveUserFromAllFencesSessionInstanceOnly(Session *sesn_ptr, unsigned long call_flags);
int RemoveUserFromInvitedList(InstanceHolderForSession *instance_sesn_ptr, FenceStateDescriptor *fence_state_joined, FenceEvent *fe_ptr_out, unsigned long fence_call_flags);
size_t NetworkRemoveUsersFromInviteList(InstanceContextForSession *ctx_ptr_carrier, InstanceHolderForFence *);
unsigned long RemoveUserFromMembersListForFence(InstanceHolderForSession *instance_sesn_ptr_target, Fence *f_ptr_in, unsigned long call_flags);
InstanceHolderForFenceStateDescriptor *RemoveFenceFromSessionFenceList(List *, Fence *);
InstanceHolderForFenceStateDescriptor *RemoveFenceFromSessionInvitedFenceList(List *, unsigned long);
int RemoveUserFromLinkJoinedList(InstanceHolderForSession *sesn_ptr_instance, InstanceHolderForFence *f_ptr_instance, unsigned long fence_call_flags);

UFSRVResult *FindFenceByCanonicalName(Session *sesn_ptr_this, const char *fence_canonical_name, bool *, unsigned long call_flags);
InstanceHolder *FindBaseFenceByCanonicalName(Session *, const char *, bool *fence_already_locked, unsigned long);
InstanceHolderForFence *FindUserFenceByCanonicalName(Session *sesn_ptr_this, const char *fence_canonical_name, bool *fence_already_locked, unsigned long call_flags);
InstanceHolderForFenceStateDescriptor *FindFenceStateInSessionFenceListByFenceId(Session *sesn_ptr, List *sesn_fence_ist_ptr, unsigned long fence_id);
UFSRVResult *FindFenceById(Session *, const unsigned long fence_id, unsigned long fence_call_flags);
InstanceHolderForSession * FindUserInFenceSessionListByID(const List *const lst_ptr_sesn, Fence *f_ptr, unsigned long cid);
size_t FenceListIterator(const List *const lst_ptr, void(^on_list_item)(ClientContextData *));
InstanceHolderForFenceStateDescriptor *IsUserMemberOfFenceByFenceId(const List *const lst_ptr_sesn, const unsigned long fence_id, bool lock_flag);
InstanceHolderForFenceStateDescriptor *IsUserMemberOfThisFence(const List *const lst_ptr, Fence *f_ptr, bool lock_flag);
Fence *IsUserMemberOfFenceByCanonicalName(const List *const lst_ptr, const char *fence_canonical_name);
int CrossCheckSessionInFenceBySessionId(Fence *f_ptr, unsigned long session_id);
bool IsUserOnFenceInvitedList(Fence *f_ptr, unsigned long uid);
bool IsUserOnFenceLinkJoinList(Fence *f_ptr, unsigned long uid);
bool IsUserOnFenceBannedList(Fence *f_ptr, unsigned long uid);
int CrossCheckFenceInSessionByFenceId(Session *sesn_ptr, unsigned long fence_id);
InstanceHolderForFenceStateDescriptor *CreateUserFenceAndLinkToUser(InstanceHolderForSession *instance_sesn_ptr, const char *fence_banner, char *userfence_canonical_name_in, FenceContextDescriptor *, unsigned long call_flags);
InstanceHolderForFenceStateDescriptor *AddUserToThisFenceListWithLinkback(InstanceHolderForSession *instance_sesn_ptr, InstanceHolderForFence *, List *user_fence_list_ptr, List *fence_user_list_ptr,  int event_type, unsigned call_flags);
CollectionDescriptor *AddToFenceInvitedListFromProtoRecord(InstanceHolderForSession *instance_sesn_ptr, InstanceHolderForFence *instance_f_ptr, UserRecord **user_records, size_t invited_members_sz, CollectionDescriptorPair *, bool flag_exclude_self);
UFSRVResult *AddMemberToInvitedFenceList(InstanceHolderForSession *instance_sesn_ptr_invited, InstanceHolderForFence *instance_f_ptr, Session *sesn_ptr_inviter, unsigned long);
UFSRVResult *IsUserAllowedToMakeUserFence(InstanceHolderForSession *instance_sesn_ptr, const char *fence_banner, const char *baseloc_prefix, FenceContextDescriptor *, bool *fence_lock_already_owned, unsigned long call_flags);
FenceEvent *UpdateBackendFenceInvitedData(Session *sesn_ptr_inviter, Session *sesn_ptr_invited, FenceStateDescriptor *fstate_ptr, unsigned event_type, FenceEvent *fe_ptr_out);

int InstateFenceListsForUser(InstanceHolderForSession *instance_sesn_ptr, unsigned long sesn_call_flags, FenceTypes fence_type, bool flag_abort_on_failure);

void DestructFenceCollection(CollectionDescriptor *fence_collection_ptr, bool flag_self_destruct);
CollectionDescriptor *GetFenceCollectionForUser(Session *sesn_ptr, CollectionDescriptor *, CollectionDescriptor *overflow_collection_ptr_in, EnumFenceCollectionType);

//events
FenceEvent *RegisterFenceEvent(Fence *f_ptr, unsigned event_type,  void *event_payload, unsigned lock_flag,  FenceEvent *fe_ptr_out);
FenceEvent *RegisterFenceEventWithFid(unsigned long fence_id, unsigned event_type,  void *event_payload, FenceEvent *fe_ptr_out);
unsigned long GetFenceEventId(Fence *f_ptr, unsigned lock_flag);
int DestructFenceEvent(FenceEvent *fe_ptr, bool self_destruct);
void *DestructFenceEventQueue(Session *sessn_ptr, Fence *f_ptr, unsigned reset_counter_flag);

UFSRVResult *DbBackendInsertUfsrvEvent(UfsrvEvent *event_ptr);
int DbBackendUpdateEventFlagger(unsigned long event_rowid, unsigned  long uid_flagged_by, time_t timestamp);
int DbBackendUpdateEventStatus(unsigned long event_rowid, enum EventStatus event_status);
unsigned long IsEventValid(unsigned long, unsigned long, EnumEventCommandType);

FenceEvent *UpdateBackendFenceData(Session *sesn_ptr_target, Fence *f_ptr, void *user_data, unsigned event_type, FenceEvent *);

UFSRVResult *CacheBackendGetFencesListSizeForUser(unsigned long userid);
UFSRVResult *CacheBackendGetFenceMembersListSize(unsigned long fid, EnumFenceCollectionType type);
UFSRVResult *CacheBackendGetInvitedToFencesListSizeForUser(Session *sesn_ptr, unsigned long uid);
UFSRVResult *InstateInvitedMembersListCacheRecordForFence(Session *sesn_ptr, InstanceHolderForFence *instance_f_ptr, unsigned long userid_loaded_for, EnumFenceCollectionType list_type_target, EnumFenceCollectionType list_type_context, unsigned long fence_call_flags);
UFSRVResult *InstateMembersListCacheRecordForFence(Session *sesn_ptr_target, InstanceHolderForFence *instance_f_ptr, unsigned long userid_loaded_for, EnumFenceCollectionType list_type_target, EnumFenceCollectionType list_type_context, unsigned long fence_call_flags);
UFSRVResult *CacheBackendLoadUserIdsForFence(unsigned long);
UFSRVResult *CacheBackendSetFenceAttributesByCollection(Session *sesn_ptr, unsigned long fence_id, CollectionDescriptor *collection_attributes, CollectionDescriptor *collection_values, CollectionDescriptorPair *);
UFSRVResult *CacheBackendSetFenceAttribute(Session *sesn_ptr, unsigned long fence_id, const char *attribute_name, const char *attribute_value);
UFSRVResult *CacheBackendSetFenceAttributeBinary(unsigned long fence_id, const char *attribute_name, BufferDescriptor *buffer_attribute_value);
UFSRVResult *CacheBackendLoadFenceAttribute(Session *sesn_ptr, unsigned long fence_id, const char *attribute_name);

UFSRVResult *InstateLinkJoiningMembersListCacheRecordForFence(Session *sesn_ptr_target, InstanceHolderForFence *instance_f_ptr, unsigned long userid_loaded_for, unsigned long fence_call_flags);
UFSRVResult *CacheBackendLoadLinkJoinUserIdsForFence(unsigned long fid);

UFSRVResult *InstateCacheRecordForFence(Session *sesn_ptr_this, EnumFenceCollectionType list_type_context, unsigned long fence_id, unsigned long uid, bool *fence_lock_state, unsigned long call_flags);
UFSRVResult *CacheBackendLoadRecordForFence(unsigned long fence_id);

Session *InstateMembersFenceListForUser(InstanceHolderForSession *instance_sesn_ptr_this, unsigned long call_flags, unsigned long);
Session *InstateInvitedFenceListForUser(InstanceHolderForSession *instance_sesn_ptr_this, unsigned long sesn_call_flags, unsigned long fence_call_flags);

void InitialiseScheduledJobTypeForOrphanedFences(void);
ScheduledJob *GetScheduledJobForOrphanedFences(void);
int CheckOrphanedFences(ScheduledJob *, void *arg);

bool IsGeoFence(const Fence *f_ptr);
bool IsUserFence(const Fence *f_ptr);
bool IsFenceReferencedByUsers(InstanceHolderForFence *);
bool IsFenceReferencedByInviteMembersOnly(const Fence *f_ptr);
bool IsFenceSticky(const Fence *f_ptr);

//type pool
void FenceStateDescriptorIncrementReference(FenceStateDescriptor *descriptor_ptr, int multiples);
void FenceStateDescriptorDecrementReference(FenceStateDescriptor *descriptor_ptr, int multiples);
void InitFenceStateDescriptorRecyclerTypePool();
unsigned  FenceStateDescriptorPoolTypeNumber() __attribute__((always_inline));
InstanceHolderForFenceStateDescriptor *FenceStateDescriptorGetInstance(ContextData *ctx_data_ptr, unsigned long call_flags);
int FenceStateDescriptorReturnToRecycler(InstanceHolder *fstat_ptr, ContextData *ctx_data_ptr, unsigned long call_flags);
bool IsFenceOwnedByUser(Session *sesn_ptr, Fence *f_ptr);
InstanceHolderForFence *FenceGetInstance(ContextData *ctx_data_ptr, unsigned long call_flags);
int FenceReturnToRecycler(InstanceHolderForFence *instance_holder_ptr, ContextData *ctx_data_ptr, unsigned long call_flags);
void FenceIncrementReference(InstanceHolderForFence *descriptor_ptr, int multiples);
void FenceDecrementReference(InstanceHolderForFence *descriptor_ptr, int multiples);
void InitFenceRecyclerTypePool();
unsigned  FencePoolTypeNumber();

FenceListTypeDescriptor *GetFenceListTypeDescriptor(EnumFenceCollectionType list_type);

#endif

