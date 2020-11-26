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

#ifndef FENCE_H
# define FENCE_H

#include <thread_context_type.h>
#include <recycler/instance_type.h>
#include <digest_mode_enum.h>
#include <misc.h>
#include <utils.h>
#include <ufsrv_core/fence/fence_type.h>
#include <uflib/adt/adt_linkedlist.h>
#include <session_type.h>
#include <uflib/adt/adt_queue.h>
#include <ufsrv_core/location/location_type.h>
#include <ufsrv_core/user/users.h>
#include <json/json.h>
#include <ufsrvwebsock/include/protocol_websocket.h>//WireProtocolData
#include <ufsrv_core/SignalService.pb-c.h>//proto
#include <message_type.h>
#include <ufsrvresult_type.h>
#include <ufsrv_core/fence/fence_state_descriptor_type.h>
#include <sessions_delegator_type.h>
#include <uflib/scheduled_jobs/scheduled_jobs_type.h>


typedef enum EnumFenceNetworkType {
	FENCE_NETWORK_TYPE_GEO=1,
	FENCE_NETWORK_TYPE_USER,
  FENCE_NETWORK_TYPE_GUARDIAN,
} EnumFenceNetworkType;

typedef enum EnumFenceCollectionType {
	MEMBER_FENCES=1,
	INVITED_FENCES,
	BLOCKED_FENCES,
	LIKED_FENCES,
	FAVED_FENCES,
	ALL_FENCES,
	UNSPECIFIED_FENCE_LISTTYPE

} EnumFenceCollectionType;

//usertypes
typedef enum FenceTypes {
	MEMBER_FENCE			=	0x1U<<MEMBER_FENCES,
	INVITED_FENCE			=	0x1U<<INVITED_FENCES,
	BLOCKED_FENCE			=	0x1U<<BLOCKED_FENCES,
	LIKED_FENCE				=	0x1U<<LIKED_FENCES,
	FAVED_FENCE				=	0x1U<<FAVED_FENCES,
	ALL_FENCE_TYPES		=	(0x1U<<MEMBER_FENCES|0x1U<<INVITED_FENCES|0x1U<<BLOCKED_FENCES|0x1U<<BLOCKED_FENCES|0x1U<<LIKED_FENCES|0x1U<<FAVED_FENCES)

} FenceTypes;

typedef enum EnumFenceLeaveType {
	LT_USER_INITIATED=0,
	LT_GEO_BASED,
	LT_BANNED,
	LT_SESSION_INVALIDATED
} EnumFenceLeaveType;

typedef enum EnumFenceJoinType {
	JT_USER_INITIATED=0,
	JT_GEO_BASED,
	JT_INVITED,
} EnumFenceJoinType;

typedef enum EnumImpairedFenceMembershipType {
	ImpairedFenceMembershipFence=0,
	ImpairedFenceMembershipSession,
} EnumImpairedFenceMembershipType;

typedef struct FencesCollectionForSession {
	CollectionDescriptor member_fences;
	CollectionDescriptor invited_fences;
	CollectionDescriptor blocked_fences;
}FencesCollectionForSession;

typedef struct PairOfFenceIdFenceCname {
	unsigned long 	fid;
	char *			fcname;
}PairOfFenceIdFenceCname;

typedef struct PairOfUserIdUserName {
	unsigned long 	uid;
	char *					uname;
	char *					aux;//whatever is remained after parsing
}PairOfUserIdUserName;

//packaging to facilitate passing of context data
typedef struct TypePoolContextDataFence {
	bool 										is_fence_locked;
	Session									*sesn_ptr;
	union {
		InstanceHolderForFence 								*instance_f_ptr;
		InstanceHolderForFenceStateDescriptor	*instance_fstate_ptr;
	} fence_data;

} TypePoolContextDataFence;


typedef void (*OnUserAttachedCallback)(Session *, FenceStateDescriptor *, ClientContextData *);

//Each list type can define custom callbacks for when users are loaded into lists
typedef struct FenceListTypeDescriptor {
	 EnumFenceCollectionType list_type;
	 struct {
		 OnUserAttachedCallback user_attached_callback;
	 } type_ops;

}	FenceListTypeDescriptor;



#define FENCE_CALLFLAG_EMPTY											0
#define FENCE_CALLFLAG_GENERATE_ID								(0x1U<<1U)
#define FENCE_CALLFLAG_LOCK_FENCE									(0x1U<<2U)
#define FENCE_CALLFLAG_KEEP_FENCE_LOCKED					(0x1U<<3U)//instructs the current lock owner to leave it locked
#define FENCE_CALLFLAG_UNLOCK_FENCE								(0x1U<<4U)
#define FENCE_CALLFLAG_SELF_DESTRUCT							(0x1U<<5U)
#define FENCE_CALLFLAG_BASEFENCE									(0x1U<<6U)
#define FENCE_CALLFLAG_USERFENCE									(0x1U<<7U)
#define FENCE_CALLFLAG_JOIN												(0x1U<<8U)
#define FENCE_CALLFLAG_SEARCH_BACKEND							(0x1U<<9U)
#define FENCE_CALLFLAG_HASH_FENCE_LOCALLY					(0x1U<<10U)
#define FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE	(0x1U<<11U)
#define	FENCE_CALLFLAG_INCLUDE_REMOTE_SESSIONS		(0x1U<<12U)
#define	FENCE_CALLFLAG_ROAMING_GEOFENCE						(0x1U<<13U)//geofence related operation
#define	FENCE_CALLFLAG_SNAPSHOT_INSTANCE					(0x1U<<14U)//unmanaged,pure data representtaion
#define	FENCE_CALLFLAG_CHECK_FENCEOWNERSHIP				(0x1U<<15U)//is user owner of fence
#define	FENCE_CALLFLAG_FENCE_LIST_WITH_SCORES			(0x1U<<16U)//raw fences list contains score information, nut just serial list of fences
#define	FENCE_CALLFLAG_TRANSFER_INVITE_CONTEXT		(0x1U<<17U)//transfer relevant invite spepcif info from a given fence stored in in invite list
#define	FENCE_CALLFLAG_MARSHAL_COMMAND_ERROR			(0x1U<<18U)//marshal error to user
#define FENCE_CALLFLAG_WRITEBACK_DATA_TO_BACKEND	(0x1U<<19U)
#define FENCE_CALLFLAG_ABORT_RECORD_IF_USER_NOT_MEMBER	(0x1U<<20U)
#define FENCE_CALLFLAG_EVICT_FROM_CACHEBACKEND		(0x1U<<21U)//deleter cachebackend record
#define FENCE_CALLFLAG_WRITEBACK_TO_DBBACKEND			(0x1U<<22U)
#define FENCE_CALLFLAG_LOCK_FENCE_BLOCKING				(0x1U<<23U) //using blocking mode as opposed tro try-mode

#define FENCECMND_JOIN		"JOIN"
#define FENCECMND_LEAVE		"LEAVE"
#define FENCECMND_UPDATE	"UPDATE"


enum {
	REDIS_KEY_FENCE_ID=0,REDIS_KEY_FENCE_TYPE, REDIS_KEY_FENCE_WHEN_CREATED, REDIS_KEY_FENCE_USERID, REDIS_KEY_FENCE_BASELOC,
	REDIS_KEY_FENCE_CNAME, REDIS_KEY_FENCE_DNAME, REDIS_KEY_FENCE_BNAME, REDIS_KEY_FENCE_LONG, REDIS_KEY_FENCE_LAT,
	REDIS_KEY_MAXUSERS, REDIS_KEY_TTL, REDIS_KEY_EVENT_COUNTER, REDIS_KEY_FENCE_AVATAR, REDIS_KEY_FENCE_MSGEXPIRY,
	REDIS_KEY_LIST_SEMANTICS,

	_REDIS_KEY_FENCE_SETSIZE
};

//INDIVIDUAL FENCE RECORD update enum above every time new attribute is added and observe order
//#define REDIS_CMD_FENCE_RECORD_GET	"HVALS BID:%lu"
#define REDIS_CMD_FENCE_RECORD_GET_ALL	"HMGET BID:%lu id type when uid baseloc cname dname bname lng lat maxusers ttl event_counter avatar expiry list_semantics"
#define REDIS_CMD_FENCE_RECORD_SET_ALL 	"HMSET BID:%lu id %lu type %u when %lu uid %lu baseloc %s cname %s dname %s  bname %s lng %f lat %f maxusers %d ttl %d event_counter %lu avatar %s expiry %lu list_semantics %d"
#define REDIS_CMD_FENCE_RECORD_REM 			"DEL BID:%lu"

//specific command for when updating fence name, cname must be done at the same time
#define REDIS_CMD_FENCE_RECORDSET_NAME	"HMSET BID:%lu dname %s cname %s"

//Set a single attribute
#define REDIS_CMD_FENCE_RECORD_SET_ATTRIBUTE "HMSET BID:%lu %s %s"
#define REDIS_CMD_FENCE_RECORD_SET_ATTRIBUTE_BINARY "HMSET BID:%lu %s %b"
#define REDIS_CMD_FENCE_RECORD_SET_ATTRIBUTES "HMSET BID:%lu '%s'"//not in use
#define REDIS_CMD_FENCE_RECORD_GET_ATTRIBUTE "HMGET BID:%lu %s"

//increment event counter by 1 returns incremented counter
//IMPORTANT IF PREFIX BID CHANGED CHANGE ALSO IN CacheBackendSetFenceAttributesByCollection()
#define REDIS_CMD_FENCE_INC_EVENT_COUNTER	"HINCRBY BID:%lu event_counter 1"
#define REDIS_CMD_FENCE_EVENT_COUNTER_GET	"HGET BID:%lu event_counter" //not in use?

//-----------------------------------------------------

//GEOHASH <%long> <%lat> <%fid>:<%type>: last colon is empty placeholder
//
#define REDIS_CMD_FENCE_GEOHASH_ADD "GEOADD FENCES_GEO %f %f %lu:%d:"
#define REDIS_CMD_FENCE_GEOHASH_REM "ZREM FENCES_GEO %lu:%d:"

//get collection vased on pure long/lat params<%long> <lat> <radius>
#define REDIS_CMD_FENCE_NEARBY_LOC_GET	"GEORADIUS FENCES_GEO %f %f %lu km"
#define REDIS_CMD_FENCE_NEARBY_LOC_GET_WITH_COUNT	"GEORADIUS FENCES_GEO %f %f %lu km COUNT %lu"

//get collection based on member fence on the list.. GEORADIUSBYMEMBER FENCES_GEO 375714604044521278:1: 100 km
#define REDISCMD_FENCES_NEARBY_FENCE_GET "GEORADIUSBYMEMBER FENCES_GEO %s %lu km"
#define REDISCMD_FENCES_NEARBY_FENCE_GET_WITH_COUNT "GEORADIUSBYMEMBER FENCES_GEO %s %lu km COUNT %lu"
//-------------


//not in use
#define REDIS_CMD_FENCE_RECORD_ARGS(x) \
		x->fence_id,	\
		x->fence_id,	\
		x->attrs,	\
		x->when,	\
		0,/*f_ptr->fence_owner_id,*/	\
		x->fence_location.canonical_name,	\
		x->fence_location.base_location,	\
		x->fence_location.display_banner_name,	\
		"fence banner",/*f_ptr->fence_location.banner_name,*/	\
		x->fence_location.fence_location.longitude,	\
		x->fence_location.fence_location.latitude,	\
		0,	\
		0,	\
		0

//Master registery of fences
//Add %cname:%fid and sort it lexographically. Each new fence must be added here
//TODO: this should be casefolded for comparison
#define REDIS_CMD_GLOBAL_FENCE_REGO_ADD "ZADD FENCES_MAIN 0 %s:%lu"
#define REDIS_CMD_MATCHING_FENCES_GET	"ZRANGEBYLEX FENCES_MAIN [%s [%s\xff"
#define REDIS_CMD_GLOBAL_FENCE_REGO_REM "ZREM FENCES_MAIN %s:%lu"

//facilitates auto completion of fence names
//<%component>:<fid>>:<baseloc>:<longit>:<lat>:<fattrs>
#define REDIS_CMD_GLOBAL_FENCE_NAMEINDEX_ADD "ZADD FENCES_NAMEINDEX 0 %s:%lu:%s:%f:%f"
#define REDIS_CMD_GLOBAL_FENCE_NAMEINDEX_SELZONE_ADD "ZADD FENCES_NAMEINDEX 0 %lu:%lu:%s:%f:%f"
#define REDIS_CMD_GLOBAL_FENCE_NAMEINDEX_GET	"ZRANGEBYLEX FENCES_NAMEINDEX [%s [%s\xff"
#define REDIS_CMD_GLOBAL_FENCE_NAMEINDEX_GET_WITHLIMIT	"ZRANGEBYLEX FENCES_NAMEINDEX [%s [%s\xff LIMIT %d %d"
#define REDIS_CMD_GLOBAL_FENCE_NAMEINDEX_REM	"ZREM FENCES_NAMEINDEX %s:%lu:%s:%f:%f"
#define REDIS_CMD_GLOBAL_FENCE_NAMEINDEX_SELFZONE_REM	"ZREM FENCES_NAMEINDEX %lu:%lu:%s:%f:%f"

//Add user to an individual fence record FUSERS:%bid %time(now) %uid sorted chronologically
//#define REDIS_CMD_FENCE_USER_RECORD "ZADD FUSERS:%lu %lu %lu"
#define REDIS_CMD_FENCE_USER_RECORD "ZADD MEMBER_USERS_FOR_FENCE:%lu %lu %lu"
//TODO: renamelist to this
//#define REDIS_CMD_FENCE_USER_RECORD "ZADD MEMBER_USERS_FOR_FENCE:%lu %lu %lu"
#define REDIS_CMD_FENCE_USERS_LIST_REM	"ZREM MEMBER_USERS_FOR_FENCE:%lu %lu"
#define REDIS_CMD_FENCE_USERS_LIST_GET "ZRANGE MEMBER_USERS_FOR_FENCE:%lu 0 -1"
//
//----------------------------------------------------------------------------------

//// FENCE MEMBERSHIP FOR USER
//ZADD  UF:<user id> <timestamp> <bid>:<invitedby>
#define REDIS_CMD_USER_FENCE_LIST_ADD	"ZADD UF:%lu %lu %lu:%lu"
//TODO: renamelist to this
//#define REDIS_CMD_USER_FENCE_LIST_ADD	"ZADD MEMBER_FENCES_FOR_USER:%lu %lu %lu:%s"
#define REDIS_CMD_USER_FENCE_LIST_REM	"ZREM UF:%lu %lu:%lu"
#define REDIS_CMD_USER_FENCE_LIST_REM_PREBUILT	"ZREM UF:%lu %s"
#define REDIS_CMD_USER_FENCE_LIST_REM_ALL	"DEL UF:%lu"
#define REDIS_CMD_USER_FENCE_LIST_GET_ALL	"ZRANGE UF:%lu 0 -1"
#define REDIS_CMD_USER_FENCE_LIST_SIZE		"ZCARD UF:%lu"

//
//-----------------------------------------------------


//// INVITED FENCE MEMBERSHIP FOR USER

//User -> InvitedFences*
//ZADD  INVITED_FENCES_FOR_USER:<user id> <timestamp> <bid>:<uid_inviter>
#define REDIS_CMD_INVITED_FENCES_FOR_USER_ADD	"ZADD INVITED_FENCES_FOR_USER:%lu %lu %lu:%lu"
#define REDIS_CMD_INVITED_FENCES_FOR_USER_REM	"ZREM INVITED_FENCES_FOR_USER:%lu %lu:%lu"
#define REDIS_CMD_INVITED_FENCES_FOR_USER_REM_PREBUILT	"ZREM INVITED_FENCES_FOR_USER:%lu %s"
#define REDIS_CMD_INVITED_FENCES_FOR_USER_REM_ALL	"DEL INVITED_FENCES_FOR_USER:%lu"
#define REDIS_CMD_INVITED_FENCES_FOR_USER_GET_ALL	"ZRANGE INVITED_FENCES_FOR_USER:%lu 0 -1"
#define REDIS_CMD_INVITED_FENCES_FOR_USER_GET_ALL_WITHSCORES	"ZRANGE INVITED_FENCES_FOR_USER:%lu 0 -1 WITHSCORES"
#define REDIS_CMD_INVITED_FENCES_FOR_USER_LIST_SIZE	"ZCARD INVITED_FENCES_FOR_USER:%lu"
//---------------------------------------------------------


//FENCE -> InvitedUsers*
//ZADD  INVITED_USERS_FOR_FENCE:<fid> <timestamp> <uid>:<uname>:<uid_inviter>
//add one entry to user lsit of fences
#define REDIS_CMD_INVITED_USERS_FOR_FERNCE_ADD	"ZADD INVITED_USERS_FOR_FENCE:%lu %lu %lu:%s:%lu"
#define REDIS_CMD_INVITED_USERS_FOR_FERNCE_REM	"ZREM INVITED_USERS_FOR_FENCE:%lu %lu:%s:%lu"
#define REDIS_CMD_INVITED_USERS_FOR_FERNCE_REM_ALL	"DEL INVITED_USERS_FOR_FENCE:%lu"
#define REDIS_CMD_INVITED_USERS_FOR_FERNCE_GET_ALL	"ZRANGE INVITED_USERS_FOR_FENCE:%lu 0 -1"
#define REDIS_CMD_INVITED_USERS_FOR_FERNCE_GET_ALL_WITHSCORES	"ZRANGE INVITED_USERS_FOR_FENCE:%lu 0 -1 WITHSCORES"
#define REDIS_CMD_INVITED_USERS_FOR_FERNCE_LIST_SIZE	"ZCARD INVITED_USERS_FOR_FENCE:%lu"
//-----------------------------------------------------------------------

//ME -> INVITE USERS
//User's list of user's current invitee list across all feces "ZRANGE MY_INVITED_USERS:%<uid> %<time> %<fid>:%<uid_invitee>"
#define REDIS_CMD_MY_FENCE_INVITED_USERS_ADD	"ZADD MY_INVITED_USERS:%lu %lu %lu:%lu"
#define REDIS_CMD_MY_FENCE_INVITED_USERS_REM	"ZREM MY_INVITED_USERS:%lu %lu:%lu"
#define REDIS_CMD_MY_FENCE_INVITED_USERS_REM_ALL	"DEL MY_INVITED_USERS:%lu"
#define REDIS_CMD_MY_FENCE_INVITED_USERS_GET_ALL	"ZRANGE MY_INVITED_USERS:%lu 0 -1"
//
//-------------------------------------------------------------------------


////ZADD FEVREGO:%bid 						    eid eid:sid:cid:when:oid:tid:%evt:%ev
//#define REDIS_CMD_FENCE_EVENTS "ZADD FEVREGO:%lu %lu %lu:%d:%lu:%lu:%lu:%lu:%d:%s"


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

typedef void(*CallbackFenceUpdater)(Session *, Fence *, ClientContextData *);

//A simple mechanism to specif how a given fence is being identified
typedef struct FenceIdentifier {
	unsigned long	fence_id;
	Fence			*f_ptr;
} FenceIdentifier;


//this is used to separate the wire processing context from the internal model processing
typedef struct FenceContextDescriptor {
	Session 							*sesn_ptr;
	FenceStateDescriptor 	*fence_state_ptr;
	ClientContextData			*context_ptr;
	struct {
		CallbackFenceUpdater	callback_update_fence;
	} callbacks;

}	FenceContextDescriptor;

UFSRVResult *FenceEventsLockRDCtx (ThreadContext *thread_ctx_ptr, Fence *f_ptr, int try_flag, UFSRVResult *res_ptr, const char *);
UFSRVResult *FenceEventsLockRWCtx (ThreadContext *thread_ctx_ptr, Fence *f_ptr, int try_flag, UFSRVResult *res_ptr, const char *func);
UFSRVResult *FenceEventsUnLockCtx (ThreadContext *thread_ctx_ptr, Fence *f_ptr, UFSRVResult *res_ptr);

UFSRVResult *RepairFenceMembershipForUser (InstanceHolderForSession *instance_sesn_ptr, InstanceHolderForFence *instance_f_ptr, EnumImpairedFenceMembershipType impairment_type);
bool IsFenceIdInCacheRecordForUser (unsigned long uid, unsigned long fid, unsigned long *uid_inviter);
bool IsUserIdInCacheRecordForFence (Session *sesn_ptr,  unsigned long fid);

UFSRVResult *IsUserAllowedToChangeFence (Session *sesn_ptr, unsigned long fid, const char *cname, bool *fence_lock_state, unsigned long fence_call_flags);
UFSRVResult *IsUserAllowedToChangeFenceName (Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, const char *fname_new, unsigned long fence_call_flags, FenceEvent *fence_event_ptr_out);
void UpdateFenceAssignments (Session *sesn_ptr, Fence *f_ptr_processed, ClientContextData *context_ptr);
UFSRVResult *UpdateFenceAvatarAssignment (Session *sesn_ptr, Fence *f_ptr, AttachmentRecord *record_ptr, unsigned long fence_call_flags);
bool UpdateFenceNameAssignment (Session *, InstanceHolderForFence *instance_f_ptr, const char *fname_new, char *cname_new, bool flag_build_cname, unsigned long);
UFSRVResult *UpdateFenceTypeAssignment (Session *sesn_ptr, Fence *f_ptr, FenceRecord__FenceType fence_type, unsigned long fence_call_flags);
UFSRVResult *UpdateFenceMaxUsersAssignment (Session *sesn_ptr, Fence *f_ptr, int maxusers, unsigned long fence_call_flags);
UFSRVResult *UpdateFencePrivacyModeAssignment (Session *sesn_ptr, Fence *f_ptr, FenceRecord__PrivacyMode privacy_mode, unsigned long fence_call_flags);
UFSRVResult *UpdateFenceDeliveryModeAssignment (Session *sesn_ptr, Fence *f_ptr, FenceRecord__DeliveryMode delivery_mode, unsigned long fence_call_flags);
UFSRVResult *IsUserAllowedToChangeFenceAvatar (Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, DataMessage *data_msg_ptr, unsigned long fence_call_flags, FenceEvent *fence_event_ptr_out);
UFSRVResult *IsUserAllowedToChangeFenceMessageExpiry (Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, time_t msg_expiry_in_seconds, unsigned long fence_call_flags, FenceEvent *fence_event_ptr_out);
UFSRVResult *UpdateFenceJoinModeAssignment (Session *sesn_ptr, Fence *f_ptr, FenceRecord__JoinMode join_mode, unsigned long fence_call_flags);

char *MakeCanonicalFenceName(Session *sesn_ptr, const char *fdname, unsigned  flag_selfzoned, char *);
LocationDescription *MapFenceLocationDescription (const Fence *f_ptr, char *canonical_name_buffer, LocationDescription *location_ptr_out);
size_t SizeofCanonicalFenceName (Session *sesn_ptr, const char *fdname);
UFSRVResult *IsUserAllowedToJoinGeoFence (InstanceHolderForSession *, LocationDescription *);
UFSRVResult *IsUserAllowedGeoFenceInvite(InstanceHolderForSession *instance_sesn_ptr, Session *sesn_ptr_inviter, unsigned long fence_call_flags);
void InitialiseMaserFenceRegistries (void);
void SummariseUserFenceConfiguration (void);
void SummariseBaseFenceConfiguration (void);
UFSRVResult *IsUserAllowedToJoinFenceById(InstanceHolderForSession *, const unsigned long, unsigned long, bool *fence_lock_state);
UFSRVResult *HandleJoinFence (InstanceContextForSession *, InstanceHolderForFenceStateDescriptor *, WebSocketMessage *, DataMessage *data_msg_ptr, EnumFenceJoinType join_type, UFSRVResult *res_ptr);
UFSRVResult *IsUserAllowedToJoinFenceByCanonicalName(InstanceHolderForSession *, const char *, unsigned long);

UFSRVResult *IsUserAllowedToChangeFenceMaxMembers (Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, int32_t maxmembers, unsigned long fence_call_flags, FenceEvent *fence_event_ptr_out);
UFSRVResult *IsUserAllowedToChangeFenceDeliveryMode (Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, int delivery_mode, unsigned long fence_call_flags, FenceEvent *fence_event_ptr_out);

struct json_object *JsonFormatSessionFenceList (Session *, enum DigestMode);
struct json_object *JsonFormatSessionInvitedFenceList (Session *sesn_ptr, enum DigestMode digest_mode);
struct json_object *JsonFormatFenceForDbBackend(Session *sesn_ptr_carrier, Fence *f_ptr, enum DigestMode digest_mode,
                                                unsigned long fence_call_flags);

void DestructFenceRawSessionList (FenceRawSessionList *raw_sesn_list_ptr, bool self_destruct);
InstanceHolderForSession *GetSessionForFenceOwner (Session *sesn_ptr, Fence *f_ptr);
FenceRawSessionList *GetRawMemberUsersListForFence  (Session *sesn_ptr, InstanceHolderForFence *instance_f_ptr, unsigned long fence_call_flags, FenceRawSessionList *raw_sesn_list_ptr_in);
FenceRawSessionList *GetRawInvitedUsersListForFence  (Session *sesn_ptr, InstanceHolderForFence *instance_f_ptr, unsigned long fence_call_flags, FenceRawSessionList *raw_sesn_list_ptr_in);

int FenceRemoveUserByFenceId (Session *sesn_ptr_this, Session *sesn_ptr, unsigned long fence_id);
unsigned RemoveUserFromAllFences (InstanceHolderForSession *, unsigned long);
unsigned RemoveUserFromAllFencesSessionInstanceOnly (Session *sesn_ptr, unsigned long call_flags);
int RemoveUserFromInvitedList(InstanceHolderForSession *instance_sesn_ptr, FenceStateDescriptor *fence_state_joined, FenceEvent *fe_ptr_out, unsigned long fence_call_flags);
size_t NetworkRemoveUsersFromInviteList (InstanceContextForSession *ctx_ptr_carrier, InstanceHolderForFence *);
unsigned long RemoveUserFromFence (InstanceHolderForSession *, Fence *, unsigned long);
InstanceHolderForFenceStateDescriptor *RemoveFenceFromSessionFenceList (List *, Fence *);
InstanceHolderForFenceStateDescriptor *RemoveFenceFromSessionInvitedFenceList (List *, unsigned long);

UFSRVResult *FindFenceByCanonicalName (Session *sesn_ptr_this, const char *fence_canonical_name, bool *, unsigned long call_flags);
InstanceHolder *FindBaseFenceByCanonicalName (Session *, const char *, bool *fence_already_locked, unsigned long);
InstanceHolderForFence *FindUserFenceByCanonicalName (Session *sesn_ptr_this, const char *fence_canonical_name, bool *fence_already_locked, unsigned long call_flags);
InstanceHolderForFenceStateDescriptor *FindFenceStateInSessionFenceListByFenceId (Session *sesn_ptr, List *sesn_fence_ist_ptr, unsigned long fence_id);
UFSRVResult *FindFenceById (Session *, const unsigned long fence_id, unsigned long fence_call_flags);
InstanceHolderForSession * FindUserInFenceSessionListByID (const List *const lst_ptr_sesn, Fence *f_ptr, unsigned long cid);
InstanceHolderForFenceStateDescriptor *IsUserMemberOfFenceById (const List *const, const unsigned long fence_id, bool);
InstanceHolderForFenceStateDescriptor *IsUserMemberOfThisFence (const List *const lst_ptr, Fence *f_ptr, bool lock_flag);
Fence *IsUserMemberOfFenceByCanonicalName (const List *const lst_ptr, const char *fence_canonical_name);
int CrossCheckSessionInFenceBySessionId (Fence *f_ptr, unsigned long session_id);
bool IsUserOnFenceInvitedList (Fence *f_ptr, unsigned long uid);
int CrossCheckFenceInSessionByFenceId (Session *sesn_ptr, unsigned long fence_id);
InstanceHolderForFenceStateDescriptor *CreateUserFenceAndLinkToUser (InstanceHolderForSession *instance_sesn_ptr, const char *fence_banner, char *userfence_canonical_name_in, FenceContextDescriptor *, unsigned long call_flags);
InstanceHolderForFenceStateDescriptor *AddUserToThisFenceListWithLinkback(InstanceHolderForSession *instance_sesn_ptr, InstanceHolderForFence *, List *user_fence_list_ptr, List *fence_user_list_ptr,  int event_type, unsigned call_flags);
CollectionDescriptor *AddToFenceInvitedListFromProtoRecord(InstanceHolderForSession *instance_sesn_ptr, InstanceHolderForFence *instance_f_ptr, UserRecord **user_records, size_t invited_members_sz, CollectionDescriptorPair *, bool flag_exclude_self);
UFSRVResult *AddMemberToInvitedFenceList (InstanceHolderForSession *instance_sesn_ptr_invited, InstanceHolderForFence *instance_f_ptr, Session *sesn_ptr_inviter, unsigned long);
UFSRVResult *IsUserAllowedToMakeUserFence (InstanceHolderForSession *instance_sesn_ptr, const char *fence_banner, const char *baseloc_prefix, FenceContextDescriptor *, bool *fence_lock_already_owned, unsigned long call_flags);
FenceEvent *UpdateBackendFenceInvitedData (Session *sesn_ptr_inviter, Session *sesn_ptr_invited, FenceStateDescriptor *fstate_ptr, unsigned event_type, FenceEvent *fe_ptr_out);

int InstateFenceListsForUser (InstanceHolderForSession *instance_sesn_ptr, unsigned long sesn_call_flags, FenceTypes fence_type, bool flag_abort_on_failure);

void DestructFenceCollection (CollectionDescriptor *fence_collection_ptr, bool flag_self_destruct);
CollectionDescriptor *GetFenceCollectionForUser (Session *sesn_ptr, CollectionDescriptor *, CollectionDescriptor *overflow_collection_ptr_in, EnumFenceCollectionType);

//events
FenceEvent *RegisterFenceEvent (Session *sesn_ptr, Fence *f_ptr, unsigned event_type,  void *event_payload, unsigned lock_flag,  FenceEvent *fe_ptr_out);
FenceEvent *RegisterFenceEventWithFid (Session *sesn_ptr_this, unsigned long fence_id, unsigned event_type,  void *event_payload, FenceEvent *fe_ptr_out);
unsigned long GetFenceEventId (Fence *f_ptr, unsigned lock_flag);
int DestructFenceEvent (FenceEvent *fe_ptr, bool self_destruct);
void *DestructFenceEventQueue (Session *sessn_ptr, Fence *f_ptr, unsigned reset_counter_flag);

UFSRVResult *DbBackendInsertUfsrvEvent (UfsrvEvent *event_ptr);
int DbBackendUpdateEventFlagger (unsigned long event_rowid, unsigned  long uid_flagged_by, time_t timestamp);
unsigned long IsEventValid (unsigned long, unsigned long, EnumEventCommandType);

FenceEvent *UpdateBackendFenceData (Session *sesn_ptr_target, Fence *f_ptr, void *user_data, unsigned event_type, FenceEvent *);

UFSRVResult *CacheBackendGetFencesListSize (Session *sesn_ptr, unsigned long userid);
UFSRVResult *CacheBackendGetFenceInviteListSize (Session *sesn_ptr, Fence *f_ptr);
UFSRVResult *CacheBackendGetUserFencesInviteListSize (Session *sesn_ptr, unsigned long);
UFSRVResult *GetInvitedMembersListCacheRecordForFence (Session *sesn_ptr,  InstanceHolderForFence *instance_f_ptr, unsigned long userid, EnumFenceCollectionType list_type_target, EnumFenceCollectionType list_type_context, unsigned long call_flags);
UFSRVResult *GetMembersListCacheRecordForFence (Session *sesn_ptr_this,  InstanceHolderForFence *instance_f_ptr, unsigned long userid_loading_for, EnumFenceCollectionType list_type_target, EnumFenceCollectionType list_type_context, unsigned long attach_to_fence_flag);
UFSRVResult *CacheBackendGetUserIdsCacheRecordForFence (unsigned long);
UFSRVResult *CacheBackendSetFenceAttributesByCollection (Session *sesn_ptr, unsigned long fence_id, CollectionDescriptor *collection_attributes, CollectionDescriptor *collection_values, CollectionDescriptorPair *);
UFSRVResult *CacheBackendSetFenceAttribute (Session *sesn_ptr, unsigned long fence_id, const char *attribute_name, const char *attribute_value);
UFSRVResult *CacheBackendSetFenceAttributeBinary (Session *sesn_ptr, unsigned long fence_id, const char *attribute_name, BufferDescriptor *buffer_attribute_value);
UFSRVResult *CacheBackendGetFenceAttribute (Session *sesn_ptr, unsigned long fence_id, const char *attribute_name);

UFSRVResult *GetCacheRecordForFence (Session *sesn_ptr_this, EnumFenceCollectionType list_type_context, unsigned long fence_id, unsigned long uid, bool *fence_lock_state, unsigned long call_flags);

Session *InstateMembersFenceListForUser (InstanceHolderForSession *instance_sesn_ptr_this, unsigned long call_flags, unsigned long);
Session *InstateInvitedFenceListForUser (InstanceHolderForSession *instance_sesn_ptr_this, unsigned long sesn_call_flags, unsigned long fence_call_flags);

void InitialiseScheduledJobTypeForOrphanedFences (void);
ScheduledJob *GetScheduledJobForOrphanedFences (void);
int CheckOrphanedFences (void *arg);

bool IsGeoFence (const Fence *f_ptr);
bool IsUserFence (const Fence *f_ptr);
bool IsFenceReferencedByUsers (InstanceHolderForFence *);
bool IsFenceReferencedByInviteMembersOnly (const Fence *f_ptr);
bool IsFenceSticky (const Fence *f_ptr);

//type pool
void FenceStateDescriptorIncrementReference (FenceStateDescriptor *descriptor_ptr, int multiples);
void FenceStateDescriptorDecrementReference (FenceStateDescriptor *descriptor_ptr, int multiples);
void InitFenceStateDescriptorRecyclerTypePool ();
unsigned  FenceStateDescriptorPoolTypeNumber() __attribute__((always_inline));
InstanceHolderForFenceStateDescriptor *FenceStateDescriptorGetInstance (ContextData *ctx_data_ptr, unsigned long call_flags);
int FenceStateDescriptorReturnToRecycler (InstanceHolder *fstat_ptr, ContextData *ctx_data_ptr, unsigned long call_flags);
bool IsFenceOwnedByUser (Session *sesn_ptr, Fence *f_ptr);
InstanceHolderForFence *FenceGetInstance (ContextData *ctx_data_ptr, unsigned long call_flags);
int FenceReturnToRecycler (InstanceHolderForFence *instance_holder_ptr, ContextData *ctx_data_ptr, unsigned long call_flags);
void FenceIncrementReference (InstanceHolderForFence *descriptor_ptr, int multiples);
void FenceDecrementReference (InstanceHolderForFence *descriptor_ptr, int multiples);
void InitFenceRecyclerTypePool ();
unsigned  FencePoolTypeNumber();

inline static Fence *
FenceOffInstanceHolder(InstanceHolderForFence *instance_holder_ptr) {
  return (Fence *)GetInstance(instance_holder_ptr);
}

FenceListTypeDescriptor *GetFenceListTypeDescriptor ( EnumFenceCollectionType list_type);

static inline EnumFenceNetworkType GetFenceNetworkType (Fence *f_ptr)
{
	if (f_ptr->attrs&F_ATTR_BASEFENCE)	return FENCE_NETWORK_TYPE_GEO;
	if (f_ptr->attrs&F_ATTR_USERFENCE)	return FENCE_NETWORK_TYPE_USER;
  if (f_ptr->attrs&F_ATTR_GUARDIANFENCE)	return FENCE_NETWORK_TYPE_GUARDIAN;

	syslog (LOG_ERR, "%s {pid:'%lu', fo:'%p', fid:'%lu', attrs:'%u'}: ERROR: COULD NOT DETERMINE FENCE NETWORK TYPE", __func__, pthread_self(), f_ptr, FENCE_ID(f_ptr), f_ptr->attrs);

	return FENCE_NETWORK_TYPE_USER;
}

inline static unsigned long
GenerateFenceEventId (Session *sesn_ptr_this, Fence *f_ptr, unsigned lock_flag)
{
	extern __thread ThreadContext ufsrv_thread_context;

	if (!(IS_EMPTY(f_ptr))) {
		PersistanceBackend	*pers_ptr;
		redisReply					*redis_ptr;

		pers_ptr = THREAD_CONTEXT_FENCE_CACHEBACKEND;

		char command_buf[MBUF] = {0};
		snprintf (command_buf, MBUF, REDIS_CMD_FENCE_INC_EVENT_COUNTER, f_ptr->fence_id);
		if (!(redis_ptr = (*pers_ptr->send_command)(NULL, pers_ptr, command_buf))) {
			syslog(LOG_DEBUG, "%s: ERROR COULD NOT INC EVENTS CUNTER for UID:'%lu': BACKEND CONNECTIVITY ERROR", __func__, f_ptr->fence_id);

			return 0;
		}

		if (redis_ptr->type == REDIS_REPLY_ERROR) {
		   syslog(LOG_DEBUG, "%s: ERROR COULD NOT INC EVENTS CUNTER for UID:'%lu': REPLY ERROR '%s'", __func__, f_ptr->fence_id, redis_ptr->str);

		   freeReplyObject(redis_ptr);

		   return 0;
		}

		if (redis_ptr->type == REDIS_REPLY_NIL) {
		   syslog(LOG_DEBUG, "%s: ERROR COULD NOT INC EVENTS CUNTER for UID:'%lu': REPLY NIL '%s'", __func__, f_ptr->fence_id, redis_ptr->str);

		   freeReplyObject(redis_ptr);

		   return 0;
		}

		long long ev_counter = redis_ptr->integer;

		freeReplyObject(redis_ptr);

		//TODO: REVISIT IF THIS IS NECESSARY: the event structure should have the event id in it
		if (lock_flag) {
			FenceEventsLockRWCtx(THREAD_CONTEXT_PTR, f_ptr, _LOCK_TRY_FLAG_TRUE, THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), __func__);

			if (THREAD_CONTEXT_UFSRV_RESULT_TYPE_ERR) {
				return 0;
			}
		}

		bool fence_lock_already_owned = THREAD_CONTEXT_UFSRV_RESULT_CODE_EQUAL(THREAD_CONTEXT, RESCODE_PROG_LOCKED_BY_THIS_THREAD);

		f_ptr->fence_events.last_event_id = (unsigned long)ev_counter;

		if (lock_flag) {
			if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));
		}

		return (unsigned long)ev_counter;
	}

	return 0;

}

/**
 * 	@brief: This is just a convenient wrapper around updating  a given Fence's  event. The fence Identifier is a convenient
 * 	mechanism to provide the minimum identifying information required event generation. Useful when When no Fence object is
 * 	available. For example from typical ufsrvapi context. This function is currently only called for Leave events
 * 	to facilitate very specific usecase, where it's invoked in stateless ufsrvapi after invalidating a session and since it doesn't
 * 	have full blown fence objects loaded it just uses fid's.. This function does not generate INTER broadcast.
 *
 * 	@locked: sesn_ptr:
 * 	@locked: f_ptr:
 * 	@locks: None
 * 	@dynamic_memory FenceEvent *: EXPORTED and maybe deallocated on error
 */
inline static FenceEvent *
BackendUpdateFenceEvent (Session *sesn_ptr, FenceIdentifier *fs_ptr, FenceEvent *fe_ptr_in, unsigned event_type)
{
	unsigned long				fence_id	= 0;
	FenceEvent					*fe_ptr		= NULL;
	__unused PersistanceBackend 	*pers_ptr	= NULL;
	MessageQueueBackend *mq_ptr		= NULL;
	redisReply 					*redis_ptr= NULL;
	extern ufsrv *const masterptr;

	if (IS_EMPTY(fe_ptr_in)) {
		if (IS_PRESENT(fs_ptr->f_ptr)) {
			fe_ptr = RegisterFenceEvent(sesn_ptr, fs_ptr->f_ptr, event_type,  NULL, 0/*LOCK_FLAG*/, NULL);
			fence_id = FENCE_ID(fs_ptr->f_ptr);
		} else {
			fe_ptr = RegisterFenceEventWithFid(sesn_ptr, fs_ptr->fence_id, event_type,  NULL, NULL);
			fence_id = fs_ptr->fence_id;
		}

		if (unlikely(IS_EMPTY(fe_ptr)))		return NULL;
	} else {
		fe_ptr = fe_ptr_in;
		fe_ptr = RegisterFenceEvent (sesn_ptr, fs_ptr->f_ptr, event_type,  NULL, 0/*LOCK_FLAG*/, fe_ptr);
	}

	if (fe_ptr->eid == 0) {
		syslog(LOG_DEBUG, "%s {pid:'%lu',o:'%p', fid:'%lu'}: ERROR: EVENT ID WAS SET TO ZERO: NO EVENT WILL BE LOGGED", __func__, pthread_self(), sesn_ptr, fence_id);

		if (IS_EMPTY(fe_ptr_in))	free (fe_ptr);//this comes from RegisterEvenetXXX() above

		return NULL;
	}

	if (IS_PRESENT(fs_ptr->f_ptr))			fence_id = FENCE_ID(fs_ptr->f_ptr);
	else																  fence_id = fs_ptr->fence_id;

	pers_ptr = sesn_ptr->persistance_backend;

//	char command_buf[LBUF] = {0};
//	snprintf(command_buf, LBUF, REDIS_CMD_FENCE_EVENTS, fence_id, fe_ptr->eid, fe_ptr->eid, masterptr->serverid, SESSION_ID(sesn_ptr), time(NULL), SESSION_ID(sesn_ptr), fence_id, event_type, "event");
//	redis_ptr = (*pers_ptr->send_command)(sesn_ptr, command_buf);
//
//	if (redis_ptr)	freeReplyObject(redis_ptr);

  DbBackendInsertUfsrvEvent ((UfsrvEvent *)fe_ptr);

	return fe_ptr;
}

static inline List *
_GetUserListByFenceCollectionType (Session *sesn_ptr, EnumFenceCollectionType fence_collection_type)
{
	switch (fence_collection_type)
	{
		case 	MEMBER_FENCES:	return SESSION_FENCE_LIST_PTR(sesn_ptr);
		case	INVITED_FENCES:	return SESSION_INVITED_FENCE_LIST_PTR(sesn_ptr);
		case	BLOCKED_FENCES:

		default:
			;
	}

	return NULL;
}

/**
 * 	@locks f_ptr:
 * 	@unlocks f_ptr: unless FENCE_CALLFLAG_KEEP_FENCE_LOCKED is set
 */
static inline UFSRVResult *
FindFence (Session *sesn_ptr, unsigned long fid, const char *cname, bool *fence_lock_state, unsigned long fence_call_flags)
{
	unsigned 	fence_call_flags_final;
	unsigned	rescode;
	Fence 		*f_ptr;
  InstanceHolder *instance_holder_ptr;

	fence_call_flags_final = FENCE_CALLFLAG_SEARCH_BACKEND|FENCE_CALLFLAG_HASH_FENCE_LOCALLY|FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE;
	if (fence_call_flags&FENCE_CALLFLAG_KEEP_FENCE_LOCKED)	fence_call_flags_final |= (FENCE_CALLFLAG_KEEP_FENCE_LOCKED|FENCE_CALLFLAG_LOCK_FENCE_BLOCKING);

	if (fid > 0) {
		FindFenceById (sesn_ptr, fid,	fence_call_flags_final);
		instance_holder_ptr = (InstanceHolder *)SESSION_RESULT_USERDATA(sesn_ptr);
	} else if	(IS_STR_LOADED(cname)) {
		FindFenceByCanonicalName (sesn_ptr, cname, fence_lock_state, fence_call_flags_final);
		instance_holder_ptr = (InstanceHolder *)SESSION_RESULT_USERDATA(sesn_ptr);
	}

	if (IS_PRESENT(instance_holder_ptr)) {_RETURN_RESULT_SESN(sesn_ptr, instance_holder_ptr, RESULT_TYPE_SUCCESS, SESSION_RESULT_CODE(sesn_ptr))}

#ifdef __UF_TESTING
	syslog (LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', uname:'%s', fid:'%lu'}: COULD NOT LOCATE FENCE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_USERNAME(sesn_ptr), fid);
#endif

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_FENCE_DOESNT_EXIST);

}
#endif

