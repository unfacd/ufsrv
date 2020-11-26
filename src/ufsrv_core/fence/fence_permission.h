/*
 * fence_permission.h
 *
 *  Created on: 11May,2017
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_FENCE_PERMISSION_H_
#define SRC_INCLUDE_FENCE_PERMISSION_H_

#include <ufsrv_core/fence/fence_permission.h>
#include <ufsrv_core/fence/fence_permission_type.h>
#include <ufsrv_core/fence/fence_state_descriptor_type.h>
#include <ufsrv_core/fence/fence_type.h>
#include <session_type.h>
#include <ufsrvresult_type.h>
#include <ufsrv_core/SignalService.pb-c.h>
#include <ufsrvuid.h>
#include <json/json.h>

#define HASHTABBLE_KEYLEN_SZ 8 //bytes

//struct ValueMapper {
//	union {
//		unsigned long value;
//		uint8_t 			value_mapped[HASHTABBLE_KEYLEN_SZ];
//	};
//};

//facilitate contextual processing
typedef struct FencePermissionContextData {
	Session 				*sesn_ptr; //user affected
	union {
		Fence									*f_ptr;
		FenceStateDescriptor 	*fence_state_ptr;
	} fence;
	FencePermission	*permission_ptr;
} FencePermissionContextData;

//SADD <%set_name>:<%fid> <%uid>
#define REDIS_CMD_FENCE_PERMISSION_SET_ADD 			"SADD %lu:%s %lu"
#define REDIS_CMD_FENCE_PERMISSION_SET_DEL 			"SREM %lu:%s %lu"
#define REDIS_CMD_FENCE_PERMISSION_SET_MEMBERS	"SMEMBERS %lu:%s"
#define REDIS_CMD_FENCE_PERMISSION_SET_ISMEMBER	"SISMEMBER %lu:%s %lu"

bool InitialiseFencePermissions (Fence *f_ptr);
void InitialiseFencePermissionsTypes (Fence *f_ptr);
void InitialiseFencePermissionsSpecs (Fence *f_ptr);
int InitialiseFencePermission (FencePermission *ht_ptr_permission, EnumFencePermissionType permission_type);
void ResetFencePermissions (Fence *f_ptr);
void ResetFencePermission (FencePermission *ht_ptr_permission);

int FormatListSemanticsForPersistance (const Fence *f_ptr);
void MapListSemantics (Fence *f_ptr, int list_semantics_persisted);
UFSRVResult *UpdateFencePermissionListSemanticAssignment(Session *sesn_ptr_carrier, Fence *f_ptr, FencePermission *permission_ptr,
																												 bool whitelist, unsigned long fence_call_flags, FenceEvent *event_ptr);
//UFSRVResult *IsUserAllowedToChangeFencePermission (Session *sesn_ptr, FenceStateDescriptor *fence_state_ptr, time_t msg_expiry_in_seconds, unsigned long fence_call_flags, FenceEvent *fence_event_ptr_out);
UFSRVResult *InstateFencePermissionMembers (Session *sesn_ptr_carrier, Fence *f_ptr, FencePermission *permission_ptr, unsigned long fence_call_flags);
UFSRVResult *RemoveUserFromFencePermissions (InstanceHolderForSession *instance_sesn_ptr, Fence *f_ptr, FencePermission *ht_ptr_permission, unsigned long fence_call_flags, FenceEvent *fence_event_ptr_out);
UFSRVResult *AddUserToFencePermissions (InstanceHolderForSession *instance_sesn_ptr, Fence *f_ptr, FencePermission *ht_ptr_permission, unsigned long fence_call_flags, FenceEvent *fence_event_ptr_out);
UFSRVResult *CacheBackendPermissionMembersSetAdd (Fence *f_ptr, FencePermission *permission_ptr, unsigned long userid_target);
UFSRVResult *CacheBackendPermissionMembersSetRem (Session *sesn_ptr_carrier, Fence *f_ptr, FencePermission *permission_ptr, unsigned long userid_target);
UFSRVResult *CacheBackendPermissionMembersIsMember (Session *sesn_ptr_carrier, Fence *f_ptr, FencePermission *permission_ptr, unsigned long userid_target);
ClientContextData *PermissionListItemExtractorCallback (ItemContainer *item_container_ptr);
json_object *JsonFormatFencePermissions (Session *sesn_ptr_carrier, Fence *f_ptr);

static inline void
_InitialiseStorageIfNecessary (Session *sesn_ptr, Fence *f_ptr, FencePermission *permission_ptr)
{
	//lazy initialisation
		if (!FENCE_PERMISSION_CONFIG_INIT(permission_ptr))	InitialiseFencePermission (permission_ptr, FENCE_PERMISSION_TYPE(permission_ptr));

}

//only initialise this if semantics are
static inline void
_InitialiseMembersIfNecessary (Session *sesn_ptr, Fence *f_ptr, FencePermission *permission_ptr)
{
	//lazy initialisation
		if (!FENCE_PERMISSION_CONFIG_USERS_LOADED(permission_ptr))	InstateFencePermissionMembers (sesn_ptr, f_ptr, permission_ptr, 0/*FENCE_CALLFLAG_EMPTY*/);

}

static inline bool
IsFencePermissionWhiteListSemantics (const FencePermission *permission_ptr)
{
	return (FENCE_PERMISSION_CONFIG_WHITELIST(permission_ptr) == true);
}

//default. Open permissions except for those on the (black)list
static inline bool
IsFencePermissionBlackListSemantics (const FencePermission *permission_ptr)
{
	return (FENCE_PERMISSION_CONFIG_WHITELIST(permission_ptr) == false);
}

/**
 * 	@brief: Check for the presence of a user on a given permission list, without regards to list semantics
 */
static inline bool
IsUserOnFencePermissionList (Session *sesn_ptr, Fence *f_ptr, FencePermission *permission_ptr)
{
	_InitialiseStorageIfNecessary(sesn_ptr, f_ptr, permission_ptr);
	_InitialiseMembersIfNecessary(sesn_ptr, f_ptr, permission_ptr);
  unsigned long userid = UfsrvUidGetSequenceId(&SESSION_UFSRVUIDSTORE(sesn_ptr));

	return (hopscotch_lookup(FENCE_PERMISSION_PERMITTED_USERS_PTR(permission_ptr), PermissionListItemExtractorCallback, (uint8_t *)&userid, CONFIG_FENCE_PERMISSIONS_KEYOFFSET(Session, sservice.user.user_details.user_id)) != NULL);
}

static inline bool
IsUserWithPermission (Session *sesn_ptr, Fence *f_ptr, FencePermission *permission_ptr)
{
	bool IsUserOnPermissionList = IsUserOnFencePermissionList (sesn_ptr, f_ptr, permission_ptr);

	//default
	if (IsFencePermissionBlackListSemantics(permission_ptr) && !IsUserOnPermissionList)	return true;
	if (IsFencePermissionWhiteListSemantics(permission_ptr) && IsUserOnPermissionList)	return true;

	return false;
}

static inline bool
_IsPermissionTypeInValid(FenceRecord__Permission__Type type)
{
	return (type <= FENCE_RECORD__PERMISSION__TYPE__NONE || type >= FENCE_RECORD__PERMISSION__TYPE__INVALID);
}

static inline int
ValidateFencePermissionCommandFromProto (Session *sesn_ptr, FenceCommand *fence_command_ptr, Fence *f_ptr, FencePermission 	**permission_ptr, FenceRecord__Permission	**fence_record_permission)
{
	void *permission_types [] = {&&perm_none, &&perm_presentation, &&perm_membership, &&perm_messaging, &&perm_attaching, &&perm_calling}; //ALIGN WITH enum FenceRecord.Permission.Type

	if (_IsPermissionTypeInValid(fence_command_ptr->type))	goto *permission_types[FENCE_RECORD__PERMISSION__TYPE__NONE];
//	if (fence_command_ptr->type<=FENCE_RECORD__PERMISSION__TYPE__NONE || fence_command_ptr->type>=FENCE_RECORD__PERMISSION__TYPE__INVALID)	goto *permission_types[FENCE_RECORD__PERMISSION__TYPE__NONE];

	goto *permission_types[fence_command_ptr->type];

	perm_none:
		goto validate_assignments;

	perm_presentation:
		*permission_ptr=FENCE_PERMISSIONS_PRESENTATION_PTR(f_ptr);
		*fence_record_permission	=	fence_command_ptr->fences[0]->presentation;
		goto validate_assignments;

	perm_membership:
		*permission_ptr=FENCE_PERMISSIONS_MEMBERSHIP_PTR(f_ptr);
		*fence_record_permission	=	fence_command_ptr->fences[0]->membership;
		goto validate_assignments;

	perm_messaging:
		*permission_ptr=FENCE_PERMISSIONS_MESSAGING_PTR(f_ptr);
		*fence_record_permission	=	fence_command_ptr->fences[0]->messaging;
		goto validate_assignments;

	perm_attaching:
	*permission_ptr=FENCE_PERMISSIONS_ATTACHING_PTR(f_ptr);
	*fence_record_permission	=	fence_command_ptr->fences[0]->attaching;
	goto validate_assignments;

	perm_calling:
	*permission_ptr=FENCE_PERMISSIONS_CALLING_PTR(f_ptr);
	*fence_record_permission	=	fence_command_ptr->fences[0]->calling;
	goto validate_assignments;

	validate_assignments:
	if (IS_EMPTY(*fence_record_permission)) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', permission_type:'%d'}: ERROR: PERMISSION TYPE NOT SET", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), fence_command_ptr->type);
		return -1;
	}

	if ((*fence_record_permission)->n_users == 0 || IS_EMPTY((*fence_record_permission)->users) || IS_EMPTY(*(*fence_record_permission)->users)) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', permission_type:'%d'}: ERROR: USER RECORD NOT SET", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), fence_command_ptr->type);
		return -1;
	}

	return 0;
}

static inline void
AssignFencePermissionForProto (FencePermission *fence_permission_ptr, FenceRecord *fence_record_ptr, FenceRecord__Permission *fence_record_permission)
{
	void *permission_types [] = {&&perm_none, &&perm_presentation, &&perm_membership, &&perm_messaging, &&perm_attaching, &&perm_calling}; //ALIGN WITH enum FenceRecord.Permission.Type
	goto *permission_types[fence_permission_ptr->type];

	perm_none:
	return;

	perm_presentation:
	fence_record_ptr->presentation = fence_record_permission;
	return;

	perm_membership:
	fence_record_ptr->membership = fence_record_permission;
	return;

	perm_messaging:
	fence_record_ptr->messaging = fence_record_permission;
	return;

	perm_attaching:
	fence_record_ptr->attaching = fence_record_permission;
	return;

	perm_calling:
	fence_record_ptr->calling = fence_record_permission;
	return;

}

//transfer between two protobufs
static inline void
GetFenceRecordPermissionForProto (FenceRecord *fence_record_source, FenceRecord *fence_record_destination, FenceRecord__Permission__Type permission_type)
{
	void *permission_types []={&&perm_none, &&perm_presentation, &&perm_membership, &&perm_messaging, &&perm_attaching, &&perm_calling}; //ALIGN WITH enum FenceRecord.Permission.Type
	goto *permission_types[permission_type];

	perm_none:
	return;

	perm_presentation:
	fence_record_destination->presentation=fence_record_source->presentation;
	return;

	perm_membership:
	fence_record_destination->membership=fence_record_source->membership;
	return;

	perm_messaging:
	fence_record_destination->messaging=fence_record_source->messaging;
	return;

	perm_attaching:
	fence_record_destination->attaching=fence_record_source->attaching;
	return;

	perm_calling:
	fence_record_destination->calling=fence_record_source->calling;
	return;

}

static inline EnumPermissionListSemantics
GetPermissionListSemantics (const FencePermission *permission_ptr)
{
	return (FENCE_PERMISSION_CONFIG_WHITELIST(permission_ptr)==false)?SEMANTICS_BLACKLIST:SEMANTICS_WHITELIST;
}

//default
static inline void
SetFencePermissionBlackListSemantics (Session *sesn_ptr, Fence *f_ptr, FencePermission *permission_ptr)
{
	_InitialiseStorageIfNecessary(sesn_ptr, f_ptr, permission_ptr);
	_InitialiseMembersIfNecessary(sesn_ptr, f_ptr, permission_ptr);

	FENCE_PERMISSION_CONFIG_WHITELIST(permission_ptr)=false;
}

static inline void
SetFencePermissionWhiteListSemantics (Session *sesn_ptr, Fence *f_ptr, FencePermission *permission_ptr)
{
	_InitialiseStorageIfNecessary(sesn_ptr, f_ptr, permission_ptr);
	_InitialiseMembersIfNecessary(sesn_ptr, f_ptr, permission_ptr);

	FENCE_PERMISSION_CONFIG_WHITELIST(permission_ptr)=true;
}

#endif /* SRC_INCLUDE_FENCE_PERMISSION_H_ */
