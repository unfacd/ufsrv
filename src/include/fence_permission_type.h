

#ifndef SRC_INCLUDE_FENCE_PERMISSION_TYPE_H_
#define SRC_INCLUDE_FENCE_PERMISSION_TYPE_H_

#include <adt_hopscotch_hashtable.h>

//Align with protobuf definition 'FenceRecord.Permission.Type'
//IMPORTANT: ENSURE AssignFencePermissionForProto() is updated whenever this enum changes
typedef  enum EnumFencePermissionType {
	PERM_NONE=0,
	PERM_PRESENTATION,
	PERM_MEMBERSHIP,
	PERM_MESSAGING,
	PERM_ATTACHING,
	PERM_CALLING,
	PERM_INVALID

} EnumFencePermissionType;

typedef enum EnumPermissionListSemantics {
	SEMANTICS_NONE=0,
	SEMANTICS_WHITELIST,
	SEMANTICS_BLACKLIST

} EnumPermissionListSemantics;

typedef struct FencePermission {
	struct {
		bool whitelist:1; //default semantic is blacklist (bit is off) (open permission except for blacklisted)
		bool init:1; //storage is lazily allocated by default.
		bool users_loaded:1; //users lazily loaded
	} config;
	EnumFencePermissionType type;
	HopscotchHashtable permitted_users;

} FencePermission;


#define FENCE_PERMISSION_TYPE(x)									(x)->type
#define FENCE_PERMISSION_PERMITTED_USERS(x)				(x)->permitted_users
#define FENCE_PERMISSION_PERMITTED_USERS_PTR(x)		&((x)->permitted_users)
#define FENCE_PERMISSION_CONFIG_INIT(x)						(x)->config.init
#define FENCE_PERMISSION_CONFIG_WHITELIST(x)			(x)->config.whitelist
#define FENCE_PERMISSION_CONFIG_USERS_LOADED(x)		(x)->config.users_loaded

#endif /* SRC_INCLUDE_FENCE_PERMISSION_TYPE_H_ */
