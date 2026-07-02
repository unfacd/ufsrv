/**
 * Copyright (C) 2015-2024 unfacd works
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

#ifndef SRC_INCLUDE_FENCE_STATE_DESCRIPTOR_TYPE_H_
#define SRC_INCLUDE_FENCE_STATE_DESCRIPTOR_TYPE_H_

#include <uflib/recycler/instance_type.h>
#include <ufsrvmsg_core/fence/fence_type.h>
#include <uflib/ufsrvuid_type.h>

/*
 * For each fence joined by user we keep state information that is independent of the underlying Fence.
 * This information is kep in the Session.FenceList
 */

#define FENCESTATE_DANGLING	(0x1<<1)//The Fence still has a reference in the user Session,but not on Fence's user sessions list (which is more authorative)

#define FENCESTATE_IS_SET(x, y)		(x->state&y)
#define FENCESTATE_SET(x, y)		(x->state|=y)
#define FENCESTATE_UNSET(x, y)		(x->state&=~y)

typedef InstanceHolder InstanceHolderForFenceStateDescriptor;

//max 64 boolean prefs
typedef struct FenceUserPrefsBoolean {
		bool 	sticky_geogroup:1, // user is left in the geo fence even as user's geolocation changes
					profile_sharing:1,
          join_request_admin_approval:1; //users joining via a link must be approved a by an admin
}	FenceUserPrefsBoolean;

//This is to facilitate accessing various bit fields by offset, as opposed by literal name. Has the side effect of
//limiting number of bitfields to 64, but that can be overcome if necessary.
typedef struct FenceUserPrefsBooleanStorage {
	union {
		FenceUserPrefsBoolean on_off;
		unsigned long storage;//total of 64 boolean prefs
	};
} FenceUserPrefsBooleanStorage;

typedef struct FenceUserPreferences {
		FenceUserPrefsBoolean	booleans;
}	FenceUserPreferences;

typedef struct FenceStateDescriptor {
	InstanceHolder *instance_holder_fence;

	unsigned long	state;
	UfsrvUid 			invited_by;//user id todo: should UfsrvUid be turned into a pointer (to economise on memory) as this user is mostlikely hashed locally and Sessions's uid can be referenced
	time_t				when_joined,
								when_left,
								when_activity,
								when_invited;
	FenceUserPreferences user_preferences;

} FenceStateDescriptor;

//convenient type to package FenceStateDescriptor context
typedef struct InstanceContextForFenceStateDescriptor {
  InstanceHolderForFenceStateDescriptor *instance_fstate_ptr;
  FenceStateDescriptor *fstate_ptr;
  InstanceContextForFence *instance_f_ptr;
} InstanceContextForFenceStateDescriptor;

#define FENCESTATE_INSTANCE_HOLDER(x)						(x)->instance_holder_fence
#define FENCESTATE_FENCE(x)						((Fence *)GetInstance(FENCESTATE_INSTANCE_HOLDER(x)))

#define FENCESTATE_STATE(x)						x->state
#define FENCESTATE_JOINED(x)					x->when_joined
#define FENCESTATE_LEFT(x)						x->when_left
#define FENCESTATE_INVITED(x)					x->when_invited
#define FENCESTATE_PREFS_PTR(x)				(&((x)->user_preferences))
#define FENCESTATE_PREFS_BOOL(x,y)		(x)->user_preferences.booleans.y
#define IS_SET_FENCE_USERPREF(x,y)		(x)->user_preferences.booleans.y

#endif /* SRC_INCLUDE_FENCE_STATE_DESCRIPTOR_TYPE_H_ */
