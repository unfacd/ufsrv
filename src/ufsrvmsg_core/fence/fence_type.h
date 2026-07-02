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

/**
* @file fence_type.h
* @brief Main type definition for Fence, along with convenient member access macros and misc supporting structures.
*/

#ifndef SRC_INCLUDE_FENCE_TYPE_H_
#define SRC_INCLUDE_FENCE_TYPE_H_

#include <uflib/recycler/instance_type.h>
#include <uflib/adt/adt_linkedlist.h>
#include <uflib/adt/adt_queue.h>
#include <ufsrvmsg_core/location/location_type.h>
#include <ufsrvmsg_core/fence/fence_event_type.h>
#include <ufsrvmsg_core/fence/fence_permission_type.h>
#include <session_type.h>
#include <uflib/ufsrvuid_type.h>
#include <zkgroup_utils/zkgroup_masterkey_type.h>

typedef InstanceHolder InstanceHolderForFence;

typedef struct FenceSessionPair {
	bool									flag_fence_local,//to provide additional context to the handling function
												flag_session_local;
	bool									fence_lock_already_owned,
												lock_already_owned;
	unsigned long					fence_type;//use FENCE_ATTRS
	InstanceHolderForFence *instance_f_ptr;
	InstanceHolder *instance_sesn_ptr;
} FenceSessionPair;

struct FenceLocationDescription {
	LocationDescription	fence_location;
	char *display_banner_name;///<short display name
	/*IMPORTANT offsetof(Fence, fence_location.canonical_name) IS HASHED DO NOT CHANGE*/
	char *canonical_name;///<fully qualified name, including display
	char *base_location;///<prefix
	char *banner_name;///<topic list ':' seperated "#xxx:#xxx:#xxx"
};
typedef struct FenceLocationDescription FenceLocationDescription;


//ListEntry type
/*! Main data model representation for a Fence */
 struct Fence {
		time_t	when, ///< creating time for fence
						last_modified;///<all fence events except messages
		time_t time_to_live, ///<duration is seconds for timed fences
						msg_expiry;	///<in millis. current setting for individual msg expiry. Cyrrently this entirly controlled by the client, based on user seeing sent message
		/*IMPORTANT THIS VALUE IS HASHED DONT CHANGE offsetof(Fence, fence_id)*/
		unsigned long fence_id; //also used as key
		unsigned int 	attrs; //check macros prefixed F_ATTR_
		unsigned long max_users; ///< maximum membership size (only \ref Fence.fence_user_sessions_list)
		unsigned long owner_uid; ///< identifier (aka sequence id derived from \ref Fence.ufsrvuid) for owner, typically user who created the fence
		UfsrvUid      ufsrvuid; ///< special encoding of fully id of fence owner
		char *				avatar; ///< unique identifier for fence's official avatar
		char *        description; ///< long format fence blurb settable by users with permission
		unsigned char fence_key[GROUP_MASTER_KEY_SIZE]; ///< unique cryptographic key for the fence stored in raw bytes

    /**
     * Coarse lock for all code changes that affect shared state of the fence.
     */
		struct  {
			unsigned long 				event_id;    ///<unique id for key fence related actions: join leave, msgd topic etc...
			pthread_rwlock_t      rwlock;
			pthread_rwlockattr_t  rwattr;
		}	fence_events;

		/*IMPORTANT offsetof(Fence, fence_location.canonical_name) IS HASHED DON'T CHANGE*/
		FenceLocationDescription	fence_location;

    /**
     * When adding new collection type, ensure \ref EnumFenceCollectionType is updated, accordingly.
     */
    List	fence_user_sessions_list; ///<list of active (member) user sessions attached to the fence
    List	fence_user_sessions_invited_list; ///<list of user sessions on the fence invite list
    List	fence_user_sessions_link_joining_list; ///<list of users who requested to join, but not yet admitted
    List	fence_user_sessions_banned_list; ///<list of users who are on the ban list for the fence

    /**
     * Permission ACL types
     */
		struct {
			FencePermission presentation, ///< ACL for changes display attributes of the fence; eg display name, avatar, description
											membership, ///< ACL for changing membership controls; eg adding/removing other members
											messaging,  ///< ACL for ability to exchange messages within fence
											attaching, ///< ACL for ability to attach media items (ie other than text) within fence
											calling;

		} permissions;
 };
 typedef struct Fence Fence;

 /*! Convenient context, grouping essential fence processing attributes */
typedef struct InstanceContextForFence {
  InstanceHolderForFence *instance_f_ptr;
  Fence *f_ptr;
  bool lock_already_owned, // extra semantic to distinguish if the lock was previously obtained by the same host thread, therefore not necessitating an unlock
       is_locked; // is lock already obtained on fence
} InstanceContextForFence;

 typedef struct FenceRawSessionList {
	 InstanceHolder	**sessions;
	 size_t		sessions_sz;
 }	FenceRawSessionList;

/**
 * Convenient macros for accessing members of \ref Fence structure
 */
#define AS_FENCE(x)                       ((Fence *)(x))
#define FENCE_ID(x)												((x)->fence_id)
#define FENCE_ATTRIBUTES(x)								((x)->attrs)
#define FENCE_TYPE(x)											((x)->type)
#define FENCE_USERS_COUNT(x) 							((x)->fence_user_sessions_list.nEntries)
#define FENCE_CNAME(x)										((x)->fence_location.canonical_name)
#define FENCE_DNAME(x)										((x)->fence_location.display_banner_name)
#define FENCE_BNAME(x)										((x)->fence_location.banner_name)
#define FENCE_BASELOC(x)									((x)->fence_location.base_location)
#define FENCE_LOCATION(x)									((x)->fence_location)
#define FENCE_EID(x)											((x)->fence_events.event_id)
#define FENCE_AVATAR(x)										((x)->avatar)
#define FENCE_OWNER_UID(x)								(x)->owner_uid
#define FENCE_MAX_MEMBERS(x)							(x)->max_users
#define FENCE_LONGITUDE(x)								(x)->fence_location.fence_location.longitude
#define FENCE_LATITUDE(x)									(x)->fence_location.fence_location.latitude
#define FENCE_TTL(x)											(x)->time_to_live
#define FENCE_MSG_EXPIRY(x)								(x)->msg_expiry
#define FENCE_WHEN_CREATED(x)							(x)->when
#define FENCE_WHEN_MODIFIED(x)						(x)->last_modified
#define FENCE_KEY(x)                      (x)->fence_key
#define FENCE_DESCRIPTION(x)              (x)->description

#define FENCE_FENECE_EVENTS_QUEUE(x)	(x()->fence_events.queue)//ok
#define FENCE_FENECE_EVENTS_QUEUE_NENTRIES(x)	((x)->fence_events.queue.nEntries)//ok
#define FENCE_FENECE_EVENTS_COUNTER(x)	((x)->fence_events.event_id)//ok
#define QUEUE_ENTRY_EFENCE_EVENT(x)	(((FenceEvent *)(x)->whatever))
#define QUEUE_ENTRY_EFENCE_EVENT_EID(x)	(((FenceEvent *)(x)->whatever)->eid)

#define FENCE_IN_LIST_ENTRY(x)						((Fence *)(x)->whatever) //input eptr ListEntry *
#define FENCE_SESSION_SERVICE_IN_LIST(x)	((SessionService *)x->whatever)//input eptr ListEntry *
#define FENCE_USER_SESSION_LIST(x)				(x->fence_user_sessions_list)
#define FENCE_USER_SESSION_LIST_SIZE(x)		(x->fence_user_sessions_list.nEntries)
#define FENCE_INVITED_USER_SESSIONS_LIST(x)				(x->fence_user_sessions_invited_list)
#define FENCE_INVITED_USER_SESSIONS_LIST_SIZE(x)	(x->fence_user_sessions_invited_list.nEntries)
#define FENCE_HAS_INVITED_MEMBERS_SIZE_SET(x)	(((x)->fence_user_sessions_invited_list.nEntries) != 0)

#define FENCE_LINK_JOINING_USER_SESSIONS_LIST_PTR(x)	(&((x)->fence_user_sessions_link_joining_list))
#define FENCE_LINK_JOINING_USER_SESSION_LIST(x)				((x)->fence_user_sessions_link_joining_list)
#define FENCE_LINK_JOINING_USER_SESSION_LIST_SIZE(x)	((x)->fence_user_sessions_link_joining_list.nEntries)

#define FENCE_BANNED_USER_SESSIONS_LIST_PTR(x)	(&((x)->fence_user_sessions_banned_list))
#define FENCE_BANNED_USER_SESSION_LIST(x)				((x)->fence_user_sessions_banned_list)
#define FENCE_BANNED_USER_SESSION_LIST_SIZE(x)	((x)->fence_user_sessions_banned_list.nEntries)

#define FENCE_INVITED_LIST_SIZE(x)	(x->fence_user_sessions_invited_list.nEntries)
#define FENCE_INVITED_LIST_EMPTY(x)	(x->fence_user_sessions_invited_list.nEntries == 0)
#define FENCE_INVITED_LIST(x)	(&(x->fence_user_sessions_invited_list))
#define FENCE_INVITED_LISTPTR(x)	(&(x->fence_user_sessions_invited_list))

#define FENCE_SESSIONS_LIST_SIZE(x)	(x->fence_user_sessions_list.nEntries)
#define FENCE_SESSIONS_LIST_EMPTY(x)	(x->fence_user_sessions_list.nEntries==0)
#define FENCE_SESSIONS_LIST(x)	(&(x->fence_user_sessions_list))
#define FENCE_SESSIONS_LIST_PTR(x)	(&(x->fence_user_sessions_list))

#define FENCE_HAS_MAX_MEMBERS_SIZE_SET(x)	!((x)->max_users == 0)
#define FENCE_HAS_REACHED_MAX_MEMBERS_SIZE(x)	((x)->fence_user_sessions_list.nEntries == (x)->max_users)

#define FENCE_IS_INVITE_ONLY(x)	((x)->attrs&F_ATTR_JOINMODE_INVITE_ONLY)

#define FENCE_PERMISSIONS(x)	(x)->permissions
#define FENCE_PERMISSIONS_PRESENTATION(x)	FENCE_PERMISSIONS(x).presentation
#define FENCE_PERMISSIONS_PRESENTATION_PTR(x)	&(FENCE_PERMISSIONS(x).presentation)
#define FENCE_PERMISSIONS_MEMBERSHIP(x)	FENCE_PERMISSIONS(x).membership
#define FENCE_PERMISSIONS_MEMBERSHIP_PTR(x)	&(FENCE_PERMISSIONS(x).membership)
#define FENCE_PERMISSIONS_MESSAGING(x)	FENCE_PERMISSIONS(x).messaging
#define FENCE_PERMISSIONS_MESSAGING_PTR(x)	&(FENCE_PERMISSIONS(x).messaging)
#define FENCE_PERMISSIONS_ATTACHING(x)	FENCE_PERMISSIONS(x).attaching
#define FENCE_PERMISSIONS_ATTACHING_PTR(x)	&(FENCE_PERMISSIONS(x).attaching)
#define FENCE_PERMISSIONS_CALLING(x)	FENCE_PERMISSIONS(x).calling
#define FENCE_PERMISSIONS_CALLING_PTR(x)	&(FENCE_PERMISSIONS(x).calling)

inline static Fence *
FenceOffInstanceHolder(InstanceHolderForFence *instance_holder_ptr) {
  return (Fence *)GetInstance(instance_holder_ptr);
}

#endif /* SRC_INCLUDE_FENCE_TYPE_H_ */
