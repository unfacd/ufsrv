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

#ifndef INCLUDE_USER_TYPE_H_
#define INCLUDE_USER_TYPE_H_

#include <instance_type.h>
#include <fence_type.h>
#include <location_type.h>
#include <share_list_type.h>
#include <vector_type.h>
#include <ufsrvuid_type.h>
#include <queue.h>
#include <list.h>

//expects User *
#define USER_ACCOUNTSTATUS_SET(x, y)			(x|=y)
#define USER_ACCOUNTSTATUS_UNSET(x,	y)		(x&=~y)
#define USER_ACCOUNTSTATUS_IS_SET(x ,y)		(x&y)

#define USERACCOUNT_STATUS_ACTIVE 		(0x1<<1)
#define USERACCOUNT_STATUS_SOFTDEACTIVE (0x1<<2)
#define USERACCOUNT_STATUS_WITHCLOUDMSG (0x1<<3)	//supports cloud messaging
#define USERACCOUNT_STATUS_UNVERIFIED 	(0x1<<4)	//rego token was sent, but never acknowledged

//expects User *
#define USER_ATTRIBUTE_SET(x, y)		(SESSION_USER_TTRIBUTES(x)|=y)
#define USER_ATTRIBUTE_UNSET(x,	y)		(SESSION_USER_TTRIBUTES(x)&=~y)
#define USER_ATTRIBUTE_IS_SET(x ,y)		(SESSION_USER_TTRIBUTES(x)&y)

#define USERATTRIBUTE_DEFINES_USERZONE 		(0x1<<1)
#define USERATTRIBUTE_LOCATIONBYSERVER 		(0x1<<2)
#define USERATTRIBUTE_IS_SENTINENT 			(0x1<<3)
#define USERATTRIBUTE_HAS_SENTINENT 		(0x1<<4)


typedef struct Fence Fence;
typedef InstanceHolder InstanceHolderForFence;

typedef struct UserPrefsBoolean {
	bool		 	roaming_mode:1, //enable automatic joining of geo fences
						roaming_mode_wanderer:1,//where roaming is on:automatically leave previous geo fencebefore joing new one
						roaming_mode_conquerer:1,//keep adding new geo fences as they pop up
						roaming_mode_journaler:1,//add the new geo fences but as invitations only
						home_baseloc_new_group:1;//when creating a new group, alway baseloc it relative to user-set home_baseloc
} UserPrefsBoolean;

typedef struct UserPrefsBooleanStorage {
	union {
		UserPrefsBoolean on_off;
		unsigned long storage;//total of 64 boolean prefs
	};
} UserPrefsBooleanStorage;

struct UserDetails {
		unsigned long 	user_id;//IMPORTANT THIS FIELD IS HASHED DONT CHANGE as stored in backend
	    char 			*user_name;//IMPORTANT THIS FILED IS HASHED: DONT CHANGE
      char 			*password;
	    char 		  profile_key[CONFIG_USER_PROFILEKEY_MAX_SIZE]; //max 32 bytes key size
	    unsigned 	verified; //1 or 0
	    unsigned long	attrs;

			UfsrvUid uid;
	    LocationDescription user_location; //current location as communicated by user
	    LocationDescription user_location_by_server;//server guess of user location
	    bool user_location_initialised;//todo: convert to bitset. see utils.c
	    bool user_location_by_server_initialised;
	    bool is_returning; //set when user reinstalls client, facilitating more detailed state sync
	    char *baseloc_prefix; 			//dynamic base loction prefix set as user's location changes
	    char *home_baseloc_prefix;	//fixed default baseloc set by user

	    unsigned long base_fence_local_id; //copy of the user local BaseFence

	    struct {
	    	UserPrefsBoolean on_off;
	    	char *nickname;
	    	char *avatar;
	    	char *e164number;
	    	ShareList sharelist_profile; //who we are sharing our profile with
	    	ShareList sharelist_location;
	    	ShareList sharelist_netstate;
        ShareList sharelist_read_receipt;
        ShareList sharelist_activity_state;
        ShareList sharelist_blocked;
        ShareList sharelist_contacts;//list of users who have allowed their contacts to be shared
	    }	user_preferences;

	};
typedef struct UserDetails UserDetails;

//unsolicited contact is a contact by someone who is not on contacts or block lists
enum UnsolicitedContactAction {
  ACTION_BLOCK      = 0,
  ACTION_ALLOW      = 1
};

#define PREFF_OFFSET_UNDEFINED ((UserPrefsOffsets)-1)

//these offsets correspond with the way they are stored in redis BITMAPS. GETBIT returns range in 8-bit chunks
//these also correspond with user prefs stored in protobuf schema
//r = x%8;
//y = r? x + (a - r) : x;
//to get the 8-bit group required: y/8
#define REDIS_BITFIELDS_ALIGNMENT_FACTOR 8
typedef enum UserPrefsOffsets{
	PREF_ROAMING_MODE=0,
	PREF_RM_WANDERER,
	PREF_RM_CONQUERER,
	PREF_RM_JOURNALER,
	PREF_HOMEBASELOC_NEW_GROUP,//when creating a new group, use home baseloc value for fence baseloc, otherwise baseloc is used. User can always explicitly set the baseloc used with fence creation.
  PREF_RM_5,
	PREF_RM_6,
	PREF_RM_7,
	PREF_RM_8,
	PREF_RM_9,
	PREF_RM_10,
	PREF_RM_11,
	PREF_RM_12,
	PREF_RM_13,
	PREF_RM_14,
	PREF_RM_15,
	PREF_RM_16,
	PREF_RM_17,
	PREF_RM_18,
	PREF_RM_19,
	PREF_RM_20,
	PREF_RM_21,
	PREF_RM_22,
	PREF_RM_23,
	PREF_RM_24,
	PREF_RM_25,
	PREF_RM_26,
	PREF_RM_27,
	PREF_RM_28,
	PREF_RM_29,
	PREF_RM_30,
	PREF_RM_31,
	PREF_RM_32,
	PREF_RM_33,
	PREF_RM_34,
	PREF_RM_35,
	PREF_RM_36,
	PREF_RM_37,
	PREF_RM_38,
	PREF_RM_39,
	PREF_RM_40,
	PREF_RM_41,
	PREF_RM_42,
	PREF_RM_43,
	PREF_RM_44,
	PREF_RM_45,
	PREF_RM_46,
	PREF_RM_47,
	PREF_RM_48,
	PREF_RM_49,
	PREF_RM_50,
	PREF_RM_51,
	PREF_RM_52,
	PREF_RM_53,
	PREF_RM_54,
	PREF_RM_55,
	PREF_RM_56,
	PREF_RM_57,
	PREF_RM_58,
	PREF_RM_59,
	PREF_RM_60,
	PREF_RM_61,
	PREF_RM_62,
	PREF_RM_63,
	//end of predefined booleans offsets

	//IMPORTANT ALWAYS ADD AT THE BOTTOM. enum numbers for sharelists are indexed in redis
	PREF_NICKNAME,
	PREF_AVATAR,
	PREF_SHLIST_PROFILE,//66
	PREF_SHLIST_LOCATION,
	PREF_SHLIST_CONTACTS,
	PREF_SHLIST_NETSTATE,
	PREF_SHLIST_FRIENDS,//70
	PREF_SHLIST_BLOCKED,
  PREF_SHLIST_READ_RECEIPT,
  PREF_SHLIST_ACTIVITY_STATE,
  PREF_SHLIST_UNUSED1,
  PREF_SHLIST_UNUSED2, //75
  PREF_SHLIST_UNUSED3,
  PREF_SHLIST_UNUSED4,
  PREF_SHLIST_UNUSED5,
  PREF_SHLIST_UNUSED6,
  PREF_SHLIST_UNUSED7,//80
  PREF_SHLIST_UNUSED8,
	PREF_E164NUMBER, //82
	PREF_REGO_PIN,
	PREF_BASELOC_ZONE,//84
	PREF_GEOLOC_TRIGGER,
	PREF_UNSOLICITED_CONTACT,//86
	//ADD MORE HERE and define corresponding ops functions in users.c prefs_table[]

	PREF_LAST_ALIGNMENT//to get alignment when reading from redis
} UserPrefsOffsets;

struct User {
	unsigned long 	account_status;
  InstanceHolderForFence  *geofence_last,
									        *geofence_current;
    UserDetails 	user_details;
  };
typedef struct User User;

#endif /* INCLUDE_USER_TYPE_H_ */
