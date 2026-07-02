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

#ifndef UFSRV_FENCE_CACHBACKEND_COMMANDS__LITERAL_H
#define UFSRV_FENCE_CACHBACKEND_COMMANDS__LITERAL_H

//INDIVIDUAL FENCE RECORD update enum above every time new attribute is added and observe order
//#define REDIS_CMD_FENCE_RECORD_GET	"HVALS BID:%lu"
#define REDIS_CMD_FENCE_RECORD_GET_ALL	"HMGET BID:%lu id type when uid baseloc cname dname bname lng lat maxusers ttl event_counter avatar expiry list_semantics fence_key"
#define REDIS_CMD_FENCE_RECORD_SET_ALL 	"HMSET BID:%lu id %lu type %u when %lu uid %lu baseloc %s cname %s dname %s  bname %s lng %f lat %f maxusers %d ttl %d event_counter %lu avatar %s expiry %lu list_semantics %d fence_key %b"
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
#define REDIS_CMD_FENCE_USER_RECORD "ZADD MEMBER_USERS_FOR_FENCE:%lu %lu %lu"
#define REDIS_CMD_FENCE_USERS_LIST_REM	"ZREM MEMBER_USERS_FOR_FENCE:%lu %lu"
#define REDIS_CMD_FENCE_USERS_LIST_GET "ZRANGE MEMBER_USERS_FOR_FENCE:%lu 0 -1"
#define REDIS_CMD_MEMBER_USERS_FOR_FENCE_LIST_SIZE "ZCARD MEMBER_USERS_FOR_FENCE:%lu"
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

//User -> InvitedFences* A registry of fences to which user has invitation (recorded in Session)
//ZADD  INVITED_FENCES_FOR_USER:<user id> <timestamp> <bid>:<uid_inviter>
#define REDIS_CMD_INVITED_FENCES_FOR_USER_ADD	"ZADD INVITED_FENCES_FOR_USER:%lu %lu %lu:%lu"
#define REDIS_CMD_INVITED_FENCES_FOR_USER_REM	"ZREM INVITED_FENCES_FOR_USER:%lu %lu:%lu"
#define REDIS_CMD_INVITED_FENCES_FOR_USER_REM_PREBUILT	"ZREM INVITED_FENCES_FOR_USER:%lu %s"
#define REDIS_CMD_INVITED_FENCES_FOR_USER_REM_ALL	"DEL INVITED_FENCES_FOR_USER:%lu"
#define REDIS_CMD_INVITED_FENCES_FOR_USER_GET_ALL	"ZRANGE INVITED_FENCES_FOR_USER:%lu 0 -1"
#define REDIS_CMD_INVITED_FENCES_FOR_USER_GET_ALL_WITHSCORES	"ZRANGE INVITED_FENCES_FOR_USER:%lu 0 -1 WITHSCORES"
#define REDIS_CMD_INVITED_FENCES_FOR_USER_LIST_SIZE	"ZCARD INVITED_FENCES_FOR_USER:%lu"
//---------------------------------------------------------


//FENCE -> InvitedUsers* A registry of users who have invitation to join this fence (recorded in Fence)
//ZADD  INVITED_USERS_FOR_FENCE:<fid> <timestamp> <uid>:<uname>:<uid_inviter>
//add one entry to user lsit of fences
#define REDIS_CMD_INVITED_USERS_FOR_FERNCE_ADD	"ZADD INVITED_USERS_FOR_FENCE:%lu %lu %lu:%s:%lu"
#define REDIS_CMD_INVITED_USERS_FOR_FERNCE_REM	"ZREM INVITED_USERS_FOR_FENCE:%lu %lu:%s:%lu"
#define REDIS_CMD_INVITED_USERS_FOR_FERNCE_REM_ALL	"DEL INVITED_USERS_FOR_FENCE:%lu"
#define REDIS_CMD_INVITED_USERS_FOR_FERNCE_GET_ALL	"ZRANGE INVITED_USERS_FOR_FENCE:%lu 0 -1"
#define REDIS_CMD_INVITED_USERS_FOR_FERNCE_GET_ALL_WITHSCORES	"ZRANGE INVITED_USERS_FOR_FENCE:%lu 0 -1 WITHSCORES"
#define REDIS_CMD_INVITED_USERS_FOR_FENCE_LIST_SIZE	"ZCARD INVITED_USERS_FOR_FENCE:%lu"
//-----------------------------------------------------------------------

//ME -> INVITE USERS
//A registry of users who received fence invitation from this user
#define REDIS_CMD_MY_FENCE_INVITED_USERS_ADD	"ZADD MY_INVITED_USERS:%lu %lu %lu:%lu"
#define REDIS_CMD_MY_FENCE_INVITED_USERS_REM	"ZREM MY_INVITED_USERS:%lu %lu:%lu"
#define REDIS_CMD_MY_FENCE_INVITED_USERS_REM_ALL	"DEL MY_INVITED_USERS:%lu"
#define REDIS_CMD_MY_FENCE_INVITED_USERS_GET_ALL	"ZRANGE MY_INVITED_USERS:%lu 0 -1"
//
//-------------------------------------------------------------------------

//FENCE -> LinkJoiningUsers* A registry of users who have linkjoining invitation to join this fence (recorded in Fence)
//<fid> <timestamp> <uid>
#define REDIS_CMD_LINKJOINING_USERS_FOR_FERNCE_ADD	    "ZADD LINKJOINING_USERS_FOR_FENCE:%lu %lu %lu"
#define REDIS_CMD_LINKJOINING_USERS_FOR_FERNCE_REM	    "ZREM LINKJOINING_USERS_FOR_FENCE:%lu %lu"
#define REDIS_CMD_LINKJOINING_USERS_FOR_FERNCE_REM_ALL	"DEL LINKJOINING_USERS_FOR_FENCE:%lu"
#define REDIS_CMD_LINKJOINING_USERS_FOR_FERNCE_GET_ALL	"ZRANGE LINKJOINING_USERS_FOR_FENCE:%lu 0 -1"
#define REDIS_CMD_LINKJOINING_USERS_FOR_FERNCE_GET_ALL_WITHSCORES	"ZRANGE LINKJOINING_USERS_FOR_FENCE:%lu 0 -1 WITHSCORES"
#define REDIS_CMD_LINKJOINING_USERS_FOR_FENCE_LIST_SIZE	"ZCARD LINKJOINING_USERS_FOR_FENCE:%lu"

//Not use. Not sure if it's a useful thing to support, as at this stage linkjoin is not a personal invitation per se, it's akin to user dropping flyers everywhere
//ME -> INVITED LinkJoining USERS
//A registry of users who received fence linkjoining invitation from this user
#define REDIS_CMD_MY_FENCE_LINKJOINING_USERS_ADD	"ZADD MY_LINKJOINING_USERS:%lu %lu %lu:%lu"
#define REDIS_CMD_MY_FENCE_LINKJOINING_USERS_REM	"ZREM MY_LINKJOINING_USERS:%lu %lu:%lu"
#define REDIS_CMD_MY_FENCE_LINKJOINING_USERS_REM_ALL	"DEL MY_LINKJOINING_USERS:%lu"
#define REDIS_CMD_MY_FENCE_LINKJOINING_USERS_GET_ALL	"ZRANGE MY_LINKJOINING_USERS:%lu 0 -1"
//
//-----------------------------------------------------------------------

//FENCE -> BannedUsers*
//ZADD  BANNED_USERS_FOR_FENCE:<fid> <timestamp> <uid>:<uid_banning_user>
//add one entry to user list of fences
#define REDIS_CMD_BANNED_USERS_FOR_FERNCE_ADD	"ZADD BANNED_USERS_FOR_FENCE:%lu %lu %lu:%lu"
#define REDIS_CMD_BANNED_USERS_FOR_FERNCE_REM	"ZREM BANNED_USERS_FOR_FENCE:%lu %lu:%s:%lu"
#define REDIS_CMD_BANNED_USERS_FOR_FERNCE_REM_ALL	"DEL BANNED_USERS_FOR_FENCE:%lu"
#define REDIS_CMD_BANNED_USERS_FOR_FERNCE_GET_ALL	"ZRANGE BANNED_USERS_FOR_FENCE:%lu 0 -1"
#define REDIS_CMD_BANNED_USERS_FOR_FERNCE_GET_ALL_WITHSCORES	"ZRANGE BANNED_USERS_FOR_FENCE:%lu 0 -1 WITHSCORES"
#define REDIS_CMD_BANNED_USERS_FOR_FENCE_LIST_SIZE	"ZCARD BANNED_USERS_FOR_FENCE:%lu"

//ME -> Banned USERS
//A registry of users who were banned by this user
#define REDIS_CMD_MY_FENCE_BANNED_USERS_ADD	"ZADD MY_BANNED_USERS:%lu %lu %lu:%lu"
#define REDIS_CMD_MY_FENCE_BANNED_USERS_REM	"ZREM MY_BANNED_USERS:%lu %lu:%lu"
#define REDIS_CMD_MY_FENCE_BANNED_USERS_REM_ALL	"DEL MY_BANNED_USERS:%lu"
#define REDIS_CMD_MY_FENCE_BANNED_USERS_GET_ALL	"ZRANGE MY_BANNED_USERS:%lu 0 -1"
//
//-----------------------------------------------------------------------

////ZADD FEVREGO:%bid 						    eid eid:sid:cid:when:oid:tid:%evt:%ev
//#define REDIS_CMD_FENCE_EVENTS "ZADD FEVREGO:%lu %lu %lu:%d:%lu:%lu:%lu:%lu:%d:%s"


#endif //UFSRV_FENCE_CACHBACKEND_COMMANDS__LITERAL_H
