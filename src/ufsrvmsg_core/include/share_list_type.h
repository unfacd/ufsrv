/**
 * Copyright (C) 2015-2021 unfacd works
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

#ifndef SRC_INCLUDE_SHARE_LIST_TYPE_H_
#define SRC_INCLUDE_SHARE_LIST_TYPE_H_

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <uflib/adt/adt_hopscotch_hashtable.h>

//Align with ShareType in protobuf. Index used for redis storage as per ZRANGE SHL_xxx:<uid>
//Also check static ShareListTypeOps sharelist_types[]
//Also add to function IsUserOnShareList()
//include entry in oid SetShareListTypes(Session *sesn_ptr)
//Also check initialisation state bits in Session's 'struct lists_init_state'
//Also clients use this index when parsing json SharedLists
typedef enum EnumShareListType {
		SHARELIST_PROFILE             = 0, //users with which profile is shared
		SHARELIST_LOCATION            = 1, //uers with which
		SHARELIST_CONTACT             = 2, //
		SHARELIST_NETSTATE            = 3, //AKA presence
    SHARELIST_FRIENDS             = 4,
    SHARELIST_BLOCKED             = 5,
    SHARELIST_READ_RECEIPT        = 6,
    SHARELIST_ACTIVITY_STATE      = 7, //typing state
    SHARELIST_BLOCKED_FENCE       = 8 //list of fences which user has blocked (for invitation)
} EnumShareListType;

typedef enum EnumShareListDirection {
  SHARELIST_DIR_RECIPRICAL  = 0,  //capture both, sharing-with (3rd party) AND shared-with (by 3rd party)
  SHARELIST_DIR_SHARING     = 1,  //sharing-with (3rd part)
  SHARELIST_DIR_SHARED      = 2   //shared-with (with us by 3rd part)

} EnumShareListDirection;

typedef struct ShareList {
	EnumShareListType list_type;
	HopscotchHashtable hashtable;
  EnumShareListDirection share_direction;
} ShareList;


#endif /* SRC_INCLUDE_SHARE_LIST_TYPE_H_ */
