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

#ifndef UFSRV_FENCE_ENUMS_TYPE_H
#define UFSRV_FENCE_ENUMS_TYPE_H


/*
 * Types of fences that can be created.
 */
typedef enum EnumFenceNetworkType {
    FENCE_NETWORK_TYPE_GEO = 1, ///< Geographic based fence, not directly created by users.
    FENCE_NETWORK_TYPE_USER,  ///< most common type: fences which are directly created by users.
    FENCE_NETWORK_TYPE_GUARDIAN, ///< Special type of fence for guardian interactions. These fences are mostly content reflectors with no direct interaction by "members".
} EnumFenceNetworkType;

/**
 * Types of item collections that are relevant for Fences. Items mostly represent user sessions.
 */
typedef enum EnumFenceCollectionType {
    MEMBER_FENCES=1, ///< public, regular members
    INVITED_FENCES, ///< members invited directly by regular member, but not yet joined.
    BLOCKED_FENCES, ///< members whore are banned or blocked from interacting with the fence
    LINKJOINED_FENCES, ///<members who are requesting to join via a link, which is yet to be authorised
    LIKED_FENCES,
    FAVED_FENCES,
    ALL_FENCES,
    UNSPECIFIED_FENCE_LISTTYPE
} EnumFenceCollectionType;

/**
 * Convenient grouping of fence collection types, enabling bitwise comparisons. See \ref EnumFenceCollectionType
 * Maintain order as per EnumFenceCollectionType.
 */
typedef enum FenceTypes {
    MEMBER_FENCE			=	0x1U << MEMBER_FENCES,
    INVITED_FENCE			=	0x1U << INVITED_FENCES,
    BLOCKED_FENCE			=	0x1U << BLOCKED_FENCES,
    LINKJOIN_FENCE    = 01U  << LINKJOINED_FENCES,
    LIKED_FENCE				=	0x1U << LIKED_FENCES,
    FAVED_FENCE				=	0x1U << FAVED_FENCES,
    ALL_FENCE_TYPES		=	(0x1U << MEMBER_FENCES | 0x1U<<INVITED_FENCES | 0x1U<<BLOCKED_FENCES | 0x1U<<BLOCKED_FENCES | 0x1U<<LIKED_FENCES | 0x1U<<FAVED_FENCES)

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
    JT_LINK_BASED,
    JT_INVITED,
} EnumFenceJoinType;

typedef enum EnumImpairedFenceMembershipType {
    ImpairedFenceMembershipFence=0,
    ImpairedFenceMembershipSession,
} EnumImpairedFenceMembershipType;

#endif //UFSRV_FENCE_ENUMS_TYPE_H
