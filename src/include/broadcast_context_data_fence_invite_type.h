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

#include <session_type.h>
#include <ufsrvmsg_core/fence/fence_state_descriptor_type.h>

typedef struct BroadcastContextDataFenceInvite {
    Session *sesn_ptr_inviter,
            *sesn_ptr_invited;
    FenceStateDescriptor 	*fence_state_ptr;
} BroadcastContextDataFenceInvite;

#ifndef UFSRV_BROADCAST_CONTEXT_DATA_FENCE_INVITE_TYPE_H
#define UFSRV_BROADCAST_CONTEXT_DATA_FENCE_INVITE_TYPE_H

#endif //UFSRV_BROADCAST_CONTEXT_DATA_FENCE_INVITE_TYPE_H
