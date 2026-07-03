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

#ifndef UFSRV_FENCE_CONTEXT_DESCRIPTOR_TYPE_H
#define UFSRV_FENCE_CONTEXT_DESCRIPTOR_TYPE_H

#include <session_type.h>
#include <ufsrvmsg_core/fence/fence_state_descriptor_type.h>

typedef void(*CallbackFenceUpdater)(Session *, Fence *, ClientContextData *);

//this is used to separate the wire processing context from the internal model processing
typedef struct FenceContextDescriptor {
    Session 							*sesn_ptr;
    FenceStateDescriptor 	*fence_state_ptr;
    ClientContextData			*context_ptr;
    struct {
        CallbackFenceUpdater	callback_update_fence;
    } callbacks;

}	FenceContextDescriptor;

#endif //UFSRV_FENCE_CONTEXT_DESCRIPTOR_TYPE_H
