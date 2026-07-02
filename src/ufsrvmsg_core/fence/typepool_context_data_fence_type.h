/*

 Copyright (c) 2015-2025 unfacd works

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.

 */

#ifndef UFSRV_TYPEPOOL_CONTEXT_DATA_FENCE_TYPE_H
#define UFSRV_TYPEPOOL_CONTEXT_DATA_FENCE_TYPE_H

#include <stdbool.h>
#include <session_type.h>
#include <ufsrvmsg_core/fence/fence_state_descriptor_type.h>


//packaging to facilitate passing of context data
typedef struct TypePoolContextDataFence {
    bool 										is_fence_locked;
    Session									*sesn_ptr;
    union {
        InstanceHolderForFence 								*instance_f_ptr;
        InstanceHolderForFenceStateDescriptor	*instance_fstate_ptr;
    } fence_data;
} TypePoolContextDataFence;


#endif //UFSRV_TYPEPOOL_CONTEXT_DATA_FENCE_TYPE_H
