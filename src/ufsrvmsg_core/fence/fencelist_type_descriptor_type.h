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

#ifndef UFSRV_FENCELIST_TYPE_DESCRIPTOR_TYPE_H
#define UFSRV_FENCELIST_TYPE_DESCRIPTOR_TYPE_H

#include "fence_enums_type.h"
#include <uflib/main_types.h>
#include <session_type.h>
#include <ufsrvmsg_core/fence/fence_state_descriptor_type.h>

typedef void (*OnUserAttachedCallback)(Session *, FenceStateDescriptor *, ClientContextData *);

//Each list type can define custom callbacks for when users are loaded into lists
typedef struct FenceListTypeDescriptor {
    EnumFenceCollectionType list_type;
    struct {
        OnUserAttachedCallback on_user_attached;
    } type_ops;

}	FenceListTypeDescriptor;

#endif //UFSRV_FENCELIST_TYPE_DESCRIPTOR_TYPE_H
