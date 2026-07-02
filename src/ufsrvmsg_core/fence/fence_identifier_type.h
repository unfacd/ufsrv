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

#ifndef UFSRV_FENCE_IDENTIFIER_TYPE_H
#define UFSRV_FENCE_IDENTIFIER_TYPE_H

#include <ufsrvmsg_core/fence/fence_type.h>

//A simple mechanism to specif how a given fence is being identified
typedef struct FenceIdentifier {
    unsigned long	fence_id;
    Fence			*f_ptr;
} FenceIdentifier;


#endif //UFSRV_FENCE_IDENTIFIER_TYPE_H
