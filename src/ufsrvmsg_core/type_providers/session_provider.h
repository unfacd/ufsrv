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

#ifndef UFSRV_SESSION_PROVIDER_H
#define UFSRV_SESSION_PROVIDER_H

#include <uflib/standard_c_includes.h>
#include <uflib/recycler/recycler_type.h>
#include <session_type.h>

int SessionReturnToRecycler(InstanceHolderForSession *instance_sesn_ptr, ContextData *ctx_data_ptr, unsigned long call_falgs);
size_t SessionGetReferenceCount(InstanceHolderForSession *instance_sesn_ptr);
void SessionIncrementReference(InstanceHolderForSession *instance_sesn_ptr, int multiples);
void SessionDecrementReference(InstanceHolderForSession *instance_sesn_ptr, int multiples);
void SessionDecrementReferenceByOne(InstanceHolderForSession *instance_sesn_ptr);
void SessionIncrementReferenceByOne(InstanceHolderForSession *instance_sesn_ptr);
void InitSessionRecyclerTypePool(type_instantiator instantiator);
unsigned SessionPoolTypeNumber();

#endif //UFSRV_SESSION_PROVIDER_H
