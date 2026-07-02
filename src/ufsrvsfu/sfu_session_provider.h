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

#ifndef UFSRV_SFU_SESSION_PROVIDER_H
#define UFSRV_SFU_SESSION_PROVIDER_H

#include <session_type.h>

typedef InstanceHolder InstanceHolderForSfuSession;

int InstantiateSessionForSfu(Session **sesn_ptr_in, unsigned long call_flags, int protocol_id);
void InitSfuSessionRecyclerTypePool();
unsigned SfuSessionPoolTypeNumber();
int SfuSessionReturnToRecycler(InstanceHolderForSfuSession *instance_sesn_ptr, ContextData *ctx_data_ptr, unsigned long call_flags);
void SfuSessionIncrementReference(InstanceHolderForSfuSession *instance_descriptor_ptr, int multiples);
void SfuSessionDecrementReference(InstanceHolderForSfuSession *instance_descriptor_ptr, int multiples);

#endif //UFSRV_SFU_SESSION_PROVIDER_H
