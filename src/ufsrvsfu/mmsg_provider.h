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


#ifndef UFSRV_MMSG_PROVIDER_H
#define UFSRV_MMSG_PROVIDER_H

#include <uflib/recycler/instance_type.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <uflib/adt/adt_mpsc_queue_type.h>
#include <string.h>
#include <uflib/recycler/recycler_type.h>

typedef InstanceHolder InstanceHolderForSfuMMsg;

InstanceHolderForSfuMMsg *GetMmsg();
size_t GetMmsgBaseVectorSize();
void SfuMMsgReturnToRecycler(InstanceHolderForSfuMMsg *instance_holder_ptr, ContextData *ctx_data_ptr, unsigned long call_flags);
void InitSfuMmsgRecyclerTypePool();
unsigned SfuMmsgPoolTypeNumber();
void SfuMMsgIncrementReference(InstanceHolderForSfuMMsg *instance_descriptor_ptr, int multiples);
void SfuMMsgDecrementReference(InstanceHolderForSfuMMsg *instance_descriptor_ptr, int multiples);
struct mpsc_queue_node * GetQueueNodeReference(void *vector);

#endif //UFSRV_MMSG_PROVIDER_H
