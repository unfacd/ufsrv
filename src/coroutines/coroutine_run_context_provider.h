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

#ifndef UFSRV_COROUTINE_RUN_CONTEXT_PROVIDER_H
#define UFSRV_COROUTINE_RUN_CONTEXT_PROVIDER_H

#include <stdbool.h>
#include <coroutines/coroutine_run_context_type.h>
#include <uflib/recycler/instance_type.h>
#include <uflib/recycler/recycler.h>
#include <stddef.h>

typedef InstanceHolder InstanceHolderForCoroutineContext;

#define REF_COUNTED(x) x

inline static CoroutineRunContext *
CoroutineContextOffInstanceHolder(InstanceHolderForCoroutineContext *instance_holder_ptr) {
  return (CoroutineRunContext *)GetInstance(instance_holder_ptr);
}

unsigned CoroutineRunContextPoolTypeNumber();
InstanceHolderForCoroutineContext *GetCoroutineRunContext(bool is_ref_counted);
void InitCoroutineRunContextRecyclerTypePool();
void CoroutineRunContextReturnToRecycler(InstanceHolderForCoroutineContext *instance_holder_ptr, ContextData *ctx_data_ptr, unsigned long call_flags);
void CoroutineRunContextIncrementReference(InstanceHolderForCoroutineContext *instance_descriptor_ptr, int multiples);
void CoroutineRunContextDecrementReference(InstanceHolderForCoroutineContext *instance_descriptor_ptr, int multiples);

#endif //UFSRV_COROUTINE_RUN_CONTEXT_PROVIDER_H
