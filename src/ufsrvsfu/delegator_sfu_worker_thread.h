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

#ifndef UFSRV_DELEGATOR_SFU_WORKER_THREAD_H
#define UFSRV_DELEGATOR_SFU_WORKER_THREAD_H

#include <ufsrv_sessions_delegator_type.h>

int GetWorkerDelegatorEventsHandler();
void SetWorkersThreadPoolSetsize(size_t setsize);
void SetListenerWorkersThreadPoolSetsize(size_t setsize);

void RegisterJobWorkersConfigurationDescriptorForSfu(WorkersConfigDescriptor *workers_config_descriptor);
UfsrvSessionsDelegator *InitialiseWorkerDelegator(void);
size_t NotificationPipeDrain(Session *sesn_ptr_ipc, UfsrvSessionsDelegator *sd_ptr, DrainBuffer *drain_buffer);
int EnableIoEventsNotification(int events_handle, InstanceHolderForSession *instance_sesn_ptr);
int DisableIoEventsNotification(int events_handle, InstanceHolderForSession *instance_sesn_ptr);

#endif //UFSRV_DELEGATOR_SFU_WORKER_THREAD_H
