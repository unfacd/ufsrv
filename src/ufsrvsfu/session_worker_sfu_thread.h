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

//
// Created by devops on 8/19/21.
//

#ifndef UFSRV_SESSION_WORKER_SFU_THREAD_H
#define UFSRV_SESSION_WORKER_SFU_THREAD_H

#include <jobworkers/base_thread_context_data_type.h>
#include <ufsrv_sessions_delegator_type.h>

typedef void * (*sessionworker_thread_callback)(void *);

sessionworker_thread_callback GetSessionWorkerThreadHandlerSfu(void);
BaseThreadContext *GetBaseThreadContextForSessionWorker(void);
int GetSessionWorkerEventsHandler(void);
int NotifySessionWorker(void);
int WriteIntoSessionWorkerIpcPipe(Session *sesn_ptr);
int LaunchSessionWorkerThreadsSfu(UfsrvSessionsDelegator *sd_ptr);
void AddSessionWorkerScheduledJobForTimeout(ScheduledJob *scheduled_job);
void AddSessionWorkersPipeEndsToMonitoredEvents(UfsrvSessionsDelegator *sd_ptr);

#endif //UFSRV_SESSION_WORKER_SFU_THREAD_H
