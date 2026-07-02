/*

 Copyright (c) 2015-2026 unfacd works

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


#ifndef UFSRV_BASE_THREAD_CONTEXT_DATA_TYPE_H
#define UFSRV_BASE_THREAD_CONTEXT_DATA_TYPE_H

#include "ufsrvresult_type.h"
#include "uflib/adt/adt_hopscotch_hashtable_type.h"
#include "http_request_context_type.h"
#include "uflib/scheduled_jobs/scheduled_jobs_type.h"
#include "ufsrv_core/include/jobworkers/ufsrvworker_pool_descriptor_type.h"

typedef void ThreadContextData; //opaque type for use by user of interface

/**
 * Base data context provided to each Ufsrv JobWork worker thread at thread instantiation time.
 */
typedef struct BaseThreadContext {
  unsigned int                    random_state; /** @brief thread specific random state */
  size_t                          thread_idx; /** @brief fixed serial index number for identifying thread */
  int                             events_handle; /** @brief epoll fd */
  ThreadContextData               *user_thread_context; /** @brief thread worker specific data context */
  WorkerPoolDescriptor            *pool_descriptor; /** @brief specs for the threads pool, enabling inter-thread signalling */

  //convenient grouping of common types
  HopscotchHashtableConfigurable  locked_objects_store;
  HttpRequestContext 	            http_request_context;
  UFSRVResult					            ufsrv_result;
  ScheduledJobs                   scheduled_jobs_store;//thread specific scheduled jobs, mainly timeout runs
} BaseThreadContext;

#endif //UFSRV_BASE_THREAD_CONTEXT_DATA_TYPE_H
