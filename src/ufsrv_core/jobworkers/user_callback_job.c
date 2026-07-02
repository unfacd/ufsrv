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

#include "uflib/standard_c_includes.h"
#include "uflib/main_types.h"
#include "ufsrv_core/include/jobworkers/worker_job_descriptor_type.h"
#include "user_callback_job.h"
#include "ufsrv_core/include/jobworkers/user_callback_job_descriptor_type.h"
#include "uflib/adt/adt_queue.h"

/**
 * Generic job executor which runs arbitrary user define jobs. This is complementary protocol to WorkerJobDescriptor
 * interface, running jobs on worker threads.
 * @param ctx_data UserCallbackJobDescriptor type describing job execution context
 * @return
 */
__attribute__((nonnull(1)))
int WorkerThreadUserCallbackJobExecutor (MessageContextData *ctx_data)
{
  UserCallbackJobDescriptor *callback_descriptor = AS_USER_CALLBACK_JOB_DESCRIPTOR(ctx_data);
  UserCallBackReturnArgs *return_args = callback_descriptor->handler(callback_descriptor->callback_args, &(InstanceHolder){});

  if (!IS_EMPTY(callback_descriptor->on_error_handler)) {
    callback_descriptor->on_error_handler(return_args);
  }

  if (IS_PRESENT(callback_descriptor->finaliser)) callback_descriptor->finaliser(callback_descriptor);

  return 0;
}

#include "include/sessions_delegator_type.h"
#include "msgqueue_backend/ufsrvmsgqueue.h"
#include "ufsrv_core/include/delegator_session_worker_thread.h"

__attribute__((nonnull(1), access(read_only, 1)))
void QueueInUserCallBackJob (UserCallbackJobDescriptor *callback_descriptor)
{
  WorkersConfigDescriptor *jobworkers_config    = GetJobWorkersConfigurationDescriptor();
  pthread_mutex_lock(&jobworkers_config->work_queue_mutex);

  QueueEntry *qe_ptr = AddQueue(&(jobworkers_config->ufsrv_work_queue));//remember this is mutex protected

  //WorkerJobSpecs *work_ptr;
  MessageQueueMsgPayload *mqp_ptr;
  mqp_ptr = InitialiseMessageQueueMsgPayload_m(NULL, &(UfsrvCommandBroadcast){0}, (void *)callback_descriptor, 0, DELEGTYPE_USER_CALLBACK);
  qe_ptr->whatever = mqp_ptr;//work_ptr;

  pthread_cond_broadcast(&jobworkers_config->queue_not_empty_cond);
  pthread_mutex_unlock(&jobworkers_config->work_queue_mutex);
}