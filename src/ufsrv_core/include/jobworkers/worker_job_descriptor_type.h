/**
 * Copyright (C) 2015-2024 unfacd works
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

#ifndef UFSRV_WORKER_JOB_DESCRIPTOR_TYPE_H
#define UFSRV_WORKER_JOB_DESCRIPTOR_TYPE_H

#include "ufsrvmsg_core/msgqueue_backend/ufsrvmsgqueue_type.h"

//IMPORTANT if you add extra types, add them just before DELEGTYPE_INVALID and ensure consistent order of instantiation in 'static WorkerJobDescriptor worker_job_specs[] = {..}'
enum {
  DELEGTYPE_UNINITIALISED=0,
  DELEGTYPE_USER_CALLBACK, ///> one off user callback action
  DELEGTYPE_TIMER, ///> jobs initiated via periodic timer fireoff
  DELEGTYPE_MSGQUEUE, ///> message quere inter communication jobs
  DELEGTYPE_TIMER_FIRST_INSERTED, ///> jobs initiated through one-off timer on-insert; ie independent of periodic firing off
  DELEGTYPE_INVALID
};

typedef int (*CallbackWorkExecutor)(MessageContextData *);
typedef MessageContextData * (*CallbackWorkArgExtractor)(MessageQueueMsgPayload *);

typedef struct WorkerJobDescriptor {
  unsigned delegator_type;
  void *args;
  CallbackWorkExecutor work_exec;
  CallbackWorkArgExtractor fetch_work_arg;
} WorkerJobDescriptor;

#endif //UFSRV_WORKER_JOB_DESCRIPTOR_TYPE_H
