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

#ifndef UFSRV_UFSRVWORKER_POOL_DESCRIPTOR_TYPE_H
#define UFSRV_UFSRVWORKER_POOL_DESCRIPTOR_TYPE_H

#include "ufsrvmsg_core/include/ufsrvresult_type.h"
#include "include/sessions_delegator_type.h"
#include "jobworkers/workers_config_descriptor_type.h"

/**
 * Basic interface for defining the the UfsrvWorker jobworker pooling subsystem. One exists per instance of the running server.
 */

struct BaseThreadContext;
struct WorkerPoolDescriptor;

typedef UFSRVResult * (*initialiser)(struct BaseThreadContext *);
typedef UFSRVResult * (*terminator)(struct BaseThreadContext *);
typedef UFSRVResult * (*oneoff_initialiser)(struct WorkerPoolDescriptor *);

typedef struct WorkerPoolDescriptor {
  SessionsDelegator 	*sessions_delegator;
  WorkersConfigDescriptor workers_pool_config_descriptor;
  oneoff_initialiser on_created;//one-off initialiser for the pool setup

  struct {
    initialiser on_instantiated;//per thread initialisation
    terminator on_terminated;//per thread tear-down routine
  } thread_handlers;

} WorkerPoolDescriptor;
#endif //UFSRV_UFSRVWORKER_POOL_DESCRIPTOR_TYPE_H
