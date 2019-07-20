/**
 * Copyright (C) 2015-2019 unfacd works
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

#ifndef SRC_INCLUDE_DELEGATOR_SESSION_WORKER_THREAD_H_
#define SRC_INCLUDE_DELEGATOR_SESSION_WORKER_THREAD_H_

#include <instance_type.h>
#include <sessions_delegator_type.h>
#include <session.h>

int AddSessionToMonitoredWorkEvents (InstanceHolderForSession *);
int RemoveSessionToMonitoredWorkEvents (InstanceHolderForSession *);
size_t UfsrvGetSessionWorkersSize(void);
 int WorkQueueLock (SessionsDelegator *, int try_flag);
 int WorkQueueUnLock (SessionsDelegator *);

#endif /* SRC_INCLUDE_DELEGATOR_SESSION_WORKER_THREAD_H_ */
