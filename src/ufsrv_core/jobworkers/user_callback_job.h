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

#ifndef UFSRV_USER_CALLBACK_JOB_H
#define UFSRV_USER_CALLBACK_JOB_H

#include "ufsrv_core/include/jobworkers/user_callback_job_descriptor_type.h"

int WorkerThreadUserCallbackJobExecutor(MessageContextData *ctx_data);
void QueueInUserCallBackJob (UserCallbackJobDescriptor *callback_descriptor);

#endif //UFSRV_USER_CALLBACK_JOB_H
