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

#ifdef HAVE_CONFIG_H
# include <config.h>
#include <uflib/utils_time.h>

#endif

#include "timeout_scheduled_job_provider.h"

static ScheduledJobType job_type_session_timeout = {
        .type_name				=	"SfuSession Timeout",
        .type_id					=	0,//gets assigned by type registry
        .frequency_mode		=	ONEOFF,
        .concurrency_mode	=	SINGLE_INSTANCE,
        .frequency				=	_CONFIGDEFAULT_SESSION_TIMEOUT_CHECK_FREQUENCY, //1min in micro sec
        .callbacks					=	{
                .on_compare_keys	= (CallbackOnCompareKeys)NULL,//TimeValueComparator,
                .on_error				=	NULL,
                .on_run					=	(CallbackOnRun)NULL,
                .on_get_time    = GetTimeNowInMillis
        },
};

static ScheduledJobType * __attribute__ ((const))
_GetScheduledJobTypeForSfuSessionTimeout(CallbackOnRun on_run)
{
  job_type_session_timeout.callbacks.on_run = on_run;
  return &job_type_session_timeout;
}

/**
 * 	@brief: Since this job type does not allow concurrent scheduling, ie one job of this type can ever exist in the scheduler
 * 	we can get away with allocating a single static reference.
 * 	@param on_run callback
 * 	@param context_data instance specific data argument to be passed to on_run callback
 */
ScheduledJob *
GetScheduledJobForSfuSessionTimeout(CallbackOnRun on_run, ClientContextData *context_data)
{
  static ScheduledJob job_session_timeout;

  job_session_timeout.job_type_ptr = _GetScheduledJobTypeForSfuSessionTimeout(on_run);
  job_session_timeout.context_data = context_data;//todo temporary static reference -> change to dynamic to each invocatoonis unique to instantiator

  return &job_session_timeout;
}
