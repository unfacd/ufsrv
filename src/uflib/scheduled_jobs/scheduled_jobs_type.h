/**
 * Copyright (C) 2015-2020 unfacd works
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

#ifndef SRC_INCLUDE_SCHEDULED_JOBS_TYPE_H_
#define SRC_INCLUDE_SCHEDULED_JOBS_TYPE_H_

#include <main_types.h>
#include <uflib/adt/adt_doubly_linkedlist.h>
#include <uflib/adt/adt_minheap_type.h>

enum ScheduledJobExecutionFrequencyMode {
	PERIODIC = 0,
	ONEOFF
};

enum ScheduledJobExecutionConcurrencyMode {
	SINGLE_INSTANCE	=	0, //only onse single inctance of the job can exit in the scheduler at any given time
	MULTI_INSTANCE
};

typedef int (*CallbackOnRun)(ClientContextData *);
typedef int (*CallbackOnError)(ClientContextData *);
typedef int (*CallbackOnCompareKeys)(void *, void *);

typedef struct ScheduledJobType {
	const char 	*type_name;
	int 				type_id;
	enum ScheduledJobExecutionFrequencyMode 	frequecy_mode;
	enum ScheduledJobExecutionConcurrencyMode concurrency_mode;
	uint64_t 																	frequency; //in micro seconds

	struct {
		int (*callback_on_compare_keys)(void *, void *);
		int (*callback_on_error)(ClientContextData *);
		int (*callback_on_run)(ClientContextData *);
	} job_ops;

} ScheduledJobType;

typedef struct ScheduledJob {
	ScheduledJobType 	*job_type_ptr;
	long long					when_scheduled;
} ScheduledJob;

typedef struct ScheduledJobs {
	struct {
		size_t 						job_types_size;
		ScheduledJobType 	**job_types_index;
	} job_types_descriptor;
	pthread_spinlock_t spin_lock;
	heap scheduled_jobs_store;
} ScheduledJobs;

//hold the return of stored job from the store
typedef struct ScheduledJobContext {
		long long 		time_key;
		ScheduledJob	*scheduled_job_ptr;
} ScheduledJobContext;


#endif /* SRC_INCLUDE_SCHEDULED_JOBS_TYPE_H_ */
