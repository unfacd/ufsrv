/**
 * Copyright (C) 2015-20120 unfacd works
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

#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <pthread.h>

#include <utils_time.h>
#include <uflib/scheduled_jobs/scheduled_jobs.h>
#include <uflib/adt/adt_minheap.h>

#define JOB_INDEX_EXPANSION_THRESHOLD 10

static size_t _ExpandJobTypesIfNecessary (ScheduledJobs *jobs_ptr);

void
InitScheduledJobsStore (ScheduledJobs *jobs_ptr, size_t count)
{
	pthread_spin_init(&(jobs_ptr->spin_lock), 0);
	heap_create (&(jobs_ptr->scheduled_jobs_store), count, compare_long_long_keys);
}

/**
 * 	@brief: Oneoff per job type. Safe to call multiple times on teh same type
 * 	@param job_type_ptr: must be heap allocated or similar by user
 * 	@locks ScheduledJobs *: to prevent concurrent expansion
 */
int
RegisterScheduledJobType (ScheduledJobs *jobs_ptr, ScheduledJobType *job_type_ptr)
{
	pthread_spin_lock(&(jobs_ptr->spin_lock));

	if (IsJobTypeNameRegistered(jobs_ptr, job_type_ptr->type_name)) {
		pthread_spin_unlock(&(jobs_ptr->spin_lock));
		return job_type_ptr->type_id;
	}

	int type_index = _ExpandJobTypesIfNecessary (jobs_ptr);
	jobs_ptr->job_types_descriptor.job_types_index[type_index]	=	job_type_ptr;
	job_type_ptr->type_id																				=	type_index;

	pthread_spin_unlock(&(jobs_ptr->spin_lock));

	syslog(LOG_INFO, "%s {type_id:'%d', type_name:'%s'}: SUCCESS: Initialised ScheduledJob Type...", __func__, job_type_ptr->type_id, job_type_ptr->type_name);

	return type_index;
}

/**
 * @param job_ptr: Must be heap allocated or similar by user
 */
void
AddScheduledJob (ScheduledJobs *jobs_ptr, ScheduledJob *job_ptr)
{
	long long time_now = GetTimeNowInMicros ();

	pthread_spin_lock(&(jobs_ptr->spin_lock));
	job_ptr->when_scheduled = time_now;
	heap_insert(&(jobs_ptr->scheduled_jobs_store), (void *)(time_now + job_ptr->job_type_ptr->frequency), (void *)job_ptr);
	pthread_spin_unlock(&(jobs_ptr->spin_lock));
}

ScheduledJobContext *
GetScheduledJob (ScheduledJobs *jobs_ptr, bool flag_keep_locked, ScheduledJobContext *context_ptr_out)
{
	ScheduledJob 	*job_ptr;
	long long 		time_key;

	if (flag_keep_locked)	pthread_spin_lock(&(jobs_ptr->spin_lock));

	if ((heap_min(&(jobs_ptr->scheduled_jobs_store), (void **) &time_key, (void **) &job_ptr)) == 1) {
		context_ptr_out->scheduled_job_ptr=	job_ptr;
		context_ptr_out->time_key					=	time_key;

		return context_ptr_out;
	}

	return NULL;
}

ScheduledJobContext *
GetRemScheduledJob (ScheduledJobs *jobs_ptr, bool flag_already_locked, ScheduledJobContext *context_ptr_out)
{
	ScheduledJob 	*job_ptr;
	long long 		time_key;

	if (!flag_already_locked)	pthread_spin_lock(&(jobs_ptr->spin_lock));

	if ((heap_delmin(&(jobs_ptr->scheduled_jobs_store), (void **) &time_key, (void **) &job_ptr)) == 1) {
		context_ptr_out->scheduled_job_ptr=	job_ptr;
		context_ptr_out->time_key					=	time_key;

		pthread_spin_unlock(&(jobs_ptr->spin_lock));
		return context_ptr_out;
	}

	pthread_spin_unlock(&(jobs_ptr->spin_lock));

	return NULL;
}

__pure bool
IsJobPeriodic (ScheduledJob *job_ptr)
{
	return (job_ptr->job_type_ptr->frequecy_mode == PERIODIC);
}

__pure bool
IsJobTypeNameRegistered (ScheduledJobs *jobs_ptr, const char *type_name)
{
	bool type_registered = false;

	if (jobs_ptr->job_types_descriptor.job_types_size == 0)	return false;

	for (size_t i=0; i<jobs_ptr->job_types_descriptor.job_types_size; i++) {
		if ((strcmp(type_name, jobs_ptr->job_types_descriptor.job_types_index[i]->type_name) == 0))	return true;
	}

	return type_registered;
}

__attribute__ ((const)) CallbackOnCompareKeys
GetDefaultComparatorForTimeValue (void)
{
	return compare_long_long_keys;
}

int
TimeValueComparator (void *key1, void *key2)
{
	return (*(GetDefaultComparatorForTimeValue()))(key1, key2);
}

int
WorkerThreadScheduledJobExecutor (MessageContextData *context_ptr)
{
	ScheduledJob *job_ptr = (ScheduledJob *)context_ptr;
	return (*job_ptr->job_type_ptr->job_ops.callback_on_run)(job_ptr);
}

/**
 * 	@returns: current available type id slot indexed at 0
 * 	@locked ScheduledJobs *: jobs table must be locked user
 */
static inline size_t
_ExpandJobTypesIfNecessary (ScheduledJobs *jobs_ptr)
{
	if (unlikely((jobs_ptr->job_types_descriptor.job_types_size == 0))) {
		jobs_ptr->job_types_descriptor.job_types_index=calloc(JOB_INDEX_EXPANSION_THRESHOLD, sizeof (ScheduledJobType *));
		return 0;
	}

	int expanded_size = jobs_ptr->job_types_descriptor.job_types_size + 1;

	if (expanded_size < JOB_INDEX_EXPANSION_THRESHOLD) return expanded_size;

	if (expanded_size < (expanded_size / JOB_INDEX_EXPANSION_THRESHOLD) * JOB_INDEX_EXPANSION_THRESHOLD)	return expanded_size;

	ScheduledJobType **types_index_new = calloc(jobs_ptr->job_types_descriptor.job_types_size+JOB_INDEX_EXPANSION_THRESHOLD, sizeof (ScheduledJobType *));
	for (size_t i=0; i<jobs_ptr->job_types_descriptor.job_types_size; i++) {
		types_index_new[i] = jobs_ptr->job_types_descriptor.job_types_index[i];
	}

	free (jobs_ptr->job_types_descriptor.job_types_index);
	jobs_ptr->job_types_descriptor.job_types_index = types_index_new;

	return jobs_ptr->job_types_descriptor.job_types_size;
}

void
DestructScheduledJobs (ScheduledJobs *jobs_ptr)
{
	if (IS_PRESENT(jobs_ptr) && IS_PRESENT(jobs_ptr->job_types_descriptor.job_types_index))
	{
		free (jobs_ptr->job_types_descriptor.job_types_index);
	}

	memset (jobs_ptr, 0, sizeof(ScheduledJobs));
}
