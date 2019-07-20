/*
 * scheduled_jobs_type.h
 *
 *  Created on: 15Apr.,2017
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_SCHEDULED_JOBS_TYPE_H_
#define SRC_INCLUDE_SCHEDULED_JOBS_TYPE_H_

#include <adt_doubly_linkedlist.h>
#include "adt_minheap_type.h"




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
