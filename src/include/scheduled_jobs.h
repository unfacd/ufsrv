/*
 * scheduled_jobs.h
 *
 *  Created on: 15Apr.,2017
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_SCHEDULED_JOBS_H_
#define SRC_INCLUDE_SCHEDULED_JOBS_H_


#include <scheduled_jobs_type.h>
#include <main_types.h>
#include <ufsrvmsgqueue_type.h>

ScheduledJobs *const GetScheduledJobsStore (void);
void InitScheduledJobsStore (ScheduledJobs *jobs_ptr, size_t count);
int RegisterScheduledJobType (ScheduledJobs *jobs_ptr, ScheduledJobType *job_type_ptr);
void AddScheduledJob (ScheduledJobs *jobs_ptr, ScheduledJob *job_ptr);
ScheduledJobContext *GetScheduledJob (ScheduledJobs *jobs_ptr, bool, ScheduledJobContext *context_ptr_out);
ScheduledJobContext *GetRemScheduledJob (ScheduledJobs *jobs_ptr, bool, ScheduledJobContext *context_ptr_out);
void DestructScheduledJob (ScheduledJob *job_ptr);
bool IsJobPeriodic (ScheduledJob *job_ptr);
bool IsJobTypeNameRegistered (ScheduledJobs *jobs_ptr, const char *type_name);
CallbackOnCompareKeys GetDefaultComparatorForTimeValue (void);
int WorkerThreadScheduledJobExecutor (MessageContextData *context_ptr);
ClientContextData *WorkerThreadScheduledJobExtractArg (MessageQueueMsgPayload *msgqueue_payload_ptr);
int TimeValueComparator (void *key1, void *key2);
void DestructScheduledJobs (ScheduledJobs *jobs_ptr);

#endif /* SRC_INCLUDE_SCHEDULED_JOBS_H_ */
