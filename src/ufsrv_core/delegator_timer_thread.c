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

#ifdef HAVE_CONFIG_H
# include "include/config.h"
#endif

#include <main.h>
#include "uflib/adt/adt_queue.h"
#include "uflib/adt/adt_minheap.h"
#include <sys/timerfd.h>
#include <sys/prctl.h>//for naming thread

#include <delegator_timer_thread.h>
#include <msgqueue_backend/ufsrvmsgqueue.h>
#include <sessions_delegator_type.h>
#include "jobworkers/worker_job_descriptor_type.h"
#include "uflib/scheduled_jobs/scheduled_jobs.h"
#include "ufsrv_core/include/delegator_session_worker_thread.h"

static inline int _SetTimer(int fd, unsigned long timer_timeout);
static void _IteratorCallback(void *stored_time_key, void *stored_job_value, ClientContextData *ctx_data);
static size_t _FireoffOnFirstInsertedJobs(ScheduledJobs *jobs_ptr, WorkersConfigDescriptor *jobworkers_config);

/**
 * @brief Run oneoff callbacks associated with scheduled jobs.
 * @param jobs_ptr
 * @param jobworkers_config
 * @return Count of the number of jobs iterated NOT firedoff jobs count.
 */
static size_t
_FireoffOnFirstInsertedJobs(ScheduledJobs *jobs_ptr, WorkersConfigDescriptor *jobworkers_config)
{
  syslog(LOG_ERR, "%s: Launching ScheduledJobs on-first-insert initialisers...", __func__);

  pthread_mutex_lock(&jobworkers_config->work_queue_mutex);

  size_t  jobs_iterated_sz = heap_foreach(&(jobs_ptr->scheduled_jobs_store), _IteratorCallback, AS_CLIENT_CONTEXT_DATA(jobworkers_config));

  pthread_cond_broadcast(&jobworkers_config->queue_not_empty_cond);
  pthread_mutex_unlock(&jobworkers_config->work_queue_mutex);

  syslog(LOG_ERR, "%s: Iterated over %lu' scheduler-stored jobs for on-first-insert initialisers...", __func__, jobs_iterated_sz);

  return jobs_iterated_sz;
}

/**
 * @brief A callback to be invoked by the iterator on every job traversed in the scheduled jobs store
 * @note this callback is run in the context of traversing jobs store internal structures and rely on specific
 * execution context to be in place; namely the locking of the job workers job queue.
 * @param stored_job_value job stored in scheduler
 * @param ctx_data user-supplied callback context data
 */
static void
_IteratorCallback(__unused void *stored_time_key, void *stored_job_value, ClientContextData *ctx_data)
{
  ScheduledJob *scheduled_job_ptr = (ScheduledJob *)stored_job_value;
  WorkersConfigDescriptor *jobworkers_config = (WorkersConfigDescriptor *)ctx_data;
  UfsrvCommandBroadcast ufsrv_broadcast_dummy	=	{0};

  if (IS_PRESENT(scheduled_job_ptr->job_type_ptr->callbacks.on_first_insert)) {
    QueueEntry *qe_ptr = AddQueue(&(jobworkers_config->ufsrv_work_queue));//remember this is mutex protected

    MessageQueueMsgPayload *mqp_ptr = InitialiseMessageQueueMsgPayload_m(NULL, &ufsrv_broadcast_dummy, (void *)scheduled_job_ptr, 0, DELEGTYPE_TIMER_FIRST_INSERTED);
    qe_ptr->whatever = mqp_ptr;
  }
}

/**
 * A standalone timer thread that interfaces a provided scheduled jobs store. Entries are fetched from the store based on
 * time expiry events.
 * @param ptr must be fed a scheduled jobs store of type ScheduledJobs
 * @return
 */
void *ThreadTimerManager(void *ptr)
{
	if (IS_EMPTY(ptr)) {
		syslog(LOG_ERR, "%s: TERMINATING: NULL data was passed", __func__);
		exit(-1);
	}

	{
		#define MAX_NAME_LEN 15
		char proc_name [MAX_NAME_LEN + 1];	/* Name must be <= 15 characters + a null */

		strncpy(proc_name, "ufTimer", MAX_NAME_LEN);
		proc_name [MAX_NAME_LEN] = 0;
		prctl(PR_SET_NAME, (unsigned long)&proc_name);
		#undef MAX_NAME_LEN
	}

	{
		ScheduledJobs *scheduled_jobs	=	(ScheduledJobs *)ptr;

		const unsigned int _TIMEOUT = _CONFIGDEDAULT_IDLE_TIME_INTERVAL;//100 ms //60;//300; //5 minutes
		int ret;
		__unused int fd = -1;

		fd = timerfd_create(CLOCK_MONOTONIC, 0);
		if (fd <= 0) {
			char error_str[250];
			strerror_r(errno, error_str, 250);

			syslog(LOG_NOTICE, "%s: TERMINATING: COULD NOT create Timer: error: '%s'", __func__, error_str);
			exit(-1);
		}

		ret = fcntl(fd, F_SETFL, O_NONBLOCK);
		if (ret) {
			char error_str[250];
			strerror_r(errno, error_str, 250);
			syslog(LOG_NOTICE, "%s: TERMINATING: COULD NOT control Timer function: error: '%s'", __func__, error_str);
			exit(-1);
		}

		if ((ret = _SetTimer(fd, _TIMEOUT))) {
			char error_str[250];
			strerror_r(errno, error_str, 250);
			syslog(LOG_DEBUG, "%s: TERMINATING: COULD NOT set time duration: error: '%s'", __func__, error_str);
			exit(-1);
		}

		const unsigned 				setsize									=	1;
		int 									epoll_handle						=	epoll_create(setsize);
		UfsrvCommandBroadcast ufsrv_broadcast_dummy		=	{0};
		struct epoll_event 		*timed_event_container	=	malloc(sizeof(struct epoll_event) * setsize);
		WorkersConfigDescriptor *jobworkers_config    = GetJobWorkersConfigurationDescriptor();

    _FireoffOnFirstInsertedJobs(scheduled_jobs, jobworkers_config);

		struct epoll_event 		timed_event							=	{0};
		timed_event.events |= EPOLLIN;
		timed_event.events |= EPOLLET;//edge triggered
		timed_event.data.u64 = 0;
		timed_event.data.fd = fd;

		ret = epoll_ctl(epoll_handle, EPOLL_CTL_ADD, fd, &timed_event);

		while (1) {
			int ready_events_count = epoll_wait(epoll_handle, timed_event_container, setsize, -1);

			if (ready_events_count > 0) {
				unsigned j;

				for (j=0; j<ready_events_count; j++) {
					struct epoll_event *ee_ptr = timed_event_container + (j * sizeof(struct epoll_event));
					if (ee_ptr->events & EPOLLIN) {
						uint64_t exp;
						ssize_t s = read(ee_ptr->data.fd, &exp, sizeof(uint64_t));
						if (s != sizeof(uint64_t)) {
							syslog(LOG_INFO, "%s: ERROR reading from timed_fd", __func__);
							continue;
						}

						ScheduledJobContext job_context = {0};
						if (IS_EMPTY(GetScheduledJob(scheduled_jobs, LOCK_HINT_KEEP_LOCKED, &job_context))) {
#if __UF_FULLDEBUG
						  syslog(LOG_ERR, "%s: ERROR: ScheduledJobsStore IS EMPTY: Did you forget to call 'AddScheduledJob()'?", __func__);
#endif
							pthread_spin_unlock(&(scheduled_jobs->spin_lock));
							continue;
						}

						//>>> ScheduledJobsStore LOCKED
						long long time_now = job_context.scheduled_job_ptr->job_type_ptr->callbacks.on_get_time();
						if (job_context.time_key > time_now) {
							//we are not ready to trigger
							//TODO: RESEED TIME WITH time_now-job_context.time_key if < _TIMEOUT to minimise execution lag
							//syslog(LOG_DEBUG, "%s {type_name:'%s', time_remaining:'%lld millisec}: Scheduled job not ready...", __func__, job_context.scheduled_job_ptr->job_type_ptr->type_name, job_context.time_key-time_now/1000);
							pthread_spin_unlock(&(scheduled_jobs->spin_lock));
							continue;
						}

						GetRemScheduledJob(scheduled_jobs, LOCK_HINT_ALREADY_LOCKED, &job_context);

						//>>> ScheduledJobsStore UNLOCKED

						pthread_mutex_lock(&jobworkers_config->work_queue_mutex);

						QueueEntry *qe_ptr = AddQueue(&(jobworkers_config->ufsrv_work_queue));//remember this is mutex protected

						//WorkerJobSpecs *work_ptr;
						MessageQueueMsgPayload *mqp_ptr;
						mqp_ptr = InitialiseMessageQueueMsgPayload_m(NULL, &ufsrv_broadcast_dummy, (void *)job_context.scheduled_job_ptr, 0, DELEGTYPE_TIMER);
						qe_ptr->whatever = mqp_ptr;//work_ptr;

						pthread_cond_broadcast(&jobworkers_config->queue_not_empty_cond);
						pthread_mutex_unlock(&jobworkers_config->work_queue_mutex);

						if (IsJobPeriodic(job_context.scheduled_job_ptr)) ReInsertScheduledJob(scheduled_jobs, job_context.scheduled_job_ptr);
					} else if ((ee_ptr->events&EPOLLERR) || (ee_ptr->events&EPOLLHUP)) {
						syslog(LOG_INFO, "%s: EPOLL WAIT ERROR...", __func__);
					}
					//nothing
				}
			}
		}

	}//block

}

static inline int
_SetTimer(int fd, unsigned long timer_timeout)
{
	unsigned int nsec;
	unsigned int sec;
	struct itimerspec timeout;

	sec 	= timer_timeout / 1000000;
	nsec 	= (timer_timeout - (sec * 1000000)) * 1000;

	timeout.it_value.tv_sec 		= sec;//_TIMEOUT;
	timeout.it_value.tv_nsec 		= nsec;//0;
	timeout.it_interval.tv_sec 	= sec;//_TIMEOUT; /* recurring */
	timeout.it_interval.tv_nsec = nsec;//0;

	return timerfd_settime(fd, 0, &timeout, NULL);

}
