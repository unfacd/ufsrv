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

#include <main.h>
#include <uflib/standard_valgrind_includes.h>
#include <uflib/utils_threads.h>
#include <sys/epoll.h>
#include <uflib/recycler/instance_type.h>
#include <worker_thread_run_context_type.h>
#include <session.h>
#include <session_worker_sfu_thread.h>
#include <jobworkers/base_thread_context_data_type.h>
#include <nportredird.h>
#include <uflib/adt/adt_mpsc_queue.h>
#include <uflib/recycler/recycler.h>
#include <ufsrvmsg_core/protocol/protocol_type.h>
#include "mmsg_provider.h"
#include "sfu_session_provider.h"
#include "delegator_sfu_worker_thread.h"

extern __thread BaseThreadContext *base_thread_context;
extern ufsrv *const 						masterptr;
extern  const  Protocol *const 	protocols_registry_ptr;
static __thread UfsrvSessionsDelegator *ufsrv_sessions_delegator;

static void *_ThreadSfuSessionWorker(void *ptr);
static long long _GetEpollTimeout(void);
static int _BuildSessionWorkersToWorkerDelegatorQueues(UfsrvSessionsDelegator *sd_ptr);
static int _BuildWorkerDelegatorToSessionWorkerPipes(UfsrvSessionsDelegator *sd_ptr);
static int _BuildSessionWorkerToWorkerDelegatorPipes(UfsrvSessionsDelegator *sd_ptr);
static InstanceHolderForSession *_BuildWorkerDelegatorToSessionWorkerPipe(UfsrvSessionsDelegator *sd_ptr);
static InstanceHolderForSession *_BuildSessionWorkerToWorkDelegatorPipe(UfsrvSessionsDelegator *sd_ptr);
static int _BuildSessionWorkerThreads(UfsrvSessionsDelegator *sd_ptr);

sessionworker_thread_callback
GetSessionWorkerThreadHandlerSfu(void)
{
  return &_ThreadSfuSessionWorker;
}

BaseThreadContext * __attribute__((const))
GetBaseThreadContextForSessionWorker(void)
{
  return base_thread_context;

}

/**
 * @brief Prepare the context for launching session workers
 * @param sd_ptr
 * @return
 */
int __attribute__((nonnull(1)))
LaunchSessionWorkerThreadsSfu(UfsrvSessionsDelegator *sd_ptr)
{
  int setsize = sd_ptr->session_workers_thread_pool.setsize;
  if (setsize <= 0) {
    syslog(LOG_ERR, "%s: FATAL: SETSIZE FOR SESSION WORKER THREADS UNDEFINED (setsize: '%d')...", __func__, setsize);
    return -1;
  }

  if (IS_EMPTY(sd_ptr->session_workers_thread_pool.work_queues)) {
    _BuildSessionWorkersToWorkerDelegatorQueues(sd_ptr);
  }

  if (IS_EMPTY(sd_ptr->session_workers_thread_pool.to_session_worker_ipc)) {
    _BuildWorkerDelegatorToSessionWorkerPipes(sd_ptr);
  }

  if (IS_EMPTY(sd_ptr->session_workers_thread_pool.to_worker_delegator_ipc)) {
    _BuildSessionWorkerToWorkerDelegatorPipes(sd_ptr);
  }

  if (IS_EMPTY(sd_ptr->session_workers_thread_pool.workers)) {
    _BuildSessionWorkerThreads(sd_ptr);
  }

  WorkerThreadRunContext *thread_run_contexts = calloc(setsize, sizeof(WorkerThreadRunContext));
  BaseThreadContext  *mempool_base_thread_context = calloc(setsize, sizeof(BaseThreadContext));

#if __VALGRIND_DRD
  VALGRIND_CREATE_MEMPOOL(thread_run_contexts, 0, 1);
  VALGRIND_MAKE_MEM_NOACCESS(thread_run_contexts, setsize * sizeof(WorkerThreadRunContext));

  VALGRIND_CREATE_MEMPOOL(mempool_base_thread_context, 0, 1);
  VALGRIND_MAKE_MEM_NOACCESS(mempool_base_thread_context, sizeof(BaseThreadContext) * setsize);
#endif

  WorkerThreadRunContext *thread_run_context;

  for (size_t i=0; i!=setsize; i++) {
#if __VALGRIND_DRD
    VALGRIND_MEMPOOL_ALLOC(thread_run_contexts, (char *)thread_run_contexts + (i * sizeof(WorkerThreadRunContext)), sizeof(WorkerThreadRunContext));
    VALGRIND_MEMPOOL_ALLOC(sd_ptr->session_workers_thread_pool.workers, &(sd_ptr->session_workers_thread_pool.workers[i]), sizeof(pthread_t));
    VALGRIND_MEMPOOL_ALLOC(mempool_base_thread_context, &(mempool_base_thread_context[i]), sizeof(BaseThreadContext));
#endif

    thread_run_context = (WorkerThreadRunContext *)((char *)thread_run_contexts + (i * sizeof(WorkerThreadRunContext)));
    thread_run_context->idx                 = i;
    thread_run_context->ipc_pipe            = sd_ptr->session_workers_thread_pool.to_session_worker_ipc[i];
    thread_run_context->queue               = sd_ptr->session_workers_thread_pool.work_queues[i];
    thread_run_context->base_thread_context = &(mempool_base_thread_context[i]);
    thread_run_context->drain_Buffer        = (DrainBuffer *)((char *)sd_ptr->session_workers_thread_pool.drain_buffer_session_worker_ipc + (sizeof(DrainBuffer) * i));
    thread_run_context->sessions_delegator  = sd_ptr;

    int result = pthread_create(&(sd_ptr->session_workers_thread_pool.workers[i]), NULL, GetSessionWorkerThreadHandlerSfu(), thread_run_context);
    if (result != 0) {
      syslog(LOG_ERR, "%s: FATAL: COULD NOT spawn Session Worker Threads (requested: '%d', iteration: '%lu'): terminating...", __func__, setsize, i);
      exit (-1);
    }
  }

  //  statsd_gauge(sd_ptr->instrumentation_backend_ptr, "worker.work.handshake_failed", 0);

  syslog(LOG_ERR, "%s (queues:'%p'): SUCCESSFULLY spawned '%d' Session Worker Threads...", __func__, sd_ptr->session_workers_thread_pool.work_queues, setsize);

  return 0;
}

/**
 * @brief Convenience function to add standard timeout checker for actively monitored sessions.
 * The job parameters (e/g frequency) is assumed fixed for all jobs of this type. If changed, it will be changed for
 * all future invocations. The @param scheduled_job can be invocation specific and will be passed back at on_run callback.
 * @param scheduled_job user provided
 */
void
AddSessionWorkerScheduledJobForTimeout(ScheduledJob *scheduled_job)
{
  InsertScheduledJob(&base_thread_context->scheduled_jobs_store, scheduled_job);
  NotifySessionWorker();
}

/**
 * @brief Return epoll handler associated with this thread.
 * @return
 */
int __attribute__((const))
GetSessionWorkerEventsHandler(void)
{
  return base_thread_context->events_handle;
}

/**
 * @brief Force SessionWorker to rerun its events loop. This will invoke current thread only.
 * @return
 */
int
NotifySessionWorker(void)
{
  int thread_idx = base_thread_context->thread_idx;
  Session *sesn_ptr_ipc = SessionOffInstanceHolder(ufsrv_sessions_delegator->session_workers_thread_pool.to_session_worker_ipc[thread_idx]);
  if (WriteIntoSessionWorkerIpcPipe(sesn_ptr_ipc) > 0)
    ;

  return -1;
}


/**
 * @brief Signal session worker of availability of work request by writing to its end of the ipc pipe.
 * @param sesn_ptr pre-allocated session holding pipe fd's
 * @return on success amount of bytes written (1)
 */
int
WriteIntoSessionWorkerIpcPipe(Session *sesn_ptr)
{
  #define PIPE_GO_MSG "G"
  const char *marshal_msg = PIPE_GO_MSG;
  ssize_t actual_written_size = 0;

  while (actual_written_size < (sizeof(PIPE_GO_MSG) - 1)) {
    ssize_t written = write(WORK_DELEGATOR_PIPE_WRITE_END(sesn_ptr), marshal_msg + actual_written_size, (sizeof(PIPE_GO_MSG) - 1) - actual_written_size);
    if (written < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        //TODO: we don't really care so long as it is not pipe error connections will just pile up and eventually delegator wil pick it up...
        syslog (LOG_ERR, LOGSTR_MAINLISTENER_PIPE_WRITE_BLOCKING,  __func__, errno, LOGCODE_MAINLISTENER_PIPE_WRITE_BLOCKING);
        return -2;
      }

      syslog (LOG_ERR, LOGSTR_MAINLISTENER_PIPE_WRITE_ERROR, __func__, errno, LOGCODE_MAINLISTENER_PIPE_WRITE_ERROR);
      return -3;
    }

    //nonerror
    actual_written_size += written;
  }

  return actual_written_size;
}

/**
 * @brief calculate the seeding timeout value going into epoll_wait()
 * @param job_context_provided User allocated job descriptor. If job's time is up, job details will be passed into it.
 * Must be initialised to empty values by provider.
 * @return Designed so returned value is aligned with epoll_wait timeour param semantics:
 * timeout > 0 in milli seconds
 * '0' timeout expired for one or more jobs.
 * '-1' No timeout
 */
static long long
_GetEpollTimeout(void)
{
  long long timeout = -1;
  ScheduledJobContext job_context = {0};
  ScheduledJobs *scheduled_jobs = &base_thread_context->scheduled_jobs_store;
  long long time_now = GetTimeNowInMillis();

  if (IS_EMPTY(GetScheduledJob(scheduled_jobs, LOCK_HINT_NONE, &job_context))) {
#if __UF_FULLDEBUG
    syslog(LOG_ERR, "%s: ERROR: ScheduledJobsStore IS EMPTY: Did you forget to call 'AddScheduledJob()'?", __func__);
#endif
    goto timeout_return_value;
  }

  if (job_context.time_key > time_now) {
#ifdef __UF_TESTING
    syslog(LOG_DEBUG, "%s {type_name:'%s', time_key:'%lld', time_now:'%lld', time_remaining:'%lld milli sec}: Scheduled job not ready...", __func__, job_context.scheduled_job_ptr->job_type_ptr->type_name, job_context.time_key, time_now, job_context.time_key - time_now);
#endif
    timeout = job_context.time_key - time_now;
    goto timeout_return_value;
  }

  timeout = job_context.time_key - time_now;//ideally '0', when in minus, it means we drifted, as we took too long to check
#ifdef __UF_TESTING
  syslog(LOG_DEBUG, "%s {type_name:'%s', drift_time(minus sign):'%lld milli-sec}: Scheduled job ready", __func__, job_context.scheduled_job_ptr->job_type_ptr->type_name, timeout);
#endif

  timeout = 0;

  timeout_return_value:
  return timeout;

}

static size_t _RunTimeoutJobsIfNecessary(ScheduledJobs *scheduled_jobs);

/**
 * @brief Retrieve and run jobs that have reached their set timeout value
 * @param collection User allocated collection for saving timeout jobs. Should be allocated with currently known active jobs.
 * User must pass initialised size.
 * May enlarge store if more jobs found than allocated.
 * @return size of active jobs in the store regardless of how many were processed. This serves as a hint as the user may have measered a different value due
 * time pass between locking/unlocking
 */
static size_t __attribute__((nonnull(1)))
_RetrieveTimeoutJobs(CollectionDescriptor *collection)
{
  long long timeout = -1;
  ScheduledJobs *scheduled_jobs = &base_thread_context->scheduled_jobs_store;
  long long time_now = GetTimeNowInMicros();

  size_t active_jobs_setsize = GetScheduleJobsSetsize(scheduled_jobs, LOCK_HINT_KEEP_LOCKED);
  if (active_jobs_setsize == 0) {
    collection->collection_sz = 0;
    pthread_spin_unlock(&(scheduled_jobs->spin_lock));
    return 0;
  }

  if (collection->collection_sz < active_jobs_setsize) {
    //todo: jobs store could have been added to by another thread since user allocated collection based on earlier reading of active jobs in store, hence why we return measured active, allowing the user to rerun
    syslog(LOG_WARNING, "%s {active_sz:'%lu', collection_sz:'%lu'}: COLLECTION UNDER SIZE FOR AMOUNT  OF JOBS IN STORE", __func__, active_jobs_setsize, collection->collection_sz);
  }

  collection->collection_sz = 0;
  size_t idx = 1;
  ScheduledJobContext *job_context = NULL;
  do {
    job_context = (ScheduledJobContext *)(char *)collection->collection + ((idx - 1) * collection->collection_base_offset);
    GetScheduledJob(scheduled_jobs, LOCK_HINT_ALREADY_LOCKED|LOCK_HINT_KEEP_LOCKED, job_context);
    if (job_context->time_key <= time_now) {
      GetRemScheduledJob(scheduled_jobs, LOCK_HINT_ALREADY_LOCKED|LOCK_HINT_KEEP_LOCKED, job_context);
      collection->collection_sz = idx; //refresh value
    } else {
      job_context = NULL;//that will mark the header of the slot as NULL
      break;//terminate, as we reached a future-scheduled job
    }
  } while (++idx < active_jobs_setsize);

  size_t in_queue_job_sz = GetScheduleJobsSetsize(scheduled_jobs, LOCK_HINT_ALREADY_LOCKED|LOCK_HINT_KEEP_LOCKED);
  pthread_spin_unlock(&(scheduled_jobs->spin_lock));

#ifdef __UF_TESTING
  syslog(LOG_DEBUG, "%s {loop_idx:'%lu', active_sz:'%lu', in_queue_sz:'%lu'}: Processed timeout jobs", __func__, idx, active_jobs_setsize, in_queue_job_sz);
#endif

  return active_jobs_setsize;
}

/**
 *
 * @param collection iterateable of type ScheduledJobContext, containing jobs jobs ready to run. Pre-allocated by
 * called and no need to reclaim.
 * @return collection size
 */
static size_t __attribute__((nonnull(1)))
_RunTimeoutJobs(CollectionDescriptor *collection)
{
  for (size_t i = 0; i < collection->collection_sz; i++) {
    ScheduledJobContext *scheduled_job = (ScheduledJobContext *)(char *)collection->collection + (i * collection->collection_base_offset);
    if (IS_PRESENT(scheduled_job)) {
      scheduled_job->scheduled_job_ptr->job_type_ptr->callbacks.on_run(AS_JOB_CONTEXT(scheduled_job->scheduled_job_ptr), scheduled_job->scheduled_job_ptr->context_data);
    } else {
      syslog(LOG_NOTICE, "%s {collection_sz:'%lu', iteration_i:'%lu'}: ScheduledJobContext was NULL in collection", __func__, collection->collection_sz, i);
    }
  }

  return collection->collection_sz;
}

/**
 * @brief Check for timeout jobs owned by the worker
 * @param scheduled_jobs Threads own scheduled jobs
 * @return number of jobs actually ran
 */
static size_t __attribute__((nonnull(1)))
_RunTimeoutJobsIfNecessary(ScheduledJobs *scheduled_jobs)
{
  size_t active_jobs_setsize_returned = 0;
  size_t active_jobs_setsize = GetScheduleJobsSetsize(scheduled_jobs, LOCK_HINT_NONE);
  if (active_jobs_setsize > 0) {
    ScheduledJobContext active_jobs[active_jobs_setsize]; memset(active_jobs, '\0', sizeof active_jobs);//note: used as memory pool chunks
    CollectionDescriptor jobs_collection = {.collection_sz = active_jobs_setsize, .collection = AS_COLLECTION_TYPE(active_jobs), .collection_base_offset = sizeof(ScheduledJobContext)};
    active_jobs_setsize_returned = _RetrieveTimeoutJobs(&jobs_collection);
    _RunTimeoutJobs(&jobs_collection);
  }

  return active_jobs_setsize_returned;
}

/**
 * @brief Enable polling on the uni-directional pipe so I/O session work notifications from Worker-Delegator can be intercepted.
 * @param epoll_handle pre-created epoll handle specific to the SessionWorker thread
 * @param instance_sesn_ptr_ipc InstanceHolder for Session's fd representing the reader end of the IPC pipe
 * @return
 */
static int
_EnablePollingForWorkerDelegatorNotification(int epoll_handle, InstanceHolderForSession *instance_sesn_ptr_ipc)
{
  struct epoll_event epoll_event = {0};
  epoll_event.events = EPOLLIN;//|EPOLLET;//default line-trigerred
  epoll_event.data.ptr = instance_sesn_ptr_ipc;

  if (epoll_ctl(epoll_handle, EPOLL_CTL_ADD, SessionOffInstanceHolder(instance_sesn_ptr_ipc)->dsptr->sock, &epoll_event) == -1) {//PIPE READER END
    syslog(LOG_ERR, "%s: COULD NOT add pipe connection to events loop: WILL NOT be able to process new connections: errno='%d'", __func__, errno);
  } else {
    syslog(LOG_ERR, "%s {o:'%p', fd:'%d'}: Added Worker-Delegator->SessionWorker IPC pipe to monitored events...", __func__, SessionOffInstanceHolder(instance_sesn_ptr_ipc), SessionOffInstanceHolder(instance_sesn_ptr_ipc)->dsptr->sock);

    return 0;
  }

  return -1;
}

static void  _ProcessSessionHandshake(WorkerThreadRunContext *thread_context, InstanceContextForSession *instance_context);
static void  _HandleSessionWorkerMessage(WorkerThreadRunContext *thread_context, InstanceContextForSession *instance_context);
static void _HandleWorkerDelegatorNotification(WorkerThreadRunContext *thread_run_context, Session *sesn_ptr);

static InstanceHolderForSession *_GenerateSignalFd(sigset_t *mask);
static int _AddSignalFdToMonitoredEvents(int epoll_handle, InstanceHolderForSession *session_signalfd);

#include <sys/types.h>
#include <signal.h>
#include <sys/signalfd.h>

/**
 * @brief Setup the signal masking for the thread and return a signal fd that can be plugged int epoll.
 * @return
 */
static InstanceHolderForSession *
_GenerateSignalFd(sigset_t *mask)
{
  sigemptyset(mask);
  sigaddset(mask, SIGTERM);
  sigaddset(mask, SIGINT);
  int r = sigprocmask(SIG_BLOCK, mask, NULL);//block signal default action momentarily
  if (r == -1) {
    syslog(LOG_ERR, "%s (errno:'%d'): ERROR COULD NOT PROCESS SIGNAL MASK FOR THREAD", __func__ , errno);
    return NULL;
  }

  int sig_fd = 0;
  if ((sig_fd = signalfd(-1, mask, O_NONBLOCK)) < 0) {
    syslog(LOG_ERR, "%s (errno:'%d'): ERROR COULD NOT GENERATE SIGNAL FD", __func__ , errno);
    return NULL;
  }

  Socket 	*ss_ptr = calloc(1, (sizeof(Socket)));;
  Session	*sesn_ptr	=	NULL;

  if (!(sesn_ptr = InstantiateSessionObject(ss_ptr, NULL, 0, -1))) {
    syslog(LOG_ERR, "%s: ERROR: COULD NOT initialise SIGNAL FD SESSION", __func__);
    free(ss_ptr);
    close(sig_fd);
    return NULL;
  }

  ss_ptr->type = SOCK_SIGNALFD; //written to by delegator
  ss_ptr->sock = sig_fd;
  strcpy(ss_ptr->address, "signal_fd.session_worker.localhost");

  InstanceHolderForSession *instance_sesn_ptr = calloc(1, sizeof(InstanceHolderForSession));
  SetInstance(instance_sesn_ptr, sesn_ptr);

  return instance_sesn_ptr;
}

static int
_AddSignalFdToMonitoredEvents(int epoll_handle, InstanceHolderForSession *session_signal_fd)
{
  struct epoll_event epoll_event = {0};
  epoll_event.events = EPOLLIN;
  epoll_event.data.ptr = session_signal_fd;

  Session *session = SessionOffInstanceHolder(session_signal_fd);

  if (epoll_ctl(epoll_handle, EPOLL_CTL_ADD, session->ssptr->sock, &epoll_event) == -1) {
    syslog(LOG_ERR, "%s {o:'%p', errno:'%d'}: COULD NOT ADD SIGNAL FD to events loop", __func__, session, errno);
    return -1;
  } else {
    syslog(LOG_ERR, "%s {o:'%p', fd:'%d'}: SignalFd: Added signal fd to monitored events...", __func__, session, session->ssptr->sock);
  }

  return 0;
}

static int
_HandleSignalNotification(InstanceHolderForSession *session_signalfd)
{
  int signal_fd = SessionOffInstanceHolder(session_signalfd)->ssptr->sock;
  struct signalfd_siginfo  siginfo;

  //more could be still in there. Rely on epoll level-triggering to push us back here
  ssize_t status = read(signal_fd, &siginfo, sizeof(siginfo));
  if(status != sizeof(siginfo)) {
    syslog(LOG_ERR, "%s (signal_fd:'%d', errno:'%d', read_sz:'%ld'): ERROR COULD READ SIGNAL INFO", __func__, signal_fd, errno, status);
    return -1;
  }
  if (siginfo.ssi_signo == SIGINT) {
    syslog(LOG_ERR, "%s (signal_fd:'%d', signo:'%d'): WARNING RECEIVED SIGINT SIGNAL", __func__, signal_fd, siginfo.ssi_signo);
  } else if(siginfo.ssi_signo == SIGTERM) {
    syslog(LOG_ERR, "%s (signal_fd:'%d', signo:'%d'): WARNING RECEIVED SIGTERM SIGNAL", __func__, signal_fd, siginfo.ssi_signo);
  } else {
    syslog(LOG_ERR, "%s (signal_fd:'%d', signo:'%d'): WARNING RECEIVED UNMONITORED SIGNAL", __func__, signal_fd, siginfo.ssi_signo);
    return siginfo.ssi_signo;
  }

  return 0;
}

/**
 * @brief Main thread execution run
 * @param ptr
 * @return
 */
static void * __attribute__((nonnull(1)))
_ThreadSfuSessionWorker(void *ptr)
{
#define MAX_FD_SETSIZE 10 //Thread only allowed 10 thread-specific fd to monitor
  WorkerThreadRunContext *thread_run_context = ptr;

  SetThreadName("SessionWorker");

  struct epoll_event *events_store = calloc(MAX_FD_SETSIZE, sizeof(struct epoll_event));
  int epoll_handle = epoll_create1(0);

  sigset_t mask;
  InstanceHolderForSession *session_instance_signalfd = _GenerateSignalFd(&mask);
  _AddSignalFdToMonitoredEvents(epoll_handle, session_instance_signalfd);

  base_thread_context = thread_run_context->base_thread_context;
  base_thread_context->thread_idx = thread_run_context->idx;
  ScheduledJobs *scheduled_jobs = &base_thread_context->scheduled_jobs_store;
  base_thread_context->events_handle = epoll_handle;
  ufsrv_sessions_delegator = thread_run_context->sessions_delegator;

  InitUfsrvScheduledJobsStore(scheduled_jobs, 0, NULL);

  _EnablePollingForWorkerDelegatorNotification(epoll_handle, thread_run_context->ipc_pipe);

  syslog(LOG_DEBUG, "%s (pid:'%lu', epoll_fd:'%d', run_ctx:'%p', base_th:'%p', th_idx:'%ld') Entering main loop...", __func__,  pthread_self(), epoll_handle, thread_run_context, base_thread_context, thread_run_context->idx);

  for (;;) {
    long long epoll_timeout = -1;
    long long time_now = GetTimeNowInMillis();
    InstanceContextForSession instance_context = {0};

    epoll_timeout = _GetEpollTimeout();

    int ready_events_count = epoll_pwait(epoll_handle, events_store, MAX_FD_SETSIZE, epoll_timeout, &mask);
    if (ready_events_count > 0) {
      for (unsigned j=0; j<ready_events_count; j++) {//read_ready_events
        struct epoll_event *ee_ptr = events_store + (j * sizeof(struct epoll_event));
        AS_INSTANCE_HOLDER_FOR_SESSION(instance_sesn_ptr, ee_ptr->data.ptr);

        if (IS_PRESENT(instance_sesn_ptr)) {
          Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
          sesn_ptr->event_descriptor = (void *)ee_ptr;//retrieve event state by workers. This value can only be written into by this thread.
          if (sesn_ptr->ssptr->type == SOCK_PIPEWRITER) {//IPC pipe signalling events by delegator or some other process
            if (SESNSTATUS_IS_SET(sesn_ptr->stat, SESNSTATUS_IPC)) {//delegator-worker ipc signalling.
              _HandleWorkerDelegatorNotification(thread_run_context, sesn_ptr);
            }
          } else if (sesn_ptr->ssptr->type == SOCK_SIGNALFD) {//unix signals
            _HandleSignalNotification(session_instance_signalfd);
          } else {//regular socket IO monitored by SessionWorker
            _HandleSessionWorkerMessage(thread_run_context, &(InstanceContextForSession){.instance_sesn_ptr=instance_sesn_ptr, .sesn_ptr=sesn_ptr});//read I/O session
          }
        } else {
          syslog(LOG_ERR, "%s (pid:'%lu', th_idx:'%lu', th_ctx:'%p', instance_sesn:'%p): SEVERE ERROR: INSTANCE HOLDER WITH EMPTY SESSION OBJECT", __func__, pthread_self(), thread_run_context->idx, thread_run_context, instance_sesn_ptr);
        }
      }
    } else if (ready_events_count == 0) {//timeout
      _RunTimeoutJobsIfNecessary(scheduled_jobs);
    } else {
      if (errno != EINTR) syslog(LOG_ERR, "%s (pid:'%lu', th_idx:'%lu', th_ctx:'%p', errno:'%d'): SEVERE ERROR: EPOLL", __func__, pthread_self(), thread_run_context->idx, thread_run_context, errno);
    }
  }

  return NULL;
}

/**
 *
 * @param sesn_ptr Session representing the IPC pipe with Worker-Delegator
 * @param thread_run_context
 */
static void __attribute__((nonnull(1, 2)))
_HandleWorkerDelegatorNotification(WorkerThreadRunContext *thread_run_context, Session *sesn_ptr)
{
  InstanceContextForSession instance_context ={0};
  NotificationPipeDrain(sesn_ptr, GetUfsrvSessionsDelegator(), thread_run_context->drain_Buffer);
  while (LamportQueuePop(thread_run_context->queue, (QueueClientData **)&instance_context.instance_sesn_ptr)) {
    instance_context.sesn_ptr = SessionOffInstanceHolder(instance_context.instance_sesn_ptr);
    _ProcessSessionHandshake(thread_run_context, &instance_context);
  }
}

/**
 * Uses a sacrificial session arriving via the listener to initiate a STUN msg request
 * @param thread_context
 * @param instance_context Session created by Listener worker thread. Under current test implementation this is a jump-session
 * which is not the same as the real conected one for which I/O would be polled in the session-worker thread.
 */
static void __attribute__((nonnull(1, 2)))
_ProcessSessionHandshake(WorkerThreadRunContext *thread_context, InstanceContextForSession *instance_context)
{
  mpsc_queue_node *queue_node = mpsc_queue_pop(&instance_context->sesn_ptr->message_queue_in.queue);
  if (IS_PRESENT(queue_node)) {
    struct mmsghdr *msg = (struct mmsghdr *)queue_node->context_data;
    syslog(LOG_DEBUG, "%s (pid:'%lu', th_idx:'%lu', th_ctx:'%p', inst_o:'%p', msg_sz:'%u'): Read msg: '%s'", __func__, pthread_self(), thread_context->idx, thread_context, instance_context->instance_sesn_ptr, msg->msg_len, (char *)msg->msg_hdr.msg_iov->iov_base);
    if (_PROTOCOL_CLLBACKS_HANDSHAKE(protocols_registry_ptr, masterptr->main_listener_protoid)) {
      UFSRVResult *res_ptr = _PROTOCOL_CLLBACKS_HANDSHAKE_INVOKE(protocols_registry_ptr,
                                                                 PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(instance_context->sesn_ptr))),
                                                                 instance_context->instance_sesn_ptr, (SocketMessage *)&instance_context->sesn_ptr->message_queue_in.queue, CALLFLAGS_EMPTY, NULL);
			}

    SfuMMsgDecrementReference(AS_INSTANCE_HOLDER(queue_node->finaliser.context_data), _ONCE_);
    SfuMMsgReturnToRecycler(AS_INSTANCE_HOLDER(queue_node->finaliser.context_data), NO_CONTEXT_DATA, CALLFLAGS_EMPTY);
    SfuSessionDecrementReference(instance_context->instance_sesn_ptr, _ONCE_);
  } else {
    syslog(LOG_ERR, "%s (pid:'%lu', th_idx:'%lu', th_ctx:'%p', inst_o:'%p'): ERROR: SESSIONS INCOMING QUEUE CONTAINED NO MSG", __func__, pthread_self(), thread_context->idx, thread_context, instance_context->instance_sesn_ptr);
  }

}

/**
 * @brief This is the main I/O processing function for SessionWorker-local (as opposed to Worker-Delegator) network sockets.
 * @param thread_context
 * @param instance_context Active connected session for which network I/O is being processed.
 */
static void __attribute__((nonnull(1, 2)))
_HandleSessionWorkerMessage(WorkerThreadRunContext *thread_context, InstanceContextForSession *instance_context)
{
    syslog(LOG_DEBUG, "%s (pid:'%lu', th_idx:'%lu', th_ctx:'%p', inst_o:'%p', msg_sz:'%u'): Read msg: '%s'", __func__, pthread_self(), thread_context->idx, thread_context, instance_context->instance_sesn_ptr, 0, "xx");
    if (_PROTOCOL_CLLBACKS_MSG(protocols_registry_ptr, masterptr->main_listener_protoid)) {
      UFSRVResult *res_ptr = _PROTOCOL_CLLBACKS_MSG_INVOKE(protocols_registry_ptr,
                                                           masterptr->main_listener_protoid,
                                                           instance_context->instance_sesn_ptr, (SocketMessage *)&instance_context->sesn_ptr->message_queue_in.queue, CALLFLAGS_EMPTY, 0);
    }

}

/**
 * @brief:  Build the unidirectional IPC pipe DelegatorWorker -> SessionWorker, enabling notification of I/O work.
 * This requires 'draining' semantics by the reader, as the reading end never really reads the content of the pipe, because it's only
 * intended as a signalling mechanism.
 * Each worker thread is handed a Session containing the pipe-set (reader and writer fds) and Single-reader-single-writer lockless queue.
 * http://www.win.tue.nl/~aeb/linux/lk/lk-12.html, http://stackoverflow.com/questions/9028934/how-to-interrupt-epoll-pwait-with-an-appropriate-signal
 *
 */
static InstanceHolderForSession *
_BuildWorkerDelegatorToSessionWorkerPipe(__unused UfsrvSessionsDelegator *sd_ptr)
{
  Socket 	*ss_ptr = NULL, *ds_ptr	=	NULL;
  Session	*sesn_ptr	=	NULL;
  int pipe_fds[2] = {0};
#define READ_END_OF_PIPE pipe_fds[0]
#define WRITE_END_OF_PIPE pipe_fds[1]

  ss_ptr = calloc(1, (sizeof(Socket)));//writer end in WorkDelegator
  ds_ptr = calloc(1, (sizeof(Socket)));//reader end in SessionWorker thread

  if (!(sesn_ptr = InstantiateSessionObject(ss_ptr, ds_ptr, 0, -1))) {//dont add to sessions hash table
    syslog(LOG_ERR, "%s: ERROR: COULD NOT initialise Worker-Delegator IPC Pipe session: Exiting...", __func__);

    goto exit_error;
  }

  if ((pipe2(pipe_fds, O_NONBLOCK)) == -1) {
    syslog(LOG_ERR, "%s: ERROR: COULD NOT initialise Worker-Delegator IPC Pipe (errno:%d)", __func__, errno);

    exit_error:
    free(sesn_ptr);
    free(ss_ptr);
    free(ds_ptr);

    return NULL;
  }

  ss_ptr->type = SOCK_PIPEWRITER; //written to by delegator
  ss_ptr->sock = WRITE_END_OF_PIPE;
  strcpy(ss_ptr->address, "pipe.writer.localhost");
  strcpy(ss_ptr->haddress, "pipe.reader.localhost");//session worker

  ds_ptr->type = SOCK_PIPEREADER; //read from by session worker
  ds_ptr->sock = READ_END_OF_PIPE;
  strcpy(ds_ptr->address, "pipe.reader.localhost");
  strcpy(ds_ptr->haddress, "pipe.writer.localhost");//delegator

  SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_IPC);

  syslog(LOG_INFO, "%s: INITIALISED Worker-Delegator->SessionWorker IPC Pipe {o:'%p'} Session: WRITER(Worker-Delegator): '%s:%d' READER(SessionWorker): '%s:%d'", __func__, sesn_ptr, sesn_ptr->ssptr->address, sesn_ptr->ssptr->sock, sesn_ptr->dsptr->address, sesn_ptr->dsptr->sock);

  InstanceHolderForSession *instance_sesn_ptr = calloc(1, sizeof(InstanceHolderForSession));
  SetInstance(instance_sesn_ptr, sesn_ptr);

  return instance_sesn_ptr;

#undef READ_END_OF_PIPE
#undef WRITE_END_OF_PIPE
}

/**
 * @brief Build the unidirectional IPC pipe, enabling SessionWorkers to request re-arming of sessions for I/O polling.
 * The pipe is used to signal back to delegator to rerun (see WorkerDelegatorRaiseRecycleRequest()). No 'draining' semantics
 * apply, since the reader end reads the pipe (to fetch session's address).
 * @param sd_ptr
 * @return
 */
static InstanceHolderForSession *
_BuildSessionWorkerToWorkDelegatorPipe(__unused UfsrvSessionsDelegator *sd_ptr)
{
  Socket 	*ss_ptr = NULL, *ds_ptr	=	NULL;
  Session	*sesn_ptr	=	NULL;
  int pipe_fds[2] = {0};
#define READ_END_OF_PIPE pipe_fds[0]
#define WRITE_END_OF_PIPE pipe_fds[1]

  ss_ptr = calloc(1, (sizeof(Socket)));//writer end in SessionWorker
  ds_ptr = calloc(1, (sizeof(Socket)));//reader end in WorkDelegator thread

  if (!(sesn_ptr = InstantiateSessionObject(ss_ptr, ds_ptr, 0, -1))) {//dont add to sessions hash table
    syslog(LOG_ERR, "%s: ERROR: COULD NOT initialise SessionWorker->Worker-Delegator IPC Pipe session: Exiting...", __func__);

    goto exit_error;
  }

  if ((pipe2(pipe_fds, O_NONBLOCK)) == -1) {
    syslog(LOG_ERR, "%s: ERROR: COULD NOT initialise SessionWorker->Worker-Delegator IPC Pipe (errno:%d)", __func__, errno);

    exit_error:
    free(sesn_ptr);
    free(ss_ptr);
    free(ds_ptr);

    return NULL;
  }

  ss_ptr->type = SOCK_PIPEWRITER; //written to by session worker
  ss_ptr->sock = WRITE_END_OF_PIPE;
  strcpy(ss_ptr->address, "pipe.writer.localhost");
  strcpy(ss_ptr->haddress, "pipe.reader.localhost");//delegator

  ds_ptr->type = SOCK_PIPEREADER; //read from by delegator
  ds_ptr->sock = READ_END_OF_PIPE;
  strcpy(ds_ptr->address, "pipe.reader.localhost");
  strcpy(ds_ptr->haddress, "pipe.writer.localhost");//session worker

  SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_IPC);

  syslog(LOG_INFO, "%s: INITIALISED SessionWorker->Worker-Delegator IPC Pipe {o:'%p'} Session: WRITER(SessionWorker): '%s:%d' READER(WorkerDelegator): '%s:%d'", __func__, sesn_ptr, sesn_ptr->ssptr->address, sesn_ptr->ssptr->sock, sesn_ptr->dsptr->address, sesn_ptr->dsptr->sock);

  InstanceHolderForSession *instance_sesn_ptr = calloc(1, sizeof(InstanceHolderForSession));
  SetInstance(instance_sesn_ptr, sesn_ptr);

  return instance_sesn_ptr;

#undef READ_END_OF_PIPE
#undef WRITE_END_OF_PIPE
}

/**
 * @brief Allocate and initialise storage to hold work allocations queues between listeners and delegator. Each listener has it's
 * own queue to persist data into.
 * @param sd_ptr
 * @return
 */
static int __attribute__((nonnull(1)))
_BuildSessionWorkersToWorkerDelegatorQueues(UfsrvSessionsDelegator *sd_ptr)
{
  int setsize = sd_ptr->session_workers_thread_pool.setsize;

  sd_ptr->session_workers_thread_pool.work_queues = calloc(setsize, sizeof(LocklessSpscQueue *));
  //allocate one whole continuous chunk for all threads, including: queue's max msg capacity * individual payload (pointer to ClientContext)
  char *allocation_tracker = calloc(setsize, sizeof(LocklessSpscQueue) + (CONFIG_LOCKLESS_SESSION_WORKER_QUEUE_SIZE * sizeof(QueueClientData *)));
#if __VALGRIND_DRD
  VALGRIND_CREATE_MEMPOOL(allocation_tracker, 0, 1);
  VALGRIND_MAKE_MEM_NOACCESS(allocation_tracker, setsize * (sizeof(LocklessSpscQueue) + (CONFIG_LOCKLESS_SESSION_WORKER_QUEUE_SIZE * sizeof(QueueClientData *))));
#endif

  //|---+---------|---+--------|
  for (size_t i=0; i!=setsize; i++) {
#if __VALGRIND_DRD
    VALGRIND_MEMPOOL_ALLOC(allocation_tracker, (allocation_tracker + (i * sizeof(LocklessSpscQueue) + (sizeof(QueueClientData *) * CONFIG_LOCKLESS_SESSION_WORKER_QUEUE_SIZE))), sizeof(LocklessSpscQueue));
#endif
    LocklessSpscQueue *lockless_queue = (LocklessSpscQueue *)(allocation_tracker + (i * sizeof(LocklessSpscQueue) + (sizeof(QueueClientData *) * CONFIG_LOCKLESS_SESSION_WORKER_QUEUE_SIZE)));
#if __VALGRIND_DRD
    VALGRIND_MEMPOOL_ALLOC(allocation_tracker, (char *)lockless_queue + sizeof(LocklessSpscQueue), sizeof(QueueClientData *) * CONFIG_LOCKLESS_SESSION_WORKER_QUEUE_SIZE);
#endif
    QueueClientData 	*queue_storage = (char *)lockless_queue + sizeof(LocklessSpscQueue);
    LamportQueueInit(lockless_queue, queue_storage, CONFIG_LOCKLESS_SESSION_WORKER_QUEUE_SIZE);
    sd_ptr->session_workers_thread_pool.work_queues[i] = lockless_queue;
  }

  return 0;
}

/**
 * @brief Allocate and initialise storage to hold the IPC sockets between session workers and workers-delegator
 * @param sd_ptr This instance of ufsrv's
 * @return 0 on success
 */
static int __attribute__((nonnull(1)))
_BuildWorkerDelegatorToSessionWorkerPipes(UfsrvSessionsDelegator *sd_ptr)
{
  int setsize = sd_ptr->session_workers_thread_pool.setsize;
  InstanceHolderForSession *instance_sesn_ptr_ipc;
  WorkerThreadRunContext *thread_context;

  sd_ptr->session_workers_thread_pool.to_session_worker_ipc = calloc(1, (sizeof(InstanceHolderForSession *) * setsize));
  for (size_t i=0; i!=setsize; i++) {
    if ((instance_sesn_ptr_ipc = _BuildWorkerDelegatorToSessionWorkerPipe(sd_ptr))) {
      sd_ptr->session_workers_thread_pool.to_session_worker_ipc[i] = instance_sesn_ptr_ipc;
    }
  }

  sd_ptr->session_workers_thread_pool.drain_buffer_session_worker_ipc = calloc(1, (sizeof(DrainBuffer *) * setsize));

  return 0;
}

/**
 * @brief Allocate and initialise storage to hold the IPC sockets between session workers->workers-delegator
 * @param sd_ptr
 * @return
 */
static int __attribute__((nonnull(1)))
_BuildSessionWorkerToWorkerDelegatorPipes(UfsrvSessionsDelegator *sd_ptr)
{
  int setsize = sd_ptr->session_workers_thread_pool.setsize;
  InstanceHolderForSession *instance_sesn_ptr_ipc;

  sd_ptr->session_workers_thread_pool.to_worker_delegator_ipc = calloc(1, (sizeof(InstanceHolderForSession *) * setsize));
  for (size_t i=0; i!=setsize; i++) {
    if ((instance_sesn_ptr_ipc = _BuildSessionWorkerToWorkDelegatorPipe(sd_ptr))) {
      sd_ptr->session_workers_thread_pool.to_worker_delegator_ipc[i] = instance_sesn_ptr_ipc;
    }
  }

  return 0;
}

/**
 * @brief Allocate and initialise storage to hold session worker threads.
 * @param sd_ptr
 * @return
 */
static int __attribute__((nonnull(1)))
_BuildSessionWorkerThreads(UfsrvSessionsDelegator *sd_ptr)
{
  int setsize = sd_ptr->session_workers_thread_pool.setsize;

  sd_ptr->session_workers_thread_pool.workers = malloc(sizeof(pthread_t) * setsize);
  #if __VALGRIND_DRD
  VALGRIND_CREATE_MEMPOOL(sd_ptr->session_workers_thread_pool.workers, 0, 1);
  VALGRIND_MAKE_MEM_NOACCESS(sd_ptr->session_workers_thread_pool.workers, sizeof(pthread_t) * setsize);
#endif

  return 0;
}

/**
 * 	@brief: Add the uni-directional IPC pip between the Session Workers -> Worker-Delegator. This signalling mechanism is used to request the
 * 	Delegator to re-queue a Session for an I/O iteration by a worker. Only the reader side of the pipe fd is plugged into epoll.
 * 	This should last for the lifetime of the worker thread.
 */
void
AddSessionWorkersPipeEndsToMonitoredEvents(UfsrvSessionsDelegator *sd_ptr)
{
  int i;
  Session *sesn_ptr_ipc = NULL;
  InstanceHolderForSession *instance_sesn_ptr_ipc;

  for (i=0; i!=sd_ptr->session_workers_thread_pool.setsize; i++) {
    instance_sesn_ptr_ipc = sd_ptr->session_workers_thread_pool.to_worker_delegator_ipc[i];

    struct epoll_event epoll_event = {0};
    epoll_event.events = EPOLLIN;//|EPOLLET; //keep default line-triggered as we want to make sure the pipe is always drained
    epoll_event.data.u64 = 0;
    epoll_event.data.ptr = instance_sesn_ptr_ipc;

    sesn_ptr_ipc = SessionOffInstanceHolder(instance_sesn_ptr_ipc);

    if (epoll_ctl(sd_ptr->epoll_handle, EPOLL_CTL_ADD, sesn_ptr_ipc->dsptr->sock, &epoll_event) == -1) {//PIPE READER END is in dsptr not ssptr
      syslog(LOG_ERR, "%s {o:'%p'}: COULD NOT add pipe connection to events loop: WILL NOT be able to process Worker->Delegator IPC pipe: errno='%d'", __func__, sesn_ptr_ipc, errno);
    } else {
      syslog(LOG_ERR, "%s {o:'%p', fd:'%d'}: Worker->Worker-Delegator IPC Pipe: Added pipe reader fd to monitored events...", __func__, sesn_ptr_ipc, sesn_ptr_ipc->dsptr->sock);
    }
  }

}
