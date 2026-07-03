/**
 * Copyright (C) 2015-2025 unfacd works
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

/**
 * This is the main I/O event listener/dispatcher thread, delegating work to session based worker threads.
 */
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <sessionworkers_utils.h>
#include <worker_session_io_thread.h>
#include <uflib/recycler/instance_type.h>
#include <uflib/adt/adt_lamport_queue.h>
#include <session.h>

static InstanceHolderForSession *_InitDelegatorWorkerInterConnectionPipe(void);

/**
 * @brief Set the data context necessary to launch session i/o workers.
 * @param[in] sd_ptr Singleton reference to Sessions Delegator
 * @param[in] user_thread_ctx_allocation_sz Data size of the worker-specific data context. This will be preallocated for wll threads
 */
void
LaunchSessionWorkerThreads(SessionsDelegator *sd_ptr, size_t user_thread_ctx_allocation_sz)
{
  if (IS_PRESENT(sd_ptr)) {
    //create a set to hold worker->delegator ipc primitives (currently self-pipes)
    sd_ptr->worker_delegator_ipc = calloc(1, (sizeof(InstanceHolderForSession *) * sd_ptr->setsize));

    //create a set of Session i/o workers
    sd_ptr->session_worker_ths = malloc(sizeof(pthread_t) * sd_ptr->setsize);
#if __VALGRIND_DRD
    VALGRIND_CREATE_MEMPOOL(sd_ptr->session_worker_ths, 0, 1);
		VALGRIND_MAKE_MEM_NOACCESS(sd_ptr->session_worker_ths, sizeof(pthread_t) * sd_ptr->setsize);
#endif

    //allocate one whole continuous chunk for all threads, include queue storage: payload + container
    sd_ptr->sessions_work_queues = calloc(sd_ptr->setsize, sizeof(LocklessSpscQueue) + (CONFIG_LOCKLESS_SESSION_WORKER_QUEUE_SIZE * sizeof(QueueClientData *)));
    void *allocation_tracker = sd_ptr->sessions_work_queues;
#if __VALGRIND_DRD
    VALGRIND_CREATE_MEMPOOL(sd_ptr->sessions_work_queues, 0, 1);
		VALGRIND_MAKE_MEM_NOACCESS(sd_ptr->sessions_work_queues, sd_ptr->setsize * (sizeof(LocklessSpscQueue) + (CONFIG_LOCKLESS_SESSION_WORKER_QUEUE_SIZE * sizeof(QueueClientData *))));
#endif

    WorkerThreadCreationContext *thread_contexts = calloc(sd_ptr->setsize, sizeof(WorkerThreadCreationContext));
#if __VALGRIND_DRD
    VALGRIND_CREATE_MEMPOOL(thread_contexts, 0, 1);
		VALGRIND_MAKE_MEM_NOACCESS(thread_contexts, sd_ptr->setsize * sizeof(WorkerThreadCreationContext));
#endif

    int i;
    int result;
    //Session *sesn_ptr_ipc = NULL;
    InstanceHolderForSession *instance_sesn_ptr_ipc = NULL;
    WorkerThreadCreationContext *thread_context     = NULL;
    for (i=0; i!=sd_ptr->setsize; i++) {
      if ((instance_sesn_ptr_ipc = _InitDelegatorWorkerInterConnectionPipe())) {
#if __VALGRIND_DRD
        VALGRIND_MEMPOOL_ALLOC(sd_ptr->sessions_work_queues, allocation_tracker, sizeof(LocklessSpscQueue));
				VALGRIND_MEMPOOL_ALLOC(sd_ptr->sessions_work_queues, allocation_tracker + sizeof(LocklessSpscQueue), (sizeof(LocklessSpscQueue) + (sizeof(QueueClientData *) * CONFIG_LOCKLESS_SESSION_WORKER_QUEUE_SIZE)));

				VALGRIND_MEMPOOL_ALLOC(thread_contexts, (((char *)thread_contexts) + (i * sizeof(WorkerThreadCreationContext))), sizeof(WorkerThreadCreationContext));

				VALGRIND_MEMPOOL_ALLOC(sd_ptr->session_worker_ths, &(sd_ptr->session_worker_ths[i]), sizeof(pthread_t));
#endif
        LocklessSpscQueue *lockless_queue = allocation_tracker;
        QueueClientData 	**queue_storage = allocation_tracker + sizeof(LocklessSpscQueue);
        LamportQueueInit(lockless_queue, queue_storage, CONFIG_LOCKLESS_SESSION_WORKER_QUEUE_SIZE);

        (sd_ptr->worker_delegator_ipc[i]) = instance_sesn_ptr_ipc;

        thread_context = (WorkerThreadCreationContext *)(((char *)thread_contexts) + (i * sizeof(WorkerThreadCreationContext)));
        thread_context->idx = i;
        thread_context->ipc_pipe = instance_sesn_ptr_ipc;
        thread_context->queue = lockless_queue;
        result = pthread_create(&(sd_ptr->session_worker_ths[i]), NULL, GetSessionWorkerThreadHandler(), thread_context);
        if (result != 0) {
          syslog(LOG_ERR, "%s: FATAL: COULD NOT spawn Session Worker Threads (requested: '%d', iteration: '%d'): terminating...", __func__, sd_ptr->setsize, i);
          exit(-1);
        }

        allocation_tracker += (sizeof(LocklessSpscQueue) + (sizeof(QueueClientData *) * CONFIG_LOCKLESS_SESSION_WORKER_QUEUE_SIZE));
      }
    }

    statsd_gauge(sd_ptr->instrumentation_backend_ptr, "worker.work.handshake_failed", 0);

    syslog(LOG_ERR, "%s (queues:'%p'): SUCCESSFULLY spawned '%d' Session Worker Threads...", __func__, sd_ptr->sessions_work_queues, sd_ptr->setsize);
  }

}

/**
 * @brief:  Setup and initialise the IPC channel between Workers -> Delegator. Current implementation uses classic simple self-pipe.
 * Each worker thread is handed a Session containing the pipe-set (reader and writer fds) and Single-reader-single-writer lockless queue.
 * The pipe is used to signal back to delegator to rerun (see WorkerDelegatorRaiseRecycleRequest()).
 */
//http://stackoverflow.com/questions/9028934/how-to-interrupt-epoll-pwait-with-an-appropriate-signal
//http://www.win.tue.nl/~aeb/linux/lk/lk-12.html
//todo explore https://man7.org/linux/man-pages/man2/eventfd.2.html instead of self pipe
static InstanceHolderForSession *
_InitDelegatorWorkerInterConnectionPipe(void)
{
  Socket 	*ss_ptr   = NULL,
          *ds_ptr		=	NULL;
  Session	*sesn_ptr	=	NULL;
  int pipe_fds[2] = {0};
#define READ_END_OF_PIPE pipe_fds[0]
#define WRITE_END_OF_PIPE pipe_fds[1]

  ss_ptr = calloc(1, (sizeof(Socket)));//writer end in worker
  ds_ptr = calloc(1, (sizeof(Socket)));//reader end in WorkDelegator thread

  if (!(sesn_ptr = InstantiateSessionObject(ss_ptr, ds_ptr, 0, -1))) {//don't add to sessions hash table
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

  ss_ptr->type = SOCK_PIPEWRITER;
  ss_ptr->sock = WRITE_END_OF_PIPE;
  strcpy(ss_ptr->address, "pipe.writer.localhost");//session worker
  strcpy(ss_ptr->haddress, "pipe.reader.localhost");//delegator

  ds_ptr->type = SOCK_PIPEREADER;
  ds_ptr->sock = READ_END_OF_PIPE;
  strcpy(ds_ptr->address, "pipe.reader.localhost");//delegator
  strcpy(ds_ptr->haddress, "pipe.writer.localhost");//session worker

  SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_IPC);

  syslog(LOG_INFO, "%s: INITIALISED Worker-Delegator IPC Pipe (cid:'%lu') connection: WRITER: '%s:%d' READER: '%s:%d'",__func__, sesn_ptr->session_id, sesn_ptr->ssptr->address, sesn_ptr->ssptr->sock, sesn_ptr->dsptr->address, sesn_ptr->dsptr->sock);

  InstanceHolderForSession *instance_sesn_ptr = calloc(1, sizeof(InstanceHolderForSession));
  SetInstance(instance_sesn_ptr, sesn_ptr);

  return instance_sesn_ptr;

#undef READ_END_OF_PIPE
#undef WRITE_END_OF_PIPE
}
