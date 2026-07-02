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
#endif

#include <main.h>
#include <uflib/standard_c_includes.h>
#include <uflib/utils_threads.h>
#include <uflib/recycler/recycler.h>
#include <ufsrvmsg_core/include/sockets.h>
#include <ufsrvmsg_core/include/net.h>
#include <nportredird.h>
#include <ufsrvmsg_core/protocol/protocol.h>
#include <sessions_delegator_type.h>
#include <ufsrvmsg_core/include/network_socket_address.h>
#include <ufsrvsfu/include/delegator_sfu_listener_thread.h>
#include <ufsrv_sessions_delegator_type.h>
#include <worker_thread_run_context_type.h>
#include <session_utils.h>
#include <uflib/adt/adt_mpsc_queue.h>
#include <ufsrvmsg_core/type_providers/mpsc_queue_node_provider.h>
#include "mmsg_provider.h"
#include "sfu_session_provider.h"

//static UFSRVResult *_p_ProcessSessionSocketMessage (Session *, SocketMessage *, int);
//static inline UFSRVResult *_HandleSessionWorkRequest (Session *sesnptr, SessionsDelegator *sd_ptr, unsigned long session_id_invoked);
//static inline UFSRVResult *_HandleSuccessfulWorkRequest (SessionsDelegator *sd_ptr, unsigned long session_id_invoked, UFSRVResult *res_ptr);
//static inline UFSRVResult *_HandleMessageForConnectedSession (Session *sesn_ptr, SocketMessage *sock_msg_ptr, int flag);
//inline static UFSRVResult *_HandlePostSuccessfulIncomingHandshake (Session *sesn_ptr, SocketMessage *sock_msg_ptr);
//static inline UFSRVResult *_InvokeLifecycleCallbackPostHandshake (Session *sesn_ptr, SocketMessage *sock_msg_ptr);
//static inline UFSRVResult *_InvokeLifecycleCallbackMsgOut (Session *sesn_ptr, SocketMessage *sock_msg_ptr, unsigned long);
//inline static bool WorkerDelegatorRaiseRecycleRequest	(Session *sesn_ptr, Session *sesn_ptr_ipc);
//inline static void _HandleBusySessionLock (Session *sesnptr);

extern ufsrv *const 						masterptr;
extern  const  Protocol *const 	protocols_registry_ptr;
extern __thread BaseThreadContext *base_thread_context;

static Socket *_GetStunUdpSocketWithReusablePort(Socket *sock_ptr);
static int _NotifyWorkerDelegator(WorkerThreadRunContext *thread_instantiation_context, InstanceHolderForSession *instance_sesn_ptr);

static int _BuildConnectionListenerToWorkerDelegatorIpcPipes(UfsrvSessionsDelegator *sd_ptr);
static InstanceHolderForSession *_BuildConnectionListenerToWorkDelegatorPipe(void);
static int _BuildConnectionListenerToWorkerDelegatorQueues(UfsrvSessionsDelegator *sd_ptr);
static int _BuildConnectionListenerThreads(UfsrvSessionsDelegator *sd_ptr);
static int _AddConnectionListenerPipeEndToMonitoredEvents(int epoll_fd, InstanceHolderForSession *instance_sesn_ptr_ipc);

static ssize_t _SendUdpPacket(int socket_fd);

//This design is based on multiple threads sharing the same port  SO_REUSEPORT, so each thread can fan ut received messages to workers or other processes.
// Since we are using recvmmsg, multiple messages (potentially from different clients), so worker-fan out is better.
// https://lwn.net/Articles/542629/, https://tech.flipkart.com/linux-tcp-so-reuseport-usage-and-implementation-6bfbf642885a, https://stackoverflow.com/questions/14388706/how-do-so-reuseaddr-and-so-reuseport-differ, https://blog.cloudflare.com/how-to-receive-a-million-packets/
void *
ThreadSfuConnectionListenerWorker(void *ptr)
{
	WorkerThreadRunContext *thread_instantiation_context = ptr;
	int thread_idx = thread_instantiation_context->idx;
	UfsrvSessionsDelegator *sd_ptr = thread_instantiation_context->sessions_delegator;
	Socket 				socket_listener	= {0};

	//controls for exponential backoff when no type pool objects available
	unsigned int  suspend_duration = 1; //in seconds
#define _MAX_SUSPEND_DURATION 128 //in seconds

	SetThreadName("ListenerDelegator");

	if (IS_EMPTY(_GetStunUdpSocketWithReusablePort(&socket_listener))) {
		//syslog
		return NULL;//essentially terminates thread
	}

	/*struct iovec 		    iovecs[MAX_PACKETS];
	struct mmsghdr 	    msgs[MAX_PACKETS];
  struct sockaddr_in  addrs[MAX_PACKETS];

	memset(msgs, 0x0, sizeof(msgs));

	for (size_t i = 0; i < MAX_PACKETS; ++i) {
		iovecs[i].iov_base 					= calloc(1, CONFIG_MMSG_MAX_PACKET_SIZE_UDP);
		iovecs[i].iov_len 					= CONFIG_MMSG_MAX_PACKET_SIZE_UDP - 1;//assuming text and allowing for terminating nul

		msgs[i].msg_hdr.msg_iov 		= &iovecs[i];
		msgs[i].msg_hdr.msg_iovlen 	= 1;
    msgs[i].msg_hdr.msg_control = 0;
    msgs[i].msg_hdr.msg_controllen = 0;

    msgs[i].msg_hdr.msg_name = &addrs[i];//Allocate room for retrieving peer's address
    msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
	}*/

	syslog(LOG_DEBUG, "%s (pid:'%lu', run_ctx:'%p', th_idx:'%d) Entering main Listener loop...", __func__,  pthread_self(), thread_instantiation_context, thread_idx);

	__unused size_t msg_processed_sz = 0;
	for (;;) {
    InstanceHolderForSfuMMsg *instance_holder_ptr = GetMmsg();//each fetch is single referenceable pool type object
    if (IS_EMPTY(instance_holder_ptr)) {
      sleep(suspend_duration);
      if (suspend_duration < _MAX_SUSPEND_DURATION) {
        suspend_duration *= 2;
        continue; //try again
      } else {
        syslog(LOG_DEBUG, "%s (pid:'%lu', run_ctx:'%p', th_idx:'%d) EXPONENTIAL BACKOFF EXCEEDED", __func__,  pthread_self(), thread_instantiation_context, thread_idx);
        suspend_duration = 1; continue; //todo temporary treatment: restart the backoff procedure
      }
    }

    suspend_duration = 1; //reset

    void *mmsg_vector = GetInstance(instance_holder_ptr);
    int res = recvmmsg(socket_listener.sock, (struct mmsghdr *)mmsg_vector, _CONFIGDEFAULT_RECVMMSG_MAX_PACKET_SZ, MSG_WAITFORONE, NULL);

		if (res < 0) {
			if (errno == EAGAIN || errno == EINTR) {
				continue;
			}

			continue;
		}

#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s (pid:'%lu', sock_fd:'%d', mmmsg_sz:'%d) Received UDP transmission...", __func__,  pthread_self(), socket_listener.sock, res);
#endif

		mpsc_queue_node *queue_node_vector = GetQueueNodeReference(mmsg_vector);
		msg_processed_sz = 0;
		syslog(LOG_DEBUG, "%s (pid:'%lu', queue_node:'%p') Queue_node allocaation", __func__,  pthread_self(), queue_node_vector);

		for (size_t i = 0; i < res; ++i) {
#if __VALGRIND_DRD
		  VALGRIND_MEMPOOL_ALLOC(queue_node_vector, (char *)queue_node_vector + (i * sizeof(mpsc_queue_node)), sizeof(struct mpsc_queue_node));
#endif
		  struct mmsghdr *mmsghdr = (struct mmsghdr *)((char *)mmsg_vector + (i * sizeof(struct mmsghdr)));//map out individual references for incoming msgs
		  mpsc_queue_node *queue_node = (mpsc_queue_node *)((char *)queue_node_vector + (i * sizeof(mpsc_queue_node)));
      queue_node->context_data = AS_QUEUE_CONTEXT_DATA(mmsghdr); //this is index'ed into the type pool so it can't be used to refcount or return to recycler (use finaliser below)
      queue_node->finaliser.context_data = AS_QUEUE_CONTEXT_DATA(instance_holder_ptr);//todo: this doesn't belong to queueitem (create new type that include both references). since we are using a pool, we need to retain a refernce to the actual InstanceHolder for the whole Mmsg type pool

			/*sock_msg_ptr->_raw_msg			=	msgs[i].msg_hdr.msg_iov->iov_base;
			sock_msg_ptr->raw_msg_size	=	msgs[i].msg_len;
			if (msgs[i].msg_hdr.msg_flags&MSG_TRUNC) {
        syslog(LOG_DEBUG, "%s (pid:'%lu', sock_fd:'%d', mmmsg_sz:'%d) UDP PACKET TRUNCATED...", __func__,  pthread_self(), socket_listener.sock, res);
			}*/

			NetworkSocketAddress socket_address_local = {0};
			NetworkSocketAddressSetLocalFromFd(socket_listener.sock, &socket_address_local);

			struct sockaddr_in *src = mmsghdr->msg_hdr.msg_name;//peer's address
//      uint16_t port = ntohs(src->sin_port);
      _SendUdpPacket(socket_listener.sock);

      Session *sesn_fetched = NULL;
      InstanceHolderForSession *instance_sesn_ptr = LocallyLocateSessionByNetAddress(&(sd_ptr->hashed_net_addresses.hashtable), src);
      if (IS_EMPTY(instance_sesn_ptr)) {
        instance_sesn_ptr = (InstanceHolderForSfuSession *)RecyclerGet(SfuSessionPoolTypeNumber(), NULL, CALLFLAGS_EMPTY);
        if (IS_EMPTY(instance_sesn_ptr)) {
          continue;
        }
        sesn_fetched = SessionOffInstanceHolder(instance_sesn_ptr);
        AssignNetAddressHashForSession(&(InstanceContextForSession){.instance_sesn_ptr=instance_sesn_ptr, .sesn_ptr=sesn_fetched}, src);
        if ((SESSION_NETADDRESS_HASH(sesn_fetched) == 0) || !(AddToHash(&sd_ptr->hashed_net_addresses.hashtable, (void *)instance_sesn_ptr))) {
          syslog(LOG_ERR, "%s (pid:'%lu', sock_fd:'%d', mmmsg_sz:'%d) ERROR HASHING SESSION", __func__,  pthread_self(), socket_listener.sock, res);
          SessionReturnToRecycler(instance_sesn_ptr, NO_CONTEXT_DATA, CALLFLAGS_EMPTY);
          continue;
        }
      } else sesn_fetched = SessionOffInstanceHolder(instance_sesn_ptr);

      SfuMMsgIncrementReference(instance_holder_ptr, _ONCE_);
      SfuSessionIncrementReference(instance_sesn_ptr, _ONCE_);
      mpsc_queue_insert(&sesn_fetched->message_queue_in.queue, queue_node);
      _NotifyWorkerDelegator(thread_instantiation_context, instance_sesn_ptr);
		}
	}//for

}

static ssize_t
_SendUdpPacket(int socket_fd)
{
  struct sockaddr_in servaddr;
  int port = 10000;
  char *ip= "139.162.56.133";

  const char* hostname=ip; /* localhost */
  char portname[6] = {0};
  itoa(portname, port);
  struct addrinfo hints;
  memset(&hints,0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = 0;
  hints.ai_flags = AI_ADDRCONFIG;

  printf("sending to %s on port %s \n", hostname, portname);

  struct addrinfo *res;
  int err = getaddrinfo(hostname, portname, &hints, &res);
  if (err != 0) {
    printf("failed to resolve remote socket address (err=%d) \n",err);
  }

  char *content = "payload";
  if (sendto(socket_fd, content, strlen(content), 0, res->ai_addr, res->ai_addrlen) == -1) {
    printf("Error sending packate: %s \n", strerror(errno));
    err = -1;
  }

  return err;
  // clear servaddr
//  bzero(&servaddr, sizeof(servaddr));
//  servaddr.sin_addr.s_addr = inet_addr(ip);
//  servaddr.sin_port = htons(port);
//  servaddr.sin_family = AF_INET;

//  printf("Trying %s:%d\n", ip, port);

  //int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  // connect to server: not necssary for UDP: binds the socket to this address only, with response only from provided adress
//  if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
//    printf("\n Error : Connect Failed \n");
//    return -1;
//  }
//    return sendto(sockfd, "payload", strlen("payload"), 0, (struct sockaddr*)NULL, sizeof(servaddr));

}

/**
 * @brief Notify the worker-delegator about a queued-in work-request. Current implementation uses MPSC queue to pass session's reference.
 * The session's incoming network msg will have been previously pushed onto session's input queue by the listener thread(s).
 * @param thread_instantiation_context Instantiation context data for current thread
 * @param instance_sesn_ptr The session for which work is being undertaken
 * @return
 */
static int
_NotifyWorkerDelegator(WorkerThreadRunContext *thread_run_context, InstanceHolderForSession *instance_sesn_ptr)
{
  Session *sesn_ptr_sender = SessionOffInstanceHolder(thread_run_context->ipc_pipe);
  InstanceHolderForMpscQueueNode *instance_holder = GetMpscQueueNode(_INCREMENT_REFERENCE(true));
  if (IS_EMPTY(instance_holder)) {
    return -1;
  }
  mpsc_queue_node *queue_node = MpscQueueNodeOffInstanceHolder(instance_holder);
  queue_node->context_data = AS_QUEUE_CONTEXT_DATA(instance_sesn_ptr);
  queue_node->finaliser.context_data = instance_holder;//so recipient can return to recycler when done
  mpsc_queue_insert(thread_run_context->msg_queue, queue_node);

#ifdef __UF_FULLDEBUG
#endif

  #define PIPE_GO_MSG "G"
  const char *marshal_msg = PIPE_GO_MSG;
  ssize_t actual_written_size = 0;

  //Signal to delegator via event loop that queue contains an entry for fetching
  while (actual_written_size < (sizeof(PIPE_GO_MSG) - 1)) {
    ssize_t written = write(WORK_DELEGATOR_PIPE_WRITE_END(sesn_ptr_sender), marshal_msg + actual_written_size, (sizeof(PIPE_GO_MSG) - 1) - actual_written_size);
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

static Socket *
_GetStunUdpSocketWithReusablePort(Socket *sock_ptr)
{
	int sock_fd;

	if ((sock_fd = SetupListeningSocket(masterptr->main_listener_address, masterptr->listen_on_port, SOCK_UDP, SOCKOPT_REUSEPORT|SOCKOPT_REUSEADDRE|SOCKOPT_BLOCKING)) > 0) {
		SocketOptionSetIP_PKTINFO(sock_fd, 1);

		sock_ptr->type = SOCK_MAIN_LISTENER;
		sock_ptr->sock = sock_fd;
		strcpy(sock_ptr->address, masterptr->main_listener_address);
		strcpy(sock_ptr->haddress, masterptr->main_listener_address);

		syslog(LOG_INFO, "%s (sock_fd:'%d'): SUCCESS created Main Listener on %s:%d ...", __func__, sock_ptr->sock, masterptr->main_listener_address, masterptr->listen_on_port);

		return sock_ptr;
	} else {
		syslog(LOG_INFO, "%s: ERROR: COULD NOT create UDP port %d (%s)...", __func__, masterptr->listen_on_port, strerror(errno));
	}

	return NULL;
}


/**
 * @brief Allocate and initialise storage to hold the IPC sockets between connection listeners and workers-delegator
 * @param sd_ptr This instance of ufsrv's
 * @return 0 on success
 */
static int __attribute__((nonnull(1)))
_BuildConnectionListenerToWorkerDelegatorIpcPipes(UfsrvSessionsDelegator *sd_ptr)
{
  int setsize = sd_ptr->connection_listeners_delegator.setsize;
  sd_ptr->connection_listeners_delegator.to_worker_delegator_ipc = calloc(1, (sizeof(InstanceHolderForSession *) * setsize));

  int i;
  InstanceHolderForSession *instance_sesn_ptr_ipc;
  for (i=0; i!=setsize; i++) {
    if ((instance_sesn_ptr_ipc = _BuildConnectionListenerToWorkDelegatorPipe())) {
      (sd_ptr->connection_listeners_delegator.to_worker_delegator_ipc[i]) = instance_sesn_ptr_ipc;
    }
  }

  return 0;
}

/**
 * @brief:  Build the unidirectional IPC pipe (self-pipe) Listener -> DelegatorWorker, enabling notification of new connections (or messages in UDP).
 * This requires 'draining' semantics by the reader, as the reading end never really reads the content of the pipe, because it's only
 * intended as a signalling mechanism.
 * Each worker thread is handed a Session containing the pipe-set (reader and writer fds) and Single-reader-single-writer lockless queue.
 * http://www.win.tue.nl/~aeb/linux/lk/lk-12.html, http://stackoverflow.com/questions/9028934/how-to-interrupt-epoll-pwait-with-an-appropriate-signal
 *
 */
static InstanceHolderForSession *
_BuildConnectionListenerToWorkDelegatorPipe(void)
{
  Socket *ss_ptr = NULL, *ds_ptr = NULL;
  Session	*sesn_ptr = NULL;
  int pipefds[2] = {0};
#define WRITE_END_OF_PIPE pipefds[1]
#define READ_END_OF_PIPE pipefds[0]

  if ((pipe2(pipefds, O_NONBLOCK)) == -1) {
    syslog(LOG_ERR, "%s: COULD NOT initialise Pipe(errno:%d): exiting...", __func__, errno);
    return NULL;
  }

  ss_ptr = malloc((sizeof(Socket)));//writer end in connections listening  thread
  memset (ss_ptr, 0, sizeof(Socket));

  ss_ptr->type = SOCK_PIPEWRITER;
  ss_ptr->sock = WRITE_END_OF_PIPE;//PIPE_WRITE_END;
  strcpy(ss_ptr->address, "pipe.writer.localhost");
  strcpy(ss_ptr->haddress, "pipe.reader.localhost");

  ds_ptr = malloc(sizeof(Socket));//reader end in Worker-Delegator thread
  memset(ds_ptr, 0, sizeof(Socket));
  ds_ptr->type = SOCK_PIPEREADER;
  ds_ptr->sock = READ_END_OF_PIPE;
  strcpy (ds_ptr->address, "pipe.reader.localhost");
  strcpy (ds_ptr->haddress, "pipe.writer.localhost");

  if (!(sesn_ptr = InstantiateSessionObject(ss_ptr, ds_ptr, 0, -1))) {
    close(ss_ptr->sock);
    close(ds_ptr->sock);
    free(ss_ptr);
    free(ds_ptr);

    syslog(LOG_ERR, "%s: COULD NOT initialise Pipe Interconnection Session: exiting...", __func__);
    return NULL;
  }

  SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_CONNECTION_LISTENER);
  InstanceHolderForSession *instance_sesn_ptr = calloc(1, sizeof(InstanceHolderForSession));
  SetInstance(instance_sesn_ptr, sesn_ptr);
  syslog(LOG_INFO, "%s: INITIALISED Worker-Delegator IPC Pipe {o:'%p'} Session: WRITER(Listener): '%s:%d' READER(Delegator-Worker): '%s:%d'",__func__,
         sesn_ptr, sesn_ptr->ssptr->address, sesn_ptr->ssptr->sock, sesn_ptr->dsptr->address, sesn_ptr->dsptr->sock);

  return instance_sesn_ptr;
}

/**
 * @brief Allocate and initialise storage to hold work allocations queues between listeners and delegator. Each listener has it's
 * own queue to persist data into.
 * @param sd_ptr
 * @return
 */
static int __attribute__((nonnull(1)))
_BuildConnectionListenerToWorkerDelegatorQueues(UfsrvSessionsDelegator *sd_ptr)
{
  int setsize = sd_ptr->connection_listeners_delegator.setsize;

  //allocate one whole continuous chunk for all threads, include queue storage: payload + container
  sd_ptr->connection_listeners_delegator.work_queues = calloc(setsize, sizeof(LocklessSpscQueue) + (CONFIG_LOCKLESS_SESSION_WORKER_QUEUE_SIZE * sizeof(QueueClientData *)));
  void *allocation_tracker = sd_ptr->connection_listeners_delegator.work_queues;
#if __VALGRIND_DRD
  VALGRIND_CREATE_MEMPOOL(sd_ptr->connection_listeners_delegator.work_queues, 0, 1);
  VALGRIND_MAKE_MEM_NOACCESS(sd_ptr->connection_listeners_delegator.work_queues, setsize * (sizeof(LocklessSpscQueue) + (CONFIG_LOCKLESS_SESSION_WORKER_QUEUE_SIZE * sizeof(QueueClientData *))));
#endif

  for (int i=0; i!=setsize; i++) {
#if __VALGRIND_DRD
    VALGRIND_MEMPOOL_ALLOC(sd_ptr->connection_listeners_delegator.work_queues, allocation_tracker, sizeof(LocklessSpscQueue));
    VALGRIND_MEMPOOL_ALLOC(sd_ptr->connection_listeners_delegator.work_queues, allocation_tracker + sizeof(LocklessSpscQueue), (sizeof(LocklessSpscQueue) + (sizeof(QueueClientData *) * CONFIG_LOCKLESS_SESSION_WORKER_QUEUE_SIZE)));
#endif
    LocklessSpscQueue *lockless_queue = allocation_tracker;
    QueueClientData 	**queue_storage = allocation_tracker + sizeof(LocklessSpscQueue);
    LamportQueueInit(lockless_queue, queue_storage, CONFIG_LOCKLESS_SESSION_WORKER_QUEUE_SIZE);

    allocation_tracker += (sizeof(LocklessSpscQueue) + (sizeof(QueueClientData *) * CONFIG_LOCKLESS_SESSION_WORKER_QUEUE_SIZE));
  }//for

  return 0;
}

/**
 * @brief Allocate and initialise storage to hold listener threads.
 * @param sd_ptr
 * @return
 */
static int __attribute__((nonnull(1)))
_BuildConnectionListenerThreads(UfsrvSessionsDelegator *sd_ptr)
{
  int setsize = sd_ptr->connection_listeners_delegator.setsize;

  sd_ptr->connection_listeners_delegator.workers = malloc(sizeof(pthread_t) * setsize);
#if __VALGRIND_DRD
  VALGRIND_CREATE_MEMPOOL(sd_ptr->connection_listeners_delegator.workers, 0, 1);
  VALGRIND_MAKE_MEM_NOACCESS(sd_ptr->connection_listeners_delegator.workers, sizeof(pthread_t) * setsize);
#endif

  return 0;
}

/**
 * @brief Prepare the context for launching connection listeners
 * @param sd_ptr
 * @return
 */
int __attribute__((nonnull(1)))
LaunchConnectionListenerThreads(UfsrvSessionsDelegator *sd_ptr)
{
  int setsize = sd_ptr->connection_listeners_delegator.setsize;
  if (setsize <= 0) {
    syslog(LOG_ERR, "%s: FATAL: SETSIZE FOR CONNECTION LISTENER THREADS UNDEFINED (setsize: '%d')...", __func__, setsize);
    return -1;
  }

  if (IS_EMPTY(sd_ptr->connection_listeners_delegator.work_queues)) {
    _BuildConnectionListenerToWorkerDelegatorQueues(sd_ptr);
  }

  if (IS_EMPTY(sd_ptr->connection_listeners_delegator.to_worker_delegator_ipc)) {
    _BuildConnectionListenerToWorkerDelegatorIpcPipes(sd_ptr);
  }

  if (IS_EMPTY(sd_ptr->connection_listeners_delegator.workers)) {
    _BuildConnectionListenerThreads(sd_ptr);
  }

  WorkerThreadRunContext *thread_run_contexts = calloc(setsize, sizeof(WorkerThreadRunContext));
#if __VALGRIND_DRD
  VALGRIND_CREATE_MEMPOOL(thread_run_contexts, 0, 1);
  VALGRIND_MAKE_MEM_NOACCESS(thread_run_contexts, setsize * sizeof(WorkerThreadRunContext));
#endif

  WorkerThreadRunContext *thread_context;

  for (int i=0; i!=setsize; i++) {
#if __VALGRIND_DRD
    VALGRIND_MEMPOOL_ALLOC(sd_ptr->connection_listeners_delegator.workers, &(sd_ptr->connection_listeners_delegator.workers[i]), sizeof(pthread_t));
    VALGRIND_MEMPOOL_ALLOC(thread_run_contexts, (char *)thread_run_contexts + (i * sizeof(WorkerThreadRunContext)), sizeof(WorkerThreadRunContext));
#endif
    thread_context = (WorkerThreadRunContext *)((char *)thread_run_contexts + (i * sizeof(WorkerThreadRunContext)));
    thread_context->idx = i;
    thread_context->sessions_delegator = sd_ptr;
    thread_context->ipc_pipe = sd_ptr->connection_listeners_delegator.to_worker_delegator_ipc[i];
    thread_context->queue = sd_ptr->connection_listeners_delegator.work_queues[i];
    thread_context->msg_queue = &sd_ptr->connection_listeners_delegator.msg_queue;

    int result = pthread_create(&(sd_ptr->connection_listeners_delegator.workers[i]), NULL, ThreadSfuConnectionListenerWorker, thread_context);
    if (result != 0) {
      syslog(LOG_ERR, "%s: FATAL: COULD NOT spawn Session Worker Threads (requested: '%d', iteration: '%d'): terminating...", __func__, setsize, i);
      exit (-1);
    }

  }//for

  syslog(LOG_ERR, "%s (queues:'%p'): SUCCESSFULLY spawned '%d' Session Worker Threads...", __func__, sd_ptr->connection_listeners_delegator.work_queues, setsize);

  return 0;
}

/**
 * @brief Connect connections listeners IPC pipe ends with the main events loop inside worker-delegator. These are
 * used to signal the delegator to read the incoming connections queue. This is oneway Listener(writer)->Worker-delegator(reader)
 * @param sd_ptr Global worker-delegator definitions.
 */
void __attribute__((nonnull(1)))
AddConnectionListenersPipeEndsToMonitoredEvents(UfsrvSessionsDelegator *sd_ptr)
{
  int setsize = sd_ptr->connection_listeners_delegator.setsize;
  int epoll_fd = sd_ptr->epoll_handle;

  for (int i=0; i!=setsize; i++) {
    int result = _AddConnectionListenerPipeEndToMonitoredEvents(epoll_fd, sd_ptr->connection_listeners_delegator.to_worker_delegator_ipc[i]);
    if (result < 0) {
      //todo log
    }
  }
}

/**
 * @brief A utility function to add pipe fds to epoll events
 * @param epoll_fd Preallocated epoll handler
 * @param instance_sesn_ptr_ipc Session representing the pipe connection
 * @return 0 on success
 */
static int __attribute__((nonnull(2)))
_AddConnectionListenerPipeEndToMonitoredEvents(int epoll_fd, InstanceHolderForSession *instance_sesn_ptr_ipc)
{
  Session *sesn_ptr_ipc = NULL;
  struct epoll_event epoll_event = {};
  epoll_event.events = EPOLLIN;//|EPOLLET; //keep default line-triggered as we want to make sure the pipe is always drained
  epoll_event.data.u64 = 0;
  epoll_event.data.ptr = instance_sesn_ptr_ipc;

  sesn_ptr_ipc = SessionOffInstanceHolder(instance_sesn_ptr_ipc);

  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sesn_ptr_ipc->dsptr->sock, &epoll_event) == -1) {//PIPE READER END is in dsptr not ssptr
    syslog(LOG_ERR, "%s {o:'%p'}: COULD NOT add pipe connection to events loop: WILL NOT be able to process Worker->Delegator IPC pipe: errno='%d'", __func__, sesn_ptr_ipc, errno);
    return -1;
  } else {
    syslog(LOG_ERR, "%s {o:'%p', fd:'%d'}: Listener->Worker-Delegator IPC Pipe: Added pipe reader fd to monitored events...", __func__, sesn_ptr_ipc, sesn_ptr_ipc->dsptr->sock);
  }

  return 0;
}

#if 0
	unsigned 	counter=0,
						cmdid=0,
						handshake=1;
	long long service_start,
						service_end;
	Session 	*sesnptr=NULL;
	Socket 		*ssptr=NULL;
	SessionService *ss_ptr=NULL;
	HttpRequestContext http_request_context={0};
	RequestRateLimitStatus ratelimit_status={0};
	WorkerThreadCreationContext *th_ctx_ptr=(WorkerThreadCreationContext *)ptr;
	extern SessionsDelegator *const sessions_delegator_ptr;

	SessionsDelegator *const sd_ptr=sessions_delegator_ptr;
	//Session *sesn_ptr_ipc=(Session *)ptr; //worker-delegator ipc pipe fds
	Session *sesn_ptr_ipc=th_ctx_ptr->ipc_pipe; //worker-delegator ipc pipe fds

	{
		#define MAX_NAME_LEN 15
		char proc_name [MAX_NAME_LEN + 1];	/* Name must be <= 15 characters + a null */

		strncpy (proc_name, "ufSessnWorker", MAX_NAME_LEN);
		proc_name [MAX_NAME_LEN] = 0;
		prctl (PR_SET_NAME, (unsigned long)&proc_name);
		#undef MAX_NAME_LEN
	}

	__init_block:
	#if 1

	//setup key for storing the value of worker-delegator pipe Session *.
	//We may not need this key outside the context of this function, as the session is passed down from thread parent
	pthread_setspecific(THRKEY_WORKER_DELEGATOR_PIPE(sessions_delegator_ptr), (void *)sesn_ptr_ipc);

	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

		//makesure you initialise all keys in UFSRVThreadsOnceInitialiser (void);
		if (IS_PRESENT(InitialiseHttpRequestContext(&http_request_context, 0)))
		{
			pthread_setspecific(masterptr->threads_subsystem.ufsrv_http_request_context_key, (void *)&http_request_context);//TODO: move key to delegator structure
		}
		else
		{
			syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE HttpRequestContext for Session Worker thread: '%lu'...", __func__, pthread_self());
			_exit(-1);
		}

		syslog(LOG_DEBUG, "%s: SUCCESS (http_ptr:'%p'): Initialised HttpRequestContext for Session Worker thread: '%lu'...", __func__, &http_request_context, pthread_self())
		;
	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

	InstrumentationBackend *instr_ptr=NULL;
	instr_ptr=InstrumentationBackendInit (NULL);//no namespace
	if (instr_ptr)
	{
		pthread_setspecific(masterptr->threads_subsystem.ufsrv_instrumentation_backend_key, (void *)instr_ptr);//TODO: move key to delegator structure
	}
	else
	{
		syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE INSTRUMENTATION for Session Worker thread: '%lu'...", __func__, pthread_self());
	}

	syslog(LOG_DEBUG, "%s: SUCCESS (instr_ptr:'%p'): Initialised Instrumentation Backend for Session Worker thread: '%lu'...", __func__, instr_ptr, pthread_self());

	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
	PersistanceBackend *per_ptr=NULL;
	per_ptr=InitialisePersistanceBackend(NULL);
	if (per_ptr)
	{
		pthread_setspecific(masterptr->threads_subsystem.ufsrv_data_key, (void *)per_ptr);//TODO: move key to delegator structure
	}
	else
	{
		syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE persistence for Session Worker thread: '%lu'...", __func__, pthread_self());
		_exit (-1);
	}

	syslog(LOG_INFO, "%s: SUCCESS: Initialised Persistence Backend for Session Worker thread: '%lu'...", __func__, pthread_self());

	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		UserMessageCacheBackend *per_ptr_usrmsg=NULL;
		per_ptr_usrmsg=InitialiseCacheBackendUserMessage(NULL);
		if (per_ptr_usrmsg)
		{
			pthread_setspecific(masterptr->threads_subsystem.ufsrv_usrmsg_key, (void *)per_ptr_usrmsg);//TODO: move key to delegator structure
		}
		else
		{
			syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE Cache Backend UserMessage  for Session Worker thread: '%lu'...", __func__, pthread_self());
			_exit (-1);
		}

		syslog(LOG_INFO, "%s: SUCCESS (%p): Initialised Cache Backend UserMessage for Session Worker thread: '%lu'...", __func__, per_ptr_usrmsg, pthread_self());

	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
	FenceCacheBackend *per_ptr_fence=NULL;
	per_ptr_fence=InitialiseCacheBackendFence(NULL);
	if (per_ptr_fence)
	{
		pthread_setspecific(masterptr->threads_subsystem.ufsrv_fence_key, (void *)per_ptr_fence);//TODO: move key to delegator structure
	}
	else
	{
		syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE Cache Backend Fence  for Session Worker thread: '%lu'...", __func__, pthread_self());
		_exit (-1);
	}

	syslog(LOG_INFO, "%s (%p): SUCCESS: Initialised Cache Backend Fence for Session Worker thread: '%lu'...", __func__, per_ptr_usrmsg, pthread_self());
	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

	struct _h_connection *db_ptr=NULL;
	db_ptr=InitialiseDbBackend();
	if (db_ptr)
	{
		pthread_setspecific(masterptr->threads_subsystem.ufsrv_db_backend_key, (void *)db_ptr);//TODO: move key to delegator structure
	}
	else
	{
		syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE DB Backend access for Session Worker thread: '%lu'...", __func__, pthread_self());
		_exit (-1);
	}

	syslog(LOG_INFO, "%s: SUCCESS: Initialised DB Backend for Session Worker thread: '%lu'...", __func__, pthread_self());


	//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

	MessageQueueBackend *mq_ptr=NULL;
	mq_ptr=InitialiseMessageQueueBackend(NULL);
	if (mq_ptr)
	{
		pthread_setspecific(masterptr->threads_subsystem.ufsrv_msgqueue_pub_key, (void *)mq_ptr);//TODO: move key to delegator structure
	}
	else
	{
		syslog(LOG_ERR, "%s: ERROR: COULD NOT INITIALISE MessageQueue Publisher for Session Worker thread: '%lu'...", __func__, pthread_self());
		_exit (-1);
	}

	syslog(LOG_INFO, "%s: SUCCESS Initialised MessageQueue Publisher backend for Session Worker thread: '%lu'...", __func__, pthread_self());

	#endif
	//end init_block

	while (1)
	{
		UFSRVResult res;
		SocketMessage *sm_ptr_consolidated=NULL;
		unsigned long stat_atomic=0;

		syslog(LOG_DEBUG, "%s (pid:'%lu): --------- START MAIN LOOP ------- ", __func__, pthread_self());

#if __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:'%lu'): BEGIN COND_WAIT EVENT: Acquiring work queue mutex lock and fetching Session... I may block", __func__, pthread_self());
#endif

		if ((WorkQueueLock(sd_ptr, 0))!=0)
		{
			syslog(LOG_NOTICE, "%s (pid:'%lu): ERROR: COULD NOT ACQUIRE WORK QUEUE LOCK: looping gain.... ", __func__, pthread_self());
			continue;
		}

//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		while (!(LamportQueuePop(th_ctx_ptr->queue, (QueueClientData **)&sesnptr)) && (sd_ptr->up_status==1))
		{
#if __UF_FULLDEBUG
			syslog(LOG_DEBUG, "ThreadWebSockets (3:2 pid:'%lu' lock:30:-1 ): Mutex automatically released: Blocking on condition: waiting for signal: queue_not_empty_cond", pthread_self());
#endif
			pthread_cond_wait(&(sd_ptr->queue_not_empty_cond),	&(sd_ptr->work_queue_mutex));
		}
//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

#if __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:%lu): >>> RECIEVED WORK SIGNAL", __func__, pthread_self());
#endif

		//lock now acquired automatically by pthreads.. we unlock at the end

		if (sd_ptr->up_status==0)
		{
			syslog(LOG_INFO, "%s (3:4 pid:%lu): SessionDelegator is shutting down: releasing mutext lock: exiting...", __func__, pthread_self());

			WorkQueueUnLock(sd_ptr);
			pthread_exit(NULL);
		}

		WorkQueueUnLock(sd_ptr);//other threads are now free to acquire the lock and dequeue further

		__atomic_op:
		//if (__sync_and_and_fetch(&sesnptr->stat, SESNSTATUS_IOERROR))
		stat_atomic=__sync_add_and_fetch (&(sesnptr->stat), 0);
		if (SESNSTATUS_IS_SET(stat_atomic, SESNSTATUS_IOERROR))
		{
			syslog(LOG_NOTICE, LOGSTR_TSWORKER_FAULTYSESN_OOB,
					__func__, pthread_self(), sesnptr, SESSION_ID(sesnptr), LOGCODE_TSWORKER_FAULTYSESN_OOB);

			//RemoveSessionToMonitoredWorkEvents(sesnptr);

			continue;
		}

		//>>>>>>>>>>>>>>>>>>>>>>>
		if ((SessionLockRW(sesnptr, 1))!=0)
		{
			_HandleBusySessionLock(sesnptr);
			continue;
		}
		//>>>>>>>>>>>>>>>>>>>>>>>

		//>>>>>>>> Session successfully locked

		//this is to trap a rare scenario where a session which is currently in recycler yet still in epoll's list
		if (SESNSTATUS_IS_SET(sesnptr->stat, SESNSTATUS_RECYCLED))
		{
			syslog(LOG_NOTICE, LOGSTR_TSWORKER_FAULTYSESN,	__func__, pthread_self(), sesnptr, SESSION_ID(sesnptr), LOGCODE_TSWORKER_FAULTYSESN);

			//>>>>>>>>>>>>>>>>>>>>>>>
			SessionUnLock (sesnptr);
			//>>>>>>>>>>>>>>>>>>>>>>>

			continue;
		}

		//how much time elapsed since work was initially signalled
		sesnptr->pid=pthread_self();
		//statsd_timing(sd_ptr->instrumentation_backend_ptr, "worker.work.signal_elapsed_time", (sesnptr->when_signal_end=time(NULL))-sesnptr->when_signal_start);

		__check_busy_session:
		#if 1

		//this can happen with long request queue and the session was terminated/suspended earlier
		if (SESNSTATUS_IS_SET(sesnptr->stat, SESNSTATUS_SUSPENDED ))
		{
			//TODO: We should fetch the message to disarm the event
			syslog(LOG_NOTICE, "%s (pid:%lu cid:%lu): RECEIVED EVENT FOR A SUSPENDED SESSION: NOT-SUSPENDING: UNLOCKING and RETURNING...",
					__func__, pthread_self(), SESSION_ID(sesnptr));

			{
				//statsd_inc(sesnptr->instrumentation_backend, "worker.in_event.suspended", 1.0);

				//>>>>>>>>>>>>>>>>>>>>>>>
				SessionUnLock (sesnptr);
				//>>>>>>>>>>>>>>>>>>>>>>>
			}

			//back to cond_wait
			continue;
		}

		//TODO: how did acquire the lock if the session is actively servicing?
		if (SESNSTATUS_IS_SET(sesnptr->stat, SESNSTATUS_INSERVICE ))
		{
			syslog(LOG_NOTICE, "%s (pid:%lu cid:%lu): RECEIVED EVENT for IN-SERVICE Session: (NOT) INSERTING in SocketMessageQueue (msg count='%lu')...",
				__func__, pthread_self(), sesnptr->session_id, sesnptr->message_queue_in.queue.nEntries);

			//statsd_inc(sesnptr->instrumentation_backend, "worker.in_event.serviced", 1.0);

			//>>>>>>>>>>>>>>>>>>>>>>>
			SessionUnLock (sesnptr);
			//>>>>>>>>>>>>>>>>>>>>>>>

			//back to cond_wait
			continue;
		}

		#endif
		//end check_busy_session

		//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		__session_in_service:

		//set the scene up... we need this as soon as possible, before we start queue consolidation, as Session context
		//needs to be setup prior to any request handling.
		__load_session_context:
		#if 1

		SESNSTATUS_SET(sesnptr->stat, SESNSTATUS_INSERVICE);//Session being picked up for service
		service_start=GetTimeNowInMicros();

		sesnptr->persistance_backend			=	pthread_getspecific(masterptr->threads_subsystem.ufsrv_data_key);
		sesnptr->instrumentation_backend	=	pthread_getspecific(masterptr->threads_subsystem.ufsrv_instrumentation_backend_key);
		sesnptr->msgqueue_backend					=	pthread_getspecific(masterptr->threads_subsystem.ufsrv_msgqueue_pub_key);
		sesnptr->usrmsg_cachebackend			=	pthread_getspecific(masterptr->threads_subsystem.ufsrv_usrmsg_key);
		sesnptr->fence_cachebackend				=	pthread_getspecific(masterptr->threads_subsystem.ufsrv_fence_key);
		sesnptr->db_backend								=	pthread_getspecific(masterptr->threads_subsystem.ufsrv_db_backend_key);

		#endif
		//end load_session_context

#if __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:%lu cid:%lu proto:'%d'): END COND_WAIT EVENT: Session retrieved: performing Session I/O work...",
				__func__, pthread_self(), SESSION_ID(sesnptr), PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesnptr))));
#endif

		//do work
		{
			unsigned long		session_id_invoked;
			Session 			*sesn_ptr_processed	= NULL;
			UFSRVResult 		*res_ptr;
			struct epoll_event	*ee_ptr=NULL;

			ee_ptr=(struct epoll_event *)sesnptr->event_descriptor;
			if (ee_ptr)
			{
				sesnptr->when_serviced_start=time(NULL);//service_start/1000000UL;

				session_id_invoked=SESSION_ID(sesnptr);

				//statsd_inc(sesnptr->instrumentation_backend, "worker_counter", 1.0);

				//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
				//this may return a suspended session
				Session *sesn_ptr_aux;
				res_ptr=_HandleSessionWorkRequest (sesnptr, sd_ptr, session_id_invoked);//we always return session back regardless
				{
					sesn_ptr_aux=(Session *)res_ptr->result_user_data;

					if (unlikely(IS_EMPTY(sesn_ptr_aux)))
					{
						syslog(LOG_ERR, "%s (pid:%lu, cid_invoked:'%lu'): SEVERE ERROR: WE LOST REFERENCE TO SESSION...", __func__, pthread_self(), session_id_invoked);
						continue;
					}
				}
				//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

				SESNSTATUS_UNSET(sesn_ptr_aux->stat, SESNSTATUS_INSERVICE);

				//This does not always mean error: could be normal user-initiated shutdown so don't operate based on RESCODE_ERR
				//here we trap all the previous soft suspend operation: ie. socket no longer connected and shouldnot be in epoll, but some
				//may still linger in epoll
				bool recycle_flag=false;

				__session_suspended:
				#if 1

				//All error handling happens at lower level. Here we are only interested if the Session is still live or suspended
				if (SESNSTATUS_IS_SET(sesn_ptr_aux->stat, SESNSTATUS_SUSPENDED))
				{
					//two rules apply:
					//1) if _RESULT_TYPE_SUCCESS means user initiated quit, so we hard suspend
					//2)if _RESULT_TYPE_ERROR we check if protocol allow for grace soft period
					///syslog(LOG_ERR, LOGSTR_TSWORKER_HARD_SUSPEND,
						///__func__, pthread_self(), sesn_ptr_aux, SESSION_ID(sesn_ptr_aux), LOGCODE_TSWORKER_HARD_SUSPEND);

					if (_RESULT_TYPE_SUCCESS(res_ptr))
					{
						//all statements with '///' intentionally disabled
						///if (SuspendSession (sesn_ptr_aux, 1))	recycle_flag=true;
					}
					else
					if ((_RESULT_TYPE_ERROR(res_ptr)) &&
						(!_PROTOCOL_CTL_RETAIN_SESSION_ON_ERROR(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr_aux))))))
					{
						///if (SuspendSession (sesn_ptr_aux, 1))	recycle_flag=true;
					}
				}//SESNSTATUS_SUSPENDED

				#endif
				//end session_suspended

				if (SESNSTATUS_IS_SET(sesn_ptr_aux->stat, SESNSTATUS_RECYCLEREQUEST))
				{
					WorkerDelegatorRaiseRecycleRequest	(sesn_ptr_aux, NULL);
					//TODO: unset SESNSTATU_RECYCLE if fail
				}

				#if 1
				{
					size_t queue_sz=0;

					//quick atomic check as we dont hold the socketmessage queue lock, other threads may still have logged something
					___atomic_check:
					if ((queue_sz=__sync_add_and_fetch (&(SESSION_INSOCKMSG_QUEUE_SIZE(sesn_ptr_aux)), 0))>0)
					{
						syslog(LOG_DEBUG, LOGSTR_TSWORKER_QUEUE_POST_REQUEST,
								__func__, pthread_self(),sesn_ptr_aux, SESSION_ID(sesn_ptr_aux), queue_sz, LOGCODE_TSWORKER_QUEUE_POST_REQUEST);

						WorkerDelegatorRaiseRecycleRequest	(sesn_ptr_aux, NULL);
					}
				}
				#endif

				//>>>>>>>>>>>>>>>>>>>>>>>
				service_end=GetTimeNowInMicros();
				sesn_ptr_aux->when_serviced_end=time(NULL);//service_end/1000000UL;
				statsd_timing(pthread_getspecific(masterptr->threads_subsystem.ufsrv_instrumentation_backend_key), "worker.session.service.elapsed_time", (service_end-service_start));

				SessionUnLock (sesn_ptr_aux);

				//at the moment this semantic is disabled. Kicking off session in this loop has proved problematic
				//instead, we rely on timer thread to catch up with it
				if (recycle_flag)
				{
					//IMPORTANT to only add to recycler after session has been unlocked and completely reset
					SESNSTATUS_SET(sesn_ptr_aux->stat, SESNSTATUS_RECYCLED);

					RecyclerPut(1, (RecyclerClientData *)sesn_ptr_aux, (ContextData *)NULL, 0);
					recycle_flag=false;
				}
				//>>>>>>>>>>>>>>>>>>>>>>>

				//else the Session either destructed or suspended so we don't care
			}//epoll event
			else
			{
				syslog(LOG_ERR, "%s (pid:%lu): !! ERROR COULD NOT FETCH WORK REQUEST EVENT: NULL...",
					__func__, pthread_self());

				SESNSTATUS_UNSET(sesnptr->stat, SESNSTATUS_INSERVICE);

				//>>>>>>>>>>>>>>>>>>>>>>>
				SessionUnLock (sesnptr);//sesnptr wouldnt have change as no processing took place
				//>>>>>>>>>>>>>>>>>>>>>>>
			}

		}//block end

	}//while(1)
#endif


#if 0
inline static void
_HandleBusySessionLock (Session *sesnptr)
{
	//check if session is stuck
	//due to the semantics of ET we will get notification of readiness because we have not fetched data pending in the buffer
	if (SESNSTATUS_IS_SET(sesnptr->stat, SESNSTATUS_IOERROR))
	{
		_LOGN(LOGSTR_TSWORKER_FAULTYSESN_COULDNTLOCK,	__func__, pthread_self(), sesnptr, SESSION_ID(sesnptr), LOGCODE_TSWORKER_FAULTYSESN_COULDNTLOCK);

		//we do this on error
		//RemoveSessionToMonitoredWorkEvents(sesnptr);

		return;
		//TODO: terminate session and force client to reauthenticate
	}

	//SESSION IS busy servicing or blocked: read back into main work events queue
	if ((sesnptr)&&(((struct epoll_event *)(sesnptr->event_descriptor))->events & EPOLLIN))
	{
		__concurrent_session_read:
		#if 1

		//we cannot check ratelimit status because we dont ownthe lock. had to be delegated to ufrvsowrker

		if (_PROTOCOL_CTL_READ_BLOCKED_SESSION(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesnptr)))))
		{
			int return_value;

			//syslog(LOG_NOTICE, "%s (pid='%lu' cid='%lu'): ERROR: COULD NOT WR-LOCK SESSION: READING INTO Session's SocketMessage INCOMING Queue WITHOUT DECODING (entries count='%lu')...",
			//	__func__, pthread_self(), SESSION_ID(sesnptr), sesnptr->message_queue_in.queue.nEntries);

			//TODO: what if the session is not handshaked? don't read WS

			__read_from_socket_into_msgqueue:
			#if 1

			if ((return_value=ReadFromSocket(sesnptr, NULL,
					SOCKMSG_READSOCKET|SOCKMSG_DONTDECODE|SOCKMSG_DONTOWNSESNLOCK|SOCKMSG_KEEPMSGQUEUE_LOCKED))<=0)
			{
				syslog(LOG_DEBUG, "%s (pid='%lu' cid='%lu' return_value'%d' queue_size:'%lu'): END COND_WAIT EVENT: Releasing mutex lock (-1): I/O error: Session request ignored...",\
					__func__, pthread_self(), SESSION_ID(sesnptr), return_value, SESSION_INSOCKMSG_QUEUE_SIZE(sesnptr));

				//restore
				MessageQueueUnLock(sesnptr, &(sesnptr->message_queue_in));
				sesnptr->when_serviced_end=time(NULL);
				return;
			}
			else
			{
#if __UF_FULLDEBUG
				syslog(LOG_DEBUG, "%s (pid='%lu', o:'%p', cid='%lu'): END COND_WAIT EVENT: Releasing mutex lock (-1): Added to MessageQueue...", __func__, pthread_self(), sesnptr, SESSION_ID(sesnptr));
#endif
				//restore
				MessageQueueUnLock(sesnptr, &(sesnptr->message_queue_in));
				sesnptr->when_serviced_end=time(NULL);
			}

			//fall-through to continue below, back to the main loop. we may have read i/o error

			#endif
			//read_from_socket_into_msgqueue:
		}
		else
		{
			syslog(LOG_ERR, "%s (pid='%lu'. o:'%p', cid='%lu'): DID NOT READ INTO SocketMessage Queue: .._CTL_READ_BLOCKED_SESSION IS OFF", __func__, pthread_self(), sesnptr, SESSION_ID(sesnptr));
		}
		#endif
		//end concurrent_session_read:
	}
	else
	if ((sesnptr)&&(((struct epoll_event *)(sesnptr->event_descriptor))->events & EPOLLOUT))
	{
		syslog(LOG_ERR, "%s (pid='%lu', o:'%p', cid='%lu'): RECIEVED EPOLLOUT Event for a LOCKED SESSION: IGNORING...", __func__, pthread_self(), sesnptr, SESSION_ID(sesnptr));
	}
	else
	{
		syslog(LOG_ERR, "%s (pid='%lu', o:'%p',  cid='%lu'): RECIEVED UNKNOWN EPOLL Event for a LOCKED SESSION: IGNORING...", __func__, pthread_self(), sesnptr, SESSION_ID(sesnptr));
	}

	sesnptr->when_serviced_end=time(NULL);

	//finish cycle: back to cond_wait and attempt to deque again
}


/**
//@brief	called from the websocket worker thread after it picked up a session work request. Its main function is a glue between the worker and the
//	low-level network i/o message processing stream, including websocket de-framing and command processing.
//	after returning from the i/o stream it checks the incoming queue for missed messages.
*	@locks: SocketMessage Queue indirectly via ConsolidateMessageQueue
*/
static inline UFSRVResult *//Session *
_HandleSessionWorkRequest(Session *sesnptr, SessionsDelegator *sd_ptr, unsigned long session_id_invoked)
{
//	Session *sesn_ptr_processed=NULL;;
	UFSRVResult *res_ptr;

	res_ptr=_p_ProcessSessionSocketMessage(sesnptr, SESSION_INSOCKMSG_TRANS_PTR(sesnptr), SOCKMSG_READSOCKET);

	if (_RESULT_TYPE_SUCCESS(res_ptr))
	{
		return (_HandleSuccessfulWorkRequest(sd_ptr, session_id_invoked, res_ptr));
	}
	else
	{
		request_error:
		//session maybe suspended or failed to Unsuspend
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s (pid:%lu, cid_invoked:'%lu'): UNSUCCESSFULLY PEROCESSED WORK REQUEST for Session...",__func__, pthread_self(), session_id_invoked);
#endif

		return res_ptr;// this contains the apropriate error designation
		//_RETURN_RESULT_SESN(sesnptr, sesnptr, RESULT_TYPE_ERR, res_ptr->result_code);//RESCODE_SERVICED);
	}

}


/**
 * 	@brief: Session request was previously successfully completed. Before we return to the thread's main loop we checke if the
 * 	the session has received any new incoming packets and process accordingly.
 *
 * 	@locked sesn_ptr_processed: by main loop
 */
static inline UFSRVResult *
_HandleSuccessfulWorkRequest (SessionsDelegator *sd_ptr, unsigned long session_id_invoked, UFSRVResult *res_ptr)
{
	Session *sesn_ptr_processed=(Session *)_RESULT_USERDATA(res_ptr);//session object is always returned, even if suspended

	if (SESSION_ID(sesn_ptr_processed)!=session_id_invoked)
	{
#if __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:%lu o:'%p' cid:%lu): SESSION CHANGE OVER: invoked with: '%lu' -> returned: '%lu'", __func__, pthread_self(), sesn_ptr_processed, SESSION_ID(sesn_ptr_processed), session_id_invoked, SESSION_ID(sesn_ptr_processed));
#endif
	}

	//(2)check for/process stored message in incoming queue whilst in locked state
	__consolidate_msgqueue_post:
	#if 1

	if (((struct epoll_event *)(sesn_ptr_processed->event_descriptor))->events & EPOLLIN)
	{
		//this locks the entire incoming queue. mid-process threads won't be able to add to it
		UFSRVResult		res;
		SocketMessage	*sm_ptr_consolidated;

		//consolidate all queue entries into the transient incoming SocketMessage buffer ie sesn_ptr->ssptr->incoming
		//LOCKS MESSAGE QUEUE
		ConsolidateSocketMessageQueue(sesn_ptr_processed,
									  (SOCKMSG_CONSOLIDATE_INSESSION|SOCKMSG_LOCK_SOCKMSGQUEUE), &res);

		if (res.result_type==RESULT_TYPE_SUCCESS)
		{
			sm_ptr_consolidated=(SocketMessage *)res.result_user_data;

			if (!(sm_ptr_consolidated->sm_errno==0))
			{
				syslog(LOG_DEBUG, LOGSTR_QUEDIOERR,
						__func__, pthread_self(), sesn_ptr_processed, SESSION_ID(sesn_ptr_processed), sm_ptr_consolidated->sm_errno, LOGCODE_TSWORKER_QUEUEDIOERR, "POST REQUEST SERVICE");

				//requires Session lock, but since we performed consolidation above, no SocketMessage queue lock is required
				//don't consolidate we are not passing SOCKMSG_CONSOLIDATE_INSESSION
				//BUFFERS(if any as result of consolidation) DEALLOCATED in hard suspend

				ErrorFromSocket (sesn_ptr_processed, 0);//Suspends session

				res_ptr->result_type=RESULT_TYPE_ERR;
				res_ptr->result_code=RESCODE_IO_SOCKETQUEUE_CONSOLIDTED;
				res_ptr->result_user_data=sesn_ptr_processed;

				goto request_error_pre;
			}

			res_ptr=_p_ProcessSessionSocketMessage(sesn_ptr_processed, sm_ptr_consolidated, SOCKMSG_READBUFFER);
			if (_RESULT_TYPE_SUCCESS(res_ptr))
			{
				goto request_successful;
			}
			else
			{
				//ON ERROR: _p_ProcessSessionSocketMessage() INVOKES SuspendsSession()
				goto request_error_pre; //this will return res_ptr along with its error settings
			}
		}
		else
		if ((res.result_code!=RESCODE_LOGIC_EMPTY_RESOURCE) && (res.result_code!=RESCODE_LOGIC_CANTLOCK))//ie error is not related to queue being empty
		{
			//too bad we just bailout the session
			syslog(LOG_DEBUG, LOGSTR_IO_BUF_CONSOLIDATION_ERR,
				__func__, pthread_self(), sesn_ptr_processed, SESSION_ID(sesn_ptr_processed), LOGCODE_IO_BUF_CONSOLIDATION_ERR);

			res_ptr->result_type=res.result_type;
			res_ptr->result_code=res.result_code;
			res_ptr->result_user_data=sesn_ptr_processed;

			SuspendSession (sesn_ptr_processed, 0);

			goto request_error_pre;
		}
		else goto request_successful;//queue was empty, so we are good to proceed
	}

	#endif
	//end __consolidate_msgqueue_post

	request_successful:
	//sesn_ptr_processed->when_serviced_end=time(NULL);//orig sesnptr
	sesn_ptr_processed->persistance_backend=NULL;
	sesn_ptr_processed->instrumentation_backend=NULL;

#ifdef __UF_FULLDEBUG
	syslog(LOG_DEBUG, "%s (pid:%lu, cid:%lu): SUCCESSFULLY PEROCESSED WORK REQUEST...", __func__, pthread_self(), SESSION_ID(sesn_ptr_processed));
#endif

	_RETURN_RESULT_SESN(sesn_ptr_processed, sesn_ptr_processed, RESULT_TYPE_SUCCESS, RESCODE_SERVICED);

	request_error_pre:
	//sesn_ptr_processed->when_serviced_end=time(NULL);//orig sesnptr
	goto request_error;

	request_error:
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s (pid:%lu, cid_invoked:'%lu'): UNSUCCESSFULLY PEROCESSED WORK REQUEST for Session...",__func__, pthread_self(), session_id_invoked);
#endif

	return res_ptr;

}


//https://medium.com/where-the-flamingcow-roams/down-the-epoll-rabbit-hole-5c0447cb6329#.seqhl1vxx
/**
* @brief	process a single message contained on in SocketMessage, which could be in any state other than new connection request,which
*	handled in the main loop. Handshake and other regular comms are processed here.
* For brand new connections:
* Session is either newly created (FLEDGLING|CONNECTED) or a previously connected one (RECYCLED|CONNECTED)
* FLEDGLING does not have a SessionService body initiated. Where it fails handshake we destruct it as opposed to recycle
* For recurring requests Sesion must be (CONNECTED|HANDSKAED|AUTHENTICATED) RECYCLED is irrelevant
* we should not allow a Session to be serviced by two simultaneous workers
* @locks
*/
static UFSRVResult *
_p_ProcessSessionSocketMessage (Session *sesn_ptr, SocketMessage *sock_msg_ptr, int flag)
{
	if (unlikely(IS_EMPTY(sesn_ptr)))
	{
		goto exit_non_successful;
	}

	SessionService				*ss_ptr					= NULL;
	extern SessionsDelegator	*const sessions_delegator_ptr;

	struct epoll_event 			*ee_ptr=(struct epoll_event *)sesn_ptr->event_descriptor;

	if ((ee_ptr->events&EPOLLRDHUP || ee_ptr->events&EPOLLERR|| ee_ptr->events&EPOLLHUP) && !(flag&SOCKMSG_READBUFFER))
	{
#ifdef __UF_FULLDEBUG
		syslog(LOG_NOTICE, LOGSTR_TSWORKER_POLLERR,
				__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_SOCKETFD(sesn_ptr), LOGCODE_TSWORKER_POLLERR, "RETURNING, UNLESS EPOLLIN & EPOLLHUP are both set");
#endif

		if ((ee_ptr->events&EPOLLHUP /*|| ee_ptr->events&EPOLLRDHUP*/) && (ee_ptr->events&EPOLLIN))//not sure about EPOLLRDHUP
		{
#ifdef __UF_FULLDEBUG
			syslog(LOG_NOTICE, LOGSTR_TSWORKER_POLLERR_IN,
					__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_SOCKETFD(sesn_ptr), LOGCODE_TSWORKER_POLLERR_IN, "EPOLLIN & EPOLLHUP set: Performing one last read");
#endif

			goto __readable_input;
		}

		//requires session lock and SocketMessage lock
		ErrorFromSocket(sesn_ptr, flag|=(SOCKMSG_CONSOLIDATE_INSESSION|SOCKMSG_LOCK_SOCKMSGQUEUE));

		//back to cond_wait
		_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_IO_POLL);

		//TODO if SOCKMSG_READBUFFER is set, we should be able to finish off local processing in "offline" mode
	}
	else
	if ((ee_ptr->events&EPOLLIN) || (flag&SOCKMSG_READBUFFER))
	{
		__readable_input:
#if 1
//new block
		if (!(sesn_ptr->stat&SESNSTATUS_CONNECTED))
		{
			syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p' cid:'%lu' fd:'%d'): SESSION NOT CONNECTED: RETURNING...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_SOCKETFD(sesn_ptr));

			goto exit_non_successful;
		}

		if (_PROTOCOL_CLLBACKS_HANDSHAKE(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr)))))
		{
			__protocol_feature_handshake:
			#if 1

			if (!(sesn_ptr->stat&SESNSTATUS_HANDSHAKED) && !(sesn_ptr->stat&SESNSTATUS_AUTHENTICATED))
			{
#ifdef __UF_FULLDEBUG
				syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p', cid:'%lu'): INVOKING HANDSHAKE LIFECYCLE CALLBACK...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
#endif

				//perform initial WS handshake validation
				__protocol_callback:
				#if 1

				if (_PROTOCOL_CLLBACKS_HANDSHAKE(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr)))))
				{
					UFSRVResult *res_ptr=_PROTOCOL_CLLBACKS_HANDSHAKE_INVOKE(protocols_registry_ptr,
														PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))),
														sesn_ptr, sock_msg_ptr, 0/*callflags*/, NULL);

					switch (res_ptr->result_type)
					{
						case RESULT_TYPE_ERR:

							statsd_gauge_inc(sesn_ptr->instrumentation_backend, "worker.work.handshake_failed", 1);

							_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_PROTOCOL_WSHANDSHAKE);

						default:
							break;
							//just continue below with the _HandlePostSuccessfulIncomingHandshake()
					}
				}

				#endif
				//end protocol_callback

				//IMPORTANT: we are yet to return the WS handshake sequence, as this happens within the called function
				return (_HandlePostSuccessfulIncomingHandshake(sesn_ptr, sock_msg_ptr));

			}
			else
			if ((sesn_ptr->stat&SESNSTATUS_HANDSHAKED) && (sesn_ptr->stat&SESNSTATUS_AUTHENTICATED))
			{
				syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p' cid:'%lu'): CONNECTED USER MSG RECEIVED...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

				//if (IsRateLimitExceeded (sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), RLNS_REQUESTS))	_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_USER_RATELIMIT_EXCEEDED);

				return (_HandleMessageForConnectedSession(sesn_ptr, sock_msg_ptr, flag));
			}
			else
			{
				//in a level triggered polling, an event could be in the queue for a session that is recycled because the object is not
				//destroyed it is in the recycler.
				syslog(LOG_NOTICE, "%s (pid:'%lu' o:'%p' cid:'%lu'): INCONSISNTENT SESSION STATE: ('%lu'): IGNORING",
					__func__, SESSION_PID(sesn_ptr), sesn_ptr, SESSION_ID(sesn_ptr), sesn_ptr->stat);

				//TODO: this is causes inconsistencies, especially if ses is already suspended
				//SuspendSession (sesn_ptr, 0);

				_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_IO_SESSIONSTATE);
			}

			#endif
			//end protocol_feature_handshake
		}//handshake lifecycle
		else
		{
			__protocol_feature_no_handshake:
#ifdef __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu' fd:'%d'): NO-HANDSHAKE CONNECTED USER MSG RECEIVED...", __func__, pthread_self(), SESSION_ID(sesn_ptr), SESSION_SOCKETFD(sesn_ptr));
#endif
			//this is too early to identify the user
			//if (IsRateLimitExceeded (sesn_ptr, SESSION_USRMSG_CACHEBACKEND(sesn_ptr), RLNS_REQUESTS))	_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_USER_RATELIMIT_EXCEEDED);

			return (_HandleMessageForConnectedSession(sesn_ptr, sock_msg_ptr, flag));

		}//no handshake lifecycle
//new block
#endif

	}
	else
	if (ee_ptr->events & EPOLLOUT)
	{
		syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu' fd:'%d'): Received  EPOLLOUT event: DEQUEUEING outgoing SocketMessage Queue...",
			__func__, pthread_self(), SESSION_ID(sesn_ptr), SESSION_SOCKETFD(sesn_ptr));

		return (_InvokeLifecycleCallbackMsgOut (sesn_ptr, sock_msg_ptr, 0));
		//DispatchSocketMessageQueue (sesn_ptr, sesn_ptr->message_queue_out.queue.nEntries);

		//_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_IO_MSGDISPATCHED);
	}


	exit_non_successful:
	_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_IO_POLL);

}


static inline UFSRVResult *
_InvokeLifecycleCallbackPostHandshake (Session *sesn_ptr, SocketMessage *sock_msg_ptr)
{
	if (_PROTOCOL_CLLBACKS_POST_HANDSHAKE(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr)))))
	{
		UFSRVResult *res_ptr=_PROTOCOL_CLLBACKS_POST_HANDSHAKE_INVOKE(protocols_registry_ptr,
											PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))),
											sesn_ptr, sock_msg_ptr, 0/*callflags*/);

		switch (_RESULT_TYPE(res_ptr))
		{
			case RESULT_TYPE_ERR:

				statsd_gauge_inc(sesn_ptr->instrumentation_backend, "worker.work.handshake_failed", 1);

				SuspendSession(sesn_ptr, 0);

				_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_PROTOCOL_WSHANDSHAKE);

			default:
				//could have fallen through to _exit_sucess: below
				_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RECODE_USER_AUTHENTICATION);
		}
	}

	exit_success:
	_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RECODE_USER_AUTHENTICATION);
}


static inline UFSRVResult *
_InvokeLifecycleCallbackMsgOut (Session *sesn_ptr, SocketMessage *sock_msg_ptr, unsigned long call_flags)
{
	DispatchSocketMessageQueue (sesn_ptr, sesn_ptr->message_queue_out.queue.nEntries);

	if (_PROTOCOL_CLLBACKS_MSG_OUT(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))))) {
		UFSRVResult *res_ptr=_PROTOCOL_CLLBACKS_MSG_OUT_INVOKE(protocols_registry_ptr,
											PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))),
											sesn_ptr, sock_msg_ptr, call_flags, 0);

		switch (_RESULT_TYPE(res_ptr))
		{
			case RESULT_TYPE_ERR:

				statsd_gauge_inc(sesn_ptr->instrumentation_backend, "worker.work.handshake_failed", 1);

				SuspendSession(sesn_ptr, 0);

				_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_IO_MSGDISPATCHED);

			default:
				//could have fallen through to _exit_sucess: below
				if (_RESULT_CODE_EQUAL(res_ptr, RESCODE_SESN_SOFTSPENDED))	SuspendSession(sesn_ptr, 0);
				_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_IO_MSGDISPATCHED);
		}
	}
	else
	{
		syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): NO MSG OUT CALLBACK DEFINED FOR PROTOCOL (id:'%d', name:'%s')", __func__, sesn_ptr->pid, SESSION_ID(sesn_ptr),
						PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))), PROTO_PROTOCOL_NAME(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))));
	}

	exit_success:
	_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_IO_MSGDISPATCHED);
}


/**
 * 	@brief: Key Session routing function for connections that support handshake.
 * 	Transition the newly connected session (aka in transient state) past initial incoming handshake.
 * 	Session is not authenticated in anyway. We have just processed basic comms/protocol semantics.
 *
 * 	@dynamic_memory redisReply: IMPORTED BY PROXY <- BackendCacheGetSessionRecordByCookie() AND EXPORTED -> _AuthenticateForBackendCookieHashedSession().
 * 	  Not feree'd here
 */
inline static UFSRVResult *
_HandlePostSuccessfulIncomingHandshake (Session *sesn_ptr, SocketMessage *sock_msg_ptr)
{
#ifdef __UF_FULLDEBUG
	syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p' cid:'%lu'): LOOKING UP SESSION COOKIE FOR EXITING SESSION...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
#endif

	Session *sesn_ptr_hashed=(Session *)HashLookup(&(sessions_delegator_ptr->hashed_cookies.hashtable), (void *)SESSION_COOKIE(sesn_ptr), true);

	//this may indicate a concurrent sign on
	if (sesn_ptr_hashed)
	{
		UFSRVResult *res_ptr_cookie=NULL;

		res_ptr_cookie=AuthenticateForCookieHashedSession(sesn_ptr, sesn_ptr_hashed, sock_msg_ptr);

		if (_RESULT_TYPE_SUCCESS(res_ptr_cookie))
		{
			Session *sesn_ptr_processed=(Session *)_RESULT_USERDATA(res_ptr_cookie);
			return (_InvokeLifecycleCallbackPostHandshake(sesn_ptr_processed, sock_msg_ptr));
		}
		else if ((_RESULT_TYPE_ERROR(res_ptr_cookie)) && (_RESULT_CODE_EQUAL(res_ptr_cookie, RESCODE_USER_SESN_KILLED)))
		{
			//falls through to new session block below: recreate session, as hash was invalid
			//goto inititialise_new_session;
		}
		else return	res_ptr_cookie;//user not allowed through

	}
	else
	{
#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p' cid:'%lu'): COULD NOT FIND SESSION IN LOCAL COOKIE HASH: TRYING BACKEND COOKIE HASH...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
#endif

		//this will help trap concurrent sign on attempts with the same cookie in the conditional above
		//depending on the context, it maybe cleared lateron if an existing session was found in the system, so until
		//that is confirmed we may end up with with the same cookie hashed twice against two different Sessions
		if (!(AddToHash(&(sessions_delegator_ptr->hashed_cookies.hashtable), (void *)sesn_ptr)))
		{
			_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
		}

		UFSRVResult res;

		BackendCacheGetSessionRecordByCookie (sesn_ptr, SESSION_COOKIE(sesn_ptr), 0/*call_flags*/, &res);

		if ((res.result_type==RESULT_TYPE_SUCCESS) && (res.result_code==RESCODE_BACKEND_DATA))//important to check for RESCODE_BACKEND_DATA
		{
			UFSRVResult *res_ptr_backend=NULL;
			res_ptr_backend=AuthenticateForBackendCookieHashedSession(sesn_ptr, &res, sock_msg_ptr);

			if (_RESULT_TYPE_SUCCESS(res_ptr_backend))
			{
				Session *sesn_ptr_processed=(Session *)_RESULT_USERDATA(res_ptr_backend);
				return (_InvokeLifecycleCallbackPostHandshake (sesn_ptr_processed, sock_msg_ptr));
			}
			else return res_ptr_backend; //user not allowed through
		}

		//falls through below to new session, as we couldn't find the user on the network
	}

	//this may uncover the user's presence under its userid value
	//inititialise_new_session:
#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p' cid:'%lu'): COULD NOT FIND SESSION IN LOCAL OR BACKEND COOKIE HASH: proceeding with New Session Initialisation", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
#endif

		UFSRVResult *res_ptr_new_session=NULL;

		res_ptr_new_session=AuthenticateForNonCookieHashedSession(sesn_ptr);

		if (_RESULT_TYPE_SUCCESS(res_ptr_new_session))
		{
			Session *sesn_ptr_processed=(Session *)_RESULT_USERDATA(res_ptr_new_session);
			return _InvokeLifecycleCallbackPostHandshake (sesn_ptr_processed, sock_msg_ptr);
		}

		//contains error of sorts
		return res_ptr_new_session;
}


static inline UFSRVResult *
_HandleMessageForConnectedSession (Session *sesn_ptr, SocketMessage *sock_msg_ptr, int flag)
{
	if (_PROTOCOL_CLLBACKS_MSG(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr)))))
	{
		UFSRVResult *res_ptr=_PROTOCOL_CLLBACKS_MSG_INVOKE(protocols_registry_ptr,
											PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))),
											sesn_ptr, sock_msg_ptr, flag/*callflags*/, 0);

		switch (res_ptr->result_type)
		{
			case RESULT_TYPE_PROTOCOLERR:
			case RESULT_TYPE_IOERR:
			case RESULT_TYPE_ERR:

				_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_ERR, res_ptr->result_code);//RESCODE_PROTOCOL_WSHANDSHAKE);

			default:
				//reset buffer
				if (sock_msg_ptr->processed_msg_size>0)
				{
					free (sock_msg_ptr->_processed_msg);
					sock_msg_ptr->_processed_msg=0;
					sock_msg_ptr->processed_msg_size=0;
				}

				_RETURN_RESULT_SESN(sesn_ptr, sesn_ptr, RESULT_TYPE_SUCCESS, RESCODE_IO_MSGPARSED);
		}
	}
	else
	{
		syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): NO MSG CALLBACK DEFINED FOR PROTOCOL (id:'%d', name:'%s')", __func__, sesn_ptr->pid, SESSION_ID(sesn_ptr),
				PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))), PROTO_PROTOCOL_NAME(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))));
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL,  RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);

}

#endif
