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

#include <uflib/standard_c_includes.h>
#include <ufsrvmsg_core/protocol/protocol.h>
#include <nportredird.h>
#include <uflib/adt/adt_mpsc_queue.h>
#include <uflib/recycler/recycler.h>
#include "sfu_session_provider.h"

extern ufsrv							*const masterptr;
extern const Protocol			*const protocols_registry_ptr;

static int TypePoolInitCallback_Session (ClientContextData *data_ptr, size_t oid);
static int TypePoolGetInitCallback_Session (InstanceHolder *data_ptr, ContextData *context_data, size_t oid, unsigned long call_flags);
static int TypePoolPutInitCallback_Session (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);
static char *TypePoolPrintCallback_Session (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);
static int TypePoolDestructCallback_Session (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);

//assigned when the typepool is initialised, holding meta data on the type under recycler management
static RecyclerPoolHandle *SessionTypePoolHandle;

static RecyclerPoolOps ops_session = {
        TypePoolInitCallback_Session,
        TypePoolGetInitCallback_Session,
        TypePoolPutInitCallback_Session,
        TypePoolPrintCallback_Session,
        TypePoolDestructCallback_Session
};

/**
* param protocol_id: >=0 protocol id which can be used as index. If -1 no protocol is associated with this session
* This is more pool aware version of the function above.
*/
int
InstantiateSessionForSfu(Session **sesn_ptr_in, unsigned long call_flags, int protocol_id)
{
  Session *sesn_ptr = NULL;

  if (sesn_ptr_in)	sesn_ptr = *sesn_ptr_in;
  else {
    sesn_ptr = calloc(1, sizeof(Session));
  }

  if (call_flags&CALL_FLAG_HASH_SESSION_LOCALLY) {
    if ((sesn_ptr->session_id = GenerateSessionId(protocol_id, &sesn_ptr->sservice.result, NULL)) == 0) {
      if (IS_EMPTY(sesn_ptr_in))	free(sesn_ptr);
      return 0;
    }
  }

  pthread_rwlockattr_init(&(sesn_ptr->session_events.rwattr));
  int rc = pthread_rwlock_init(&(sesn_ptr->session_events.rwlock), &(sesn_ptr->session_events.rwattr));//==0 on success

  if (unlikely(rc != 0)) {
    char error_str[MBUF] = {0};
    char *er;
    er = strerror_r(errno, error_str, MBUF);

    syslog(LOG_ERR, "%s {pid:'%lu', errno:'%d' error:'%s'}: ERROR: COULD NOT INITIALISE MUTEX",	__func__, pthread_self(), errno, er);

    goto final_clean_up;
  }

  if (true) {
    //TODO: consider using local variable
    pthread_mutexattr_t attr;

    //Note: using adaptive mutex changes the error reporting behaviour in lock/unlock it would appears multipe locks acquired at the same time
    pthread_mutexattr_init(&(sesn_ptr->message_queue_in.mutex_attr));
    pthread_mutexattr_settype(&(sesn_ptr->message_queue_in.mutex_attr), PTHREAD_MUTEX_ADAPTIVE_NP);//PTHREAD_MUTEX_ERRORCHECK);

    if ((pthread_mutex_init (&(sesn_ptr->message_queue_in.mutex), 	&(sesn_ptr->message_queue_in.mutex_attr))) != 0) {
      syslog(LOG_ERR, "%s (pid:'%lu', errno:'%d'): ERROR: COULD NOT INITIALISE MUTEX FOR INCOMING SOCKETMESSAGE QUEUE...", __func__, pthread_self(), errno);
      pthread_mutexattr_destroy(&(sesn_ptr->message_queue_in.mutex_attr));

      goto final_clean_up;
    }

    pthread_mutexattr_destroy(&(sesn_ptr->message_queue_in.mutex_attr));

    ///////////////

    pthread_mutexattr_init(&(sesn_ptr->message_queue_out.mutex_attr));
    pthread_mutexattr_settype(&(sesn_ptr->message_queue_out.mutex_attr), PTHREAD_MUTEX_ADAPTIVE_NP);//PTHREAD_MUTEX_ERRORCHECK);

    if ((pthread_mutex_init(&(sesn_ptr->message_queue_out.mutex), 	&(sesn_ptr->message_queue_out.mutex_attr))) != 0) {
      syslog(LOG_ERR, "%s (pid:'%lu' errno:'%d'): ERROR: COULD NOT INITIALISE MUTEX FOR OUTGOING SOCKETMESSAGE QUEUE...", __func__, pthread_self(), errno);
      pthread_mutexattr_destroy(&(sesn_ptr->message_queue_out.mutex_attr));

      goto final_clean_up;
    }

    pthread_mutexattr_destroy(&(sesn_ptr->message_queue_out.mutex_attr));

    sesn_ptr->ssptr = calloc(1, sizeof(Socket));
    mpsc_queue_init(&sesn_ptr->message_queue_in.queue);
    mpsc_queue_init(&sesn_ptr->message_queue_out.queue);
  }

  //invoke protocol session specific initialisation for this session
  if (protocol_id >= 0) {
    //1) assign static protocol type data
    SESSION_PROTOCOLTYPE(sesn_ptr) = (ProtocolTypeData *)ProtocolGet(protocol_id);
    //TODO: this is to be phased out in favour of protocol_type_data
    sesn_ptr->protocol_registry = (void *)&protocols_registry_ptr[protocol_id];

    //2)assign dynamic protocol type session data (per session)
    if (_PROTOCOL_CLLBACKS_INIT_SESSION(protocols_registry_ptr, protocol_id)) {
#define SESSION_RECYCLERINSTANCE	0
      _PROTOCOL_CLLBACKS_INIT_SESSION_INVOKE(protocols_registry_ptr, protocol_id, sesn_ptr, SESSION_RECYCLERINSTANCE);
    }
  }

  *sesn_ptr_in  = sesn_ptr;
  return 0;//success

  mutex_clean_up:
  pthread_rwlockattr_destroy(&(sesn_ptr->session_events.rwattr));
  pthread_mutexattr_destroy(&(sesn_ptr->message_queue_in.mutex_attr));
  pthread_mutexattr_destroy(&(sesn_ptr->message_queue_out.mutex_attr));

  pthread_rwlock_destroy(&(sesn_ptr->session_events.rwlock));
  pthread_mutex_destroy(&(sesn_ptr->message_queue_in.mutex));
  pthread_mutex_destroy(&(sesn_ptr->message_queue_out.mutex));

  //this was allocated in tandem with mutex
  free(sesn_ptr->ssptr);
  //TODO: CLEAN UP PROTOCOL INIT

  goto final_clean_up;

  //
  final_clean_up:
  if (!sesn_ptr_in)	free(sesn_ptr);

  return 1;

#undef	SESSION_RECYCLERINSTANCE
}  /**/

unsigned __attribute__((const))
SfuSessionPoolTypeNumber()
{
  return SessionTypePoolHandle->type;
}

int
SfuSessionReturnToRecycler(InstanceHolderForSfuSession *instance_sesn_ptr, ContextData *ctx_data_ptr, unsigned long call_flags)
{
  int rc = RecyclerPut(SfuSessionPoolTypeNumber(), instance_sesn_ptr, (ContextData *)ctx_data_ptr, call_flags);
  if (rc == -3) {
    Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
    if (_PROTOCOL_CLLBACKS_RECYCLER_ERROR(protocols_registry_ptr, PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))))) {
      UFSRVResult *res_ptr=_PROTOCOL_CLLBACKS_RECYCLER_ERROR_INVOKE(protocols_registry_ptr,
                                                                    PROTO_PROTOCOL_ID(((Protocol *)SESSION_PROTOCOLTYPE(sesn_ptr))),
                                                                    instance_sesn_ptr, CALLFLAGS_EMPTY);
    }
  }

  return rc;

}

/**
 * 	@brief: "constructor" type intialiser for newly memory-instantiated objects just before attaching them to the recycler.
 * 	No InstanceHolder is available for object.
 * 	One off for the object's lifetime.
 *
 */
static int
TypePoolInitCallback_Session(ClientContextData *data_ptr, size_t oid)
{
  Session *sesn_ptr = (Session *)data_ptr;

  return (InstantiateSessionForSfu(&sesn_ptr, CALLFLAGS_EMPTY, masterptr->main_listener_protoid));

}

void
InitSfuSessionRecyclerTypePool ()
{
  SessionTypePoolHandle = RecyclerInitTypePool("SfuSession", sizeof(Session), _CONF_SESNMEMSPECS_ALLOC_GROUPS(masterptr),
                                               _CONF_SESNMEMSPECS_ALLOC_GROUP_SZ(masterptr), &ops_session);

}

void
SfuSessionIncrementReference(InstanceHolderForSfuSession *instance_descriptor_ptr, int multiples)
{
  RecyclerTypeReferenced(SfuSessionPoolTypeNumber(), instance_descriptor_ptr, multiples);
}

void
SfuSessionDecrementReference(InstanceHolderForSfuSession *instance_descriptor_ptr, int multiples)
{
  RecyclerTypeUnReferenced(SfuSessionPoolTypeNumber(), instance_descriptor_ptr, multiples);
}

/**
 * @brief: initialiser Each time the object is fetched from the recycler. On error, the data is automatically pushed back to the recycler.
 * and the original caller of RecyclerGet() gets NULL back.
 *
 * @param call_flags: passed down from the client through the lifecycle manager
 */
static int
TypePoolGetInitCallback_Session (InstanceHolder *data_ptr, ContextData *context_data, size_t oid, unsigned long call_flags)
{
  Session *sesn_ptr = SessionOffInstanceHolder((InstanceHolderForSession *)data_ptr);
  UfsrvSessionsDelegator *sessions_delegator = GetUfsrvSessionsDelegator();

  if (!(call_flags&CALL_FLAG_INSTANTIATE_FROM_SYSTEM_USER)) {
    if ((sesn_ptr->session_id = GenerateSessionId(masterptr->main_listener_protoid, &sesn_ptr->sservice.result, NULL)) == 0)	return 1;//object queued back automatically
  } else CloneUfsrvSystemUser((InstanceHolderForSession *)data_ptr, SESSION_CALLFLAGS_EMPTY);

  //re-assign relevant values to recycled session so we can use it
  SESNSTATUS_UNSET(sesn_ptr->stat, SESNSTATUS_RECYCLED);

  if (unlikely(call_flags&CALL_FLAG_CARRIER_INSTANCE)) {
    SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_CARRIER);
    return 0;
  }

  if (call_flags&CALL_FLAG_SNAPSHOT_INSTANCE)	SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_SNAPSHOT);

  SESSION_SOCKETBLOCKSZ(sesn_ptr) = masterptr->buffer_size;//set default read block size

  //reassign protocol as a reminder for future multi
  SESSION_PROTOCOLTYPE(sesn_ptr) = (ProtocolTypeData *)&protocols_registry_ptr[masterptr->main_listener_protoid];

  //invoke lifecycle callback for session initialisation (soft, recycler based)
  if (_PROTOCOL_CLLBACKS_INIT_SESSION(protocols_registry_ptr, masterptr->main_listener_protoid)) {
	#define SESSION_RECYCLERINSTANCE	1
    _PROTOCOL_CLLBACKS_INIT_SESSION_INVOKE(protocols_registry_ptr, masterptr->main_listener_protoid, sesn_ptr, SESSION_RECYCLERINSTANCE);
  }

  if (call_flags&CALL_FLAG_HASH_SESSION_LOCALLY) {
    if (!(AddToHash(&(sessions_delegator->hashed_sessions.hashtable), (void *)(InstanceHolderForSession *)data_ptr))) {
      SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_RECYCLED);

      return 1;//object queued back automatically
    }
  }

  return 0;//success

#undef	SESSION_RECYCLERINSTANCE
}

/**
 * @brief: initialiser Each time the object is pushed back into the recycler.
 */
static int
TypePoolPutInitCallback_Session (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
  Session *sesn_ptr = SessionOffInstanceHolder((InstanceHolderForSession *)data_ptr);
  UfsrvSessionsDelegator *sessions_delegator = GetUfsrvSessionsDelegator();

  sesn_ptr->stat = 0;
  SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_RECYCLED);

  if (call_flags&CALL_FLAG_HASH_SESSION_LOCALLY) {
    RemoveFromHash(&(sessions_delegator->hashed_sessions.hashtable), (void *) (InstanceHolderForSession *)data_ptr);
  }

  return 0;//success

}

/**
 * @brief: initialiser Each time the object is pushed back into the recycler.
 */
static char *
TypePoolPrintCallback_Session (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
  Session *sesn_ptr = SessionOffInstanceHolder((InstanceHolderForSession *)data_ptr);

  return 0;//success

}

/**
 * @brief:
 */
static int
TypePoolDestructCallback_Session (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
  Session *sesn_ptr = SessionOffInstanceHolder((InstanceHolderForSession *)data_ptr);

  return 0;//success

}
