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

#include <uflib/recycler/recycler.h>
#include <protocol/protocol.h>
#include <nportredird.h>
#include "session_provider.h"

extern const Protocol *const protocols_registry_ptr;
extern SessionsDelegator *const sessions_delegator_ptr;
extern ufsrv *const masterptr;

static int TypePoolInitCallback_Session (ClientContextData *data_ptr, size_t oid);
static int TypePoolGetInitCallback_Session (InstanceHolder *data_ptr, ContextData *context_data, size_t oid, unsigned long call_flags);
static int TypePoolPutInitCallback_Session (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);
static char *TypePoolPrintCallback_Session (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);
static int TypePoolDestructCallback_Session (InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags);

static RecyclerPoolHandle *SessionTypePoolHandle;

static RecyclerPoolOps ops = {
        TypePoolInitCallback_Session,
        TypePoolGetInitCallback_Session,
        TypePoolPutInitCallback_Session,
        TypePoolPrintCallback_Session,
        TypePoolDestructCallback_Session
};

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

  return (ops.poolop_instantiator_callback((ContextData **)&sesn_ptr, CALLFLAGS_EMPTY, masterptr->main_listener_protoid));

}

void
InitSessionRecyclerTypePool(type_instantiator instantiator)
{
  if (IS_PRESENT(instantiator)) ops.poolop_instantiator_callback = instantiator;
  SessionTypePoolHandle = RecyclerInitTypePool("Session", sizeof(Session), _CONF_SESNMEMSPECS_ALLOC_GROUPS(masterptr),
                                               _CONF_SESNMEMSPECS_ALLOC_GROUP_SZ(masterptr), &ops);

}

/**
 * @brief: initialiser Each time the object is fetched from the recycler. On error, the data is automatically pushed back to the recycler.
 * and the original caller of RecyclerGet() gets NULL back.
 *
 * @param call_flags: passed down from the client through the lifecycle manager
 */
static int
TypePoolGetInitCallback_Session(InstanceHolder *data_ptr, ContextData *context_data, size_t oid, unsigned long call_flags)
{
  Session *sesn_ptr = SessionOffInstanceHolder((InstanceHolderForSession *)data_ptr);

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

  LoadDefaultUserPreferences(sesn_ptr);

  SESSION_SOCKETBLOCKSZ(sesn_ptr) = masterptr->buffer_size;//set default read block size

  //reassign protocol as a reminder for future multi
  SESSION_PROTOCOLTYPE(sesn_ptr) = (ProtocolTypeData *)&protocols_registry_ptr[masterptr->main_listener_protoid];

  //invoke lifecycle callback for session initialisation (soft, recycler based)
  if (_PROTOCOL_CLLBACKS_INIT_SESSION(protocols_registry_ptr, masterptr->main_listener_protoid)) {
	#define SESSION_RECYCLERINSTANCE	1
    _PROTOCOL_CLLBACKS_INIT_SESSION_INVOKE(protocols_registry_ptr, masterptr->main_listener_protoid, sesn_ptr, SESSION_RECYCLERINSTANCE);
  }

  if (call_flags&CALL_FLAG_HASH_SESSION_LOCALLY) {
    if (!(AddToHash(&(sessions_delegator_ptr->hashed_sessions.hashtable), (void *)(InstanceHolderForSession *)data_ptr))) {
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
TypePoolPutInitCallback_Session(InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
  Session *sesn_ptr = SessionOffInstanceHolder((InstanceHolderForSession *)data_ptr);
  sesn_ptr->stat = 0;
  SESNSTATUS_SET(sesn_ptr->stat, SESNSTATUS_RECYCLED);

  if (call_flags&CALL_FLAG_HASH_SESSION_LOCALLY) {
    RemoveFromHash(&(sessions_delegator_ptr->hashed_sessions.hashtable), (void *) (InstanceHolderForSession *)data_ptr);
  }

  return 0;//success

}

/**
 * @brief: initialiser Each time the object is pushed back into the recycler.
 */
static char *
TypePoolPrintCallback_Session(InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
  Session *sesn_ptr = SessionOffInstanceHolder((InstanceHolderForSession *)data_ptr);

  return 0;//success

}

/**
 * @brief:
 */
static int
TypePoolDestructCallback_Session(InstanceHolder *data_ptr, ContextData *context_data, unsigned long call_flags)
{
  Session *sesn_ptr = SessionOffInstanceHolder((InstanceHolderForSession *)data_ptr);

  return 0;//success

}

void
SessionIncrementReference(InstanceHolderForSession *instance_sesn_ptr, int multiples)
{
  RecyclerTypeReferenced(SessionPoolTypeNumber(), (RecyclerClientData *)instance_sesn_ptr, multiples);
}

void
SessionIncrementReferenceByOne(InstanceHolderForSession *instance_sesn_ptr)
{
  RecyclerTypeReferenced (SessionPoolTypeNumber(), (RecyclerClientData *)instance_sesn_ptr, _ONCE_);
}

void
SessionDecrementReference(InstanceHolderForSession *instance_sesn_ptr, int multiples)
{
  RecyclerTypeUnReferenced(SessionPoolTypeNumber(), (RecyclerClientData *)instance_sesn_ptr, multiples);
}

void
SessionDecrementReferenceByOne(InstanceHolderForSession *instance_sesn_ptr)
{
  RecyclerTypeUnReferenced(SessionPoolTypeNumber(), (RecyclerClientData *)instance_sesn_ptr, _ONCE_);
}

size_t
SessionGetReferenceCount(InstanceHolderForSession *instance_sesn_ptr)
{
  return RecyclerTypeGetReferenceCount(SessionPoolTypeNumber(), (RecyclerClientData *)instance_sesn_ptr);
}

int
SessionReturnToRecycler(InstanceHolderForSession *instance_sesn_ptr, ContextData *ctx_data_ptr, unsigned long call_flags)
{
  int rc = RecyclerPut(SessionPoolTypeNumber(), instance_sesn_ptr, (ContextData *)ctx_data_ptr, call_flags);
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

unsigned __attribute__((const))
SessionPoolTypeNumber()
{
  return SessionTypePoolHandle->type;
}
