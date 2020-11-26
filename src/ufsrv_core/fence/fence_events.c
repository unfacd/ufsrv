/**
 * Copyright (C) 2015-2019 unfacd works
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
#include <fence.h>
#include <ufsrv_core/cache_backend/redis.h>
#include <ufsrv_events.h>
#include <sessions_delegator_type.h>

extern SessionsDelegator *const sessions_delegator_ptr;
extern __thread ThreadContext ufsrv_thread_context;

#ifdef _LOCAL_FENCE_EVENT_QUEUE
static void *_AddEventToFenceEventsQueue (Session *sesn_ptr, Fence *f_ptr, FenceEventTemp *fe_ptr) __attribute__((unused));
#endif

static FenceEvent *_CreateFenceEvent (Session *sesn_ptr, Fence *f_ptr, int, unsigned lock_flag, FenceEvent *fe_ptr_out);
static UFSRVResult *_DbBackendGetEvent (unsigned long originator_uid, unsigned long eid, EnumEventCommandType type);

/**
 * 	@brief:
 * 	returns last used event id in the cntext of locally processed fence operation
 * 	The value is nly valid if read in the context of currently served session
 */
inline unsigned long
GetFenceEventId (Fence *f_ptr, unsigned lock_flag)
{
	bool fence_lock_already_owned=false;

	if (lock_flag)
	{
		FenceEventsLockRDCtx(THREAD_CONTEXT_PTR, f_ptr, _LOCK_TRY_FLAG_TRUE, THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), __func__);

		if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_ERR))	return 0;

		fence_lock_already_owned=(_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_BY_THIS_THREAD));
	}

	unsigned long fence_event_counter=f_ptr->fence_events.last_event_id;

	if (lock_flag)
	{
		if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr, THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT));
	}

	return fence_event_counter;

}

/**
 * 	@brief: Main interface  for generating unique event ids for fence related actions. Each fence keeps its own counter, which
 * 	is persisted in the cache backend and incremented upon each new event generation.
 *
 * 	@locked sesn_ptr_this
 *
 */
FenceEvent *
RegisterFenceEvent (Session *sesn_ptr_this, Fence *f_ptr, unsigned event_type,  void *event_payload, unsigned lock_flag,  FenceEvent *fe_ptr_out)
{
	FenceEvent *fe_ptr = NULL;

		//1)instantiate message
	if (event_type == EVENT_TYPE_FENCE_CREATED) fe_ptr = _CreateFenceEvent(sesn_ptr_this, f_ptr, 1, lock_flag, fe_ptr_out);//seed with 1
	else fe_ptr = _CreateFenceEvent(sesn_ptr_this, f_ptr, 0, lock_flag, fe_ptr_out);//increment backend

	if (unlikely(IS_EMPTY(fe_ptr)))	return NULL;

	fe_ptr->event_cmd_type= MSGCMD_FENCE;
	fe_ptr->event_type    = event_type;
	fe_ptr->event_payload = event_payload;
	fe_ptr->originator_ptr= &SESSION_UFSRVUIDSTORE(sesn_ptr_this);

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fid:'%lu', eid:'%lu'}: FenceEvent: Added..", __func__, pthread_self(), sesn_ptr_this, SESSION_ID(sesn_ptr_this), FENCE_ID(f_ptr), fe_ptr->eid);
#endif

	return fe_ptr;

}

/**
 * 	@brief: this creates a mock Fence object, as there is no need for full blown,real Fence instance
 * 	@locked sesn_ptr_this
 */
FenceEvent *
RegisterFenceEventWithFid (Session *sesn_ptr_this, unsigned long fence_id, unsigned event_type,  void *event_payload, FenceEvent *fe_ptr_out)
{
	FenceEvent	*fe_ptr	= NULL;
	Fence				fence		= {0};

	fence.fence_id = fence_id;

		//1)instantiate message
	if (event_type == EVENT_TYPE_FENCE_CREATED)
		fe_ptr = _CreateFenceEvent (sesn_ptr_this, &fence, 1, 0/*lock_flag*/, fe_ptr_out);//seed with 1
	else
		fe_ptr = _CreateFenceEvent (sesn_ptr_this, &fence, 0, 0/*lock_flag*/, fe_ptr_out);//increment backend

	if (unlikely(IS_EMPTY(fe_ptr)))	return NULL;

  fe_ptr->event_cmd_type= MSGCMD_FENCE;
	fe_ptr->event_type		=	event_type;
	fe_ptr->event_payload	=	event_payload;
  fe_ptr->originator_ptr= &SESSION_UFSRVUIDSTORE(sesn_ptr_this);

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', bid:'%lu', eid:'%lu'}: FenceEvent: Added..", __func__, pthread_self(), sesn_ptr_this, fence_id, fe_ptr->eid);
#endif

	return fe_ptr;

}

#ifdef _LOCAL_FENCE_EVENT_QUEUE
//export
//destructive all message queue for user is destroyed and freed
//LOCK: MUST LOCKED IN THE CALLING ENVIRONMENT
void *
DestructFenceEventQueue (Session *sesn_ptr_this, Fence *f_ptr, unsigned reset_counter_flag)

{
	if (unlikely(IS_EMPTY(sesn_ptr_this) || IS_EMPTY(f_ptr)))	return NULL;


	if (FENCE_FENECE_EVENTS_QUEUE_NENTRIES(f_ptr)==0)
	{
		syslog(LOG_DEBUG, "%s: FENCE (bid='%lu') has no events in queue", __func__, 			f_ptr->fence_id);

		return NULL;
	}

	syslog(LOG_DEBUG, "%s: FENCE (bid='%lu') has '%lu' ENTRIES IN ITS EVENTS QUEUE...", __func__,
		FENCE_ID(f_ptr), FENCE_FENECE_EVENTS_QUEUE_NENTRIES(f_ptr));

	QueueEntry *qe_ptr=NULL;
	while (FENCE_FENECE_EVENTS_QUEUE_NENTRIES(f_ptr)!=0)
	{
		//1)Retrieve carrier object
		qe_ptr=deQueue(&FENCE_FENECE_EVENTS_QUEUE(f_ptr));

		//2)destruct payload
		DestructFenceEvent(QUEUE_ENTRY_EFENCE_EVENT(qe_ptr), true);

		//3)destruct carrier object
		free(qe_ptr);
	}

	if (reset_counter_flag)	f_ptr->fence_events.last_event_id=0;

	return NULL;

}



//fence must be locked in the calling environment
static void *
_AddEventToFenceEventsQueue (Session *sesn_ptr, Fence *f_ptr, FenceEventTemp *fe_ptr)
{

	QueueEntry *qe_ptr=NULL;

	if (FENCE_FENECE_EVENTS_QUEUE_NENTRIES(f_ptr)<10)//TODO: define the constant in the config file
	{
		qe_ptr=AddQueue(&FENCE_FENECE_EVENTS_QUEUE(f_ptr));
		qe_ptr->whatever=(void *)fe_ptr;

		return fe_ptr;
	}
	else
	{
		qe_ptr=deQueue(&FENCE_FENECE_EVENTS_QUEUE(f_ptr));

		syslog(LOG_DEBUG, "_AddFenceEventToUserQueue: FenceEventQueue reached max size (%lu entries): popping off the oldest eid: '%lu'",
				FENCE_FENECE_EVENTS_QUEUE_NENTRIES(f_ptr), QUEUE_ENTRY_EFENCE_EVENT_EID(qe_ptr));

		DestructFenceEvent(QUEUE_ENTRY_EFENCE_EVENT(qe_ptr), true);
		free(qe_ptr);

		qe_ptr=AddQueue(&FENCE_FENECE_EVENTS_QUEUE(f_ptr));
		qe_ptr->whatever=(void *)fe_ptr;

		return fe_ptr;
	}

	return NULL;

}
#endif

/**
 * 	/brief create individual, unattached FenceEvent.
 * 	/lock	caller must specifiy lock condition
 */
static FenceEvent *
_CreateFenceEvent (Session *sesn_ptr_this, Fence *f_ptr, int eid_in, unsigned lock_flag, FenceEvent *fe_ptr_out)
{
	FenceEvent *fe_ptr = NULL;
	if (IS_PRESENT(fe_ptr_out))	fe_ptr = fe_ptr_out;
	else												fe_ptr = malloc(sizeof(FenceEvent));

	//generate at the backend
	if (eid_in == 0) {
		fe_ptr->eid = GenerateFenceEventId(sesn_ptr_this, f_ptr, lock_flag);
		if (fe_ptr->eid <= 0) {
			syslog(LOG_INFO, LOGSTR_FENCE_EVENET_ID_ERROR_BACKEND, __func__, pthread_self(), sesn_ptr_this, SESSION_ID(sesn_ptr_this), f_ptr, FENCE_ID(f_ptr), fe_ptr->eid,  LOGCODE_FENCE_EVENET_ID_ERROR_BACKEND);
			if (!IS_PRESENT(fe_ptr_out))	free (fe_ptr);

			return NULL;
		}
	}
	else 						fe_ptr->eid = eid_in;//use given value

	fe_ptr->when				=	time(NULL);
	fe_ptr->session_id	=	SESSION_ID(sesn_ptr_this);
	fe_ptr->target_id		=	f_ptr->fence_id;

	return fe_ptr;

}

int
DestructFenceEvent (FenceEvent *fe_ptr, bool self_destruct)
{

	if (fe_ptr->event_payload)			free (fe_ptr->event_payload);

	memset(fe_ptr, 0, sizeof(FenceEvent));
	if (self_destruct)	{free (fe_ptr);	fe_ptr=NULL;}
	return 0;

}

/**
 *
 * @param event_ptr Fully defined event descriptor
 * @return on success id of row insertion
 */
UFSRVResult *
DbBackendInsertUfsrvEvent (UfsrvEvent *event_ptr)
{
#define SQL_INSERT_NEW_INCOMING_MESSAGE "INSERT INTO events (eid, cmd_type, event_type, timestamp, originator) VALUES ('%lu', '%u', '%u', '%lu', '%lu')"

  char *sql_query_str;
  sql_query_str = mdsprintf(SQL_INSERT_NEW_INCOMING_MESSAGE, event_ptr->eid, event_ptr->event_cmd_type, event_ptr->event_type, event_ptr->when, UfsrvUidGetSequenceId(event_ptr->originator_ptr));

#ifdef __UF_TESTING
  syslog(LOG_DEBUG, "%s (pid:'%lu', th_ctx:'%p'): GENERATED SQL QUERY: '%s'", __func__, pthread_self(), THREAD_CONTEXT_PTR, sql_query_str);
#endif
  int sql_result = h_query_insert(THREAD_CONTEXT_DB_BACKEND, sql_query_str);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, "%s (pid:'%lu', th_ctx:'%p'): ERROR: COULD NOT EXECUTE QUERY: '%s'", __func__, pthread_self(), THREAD_CONTEXT_PTR, sql_query_str);
  }

  free (sql_query_str);

  struct _h_data *db_data = h_query_last_insert_id(THREAD_CONTEXT_DB_BACKEND);
  if (db_data->type == HOEL_COL_TYPE_INT) {
    int last_id = ((struct _h_type_int *)db_data->t_data)->value;
    h_clean_data_full(db_data);

    event_ptr->gid = (unsigned long)last_id;

    THREAD_CONTEXT_RETURN_RESULT_SUCCESS((void *)(uintptr_t)last_id, RESCODE_BACKEND_DATA)
  }

  THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_BACKEND_DATA)

#undef SQL_INSERT_NEW_INCOMING_MESSAGE
}

static UFSRVResult *
_DbBackendGetEvent (unsigned long originator_uid, unsigned long eid, EnumEventCommandType type)
{
#define SQL_GET_EVENT "SELECT id FROM events WHERE eid = '%lu' AND cmd_type = '%u' AND originator = '%lu'"
#define COLUMN_ID(x)	    ((struct _h_type_int *)result.data[0][0].t_data)->value

  struct _h_result result;

  char *sql_query_str = mdsprintf(SQL_GET_EVENT, eid, type, originator_uid);

#if __UF_TESTING
  syslog(LOG_DEBUG, "%s {th_ctx:'%p', uid:'%lu', eid:'%lu'}: GENERATED SQL QUERY: '%s'", __func__, THREAD_CONTEXT_PTR, originator_uid,  eid, sql_query_str);
#endif

  int sql_result = h_query_select(THREAD_CONTEXT_DB_BACKEND, sql_query_str, &result);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, "%s {th_ctx:'%p', uid:'%lu', eid:'%lu'}: ERROR: COULD EXECUTE QUERY: '%s'", __func__, THREAD_CONTEXT_PTR, originator_uid, eid, sql_query_str);

    free (sql_query_str);

    THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_BACKEND_DATA)
  }

  free (sql_query_str);

  //we should ever only find 1 or zero really
  if (result.nb_rows > 0) {
    unsigned long id = COLUMN_ID(result);

    h_clean_result(&result);

    THREAD_CONTEXT_RETURN_RESULT_SUCCESS((void *)(uintptr_t)id, RESCODE_BACKEND_DATA)
  } else {
#ifdef __UF_TESTING
    syslog(LOG_DEBUG, "%s {th_ctx:'%p', uid:'%lu', eid:'%lu'}: ERROR: COULD RETRIEVE MESSAGE", __func__, THREAD_CONTEXT_PTR, originator_uid, eid);
#endif
  }

  exit_user_not_found:
  h_clean_result(&result);

  THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_BACKEND_DATA_EMPTYSET)

#undef COLUMN_TYPE
#undef SQL_GET_EVENT
#undef COLUMN_ID

}

//SELECT a.id, a.id_events, a.fid, b.eid FROM messages AS a INNER JOIN events AS b ON a.id_events = b.id WHERE b.eid = 177;
/**
 * @brief Target of this query is the Events table. Retrieve a complete message descriptor
 * @param originator_uid
 * @param eid
 * @param type
 * @param event_descriptor_ptr_out
 * @return
 */
UFSRVResult *
DbBackendGetEventDescriptorByGid (UfsrvEventDescriptor *event_descriptor_ptr_out)
{
#define SQL_GET_EVENT "SELECT a.id, a.id_events, a.fid, b.eid FROM messages AS a INNER JOIN events AS b ON a.id_events = b.id WHERE b.id = '%lu'"
#define COLUMN_ID(x)	          ((struct _h_type_int *)result.data[x][0].t_data)->value
#define COLUMN_ID_EVENTS(x)	    ((struct _h_type_int *)result.data[x][1].t_data)->value
#define COLUMN_FID(x)	          ((struct _h_type_int *)result.data[x][2].t_data)->value

  struct _h_result result;

  char *sql_query_str = mdsprintf(SQL_GET_EVENT, event_descriptor_ptr_out->gid);

#if __UF_TESTING
  syslog(LOG_DEBUG, "%s {th_ctx:'%p', gid:'%lu'}: GENERATED SQL QUERY: '%s'", __func__, THREAD_CONTEXT_PTR, event_descriptor_ptr_out->gid, sql_query_str);
#endif

  int sql_result = h_query_select(THREAD_CONTEXT_DB_BACKEND, sql_query_str, &result);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, "%s {th_ctx:'%p', gid:'%lu'}: ERROR: COULD EXECUTE QUERY: '%s'", __func__, THREAD_CONTEXT_PTR, event_descriptor_ptr_out->gid, sql_query_str);

    free (sql_query_str);

    THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_BACKEND_DATA)
  }

  free (sql_query_str);

  //we should ever only find 1 or zero really
  if (result.nb_rows > 0) {
    event_descriptor_ptr_out->eid = COLUMN_ID_EVENTS(0);
    event_descriptor_ptr_out->ctx_id = COLUMN_FID(0);

    h_clean_result(&result);

    THREAD_CONTEXT_RETURN_RESULT_SUCCESS(event_descriptor_ptr_out, RESCODE_BACKEND_DATA)
  } else {
#ifdef __UF_TESTING
    syslog(LOG_DEBUG, "%s {th_ctx:'%p', gid:'%lu'}: ERROR: COULD RETRIEVE MESSAGE", __func__, THREAD_CONTEXT_PTR, event_descriptor_ptr_out->gid);
#endif
  }

  exit_user_not_found:
  h_clean_result(&result);

  THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_BACKEND_DATA_EMPTYSET)

#undef COLUMN_TYPE
#undef SQL_GET_EVENT

}

int
DbBackendUpdateEventFlagger (unsigned long event_rowid, unsigned  long uid_flagged_by, time_t timestamp)
{
#define SQL_INSERT_NEW_FLAGGED_EVENT "INSERT INTO flagged_events (id, originator, timestamp) VALUES ('%lu', '%lu', '%lu') ON DUPLICATE KEY UPDATE timestamp = '%lu'"

  char *sql_query_str;
  sql_query_str = mdsprintf(SQL_INSERT_NEW_FLAGGED_EVENT, event_rowid, uid_flagged_by, timestamp, timestamp);

#ifdef __UF_TESTING
  syslog(LOG_DEBUG, "%s (pid:'%lu', th_ctx:'%p'): GENERATED SQL QUERY: '%s'", __func__, pthread_self(), THREAD_CONTEXT_PTR, sql_query_str);
#endif
  int sql_result = h_query_insert(THREAD_CONTEXT_DB_BACKEND, sql_query_str);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, "%s (pid:'%lu', th_ctx:'%p'): ERROR: COULD NOT EXECUTE QUERY: '%s'", __func__, pthread_self(), THREAD_CONTEXT_PTR, sql_query_str);
  }

  free (sql_query_str);

  return sql_result;

#undef SQL_INSERT_NEW_FLAGGED_EVENT

}

/**
 * @brief Based on provide tuple, determine if an associated event exists.
 * @param originator_uid sequence id derived from UfsrvUid
 * @param eid event id
 * @param type message command type
 * @return db column id for the event
 */
unsigned long
IsEventValid (unsigned long originator_uid, unsigned long eid, EnumEventCommandType cmd_type)
{
  UFSRVResult *res_ptr = _DbBackendGetEvent(originator_uid, eid, cmd_type);

  if (_RESULT_TYPE_SUCCESS(res_ptr)) {
    return (unsigned long)res_ptr->result_user_data;
  }

  return 0;
}