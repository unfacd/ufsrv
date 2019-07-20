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
#include <nportredird.h>
#include <fence.h>
#include <persistance.h>
#include <redis.h>
#include <sessions_delegator_type.h>

extern SessionsDelegator *const sessions_delegator_ptr;
extern __thread ThreadContext ufsrv_thread_context;

#ifdef _LOCAL_FENCE_EVENT_QUEUE
static void *_AddEventToFenceEventsQueue (Session *sesn_ptr, Fence *f_ptr, FenceEventTemp *fe_ptr) __attribute__((unused));
#endif

static FenceEvent *_CreateFenceEvent (Session *sesn_ptr, Fence *f_ptr, int, unsigned lock_flag, FenceEvent *fe_ptr_out);

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

		fence_lock_already_owned=(_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_THIS_THREAD));
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
 */
FenceEvent *
RegisterFenceEvent (Session *sesn_ptr_this, Fence *f_ptr, unsigned event_type,  void *event_payload, unsigned lock_flag,  FenceEvent *fe_ptr_out)
{
	FenceEvent *fe_ptr = NULL;

		//1)instantiate message
	if (event_type == EVENT_TYPE_FENCE_CREATED) fe_ptr = _CreateFenceEvent (sesn_ptr_this, f_ptr, 1, lock_flag, fe_ptr_out);//seed with 1
	else fe_ptr = _CreateFenceEvent (sesn_ptr_this, f_ptr, 0, lock_flag, fe_ptr_out);//increment backend

	if (unlikely(IS_EMPTY(fe_ptr)))	return NULL;

	fe_ptr->event_type    = event_type;
	fe_ptr->event_payload = event_payload;

	//2)add it to user queue (DISABLED, as it is of no use)
	//_AddEventToFenceEventsQueue (sesn_ptr_this, f_ptr, fe_ptr);

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fid:'%lu', eid:'%lu'}: FenceEvent: Added..", __func__, pthread_self(), sesn_ptr_this, SESSION_ID(sesn_ptr_this), FENCE_ID(f_ptr), fe_ptr->eid);
#endif

	return fe_ptr;

}

/**
 * 	@brief: this creates a mock Fence object, as there is no need for full blown,real Fence instance
 */
FenceEvent *
RegisterFenceEventWithFid (Session *sesn_ptr_this, unsigned long fence_id, unsigned event_type,  void *event_payload, FenceEvent *fe_ptr_out)

{
	FenceEvent	*fe_ptr	= NULL;
	Fence				fence		= {0};

	fence.fence_id=fence_id;

		//1)instantiate message
	if (event_type==EVENT_TYPE_FENCE_CREATED)
		fe_ptr=_CreateFenceEvent (sesn_ptr_this, &fence, 1, 0/*lock_flag*/, fe_ptr_out);//seed with 1
	else
		fe_ptr=_CreateFenceEvent (sesn_ptr_this, &fence, 0, 0/*lock_flag*/, fe_ptr_out);//increment backend

	if (unlikely(IS_EMPTY(fe_ptr)))	return NULL;

	fe_ptr->event_type		=	event_type;
	fe_ptr->event_payload	=	event_payload;

	//2)add it to user queue (DISABLED, as it is of no use)
	//_AddEventToFenceEventsQueue (sesn_ptr_this, f_ptr, fe_ptr);

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
	FenceEvent *fe_ptr=NULL;
	if (IS_PRESENT(fe_ptr_out))	fe_ptr=fe_ptr_out;
	else												fe_ptr=malloc(sizeof(FenceEvent));

	//generate at the backend
	if (eid_in==0)
	{
		fe_ptr->eid=GenerateFenceEventId (sesn_ptr_this, f_ptr, lock_flag);
		if (fe_ptr->eid<=0)
		{
			syslog(LOG_INFO, LOGSTR_FENCE_EVENET_ID_ERROR_BACKEND, __func__, pthread_self(), sesn_ptr_this, SESSION_ID(sesn_ptr_this), f_ptr, FENCE_ID(f_ptr), fe_ptr->eid,  LOGCODE_FENCE_EVENET_ID_ERROR_BACKEND);
			if (!IS_PRESENT(fe_ptr_out))	free (fe_ptr);

			return NULL;
		}
	}
	else 						fe_ptr->eid=eid_in;//use given value

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
