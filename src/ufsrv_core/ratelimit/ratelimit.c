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
#include <utils.h>
#include <ufsrv_core/cache_backend/redis.h>
#include <ufsrv_core/ratelimit/ratelimit.h>

#include <ratelimit_data.h>
#include <thread_context_type.h>

extern __thread ThreadContext ufsrv_thread_context;

enum RateLimitCommandCode{
	COMMAND_CODE_MULTI=0,
	COMMAND_CODE_ZREM,
	COMMAND_CODE_ZRANGE,
	COMMAND_CODE_ZADD,
	COMMAND_CODE_EXPIRE,
	COMMAND_CODE_EXEC
};

#if 0
//namespace: <uid>:<cid>:<category:>
typedef struct RequestRateLimit {
			enum 		RateLimitNamespaceCategory namespace;
	    size_t 	interval, //1000 one sec
	    				max_in_interval, //10 requests in interval
							min_difference;	//100 time diff between successive requests. can be set to zero
} RequestRateLimit;

#endif

/*
 * When a user attempts to perform an action, we first drop all elements of the set which occured before one interval ago. This can be accomplished with Redis�s ZREMRANGEBYSCORE command.

We fetch all elements of the set, using ZRANGE(0, -1).

We add the current timestamp to the set, using ZADD.

We set a TTL equal to the rate-limiting interval on the set (to save space).

After all operations are completed, we count the number of fetched elements. If it exceeds the limit, we don�t allow the action.

We also can compare the largest fetched element to the current timestamp. If they�re too close, we also don�t allow the action.
 */
UFSRVResult *
GetRequestRateLimitStatus (RateLimitDescriptor *rl_descriptor_ptr, RequestRateLimitStatus 	*rl_status_ptr_out)
{
  CacheBackend *pers_ptr = rl_descriptor_ptr->pers_ptr;
  const RequestRateLimit *rl_ptr = rl_descriptor_ptr->request_rl_ptr;

	int											rescode						=	RESCODE_BACKEND_RESOURCE_NULL;
	long long 							time_now_in_micros=GetTimeNowInMicros();
	size_t 									clear_before			=time_now_in_micros - (rl_ptr->interval*1000);//in micros
	RequestRateLimitStatus 	*rl_status_ptr		=NULL;

	if (IS_PRESENT(rl_status_ptr_out))	rl_status_ptr = rl_status_ptr_out;
	else																rl_status_ptr = calloc(1, sizeof (RequestRateLimitStatus));

	char 								command_buf[MBUF] = {0};

	(*pers_ptr->send_command_multi)(NULL, pers_ptr, "MULTI");

	snprintf(command_buf, MBUF-1, "ZREMRANGEBYSCORE %s 0 %lu ", rl_descriptor_ptr->namespace, clear_before);//integer, type:3
	(*pers_ptr->send_command_multi)(NULL, pers_ptr, command_buf);

	(*pers_ptr->send_command_multi)(NULL, pers_ptr, "ZRANGE %s 0 -1", rl_descriptor_ptr->namespace);//array, type:2

	snprintf(command_buf, MBUF-1, "ZADD %s %llu %llu", rl_descriptor_ptr->namespace, time_now_in_micros, time_now_in_micros); //integer
	(*pers_ptr->send_command_multi)(NULL, pers_ptr, command_buf);

	snprintf(command_buf, MBUF-1, "EXPIRE %s %lu", rl_descriptor_ptr->namespace, (rl_ptr->interval*1000)/ 1000000);//integer, (convert to seconds)
	(*pers_ptr->send_command_multi)(NULL, pers_ptr, command_buf);

	(*pers_ptr->send_command_multi)(NULL, pers_ptr, "EXEC");//array

	size_t		commands_processed  = 6,
						commands_successful = 6;

	//TODO: error recovery not done well..
	{
		size_t 			i;
		redisReply	*replies[commands_processed];

		//TODO: we need error recover for intermediate errors
		for (i=0; i<commands_processed; i++) {
			if ((RedisGetReply(NULL, pers_ptr, (void*)&replies[i])) != REDIS_OK) {
				commands_successful--;

				if ((replies[i] != NULL)) {
					syslog(LOG_DEBUG, "%s (pid:'%lu', ns:'%s', idx:'%lu'): ERROR PROCESSING MULTI SET COMMAND. ERROR: '%s'", __func__, pthread_self(), rl_descriptor_ptr->namespace, i, replies[i]->str);
				} else {
					syslog(LOG_DEBUG, "%s (pid:'%lu', ns:'%s' idx:'%lu'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), rl_descriptor_ptr->namespace, i);
				}
			}
		}

		//diagnostics
		if (commands_successful != commands_processed) {
			for (i=0; i<commands_processed; i++)	if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);
			goto return_range_error;
		}

		//verification block
		{
			//we only want to keep the last one which contains array of redisReply * corresponding with the number of commands issued,less exec/multi
			//the rest will return value of type REDIS_REPLY_STATUS
			for (i=0; i<commands_processed-1; i++)	if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);
			if (IS_EMPTY(replies[COMMAND_CODE_EXEC])) {
				syslog(LOG_DEBUG, "%s (pid:'%lu', ns:'%s'): ERROR: REDIS TRANSACTION ERROR: NULL COMMAND ARRAY RESPONSE", __func__, pthread_self(), rl_descriptor_ptr->namespace);
				goto return_range_error;
			}

			//reuse the array and repoint replies inline with index value, excluding multi/exec
			if (replies[COMMAND_CODE_EXEC]->elements == commands_processed - 2) {
				//dont use index 0 or free hereafter
				replies[0] = NULL;
				for (i=1; i<commands_processed-1; i++) {
					replies[i]=replies[COMMAND_CODE_EXEC]->element[i-1];
				}
			} else {
				//bomb the whole lot -- NO BECAUSE WE ALEADY FREED ALL ELEMENTS EXCEPT FOR EXEC
				syslog(LOG_DEBUG, "%s (pid:'%lu', ns:'%s', dispatched:'%lu', received:'%lu'): ERROR: REDIS TRANSACTION ERROR: DISPATCHED/RECEIVED COMMANDS COUNT MISMATCH", __func__, pthread_self(), rl_descriptor_ptr->namespace, commands_processed-2, replies[COMMAND_CODE_EXEC]->elements);
				//for (i=0; i<commands_processed; i++)	if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);
				if (IS_PRESENT(replies[COMMAND_CODE_EXEC]))	freeReplyObject(replies[COMMAND_CODE_EXEC]);
				goto return_range_error;
			}
		}

		//how many requests remain after we cleared since last interval. can be zero, or array of timestamps
		size_t userset_sz = replies[COMMAND_CODE_ZRANGE]->elements;

		//shortcut for empty set
		if (userset_sz == 0) {
#ifdef __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', cid_user:'%lu', uid_user:'%lu'): NOTICE: RANGE RECORD SET EMPTY..", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), cid, userid);
#endif

			rl_status_ptr->remaining_time = 0;
			rl_status_ptr->remaining_actions = rl_ptr->max_in_interval - 1;//since user already performed one

			//BE CAREFUL WITH THE STARTING INDEX must start at 1, as 0 has been freed already
			//for (i=1; i<commands_processed; i++)					if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);
			freeReplyObject(replies[COMMAND_CODE_EXEC]);//this free the repointed replies above
			goto return_success;
		}

		bool IsTooManyInInterval = (userset_sz >= rl_ptr->max_in_interval);

		time_t time_since_last_request;

		////fetch most recent in list, which has the highest timestamp value
		rl_ptr->min_difference > 0?
			(time_since_last_request = (time_now_in_micros - strtoll(replies[COMMAND_CODE_ZRANGE]->element[userset_sz-1]->str, NULL, 10))):
			(time_since_last_request = 0);

		int 		result; //time left
		//ssize_t remaining; //how many allowable actions remained in the given interval

		if (IsTooManyInInterval || time_since_last_request < (rl_ptr->min_difference*1000)) {
				ssize_t v1;
				v1 = ((strtoll(replies[COMMAND_CODE_ZRANGE]->element[0]->str, NULL, 10) - time_now_in_micros) +  (rl_ptr->interval*1000));
//				if (userset_sz>0) v1=((replies[COMMAND_CODE_ZRANGE]->element[0]->integer - time_now_in_micros) +  (rl_ptr->interval*1000));
//				else							v1=(0- time_now_in_micros) +  (rl_ptr->interval*1000);

				result = _min(v1,
											rl_ptr->min_difference>0 ? (rl_ptr->min_difference*1000) - time_since_last_request : time_now_in_micros
											 );

				rl_status_ptr->remaining_time = (result / 1000); // convert to milliseconds for user readability.
				rl_status_ptr->remaining_actions = 0;
		} else {
			rl_status_ptr->remaining_actions = rl_ptr->max_in_interval - userset_sz; //if <=0 we are good, 0 is border case
			rl_status_ptr->remaining_time = 0;//result = 0;//we are good request-rate wise
		}

		//BE CAREFUL WITH THE STARTING INDEX must start at 1, as 0 has been freed already
		//for (i=1; i<commands_processed; i++)	if (!IS_EMPTY(replies[i]))	freeReplyObject(replies[i]);
		freeReplyObject(replies[COMMAND_CODE_EXEC]);
	}

	return_success:
//	_RETURN_RESULT_SESN(sesn_ptr, rl_status_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA_SETCREATED)
  _RETURN_RESULT_RES(rl_descriptor_ptr->res_ptr, rl_status_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA_SETCREATED)

	return_range_error:
	rescode = RESCODE_BACKEND_RESOURCE_NULL;
	goto return_free;

	return_free:
	if (IS_EMPTY(rl_status_ptr_out))	free(rl_status_ptr);

	return_missing_param:
	rescode = RESCODE_PROG_MISSING_PARAM;

	return_final:
//	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)
  _RETURN_RESULT_RES(rl_descriptor_ptr->res_ptr, NULL, RESULT_TYPE_ERR, rescode)
}

__attribute__((pure)) const RequestRateLimit *GetRateLimitSpecsFor (enum RateLimitNamespaceCategory category)
{
	if (category < RLNS_MAXVALUE)	return &(RequestRateLimitSpecs[category-1]);

	return NULL;
}

bool
IsRateLimitExceededWithNamespace (RateLimitDescriptor *rl_descriptor, enum RateLimitNamespaceCategory ratelimit_category)
{
  rl_descriptor->request_rl_ptr = GetRateLimitSpecsFor(ratelimit_category);
  RequestRateLimitStatus 	ratelimit_status_local;

  GetRequestRateLimitStatus (rl_descriptor, &ratelimit_status_local);
  if (IS_PRESENT(_RESULT_USERDATA(rl_descriptor->res_ptr))) {
    //we are interested in both, rate and number of requests
    if (rl_descriptor->request_rl_ptr->min_difference > 0) {
      if (ratelimit_status_local.remaining_time == 0 && ratelimit_status_local.remaining_actions >= 0) {
        return false;
      } else {
#ifdef __UF_TESTING
        syslog(LOG_DEBUG, LOGSTR_IO_RL_EXCEEDED_RATE_ACTIONS, __func__, pthread_self(), rl_descriptor->namespace, ratelimit_status_local.remaining_time, ratelimit_status_local.remaining_actions, LOGCODE_IO_RL_EXCEEDED_RATE_ACTIONS);
#endif
        return true;
      }
    } else {
      if (ratelimit_status_local.remaining_actions >= 0)	return false;
      else {
#ifdef __UF_TESTING
        syslog(LOG_DEBUG, LOGSTR_IO_RL_EXCEEDED_ACTIONS, __func__, pthread_self(), rl_descriptor->namespace, ratelimit_status_local.remaining_actions, LOGCODE_IO_RL_EXCEEDED_ACTIONS);
#endif
        return true;
      }
    }
  } else {
    syslog(LOG_DEBUG, "%s (pid:'%lu', ns:'%s'): ERROR: RATELIMIT COULD NOT BE DETERMINED..", __func__, pthread_self(), rl_descriptor->namespace);
    return true;
  }

  return true;
}

/**
 * Helper function to abstract the interpretation of the status of the RateLimit
 * Note: this uses current Session owner's credentials.
 * Note: in this specific context we are directly specifying cachebackend
 *
 * @returns: false: ratelimit not exceed
 */
 bool
IsRateLimitExceededForSession (CacheBackend *pers_ptr, unsigned long userid, unsigned long cid, enum RateLimitNamespaceCategory ratelimit_category)
{
  char 										namespace[SBUF]					=	{0};
  snprintf(namespace, SBUF-1, "%lu:%lu:%d", userid, cid, ratelimit_category);
  RateLimitDescriptor rl_descriptor = {.res_ptr=THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), .pers_ptr=pers_ptr, .namespace=namespace};
  return IsRateLimitExceededWithNamespace(&rl_descriptor, ratelimit_category);

	/*const RequestRateLimit 	*ratelimit_specs_ptr = GetRateLimitSpecsFor(ratelimit_category);
	RequestRateLimitStatus 	ratelimit_status_local;

	char 										namespace[SBUF]					=	{0};
  snprintf(namespace, SBUF-1, "%lu:%lu:%d", userid, cid, ratelimit_specs_ptr->namespace);

	GetRequestRateLimitStatus (pers_ptr, ratelimit_specs_ptr, namespace, &ratelimit_status_local);
	if (IS_PRESENT(SESSION_RESULT_USERDATA(sesn_ptr))) {
		//we are interested in both, rate and number of requests
		if (ratelimit_specs_ptr->min_difference > 0) {
			if (ratelimit_status_local.remaining_time == 0 && ratelimit_status_local.remaining_actions >= 0) {
				return false;
			} else {
#ifdef __UF_TESTING
				syslog(LOG_DEBUG, LOGSTR_IO_RL_EXCEEDED_RATE_ACTIONS, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), ratelimit_status_local.remaining_time, ratelimit_status_local.remaining_actions, LOGCODE_IO_RL_EXCEEDED_RATE_ACTIONS);
#endif
				return true;
			}
		} else {
			if (ratelimit_status_local.remaining_actions >= 0)	return false;
			else {
#ifdef __UF_TESTING
				syslog(LOG_DEBUG, LOGSTR_IO_RL_EXCEEDED_ACTIONS, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), ratelimit_status_local.remaining_actions, LOGCODE_IO_RL_EXCEEDED_ACTIONS);
#endif
				return true;
			}
		}
	} else {
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR: RATELIMIT COULD NOT BE DETERMINED..", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
		return true;
	}

	return true;*/
}

bool
IsRateLimitExceededForIPAddress (CacheBackend *pers_ptr, const char *ip_address, enum RateLimitNamespaceCategory ratelimit_category, UFSRVResult *res_ptr) {
  syslog(LOG_DEBUG, "%s {pid:'%lu', ip:'%s'}: Checking RateLimit...", __func__, pthread_self(), ip_address);
  RateLimitDescriptor rl_descriptor = {.res_ptr=THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), .res_ptr=res_ptr, .pers_ptr=pers_ptr, .namespace=ip_address};
  return IsRateLimitExceededWithNamespace(&rl_descriptor, ratelimit_category);
}