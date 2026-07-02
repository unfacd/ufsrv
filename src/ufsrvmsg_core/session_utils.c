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

#include <main.h>
#include <session_utils.h>
#include <session.h>
#include <thread_context_type.h>
#include <ufsrv_core/cache_backend/redis.h>
#include <uflib/ufsrvuid.h>
#include <net.h>

struct json_object *
GetPresenceInformation(Session *sesn_ptr, struct json_object *jobj_contacts)
{
  int contacts_count = json_object_array_length(jobj_contacts);

  if (contacts_count <= 0) {
    return NULL;
  }

#ifdef __UF_FULLDEBUG
  syslog(LOG_DEBUG, "%s (cid: '%lu', array_sz:'%d'): RECEIVED userids", __func__, SESSION_ID(sesn_ptr), contacts_count);
#endif

  int 					actually_processed	=	contacts_count;
  CacheBackend 	*pers_ptr						=	sesn_ptr->persistance_backend;

  //{"userIds":["1","2","3", ...]}
  int i;
  for (i=0; i<contacts_count; i++) {
    struct json_object *jobj_contact  = json_object_array_get_idx(jobj_contacts, i);
    unsigned long user_sequence_id    = json_object_get_int64(jobj_contact);
    if (user_sequence_id > 0) {
      if (!((*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_USER_SESSION_SERVICE_TIMING_GET, user_sequence_id))) {
        actually_processed--;

        syslog(LOG_DEBUG, "%s (cid: '%lu'): ERROR PROCESSING CONTACT TOKEN: '%lu'", __func__, SESSION_ID(sesn_ptr), user_sequence_id);
      }
    } else {
      actually_processed--;
    }
  }

  //IMPORTANT TODO: KEEP AN EYE ON STACK OVERFLOW WITH THIS FOR USERS WITH LARGE MARCHES as we ADDITIONALLY STRDUPA matched token
  //We need to retain a local copy of the matched token because we cannot issue nested redis commands on the same  pers_ptr->context
  //as that will corrupt its state, so we have to serialise the calls separately in a third iteration
  unsigned long when_suspended[actually_processed];
  unsigned long when_serviced[actually_processed];
  char *uids[actually_processed];
  int status[actually_processed];

  //2 process replies
  int 								tokens_processed __unused,
                      tokens_matched_idx		=	0;
  redisReply 					**replies;
  struct json_object 	*jobj_shared_contacts	=	json_object_new_array();
  struct json_object 	*jobj_token						=	NULL;

  replies = malloc(sizeof(redisReply *) * actually_processed);

  tokens_processed = actually_processed;

  char uids_encoded[actually_processed][CONFIG_MAX_UFSRV_ID_ENCODED_SZ + 1];
  memset(uids_encoded, '\0', sizeof(uids_encoded));

  for (i=0; i<actually_processed; i++) {
    if ((RedisGetReply(sesn_ptr, pers_ptr, (void *)&replies[i]) == REDIS_OK)) {
      if ((replies[i] != NULL && replies[i]->type != REDIS_REPLY_NIL) && (replies[i]->element[0]->type != REDIS_REPLY_NIL)) {
        uids[tokens_matched_idx]              = UfsrvUidConvertSerialise((UfsrvUid *) replies[i]->element[0]->str, uids_encoded[i]);
        status[tokens_matched_idx]            = atoi(replies[i]->element[1]->str);
        when_serviced[tokens_matched_idx]     = strtoul(replies[i]->element[2]->str, NULL, 10);
        when_suspended[tokens_matched_idx++]  = strtoul(replies[i]->element[3]->str, NULL, 10);
      } else	tokens_processed--;

      freeReplyObject(replies[i]);
    } else	tokens_processed--;
  }//for

  free(replies);

  //3 actually produce payload
  for (i=0; i<tokens_matched_idx; i++) {
    jobj_token = json_object_new_object();

    json_object_object_add(jobj_token, "ufsrvuid", json_object_new_string(uids[i]));
    json_object_object_add(jobj_token, "status", json_object_new_int(status[i]));
    json_object_object_add(jobj_token, "suspended", json_object_new_int64(when_suspended[i]));
    json_object_object_add(jobj_token, "serviced", json_object_new_int64(when_serviced[i]));

    json_object_array_add(jobj_shared_contacts, jobj_token);
  }

  if (json_object_array_length(jobj_shared_contacts) == 0) {
    syslog (LOG_DEBUG, LOGSTR_BACKENDCACHE_SHARED_CONTACTS_REPORT, __func__, pthread_self(), sesn_ptr, 0UL, LOGCODE_BACKENDCACHE_SHARED_CONTACTS_FOUNDNONE, "No userid were found");

    json_object_put(jobj_shared_contacts);

    return NULL;
  } else {
#ifdef __UF_FULLDEBUG
    syslog (LOG_DEBUG, LOGSTR_BACKENDCACHE_SHARED_CONTACTS_REPORT, __func__, pthread_self(), sesn_ptr, json_object_array_length(jobj_shared_contacts), LOGCODE_BACKENDCACHE_SHARED_CONTACTS_TOTALFOUND, "Total uids found");
#endif
    return jobj_shared_contacts;
    }

  return NULL;

}

InstanceHolderForSession * __attribute__((nonnull(1, 2)))
LocallyLocateSessionByNetAddress(HashTable *hash_table, struct sockaddr_in *src)
{
  unsigned long hashed_net_address  = HashNetAddress(src);
  if (hashed_net_address > 0) {
    return ((InstanceHolderForSession *)HashLookup(hash_table, (void *)&hashed_net_address, true));
  } else {
    syslog(LOG_ERR, "%s: ERROR: PROVIDED NET ADDRESS COULD NOT BE HASHED", __func__ );
    return NULL;
  }
}

int __attribute__((nonnull(1, 2)))
AssignNetAddressHashForSession(InstanceContextForSession *instance_context, const struct sockaddr_in *src)
{
  unsigned long hashed_net_address  = HashNetAddress(src);
  if (hashed_net_address > 0) {
    SESSION_NETADDRESS_HASH(instance_context->sesn_ptr) = hashed_net_address;
  } else {
    syslog(LOG_ERR, "%s (ins_o:'%p'): ERROR: UNABLE TO HASH NET ADDRESS FOR SESSION", __func__, instance_context->instance_sesn_ptr);
  }

  return hashed_net_address;
}

__unused UFSRVResult * __attribute__((nonnull(1)))
GetSessionForHashedNetAddress(HashTable *hash_table, struct sockaddr_in *src, unsigned long call_flags)
{
  __unused Session *sesn_ptr_other_user = NULL;

  InstanceHolderForSession *instance_sesn_ptr_other_user = LocallyLocateSessionByNetAddress(hash_table, src);

  if (IS_PRESENT(instance_sesn_ptr_other_user)) {
    sesn_ptr_other_user = SessionOffInstanceHolder(instance_sesn_ptr_other_user);
/*
    int res_code = RESCODE_PROG_LOCKED;

    if (call_flags&CALL_FLAG_LOCK_SESSION) {
      if (!(call_flags&CALL_FLAG_LOCK_SESSION_BLOCKING)) 	SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_other_user, _LOCK_TRY_FLAG_TRUE, __func__);
      else 																								SessionLockRWCtx(THREAD_CONTEXT_PTR, sesn_ptr_other_user, _LOCK_TRY_FLAG_FALSE, __func__);

      if (_RESULT_TYPE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESULT_TYPE_SUCCESS)) {
        if (_RESULT_CODE_EQUAL(THREAD_CONTEXT_UFSRV_RESULT(THREAD_CONTEXT), RESCODE_PROG_LOCKED_BY_THIS_THREAD)) res_code = RESCODE_PROG_LOCKED_BY_THIS_THREAD;
      }
      else {_RETURN_RESULT_SESN(sesn_ptr_carrier, NULL, RESULT_TYPE_ERR, RESCODE_PROG_WONTLOCK)
      }
    }

    if (SESNSTATUS_IS_SET(sesn_ptr_other_user->stat, SESNSTATUS_FENCELIST_LAZY)) {
      SessionTransferAccessContext (sesn_ptr_carrier, sesn_ptr_other_user, false);
      InstateFenceListsForUser (instance_sesn_ptr_other_user, SESSION_CALLFLAGS_EMPTY, ALL_FENCE_TYPES, true);
    }

    if (IS_PRESENT(lock_state))	*lock_state = (res_code == RESCODE_PROG_LOCKED_BY_THIS_THREAD ? true : false);
    _RETURN_RESULT_SESN(sesn_ptr_carrier, sesn_ptr_other_user, RESULT_TYPE_SUCCESS, SESSION_RESULT_CODE(sesn_ptr_carrier))
    */
  }

  return NULL;
}

#include <regex.h>

static bool
_is_ufsrvuid_serialised_format(const char * _Nonnull ufsrvuid_serialised)
{
#define UFSRVUID_SERIALISED_REGEX_PATTERN "[1-9][0123456789ABCDEFGHJKMNPQRSTVWXYZ]{25}$"
  regex_t regex;

  if (regcomp(&regex, UFSRVUID_SERIALISED_REGEX_PATTERN, REG_EXTENDED) != 0) {
    return false;
  }

  int ret = regexec(&regex, ufsrvuid_serialised, (size_t) 0, NULL, 0);
  regfree(&regex);

  if (ret == 0) {
    return true;
  }

  return false;

#undef UFSRVUID_SERIALISED_REGEX_PATTERN
}

bool
IsSessionIdFormatValid(const char * _Nonnull session_id_str)
{
  return _is_ufsrvuid_serialised_format(session_id_str);
}