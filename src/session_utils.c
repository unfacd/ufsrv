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
#include <session_utils.h>
#include <session.h>
#include <utils.h>
#include <thread_context_type.h>
#include <nportredird.h>
#include <persistance.h>
#include <redis.h>
#include <ufsrvuid.h>


struct json_object *
GetPresenceInformation (Session *sesn_ptr, struct json_object *jobj_contacts)
{
  int contacts_count=json_object_array_length(jobj_contacts);

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
  {
    int 								i;
    int 								tokens_processed,
                        tokens_matched_idx		=	0;
    redisReply 					**replies;
    struct json_object 	*jobj_shared_contacts	=	json_object_new_array();
    struct json_object 	*jobj_token						=	NULL;

    replies = malloc(sizeof(redisReply*)*actually_processed);

    tokens_processed=actually_processed;

    for (i=0; i<actually_processed; i++) {
      if ((RedisGetReply(sesn_ptr, pers_ptr, (void*)&replies[i]) == REDIS_OK)) {
        if (replies[i] != NULL && replies[i]->type != REDIS_REPLY_NIL && replies[i]->element[0]->type!=REDIS_REPLY_NIL) {
          //retain a local copy
          char uid_encoded[CONFIG_MAX_UFSRV_ID_ENCODED_SZ+1] = {0};

          uids[tokens_matched_idx]              = UfsrvUidConvertToString((UfsrvUid *)replies[i]->element[0]->str, uid_encoded);
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
      jobj_token=json_object_new_object();

      json_object_object_add (jobj_token, "ufsrvuid", json_object_new_string(uids[i]));
      json_object_object_add (jobj_token, "status", json_object_new_int(status[i]));
      json_object_object_add (jobj_token, "suspended", json_object_new_int64(when_suspended[i]));
      json_object_object_add (jobj_token, "serviced", json_object_new_int64(when_serviced[i]));

      json_object_array_add(jobj_shared_contacts, jobj_token);
    }

    if (json_object_array_length(jobj_shared_contacts)==0) {
      syslog (LOG_DEBUG, LOGSTR_BACKENDCACHE_SHARED_CONTACTS_REPORT, __func__, pthread_self(), sesn_ptr, 0, LOGCODE_BACKENDCACHE_SHARED_CONTACTS_FOUNDNONE, "No userid were found");

      json_object_put(jobj_shared_contacts);

      return NULL;
    } else {
#ifdef __UF_FULLDEBUG
      syslog (LOG_DEBUG, LOGSTR_BACKENDCACHE_SHARED_CONTACTS_REPORT, __func__, pthread_self(), sesn_ptr, json_object_array_length(jobj_shared_contacts), LOGCODE_BACKENDCACHE_SHARED_CONTACTS_TOTALFOUND, "Total uids found");
#endif
      return jobj_shared_contacts;
    }
  }

  return NULL;

}
