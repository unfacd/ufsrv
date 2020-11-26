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
#include <ufsrv_core/user/user_preferences.h>
#include <ufsrv_core/user/users_protobuf.h>
#include "users.h"
#include <ufsrv_core/msgqueue_backend/ufsrvcmd_broadcast.h>
#include <ufsrv_core/msgqueue_backend/UfsrvMessageQueue.pb-c.h>
#include <ufsrv_core/SignalService.pb-c.h>

//this holds the two main preference sources: user prefs and fence user prefs. See defined enum PrefType
static UserPreferencesRegistry master_prefs[2];

void
RegisterUserPreferenceSource(UserPreferences *prefs_table, enum PrefType pref_type, size_t size)
{
  if (IS_PRESENT(prefs_table))	{
    master_prefs[pref_type].master_pref       = prefs_table;
    master_prefs[pref_type].master_pref_size  = size;
  }
}

UserPreferences *
GetUserPreferencesSource (enum PrefType pref_type)
{
//	return master_prefs[pref_type];
  return master_prefs[pref_type].master_pref;
}

UserPreferencesRegistry const *
GetUserPreferencesMasterRegistry (enum PrefType pref_type)
{
  return &master_prefs[pref_type];
}

/**
 * 	@brief: main interface function for storing user pref regardless of type
 * 	@param pref_ptr: a preference with the desired value set, most likely seeded with GetUserPreferenceDescriptorByName (prefs_table_ptr, pref_name);
 * 	@param pref_store: where to store the value: memory, cached, persisted. IMPORTANT: writes automatically cascades through  from high(mem)->low(persisted)
 *
 * 	TODO: FACTOR OUT PrefsStore pref_store, UserPreferenceDescriptor *pref_ptr_out from signature
 */
UserPreferenceDescriptor *
SetUserPreference(ClientContextData *ctx_ptr, UserPreferenceDescriptor *pref_ptr, PrefsStore pref_store, UfsrvEvent *event_ptr)
{
	if (IS_EMPTY(pref_ptr)) {
		syslog(LOG_DEBUG, "%s {pid:'%lu, o_ctx:'%p', pref_name:'%s'}: ERROR: PREF_NAME INVALID", __func__, pthread_self(), ctx_ptr, pref_ptr->pref_name);
		return NULL;
	}

	if (IS_PRESENT(pref_ptr->pref_validate))	if (IS_EMPTY((*pref_ptr->pref_validate)(ctx_ptr, pref_ptr))) return NULL;

	return (*pref_ptr->pref_ops->pref_set)(ctx_ptr, pref_ptr, pref_store, event_ptr);

}

/**
 * 	@brief: main interface function for storing  preference value in memory-resident instance
 * 	@param pref_ptr: a preference with the desired value set, most likely seeded with GetUserPreferenceDescriptorByName (prefs_table_ptr, pref_name);
 */
UserPreferenceDescriptor *
SetLocalUserPreference (ClientContextData *ctx_ptr, UserPreferenceDescriptor 	*pref_ptr, bool flag_validate)
{
	if (IS_EMPTY(pref_ptr))
	{
		syslog(LOG_DEBUG, "%s {pid:'%lu, o_ctx:'%p', pref_name:'%s'}: ERROR: PREF_NAME INVALID", __func__, pthread_self(), ctx_ptr, pref_ptr->pref_name);
		return NULL;
	}

	//TODO: is this necessary for local value update? Should happen at the containing level
	if (flag_validate)	if (IS_PRESENT(pref_ptr->pref_validate))	if (IS_EMPTY((*pref_ptr->pref_validate)(ctx_ptr, pref_ptr)))	return NULL;

	return (*pref_ptr->pref_ops->pref_set_local)(ctx_ptr, pref_ptr);

}

/**
 * 	@brief: interface function for getting pref values
 * 	@param pref_ptr: User supplied preloaded with descriptor specs. e.g. using GetFenceUserPreferenceDescriptorByName("sticky_geogroup", &pref)
 * 	@param pref_store: which store to get the value from: memory, cached (redis), persisted(db)
 */
UserPreferenceDescriptor *
GetUserPreference (ClientContextData *ctx_ptr, UserPreferenceDescriptor *pref_ptr, PrefsStore pref_store)
{
	return (*pref_ptr->pref_ops->pref_get)(ctx_ptr, pref_ptr, pref_store, NULL);

}

/*
 * @brief: check the memory-stored value for preference is valid
 */
UserPreferenceDescriptor *
ValidateUserPreference (ClientContextData *ctx_ptr, UserPreferenceDescriptor *pref_ptr)
{
	if (IS_PRESENT(pref_ptr->pref_validate)) return ((*pref_ptr->pref_validate)(ctx_ptr, pref_ptr));

	return NULL;

}

/**
 * 	@brief: returns the meta descriptor for a given preference based on name
 * 	@param pref_ptr_out: User must provide storage for the return copy to store canonical information into
 * 	TODO: This uses a quick and dirty strcmp(), consider using lexer.
 */
UserPreferenceDescriptor *
GetUserPreferenceDescriptorByName (UserPreferences *prefs_table_ptr, const char *pref_name, UserPreferenceDescriptor *pref_ptr_out)
{
	if (!IS_STR_LOADED(pref_name))	return NULL;

	for (size_t i=0; i<prefs_table_ptr->prefs_table_sz-1; i++)
	{
		UserPreferenceDescriptor *pref_ptr=(UserPreferenceDescriptor *)(prefs_table_ptr->prefs_table+(i*sizeof(UserPreferenceDescriptor)));
		if (strcmp(pref_ptr->pref_name, pref_name)==0)
		{
			*pref_ptr_out=*pref_ptr;
			return pref_ptr_out;//&(prefs_table_ptr->fence_prefs_table[i]);
		}
	}

	return NULL;
}

/**
 *  @brief: returns the meta descriptor for a given preference based on id
 */
UserPreferenceDescriptor *
GetUserPreferenceDescriptorById (UserPreferences *prefs_table_ptr, const UserPrefsOffsets pref_offset, UserPreferenceDescriptor *pref_ptr_out)
{

	if (pref_offset >= 0 && pref_offset < prefs_table_ptr->prefs_table_sz-1) {
		UserPreferenceDescriptor *prefs_ptr = (UserPreferenceDescriptor *)prefs_table_ptr->prefs_table;
		UserPreferenceDescriptor *pref_ptr  = prefs_ptr+pref_offset;
		*pref_ptr_out                       = *pref_ptr;

		return pref_ptr_out;
	}

	return NULL;
}

inline static void _SetJsonPrefValueByType(struct json_object *jobj_pref, const char *, UserPreferenceDescriptor *pref_ptr);

struct json_object *
JsonFormatUserPreference (UserPreferenceDescriptor *pref_ptr)
{
	json_object 		*jobj_pref = json_object_new_object();

	json_object_object_add (jobj_pref, "name", 			json_object_new_string(pref_ptr->pref_name));
//	json_object_object_add (jobj_pref, "value_type", json_object_new_int(pref_ptr->pref_value_type));
	_SetJsonPrefValueByType(jobj_pref, "value", 			pref_ptr);

	return jobj_pref;
}

inline static void
_SetJsonPrefValueByType(struct json_object *jobj_pref, const char *json_name, UserPreferenceDescriptor *pref_ptr)
{
	switch (pref_ptr->pref_value_type)
	{
		case PREFVALUETYPE_BOOL:
			json_object_object_add (jobj_pref, json_name, json_object_new_boolean(pref_ptr->value.pref_value_bool));
			break;
		case PREFVALUETYPE_INT:
			json_object_object_add (jobj_pref, json_name, json_object_new_int(pref_ptr->value.pref_value_int));
			break;
		case PREFVALUETYPE_STR:
			json_object_object_add (jobj_pref, json_name, json_object_new_string(pref_ptr->value.pref_value_str));
			break;
		default:
			json_object_object_add (jobj_pref, json_name, json_object_new_string("_INVALID"));
	}

}

/**
 * 	@brief: Helper function to transfer the pref value from "wire" into native form
 * 	@WARNING: String value is pointer reference. make sure sesn_msg_pref_ptr stays in scope until string value no longer needed
 */
void
SetPrefValueByTypeFromIntraSessionMessage (UserPreference *sesn_msg_pref_ptr, UserPreferenceDescriptor *pref_ptr)
{
	switch (pref_ptr->pref_value_type)
		{
			case PREFVALUETYPE_BOOL:
				pref_ptr->value.pref_value_bool=sesn_msg_pref_ptr->values_int;
				break;
			case PREFVALUETYPE_INT:
				pref_ptr->value.pref_value_int=sesn_msg_pref_ptr->values_int;
				break;
			case PREFVALUETYPE_STR:
				pref_ptr->value.pref_value_str=sesn_msg_pref_ptr->values_str;//TODO: Do we strudp?? No because pref_ptr is not dynamically allocated
				break;
			case PREFVALUETYPE_INT_MULTI:
			case PREFVALUETYPE_STR_MULTI:
				pref_ptr->value.pref_value_multi=(void**)sesn_msg_pref_ptr->values_str_m;
				break;
			case PREFVALUETYPE_BLOB:
				pref_ptr->value.pref_value_blob = (void *)&(sesn_msg_pref_ptr->vaues_blob); //this contain payload+length
				break;
			default:
				;
		}
}

/**
 * THIS probably won't be needed under  current implementation due to the way user prefs are handled. The backend data model
 * can be changed by the ufsrvapi which will trigger and INTRA broadcast, forcing every body to interpret it with INTER semantics.
 *
 * 	@brief: Inter-Broadcast change in Prefs status to ufsrv peers. This should only originate from stateful ufsrv.
 * 	@param pref_collection_ptr: collection of UserPreferenceDescriptor * containing pref values to encode
 *
 */
#if 0
UFSRVResult *
InterBroadcastForSessionPreferences (Session *sesn_ptr, CollectionDescriptor *pref_collection_ptr)
{
	if (IS_PRESENT(sesn_ptr) && IS_PRESENT(pref_collection_ptr) && (pref_collection_ptr->collection_sz>0))
	{
		MessageQueueBackend *mq_ptr=sesn_ptr->msgqueue_backend;

		MessageQueueMessage msgqueue_msg			=	MESSAGE_QUEUE_MESSAGE__INIT;
		SessionMessage 			msgqueue_sesn_msg	=	SESSION_MESSAGE__INIT;
		CommandHeader				header						=	COMMAND_HEADER__INIT;

		msgqueue_msg.session									=	&msgqueue_sesn_msg;
		msgqueue_sesn_msg.header							=	&header;

		MakeUfsrvUidInProto(&SESSION_UFSRVUIDSTORE(sesn_ptr), &(header.ufsrvuid), true); header.has_ufsrvuid = 1;
		header.when														=	time(NULL);								header.has_when=1;

		CollectionDescriptor collection_prefs={0};
		UserPreference pref_descriptor_mempool[pref_collection_ptr->collection_sz];//mempool
		UserPreference *pref_descriptor_ptrs[pref_collection_ptr->collection_sz];
		void *ppool=pref_descriptor_mempool;

		memset(pref_descriptor_mempool, 0, sizeof pref_descriptor_mempool);

		for (size_t i=0; i<pref_collection_ptr->collection_sz; i++)
			pref_descriptor_ptrs[i]=(UserPreference *)(pref_descriptor_mempool+(i*sizeof(UserPreference)));

		collection_prefs.collection_sz=pref_collection_ptr->collection_sz;
		collection_prefs.collection		=(collection_t **)pref_descriptor_ptrs;

		if (IS_EMPTY(MakeSessionMessageUserPreferenceInProto (sesn_ptr, pref_collection_ptr, &collection_prefs)))
		{
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: ERROR: recieved zero size Prefs collection", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
		}

		msgqueue_msg.origin								=	masterptr->serverid;
    MakeUfsrvUidInProto(&SESSION_UFSRVUIDSTORE(sesn_ptr), &(msgqueue_msg.ufsrvuid), true);
    msgqueue_msg.has_ufsrvuid = 1;
		msgqueue_sesn_msg.prefs						=	(UserPreference **)collection_prefs.collection;
		msgqueue_sesn_msg.n_prefs					=	collection_prefs.collection_sz;
		msgqueue_sesn_msg.status					=	SESSION_MESSAGE__STATUS__PREFERENCE;

		size_t packed_sz=message_queue_message__get_packed_size(&msgqueue_msg);
		//uint8_t *packed_msg=malloc(packed_sz);
		uint8_t packed_msg[packed_sz];
		message_queue_message__pack (&msgqueue_msg, packed_msg);

	#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', origin:'%d', uname:'%s'}: Publishing inter-Session-pref message...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), masterptr->serverid, SESSION_USERNAME(sesn_ptr));
	#endif

		redisReply *redis_ptr=(*mq_ptr->send_command)(sesn_ptr, REDIS_CMD_SESSION_PUBLISH_INTERMSG_P, packed_msg, packed_sz);

		if (IS_PRESENT(redis_ptr))
		{
			if (unlikely((redis_ptr->type==REDIS_REPLY_ERROR)))
			{
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', origin:'%d', uname:'%s', error:'%s'}: ERROR: COULD NOT INTRA-PUBLISH MESSAGE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), masterptr->serverid, SESSION_USERNAME(sesn_ptr), redis_ptr->str);
				freeReplyObject(redis_ptr);

				_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
			}

			freeReplyObject(redis_ptr);
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);
		}
	}//if

	if 	((IS_EMPTY(sesn_ptr)))	goto return_error_generic;
	if 	((IS_EMPTY(pref_collection_ptr)))		goto return_error_prefs_param;
	if	((pref_collection_ptr->collection_sz==0))	goto return_error_empty_set;

	return_error_empty_set:
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: ERROR: recieved zer size Prefs collection", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);

	return_error_prefs_param:
	syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "CollectionDescriptor *");
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_MISSING_PARAM);

	return_error_generic:
	syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Session *");
	return _ufsrv_result_generic_error;

}

/**
 * 	@brief: Generic Inter-Broadcast change in Prefs status to ufsrv peers. This should originate from stateless ufsrv (ufsrvapi).
 * 	Another more specific implementation exists BroadcastIntraSessionMessageFenceUserPrefs().
 *
 * 	This is currently designed to be invoked from ufsrvapi, because the prefs api is oblivion
 * to server processing environment and POST requests will be executed against the data backend model in order to acknowledge the request
 * properly. Therefore this broadcast is kind of "after-the-fact" from the point of view of the ufsrv class servers and should treat it with INTER
 * semantics. In turn ufsrv should not invoke an INTER broadcast when it receives this.
 * Also, this broadcast need not be target at a named instance: all servers must that have this user/fence must updated their
 * local data model.
 *
 * 	@param pref_collection_ptr: collection of UserPreferenceDescriptor * containing pref values to encode
 */
UFSRVResult *
IntraBroadcastForSessionPreferences (Session *sesn_ptr, CollectionDescriptor *pref_collection_ptr)
{
	if (IS_PRESENT(sesn_ptr) && IS_PRESENT(pref_collection_ptr) && (pref_collection_ptr->collection_sz>0))
	{
		CollectionDescriptor collection_prefs={0};
		UserPreference pref_descriptor_mempool[pref_collection_ptr->collection_sz];//mempool
		UserPreference *pref_descriptor_ptrs[pref_collection_ptr->collection_sz];

		memset(pref_descriptor_mempool, 0, sizeof pref_descriptor_mempool);

		for (size_t i=0; i<pref_collection_ptr->collection_sz; i++)
			pref_descriptor_ptrs[i]=(UserPreference *)(pref_descriptor_mempool+(i*sizeof(UserPreference)));

		collection_prefs.collection_sz=pref_collection_ptr->collection_sz;
		collection_prefs.collection		=(collection_t **)pref_descriptor_ptrs;

		if (IS_EMPTY(MakeSessionMessageUserPreferenceInProto (sesn_ptr, pref_collection_ptr, &collection_prefs)))
		{
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: ERROR: recieved zero size Prefs collection", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
		}

		//SessionMessage are formatted slightly differently
		SessionMessage 	msgqueue_sesn_msg	=	SESSION_MESSAGE__INIT;
		CommandHeader		header						=	COMMAND_HEADER__INIT;

		msgqueue_sesn_msg.header					=	&header;
		MakeUfsrvUidInProto(&SESSION_UFSRVUIDSTORE(sesn_ptr), &(header.ufsrvuid), true); header.has_ufsrvuid = 1;
		header.when												=	time(NULL);								header.has_when=1;

		msgqueue_sesn_msg.prefs						=	(UserPreference **)collection_prefs.collection;
		msgqueue_sesn_msg.n_prefs					=	collection_prefs.collection_sz;
		msgqueue_sesn_msg.status					=	SESSION_MESSAGE__STATUS__PREFERENCE;

	#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', origin:'%d', uname:'%s'}: Publishing intra-Session-pref message...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), masterptr->serverid, SESSION_USERNAME(sesn_ptr));
	#endif

		UfsrvApiIntraBroadcastMessage (sesn_ptr, _WIRE_PROTOCOL_DATA((&msgqueue_sesn_msg)), MSGCMD_SESSION, INTRA_WITH_INTER_SEMANTICS, NULL);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);
	}//if

	return _ufsrv_result_generic_error;

}
#endif

/**
 * 	@brief: Interface function called when an update to a user's preference received through INTRA command message.
 * 	This command does not require backend model changes, as that would have been taken care of by the broadcaster, therefore
 * 	we dont test for target_ufsrv.
 *
 * 	@param sesn_ptr: user session loaded in ephemeral mode
 * 	@locked sesn_ptr: by caller
 */
UFSRVResult *
HandleIntraCommandForSessionPreference (Session *sesn_ptr, SessionMessage *sesn_msg_ptr)
{
	if (unlikely(IS_EMPTY(sesn_msg_ptr)))
	{
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', uname:'%s'}: ERROR: SessionMessage missing", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_USERNAME(sesn_ptr));
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
	}

	UserPreferences *prefs_table_ptr	=	NULL;

	if (sesn_msg_ptr->n_prefs>0)
	{
		prefs_table_ptr=GetUserPreferencesSource (PREFTYPE_USER);
	}
	else if (sesn_msg_ptr->n_fence_prefs>0)
	{
		prefs_table_ptr=GetUserPreferencesSource (PREFTYPE_FENCEUSER);
	}
	else
	{
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', uname:'%s'}: ERROR: SessionMessage DID NOT CONTAIN VALID PREFS DFINITION", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), SESSION_USERNAME(sesn_ptr));
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
	}

	return (*prefs_table_ptr->type_ops.intra_msg_handler)(sesn_ptr, sesn_msg_ptr);
}

json_object *
PreferenceBooleanJsonValueFormatter (UserPreferenceDescriptor *pref_descriptor, json_object *jobj_out)
{
	json_object	*jobj;

	if (IS_PRESENT(jobj_out))	jobj=jobj_out;
	else											jobj=json_object_new_object();

	json_object_object_add(jobj, "id", json_object_new_int(pref_descriptor->pref_id));
	json_object_object_add(jobj, "value", json_object_new_boolean(pref_descriptor->value.pref_value_bool));

	return jobj;
}

json_object *
JsonValueFormatForGenericInteger (Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out)
{
  json_object	*jobj;
  if (IS_PRESENT(jobj_out))	jobj = jobj_out;
  else											jobj = json_object_new_object();

  UserPreferenceDescriptor pref = {.pref_id=preference_descriptor->pref_id, .pref_name=preference_descriptor->pref_name};
  GetUserPreferenceInteger(&SESSION_UFSRVUIDSTORE(sesn_ptr), PREFSTORE_CACHED, preference_descriptor->pref_id, &pref);

  return PreferenceIntegerJsonValueFormatter (&pref, jobj);

}

json_object *
JsonValueFormatForGenericString (Session *sesn_ptr, UserPreferenceDescriptor *preference_descriptor, json_object *jobj_out)
{
  json_object	*jobj;
  if (IS_PRESENT(jobj_out))	jobj = jobj_out;
  else											jobj = json_object_new_object();

  UserPreferenceDescriptor pref = {0};//.pref_id=preference_descriptor->pref_id, .pref_name=preference_descriptor->pref_name};
  GetUserPreferenceString(&SESSION_UFSRVUIDSTORE(sesn_ptr), PREFSTORE_CACHED, preference_descriptor->pref_id, &pref);

  return PreferenceStringJsonValueFormatter (&pref, jobj);

}

json_object *
PreferenceIntegerJsonValueFormatter (UserPreferenceDescriptor *pref_descriptor, json_object *jobj_out)
{
	json_object	*jobj;

	if (IS_PRESENT(jobj_out))	jobj=jobj_out;
	else											jobj=json_object_new_object();

	json_object_object_add(jobj, "id", json_object_new_int(pref_descriptor->pref_id));
	json_object_object_add(jobj, "value", json_object_new_int64(pref_descriptor->value.pref_value_int));

	return jobj;
}

json_object *
PreferenceStringJsonValueFormatter (UserPreferenceDescriptor *pref_descriptor, json_object *jobj_out)
{
	json_object	*jobj;

	if (IS_PRESENT(jobj_out))	jobj=jobj_out;
	else											jobj=json_object_new_object();

	json_object_object_add(jobj, "id", json_object_new_int(pref_descriptor->pref_id));
	json_object_object_add(jobj, "value", json_object_new_string(pref_descriptor->value.pref_value_str));

	return jobj;
}

/**
 *
 * @param pref_descriptor
 * @param jobj_out represents preallocated json array
 * @return locally allocated json object
 * @dynamic_memory: ALLOCATE json_object *
 */
json_object *
PreferenceListJsonValueFormatter(UserPreferenceDescriptor *pref_descriptor, json_object *jobj_array)
{
	json_object	*jobj = json_object_new_object();

	json_object_object_add(jobj, "id", json_object_new_int(pref_descriptor->pref_id));
	json_object_object_add(jobj, "value", jobj_array);

	return jobj;
}

/**
 *
 * @param sesn_ptr session used for preference value lookup
 * @param pref_type session or fence prefs
 * @param digest_mode
 * @param jobj_out if provided must be of type array
 * @return binary json object
 *
 * @locked sesn_ptr: minimum readonly
 */
json_object *
JsonFormatUserPreferences (Session *sesn_ptr, enum PrefType pref_type, enum DigestMode digest_mode, json_object *jobj_out)
{
  UserPreferencesRegistry const *pref_rego = GetUserPreferencesMasterRegistry (pref_type);
  json_object	*jobj_array;

  if (IS_PRESENT(jobj_out))	jobj_array = jobj_out;
  else											jobj_array = json_object_new_array();

  for (size_t i = 0; i<pref_rego->master_pref_size; i++) {
    const UserPreferenceDescriptor *pref_descriptor = ((UserPreferenceDescriptor *)pref_rego->master_pref->prefs_table+i);
    if (likely(IS_PRESENT(pref_descriptor->pref_validate) && IS_PRESENT((pref_descriptor->pref_value_formatter)))) {
    	json_object *jobj_pref;
    	if ((jobj_pref = (*pref_descriptor->pref_value_formatter)(CLIENT_CTX_DATA(sesn_ptr), (UserPreferenceDescriptor *)pref_descriptor, NULL))) {
				json_object_array_add(jobj_array, jobj_pref);
    	}
		}
  }

  return jobj_array;

}
