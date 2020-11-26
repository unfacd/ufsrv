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
#include <misc.h>
#include <utils_crypto.h>
#include <utils_hex.h>
#include <utils_str.h>
#include <ufsrv_core/user/users.h>
#include <ufsrv_core/user/user_preferences.h>
#include <session_service.h>
#include <session_broadcast.h>
#include <session.h>
#include <ufsrv_core/cache_backend/redis.h>
#include <ufsrv_core/user/user_backend.h>
#include <http_request.h>
#include <uflib/db/db_sql.h>
#include <sessions_delegator_type.h>
#include <attachment_descriptor_type.h>
#include <ufsrvuid.h>
#include <ufsrv_core/user/user_preference_descriptor_type.h>
#include <uuid_type.h>
#include <uflib/db/dp_ops.h>
#include <ufsrv_core/user/user_profile.h>
#include <utils_nonce.h>
#include <utils_db_account.h>
#include <include/nportredird.h>

extern SessionsDelegator *const sessions_delegator_ptr;
extern __thread ThreadContext ufsrv_thread_context;

static int			_DbCreateAccount (Session *sesn_ptr, struct json_object *jobj_device, struct json_object *jobj_userdata, enum AccountRegoStatus);
static int      _DbAccountUpdateUfrsvUid (Session *sesn_ptr, const UfsrvUid *uid_ptr);
static int			_DbUpdateAccountInJson (Session *sesn_ptr, unsigned long, struct json_object *jobj_account);
static UFSRVResult  *_DbCreateNewPendingAccount (Session *sesn_ptr, const char *cookie, UserCredentials *creds_ptr, VerificationCode *vcode_ptr);
static UFSRVResult	*_DbAccountAttributeSetText (Session *sesn_ptr, const UfsrvUid *, int device_id, const char *attr_name, const char *new_value);
static UFSRVResult	*_DbAccountAttributeSetJsonObject (Session *sesn_ptr, const UfsrvUid *, int device_id_in, const char *attr_name, struct json_object *jobj);
static UFSRVResult	*_DbAccountDataDeviceAttributeGetText(Session *sesn_ptr, unsigned long, int device_id, const char *attribute_name);
static UFSRVResult *_DbAccountDataAttributeGetTextByUsername (Session *sesn_ptr, const char *username, const char *attribute_name);
static UFSRVResult	*_DbAccountAttributeSetTextTopLevel (Session *sesn_ptr, const UfsrvUid *, const char *attr_name, const char *new_value);
static UFSRVResult	*_DbAccountAttributeGetJsonObject (Session *sesn_ptr, unsigned long, int device_id, const char *attribute_name) __attribute__((unused));
static UFSRVResult	*_DbAccountNicknameGet (Session *sesn_ptr, const char *nickname, UFSRVResult *res_ptr_in);
static struct json_object *_GenerateUserDataJsonDescriptor(Session *sesn_ptr, const UfsrvUid *uid_ptr, bool flag_check_backend);
static void _BackendUpdateE164NumberIfNecessary(Session *sesn_ptr, const char *e164number_provided, unsigned long id_sequence_number, char *e164number_updated_out, bool is_force_assigned);
static void _GenerateUfsrvE164Number (unsigned long id_sequence_number, char *e164number_generated_out);

static const uintptr_t _AttribueValueGetterByText(json_object *jobj_data, const char *attribute_name);
static const uintptr_t _AttribueValueGetterByBoolean(json_object *jobj_data, const char *attribute_name);
static const uintptr_t _AttribueValueGetterByInt(json_object *jobj_data, const char *attribute_name);
typedef const uintptr_t (*AttribueValueGetter)(json_object *, const char *attribute_name);
static const uintptr_t _GetAccountDataDeviceAttributeByJsonObject(json_object *jobj_account, unsigned int device_id, const char *attribute_name, AttribueValueGetter value_getter_callback);

struct RawBuffer {
	char *memory;
	size_t size;
};
typedef struct RawBuffer RawBuffer;

/**
 *  If value of gcm_id is empty, it will set the value to empty ''
 *	Setting to empty will also have the side effect of disabling the account, as "fetches_messages" property will be be set to false
 *  @dynamic_memory jobj_account: dynamicly created from backend data. must be freed herein.
 */
int
DbSetGcmId (Session *sesn_ptr, const UfsrvUid *uid_ptr, int device_id, const char *gcm_id)
{
	struct json_object *jobj_account;

	jobj_account=DbGetAccountInJson (sesn_ptr, uid_ptr);
	if (!IS_PRESENT(jobj_account)) {
		syslog(LOG_DEBUG, "%s (o:'%p', cid:'%lu'): ERROR: COULD NOT GENERATE JSON OBJECT FOR ACCOUNT USERID:'%lu'", __func__, sesn_ptr, SESSION_ID(sesn_ptr), UfsrvUidGetSequenceId(uid_ptr));

		return -1;
	}

	struct json_object *jobj_authenticated_device=json__get(jobj_account, "authenticated_device");
	json_object_object_del(jobj_authenticated_device, "gcm_id");
	json_object_object_add (jobj_authenticated_device, "gcm_id", json_object_new_string(gcm_id));

	json_bool fetches_message=json_object_get_boolean(json__get(jobj_authenticated_device, "fetches_messages"));
	if (fetches_message==0) {
#if __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', userid:'%lu'}: Recieved gcm_id for an inactive account: Activating...", __func__, pthread_self(), sesn_ptr, UfsrvUidGetSequenceId(uid_ptr));
#endif
		json_object_object_del(jobj_authenticated_device, "fetches_messages");
		json_object_object_add (jobj_authenticated_device,"fetches_messages", json_object_new_boolean(1));//only turned on once gcm is received
	}

	{
		//fetch device id and update there as well
		struct json_object *jobj_devices_array=json__get(jobj_account, "devices");
		int array_size=json_object_array_length(jobj_devices_array);
		int i;

#if __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: DEVICES ARRAY CONTAIN:'%d' DEVICES IN IT", __func__, pthread_self(), sesn_ptr, array_size);
#endif

		for (i=0; i<array_size; i++) {
			struct json_object *jobj_device=json_object_array_get_idx(jobj_devices_array, i);
			if (device_id==json_object_get_int(json__get(jobj_device, "id"))) {
				json_object_object_del(jobj_device, "gcm_id");
				json_object_object_add (jobj_device, "gcm_id", json_object_new_string(gcm_id));

				json_bool fetches_message=json_object_get_boolean(json__get(jobj_device, "fetches_messages"));
				if (fetches_message==0) {
#if __UF_TESTING
					syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', uname:'%s'}: Recieved gcm_id for an inactive account: Activating...", __func__, pthread_self(), sesn_ptr, SESSION_USERNAME(sesn_ptr));
#endif
					json_object_object_del(jobj_device, "fetches_messages");
					json_object_object_add (jobj_device,"fetches_messages", json_object_new_boolean(1));//only turned on once gcm is received
				}

				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', uname:'%s'}: UPDATED DEVICE ID:'%d' WITH NEW GCM_ID VALUE:'%s': UPDATING DB...", __func__, pthread_self(), sesn_ptr, SESSION_USERNAME(sesn_ptr), device_id,  gcm_id);

				_DbUpdateAccountInJson (sesn_ptr, UfsrvUidGetSequenceId(uid_ptr), jobj_account);

				json_object_put(jobj_account);

				return 0;//success
			}
		}

		syslog(LOG_DEBUG, "%s (cid='%lu'): COULD NOT UPDATE DEVICE ID:'%d' WITH NEW GCM_ID VALUE:'%s'", __func__, SESSION_ID(sesn_ptr), device_id,  gcm_id);
	}

	json_object_put(jobj_account);

	return -1;
}

/**
 * @dynamic_memroy: EXPORTS the returned string and passes it upstream.
 */
char *
DbGetGcmId (Session *sesn_ptr, const UfsrvUid *uid_ptr, int device_id)
{
  _DbAccountDataDeviceAttributeGetText(sesn_ptr, UfsrvUidGetSequenceId(uid_ptr), device_id, ACCOUNT_JSONATTR_GCM_ID);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
	  char *cm_token = (char *)SESSION_RESULT_USERDATA(sesn_ptr);
	  if (!(*cm_token == CONFIG_CM_TOKEN_UNDEFINED)) {
      return (char *) SESSION_RESULT_USERDATA(sesn_ptr);
    }

	  free (cm_token);
	}

	return NULL;
}

long long
DbGetWhenCreated (Session *sesn_ptr, const UfsrvUid *uid_ptr, int device_id)
{
	_DbAccountDataDeviceAttributeGetText(sesn_ptr, UfsrvUidGetSequenceId(uid_ptr), device_id, ACCOUNT_JSONATTR_CREATED);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
		return strtoul((char *)SESSION_RESULT_USERDATA(sesn_ptr), NULL, 10);
	}

	return 0L;
}

#if 0
SELECT  id,JSON_UNQUOTE(JSON_EXTRACT(data, '$.authenticated_device.gcm_id')) As gcm_id FROM accounts NATURAL JOIN
		(SELECT '+61xxxxx' AS number UNION ALL
		 SELECT '+61414821358'
		)t;

 use row constructors:index-friendly and would not be recommended on a table of any significant size.

SELECT * FROM email_phone_notes WHERE (email, phone) IN (
  ('foo@bar.com'  , '555-1212'),
  ('test@test.com', '888-1212')
  -- etc.
);

 materialise a table with your desired pairs and join that with your table:

SELECT * FROM email_phone_notes NATURAL JOIN (
  SELECT 'foo@bar.com' AS email, '555-1212' AS phone
UNION ALL
  SELECT 'test@test.com', '888-1212'
-- etc.
) t;
Or else pre-populate a (temporary) table:

CREATE TEMPORARY TABLE foo (PRIMARY KEY (email, phone)) Engine=MEMORY
  SELECT email, phone FROM email_phone_notes WHERE FALSE
;

INSERT INTO foo
  (email, phone)
VALUES
  ('foo@bar.com'  , '555-1212'),
  ('test@test.com', '888-1212')
  -- etc.
;

SELECT * FROM email_phone_notes NATURAL JOIN foo;
#endif

/**
 * 	@ALERT: This is highly specific function and builds on the assumption that usernames are max sizeof("+12345678901")
 */
UFSRVResult *
DbGetGcmIdMulti (Session *sesn_ptr, CollectionDescriptor *collection_ptr_in, CollectionDescriptor *collection_ptr_out)
{
	if (collection_ptr_in->collection_sz<=0)	return NULL;
#define QUERY_GCM_MULTISELECT_MAIN 				"SELECT  JSON_UNQUOTE(JSON_EXTRACT(data, '$.authenticated_device.gcm_id')) FROM accounts NATURAL JOIN "
#define QUERY_GCM_MULTISELECTROW					"(SELECT '+12345678901' AS number UNION ALL "
#define QUERY_GCM_MULTISELECTROW_PARAM		"(SELECT '%s' AS number UNION ALL "
#define QUERY_GCM_MULTISELECTROWSUB				"SELECT '+12345678901' "
#define QUERY_GCM_MULTISELECTROWSUB_PARAM	"SELECT '%s' "
#define QUERY_GCM_MULTISELECT_END					")t;"


	//TODO: sizeof() counts the NULL: recheck buffers
	char sql_query_str[sizeof(QUERY_GCM_MULTISELECT_MAIN)+(collection_ptr_in->collection_sz*sizeof(QUERY_GCM_MULTISELECTROW))];//little over specified
	char *query_str_walker_ptr = sql_query_str;

	memcpy (query_str_walker_ptr, QUERY_GCM_MULTISELECT_MAIN, sizeof(QUERY_GCM_MULTISELECT_MAIN));
	query_str_walker_ptr += sizeof(QUERY_GCM_MULTISELECT_MAIN);

	sprintf(query_str_walker_ptr, QUERY_GCM_MULTISELECTROW_PARAM, (char *)collection_ptr_in->collection[0]);
	query_str_walker_ptr+=sizeof(QUERY_GCM_MULTISELECTROW);

	for (size_t i=1; i<collection_ptr_in->collection_sz; i++) {
		sprintf(query_str_walker_ptr, QUERY_GCM_MULTISELECTROWSUB_PARAM, (char *)collection_ptr_in->collection[i]);
		query_str_walker_ptr += sizeof(QUERY_GCM_MULTISELECTROWSUB);
	}

	memcpy(query_str_walker_ptr, QUERY_GCM_MULTISELECT_END, sizeof(QUERY_GCM_MULTISELECT_END));
	query_str_walker_ptr += sizeof(QUERY_GCM_MULTISELECT_END);
	*query_str_walker_ptr = '\0';

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', bulk_sz:'%lu', final_sz:'%lu} Constructed multi query: '%s'", __func__, pthread_self(), sesn_ptr, sizeof(QUERY_GCM_MULTISELECT_MAIN)+(collection_ptr_in->collection_sz*sizeof(QUERY_GCM_MULTISELECTROW)), strlen(sql_query_str), sql_query_str);
#endif

#define SQL_QUERY_GCM_ATTRIBUTE(x)				((struct _h_type_blob *)result.data[x][0])
#define	SQL_QUERY_GCM_ATTRIBUTE_VALUE(x) 	((struct _h_type_blob *)result.data[x][0].t_data)->value
#define SQL_QUERY_GCM_ATTRIBUTE_VALUE_LENGTH(x)	((struct _h_type_blob *)result.data[x][0].t_data)->length

	struct _h_result result;

	int sql_result = h_query_select(sesn_ptr->db_backend, sql_query_str, &result);

	if (sql_result != H_OK) {
		syslog(LOG_DEBUG, LOGSTR_BACKENDDB_CONNECTION_ERROR, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str, LOGCODE_BACKENDDB_CONNECTION_ERROR);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
	}

	if (result.nb_rows == 0) {
		syslog(LOG_DEBUG, LOGSTR_BACKENDDB_EMPTY_RESULTSET, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str, LOGCODE_BACKENDDB_EMPTY_RESULTSET);

    h_clean_result (&result);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EMPTYSET)
	}

	CollectionDescriptor *collection_ptr = NULL;
	if (collection_ptr_out)	collection_ptr = collection_ptr_out;
	else {
		collection_ptr = calloc(1, sizeof(CollectionDescriptor));
		collection_ptr->collection = calloc(collection_ptr_in->collection_sz * MBUF, sizeof(char));
		collection_ptr->collection_sz = collection_ptr_in->collection_sz;
	}

	for (struct{size_t i; size_t collection_offset;} loop={0, 0}; loop.i<result.nb_rows; loop.i++) {
		char *gcm_id = (char *)(collection_ptr->collection + loop.collection_offset);
		memcpy (gcm_id, SQL_QUERY_GCM_ATTRIBUTE_VALUE(loop.i), SQL_QUERY_GCM_ATTRIBUTE_VALUE_LENGTH(loop.i));
		loop.collection_offset += MBUF;
	}

	h_clean_result (&result);

	_RETURN_RESULT_SESN(sesn_ptr, (void *)collection_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)

}

//attribute to be replace must already be in the set., otherwise JSON_INSERT is required
int
DbAccountUserDataUpdatePreference (Session *sesn_ptr,  UserPreferenceDescriptor *pref_ptr, unsigned long userid)
{
#define SQL_UPDATE_ACCOUNT_DATA_BOOLEAN  "UPDATE accounts SET data_user = JSON_REPLACE(data_user, '$.prefs_bool', '%lu') WHERE id='%lu'"
#define SQL_UPDATE_ACCOUNT_DATA_STRING 	 "UPDATE accounts SET data_user = JSON_REPLACE(data_user, '$.%s', '%s') WHERE id='%lu'"
#define SQL_UPDATE_ACCOUNT_DATA_INT 		 "UPDATE accounts SET data_user = JSON_REPLACE(data_user, '$.%s', '%lu') WHERE id='%lu'"

	char *sql_query_str;

	if (pref_ptr->pref_value_type == PREFVALUETYPE_BOOL) {
		unsigned long pref_boolean = GenerateUserPrefsBooleanForStorage (sesn_ptr);
		sql_query_str = mdsprintf(SQL_UPDATE_ACCOUNT_DATA_BOOLEAN, pref_boolean, userid);
	}
	else if (pref_ptr->pref_value_type == PREFVALUETYPE_INT) {
		sql_query_str = mdsprintf(SQL_UPDATE_ACCOUNT_DATA_INT, pref_ptr->pref_name, pref_ptr->value.pref_value_int, userid);
	}
	else if (pref_ptr->pref_value_type == PREFVALUETYPE_STR) {
		sql_query_str = mdsprintf(SQL_UPDATE_ACCOUNT_DATA_STRING, pref_ptr->pref_name, IS_STR_LOADED(pref_ptr->value.pref_value_str)?pref_ptr->value.pref_value_str:CONFIG_DEFAULT_PREFS_STRING_VALUE, userid);
	}
	else if (pref_ptr->pref_value_type == PREFVALUETYPE_STR_MULTI) {

	}
	else if (pref_ptr->pref_value_type == PREFVALUETYPE_INT_MULTI) {
    syslog(LOG_ERR, "%s {o:'%p', cid:'%lu'}: ERROR: PREF TYPE PREFVALUETYPE_INT_MULTI UNSUPPORTED '%d'", __func__, sesn_ptr, SESSION_ID(sesn_ptr), pref_ptr->pref_value_type);
	}
	else {
		syslog(LOG_ERR, "%s {o:'%p', cid:'%lu'}: ERROR: UNKNOWN PREF TYPE '%d'", __func__, sesn_ptr, SESSION_ID(sesn_ptr), pref_ptr->pref_value_type);
	}


#ifdef __UF_FULLDEBUG
	syslog(LOG_DEBUG, "%s (cid='%lu'): GENERATED SQL QUERY: '%s'", __func__, SESSION_ID(sesn_ptr), sql_query_str);
#endif

	int sql_result = h_query_update(sesn_ptr->db_backend, sql_query_str);

	if (sql_result != H_OK) {
		syslog(LOG_DEBUG, "%s (o:'%p', cid:'%lu'): ERROR: COULD EXECUTE QUERY: '%s'", __func__, sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str);
	}

  free (sql_query_str);

	return sql_result;

#undef SQL_UPDATE_ACCOUNT_DATA_STRING
}

/**
 * @brief: retrieves one json attribute from the user's account, defaulting to authenticated device
 * @dynamic_memory: upon success, allocates memory for the retunred string value, which the user must free
 */
static UFSRVResult *
_DbAccountDataDeviceAttributeGetText(Session *sesn_ptr, unsigned long userid, int device_id, const char *attribute_name)
{
	//IMPORTANT: USING JSON_UNQUOTE turns the value from json string,  ie. "value", to my sql string, i.e. value, but the library then returns blob type,
	//as opposed to string type. Without UNQUOTE we get string type, but we have to remove the opening and closing " manually
	#define SQL_SELECT_ACCOUNT_ATTRIBUTE_STRING "SELECT  JSON_UNQUOTE(JSON_EXTRACT(data, '$.authenticated_device.%s')) FROM accounts WHERE id=%lu"
	#define SQL_QUERY_ATTRIBUTE	((struct _h_type_blob *)result.data[0][0].t_data) //if attribute has null data this will be null
	#define	SQL_QUERY_ATTRIBUTE_VALUE ((struct _h_type_blob *)result.data[0][0].t_data)->value
	#define SQL_QUERY_ATTRIBUTE_VALUE_LENGTH	((struct _h_type_blob *)result.data[0][0].t_data)->length

		struct _h_result result;
		char *sql_query_str;

		sql_query_str=mdsprintf(SQL_SELECT_ACCOUNT_ATTRIBUTE_STRING, attribute_name, userid);

		syslog(LOG_DEBUG, LOGSTR_BACKENDDB_QUERY_STRING, __func__, pthread_self(), sesn_ptr, sql_query_str, LOGCODE_BACKENDDB_QUERY_STRING);

		int sql_result = h_query_select(sesn_ptr->db_backend, sql_query_str, &result);


		if (sql_result != H_OK) {
			syslog(LOG_DEBUG, LOGSTR_BACKENDDB_CONNECTION_ERROR, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str, LOGCODE_BACKENDDB_CONNECTION_ERROR);

			free (sql_query_str);

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
		}

		if (result.nb_rows == 0) {
			syslog(LOG_DEBUG, LOGSTR_BACKENDDB_EMPTY_RESULTSET, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str, LOGCODE_BACKENDDB_EMPTY_RESULTSET);

			h_clean_result(&result);
			free (sql_query_str);

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EMPTYSET)
		}

		free (sql_query_str);

		const char *attribute_value_returned=NULL;

		if ((SQL_QUERY_ATTRIBUTE) && (SQL_QUERY_ATTRIBUTE_VALUE_LENGTH > 0)) {
			attribute_value_returned = strndup((char *)SQL_QUERY_ATTRIBUTE_VALUE, SQL_QUERY_ATTRIBUTE_VALUE_LENGTH);

			h_clean_result(&result);

			_RETURN_RESULT_SESN(sesn_ptr, (void *)attribute_value_returned, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
		}

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

#undef 	SQL_SELECT_ACCOUNT_ATTRIBUTE_STRING
#undef 	SQL_QUERY_ATTRIBUTE
#undef	SQL_QUERY_ATTRIBUTE_VALUE
#undef 	SQL_QUERY_ATTRIBUTE_VALUE_LENGTH

}

static UFSRVResult *
_DbAccountDataAttributeGetTextByUsername (Session *sesn_ptr, const char *username, const char *attribute_name)
{
  //IMPORTANT: USING JSON_UNQUOTE turns the value from json string,  ie. "value", to my sql string, i.e. value, but the library then returns blob type,
  //as opposed to string type. Without UNQUOTE we get string type, but we have to remove the opening and closing " manually
#define SQL_SELECT_ACCOUNT_ATTRIBUTE_STRING "SELECT  JSON_UNQUOTE(JSON_EXTRACT(data, '$.%s')) FROM accounts WHERE number='%s'"
#define SQL_QUERY_ATTRIBUTE	((struct _h_type_blob *)result.data[0][0].t_data) //if attribute has null data this will be null
#define	SQL_QUERY_ATTRIBUTE_VALUE ((struct _h_type_blob *)result.data[0][0].t_data)->value
#define SQL_QUERY_ATTRIBUTE_VALUE_LENGTH	((struct _h_type_blob *)result.data[0][0].t_data)->length

  struct _h_result result;
  char *sql_query_str;

  sql_query_str = mdsprintf(SQL_SELECT_ACCOUNT_ATTRIBUTE_STRING, attribute_name, username);

  syslog(LOG_DEBUG, LOGSTR_BACKENDDB_QUERY_STRING, __func__, pthread_self(), sesn_ptr, sql_query_str, LOGCODE_BACKENDDB_QUERY_STRING);

  int sql_result = h_query_select(sesn_ptr->db_backend, sql_query_str, &result);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, LOGSTR_BACKENDDB_CONNECTION_ERROR, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str, LOGCODE_BACKENDDB_CONNECTION_ERROR);

    free (sql_query_str);

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
  }

  if (result.nb_rows == 0) {
    syslog(LOG_DEBUG, LOGSTR_BACKENDDB_EMPTY_RESULTSET, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str, LOGCODE_BACKENDDB_EMPTY_RESULTSET);

    h_clean_result(&result);
    free (sql_query_str);

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EMPTYSET)
  }

  free (sql_query_str);

  const char *attribute_value_returned = NULL;

  if ((SQL_QUERY_ATTRIBUTE) && (SQL_QUERY_ATTRIBUTE_VALUE_LENGTH > 0)) {
    attribute_value_returned = strndup((char *)SQL_QUERY_ATTRIBUTE_VALUE, SQL_QUERY_ATTRIBUTE_VALUE_LENGTH);

    h_clean_result(&result);

    _RETURN_RESULT_SESN(sesn_ptr, (void *)attribute_value_returned, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
  }

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

#undef 	SQL_SELECT_ACCOUNT_ATTRIBUTE_STRING
#undef 	SQL_QUERY_ATTRIBUTE
#undef	SQL_QUERY_ATTRIBUTE_VALUE
#undef 	SQL_QUERY_ATTRIBUTE_VALUE_LENGTH

}

/**
 * @brief: retrieves one json attribute from the user's account, defaulting to authenticated device
 * @dynamic_memory: uponsuccess, allocates memrory for the retunred string value, whicg the user must free
 */
static UFSRVResult *
_DbAccountAttributeGetJsonObject (Session *sesn_ptr, unsigned long userid, int device_id, const char *attribute_name)
{
	//IMPORTANT: USING JSON_UNQUOTE turns the value from json string,  ie. "value", to my sql string, i.e. value, but the library then return blob type,
	//as opposed to string type. Without UNQUOTE we get string type, but we have to remove the opening and closing " manually
	#define SQL_SELECT_ACCOUNT_ATTRIBUTE_STRING "SELECT  JSON_UNQUOTE(JSON_EXTRACT(data, '$.authenticated_device.%s')) FROM accounts WHERE id=%lu"
	#define SQL_QUERY_ATTRIBUTE	((struct _h_type_blob *)result.data[0][0].t_data)//this will be nulll if attribute had null value in db
	#define	SQL_QUERY_ATTRIBUTE_VALUE ((struct _h_type_blob *)result.data[0][0].t_data)->value
	#define SQL_QUERY_ATTRIBUTE_VALUE_LENGTH	((struct _h_type_blob *)result.data[0][0].t_data)->length

	struct _h_result result;
	char *sql_query_str;

	sql_query_str=mdsprintf(SQL_SELECT_ACCOUNT_ATTRIBUTE_STRING, attribute_name, userid);

	syslog(LOG_DEBUG, LOGSTR_BACKENDDB_QUERY_STRING, __func__, pthread_self(), sesn_ptr, sql_query_str, LOGCODE_BACKENDDB_QUERY_STRING);

	int sql_result=h_query_select(sesn_ptr->db_backend, sql_query_str, &result);

	if (sql_result!=H_OK) {
		syslog(LOG_DEBUG, LOGSTR_BACKENDDB_CONNECTION_ERROR, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str, LOGCODE_BACKENDDB_CONNECTION_ERROR);

    free (sql_query_str);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
	}

	if (result.nb_rows==0) {
		syslog(LOG_DEBUG, LOGSTR_BACKENDDB_EMPTY_RESULTSET, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str, LOGCODE_BACKENDDB_EMPTY_RESULTSET);

    free (sql_query_str);
    h_clean_result(&result);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EMPTYSET)
	}

  free (sql_query_str);

	const char *attribute_value_returned=NULL;

	if (/*(SQL_QUERY_ATTRIBUTE)&&*/(SQL_QUERY_ATTRIBUTE_VALUE)) {
		attribute_value_returned=strndup((char *)SQL_QUERY_ATTRIBUTE_VALUE, SQL_QUERY_ATTRIBUTE_VALUE_LENGTH);

		_RETURN_RESULT_SESN(sesn_ptr, (void *)attribute_value_returned, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

#undef 	SQL_QUERY_ATTRIBUTE
#undef 	SQL_SELECT_ACCOUNT_ATTRIBUTE_STRING
#undef	SQL_QUERY_ATTRIBUTE_VALUE
#undef 	SQL_QUERY_ATTRIBUTE_VALUE_LENGTH

}

/**
 * 	@brief: updates the json data portion FOR THE AUTHENTICATED DEVICE but only for attributes whose values are text
 * 	This is not efficient, as it fetches the entire json payload. We should be able to use the native mysql json command:
 *  UPDATE accounts SET data= JSON_SET(data, '$.access_token', '*') where id=351; as toplevel_keys from accounts where number=+61xxxxx;
 *	@param device_id_in: -1 use authenticated device id. Other values are not supported at this stage.
 * 	@dynamic_memory: INTERNALLY ALLOCATES struct json_object * and FREES it
 */
static UFSRVResult *
_DbAccountAttributeSetText (Session *sesn_ptr, const UfsrvUid *uid_ptr, int device_id_in, const char *attr_name, const char *new_value)
{
  json_object *jobj_account = DbGetAccountInJson (sesn_ptr, uid_ptr);
	if (IS_EMPTY(jobj_account)) {
		syslog(LOG_DEBUG, "%s {o:'%p', cid:'%lu'}: ERROR: COULD NOT GENERATE JSON OBJECT FOR ACCOUNT:'%lu'", __func__, sesn_ptr, SESSION_ID(sesn_ptr), UfsrvUidGetSequenceId(uid_ptr));

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
	}

	struct json_object *jobj_authenticated_device=json__get(jobj_account, "authenticated_device");
	json_object_object_del(jobj_authenticated_device, attr_name);
	json_object_object_add (jobj_authenticated_device, attr_name, json_object_new_string(new_value));

	//assign the target device id
	int device_id = 1;
	if (device_id_in == -1)	device_id=json_object_get_int(json__get(jobj_authenticated_device, "id"));
	else	device_id=device_id_in;

	{
		//fetch device id and update there as well
		struct json_object *jobj_devices_array=json__get(jobj_account, "devices");
		int array_size = json_object_array_length(jobj_devices_array);
		int i;

		for (i=0; i<array_size; i++) {
			struct json_object *jobj_device=json_object_array_get_idx(jobj_devices_array, i);
			if (device_id==json_object_get_int(json__get(jobj_device, "id"))) {
				json_object_object_del(jobj_device, attr_name);
				json_object_object_add (jobj_device, attr_name, json_object_new_string(new_value));
#ifdef __UF_FULLDEBUG
				syslog(LOG_DEBUG, "%s (cid='%lu'): UPDATED DEVICE ID:'%d' ATTR %s WITHNEW VALUE:'%s': UPDATING DB...", __func__, SESSION_ID(sesn_ptr), device_id,  attr_name, new_value);
#endif
				_DbUpdateAccountInJson (sesn_ptr, UfsrvUidGetSequenceId(uid_ptr), jobj_account);

				json_object_put(jobj_account);

				_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
			}
		}

		syslog(LOG_DEBUG, "%s (cid='%lu'): COULD NOT UPDATE DEVICE ID:'%d' ATTR '%s' WITH NEW VALUE:'%s'", __func__, SESSION_ID(sesn_ptr), device_id,  attr_name, new_value);
	}

	json_object_put(jobj_account);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

/**
 * 	@brief: updates the json data portion for the TOP LEVEL ACCOUNT ATTRIBUTES (ie not inside device level) whose values are text
 * 	This is not efficient, as it fetches the entire json payload. We should beable to use the native mysql json command:
 * 	UPDATE accounts SET data= JSON_SET(data, '$.access_token', '*') where id=351;
 *	@param device_id_in: -1 use authenticated device id. Other values are not supported at this stage.
 * 	@dynamic_memory: INTERNALLY ALLOCATES struct json_object * and FREES it
 */
__unused static UFSRVResult *
_DbAccountAttributeSetTextTopLevel (Session *sesn_ptr, const UfsrvUid *uid_ptr, const char *attr_name, const char *new_value)
{
  json_object *jobj_account = DbGetAccountInJson(sesn_ptr, uid_ptr);
	if (IS_EMPTY(jobj_account)) {
		syslog(LOG_DEBUG, "%s {o:'%p', cid:'%lu'}: ERROR: COULD NOT GENERATE JSON OBJECT FOR ACCOUNT:'%lu'", __func__, sesn_ptr, SESSION_ID(sesn_ptr), UfsrvUidGetSequenceId(uid_ptr));

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
	}

	json_object_object_del(jobj_account, attr_name);
	json_object_object_add(jobj_account, attr_name, json_object_new_string(new_value));

	_DbUpdateAccountInJson(sesn_ptr, UfsrvUidGetSequenceId(uid_ptr), jobj_account);

	json_object_put(jobj_account);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

/**
 * 	@brief: updates the json data portion FOR THE AUTHENTICATED DEVICE but only for attributes whose values are text
 * 	This is not efficient, as it fetches the entire json payload. We should beable to use the native mysql json command:
 * 	UPDATE accounts SET data= JSON_SET(data, '$.access_token', '*') where id=351;
 *	@param device_id_in: -1 use authenticated device id. Other values are not supported at this stage.
 * 	@dynamic_memory: INTERNALLY ALLOCATES struct json_object * and FREES it
 */
static UFSRVResult *
_DbAccountAttributeSetJsonObject (Session *sesn_ptr, const UfsrvUid *uid_ptr, int device_id_in, const char *attr_name, struct json_object *jobj)
{
  json_object *jobj_account = DbGetAccountInJson(sesn_ptr, uid_ptr);
	if (!jobj_account) {
		syslog(LOG_DEBUG, "%s (o:'%p', cid:'%lu'): ERROR: COULD NOT GENERATE JSON OBJECT FOR ACCOUNT:'%lu'", __func__, sesn_ptr, SESSION_ID(sesn_ptr), UfsrvUidGetSequenceId(uid_ptr));

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
	}

	struct json_object *jobj_authenticated_device=json__get(jobj_account, "authenticated_device");
	json_object_object_del(jobj_authenticated_device, attr_name);
	json_object_object_add (jobj_authenticated_device, attr_name, jobj);

	//assign the target device id
	int device_id=1;
	if (device_id_in==-1)	device_id=json_object_get_int(json__get(jobj_authenticated_device, "id"));
	else	device_id=device_id_in;

	{
		//fetch device id and update there as well
		struct json_object *jobj_devices_array=json__get(jobj_account, "devices");
		int array_size=json_object_array_length(jobj_devices_array);
		int i;

		syslog(LOG_DEBUG, "%s (pid:'%lu' cid='%lu'): DEVICES ARRAY CONTAIN:'%d' DEVICES IN IT. TARGTING ID: '%d'", __func__, pthread_self(), SESSION_ID(sesn_ptr), array_size, device_id);

		for (i=0; i<array_size; i++) {
			struct json_object *jobj_device=json_object_array_get_idx(jobj_devices_array, i);
			if (device_id==json_object_get_int(json__get(jobj_device, "id"))) {
				json_object_object_del(jobj_device, attr_name);
				json_object_object_add (jobj_device, attr_name, jobj);
				json_object_get	(jobj);//increase refcount on the imported object, because it's managed outside this invocation

#ifdef __UF_FULLDEBUG
				const char *jobj_str=json_object_to_json_string(jobj);

				syslog(LOG_DEBUG, "%s (cid='%lu'): UPDATED DEVICE ID:'%d' ATTR %s WITHNEW VALUE:'%s': UPDATING DB...", __func__, SESSION_ID(sesn_ptr), device_id,  attr_name, jobj_str);
#endif
				_DbUpdateAccountInJson(sesn_ptr, UfsrvUidGetSequenceId(uid_ptr), jobj_account);

				if ((json_object_put(jobj_account)) != 1) {
					syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): ERROR: MEMORY LEAK JSON WAS NOT FREED", __func__, pthread_self(), SESSION_ID(sesn_ptr));
				}

				_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
			}
		}

		syslog(LOG_DEBUG, "%s (cid='%lu'): COULD NOT UPDATE DEVICE ID:'%d' ATTR '%s' WITH NEW VALUE", __func__, SESSION_ID(sesn_ptr), device_id,  attr_name);
	}

	json_object_put(jobj_account);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

/// START \\\ PENDING ACCOUNT ROUTINES //////

static UFSRVResult *
_DbCreateNewPendingAccount (Session *sesn_ptr, const char *cookie, UserCredentials *creds_ptr, VerificationCode *vcode_ptr)
{
//if number already has a code, overwrite it... 'returning' seems to be a reserved word in mariadb hence the back ticks
#define SQL_UPSERT_PENDING_ACCOUNT "INSERT INTO pending_accounts (number, password, cookie, `returning`, verification_code) VALUES ('%s', '%s', '%s', '%d', '%lu') ON DUPLICATE KEY UPDATE verification_code = '%lu', cookie = '%s'"

	char *sql_query_str;
	sql_query_str=mdsprintf(SQL_UPSERT_PENDING_ACCOUNT, creds_ptr->username, creds_ptr->password, cookie, creds_ptr->rego_status, vcode_ptr->code, vcode_ptr->code, cookie);

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s (cid='%lu'): GENERATED SQL QUERY: '%s'", __func__, SESSION_ID(sesn_ptr), sql_query_str);
#endif

	int sql_result=h_query_insert(sesn_ptr->db_backend, sql_query_str);

	if (sql_result!=H_OK) {
		syslog(LOG_DEBUG, "%s (cid='%lu'): ERROR: COULD NOT EXECUTE QUERY: '%s'", __func__, SESSION_ID(sesn_ptr), sql_query_str);
		free (sql_query_str);
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
	}

	free (sql_query_str);

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)

#undef SQL_UPSERT_PENDING_ACCOUNT
}

/**
 * 	@brief: main entry point for creating user accounts.
 *
 * 	@returns: PendingAccount, confirming session creation and transaction completion, along with verification code.
 *	Both, cookie and code are valid for 24hours.
 *	When verified, the user is issued with a  new cookie, but is handled somewhere else.
 *	@dynamic_memory: RECEIVES ALLOCATED 'char *cookie', which is free'd here
 * 	@dynamic_memory: ALLOCATES 'PendingAccount *' which the user is responsible for freeing
 */
PendingAccount *
DbCreateNewAccount (Session *sesn_ptr,  const char *username, const char *e164number, const char *password, const char *nonce)
{
	VerificationCode 	verification_code = {0};
	UserCredentials 	creds;
	PendingAccount 		*pacct_ptr = NULL;

	if (!IsNonceValid(sesn_ptr, nonce, _OPEN_NONCE_PREFIX)) {
		syslog(LOG_DEBUG, "%s (pid:%lu o:'%p'): NOTICE: NONCE NOT VALID: '%s'. Prefix:'%s'...", __func__, pthread_self(), sesn_ptr, nonce, _OPEN_NONCE_PREFIX);

		return NULL;
	}

	//At this stage we don't allow  that. We only let rego through if: 1)account inactive 2)does not exist
	enum AccountRegoStatus rego_status;
	if ((rego_status = GetAccountRegisterationStatus(sesn_ptr, username)) != REGOSTATUS_UNKNOWN) {
#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:%lu o:'%p'): NOTICE: USER:'%s' ALREADY REGISTERED...", __func__, pthread_self(), sesn_ptr, username);
#endif

		//commented out to allow overwrting a live account in case of end-user device issues preventing them from unregistering first
		//return NULL;
	}

	GenerateVerificationCode(&verification_code);

	char *cookie = GenerateCookie ();
	if (!IS_PRESENT(cookie)) goto exit_error;

	_USERCREDENTIALS_INIT(creds);
	creds.password		=	(unsigned char *)password;
	creds.username		=	(unsigned char *)username;
	creds.rego_status	=	REGOSTATUS_PENDING;

	_DbCreateNewPendingAccount(sesn_ptr, cookie, &creds, &verification_code);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
		redisReply *redis_ptr;
		PersistanceBackend *pers_ptr=sesn_ptr->persistance_backend;

		pacct_ptr = calloc(1, sizeof(PendingAccount));
		pacct_ptr->cookie		=	strdup(cookie); free (cookie); cookie = NULL;
		pacct_ptr->password	=	strdup(password);
		pacct_ptr->username = strdup(username);
		if (IS_STR_LOADED(e164number))	pacct_ptr->e164number	=	strdup(e164number);
		memcpy(&(pacct_ptr->verification_code), &(verification_code), sizeof(VerificationCode));

		if (!(redis_ptr = (*pers_ptr->send_command)(sesn_ptr, "SET PENDINGACCT_COOKIE:%s %d EX %lu"/*EDIS_CMD_PENDINGACCTCOOKIE_SET*/, pacct_ptr->cookie, verification_code.code, 43200L)))/*half day*/ {
			syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p'): ERROR COULD ISSUE SET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr);

			goto exit_error;
		}

		if (strcasecmp(redis_ptr->str, "OK") == 0) {
			freeReplyObject(redis_ptr);

			syslog(LOG_DEBUG, "%s {pid:'%lu' o:'%p'}: SUCCESS: PENDING ACCOUNT COOKIE SET:'%s' WITH EXPIRY:'%lu' SECONDS", __func__, pthread_self(), sesn_ptr, pacct_ptr->cookie, 43200L);
		} else {
			syslog(LOG_DEBUG, "%s {pid:'%lu' o:'%p'}: ERROR: PENDING ACCOUNT COOKIE SET FAILED: '%s' REPLY CODE:'%d'", __func__, pthread_self(), sesn_ptr, redis_ptr->str, redis_ptr->type);

			freeReplyObject(redis_ptr);

			goto exit_error;
		}

		exit_success:
		return pacct_ptr;
	} else {
		exit_error:
		if (IS_PRESENT(pacct_ptr))	PendingAccountMemDestruct (pacct_ptr, 1);//self-destruct flag
		if (IS_PRESENT(cookie))	free(cookie);
	}

	return NULL;

}

/**
 * @brief: alter the registration status stored in pending account.
 * @param sesn_ptr for context only, as 'number' paramater is seperately provided
 * @param number
 * @param rego_status
 * @return
 */
int
DbSetPendingAccountRegoStatus (Session *sesn_ptr, const PendingAccount *pacct_ptr)//const char *number, enum AccountRegoStatus rego_status)
{
#define SQL_INSERT_KEY "UPDATE ufsrv.pending_accounts SET `returning` = %d where cookie='%s'"
	char *sql_query_str;
	sql_query_str = mdsprintf(SQL_INSERT_KEY, PENDINGACCOUNT_PTR_REGO_STATUS(pacct_ptr), PENDINGACCOUNT_PTR_COOKIE(pacct_ptr));

#ifdef __UF_FULDEBUG
	syslog(LOG_DEBUG, "%s (cid='%lu'): GENERATED SQL QUERY: '%s'", __func__, SESSION_ID(sesn_ptr), sql_query_str);
#endif

	int sql_result=h_query_update(sesn_ptr->db_backend, sql_query_str);

	if (sql_result!=H_OK) {
		syslog(LOG_DEBUG, "%s {o:'%p', cid:'%lu'}: ERROR: COULD EXECUTE QUERY: '%s'", __func__, sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str);
	}

	free (sql_query_str);

	return sql_result;

#undef SQL_INSERT_KEY
}

UFSRVResult *
DbDeleteUserAccount (Session *sesn_ptr, unsigned long userid)
{
#define SQL_DELETE_USER_ACCOUNT "DELETE FROM accounts WHERE id='%lu'"

	char *sql_query_str;
	sql_query_str=mdsprintf(SQL_DELETE_USER_ACCOUNT, userid);

	syslog(LOG_DEBUG, "%s (o:'%p', cid:'%lu', userid:'%lu'): GENERATED SQL QUERY: '%s'", __func__, sesn_ptr, SESSION_ID(sesn_ptr), userid, sql_query_str);

	int sql_result=h_query_delete(sesn_ptr->db_backend, sql_query_str);
	free (sql_query_str);

	if (sql_result!=H_OK) {
		syslog(LOG_DEBUG, LOGSTR_BACKENDDB_CONNECTION_ERROR, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str, LOGCODE_BACKENDDB_CONNECTION_ERROR);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

#undef SQL_DELETE_USER_ACCOUNT
}

/**
 * 	@returns: 0 on success
 */
int
DbDeletePendingAccount (Session *sesn_ptr, const char *cookie)
{
//if number alreaduy has a code, overwrite it...
#define SQL_DELETE_PENDING_ACCOUNT "DELETE FROM pending_accounts WHERE cookie='%s'"

	char *sql_query_str;
	sql_query_str=mdsprintf(SQL_DELETE_PENDING_ACCOUNT, cookie);

	syslog(LOG_DEBUG, "%s (cid='%lu'): GENERATED SQL QUERY: '%s'", __func__, SESSION_ID(sesn_ptr), sql_query_str);

	int sql_result=h_query_delete(sesn_ptr->db_backend, sql_query_str);
	free (sql_query_str);

	if (sql_result!=H_OK)
	{
		syslog(LOG_DEBUG, "%s (cid='%lu'): ERROR: COULD EXEUTE QUERY: '%s'", __func__, SESSION_ID(sesn_ptr), sql_query_str);
		return H_ERROR;
	}

	return sql_result;

#undef SQL_DELETE_PENDING_ACCOUNT
}

/**
 * return verification code stored for user based on provided pending cookie.
 *
 * @return: 0
 */
UFSRVResult *
DbGetPendingAccountVerificationCode (Session *sesn_ptr, PendingAccount *pending_acct_ptr)
{
#define SQL_GET_VERIFICATION_CODE "SELECT verification_code, `returning` FROM pending_accounts WHERE cookie='%s'"
	struct _h_result result;
	char *sql_query_str;

	sql_query_str=mdsprintf(SQL_GET_VERIFICATION_CODE, pending_acct_ptr->cookie);

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s {o:'%p'}: GENERATED SQL QUERY: '%s'", __func__, sesn_ptr, sql_query_str);
#endif

	int sql_result=h_query_select(sesn_ptr->db_backend, sql_query_str, &result);

	if (sql_result!=H_OK) {
		syslog(LOG_DEBUG, "%s {o:'%p', cid:'%lu'}: ERROR: COULD EXECUTE QUERY: '%s'", __func__, sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str);

		free (sql_query_str);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
	}

	free (sql_query_str);

	if (result.nb_rows>0) {
		pending_acct_ptr->verification_code.code	=	atoi(((struct _h_type_text *)result.data[0][0].t_data)->value);
		pending_acct_ptr->rego_status				=	((struct _h_type_int *)result.data[0][1].t_data)->value;

#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: FOUND VERIFICATION CODE: '%lu', RETURNING: '%d'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), pending_acct_ptr->verification_code.code, pending_acct_ptr->rego_status);
#endif

		h_clean_result(&result);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
	} else {
		syslog(LOG_DEBUG, "%s {o:'%p', cid:'%lu'}: ERROR: COULD NOT LOCATE USER RECORD", __func__, sesn_ptr, SESSION_ID(sesn_ptr));
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EMPTYSET)
	}

	h_clean_result(&result);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)

#undef SQL_GET_VERIFICATION_CODE
}

/**
 *
 * @param sesn_ptr
 * @param pending_acct_ptr user provided, includes username (seeded by user) and returns with db payload
 * @return
 * @dynamic_memory: ALLOCATES 'char *' in PendingAccount
 */
UFSRVResult *
DbGetPendingAccount (Session *sesn_ptr, PendingAccount *pending_acct_ptr)
{
  int verification_code=-1;

#define SQL_GET_PENDING_ACCOUNT "SELECT verification_code,`returning`, when, cookie, password FROM pending_accounts WHERE number='%s'"
  struct _h_result result;
  char *sql_query_str;

  sql_query_str=mdsprintf(SQL_GET_PENDING_ACCOUNT, pending_acct_ptr->username);//;SESSION_USERNAME(sesn_ptr));

  int sql_result=h_query_select(sesn_ptr->db_backend, sql_query_str, &result);

  if (sql_result!=H_OK) {
    syslog(LOG_DEBUG, "%s (cid='%lu'): ERROR: COULD EXEUTE QUERY: '%s'", __func__, SESSION_ID(sesn_ptr), sql_query_str);

    free (sql_query_str);

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
  }

  free (sql_query_str);

  if (result.nb_rows>0) {
    pending_acct_ptr->verification_code.code	=	atoi(((struct _h_type_text *)result.data[0][0].t_data)->value);
    pending_acct_ptr->rego_status				=	((struct _h_type_int *)result.data[0][1].t_data)->value;
    pending_acct_ptr->cookie            = strdup((char *)(((struct _h_type_blob *)result.data[0][2].t_data)->value));
    pending_acct_ptr->when              = ((struct _h_type_int *)result.data[0][3].t_data)->value;

    h_clean_result(&result);

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
  } else {
    syslog(LOG_DEBUG, "%s (cid='%lu'): ERROR: COULD NOT LOCATE USER RECORD", __func__, SESSION_ID(sesn_ptr));
  }

  h_clean_result(&result);

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EMPTYSET)

#undef SQL_GET_PENDING_ACCOUNT
}

/**
 * 	@brief:	free dynamic memory associated with object.
 * 	@param self_destruct_flag: free the container object as well
 */
void
PendingAccountMemDestruct (PendingAccount *pacct_ptr, bool self_destruct_flag)
{
  if (pacct_ptr->cookie)	free(pacct_ptr->cookie);
  if (pacct_ptr->username)	free(pacct_ptr->username);
  if (pacct_ptr->password)	free(pacct_ptr->password);
  if (pacct_ptr->e164number)	free(pacct_ptr->e164number);

  memset(pacct_ptr, 0, sizeof(PendingAccount));

  if (self_destruct_flag)	free (pacct_ptr);

}

void
AuthenticatedAccountMemDestruct (AuthenticatedAccount *pacct_ptr, bool self_destruct_flag)
{
	PendingAccountMemDestruct ((PendingAccount *)pacct_ptr, self_destruct_flag);
}

static json_object *_GenerateDefaultUserDataJsonDescriptor(void);

static json_object *
_GenerateDefaultUserDataJsonDescriptor(void)
{
  struct json_object *jobj_userdata = json_object_new_object();

  json_object_object_add(jobj_userdata, ACCOUNT_JSONATTR_PREFS_BOOL, json_object_new_int64(CONFIG_DEFAULT_BOOLPREFS_VALUE));
  json_object_object_add(jobj_userdata, ACCOUNT_JSONATTR_NICKNAME, json_object_new_string(CONFIG_DEFAULT_PREFS_STRING_VALUE));
  json_object_object_add(jobj_userdata, ACCOUNT_JSONATTR_AVATAR, json_object_new_string(CONFIG_DEFAULT_PREFS_STRING_VALUE));
  json_object_object_add(jobj_userdata, ACCOUNT_JSONATTR_E164NUMBER, json_object_new_string(CONFIG_DEFAULT_PREFS_STRING_VALUE));
  json_object_object_add(jobj_userdata, ACCOUNT_JSONATTR_REGO_PIN, json_object_new_int(CONFIG_DEFAULT_PREFS_INT_VALUE));
  json_object_object_add(jobj_userdata, ACCOUNT_JSONATTR_GEOLOC_TRIGGER, json_object_new_int(CONFIG_DEFAULT_PREFS_INT_VALUE));
  json_object_object_add(jobj_userdata, ACCOUNT_JSONATTR_BASELOC_ZONE, json_object_new_int(CONFIG_DEFAULT_PREFS_INT_VALUE));
  json_object_object_add(jobj_userdata, ACCOUNT_JSONATTR_UNSOLICITED_CONTACT, json_object_new_int(CONFIG_DEFAULT_PREFS_INT_VALUE));

  return jobj_userdata;

}

static struct json_object *
_GenerateUserDataJsonDescriptor(Session *sesn_ptr, const UfsrvUid *uid_ptr, bool flag_check_backend)
{
	if (!flag_check_backend || IS_EMPTY(uid_ptr)) {
    return _GenerateDefaultUserDataJsonDescriptor();
  } else {
      DbBackendGetUserPrefs(sesn_ptr, UfsrvUidGetSequenceId(uid_ptr));
      if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr) && SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA)) {
        struct json_object *jobj_userdata = (json_object *)SESSION_RESULT_USERDATA(sesn_ptr);

        return jobj_userdata;
      } else {
        return _GenerateDefaultUserDataJsonDescriptor();
      }
	}
	//Add more prefs

	return NULL;
}

/**
 * 	@brief: at this stage, password is saved in pending-account as clear text, so we must hash it with salt before storing it securely.
 * 	We also have hint if the account is re-registration by looking at 'returning' field of PendingAccount.
 * 	IMPORTANT: the cookie contained in PendingAccount is the pending cookie, not the authentication cookie. In order to generate one,
 * 	user must sign on.
 *	@param pacct_pt: Pre-filled with data stored in the db backend in the pending_account table, which is basic.
 *
 * 	@dynamic_memory: ALLOCATE 'json_object *' WHICH IS free'd in DbCreateAccount()
 * 	@dynamic_memory aauthacct_ptr *: EXPORTS. User responsible for deallocating
 */
UFSRVResult *
UpgradePendingAccountByJson(Session *sesn_ptr, PendingAccount *pacct_ptr, struct json_object *jobj_by_user, bool flag_nuke_old)
{
	UserCredentials creds = {0};
	creds.password = (unsigned char *)PENDINGACCOUNT_PTR_PASSWORD(pacct_ptr);

	if (!(GeneratePasswordHash(&creds) == 0)) {
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}

	unsigned int rego_id                = json_object_get_int(json__get(jobj_by_user, "registrationId"));
  enum AccountRegoStatus rego_status  = REGOSTATUS_UNKNOWN;
  char *profile_key_encoded           = CONFIG_DEFAULT_PREFS_STRING_VALUE,
       *access_token_encoded          = CONFIG_DEFAULT_PREFS_STRING_VALUE,
       *e164number                    = NULL;
  long long time_now,
            when_created              = 0;
  UfsrvUid uid                        = {0},
          *uid_ptr;
  __unused Uuid    uuid                        = {0},
          *uuid_ptr                   = NULL;
  DbOpDescriptor dbop_descriptor_uuid = {.ctx_data=&uuid};

  DbAccountGetUfrsvUid(sesn_ptr, SESSION_USERNAME(sesn_ptr), &uid);
  uid_ptr = SESSION_RESULT_USERDATA(sesn_ptr); //can be NULL

  if (IS_PRESENT(uid_ptr)) {
    //restore reusable values if already known. We keep this across re-registrations
    //todo: should issue one call and retrieve all transferable account attributes
    rego_status = GetAccountRegisterationStatus(sesn_ptr, PENDINGACCOUNT_PTR_USERNAME(pacct_ptr));

    ProfileKeyStore key_store = {0};
    DbBackendGetProfileKey(sesn_ptr, uid_ptr, KEY_B64_SERIALISED, &key_store);
    if (IS_STR_LOADED(key_store.serialised)) profile_key_encoded = key_store.serialised;

    access_token_encoded = (char *) DbBackendGetAccessToken(sesn_ptr, uid_ptr, false);
    if (IS_EMPTY(access_token_encoded)) access_token_encoded = CONFIG_DEFAULT_PREFS_STRING_VALUE;

    time_now = GetTimeNowInMillis();
    when_created = DbGetWhenCreated(sesn_ptr, uid_ptr, DEFAULT_DEVICE_ID);

    GetUuid(SESSION_USERNAME(sesn_ptr), &uuid, &dbop_descriptor_uuid);
    uuid_ptr = &uuid; //reasonably confident not NULL
    DBOP_DESCRIPTOR_INVOKE_RESULT_FINALISER(&dbop_descriptor_uuid);//not doing anything with it at the moment
  }

  //this is especially treated because e164number can come through during initial registration.
  if (IS_STR_LOADED(PENDINGACCOUNT_PTR_E164_NUMEBR(pacct_ptr)) &&
      !(strcmp(PENDINGACCOUNT_PTR_E164_NUMEBR(pacct_ptr), CONFIG_UNSPECIFIED_E164_NUMBER) == 0))
    e164number = PENDINGACCOUNT_PTR_E164_NUMEBR(pacct_ptr); //provided by user via API endpoint contact. Dont free
  else if (IS_PRESENT(uid_ptr)) {
    DbAccountGetE164Number(sesn_ptr, UfsrvUidGetSequenceId(uid_ptr));
    if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
      e164number = strdupa((char *) SESSION_RESULT_USERDATA(sesn_ptr));
      free (SESSION_RESULT_USERDATA(sesn_ptr));
    }
  }

	//first registration device is considered master and marked with id for the user
	struct json_object *jobj_device = json_object_new_object();
	json_object_object_add (jobj_device, ACCOUNT_JSONATTR_ID, json_object_new_int(1));
  json_object_object_add (jobj_device, ACCOUNT_JSONATTR_PROFILE_KEY, json_object_new_string(profile_key_encoded)); //temprary -> to be removed at account creation
  json_object_object_add (jobj_device, ACCOUNT_JSONATTR_PROFILE_COMMITMENT, json_object_new_string(CONFIG_DEFAULT_PREFS_STRING_VALUE));
  json_object_object_add (jobj_device, ACCOUNT_JSONATTR_PROFILE_VERSION, json_object_new_string(CONFIG_DEFAULT_PREFS_STRING_VALUE));
  json_object_object_add (jobj_device, ACCOUNT_JSONATTR_ACCESS_TOKEN, json_object_new_string(access_token_encoded)); //temporary -> to be removed at account creation
	json_object_object_add (jobj_device, ACCOUNT_JSONATTR_REGO_ID, json_object_new_int(rego_id));
	json_object_object_add (jobj_device, ACCOUNT_JSONATTR_AUTH_TOKEN, json_object_new_string((char *)creds.hashed_password));
	json_object_object_add (jobj_device, ACCOUNT_JSONATTR_SALT, json_object_new_string((char *)creds.salt));
	json_object_object_add (jobj_device, ACCOUNT_JSONATTR_COOKIE, json_object_new_string(CONFIG_DEFAULT_PREFS_STRING_VALUE));
	json_object_object_add (jobj_device, ACCOUNT_JSONATTR_SIGNED_PREKY, json_object_new_string(CONFIG_DEFAULT_PREFS_STRING_VALUE));
	json_object_object_add (jobj_device, ACCOUNT_JSONATTR_GCM_ID, json_object_new_string(CONFIG_DEFAULT_PREFS_STRING_VALUE));
	json_object_object_add (jobj_device, ACCOUNT_FETCHES_MSG, json_object_new_boolean(0));//only turned on once gcm is received
	json_object_object_add (jobj_device, ACCOUNT_JSONATTR_NUMBER, json_object_new_string(PENDINGACCOUNT_PTR_USERNAME(pacct_ptr)));//todo: this (username as email) should be removed from here and kept at toplevel
//	json_object_object_add (jobj_device, ACCOUNT_JSONATTR_E164NUMBER, json_object_new_string(IS_PRESENT(e164number)?e164number:CONFIG_DEFAULT_PREFS_STRING_VALUE)); //allow e164 per device
	if (when_created > 0) json_object_object_add (jobj_device, ACCOUNT_JSONATTR_CREATED, json_object_new_int64(when_created));
	else json_object_object_add (jobj_device, ACCOUNT_JSONATTR_CREATED, json_object_new_int64(time_now));
	json_object_object_add (jobj_device, ACCOUNT_JSONATTR_LASTSEEN, json_object_new_int64(time_now));
	json_object_object_add (jobj_device, ACCOUNT_JSONATTR_USER_AGENT, json_object_new_string(CONFIG_DEFAULT_PREFS_STRING_VALUE));

	free(creds.hashed_password);
  if (strlen(access_token_encoded) > 1) free (access_token_encoded); //only gets allocated if != "*"

  json_object *jobj_userdata = _GenerateUserDataJsonDescriptor(sesn_ptr, uid_ptr, true);

	//if any previous data is to be remembered that must be handled before this call
	if (flag_nuke_old && IS_PRESENT(uid_ptr)) {
    char ufsrvuid_encoded[CONFIG_MAX_UFSRV_ID_ENCODED_SZ+1] = {0};
    UfsrvUidConvertSerialise(&SESSION_UFSRVUIDSTORE(sesn_ptr), ufsrvuid_encoded);

		DbAccountDeleteKeys(sesn_ptr, ufsrvuid_encoded, DEFAULT_DEVICE_ID);
		DbDeleteUserAccount(sesn_ptr, UfsrvUidGetSequenceId(uid_ptr));
	}

  json_object_get(jobj_device);

	//otherwise we retain the old UID if exists against the same number
	if (_DbCreateAccount(sesn_ptr, jobj_device, jobj_userdata, rego_status) == 0) {
		if ((json_object_put(jobj_device)) != 1) {
			syslog(LOG_DEBUG, "%s {pid:'%lu' o:'%p', cid:'%lu'}: ERROR: MEMORY LEAK JSON WAS NOT FREED", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
		}

		if ((json_object_put(jobj_userdata)) != 1) {
			syslog(LOG_DEBUG, "%s {pid:'%lu' o:'%p', cid:'%lu'}: ERROR: MEMORY LEAK JSON USERDATA WAS NOT FREED", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
		}

		//update in Global Users Registry
    DbBackendUfsrvUidDescriptor uid_descriptor = {0};
    DbAccountGetUserId(sesn_ptr, SESSION_USERNAME(sesn_ptr), &uid_descriptor);
    if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA)) {
#ifdef __UF_TESTING
			syslog (LOG_INFO, "%s {pid:'%lu', o:'%p', is_ufsrvuid_set:'%s', userid:'%lu', username:'%s'} SUCCESS: User account upgraded from pending status", __func__, pthread_self(), sesn_ptr, uid_descriptor.is_ufsrvuid_set? "true" : "false", uid_descriptor.sequence_id, SESSION_USERNAME(sesn_ptr));
#endif

			if (!uid_descriptor.is_ufsrvuid_set) {//brand new account
        UfsrvUidGeneratorDescriptor uid_gen_descriptor = {
                .uid        = uid_descriptor.sequence_id,
                .instance_id= UfsrvGetServerId(),
                .timestamp  = time_now
        };
        UfsrvUidGenerate(&uid_gen_descriptor, &(uid_gen_descriptor.ufsrvuid));
        _DbAccountUpdateUfrsvUid(sesn_ptr, (const UfsrvUid *) &(uid_gen_descriptor.ufsrvuid)); //todo: userid error recovery missing

        memcpy(&uid, &(uid_gen_descriptor.ufsrvuid), sizeof(UfsrvUid)); //retain a copy to use with sign on
        uid_ptr = &uid;
      }

      char e164number_updated[CONFIG_E164_NUMBER_SZ_MAX + 1] = {0};
			_BackendUpdateE164NumberIfNecessary(sesn_ptr, e164number, uid_descriptor.sequence_id, e164number_updated, false); //set to 'true' to always for generation of e164number
			BackendDirectoryContactTokenSet(sesn_ptr, e164number_updated, uid_descriptor.sequence_id);
		} else {
    	SESSION_RESULT_TYPE(sesn_ptr) = RESULT_TYPE_ERR; //this is necessary as DbAccountGetUserId() returns success if empty set and we're only checking for RESCODE_BACKEND_DATA above
			syslog (LOG_INFO, "%s {pid:'%lu', o:'%p', username:'%s'} ERROR: COULD NOT retrieve userid for newly upgraded pending account: PROFILES_DIRECTORY entry not set for this user", __func__, pthread_self(), sesn_ptr, SESSION_USERNAME(sesn_ptr));
			//TODO: flag that somewhere so we could attempt assignment again
		}

		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {//from BackendDirectoryContactTokenSet
			free (SESSION_RESULT_USERDATA(sesn_ptr));//returned user token

			SESSION_DEVICEID(sesn_ptr) = 1;

			DbAuthenticateUser(sesn_ptr, UfsrvUidGetSequenceId(uid_ptr), SESSION_USERPASSWORD(sesn_ptr), NULL, CALL_FLAG_USER_SIGNON);//1: signon user and generate cookie

			if ((SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) && (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESULT_CODE_USER_SIGNON))) {
				AuthenticatedAccount *authacct_ptr = ((AuthenticatedAccount *)SESSION_RESULT_USERDATA(sesn_ptr));
				if (pacct_ptr->rego_status != 0)	IntraBroadcastSessionStatusRebooted(sesn_ptr, authacct_ptr, SESSION_MESSAGE__STATUS__REBOOTED, 0);

				_RETURN_RESULT_SESN(sesn_ptr, authacct_ptr, RESULT_TYPE_SUCCESS, RESULT_CODE_USER_SIGNON)
			}
		}
	} else {
		if ((json_object_put(jobj_userdata)) != 1) {
			syslog(LOG_DEBUG, "%s (pid:'%lu' cid='%lu'): ERROR: MEMORY LEAK JSON USERDATA WAS NOT FREED", __func__, pthread_self(), SESSION_ID(sesn_ptr));
		}
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

/**
 * @brief Single entry point for updating e164number. User must check for format validity.
 * @param sesn_ptr session for which update is performed
 * @param e164number_provided
 * @param id_sequence_number sourced from accounts table
 * @param e164number_updated_out user allocated buffer to store actual value used. Must be of size CONFIG_E164_NUMBER_SZ_MAX + 1 and zero'ed by user
 */
static void
_BackendUpdateE164NumberIfNecessary (Session *sesn_ptr, const char *e164number_provided, unsigned long id_sequence_number, char *e164number_updated_out, bool is_force_assigned)
{
	if (is_force_assigned) {
    _GenerateUfsrvE164Number(id_sequence_number, e164number_updated_out);
    DbAccountSetE164Number(sesn_ptr, id_sequence_number, e164number_updated_out);

    return;
	}

  if (IS_STR_LOADED(e164number_provided)) {
		DbAccountGetE164Number(sesn_ptr, id_sequence_number);
		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
			char *e164number_stored = SESSION_RESULT_USERDATA(sesn_ptr);
			if ((strcmp(e164number_provided, e164number_stored) == 0)) {
				strncpy(e164number_updated_out, e164number_stored, CONFIG_E164_NUMBER_SZ_MAX);
        free(e164number_stored);
				return;
			}

			DbAccountSetE164Number(sesn_ptr, id_sequence_number, e164number_provided);
			strncpy(e164number_updated_out, e164number_provided, CONFIG_E164_NUMBER_SZ_MAX);
			free(e164number_stored);
		} else {
			//nothing was stored. Since this is externally provided, we have to validate
			if (DbAccountSetE164Number(sesn_ptr, id_sequence_number, e164number_provided)==0) {
        strncpy(e164number_updated_out, e164number_provided, CONFIG_E164_NUMBER_SZ_MAX);
      } else {
			  //force generate
        _GenerateUfsrvE164Number(id_sequence_number, e164number_updated_out);
        DbAccountSetE164Number(sesn_ptr, id_sequence_number, e164number_updated_out);
			}
		}
	} else {
		DbAccountGetE164Number(sesn_ptr, id_sequence_number);
		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
			//return stored value
			strncpy(e164number_updated_out, SESSION_RESULT_USERDATA(sesn_ptr), CONFIG_E164_NUMBER_SZ_MAX);
			free (SESSION_RESULT_USERDATA(sesn_ptr));
		} else {
			generate_number:
			_GenerateUfsrvE164Number(id_sequence_number, e164number_updated_out);
			DbAccountSetE164Number(sesn_ptr, id_sequence_number, e164number_updated_out);

			return;
		}
  }
}

static void
_GenerateUfsrvE164Number (unsigned long id_sequence_number, char *e164number_generated_out)
{
	unsigned sequence_number_digits_count = digits_count(id_sequence_number, 10);
	if (likely(sequence_number_digits_count < CONFIG_E164_NUMBER_VALUE_DIGITS_COUNT)) {
    snprintf(e164number_generated_out, CONFIG_E164_NUMBER_SZ_MAX, "%s%lu%0*d", CONFIG_E164_NUMBER_UFSRV_COUNTRY_PREFIX, id_sequence_number, (CONFIG_E164_NUMBER_VALUE_DIGITS_COUNT - sequence_number_digits_count), 0);
  } else {
    snprintf(e164number_generated_out, CONFIG_E164_NUMBER_SZ_MAX, "%s", CONFIG_UNSPECIFIED_E164_NUMBER);
	}

}

UFSRVResult *
CachebackendDelPendingAccountCookie (Session *sesn_ptr, const char *cookie)
{
	PersistanceBackend 	*pers_ptr;
	redisReply 					*redis_ptr;

	pers_ptr=sesn_ptr->persistance_backend;

	if (!(redis_ptr = (*pers_ptr->send_command)(sesn_ptr, REDIS_CMD_PENDINGACCTCOOKIE_DEL, cookie))) {
		syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p'): ERROR COULD NOT DEL COOKIE: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
	}

	if (redis_ptr->type == REDIS_REPLY_INTEGER && redis_ptr->integer == 1) {
		syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p'): SUCCESS COOKIE:'%s' DELETED...", __func__, pthread_self(), sesn_ptr, cookie);

		freeReplyObject(redis_ptr);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
	} else {
		syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p'): ERROR COULD NOT DEL NONCE: REPLY ERROR '%s'", __func__, pthread_self(), sesn_ptr, redis_ptr->str);

		freeReplyObject(redis_ptr);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}

}

/**
 * @brief Query the backend to determine if the pending cookie is still present; meaning the associated account has not verified yet
 * @param sesn_ptr
 * @param cookie cookie key to verify
 * @return The value stored against the cookie: the verification code
 * @dynamic_memory: ALLOCCATES str value upon success (if @param is_return_code is set)
 */
UFSRVResult *
CachebackendGetPendingAccountCookie (Session *sesn_ptr, const char *cookie, bool is_return_code)
{
	redisReply *redis_ptr;

	if (!(redis_ptr = (*SESSION_PERSISTANCE_BACKEND(sesn_ptr)->send_command)(sesn_ptr, REDIS_CMD_PENDINGACCTCOOKIE_GET, cookie))) {//half day
		syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_RESOURCE_NULL);
	}

	if (redis_ptr->type==REDIS_REPLY_STRING) {
		const char *stored_value=NULL;
		if (is_return_code) stored_value=strdup(redis_ptr->str);

		freeReplyObject(redis_ptr);

		_RETURN_RESULT_SESN(sesn_ptr, stored_value, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
	} else {
		syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p'): ERROR: PENDING ACCOUNT COOKIE GET FAILED FROM CACHEBACKEND: '%s' REPLY CODE:'%d'", __func__, pthread_self(), sesn_ptr, redis_ptr->str, redis_ptr->type);

		freeReplyObject(redis_ptr);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_RESOURCE_NULL);
	}
}

/**
 * @brief: Check account's verification state. This assumes user has successfully created a pending account and have a
 * verification code sent to them. Therefore a valid pending cookie is needed. This is designed to work with new registrations only, where
 * 'username' in the form other than ufsrvuid is provided in the basic auth header.
 * @param sesn
 * @param pacct_ptr registartion cookie supplied when pending account was created
 * @return true if account is unverified and the PendingAccount
 */
enum AccountRegoStatus
GetAccountVerificationStatus(Session *sesn_ptr, PendingAccount *pacct_ptr_out)
{
	__unused bool is_cachebackend_present = false;

	//todo: this is probably redundant check
	CachebackendGetPendingAccountCookie (sesn_ptr, pacct_ptr_out->cookie, false);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) { //user could still have verified
		is_cachebackend_present = true;
	}

	//cookie may have expired, but user already verified (e.g via email link), but not yet performed full registration, so we'd still have a record of the user in Pending
	//OR user already verified
	pacct_ptr_out->username	=	SESSION_USERNAME(sesn_ptr);
	DbGetPendingAccountVerificationCode(sesn_ptr, pacct_ptr_out);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
		return pacct_ptr_out->rego_status;
	}

	//No record for user in pending, try accounts for returning users
  return GetAccountRegisterationStatus(sesn_ptr, SESSION_USERNAME(sesn_ptr));

  return_account_unverified:
  return  REGOSTATUS_PENDING;
}

/**
 * 	@brief: The verification process: 1)check if cookie is valid, 2)check if user already exists, 3)check verification code
 * 	If the above pass, 1)delete the pending account entry, 2)delete the pending cookie, 3)issue a new permanent cookie and the user is 'signed on' (not performed here)
 * 	This request is only valid after user is placed in pending state, with valid and timed cookie. Once verified, it retains the pending account and only
 * 	marks the rego status of teh user as verified. User still has to "VERIFY_NEW' to be issues with a sign on cookie, at which point Pending data is deleted
 * 	@param pacct_ptr: must be loaded with pending cookie
 *
 */
bool
PendingAccountVerify (Session *sesn_ptr, PendingAccount *pacct_ptr, int verification_code_given, bool delete_flag)
{
	bool test_account=false;

#ifdef __UF_TESTING
//TODO: SMS VERIFICATION DISABLED FOR BETA TESTING
  if (true) {
	/*if ((strcasecmp(PENDINGACCOUNT_PTR_USERNAME(pacct_ptr), "+61412345678")==0) ||
			(strcasecmp(PENDINGACCOUNT_PTR_USERNAME(pacct_ptr), "+61400000000")==0)	||
			(strcasecmp(PENDINGACCOUNT_PTR_USERNAME(pacct_ptr), TESTUSER_NAME)==0)) {*/
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', uname_test:'%s'}: DETECTED VERIFICATION FOR TEST-ACCOUNT...", __func__, pthread_self(), sesn_ptr, PENDINGACCOUNT_PTR_USERNAME(pacct_ptr));
		test_account	=	true;
	}
#endif

	//potentially, this test is enough, but we also test the db backend to ensure end-t-end data consistency and security
	//we d this test first, because it indicates if the pending account has expired or not
	CachebackendGetPendingAccountCookie(sesn_ptr, pacct_ptr->cookie, true);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
		int registration_code_returned = atoi((const char *)SESSION_RESULT_USERDATA(sesn_ptr));
		if (test_account ||	verification_code_given == registration_code_returned) {
			syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p', test_account:'%d'): SUCCESS PENDING COOKIE:'%s' WITH Stored verification code value:'%s'", __func__, pthread_self(), sesn_ptr, test_account, pacct_ptr->cookie, (const char *)SESSION_RESULT_USERDATA(sesn_ptr));
		} else {
			//note: we compare against user supplied, not stored, which is done below
			syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p'): ERROR PENDING COOKIE:'%s' AND SUPPLIED VERIFICATION CODE DOES NOT MATCH", __func__, pthread_self(), sesn_ptr, pacct_ptr->cookie);

			free(SESSION_RESULT_USERDATA(sesn_ptr));
			goto exit_error;
		}

		free(SESSION_RESULT_USERDATA(sesn_ptr));
	} else {
		exit_error:
		return false;
	}

	//TBD
	/*__redis_get_pending_cookie:
	{
		redisReply *redis_ptr;


		if (!(redis_ptr=(*SESSION_PERSISTANCE_BACKEND(sesn_ptr)->send_command)(sesn_ptr, REDIS_CMD_PENDINGACCTCOOKIE_GET, pacct_ptr->cookie))) {//half day
			syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr);
			//TODO: a corresponding entry for the same username may still exist in pending_account

			return false;
		}

		if (redis_ptr->type==REDIS_REPLY_STRING) {//we got the value of stored against the cookie 'key'
			if (test_account	||	verification_code_given==atoi(redis_ptr->str)) {
				syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p', test_account:'%d'): SUCCESS PENDING COOKIE:'%s' WITH Stored verification code value:'%s'", __func__, pthread_self(), sesn_ptr, test_account, pacct_ptr->cookie, redis_ptr->str);
			} else {
				//note: we compare agains user supplied, not stored, which is done below
				syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p'): ERROR PENDING COOKIE:'%s' AND SUPPLIED VERIFICATION CODE DOES NOT MATCH", __func__, pthread_self(), sesn_ptr, pacct_ptr->cookie);

				goto exit_error;
			}

		   freeReplyObject(redis_ptr);
		} else {
			syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p'): ERROR: PENDING ACCOUNT COOKIE GET FAILED FROM PERSISTANCE BACEND: '%s' REPLY CODE:'%d'", __func__, pthread_self(), sesn_ptr, redis_ptr->str, redis_ptr->type);

			exit_error:
			//TODO: a corresponding entry for the same username may still exist in pending_account
			freeReplyObject(redis_ptr);

			return false;
		}
	}*/

	DbGetPendingAccountVerificationCode(sesn_ptr, pacct_ptr);

	if (test_account || pacct_ptr->verification_code.code == verification_code_given) {
#ifdef _UF_TESTING
		syslog (LOG_DEBUG, "%s (cid:'%lu', returning:'%d'): VERIFICATION CODES MATCH: '%d'", __func__, SESSION_ID(sesn_ptr), pacct_ptr->rego_status, verification_code_given);
#endif

		if (delete_flag) {
			//note this is done on second pass when VERIFY_NEW is issued. BasicAuth info MUST BE PROVIDED
			DbDeletePendingAccount(sesn_ptr, PENDINGACCOUNT_PTR_COOKIE(pacct_ptr));
			CachebackendDelPendingAccountCookie(sesn_ptr, PENDINGACCOUNT_PTR_COOKIE(pacct_ptr));//note: self expiring anyway
		} else {
			//note this is done on first pass when user verifies via Account/VerifyStatus endpoint
			pacct_ptr->rego_status	=	REGOSTATUS_VERIFIED;
			DbSetPendingAccountRegoStatus(sesn_ptr, pacct_ptr);
		}

		return true;
	} else {
		syslog (LOG_DEBUG, LOGSTR_ACCOUNT_VERIFICATION_CODE_MISMATCH, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), verification_code_given, pacct_ptr->verification_code.code, LOGCODE_ACCOUNT_VERIFICATION_CODE_MISMATCH);
	}

	return false;

}

/// END \\\ PENDING ACCOUNT ROUTINES //////////
// accounts_authenticated_device_gcm_id

/// START \\\ Global Users Registery ROUTINES //////////

/**
 * 	@brief: Global directory of all user names tokens (e64 numbers) SHA1 and Base64 encoded. This is also used to produce
 * 	shared contact matches for a given user, as they supply their own encoded tokens (for other shared contacts) for lookup.
 * 	This function is invoked at thend of account verification phase.
 *
 * 	@dynamic_memort: INTERNALLy ALLOCATES AND FREES redisReply *
 * 	@dynamic_memory: returns the encoded username in the reply, which user must free
 */
UFSRVResult *
BackendDirectoryContactTokenSet (Session *sesn_ptr, const char *username, unsigned long userid)
{
	//generate SHA-1 value for user number
	char number_encoded[SHA_DIGEST_LENGTH*2+1]={0};

	memset (number_encoded, 0, sizeof(number_encoded));
	const unsigned char *number_unhashed = (const unsigned char *)username;

	ComputeSHA1 (number_unhashed, strlen((const char *)number_unhashed), number_encoded, sizeof(number_encoded), 1);
	number_encoded[USER_NUMBER_SHA_1_TOKEN_LIMIT]='\0'; //should match the size of what the client sends, currently 14bytes

	for (char *p=number_encoded; *p; p++)	{if (*p=='+')	*p='-'; else if (*p=='/')	*p='_';} //url safe

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu', userid:'%lu'): GENERATED SHA-1: '%s'", __func__, pthread_self(), SESSION_ID(sesn_ptr), userid, number_encoded);
#endif

	//update redis directory. If account is not in directory it is in pending
	redisReply *redis_ptr;
	PersistanceBackend *pers_ptr;

	pers_ptr = sesn_ptr->persistance_backend;

	redis_ptr = (*pers_ptr->send_command)(sesn_ptr, REDIS_CMD_ACCOUNTS_DIRECTORY_SET, number_encoded, number_encoded, userid);

	if (redis_ptr) {
		freeReplyObject(redis_ptr);
		_RETURN_RESULT_SESN(sesn_ptr, strdup(number_encoded), RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)

}

/* 	@brief: Serach the golbal directory using the token value of the contact
 *	@params contact_token: encoded user identifier
 * 	@returns: stored value of token, which is the userid
 *
 * 	@returns NULL: if error or no shared contacts found
 *
 * 	@dynamic_memory: char * object returned, which the user must free
 */
UFSRVResult *
BackendDirectoryContactTokenGet (Session *sesn_ptr, const char *contact_token)
{
	if (unlikely(sesn_ptr == NULL)) {
		syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Session *");
		return NULL;
	}

	syslog(LOG_DEBUG, "%s (pid:'%lu', oid:'%p', cid: '%lu', contact:'%s'): Fetching tokenised contact", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), contact_token);

	RedisBackend *pers_ptr = (RedisBackend *)sesn_ptr->persistance_backend;
	{
		redisReply *redis_ptr;
		//{"contacts":["HSasDj77+hyY5w","WGYFTryHOznWVg","26p5JSZkr9mHxA", ...]}

		if (!(redis_ptr = (*pers_ptr->send_command)(sesn_ptr, REDIS_CMD_ACCOUNTS_DIRECTORY_GET, contact_token))) {
			syslog(LOG_DEBUG, LOGSTR_BACKENDCACHE_ERROR_REPLYOBJECT, __func__, pthread_self(), sesn_ptr, REDIS_CMD_ACCOUNTS_DIRECTORY_GET, LOGCODE_BACKENDCACHE_ERROR_REPLYOBJECT);

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_BACKENDERR, RESCODE_BACKEND_CONNECTION)
		}

		if ((redis_ptr->type != REDIS_REPLY_NIL)) {
			syslog(LOG_DEBUG, LOGSTR_BACKENDCACHE_REPLY, __func__, pthread_self(), sesn_ptr, redis_ptr->str, LOGCODE_BACKENDCACHE_REPLY, "Found contact token...");

			char *return_token = strdup(redis_ptr->str);

			freeReplyObject(redis_ptr);

			_RETURN_RESULT_SESN(sesn_ptr, return_token, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
		}

		syslog(LOG_DEBUG, LOGSTR_BACKENDCACHE_UNSPECIFIED_REPLY, __func__, pthread_self(), sesn_ptr, REDIS_CMD_ACCOUNTS_DIRECTORY_GET, redis_ptr->type, LOGCODE_BACKENDCACHE_UNSPECIFIED_REPLY, "Token not found");

		freeReplyObject(redis_ptr);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)

}

UFSRVResult *
BackendDirectoryContactTokenDel (Session *sesn_ptr, const char *contact_token)
{
	if (unlikely(sesn_ptr == NULL)) {
		syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "Session *");
		return NULL;
	}

	syslog(LOG_DEBUG, "%s (pid:'%lu', oid:'%p', cid: '%lu', contact:'%s'): Deleting tokenised contact", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), contact_token);

	RedisBackend *pers_ptr = (RedisBackend *)sesn_ptr->persistance_backend;
	{
		redisReply *redis_ptr;

		if (!(redis_ptr = (*pers_ptr->send_command)(sesn_ptr, REDIS_CMD_ACCOUNTS_DIRECTORY_DEL, contact_token))) {
			syslog(LOG_DEBUG, LOGSTR_BACKENDCACHE_ERROR_REPLYOBJECT, __func__, pthread_self(), sesn_ptr, REDIS_CMD_ACCOUNTS_DIRECTORY_GET, LOGCODE_BACKENDCACHE_ERROR_REPLYOBJECT);

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_BACKENDERR, RESCODE_BACKEND_CONNECTION)
		}

		if ((redis_ptr->type == REDIS_REPLY_INTEGER)) {
			syslog(LOG_DEBUG, LOGSTR_BACKENDCACHE_REPLY, __func__, pthread_self(), sesn_ptr, redis_ptr->integer==1?"1":"*", LOGCODE_BACKENDCACHE_REPLY, "Deleted contact token...");

			freeReplyObject(redis_ptr);

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
		}

		syslog(LOG_DEBUG, LOGSTR_BACKENDCACHE_UNSPECIFIED_REPLY, __func__, pthread_self(), sesn_ptr, REDIS_CMD_ACCOUNTS_DIRECTORY_GET, redis_ptr->type, LOGCODE_BACKENDCACHE_UNSPECIFIED_REPLY, "Token could not be deleted");

		freeReplyObject(redis_ptr);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

/**
 * 	@brief: returned contacts which are shared with the user
 *
 * 	@returns jobj_shared_contacts: array of shared tokens
 *
 * 	@returns NULL: if error or no shared contacts found
 *
 * 	@dynamic_memory jobj_shared_contacts: calling environment is responsible for freeing
 */
struct json_object *
BackendDirectorySharedContactsGet (Session *sesn_ptr, struct json_object *jobj_contacts, const char *user_name)
{
	int contacts_count = json_object_array_length(jobj_contacts);

	if (contacts_count <= 0) {
		return NULL;
	}

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s (cid: '%lu'): RECEIVED contacts: '%d'", __func__, SESSION_ID(sesn_ptr), json_object_array_length(jobj_contacts));
#endif

	int 					actually_processed	=	contacts_count;
	CacheBackend 	*pers_ptr						=	sesn_ptr->persistance_backend;

	//send redis commands
	{
		const char *contact_token;
		redisReply *redis_ptr;
		//{"contacts":["HSasDj77+hyY5w","WGYFTryHOznWVg","26p5JSZkr9mHxA", ...]}

		int i;
		for (i=0; i<contacts_count; i++) {
			struct json_object *jobj_contact = json_object_array_get_idx(jobj_contacts, i);

			if ((contact_token = json_object_get_string(jobj_contact))) {
				if (!((*pers_ptr->send_command_multi)(sesn_ptr, REDIS_CMD_ACCOUNTS_DIRECTORY_GET, contact_token))) {
					actually_processed--;

					syslog(LOG_DEBUG, "%s (cid: '%lu'): ERROR PROCESSING CONTACT TOKEN: '%s'", __func__, SESSION_ID(sesn_ptr), contact_token);
				}
			} else {
				actually_processed--;
			}
		}
	}

	//IMPORTANT TODO: KEEP AN EYE ON STACK OVERFLOW WITH THIS FOR USERS WITH LARGE MATCHES as we ADDITIONALLY STRDUPA matched token
	//We need to retain a local copy of the matched token because we cannot issue nested redis commands on the same  pers_ptr->context
	//as that will corrupt its state, so we have to serialise the calls separately in a third iteration
	char *tokens_matched[actually_processed];

	//2 process replies
	{
		int 								i;
		int 								tokens_processed,
												tokens_matched_idx		=	0;
		redisReply 					**replies;
		struct json_object 	*jobj_shared_contacts	=	json_object_new_array();
		struct json_object 	*jobj_token						=	NULL;

		replies = malloc(sizeof(redisReply*)*actually_processed);

		tokens_processed = actually_processed;

		for (i=0; i<actually_processed; i++) {
			if ((RedisGetReply(sesn_ptr, pers_ptr, (void*)&replies[i]) == REDIS_OK)) {
				if ((replies[i] != NULL) && (replies[i]->type != REDIS_REPLY_NIL)) {
					if (unlikely(replies[i]->len == 0)) {
						syslog (LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu', i:'%d', redis_type:'%d'}: SEVERE DATA ERROR: RECORD PASSED AS NON-NIL BUT CONTAINS ZERO-LENGTH DATA", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i, replies[i]->type);
						freeReplyObject(replies[i]);
						tokens_processed--;
						continue;
					}

#ifdef __UF_TESTING
					syslog (LOG_DEBUG, LOGSTR_BACKENDCACHE_SHARED_CONTACTS, __func__, pthread_self(), sesn_ptr, i, replies[i]->str, LOGCODE_BACKENDCACHE_SHARED_CONTACTS_HIT, "Found shared contact token");
#endif

					//retain a local copy
					tokens_matched[tokens_matched_idx++]=strdupa(replies[i]->str);
				}
				else	tokens_processed--;

				freeReplyObject(replies[i]);
			}
			else	tokens_processed--;
		}//for

		free(replies);

		//3 actually produce payload
		for (i=0; i<tokens_matched_idx; i++) {
			char *userid = strrchr(tokens_matched[i], ':');
			if (IS_PRESENT(userid)) {
				jobj_token = json_object_new_object();

				*userid++ = '\0';
				json_object_object_add(jobj_token, "token", json_object_new_string(tokens_matched[i]));

				if (IS_PRESENT(JsonFormatUserProfile(sesn_ptr, strtoul(userid, NULL, 10), DIGESTMODE_CONTACTS_SHARING, true, jobj_token))) {
          json_object_array_add(jobj_shared_contacts, jobj_token);
        }
			}
		}

		if (json_object_array_length(jobj_shared_contacts) == 0) {
#ifdef __UF_TESTING
			syslog (LOG_DEBUG, LOGSTR_BACKENDCACHE_SHARED_CONTACTS_REPORT, __func__, pthread_self(), sesn_ptr, 0, LOGCODE_BACKENDCACHE_SHARED_CONTACTS_FOUNDNONE, "No shared contacts found");
#endif
			json_object_put(jobj_shared_contacts);

			return NULL;
		} else {
			syslog (LOG_DEBUG, LOGSTR_BACKENDCACHE_SHARED_CONTACTS_REPORT, __func__, pthread_self(), sesn_ptr, json_object_array_length(jobj_shared_contacts), LOGCODE_BACKENDCACHE_SHARED_CONTACTS_TOTALFOUND, "Total shared contacts found");

			return jobj_shared_contacts;
		}
	}

	return NULL;

}

/// END \\\ Global Users Registery ROUTINES //////////


//START support for nick names _NAMESPACE_BACKEND_NICKNAMES

/**
 * @param is_decoded if flagged, key is returned in raw binary format, otherwise returned in base64 db stored format
 * @DYNAMIC_MEMORY: EXPORTS char *
 * @return access token encoded in b64
 */
const char *
DbBackendGetAccessToken(Session *sesn_ptr, const UfsrvUid *uid_ptr, bool is_decoded)
{
  DbAccountDataAttributeGetText(sesn_ptr, UfsrvUidGetSequenceId(uid_ptr), ACCOUNT_JSONATTR_ACCESS_TOKEN);
  if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
    char *access_token_encoded = (char *) SESSION_RESULT_USERDATA(sesn_ptr);
    if (*access_token_encoded=='*')	 {
      free (SESSION_RESULT_USERDATA(sesn_ptr));
      return NULL;
    }

    if (!is_decoded) {
      return (char *) SESSION_RESULT_USERDATA(sesn_ptr);
    } else {
      int decoded_sz = 0;
      unsigned char *access_token_decoded=base64_decode((const unsigned char *) SESSION_RESULT_USERDATA(sesn_ptr), CONFIG_USER_PROFILEKEY_MAX_SIZE, &decoded_sz);
      free (SESSION_RESULT_USERDATA(sesn_ptr));

      return (const char *)access_token_decoded;
    }
  }

  return NULL;
}

/**
 *
 */
UFSRVResult *
DbBackendSetAccessToken(Session *sesn_ptr, const char *access_token_encoded)
{
  if (likely(strlen(access_token_encoded)<CONFIG_USER_ACCESS_TOKEN_MAX_SIZE_ENCODED)) {
    if ((DbAccountUpdateData(sesn_ptr, ACCOUNT_JSONATTR_ACCESS_TOKEN, access_token_encoded, SESSION_USERID(sesn_ptr))) == 0) {
      _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
    } else {
      _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)
    }
  } else {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', uname:'%s', token_sz:'%lu'): ERROR: ACCESS TOKEN TOO LONG", __func__, pthread_self(), sesn_ptr, SESSION_USERNAME(sesn_ptr), strlen(access_token_encoded));
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONSTRAINT);
  }
}

/**
 * Extra logic to check for existing value and only update if it doesn't match, including if not set, where is_force_update flag is true
 * @param sesn_ptr
 * @param access_token_encoded must be CONFIG_USER_ACCESS_TOKEN_MAX_SIZE
 * @param is_force_update if set where values don't match update stored with provided
 * @dynamic_memory: EXPORTs string. free'd locally if force_update is true
 * @return
 */
UFSRVResult *
DbBackendSetAccessTokenIfNecessary (Session *sesn_ptr, const char *access_token_encoded, bool is_force_update)
{
  if (unlikely((strlen(access_token_encoded)>CONFIG_USER_ACCESS_TOKEN_MAX_SIZE_ENCODED))) {
    goto return_token_constraint;
  }

  const char *access_token_encoded_stored = DbBackendGetAccessToken (sesn_ptr, &(SESSION_UFSRVUIDSTORE(sesn_ptr)), false);
  if (IS_PRESENT(access_token_encoded_stored)) {
    if (strcmp(access_token_encoded_stored, access_token_encoded)==0) {
      goto return_do_thing;
    } else {
      if (is_force_update) {
        free ((char *)access_token_encoded_stored);
        goto return_update_token;
      } else {
        goto return_stored_token;
      }
    }
  } else {
    goto return_update_token;
  }

  return_token_constraint:
  syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', uname:'%s', token_sz:'%lu'): ERROR: ACCESS TOKEN TOO LONG", __func__, pthread_self(), sesn_ptr, SESSION_USERNAME(sesn_ptr), strlen(access_token_encoded));
  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONSTRAINT);

  return_do_thing:
  _RETURN_RESULT_SESN(sesn_ptr, access_token_encoded_stored, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA_EXISTINGSET)

  return_stored_token:
  syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', uname:'%s', token_provided:'%s', token_stored:'%s'): WARNING: Mismatched access tokens: no force update flag: returning stored value", __func__, pthread_self(), sesn_ptr, SESSION_USERNAME(sesn_ptr), access_token_encoded, access_token_encoded_stored);
  _RETURN_RESULT_SESN(sesn_ptr, access_token_encoded_stored, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EXISTINGSET);

  return_update_token:
  DbBackendSetAccessToken(sesn_ptr, access_token_encoded);
  SESSION_RESULT_USERDATA(sesn_ptr)=strdup(access_token_encoded);
  return SESSION_RESULT_PTR(sesn_ptr);
}

/**
 * 	@brief:
 */
UFSRVResult *
BackendDirectoryNicknameSet (Session *sesn_ptr, const char *nickname)
{
	PersistanceBackend	*pers_ptr;
	redisReply 			*redis_ptr;

	pers_ptr = sesn_ptr->persistance_backend;

	redis_ptr = (*pers_ptr->send_command)(sesn_ptr, REDIS_CMD_NICKNAMES_DIRECTORY_SET, nickname, SESSION_USERID(sesn_ptr));

	if (redis_ptr) {
		freeReplyObject(redis_ptr);
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)

}

 /**
  * @brief: Query the cache backend for the presence of a given nickname.
  * @return sequence id of ufsrvuid, indicating the presence of the nickname
  *
  */
UFSRVResult *
BackendDirectoryNicknameGet (Session *sesn_ptr, const char *nickname)
{
	RedisBackend *pers_ptr = (RedisBackend *)sesn_ptr->persistance_backend;
  redisReply *redis_ptr;

  if (!(redis_ptr = (*pers_ptr->send_command)(sesn_ptr, REDIS_CMD_NICKNAMES_DIRECTORY_GET, nickname))) {
    syslog(LOG_DEBUG, LOGSTR_BACKENDCACHE_ERROR_REPLYOBJECT, __func__, pthread_self(), sesn_ptr, REDIS_CMD_NICKNAMES_DIRECTORY_GET, LOGCODE_BACKENDCACHE_ERROR_REPLYOBJECT);

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_BACKENDERR, RESCODE_BACKEND_CONNECTION)
  }

  if (redis_ptr->type != REDIS_REPLY_NIL && IS_STR_LOADED(redis_ptr->str)) {
    syslog(LOG_DEBUG, LOGSTR_BACKENDCACHE_REPLY, __func__, pthread_self(), sesn_ptr, redis_ptr->str, LOGCODE_BACKENDCACHE_REPLY, "Found nickname token...");

    long long sequence_id = strtoul(redis_ptr->str, NULL, 10);
    freeReplyObject(redis_ptr);

    _RETURN_RESULT_SESN(sesn_ptr, (uintptr_t)sequence_id, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
  }

  syslog(LOG_DEBUG, LOGSTR_BACKENDCACHE_UNSPECIFIED_REPLY, __func__, pthread_self(), sesn_ptr, REDIS_CMD_ACCOUNTS_DIRECTORY_GET, redis_ptr->type, LOGCODE_BACKENDCACHE_UNSPECIFIED_REPLY, "Token not found");

  freeReplyObject(redis_ptr);

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)

}

UFSRVResult *
BackendDirectoryNicknameDel (Session *sesn_ptr, const char *nickname)
{
  redisReply *redis_ptr;
	RedisBackend *pers_ptr=(RedisBackend *)sesn_ptr->persistance_backend;

  if (!(redis_ptr=(*pers_ptr->send_command)(sesn_ptr, REDIS_CMD_NICKNAMES_DIRECTORY_DEL, nickname))) {
#ifdef __UF_TESTING
    syslog(LOG_DEBUG, LOGSTR_BACKENDCACHE_ERROR_REPLYOBJECT, __func__, pthread_self(), sesn_ptr, REDIS_CMD_ACCOUNTS_DIRECTORY_GET, LOGCODE_BACKENDCACHE_ERROR_REPLYOBJECT);
#endif
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_BACKENDERR, RESCODE_BACKEND_CONNECTION)
  }

  if ((redis_ptr->type == REDIS_REPLY_INTEGER)) {
#ifdef __UF_TESTING
    syslog(LOG_DEBUG, LOGSTR_BACKENDCACHE_REPLY, __func__, pthread_self(), sesn_ptr, redis_ptr->integer==1?"1":"*", LOGCODE_BACKENDCACHE_REPLY, "Deleted nickname...");
#endif
    freeReplyObject(redis_ptr);

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
  }

  syslog(LOG_DEBUG, LOGSTR_BACKENDCACHE_UNSPECIFIED_REPLY, __func__, pthread_self(), sesn_ptr, REDIS_CMD_ACCOUNTS_DIRECTORY_GET, redis_ptr->type, LOGCODE_BACKENDCACHE_UNSPECIFIED_REPLY, "Nickname could not be deleted");

  freeReplyObject(redis_ptr);

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)

}

/**
 * @brief: Snappy lookup against backend cache.
 */
bool
IsNicknameAvailable (Session *sesn_ptr, const char *nickname)
{
	if (unlikely(!IS_STR_LOADED(nickname)))	return false;

	BackendDirectoryNicknameGet(sesn_ptr, nickname);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
		return false;
	}

	return true;
}

/**
 * 	@brief: preforms global scan across all accounts for the (hopefully single) occurrence of a nickname.
 *
 * 	@return: On success, (RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA) with 'AuthenticatedAccount *' returned with found owner details.
 * 			where no match was found (RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EMPTYSET) is returned.
 *
 * 	@dynamic_memory: Allocates 'AuthenticatedAccount *' which theuser must free
 */
UFSRVResult *
_DbAccountNicknameGet (Session *sesn_ptr, const char *nickname, UFSRVResult *res_ptr_in)
{
	UFSRVResult *res_ptr=NULL;

	if (res_ptr_in)	res_ptr=res_ptr_in;
	else	res_ptr=SESSION_RESULT_PTR(sesn_ptr);

	//IMPORTANT THIS QUERY USES 'GENERATED COLUMN' feature of mysql TO INDEX THE NICKNAME FIELD IN JSON
	//or traditional json: select * from accounts where data->"$.nickname"='xxx';
	#define SQL_GET_NICKNAME "SELECT id, ufsrvuid FROM accounts WHERE accounts_nickname = '%s'"
	#define COLUMN_USERID(x)	    ((struct _h_type_int *)result.data[0][0].t_data)->value
  #define COLUMN_UFSRVUID	      ((struct _h_type_blob *)result.data[0][1].t_data) //if attribute has null data this will be null
  #define	COLUMN_UFSRVUID_VALUE ((struct _h_type_text *)result.data[0][1].t_data)->value //binary fields are designated as text.

		struct _h_result result;
		char *sql_query_str;

		sql_query_str = mdsprintf(SQL_GET_NICKNAME, nickname);

#if __UF_TESTING
		syslog(LOG_DEBUG, "%s (o:'%p', cid='%lu'): GENERATED SQL QUERY: '%s'", __func__, sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str);
#endif

		int sql_result = h_query_select(sesn_ptr->db_backend, sql_query_str, &result);

		if (sql_result != H_OK) {
			syslog(LOG_DEBUG, "%s (o:'%p', cid='%lu'): ERROR: COULD EXEUTE QUERY: '%s'", __func__, sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str);

      free (sql_query_str);

			_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)
		}

  free (sql_query_str);

		//we should ever only find 1 or zero really
		if (result.nb_rows > 0) {
#if __UF_TESTING
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', uid:'%li', rows_sz:'%u'): Found occurrence of nickname", __func__, pthread_self(), sesn_ptr, COLUMN_USERID(result), result.nb_rows);
#endif

			AuthenticatedAccount *acct_ptr=calloc(1, sizeof(AuthenticatedAccount));
			acct_ptr->userid = COLUMN_USERID(result);
      memcpy(acct_ptr->ufsrvuid.data, COLUMN_UFSRVUID_VALUE, CONFIG_MAX_UFSRV_ID_SZ);

      h_clean_result(&result);

			_RETURN_RESULT_RES(res_ptr, acct_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
		} else {
#ifdef __UF_TESTING
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', nickname:'%s'): Nickname does not exist in the system...", __func__, pthread_self(), sesn_ptr, nickname);
#endif
		}

		exit_user_not_found:
		h_clean_result(&result);

		_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EMPTYSET)

	#undef COLUMN_USERID
	#undef COLUMN_UFSRVUID
  #undef COLUMN_UFSRVUID_VALUE
	#undef SQL_GET_NICKNAME

}

/**
 * 	@brief: validate provided nickname for availability. When validated and store flag is flagged, the name is cached on redis backend
 * 	@returns: If nickname already exists (RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EXISTINGSET)
 * 			where nickname is stored successfully (RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA_SETCREATED)
 * 			where nick is not taken and not srored RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA_EMPTYSET
 * 	@dynamic_memory: NONE EXPORTED
 */
UFSRVResult *
AccountNicknameValidateForUniqueness(Session *sesn_ptr, const UfsrvUid *uid_ptr, const char *nickname_by_user)
{
	if (!unlikely(IS_STR_LOADED(nickname_by_user))) {
		syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "nickname");
    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}

	UFSRVResult *res_ptr=_DbAccountNicknameGet (sesn_ptr, nickname_by_user, NULL);
	if (_RESULT_TYPE_SUCCESS(res_ptr)) {
		AuthenticatedAccount *acct_ptr=((AuthenticatedAccount *)_RESULT_USERDATA(res_ptr));

		//we are being mocked...
    if (memcmp(&(acct_ptr->ufsrvuid), uid_ptr, CONFIG_MAX_UFSRV_ID_SZ)==0) {
#ifdef	__UF_TESTING
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', nickname:'%s'}: Stored and user supplied nickname are identical...", __func__, pthread_self(), sesn_ptr, nickname_by_user);
#endif
			AuthenticatedAccountMemDestruct(acct_ptr, true);

			BackendDirectoryNicknameSet (sesn_ptr, nickname_by_user);//cache it anyway

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_RESOURCE_OWNER);
		} else {
#ifdef	__UF_TESTING
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', nickname:'%s', owner:'%s'}: ERROR: Requested nickname is already taken...", __func__, pthread_self(), sesn_ptr, nickname_by_user, acct_ptr->username);
#endif
			AuthenticatedAccountMemDestruct(acct_ptr, true);

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EXISTINGSET);
		}
	}
	else
	if (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_DATA_EMPTYSET)) {
#ifdef	__UF_TESTING
		syslog(LOG_DEBUG, "%s{pid:'%lu', o:'%p', nickname:'%s'}: Nickname is not found in the system...", __func__, pthread_self(), sesn_ptr, nickname_by_user);
#endif

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA_EMPTYSET)
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

////  END	NICKNAME\\\\

/**
 * @brief: Last step in the context of new account creation process, having previously verified a user.
 * Create a physical account record for the given username (number).
 * No integrity is performed here; that must be done in the calling method.
 *
 * @param verification_code: must be allocated by user min 8 chars, including null: 'xxx-xxx0'
 *registrationId":11515,"signalingKey":"h00I1bqwNYAMy1B34PE+1d1uqU4DTwOm/Ua7aoli5p22dU+ozeAF+D91eaBKu9WVqMCTHA=="
 *
 * @dynamic_memory: INTERNALLY ALLOCATES and FREEs 'char *sql_query_str'
 * @dynamic_memory: INTERNALLY ALLOCATES and FREEs various types 'json_object *'
 * @dynamic_memory: EXTERNALLY ALLOCATED and FREEs 'json_object *jobj_device'
 * @dynamic_memory:	EXPORTED 'char *' which is assigned to Session and gets freed at session destruction time
 *
 * @return 0: on success
 */
static int
_DbCreateAccount (Session *sesn_ptr, struct json_object *jobj_device, struct json_object *jobj_userdata, enum AccountRegoStatus rego_status)
{
	unsigned long verification_code;

#define SQL_INSERT_NEW_ACCOUNT "INSERT INTO accounts (number, `uuid`, data, data_user) VALUES ('%s', unhex(replace(uuid(),'-','')), '%s', '%s') ON DUPLICATE KEY UPDATE data = '%s', data_user = '%s'"

  const char	*username;
  const char 	*profile_key,
              *profile_version,
              *profile_commitment;
  const char 	*access_token;
  const char 	*e164number;

  //this will hold top level fields
  struct json_object *jobj_account = json_object_new_object();
  username = json_object_get_string(json__get(jobj_device, ACCOUNT_JSONATTR_NUMBER));

  profile_key = strdupa(json_object_get_string(json__get(jobj_device, ACCOUNT_JSONATTR_PROFILE_KEY)));//necessary to retain a local copy as object_del below will blow it off
  json_object_object_del(jobj_device, ACCOUNT_JSONATTR_PROFILE_KEY); //used just as carrier object bit hackish
  //profile_commitment and profile_version do not cuurently come through during rego, unlike profile_key, but that may change in the future
  profile_commitment = strdupa(json_object_get_string(json__get(jobj_device, ACCOUNT_JSONATTR_PROFILE_COMMITMENT)));//necessary to retain a local copy as object_del below will blow it off
  json_object_object_del(jobj_device, ACCOUNT_JSONATTR_PROFILE_COMMITMENT); //used just as carrier object bit hackish
  profile_version = strdupa(json_object_get_string(json__get(jobj_device, ACCOUNT_JSONATTR_PROFILE_VERSION)));//necessary to retain a local copy as object_del below will blow it off
  json_object_object_del(jobj_device, ACCOUNT_JSONATTR_PROFILE_VERSION); //used just as carrier object bit hackish

  access_token = strdupa(json_object_get_string(json__get(jobj_device, ACCOUNT_JSONATTR_ACCESS_TOKEN)));//necessary to retain a local copy as object_del below will blow it off
  json_object_object_del(jobj_device, ACCOUNT_JSONATTR_ACCESS_TOKEN); //used just as carrier object bit hackish

  json_object_object_add (jobj_account, ACCOUNT_JSONATTR_NUMBER, json_object_new_string(username));
  //TODO: supplied in another stream. but is currently saved at device level, so this maybe bogus entry
  json_object_object_add (jobj_account, "identity_key", json_object_new_string(CONFIG_DEFAULT_PREFS_STRING_VALUE));
  json_object_object_add (jobj_account, ACCOUNT_JSONATTR_ACCESS_TOKEN, json_object_new_string(access_token)); //set at account verification time
  json_object_object_add (jobj_account, ACCOUNT_JSONATTR_PROFILE_KEY, json_object_new_string(profile_key));
  json_object_object_add (jobj_account, ACCOUNT_JSONATTR_PROFILE_COMMITMENT, json_object_new_string(profile_commitment));
  json_object_object_add (jobj_account, ACCOUNT_JSONATTR_PROFILE_VERSION, json_object_new_string(profile_version));
  json_object_object_add (jobj_account, ACCOUNT_JSONATTR_REGO_STATUS, json_object_new_int(REGOSTATUS_VERIFIED));
//		json_object_object_add (jobj_account, ACCOUNT_JSONATTR_E164NUMBER, json_object_new_string(e164number));

  if (rego_status > REGOSTATUS_PENDING)	json_object_object_add (jobj_device, "is_returning", json_object_new_boolean(1));
  json_object_object_add(jobj_account, "authenticated_device", jobj_device);

  //attach master device to array of devices
  struct json_object *jarray_accounts = json_object_new_array();
  json_object_array_add(jarray_accounts, jobj_device);
   json_object_get(jobj_device);

  //attach the arry to the main account node
  json_object_object_add (jobj_account, "devices", jarray_accounts);

  const char *json_account_str = json_object_to_json_string(jobj_account);
  const char *json_userdata_str = json_object_to_json_string(jobj_userdata);
#ifdef __UF_TESTING
  syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu'): GENERATED JSON ACCOUNT: '%s'", __func__, pthread_self(), SESSION_ID(sesn_ptr), json_account_str);
  syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu'): GENERATED JSON USERDATA: '%s'", __func__, pthread_self(), SESSION_ID(sesn_ptr), json_userdata_str);
#endif

  char *sql_query_str;
  sql_query_str = mdsprintf(SQL_INSERT_NEW_ACCOUNT, username, json_account_str, json_userdata_str, json_account_str, json_userdata_str);

#ifdef __UF_TESTING
  syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu'): GENERATED SQL QUERY: '%s'", __func__, pthread_self(), SESSION_ID(sesn_ptr), sql_query_str);
#endif
  int sql_result = h_query_insert(sesn_ptr->db_backend, sql_query_str);

  //this seems to be necessary, because the same object is attached twice. The reference in the array remains (valgrind complaint)
  //json_object_object_del(jobj_account, "authenticated_device");
  json_object_put(jobj_account);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu'): ERROR: COULD EXEUTE QUERY: '%s'", __func__, pthread_self(), SESSION_ID(sesn_ptr), sql_query_str);
  }

  free (sql_query_str);

  return sql_result;

#undef SQL_INSERT_NEW_ACCOUNT
}

/**
 * 	@brief: soft delete only flags the "receives_message" attribute. Everything else is left intact
 */
UFSRVResult *
DbAccountDeactivate (Session  *sesn_ptr, const UfsrvUid *uid_ptr, bool flag_nuke)
{
	struct json_object *jobj_account;

	jobj_account=DbGetAccountInJson (sesn_ptr, uid_ptr);
	if (!jobj_account) {
		syslog(LOG_DEBUG, "%s {o:'%p', cid:'%lu'}: ERROR: COULD NOT GENERATE JSON OBJECT FOR ACCOUNT:'%lu'", __func__, sesn_ptr, SESSION_ID(sesn_ptr), UfsrvUidGetSequenceId(uid_ptr));

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
	}

	if (flag_nuke) {
    char ufsrvuid_encoded[CONFIG_MAX_UFSRV_ID_ENCODED_SZ+1] = {0};
    UfsrvUidConvertSerialise(&SESSION_UFSRVUIDSTORE(sesn_ptr), ufsrvuid_encoded);

		DbDeleteUserAccount (sesn_ptr, UfsrvUidGetSequenceId(uid_ptr));
		DbAccountDeleteKeys (sesn_ptr, ufsrvuid_encoded, DEFAULT_DEVICE_ID);//TODO: loop for all devices

		return &(sesn_ptr->sservice.result);
	}

	//soft deactivaton
	struct json_object *jobj_authenticated_device=json__get(jobj_account, "authenticated_device");
	json_object_object_del(jobj_authenticated_device, "gcm_id");
	json_object_object_add (jobj_authenticated_device, "gcm_id", json_object_new_string(CONFIG_DEFAULT_PREFS_STRING_VALUE));
	json_object_object_del(jobj_authenticated_device, "fetches_messages");
	json_object_object_add (jobj_authenticated_device, "fetches_messages", json_object_new_boolean(0));

	{
		//fetch device id and update there as well
		struct json_object *jobj_devices_array=json__get(jobj_account, "devices");
		int array_size=json_object_array_length(jobj_devices_array);
		int i;

		syslog(LOG_DEBUG, "%s (o:'%p', cid:'%lu'): DEVICES ARRAY CONTAIN:'%d' DEVICES IN IT", __func__, sesn_ptr, SESSION_ID(sesn_ptr), array_size);

		for (i=0; i<array_size; i++) {
			struct json_object *jobj_device=json_object_array_get_idx(jobj_devices_array, i);
			//if (device_id==json_object_get_int(json__get(jobj_device, "id")))//not applicable
			{
				json_object_object_del(jobj_device, "gcm_id");
				json_object_object_add (jobj_device, "gcm_id", json_object_new_string(CONFIG_DEFAULT_PREFS_STRING_VALUE));
				json_object_object_del(jobj_device, "fetches_messages");
				json_object_object_add (jobj_device, "fetches_messages", json_object_new_boolean(0));

				_DbUpdateAccountInJson (sesn_ptr, UfsrvUidGetSequenceId(uid_ptr), jobj_account);

				json_object_put(jobj_account);

				//TODO: this shoud be done somewhere else+broadcast of change
				USER_ACCOUNTSTATUS_SET(SESSION_USER_ACCOUNTSTATUS(sesn_ptr), USERACCOUNT_STATUS_SOFTDEACTIVE);

				_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
			}
		}
	}

	json_object_put(jobj_account);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER);
}

UFSRVResult *
ReturnUfsrvResultFromDbOpDescriptor(const DbOpDescriptor *dbop_descriptor)
{
  switch(dbop_descriptor->dbop_status.status) {
    case SUCCESS:
    THREAD_CONTEXT_RETURN_RESULT_SUCCESS(NULL, RESCODE_BACKEND_DATA)
    case TRANSFORMER_ERROR:
    THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_BACKEND_DATA_TRANSFORMATION)
    case DB_ERROR:
    THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_BACKEND_CONNECTION)
    case  EMPTY_SET:
    THREAD_CONTEXT_RETURN_RESULT_SUCCESS(NULL, RESCODE_BACKEND_DATA_EMPTYSET)
    default:;
  }

  THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_PROG_INCONSISTENT_STATE)
}

static int
_DbAccountUpdateUfrsvUid (Session *sesn_ptr, const UfsrvUid *uid_ptr)
{
#define SQL_UPDATE_ACCOUNT_DATA_STRING 	 "UPDATE accounts SET ufsrvuid = UNHEX('%s') WHERE id=%lu"

  char *sql_query_str;
  char uid_hexified[(CONFIG_MAX_UFSRV_ID_SZ * 2) + 1] = {0};

  bin2hex(uid_ptr->data, CONFIG_MAX_UFSRV_ID_SZ, uid_hexified);
  sql_query_str = mdsprintf(SQL_UPDATE_ACCOUNT_DATA_STRING, uid_hexified, UfsrvUidGetSequenceId(uid_ptr));

#ifdef __UF_FULLDEBUG
  syslog(LOG_DEBUG, "%s (cid='%lu'): GENERATED SQL QUERY: '%s'", __func__, SESSION_ID(sesn_ptr), sql_query_str);
#endif

  int sql_result = h_query_update(sesn_ptr->db_backend, sql_query_str);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, "%s (cid='%lu'): ERROR: COULD NOT EXECUTE: '%s'", __func__, SESSION_ID(sesn_ptr), sql_query_str);
  }

  free (sql_query_str);

  return sql_result;

#undef SQL_UPDATE_ACCOUNT_DATA_STRING
}

__unused static int
_DbAccountUpdateUuid (Session *sesn_ptr, unsigned long userid, const char *uuid_provided)
{
#define SQL_UPDATE_ACCOUNT_DATA_STRING 	 "UPDATE accounts SET `uuid` = UNHEX(REPLACE(uuid(), '-', '')) WHERE id = %lu"
#define SQL_UPDATE_ACCOUNT_DATA_STRING_PROVIDED 	 "UPDATE accounts SET `uuid` = unhex(replace(%s, '-', '')) WHERE id = %lu"

char *sql_query_str;

  if (IS_STR_LOADED(uuid_provided)) {
    sql_query_str = mdsprintf(SQL_UPDATE_ACCOUNT_DATA_STRING_PROVIDED, uuid_provided, userid);
  } else {
    sql_query_str = mdsprintf(SQL_UPDATE_ACCOUNT_DATA_STRING, userid);
  }
#ifdef __UF_FULLDEBUG
syslog(LOG_DEBUG, "%s: GENERATED SQL QUERY: '%s'", __func__, sql_query_str);
#endif

  int sql_result = h_query_update(sesn_ptr->db_backend, sql_query_str);

  if (sql_result != H_OK) {
  syslog(LOG_DEBUG, "%s (cid='%lu'): ERROR: COULD NOT EXECUTE: '%s'", __func__, SESSION_ID(sesn_ptr), sql_query_str);
  }

  free (sql_query_str);

  return sql_result;

#undef SQL_UPDATE_ACCOUNT_DATA_STRING
}

/**
 * Necessary convention must be followed with this style of DB operation:
 * 1) User must allocate a DbOpDescriptor defined as follows:
 * 1.1)Query builder that returns a fully constructed query string
 * 1.2)Values into the query string builder must be passed as intptr_t array
 * 1.3)If you don't want the the result object to be finalised after transformation set finaliser.finalise to NULL.
 *     In this case, you have to to invoke the finaliser yourself, otherwise your are leaking memory
 * @param username
 * @param dbop_descriptor
 * @return
 */
UFSRVResult *
DbAccountGetUuid(DbOpDescriptor *dbop_descriptor)
{
  GetDbResult(THREAD_CONTEXT_DB_BACKEND, dbop_descriptor);
  return ReturnUfsrvResultFromDbOpDescriptor(dbop_descriptor);
/*  struct _h_result *result = &dbop_descriptor->result;
  char *sql_query_str  = DBOP_DESCRIPTOR_INVOKE_QUERY_PROVIDER(dbop_descriptor);

#ifdef __UF_FULLDEBUG
  syslog(LOG_DEBUG, "%s (th_ctx:'%p'): GENERATED SQL QUERY: '%s'", __func__, THREAD_CONTEXT_PTR, sql_query_str);
#endif

  int sql_result = h_query_select(THREAD_CONTEXT_DB_BACKEND, sql_query_str, result);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, "%s (th_ctx:'%p', username''%s'): ERROR: COULD NOT EXECUTE QUERY: '%s'", __func__, THREAD_CONTEXT_PTR, username, sql_query_str);

    DBOP_DESCRIPTOR_INVOKE_QUERY_PROVIDER_FINALISER(dbop_descriptor, sql_query_str);

    THREAD_CONTEXT_RETURN_RESULT_SUCCESS(NULL, RESCODE_BACKEND_CONNECTION)
  }

  DBOP_DESCRIPTOR_INVOKE_QUERY_PROVIDER_FINALISER(dbop_descriptor, sql_query_str);

  if (result->nb_rows == 0) {
    syslog(LOG_DEBUG, "%s (th_ctx:'%p', username:'%s'): ERROR: COULD FIND CORRESPONDING DB RECORD", __func__, THREAD_CONTEXT_PTR, username);

    h_clean_result(&result);

    THREAD_CONTEXT_RETURN_RESULT_SUCCESS(NULL, RESCODE_BACKEND_DATA_EMPTYSET)
  }

  DBOP_DESCRIPTOR_INVOKE_RESULT_FINALISER_IF_PRESENT(dbop_descriptor);

  THREAD_CONTEXT_RETURN_RESULT_SUCCESS(NULL, RESCODE_BACKEND_DATA)*/

}

UFSRVResult *
DbAccountGetUfrsvUid (Session *sesn_ptr, const char *username, UfsrvUid *uid_ptr_out)
{
#define SQL_SELECT_UFSRVUID 	 "SELECT ufsrvuid FROM accounts WHERE number = '%s'"
#define COLUMN_UFSVUID(x)		((uint8_t *)((struct _h_type_blob *)result.data[0][0].t_data)->value)

  struct _h_result result;
  char *sql_query_str;

  sql_query_str = mdsprintf(SQL_SELECT_UFSRVUID, username);

#ifdef __UF_FULLDEBUG
  syslog(LOG_DEBUG, "%s (o:'%p', cid:'%lu'): GENERATED SQL QUERY: '%s'", __func__, sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str);
#endif

  int sql_result = h_query_select(sesn_ptr->db_backend, sql_query_str, &result);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, "%s (o:'%p', cid:'%lu', username''%s'): ERROR: COULD NOT EXECUTE QUERY: '%s'", __func__, sesn_ptr, SESSION_ID(sesn_ptr), username, sql_query_str);

    free (sql_query_str);

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
  }

  free (sql_query_str);

  if (result.nb_rows == 0) {
    syslog(LOG_DEBUG, "%s (o:'%p', cid:'%lu', username:'%s'): ERROR: COULD FIND CORRESPONDING DB RECORD", __func__, sesn_ptr, SESSION_ID(sesn_ptr), username);

    h_clean_result(&result);

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EMPTYSET)
  }

  memcpy(uid_ptr_out->data, COLUMN_UFSVUID(result), CONFIG_MAX_UFSRV_ID_SZ);

  h_clean_result(&result);

  _RETURN_RESULT_SESN(sesn_ptr, uid_ptr_out, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)

#undef SQL_SELECT_UFSRVUID
#undef COLUMN_UFSVUID
}

////////// START Signed Prekey functions \\\\\\\\\\

UFSRVResult *
DbAccountIdentityKeyGet (Session *sesn_ptr, const UfsrvUid *uid_ptr, int device_id)
{
	//TODO: we should separate this out and perform proper cache update
	UFSRVResult *res_ptr= _DbAccountDataDeviceAttributeGetText(sesn_ptr, UfsrvUidGetSequenceId(uid_ptr), device_id, ACCOUNT_JSONATTR_IDENTITY_KEY);
	if (_RESULT_TYPE_SUCCESS(res_ptr)) {
		__cache_update_block:
		{
			//TODO: update cache
		}

		return res_ptr;//success
	}

	return res_ptr;//contains error

}

/**
 * @brief: Fetches the signed prekey record (json structure) contining signed pre key attributes. The attributes are returned verbatim
 * as they are stored in the db field.
 *
 * @dynamic_memory: Upon sccess client data contains a char * whicg user must free
 */
UFSRVResult *
DbAccountSignedPreKeyGet (Session *sesn_ptr, const UfsrvUid *uid_ptr, int device_id)
{
	//TODO: we should separate this out and perform proper cache update
	UFSRVResult *res_ptr= _DbAccountDataDeviceAttributeGetText(sesn_ptr, UfsrvUidGetSequenceId(uid_ptr), 0, ACCOUNT_JSONATTR_SIGNED_PREKY);
	if (_RESULT_TYPE_SUCCESS(res_ptr)) {
	//	struct jsonobject *jobj_signed_pre_key=((struct json_object *)_RESULT_USERDATA(res_ptr));

		__cache_update_block:
		{
			//TODO: update cache
		}

		return res_ptr;//success
	}

	return res_ptr;//contains error

}

/**
 * 	@brief:	Update the value of the signed prekey value attached to the user's account on a particular device.
 * 	Defaults to authenticated device.
 */
UFSRVResult *
DbAccountSignedPreKeySet (Session *sesn_ptr, const UfsrvUid *uid_ptr, int device_id, struct json_object *jobj_signed_prekey)
{
	//TODO: we should separate this out and perform proper cache update
	UFSRVResult *res_ptr=_DbAccountAttributeSetJsonObject (sesn_ptr, uid_ptr, -1/*device_id*/, ACCOUNT_JSONATTR_SIGNED_PREKY, jobj_signed_prekey);
	if (_RESULT_TYPE_SUCCESS(res_ptr)) {
			//TODO: update cache

		return res_ptr;//success
	}

	return res_ptr;//contains error, albeit lower level

}

/**
 * 	@brief: returns the structure associated with user's signed key on apraticular device
 * 	@dynamic_memory: Allocates json_object, which user must free
 */
struct json_object *
AccountSignedPreKeyGetInJson (Session *sesn_ptr, const UfsrvUid *uid_ptr, int device_id)
{
	UFSRVResult *res_ptr=DbAccountSignedPreKeyGet (sesn_ptr, uid_ptr, device_id);
	if (_RESULT_TYPE_SUCCESS(res_ptr)) {
		struct json_object *jobj_prekey=NULL;

		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', json:'%s'}: Account: Signed prekey result...", __func__, pthread_self(), sesn_ptr, (char *)_RESULT_USERDATA(res_ptr));

#if 1
		enum json_tokener_error jerr;
		struct json_tokener *jtok=json_tokener_new();

		do {
			jobj_prekey=json_tokener_parse_ex(jtok, (char *)_RESULT_USERDATA(res_ptr), strlen((char *)_RESULT_USERDATA(res_ptr)));
		} while ((jerr=json_tokener_get_error(jtok))==json_tokener_continue);

		if (jerr!=json_tokener_success) {
			syslog(LOG_NOTICE, "%s (pid:'%lu' o:'%p' cid:'%lu'): JSON tokeniser Error: '%s'...",
				__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), json_tokener_error_desc(jerr));

			jobj_prekey=NULL;
		}

		json_tokener_free(jtok);
#endif

		free (_RESULT_USERDATA(res_ptr));

		return jobj_prekey;
	}

	return NULL;

}

/**
 * @dynamic_memory: Upon success returns a 'AccountKeyRecordSigned *' which the use must free with void AccountKeyRecordSignedDestruct()
 */
struct AccountKeyRecordSigned *
AccountSignedPreKeyGet (Session *sesn_ptr, const UfsrvUid *uid_ptr, int device_id)
{
	struct json_object *jobj_prekey=AccountSignedPreKeyGetInJson (sesn_ptr, uid_ptr, device_id);
	if (IS_PRESENT(jobj_prekey)) {
		AccountKeyRecordSigned *skey_record_ptr=calloc(1, sizeof(AccountKeyRecordSigned));
		skey_record_ptr->key.key_id=json_object_get_int(json__get(jobj_prekey, "keyId"));
		skey_record_ptr->signature=strdup(json_object_get_string(json__get(jobj_prekey, "signature")));
		skey_record_ptr->key.public_key=strdup(json_object_get_string(json__get(jobj_prekey, "publicKey")));

		json_object_put(jobj_prekey);

		return skey_record_ptr;
	}

	return NULL;

}

////////// END Signed Prekey functions \\\\\\\\\\


///////////// START OF KEYS FUNCTIONS \\\\\\\\\\\


/**
 * Helper method to DbSetKeys() to extract prekey records from json stream
 * "identityKey":"BVtqnUDDutbzzz0KVEqgmyJ7hiin3joVhOIoi5Y4kWEB",
 * "preKeys":[{"keyId":647918,"publicKey":"BVo3cFV1eb95XvAbC8sS25snmUwc/zs4utWa6vhaR5J7"},...],
 * "signedPreKey":{"keyId":16322360,"publicKey":"BUnv...y","signature":"8Y..naBA"}
 */
int
SetUserKeys (Session *sesn_ptr, const UfsrvUid *uid_ptr, json_object *jobj, int device_id)
{
	struct json_object *jobj_array=json__get(jobj, "preKeys");
	if (IS_EMPTY(jobj_array)) {
		syslog(LOG_DEBUG, LOGSTR_ACCOUNT_PREKEY_ERROR, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), LOGCODE_ACCOUNT_PREKEY_ERROR, "PeKey entity was missing");

		return -2;
	}

	int jobj_array_len = json_object_array_length(jobj_array);
	if (jobj_array_len==0) {
		syslog(LOG_DEBUG, LOGSTR_ACCOUNT_PREKEY_ERROR, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), LOGCODE_ACCOUNT_PREKEY_ERROR, "PeKey entity contain no entries");

		return 0;
	}

	//first we clean up if any before the "new" batch
  char ufsrvuid_encoded[CONFIG_MAX_UFSRV_ID_ENCODED_SZ+1] = {0};
  UfsrvUidConvertSerialise(uid_ptr, ufsrvuid_encoded);
	DbAccountDeleteKeys (sesn_ptr, ufsrvuid_encoded, device_id);

	//pre_key block
	json_object *jobj_entry=NULL;
	unsigned long key_id;
	const char *public_key;

	unsigned i=0;
	for (i=0; i<jobj_array_len; i++) {
		jobj_entry=json_object_array_get_idx (jobj_array, i);
		if (IS_PRESENT(jobj_entry)) {
			key_id=json_object_get_int64(json__get(jobj_entry, "keyId"));
			public_key=json_object_get_string(json__get(jobj_entry, "publicKey"));
			if (key_id>0 && IS_STR_LOADED(public_key)) {
				DbSetKeys (sesn_ptr, ufsrvuid_encoded, device_id, key_id, public_key, 0);
			} else {
				syslog(LOG_DEBUG, LOGSTR_ACCOUNT_PREKEY_ERROR, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), LOGCODE_ACCOUNT_PREKEY_ERROR, "PeKey entity was missing");
			}
		}
	}

	//signedPreKey
	struct json_object *jobj_signed_prekey=json__get(jobj, "signedPreKey");
	if (IS_PRESENT(jobj_signed_prekey)) {
		json_object_get	(jobj_signed_prekey);
		UFSRVResult *res_ptr=_DbAccountAttributeSetJsonObject (sesn_ptr, &(SESSION_UFSRVUIDSTORE(sesn_ptr)), -1/*device_id*/, "signed_prekey", jobj_signed_prekey);
		//jobj_signed_prekey refcount will be decremented;

		if (_RESULT_TYPE_SUCCESS(res_ptr)) {
			//success
		} else {
			syslog(LOG_DEBUG, LOGSTR_ACCOUNT_SIGNED_PREKEY_ERROR, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), LOGCODE_ACCOUNT_SIGNED_PREKEY_ERROR, "Db Backend store error");

			return -4;
		}
	} else {
		syslog(LOG_DEBUG, LOGSTR_ACCOUNT_SIGNED_PREKEY_ERROR, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), LOGCODE_ACCOUNT_SIGNED_PREKEY_ERROR, "Missing from stream");

		return -4;
	}

	//IdentityKey
		//struct json_object *jobj_idkey=json__get(jobj, "identityKey");
	const char *jobj_str_idkey=json_object_get_string(json__get(jobj, "identityKey"));
	if (jobj_str_idkey) {
		UFSRVResult *res_ptr=_DbAccountAttributeSetText (sesn_ptr, &(SESSION_UFSRVUIDSTORE(sesn_ptr)), -1/*device_id*/, "identityKey", jobj_str_idkey);
		if (_RESULT_TYPE_SUCCESS(res_ptr)) {
			//success
		} else {
			syslog(LOG_DEBUG, LOGSTR_ACCOUNT_IDKEY_ERROR, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), LOGCODE_ACCOUNT_IDKEY_ERROR, "Db Backend store error");

			return -5;
		}
	} else {
		syslog(LOG_DEBUG, LOGSTR_ACCOUNT_IDKEY_ERROR, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), LOGCODE_ACCOUNT_IDKEY_ERROR, "Missing from stream: identityKey");

		return -4;
	}

		return 0;//success

}

/**
 * Create a new account record for the given number (username).
 *
 * @param verification_code: must be allocated by user min 8 chars, including null: 'xxx-xxx0'
 * @return 0: on success
 */
int
DbSetKeys (Session *sesn_ptr, const char *ufsrvuid, unsigned long device_id, unsigned long key_id, const char *public_key, int last_resort_key_flag)
{
	unsigned long verification_code;

  //if number alreaduy has a code, overwrite it...
#define SQL_INSERT_KEY "INSERT INTO ufsrv.keys (number, device_id, key_id, public_key, last_resort) VALUES ('%s', '%lu', '%lu', '%s', '%d')"
  char *sql_query_str;
  sql_query_str=mdsprintf(SQL_INSERT_KEY, ufsrvuid, device_id, key_id, public_key, last_resort_key_flag);

#ifdef __UF_FULLDEBUG
  syslog(LOG_DEBUG, "%s (cid='%lu'): GENERATED SQL QUERY: '%s'", __func__, SESSION_ID(sesn_ptr), sql_query_str);
#endif

  int sql_result=h_query_insert(sesn_ptr->db_backend, sql_query_str);
  free (sql_query_str);
  if (sql_result!=H_OK) {
    //syslog(LOG_DEBUG, "%s (cid='%lu'): ERROR: COULD NOT EXECUTE QUERY: '%s'", __func__, SESSION_ID(sesn_ptr), sql_query_str);
  }
  return sql_result;

#undef SQL_INSERT_KEY
}

/*
 * @brief: select the first available key for the combination of {device,number}
 * @dynamic_memory: upon success create AccountKeyRecord , which the user must free
 *
 * Original query selected the first available key from each distinct combination of deices_id/number
 * So, if a user had one device only, we'd get one row for the first available key for that device
 * * http://stackoverflow.com/questions/17673457/converting-select-distinct-on-queries-from-postgresql-to-mysql
 *
 * "SELECT DISTINCT ON (number, device_id) * FROM keys WHERE number = number ORDER BY number, device_id, key_id ASC"
 */
UFSRVResult *
DbAccountGetFirstAvailableKeyByDevice (Session *sesn_ptr, const char *ufsrvuid, int device_id)
{
#define SQL_SELECT_KEY_COUNT "SELECT id, number, device_id, key_id, public_key, last_resort FROM ufsrv.keys WHERE number = '%s' AND device_id = '%d' ORDER BY key_id ASC LIMIT 1 FOR UPDATE"
#define QUERY_RESULT_ID(x)	((struct _h_type_int *)result.data[x][0].t_data)->value
#define QUERY_RESULT_NUMBER(x)	((struct _h_type_text *)result.data[x][1].t_data)->value
#define QUERY_RESULT_DEVICE_ID(x)	((struct _h_type_int *)result.data[x][2].t_data)->value
#define QUERY_RESULT_KEY_ID(x)	((struct _h_type_int *)result.data[x][3].t_data)->value
#define QUERY_RESULT_KEY_PUBKEY(x)	(char *)(((struct _h_type_blob *)result.data[x][4].t_data)->value)
#define QUERY_RESULT_KEY_PUBKEY_LEN(x)	((struct _h_type_blob *)result.data[x][4].t_data)->length
#define QUERY_RESULT_LASTRESORT(x)	((struct _h_type_int *)result.data[x][5].t_data)->value
//#define QUERY_RESULT_REGO_ID(x)	((struct _h_type_int *)result.data[x][6].t_data)->value

	struct _h_result result;
	char *sql_query_str;

	sql_query_str = mdsprintf(SQL_SELECT_KEY_COUNT, ufsrvuid, device_id);

	syslog(LOG_DEBUG, LOGSTR_BACKENDDB_QUERY_STRING, __func__, pthread_self(), sesn_ptr, sql_query_str, LOGCODE_BACKENDDB_QUERY_STRING);

	int sql_result = h_query_select(sesn_ptr->db_backend, sql_query_str, &result);

	if (sql_result != H_OK) {
		syslog(LOG_DEBUG, LOGSTR_BACKENDDB_CONNECTION_ERROR, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str, LOGCODE_BACKENDDB_CONNECTION_ERROR);

		free (sql_query_str);
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
	}

	if (result.nb_rows == 0) {
		syslog(LOG_DEBUG, LOGSTR_BACKENDDB_EMPTY_RESULTSET, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str, LOGCODE_BACKENDDB_EMPTY_RESULTSET);

		free (sql_query_str);
		h_clean_result(&result);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EMPTYSET)
	}

	free (sql_query_str);

	//get it out of circulation. We may need a transaction for this or lock
	//http://dev.mysql.com/doc/refman/5.7/en/lock-tables.html
	//http://dba.stackexchange.com/questions/15854/innodb-row-locking-how-to-implement
	//TODO check for error
	DbAccountDeleteKey(sesn_ptr, QUERY_RESULT_KEY_ID(0));

	AccountKeyRecord *account_key_ptr=calloc(1, sizeof(AccountKeyRecord));
	account_key_ptr->device_id = QUERY_RESULT_DEVICE_ID(0);
	account_key_ptr->is_lastresort = QUERY_RESULT_LASTRESORT(0);
	account_key_ptr->key_id = QUERY_RESULT_KEY_ID(0);
	account_key_ptr->public_key = strndup(QUERY_RESULT_KEY_PUBKEY(0), QUERY_RESULT_KEY_PUBKEY_LEN(0));

	h_clean_result(&result);

	_RETURN_RESULT_SESN(sesn_ptr, (void *)account_key_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)

#undef SQL_SELECT_KEY_COUNT

}

/**
 * 	@brief: Delete a single key record for given user using the unique key_id identifier
 */
UFSRVResult *
DbAccountDeleteKey (Session *sesn_ptr, int key_id)
{
#define SQL_DELETE_KEY "DELETE FROM ufsrv.keys WHERE key_id = '%d'"

	char *sql_query_str;
	sql_query_str=mdsprintf(SQL_DELETE_KEY, key_id);

	syslog(LOG_DEBUG, LOGSTR_BACKENDDB_QUERY_STRING, __func__, pthread_self(), sesn_ptr, sql_query_str, LOGCODE_BACKENDDB_QUERY_STRING);

	int sql_result=h_query_delete(sesn_ptr->db_backend, sql_query_str);

	if (sql_result!=H_OK) {
		syslog(LOG_DEBUG, LOGSTR_BACKENDDB_CONNECTION_ERROR, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str, LOGCODE_BACKENDDB_CONNECTION_ERROR);

    free (sql_query_str);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
	}

  free (sql_query_str);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)

#undef SQL_DELETE_KEY

}

/**
 * 	@brief: Delete all keys under device id for a given user
 */
UFSRVResult *
DbAccountDeleteKeys (Session *sesn_ptr, const char *ufsrvuid, int device_id)
{
#define SQL_DELETE_DEVICE_KEYS "DELETE FROM ufsrv.keys WHERE number = '%s' AND device_id = '%d'"

	char *sql_query_str;
	sql_query_str=mdsprintf(SQL_DELETE_DEVICE_KEYS, ufsrvuid, device_id);

	syslog(LOG_DEBUG, LOGSTR_BACKENDDB_QUERY_STRING, __func__, pthread_self(), sesn_ptr, sql_query_str, LOGCODE_BACKENDDB_QUERY_STRING);

	int sql_result=h_query_delete(sesn_ptr->db_backend, sql_query_str);

	if (sql_result!=H_OK) {
		syslog(LOG_DEBUG, LOGSTR_BACKENDDB_CONNECTION_ERROR, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str, LOGCODE_BACKENDDB_CONNECTION_ERROR);

    free (sql_query_str);
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
	}

  free (sql_query_str);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)

#undef SQL_DELETE_DEVICE_KEYS

}

UFSRVResult *
DbAccountGetKeysCountForDevice (Session *sesn_ptr, const char *ufsrvuid, int device_id)
{
#define SQL_SELECT_KEY_COUNT	"SELECT COUNT(*) FROM ufsrv.keys WHERE number = '%s' AND device_id = '%d'"
#define QUERY_RESULT_COUNT	((struct _h_type_int *)result.data[0][0].t_data)->value

	struct _h_result result;
	char *sql_query_str;

	sql_query_str=mdsprintf(SQL_SELECT_KEY_COUNT, ufsrvuid, device_id);

	syslog(LOG_DEBUG, LOGSTR_BACKENDDB_QUERY_STRING, __func__, pthread_self(), sesn_ptr, sql_query_str, LOGCODE_BACKENDDB_QUERY_STRING);

	int sql_result=h_query_select(sesn_ptr->db_backend, sql_query_str, &result);

	if (sql_result!=H_OK) {
		syslog(LOG_DEBUG, LOGSTR_BACKENDDB_CONNECTION_ERROR, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str, LOGCODE_BACKENDDB_CONNECTION_ERROR);

    free (sql_query_str);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
	}

	if (result.nb_rows==0) {
		syslog(LOG_DEBUG, LOGSTR_BACKENDDB_EMPTY_RESULTSET, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str, LOGCODE_BACKENDDB_EMPTY_RESULTSET);

    free (sql_query_str);
    h_clean_result(&result);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EMPTYSET)
	}

	size_t keys_count=QUERY_RESULT_COUNT;

  free (sql_query_str);
	h_clean_result(&result);

	_RETURN_RESULT_SESN(sesn_ptr, (void *)keys_count, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)

#undef SQL_SELECT_KEY_COUNT
#undef QUERY_RESULT_COUNT

}

void
AccountKeyRecordDestruct (AccountKeyRecord *account_key_ptr, bool self_destruct)
{
	if (unlikely(account_key_ptr==NULL)) {
		syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "AccountKeyRecord *");
		return;
	}

	if (account_key_ptr->public_key)	free (account_key_ptr->public_key);
	if (account_key_ptr->ufsrvuid)	free (account_key_ptr->ufsrvuid);

	if (self_destruct)	{free (account_key_ptr);	account_key_ptr=NULL;}

}

void
AccountKeyRecordSignedDestruct (AccountKeyRecordSigned *saccount_key_ptr, bool self_destruct)
{
	if (unlikely(saccount_key_ptr==NULL))
	{
		syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "AccountKeyRecord *");
		return;
	}

	AccountKeyRecordDestruct(&(saccount_key_ptr->key), false);
	if (saccount_key_ptr->signature)	free (saccount_key_ptr->signature);

	if (self_destruct)	{free (saccount_key_ptr);	saccount_key_ptr=NULL;}

}

////// END OF KEYS FUNCTIONS \\\\\\\\\\\\\\


////////// START Account sign on FUNCTIONS\\\\\\\\

/**
* 	@brief: verifies if cookie is attached to user's authenticated device account, indicating user's been previously authenticated
* 	@returns AuthenticatedAccount * on sucess. NULL if not
*
* 	@dynamic_memory: ALLOCATES 'AuthenticatedAccount *' which user must free. User must also check for dynamic strings by testing for NULL
* 	@dynamic_memory: INTERNALLY ALLOCATES AND FREEs 'char *sql_query_str'
* 	@dynamic_memory: INTERNALLY ALLOCATES AND FREEs internals for 'struct _h_result'
*/
UFSRVResult *
DbValidateUserSignOnWithCookie (Session *sesn_ptr, const char *cookie, AuthenticatedAccount *acct_ptr_out, UFSRVResult *res_ptr_in)
{
	UFSRVResult *res_ptr=NULL;
	if (res_ptr_in)	res_ptr=res_ptr_in;
	else	res_ptr=SESSION_RESULT_PTR(sesn_ptr);

//IMPORTANT THIS QUERY USES 'GENERATED COLUMN' feature of mysql TO INDEX THE COOKIE FIELD IN JSON
//#define SQL_GET_SIGNON_COOKIE "SELECT id, number, data->'$.authenticated_device.id', data->'$.authenticated_device.fetches_messages', accounts_nickname FROM accounts WHERE accounts_authenticated_device_cookie = '%s'"
#define SQL_GET_SIGNON_COOKIE "SELECT id, ufsrvuid, number, JSON_VALUE(data, '$.authenticated_device.id'), JSON_VALUE(data, '$.authenticated_device.fetches_messages'), accounts_nickname FROM accounts WHERE accounts_authenticated_device_cookie = '%s'"
#define COLUMN_USERID(x)		((struct _h_type_int *)result.data[0][0].t_data)->value
#define COLUMN_UFSVUID(x)		((uint8_t *)((struct _h_type_blob *)result.data[0][1].t_data)->value)
#define COLUMN_USERNAME(x)		((struct _h_type_text *)result.data[0][2].t_data)->value
#define COLUMN_DEVICEID(x)		((struct _h_type_int *)result.data[0][3].t_data)->value
#define COLUMN_FETCHESMSG(x)		((char *)((struct _h_type_blob *)result.data[0][4].t_data)->value)
#define COLUMN_NICKNAME(x)		((struct _h_type_text *)result.data[0][5].t_data)->value

	int	rescode	= RESCODE_USER_AUTHCOOKIE;
	char	*sql_query_str;
	struct	_h_result result;

	sql_query_str = mdsprintf(SQL_GET_SIGNON_COOKIE, cookie);

#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s (cid='%lu'): GENERATED SQL QUERY: '%s'", __func__, SESSION_ID(sesn_ptr), sql_query_str);
#endif

	int sql_result = h_query_select(sesn_ptr->db_backend, sql_query_str, &result);

	if (sql_result != H_OK) {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: ERROR: COULD EXECUTE QUERY: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str);
		free (sql_query_str);

		_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
	}

	free (sql_query_str);

	if (result.nb_rows >= 1) {
		if ((strncasecmp("false", COLUMN_FETCHESMSG(result), 1))==0) {
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu', fetches_msg:'%c'}: WARNING: COOKIE EXITS BUT ACCOUNT DISABLED FOR USERNAME: '%s'. device_id:'%li'",
					__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), *COLUMN_FETCHESMSG(result), COLUMN_USERNAME(result), COLUMN_DEVICEID(result));

			rescode = RESCODE_ACCOUNT_DISABLED;
//			goto exit_user_not_found;
				//let through but indicate rescode. Account coudld be disabled because GMC ID has not been set yet
				// Upto caller to make sense of this
		}

		AuthenticatedAccount *acct_ptr;
		if (!IS_EMPTY(acct_ptr_out))	acct_ptr  = acct_ptr_out;
		else													acct_ptr  = calloc(1, sizeof(AuthenticatedAccount));

		acct_ptr->userid = COLUMN_USERID(result);
		memcpy(acct_ptr->ufsrvuid.data, COLUMN_UFSVUID(result), CONFIG_MAX_UFSRV_ID_SZ);
		acct_ptr->username = strdup(COLUMN_USERNAME(result));
		acct_ptr->nickname = strdup(COLUMN_NICKNAME(result));
		acct_ptr->device_id= COLUMN_DEVICEID(result);
		acct_ptr->ufsrv_geogroup = 3;//COLUMN_UFSRV_GEOGROUP(result); todo: assign geogroup based on db stored value

#ifdef __UF_TESTING
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: SUCCESS: UFSRVUID:'%lu', COOKIE VALID FOR USERNAME: '%s', NICKNAME:'%s'. device_id:'%li'",
           __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), UfsrvUidGetSequenceId(&acct_ptr->ufsrvuid), COLUMN_USERNAME(result), COLUMN_NICKNAME(result), COLUMN_DEVICEID(result));
#endif

		h_clean_result(&result);

		_RETURN_RESULT_RES(res_ptr, acct_ptr, RESULT_TYPE_SUCCESS, rescode);
	} else {
#ifdef __UF_FULLDEBUG
#endif
	}

	exit_user_not_found:
	h_clean_result(&result);

	_RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, rescode);

#undef COLUMN_USERID
#undef COLUMN_UFSVUID
#undef COLUMN_USERNAME
#undef SQL_GET_SIGNON_COOKIE
#undef COLUMN_FETCHESMSG
#undef COLUMN_NICKNAME

}

/**
 * 	@brief:	Given an authenticated user, establish a SignOn status for thr user and generate new cookie
 *
 * 	@dynamic_memory: ALLOCATE 'char *cookie' which the user must free
 * 	@return: 0 on success -1 on error
 */
int
AccountSignOnUser (Session *sesn_ptr, AuthenticatedAccount *authacct_ptr)
{
	char *cookie=GenerateCookie();
	if (IS_PRESENT(cookie)) {
		authacct_ptr->cookie=cookie;

		//TODO: we should separate this out and perform proper cache update
		UFSRVResult *res_ptr=_DbAccountAttributeSetText (sesn_ptr, (const UfsrvUid *)&(authacct_ptr->ufsrvuid), -1/*device_id*/, ACCOUNT_JSONATTR_COOKIE, cookie);
		if (_RESULT_TYPE_SUCCESS(res_ptr)) {
				//TODO update cache

			return 0;
		} else {
			free(cookie);
			authacct_ptr->cookie=NULL;

			return -1;
		}
	}

	return -1;

}

/**
 * 	@brief: Performs DB check for user credentials This considered the most authoritative source. It can also generate a new cookie
 * 	for the user, practically, signing them on.
 *
 * 	@params password: user-supplied clear text password
 * 	@param signon_flag: when set, generate cookie for the user. Essential signing user on
 *
 *	@dynamic_memory: ALLOCATES AuthenticatedAccount  when signon flag is set.user responsible for freeing
 *	@dynamic_memory: ALLCOATES 'char *cookie' inside AuthenticatedAccount when signon flag is set.user responsible for freeing
 *	@dynamic_memory: ALLOCATES 'char *' for e164number member of  AuthenticatedAccount
 * 	@dynamic_memory: INTERNALLY ALLOCATES 'char *' for dynamic DB query string
 * 	@dynamic_memory: INTERNALLY ALLOCATES internal structures in 'struct _h_result'
 *
 *	@returns RESULT_TYPE_SUCCESS, RESULT_CODE_USER_AUTHENTICATION: User authenticated with existing cookie. AuthenticatedAccount * returned
 *	@returns RESULT_TYPE_SUCCESS, RESULT_CODE_USER_SIGNON: User authenticates and signed on. New cookie generated
 *	@returns RESULT_TYPE_SUCCESS, RESULT_CODE_PROG_NULL_POINTER. As a special case userid is returned as a pointer
 *
 *	@call_flag CALL_FLAG_USER_SIGNON: request to sign user on
 *	@call_flag CALL_FLAG_USER_AUTHENTICATED: user already authenticated, so no password validation is performed
 *
 * 	select JSON_EXTRACT(data, '$.authenticated_device.number', '$.authenticated_device.salt',
 * 	'$.authenticated_device.authentication_token') as toplevel_keys from accounts where number=+61xxxxx;
 */
UFSRVResult *
DbAuthenticateUser (Session *sesn_ptr, unsigned long userid, char *password, const char *cookie, unsigned call_flags)
{
//IMPORTANT: USING JSON_UNQUOTE turns the value from json string,  ie. "value", to my sql string, i.e. value, but the library then return blob type,
//as opposed to string type. Without UNQUOTE we get string type, but we have to remove the opening and closing " manually
#define SQL_SELECT_AUTHENTICATION_CREDS "SELECT id, ufsrvuid, " \
                                          " JSON_UNQUOTE(JSON_EXTRACT(data, '$.authenticated_device.salt'))," \
                                          " JSON_UNQUOTE(JSON_EXTRACT(data, '$.authenticated_device.authentication_token'))," \
                                          " JSON_UNQUOTE(JSON_EXTRACT(data, '$.authenticated_device.cookie'))," \
                                          " JSON_UNQUOTE(JSON_EXTRACT(data_user, '$.e164number'))," \
                                          " number,"           \
                                          " uuid,"              \
                                          " uuid_serialised"                      \
                                          " FROM accounts WHERE id = %lu"
#define SQL_QUERY_ID	            (((struct _h_type_int *)result.data[0][0].t_data)->value)
#define SQL_QUERY_UFSRVUID	      ((struct _h_type_blob *)result.data[0][1].t_data) //if attribute has null data this will be null
#define	SQL_QUERY_UFSRVUID_VALUE  ((struct _h_type_text *)result.data[0][1].t_data)->value //binary fields are designated as text.
#define SQL_QUERY_SALT          	(((struct _h_type_blob *)result.data[0][2].t_data)->value)
#define SQL_QUERY_SALT_SZ         (((struct _h_type_blob *)result.data[0][2].t_data)->length)
#define SQL_QUERY_AUTH_TOKEN     	(((struct _h_type_blob *)result.data[0][3].t_data)->value)
#define SQL_QUERY_AUTH_TOCKEN_SZ  (((struct _h_type_blob *)result.data[0][3].t_data)->length)
#define SQL_QUERY_COOKIE         	(((struct _h_type_blob *)result.data[0][4].t_data)->value)
#define SQL_QUERY_COOKIE_SZ       (((struct _h_type_blob *)result.data[0][4].t_data)->length)
#define SQL_QUERY_E164NUMBER_DATA ((struct _h_type_blob *)result.data[0][5].t_data)
#define SQL_QUERY_E164NUMBER     	(((struct _h_type_blob *)result.data[0][5].t_data)->value)
#define SQL_QUERY_E164NUMBER_SZ   (((struct _h_type_blob *)result.data[0][5].t_data)->length)
#define SQL_QUERY_USERNAME       	(((struct _h_type_blob *)result.data[0][6].t_data)->value)
#define SQL_QUERY_USERNAME_SZ     (((struct _h_type_blob *)result.data[0][6].t_data)->length)
#define SQL_QUERY_UUID       	    (((struct _h_type_blob *)result.data[0][7].t_data)->value)
#define SQL_QUERY_UUID_SZ         (((struct _h_type_blob *)result.data[0][7].t_data)->length)
#define SQL_QUERY_UUID_SERIALISED (((struct _h_type_text *)result.data[0][8].t_data)->value)

	struct _h_result result;
	char *sql_query_str;
	UserCredentials *creds_ptr;

	sql_query_str = mdsprintf(SQL_SELECT_AUTHENTICATION_CREDS, userid);

#ifdef __UF_FULLDEBUG
	syslog(LOG_DEBUG, "%s (cid='%lu'): GENERATED SQL QUERY: '%s'", __func__, SESSION_ID(sesn_ptr), sql_query_str);
#endif

	int sql_result = h_query_select(sesn_ptr->db_backend, sql_query_str, &result);

	if (sql_result != H_OK) {
		syslog(LOG_DEBUG, "%s (o:'%p', cid:'%lu', userid:'%lu'): ERROR: COULD NOT EXECUTE QUERY: '%s'", __func__, sesn_ptr, SESSION_ID(sesn_ptr), userid, sql_query_str);

    free (sql_query_str);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
	}

  free (sql_query_str);

	if (result.nb_rows == 0) {
		syslog(LOG_DEBUG, "%s (o:'%p', cid:'%lu', userid:'%lu'): ERROR: COULD FIND CORRESPONDING DB RECORD", __func__, sesn_ptr, SESSION_ID(sesn_ptr), userid);

		h_clean_result(&result);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EMPTYSET)
	}

	char *salt    = NULL;
	char *token   = NULL;

	int uid = SQL_QUERY_ID;
	if (IS_PRESENT(SQL_QUERY_SALT)) {
    salt = strndupa((char *)SQL_QUERY_SALT, SQL_QUERY_SALT_SZ);
	}
	if (IS_PRESENT(SQL_QUERY_AUTH_TOKEN)) {
    token = strndupa((char *)SQL_QUERY_AUTH_TOKEN, SQL_QUERY_AUTH_TOCKEN_SZ);
	}

	if (!CALLGFLAG_IS_SET(call_flags, CALL_FLAG_USER_AUTHENTICATED)) {
		if (!IsPasswordCorrect(password, (const char *)token, salt))	goto exit_error;
	}

  if (CALLGFLAG_IS_SET(call_flags, CALL_FLAG_USER_SIGNON)) {
    AuthenticatedAccount *authacct_ptr;
    authacct_ptr = calloc(1, sizeof(AuthenticatedAccount));//@dynamic_memory: user must free this
    authacct_ptr->userid    = uid;
    authacct_ptr->password  = password;
    authacct_ptr->username  = strndup((char *)SQL_QUERY_USERNAME, SQL_QUERY_USERNAME_SZ);//username;
    if (SQL_QUERY_UFSRVUID) {
      memcpy(authacct_ptr->ufsrvuid.data, SQL_QUERY_UFSRVUID_VALUE, CONFIG_MAX_UFSRV_ID_SZ);
    }

    if (IS_PRESENT(SQL_QUERY_E164NUMBER_DATA) && IS_PRESENT(SQL_QUERY_E164NUMBER)) {
      authacct_ptr->e164number = strndup((char *)SQL_QUERY_E164NUMBER, SQL_QUERY_E164NUMBER_SZ);
    }

    if (IS_PRESENT(SQL_QUERY_UUID)) {
      memcpy(authacct_ptr->uuid.raw.by_value, SQL_QUERY_UUID, UUID_LEN);
    }

    if (IS_PRESENT(SQL_QUERY_UUID_SERIALISED)) {
      memcpy(authacct_ptr->uuid.serialised.by_value, SQL_QUERY_UUID_SERIALISED, UUID_SERIALISED_LENGTH);
    }

    h_clean_result(&result);

    if ((AccountSignOnUser (sesn_ptr, authacct_ptr)) == 0) {
      _RETURN_RESULT_SESN(sesn_ptr, authacct_ptr, RESULT_TYPE_SUCCESS, RESULT_CODE_USER_SIGNON);
    } else {
      exit_error_signon:
      if (!IS_EMPTY(authacct_ptr->e164number)) free (authacct_ptr->e164number);
      free (authacct_ptr);
      _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
    }
  } else {
    //we are just performing lookup. If cookie is available, return it
    char *cookie_stored = NULL;
    if (SQL_QUERY_COOKIE) {
      cookie_stored = strndup((char *)SQL_QUERY_COOKIE, SQL_QUERY_COOKIE_SZ);
      if (IS_PRESENT(cookie) && !(strncmp(cookie, cookie_stored, CONFIG_MAX_COOKIE_SZ)==0)) {
        free (cookie_stored);
        h_clean_result(&result);
        _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_USER_AUTHCOOKIE)
      }
    }

    if (IS_PRESENT(cookie_stored)) {
      AuthenticatedAccount *authacct_ptr;
      authacct_ptr = calloc(1, sizeof(AuthenticatedAccount));//@dynamic_memory: user must free this

      authacct_ptr->userid    = uid;
      authacct_ptr->cookie    = cookie_stored;
      authacct_ptr->password  = password;
      authacct_ptr->username  = strndup((char *)SQL_QUERY_USERNAME, SQL_QUERY_USERNAME_SZ);
      if ((SQL_QUERY_UFSRVUID)) {
        memcpy(authacct_ptr->ufsrvuid.data, SQL_QUERY_UFSRVUID_VALUE, CONFIG_MAX_UFSRV_ID_SZ);
      }

      if (IS_PRESENT(SQL_QUERY_E164NUMBER_DATA) && IS_PRESENT(SQL_QUERY_E164NUMBER)) {
        authacct_ptr->e164number=strndup((char *)SQL_QUERY_E164NUMBER, SQL_QUERY_E164NUMBER_SZ);
      }

      if (IS_PRESENT(SQL_QUERY_UUID)) {
        memcpy(authacct_ptr->uuid.raw.by_value, SQL_QUERY_UUID, UUID_LEN);
      }

      if (IS_PRESENT(SQL_QUERY_UUID_SERIALISED)) {
        memcpy(authacct_ptr->uuid.serialised.by_value, SQL_QUERY_UUID_SERIALISED, UUID_SERIALISED_LENGTH);
      }

      h_clean_result(&result);
      _RETURN_RESULT_SESN(sesn_ptr, authacct_ptr, RESULT_TYPE_SUCCESS, RESULT_CODE_USER_AUTHENTICATION);//this indicates existing cookie
    } else {
      h_clean_result(&result);
      _RETURN_RESULT_SESN(sesn_ptr, (unsigned long)uid, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)
    }
  }

	exit_error:
	h_clean_result(&result);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESULT_CODE_USER_AUTHENTICATION);


#undef SQL_SELECT_AUTHENTICATION_CREDS
#undef SQL_QUERY_ID
#undef SQL_QUERY_UFSRVUID
#undef SQL_QUERY_UFSRVUID_VALUE
#undef SQL_QUERY_SALT
#undef SQL_QUERY_SALT_SZ
#undef SQL_QUERY_AUTH_TOKEN
#undef SQL_QUERY_AUTH_TOCKEN_SZ
#undef SQL_QUERY_COOKIE
#undef SQL_QUERY_COOKIE_SZ
#undef SQL_QUERY_E164NUMBER_DATA
#undef SQL_QUERY_E164NUMBER
#undef SQL_QUERY_E164NUMBER_SZ
#undef SQL_QUERY_UUID
#undef SQL_QUERY_UUID_SZ
#undef SQL_QUERY_UUID_SERIALISED
#undef SQL_QUERY_UUID_SERIALISED_SZ
}

/**
 * 	@brief: Retrive basic user account data based on rego email.
 *
 * 	@params username: rego name. According to current implementation this is a unique email address across the userbase
 * 	@param signon_flag: when set, generate cookie for the user. Essential signing user on
 *
 *	@dynamic_memory: ALLOCATES AuthenticatedAccount  when signon flag is set.user responsible for freeing
 *
 *	@returns RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA: User found. AuthenticatedAccount * returned
 *
 *	@call_flag none defined
 *
 */
UFSRVResult *
DbGetUserByUsername (const char *username, unsigned long call_flags)
{
//IMPORTANT: USING JSON_UNQUOTE turns the value from json string,  ie. "value", to my sql string, i.e. value, but the library then return blob type,
//as opposed to string type. Without UNQUOTE we get string type, but we have to remove the opening and closing " manually
#define SQL_SELECT_AUTHENTICATION_CREDS "SELECT id, ufsrvuid, " \
                                          " JSON_UNQUOTE(JSON_EXTRACT(data_user, '$.e164number')) " \
                                          " FROM accounts WHERE number = '%s'"
#define SQL_QUERY_ID	            (((struct _h_type_int *)result.data[0][0].t_data)->value)
#define SQL_QUERY_UFSRVUID	      ((struct _h_type_blob *)result.data[0][1].t_data) //if attribute has null data this will be null
#define	SQL_QUERY_UFSRVUID_VALUE  ((struct _h_type_text *)result.data[0][1].t_data)->value //binary fields are designated as text.
#define SQL_QUERY_E164NUMBER_DATA ((struct _h_type_blob *)result.data[0][2].t_data)
#define SQL_QUERY_E164NUMBER     	(((struct _h_type_blob *)result.data[0][2].t_data)->value)
#define SQL_QUERY_E164NUMBER_SZ   (((struct _h_type_blob *)result.data[0][2].t_data)->length)

  struct _h_result result;
  char *sql_query_str;

  sql_query_str = mdsprintf(SQL_SELECT_AUTHENTICATION_CREDS, username);

  int sql_result = h_query_select(THREAD_CONTEXT_DB_BACKEND, sql_query_str, &result);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, "%s (th:'%lu', uname:'%s'): ERROR: COULD NOT EXECUTE QUERY: '%s'", __func__, pthread_self(), username, sql_query_str);

    free (sql_query_str);

    THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_BACKEND_CONNECTION)
  }

  free (sql_query_str);

  if (result.nb_rows == 0) {
    syslog(LOG_DEBUG, "%s (th:'%lu', uname:'%s'): ERROR: COULD FIND CORRESPONDING DB RECORD", __func__, pthread_self(), username);

    h_clean_result(&result);

    THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_BACKEND_DATA_EMPTYSET)
  }

  AuthenticatedAccount *authacct_ptr;
  authacct_ptr = calloc(1, sizeof(AuthenticatedAccount));//@dynamic_memory: user must free this
  authacct_ptr->userid    = SQL_QUERY_ID;
  if ((SQL_QUERY_UFSRVUID)) {
    memcpy(authacct_ptr->ufsrvuid.data, SQL_QUERY_UFSRVUID_VALUE, CONFIG_MAX_UFSRV_ID_SZ);
  }

  //disabled for now
//  if (IS_PRESENT(SQL_QUERY_E164NUMBER_DATA) && IS_PRESENT(SQL_QUERY_E164NUMBER)) {
//    authacct_ptr->e164number = strndup((char *)SQL_QUERY_E164NUMBER, SQL_QUERY_E164NUMBER_SZ);
//  }

  h_clean_result(&result);
  THREAD_CONTEXT_RETURN_RESULT_SUCCESS(authacct_ptr, RESCODE_BACKEND_DATA)

  exit_error:
  h_clean_result(&result);

  THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, LOGCODE_BACKENDDB_EMPTY_RESULTSET)

#undef SQL_SELECT_AUTHENTICATION_CREDS
#undef SQL_QUERY_ID
#undef SQL_QUERY_UFSRVUID
#undef SQL_QUERY_UFSRVUID_VALUE
#undef SQL_QUERY_E164NUMBER_DATA
#undef SQL_QUERY_E164NUMBER
#undef SQL_QUERY_E164NUMBER_SZ
}

/**
 * 	@brief: update user account with new wholesale json object
 *
 * 	@dynamic_memory sql_query_str: free result associated with db query
 * 	@dynamic_memory: not responsible for freeing json objects
 */
static int
_DbUpdateAccountInJson (Session *sesn_ptr, unsigned long userid, struct json_object *jobj_account)
{
	if (!sesn_ptr || !jobj_account)	return -1;

#define SQL_UPDATE_ACCOUNT_DATA "UPDATE accounts SET data='%s' WHERE id='%lu'"

	char *sql_query_str;
	const char *account_json_str=json_object_to_json_string(jobj_account);

	sql_query_str=mdsprintf(SQL_UPDATE_ACCOUNT_DATA, account_json_str, userid);

#ifdef __UF_FULLDEBUG
	syslog(LOG_DEBUG, "%s (cid='%lu'): GENERATED SQL QUERY: '%s'", __func__, SESSION_ID(sesn_ptr), sql_query_str);
#endif

	int sql_result=h_query_update(sesn_ptr->db_backend, sql_query_str);
	free (sql_query_str);

	if (sql_result!=H_OK) {
		//syslog(LOG_DEBUG, "%s (cid='%lu'): ERROR: COULD EXEUTE QUERY: '%s'", __func__, SESSION_ID(sesn_ptr), sql_query_str);
	}

	return sql_result;

#undef SQL_UPDATE_ACCOUNT_DATA
}

/**
 * 	@brief: Looks up the rego_status property to determine if user has  1)registered and 2)active account etc..
 */
enum AccountRegoStatus
GetAccountRegisterationStatus(Session *sesn_ptr, const char *username)
{
	_DbAccountDataAttributeGetTextByUsername (sesn_ptr, username, ACCOUNT_JSONATTR_REGO_STATUS);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
		enum AccountRegoStatus rego_status = atoi((char *)SESSION_RESULT_USERDATA(sesn_ptr));
		free (SESSION_RESULT_USERDATA(sesn_ptr));
		return rego_status;
	}

	return REGOSTATUS_UNKNOWN;

}

/**
 *
 * @param jobj_data
 * @param attribute_name
 * @dynamic_memory Don't retain returned value, as it get deallocated when json object is gone
 * @return
 */
inline static const uintptr_t
_AttribueValueGetterByText(json_object *jobj_data, const char *attribute_name)
{
  return (uintptr_t)json_object_get_string(json__get(jobj_data, attribute_name));
}

__unused inline static const uintptr_t
_AttribueValueGetterByBoolean(json_object *jobj_data, const char *attribute_name)
{
  return (uintptr_t)json_object_get_boolean(json__get(jobj_data, attribute_name));
}

__unused inline static const uintptr_t
_AttribueValueGetterByInt(json_object *jobj_data, const char *attribute_name)
{
  return (uintptr_t)json_object_get_int(json__get(jobj_data, attribute_name));
}

/**
 * Return attributes associated with devices.
 * @param jobj_account instantiated json objec at the root of account definition
 * @param device_id to query default authenticated device pass 0, otherwise >=1
 * @param attribute_name json attribute
 * @param value_getter_callback type specific and aware getter
 * @return
 */
static const uintptr_t
_GetAccountDataDeviceAttributeByJsonObject(json_object *jobj_account, unsigned int device_id, const char *attribute_name, AttribueValueGetter value_getter_callback)
{
  struct json_object *jobj_data = NULL;

  if (device_id == AUTHENTICATED_DEVICE) {
    jobj_data = json__get(jobj_account, "authenticated_device");
  } else {
    json_object *jobj_array_devices = json__get(jobj_account, "devices");
    jobj_data = 	json_object_array_get_idx (jobj_array_devices, device_id-1);
  }

  return value_getter_callback(jobj_data, attribute_name);
}

/**
 * @brief Query the provided json object for the cm token. Since the returned value is destroyed when json object is deallocated,
 * user must retain a copy locally if required.
 * @param jobj_account
 * @param device_id
 * @dynamic_memory value returned by reference to stored json value
 * @return
 */
const char *
GetAccountAttributeForCloudMessaging (json_object *jobj_account, unsigned int device_id)
{
  const char *cm_token = (const char *)_GetAccountDataDeviceAttributeByJsonObject(jobj_account, device_id, ACCOUNT_JSONATTR_GCM_ID, _AttribueValueGetterByText);
  if (IS_STR_LOADED(cm_token)) {
    if (*cm_token == CONFIG_CM_TOKEN_UNDEFINED) {
      goto return_undefined;
    }

    return cm_token;
  }

  return_undefined:
  return NULL;
}

UFSRVResult *
DbAccountGetUserId(Session *sesn_ptr, const char *username, DbBackendUfsrvUidDescriptor *uid_descriptor_out)
{
#define SQL_SELECT_USERID "SELECT id, ufsrvuid, `uuid`, uuid_serialised FROM accounts WHERE number = '%s';"
#define SQL_QUERY_UFSRVUID	((struct _h_type_blob *)result.data[0][1].t_data) //if attribute has null data this will be null
#define	SQL_QUERY_UFSRVUID_VALUE ((struct _h_type_text *)result.data[0][1].t_data)->value //binary fields are designated as text.
#define SQL_QUERY_UUID	((struct _h_type_blob *)result.data[0][2].t_data) //if attribute has null data this will be null
#define	SQL_QUERY_UUID_VALUE ((struct _h_type_text *)result.data[0][2].t_data)->value //binary fields are designated as text.
#define SQL_QUERY_UUID_SERIALISED	((struct _h_type_blob *)result.data[0][3].t_data) //if attribute has null data this will be null
#define	SQL_QUERY_UUID_SERIALISED_VALUE ((struct _h_type_text *)result.data[0][3].t_data)->value //binary fields are designated as text.

  struct _h_result result;
	char *sql_query_str;

	sql_query_str = mdsprintf(SQL_SELECT_USERID, username);
#ifdef __UF_TESTING
	syslog(LOG_DEBUG, "%s (): GENERATED SQL QUERY: '%s'", __func__, sql_query_str);
#endif

	int sql_result = h_query_select(sesn_ptr->db_backend, sql_query_str, &result);

	if (sql_result != H_OK) {
		syslog(LOG_DEBUG, "%s (): ERROR: COULD NOT EXECUTE QUERY: '%s'", __func__, sql_query_str);

    free (sql_query_str);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
	}

  free (sql_query_str);

	if (result.nb_rows == 0) {
		syslog(LOG_DEBUG, "%s (): ERROR: COULD NOT FIND CORRESPONDING DB RECORD", __func__);

		h_clean_result(&result);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA_EMPTYSET)
	}

  DbBackendUfsrvUidDescriptor *uid_descriptor_ptr;
  if (IS_PRESENT(uid_descriptor_out)) {
    uid_descriptor_ptr = uid_descriptor_out;
  } else {
    uid_descriptor_ptr = calloc(1, sizeof(DbBackendUfsrvUidDescriptor));
  }

  if ((SQL_QUERY_UFSRVUID)) {
    memcpy (uid_descriptor_ptr->ufsrvid, SQL_QUERY_UFSRVUID_VALUE, CONFIG_MAX_UFSRV_ID_SZ);
    uid_descriptor_ptr->is_ufsrvuid_set = true;
  }

  if ((SQL_QUERY_UUID)) {
    memcpy(uid_descriptor_ptr->uuid.raw.by_value, SQL_QUERY_UUID_VALUE, UUID_LEN);
  }

  if ((SQL_QUERY_UUID_SERIALISED)) {
    memcpy(uid_descriptor_ptr->uuid.serialised.by_value, SQL_QUERY_UUID_SERIALISED_VALUE, UUID_SERIALISED_LENGTH);
  }

  uid_descriptor_ptr->sequence_id = (unsigned long)((struct _h_type_int *)result.data[0][0].t_data)->value;

	h_clean_result(&result);

	_RETURN_RESULT_SESN(sesn_ptr, uid_descriptor_ptr, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)

#undef SQL_SELECT_USERID
}

UFSRVResult *
DbValidateUserId (Session *sesn_ptr, unsigned long userid)
{
#define SQL_SELECT_USERNAME "SELECT number FROM accounts WHERE id='%lu';"

	if (unlikely(IS_EMPTY(sesn_ptr)))	return _ufsrv_result_generic_error;

	char	*sql_query_str;
	struct	_h_result result;

	sql_query_str=mdsprintf(SQL_SELECT_USERNAME, userid);

#ifdef __UF_FULLDEBUG
	syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): GENERATED SQL QUERY: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str);
#endif

	int sql_result=h_query_select(sesn_ptr->db_backend, sql_query_str, &result);

	if (sql_result!=H_OK) {
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR: COULD NOT EXEUTE QUERY: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str);

    free (sql_query_str);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
	}

  free (sql_query_str);

	if (result.nb_rows==0) {
		syslog(LOG_DEBUG, "%s (cid='%lu'): ERROR: COULD FIND CORRESPONDING DB RECORD", __func__, SESSION_ID(sesn_ptr));

    h_clean_result(&result);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EMPTYSET)
	}

	h_clean_result(&result);

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)

#undef SQL_SELECT_USERNAME
}

/**
 * 	@ALERT: this function merely checks for success and the limited nature of the return type doesn't allow
 * 	to relay back if false was related to backend error, as opposed pure data mismatch. Use DbValidateUserId()
 * 	where detailed inspection is required.
 */
bool IsUserIdValid (Session *sesn_ptr, unsigned long userid)
{
	DbValidateUserId(sesn_ptr, userid);

	if	 (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))	return true;

	return false;
}

/**
 *
 * @param sesn_ptr
 * @param username
 * @return the stored value, unless it is set to '*' which is always interpreted as unset
 * @dynamic_memroy PASSES downstream allocated 'char *'
 */
UFSRVResult *
DbAccountGetE164Number (Session *sesn_ptr, unsigned long userid)
{
	DbAccountDataUserAttributeGetText(sesn_ptr, userid, ACCOUNT_JSONATTR_E164NUMBER);
	if (RESULT_IS_SUCCESS_THRCTX) {
	  char *e164_stored = (char *) RESULT_USERDATA_THCTX;
		if (*e164_stored == '*') {
		  free (e164_stored);
      _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EMPTYSET)
		}

    _RETURN_RESULT_SESN(sesn_ptr, RESULT_USERDATA_THCTX, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EMPTYSET);
}

int
DbAccountSetE164Number (Session *sesn_ptr, unsigned long userid, const char *e164number)
{
	if (*e164number!='*' && likely(strlen(e164number)<=CONFIG_E164_NUMBER_SZ_MAX)) {
		UserPreferenceDescriptor pref = {0};
		const UserPreferenceDescriptor *pref_ptr = GetPrefDescriptorById (PREF_E164NUMBER);
		pref.pref_value_type 			= pref_ptr->pref_value_type;
		pref.pref_name						=	pref_ptr->pref_name;
		pref.value.pref_value_str	=	(char *)e164number;
		if ((DbAccountUserDataUpdatePreference(sesn_ptr, &pref, userid))==0) {
			return 0;
		} else {
			goto return_error;
		}
	} else {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', uname:'%s', e164'%s', key_sz:'%lu'): ERROR: E164NUMBER FORMAT", __func__, pthread_self(), sesn_ptr, SESSION_USERNAME(sesn_ptr), e164number, strlen(e164number));
	}

	return_error:
	return -1;
}

////////// END OF ACCOUNT SIGN ON FUNCTIONS \\\\\\\\\\\\\\\\