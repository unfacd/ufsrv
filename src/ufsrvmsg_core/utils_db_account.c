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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <misc.h>
#include <thread_context_type.h>
#include <utils_db_account.h>
#include <uflib/ufsrvuid.h>
#include <uflib/db/db_sql.h>
#include <json_attribute_names_account.h>

extern __thread ThreadContext ufsrv_thread_context;

/**
 * @brief Retrieve one json attribute from the user's account from toplevel attributes
 * @dynamic_memory upon success, allocates memory for the returned string value, which the user must free
 */
UFSRVResult *
DbAccountDataAttributeGetText(unsigned long userid, const char *attribute_name)
{
  //IMPORTANT: USING JSON_UNQUOTE turns the value from json string,  i.e. "value", to my sql string, i.e. value, but the library then returns blob type,
  //as opposed to string type. Without UNQUOTE we get string type, but we have to remove the opening and closing " manually
#define SQL_SELECT_ACCOUNT_ATTRIBUTE_STRING "SELECT JSON_UNQUOTE(JSON_EXTRACT(data, '$.%s')) FROM accounts WHERE id = %lu"
#define SQL_QUERY_ATTRIBUTE	((struct _h_type_blob *)result.data[0][0].t_data) //if attribute has null data this will be null
#define	SQL_QUERY_ATTRIBUTE_VALUE ((struct _h_type_blob *)result.data[0][0].t_data)->value
#define SQL_QUERY_ATTRIBUTE_VALUE_LENGTH	((struct _h_type_blob *)result.data[0][0].t_data)->length

  struct _h_result result;
  char *sql_query_str;

  sql_query_str = mdsprintf(SQL_SELECT_ACCOUNT_ATTRIBUTE_STRING, attribute_name, userid);

  syslog(LOG_DEBUG, LOGSTR_BACKENDDB_QUERY_STRING, __func__, pthread_self(), NULL, sql_query_str, LOGCODE_BACKENDDB_QUERY_STRING);

  int sql_result = h_query_select(THREAD_CONTEXT_DB_BACKEND, sql_query_str, &result);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, LOGSTR_BACKENDDB_CONNECTION_ERROR, __func__, pthread_self(), NULL, 0UL, sql_query_str, LOGCODE_BACKENDDB_CONNECTION_ERROR);

    free(sql_query_str);

    THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_BACKEND_CONNECTION)
  }

  if (result.nb_rows == 0) {
    syslog(LOG_DEBUG, LOGSTR_BACKENDDB_EMPTY_RESULTSET, __func__, pthread_self(), NULL, 0UL, sql_query_str, LOGCODE_BACKENDDB_EMPTY_RESULTSET);

    h_clean_result(&result);
    free(sql_query_str);

    THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_BACKEND_DATA_EMPTYSET)
  }

  free(sql_query_str);

  const char *attribute_value_returned = NULL;

  if (SQL_QUERY_ATTRIBUTE && SQL_QUERY_ATTRIBUTE_VALUE_LENGTH > 0) {
    attribute_value_returned = strbufdup((char *)SQL_QUERY_ATTRIBUTE_VALUE, SQL_QUERY_ATTRIBUTE_VALUE_LENGTH);

    h_clean_result(&result);

    THREAD_CONTEXT_RETURN_RESULT_SUCCESS((void *)attribute_value_returned, RESCODE_BACKEND_DATA)
  }

  THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_PROG_NULL_POINTER)

#undef 	SQL_SELECT_ACCOUNT_ATTRIBUTE_STRING
#undef 	SQL_QUERY_ATTRIBUTE
#undef	SQL_QUERY_ATTRIBUTE_VALUE
#undef 	SQL_QUERY_ATTRIBUTE_VALUE_LENGTH

}

/**
 * @brief retrieves one json attribute from the user's account from toplevel attributes
 * @dynamic_memory upon success, allocates memory for the returned string value, which the user must free
 */
UFSRVResult *
DbAccountDataUserAttributeGetText(unsigned long userid, const char *attribute_name)
{
  //IMPORTANT: USING JSON_UNQUOTE turns the value from json string,  ie. "value", to my sql string, i.e. value, but the library then returns blob type,
  //as opposed to string type. Without UNQUOTE we get string type, but we have to remove the opening and closing " manually
#define SQL_SELECT_ACCOUNT_ATTRIBUTE_STRING "SELECT JSON_UNQUOTE(JSON_EXTRACT(data_user, '$.%s')) FROM accounts WHERE id = %lu"
#define SQL_QUERY_ATTRIBUTE	((struct _h_type_blob *)result.data[0][0].t_data) //if attribute has null data this will be null
#define	SQL_QUERY_ATTRIBUTE_VALUE ((struct _h_type_blob *)result.data[0][0].t_data)->value
#define SQL_QUERY_ATTRIBUTE_VALUE_LENGTH	((struct _h_type_blob *)result.data[0][0].t_data)->length

  struct _h_result result;
  char *sql_query_str;
  UFSRVResult *res_ptr  = THREAD_CONTEXT_UFSRV_RESULT(ufsrv_thread_context);

  sql_query_str = mdsprintf(SQL_SELECT_ACCOUNT_ATTRIBUTE_STRING, attribute_name, userid);

  syslog(LOG_DEBUG, LOGSTR_BACKENDDB_QUERY_STRING, __func__, pthread_self(), NULL, sql_query_str, LOGCODE_BACKENDDB_QUERY_STRING);

  int sql_result = h_query_select(THREAD_CONTEXT_DB_BACKEND, sql_query_str, &result);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, LOGSTR_BACKENDDB_CONNECTION_ERROR, __func__, pthread_self(), NULL, 0L, sql_query_str, LOGCODE_BACKENDDB_CONNECTION_ERROR);

    free (sql_query_str);

    _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
  }

  if (result.nb_rows == 0) {
    syslog(LOG_DEBUG, LOGSTR_BACKENDDB_EMPTY_RESULTSET, __func__, pthread_self(), NULL, 0L, sql_query_str, LOGCODE_BACKENDDB_EMPTY_RESULTSET);

    h_clean_result(&result);
    free(sql_query_str);

    _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EMPTYSET)
  }

  free(sql_query_str);

  const char *attribute_value_returned = NULL;

  if ((SQL_QUERY_ATTRIBUTE)&&(SQL_QUERY_ATTRIBUTE_VALUE_LENGTH > 0)) {
    attribute_value_returned = strbufdup((char *)SQL_QUERY_ATTRIBUTE_VALUE, SQL_QUERY_ATTRIBUTE_VALUE_LENGTH);

    h_clean_result(&result);

    _RETURN_RESULT_RES(res_ptr, (void *)attribute_value_returned, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)
  }

  _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

#undef 	SQL_SELECT_ACCOUNT_ATTRIBUTE_STRING
#undef 	SQL_QUERY_ATTRIBUTE
#undef	SQL_QUERY_ATTRIBUTE_VALUE
#undef 	SQL_QUERY_ATTRIBUTE_VALUE_LENGTH

}

int
DbAccountUpdateDataByText(const char *data_path, const char *value, unsigned long userid)
{
#define SQL_UPDATE_ACCOUNT_DATA_STRING 	 "UPDATE accounts SET data = JSON_REPLACE(data, '$.%s', '%s') WHERE id='%lu'"

  char *sql_query_str = mdsprintf(SQL_UPDATE_ACCOUNT_DATA_STRING, data_path, value, userid);

#ifdef __UF_FULLDEBUG
  syslog(LOG_DEBUG, "%s (cid='%lu'): GENERATED SQL QUERY: '%s'", __func__, SESSION_ID(sesn_ptr), sql_query_str);
#endif

  int sql_result = h_query_update(THREAD_CONTEXT_DB_BACKEND, sql_query_str);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, "%s: ERROR: COULD EXECUTE QUERY: '%s'", __func__, sql_query_str);
  }

  free(sql_query_str);

  return sql_result;

#undef SQL_UPDATE_ACCOUNT_DATA_STRING
}

int
DbAccountUpdateDataByInt(const char *data_path, int value, unsigned long userid)
{
#define SQL_UPDATE_ACCOUNT_DATA_INT 	 "UPDATE accounts SET data = JSON_REPLACE(data, '$.%s', '%i') WHERE id='%lu'"

  char *sql_query_str = mdsprintf(SQL_UPDATE_ACCOUNT_DATA_INT, data_path, value, userid);

#ifdef __UF_FULLDEBUG
  syslog(LOG_DEBUG, "%s: GENERATED SQL QUERY: '%s'", __func__, sql_query_str);
#endif

  int sql_result = h_query_update(THREAD_CONTEXT_DB_BACKEND, sql_query_str);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, "%s: ERROR: COULD EXECUTE QUERY: '%s'", __func__, sql_query_str);
  }

  free(sql_query_str);

  return sql_result;

#undef SQL_UPDATE_ACCOUNT_DATA_INT
}

int
DbAccountUpdateKbs(KbsDescriptor *kbs_descriptor_ptr, unsigned long userid)
{
#define SQL_UPDATE_ACCOUNT_KBS "UPDATE accounts SET data = JSON_MERGE_PATCH(data, '{\"kbs\":{\"masterkey\":\"%s\", \"argon2_hash\": \"%s\", \"rego_lock\":\"%s\", \"pin\":\"%s\", \"ciphertext\": \"%s\"}}') WHERE id='%lu'"

  char *sql_query_str = mdsprintf(SQL_UPDATE_ACCOUNT_KBS, kbs_descriptor_ptr->masterkey, kbs_descriptor_ptr->hash, kbs_descriptor_ptr->rego_lock, kbs_descriptor_ptr->pin, kbs_descriptor_ptr->ciphertext, userid);

#ifdef __UF_FULLDEBUG
  syslog(LOG_DEBUG, "%s: GENERATED SQL QUERY: '%s'", __func__, sql_query_str);
#endif

  int sql_result = h_query_update(THREAD_CONTEXT_DB_BACKEND, sql_query_str);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, "%s: ERROR: COULD EXECUTE QUERY: '%s'", __func__, sql_query_str);
  }

  free(sql_query_str);

  return sql_result;

#undef SQL_UPDATE_ACCOUNT_KBS
}

int
DbAccountUpdateKbsSansReglock(KbsDescriptor *kbs_descriptor_ptr, unsigned long userid)
{
#define SQL_UPDATE_ACCOUNT_KBS "UPDATE accounts SET data = JSON_MERGE_PATCH(data, '{\"kbs\":{\"masterkey\":\"%s\", \"argon2_hash\": \"%s\", \"pin\":\"%s\", \"ciphertext\": \"%s\"}}') WHERE id='%lu'"

  char *sql_query_str = mdsprintf(SQL_UPDATE_ACCOUNT_KBS, kbs_descriptor_ptr->masterkey, kbs_descriptor_ptr->hash, kbs_descriptor_ptr->pin, kbs_descriptor_ptr->ciphertext, userid);

#ifdef __UF_FULLDEBUG
  syslog(LOG_DEBUG, "%s: GENERATED SQL QUERY: '%s'", __func__, sql_query_str);
#endif

  int sql_result = h_query_update(THREAD_CONTEXT_DB_BACKEND, sql_query_str);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, "%s: ERROR: COULD EXECUTE QUERY: '%s'", __func__, sql_query_str);
  }

  free(sql_query_str);

  return sql_result;

#undef SQL_UPDATE_ACCOUNT_KBS
}

__attribute_const__ const char *
ProvideDefaultKbsTokenForDbAccount()
{
  return "{\"masterkey\":\"\", \"argon2_hash\": \"\", \"rego_lock\":\"\", \"pin\":\"\", \"ciphertext\":\"\"}";
}

/**
 * @brief Construct a binary json object representing default values for kbs.
 * @return on success allocated json_object *, otherwise NULL
 * @dynamic_memory EXPORTS 'json_object *'
 */
json_object *
ProvideDefaultKbsJsonToken()
{
  json_object *jobj_kbs = NULL;
  const char *json_str_kbs = ProvideDefaultKbsTokenForDbAccount();

  enum json_tokener_error jerr;
  struct json_tokener *jtok = json_tokener_new();

  do {
    jobj_kbs = json_tokener_parse_ex(jtok, json_str_kbs, strlen(json_str_kbs));
  } while ((jerr = json_tokener_get_error(jtok)) == json_tokener_continue);

  if (jerr != json_tokener_success) {
    syslog(LOG_NOTICE, "%s {pid:'%lu', json:'%s'}: JSON tokeniser Error: '%s'...", __func__, pthread_self(), json_tokener_error_desc(jerr), json_str_kbs);

    return NULL;
  }

  tokeniser_success:
  json_tokener_free(jtok);
  return jobj_kbs;
}

static json_object *_TransformKbsJsonObject(const char *json_str_kbs, bool is_struct_transfer, KbsDescriptor *kbs_descriptor_ptr_out);

/**
 * @brief A utility function to retrieve and transform db stored kbs token.
 * @param json_str_kbs[in] serialised json
 * @param is_struct_transfer is set, json values will be transferred to KbsDescriptor by 'copy'
 * @param kbs_descriptor_ptr_out[inout] Data structure representing stored KBS values
 * @return Allocated raw json object representing supplied serialised json
 * @dynamic_memory EXPORTS 'char *' into KbsDescriptor members
 */
static json_object *
_TransformKbsJsonObject(const char *json_str_kbs, bool is_struct_transfer, KbsDescriptor *kbs_descriptor_ptr_out)
{
  struct json_object *jobj_kbs = NULL;

  syslog(LOG_DEBUG, "%s {pid:'%lu', json:'%s'}: Account: KBS token...", __func__, pthread_self(), json_str_kbs);

  enum json_tokener_error jerr;
  struct json_tokener *jtok = json_tokener_new();

  do {
    jobj_kbs = json_tokener_parse_ex(jtok, json_str_kbs, strlen(json_str_kbs));
  } while ((jerr = json_tokener_get_error(jtok)) == json_tokener_continue);

  if (jerr != json_tokener_success) {
    syslog(LOG_NOTICE, "%s {pid:'%lu', json:'%s'}: JSON tokeniser Error: '%s'...", __func__, pthread_self(), json_tokener_error_desc(jerr), json_str_kbs);

    return NULL;
  }

  tokeniser_success:
  json_tokener_free(jtok);

  if (is_struct_transfer && IS_PRESENT(kbs_descriptor_ptr_out)) {
    const char *stored_value = json_object_get_string(json__get(jobj_kbs, "masterkey"));
    if (IS_STR_LOADED(stored_value)) kbs_descriptor_ptr_out->masterkey = strdup(stored_value);
    stored_value = json_object_get_string(json__get(jobj_kbs, "argon2_hash"));
    if (IS_STR_LOADED(stored_value)) kbs_descriptor_ptr_out->hash = strdup(stored_value);
    stored_value = json_object_get_string(json__get(jobj_kbs, "rego_lock"));
    if (IS_STR_LOADED(stored_value)) kbs_descriptor_ptr_out->rego_lock = strdup(stored_value);
    stored_value = json_object_get_string(json__get(jobj_kbs, "pin"));
    if (IS_STR_LOADED(stored_value)) kbs_descriptor_ptr_out->pin = strdup(stored_value);
    stored_value = json_object_get_string(json__get(jobj_kbs, "ciphertext"));
    if (IS_STR_LOADED(stored_value)) kbs_descriptor_ptr_out->ciphertext = strdup(stored_value);
    kbs_descriptor_ptr_out->is_struct_transfer = true;
  }

  return jobj_kbs;
}

/**
 * @brief Retrieve stored KBS values for a given account.
 * @param userid account identification as a sequence id
 * @param is_struct_transfer is set, json values will be transferred to the KbsDescriptor member fields by dynamic memory copy
 * @param is_serialised if set, the serialised json token as stored in the db is returned in KbsDescriptor.serialised
 * @param is_raw if set, the raw json object successfully parsed from copy as stored in the db is returned in KbsDescriptor.raw
 * @param kbs_descriptor_ptr_out[inout] User-allocated return structure, If not provided, a dynamic memory allocation will be used
 * @return KbsDescriptor on success, otherwise NULL
 * @dynamic_memory EXPORTS 'char *'  is_serialised or KbsDescriptor.serialised if either or both true
 * @dynamic_memory EXPORTS 'json_object *'  is_raw KbsDescriptor.raw if either or both true
 * @dynamic_memory EXPORTS 'KbsDescriptor *'  if kbs_descriptor_ptr_out is not provided by caller
 * @dynamic_memory EXPORTS 'char *' KbsDescriptor member fields
 */
KbsDescriptor *
DbAccountGetKbs(unsigned long userid, bool is_struct_transfer, bool is_serialised, bool is_raw, KbsDescriptor *kbs_descriptor_ptr_out)
{
  KbsDescriptor *kbs_descriptor_ptr = NULL;

  if (IS_PRESENT(kbs_descriptor_ptr_out)) kbs_descriptor_ptr = kbs_descriptor_ptr_out;
  else {
    kbs_descriptor_ptr = calloc(1, sizeof(KbsDescriptor));
  }

  DbAccountDataUserAttributeGetText(userid, "kbs");
  if (THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA) {
    json_object *jobj_kbs = _TransformKbsJsonObject((char *) THREAD_CONTEXT_UFSRV_RESULT_USERDATA, is_struct_transfer, kbs_descriptor_ptr);
    if (IS_PRESENT(jobj_kbs)) { //successfully retrieved and tokenised
      if (is_serialised) {
        kbs_descriptor_ptr->serialised.jobj_str = THREAD_CONTEXT_UFSRV_RESULT_USERDATA;
        kbs_descriptor_ptr->serialised.is_set = true;
      } else {
        free(THREAD_CONTEXT_UFSRV_RESULT_USERDATA);
        kbs_descriptor_ptr->serialised.is_set = false;
      }

      if (is_raw) {
        kbs_descriptor_ptr->raw.jobj = jobj_kbs;
        kbs_descriptor_ptr->raw.is_set = true;
      } else {
        json_object_put(jobj_kbs);
        kbs_descriptor_ptr->raw.is_set = false;
      }

      return kbs_descriptor_ptr;
    }
  }

  return_error:
  if (IS_EMPTY(kbs_descriptor_ptr_out)) free(kbs_descriptor_ptr);
  return NULL;
}

/// donations
#include "donations/donation_descriptor_type.h"

//


static __attribute_const__ const char *
_ProvideDefaultProfilePersonalForDbAccount()
{
  return "{\"firstname\":\"*\", \"lastname\": \"*\", \"about\":\"*\"}";
}

/**
 * @brief Construct a binary json object representing default values for user personal profile data.
 * @return on success allocated json_object *, otherwise NULL
 * @dynamic_memory EXPORTS 'json_object *'
 */
json_object *
ProvideDefaultProfilePersonalJsonToken()
{
  json_object *jobj_kbs = NULL;
  const char *json_str_kbs = _ProvideDefaultProfilePersonalForDbAccount();

  enum json_tokener_error jerr;
  struct json_tokener *jtok = json_tokener_new();

  do {
    jobj_kbs = json_tokener_parse_ex(jtok, json_str_kbs, strlen(json_str_kbs));
  } while ((jerr = json_tokener_get_error(jtok)) == json_tokener_continue);

  if (jerr != json_tokener_success) {
    syslog(LOG_NOTICE, "%s {pid:'%lu', json:'%s'}: JSON tokeniser Error: '%s'...", __func__, pthread_self(), json_tokener_error_desc(jerr), json_str_kbs);

    return NULL;
  }

  tokeniser_success:
  json_tokener_free(jtok);
  return jobj_kbs;
}

static struct json_object *_DBAccountRetrieveJsonTransformDataStore(const char *query_str);
static json_object *_DbGetAccountDataInJson(const char *data_store, unsigned long userid);

/**
 * @brief Utility function for retrieving account information from the 'data' store
 * @param uid_ptr[in] user identifier
 * @return json_object * raw json representation of store information
 */
struct json_object *
DbGetAccountInJson(const UfsrvUid *uid_ptr)
{
  return _DbGetAccountDataInJson("data", UfsrvUidGetSequenceId(uid_ptr));
}

/**
 * @brief Utility function for retrieving account information from the 'data_user' store
 * @param uid_ptr[in] user identifier
 * @return json_object * raw json representation of store information
 */
struct json_object *
DbGetAccountUserDataInJson(const UfsrvUid *uid_ptr)
{
  return _DbGetAccountDataInJson("data_user", UfsrvUidGetSequenceId(uid_ptr));
}


struct json_object *
DbGetAccountInJsonByUserId(unsigned long userid)
{
  return _DbGetAccountDataInJson("data", userid);
}

/**
 * @brief Retrieves the json 'account user-data' record associated with userid.
 * @param userid Numerical userid identifying a user record
 * @return Binary json object
 */
struct json_object *
DbGetAccountUserDataInJsonByUserId(unsigned long userid)
{
  return _DbGetAccountDataInJson("data_user", userid);
}

/**
 * @brief Prepare the query string for retrieving account information based on predefined data store.
 * @param data_store Predefined data store names: 'data', 'data_user'
 * @param userid sequence user id
 * @return Preallocated json_object *
 */
static struct json_object *
_DbGetAccountDataInJson(const char *data_store, unsigned long userid)
{
#define SQL_GET_ACCOUNT_DATA "SELECT %s FROM accounts WHERE id='%lu'"

  char *sql_query_str			=	NULL;

  sql_query_str = mdsprintf(SQL_GET_ACCOUNT_DATA, data_store, userid);

#ifdef __UF_FULLDEBUG
  syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu'): GENERATED SQL QUERY: '%s'", __func__,  pthread_self(), SESSION_ID(sesn_ptr), sql_query_str);
#endif

  json_object *jobj = _DBAccountRetrieveJsonTransformDataStore(sql_query_str);
  free(sql_query_str);

  return jobj;

#undef SQL_GET_ACCOUNT_DATA

}

/**
 *  @brief: Retrieve the json 'account data' associated with userid from a given data store.
 *
 *  @dynamic_memory json_object *: ALLOCATES a jobj objects instantiated form backend data. caller responsible for freeing.
 */
/*static struct json_object *
_DbGetAccountDataInJsonByUserId(const char *data_store, unsigned long userid)
{
#define SQL_GET_ACCOUNT_DATA "SELECT %s FROM accounts WHERE id=%lu"
  char *sql_query_str			=	NULL;

  sql_query_str = mdsprintf(SQL_GET_ACCOUNT_DATA, data_store, userid);

#ifdef __UF_FULLDEBUG
  syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu'): GENERATED SQL QUERY: '%s'", __func__,  pthread_self(), SESSION_ID(sesn_ptr), sql_query_str);
#endif

  json_object *jobj = _DBAccountRetrieveJsonTransformDataStore(sql_query_str);
  free (sql_query_str);

#ifdef __UF_FULLDEBUG
  syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: GENERATED json str: '%s'", __func__,  pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), json_object_to_json_string(jobj));
#endif

  return jobj;

#undef SQL_GET_ACCOUNT_DATA

}*/

/**
 * @brief Transform a singular raw db record into a binary json object. db record must hold data natively in json.
 * @param query_str[in] pre-constructed query string that returns a record natively stored as json
 * @return Allocated json object
 * @dynamic_memory: ALLOCATES json_object *
 */
static struct json_object *
_DBAccountRetrieveJsonTransformDataStore(const char *query_str)
{
  struct _h_result result	=	{0};

  int sql_result = h_query_select(THREAD_CONTEXT_DB_BACKEND, query_str, &result);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, "%s (pid:'%lu'): ERROR: COULD NOT EXECUTE QUERY: '%s'", __func__, pthread_self(), query_str);

    return NULL;
  }

  if (result.nb_rows == 0) {
    syslog(LOG_DEBUG, "%s (pid:'%lu'): ERROR: COULD FIND CORRESPONDING DB RECORD", __func__, pthread_self());

    h_clean_result(&result);

    return NULL;
  }

  const char *account_data_json_str = NULL;
  if (((struct _h_type_blob *)result.data[0][0].t_data)->value) {
    account_data_json_str = strndupa((char *)(((struct _h_type_blob *)result.data[0][0].t_data)->value), ((struct _h_type_blob *)result.data[0][0].t_data)->length);
  } else {
    syslog(LOG_NOTICE, "%s (pid:'%lu', data_sz:'%lu'): ERROR: JSON BLOB PAYLOAD ERROR...", __func__, pthread_self(), ((struct _h_type_blob *)result.data[0][0].t_data)->length);

    h_clean_result(&result);

    return NULL;
  }

#ifdef __UF_FULLDEBUG
  syslog(LOG_DEBUG, "%s (pid:'%lu': RETRIEVED JSON ACCOUNT DATA: '%s'",  __func__, pthread_self(), account_data_json_str);
#endif

  //start of json tokeniser block
  {
    enum json_tokener_error jerr;
    struct json_tokener *jtok;
    struct json_object *jobj_account = NULL;

    jtok = json_tokener_new();

    do {
      jobj_account = json_tokener_parse_ex(jtok, account_data_json_str, strlen(account_data_json_str));
    } while ((jerr = json_tokener_get_error(jtok)) == json_tokener_continue);

    if (jerr != json_tokener_success) {
      syslog(LOG_NOTICE, "%s (pid:'%lu'): JSON tokeniser Error: '%s'. Terminating.", __func__, pthread_self(), json_tokener_error_desc(jerr));

      h_clean_result(&result);

      json_tokener_free(jtok);

      return NULL;
    }

    json_tokener_free(jtok);

    h_clean_result(&result);

    return jobj_account;
  }//end of json tokeniser

  return NULL;

}

/**
 * @brief Retrieve the two know data stores for user and transform results into raw json. DB records must stored natively in json.
 * @param query_str[in] pre-constructed query string that returns a record natively stored as json
 * @return Allocated json object
 * @dynamic_memory: ALLOCATES json_object *
 */
__unused static struct json_object *
_DBAccountRetrieveJsonTransformAllDataStore(const char *query_str)
{
  struct _h_result result	=	{0};

  int sql_result = h_query_select(THREAD_CONTEXT_DB_BACKEND, query_str, &result);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, "%s (pid:'%lu'): ERROR: COULD NOT EXECUTE QUERY: '%s'", __func__, pthread_self(), query_str);

    return NULL;
  }

  if (result.nb_rows == 0) {
    syslog(LOG_DEBUG, "%s (pid:'%lu'): ERROR: COULD FIND CORRESPONDING DB RECORD", __func__, pthread_self());

    h_clean_result(&result);

    return NULL;
  }

  const char *account_data_json_str = NULL;
  __unused const char *account_data_user_json_str = NULL;

  if ((((struct _h_type_blob *)result.data[0][0].t_data)->value) && (((struct _h_type_blob *)result.data[0][1].t_data)->value)) {
    account_data_json_str       = strndupa((char *)(((struct _h_type_blob *)result.data[0][0].t_data)->value), ((struct _h_type_blob *)result.data[0][0].t_data)->length);
    account_data_user_json_str  = strndupa((char *)(((struct _h_type_blob *)result.data[0][1].t_data)->value), ((struct _h_type_blob *)result.data[0][1].t_data)->length);
  } else {
    syslog(LOG_NOTICE, "%s (pid:'%lu', data_sz:'%lu', data_user_sz:'%lu'): ERROR: JSON BLOB PAYLOAD ERROR...", __func__, pthread_self(), ((struct _h_type_blob *)result.data[0][0].t_data)->length, ((struct _h_type_blob *)result.data[0][1].t_data)->length);

    h_clean_result(&result);

    return NULL;
  }

#ifdef __UF_FULLDEBUG
  syslog(LOG_DEBUG, "%s (pid:'%lu': RETRIEVED JSON ACCOUNT DATA: '%s'",  __func__, pthread_self(), account_data_json_str);
#endif

  //start of json tokeniser block
  {
    enum json_tokener_error jerr;
    struct json_tokener *jtok;
    struct json_object *jobj_account = NULL;

    jtok = json_tokener_new();

    do {
      jobj_account = json_tokener_parse_ex(jtok, account_data_json_str, strlen(account_data_json_str));
    } while ((jerr = json_tokener_get_error(jtok)) == json_tokener_continue);

    if (jerr != json_tokener_success) {
      syslog(LOG_NOTICE, "%s (pid:'%lu'): JSON tokeniser Error: '%s'. Terminating.", __func__, pthread_self(), json_tokener_error_desc(jerr));

      h_clean_result(&result);

      json_tokener_free(jtok);

      return NULL;
    }

    json_tokener_free(jtok);

    h_clean_result(&result);

    return jobj_account;
  }//end of json tokeniser

  return NULL;

}