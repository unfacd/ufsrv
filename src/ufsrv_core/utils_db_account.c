/**
 * Copyright (C) 2015-2020 unfacd works
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
#include <thread_context_type.h>
#include <utils_db_account.h>
#include <uflib/db/db_sql.h>

extern __thread ThreadContext ufsrv_thread_context;

/**
 * @brief: retrieves one json attribute from the user's account from toplevel attributes
 * @dynamic_memory: upon success, allocates memory for the returned string value, which the user must free
 */
UFSRVResult *
DbAccountDataAttributeGetText(Session *sesn_ptr, unsigned long userid, const char *attribute_name)
{
  //IMPORTANT: USING JSON_UNQUOTE turns the value from json string,  ie. "value", to my sql string, i.e. value, but the library then returns blob type,
  //as opposed to string type. Without UNQUOTE we get string type, but we have to remove the opening and closing " manually
#define SQL_SELECT_ACCOUNT_ATTRIBUTE_STRING "SELECT  JSON_UNQUOTE(JSON_EXTRACT(data, '$.%s')) FROM accounts WHERE id = %lu"
#define SQL_QUERY_ATTRIBUTE	((struct _h_type_blob *)result.data[0][0].t_data) //if attribute has null data this will be null
#define	SQL_QUERY_ATTRIBUTE_VALUE ((struct _h_type_blob *)result.data[0][0].t_data)->value
#define SQL_QUERY_ATTRIBUTE_VALUE_LENGTH	((struct _h_type_blob *)result.data[0][0].t_data)->length

  struct _h_result result;
  char *sql_query_str;

  sql_query_str = mdsprintf(SQL_SELECT_ACCOUNT_ATTRIBUTE_STRING, attribute_name, userid);

  syslog(LOG_DEBUG, LOGSTR_BACKENDDB_QUERY_STRING, __func__, pthread_self(), sesn_ptr, sql_query_str, LOGCODE_BACKENDDB_QUERY_STRING);

  int sql_result = h_query_select(sesn_ptr->db_backend, sql_query_str, &result);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, LOGSTR_BACKENDDB_CONNECTION_ERROR, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str, LOGCODE_BACKENDDB_CONNECTION_ERROR);

    free(sql_query_str);

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_CONNECTION)
  }

  if (result.nb_rows == 0) {
    syslog(LOG_DEBUG, LOGSTR_BACKENDDB_EMPTY_RESULTSET, __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), sql_query_str, LOGCODE_BACKENDDB_EMPTY_RESULTSET);

    h_clean_result(&result);
    free(sql_query_str);

    _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EMPTYSET)
  }

  free (sql_query_str);

  const char *attribute_value_returned = NULL;

  if (SQL_QUERY_ATTRIBUTE && SQL_QUERY_ATTRIBUTE_VALUE_LENGTH > 0) {
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
 * @brief: retrieves one json attribute from the user's account from toplevel attributes
 * @dynamic_memory: upon success, allocates memory for the returned string value, which the user must free
 */
UFSRVResult *
DbAccountDataUserAttributeGetText(Session *sesn_ptr, unsigned long userid, const char *attribute_name)
{
  //IMPORTANT: USING JSON_UNQUOTE turns the value from json string,  ie. "value", to my sql string, i.e. value, but the library then returns blob type,
  //as opposed to string type. Without UNQUOTE we get string type, but we have to remove the opening and closing " manually
#define SQL_SELECT_ACCOUNT_ATTRIBUTE_STRING "SELECT  JSON_UNQUOTE(JSON_EXTRACT(data_user, '$.%s')) FROM accounts WHERE id=%lu"
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
    free (sql_query_str);

    _RETURN_RESULT_RES(res_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA_EMPTYSET)
  }

  free (sql_query_str);

  const char *attribute_value_returned = NULL;

  if ((SQL_QUERY_ATTRIBUTE)&&(SQL_QUERY_ATTRIBUTE_VALUE_LENGTH > 0)) {
    attribute_value_returned = strndup((char *)SQL_QUERY_ATTRIBUTE_VALUE, SQL_QUERY_ATTRIBUTE_VALUE_LENGTH);

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
DbAccountUpdateData(Session *sesn_ptr, const char *data_path, const char *value, unsigned long userid)
{
#define SQL_UPDATE_ACCOUNT_DATA_STRING 	 "UPDATE accounts SET data = JSON_REPLACE(data, '$.%s', '%s') WHERE id='%lu'"

  char *sql_query_str;

  sql_query_str = mdsprintf(SQL_UPDATE_ACCOUNT_DATA_STRING, data_path, value, userid);

#ifdef __UF_FULLDEBUG
  syslog(LOG_DEBUG, "%s (cid='%lu'): GENERATED SQL QUERY: '%s'", __func__, SESSION_ID(sesn_ptr), sql_query_str);
#endif

  int sql_result = h_query_update(sesn_ptr->db_backend, sql_query_str);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, "%s (cid='%lu'): ERROR: COULD EXECUTE QUERY: '%s'", __func__, SESSION_ID(sesn_ptr), sql_query_str);
  }

  free (sql_query_str);

  return sql_result;

#undef SQL_UPDATE_ACCOUNT_DATA_STRING
}

static struct json_object *_DBAccountDataGenerateJson(Session *sesn_ptr, const char *query_str);

struct json_object *
DbGetAccountInJson(Session *sesn_ptr, const UfsrvUid *uid_ptr)
{
  return DbGetAccountDataInJson(sesn_ptr, "data", UfsrvUidGetSequenceId(uid_ptr));
}

struct json_object *
DbGetAccountUserDataInJson(Session *sesn_ptr, const UfsrvUid *uid_ptr)
{
  return DbGetAccountDataInJson(sesn_ptr, "data_user", UfsrvUidGetSequenceId(uid_ptr));
}

struct json_object *
DbGetAccountDataInJson(Session *sesn_ptr, const char *data_store, unsigned long userid)
{
#define SQL_GET_ACCOUNT_DATA "SELECT %s FROM accounts WHERE id='%lu'"
  char *sql_query_str			=	NULL;

  sql_query_str = mdsprintf(SQL_GET_ACCOUNT_DATA, data_store, userid);

#ifdef __UF_FULLDEBUG
  syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu'): GENERATED SQL QUERY: '%s'", __func__,  pthread_self(), SESSION_ID(sesn_ptr), sql_query_str);
#endif

  json_object *jobj = _DBAccountDataGenerateJson(sesn_ptr, sql_query_str);
  free (sql_query_str);

  return jobj;

#undef SQL_GET_ACCOUNT_DATA

}

struct json_object *
DbGetAccountInJsonByUserId(Session *sesn_ptr, unsigned long userid)
{
  return DbGetAccountDataInJsonByUserId(sesn_ptr, "data", userid);
}

struct json_object *
DbGetAccountUserDataInJsonByUserId(Session *sesn_ptr, unsigned long userid)
{
  return DbGetAccountDataInJsonByUserId(sesn_ptr, "data_user", userid);
}

/**
 *  @brief: retrieves the json data object associated with userid.
 *
 *  @dynamic_memory jobj: ALLOCATES a jobj objects instantiated form backend data. caller responsible for freeing.
 */
struct json_object *
DbGetAccountDataInJsonByUserId(Session *sesn_ptr, const char *data_store, unsigned long userid)
{
#define SQL_GET_ACCOUNT_DATA "SELECT %s FROM accounts WHERE id=%lu"
  char *sql_query_str			=	NULL;

  sql_query_str = mdsprintf(SQL_GET_ACCOUNT_DATA, data_store, userid);

#ifdef __UF_FULLDEBUG
  syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu'): GENERATED SQL QUERY: '%s'", __func__,  pthread_self(), SESSION_ID(sesn_ptr), sql_query_str);
#endif

  json_object *jobj = _DBAccountDataGenerateJson(sesn_ptr, sql_query_str);
  free (sql_query_str);

#ifdef __UF_FULLDEBUG
  syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: GENERATED json str: '%s'", __func__,  pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), json_object_to_json_string(jobj));
#endif

  return jobj;

#undef SQL_GET_ACCOUNT_DATA

}

static struct json_object *
_DBAccountDataGenerateJson (Session *sesn_ptr, const char *query_str)
{
  struct _h_result result	=	{0};

  int sql_result = h_query_select(THREAD_CONTEXT_DB_BACKEND, query_str, &result);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu'): ERROR: COULD NOT EXECUTE QUERY: '%s'", __func__, pthread_self(), SESSION_ID(sesn_ptr), query_str);

    return NULL;
  }

  if (result.nb_rows == 0) {
    syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu'): ERROR: COULD FIND CORRESPONDING DB RECORD", __func__, pthread_self(), SESSION_ID(sesn_ptr));

    h_clean_result(&result);

    return NULL;
  }

  const char *account_data_json_str = NULL;
  if (((struct _h_type_blob *)result.data[0][0].t_data)->value) {
    account_data_json_str=strndupa((char *)(((struct _h_type_blob *)result.data[0][0].t_data)->value), ((struct _h_type_blob *)result.data[0][0].t_data)->length);
  } else {
    syslog(LOG_NOTICE, "%s (pid:'%lu' cid:'%lu', data_sz:'%lu'): ERROR: JSON BLOB PAYLOAD ERROR...", __func__, pthread_self(), SESSION_ID(sesn_ptr), ((struct _h_type_blob *)result.data[0][0].t_data)->length);

    h_clean_result(&result);

    return NULL;
  }

#ifdef __UF_FULLDEBUG
  syslog(LOG_DEBUG, "%s (pid:'%lu', cid:'%lu'): RETRIEVED JSON ACCOUNT DATA: '%s'",  pthread_self(), __func__, SESSION_ID(sesn_ptr), account_data_json_str);
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
      syslog(LOG_NOTICE, "%s (pid:'%lu' cid:'%lu'): JSON tokeniser Error: '%s'. Terminating.", __func__, pthread_self(), SESSION_ID(sesn_ptr), json_tokener_error_desc(jerr));

      h_clean_result(&result);

      json_tokener_free(jtok);

      return NULL;
    }

    json_tokener_free(jtok);

    h_clean_result(&result);

    return jobj_account;
  }//end of json tokeniser

  return NULL;

  on_successfull_result:
  h_clean_result(&result);

}
