/**
 * Copyright (C) 2015-2024 unfacd works
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
#include <fence/fence_utils_db.h>
#include <fence/fence.h>
#include <uflib/recycler/recycler.h>
#include <uflib/db/dp_ops.h>
#include <json_attribute_names_fence.h>

extern __thread ThreadContext ufsrv_thread_context;

static UFSRVResult *_DbBackendGetFenceDataNamedAttributes(DbOpDescriptor *dbop_descriptor);
static char *_FenceDataDbOpQueryProvider(intptr_t values[static 1]);
static int _FenceDataDbOpTransformer(DbOpDescriptor *dbop_descriptor);

/**
 * @brief Load the value for fence description as freshly fetched form the db backend.
 *
 * User is responsbile for deallocatin old descripttion value if present in Fence object @param f_ptr_instance.
 * @return Direct return from the function performing db query.
 */
UFSRVResult *
DbBackendLoadFenceDescription(InstanceHolderForFence *f_ptr_instance)
{
  Fence *f_ptr                    = FenceOffInstanceHolder(f_ptr_instance);
  DbOpDescriptor db_op_descriptor = {.ctx_data=f_ptr_instance};
  db_op_descriptor.transformer.on_transform = ^(DbOpDescriptor *dbop_descriptor) {
#define COLUMN_PREFS_ATTRIBUTE_VALUE	((struct _h_type_blob *)result->data[0][0].t_data)->value
#define COLUMN_PREFS_ATTRIBUTE_VALUE_LEN (((struct _h_type_blob *)result->data[0][0].t_data)->length)

      struct _h_result *result = &dbop_descriptor->result;
      if (!IS_EMPTY(result->data[0]->t_data)) { //if stored json payload doesn't have the queried attribute we get a null record, not error.
        Fence *f_ptr_loaded = FenceOffInstanceHolder(dbop_descriptor->ctx_data);
        if (*(const char *) COLUMN_PREFS_ATTRIBUTE_VALUE == CONFIG_DEFAULT_PREFS_CHAR_VALUE) {
          FENCE_DESCRIPTION(f_ptr_loaded) = NULL;
        } else {
          FENCE_DESCRIPTION(f_ptr_loaded) = strbufdup(COLUMN_PREFS_ATTRIBUTE_VALUE, COLUMN_PREFS_ATTRIBUTE_VALUE_LEN);
        }
      }
      return 0;

#undef COLUMN_PREFS_ATTRIBUTE_VALUE
#undef COLUMN_PREFS_ATTRIBUTE_VALUE_LEN
  };

  return DbBackendGetFenceDataNamedAttribute(FENCE_ID(f_ptr), FENCE_JSONATTR_DESCRIPTION, &db_op_descriptor, CALLFLAGS_EMPTY);

}

/** \addtogroup fence_db_data_get
*  Implement interface for querying fence stored json attributes
*  @{
*/

/**
 * @brief Retrieve a singular named attribute from a Fence's json data structure as stored in the db.
 *
 * A generalised retriever for fence named attributes as stored in the db. The user may optionally pass a pre-allocated Fence object
 * or rely on the function to do so, in which case @param call_flags must defined minimally with fence type FENCE_CALLFLAG_BASEFENCE or FENCE_CALLFLAG_USERFENCE
 * @param fid[in] Fence id
 * @param attribute_name[in] a recognised fence attribute name
 * @param db_descriptor[inout] pre-allocated descriptor
 * @param call_flags[in] Fence creation call-flags to be used with Fence instantiation
 * @return \ref UFSRVResult *
 */
UFSRVResult *
DbBackendGetFenceDataNamedAttribute(unsigned long fid, const char *attribute_name, DbOpDescriptor *db_descriptor, unsigned long call_flags)
{
  InstanceHolderForFence *instance_f_ptr = NULL;
  if (IS_EMPTY(db_descriptor->ctx_data)) {
    if (call_flags == 0) {//todo 7/19/24 devops: this callflag check is not strong enough
      syslog(LOG_DEBUG, "%s (pid:'%lu', fid:'%lu', attr_name:'%s'): ERROR: CALLFLAGS MISSING AND NO CONTEXT DATA PROVIDED", __func__, pthread_self(), fid, attribute_name);
      return NULL;
    }

    instance_f_ptr = RecyclerGet(FencePoolTypeNumber(), NULL, call_flags);
    if (unlikely(IS_EMPTY(instance_f_ptr))) {
      syslog(LOG_DEBUG, LOGSTR_INCONSISTENT_STATE, __func__, pthread_self(), NULL, 0UL, LOGCODE_PROTO_INCONSISTENT_STATE, "Could not get Fence *");

      return NULL;
    }
    db_descriptor->ctx_data = CLIENT_CTX_DATA(instance_f_ptr);
  } else {
    instance_f_ptr = (InstanceHolderForSession *)db_descriptor->ctx_data;
  }

  db_descriptor->transformer.transform = _FenceDataDbOpTransformer;
//  db_descriptor->finaliser.finalise    = GetDefaultDbOpResultFinaliser();//don't set it, otherwise it will be automatically called after transformation

  db_descriptor->query_statement_provider.provide = _FenceDataDbOpQueryProvider;
  db_descriptor->query_statement_provider.values  = (intptr_t[]){DBOP_QUERY_PROVIDER_VALUE(attribute_name), DBOP_QUERY_PROVIDER_VALUE(fid), 0};
  db_descriptor->query_statement_provider.finalise = GetDefaultQueryStatementProviderFinalser();

  _DbBackendGetFenceDataNamedAttributes(db_descriptor);
  if (THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA) {
    db_descriptor->finaliser.finalise = GetDefaultDbOpResultFinaliser();
  }

  return THREAD_CONTEXT_UFSRV_RESULT_PTR;
}

static UFSRVResult *
_DbBackendGetFenceDataNamedAttributes(DbOpDescriptor *dbop_descriptor)
{
  GetDbResultForQuery(THREAD_CONTEXT_DB_BACKEND, dbop_descriptor);
  return ReturnUfsrvResultFromDbOpDescriptor(dbop_descriptor);
}

static char *
_FenceDataDbOpQueryProvider(intptr_t values[static 1])
{
#define SQL_SELECT_FENCE_DATA_ATTRIBUTE_STRING "SELECT  JSON_UNQUOTE(JSON_EXTRACT(data, '$.%s')) FROM fences WHERE fid=%lu"
  char *sql_query_str = mdsprintf(SQL_SELECT_FENCE_DATA_ATTRIBUTE_STRING, (char *)values[0], (unsigned long)values[1]);

  return sql_query_str;
#undef SQL_SELECT_FENCE_DATA_ATTRIBUTE_STRING
}

/**
 * Standard by-ref transformer for stored  account values
 * @param dbop_descriptor
 * @return
 */
static int
_FenceDataDbOpTransformer(DbOpDescriptor *dbop_descriptor)
{
  //invoke the closure. This is an extra indirection, locally
  //todo 7/20/24 devops: closure invocation should be called by the driver, not locally like this
  __unused struct _h_result *result = &dbop_descriptor->result;

  if (IS_PRESENT(dbop_descriptor->transformer.on_transform)) return dbop_descriptor->transformer.on_transform(dbop_descriptor);

  return 0;
}
/** @} */

/** \addtogroup fence_db_data_update
*  Implement interface for updating fence stored json attributes
*  @{
*/
static char *_FenceDataDbOpUpdateProvider(intptr_t values[static 1]);
static UFSRVResult *_DbBackendUpdateFenceDataNamedAttributes(DbOpDescriptor *dbop_descriptor);

UFSRVResult *
DbBackendUpdateFenceDataNamedAttribute(unsigned long fid, const char *attribute_name, const char *attribute_value, DbOpDescriptor *db_descriptor, __unused unsigned long call_flags)
{
  db_descriptor->transformer.transform = NULL;
  db_descriptor->finaliser.finalise = NULL;
  db_descriptor->query_statement_provider.provide = _FenceDataDbOpUpdateProvider;
  db_descriptor->query_statement_provider.values  = (intptr_t[]){DBOP_QUERY_PROVIDER_VALUE(attribute_name), DBOP_QUERY_PROVIDER_VALUE(attribute_value), DBOP_QUERY_PROVIDER_VALUE(fid), 0};
  db_descriptor->query_statement_provider.finalise = GetDefaultQueryStatementProviderFinalser();

  _DbBackendUpdateFenceDataNamedAttributes(db_descriptor);
  if (THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_EMPTYSET_DATA) {
    //NOOP
  }

  return THREAD_CONTEXT_UFSRV_RESULT_PTR;
}

static UFSRVResult *
_DbBackendUpdateFenceDataNamedAttributes(DbOpDescriptor *dbop_descriptor)
{
  GetDbResultForUpdate(THREAD_CONTEXT_DB_BACKEND, dbop_descriptor);
  return ReturnUfsrvResultFromDbOpDescriptor(dbop_descriptor);
}

static char *
_FenceDataDbOpUpdateProvider(intptr_t values[static 1])
{
#define SQL_UPDATE_FENCE_DATA_ATTRIBUTE_STRING "UPDATE fences SET data = JSON_REPLACE(data, '$.%s', '%s') WHERE fid = %lu"
  char *sql_query_str = mdsprintf(SQL_UPDATE_FENCE_DATA_ATTRIBUTE_STRING, (char *)values[0], (char *)values[1], (unsigned long)values[1]);

  return sql_query_str;
#undef SQL_UPDATE_FENCE_DATA_ATTRIBUTE_STRING
}
/** @} */

//TBD
__unused UFSRVResult * __attribute__((deprecated()))
DbFenceDataAttributeGetText(unsigned long fid, const char *attribute_name)
{
  //IMPORTANT: USING JSON_UNQUOTE turns the value from json string,  ie. "value", to my sql string, i.e. value, but the library then returns blob type,
  //as opposed to string type. Without UNQUOTE we get string type, but we have to remove the opening and closing " manually
#define SQL_SELECT_ACCOUNT_ATTRIBUTE_STRING "SELECT JSON_UNQUOTE(JSON_EXTRACT(data, '$.%s')) FROM fences WHERE fid=%lu"
#define SQL_QUERY_ATTRIBUTE	((struct _h_type_blob *)result.data[0][0].t_data) //if attribute has null data this will be null
#define	SQL_QUERY_ATTRIBUTE_VALUE ((struct _h_type_blob *)result.data[0][0].t_data)->value
#define SQL_QUERY_ATTRIBUTE_VALUE_LENGTH	((struct _h_type_blob *)result.data[0][0].t_data)->length

  struct _h_result result;
  char *sql_query_str;
  UFSRVResult *res_ptr  = THREAD_CONTEXT_UFSRV_RESULT(ufsrv_thread_context);

  sql_query_str = mdsprintf(SQL_SELECT_ACCOUNT_ATTRIBUTE_STRING, attribute_name, fid);

  syslog(LOG_DEBUG, LOGSTR_BACKENDDB_QUERY_STRING, __func__, pthread_self(), NULL, sql_query_str, LOGCODE_BACKENDDB_QUERY_STRING);

  int sql_result = h_query_select(THREAD_CONTEXT_DB_BACKEND, sql_query_str, &result);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, LOGSTR_BACKENDDB_CONNECTION_ERROR, __func__, pthread_self(), NULL, 0L, sql_query_str, LOGCODE_BACKENDDB_CONNECTION_ERROR);

    free(sql_query_str);

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