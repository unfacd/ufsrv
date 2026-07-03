/*

 Copyright (c) 2015-2025 unfacd works

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.

 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <system_roles.h>
#include <thread_context_type.h>
#include <uflib/db/dp_ops.h>
#include <uflib/db/db_op_descriptor_type.h>
#include <user/user_backend.h>

extern __thread ThreadContext ufsrv_thread_context;


static const char *const SystemAdminLevelsNames[] = {
  [SYSADMIN_LEVEL_UNSET]      = "unset",
  [SYSADMIN_LEVEL_DEVOPS]     = "devops",
  [SYSADMIN_LEVEL_ADMIN]      = "admin",
  [SYSADMIN_LEVEL_SUPERUSER]  = "super_admin",
};

static const char *const SystemAdminActiveStatusNames[] = {
  [SYSADMIN_STATUS_UNSET]   = "unset",
  [SYSADMIN_STATUS_ACTIVE]  = "active",
  [SYSADMIN_STATUS_PAUSED]  = "paused",
  [SYSADMIN_STATUS_REVOKED] = "revoked"
};

bool
IsUserSystemRoleMeetsAdminLevel(unsigned long user_id)
{
  SystemUserRoleDescriptor user_role_descriptor = {0};
  DbOpDescriptor dbop_descriptor = {0};

  DbBackendGetUserSystemLevels(user_id, SYSADMIN_STATUS_ACTIVE, &user_role_descriptor, &dbop_descriptor);
  if (THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA) {
    if (user_role_descriptor.admin_level >  SYSADMIN_LEVEL_DEVOPS) {
      DBOP_DESCRIPTOR_INVOKE_RESULT_FINALISER_IF_PRESENT(&dbop_descriptor);
      return true;
    }
  }

  return false;

}

static char *
_UserSystemLevelsDbOpQueryProvider(intptr_t values[static 1])
{
  //alt syntax 'CAST(admin_level AS UNSIGNED)'
#define SQL_SELECT_DONATIONS_SUBSCRIPTION 	 "SELECT role_id, admin_level + 0, roles " \
                                             "FROM user_system_roles WHERE user_id = '%lu' AND active_status = '%s'"
  char *sql_query_str = mdsprintf(SQL_SELECT_DONATIONS_SUBSCRIPTION, (unsigned long)values[0], (char *)values[1]);
  return sql_query_str;
#undef SQL_SELECT_DONATIONS_SUBSCRIPTION
}

static int
_UserSystemLevelsDbOpTransformer(DbOpDescriptor *dbop_descriptor)
{
#define COLUMN_ROLE_ID		(((struct _h_type_int *)result->data[0][0].t_data)->value)
#define COLUMN_ADMIN_LEVEL	(((struct _h_type_int *)result->data[0][1].t_data)->value)
#define COLUMN_ADMIN_ROLES  ((struct _h_type_blob *)result.data[0][2].t_data))
#define COLUMN_ADMIN_ROLES_VALUE (((struct _h_type_blob *)result.data[0][2].t_data)->value)
#define COLUMN_ADMIN_ROLES_VALUE_LENGTH (((struct _h_type_blob *)result.data[0][2].t_data)->length)

  struct _h_result *result = &dbop_descriptor->result;
  SystemUserRoleDescriptor *role_descriptor_ptr = AS_SYSTEM_USER_ROLE_DESCRIPTOR(dbop_descriptor->ctx_data);

  role_descriptor_ptr->admin_level = COLUMN_ADMIN_LEVEL - 1; //mysql indexes enums at starting position of 1

  return 0;
}
/**
 * @brief Main interface for querying system user roles table.
 * @param db_descriptor Empty, pre-allocated by user
 * @param role_descriptor_ptr user provided with pre-filled values for userid
 * @return thread_context UFSRVResult
 * @warn caller must invoke @code{.c} DBOP_DESCRIPTOR_INVOKE_RESULT_FINALISER_IF_PRESENT(dbop_descriptor);@endcode to release memory associated with result set
 */
UFSRVResult *
DbBackendGetUserSystemLevels(unsigned long user_id, enum SystemAdminActiveStatus active_status, SystemUserRoleDescriptor *role_descriptor_ptr, DbOpDescriptor *db_descriptor)
{
  db_descriptor->ctx_data = AS_CLIENT_CONTEXT_DATA(role_descriptor_ptr);
  db_descriptor->query_statement_provider.provide = _UserSystemLevelsDbOpQueryProvider;
  db_descriptor->query_statement_provider.values  = (intptr_t[]){DBOP_QUERY_PROVIDER_VALUE(user_id), DBOP_QUERY_PROVIDER_VALUE(SystemAdminActiveStatusNames[active_status]), 0};
  db_descriptor->query_statement_provider.finalise = GetDefaultQueryStatementProviderFinalser();
  db_descriptor->transformer.transform = _UserSystemLevelsDbOpTransformer;

  GetDbResultForQuery(THREAD_CONTEXT_DB_BACKEND, db_descriptor);
  ReturnUfsrvResultFromDbOpDescriptor(db_descriptor);

  if (THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA) {
    db_descriptor->finaliser.finalise = GetDefaultDbOpResultFinaliser(); //enable caller to issue result-set deallocation
  }

  return THREAD_CONTEXT_UFSRV_RESULT_PTR;
}