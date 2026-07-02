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


#ifndef UFSRV_SYSTEM_ROLES_H
#define UFSRV_SYSTEM_ROLES_H

#include <system_user_role_descriptor_type.h>
#include <uflib/db/db_op_descriptor_type.h>
#include <ufsrvresult_type.h>

bool IsUserSystemRoleMeetsAdminLevel(unsigned long user_id);
UFSRVResult * DbBackendGetUserSystemLevels(unsigned long user_id, enum SystemAdminActiveStatus active_status, SystemUserRoleDescriptor *role_descriptor_ptr, DbOpDescriptor *db_descriptor);

#endif //UFSRV_SYSTEM_ROLES_H
