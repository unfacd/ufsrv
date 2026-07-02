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


#ifndef UFSRV_SYSTEM_USER_ROLE_DESCRIPTOR_TYPE_H
#define UFSRV_SYSTEM_USER_ROLE_DESCRIPTOR_TYPE_H

enum SystemAdminLevels {
    SYSADMIN_LEVEL_UNSET,
    SYSADMIN_LEVEL_DEVOPS,
    SYSADMIN_LEVEL_ADMIN,
    SYSADMIN_LEVEL_SUPERUSER
};
enum SystemAdminActiveStatus {
    SYSADMIN_STATUS_UNSET,
    SYSADMIN_STATUS_ACTIVE,
    SYSADMIN_STATUS_PAUSED,
    SYSADMIN_STATUS_REVOKED
};

typedef struct SystemUserRoleDescriptor {
  enum SystemAdminLevels admin_level;
  enum SystemAdminActiveStatus active_status;
  unsigned long user_id;
} SystemUserRoleDescriptor;

#define AS_SYSTEM_USER_ROLE_DESCRIPTOR(x) ((SystemUserRoleDescriptor *)(x))

#endif //UFSRV_SYSTEM_USER_ROLE_DESCRIPTOR_TYPE_H
