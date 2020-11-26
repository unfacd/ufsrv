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

#ifndef UFSRV_UTILS_DB_ACCOUNT_H
#define UFSRV_UTILS_DB_ACCOUNT_H

#include <session_type.h>

UFSRVResult *DbAccountDataAttributeGetText (Session *sesn_ptr, unsigned long userid, const char *attribute_name);
UFSRVResult *DbAccountDataUserAttributeGetText(Session *sesn_ptr, unsigned long userid, const char *attribute_name);
int DbAccountUpdateData (Session *sesn_ptr, const char *data_path, const char *value, unsigned long userid);

json_object *DbGetAccountInJson (Session *sesn_ptr, const UfsrvUid *uid_ptr);
json_object *DbGetAccountUserDataInJson (Session *sesn_ptr, const UfsrvUid *uid_ptr);
json_object *DbGetAccountDataInJson (Session *sesn_ptr, const char *data_store, unsigned long userid);
json_object *DbGetAccountInJsonByUserId (Session *sesn_ptr, unsigned long userid);
json_object *DbGetAccountUserDataInJsonByUserId (Session *sesn_ptr, unsigned long userid);
json_object *DbGetAccountDataInJsonByUserId (Session *sesn_ptr, const char *data_store, unsigned long userid);

#endif