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

#ifndef UFSRV_UTILS_DB_ACCOUNT_H
#define UFSRV_UTILS_DB_ACCOUNT_H

#include <uflib/ufsrvuid_type.h>
#include <ufsrvresult_type.h>
#include <kbs_descriptor_type.h>
#include <json/json.h>

UFSRVResult *DbAccountDataAttributeGetText(unsigned long userid, const char *attribute_name);
UFSRVResult *DbAccountDataUserAttributeGetText(unsigned long userid, const char *attribute_name);
int DbAccountUpdateDataByText(const char *data_path, const char *value, unsigned long userid);
int DbAccountUpdateDataByInt(const char *data_path, int value, unsigned long userid);

int DbAccountUpdateKbs(KbsDescriptor *kbs_descriptor_ptr, unsigned long userid);
int DbAccountUpdateKbsSansReglock(KbsDescriptor *kbs_descriptor_ptr, unsigned long userid);
KbsDescriptor *DbAccountGetKbs(unsigned long userid, bool is_struct_transfer, bool is_serialised, bool is_raw, KbsDescriptor *kbs_descriptor_ptr_out);
const char *ProvideDefaultKbsTokenForDbAccount();
json_object *ProvideDefaultKbsJsonToken();
json_object *ProvideDefaultProfilePersonalJsonToken();

json_object *DbGetAccountInJson(const UfsrvUid *uid_ptr);
json_object *DbGetAccountUserDataInJson(const UfsrvUid *uid_ptr);
json_object *DbGetAccountInJsonByUserId(unsigned long userid);
json_object *DbGetAccountUserDataInJsonByUserId(unsigned long userid);


#endif