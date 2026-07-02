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
#ifndef UFSRV_FENCE_UTILS_DB_H
#define UFSRV_FENCE_UTILS_DB_H

#include <uflib/main_types.h>
#include <ufsrvresult_type.h>
#include <uflib/db/db_op_descriptor_type.h>
#include <fence/fence_type.h>

//UFSRVResult *DbFenceDataAttributeGetText(unsigned long fid, const char *attribute_name);
UFSRVResult *DbBackendLoadFenceDescription(InstanceHolderForFence *f_ptr_instance);
UFSRVResult *DbBackendGetFenceDataNamedAttribute(unsigned long fid, const char *attribute_name, DbOpDescriptor *db_descriptor, unsigned long call_flags);
UFSRVResult *DbBackendUpdateFenceDataNamedAttribute(unsigned long fid, const char *attribute_name, const char *attribute_value, DbOpDescriptor *db_descriptor, unsigned long call_flags);

#endif //UFSRV_FENCE_UTILS_DB_H
