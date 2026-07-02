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

#ifndef SESSION_UTILS_H
# define SESSION_UTILS_H

#include <session_type.h>
#include <uflib/adt/adt_hashtable_type.h>
#include <json/json.h>
#include <netinet/in.h>

json_object *GetPresenceInformation(Session *sesn_ptr, struct json_object *jobj_contacts);
InstanceHolderForSession *LocallyLocateSessionByNetAddress(HashTable *hash_table, struct sockaddr_in *src);
int AssignNetAddressHashForSession(InstanceContextForSession *instance_context, const struct sockaddr_in *src);
bool IsSessionIdFormatValid(const char * _Nonnull session_id_str);

#endif