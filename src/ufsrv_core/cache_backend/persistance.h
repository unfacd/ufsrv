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

#ifndef SRC_INCLUDE_PERSISTANCE_H_
#define SRC_INCLUDE_PERSISTANCE_H_

#include <hiredis/hiredis.h>
#include <ufsrv_core/cache_backend/persistance_type.h>
#include <session.h>
#include <ufsrv_core/cache_backend/redis.h>

unsigned DisconnectPersistanceBackend(Session *, int);//redisContext *c, int keep_fd);
PersistanceBackend *InitialisePersistanceBackend (PersistanceBackend *);
UserMessageCacheBackend *InitialiseCacheBackendUserMessage (PersistanceBackend *in_per_ptr);
UserMessageCacheBackend *InitialiseCacheBackendFence (PersistanceBackend *in_per_ptr);
void PrintPersistanceError (Session *sesn_ptr, char *user_str)__attribute__((unused));

#endif /* SRC_INCLUDE_PERSISTANCE_H_ */
