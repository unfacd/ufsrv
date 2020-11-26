/**
 * Copyright (C) 2015-2019 unfacd works
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

#ifndef SRC_INCLUDE_REDIS_BACKEND_TYPE_H_
#define SRC_INCLUDE_REDIS_BACKEND_TYPE_H_

#include <hiredis/hiredis.h>

//A generalised type exists in struct PersistanceBackend. For the time being they must match in layout.
typedef struct RedisBackend RedisBackend;
struct RedisBackend	{
		redisContext *persistance_agent;//redisConetx *
		void *(*send_command)();
		void *(*send_command_multi)();//pipelined synchronous redis command
		void *(*send_command_sessionless)();
		RedisBackend *(*init_connection)(RedisBackend *);
    char *backend_label;
	};

#endif /* SRC_INCLUDE_REDIS_BACKEND_TYPE_H_ */
