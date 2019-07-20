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

#ifndef SRC_INCLUDE_PERSISTANCE_TYPE_H_
#define SRC_INCLUDE_PERSISTANCE_TYPE_H_

typedef struct PersistanceBackend UserMessageCacheBackend;
typedef struct PersistanceBackend FenceCacheBackend;
typedef struct PersistanceBackend	CacheBackend;

typedef struct PersistanceBackend PersistanceBackend;
struct PersistanceBackend	{
	void *persistance_agent;//redisConetx *
	void *(*send_command)();
	void *(*send_command_multi)();//pipelined synchronous redis command
	void *(*send_command_sessionless)();
	PersistanceBackend *(*init_connection)(PersistanceBackend *);
};
//typedef struct PersistanceBackend PersistanceBackend;

#endif /* SRC_INCLUDE_PERSISTANCE_TYPE_H_ */
