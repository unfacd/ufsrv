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

#ifndef SRC_INCLUDE_REDIS_H_
#define SRC_INCLUDE_REDIS_H_

#include <session_type.h>
#include <backendconfig_type.h>
#include "redis_backend_type.h"
#include <utils.h>

#if 0
	struct RedisBackend	{
		redisContext *persistance_agent;//redisConetx *
		void *(*send_command)();
		void *(*send_command_multi)();//pipelined synchronous redis command
	};
	typedef struct RedisBackend RedisBackend;

//#define PERSIST_DATA(x, ...) (*x->persistance_backend.send_command)(...)
#endif

#if 0
	enum connection_type {
	    CONN_TCP,
	    CONN_UNIX,
	    CONN_FD
	};
#endif

/**
 * 1)currently scripts are saved in teh same working directory as redis instalation
 * 2)at startup time, the script must be loaded into redis: /opt/redis/redis-cli -p 19705 SCRIPT LOAD "$(cat redis_id_generation.lua)"
 *
 * 3)at ufsrv startup (InitUfsrv()) time we check for the presence of the script with command (SCRIPT EXISTS %s", REDIS_SCRIPT_SHA1_UNIQUE_ID);
 * This generated at redis start up time using the command "/opt/redis/redis-cli -p 19705 SCRIPT LOAD "$(cat redis_id_generation.lua)""
 * It needs to be regenerated overtime the script is modified.
 */
#define REDIS_SCRIPT_SHA1_UNIQUE_ID "5ddb0d7aa876a99a1f03ae483ada43b30d3731be"
#define REDIS_SCRIPT_SHA1_DEL_LOCK	"3d84bffbe72d4ec06e345cb3db2eae1345524faf"

unsigned DisconnectRedisBackend(Session *, int);
RedisBackend *InitialiseRedisBackend (RedisBackend *, struct BackendConfig *);
void PrintPersistanceError (Session *sesn_ptr, char *user_str);
void *RedisSendCommandSessionless (void *ptr, const char *format, ...);
void *RedisSendSessionCommand(Session *sesn_ptr_this, CacheBackend *pers_ptr_in, const char *format, ...);
void *RedisSendCommand(CacheBackend *pers_ptr_in, const char *format, ...);
void *RedisSendCommandMulti (Session *, CacheBackend *, const char *format, ...);
void *RedisSendCommandOld (Session *,  const char *format, ...);
void *RedisSendCommandMultiOld (Session *,  const char *format, ...);
void *RedisSendCommandWithCollection (Session *sesn_ptr, CacheBackend *pers_ptr, CollectionDescriptorPair *collection_argv_argvlen);
int RedisGetReply (Session *sesn_ptr, CacheBackend *pers_ptr, redisReply	**reply);
int CheckForScript (RedisBackend *pers_ptr, const char *unique_id);
unsigned long GenerateCacheBackendId (PersistanceBackend *backend_ptr);
#endif /* SRC_INCLUDE_REDIS_H_ */
