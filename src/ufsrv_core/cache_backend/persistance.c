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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <cache_backend/persistance.h>
#include <backendconfig_type.h>
#include <nportredird.h>
#include <net.h>
#include <cache_backend/redis.h>

extern ufsrv *const masterptr;

//When passing in_per_ptr we assume we are reinitialisng an existing backend
//free context and reallocate
PersistanceBackend *InitialisePersistanceBackend (PersistanceBackend *in_per_ptr)
{
	struct BackendConfig config;
	struct timeval tv;
	char resolved_ip[SBUF];

	GenericDnsResolve(masterptr->persistance_backend_address, resolved_ip, sizeof(resolved_ip));
	config.con_tcp.host                           = resolved_ip;
	config.con_tcp.port                           = masterptr->persistance_backend_port;
	config.cache_backend.send_command             = (void *(*)())RedisSendCommandOld;
	config.cache_backend.send_command_multi       = (void *(*)())RedisSendCommandMultiOld;
	config.cache_backend.send_command_sessionless = (void *(*)())RedisSendCommandSessionless;
	config.cache_backend.init_connection          = InitialisePersistanceBackend;
	config.type             = SOCK_TCP;//TODO: read actual type
	tv.tv_sec               =_CONFIG_CACHE_BACKEND_REPLY_TIMEOUT_SEC;
	tv.tv_usec              =_CONFIG_CACHE_BACKEND_REPLY_TIMEOUT_USEC;
	config.con_tcp.timeout  = tv;
  config.backend_label    = masterptr->server_descriptive_name;

	return ((PersistanceBackend *)InitialiseRedisBackend((RedisBackend *)in_per_ptr, &config));

}

UserMessageCacheBackend *InitialiseCacheBackendUserMessage (PersistanceBackend *in_per_ptr)
{
	struct BackendConfig config;
	struct timeval tv;
	char resolved_ip[SBUF];

	GenericDnsResolve(masterptr->cache_backend_address_usrmsg, resolved_ip, sizeof(resolved_ip));
	config.con_tcp.host = resolved_ip;
	config.con_tcp.port = masterptr->cache_backend_port_usrmsg;
	config.cache_backend.send_command             = (void *(*)())RedisSendSessionCommand;
	config.cache_backend.send_command_multi       = (void *(*)())RedisSendCommandMulti;
	config.cache_backend.send_command_sessionless = (void *(*)())RedisSendCommandSessionless;
	config.cache_backend.init_connection  =InitialiseCacheBackendUserMessage;
	config.type                           = SOCK_TCP;//TODO: read actual type
	tv.tv_sec   = _CONFIG_CACHE_BACKEND_REPLY_TIMEOUT_SEC;
	tv.tv_usec  = _CONFIG_CACHE_BACKEND_REPLY_TIMEOUT_USEC;
	config.con_tcp.timeout  = tv;
  config.backend_label    = masterptr->server_descriptive_name;

	return ((UserMessageCacheBackend *)InitialiseRedisBackend((RedisBackend *)in_per_ptr, &config));

}

FenceCacheBackend *InitialiseCacheBackendFence (PersistanceBackend *in_per_ptr)
{
	struct BackendConfig config;
	struct timeval tv;
	char resolved_ip[SBUF];

	GenericDnsResolve(masterptr->cache_backend_address_fence, resolved_ip, sizeof(resolved_ip));
	config.con_tcp.host = resolved_ip;
	config.con_tcp.port = masterptr->cache_backend_port_fence;
	config.cache_backend.send_command = (void *(*)())RedisSendSessionCommand;
	config.cache_backend.send_command_multi = (void *(*)())RedisSendCommandMulti;
	config.cache_backend.send_command_sessionless = (void *(*)())RedisSendCommandSessionless;
	config.cache_backend.init_connection = InitialiseCacheBackendFence;
	config.type = SOCK_TCP;//TODO: read actual type
	tv.tv_sec = _CONFIG_CACHE_BACKEND_REPLY_TIMEOUT_SEC;
	tv.tv_usec = _CONFIG_CACHE_BACKEND_REPLY_TIMEOUT_USEC;
	config.con_tcp.timeout = tv;
  config.backend_label = masterptr->server_descriptive_name;

	return ((FenceCacheBackend *)InitialiseRedisBackend((RedisBackend *)in_per_ptr, &config));

}
