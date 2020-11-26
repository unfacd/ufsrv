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


#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <error.h>
#include <misc.h>
#include <configfile.h>
#include <sys/stat.h>
#include <nportredird.h>
#include <sessions_delegator_type.h>

static unsigned long FileExist (char *, const char *);
static double ParsePercentage (const char *str);

static unsigned long FileExist (char *file, const char *conf)
{
	extern ufsrv *const masterptr;
	char path[sizeof(masterptr->config_dir)+sizeof(masterptr->config_file)+2];
	struct stat st;

 	sprintf (path, "%s/%s", masterptr->config_dir, masterptr->config_file);

 	strcpy (file, path);

	if ((access(path, F_OK|R_OK))<0)  return 0;

	if ((stat(path, &st))<0)  return 0;

	return st.st_size;

}

int ProcessConfigfile (const char *conf)
{
	char path[_POSIX_PATH_MAX];
	unsigned long size;
	FILE *fp;
	extern ufsrv *const masterptr;
	extern SessionsDelegator *const sessions_delegator_ptr;

	masterptr->lua_ptr=luaL_newstate();
	if (!masterptr->lua_ptr) {
		syslog (LOG_ERR, "%s: FATAL: COULD NOT INITIALISE LUA: exiting...", __func__);

		_exit(-1);
	}

	luaL_openlibs(masterptr->lua_ptr);

	size=FileExist(path, conf);
      
	if (!size) {
		syslog (LOG_INFO, "%s: ERROR: Configuration file is missing (%s) - %s", __func__, path, strerror(errno));
		fprintf (stderr, "%s: ERROR: Configuration file is missing (%s) - %s.\n", __func__, conf, strerror(errno));

		_exit (-1);
	}

	if (luaL_loadfile(masterptr->lua_ptr, path) || lua_pcall(masterptr->lua_ptr, 0, 0, 0)) {
		fprintf(stderr, "%s: ERROR: COULD NOT processes configuration file '%s/%s': error: '%s'", __func__, path, conf, lua_tostring(masterptr->lua_ptr, -1));

		_exit(-2);
	}

	//IMPORTANT ALWAYS ADD NEW ENTRIES BELOW THIS COMMENT LINE  AND INCREMENT THE STACK ACCORDINGLY
//	masterptr->ufsrvmedia_upload_uri
	lua_getglobal(masterptr->lua_ptr, "server_run_mode");
	lua_getglobal(masterptr->lua_ptr, "ufsrv_media_upload_uri");
	lua_getglobal(masterptr->lua_ptr, "session_workers_thread_pool");
	lua_getglobal(masterptr->lua_ptr, "ufsrv_geogroup");
	lua_getglobal(masterptr->lua_ptr, "main_listener_protocol_id");
	lua_getglobal(masterptr->lua_ptr, "ufsrvmsgqueue_bind_address");
	lua_getglobal(masterptr->lua_ptr, "ufsrvmsgqueue_port");
	lua_getglobal(masterptr->lua_ptr, "server_cpu_affinity");
	lua_getglobal(masterptr->lua_ptr, "server_id");
	lua_getglobal(masterptr->lua_ptr, "main_listener_port");
	lua_getglobal(masterptr->lua_ptr, "command_console_port");
	lua_getglobal(masterptr->lua_ptr, "main_listener_bind_address");

	if (!lua_isstring(masterptr->lua_ptr, -12)) {
		syslog(LOG_ERR, "%s: ERROR: UNRECOGNISED VALUE SET FOR 'shadow_mode': shadow mode will be disabled", __func__);
	} else {
		const char *runmode = lua_tostring(masterptr->lua_ptr, -12);
		if (strcmp(runmode, "shadow")==0)	_CONF_SERVER_RUNMODE(masterptr)=RUNMODE_SHADOW;
		else if (strcmp(runmode, "normal")==0)	_CONF_SERVER_RUNMODE(masterptr)=RUNMODE_NORMAL;
		else {
			syslog(LOG_ERR, "%s: ERROR: UNRECOGNISED 'server_run_mode' value (%s): defaulting to normal...", __func__, runmode);
			_CONF_SERVER_RUNMODE(masterptr)=RUNMODE_NORMAL;
		}
	}

	if (!lua_isstring(masterptr->lua_ptr, -11)) {
		syslog(LOG_INFO, ">>> %s: wrong value type for 'ufsrv_media_upload_uri'", __func__);
		strncpy( masterptr->ufsrvmedia_upload_uri,_CONFIGDEFAULT_DEFAULT_UFSRVMEDIA_UPLOAD_URI, SBUF-1);
	} else	strncpy( masterptr->ufsrvmedia_upload_uri,(lua_tostring(masterptr->lua_ptr, -11)), SBUF-1);

	if (!lua_isnumber(masterptr->lua_ptr, -10)) {
		syslog(LOG_ERR, "%s: ERROR: UNRECOGNISED VALUE SET FOR 'session_workers_thread_pool': using default '%d'", __func__, _CONFIGDEFAULT_MAX_SESSION_WORKERS);
	} else	sessions_delegator_ptr->setsize=(int)lua_tonumber(masterptr->lua_ptr, -10);

	if (sessions_delegator_ptr->setsize<1) sessions_delegator_ptr->setsize=_CONFIGDEFAULT_MAX_SESSION_WORKERS;

	if (!lua_isnumber(masterptr->lua_ptr, -9)) {
		syslog(LOG_INFO, ">>> %s: Ufsrv Geogroup not specified: using compiled default '%d'", __func__, _CONFIGDEFAULT_DEFAULT_UFSRVGEOGROUP);
		_CONF_UFSRV_GEOGROUP(masterptr)=_CONFIGDEFAULT_DEFAULT_UFSRVGEOGROUP;
	} else {
		_CONF_UFSRV_GEOGROUP(masterptr)=(int)lua_tonumber(masterptr->lua_ptr, -9);
		syslog(LOG_INFO, ">>> %s: Ufsrv Geogroup specified: '%u'", __func__, _CONF_UFSRV_GEOGROUP(masterptr));
	}

	if (!lua_isnumber(masterptr->lua_ptr, -8)) {
		syslog(LOG_INFO, ">>> %s: Protocol id not specified: using '0'", __func__);
		masterptr->main_listener_protoid=0;
	} else {
		syslog(LOG_INFO, ">>> %s: Protocol id specified: '%u'", __func__, (unsigned )lua_tonumber(masterptr->lua_ptr, -8));
		masterptr->main_listener_protoid=(unsigned )lua_tonumber(masterptr->lua_ptr, -8);
	}

	if (!lua_isstring(masterptr->lua_ptr, -7)) {
		syslog(LOG_INFO, ">>> %s: wrong value type for 'ufsrvmsgqueue_bind_address'", __func__);
		strncpy( masterptr->ufsrvmsgqueue_address,"ufsrvmsgqueue.unfacd.com", MBUF);
	} else	strncpy( masterptr->ufsrvmsgqueue_address,(lua_tostring(masterptr->lua_ptr, -7)), MBUF-1);

	if (!lua_isnumber(masterptr->lua_ptr, -6)) {
		syslog(LOG_INFO, ">>> config: wrong value type for 'ufsrvmsgqueue_port'");
		masterptr->ufsrvmsgqueue_port=-1;
	} else	masterptr->ufsrvmsgqueue_port=(int)lua_tonumber(masterptr->lua_ptr, -6);

	if (!lua_isnumber(masterptr->lua_ptr, -5)) {
		syslog(LOG_INFO, ">>> config: wrong value type for 'server_cpu_affinity'");
		masterptr->server_cpu_affinity=-1;
	} else	masterptr->server_cpu_affinity=(int)lua_tonumber(masterptr->lua_ptr, -5);

	if (!lua_isstring(masterptr->lua_ptr, -4)) {
		syslog(LOG_INFO,  ">>> config: wrong value type for 'server_id'");
		error(-1, 0, ">>> config: wrong value type for 'server_id'");
	}
	//this is now supplied in command line argument
	//else	strncpy( masterptr->server_id_notused,(lua_tostring(masterptr->lua_ptr, -4)), MBUF);


	if (!lua_isnumber(masterptr->lua_ptr, -3))	syslog(LOG_INFO,  ">>> config: wrong value type for 'listen_on_port'");
	else	masterptr->listen_on_port=(int)lua_tonumber(masterptr->lua_ptr, -3);

	if (!lua_isnumber(masterptr->lua_ptr, -2))syslog(LOG_INFO,  ">>> config: wrong value type for 'command_centre_port'");
	else	masterptr->command_console_port=(int)lua_tonumber(masterptr->lua_ptr, -2);

	if (!lua_isstring(masterptr->lua_ptr, -1))syslog(LOG_INFO,  ">>> config: wrong value type for 'main_listener_bind_address'");
	else	strncpy( masterptr->main_listener_address,(lua_tostring(masterptr->lua_ptr, -1)), MBUF-1);

	lua_getglobal(LUA_CTX, "ufsrv_db_backend");
	if (!lua_istable(LUA_CTX, -1)) {
		syslog(LOG_INFO, "%s: COULD NOT load the db backend address information: LOADING DEFAULTS", __func__);
		strncpy(masterptr->db_backend.address, "127.0.0.1", strlen("127.0.0.1"));
		masterptr->db_backend.port=3306;
		strncpy(masterptr->db_backend.username, "ufsrv", strlen("ufsrv"));
		//password set to empt
	} else {
		masterptr->db_backend.port=LUA_GetFieldToInteger("port");
		strncpy(masterptr->db_backend.address, LUA_GetFieldToString("address"), SBUF-1);
		masterptr->db_backend.address[SBUF-1]=0;
		strncpy(masterptr->db_backend.password, LUA_GetFieldToString("password"), SBUF-1);
		masterptr->db_backend.password[SBUF-1]=0;
		strncpy(masterptr->db_backend.username, LUA_GetFieldToString("username"), SBUF-1);
		masterptr->db_backend.username[SBUF-1]=0;
	}
	syslog(LOG_INFO, "%s: ufsrv_db_backend: DB Backend Server: '%s' on port: '%d'", __func__, masterptr->db_backend.address, masterptr->db_backend.port );

	lua_getglobal(LUA_CTX, "ufsrv_stats_backend");
	if (!lua_istable(LUA_CTX, -1)) {
		syslog(LOG_INFO, "%s: COULD NOT load the stats backend address information: LOADING DEFAULTS", __func__);
		strncpy(masterptr->stats_backend.address, "127.0.0.1", strlen("127.0.0.1"));
		masterptr->stats_backend.port=8125;
	} else {
		masterptr->stats_backend.port=LUA_GetFieldToInteger("port");
		strncpy(masterptr->stats_backend.address, LUA_GetFieldToString("address"), SBUF-1);
		masterptr->stats_backend.address[SBUF-1]=0;
	}
	syslog(LOG_INFO, "%s: ufsrv_stats_backend: Stats Server: '%s' on port: '%d'", __func__, masterptr->stats_backend.address, masterptr->stats_backend.port );

	lua_getglobal(LUA_CTX, "ufsrv_geoip_backend");
	if (!lua_istable(LUA_CTX, -1)) {
		syslog(LOG_INFO, "%s: COULD NOT load the geoip backend address information: LOADING DEFAULTS", __func__);
		strncpy(masterptr->geoip_backend.address, "127.0.0.1", strlen("127.0.0.1"));
		masterptr->geoip_backend.port=1980;
	} else {
		masterptr->geoip_backend.port=LUA_GetFieldToInteger("port");
		strncpy(masterptr->geoip_backend.address, LUA_GetFieldToString("address"), SBUF-1);
		masterptr->geoip_backend.address[SBUF-1]=0;
	}
	syslog(LOG_INFO, "%s: ufsrv_geoip_backend: geoip Server: '%s' on port: '%d'", __func__, masterptr->geoip_backend.address, masterptr->geoip_backend.port );

	lua_getglobal(LUA_CTX, "ufsrv_persistance_backend");
	//TODO: NOT Safe from multiple threads as that will confuse the lua stack
	if (!lua_istable(LUA_CTX, -1)) {
	  syslog(LOG_INFO, "%s: COULD NOT load the Persistence backend address information: LOADING DEFAULTS", __func__);
	  strncpy(masterptr->persistance_backend_address, "127.0.0.1", strlen("127.0.0.1"));
	  masterptr->persistance_backend_port=19705;
	} else {
		masterptr->persistance_backend_port=LUA_GetFieldToInteger("port");
		strncpy(masterptr->persistance_backend_address, LUA_GetFieldToString("address"), MBUF);//TODO free str
		masterptr->persistance_backend_address[MBUF-1]=0;

	}
	syslog(LOG_INFO, "%s: ufsrv_persistance_backend: Session Cache Backend Server: '%s' on port: '%d'", __func__, masterptr->persistance_backend_address, masterptr->persistance_backend_port );



	lua_getglobal(LUA_CTX, "ufsrv_cache_backend_usrmsg");
	//TODO: NOT Safe from multiple threads as that will confuse the lua stack
	if (!lua_istable(LUA_CTX, -1)) {
		syslog(LOG_INFO, "%s: COULD NOT load the UserMessage Cache Backend address information: LOADING DEFAULTS", __func__);
		strncpy(masterptr->cache_backend_address_usrmsg, _CONFIGDEFAULT_BACKENDCACHE_HOST_USRMSG, strlen(_CONFIGDEFAULT_BACKENDCACHE_HOST_USRMSG));
		masterptr->cache_backend_port_usrmsg=_CONFIGDEFAULT_BACKENDCACHE_PORT_USRMSG;
	} else {
		masterptr->cache_backend_port_usrmsg=LUA_GetFieldToInteger("port");
		strncpy(masterptr->cache_backend_address_usrmsg, LUA_GetFieldToString("address"), MBUF);//TODO free str
		masterptr->cache_backend_address_usrmsg[MBUF-1]=0;

	}
	syslog(LOG_INFO, "%s: ufsrv_cache_backend_usrmsg: Cache Backend Server: '%s' on port: '%d'", __func__, masterptr->cache_backend_address_usrmsg, masterptr->cache_backend_port_usrmsg);


	lua_getglobal(LUA_CTX, "ufsrv_cache_backend_fence");
	//TODO: NOT Safe from multiple threads as that will confuse the lua stack
	if (!lua_istable(LUA_CTX, -1)) {
		syslog(LOG_INFO, "%s: COULD NOT load the Fence Backend address information: LOADING DEFAULTS", __func__);
		strncpy(masterptr->cache_backend_address_fence, _CONFIGDEFAULT_BACKENDCACHE_HOST_FENCE, strlen(_CONFIGDEFAULT_BACKENDCACHE_HOST_FENCE));
		masterptr->cache_backend_port_fence=_CONFIGDEFAULT_BACKENDCACHE_PORT_FENCE;
	} else {
		masterptr->cache_backend_port_fence=LUA_GetFieldToInteger("port");
		strncpy(masterptr->cache_backend_address_fence, LUA_GetFieldToString("address"), MBUF);//TODO free str
		masterptr->cache_backend_address_fence[MBUF-1]=0;
	}
	syslog(LOG_INFO, "%s: ufsrv_cache_backend_fence: Fence Backend Server: '%s' on port: '%d'", __func__, masterptr->cache_backend_address_fence, masterptr->cache_backend_port_fence);


	lua_getglobal(LUA_CTX, "ufsrv_user_timeouts");
	if (!lua_istable(LUA_CTX, -1)) {
		  error(-1, 0, "`ufsrv_user_timeouts' is not a valid config table");
		  sessions_delegator_ptr->user_timeouts.connected=300;
		  sessions_delegator_ptr->user_timeouts.unauthenticated=300;
		  sessions_delegator_ptr->user_timeouts.suspended=300;
		  sessions_delegator_ptr->user_timeouts.locationless=300;
	} else {
		//TODO: validate values
		sessions_delegator_ptr->user_timeouts.connected=LUA_GetFieldToInteger("connected_timeout");
		sessions_delegator_ptr->user_timeouts.unauthenticated=LUA_GetFieldToInteger("unauthenticated_timeout");
		sessions_delegator_ptr->user_timeouts.suspended=LUA_GetFieldToInteger("suspended_timeout");
		sessions_delegator_ptr->user_timeouts.locationless=LUA_GetFieldToInteger("locationless_timeout");
	}

	syslog(LOG_INFO, "%s: ufsrv_user_timeouts: connected_timeou: connected_timeou: '%d', unauthenticated_timeout: '%d', suspended_timeout: '%d', locationless_timeout: '%d'", __func__,
			sessions_delegator_ptr->user_timeouts.connected, sessions_delegator_ptr->user_timeouts.unauthenticated, sessions_delegator_ptr->user_timeouts.suspended, sessions_delegator_ptr->user_timeouts.locationless);

	lua_getglobal(LUA_CTX, "ufsrv_buffer_sizes");
	if (!lua_istable(LUA_CTX, -1)) {
	  syslog(LOG_INFO, "%s: `ufsrv_buffer_sizes' is not a valid config table: using defaults", __func__);
	  masterptr->buffer_size=_BUFFER_DEFAUL_BLOCKSZ;
	  masterptr->buffer_maxsize=_BUFFER_MAX_BLOCKSZ;
	} else {
		//TODO: validate values
		masterptr->buffer_size=LUA_GetFieldToInteger("incoming_buffer_size");
		if ((masterptr->buffer_size<=0)) masterptr->buffer_size=_BUFFER_DEFAUL_BLOCKSZ;
		masterptr->buffer_maxsize=LUA_GetFieldToInteger("incoming_buffer_maxsize");
		if ((masterptr->buffer_maxsize<=0)) masterptr->buffer_maxsize=_BUFFER_MAX_BLOCKSZ;

		//ensure we are with upper bound
		if (masterptr->buffer_size>masterptr->buffer_maxsize)	masterptr->buffer_size=masterptr->buffer_maxsize;
	}

	syslog(LOG_INFO, "%s: ufsrv_buffer_sizes: connected_timeou: incoming_buffer_size: '%lu'", __func__, masterptr->buffer_size);


	lua_getglobal(LUA_CTX, "memory_specs_for_session");
	if (!lua_istable(LUA_CTX, -1)) {
		syslog(LOG_INFO, "%s: `memory_specs_for_session' is not a valid config table: using defaults", __func__);
		masterptr->memspecs_session.allocation_groups=_MEMSPECS_SESSION_ALLOCGROUPS;
		masterptr->memspecs_session.allocation_group_sz=_MEMSPECS_SESSION_ALLOCGROUP_SZ;
		masterptr->memspecs_session.allocation_trigger_threshold=ParsePercentage(_MEMSPECS_SESSION_ALLOC_TRIGGER_THRESHOLD);
	} else {
		//TODO: validate values
		masterptr->memspecs_session.allocation_group_sz=LUA_GetFieldToInteger("sessions_per_allocation_group");
		if ((masterptr->memspecs_session.allocation_group_sz<=0)) masterptr->memspecs_session.allocation_group_sz=_MEMSPECS_SESSION_ALLOCGROUP_SZ;
		masterptr->memspecs_session.allocation_groups=LUA_GetFieldToInteger("allocation_groups");
		if ((masterptr->memspecs_session.allocation_groups<=0)) masterptr->memspecs_session.allocation_groups=_MEMSPECS_SESSION_ALLOCGROUPS;

		masterptr->memspecs_session.allocation_trigger_threshold=ParsePercentage(LUA_GetFieldToString("allocation_threshold_trigger"));
		if ((masterptr->memspecs_session.allocation_trigger_threshold<=0)) masterptr->memspecs_session.allocation_trigger_threshold=ParsePercentage(_MEMSPECS_SESSION_ALLOC_TRIGGER_THRESHOLD);
	}

		syslog(LOG_INFO, "%s: Memory Specs for Sessions: allocation_groups: '%d'. sessions_per_allocation_group: '%lu'. allocation_threshold_trigger:'%f'", __func__,
				masterptr->memspecs_session.allocation_groups, masterptr->memspecs_session.allocation_group_sz, masterptr->memspecs_session.allocation_trigger_threshold);

   return 1;

 }

 static double ParsePercentage (const char *str)
 {

	 if	(likely(str!=NULL))
	 {
		 char *strcopy=strdupa(str);
		 char *axe=NULL;
		 int value;
		 if ((axe=strrchr(strcopy, '%')))
		 {
			 *axe='\0';
			 value=atoi(strcopy);
			 if (value<=100||value>0) return (value/100);
		 }
	 }

	 return -1.0;
 }
