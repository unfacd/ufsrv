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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <math.h>
#include <main.h>
#include <uflib/utils_str.h>
#include <ufsrvmsg_core/location/location.h>
#include <fence/fence.h>
#include <session_cachebackend.h>
#include <ufsrv_core/cache_backend/redis.h>
#include <ufsrvmsg_core/fence/fence_state.h>
#include <http_request.h>
#include <location_broadcast.h>
#include <ufsrvwebsock/include/protocol_websocket_session.h>
#include <uflib/ufsrvuid.h>

extern ufsrv *const masterptr;
extern __thread ThreadContext ufsrv_thread_context;

static void RememberLastKnownLocation(User *, json_object *);

#define CHECK_GET_URL_RESULT_FOR_ERROR(x) \
		if (result==0)\
		{\
			syslog(LOG_ERR, "(x): error fetching url: '%s'", url_str);\
			free (url_str);\
			return NULL;\
		}

//const char *location_locator_address_prefix="http://127.0.0.1:19801/json/";

#if 0
//freegeoip output
{"ip":"110.20.170.119","country_code":"AU","country_name":"Australia","region_code":"NSW","region_name":"New South Wales", "city":"Strathfield","zip_code":"2135","time_zone":"Australia/Sydney","latitude":-33.867,"longitude":151.1,"metro_code":0}
 //maxmind output
 {"ip":"109.255.186.0","continent_code":"EU","country":"Ireland","country_code":"IE","country_code3":"IRL","is_in_european_union":true,"region":"Munster","region_code":"M","city":"Limerick","postal_code":"V94","latitude":52.6669,"longitude":-8.6274,"timezone":"Europe/Dublin","offset":0,"asn":6830,"organization":"Liberty Global B.V."}
#endif

LocationDescription *
DetermineLocationByServerByJson(Session *sesn_ptr, HttpRequestContext *http_ptr, json_object *jobj)
{
	char *url_str = NULL;
	int location_status = json_object_get_int(json__get(jobj, "status"));

	if (location_status == 2) {
		//complete processing of user location
		DetermineUserLocationByServer(sesn_ptr, GetHttpRequestContext(sesn_ptr),  0);//broadcast event

	} else if (location_status == 1) {
		double longitude = json_object_get_double(json__get(jobj, ACCOUNT_JSONATTR_LONGITUDE));
		double latitude = json_object_get_double(json__get(jobj, ACCOUNT_JSONATTR_LATITUDE));

		if (longitude && latitude) {//these values can be negative
			//TODO: perform reverse geo on these values NOT REVERSE GEO IP
			syslog(LOG_NOTICE, "%s: PARTIAL location received: longitude: '%f', latitude: '%f'", __func__, longitude, latitude);
			DetermineUserLocationByServer(sesn_ptr, GetHttpRequestContext(sesn_ptr),  0);//broadcast event
		} else {
			//some junk apparently, do reverse geo ip just as per 'status=unknown"
			syslog(LOG_NOTICE, "%s: PARTIAL INCONSISTENT location received: longitude: '%f', latitude: '%f'", __func__, longitude, latitude);
			DetermineUserLocationByServer(sesn_ptr, GetHttpRequestContext(sesn_ptr),  0);//broadcast event
		}
	} else {
		//unknown value passed
		syslog(LOG_NOTICE, "%s: LOCATION STATUS unknown: '%d'", __func__, location_status);
		DetermineUserLocationByServer(sesn_ptr, GetHttpRequestContext(sesn_ptr),  0);//broadcast event
	}

	return NULL;

}

////todo 9/5/25 devops: this always returns null. Results are returned in UfsrvResult
LocationDescription *
DetermineLocationByServerByWireProto(Session *sesn_ptr, const LocationRecord *location_record_ptr)
{
  char *url_str = NULL;

  //0: completely resolved, 1: partially 2: unknown. In partially we could be missing any of the address components
  if (location_record_ptr->source == LOCATION_RECORD__SOURCE__BY_UNDEFINED) {
    //complete processing of user location
    DetermineUserLocationByServer(sesn_ptr, GetHttpRequestContext(sesn_ptr),  0);//broadcast event
  } else  {
    double longitude = location_record_ptr->longitude;
    double latitude = location_record_ptr->latitude;

    if (longitude && latitude) {//these values can be negative
      //TODO: perform reverse geo on these values NOT REVERSE GEO IP
      syslog(LOG_NOTICE, "%s: PARTIAL location received: longitude: '%f', latitude: '%f'", __func__, longitude, latitude);
      DetermineUserLocationByServer(sesn_ptr, GetHttpRequestContext(sesn_ptr),  0);//broadcast event
    } else {
      //some junk apparently, do reverse geo ip just as per 'status=unknown"
      syslog(LOG_NOTICE, "%s: PARTIAL INCONSISTENT location received: longitude: '%f', latitude: '%f'", __func__, longitude, latitude);
      DetermineUserLocationByServer(sesn_ptr, GetHttpRequestContext(sesn_ptr),  0);//broadcast event
    }
  }

  return NULL;

}

/**
 * 	@brief: Establish user's current location based on geoip decoding.
 * 	curl http://10.1.33.1:19800/location/109.255.186.0
 * 	@note freegeoip used: http://10.1.33.1:19800/json/109.255.186.0 and minor changes to json attribute names
 */
LocationDescription *
DetermineUserLocationByServer(Session *sesn_ptr, HttpRequestContext *http_ptr, unsigned long sesn_call_flags)
{
  char *url_str = NULL;

  if (asprintf(&url_str, "http://%s:%d/location/%s", masterptr->geoip_backend.address, masterptr->geoip_backend.port, sesn_ptr->ssptr->haddress ) > 0) {
#ifdef __UF_TESTING
    syslog(LOG_INFO, "%s {pid:'%lu', th_ctx:'%p', o:'%p'}: Establishing LocationDescription for '%s'...", __func__, pthread_self(), THREAD_CONTEXT_PTR, sesn_ptr, url_str);
#endif

    if ((HttpRequestGetUrlJson(http_ptr, url_str, NULL, NULL)) == 0) {
      syslog(LOG_ERR, "%s {pid:'%lu', th_ctx:'%p, o:'%p'}: ERROR: COULD NOT FETCH URL: '%s'", __func__, pthread_self(), THREAD_CONTEXT_PTR, sesn_ptr, url_str);

      free(url_str);

      return NULL;
    }

#ifdef __UF_FULLDEBUG
    syslog(LOG_INFO, "%s {pid:'%lu', o:'%p'}: received response from Location Service: '%s'", __func__, pthread_self(), sesn_ptr, http_ptr->rb.memory);
#endif

    UpdateUserLocationAssignment(sesn_ptr, CLIENT_CTX_DATA(http_ptr->jobj), GEOLOC_TRIGGER_UNDEFINED, CALL_FLAG_LOCATION_BY_SERVER | CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND | CALL_FLAG_BROADCAST_SESSION_EVENT);

    SESSION_ULOCATION_BYSERVER_INITIALISED(sesn_ptr) = 1;

    if (SESSION_UFSRV_GEOGROUP(sesn_ptr) == 0)	SESSION_UFSRV_GEOGROUP(sesn_ptr) = GetUfsrvGeoGroupForUser(sesn_ptr, SESSION_ULOCATION_BYSERVER(sesn_ptr).country);

    free(url_str);

    return SESSION_ULOCATION_BYSERVER_PTR(sesn_ptr);
  }

  return NULL;

}

void static _UpdateUserLocationAssignmentByServerSource(LocationDescription *location_ptr, struct json_object *jobj);
void static _UpdateUserLocationAssignmentByUserSourceByProto(LocationDescription *location_ptr,  LocationRecord *location_record_ptr);
static UFSRVResult *_CacheBackendUpdateLocationRecord(Session *sesn_ptr, const LocationDescription *location_ptr, const char *location_name, const char *location_value);

/**
 */
void static
_UpdateUserLocationAssignmentByServerSource(LocationDescription *location_ptr, struct json_object *jobj)
{
	DestructLocationDescription(location_ptr);

	location_ptr->longitude				=	json_object_get_double(json__get(jobj, ACCOUNT_JSONATTR_LONGITUDE));
	location_ptr->latitude				=	json_object_get_double(json__get(jobj, ACCOUNT_JSONATTR_LATITUDE));
	_FuzzGeoLocation(location_ptr, _CONFIGDEFAULT_GEOLOC_FUZZFACTOR);

  const char *country = json_object_get_string(json__get(jobj, ACCOUNT_JSONATTR_LOC_ZONE_COUNTRY));
  const char *region  = json_object_get_string(json__get(jobj, ACCOUNT_JSONATTR_LOC_ZONE_REGION));
  const char *city    = json_object_get_string(json__get(jobj, ACCOUNT_JSONATTR_LOC_ZONE_CITY));
  location_ptr->country					=	strbufdup_nullable(country, MINIBUF, ^{return CONFIG_DEFAULT_PREFS_STRING_VALUE;});
  location_ptr->admin_area			=	strbufdup_nullable(region, MINIBUF, ^{return CONFIG_DEFAULT_PREFS_STRING_VALUE;});
	location_ptr->locality				=	strbufdup_nullable(city, MINIBUF, ^{return CONFIG_DEFAULT_PREFS_STRING_VALUE;});
	location_ptr->last_updated		=	time(NULL);
}

void static
_UpdateUserLocationAssignmentByUserSourceByProto(LocationDescription *location_ptr,  LocationRecord *location_record_ptr)
{
  DestructLocationDescription(location_ptr);

  location_ptr->longitude				=	location_record_ptr->longitude;
  location_ptr->latitude				=	location_record_ptr->latitude;
  _FuzzGeoLocation(location_ptr, _CONFIGDEFAULT_GEOLOC_FUZZFACTOR);

  const char *location_descriptor = location_record_ptr->country;
  location_ptr->country					=	IS_STR_LOADED(location_descriptor)?strdup(location_descriptor):NULL;
  location_descriptor = location_record_ptr->adminarea;
  location_ptr->admin_area			=	IS_STR_LOADED(location_descriptor)?strdup(location_descriptor):NULL;
  location_descriptor = location_record_ptr->locality;
  location_ptr->locality				=	IS_STR_LOADED(location_descriptor)?strdup(location_descriptor):NULL;
  location_ptr->last_updated		=	time(NULL);

}

void
UpdateUserLocationAssignmentByProto(LocationDescription *location_ptr,  LocationRecord *location_record_ptr)
{
	DestructLocationDescription(location_ptr);

	location_ptr->longitude				=	location_record_ptr->longitude;
	location_ptr->latitude				=	location_record_ptr->latitude;
	_FuzzGeoLocation(location_ptr, _CONFIGDEFAULT_GEOLOC_FUZZFACTOR);

	location_ptr->country					=	IS_STR_LOADED(location_record_ptr->country)?strdup(location_record_ptr->country):NULL;
	location_ptr->admin_area			=	IS_STR_LOADED(location_record_ptr->adminarea)?strdup(location_record_ptr->adminarea):NULL;
	location_ptr->locality				=	IS_STR_LOADED(location_record_ptr->locality)?strdup(location_record_ptr->locality):NULL;
	location_ptr->last_updated		=	time(NULL);
}

/**
 * 	@brief: calculate the total possible byte size based on given location fields
 */
__attribute__ ((const)) size_t
SizeofLocationDescription(const LocationDescription *location_ptr)
{
	size_t len	=	(IS_PRESENT(location_ptr->country)    ? strlen(location_ptr->country)   : 0)			+
								(IS_PRESENT(location_ptr->admin_area) ? strlen(location_ptr->admin_area): 0)	    +
								(IS_PRESENT(location_ptr->locality)   ? strlen(location_ptr->locality)  : 0)			+
								((sizeof(UINT64_LONGEST_STR) * 4 ) + 2); //long/lat xxx.yyy, +2 for the '-' sign... going bit over here to be safe

	return len;
}

/**
 * 	@brief: returns the fields tokensied with each field's size computed as well
 * 	User must allocate two collections inline with known an fixed number of fields
 * 	@deprecated dont use this function, as scope of variable declared below will be lost. Should bbe declared in the calling function scope
 */
__attribute__ ((unused)) void
SizeofLocationDescriptionTokenised(const LocationDescription *location_ptr, CollectionDescriptorPair *pair)
{
  //TODO dont use this function, as scope of variable declared below will be lost. Should bbe declared in the calling function scope
	char 		*location_fields[5];
	size_t	location_fields_sz[5];

	pair->first.collection		=	(collection_t **)location_fields;
	pair->second.collection	=	(collection_t **)location_fields_sz;

	if (likely(IS_PRESENT(location_ptr->country))) {
		location_fields[LOCATION_COUNTRY]			=	location_ptr->country;
		location_fields_sz[LOCATION_COUNTRY]	=	strlen(location_ptr->country);
	} else {
		location_fields[LOCATION_COUNTRY]			=	"";
		location_fields_sz[LOCATION_COUNTRY]	=	0;
	}

	if (likely(IS_PRESENT(location_ptr->admin_area))) {
		location_fields[LOCATION_ADMINAREA]			=	location_ptr->admin_area;
		location_fields_sz[LOCATION_ADMINAREA]	=	strlen(location_ptr->admin_area);
	} else {
		location_fields[LOCATION_ADMINAREA]			=	"";
		location_fields_sz[LOCATION_ADMINAREA]	=	0;
	}

	if (likely(IS_PRESENT(location_ptr->locality))) {
		location_fields[LOCATION_LOCALITY]			=	location_ptr->locality;
		location_fields_sz[LOCATION_LOCALITY]		=	strlen(location_ptr->locality);
	} else {
		location_fields[LOCATION_LOCALITY]			=	"";
		location_fields_sz[LOCATION_LOCALITY]		=	0;
	}

}

/**
 * 	@brief: format the location description fileds in way suitable for redis storage.
 * 	@param formated_location_value_out: must be allocated by user
 */
void
FormatCacheBackendLocationFieldValue(const LocationDescription *location_ptr, BufferDescriptor *buffer_out)
{
	buffer_out->size = snprintf(buffer_out->data, buffer_out->size_max, "%s:%s:%s:%f:%f",
                              (IS_PRESENT(location_ptr->country)? location_ptr->country : ""),
                              (IS_PRESENT(location_ptr->admin_area)? location_ptr->admin_area : ""),
                              (IS_PRESENT(location_ptr->locality)? location_ptr->locality : ""),
                              location_ptr->longitude,
                              location_ptr->latitude);

}

int
ParseCacheBackendStoredLocationDescription(LocationDescription *location_ptr, const char *location_stored, bool flag_dirty)
{
	char *location_copy = strdupa(location_stored);

	char 		*location_fields[5];
	size_t	location_fields_sz[5] __unused;

	//"c:a:l:long:lat"
	char *walker;
	char *token	=	strchr(location_copy, ':');
	if (IS_EMPTY(token))	goto return_misformatted_location;

	*token++='\0';	//"a:l:long:lat"

	if (*location_copy == '\0')	goto return_misformatted_location;
	location_fields[LOCATION_COUNTRY]			=	location_copy;
	location_fields_sz[LOCATION_COUNTRY]	=	strlen(location_copy);

	///--------
	if (*token == '\0')	goto return_misformatted_location;
	walker = token;
	token = strchr(walker, ':');
	if (IS_EMPTY(token))	goto return_misformatted_location;

	*token++ = '\0';	//"l:long:lat"
	if (*walker == '\0')	goto return_misformatted_location;
	location_fields[LOCATION_ADMINAREA]			=	walker;
	location_fields_sz[LOCATION_ADMINAREA]	=	strlen(walker);

	///----------
	if (*token == '\0')	goto return_misformatted_location;
	walker = token;
	token = strchr(walker, ':');
	if (IS_EMPTY(token))	goto return_misformatted_location;

	*token++ = '\0';	//"long:lat"
	if (*walker == '\0')	goto return_misformatted_location;
	location_fields[LOCATION_LOCALITY]			=	walker;
	location_fields_sz[LOCATION_LOCALITY]	=	strlen(walker);

	///-------
	if (*token == '\0')	goto return_misformatted_location;
	walker = token;
	token = strchr(walker, ':');
	if (IS_EMPTY(token))	goto return_misformatted_location;

	*token++ = '\0';	//"lat"
	if (*walker == '\0')	goto return_misformatted_location;
	location_fields[LOCATION_LONGITUDE]			=	walker;
	location_fields_sz[LOCATION_LONGITUDE]	=	strlen(walker);

	///-------
	if (*token == '\0')	goto return_misformatted_location;
	location_fields[LOCATION_LATITUDE]			=	token;
	location_fields_sz[LOCATION_LATITUDE]	=	strlen(token);

	float long_backup	=	location_ptr->longitude;
	float lat_backup	=	location_ptr->latitude;

	if ((location_ptr->longitude = atof(location_fields[LOCATION_LONGITUDE])) == 0.0)	{location_ptr->longitude = long_backup; goto return_misformatted_location;}
	if ((location_ptr->latitude = atof(location_fields[LOCATION_LATITUDE])) == 0.0)		{location_ptr->longitude = long_backup; location_ptr->latitude = lat_backup; goto return_misformatted_location;}

	if (flag_dirty)	DestructLocationDescription(location_ptr);

	location_ptr->country			=	strdup(location_fields[LOCATION_COUNTRY]);
	location_ptr->admin_area	=	strdup(location_fields[LOCATION_ADMINAREA]);
	location_ptr->locality		=	strdup(location_fields[LOCATION_LOCALITY]);

	return_success:
	return 0;

	return_misformatted_location:
	syslog(LOG_DEBUG, "%s (pid:'%lu' location_stored:'%s'): ERROR: STORED LOCATION DESCRIPTOR IS MISFORMATTED", __func__, pthread_self(), location_stored);

	return -1;
}

/**
 * 	@brief Main interface for globally updating the baseloc value
 */
UFSRVResult *
UpdateHomebaseGeoLocDynamicAssignment(Session *sesn_ptr, const char *baseloc, unsigned long call_flags_sesn)
{
	if (IS_STR_LOADED(baseloc) && IS_STR_LOADED(SESSION_HOMEBASE_GEOLOC_DYNAMIC(sesn_ptr))) {
		if ((strcasecmp(baseloc, SESSION_HOMEBASE_GEOLOC_DYNAMIC(sesn_ptr))) == 0)	goto return_baseloc_unchanged;
	}

	if (call_flags_sesn&CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND) {
		CacheBackendSetSessionAttribute(sesn_ptr, SESSION_USERID(sesn_ptr), "baseloc", baseloc);
		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
			if (call_flags_sesn&CALL_FLAG_BROADCAST_SESSION_EVENT) {
				InterBroadcastBaseLoc(sesn_ptr, (ClientContextData *)SESSION_HOMEBASE_GEOLOC_DYNAMIC(sesn_ptr), &((FenceEvent){0}), COMMAND_ARGS__UPDATED);
			}
			else goto memory_store;

			goto memory_store;
		}

		goto return_backend_error;
	}

	memory_store:
	if (IS_PRESENT(SESSION_HOMEBASE_GEOLOC_DYNAMIC(sesn_ptr))) free(SESSION_HOMEBASE_GEOLOC_DYNAMIC(sesn_ptr));
  SESSION_HOMEBASE_GEOLOC_DYNAMIC(sesn_ptr) = strdup(baseloc);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

	return_baseloc_unchanged:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_LOCATION_UNCHANGED)

	return_backend_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
}

/**
 * 	@brief Main interface for globally updating the baseloc value
 */
UFSRVResult *
UpdateHomebaseGeoLocUserPrefAssignment(Session *sesn_ptr, const char *baseloc, unsigned long call_flags_sesn)
{
	if (IS_STR_LOADED(baseloc) && IS_STR_LOADED(SESSION_USERPREF_HOMEBASE_GEOLOC(sesn_ptr))) {
		if ((strcasecmp(baseloc, SESSION_USERPREF_HOMEBASE_GEOLOC(sesn_ptr))) == 0)	goto return_baseloc_unchanged;
	}

	if (call_flags_sesn&CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND) {
		CacheBackendSetSessionAttribute(sesn_ptr, SESSION_USERID(sesn_ptr), "home_baseloc", baseloc);
		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
			if (call_flags_sesn&CALL_FLAG_BROADCAST_SESSION_EVENT) {
				InterBroadcastBaseLoc(sesn_ptr, (ClientContextData *)SESSION_USERPREF_HOMEBASE_GEOLOC(sesn_ptr), &((FenceEvent){0}), COMMAND_ARGS__UPDATED);
			}
			else goto memory_store;

			goto memory_store;
		}

		goto return_backend_error;
	}

	memory_store:
	if (IS_PRESENT(SESSION_USERPREF_HOMEBASE_GEOLOC(sesn_ptr))) free(SESSION_USERPREF_HOMEBASE_GEOLOC(sesn_ptr));
  SESSION_USERPREF_HOMEBASE_GEOLOC(sesn_ptr) = strdup(baseloc);
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

	return_baseloc_unchanged:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_LOCATION_UNCHANGED)

	return_backend_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
}

/**
 * 	@brief Main interface for updating the user's location values across all stores. Currently relies on json formatting,
 * 	but that might change
 * 	@locks NONE
 * 	@locked sesn_ptr by caller
 */
UFSRVResult *
UpdateUserLocationAssignment(Session *sesn_ptr, ClientContextData *location_data_ptr, enum GeoLocRoamingTrigger geoloc_trigger, unsigned long call_flags_sesn)
{
	const char *cachebackend_attrname;

	LocationDescription *location_ptr	=	NULL;
	UFSRVResult * (*inter_broadcaster)();

	if (call_flags_sesn&CALL_FLAG_LOCTION_BY_USER) {
		location_ptr = SESSION_ULOCATION_BYUSER_PTR(sesn_ptr);
		cachebackend_attrname = "location_byu"; //define in session.h
		_UpdateUserLocationAssignmentByUserSourceByProto(SESSION_ULOCATION_BYUSER_PTR(sesn_ptr), (LocationRecord *)location_data_ptr);
    LOCATION_GEOLOC_TRIGGER(SESSION_ULOCATION_BYUSER_PTR(sesn_ptr)) = geoloc_trigger;
		inter_broadcaster = (UFSRVResult * (*)())InterBroadcastLocationAddressByUser;
	} else	if (call_flags_sesn & CALL_FLAG_LOCATION_BY_SERVER) {
		location_ptr = SESSION_ULOCATION_BYSERVER_PTR(sesn_ptr);
		cachebackend_attrname = "location_bys";
		_UpdateUserLocationAssignmentByServerSource(SESSION_ULOCATION_BYSERVER_PTR(sesn_ptr), (json_object *)location_data_ptr);
    LOCATION_GEOLOC_TRIGGER(SESSION_ULOCATION_BYSERVER_PTR(sesn_ptr)) = geoloc_trigger;
		inter_broadcaster = (UFSRVResult * (*)())InterBroadcastLocationAddressByServer;
	} else {
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
	}

	if (call_flags_sesn&CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND) {
		size_t	value_sz	=	SizeofLocationDescription((const LocationDescription *)location_ptr) + BACKEND_LOCATION_SEPARATORS_SZ;
		char 		formatted_location_value[value_sz];

		FormatCacheBackendLocationFieldValue((const LocationDescription *)location_ptr, &((BufferDescriptor){formatted_location_value, 0, value_sz}));
		//CacheBackendSetSessionAttribute(sesn_ptr, SESSION_USERID(sesn_ptr), cachebackend_attrname, (const char *)formatted_location_value);
		_CacheBackendUpdateLocationRecord(sesn_ptr, (const LocationDescription *)location_ptr, cachebackend_attrname, (const char *)formatted_location_value);
		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
			//we only set this if the former succeded
			if (call_flags_sesn&CALL_FLAG_BROADCAST_SESSION_EVENT) {
				return ((*inter_broadcaster)(sesn_ptr, (ClientContextData *)location_ptr, &((FenceEvent){0}), COMMAND_ARGS__UPDATED));
			}
		}

		return &(sesn_ptr->sservice.result);//could be error or success output of CacheBackendSetSessionAttribute
	}

	if (call_flags_sesn&CALL_FLAG_BROADCAST_SESSION_EVENT) {
		return ((*inter_broadcaster)(sesn_ptr, (ClientContextData *)location_ptr, &((FenceEvent){0}), COMMAND_ARGS__UPDATED));
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

/**
 * @brief given a new location state, update stored location state for the user
 * @param location_record_ptr Raw protobuf record provided by user
 * @return state describing nature of location change
 */
UFSRVResult *
UpdateLocationByWireProto(InstanceContextForSession *ctx_ptr, const LocationRecord *location_record_ptr)
{
		unsigned short origin					=	0;
		LocationDescription *loc_ptr	=	NULL;
    LocationChangeZoneMarker location_marker = {0};

//		json_bool self_zoned = json_object_get_boolean(json__get(jobj, "isSelfZoned"));
//		if (self_zoned != 0)	USER_ATTRIBUTE_SET(ctx_ptr->sesn_ptr, USERATTRIBUTE_DEFINES_USERZONE);

    //at least one reference, as either locality and admin can be null
		if (IS_STR_LOADED(location_record_ptr->country) || IS_STR_LOADED(location_record_ptr->adminarea) || IS_STR_LOADED(location_record_ptr->locality)) {
      UpdateUserLocationByUserByWireProto(ctx_ptr->sesn_ptr, location_record_ptr, &location_marker, CALL_FLAG_LOCTION_BY_USER | CALL_FLAG_WRITEBACK_SESSION_DATA_TO_BACKEND | CALL_FLAG_BROADCAST_SESSION_EVENT);
      loc_ptr = (LocationDescription *)SESSION_RESULT_USERDATA(ctx_ptr->sesn_ptr);
      origin = 2;
		} else {
      loc_ptr = DetermineLocationByServerByWireProto(ctx_ptr->sesn_ptr, location_record_ptr);
      origin = 1;
		}

		//feeds into the creation of geo base fence if one doesn't already exist
		int result;
	   switch ((result = ProcessUserLocationRoaming(ctx_ptr->instance_sesn_ptr, loc_ptr, &location_marker, origin))) //<<<<<<<<<<<<<<<<<<<<<<<<<<
	   {
		   case LOCATION_STATE_UNCHANGED:
       _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_LOCATION_UNCHANGED)

		   case LOCATION_STATE_CHANGED:
		   case LOCATION_STATE_INITIALISED:
				if (SESSION_RESULT_TYPE_ERROR(ctx_ptr->sesn_ptr))	_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

				_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, result == LOCATION_STATE_CHANGED? RESCODE_LOCATION_CHANGED : RESCODE_LOCATION_INIT)

		   case LOCATION_STATE_UNINITIALISED:
				syslog(LOG_NOTICE, "%s (pid:'%lu',  cid:'%lu'): COULD NOT INITIALISE USER LOCATION", __func__, pthread_self(), SESSION_ID(ctx_ptr->sesn_ptr));
				_RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOCATION_UNINIT)

		   case LOCATION_STATE_ERROR:
			   syslog (LOG_NOTICE, "%s (pid:'%lu', cid:'%lu'): ERROR: COULD NOT INITIALISE USER LOCATION", __func__, pthread_self(), SESSION_ID(ctx_ptr->sesn_ptr));
			   _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_LOCATION_UNINIT)
	   }

  _RETURN_RESULT_SESN(ctx_ptr->sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_LOCATION_UNINIT)
}

/**
 * @brief Initialise LocationRecord based on stored location information. All pointer assignments by reference,
 * so object must remain in scope.
 * @param sesn_ptr
 * @param location_record_ptr user-provided and allocated
 * @return true on successfull initialisation
 * @locked sesn_ptr
 */
bool
BuildUserLocationByProto(Session *sesn_ptr, LocationRecord *location_record_ptr)
{
  if (SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_initialised) {
    location_record_ptr->source = LOCATION_RECORD__SOURCE__BY_USER;
    //client should use its own readings
    if (SESSION_SERVICE(sesn_ptr)->user.user_details.user_location.country)
      location_record_ptr->country = SESSION_SERVICE(sesn_ptr)->user.user_details.user_location.country;
    if (SESSION_SERVICE(sesn_ptr)->user.user_details.user_location.admin_area)
      location_record_ptr->adminarea = SESSION_SERVICE(sesn_ptr)->user.user_details.user_location.admin_area;
    if (SESSION_SERVICE(sesn_ptr)->user.user_details.user_location.locality)
      location_record_ptr->adminarea = SESSION_SERVICE(sesn_ptr)->user.user_details.user_location.locality;
    if (SESSION_SERVICE(sesn_ptr)->user.user_details.user_location.longitude != 0.0)
      location_record_ptr->longitude = SESSION_SERVICE(sesn_ptr)->user.user_details.user_location.longitude;
    if (SESSION_SERVICE(sesn_ptr)->user.user_details.user_location.latitude != 0.0)
      location_record_ptr->latitude = SESSION_SERVICE(sesn_ptr)->user.user_details.user_location.latitude;

    return true;
  } else if (SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_by_server_initialised) {
    location_record_ptr->source = LOCATION_RECORD__SOURCE__BY_SERVER;

    if (SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_by_server.country)
      location_record_ptr->country =  SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_by_server.country;
    if (SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_by_server.admin_area)
      location_record_ptr->adminarea = SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_by_server.admin_area;
    if (SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_by_server.locality)
      location_record_ptr->locality = SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_by_server.locality;
    if (SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_by_server.longitude != 0.0)
      location_record_ptr->longitude = SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_by_server.longitude;
    if (SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_by_server.latitude != 0.0)
      location_record_ptr->latitude = SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_by_server.latitude;

    return  true;
  }

  return false;

}

static void
_MarkLocationChangedZones(const LocationRecord *location_record_ptr, LocationDescription *location_description_ptr, LocationChangeZoneMarker *marker_ptr) {
  const char *locality = location_record_ptr->locality;
  if (IS_STR_LOADED(locality)) {
    if (!IS_STR_LOADED(location_description_ptr->locality) || (IS_STR_LOADED(location_description_ptr->locality) && strcasecmp(locality, location_description_ptr->locality) != 0)) {//user with no location_description_ptr->locality in their session may indicate a brand new user, or user's devices relation location permission was off
      marker_ptr->locality.isLocalityChanged = true;
      marker_ptr->locality.geoloc_trigger = GEOLOC_TRIGGER_NEIGHBOURHOOD;
    }
  }

  const char *admin_area = location_record_ptr->adminarea;
  if (IS_STR_LOADED(admin_area)) {
    if (!IS_STR_LOADED(location_description_ptr->admin_area) || (IS_STR_LOADED(location_description_ptr->admin_area) && strcasecmp(admin_area, location_description_ptr->admin_area) != 0)) {
      marker_ptr->admin_area.isAdminAreaChanged = true;
      marker_ptr->admin_area.geoloc_trigger = GEOLOC_TRIGGER_REGIONHOOD;
    }
  }

  const char *country = location_record_ptr->country;
  if (IS_STR_LOADED(country)) {
    if (!IS_STR_LOADED(location_description_ptr->country) || (IS_STR_LOADED(location_description_ptr->country) && strcasecmp(country, location_description_ptr->country) != 0)) {
      marker_ptr->country.isCountryChanged = true;
      marker_ptr->country.geoloc_trigger = GEOLOC_TRIGGER_COUNTRYHOOD;
    }
  }
}

static bool _IsAnyLocationZoneChanged(const LocationChangeZoneMarker *location_marker_ptr)
{
  return location_marker_ptr->locality.isLocalityChanged || location_marker_ptr->admin_area.isAdminAreaChanged || location_marker_ptr->country.isCountryChanged;
}

/**
 * 	@brief Main interface function for handling direct, user-initiated updates to user's location. Currently the feed-in is based on
 * 	json.
 *
 * 	@return on location change the LocationDescription is returned. If no change, NULL is returned and rescode set
 * 	to RESCODE_LOCATION_UNCHANGED
 */
UFSRVResult *
UpdateUserLocationByUserByWireProto(Session *sesn_ptr, const LocationRecord *location_record_ptr, LocationChangeZoneMarker *location_marker_ptr_out, unsigned long call_flags_sesn)
{
  _MarkLocationChangedZones(location_record_ptr, &sesn_ptr->sservice.user.user_details.user_location, location_marker_ptr_out);

  if (sesn_ptr->sservice.user.user_details.user_location_initialised) {
    if (_IsAnyLocationZoneChanged(location_marker_ptr_out)) {
#ifdef __UF_TESTING
      syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: CHANGE in user location: provided locality: '%s'. current in-use locality: '%s'. provided admin_area: '%s'. current in-use admin_area: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), location_record_ptr->locality,  sesn_ptr->sservice.user.user_details.user_location.locality, location_record_ptr->adminarea,  sesn_ptr->sservice.user.user_details.user_location.admin_area);
#endif

      UpdateUserLocationAssignment(sesn_ptr, CLIENT_CTX_DATA(location_record_ptr), GEOLOC_TRIGGER_UNDEFINED, call_flags_sesn);
      UpdateHomebaseGeoLocDynamicAssignment(sesn_ptr, location_record_ptr->baseloc, call_flags_sesn);

      _RETURN_RESULT_SESN(sesn_ptr, SESSION_ULOCATION_BYUSER_PTR(sesn_ptr), RESULT_TYPE_SUCCESS, RESCODE_LOCATION_CHANGED)
    } else {
#ifdef __UF_TESTING
      syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: NO CHANGE in user location: passed locality: '%s'. Current in-use locality: '%s': No further processing.", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), location_record_ptr->locality, sesn_ptr->sservice.user.user_details.user_location.locality);
#endif
      _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_LOCATION_UNCHANGED)
    }
  } else {
    //this is new user session for which we never processed location prior or some complete reset.
    User *u_ptr = &(sesn_ptr->sservice.user);
    UpdateUserLocationAssignment(sesn_ptr, CLIENT_CTX_DATA(location_record_ptr), GEOLOC_TRIGGER_UNDEFINED, call_flags_sesn);
    UpdateHomebaseGeoLocDynamicAssignment(sesn_ptr, location_record_ptr->baseloc, call_flags_sesn);

#ifdef __UF_TESTING
    syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): INITIALISE user location:  current in-use admin area: '%s'.", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), u_ptr->user_details.user_location.admin_area);
#endif

    _RETURN_RESULT_SESN(sesn_ptr, SESSION_ULOCATION_BYUSER_PTR(sesn_ptr), RESULT_TYPE_SUCCESS, RESCODE_LOCATION_CHANGED)
  }

  _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

static UFSRVResult *
_CacheBackendUpdateLocationRecord(Session *sesn_ptr, const LocationDescription *location_ptr, const char *location_name, const char *location_value)
{
	PersistanceBackend		*sesn_backend_ptr	=	SESSION_SESSION_BACKEND(sesn_ptr);
#define COMMANDSET_SIZE	4

	(*sesn_backend_ptr->send_command_multi)(sesn_ptr,	"MULTI");
	(*sesn_backend_ptr->send_command_multi)(sesn_ptr,	REDIS_CMD_USER_LOCATION_SET,  SESSION_USERID(sesn_ptr), location_name, location_value);
	(*sesn_backend_ptr->send_command_multi)(sesn_ptr,	REDIS_CMD_USER_GEOHASH_ADD, location_ptr->longitude, location_ptr->latitude, SESSION_USERID(sesn_ptr), 0);//0 empty placeholder
	(*sesn_backend_ptr->send_command_multi)(sesn_ptr,	"EXEC");

	size_t				actually_processed	=	COMMANDSET_SIZE;
	size_t				commands_successful	=	actually_processed;
	redisReply		*replies[actually_processed];
	memset (replies, 0, sizeof(replies));

	for (size_t i=0; i<actually_processed; i++) {
		if ((RedisGetReply(sesn_ptr, sesn_backend_ptr, (void *)&replies[i])) != REDIS_OK) {
			commands_successful--;

			if ((replies[i] != NULL)) {
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', idx:'%lu'): ERROR PROCESSING MULTI SET COMMAND. ERROR: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i, replies[i]->str);
			} else {
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', i:'%lu'): ERROR COULD ISSUE GET COMMAND: BACKEND CONNECTIVITY ERROR", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), i);
			}
		}
	}//for

	//diagnostics
	if (commands_successful!=actually_processed) {
		for (size_t i=0; i<actually_processed; i++)	if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);

		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
	}

	//verification block
	{
#define EXEC_COMMAND_IDX (actually_processed - 1)

		for (size_t i=0; i<actually_processed-1; i++)	if (IS_PRESENT(replies[i]))	freeReplyObject(replies[i]);

		if (unlikely(IS_EMPTY(replies[EXEC_COMMAND_IDX]))) {//idx for EXEC, which is last
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR: REDIS TRANSCTION ERROR: NULL COMMAND ARRAY RESPONSE", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
		}

		if (replies[EXEC_COMMAND_IDX]->elements == actually_processed - 2) {
			//these should be contextual to the actual return codes for the above commands
			bool is_error = false;
			if (!(strcmp(replies[EXEC_COMMAND_IDX]->element[0]->str, "OK") == 0)) {
				syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', error:'%s'): ERROR: HMSET Failed", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), replies[EXEC_COMMAND_IDX]->element[0]->str);
				is_error = true;
			}
			//for this command we get 1 if newly added record, but we also get zero if existing record was updated
			//if (replies[EXEC_COMMAND_IDX]->element[1]->integer!=1)	{
			// syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', integer:'%llu', error:'%s'): ERROR: GEOADD Failed", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), replies[EXEC_COMMAND_IDX]->element[1]->integer, replies[EXEC_COMMAND_IDX]->element[1]->str);
			// is_error = true;
		  //}

			freeReplyObject(replies[EXEC_COMMAND_IDX]);

			if (is_error) _RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA);
		} else {
			//only remaining element is at EXEC_COMMAND_IDX
			syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu', dispatched:'%lu', received:'%lu'): ERROR: REDIS TRANSCTION ERROR: DISPATCHED/RECEIVED COMMANDS COUNT MISMATCH", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), actually_processed-2, replies[EXEC_COMMAND_IDX]->elements);
			if (IS_PRESENT(replies[EXEC_COMMAND_IDX]))	freeReplyObject(replies[EXEC_COMMAND_IDX]);

			_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_BACKEND_DATA)
		}
	}


	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA);

#undef EXEC_COMMAND_IDX

}

void
ResetSessionGeoFenceData(InstanceHolderForSession *instance_sesn_ptr)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
	if (IS_PRESENT(SESSION_GEOFENCE_CURRENT_INSTANCE(sesn_ptr)))	{FenceDecrementReference(SESSION_GEOFENCE_CURRENT_INSTANCE(sesn_ptr), 1); 	SESSION_GEOFENCE_CURRENT_INSTANCE(sesn_ptr) = NULL;}
	if (IS_PRESENT(SESSION_GEOFENCE_LAST_INSTANCE(sesn_ptr)))		{FenceDecrementReference(SESSION_GEOFENCE_LAST_INSTANCE(sesn_ptr), 1);			SESSION_GEOFENCE_LAST_INSTANCE(sesn_ptr) = NULL;}

}

/**
 * 	@brief: Designed to to work with session data loaded from backend, where only fids are known
 */
void
UpdateSessionGeoFenceDataByFid(Session *sesn_ptr, unsigned long fid_current, unsigned long fid_past)
{
	InstanceHolder  *instance_f_ptr_current  = NULL,
				          *instance_f_ptr_past		 = NULL;

	if (fid_current > 0) {
		FindFenceById(sesn_ptr, fid_current, FENCE_CALLFLAG_SEARCH_BACKEND|FENCE_CALLFLAG_HASH_FENCE_LOCALLY|FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE);//0);
    instance_f_ptr_current = (InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr);
	}
	if (fid_past > 0) {
		FindFenceById(sesn_ptr, fid_past, FENCE_CALLFLAG_SEARCH_BACKEND|FENCE_CALLFLAG_HASH_FENCE_LOCALLY|FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE);//0);
    instance_f_ptr_past = (InstanceHolderForFence *)SESSION_RESULT_USERDATA(sesn_ptr);
	}

	UpdateSessionGeoFenceData(sesn_ptr, instance_f_ptr_current, instance_f_ptr_past);
}

/**
 * 	@brief: This is a utility designed to be called in the context of INCOMING UfsrvMsgQueue communication.
 * 	Always cleared and set s one unit.
 * 	@locked sesn_ptr: must be locked by the caller
 */
void
UpdateSessionGeoFenceData(Session *sesn_ptr, InstanceHolderForFence *instance_f_ptr_current, InstanceHolderForFence *instance_f_ptr_past)
{
	//reset regardless
	if (IS_PRESENT(SESSION_GEOFENCE_CURRENT_INSTANCE(sesn_ptr)))	FenceDecrementReference(SESSION_GEOFENCE_CURRENT_INSTANCE(sesn_ptr), 1);
	if (IS_PRESENT(SESSION_GEOFENCE_LAST_INSTANCE(sesn_ptr)))		FenceDecrementReference(SESSION_GEOFENCE_LAST_INSTANCE(sesn_ptr), 1);

	if (IS_PRESENT(instance_f_ptr_current)) {
			SESSION_GEOFENCE_CURRENT_INSTANCE(sesn_ptr) = instance_f_ptr_current;
			FenceIncrementReference(SESSION_GEOFENCE_CURRENT_INSTANCE(sesn_ptr), 1);
	}
	else 	SESSION_GEOFENCE_CURRENT_INSTANCE(sesn_ptr) = NULL;

	if (IS_PRESENT(instance_f_ptr_past)) {
		SESSION_GEOFENCE_LAST_INSTANCE(sesn_ptr) = instance_f_ptr_past;
		FenceIncrementReference(SESSION_GEOFENCE_LAST_INSTANCE(sesn_ptr), 1);
	}
	else 	SESSION_GEOFENCE_LAST_INSTANCE(sesn_ptr) = NULL;

}

static UFSRVResult *
_ResolveRoamingModeAndJoin(InstanceHolderForSession *instance_sesn_ptr, LocationDescription *location_description_ptr, const LocationChangeZoneMarker *location_marker_ptr);
static UFSRVResult *_HandleRoamingModeWandererGeoJoin(InstanceHolderForSession *instance_sesn_ptr, LocationDescription *location_description_ptr);
static UFSRVResult *_HandleRoamingModeConquerorGeoJoin(InstanceHolderForSession *instance_sesn_ptr, LocationDescription *location_description_ptr);
static UFSRVResult *_HandleRoamingModeJournalerGeoJoin(InstanceHolderForSession *instance_sesn_ptr, LocationDescription *location_description_ptr);
static UFSRVResult *_HandleGeoJoinForWanderer(InstanceHolderForSession *instance_sesn_ptr, LocationDescription *location_description_ptr);
static inline UFSRVResult * _UpdateCurrentPastGeoFenceAssignments(Session *sesn_ptr, InstanceHolderForFence *instance_f_ptr_current, bool);

/**
 * 	@brief: Helper routine to consistently maintain the values of SESSION_GEOFENCE_CURRENT(sesn_ptr) and
 * 	 SESSION_GEOFENCE_LAST(sesn_ptr)
 */
static inline UFSRVResult *
_UpdateCurrentPastGeoFenceAssignments(Session *sesn_ptr, InstanceHolderForFence *instance_f_ptr_current, bool update_backend_flag)
{
  Fence *f_ptr_current = FenceOffInstanceHolder(instance_f_ptr_current);

	if	(IS_PRESENT(SESSION_GEOFENCE_CURRENT_INSTANCE(sesn_ptr)) && FENCE_ID(f_ptr_current) != FENCE_ID(SESSION_GEOFENCE_CURRENT(sesn_ptr))) {
		if (IS_PRESENT(SESSION_GEOFENCE_LAST_INSTANCE(sesn_ptr)))	FenceDecrementReference(SESSION_GEOFENCE_LAST_INSTANCE(sesn_ptr), 1);
		SESSION_GEOFENCE_LAST_INSTANCE(sesn_ptr) = SESSION_GEOFENCE_CURRENT_INSTANCE(sesn_ptr); //no need to increment ref as we just reuse that from old current

		SESSION_GEOFENCE_CURRENT_INSTANCE(sesn_ptr) = instance_f_ptr_current;
		FenceIncrementReference(instance_f_ptr_current, 1);

		if (update_backend_flag)	return(UpdateBackendSessionGeoJoinData (sesn_ptr, SESSION_GEOFENCE_CURRENT(sesn_ptr), SESSION_GEOFENCE_LAST(sesn_ptr)));
		else 											{_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)}
	}
	//else if the same we keep as is

	if (IS_EMPTY(SESSION_GEOFENCE_CURRENT_INSTANCE(sesn_ptr))) {
		if (IS_PRESENT(SESSION_GEOFENCE_LAST_INSTANCE(sesn_ptr)) && (FenceOffInstanceHolder(instance_f_ptr_current) == SESSION_GEOFENCE_LAST(sesn_ptr))) {
			SESSION_GEOFENCE_LAST_INSTANCE(sesn_ptr) = NULL;
			SESSION_GEOFENCE_CURRENT_INSTANCE(sesn_ptr) = instance_f_ptr_current;//not incrementing ref as PAST would have had that already

			if (update_backend_flag)	return(UpdateBackendSessionGeoJoinData(sesn_ptr, SESSION_GEOFENCE_CURRENT(sesn_ptr), IS_PRESENT(SESSION_GEOFENCE_LAST_INSTANCE(sesn_ptr))?SESSION_GEOFENCE_LAST(sesn_ptr):NULL));
			else 											{_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)}
		}

		SESSION_GEOFENCE_CURRENT_INSTANCE(sesn_ptr) = instance_f_ptr_current;
		FenceIncrementReference(instance_f_ptr_current, 1);

		//keep LAST as is

		if (update_backend_flag)	return(UpdateBackendSessionGeoJoinData(sesn_ptr, SESSION_GEOFENCE_CURRENT(sesn_ptr), IS_PRESENT(SESSION_GEOFENCE_LAST_INSTANCE(sesn_ptr))?SESSION_GEOFENCE_LAST(sesn_ptr):NULL));
		else 											{_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)}
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER)

}

/**
 * 	@brief: User just piles up geofences as they happen
 */
static UFSRVResult *
_HandleRoamingModeConquerorGeoJoin(InstanceHolderForSession *instance_sesn_ptr, LocationDescription *location_description_ptr)
{
	UFSRVResult *res_ptr;

	Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	res_ptr = IsUserAllowedToJoinGeoFence(instance_sesn_ptr, location_description_ptr);

	if (_RESULT_TYPE_SUCCESS(res_ptr) && (_RESULT_CODE_EQUAL(res_ptr, RESCODE_USER_FENCE_JOINED))) {
		FenceStateDescriptor *fstate_ptr  = FenceStateDescriptorOffInstanceHolder(((InstanceHolderForFenceStateDescriptor *)_RESULT_USERDATA(res_ptr)));
		return(_UpdateCurrentPastGeoFenceAssignments(sesn_ptr, FENCESTATE_INSTANCE_HOLDER(fstate_ptr), true));
	} else if (_RESULT_CODE_EQUAL(res_ptr, RESCODE_USER_FENCE_ALREADYIN)) {
    FenceStateDescriptor *fstate_ptr = FenceStateDescriptorOffInstanceHolder((InstanceHolderForFenceStateDescriptor *)_RESULT_USERDATA(res_ptr));
		return(_UpdateCurrentPastGeoFenceAssignments(sesn_ptr, FENCESTATE_INSTANCE_HOLDER(fstate_ptr), true));
	}

	return res_ptr;//outcome ofIsUserAllowed...
}

/**
 * 	@brief: Helper function. Assumes that SESSION_GEOFENCE_CURRENT slot has been cleaned and dereferenced
 */
__unused inline static UFSRVResult *
_HandleGeoJoinForWanderer(InstanceHolderForSession *instance_sesn_ptr, LocationDescription *location_description_ptr)
{
  Session *sesn_ptr  = SessionOffInstanceHolder(instance_sesn_ptr);

	UFSRVResult *res_ptr = IsUserAllowedToJoinGeoFence(instance_sesn_ptr, location_description_ptr);

	if ((_RESULT_TYPE_SUCCESS(res_ptr) && _RESULT_CODE_EQUAL(res_ptr, RESCODE_USER_FENCE_JOINED)) ||
			(_RESULT_CODE_EQUAL(res_ptr, RESCODE_USER_FENCE_ALREADYIN))) {
		FenceStateDescriptor *fstate_ptr = FenceStateDescriptorOffInstanceHolder((InstanceHolderForFenceStateDescriptor *)_RESULT_USERDATA(res_ptr));
		return (_UpdateCurrentPastGeoFenceAssignments(sesn_ptr, FENCESTATE_INSTANCE_HOLDER(fstate_ptr), true));
	}

	return res_ptr;//note this res is outcome of IsUserAllowedToJoinGeoFence() eg RESULT_CODE_NOOP
}

/**
 * 	@brief: In wanderer mode, we automatically remove the user from the current geo fence and lodge them into the new one
 */
static UFSRVResult *
_HandleRoamingModeWandererGeoJoin(InstanceHolderForSession *instance_sesn_ptr, LocationDescription *location_description_ptr)
{
	Fence				*f_ptr_to_join = NULL;
	InstanceHolderForFence *instance_f_ptr_to_join = NULL;
	UFSRVResult *res_ptr;

	Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

  //TODO this condition is messy and should be rewritten. Also, we are removing user from current fence even though we have not yet determined if zone was triggered.
	/*if (IS_PRESENT(SESSION_GEOFENCE_CURRENT_INSTANCE(sesn_ptr))) {
		bool fence_lock_already_owned = false;
		size_t cname_sz = SizeofCanonicalFenceName(sesn_ptr, NULL) + 1;
		char cname[cname_sz]; memset (cname, 0, sizeof(cname));

		MakeCanonicalFenceName(sesn_ptr, NULL, USER_ATTRIBUTE_IS_SET(sesn_ptr, USERATTRIBUTE_DEFINES_USERZONE), cname);

		if ((instance_f_ptr_to_join = FindBaseFenceByCanonicalName(sesn_ptr, cname, NULL, FENCE_CALLFLAG_SEARCH_BACKEND|FENCE_CALLFLAG_HASH_FENCE_LOCALLY|FENCE_CALLFLAG_ATTACH_USER_LIST_TO_FENCE))) {
		  f_ptr_to_join = FenceOffInstanceHolder(instance_f_ptr_to_join);
			if (f_ptr_to_join != SESSION_GEOFENCE_CURRENT(sesn_ptr)) {
				unsigned long eid;
				Fence 				*f_ptr_geo_current = SESSION_GEOFENCE_CURRENT(sesn_ptr);

				//we shouldn't need to lock f_ptr_geo_current before reading the pref, as the pref is property of the Session, which is locked
				if (!IsStickyGeogroupForFenceSet(sesn_ptr, f_ptr_geo_current)) {
					FenceEventsLockRWCtx(THREAD_CONTEXT_PTR, f_ptr_geo_current, _LOCK_TRY_FLAG_FALSE, SESSION_RESULT_PTR(sesn_ptr), __func__);
					if (SESSION_RESULT_TYPE_EQUAL(sesn_ptr, RESULT_TYPE_ERR)) goto return_error;
					fence_lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_PROG_LOCKED_BY_THIS_THREAD));

					if ((eid = RemoveUserFromMembersListForFence(instance_sesn_ptr, f_ptr_geo_current, FENCE_CALLFLAG_ROAMING_GEOFENCE)) != 0) {
            InstanceContextForSession instance_ctx = {instance_sesn_ptr, sesn_ptr};
						res_ptr = MarshalFenceStateSyncForLeave(&instance_ctx, &instance_ctx, &(InstanceContextForFence){SESSION_GEOFENCE_CURRENT_INSTANCE(sesn_ptr), f_ptr_geo_current}, NULL, LT_GEO_BASED);
					}

					if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr_geo_current, SESSION_RESULT_PTR(sesn_ptr));
				}

				return (_HandleGeoJoinForWanderer(instance_sesn_ptr, location_description_ptr));
			}
			//else it seems we are cycling back into a fence that we joined once (or still members of)
		}
		//fallback below
	} else return (_HandleGeoJoinForWanderer(instance_sesn_ptr, location_description_ptr));*/

	//we are here: 1)couldn't find the Fence in the registry; OR 2)Potentially cycling back into an existing fence;
	bool fence_lock_already_owned = false;

	res_ptr = IsUserAllowedToJoinGeoFence(instance_sesn_ptr, location_description_ptr);

  if (_RESULT_TYPE_EQUAL(res_ptr, RESULT_TYPE_NOOP)) {
    return res_ptr; //maybe geoloc zone was not triggered....
  }

	if ((_RESULT_TYPE_SUCCESS(res_ptr) && _RESULT_CODE_EQUAL(res_ptr, RESCODE_USER_FENCE_JOINED)) || (_RESULT_CODE_EQUAL(res_ptr, RESCODE_USER_FENCE_ALREADYIN))) {
	  instance_f_ptr_to_join = FENCESTATE_INSTANCE_HOLDER(FenceStateDescriptorOffInstanceHolder(_RESULT_USERDATA(res_ptr)));
		f_ptr_to_join = FenceOffInstanceHolder(instance_f_ptr_to_join);

		if	(IS_PRESENT(SESSION_GEOFENCE_CURRENT_INSTANCE(sesn_ptr)) && f_ptr_to_join != SESSION_GEOFENCE_CURRENT(sesn_ptr)) {
				unsigned long eid;
				Fence 				*f_ptr_geo_current = SESSION_GEOFENCE_CURRENT(sesn_ptr);

				//we shouldn't need to lock f_ptr_geo_current before reading the pref, as the pref is property of the Session, which is locked
				if (!IsStickyGeogroupForFenceSet(sesn_ptr, f_ptr_geo_current)) {
					FenceEventsLockRWCtx(THREAD_CONTEXT_PTR, f_ptr_geo_current, _LOCK_TRY_FLAG_FALSE, SESSION_RESULT_PTR(sesn_ptr), __func__);
					if (SESSION_RESULT_TYPE_EQUAL(sesn_ptr, RESULT_TYPE_ERR)) goto return_error;
					fence_lock_already_owned = (SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_PROG_LOCKED_BY_THIS_THREAD));

					if ((eid = RemoveUserFromMembersListForFence(instance_sesn_ptr, f_ptr_geo_current, FENCE_CALLFLAG_ROAMING_GEOFENCE)) != 0) {
            InstanceContextForSession instance_ctx = {instance_sesn_ptr, sesn_ptr};
						res_ptr = MarshalFenceStateSyncForLeave(&instance_ctx, &instance_ctx, &(InstanceContextForFence){SESSION_GEOFENCE_CURRENT_INSTANCE(sesn_ptr), f_ptr_geo_current}, NULL, LT_GEO_BASED);
					}

					if (!fence_lock_already_owned)	FenceEventsUnLockCtx(THREAD_CONTEXT_PTR, f_ptr_geo_current, SESSION_RESULT_PTR(sesn_ptr));
				}
		}

		return (_UpdateCurrentPastGeoFenceAssignments(sesn_ptr, instance_f_ptr_to_join, true));
	}

	return_error:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)

}

/**
 * @brief in journaler mode, user receives invitation to join triggered geofences
 * 	@locked sesn_ptr:
 * 	@locks f_ptr: NOT DIRECTLY, downstream by IsUserAllowedGeoFenceInvite
 */
static UFSRVResult *
_HandleRoamingModeJournalerGeoJoin(InstanceHolderForSession *instance_sesn_ptr, LocationDescription *location_description_ptr)
{
	Fence				*f_ptr										= NULL;
	UFSRVResult *res_ptr									=	NULL;

	Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	res_ptr = IsUserAllowedGeoFenceInvite(instance_sesn_ptr, NULL, GetUfsrvSystemUser(), FENCE_CALLFLAG_ROAMING_GEOFENCE);
	if (_RESULT_TYPE_SUCCESS(res_ptr)) {
			return _UpdateCurrentPastGeoFenceAssignments(sesn_ptr, (InstanceHolderForFence *)_RESULT_USERDATA(res_ptr), true);//fence unlocked
	}

	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, RESCODE_PROG_NULL_POINTER)
}

/**
 * Check if location zones have changed at all and if the user has a settable geoloc trigger value (admittedly this is not useful)
 * @param location_marker_ptr user-session specific, could be by user or by server descriptor
 * @return
 */
__unused static bool _IsGeoLocRoamingZoneTriggered(InstanceHolderForSession *instance_sesn_ptr, const LocationChangeZoneMarker *location_marker_ptr)
{
  enum GeoLocRoamingTrigger geo_loc_trigger = GetUserPrefGeolocRoamingTrigger(SessionOffInstanceHolder(instance_sesn_ptr));
  if (_IsAnyLocationZoneChanged(location_marker_ptr) && geo_loc_trigger != GEOLOC_TRIGGER_UNDEFINED) {
#ifdef __UF_TESTING
    syslog(LOG_DEBUG,"%s {pid:'%lu', cid:'%lu', zone_locality:'%d', zone_admin_area: '%d', zone_country: '%d'}: geoloc zone triggered...", __func__, pthread_self(), SessionOffInstanceHolder(instance_sesn_ptr)->session_id, location_marker_ptr->locality.isLocalityChanged, location_marker_ptr->admin_area.isAdminAreaChanged, location_marker_ptr->country.isCountryChanged);
#endif
    return true;
  }

  return false;
}

/**
 * @brief Based on user pref for geoloc trigger zone determine if location has changed in the same zone that the user has set pref for.
 * @param location_marker_ptr state of location under consideration
 * @param geoloc_trigger_loaded User's current pref for eoloc trigger zone
 * @return
 */
static enum GeoLocRoamingTrigger _DetermineTriggeredGeolocZone(const LocationChangeZoneMarker *location_marker_ptr, enum GeoLocRoamingTrigger geoloc_trigger_loaded)
{
  if (location_marker_ptr->locality.isLocalityChanged && geoloc_trigger_loaded == GEOLOC_TRIGGER_NEIGHBOURHOOD) return GEOLOC_TRIGGER_NEIGHBOURHOOD;
  if (location_marker_ptr->admin_area.isAdminAreaChanged && geoloc_trigger_loaded == GEOLOC_TRIGGER_REGIONHOOD) return GEOLOC_TRIGGER_REGIONHOOD;
  if (location_marker_ptr->country.isCountryChanged && geoloc_trigger_loaded == GEOLOC_TRIGGER_COUNTRYHOOD) return GEOLOC_TRIGGER_COUNTRYHOOD;

  return GEOLOC_TRIGGER_UNDEFINED;
}

static UFSRVResult *
_ResolveRoamingModeAndJoin(InstanceHolderForSession *instance_sesn_ptr, LocationDescription *location_description_ptr, const LocationChangeZoneMarker *location_marker_ptr)
{
	UFSRVResult *res_ptr __unused;
  Session     *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

  //TBD this determined further downstream based on LOCATION_GEOLOC_TRIGGER(location_description_ptr)	= geoloc_roaming_triggered;
//  if (!_IsGeoLocRoamingZoneTriggered(instance_sesn_ptr, location_marker_ptr)) goto return_noop;

  enum GeoLocRoamingTrigger geoloc_trigger_loaded = GetUserPrefGeolocRoamingTrigger(sesn_ptr);
  enum GeoLocRoamingTrigger geoloc_roaming_triggered = _DetermineTriggeredGeolocZone(location_marker_ptr, geoloc_trigger_loaded);//this may return GEOLOC_TRIGGER_UNDEFINED
  LOCATION_GEOLOC_TRIGGER(location_description_ptr)	= geoloc_roaming_triggered;

  if (SESSION_USERPREF_ONOFF_GET(sesn_ptr, roaming_mode)) {
		if (SESSION_USERPREF_ONOFF_GET(sesn_ptr, roaming_mode_conqueror)) {
			return (_HandleRoamingModeConquerorGeoJoin(instance_sesn_ptr, location_description_ptr));
		} else	if (SESSION_USERPREF_ONOFF_GET(sesn_ptr, roaming_mode_wanderer)) {
			return (_HandleRoamingModeWandererGeoJoin(instance_sesn_ptr, location_description_ptr));
		} else 	if	(SESSION_USERPREF_ONOFF_GET(sesn_ptr, roaming_mode_journaler)) {
			return (_HandleRoamingModeJournalerGeoJoin(instance_sesn_ptr, location_description_ptr));
		}
	}

  return_noop:
	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_NOOP, RESCODE_PROG_NULL_POINTER)
}

/**
 * 	@brief Using the provided location description and its originator, determine if the user is to be joined a new geo basefance which
 * 	would happen if user's current location is different from provided one and trigger zone is triggered.
 * 	As a side effect, if user location changed, and new geo location components will have new basefences created for them.
 * 	This is the main entry point for dynamically creating basefences based on user input.
 *
 * 	TODO: this should be preference driven. At the moment is just drops user into basefences as they change relative to user's current location
 */
int
ProcessUserLocationRoaming(InstanceHolderForSession *instance_sesn_ptr, LocationDescription *loc_ptr, const LocationChangeZoneMarker *location_marker_ptr, unsigned short origin)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	User *u_ptr = &(sesn_ptr->sservice.user);

	if (origin == 1) {//server
		if (u_ptr->user_details.user_location_by_server_initialised) {
#ifdef __UF_TESTING
			syslog(LOG_DEBUG,"%s (pid:'%lu' cid:'%lu'): No location BY SERVER  delta  for '%s'. Returning LOCATION_STATE_UNCHANGED.", __func__, pthread_self(), sesn_ptr->session_id, u_ptr->user_details.user_name);
#endif
			return LOCATION_STATE_UNCHANGED;
		} else {
			//we only do take notice of server if user did not supply data
			//TODO: poor brittle logic
			if (!(u_ptr->user_details.user_location_initialised)) {
			//newly logged on user or user for which we have no prior history and drop user into respective base fence
#ifdef __UF_TESTING
			  syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): Uninitialised user location BY SERVER '%s': Dropping user into base fence...", __func__, pthread_self(), SESSION_ID(sesn_ptr), u_ptr->user_details.user_name);
#endif

			  UFSRVResult	*res_ptr = _ResolveRoamingModeAndJoin(instance_sesn_ptr, &(sesn_ptr->sservice.user.user_details.user_location), location_marker_ptr);
			  switch (res_ptr->result_type)
			  {
          case RESULT_TYPE_SUCCESS:
            u_ptr->user_details.user_location_by_server_initialised = 1;
          return LOCATION_STATE_INITIALISED;

          case RESULT_TYPE_NOOP:
            if (res_ptr->result_code == RESCODE_USER_FENCE_ALREADYIN) {
              //this happens when user is automatically included into fence upon joining the network
              //or roaming mode is off, so no state change
              if (!u_ptr->user_details.user_location_by_server_initialised)	u_ptr->user_details.user_location_by_server_initialised = 1;
            }
            return LOCATION_STATE_UNCHANGED;

          case RESULT_TYPE_LOGICERR:
            return LOCATION_STATE_ERROR;
            //we have a fence with the user dropped in it
			  }
			}
		}
	}
	else if (origin == 2) {
		//client: by this time we have in-use and last-known values set
	  if (u_ptr->user_details.user_location_initialised) {
	  //TODO: this is simplistic we should not consider such a literal comparison; we should allow a margin of fluctuation
		if (IS_EMPTY(loc_ptr)) {
#ifdef __UF_TESTING
			  syslog(LOG_DEBUG,"%s (pid:'%lu', cid:'%lu'): No location delta  for '%s'. Returning LOCATION_STATE_UNCHANGED.", __func__,  pthread_self(), SESSION_ID(sesn_ptr), SESSION_USERNAME(sesn_ptr));
#endif
			  return LOCATION_STATE_UNCHANGED;
		  } else {
			  Fence			*f_ptr     = NULL;
			  UFSRVResult	*res_ptr = _ResolveRoamingModeAndJoin(instance_sesn_ptr, &(sesn_ptr->sservice.user.user_details.user_location), location_marker_ptr);

			  switch (res_ptr->result_type)
			  {
				  case RESULT_TYPE_SUCCESS:
					  //user has been joined
					  return LOCATION_STATE_CHANGED;

				  case RESULT_TYPE_NOOP:
					  //user already in fence
					  return LOCATION_STATE_UNCHANGED;

				  case RESULT_TYPE_ERR:
					  return LOCATION_STATE_ERROR;

			  }
		  }
	  } else {
		  //newly logged on user or user for which we have no prior history and drop user into respective base fence
		  //PROCESS_USER_LOCATION_FIELEDS;
#ifdef __UF_TESTING
		  syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): Uninitialised uname='%s': Dropping user into base fence...", __func__, pthread_self(), sesn_ptr->session_id, u_ptr->user_details.user_name);
#endif

		  UFSRVResult	*res_ptr = _ResolveRoamingModeAndJoin(instance_sesn_ptr, &(sesn_ptr->sservice.user.user_details.user_location), location_marker_ptr);
		  switch (res_ptr->result_type)
		  {
			  case RESULT_TYPE_SUCCESS:
				  u_ptr->user_details.user_location_initialised = 1;
				  u_ptr->user_details.user_location_by_server_initialised = 0;
			  return LOCATION_STATE_INITIALISED;

			  case RESULT_TYPE_NOOP:
				  if (res_ptr->result_code == RESCODE_USER_FENCE_ALREADYIN) {
					  //this happens when user is automatically included into fence upon joining the network
					  if (!u_ptr->user_details.user_location_initialised) {
						  u_ptr->user_details.user_location_initialised = 1;
						  u_ptr->user_details.user_location_by_server_initialised = 0;
					  }
				  }
				  return LOCATION_STATE_UNCHANGED;

			  case RESULT_TYPE_ERR:
				  return LOCATION_STATE_ERROR;
		  }
	  }
	}

	return LOCATION_STATE_UNINITIALISED;

}

struct json_object *
JsonFormatUserLocation(Session *sesn_ptr, struct json_object *jobj_in)
{
	json_object *jobj;
	if (jobj_in)	jobj = jobj_in;
	else  jobj = json_object_new_object();

	if (SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_initialised) {
		//client should use its own readings
		json_object_object_add (jobj,"origin", json_object_new_string("client"));

		if (SESSION_SERVICE(sesn_ptr)->user.user_details.user_location.country)
				json_object_object_add (jobj,ACCOUNT_JSONATTR_LOC_ZONE_COUNTRY, json_object_new_string(SESSION_SERVICE(sesn_ptr)->user.user_details.user_location.country));
		if (SESSION_SERVICE(sesn_ptr)->user.user_details.user_location.admin_area)
				json_object_object_add (jobj,"adminArea", json_object_new_string(SESSION_SERVICE(sesn_ptr)->user.user_details.user_location.admin_area));
		if (SESSION_SERVICE(sesn_ptr)->user.user_details.user_location.locality)
				json_object_object_add (jobj,"locality", json_object_new_string(SESSION_SERVICE(sesn_ptr)->user.user_details.user_location.locality));
		if (SESSION_SERVICE(sesn_ptr)->user.user_details.user_location.longitude!=0.0)
				json_object_object_add (jobj, ACCOUNT_JSONATTR_LONGITUDE, json_object_new_double(SESSION_SERVICE(sesn_ptr)->user.user_details.user_location.longitude));
		if (SESSION_SERVICE(sesn_ptr)->user.user_details.user_location.latitude!=0.0)
				json_object_object_add (jobj, ACCOUNT_JSONATTR_LATITUDE, json_object_new_double(SESSION_SERVICE(sesn_ptr)->user.user_details.user_location.latitude));
	} else if (SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_by_server_initialised) {
		json_object_object_add (jobj,"origin", json_object_new_string("server"));

		if (SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_by_server.country)
				json_object_object_add (jobj,ACCOUNT_JSONATTR_LOC_ZONE_COUNTRY, json_object_new_string(SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_by_server.country));
		if (SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_by_server.admin_area)
				json_object_object_add (jobj,"adminArea", json_object_new_string(SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_by_server.admin_area));
		if (SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_by_server.locality)
				json_object_object_add (jobj,"locality", json_object_new_string(SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_by_server.locality));
		if (SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_by_server.longitude!=0.0)
				json_object_object_add (jobj, ACCOUNT_JSONATTR_LONGITUDE, json_object_new_double(SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_by_server.longitude));
		if (SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_by_server.latitude!=0.0)
				json_object_object_add (jobj, ACCOUNT_JSONATTR_LATITUDE, json_object_new_double(SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_by_server.latitude));
	} else {
		//bail out
		if (!jobj_in) json_object_put(jobj);
		return NULL;
	}

	return jobj;

}

#if 0
//https://maps.googleapis.com/maps/api/place/textsearch/json?query=auburn+new+south+wales+australia&key=xxx
{
   "html_attributions" : [],
   "results" : [
      {
         "formatted_address" : "Auburn NSW 2144, Australia",
         "geometry" : {
            "location" : {
               "lat" : -33.86563,
               "lng" : 151.0236
            },
            "viewport" : {
               "northeast" : {
                  "lat" : -33.8344535,
                  "lng" : 151.0446432
               },
               "southwest" : {
                  "lat" : -33.8812756,
                  "lng" : 151.0118565
               }
            }
         },
         "icon" : "https://maps.gstatic.com/mapfiles/place_api/icons/geocode-71.png",
         "id" : "f6dab77b53b1a294aa119c684c2a58188534413b",
         "name" : "Auburn",
         "photos" : [
            {
               "height" : 1365,
               "html_attributions" : [
                  "\u003ca href=\"https://maps.google.com/maps/contrib/105932078588305868215/photos\"\u003eMaksym Kozlenko\u003c/a\u003e"
               ],
               "photo_reference" : "CoQBdwAAAJumSiOpTvxZvPJSxBPaDlLKrXmFpOjGF1SyNHFO4iA9wnwgx5aGQoJEvDAsAEWq36jL2kegD0976dI8aSzVhO91f5L5lVpP8RDbzhnmhonPzjqBvrUZYc3FVMi01gduD4w-u69PBBGBku-R8mRAjW8857Lrb35Tqi-0wIaj8qM2EhBpNaE3SHzzgLXZw2aVHYCAGhQe7CmXAqN5FOoPiZJKq95QiamoRQ",
               "width" : 2048
            }
         ],
         "place_id" : "ChIJt4rvN7m8EmsRIKwyFmh9AQU",
         "reference" : "CmRbAAAAM3EEnaRWM0--FGBXPgyqLMCbDx4xW7wp2-e5WM8ocWHu2Uj9lZlI0nYR0cJtSDUzITBEH2tGNmHtf94A4Pp6pgYQJUU_hYfHU_ZeFTOlb-B-XMYuSS5xpY0lXtpEJ8zDEhBAa7X9mJkvwnqWg0KaxCLfGhROPaoKLUvaHVx6o1ZNJQPWuRWmfg",
         "types" : [ "locality", "political" ]
      }
   ],
   "status" : "OK"
}

//retrieve image
https://maps.googleapis.com/maps/api/place/photo?photoreference=CoQBdwAAAJumSiOpTvxZvPJSxBPaDlLKrXmFpOjGF1SyNHFO4iA9w&key=xxx

#endif

//reverse geocoding note api defined in google developer console https://console.developers.google.com/apis/credentials?project=unfacd
//https://developers.google.com/maps/documentation/geocoding/start#geocoding-request-and-response-latitudelongitude-lookup
//https://maps.googleapis.com/maps/api/geocode/json?latlng=40.714224,-73.961452&key=xxx
//http://maps.googleapis.com/maps/api/geocode/json?address=australia,%20nsw,%20auburn
//designed to be used with BaseFences
void *GeocodeLocation(Session *sesn_ptr, HttpRequestContext *http_ptr, LocationDescription *ld_ptr, const char *address)
{
//	static const char *gecode_url_prefix = "http://maps.googleapis.com/maps/api/geocode/json?address=";

#ifdef __UF_TESTING
  syslog(LOG_INFO, "%s {pid:'%lu'}: Geocoding for '%s'...", __func__, pthread_self(), address);
#endif

  int result = HttpRequestGetUrlInJson(http_ptr, APIURL_GEOCODING, address, NULL);
  if (result == 0) {
    syslog(LOG_ERR, "%s {pid:'%lu', o:'%p', cid:'%lu'}: error fetching url: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), address);
    return NULL;
  }

#ifdef __UF_FULLDEBUG
  syslog(LOG_INFO, "%s: received response from Location Service: '%s'", __func__, http_ptr->rb.memory);
#endif

  const char *status = json_object_get_string(json__get(http_ptr->jobj, "status"));
  if ((status) && (strcasecmp(status, "ok") == 0)) {
    json_object *jobj_array = json__get(http_ptr->jobj, "results");//array
    if (!jobj_array) {syslog(LOG_INFO, "%s: array node was not found", __func__); return NULL;}

    json_object *jobj_results = json_object_array_get_idx (jobj_array, 0);//results
    if (!jobj_results){syslog(LOG_INFO, "%s: 'results' node was not found", __func__); return NULL;}

    json_object *jobj_geometry = json__get(jobj_results, "geometry");
    if (!jobj_geometry){syslog(LOG_INFO, "%s: 'geometry' node was not found", __func__); return NULL;}

    json_object *jobj_location = json__get(jobj_geometry, "location");
    if (!jobj_location){syslog(LOG_INFO, "%s: 'location' node was not found", __func__); return NULL;}

    ld_ptr->longitude = json_object_get_double(json__get(jobj_location, "lng"));
    ld_ptr->latitude = json_object_get_double(json__get(jobj_location, "lat"));

#ifdef __UF_TESTING
    syslog(LOG_INFO, "%s (pid:'%lu'): locations longitude: '%f'. Location latitude: '%f'", __func__, pthread_self(), ld_ptr->longitude, ld_ptr->latitude);
#endif
  } else {
    syslog(LOG_INFO, "%s (pid:'%lu'):  'status=ok' was not present in stream... received: '%s'", __func__, pthread_self(), status);
    return NULL;
  }

  return NULL;

}

//TODO: jobj not in use
__unused static void
RememberLastKnownLocation(User *u_ptr, json_object *jobj)
{
#if 0
	//currently disabled
	if (u_ptr && jobj)
	{
		DestructLocationDescription(&(u_ptr->user_details.user_location_last_known));

		//shuffle in-use into last-known
		u_ptr->user_details.user_location_last_known.longitude=u_ptr->user_details.user_location.longitude;
		u_ptr->user_details.user_location_last_known.latitude=u_ptr->user_details.user_location.latitude;
		u_ptr->user_details.user_location_last_known.admin_area=u_ptr->user_details.user_location.admin_area;
		u_ptr->user_details.user_location_last_known.country=u_ptr->user_details.user_location.country;
		u_ptr->user_details.user_location_last_known.locality=u_ptr->user_details.user_location.locality;

#ifdef __UF_TESTING
		syslog(LOG_INFO, "%s {pid:'%lu'}: Last Known Location updated for user '%s'. Last known locality: '%s'",__func__, pthread_self(),
			u_ptr->user_details.user_name, u_ptr->user_details.user_location_last_known.locality );
#endif
	}
#endif
}

/**
 * 	@brief: callback. Commits changes to memory, ahead of committing to cache and db backends
 */
UserPreferenceDescriptor *
PrefValidateGeoGroupsRoaming(Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr)
{
	switch (pref_ptr->pref_id)
	{
    case PREF_ROAMING_MODE:
      if (pref_ptr->value.pref_value_bool == 1) {
      //note we set wanderer to 1 by default on master switch on-flip
        SetBooleanPrefById(sesn_ptr, PREF_RM_WANDERER, true);
        SetBooleanPrefById(sesn_ptr, PREF_RM_CONQUERER, false);
        SetBooleanPrefById(sesn_ptr, PREF_RM_JOURNALER, false);
      } else if (pref_ptr->value.pref_value_bool == 0) {
        SetBooleanPrefById(sesn_ptr, PREF_RM_WANDERER, false);
        SetBooleanPrefById(sesn_ptr, PREF_RM_CONQUERER, false);
        SetBooleanPrefById(sesn_ptr, PREF_RM_JOURNALER, false);
      }
      break;
		case 	PREF_RM_WANDERER:
			if (pref_ptr->value.pref_value_bool == 1) {
				SetBooleanPrefById(sesn_ptr, PREF_RM_CONQUERER, false);
				SetBooleanPrefById(sesn_ptr, PREF_RM_JOURNALER, false);
			}
			break;
		case	PREF_RM_CONQUERER:
			if (pref_ptr->value.pref_value_bool == 1) {
				SetBooleanPrefById(sesn_ptr, PREF_RM_WANDERER, false);
				SetBooleanPrefById(sesn_ptr, PREF_RM_JOURNALER, false);
			}
			break;
		case 	PREF_RM_JOURNALER:
			if (pref_ptr->value.pref_value_bool == 1) {
				SetBooleanPrefById(sesn_ptr, PREF_RM_CONQUERER, false);
				SetBooleanPrefById(sesn_ptr, PREF_RM_WANDERER, false);
			}
			break;
	}

	return pref_ptr;
}

void
DestructLocationDescription(LocationDescription *ld_ptr)
{
	if (IS_PRESENT(ld_ptr)) {
		if (!IS_STR_DEFAULT_LOADED(ld_ptr->admin_area))		free(ld_ptr->admin_area);
		if (!IS_STR_DEFAULT_LOADED(ld_ptr->country))		  free(ld_ptr->country);
		if (!IS_STR_DEFAULT_LOADED(ld_ptr->selfzone))	    free(ld_ptr->selfzone);
		if (!IS_STR_DEFAULT_LOADED(ld_ptr->locality))		  free(ld_ptr->locality);
		memset(ld_ptr, 0, sizeof(LocationDescription));
	}

}

static UFSRVResult *
_DbGetUfsrvGeoGroupForUser(Session *sesn_ptr, const char *location_name);

static UFSRVResult *
_DbGetUfsrvGeoGroupForUser(Session *sesn_ptr, const char *location_name)
{
#define SQL_GET_GEOCODE "SELECT geogroup_code FROM countries WHERE name='%s'"
		int 	rescode;
		struct _h_result result;

  char 	*sql_query_str = mdsprintf(SQL_GET_GEOCODE, location_name);

#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s (cid='%lu'): GENERATED SQL QUERY: '%s'", __func__, SESSION_ID(sesn_ptr), sql_query_str);
#endif

		int sql_result = h_query_select(sesn_ptr->db_backend, sql_query_str, &result);

		if (sql_result != H_OK)		goto return_db_error;
		if (result.nb_rows == 0)	goto return_empty_set;

		int ufsrv_gecocode = ((struct _h_type_int *)result.data[0][0].t_data)->value;

#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:%p', cid:'%lu'): RETRIEVED JSON ACCOUNT DATA: '%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), account_data_json_str);
#endif

		return_success:
		h_clean_result(&result);
		free(sql_query_str);
		_RETURN_RESULT_SESN(sesn_ptr, (void *) (intptr_t)ufsrv_gecocode, RESULT_TYPE_SUCCESS, RESCODE_BACKEND_DATA)

		return_empty_set:
#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid:'%lu'): ERROR: COULD FIND CORRESPONDING DB RECORD", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));
#endif
		rescode = RESCODE_BACKEND_DATA_EMPTYSET;
		goto return_free_sql_handle;

		return_db_error:
		syslog(LOG_DEBUG, "%s (cid='%lu'): ERROR: COULD EXEUTE QUERY: '%s'", __func__, SESSION_ID(sesn_ptr), sql_query_str);
		rescode = RESCODE_BACKEND_CONNECTION;
		goto return_free;

		return_free_sql_handle:
		h_clean_result(&result);

		return_free:
		free(sql_query_str);

		return_error:
		_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_ERR, rescode)

#undef SQL_GET_ACCOUNT_DATA

}

int GetUfsrvGeoGroupForUser(Session *sesn_ptr, const char *location_name)
{
	_DbGetUfsrvGeoGroupForUser(sesn_ptr, location_name);

	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
		return (intptr_t)SESSION_RESULT_USERDATA(sesn_ptr);
	}

	return 0;
}

void _FuzzGeoLocation(LocationDescription *location_ptr, double factor)
{
	_FuzzGeoLocationByCoords(&(location_ptr->longitude), &(location_ptr->latitude), factor);
}

#define TO_RADIANS(x) (x * M_PI / 180.0)
#define TO_DEGREES(x)	(x * 180.0 / M_PI)

void  _FuzzGeoLocationByCoords(double *longitude_x, double *latitude_y, double factor)
{
//	double x0 = currentLocation.getLongitude();
//	    double y0 = currentLocation.getLatitude();
//
//	    Random random = new Random();
//
//	    // Convert radius from meters to degrees.
//	    double radiusInDegrees = radiusInMeters / 111320f;
//
//	    // Get a random distance and a random angle.
//	    double u = random.nextDouble();
//	    double v = random.nextDouble();
//	    double w = radiusInDegrees * Math.sqrt(u);
//	    double t = 2 * Math.PI * v;
//	    // Get the x and y delta values.
//	    double x = w * Math.cos(t);
//	    double y = w * Math.sin(t);
//
//	    // Compensate the x value.
//	    double new_x = x / Math.cos(Math.toRadians(y0));
//
//	    double foundLatitude;
//	    double foundLongitude;
//
//	    foundLatitude = y0 + y;
//	    foundLongitude = x0 + new_x;
//
//	    Location copy = new Location(currentLocation);
//	    copy.setLatitude(foundLatitude);
//	    copy.setLongitude(foundLongitude);
//	    return copy;

#define DEGREES_VS_METER_RATIO	(111320.0)
#define RADIUS_IN_DEGREES(x) (x/111320.0)

	double random_a = GetRandomFromRangeInDoubles(0, 1.0);//u
	double random_b = GetRandomFromRangeInDoubles(0, 1.0);//v

//	double radius_degrees	=	factor/111320.0;
	double random_distance = RADIUS_IN_DEGREES(factor) * sqrt(random_a);//get more uniform distribution of random points within radius
	double random_angle_0_360 = 2 * M_PI * random_b; // there are 2 * pi radians in a full circle

	//point somewhere random distance from original point in the random direction of random_angle_0_360
	double x = random_distance * cos(random_angle_0_360);
	double y = random_distance * sin(random_angle_0_360);

	//compensate for varying distance between longitude lines
	double new_x = x / cos(TO_RADIANS(*latitude_y));

	*longitude_x	=	*longitude_x + new_x;
	*latitude_y		=	*latitude_y + y;
}

/**
 * Value comes in as 'lat,long:country:region:area:zone:'
 * @param location_serialised
 * @param location_ptr_out[OUT]
 * @param is_validate_address if set, the address component of the serialised location will be parsed too
 * @return
 */
LocationDescription *
ProvideLocationDescriptionFromSerialised(char *location_serialised, LocationDescription *location_ptr_out, bool is_validate_address)
{
  char *address = strchr(location_serialised, ':');
  if (IS_EMPTY(address)) return NULL;

  *address++ = '\0';
  char *lat_value = location_serialised;
  char *long_value = strchr(lat_value, ',');
  if (IS_EMPTY(long_value)) return NULL;
  *long_value++ = '\0';
  location_ptr_out->latitude = strtof(lat_value, NULL);
  location_ptr_out->longitude = strtof(long_value, NULL);

  if (is_validate_address){
    //location_serialised holds the value
  }

  return location_ptr_out;
}

#if 0
{
   "results" : [
      {
         "address_components" : [
            {
               "long_name" : "Australia",
               "short_name" : "AU",
               "types" : [ "country", "political" ]
            }
         ],
         "formatted_address" : "Australia",
         "geometry" : {
            "bounds" : {
               "northeast" : {
                  "lat" : -9.2198215,
                  "lng" : 159.2872223
               },
               "southwest" : {
                  "lat" : -54.7772185,
                  "lng" : 112.9214544
               }
            },
            "location" : {
               "lat" : -25.274398,
               "lng" : 133.775136
            },
            "location_type" : "APPROXIMATE",
            "viewport" : {
               "northeast" : {
                  "lat" : -9.2198215,
                  "lng" : 159.2872223
               },
               "southwest" : {
                  "lat" : -43.9672498,
                  "lng" : 112.9239721
               }
            }
         },
         "place_id" : "ChIJ38WHZwf9KysRUhNblaFnglM",
         "types" : [ "country", "political" ]
      }
   ],
   "status" : "OK"
}
#endif
