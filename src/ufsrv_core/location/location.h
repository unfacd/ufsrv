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

#ifndef INCLUDE_LOCATION_H_
#define INCLUDE_LOCATION_H_

#include <recycler/instance_type.h>
#include <session_type.h>
#include <ufsrv_core/location/location_type.h>
#include <ufsrvresult_type.h>
#include <json/json.h>
#include <http_request_context_type.h>
#include <ufsrv_core/fence/fence_type.h>
#include <ufsrv_core/user/users.h>

#include <ufsrv_core/SignalService.pb-c.h>

void UpdateSessionGeoFenceDataByFid (Session *sesn_ptr, unsigned long fid_current, unsigned long fid_past);
void UpdateSessionGeoFenceData (Session *sesn_ptr, InstanceHolderForFence *instance_f_ptr_current, InstanceHolderForFence *instance_f_ptr_past);
void FormatCacheBackendLocationFieldValue (const LocationDescription *location_ptr, BufferDescriptor *buffer_out);
void ResetSessionGeoFenceData (InstanceHolderForSession *instance_sesn_ptr);
void DestructLocationDescription (LocationDescription *);
LocationDescription *DetermineLocationByServerByJson(Session *, HttpRequestContext *, json_object *);
LocationDescription *DetermineUserLocationByServer(Session *, HttpRequestContext *, unsigned long sesn_call_flags);
UFSRVResult *UpdateUserLocationByUser (Session *, json_object *, unsigned long);
UFSRVResult *UpdateUserLocationAssignment (Session *sesn_ptr, ClientContextData  */*json_object *jobj*/, unsigned long call_flags_sesn);
UFSRVResult *UpdateBaseLocAssignment (Session *sesn_ptr, const char *baseloc, unsigned long call_flags_sesn);
UFSRVResult *UpdateHomeBaseLocAssignment (Session *sesn_ptr, const char *baseloc, unsigned long call_flags_sesn);
UFSRVResult *UpdateLocationByProto (InstanceContextForSession *ctx_ptr, const LocationRecord *location_record_ptr);
bool BuildUserLocationByProto (Session *sesn_ptr, LocationRecord *location_record_ptr);
UFSRVResult *UpdateUserLocationByUserByProto (Session *sesn_ptr, const LocationRecord *location_record_ptr, unsigned long call_flags_sesn);
LocationDescription *DetermineLocationByServerByProto(Session *, const LocationRecord *);
int ProcessUserLocation (InstanceHolderForSession *instance_sesn_ptr, LocationDescription *, unsigned short);//in user.c
void *GeocodeLocation (Session *, HttpRequestContext *, LocationDescription *, const char *);
struct json_object *JsonFormatUserLocation(Session *sesn_ptr, struct json_object *jobj_in);
UserPreferenceDescriptor *PrefValidateGeoGroupsRoaming (Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr);
int GetUfsrvGeoGroupForUser (Session *sesn_ptr, const char *location_name);
size_t SizeofLocationDescription (const LocationDescription *location_ptr);
void UpdateUserLocationAssignmentByProto (LocationDescription *location_ptr,  LocationRecord *location_record_ptr);
int ParseCacheBackendStoredLocationDescription (LocationDescription *location_ptr, const char *location_stored, bool flag_dirty);
void _FuzzGeoLocation (LocationDescription *location_ptr, double factor);
void  _FuzzGeoLocationByCoords (double *longitude_x, double *latitude_y, double factor);

static inline LocationDescription *
GetLocationDescription (Session *sesn_ptr)
{
	LocationDescription *ld_ptr=SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_initialised?
		  			  &(SESSION_SERVICE(sesn_ptr)->user.user_details.user_location):
		  			  &(SESSION_SERVICE(sesn_ptr)->user.user_details.user_location_by_server);

	return ld_ptr;
}

//static inline void _FuzzGeoLocation (LocationDescription *location_ptr, double factor)
//{
//	double random = GetRandomFromRangeInDoubles (0, 1.0);
////	coord += (Math.random() = 0.5) * 0.1;
//	location_ptr->longitude+=(random) * (factor=0.1);//override factor for now
//	location_ptr->latitude-=(random) * (factor=0.1);//override factor for now
//	location_ptr->fuzz_factor=random;
//}
//
//#define TO_RADIANS(x) (x * M_PI / 180.0)
//#define TO_DEGREES(x)	(x * 180.0 / M_PI)
//
//static inline void _FuzzGeoLocationByCoords (double *longitude_x, double *latitude_y, double factor)
//{
//	//Pick two random numbers in the range (0, 1), namely a and b. If b < a, swap them. Your point is (b*R*cos(2*pi*a/b), b*R*sin(2*pi*a/b)).
////	double x0 = currentLocation.getLongitude();
////	    double y0 = currentLocation.getLatitude();
////
////	    Random random = new Random();
////
////	    // Convert radius from meters to degrees.
////	    double radiusInDegrees = radiusInMeters / 111320f;
////
////	    // Get a random distance and a random angle.
////	    double u = random.nextDouble();
////	    double v = random.nextDouble();
////	    double w = radiusInDegrees * Math.sqrt(u);
////	    double t = 2 * Math.PI * v;
////	    // Get the x and y delta values.
////	    double x = w * Math.cos(t);
////	    double y = w * Math.sin(t);
////
////	    // Compensate the x value.
////	    double new_x = x / Math.cos(Math.toRadians(y0));
////
////	    double foundLatitude;
////	    double foundLongitude;
////
////	    foundLatitude = y0 + y;
////	    foundLongitude = x0 + new_x;
////
////	    Location copy = new Location(currentLocation);
////	    copy.setLatitude(foundLatitude);
////	    copy.setLongitude(foundLongitude);
////	    return copy;
//
//	double random_a = GetRandomFromRangeInDoubles (0, 1.0);//u
//	double random_b = GetRandomFromRangeInDoubles (0, 1.0);//v
//	double radius_degrees	=	factor/111320.0;
//	double w = radius_degrees * sqrt(random_a);
//	double t = 2 * M_PI * random_b;
//	double x = w * cos(t);
//	double y = w * sin(t);
//	double new_x = x / cos(TO_RADIANS(*latitude_y));
//
//	*longitude_x	=	*longitude_x + new_x;
//	*latitude_y		=	*latitude_y + y;
//	/*
//	double 	random 	= GetRandomFromRangeInDoubles (0, 1.0);
//	double 	lng			=	*longitude,
//					lat			=	*latitude;
//
//	lng+=(random) * (factor);
//	lat-=(random) * (factor);
//
//	*longitude	=	lng;
//	*latitude		=	lat;
//*/
//}


#endif /* SRC_INCLUDE_LOCATION_H_ */
