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


#ifndef INCLUDE_LOCATION_TYPE_H_
#define INCLUDE_LOCATION_TYPE_H_


//used to index location string tokens
enum LocationTokenIndexer {
	LOCATION_COUNTRY			=	0,
	LOCATION_ADMINAREA,
	LOCATION_LOCALITY,
	LOCATION_LONGITUDE,
	LOCATION_LATITUDE,
	LOCATION_SELFZONE, //aka private cloud
	LOCATION_MAX
};

//works with geo roaming feature. Location change sensitivity at which geoloc roaming is triggered. Abstracted from location information delivered via geolocation service
enum GeoLocRoamingTrigger {
  GEOLOC_TRIGGER_UNDEFINED = 0,
  GEOLOC_TRIGGER_NEIGHBOURHOOD, //default and most sensitive to geoloc change
  GEOLOC_TRIGGER_REGIONHOOD,
  GEOLOC_TRIGGER_COUNTRYHOOD,
  GEOLOC_TRIGGER_NOT_VALID
};

#define BACKEND_LOCATION_SEPARATORS_SZ 6 //number of field separators ':' when storing locatioon in backend

//Location zones at which user-created groups are anchored: Country:admin_area:locality:self_zone
enum BaseLocAnchorZones {
  BASELOC_ZONE_UNDEFINED = 0,
  BASELOC_ZONE_NEIGHBOURHOOD, //Narrowest zone Australia:Victoria:Doncaster:0:zzz
  BASELOC_ZONE_REGIONHOOD, //Australia:Victoria::0:zzz
  BASELOC_ZONE_COUNTRYHOOD, //Australia:::0:zzz
  BASELOC_ZONE_SELFZONE_EXCLUSIVE, //private cloud :::<uid>:zzz
  BASELOC_ZONE_SELFZONE_GEOLOC, //private cloud with geoloc encoded 'Australia:Victoria:Doncaster:<uid>>:zzz'
  BASELOC_ZONE_NETWORK, //unfacd network :::0:zzz
  BASELOC_ZONE_GEOLOC_ROAMING, //kind of dynamic; meaning it can change depending on GeoLocRoamingTrigger setting. If current setting is GEOLOC_TRIGGER_NEIGHBOURHOOD (e.g Australia:Victoria:Doncaster:0). new user group will be anchored at 'Australia:Victoria:Doncaster:0:zzz'
    BASELOC_ZONE_NOT_VALID
};

struct LocationDescription	{
		double 	longitude,
						latitude;
		char 		*locality,
						*admin_area,
						*country,
						*selfzone;
		time_t	last_updated;
		double	fuzz_factor;
    enum    GeoLocRoamingTrigger geoloc_trigger; //which of the three fields changed at the last event
};
typedef struct LocationDescription LocationDescription;

typedef struct _LocationChangeZoneMarker {
    struct {
        bool isLocalityChanged;
        enum GeoLocRoamingTrigger geoloc_trigger;
    } locality;
    struct {
        bool isAdminAreaChanged;
        enum GeoLocRoamingTrigger geoloc_trigger;
    } admin_area;

    struct {
        bool isCountryChanged;
        enum GeoLocRoamingTrigger geoloc_trigger;
    } country;
} LocationChangeZoneMarker;

#define LOCATION_ADMIN(x)			((x)->admin_area)
#define LOCATION_LOCALITY(x)	((x)->latitude)
#define LOCATION_COUNTRY(x)		((x)->country)
#define LOCATION_LONG(x)			((x)->longitude)
#define LOCATION_LAT(x)				((x)->latitude)
#define LOCATION_SELFZONE(x)	((x)->selfzone)
#define LOCATION_GEOLOC_TRIGGER(x)	((x)->geoloc_trigger)

#endif /* SRC_INCLUDE_LOCATION_H_ */
