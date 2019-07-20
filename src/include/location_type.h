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


#ifndef INCLUDE_LOCATION_TYPE_H_
#define INCLUDE_LOCATION_TYPE_H_


//used to index location string tokens
enum LocationFields {
	LOCATION_COUNTRY			=	0,
	LOCATION_ADMINAREA,
	LOCATION_LOCALITY,
	LOCATION_LONGITUDE,
	LOCATION_LATITUDE,
	LOCATION_SELFZONE,
	LOCATION_MAX
};

//location sensitivities at which geoloc roaming is triggered. Abstracted from location information delivered via geolocation service
enum GeoLocTrigger {
  GEOLOC_TRIGGER_NEIGHBOURHOOD = 0, //most sensitive to geoloc change
  GEOLOC_TRIGGER_REGIONHOOD,
  GEOLOC_TRIGGER_COUNTRYHOOD
};

//zone
enum BaseLocZone {
  BASELOC_LVEL_NEIGHBOURHOOD = 0, //most sensitive to geoloc change
  BASELOC_LVEL_REGIONHOOD,
  BASELOC_LVEL_COUNTRYHOOD,
  BASELOC_LEVEL_SELFZONE,
  BASELOC_NETWORK
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
};
typedef struct LocationDescription LocationDescription;

#define LOCATION_ADMIN(x)			((x)->admin_area)
#define LOCATION_LOCALITY(x)	((x)->latitude)
#define LOCATION_COUNTRY(x)		((x)->country)
#define LOCATION_LONG(x)			((x)->longitude)
#define LOCATION_LAT(x)				((x)->latitude)
#define LOCATION_SELFZONE(x)	((x)->selfzone)

#endif /* SRC_INCLUDE_LOCATION_H_ */
