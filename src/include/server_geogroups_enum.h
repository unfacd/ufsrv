/*
 * enum_geogroups.h
 *
 *  Created on: 7 Dec 2016
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_SERVER_GEOGROUPS_ENUM_H_
#define SRC_INCLUDE_SERVER_GEOGROUPS_ENUM_H_


 typedef enum EnumServerGeoGroup {
 	GEOGROUP_APAC=1,
 	GEOGROUP_APAC_Singapore,
 	GEOGROUP_APAC_Sydney,
 	GEOGROUP_APAC_Tokyo,
 	GEOGROUP_APAC_Seoul,
 	GEOGROUP_APAC_Mumbai,
 	GEOGROUP_EU=100,
 	GEOGROUP_EU_Ireland,
 	GEOGROUP_EU_Frankfurt,
 	GEOGROUP_US_WEST=200,
 	GEOGROUP_US_WEST_Oregon,
 	GEOGROUP_US_WEST_NorthernCalifornia,
 	GEOGROUP_US_EAST=250,
 	GEOGROUP_US_EAST_Northern_Virginia,
 	GEOGROUP_US_EAST_Ohio,
 	GEOGROUP_SOUTH_AMERICA=300,
 	GEOGROUP_AFRICA=400,
 	GEOGROUP_CHINA=500,
 	GEOGROUP_ME=600
 } EnumSessionGeoGroup;

 typedef EnumSessionGeoGroup EnumServerGeoGroup;


#endif /* SRC_INCLUDE_SERVER_GEOGROUPS_ENUM_H_ */
