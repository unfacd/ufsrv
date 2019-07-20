/*
 * trip_type.h
 *
 *  Created on: 4 Apr 2015
 *      Author: ayman
 */

#ifndef INCLUDE_TRIP_TYPE_H_
#define INCLUDE_TRIP_TYPE_H_

//a mechanism to check for quick succession of exceptions (trips) by a user session to
//facilitate inferring if we are under kind of sustain, deliberate DOS attack
struct Trip {
	List trips_list;
	time_t last_trip_time;
	unsigned counter;
};
typedef struct Trip Trip;

#endif /* SRC_INCLUDE_TRIP_TYPE_H_ */
