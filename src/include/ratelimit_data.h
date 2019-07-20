/*
 * ratelimit_data.h
 *
 *  Created on: 13 Nov 2016
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_RATELIMIT_DATA_H_
#define SRC_INCLUDE_RATELIMIT_DATA_H_

#include <ratelimit_type.h>

const static RequestRateLimit RequestRateLimitSpecs[]={
		{
				RLNS_CONNECTONS,
				1000, //in millis
				1,
				100 //at rate of 1 per 100 millisecs
		},
		{
				RLNS_REQUESTS,
				1000,//1 sec
				20,
				0//dont care about rate
		}
};



#endif /* SRC_INCLUDE_RATELIMIT_DATA_H_ */
