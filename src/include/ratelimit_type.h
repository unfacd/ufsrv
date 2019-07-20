/*
 * ratelimit_type.h
 *
 *  Created on: 13 Nov 2016
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_RATELIMIT_TYPE_H_
#define SRC_INCLUDE_RATELIMIT_TYPE_H_



enum RateLimitNamespaceCategory{
	RLNS_CONNECTONS	=	1,
	RLNS_REQUESTS,
	RLNS_MAXVALUE,

};


//namespace: <uid>:<cid>:<category:>
typedef struct RequestRateLimit {
			enum 		RateLimitNamespaceCategory namespace;
	    size_t 	interval, //1000 one sec
	    				max_in_interval, //10 requests in interval
							min_difference;	//100 time diff between successive requests. can be set to zero
} RequestRateLimit;

typedef struct RequestRateLimitStatus {
	size_t 			remaning_time;
	ssize_t			remaining_actions; //0: none left, >0: how many left, <0:how many exceeded by
} RequestRateLimitStatus;

#endif /* SRC_INCLUDE_RATELIMIT_TYPE_H_ */
