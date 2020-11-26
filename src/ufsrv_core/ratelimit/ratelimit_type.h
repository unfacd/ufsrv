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
	size_t 			remaining_time;
	ssize_t			remaining_actions; //0: none left, >0: how many left, <0:how many exceeded by
} RequestRateLimitStatus;

#endif /* SRC_INCLUDE_RATELIMIT_TYPE_H_ */
