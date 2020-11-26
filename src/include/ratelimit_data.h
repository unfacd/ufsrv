/**
 * Copyright (C) 2015-2020 unfacd works
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


#ifndef SRC_INCLUDE_RATELIMIT_DATA_H_
#define SRC_INCLUDE_RATELIMIT_DATA_H_

#include <ufsrv_core/ratelimit/ratelimit_type.h>

const static RequestRateLimit RequestRateLimitSpecs[] = {
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
