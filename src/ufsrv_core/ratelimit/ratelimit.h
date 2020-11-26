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


#ifndef SRC_INCLUDE_RATELIMIT_H_
#define SRC_INCLUDE_RATELIMIT_H_

#include <ufsrvresult_type.h>
#include <ufsrv_core/cache_backend/persistance_type.h>
#include <ufsrv_core/ratelimit/ratelimit_type.h>
#include <ufsrv_core/ratelimit/ratelimit_descriptor_type.h>

UFSRVResult *GetRequestRateLimitStatus (RateLimitDescriptor *rl_descriptor_ptr, RequestRateLimitStatus 	*rl_status_ptr_out);
const RequestRateLimit *GetRateLimitSpecsFor (enum RateLimitNamespaceCategory category);
bool IsRateLimitExceededForSession (CacheBackend *pers_ptr, unsigned long userid, unsigned long cid, enum RateLimitNamespaceCategory ratelimit_category);
bool IsRateLimitExceededWithNamespace (RateLimitDescriptor *, enum RateLimitNamespaceCategory ratelimit_category);
bool IsRateLimitExceededForIPAddress (CacheBackend *pers_ptr, const char *ip_address, enum RateLimitNamespaceCategory ratelimit_category, UFSRVResult *);
#endif /* SRC_INCLUDE_RATELIMIT_H_ */
