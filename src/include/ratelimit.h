/*
 * ratelimit.h
 *
 *  Created on: 13 Nov 2016
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_RATELIMIT_H_
#define SRC_INCLUDE_RATELIMIT_H_

#include <ufsrvresult_type.h>
#include <session_type.h>
#include <persistance_type.h>
#include <ratelimit_type.h>

UFSRVResult *GetRequestRateLimitStatus (Session *sesn_ptr, CacheBackend *pers_ptr, const RequestRateLimit *rl_ptr, unsigned long userid, unsigned long cid, RequestRateLimitStatus *rl_status_ptr_out);
const RequestRateLimit *GetRateLimitSpecsFor (enum RateLimitNamespaceCategory category);
bool IsRateLimitExceeded (Session *sesn_ptr, CacheBackend *pers_ptr, unsigned long userid, unsigned long cid, enum RateLimitNamespaceCategory ratelimit_category);

#endif /* SRC_INCLUDE_RATELIMIT_H_ */
