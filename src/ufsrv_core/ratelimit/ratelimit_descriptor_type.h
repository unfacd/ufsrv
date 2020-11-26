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

//
// Created by devops on 8/21/19.
//

#ifndef UFSRV_RATELIMIT_DESCRIPTOR_TYPE_H
#define UFSRV_RATELIMIT_DESCRIPTOR_TYPE_H

#include <ufsrvresult_type.h>
#include <ufsrv_core/cache_backend/persistance_type.h>
#include <ufsrv_core/ratelimit/ratelimit_type.h>

typedef struct RateLimitDescriptor {
  CacheBackend *pers_ptr;
  const char *namespace;
  const RequestRateLimit  *request_rl_ptr;
  UFSRVResult *res_ptr;
} RateLimitDescriptor;

#endif //UFSRV_RATELIMIT_DESCRIPTOR_TYPE_H
