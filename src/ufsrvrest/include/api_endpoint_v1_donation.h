/**
 * Copyright (C) 2015-2025 unfacd works
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

#ifndef UFSRV_API_ENDPOINT_V1_DONATION_H
#define UFSRV_API_ENDPOINT_V1_DONATION_H

#include <uflib/recycler/instance_type.h>
#include <json/json.h>

#define API_ENDPOINT_V1(x) int x (InstanceHolder *instance_sesn_ptr)

API_ENDPOINT_V1(DONATION_SUBSCRIPTION);
API_ENDPOINT_V1(DONATION_SUBSCRIPTION_LEVEL);
API_ENDPOINT_V1(DONATION_SUBSCRIPTION_CREATE_PAYMENT_METHOD);
API_ENDPOINT_V1(DONATION_SUBSCRIPTION_DEFAULT_PAYMENT_METHOD);
API_ENDPOINT_V1(DONATION_SUBSCRIPTION_LEVELS);
API_ENDPOINT_V1(DONATION_SUBSCRIPTION_BOOST_AMOUNTS);
API_ENDPOINT_V1(DONATION_SUBSCRIPTION_BOOST_BADGES);

#endif //UFSRV_API_ENDPOINT_V1_DONATION_H
