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

#ifndef UFSRV_API_ENDPOINT_V1_SERVER_H
#define UFSRV_API_ENDPOINT_V1_SERVER_H

#include <recycler/instance_type.h>

#define API_ENDPOINT_V1(x) int x (InstanceHolder *instance_sesn_ptr)

API_ENDPOINT_V1(SERVER_CERTIFICATE);
API_ENDPOINT_V1(SERVER_ZKGROUP_PARAMS);

#endif //UFSRV_API_ENDPOINT_V1_SERVER_H
