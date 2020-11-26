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

#ifndef UFSRV_ZKGROUP_SERVER_PARAMS_TYPE_H
#define UFSRV_ZKGROUP_SERVER_PARAMS_TYPE_H

#include <standard_c_includes.h>

#define SERVER_SECRET_PARAM_SIZE  SERVER_SECRET_PARAMS_LEN//769
#define SERVER_PUB_PARAM_SIZE     SERVER_PUBLIC_PARAMS_LEN

typedef struct ZKGroupServerParams {
  struct {
    uint8_t raw[SERVER_SECRET_PARAM_SIZE];
    uint8_t encoded[((SERVER_SECRET_PARAM_SIZE + 2) / 3) * 5];
  } secret_param;

  struct {
    uint8_t raw[SERVER_PUB_PARAM_SIZE];
    uint8_t encoded[((SERVER_PUB_PARAM_SIZE + 2) / 3) * 5];
  } public_param;

} ZKGroupServerParams;

#endif //UFSRV_ZKGROUP_SERVER_PARAMS_TYPE_H
