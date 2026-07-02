/**
 * Copyright (C) 2015-2021 unfacd works
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

#ifndef UFSRV_ZKGROUP_PARAMS_TYPE_H
#define UFSRV_ZKGROUP_PARAMS_TYPE_H

#include <uflib/standard_c_includes.h>
#include <signal_ffi.h>

#define GROUP_SECRET_PARAMS_SIZE  SignalGROUP_SECRET_PARAMS_LEN
#define GROUP_PUBLIC_PARAMS_SIZE  SignalGROUP_PUBLIC_PARAMS_LEN
#define GROUP_IDENTIFIER_SIZE     SignalGROUP_IDENTIFIER_LEN

typedef struct ZKGroupParams {
  struct {
    uint8_t raw[GROUP_SECRET_PARAMS_SIZE];
    uint8_t encoded[((GROUP_SECRET_PARAMS_SIZE + 2) / 3) * 5];
  } secret_param;

  struct {
    uint8_t raw[GROUP_PUBLIC_PARAMS_SIZE];
    uint8_t encoded[((GROUP_PUBLIC_PARAMS_SIZE + 2) / 3) * 5];
  } public_param;

  struct {
    uint8_t raw[GROUP_IDENTIFIER_SIZE];
    uint8_t encoded[((GROUP_IDENTIFIER_SIZE + 2) / 3) * 5];
  } public_identifier;
} ZKGroupParams;

#endif //UFSRV_ZKGROUP_PARAMS_TYPE_H
