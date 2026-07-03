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

#ifndef UFSRV_ZKGROUP_MASTERKEY_TYPE_H
#define UFSRV_ZKGROUP_MASTERKEY_TYPE_H

#include <signal_ffi.h>

#define GROUP_MASTER_KEY_SIZE SignalGROUP_MASTER_KEY_LEN

typedef struct ZKGroupMasterKey {
  struct {
    union {
      uint8_t bytes[GROUP_MASTER_KEY_SIZE];
      uint8_t *bytes_by_ref;
    };
    bool is_by_ref;
  } raw;

  struct {
    int8_t bytes[((GROUP_MASTER_KEY_SIZE + 2) / 3) * 5];
  } encoded;
} ZKGroupMasterKey;

#endif //UFSRV_ZKGROUP_MASTERKEY_TYPE_H
