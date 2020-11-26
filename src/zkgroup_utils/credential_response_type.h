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

#ifndef UFSRV_CREDENTIAL_RESPONSE_TYPE_H
#define UFSRV_CREDENTIAL_RESPONSE_TYPE_H

#include <zkgroup.h>

typedef struct CredentialResponse {
  struct {
    uint8_t by_value[AUTH_CREDENTIAL_RESPONSE_LEN];
    uint8_t *by_ref;
  } raw;

  struct {
    uint8_t by_value[((AUTH_CREDENTIAL_RESPONSE_LEN + 2) / 3) * 5];
    uint8_t *by_ref;
  } serialised;
} CredentialResponse;


#endif //UFSRV_CREDENTIAL_RESPONSE_TYPE_H
