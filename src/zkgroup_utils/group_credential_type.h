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
// Created by devops on 10/20/20.
//

#ifndef UFSRV_GROUP_CREDENTIAL_TYPE_H
#define UFSRV_GROUP_CREDENTIAL_TYPE_H

#include "credential_response_type.h"

typedef struct GroupCredential {
  CredentialResponse credential;
  size_t redemption_time;
} GroupCredential;

#endif //UFSRV_GROUP_CREDENTIAL_TYPE_H
