/**
 * Copyright (C) 2015-2024 unfacd works
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

/**
* @file cloud_authorization_token.h
* @brief Opaque type representing CloudAuthorizationDescriptor.
*/

#ifndef UFSRV_CLOUD_AUTHORIZATION_TOKEN_TYPE_H
#define UFSRV_CLOUD_AUTHORIZATION_TOKEN_TYPE_H

/**
 * Opaque type representing CloudAuthorizationDescriptor.
 */
typedef struct CloudAuthorizationToken CloudAuthorizationToken;
#define AS_CLOUD_AUTHORIZATION_TOKEN(x) ((CloudAuthorizationToken *)(x))

#endif //UFSRV_CLOUD_AUTHORIZATION_TOKEN_TYPE_H
