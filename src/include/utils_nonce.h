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

#ifndef UFSRV_UTILS_NONCE_H
#define UFSRV_UTILS_NONCE_H

#include <standard_c_includes.h>
#include <session_type.h>

int BackEndDeleteNonce (Session *, const char *nonce, const char *prefix);
bool IsNonceValid(Session *sesn_ptr, const char *nonce, const char *prefix);
int BackEndGetNonce (Session *sesn_ptr_carrier, const char *nonce,  const char *prefix);
char *BackEndGenerateNonce (Session *, time_t expiry_in, const char *, const char *);

#endif //UFSRV_UTILS_NONCE_H
