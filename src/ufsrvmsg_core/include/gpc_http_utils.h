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

#ifndef UFSRV_GPC_HTTP_UTILS_H
#define UFSRV_GPC_HTTP_UTILS_H

#include <main.h>
#include <http_request_context_type.h>
#include <gpc_service_request_descriptor.h>

char *GetGoogleAccessCodeAuthorization(HttpRequestContext *http_ptr, const GpcServiceRequestDescriptor *const gpc_request_descriptor_ptr);
char *RequestGoogleAccessToken(HttpRequestContext *http_ptr, const char *jwt_encoded);
char *GenerateSignedJWT(HttpRequestContext *http_ptr, const GpcServiceRequestDescriptor *const gpc_request_descriptor_ptr);
int VerifySignedJWT(char *jwt_signature_input_str,  const char *signature);
void ComputeMessageDigest(unsigned char *message, size_t message_sz, unsigned char *message_hashed_out, unsigned int *message_hashed_out_sz);

#endif //UFSRV_GPC_HTTP_UTILS_H
