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

#ifndef UFSRV_INTEGRITY_H
#define UFSRV_INTEGRITY_H

#include <main.h>
#include <http_request_context_type.h>
#include <integrity_verdict_descriptor_type.h>
#include <gpc_service_request_descriptor.h>

int GetGoogleIntegrityVerdictResponse(HttpRequestContext *http_ptr, const char *integrity_token, IntegrityVerdictDescriptor *verdict_descriptor_out, const GpcServiceRequestDescriptor *const gpc_request_descriptor_ptr);
IntegrityVerdictDescriptor *ParseIntegrityVerdictResponse(json_object *jobj_ptr, IntegrityVerdictDescriptor *verdict_descriptor_ptr_out);

#endif //UFSRV_INTEGRITY_H
