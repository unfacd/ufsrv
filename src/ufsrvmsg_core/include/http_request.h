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

#ifndef SRC_INCLUDE_HTTP_REQUEST_H_
#define SRC_INCLUDE_HTTP_REQUEST_H_

#include <uflib/main_types.h>
#include <http_request_context_type.h>
#include <gpc_service_request_descriptor.h>

HttpRequestContext *InitialiseHttpRequestContext(HttpRequestContext *http_ptr, unsigned long call_flags);
void DestructHttpRequestContext(HttpRequestContext *http_ptr, bool self_destruct);
void ResetHttpRequestContext(HttpRequestContext *http_ptr);
int
HttpRequestGetUrl(HttpRequestContext *, const char *, const char *auth, CollectionDescriptor *collection_query_params);
int HttpRequestGetUrlInJson(HttpRequestContext *http_ptr, const char *url_str, const char *url_params, const char *auth);
int HttpRequestGetUrlWithQueryParamsInJson(HttpRequestContext *http_ptr, const char *url_str, const char *url_params, const char *auth, CollectionDescriptor *collection_ptr);
int HttpRequestGetUrlJson(HttpRequestContext *, const char *, const char *auth, CollectionDescriptor *collection_query_params);
int HttpRequestPostUrl(HttpRequestContext *http_ptr, const char *url_str, const char *post_fields, const char *auth, const char *header_param_user, const char *content_type, unsigned long content_len);
int	HttpRequestPostUrlJson(HttpRequestContext *ss_ptr, const char *url_str, const char *post_fields, const char *auth, const char *content_type, unsigned long content_len);
int ExtractJsonResponse(HttpRequestContext *http_ptr);
int HttpRequestGoogleGcm(HttpRequestContext *http_ptr, const char *url_str, const char *);
int HttpRequestGoogleFcm(HttpRequestContext *http_ptr, const char *payload);

#endif /* SRC_INCLUDE_HTTP_REQUEST_H_ */
