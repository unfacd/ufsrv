/*
 * http_request.h
 *
 *  Created on: 6 Nov 2016
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_HTTP_REQUEST_H_
#define SRC_INCLUDE_HTTP_REQUEST_H_

#include <http_request_context_type.h>

HttpRequestContext *InitialiseHttpRequestContext (HttpRequestContext *http_ptr, unsigned long call_flags);
void DestructHttpRequestContext (HttpRequestContext *http_ptr, bool self_destruct);
void ResetHttpRequestContext (HttpRequestContext *http_ptr);
int HttpRequestGetUrl (HttpRequestContext *, const char *);
int HttpRequestGetUrlInJson (HttpRequestContext *http_ptr, const char *url_str, const char *url_params);
int HttpRequestGetUrlJson (HttpRequestContext *, const char *);
int HttpRequestPostUrl (HttpRequestContext *http_ptr, const char *url_str, const char *post_fields, const char *auth, const char *content_type, unsigned long content_len);
int	HttpRequestPostUrlJson (HttpRequestContext *ss_ptr, const char *url_str, const char *post_fields, const char *auth, const char *content_type, unsigned long content_len);

int HttpRequestGoogleGcm (HttpRequestContext *http_ptr, const char *url_str, const char *);
#endif /* SRC_INCLUDE_HTTP_REQUEST_H_ */
