/*
 * http_request_context_type.h
 *
 *  Created on: 6 Nov 2016
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_HTTP_REQUEST_CONTEXT_TYPE_H_
#define SRC_INCLUDE_HTTP_REQUEST_CONTEXT_TYPE_H_

#include <json/json.h>
#include <curl/curl.h>

struct RawBuffer_ {
    char *memory;
    size_t size;
  };
  typedef struct RawBuffer_ RawBuffer_;

struct HttpRequestContext {
	CURL *curl;
	CURLcode curl_code;
	char curl_error_str[CURL_ERROR_SIZE];

	struct RawBuffer_ rb;

	struct json_object *jobj;
	enum json_tokener_error jerr;
	struct json_tokener *jtok;

};
typedef struct HttpRequestContext HttpRequestContext;


#endif /* SRC_INCLUDE_HTTP_REQUEST_CONTEXT_TYPE_H_ */
