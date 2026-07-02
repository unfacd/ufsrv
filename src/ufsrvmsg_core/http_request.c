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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <uflib/standard_defs.h>
#include <uflib/standard_c_includes.h>
#include <thread_context_type.h>
#include <nportredird.h>
#include <misc.h>
#include <http_request.h>
#include <gpc_utils.h>
#include <gpc_http_utils.h>

extern __thread ThreadContext ufsrv_thread_context;

static size_t (*_GetDefaultBackendResponse()) (void *,size_t, size_t, void *);
inline static void _SetupBasicRequestOptions(HttpRequestContext *http_ptr);

//one-off initialisation per thread
HttpRequestContext *
InitialiseHttpRequestContext(HttpRequestContext *http_ptr_in, unsigned long call_flags)
{
	HttpRequestContext *http_ptr;

	if (IS_EMPTY(http_ptr_in))	http_ptr = calloc(1, sizeof(HttpRequestContext));
	else												http_ptr = http_ptr_in;

	//init CURL handle
	if (!(http_ptr->curl = curl_easy_init()))	goto return_error_curl_init;

	//more CURL one-off inits. these should not need to change throughout teh threadlifeccyle
	http_ptr->rb.memory = NULL;//mymalloc(1);//must be freed across successive calls which is done in reset function below
	http_ptr->rb.size = 0;
	_SetupBasicRequestOptions(http_ptr);
	/*curl_easy_setopt(http_ptr->curl, CURLOPT_ERRORBUFFER, http_ptr->curl_error_str);
	curl_easy_setopt(http_ptr->curl, CURLOPT_WRITEFUNCTION, _GetDefaultBackendResponse());
	curl_easy_setopt(http_ptr->curl, CURLOPT_WRITEDATA, (void *)&(http_ptr->rb));
	curl_easy_setopt(http_ptr->curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);//prevents ipv6 lookup which slows down dns resolution
	curl_easy_setopt(http_ptr->curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(http_ptr->curl, CURLOPT_FORBID_REUSE, 1L);
*/
	http_ptr->jtok = json_tokener_new();
	http_ptr->jobj = NULL;

	return http_ptr;

	return_error_curl_init:
	syslog(LOG_ERR, "%s: ERROR COULD NOT INITIALISE HTTP REQUEST subsystem", __func__);

	return_free_null:
	if (IS_EMPTY(http_ptr_in))	free(http_ptr_in);
	return NULL;

}

inline static void
_SetupBasicRequestOptions(HttpRequestContext *http_ptr)
{
	curl_easy_setopt(http_ptr->curl, CURLOPT_ERRORBUFFER, http_ptr->curl_error_str);
	curl_easy_setopt(http_ptr->curl, CURLOPT_WRITEFUNCTION, _GetDefaultBackendResponse());
	curl_easy_setopt(http_ptr->curl, CURLOPT_WRITEDATA, (void *)&(http_ptr->rb));
	curl_easy_setopt(http_ptr->curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);//prevents ipv6 lookup which slows down dns resolution
	curl_easy_setopt(http_ptr->curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(http_ptr->curl, CURLOPT_FORBID_REUSE, 1L);
}

void
DestructHttpRequestContext(HttpRequestContext *http_ptr, bool self_destruct)
{
	if (unlikely(IS_EMPTY(http_ptr)))	return;

	if (http_ptr->rb.size > 0)	free(http_ptr->rb.memory);
	curl_easy_cleanup(http_ptr->curl);

	if (IS_PRESENT(http_ptr->jobj)) json_object_put(http_ptr->jobj);
	json_tokener_free(http_ptr->jtok);

	memset(http_ptr, 0, sizeof(HttpRequestContext));
	if (self_destruct)	free(http_ptr);

}

void
ResetHttpRequestContext(HttpRequestContext *http_ptr)
{
	if (unlikely(IS_EMPTY(http_ptr)))	return;

	if (http_ptr->rb.size > 0)	free(http_ptr->rb.memory);

	//CURL reallocates as needed depending on response size
	http_ptr->rb.memory = malloc(1);
	http_ptr->rb.size = 0;

	curl_easy_reset(http_ptr->curl); //destroys the fixed optionssetup in nitialise...() above
	_SetupBasicRequestOptions(http_ptr);

	if (IS_PRESENT(http_ptr->jobj)) {
		json_object_put(http_ptr->jobj);
		http_ptr->jobj = NULL;
		json_tokener_reset(http_ptr->jtok);
	}
}

//if we get url_params we encode then we concat into geturl and ESCAPE
//this should be used instead of the other Json one
/**
 * 	@return 0: on error
 */
int
HttpRequestGetUrlInJson(HttpRequestContext *http_ptr, const char *url_str, const char *url_params, const char *auth)
{
	if (IS_PRESENT(url_params)) {
		char encoded_url_str[XLBUF] = {0};
		char *s = curl_easy_escape(http_ptr->curl, url_params, 0);

		snprintf(encoded_url_str, XLBUF-1, "%s%s", url_str, s);

		int result = HttpRequestGetUrlJson(http_ptr, encoded_url_str, auth, NULL);

		curl_free(s);

		return result;
	}
	else return HttpRequestGetUrlJson(http_ptr, url_str, auth, NULL);

}

int
HttpRequestGetUrlWithQueryParamsInJson(HttpRequestContext *http_ptr, const char *url_str, const char *url_params, const char *auth, CollectionDescriptor *collection_ptr)
{
  if (IS_PRESENT(url_params)) {
    char encoded_url_str[XLBUF] = {0};
    char *s = curl_easy_escape(http_ptr->curl, url_params, 0);

    snprintf(encoded_url_str, XLBUF-1, "%s%s", url_str, s);

    int result = HttpRequestGetUrlJson(http_ptr, encoded_url_str, auth, collection_ptr);

    curl_free(s);

    return result;
  } else {
    return HttpRequestGetUrlJson(http_ptr, url_str, auth, collection_ptr);
  }

}


//fetches the content of url in context of user session.Essentially abstracts out the CURL implementation
//return  0 on error
//
int
HttpRequestGetUrl(HttpRequestContext *http_ptr, const char *url_str, const char *auth, CollectionDescriptor *collection_query_params)
{

#ifdef __UF_TESTING
  syslog(LOG_DEBUG, "%s (pid:'%lu'): FETCHING '%s'", __func__, pthread_self(),  url_str);
#endif

  ResetHttpRequestContext(http_ptr);
  __unused CURLUcode result;
  CURLU *url = curl_url();
  char *url_str_with_params = NULL;

  result = curl_url_set(url, CURLUPART_URL, url_str, 0);
  if (IS_PRESENT(collection_query_params) && collection_query_params->collection_sz > 0) {
    for (size_t i = 0; i< collection_query_params->collection_sz; i++) {
      curl_url_set(url, CURLUPART_QUERY, (char *)collection_query_params->collection[i], CURLU_APPENDQUERY);
    }

    curl_url_get(url, CURLUPART_URL, &url_str_with_params, 0);
    curl_easy_setopt(http_ptr->curl, CURLOPT_URL, url_str_with_params);
#ifdef __UF_TESTING
    syslog(LOG_DEBUG, "%s (pid:'%lu'): FETCHING '%s'", __func__, pthread_self(),  url_str_with_params);
#endif
  } else {
    curl_easy_setopt(http_ptr->curl, CURLOPT_URL, url_str);
#ifdef __UF_TESTING
    syslog(LOG_DEBUG, "%s (pid:'%lu'): FETCHING '%s'", __func__, pthread_self(),  url_str);
#endif
  }

  if (IS_PRESENT(auth))	curl_easy_setopt(http_ptr->curl, CURLOPT_USERPWD, auth);

  if ((http_ptr->curl_code = curl_easy_perform(http_ptr->curl)) != CURLE_OK) {
    syslog(LOG_ERR, "%s (pid:'%lu'): ERROR COULD NOT GET '%s'. Error: '%s'", __func__, pthread_self(), url_str, http_ptr->curl_error_str);

    if (IS_PRESENT(url_str_with_params)) curl_free(url_str_with_params);
    curl_url_cleanup(url);

    //no clean up we just rely n reset upon subsequent calls ro get url
    return 0;
  }

	//fetch http response code. 200 is success
	long http_code = 0;
	curl_easy_getinfo(http_ptr->curl, CURLINFO_RESPONSE_CODE, &http_code);

  if (IS_PRESENT(url_str_with_params)) curl_free(url_str_with_params);
  curl_url_cleanup(url);

	//syslog(LOG_ERR, "%s (pid:'%lu'): server response stream: '%s'", __func__, pthread_self(), http_ptr->rb.memory);
	return (int)http_code;

}

/**
 * @brief Google FireBase Cloud Messaging aka FCM interface point.
 * @note see https://firebase.google.com/docs/cloud-messaging/migrate-v1#java
 * @note see https://firebase.google.com/docs/reference/fcm/rest/v1/projects.messages and https://firebase.google.com/docs/reference/fcm/rest/v1/projects.messages/send https://firebase.google.com/docs/cloud-messaging/send-message#rest_1 (will be depracted)
 * @note perimission: "cloudmessaging.messages.create" is needed for the service account. Check https://cloud.google.com/iam/docs/understanding-roles#firebase-roles for applicable roles (search the permission).
 * currently using: (roles/firebasecloudmessaging.admin)
 * @note On success, each send method returns a message ID. The Firebase Admin SDK returns the ID string in the format projects/{project_id}/messages/{message_id}. eg '{ "name": "projects/invertible-fin-87106/messages/0:1725444409198900%b755eaa8f9fd7ecd" }'
 * unregistered user error: { "error": { "code": 404, "message": "Requested entity was not found.", "status": "NOT_FOUND", "details": [ { "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError", "errorCode": "UNREGISTERED" } ] } }
 * @param http_ptr
 * @param payload Preformatted json payload to push through FCM
 * @return 0 on error
 */
int
HttpRequestGoogleFcm(HttpRequestContext *http_ptr, const char *payload)
{
#define GOOGLE_FIREBASE_MESSAGING_SERVER "https://fcm.googleapis.com/v1/projects/invertible-fin-87106/messages:send"
#define GOOGLE_API_AUTHORIZATION "Authorization: Bearer %s"

  char *post_data = NULL;
//  char *gpc_access_token = GetGoogleAccessCodeAuthorization(http_ptr, ProvideGpcServiceRequestDescriptorForFirebaseMessaging());
  CloudAuthorizationTokenState gpc_token_state = {0};
  if (IS_EMPTY(ProvideGpcAuthorizationToken(GetUfsrvCloudAuthorizationTokenForFcm(), BLOCKING, &gpc_token_state))) {
    return 0;
  }
  char *authorization_str = NULL;
  asprintf(&authorization_str, GOOGLE_API_AUTHORIZATION, gpc_token_state.authorization_token);
  free(gpc_token_state.authorization_token);

  ResetHttpRequestContext(http_ptr);
  struct curl_slist *headers_dictionary = NULL;

  headers_dictionary = curl_slist_append(headers_dictionary, authorization_str);
  curl_slist_append(headers_dictionary, "Content-Type: application/json");
  curl_slist_append(headers_dictionary, "Accept: application/json");

  curl_easy_setopt(http_ptr->curl, CURLOPT_CUSTOMREQUEST, "POST");
  curl_easy_setopt(http_ptr->curl, CURLOPT_HTTPHEADER, headers_dictionary);
  curl_easy_setopt(http_ptr->curl, CURLOPT_POSTFIELDS, payload);
  curl_easy_setopt(http_ptr->curl, CURLOPT_URL, GOOGLE_FIREBASE_MESSAGING_SERVER);

  if ((http_ptr->curl_code = curl_easy_perform(http_ptr->curl)) != CURLE_OK) {
    syslog(LOG_ERR, "%s (pid:'%lu'): ERROR COULD NOT POST REQUEST '%s'. Error: '%s'", __func__, pthread_self(), post_data, http_ptr->curl_error_str);
    free(post_data);
    free(authorization_str);
    //no clean up we just rely n reset upon subsequent calls ro get url
    return -1;
  }

  free(post_data);
  free(authorization_str);

  //fetch http response code. 200 is success
  long http_code = 0;
  curl_easy_getinfo(http_ptr->curl, CURLINFO_RESPONSE_CODE, &http_code);

  if ((ExtractJsonResponse(http_ptr)) == 0) {
    const char *message_id = json_object_get_string(json__get(http_ptr->jobj, "name"));
    if (IS_PRESENT(message_id)) {
#ifdef __UF_TESTING
      syslog(LOG_ERR, "%s {pid:'%lu', message_id:'%s'}: Fcm: Success delivery confirmed...", __func__, pthread_self(), message_id);
#endif

      return (int)http_code;
    } else {
      syslog(LOG_ERR, "%s (pid:'%lu'): ERROR: COULD NOT DELIVER FCM MESSAGE: '%s'..", __func__, pthread_self(), json_object_to_json_string(http_ptr->jobj));
      //{ "error": { "code": 403, "message": "Permission 'cloudmessaging.messages.create' denied on resource '\/\/cloudresourcemanager.googleapis.com\/projects\/invertible-fin-87106' (or it may not exist).", "status": "PERMISSION_DENIED", "details": [ { "@type": "type.googleapis.com\/google.rpc.ErrorInfo", "reason": "IAM_PERMISSION_DENIED", "domain": "cloudresourcemanager.googleapis.com", "metadata": { "permission": "cloudmessaging.messages.create", "resource": "projects\/invertible-fin-87106" } } ] } }'
    }
  }

  return 0;

}

/**
 *	Note the dry_run parameter which defaults to false. Allows to check if the token is valid or not without actually contacting the client
 * 	curl --header "Authorization: key=xxx" --header "Content-Type:application/json" https://android.googleapis.com/gcm/send -d '{"dry_run":false, "registration_ids":["APA91bEW6clA02RI2S_4caipD1k-SotCMjCbdrwrHWeNcxAPBG7Pra3ermvKN-gn9bi_rY4l6iTEZ3gPqYZyaW5V_hpZKv9JOn1IoPo5aHTobzaAb1lJHpST0PT3Y0Dx-iTnV3eFKKWm"] "message":"h"}'
 *
 */
int __attribute__((deprecated()))
HttpRequestGoogleGcm(HttpRequestContext *http_ptr, const char *url_str, const char *json_payload)
{
	//curl --header "Authorization: key=xxx" --header "Content-Type:application/json" https://android.googleapis.com/gcm/send -d "{\"registration_ids\":[\"APA91bFaBGQMQQ8XzNlo1Zw86e8e8IpbiJF1xXbFlcQul2TtcTg9oymXImN3FBhpuocYGeFILssTxh6paB8WwEfZdi1kLmqepfguB7yXnUTMc2bdw5Tq2IWR71stpmtcpFtvyNp9tGBY\"], \"message\":\"hellow\"}"

		ResetHttpRequestContext(http_ptr);
		struct curl_slist *headers_dictionary = NULL;

		char header_buf[XLBUF] = {0};
		snprintf(header_buf, XLBUF-1, "Authorization: key=%s", APIKEY_GOOGLE_GCM);
		headers_dictionary = curl_slist_append(headers_dictionary, header_buf);
		headers_dictionary = curl_slist_append(headers_dictionary, "Content-Type: application/json");
		headers_dictionary = curl_slist_append(headers_dictionary,  "Accept: application/json");

		curl_easy_setopt(http_ptr->curl, CURLOPT_CUSTOMREQUEST, "POST");
		curl_easy_setopt(http_ptr->curl, CURLOPT_HTTPHEADER, headers_dictionary);
		curl_easy_setopt(http_ptr->curl, CURLOPT_POSTFIELDS, json_payload);
		curl_easy_setopt(http_ptr->curl, CURLOPT_URL, url_str);

		if ((http_ptr->curl_code = curl_easy_perform(http_ptr->curl)) != CURLE_OK) {
			syslog(LOG_ERR, "%s (pid:'%lu'): ERROR COULD NOT POST REQUEST '%s'. Error: '%s'", __func__, pthread_self(), url_str, http_ptr->curl_error_str);

			//no clean up we just rely n reset upon subsequent calls ro get url
			return 0;
		}

	//fetch http response code. 200 is success
	long http_code = 0;
	curl_easy_getinfo(http_ptr->curl, CURLINFO_RESPONSE_CODE, &http_code);


	if ((ExtractJsonResponse(http_ptr)) == 0) {
		//response
		//{"multicast_id":6126472261424557086,"success":1,"failure":0,"canonical_ids":1,"results":[{"registration_id":"APA91bEW6clA02RI2S_4caipD1k-SotCMjCbdrwrHWeNcxAPBG7Pra3ermvKN-gn9bi_rY4l6iTEZ3gPqYZyaW5V_hpZKv9JOn1IoPo5aHTobzaAb1lJHpST0PT3Y0Dx-iTnV3eFKKWm","message_id":"0:1478614820005773%3af43603f9fd7ecd"}]}

		int success = json_object_get_int(json__get(http_ptr->jobj, "success"));
		if (success == 1) {
#ifdef __UF_TESTING
			syslog(LOG_ERR, "%s (pid:'%lu'): Gcm: Success delivery confirmed...", __func__, pthread_self());
#endif

			return (int)http_code;
		} else {
			syslog(LOG_ERR, "%s (pid:'%lu'): ERROR: COULD NOT DELIVER GCM MESSAGE: '%s'..", __func__, pthread_self(), json_object_to_json_string(http_ptr->jobj));
			//{ "multicast_id": 7707098584016451211, "success": 0, "failure": 1, "canonical_ids": 0, "results": [ { "error": "NotRegistered" } ] }
		}
	}

	return 0;

}

/**
 *  @brief A generalised http request using POST and response encoded in json.
 *	@return 0: on error
 * 	@return: standard http response code on request
 */
int
HttpRequestPostUrlJson(HttpRequestContext *http_ptr, const char *url_str, const char *post_fields, const char *auth, const char *content_type, unsigned long content_len)

{
	int rc = 0;

	if ((rc = HttpRequestPostUrl(http_ptr, url_str, post_fields, auth, NULL, content_type, content_len))) {
		//we rely on the fact that SessionServicePostUrl above has invoked the reset routine simple html buffer fetch
		if (strlen(http_ptr->rb.memory) == 0) {
			syslog(LOG_NOTICE, "%s (pid:'%lu'): ERROR: EMPTY JSON RESPONSE WAS RETURNED...", __func__, pthread_self());
			return 0;
		}

		do {
			http_ptr->jobj = json_tokener_parse_ex(http_ptr->jtok, http_ptr->rb.memory, strlen(http_ptr->rb.memory));
		} while ((http_ptr->jerr = json_tokener_get_error(http_ptr->jtok)) == json_tokener_continue);

		if (http_ptr->jerr != json_tokener_success) {
			syslog(LOG_NOTICE, "%s (pid='%lu'): ERROR JSON TOKENISER: '%s' ", __func__, pthread_self(),	json_tokener_error_desc(http_ptr->jerr));

			//no cleanup necessaru we rely on subsequent get url invoking reset
			return 0;
		} else {
			//success result are in ubawp_ptr->jobj
			return rc;
		}
	} else {
		return rc;
	}
}

/*
 * @param post_fields: in the format "Field=1&Field=2&Field=3"
 * @param auth: when, specified must be in 'user:passswd'
 * @return HTTP response code
 * @return 0 on error
 */
int
HttpRequestPostUrl(HttpRequestContext *http_ptr, const char *url_str, const char *post_fields, const char *auth, const char *header_param_user, const char *content_type, unsigned long content_len)
{
  struct curl_slist *headers = NULL;
  char *header_params = NULL;

  syslog(LOG_DEBUG, "%s (pid:'%lu'): POST '%s' with fields:'%s'", __func__, pthread_self(), url_str, post_fields? post_fields : "_empty_");

  char *encoded_url_str = NULL;
  if (post_fields)	encoded_url_str = curl_easy_escape(http_ptr->curl, post_fields, 0);

  ResetHttpRequestContext(http_ptr);

  bool is_headers_used = IS_STR_LOADED(content_type) || IS_STR_LOADED(header_param_user);

  if (is_headers_used) {
    if (IS_STR_LOADED(content_type)) {
      asprintf(&header_params, "Content-Type: %s", content_type);
      headers = curl_slist_append(headers, header_params);
    }
    if (IS_STR_LOADED(header_param_user)) {
      headers = curl_slist_append(headers, header_param_user);
    }
    if (content_len > 0)	curl_easy_setopt(http_ptr->curl, CURLOPT_POSTFIELDSIZE, content_len);
  }

  curl_easy_setopt(http_ptr->curl, CURLOPT_URL, url_str);
  if (IS_PRESENT(post_fields))	curl_easy_setopt(http_ptr->curl, CURLOPT_POSTFIELDS, post_fields);//encoded_url_str);
  if (IS_PRESENT(auth))	curl_easy_setopt(http_ptr->curl, CURLOPT_USERPWD, auth);
  if (IS_PRESENT(content_type))	curl_easy_setopt(http_ptr->curl, CURLOPT_HTTPHEADER, headers);

  //TODO: look into what CURL does with the buffer memory and len
  if ((http_ptr->curl_code = curl_easy_perform(http_ptr->curl)) != CURLE_OK) {
    syslog(LOG_ERR, "%s (pid='%lu'): ERROR COULD NOT POST '%s'. Error: '%s'", __func__, pthread_self(), url_str, http_ptr->curl_error_str);

    //no clean up we just rely n reset upon subsequent calls ro get url
    curl_free(encoded_url_str);
    if (content_type) {
      free(header_params);
      curl_slist_free_all(headers);
    }

    return 0;
  }

  curl_free(encoded_url_str);
  if (is_headers_used) {
    if (!IS_EMPTY(header_params)) free(header_params);
    curl_slist_free_all(headers);
  }

  //fetch http response code. 200 is success
  long http_code = 0;
  curl_easy_getinfo(http_ptr->curl, CURLINFO_RESPONSE_CODE, &http_code);

  return (int)http_code;

}

//fetches the content of url in context of user session.Essentially abstracts out the CURL implementation
//we don't do clean-ups here; we just reuse the pre-allocated data structure for future calls  after we called reset functions
//just a service request. upto caller to decide how recover from error
//@return http response code on success
//return 0 on error
int
HttpRequestGetUrlJson(HttpRequestContext *http_ptr, const char *url_str, const char *auth, CollectionDescriptor *collection_query_params)
{
	int http_response_code;

	if ((http_response_code = HttpRequestGetUrl(http_ptr, url_str, auth, NULL)) > 0) {
		if (strlen(http_ptr->rb.memory) == 0) {
			syslog(LOG_NOTICE, "%s (pid:'%lu'): ERROR: EMPTY JSON RESPONSE WAS RETURNED...", __func__, pthread_self());
			return 0;
		}
		//we rely on the fact that SessionServiceGetUrl above has invoked the reset routine simple html buffer fetch
		do {
			http_ptr->jobj = json_tokener_parse_ex(http_ptr->jtok, http_ptr->rb.memory, strlen(http_ptr->rb.memory));
		}
		while ((http_ptr->jerr = json_tokener_get_error(http_ptr->jtok)) == json_tokener_continue);

		if (http_ptr->jerr != json_tokener_success) {
			syslog(LOG_NOTICE, "%s (pid='%lu', json:'%s'): ERROR JSON TOKENISER: '%s' ", __func__, pthread_self(),	http_ptr->rb.memory,
			 json_tokener_error_desc(http_ptr->jerr));

			//no cleanup necessary we rely on subsequent get url invoking reset
			return 0;
		} else {
			//success result are in ubawp_ptr->jobj but http code may not be 200
			return http_response_code;
		}
	} else {
		syslog(LOG_ERR, "%s (pid='%lu'): HTTP SUBSYSTEM GET ERROR.", __func__, pthread_self());

		return 0;
	}

}

/**
 * @brief Process a previously tokenized json stream and creat the corresponding binary object which is allocated in \ref HttpRequestContext.jobj
 * @param[IN] http_ptr ttp context containing data objects necessary for handling http request, response and processing of response
 * @return 0: on success
 */
int
ExtractJsonResponse(HttpRequestContext *http_ptr)
{
	if (strlen(http_ptr->rb.memory) == 0) {
		syslog(LOG_NOTICE, "%s (pid:'%lu'): ERROR: EMPTY JSON RESPONSE WAS RETURNED...", __func__, pthread_self());
		return 1;
	}
	do {
		http_ptr->jobj = json_tokener_parse_ex(http_ptr->jtok, http_ptr->rb.memory, strlen(http_ptr->rb.memory));
	} while ((http_ptr->jerr = json_tokener_get_error(http_ptr->jtok)) == json_tokener_continue);

	if (http_ptr->jerr != json_tokener_success) {
		syslog(LOG_NOTICE, "%s (pid: '%lu', json:'%s'): ERROR JSON TOKENISER: '%s' ", __func__, pthread_self(),	http_ptr->rb.memory, json_tokener_error_desc(http_ptr->jerr));

		return 1;
	}

	return 0;
}

static size_t _BackendResponse(void *contents, size_t size, size_t nmemb, void *userp);

//return a pointer to the function below
static size_t(*_GetDefaultBackendResponse()) (void *, size_t, size_t, void *)
{
	return _BackendResponse;
}

//generic callback that manipulates memory based buffer for use by CURL's html response fetching mechanism
//just works... must free mem->memory between usages
static size_t
_BackendResponse(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	RawBuffer_ *mem = (RawBuffer_ *)userp;

	mem->memory = realloc(mem->memory, mem->size + realsize + 1);
	if (mem->memory == NULL) {
		printf("not enough memory (realloc returned NULL)\n");
		return 0;
	}

	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize;

}