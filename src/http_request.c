/*
 * http_request.c
 *
 *  Created on: 6 Nov 2016
 *      Author: ayman
 */



#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <misc.h>
#include <http_request.h>

static size_t (*GetDefaultBackendResponse()) (void *,size_t, size_t, void *);
inline static int _FetchJsonResponse (HttpRequestContext *http_ptr);
inline static void _SetupBasicRequestOptions (HttpRequestContext *http_ptr);

//one-off initialisation per thread
HttpRequestContext *
InitialiseHttpRequestContext (HttpRequestContext *http_ptr_in, unsigned long call_flags)

{
	HttpRequestContext *http_ptr;

	if (IS_EMPTY(http_ptr_in))	http_ptr=calloc(1, sizeof(HttpRequestContext));
	else												http_ptr=http_ptr_in;

	//init CURL handle
	if (!(http_ptr->curl=curl_easy_init()))	goto return_error_curl_init;

	//more CURL one-off inits. these should not need to change throughout teh threadlifeccyle
	http_ptr->rb.memory = NULL;//mymalloc(1);//must be freed across successive calls which is done in reset function below
	http_ptr->rb.size = 0;
	_SetupBasicRequestOptions(http_ptr);
	/*curl_easy_setopt(http_ptr->curl, CURLOPT_ERRORBUFFER, http_ptr->curl_error_str);
	curl_easy_setopt(http_ptr->curl, CURLOPT_WRITEFUNCTION, GetDefaultBackendResponse());
	curl_easy_setopt(http_ptr->curl, CURLOPT_WRITEDATA, (void *)&(http_ptr->rb));
	curl_easy_setopt(http_ptr->curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);//prevents ipv6 lookup which slows down dns resolution
	curl_easy_setopt(http_ptr->curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(http_ptr->curl, CURLOPT_FORBID_REUSE, 1L);
*/
	http_ptr->jtok=json_tokener_new();
	http_ptr->jobj=NULL;

	return http_ptr;

	return_error_curl_init:
	syslog(LOG_ERR, "%s (pid:'%lu'): ERROR COULD NOT INITIALISE HTTP REQUEST subsystem", __func__, pthread_self());

	return_free_null:
	if (IS_EMPTY(http_ptr_in))	free(http_ptr_in);
	return NULL;

}


inline static void
_SetupBasicRequestOptions (HttpRequestContext *http_ptr)
{
	curl_easy_setopt(http_ptr->curl, CURLOPT_ERRORBUFFER, http_ptr->curl_error_str);
	curl_easy_setopt(http_ptr->curl, CURLOPT_WRITEFUNCTION, GetDefaultBackendResponse());
	curl_easy_setopt(http_ptr->curl, CURLOPT_WRITEDATA, (void *)&(http_ptr->rb));
	curl_easy_setopt(http_ptr->curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);//prevents ipv6 lookup which slows down dns resolution
	curl_easy_setopt(http_ptr->curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(http_ptr->curl, CURLOPT_FORBID_REUSE, 1L);
}


void
DestructHttpRequestContext (HttpRequestContext *http_ptr, bool self_destruct)

{
	if (unlikely(IS_EMPTY(http_ptr)))	return;

	if (http_ptr->rb.size>0)	free (http_ptr->rb.memory);
	curl_easy_cleanup(http_ptr->curl);

	if (IS_PRESENT(http_ptr->jobj)) json_object_put(http_ptr->jobj);
	json_tokener_free(http_ptr->jtok);

	memset(http_ptr, 0, sizeof(HttpRequestContext));
	if (self_destruct)	free(http_ptr);

}


void
ResetHttpRequestContext (HttpRequestContext *http_ptr)
{
	if (unlikely(IS_EMPTY(http_ptr)))	return;

	if (http_ptr->rb.size>0)	free (http_ptr->rb.memory);

	//CURL reallocates as needed depending on response size
	http_ptr->rb.memory=malloc(1);
	http_ptr->rb.size=0;

	curl_easy_reset(http_ptr->curl); //destroys the fixed optionssetup in nitialise...() above
	_SetupBasicRequestOptions(http_ptr);

	if (IS_PRESENT(http_ptr->jobj))
	{
		json_object_put(http_ptr->jobj);
		http_ptr->jobj=NULL;
		json_tokener_reset(http_ptr->jtok);
	}

}


//if we get url_params we encode then we concat into geturl and ESCAPE
//this should be used instead of the other Json one
/**
 * 	@return 0: on error
 */
int
HttpRequestGetUrlInJson (HttpRequestContext *http_ptr, const char *url_str, const char *url_params)
{

	if (IS_PRESENT(url_params))
	{
		char encoded_url_str[XLBUF] = {0};
		char *s = curl_easy_escape(http_ptr->curl, url_params, 0);

		snprintf(encoded_url_str, XLBUF-1, "%s%s", url_str, s);

		int result = HttpRequestGetUrlJson (http_ptr, encoded_url_str);

		curl_free(s);

		return result;
	}
	else return HttpRequestGetUrlJson (http_ptr, url_str);

}


//fetches the content of url in context of user session.Essentially abstracts out the CURL implementation
//return  0 on error
//
int
HttpRequestGetUrl (HttpRequestContext *http_ptr, const char *url_str)
{

#ifdef __UF_TESTING
		syslog(LOG_DEBUG, "%s (pid:'%lu'): FETCHING '%s'", __func__, pthread_self(),  url_str);
#endif


		ResetHttpRequestContext(http_ptr);

		curl_easy_setopt(http_ptr->curl, CURLOPT_URL, url_str);

		if ((http_ptr->curl_code = curl_easy_perform(http_ptr->curl)) != CURLE_OK)
		{
			syslog(LOG_ERR, "%s (pid:'%lu'): ERROR COULD NOT GET '%s'. Error: '%s'", __func__, pthread_self(), url_str, http_ptr->curl_error_str);

			//no clean up we just rely n reset upon subsequent calls ro get url
			return 0;
		}

	//fetch http response code. 200 is success
	long http_code = 0;
	curl_easy_getinfo (http_ptr->curl, CURLINFO_RESPONSE_CODE, &http_code);

	//syslog(LOG_ERR, "%s (pid:'%lu'): server response stream: '%s'", __func__, pthread_self(), http_ptr->rb.memory);
	return (int)http_code;

}

/**
 *	Note the dry_run parameter which defaults to false. Allows to check if the token is valid or not without actually contacting the client
 * 	curl --header "Authorization: key=xxx" --header "Content-Type:application/json" https://android.googleapis.com/gcm/send -d '{"dry_run":false, "registration_ids":["APA91bEW6clA02RI2S_4caipD1k-SotCMjCbdrwrHWeNcxAPBG7Pra3ermvKN-gn9bi_rY4l6iTEZ3gPqYZyaW5V_hpZKv9JOn1IoPo5aHTobzaAb1lJHpST0PT3Y0Dx-iTnV3eFKKWm"] "message":"h"}'
 */
int
HttpRequestGoogleGcm (HttpRequestContext *http_ptr, const char *url_str, const char *json_payload)
{
	//curl --header "Authorization: key=xxx" --header "Content-Type:application/json" https://android.googleapis.com/gcm/send -d "{\"registration_ids\":[\"APA91bFaBGQMQQ8XzNlo1Zw86e8e8IpbiJF1xXbFlcQul2TtcTg9oymXImN3FBhpuocYGeFILssTxh6paB8WwEfZdi1kLmqepfguB7yXnUTMc2bdw5Tq2IWR71stpmtcpFtvyNp9tGBY\"], \"message\":\"hellow\"}"

		ResetHttpRequestContext(http_ptr);
		struct curl_slist *headers_dictionary = NULL;

		char header_buf[XLBUF]={0};
		snprintf(header_buf, XLBUF-1, "Authorization: key=%s", APIKEY_GOOGLE_GCM);
		headers_dictionary = curl_slist_append(headers_dictionary, header_buf);
		headers_dictionary = curl_slist_append(headers_dictionary, "Content-Type: application/json");
		headers_dictionary = curl_slist_append(headers_dictionary,  "Accept: application/json");

		curl_easy_setopt(http_ptr->curl, CURLOPT_CUSTOMREQUEST, "POST");
		curl_easy_setopt(http_ptr->curl, CURLOPT_HTTPHEADER, headers_dictionary);
		curl_easy_setopt(http_ptr->curl, CURLOPT_POSTFIELDS, json_payload);
		curl_easy_setopt(http_ptr->curl, CURLOPT_URL, url_str);

		if ((http_ptr->curl_code=curl_easy_perform(http_ptr->curl))!=CURLE_OK)
		{
			syslog(LOG_ERR, "%s (pid:'%lu'): ERROR COULD NOT POST REQUEST '%s'. Error: '%s'", __func__, pthread_self(), url_str, http_ptr->curl_error_str);

			//no clean up we just rely n reset upon subsequent calls ro get url
			return 0;
		}

	//fetch http response code. 200 is success
	long http_code = 0;
	curl_easy_getinfo (http_ptr->curl, CURLINFO_RESPONSE_CODE, &http_code);


	if ((_FetchJsonResponse(http_ptr))==0)
	{
		//response
		//{"multicast_id":6126472261424557086,"success":1,"failure":0,"canonical_ids":1,"results":[{"registration_id":"APA91bEW6clA02RI2S_4caipD1k-SotCMjCbdrwrHWeNcxAPBG7Pra3ermvKN-gn9bi_rY4l6iTEZ3gPqYZyaW5V_hpZKv9JOn1IoPo5aHTobzaAb1lJHpST0PT3Y0Dx-iTnV3eFKKWm","message_id":"0:1478614820005773%3af43603f9fd7ecd"}]}

		int success=json_object_get_int(json__get(http_ptr->jobj, "success"));
		if (success==1)
		{
#ifdef __UF_TESTING
			syslog(LOG_ERR, "%s (pid:'%lu'): Gcm: Success delivery confirmed...", __func__, pthread_self());
#endif

			return (int)http_code;
		}
		else
		{
			syslog(LOG_ERR, "%s (pid:'%lu'): ERROR: COULD NOT DELIVER GCM MESSAGE: '%s'..", __func__, pthread_self(), json_object_to_json_string(http_ptr->jobj));
		}
	}

	return 0;

}


/**
 * 	@return 0: on error
 * 	@return: standard http response code on request
 */
int
HttpRequestPostUrlJson (HttpRequestContext *http_ptr, const char *url_str, const char *post_fields, const char *auth, const char *content_type, unsigned long content_len)

{
	int rc=0;

	if ((rc=HttpRequestPostUrl(http_ptr, url_str, post_fields, auth, content_type, content_len)))
	{
		//we rely on the fact that SessionServicePostUrl above has invoked the reset routine simple html buffer fetch
		if (strlen(http_ptr->rb.memory)==0)
		{
			syslog(LOG_NOTICE, "%s (pid:'%lu'): ERROR: EMPTY JSON RESPONSE WAS RETURNED...", __func__, pthread_self());
			return 0;
		}

		do
		{
			http_ptr->jobj=json_tokener_parse_ex(http_ptr->jtok, http_ptr->rb.memory, strlen(http_ptr->rb.memory));
		}
		while ((http_ptr->jerr=json_tokener_get_error(http_ptr->jtok))==json_tokener_continue);

		if (http_ptr->jerr!=json_tokener_success)
		{
			syslog(LOG_NOTICE, "%s (pid='%lu'): ERROR JSON TOKENISER: '%s' ", __func__, pthread_self(),	json_tokener_error_desc(http_ptr->jerr));

			//no cleanup necessaru we rely on subsequent get url invoking reset
			return 0;
		}
		else
		{
			//success result are in ubawp_ptr->jobj
			return rc;
		}
	}
	else
	{
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
HttpRequestPostUrl (HttpRequestContext *http_ptr, const char *url_str, const char *post_fields, const char *auth, const char *content_type, unsigned long content_len)
{
		struct curl_slist *headers=NULL;
		char *header_params;

		syslog(LOG_DEBUG, "%s (pid:'%lu'): POST '%s' with fields:'%s'", __func__, pthread_self(),
				url_str, post_fields?post_fields:"_empty_");

		char *encoded_url_str=NULL;
		if (post_fields)	encoded_url_str=curl_easy_escape(http_ptr->curl, post_fields, 0);

		ResetHttpRequestContext(http_ptr);

		if (content_type)
		{
			asprintf(&header_params, "Content-Type: %s", content_type);
			headers = curl_slist_append(headers, header_params);

			if (content_len)	curl_easy_setopt(http_ptr->curl, CURLOPT_POSTFIELDSIZE, content_len);
		}

		curl_easy_setopt(http_ptr->curl, CURLOPT_URL, url_str);
		if (post_fields)	curl_easy_setopt(http_ptr->curl, CURLOPT_POSTFIELDS, post_fields);//encoded_url_str);
		if (auth)	curl_easy_setopt(http_ptr->curl, CURLOPT_USERPWD, auth);
		if (content_type)	curl_easy_setopt(http_ptr->curl, CURLOPT_HTTPHEADER, headers);


		//TODO: look into what CURL does with the buffer memory and len
		if ((http_ptr->curl_code=curl_easy_perform(http_ptr->curl))!=CURLE_OK)
		{
			syslog(LOG_ERR, "%s (pid='%lu'): ERROR COULD NOT POST '%s'. Error: '%s'", __func__, pthread_self(), url_str, http_ptr->curl_error_str);

			//no clean up we just rely n reset upon subsequent calls ro get url
			curl_free(encoded_url_str);
			if (content_type)
			{
				free(header_params);
				curl_slist_free_all(headers);
			}

			return 0;
		}

		curl_free(encoded_url_str);
		if (content_type)
		{
			free(header_params);
			curl_slist_free_all(headers);
		}

		//fetch http response code. 200 is success
		long http_code = 0;
		curl_easy_getinfo (http_ptr->curl, CURLINFO_RESPONSE_CODE, &http_code);

		return (int)http_code;

}


//fetches the content of url in context of user session.Essentially abstracts out the CURL implementation
//we dont do clean ups here we just reuse the preallocated data structure for future calls  after we called reset functions
//just a service request. upto caller to decide how recover from error
//@retruns http response code on success
//return 0 on error
int
HttpRequestGetUrlJson (HttpRequestContext *http_ptr, const char *url_str)
{
	int http_response_code;
	if ((http_response_code = HttpRequestGetUrl(http_ptr, url_str)) > 0)
	{
		if (strlen(http_ptr->rb.memory) == 0)
		{
			syslog(LOG_NOTICE, "%s (pid:'%lu'): ERROR: EMPTY JSON RESPONSE WAS RETURNED...", __func__, pthread_self());
			return 0;
		}
		//we rely on the fact that SessionServiceGetUrl above has invoked the reset routine simple html buffer fetch
		do
		{
			http_ptr->jobj = json_tokener_parse_ex(http_ptr->jtok, http_ptr->rb.memory, strlen(http_ptr->rb.memory));
		}
		while ((http_ptr->jerr = json_tokener_get_error(http_ptr->jtok))==json_tokener_continue);

		if (http_ptr->jerr != json_tokener_success)
		{
			syslog(LOG_NOTICE, "%s (pid='%lu', json:'%s'): ERROR JSON TOKENISER: '%s' ", __func__, pthread_self(),	http_ptr->rb.memory,
			 json_tokener_error_desc(http_ptr->jerr));

			//no cleanup necessaru we rely on subsequent get url invoking reset
			return 0;
		}
		else
		{
			//success result are in ubawp_ptr->jobj
			return http_response_code;
		}

	}
	else
	{
		syslog(LOG_ERR, "%s (pid='%lu'): error.", __func__, pthread_self());

		return 0;
	}

}


/**
 * 	@return 0: on success
 */
inline static int
_FetchJsonResponse (HttpRequestContext *http_ptr)
{
	if (strlen(http_ptr->rb.memory)==0)
	{
		syslog(LOG_NOTICE, "%s (pid:'%lu'): ERROR: EMPTY JSON RESPONSE WAS RETURNED...", __func__, pthread_self());
		return 1;
	}
	do
	{
		http_ptr->jobj=json_tokener_parse_ex(http_ptr->jtok, http_ptr->rb.memory, strlen(http_ptr->rb.memory));
	}
	while ((http_ptr->jerr=json_tokener_get_error(http_ptr->jtok))==json_tokener_continue);

	if (http_ptr->jerr!=json_tokener_success)
	{
		syslog(LOG_NOTICE, "%s (pid: '%lu', json:'%s'): ERROR JSON TOKENISER: '%s' ", __func__, pthread_self(),	http_ptr->rb.memory, json_tokener_error_desc(http_ptr->jerr));

		return 1;
	}

	return 0;
}


static size_t BackendResponse (void *contents, size_t size, size_t nmemb, void *userp);

//return a pointer to the function below
static size_t (*GetDefaultBackendResponse()) (void *,size_t, size_t, void *)
{

	return BackendResponse;
}


//generic callback that manipulates memory based buffer for use by CURL's html response fetching mechanism
//just works... must free mem->memory between usages
static size_t
BackendResponse (void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	RawBuffer_ *mem = (RawBuffer_ *)userp;

	mem->memory = realloc(mem->memory, mem->size + realsize + 1);
	if(mem->memory == NULL)
	{
		/* fatal: out of memory: should terminate */
		printf("not enough memory (realloc returned NULL)\n");
		return 0;
	}

	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize;

}
