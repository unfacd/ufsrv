/**
 * Copyright (C) 2015-2019 unfacd works
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

#include <main.h>
#include <misc.h>
#include <api_endpoint_v1_registry.h>
#include <ufsrv_core/user/user_backend.h>
#include <http_request_handler.h>
#include <response.h>
#include <session_type.h>
#include <http_session_type.h>
#include <protocol_http_type.h>
#include <ufsrvuid.h>

static const char *err = "Server unable to complete request.";

/**
 * 	@brief: This endpoint manipulates the hashstore ACCOUNTS_DIRECTORY in the redis backend.
 * 	Each account, upon successful registration will have its verified number encoded and stored in this directory,
 * 	which is primarily used to cache users for quick look up if they are registred and also to perform intersection between user shared
 * 	accounts.
 *
 * 	GET: return a previously stored, encoded user number.
 * 	curl -u a:a -X GET "https://api.unfacd.io:20080/V1/Registry/UserToken/eG1eChJyw5d/I"
{ "token": "eG1eChJyw5d\/I" }

	Only available in trusted/dev mode
 	 POST/PUT: both idempotent. The passed number will be encoded and stored in the backend
 * 	curl -u a:a -X POST "https://api.unfacd.io:20080/V1/Registry/UserToken/%2B+61xxxxx"
{ "token": "eG1eChJyw5d\/I" }

 curl -Ss -u +61412345678:dxHXgDXYc+fLhHlp92b0741z -X GET 'https://api.unfacd.io:20080/V1/Registry/UserToken/%2B+61xxxxx'
	Only available in trusted/dev mode
	DELETE: Delete previously stored token. 200 retuned upon success.
 */
API_ENDPOINT_V1(REGISTERY_USER)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
	HttpSession *http_ptr = (HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);
	#define _THIS_PATH	"/V1/Registry/UserToken/"

	const char *user_token_req;
	size_t pathprefix_len = strlen( _THIS_PATH);
	const char *full_path = onion_request_get_fullpath(HTTPSESN_REQUEST_PTR(http_ptr));

	if (strlen(full_path) <= pathprefix_len)	goto request_error;

	user_token_req = full_path + pathprefix_len;
	if (unlikely(*user_token_req == '\0')) {
		goto request_error;
	}

	syslog(LOG_DEBUG, ">> FOUND USER TOKEN: '%s'", user_token_req);

#ifndef __UF_DEV
	//TODO check for number length
#endif

	char *user_token = strdupa(user_token_req);

	int flags = onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));
	if ((flags&OR_METHODS) == OR_GET) {
		BackendDirectoryContactTokenGet(sesn_ptr, user_token);
		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr) && IS_STR_LOADED((char *)SESSION_RESULT_USERDATA(sesn_ptr))) {
			char *userid = strrchr((char *)SESSION_RESULT_USERDATA(sesn_ptr), ':');
			if (IS_PRESENT(userid)) {
				struct json_object *jobj_token = json_object_new_object();

				*userid++ = '\0';
				json_object_object_add(jobj_token, "token", json_object_new_string((char *)SESSION_RESULT_USERDATA(sesn_ptr)));

				if (IS_PRESENT(JsonFormatUserProfile(sesn_ptr, strtoul(userid, NULL, 10), DIGESTMODE_BRIEF, true, jobj_token))) {

          const char *json_str_reply = json_object_to_json_string(jobj_token);

          onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(json_str_reply));
          onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), json_str_reply, strlen(json_str_reply));

          free(SESSION_RESULT_USERDATA(sesn_ptr));
          json_object_put(jobj_token);

          goto request_processed;
        } else {
          free(SESSION_RESULT_USERDATA(sesn_ptr));
          json_object_put(jobj_token);
          goto request_error;
				}
			} else	{
        free (SESSION_RESULT_USERDATA(sesn_ptr));
			  goto request_no_token;
			}
		}
		else {
			goto request_no_token;
		}
	}
	else
	if ((flags&OR_METHODS) == OR_POST) {
#if  0 //def __UF_DEV TODO: must supply userid
		BackendDirectoryContactTokenSet (sesn_ptr, user_token);
		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))
		{
			struct json_object *jobj_token=json_object_new_object();
			json_object_object_add (jobj_token, "token", json_object_new_string((char *)SESSION_RESULT_USERDATA(sesn_ptr)));

			const char *json_str_reply=json_object_to_json_string(jobj_token);
			//const char *json_str_reply=json_object_to_json_string_ext(jobj_token, JSON_C_TO_STRING_NOSLASHESCAPE);

			onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(json_str_reply));
			onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),json_str_reply, strlen(json_str_reply));

			free (SESSION_RESULT_USERDATA(sesn_ptr));
			json_object_put(jobj_token);

			goto request_processed;
		}
#endif
	}
	else
	if 	((flags&OR_METHODS) == OR_DELETE) {
#ifdef __UF_DEV
		BackendDirectoryContactTokenDel (sesn_ptr, user_token);
		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
			goto request_processed;
		} else {
			goto request_error;
		}
#endif
	}

	request_no_token:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 404);
	goto request_written;

	request_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
	goto request_written;

	request_written:
	onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));

	request_processed:
	return OCS_PROCESSED;

#undef _THIS_PATH

}

API_ENDPOINT_V1(REGISTERY_USERID)
{
  int response_code = HTTP_RESPONSE_CODE_GENERIC_ERROR;

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
	HttpSession *http_ptr = (HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);

	#define _THIS_PATH	"/V1/Registry/UserId/"

	const char *user_token_req;
	size_t pathprefix_len = strlen( _THIS_PATH);
	const char *full_path = onion_request_get_fullpath(HTTPSESN_REQUEST_PTR(http_ptr));

	if (strlen(full_path) <= pathprefix_len)	goto request_error;

	user_token_req = full_path + pathprefix_len;
	if (*user_token_req == '\0' || strlen(user_token_req) < CONFIG_MAX_UFSRV_ID_ENCODED_SZ) { //user id zero ignored
		goto request_error;
	}

//	char *userid=strndupa(user_token_req, CONFIG_MAX_UFSRV_ID_ENCODED_SZ+1);
	UfsrvUid uid = {0};
	unsigned long userid_sequence = UfsrvUidGetSequenceId(UfsrvUidCreateFromEncodedText(user_token_req, &uid));

	if (userid_sequence <= 0) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', uid:'%s', uid_sequence:'%lu'}: ERROR: INVALID USERID", __func__,  pthread_self(), user_token_req, userid_sequence);
    goto request_error;
	}

#ifdef __UF_FULLDEBUG
	syslog(LOG_DEBUG, ">> FOUND USER TOKEN: '%s'", userid);
#endif

	int flags = onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));
	if ((flags&OR_METHODS) == OR_GET) {
			struct json_object *jobj_token = json_object_new_object();

			if (IS_PRESENT(JsonFormatUserProfile(sesn_ptr, userid_sequence, DIGESTMODE_BRIEF, true, jobj_token))) {
        const char *json_str_reply = json_object_to_json_string(jobj_token);

        onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(json_str_reply));
        onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), json_str_reply, strlen(json_str_reply));

        json_object_put(jobj_token);

        goto request_processed;
      } else {
        json_object_put(jobj_token);
        goto request_error;
			}
	} else if ((flags&OR_METHODS) == OR_POST) {
	  response_code = HTTP_RESPONSE_CODE_UNSUPPORTED_OP;
		//fallthrough to error
	} else if 	((flags&OR_METHODS) == OR_DELETE) {
		//fallthrough to error
    response_code = HTTP_RESPONSE_CODE_UNSUPPORTED_OP;
	}

	request_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), response_code);
	onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));

	request_processed:
	return OCS_PROCESSED;

#undef _THIS_PATH
}

