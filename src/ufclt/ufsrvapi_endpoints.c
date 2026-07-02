#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <misc.h>
#include <session.h>
#include <session_service.h>
//#include <protocol_websocket.h>
//#include "user_backend.h"
#include <user_backend_access_wordpress.h>//struct UserBackendAccessWordPress
#include "ufsrvapi_endpoints.h"
#include <json/json.h>

const char *validation_url="http://api.unfacd.io:20080/V1/Account/SignOn";


//perform login and generate a fresh signon cookie
//{ "userid": 18, "cookie": "fd273838a7c9f95dea1ebc2d63fa480cda259aa4d4a6eed36fa3786c99e27efc" }
int
BackendGenerateAuthenticationCookie (Session *sesn_ptr)

{
	char *url_str;
	UserBackendAccessWordPress *ubawp_ptr=NULL;
	UserBackendAccessRoutines *ubar_ptr=NULL;
	SessionService *ss_ptr=NULL;

	if (!sesn_ptr)
	{
		syslog (LOG_ERR, "%s (pid='%lu'): ERROR: was passed NULL Session *",
		  __func__, pthread_self());

		return 0;
	}

  ss_ptr=&(sesn_ptr->sservice);
  ubawp_ptr=(UserBackendAccessWordPress *)SESSION_SERVICE_BACKEND_ACCESS_DATA(ss_ptr);
  ubar_ptr=SESSION_SERVICE_BACKEND_ACCESS_ROUTINES(ss_ptr);

  char *auth_params;
  asprintf(&auth_params, "%lu:%lu", SESSION_ID(sesn_ptr), SESSION_ID(sesn_ptr));
  int http_response=0;

	if((http_response=SessionServicePostUrl (ss_ptr, validation_url, NULL, auth_params, NULL, 0L))==200)
	{

		const char *cookie=json_object_get_string(json__get(ubawp_ptr->jobj, "cookie"));
		if (!cookie)	goto exit_error;

		syslog (LOG_ERR, "%s (pid='%lu'): SUCCESS: USER SESSION COOKIE REGENERATED. USERID: '%lu'",
				__func__, pthread_self(), json_object_get_int64(json__get(ubawp_ptr->jobj, "userid")));


		free(auth_params);

		return 1;
	}
	else
	{
		exit_error:
		syslog (LOG_ERR, "%s (pid='%lu'): ERROR: COULD NOT AUTHENTICATE USER",	__func__, pthread_self());

		free(auth_params);
		return 0;
	}

	return 0;

}


int
BackendSignUpUser (Session *sesn_ptr)
{
	const char *backend_nonce_register_call="https://api.unfacd.io:20080/V1/Nonce";
	const char *backend_register_call="https://api.unfacd.io:20080/V1/Account/New";
	const char *backend_verify_new="https://api.unfacd.io:20080/V1/Account/VerifyNew";

	char *url_str;
	UserBackendAccessWordPress *ubawp_ptr=NULL;
	UserBackendAccessRoutines *ubar_ptr=NULL;
	SessionService *ss_ptr=NULL;
	const char *nonce, *pending_cookie, *verification_code;

	ss_ptr=&(sesn_ptr->sservice);
	ubawp_ptr=(UserBackendAccessWordPress *)SESSION_SERVICE_BACKEND_ACCESS_DATA(ss_ptr);
	ubar_ptr=SESSION_SERVICE_BACKEND_ACCESS_ROUTINES(ss_ptr);

	if (SessionServiceGetUrlJson(ss_ptr, backend_nonce_register_call)) {
		nonce=json_object_get_string(json__get(ubawp_ptr->jobj, "nonce"));
		if (!nonce) {
			syslog (LOG_ERR, "%s (pid='%lu'): ERROR: COULD NOT OBTAIN NONCE", __func__, pthread_self());

			return 0;
		}

		syslog (LOG_ERR, "%s (pid='%lu'): SUCCESS: NONCE: '%s'", __func__, pthread_self(), nonce);
	} else {
		syslog (LOG_ERR, "%s (pid='%lu'): ERROR: COULD NOT CONATCT SERVER FOR NONCE", __func__, pthread_self());

		return 0;
	}

	char *post_params=NULL;
	char *auth_params=NULL;

	asprintf(&post_params, "username=%lu&password=%lu&nonce=%s&verifysms=false", SESSION_ID(sesn_ptr), SESSION_ID(sesn_ptr), nonce);

	if(SessionServicePostUrlJson(ss_ptr, backend_register_call, post_params, NULL, NULL, 0L)) {
		pending_cookie=json_object_get_string(json__get(ubawp_ptr->jobj, "cookie"));
		verification_code=json_object_get_string(json__get(ubawp_ptr->jobj, "verification_code"));

		if (!pending_cookie || !verification_code) {
			syslog (LOG_ERR, "%s (pid='%lu'): ERROR: COULD NOT OBTAIN PENDING COOKIE OR VERIFICATION CODE",
				 __func__, pthread_self());

			free (post_params);

			return 0;
		}

		syslog (LOG_ERR, "%s (pid='%lu'): SUCCESS: VERIFICATION_CODE: '%s'", __func__, pthread_self(), verification_code);

	} else {
		syslog (LOG_ERR, "%s (pid='%lu'): ERROR: COULD NOT CONTACT SERVER FOR NEW ACCOUNT", __func__, pthread_self());

		free(post_params);

		return 0;
	}

	char *auth_params;
	asprintf(&auth_params, "%lu:%lu", SESSION_ID(sesn_ptr), SESSION_ID(sesn_ptr));

	struct json_object *jobj_account = json_object_new_object();

	json_object_object_add(jobj_account, "cookie", json_object_new_string(pending_cookie));
	json_object_object_add(jobj_account, "verificationCode", json_object_new_string(verification_code));
	json_object_object_add(jobj_account, "registrationId",  json_object_new_int64((unsigned long)sesn_ptr));
	json_object_object_add(jobj_account, "voice", json_object_new_boolean(true));

	const char *json_account_str=json_object_to_json_string(jobj_account);

	syslog (LOG_ERR, "%s (pid='%lu'): GENERATED  ACCOUNT URL: '%s'", __func__, pthread_self(), json_account_str);

	if (SessionServicePostUrlJson(ss_ptr, backend_verify_new, json_account_str, auth_params, "application/json", strlen(json_account_str))) {
		const char *signon_cookie = json_object_get_string(json__get(ubawp_ptr->jobj, "cookie"));

		if (!signon_cookie)	goto exit_error;

		strncpy(SESSION_COOKIE(sesn_ptr), signon_cookie, strlen(signon_cookie));
		SESSION_USERID(sesn_ptr)=json_object_get_int64(json__get(ubawp_ptr->jobj, "userid"));

		syslog(LOG_INFO, "%s (pid='%lu' cid='%lu'): SUCCESS: USERID: '%lu' SIGNON COOKIE: '%s'",
			 __func__, pthread_self(), SESSION_ID(sesn_ptr), SESSION_USERID(sesn_ptr), signon_cookie);
	} else {
		exit_error:
		syslog (LOG_ERR, "%s (pid='%lu'): ERROR:  COULD NOT VERIFY ACCOUNT: '%s'",
		 __func__, pthread_self(), json_account_str);

		json_object_put(jobj_account);
		free(auth_params);

		return 0;
	}

	json_object_put(jobj_account);
	free(auth_params);

	return 1;

}


int
BackendValidateUser(Session *sesn_ptr)

{
	const char *validation_url="http://api.unfacd.io:20080/V1/Account/SignOn";
	char *url_str;
	UserBackendAccessWordPress *ubawp_ptr=NULL;
	UserBackendAccessRoutines *ubar_ptr=NULL;
	SessionService *ss_ptr=NULL;

	if (!sesn_ptr)
	{
	  syslog (LOG_ERR, "%s (pid='%lu'): ERROR: was passed NULL Session *", 
			__func__, pthread_self());
	
	  return 0;
	}

	ss_ptr=&(sesn_ptr->sservice);
	ubawp_ptr=(UserBackendAccessWordPress *)SESSION_SERVICE_BACKEND_ACCESS_DATA(ss_ptr);
	ubar_ptr=SESSION_SERVICE_BACKEND_ACCESS_ROUTINES(ss_ptr);

	char *auth_params;
	char *post_params;
	int http_response=0;

	asprintf(&auth_params, "cookie=%s", SESSION_COOKIE(sesn_ptr));
	asprintf(&auth_params, "%lu:%lu", SESSION_ID(sesn_ptr), SESSION_ID(sesn_ptr));

	if((http_response=SessionServicePostUrl (ss_ptr, validation_url, post_params, auth_params, NULL, 0L))==200)
	{

		 syslog (LOG_ERR, "%s (pid='%lu'): SUCCESS: USER SESSION COOKIE VALIDATED",
			__func__, pthread_self());

		free (post_params);
		free(auth_params);

		return 1;
	}
	else
	{
		syslog (LOG_ERR, "%s (pid='%lu'): ERROR: USER SESSION COOKIE INVALID",                              __func__, pthread_self());

		free (post_params);
		free(auth_params);

		return 0;
	}

}


