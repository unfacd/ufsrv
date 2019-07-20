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
#include <utils.h>
#include <api_endpoint_v1_account.h>
#include <user_backend.h>
#include <fence_state.h>
#include <users.h>
#include <user_preferences.h>
#include <http_request_handler.h>
#include <protocol_http_io.h>
#include <h_handler.h>
#include <response.h>
#include <url.h>
#include <http_session_type.h>
#include <json/json.h>
#include <attachments.h>
#include <protocol_http_attachments.h>
#include <protocol_http.h>
#include <protocol_http_user.h>
#include <ufsrvuid.h>
#include <dictionary.h>
#include <users_proto.h>

extern __thread ThreadContext ufsrv_thread_context;

static const char *err="Server unable to complete request.";

//#define API_ENDPOINT_V1(x) int x (Session *sesn_ptr, void *p, onion_request *req, onion_response *res)

/**
 * @brief:	Main endpoint for signing on users. When cookie is present, cookie is validated. If validated, internal userid is returned, which uniform across all devices.
 * @http_verb: POST
 * @http_auth: Basic Authorization
 * @http_param cookie: if sent, cookie is validated for the given user
 * @http_param _NONE: new signon cookie returned
 * @http_return_code: 200, 409
 */
API_ENDPOINT_V1(ACCOUNT_SIGNON)
{
	HttpSession *http_ptr;
	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);

	const char *cookie=onion_request_get_post(HTTPSESN_REQUEST_PTR(http_ptr), "cookie");
	if (IS_STR_LOADED(cookie) && (strlen(cookie)<MBUF)) {
		AuthenticatedAccount authacct = {0};

		UFSRVResult *res_ptr=DbValidateUserSignOnWithCookie(sesn_ptr, cookie, &authacct, NULL);
		if (_RESULT_TYPE_SUCCESS(res_ptr)) {
			json_generation_block:
			{
				struct json_object *jobj_auth=json_object_new_object();

				json_object_object_add (jobj_auth,"userid", json_object_new_int(authacct.userid));
				const char *json_str_reply=json_object_to_json_string(jobj_auth);

				onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(json_str_reply));
				onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),json_str_reply, strlen(json_str_reply));

				json_object_put(jobj_auth);
				if (IS_PRESENT(authacct.username))	free (authacct.username);
				if (IS_PRESENT(authacct.nickname))	free (authacct.nickname);

				goto request_processed;
			}//end json block
		} else {
			//cookie invalid or some other error
			goto request_error;
		}
	} else {
		//sign on
		AuthenticatedAccount *authacct_ptr=NULL;
		UFSRVResult *res_ptr = DbAuthenticateUser (sesn_ptr, UfsrvUidGetSequenceId(&(SESSION_UFSRVUIDSTORE(sesn_ptr))), SESSION_USERPASSWORD(sesn_ptr), NULL, CALL_FLAG_USER_AUTHENTICATED|CALL_FLAG_USER_SIGNON);

		if (_RESULT_TYPE_SUCCESS(res_ptr) && _RESULT_CODE_EQUAL(res_ptr, RESULT_CODE_USER_SIGNON)) {
			authacct_ptr=(AuthenticatedAccount *)_RESULT_USERDATA(res_ptr);

      struct json_object *jobj_auth=json_object_new_object();

      json_object_object_add (jobj_auth, "userid", json_object_new_int(authacct_ptr->userid));
      json_object_object_add (jobj_auth, ACCOUNT_JSONATTR_COOKIE, json_object_new_string(authacct_ptr->cookie));
      char ufsrvuid_encoded[CONFIG_MAX_UFSRV_ID_ENCODED_SZ+1] = {0};
      UfsrvUidConvertToString (&(authacct_ptr->ufsrvuid), ufsrvuid_encoded);
      json_object_object_add (jobj_auth, ACCOUNT_JSONATTR_UFSRVUID, json_object_new_string(ufsrvuid_encoded));
      json_object_object_add (jobj_auth, ACCOUNT_JSONATTR_USERNAME, json_object_new_string(authacct_ptr->username));
      const char *json_str_reply=json_object_to_json_string(jobj_auth);

      onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(json_str_reply));
      onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),json_str_reply, strlen(json_str_reply));

      json_object_put(jobj_auth);
      free (authacct_ptr->cookie);
      free (authacct_ptr->e164number);
      if (IS_PRESENT(authacct_ptr->e164number)) free (authacct_ptr->e164number);
      if (IS_PRESENT(authacct_ptr->username)) free (authacct_ptr->username);
      free(authacct_ptr);

      goto request_processed;
		}
	}

  request_error:
  onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
  onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));

	request_processed:
	return OCS_PROCESSED;

}

/**	TODO: THIS IS CURRENTLY BROKEN BECAUSE PENDING COOKIE IS NOT PROVIDED, so DbGetPendingAccountVerificationCode will fail
 * 	@brief: This is the endpoint to initiate a account verification by voice.
 * 	@http_verb: GET
 * 	@path_args: the nonce/cookie used to setup the account (not implemented properly)
 *
 * 	curl -Ss -XGET -u '+614x:u+VziKT4fqxA' https://api.unfacd.io:20080/V1/Account/VerifyNew/Voice/1234
 */
API_ENDPOINT_V1(ACCOUNT_VERIFYNEW_VOICE)
{
#define _THIS_PATH_VOICE	"/V1/Account/VerifyNew/Voice/"

	HttpSession *http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);

	size_t 			pathprefix_len=sizeof( _THIS_PATH_VOICE)-1;
	const char	*nonce=NULL;
	const char 	*full_path=onion_request_get_fullpath(HTTPSESN_REQUEST_PTR(http_ptr));

	if (strlen(full_path)<pathprefix_len)	goto return_post_error;

	if (strlen(full_path)> pathprefix_len+2) {// angling for '/' plus at least 5 additional digits
		nonce=full_path+pathprefix_len;//skip the '/' since we did not include in the consta string above

		PendingAccount pending_account 	=	{.username=SESSION_USERNAME(sesn_ptr)};
		DbGetPendingAccountVerificationCode (sesn_ptr, &pending_account);
		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
			SendVerificationVoice (sesn_ptr, SESSION_USERNAME(sesn_ptr), &((VerificationCode){pending_account.verification_code.code, {0}}));

#ifdef __UF_TESTING
			struct json_object *jobj_in=json_object_new_object();

			json_object_object_add (jobj_in,"nonce", json_object_new_string(nonce));
			json_object_object_add (jobj_in,"destination", json_object_new_string( SESSION_USERNAME(sesn_ptr)));
			json_object_object_add (jobj_in,"verification_code", json_object_new_int64(pending_account.verification_code.code));
			const char *json_str_reply=json_object_to_json_string(jobj_in);

			onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(json_str_reply));
			onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),json_str_reply, strlen(json_str_reply));

			json_object_put(jobj_in);
			return OCS_PROCESSED;
#endif

			return OCS_PROCESSED;
		}
	}

	return_post_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
	return OCS_PROCESSED;

#undef _THIS_PATH_VOICE
}

static char *_FormatVerificationCodeForTwiml (const char *verification_code, char *formatted_out);

/**
 * 	@param formatted_out: Allocate 12 bytes, including the null: '1 2 3 4 5 6\0'
 */
__pure static char *
_FormatVerificationCodeForTwiml (const char *verification_code, char *formatted_out)
{
	memset (formatted_out, ' ', 11);

	formatted_out[0]=verification_code[0];
	formatted_out[2]=verification_code[1];
	formatted_out[4]=verification_code[2];
	formatted_out[6]=verification_code[3];
	formatted_out[8]=verification_code[4];
	formatted_out[10]=verification_code[5];
	formatted_out[11]='\0';

	return formatted_out;

}

/**
	 curl -Ss -XPOST  https://api.unfacd.io:20080/V1/Account/VerifyNew/Voice/Script/123456
	 verification code has to be exactly 6 digits

	 To test:
	 1)Ensure a pending_accounts row is created, corresponding with the username. Assuming: +61xxxxx
	 1.1)from pure testing perspective the password is irrelvant. The nonce/cookie value 1234' is not currently considered
	 2)Issue: curl -Ss -XGET -u '+61:ttBVLuQRpEc4cr' https://api.unfacd.io:20080/V1/Account/VerifyNew/Voice/1234

	 POST data from the provider:
	 Called=%2B6141&ToState=&CallerCountry=AU&Direction=outbound-api&CallerState=&ToZip=&CallSid=CA2eccfa8d83bf6e74f6&To=%2B6141&CallerZip=&ToCountry=AU&ApiVersion=2010-04-01&CalledZip=&CalledCity=&CallStatus=in-progress&From=%2B6141&AccountSid=ACddcb4&CalledCountry=AU&CallerCity=&Caller=%2B61428260161&FromCountry=AU&ToCity=&FromCity=&CalledState=&FromZip=&FromState=
 */
API_ENDPOINT_V1(ACCOUNT_VERIFYNEW_VOICESCRIPT)
{
#define _THIS_PATH_VOICESCRIPT	"/V1/Account/VerifyNew/Voice/Script/"
#define SAY_TWIML  "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"\
  "<Response>"\
  "    <Say voice=\"alice\" language=\"en-AU\" loop=\"4\"> Your verification code is: %s</Say>"\
  "</Response>"

	HttpSession *http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);

	size_t 			pathprefix_len=sizeof( _THIS_PATH_VOICESCRIPT)-1;
	const char	*verification_code=NULL;
	const char 	*full_path=onion_request_get_fullpath(HTTPSESN_REQUEST_PTR(http_ptr));

	if (strlen(full_path)<pathprefix_len)	goto return_post_error;

	if (strlen(full_path)==pathprefix_len+(_VERIFICATION_CODE_SZ-1))// angling for '/' plus at least 6 additional digits
	{
		verification_code=full_path+pathprefix_len;//skip the '/' since we did not include in the consta string above
	}

	int flags=onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));
	if ((flags&OR_METHODS)==OR_POST)
	{
		if (IS_EMPTY(verification_code) || strlen(verification_code)>_VERIFICATION_CODE_SZ)
		{
			goto return_post_error;
		}
		else
		{
			char processed_twiml[sizeof(SAY_TWIML)+(_VERIFICATION_CODE_SZ*2)]={0};
			char formatted_out[_VERIFICATION_CODE_SZ*2]={0};

			size_t processed_twiml_sz=snprintf(processed_twiml, (sizeof(SAY_TWIML)+(_VERIFICATION_CODE_SZ*2)), SAY_TWIML, _FormatVerificationCodeForTwiml (verification_code, formatted_out));

#ifdef __UF_TESTING
			syslog(LOG_NOTICE, "%s {pid:'%lu', o:'%p', cid:'%lu'}: Final TWIML:'%s'", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), processed_twiml);
#endif

			onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), processed_twiml_sz);
			onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), processed_twiml, processed_twiml_sz);
			return OCS_PROCESSED;
		}
	}

	return_post_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
	return OCS_PROCESSED;

#undef _THIS_PATH_VOICESCRIPT
}

API_ENDPOINT_V1(ACCOUNT_NONCE)
{
	HttpSession *http_ptr;
	struct json_object *jobj_in=NULL;

	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);

	char *nonce=BackEndGenerateNonce (sesn_ptr, _ACCOUNT_NONCE_TTL/*seconds*/, _ACCOUNT_NONCE_PREFIX, NULL);
	if (nonce) {
		jobj_in=json_object_new_object();

		json_object_object_add (jobj_in,_NONCE_NAME, json_object_new_string(nonce));
		const char *json_str_reply=json_object_to_json_string(jobj_in);

		onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(json_str_reply));
		onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),json_str_reply, strlen(json_str_reply));

		json_object_put(jobj_in);
		free (nonce);
	} else {
		onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
		//onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), 11);
		onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));
	}

    return OCS_PROCESSED;
}

API_ENDPOINT_V1(NONCE)
{
	HttpSession *http_ptr;
	struct json_object *jobj_in=NULL;

	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);

	char *nonce=BackEndGenerateNonce (sesn_ptr, _OPEN_NONCE_TTL/*seconds*/,  _OPEN_NONCE_PREFIX, NULL);
	if (nonce) {
		jobj_in=json_object_new_object();

		json_object_object_add (jobj_in,_NONCE_NAME, json_object_new_string(nonce));
		const char *json_str_reply=json_object_to_json_string(jobj_in);

		onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(json_str_reply));
		onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),json_str_reply, strlen(json_str_reply));

		json_object_put(jobj_in);
		free (nonce);
	} else {
		onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
		//onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), 11);
		onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));
	}

    return OCS_PROCESSED;
}

/**
 * V1/Account/New
 */
API_ENDPOINT_V1(ACCOUNT_CREATENEW)
{
	const char *username;
	const char *e164number;
	const char *password;
	const char *nonce;
  const char *android_sms_retriever;
	bool verify_sms=false;

	//post data
	HttpSession *http_ptr;

	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);

	if (HTTPSESN_JSONDATA(((HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr)))) {
		struct json_object *jobj=HTTPSESN_JSONDATA(((HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr)));

		nonce=json_object_get_string(json__get(jobj, ACCOUNT_JSONATTR_NONCE));
		username=json_object_get_string(json__get(jobj, ACCOUNT_JSONATTR_USERNAME));
		e164number=json_object_get_string(json__get(jobj, ACCOUNT_JSONATTR_E164NUMBER));
		password=json_object_get_string(json__get(jobj, ACCOUNT_JSONATTR_PASSWORD));
    android_sms_retriever=json_object_get_string(json__get(jobj, "androidSmsRetriever"));

#ifdef __UF_TESTING
		//verify_sms=json_object_get_boolean(json__get(jobj, "verifysms"));
#endif
	} else {
		syslog(LOG_NOTICE, "%s (pid:'%lu' o:'%p' cid:'%lu'): JSON DATA WAS MISSING, TRYING POST FORM DATA...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

		username=onion_request_get_post(HTTPSESN_REQUEST_PTR(http_ptr), ACCOUNT_JSONATTR_USERNAME);
		e164number=onion_request_get_post(HTTPSESN_REQUEST_PTR(http_ptr), ACCOUNT_JSONATTR_E164NUMBER);
		password=onion_request_get_post(HTTPSESN_REQUEST_PTR(http_ptr), ACCOUNT_JSONATTR_PASSWORD);
		nonce=onion_request_get_post(HTTPSESN_REQUEST_PTR(http_ptr), ACCOUNT_JSONATTR_NONCE);
		android_sms_retriever = onion_request_get_post(HTTPSESN_REQUEST_PTR(http_ptr), "androidSmsRetriever");
#ifdef __UF_TESTING
		const char *verify_sms_str=onion_request_get_post(HTTPSESN_REQUEST_PTR(http_ptr), "verifysms");
		if (verify_sms_str) {
			if (strcasecmp(verify_sms_str, "false")==0)	verify_sms=false;
		}

		if (strncmp(username, TESTUSER_NAME, 12)==0) verify_sms=false;//additional testing aid
#endif
	}

	if (!username || !password || !nonce) {
		goto request_error;
	}

  if (strlen(username) > CONFIG_EMAIL_ADDRESS_SZ_MAX) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', email_sz:'%lu'}: ERROR: EMAIL ADDRESS PROVIDED TOO LONG", __func__, pthread_self(), sesn_ptr, strlen(username));
    goto request_error;
  }

  if (!IsEmailAddressValid(username)) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: INVALID EMAIL ADDRESS PROVIDED: '%s'", __func__, pthread_self(), sesn_ptr, username);
    goto request_error;
  }

  if (strlen(password) < 2||strlen(password) > MBUF)	goto request_error;

	PendingAccount *pacct_ptr=DbCreateNewAccount (sesn_ptr,  username, e164number, password, nonce);
	if (IS_PRESENT(pacct_ptr)) {
    if (verify_sms) {
#ifdef	__UF_TESTING
      //TODO: SMS REGISTRATION DISABLED FOR BETA TESTING
//	if ((strcasecmp(username, "+61412345678")==0)||(strcasecmp(username, "+61000000000")==0))
//	{
//		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: DETECTED REGISTRATION FOR TEST ACCOUNT...", __func__, pthread_self(), sesn_ptr);
//
//		goto exit_success;
//	}
#endif

      bool android_sms_retriever_flag=(strcmp(android_sms_retriever, "android-ng")==0);
      if (!(SendVerificationSms (sesn_ptr, pacct_ptr->username, &(pacct_ptr->verification_code), android_sms_retriever_flag)==0)) { //check for "android-ng" in android_sms_retriever for android specific sms payload
        PendingAccountMemDestruct (pacct_ptr, 1);//self-destruct flag
        goto request_error;
      }
    } else { //temporary conditional to force email verification. TODO: clean up verification logic
			if (!(SendVerificationEmail (sesn_ptr, pacct_ptr->username, pacct_ptr)==0)) {
				PendingAccountMemDestruct (pacct_ptr, 1);//self-destruct flag
				goto request_error;
			}
    }

		struct json_object *jobj_in=json_object_new_object();

		json_object_object_add (jobj_in, ACCOUNT_JSONATTR_COOKIE, json_object_new_string(pacct_ptr->cookie));
		//json_object_object_add (jobj_in,"verification_code", json_object_new_int(pacct_ptr->verification_code.code)); //no need to send at this stage
		const char *json_str_reply=json_object_to_json_string(jobj_in);

		onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(json_str_reply));
		onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),json_str_reply, strlen(json_str_reply));

		json_object_put(jobj_in);
		PendingAccountMemDestruct (pacct_ptr, 1);
	} else {
		goto request_error;
	}

	return OCS_PROCESSED;

  request_error:
  onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
  onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));
	return OCS_PROCESSED;

}

/**
 * @brief: Primarily used to work with email based verification, as opposed to sms. Does not use BasicAuth.
 * @http_verb GET:check if account is still in a verified state. Cookie is required to service request.
 * @http_verb GET: this allows the user to verify a given registration code, but otherwise doesn't change the state of
 * the backend except for marking the pending account rego status. To complete registration a separate /V1/AccountVerifyNew is required
 * @param sesn_ptr
 * @return 200OK if account is in unverified state
 */
API_ENDPOINT_V1(ACCOUNT_VERIFYSTATUS)
{
	HttpSession 		*http_ptr;

	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);
#define _THIS_PATH	"/V1/Account/VerifyStatus"

	size_t pathprefix_len=strlen( _THIS_PATH);
	char *full_path=(char *)onion_request_get_fullpath(HTTPSESN_REQUEST_PTR(http_ptr));
	int flags=onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));

	if (strlen(full_path)<pathprefix_len)	goto return_error;

	///V1/Account/VerifyStatus/xxxxxxx
	char *cookie;

	cookie=full_path+pathprefix_len+1; //1 for '/'

	if ((flags&OR_METHODS)==OR_GET) {
		const char *verification_code_provided = cookie+CONFIG_MAX_COOKIE_SZ; //points at '\0' or '/'
		if (*verification_code_provided=='\0') {
			if (strlen(full_path)!=pathprefix_len+CONFIG_MAX_COOKIE_SZ+1) {//max size plus 1 for  '/'
				goto return_error;
			}

			PendingAccount pending_account = {0};
			pending_account.cookie = cookie;
			switch (GetAccountVerificationStatus(sesn_ptr, &pending_account)) {
				case REGOSTATUS_VERIFIED: {
					struct json_object *jobj_in=json_object_new_object();

					json_object_object_add (jobj_in, "verification_code", json_object_new_int(pending_account.verification_code.code));
					const char *json_str_reply=json_object_to_json_string(jobj_in);

					onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(json_str_reply));
					onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),json_str_reply, strlen(json_str_reply));

					json_object_put(jobj_in);
					goto return_processed;
				}
				default:
					goto return_error;
			}
		} else {
			if (strlen(full_path)!=pathprefix_len+CONFIG_MAX_COOKIE_SZ+CONFIG_MAX_VERIFICATION_CODE_SZ+2) {//max size plus 2 for  '/'
				goto return_error;
			}

			if (strlen(verification_code_provided) == CONFIG_MAX_VERIFICATION_CODE_SZ + 1) {//plus 1 for leading '/' in '/xxxxxx'
				*(cookie + CONFIG_MAX_COOKIE_SZ) = '\0'; //'/' gone
				verification_code_provided++; //repoint at begining of code

				PendingAccount pending_account = {0};
				pending_account.cookie = cookie;

				if (PendingAccountVerify(sesn_ptr, &pending_account, atoi(verification_code_provided), 0)) {
					goto return_processed;
				}
			}
		}
	} else if ((flags&OR_METHODS)==OR_POST) {
		goto return_unsupport_op;
	} else {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', request_flags:'%d'}: ERROR: UNSUPPORTED HTTP REQUEST TYPE...", __func__, pthread_self(), sesn_ptr, flags);
		goto return_unsupport_op;
	}

	return_unsupport_op:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 405);
	goto write_error_msg;

	return_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
	goto write_error_msg;

	write_error_msg:
	onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));
	goto return_processed;

	return_processed:
	return OCS_PROCESSED;

#undef _THIS_PATH
}

//int verification_code=DbGetPendingAccountVerificationCode (sesn_ptr);
//'{"registrationId":11515,"signalingKey":"h00MCTHA==","verificationCode":"579323", "cookie":"xxxxx", "voice":true, nickname:"mm"}' id: '145069'
/**
 * 	@brief: Verify the validity of pending new account
 * 	@http_verb: POST
 * 	@http_auth:	Basic Authorization. But since this concerns a pending account no actual Authentication is perform, but username:passwd are
 * 	user to setup proper salted password hash
 */
API_ENDPOINT_V1(ACCOUNT_VERIFYNEW)
{
	HttpSession *http_ptr;

	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);

	if (!HTTPSESN_JSONDATA(((HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr)))) {
		syslog(LOG_NOTICE, "%s (pid:'%lu' o:'%p' cid:'%lu'): JSON DATA IS MISSING...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

		goto request_error;
	}

	struct json_object *jobj_by_user=HTTPSESN_JSONDATA(((HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr)));

	PendingAccount pending_account={0};

	const char *pending_cookie=json_object_get_string(json__get(jobj_by_user, ACCOUNT_JSONATTR_COOKIE));//pending account cookie
	if (!IS_STR_LOADED(pending_cookie)) {
		goto request_error;
	}

	const char *e164number = json_object_get_string(json__get(jobj_by_user, ACCOUNT_JSONATTR_E164NUMBER));

	pending_account.cookie=strdupa(pending_cookie);
	if (IS_STR_LOADED(e164number))	pending_account.e164number = strdupa(e164number);

	pending_account.username=SESSION_USERNAME(sesn_ptr);//fetched from basic auth header. At this stage corresponds with email
	pending_account.password=SESSION_USERPASSWORD(sesn_ptr);//fetched from basic auth header

	if (PendingAccountVerify(sesn_ptr, &pending_account, json_object_get_int(json__get(jobj_by_user, "verificationCode")), 1)) {
		UFSRVResult *res_ptr=UpgradePendingAccountByJson(sesn_ptr, &pending_account, jobj_by_user, false);
		if ((_RESULT_TYPE_SUCCESS(res_ptr)) && (_RESULT_CODE_EQUAL(res_ptr, RESULT_CODE_USER_SIGNON))) {
			AuthenticatedAccount *authacct_ptr=((AuthenticatedAccount *)_RESULT_USERDATA(res_ptr));

			UfsrvUidCopy (&(authacct_ptr->ufsrvuid), &SESSION_UFSRVUIDSTORE(sesn_ptr)); //necessary as some queries below depend on uid being known

#ifdef __UF_TESTING
			syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p' userid:'%lu'): SUCCESS: USER AUTHENTICATED AND SIGNED ON WITH NEW COOKIE: '%s'", __func__, pthread_self(), sesn_ptr, authacct_ptr->userid, authacct_ptr->cookie);
#endif
			char *profile_key_processed;
			const char *profile_key_encoded = json_object_get_string(json__get(jobj_by_user, ACCOUNT_JSONATTR_PROFILE_KEY));
			if (IS_STR_LOADED(profile_key_encoded)) {
				DbBackendSetProfileKeyIfNecessary(sesn_ptr, profile_key_encoded, false);
				profile_key_processed = (char *)SESSION_RESULT_USERDATA(sesn_ptr);
			}

			char *access_token_processed;
			const char *access_token_encoded = json_object_get_string(json__get(jobj_by_user, "unidentifiedAccessKey"));
			if (IS_STR_LOADED(access_token_encoded)) {
				DbBackendSetAccessTokenIfNecessary(sesn_ptr, access_token_encoded, false);
				access_token_processed = (char *)SESSION_RESULT_USERDATA(sesn_ptr);
			}

			struct json_object *jobj_auth=json_object_new_object();
			char ufsrvuid_encoded[CONFIG_MAX_UFSRV_ID_ENCODED_SZ+1] = {0};
			UfsrvUidConvertToString (&(authacct_ptr->ufsrvuid), ufsrvuid_encoded);

			json_object_object_add (jobj_auth, ACCOUNT_JSONATTR_COOKIE, json_object_new_string(authacct_ptr->cookie));
      free(authacct_ptr->cookie);
			json_object_object_add (jobj_auth, ACCOUNT_JSONATTR_USERNAME, json_object_new_string(authacct_ptr->username));
			free(authacct_ptr->username);
			json_object_object_add (jobj_auth, ACCOUNT_JSONATTR_USERID, json_object_new_int(authacct_ptr->userid));
			json_object_object_add (jobj_auth, ACCOUNT_JSONATTR_UFSRVUID, json_object_new_string(ufsrvuid_encoded));
			if (IS_STR_LOADED(profile_key_processed)){ //this could be a previously stored value for returning installations
				json_object_object_add (jobj_auth, ACCOUNT_JSONATTR_PROFILE_KEY, json_object_new_string(profile_key_processed));
				free (profile_key_processed);
			}
			if (IS_STR_LOADED(access_token_processed)){ //this could be a previously stored value for returning installations
				json_object_object_add (jobj_auth, ACCOUNT_JSONATTR_ACCESS_TOKEN, json_object_new_string(access_token_processed));
				free (access_token_processed);
			}
      if	(IS_STR_LOADED(authacct_ptr->e164number)) {
        json_object_object_add (jobj_auth, ACCOUNT_JSONATTR_E164NUMBER, json_object_new_string(authacct_ptr->e164number));
        free(authacct_ptr->e164number);
      }
			const char *json_str_reply=json_object_to_json_string(jobj_auth);

			onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(json_str_reply));
			onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),json_str_reply, strlen(json_str_reply));

			json_object_put(jobj_auth);

			free(authacct_ptr);

			goto request_processed;
		} else {
			///error
			syslog(LOG_DEBUG, "%s (pid:'%lu' o:'%p'): ERROR: UNEXPECTED RETURN TYPE...", __func__, pthread_self(), sesn_ptr);

			goto request_error;
		}
	} else {
		goto request_error;
	}

	request_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
	onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));

	request_processed:
	return OCS_PROCESSED;

}

/**
 * Post the account keys records for the user
 identityKey":"BVtqnUDDutbzzz0KVEqgmyJ7hiin3joVhOIoi5Y4kWEB",
 "preKeys":[{"keyId":647918,"publicKey":"BVo3cFV1eb95XvAbC8sS25snmUwc/zs4utWa6vhaR5J7"}],
  "signedPreKey":{"keyId":16322360,"publicKey":"BUnv...y","signature":"8Y..naBA"}
 */
API_ENDPOINT_V1(ACCOUNT_KEYS)
{
	HttpSession *http_ptr;

	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);

	if (HTTPSESN_JSONDATA(((HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr)))) {
		int rescode;
		int flags=onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));
		//if ((flags&OR_METHODS)==OR_POST)

		struct json_object *jobj_keys=HTTPSESN_JSONDATA(((HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr)));
		json_object_get	(jobj_keys);//retain ownership by increasing refcount
		rescode=SetUserKeys(sesn_ptr, &(SESSION_UFSRVUIDSTORE(sesn_ptr)), jobj_keys, DEFAULT_DEVICE_ID);
		json_object_put(jobj_keys);

		if ((json_object_put(jobj_keys))!=1) {
			syslog(LOG_DEBUG, "%s (pid:'%lu' cid:'%lu'): ERROR: MEMORY LEAK JSON WAS NOT FREED", __func__, pthread_self(), SESSION_ID(sesn_ptr));
		}

		//we already took care of terminating the jobj
		HTTPSESN_JSONDATA(((HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr)))	=	NULL;

		if (rescode!=0)	goto request_error;//!(SetUserKeys(sesn_ptr, jobj_keys, 1)==0))
	} else {
		syslog(LOG_NOTICE, "%s {pid:'%lu', o:'%p', cid:'%lu'}: JSON DATA WAS MISSING...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

		request_error:
			onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
			onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));
	}


	return OCS_PROCESSED;

}

/**
 * @brief: this is the signed preKey, saved into Account against a device id
 * {"keyId":16322360,"publicKey":"BUnv...y","signature":"8Y..naBA"}
 */
API_ENDPOINT_V1(ACCOUNT_KEYS_SIGNED)
{
	const char *username;
	const char *password;
	//post data
	HttpSession *http_ptr;

	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);

	int flags=onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));


	if ((flags&OR_METHODS)==OR_POST)
	{
		struct json_object *jobj_signed_key=HTTPSESN_JSONDATA(((HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr)));
		if(unlikely(jobj_signed_key==NULL))
		{
			syslog(LOG_DEBUG, LOGSTR_NULL_PARAM, __func__, pthread_self(), LOGCODE_PROTO_MISSING_PARAM, "json_object *");

			goto request_error;
		}

		//TODO: this conversion is double handling as the string is save as json "blob" inside the db
		const char *json_str_prekey=json_object_to_json_string(jobj_signed_key);
		if (json_str_prekey==NULL)	goto request_error;

#ifdef __UF_FULLDEBUG
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', cid:'%lu'}: JSON DATA: '%s' ", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), json_str_prekey);
#endif

		json_object_get	(jobj_signed_key);//retain object ownership by increasing refcount
		UFSRVResult *res_ptr=DbAccountSignedPreKeySet (sesn_ptr, &(SESSION_UFSRVUIDSTORE(sesn_ptr)), -1, jobj_signed_key);//json_str_prekey);
		if ((json_object_put(jobj_signed_key))!=1) {
			syslog(LOG_DEBUG, "%s (pid:'%lu' cid='%lu'): ERROR: MEMORY LEAK JSON WASNOT FREEd", __func__, pthread_self(), SESSION_ID(sesn_ptr));
		}

		//this gets killed regardless of success status. so as to prevent the handler from issuing a put on jobj.
		HTTPSESN_JSONDATA(((HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr)))	=	NULL;

		if (_RESULT_TYPE_SUCCESS(res_ptr)) {
			return OCS_PROCESSED;
		}
	} else if ((flags&OR_METHODS)==OR_GET) {
		UFSRVResult *res_ptr=DbAccountSignedPreKeyGet (sesn_ptr, &(SESSION_UFSRVUIDSTORE(sesn_ptr)), -1);
		if (_RESULT_TYPE_SUCCESS(res_ptr)) {
			size_t res_len=strlen((char *)_RESULT_USERDATA(res_ptr));
			onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), res_len);
			onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), (char *)_RESULT_USERDATA(res_ptr), res_len);

			free (_RESULT_USERDATA(res_ptr));

			return OCS_PROCESSED;
		}
	} else if ((flags&OR_METHODS)==OR_DELETE) {
		//not implemented
	}

	request_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
	onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));

	return OCS_PROCESSED;

}

/**
 * @brief: Return prekeys status. Only status returned at the moment count of useable prekeys
 */
API_ENDPOINT_V1(ACCOUNT_KEYS_STATUS)
{
	HttpSession *http_ptr;

	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);

	int flags=onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));

	if ((flags&OR_METHODS)==OR_GET) {
    char ufsrvuid_encoded[CONFIG_MAX_UFSRV_ID_ENCODED_SZ+1] = {0};
    UfsrvUidConvertToString (&SESSION_UFSRVUIDSTORE(sesn_ptr), ufsrvuid_encoded);
		UFSRVResult *res_ptr=DbAccountGetKeysCountForDevice (sesn_ptr, ufsrvuid_encoded, DEFAULT_DEVICE_ID);
		if (_RESULT_TYPE_SUCCESS(res_ptr)) {
			//note cast of (uintptr_t) is necessary to silence 'cast from pointer to integer of different size' warining
			int keys_count=((uintptr_t)_RESULT_USERDATA(res_ptr));

			struct json_object *jobj_in=json_object_new_object();

			json_object_object_add (jobj_in,"count", json_object_new_int(keys_count));
			const char *json_str_reply=json_object_to_json_string(jobj_in);

			onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(json_str_reply));
			onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),json_str_reply, strlen(json_str_reply));

			json_object_put(jobj_in);

			return OCS_PROCESSED;
		}
	}

	request_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
	onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));

	return OCS_PROCESSED;

}

/**
 * 	@brief: Get the firstavailable prekey for a device.
 * 	@http_methods: GET
 * 	@url_args:	/<number>/
 * 	@url_args:	/<number>/<device_id>
 * 	@url_args:	/<number>/*
 * 	@return: json
 */
API_ENDPOINT_V1(ACCOUNT_KEYS_PREKEYS)
{
	HttpSession *http_ptr;

	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);

	int flags=onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));
	#define _THIS_PATH_PREKEY	"/V1/Registry/Keys/PreKeys"

	const char *ufsrvuid=NULL;
	size_t pathprefix_len=strlen( _THIS_PATH_PREKEY);
	const char *full_path=onion_request_get_fullpath(HTTPSESN_REQUEST_PTR(http_ptr));

	if (strlen(full_path)<=pathprefix_len)	goto request_error;

	ufsrvuid=full_path+pathprefix_len;
	if (unlikely(*ufsrvuid=='\0')) {
		goto request_error;
	}

	char *device_id_str;
	if ((device_id_str=strchr(ufsrvuid, '/'))) {
		*device_id_str='\0';
		device_id_str++;
		if (*device_id_str=='\0')	goto request_error;
	}

	int device_id=0;

	if (device_id_str && *device_id_str=='*')	device_id=0;
	else {
		device_id=strtol(device_id_str, NULL, 10);
		if (device_id==0)	goto request_error;
	}

	syslog(LOG_DEBUG, ">> FOUND USER ARGS: ufsrvuid: '%s', device_id:'%s'", ufsrvuid, device_id_str?device_id_str:"undefined");

	if ((flags&OR_METHODS)==OR_GET) {
		UFSRVResult *res_ptr=DbAccountGetFirstAvailableKeyByDevice (sesn_ptr, ufsrvuid, DEFAULT_DEVICE_ID);
		if (_RESULT_TYPE_SUCCESS(res_ptr)) {
			struct json_object *jobj_signed_prekey=NULL;

			AccountKeyRecord *account_key_ptr=((AccountKeyRecord *)_RESULT_USERDATA(res_ptr));

			UfsrvUid uid={0};
      UfsrvUidCreateFromEncodedText(ufsrvuid, &uid);

			jobj_signed_prekey=AccountSignedPreKeyGetInJson(sesn_ptr, &uid, DEFAULT_DEVICE_ID);
			if (jobj_signed_prekey==NULL) {
				AccountKeyRecordDestruct(account_key_ptr, true);
				goto request_error;
			}

			struct json_object *jobj_prekey=json_object_new_object();

			json_object_object_add (jobj_prekey, "publicKey", json_object_new_string(account_key_ptr->public_key));
			json_object_object_add (jobj_prekey, "keyId", json_object_new_int(account_key_ptr->key_id));

			struct json_object *jobj_final_key_response=json_object_new_object();
			json_object_object_add (jobj_final_key_response, "registrationId", json_object_new_int(account_key_ptr->rego_id));
			json_object_object_add (jobj_final_key_response, "deviceId", json_object_new_int(account_key_ptr->device_id));
			json_object_object_add(jobj_final_key_response, "preKey", jobj_prekey);
			json_object_object_add(jobj_final_key_response, "signedPreKey", jobj_signed_prekey);

			struct json_object *jarray=json_object_new_array();
			json_object_array_add(jarray, jobj_final_key_response);
			struct json_object *jobj_devices=json_object_new_object();
			json_object_object_add(jobj_devices,"devices", jarray);

			res_ptr=DbAccountIdentityKeyGet (sesn_ptr, &uid, 0);
			if (_RESULT_TYPE_SUCCESS(res_ptr)) {
				json_object_object_add(jobj_devices,"identityKey", json_object_new_string(((char *)_RESULT_USERDATA(res_ptr))));
			} else {
				//TODO: bail out
			}

			const char *jobj_str=json_object_to_json_string(jobj_devices);

			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', json:'%s'}: Final json string representation...", __func__, pthread_self(), sesn_ptr, jobj_str);

			onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(jobj_str));
			onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),jobj_str, strlen(jobj_str));

			memory_cleanup:
			json_object_put(jobj_devices);
			AccountKeyRecordDestruct(account_key_ptr, true);

			return OCS_PROCESSED;
		}
	}

	request_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
	onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));

	return OCS_PROCESSED;
	#undef _THIS_PATH_PREKEY

}

/**
 * public class DeviceInfo {

  @JsonProperty
  private long id;

  @JsonProperty
  private String name;

  @JsonProperty
  private long created;

  @JsonProperty
  private long lastSeen;
 */
API_ENDPOINT_V1(ACCOUNT_DEVICES)
{
	HttpSession *http_ptr;
	struct json_object *jobj_msg=NULL;
	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);
	#define _THIS_PATH_DEVICES	"/V1/Account/Devices/"

	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);

	const char *destination_device;
	size_t pathprefix_len=strlen( _THIS_PATH_DEVICES);
	const char *full_path=onion_request_get_fullpath(HTTPSESN_REQUEST_PTR(http_ptr));

	if (strlen(full_path)<=pathprefix_len)	goto request_error;

	destination_device=full_path+pathprefix_len;
	if (unlikely(*destination_device=='\0'))	goto request_error;

	int device_id=atoi(destination_device);
	if (unlikely(strlen(destination_device)>CONFIG_E164_NUMBER_SZ_MAX))	goto request_error;

	//TODO: increase device_id limit when ready
	if (unlikely(device_id>1))	goto request_error;

	syslog(LOG_DEBUG, ">> FOUND DESTINATION DEVICE: '%d'", device_id);

	int flags=onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));

	if ((flags&OR_METHODS)==OR_GET)
	{
		//process DeviceRecord struct
		return OCS_PROCESSED;
	}
	else
	if ((flags&OR_METHODS)==OR_DELETE)
	{
		return OCS_PROCESSED;
	}

	request_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
	onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));

	request_processed:
	return OCS_PROCESSED;

#undef _THIS_PATH_DEVICES

}

/**
 *gcmRegistrationId
 */
API_ENDPOINT_V1(ACCOUNT_GCM)
{
	const char *username;
	const char *password;
	//post data
	HttpSession *http_ptr;

	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);
	int flags=onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));

	if ((flags&OR_METHODS)==OR_POST) {
		if (HTTPSESN_JSONDATA(((HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr)))) {

			struct json_object *jobj=HTTPSESN_JSONDATA(((HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr)));
			const char *gcm_id=json_object_get_string(json__get(jobj, "gcmRegistrationId"));
			if (!IS_STR_LOADED(gcm_id)) {
				goto request_error;
			}
			//TODO: check for length LBUF
			size_t gcm_id_len=0;
			if ((gcm_id_len=strlen(gcm_id))>CONFIG_CM_TOKEN_SZ_MAX) {
				goto request_error;
			}

			ReloadCMToken(sesn_ptr, gcm_id);

			if (!(DbSetGcmId (sesn_ptr, &(SESSION_UFSRVUIDSTORE(sesn_ptr)), 1, gcm_id)==0))	goto request_error;
		}
		else {
		  syslog(LOG_NOTICE, "%s {pid:'%lu', o:'%p', cid:'%lu'}: JSON DATA WAS MISSING...", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

			request_error:
				onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
				onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));
		}
	} else if ((flags&OR_METHODS)==OR_DELETE) {
    char ufsrvuid_encoded[CONFIG_MAX_UFSRV_ID_ENCODED_SZ+1] = {0};
    UfsrvUidConvertToString (&(SESSION_UFSRVUIDSTORE(sesn_ptr)), ufsrvuid_encoded);
		DeactivateUserAndPropogate (sesn_ptr, &(SESSION_UFSRVUIDSTORE(sesn_ptr)),  true/*flag_nuke*/);
	}

	return OCS_PROCESSED;

}

/**
 * 	@brief: Support a basic GET whereby a nickname is looked up for existence. If not available error code is returned, otherwise 200.
 * 	POST currently doesn't work because this endpoint is not authenticated, so we cannot determine username/id.
 * 	@basicauth: No
 *
 *
 */
API_ENDPOINT_V1(NICKNAME)
{
	const char *nickname;
	HttpSession *http_ptr;
	int return_code=409;

	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);
	int flags=onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));

#define _THIS_PATH_NICKNAME	"/V1/Nickname"

	size_t pathprefix_len=strlen(_THIS_PATH_NICKNAME);
	const char *full_path=onion_request_get_fullpath(HTTPSESN_REQUEST_PTR(http_ptr));

	if (strlen(full_path)<pathprefix_len)	goto request_error;

	if (strlen(full_path)> pathprefix_len+2) {// angling for '/' plus at least one more char after that 'Attachment/xxx'
		nickname=full_path+pathprefix_len+1;//skip the '/' since we did not include in the consta string above
	}
	else	goto request_error;

	if ((strlen(nickname))>CONFIG_MAX_NICKNAME_SIZE) {//max 20 letters
		goto request_error;
	}

#if __UF_TESTING
	syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', nickname:'%s'}: Processing nickname...", __func__, pthread_self(), sesn_ptr, nickname);
#endif

	if ((flags&OR_METHODS)==OR_GET) {
		//check backend
		if (IsNicknameAvailable(sesn_ptr, nickname))	goto request_success;
		else {
			 goto request_error;
		}
	}
	else
	if ((flags&OR_METHODS)==OR_POST) {
		return_code=405;//405 Method Not Allowed
		goto request_error;

		//POST not supported for changes that need to be broadcast across the network; use protobuf protocol instead
//		if (SESSION_USERNICKNAME(sesn_ptr))
//		{
//			if (strcasecmp(SESSION_USERNICKNAME(sesn_ptr), nickname)==0)
//			{
//				//TODO: improve return code
//				goto request_error;
//			}
//		}
//
//		//'true' for flag_store_if_valid
//		AccountNicknameValidateForUniqueness(sesn_ptr, NULL, nickname, true);
//		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)||SESSION_RESULT_CODE_EQUAL(sesn_ptr, RESCODE_BACKEND_RESOURCE_OWNER))
//		{
//			{
//				json_object *jobj_response=json_object_new_object();
//
//				json_object_object_add (jobj_response, "owner", json_object_new_boolean(1));
//				const char *json_str_reply=json_object_to_json_string(jobj_response);
//
//				onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(json_str_reply));
//				onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),json_str_reply, strlen(json_str_reply));
//
//				json_object_put(jobj_response);
//			}
//			goto request_success;
//		}
//		else
//		{
//			//TODO: improve return code
//			goto request_error;
//		}
	} else if ((flags&OR_METHODS)==OR_DELETE) {
		return_code=405;//405 Method Not Allowed
		goto request_error;
	}

	request_success:
	return OCS_PROCESSED;

	request_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), return_code);
	onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));
	return OCS_PROCESSED;
}

/*gcmRegistrationId
 */
API_ENDPOINT_V1(ACCOUNT_USERATTRIBUTES)
{
	const char *username;
	const char *password;
	//post data
	HttpSession *http_ptr;

	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);
	int flags=onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));

	if ((flags&OR_METHODS)==OR_GET)
	{

	}
	else
	if ((flags&OR_METHODS)==OR_POST)
	{
		if (HTTPSESN_JSONDATA(((HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr))))
		{

			struct json_object *jobj=HTTPSESN_JSONDATA(((HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr)));
			const char *nickname=json_object_get_string(json__get(jobj, "nickname"));
			if ((nickname==NULL)||(*nickname=='\0'))
			{
				goto request_error;
			}
			//TODO: check for length LBUF
			size_t nickname_len=0;
			if ((nickname_len=strlen(nickname))>20)//max 20 letters
			{
				goto request_error;
			}

			//if (!(AccountNicknameSet (sesn_ptr, SESSION_USERNAME(sesn_ptr), 1, gcm_id)==0))	goto request_error;
		}
		else
		{
			syslog(LOG_NOTICE, "%s {pid:'%lu', o:'%p', cid:'%lu'}: JSON DATA WAS MISSING...",
					__func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

			request_error:
				onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
				onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));
		}
	}
	else
	if ((flags&OR_METHODS)==OR_DELETE)
	{
		//DbAccountDeactivate (sesn_ptr, SESSION_USERNAME(sesn_ptr), false/*flag_nuke*/);
	}

	return OCS_PROCESSED;

}

API_ENDPOINT_V1(ACCOUNT_SHARED_CONTACTS)
{
	HttpSession *http_ptr;
	struct json_object *jobj_client=HTTPSESN_JSONDATA(((HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr)));

	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);

	{
		syslog (LOG_DEBUG, "%s (cid:'%lu'): CREATING matched contacts tokens...", __func__, SESSION_ID(sesn_ptr));

		if (true) {//get matched keys from db
			struct json_object *jobj_shared_contacts_array;
			{
				struct json_object *jobj_array_orig=json__get(jobj_client, "contacts");//array
				if (!jobj_array_orig) {
					syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', cid: '%lu'}: NOTICE: Array node for contacts was not found", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr));

					goto request_error;
				}
				else 		syslog(LOG_DEBUG, "%s {pid:'%lu, o:'%p', cid: '%lu', contacts_sz:'%d'}: RECEIVED contacts array node", __func__, pthread_self(), sesn_ptr, SESSION_ID(sesn_ptr), json_object_array_length(jobj_array_orig));

				jobj_shared_contacts_array=BackendDirectorySharedContactsGet (sesn_ptr, jobj_array_orig, NULL);
			}

			const char *json_str_reply=NULL;
			struct json_object *jobj_shared_contacts=NULL;

			if (jobj_shared_contacts_array) {
				jobj_shared_contacts=json_object_new_object();
				json_object_object_add(jobj_shared_contacts,"contacts", jobj_shared_contacts_array);
				json_str_reply=json_object_to_json_string(jobj_shared_contacts);
			} else {
				json_str_reply="{\"contacts\":[]}";
			}

			onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(json_str_reply));
			onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),json_str_reply, strlen(json_str_reply));

			if (jobj_shared_contacts)	json_object_put(jobj_shared_contacts);
			else if (jobj_shared_contacts_array)	json_object_put(jobj_shared_contacts_array);

			return OCS_PROCESSED;
		}
	}//request_type

	request_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
	onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));

	return OCS_PROCESSED;
}

API_ENDPOINT_V1(ACCOUNT_GENERATEPASSWORDHASH)
{
	HttpSession *http_ptr;

	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);
	const char *password=onion_request_get_query(HTTPSESN_REQUEST_PTR(http_ptr), "password");
	if (password)
	{
		UserCredentials creds;
		creds.password=(unsigned char *)password;
		if (GeneratePasswordHash(&creds)==0)
		{
			struct json_object *jobj_in=json_object_new_object();

			json_object_object_add (jobj_in,"hashed", json_object_new_string((char *)creds.hashed_password));
			json_object_object_add (jobj_in,"password", json_object_new_string((char *)creds.password));
			json_object_object_add (jobj_in,"salt", json_object_new_string((char *)creds.salt));
			const char *json_str_reply=json_object_to_json_string(jobj_in);

			onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(json_str_reply));
			onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),json_str_reply, strlen(json_str_reply));

			json_object_put(jobj_in);
			free(creds.hashed_password);
			free(creds.salt);
		}
		else
		{
			onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
			onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));
		}
	}

    return OCS_PROCESSED;
}

/**
 * 	@brief: This endpoint manages uploading of attachments, which is a 2-step process.
 * 	1)Acquiring an authorisation nonce: In order to upload an attachment a nonce is required via an authenticated GET request, which returns a
 * 	'nonce' value that has short TTL value and a temporary location.These are key-value hashed as nonce -> location
 *
 * 	2)Physically uploading the requires authenticated PUT request with a header  'X-UFSRV_ATTACHMENT-NONCE' HEADER with the value
 * 	set to nonce and request param set to location
 * 	Upon successful upload a json stream the nonce value is used to identify the location of this particular blob.
 *
 * 	@url: GET 'https://api.unfacd.io:20080/V1/Account/Attachment' --> {location:"..", nonce:".."
 *
 * 	@url: GET 'https://api.unfacd.io:20080/V1/Account/Attachment/{attchment_id}' --> {location:"..", nonce:".."
 * 	curl -u a:a https://api.unfacd.io:20080/V1/Account/Attachment/c2566ce957eca2de45ea1827d3e1f31e4fb226a7
 *
 * 	@url: PUT 'https://api.unfacd.io:20080/V1/Account/Attachment/@location' WITH REQUEST HEADER  X-UFSRV_ATTACHMENT-NONCE
 *
 * 	 curl -u a:a https://api.unfacd.io:20080/V1/Account/Attachment
{ "nonce": "9b54ec", "location": "https://api.unfacd.io:20080/V1/Account/Attachment/f61fa8..ab" }
 *
 */
API_ENDPOINT_V1(ACCOUNT_ATTACHMENT)
{
	HttpSession *http_ptr=NULL;
	const char *attachment_id=NULL;

	http_ptr = (HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);

	#define _THIS_PATH_ATTACHMENT	"/V1/Account/Attachment"

	const char *user_token_req;
	size_t pathprefix_len = strlen( _THIS_PATH_ATTACHMENT);
	const char *full_path = onion_request_get_fullpath(HTTPSESN_REQUEST_PTR(http_ptr));
	int flags = onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));

	if (strlen(full_path) < pathprefix_len)	goto request_error;

	if (strlen(full_path) > pathprefix_len + 2)// angling for '/' plus at least one more char after that 'Attachment/xxx'
	{
		attachment_id = full_path + pathprefix_len + 1;//skip the '/' since we did not include in the consta string above
	}


	if ((flags&OR_METHODS) == OR_GET) {
		if (IS_EMPTY(attachment_id)) {
			AttachmentDescription *attch_ptr = BackendAttachmentGenerate(sesn_ptr);
			if (attch_ptr) {
				struct json_object *jobj_attachment = json_object_new_object();

				json_object_object_add (jobj_attachment, "nonce", json_object_new_string(attch_ptr->nonce));
				json_object_object_add (jobj_attachment, "location", json_object_new_string(attch_ptr->path));

				const char *json_str_reply = json_object_to_json_string(jobj_attachment);

				onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(json_str_reply));
				onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),json_str_reply, strlen(json_str_reply));

				json_object_put(jobj_attachment);
				AttachementDescriptionDestruct(attch_ptr, true);

				return OCS_PROCESSED;
			}
		} else {
#ifdef __UF_FULLDEBUG
			syslog(LOG_DEBUG, "%s: {pid:'%lu', o:'%p', blob_id:'%s'} SERVING Attachment...", __func__, pthread_self(), sesn_ptr, attachment_id);
#endif

			char file_fullpath[LBUF];
			snprintf(file_fullpath, LBUF-1, _CONFIGDEFAULT_DEFAULT_UFSRVMEDIA_STORAGE_LOCATION"%s", attachment_id);

      AttachmentDescriptor *attachment_ptr = GetAttachmentDescriptor (sesn_ptr, attachment_id, true);
			if (!IS_EMPTY(attachment_ptr)) {
				return (InitialiseSendFileContext(sesn_ptr, file_fullpath, attachment_ptr));
			} else {
#ifdef __UF_TESTING
				//Special mode for testing. Record doesn't have to be saved in the db backend: we retrieve location from cache backend

				BackendAttachmentGetFileLocation (sesn_ptr, attachment_id);
				if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
					char *file_location = (char *)SESSION_RESULT_USERDATA(sesn_ptr);
					int res = InitialiseSendFileContext(sesn_ptr, file_fullpath, attachment_ptr);
					free (file_location);

					return res;
				}
#endif
				goto request_error;
			}
		}
	}
	else
	if ((flags&OR_METHODS) == OR_PUT) {//IMPORTANT DBBackend record only stored if request is from end device commandline testing doesnt do that
		const char *nonce = onion_request_get_header(HTTPSESN_REQUEST_PTR(http_ptr), _ATTACHMENT_HEADER_NONCE);

		if (IS_EMPTY(nonce))	goto return_nonce_error;

		if (!(IsAttachmentDescriptionValid(sesn_ptr, nonce, attachment_id)))	goto request_error;

		char finalname[1024];
		snprintf(finalname, sizeof(finalname), "%s%s", _CONFIGDEFAULT_DEFAULT_UFSRVMEDIA_STORAGE_LOCATION, nonce);
		const onion_block *block=onion_request_get_data(HTTPSESN_REQUEST_PTR(http_ptr));

		if ((FileUtilsRenameFile(block->data, finalname)) != 0)	goto request_error;

		BackendAttachmentStoreLocationId (sesn_ptr, nonce, finalname);//we use nonce as key

		syslog(LOG_DEBUG, LOGSTR_ACCOUNT_ATTCH_DOWNLOADED_SUCCESS, __func__, pthread_self(), sesn_ptr, finalname, LOGCODE_ACCOUNT_ATTCH_DOWNLOADED_SUCCESS);

		return OCS_PROCESSED;
	}

	return_nonce_error:
	syslog(LOG_DEBUG, LOGCSTR_ACCOUNT_ATTCH_NO_REQUEST_NONCE, __func__, pthread_self(), sesn_ptr, attachment_id, LOGCCODE_ACCOUNT_ATTCH_NO_REQUEST_NONCE);

	request_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
	return OCS_PROCESSED;

#undef _THIS_PATH_ATTACHMENT
}

API_ENDPOINT_V1(STATESYNC)
{
	HttpSession 					*http_ptr;
	struct json_object 		*jobj;

	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);
	#define _THIS_PATH_STATESYNC	"/V1/Account/StateSync"

	const char	*json_str_reply;
	size_t 			pathprefix_len=strlen( _THIS_PATH_STATESYNC);
	const char 	*full_path=onion_request_get_fullpath(HTTPSESN_REQUEST_PTR(http_ptr));
	int 				flags=onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));

	if (strlen(full_path)> pathprefix_len)	goto return_post_error;

	if ((flags&OR_METHODS)==OR_GET) {
			if (IS_PRESENT((jobj=JsonFormatStateSync(sesn_ptr, DIGESTMODE_BRIEF, true, NULL))))
			{
				json_str_reply=json_object_to_json_string(jobj);
				goto	return_post_reply;
			}
			else goto return_post_error;
	} else {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', request_flags:'%d'}: ERROR: UNSUPPORTED HTTP REQUEST TYPE...", __func__, pthread_self(), sesn_ptr, flags);
		goto return_post_error;
	}

	return_post_reply:
	onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(json_str_reply));
	onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),json_str_reply, strlen(json_str_reply));
	json_object_put(jobj);
	return OCS_PROCESSED;

	return_post_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
	return OCS_PROCESSED;

}

/**
 * 	 curl -Ss -u a:a https://api.unfacd.io:20080/V1/Account/Prefs/Group/pref_rm_conquerer
 */
API_ENDPOINT_V1(PREFSGROUP)
{
	HttpSession 		*http_ptr;
	json_object 		*jobj_pref;

	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);
	#define _THIS_PATH_PREFSGROUP	"/V1/Account/Prefs/Group"

	const char	*json_str_reply;
	const char	*pref_name=NULL,
							*pref_value;

	const char 	*user_token_req;
	size_t 			pathprefix_len=strlen( _THIS_PATH_PREFSGROUP);
	const char 	*full_path=onion_request_get_fullpath(HTTPSESN_REQUEST_PTR(http_ptr));
	int 				flags=onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));

	if (strlen(full_path)<pathprefix_len)	goto return_post_error;

	if (strlen(full_path)> pathprefix_len+2) {// angling for '/' plus at least one more char after that 'Attachment/xxx'
		pref_name=full_path+pathprefix_len+1;//skip the '/' since we did not include in the consta string above
	}

	if ((flags&OR_METHODS)==OR_GET) {
		if (IS_EMPTY(pref_name)) {
			goto return_post_error;
		} else {
			UserPreferenceDescriptor pref={0};
			if (GetUserPreferenceByRange (sesn_ptr, GetPrefIndexByName(pref_name), &pref)) {
				jobj_pref=JsonFormatUserPreference(&pref);
				json_str_reply=json_object_to_json_string(jobj_pref);
				goto	return_post_reply;
			}

			goto return_post_error;
		}
	} else {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', request_flags:'%d'}: ERROR: UNSUPPORTED HTTP REQUEST TYPE...", __func__, pthread_self(), sesn_ptr, flags);
		goto return_post_error;
	}

	return_post_reply:
	onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(json_str_reply));
	onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),json_str_reply, strlen(json_str_reply));
	json_object_put(jobj_pref);
	return OCS_PROCESSED;

	return_post_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
	return OCS_PROCESSED;

}

/**
 * 	 curl -Ss -u a:a https://api.unfacd.io:20080/V1/Account/Prefs/StickyGeogroup/159683336
 * 	 curl -Ss -X POST -u '+61xxxxx:tErwzxNdmO68wjxAZGYdoreE'  https://api.unfacd.io:20080/V1/Account/Prefs/StickyGeogroup/159683336/1
 * 	 HMGET FENCE_USERPREFS:279:159683336 sticky_geogroup
 *
 */
API_ENDPOINT_V1(PREFSSTICKY_GEOGROUP)
{
					HttpSession 		*http_ptr;
	struct 	json_object 		*jobj_pref;

	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);
	#define _THIS_PATH_PREFSSTICKYGEOGROUP	"/V1/Account/Prefs/StickyGeogroup"

	unsigned long	fid;
	const char		*json_str_reply,
								*fid_str;
				char		*pref_value_str	=	NULL;

	size_t 			pathprefix_len = sizeof( _THIS_PATH_PREFSSTICKYGEOGROUP)-1;
	const char 	*full_path = strdupa(onion_request_get_fullpath(HTTPSESN_REQUEST_PTR(http_ptr)));
	int 				flags = onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));


	if (strlen(full_path) < pathprefix_len)	goto return_post_error;

	if (strlen(full_path) > pathprefix_len + 2)// angling for '/' plus at least one more char after that '/V1/Account/Prefs/StickyGeogroups/xxx'
	{
		fid_str = full_path+pathprefix_len + 1;//skip the '/' since we did not include in the const string above
		if (IS_PRESENT((pref_value_str = strchr(fid_str, '/'))))//xxxx/x
		{
			*pref_value_str = '\0'; //this isolates fid
			++pref_value_str;
			//we may or may not have a pref value set, test later
		}
		//else only fid is present so this must be GET or else bail out

		if (! IsUserIdInCacheRecordForFence(sesn_ptr,  (fid = strtoul(fid_str, NULL, 10)))) {
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', fid_str='%s'}: ERROR: USER NOT MEMBER OF FENCE", __func__, pthread_self(), sesn_ptr, fid_str);
			goto return_post_error;
		}
	}
	//else no fid present -> return all sticky groups

	if ((flags&OR_METHODS) == OR_GET) {
		if (IS_EMPTY(fid_str)) {
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: Returning the geosticky value of all fences for this user", __func__, pthread_self(), sesn_ptr);
			if ((jobj_pref = CacheBackendGetAllFenceUserPreferencesByJson (sesn_ptr, SESSION_USERID(sesn_ptr)))) {
				json_str_reply = json_object_to_json_string(jobj_pref);
				goto	return_post_reply;
			}

			goto return_post_error;
		} else {
			UserPreferenceDescriptor 	pref	=	{0};

			if	(GetFenceUserPreferenceDescriptorByName("sticky_geogroup", &pref)) {
        Fence											fence				=	{.fence_id=fid};
        InstanceHolderForFence    instance    = {.holder.instance=&fence};
        FenceStateDescriptor			fence_state	=	{.instance_holder_fence=&instance};

				if (GetUserPreference(&((PairedSessionFenceState){&fence_state, sesn_ptr}), &pref, PREFSTORE_CACHED)) {
					jobj_pref = JsonFormatUserPreference(&pref);
					json_str_reply = json_object_to_json_string(jobj_pref);
					goto	return_post_reply;
				}
			}

			goto return_post_error;
		}
	} else if ((flags&OR_METHODS) == OR_POST) {
		if (IS_PRESENT(fid_str) && IS_STR_LOADED(pref_value_str)) {
			unsigned long 						pref_value		=	strtoul(pref_value_str, NULL, 10);
			UserPreferenceDescriptor 	pref					=	{0};

			if	(GetFenceUserPreferenceDescriptorByName("sticky_geogroup", &pref)) {
				Fence											fence				=	{.fence_id=fid};
				InstanceHolderForFence    instance    = {.holder.instance=&fence};
				FenceStateDescriptor			fence_state	=	{.instance_holder_fence=&instance};

				pref.value.pref_value_bool = pref_value;

				if (SetUserPreference (&((PairedSessionFenceState){&fence_state, sesn_ptr}), &pref, PREFSTORE_CACHED, &((UfsrvEvent){0}))) {
					jobj_pref = JsonFormatUserPreference(&pref);
					json_str_reply = json_object_to_json_string(jobj_pref);
					goto	return_post_reply;
				}
			}

			goto return_post_error;
		}
		else {
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', fid:'%s', pref_value:'%s'}: ERROR: FID OR PREF_VALUE NOT SET FOR FENCE", __func__, pthread_self(), sesn_ptr, fid_str?:CONFIG_DEFAULT_PREFS_STRING_VALUE, pref_value_str?:CONFIG_DEFAULT_PREFS_STRING_VALUE);
			goto return_post_error;
		}
	}
	else if ((flags&OR_METHODS) == OR_DELETE) {
		goto return_unsupported;
	} else {
		goto return_unsupported;
	}

	return_post_reply:
	onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(json_str_reply));
	onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),json_str_reply, strlen(json_str_reply));
	json_object_put(jobj_pref);
	return OCS_PROCESSED;

	return_post_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
	return OCS_PROCESSED;

	return_unsupported:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 405);
	return OCS_PROCESSED;

}

/**
 * 	 curl -Ss -X POST -u a:a https://api.unfacd.io:20080/V1/Account/Prefs/roaming_mode/1
 * 	  curl -Ss -u a:a https://api.unfacd.io:20080/V1/Account/Prefs/roaming_mode
 * 	  '+61xxxxx:tErwzxNdmO68wjxAZGYdoreE'
 */
API_ENDPOINT_V1(PREFS)
{
	HttpSession 		*http_ptr;
	json_object 		*jobj_pref = NULL;

	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);
	#define _THIS_PATH_PREFS	"/V1/Account/Prefs"

	const char	*json_str_reply;
	const char	*pref_name=NULL,
							*pref_value;

	const char *user_token_req;
	size_t pathprefix_len=strlen( _THIS_PATH_PREFS);
	const char *full_path=onion_request_get_fullpath(HTTPSESN_REQUEST_PTR(http_ptr));
	int flags=onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));

	if (strlen(full_path)<pathprefix_len)	goto return_post_error;

	if (strlen(full_path)> pathprefix_len+2)// angling for '/' plus at least one more char after that 'Attachment/xxx'
	{
		pref_name=full_path+pathprefix_len+1;//skip the '/' since we did not include in the consta string above
	}

	if ((flags&OR_METHODS)==OR_GET) {
		if (IS_EMPTY(pref_name)) {
			//get all prefs value
			goto return_post_error;
		} else {
			UserPreferenceDescriptor pref = {0};
			if (GetUserPreferenceBoolean(sesn_ptr, GetPrefIndexByName(pref_name), PREFSTORE_CACHED, &pref)) {
				jobj_pref       = JsonFormatUserPreference(&pref);
				json_str_reply  = json_object_to_json_string(jobj_pref);
				goto	return_post_reply;
			}

			goto return_post_error;
		}
	}
	else if ((flags & OR_METHODS) == OR_POST) {
		goto return_post_error;
	} else {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', request_flags:'%d'}: ERROR: UNSUPPORTED HTTP REQUEST TYPE...", __func__, pthread_self(), sesn_ptr, flags);
		goto return_post_error;
	}

	return_post_reply:
	onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(json_str_reply));
	onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),json_str_reply, strlen(json_str_reply));
	if (IS_PRESENT(jobj_pref))	json_object_put(jobj_pref);
	return OCS_PROCESSED;

	return_post_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
	return OCS_PROCESSED;

#undef _THIS_PATH_PREFS
}

#include <crypto_certificates.pb-c.h>
#include <users_proto.h>

#define _PROVIDE_SENDER_CERTIFICATE_CONTEXT() \
  SenderCertificate cert_sender     = SENDER_CERTIFICATE__INIT; \
  ServerCertificate cert_server     = SERVER_CERTIFICATE__INIT; \
  Certificate    cert_key        		= CERTIFICATE__INIT;  \
  IdentityCertificate cert_identity = IDENTITY_CERTIFICATE__INIT; \
  SenderCertificateContext sender_cert_ctx = {  \
        .cert_sender_ptr=&cert_sender, .cert_identity_ptr=&cert_identity, .cert_server_ptr=&cert_server, .cert_key_ptr=&cert_key \
  };

/**
 */
API_ENDPOINT_V1(CERTIFICATE_DELIVERY)
{
  HttpSession 		*http_ptr;

  http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);
#define _THIS_PATH_CERT	"/V1/Account/Certificate/Delivery"

  char	*json_str_reply;
  size_t pathprefix_len=strlen( _THIS_PATH_CERT);
  const char *full_path=onion_request_get_fullpath(HTTPSESN_REQUEST_PTR(http_ptr));
  int flags=onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));

  if (strlen(full_path)<pathprefix_len)	goto return_error;

  if ((flags&OR_METHODS)==OR_GET) {
    _PROVIDE_SENDER_CERTIFICATE_CONTEXT();
    MakeSenderCertificate (sesn_ptr, &sender_cert_ctx);
    if (SESSION_RESULT_TYPE_ERROR(sesn_ptr)) {
      onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 402);
      return OCS_PROCESSED;
    }

    size_t sender_cert_packed_sz = sender_certificate__get_packed_size(sender_cert_ctx.cert_sender_ptr);
    unsigned char sender_cert_packed[sender_cert_packed_sz];
    sender_certificate__pack(sender_cert_ctx.cert_sender_ptr, sender_cert_packed);
    unsigned char sender_cert_b64encoded[GetBase64BufferAllocationSize(sender_cert_packed_sz)];
    base64_encode(sender_cert_packed, sender_cert_packed_sz, sender_cert_b64encoded);
    asprintf(&json_str_reply, "{\"certificate\":\"%s\"}", sender_cert_b64encoded);

    free (sender_cert_ctx.cert_server_ptr->signature.data-sizeof(data_buffer));
    free (sender_cert_ctx.cert_server_ptr->certificate.data);
    free (sender_cert_ctx.cert_sender_ptr->certificate.data);
		free (sender_cert_ctx.cert_sender_ptr->signature.data-sizeof(data_buffer));

    goto return_reply;
  } else {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', request_flags:'%d'}: ERROR: UNSUPPORTED HTTP REQUEST TYPE...", __func__, pthread_self(), sesn_ptr, flags);
    goto return_error;
  }

  return_reply:
  onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(json_str_reply));
  onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),json_str_reply, strlen(json_str_reply));
  return OCS_PROCESSED;

  return_error:
  onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
  return OCS_PROCESSED;

#undef _THIS_PATH_CERT
}

API_ENDPOINT_V1(CAPTCHA)
{
  HttpSession 		*http_ptr;

  char *captcha_response =
#include "google_captcha_html.h"
        ;

  http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);
#define _THIS_PATH_CAPTCHA	"/V1/Account/Captcha"

  size_t pathprefix_len=strlen( _THIS_PATH_CAPTCHA);
  const char *full_path=onion_request_get_fullpath(HTTPSESN_REQUEST_PTR(http_ptr));
  int flags=onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));

  if (strlen(full_path)<pathprefix_len)	goto return_error;

  if ((flags&OR_METHODS)==OR_GET) {
    goto return_reply;
  } else {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', request_flags:'%d'}: ERROR: UNSUPPORTED HTTP REQUEST TYPE...", __func__, pthread_self(), sesn_ptr, flags);
    goto return_error;
  }

  return_reply:
  onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(captcha_response));
  onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),captcha_response, strlen(captcha_response));
  return OCS_PROCESSED;

  return_error:
  onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
  return OCS_PROCESSED;

}

#if 0
/**
 * 	@param jobj_pref: preallocated
 */
static inline const char *
_PREFSMakeResultByJson (Session *sesn_ptr, UserPreferenceDescriptor *pref_ptr, struct json_object *jobj_pref)
{
	UserPreferenceDescriptor pref_descriptor={0};
	json_object_object_add (jobj_pref, "pref_name", json_object_new_string(pref_ptr->pref_name));
	json_object_object_add (jobj_pref, "pref_id", json_object_new_int(pref_ptr->pref_id));
	_SetJsonPrefValueByType(jobj_pref, "pref_value_previous", pref_ptr);

	GetUserPreferenceBoolean (sesn_ptr, GetPrefIndexByName(pref_ptr->pref_name), PREFSTORE_MEM, &pref_descriptor);
	_SetJsonPrefValueByType(jobj_pref, "pref_value_mem", &pref_descriptor);

	const char *json_str_reply=json_object_to_json_string(jobj_pref);

	return json_str_reply;
}
#endif
