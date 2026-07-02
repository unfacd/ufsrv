/**
 * Copyright (C) 2015-2025 unfacd works
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
#include <api_endpoint_v1_donation.h>
#include <ufsrv_core/http/http_request_handler.h>
#include <ufsrv_core/http/response.h>
#include <session_type.h>
#include <http_session_type.h>
#include <uflib/utils_urls.h>
#include <ufsrvmsg_core/donations/utils_donations.h>

/** \addtogroup api_endpoints_donation
 *  Url endpoints that handle donation related commands
 *  @{
 */

extern __thread ThreadContext ufsrv_thread_context;

static const char *err = "Server unable to complete request.";

/**
 * wget -q -O - --user=3J140H9YY5H43K608000000000 --password=DGvvRuIxzBUitDv5CcnQt9UM https://api.unfacd.io/V1/Donation/Subscription/%subscription_id
 * https://api.unfacd.io/V1/Donation/Subscription/gPwtC9LA9ZIzsovwoD1Bjxq03Wo7OTRSOs_8lEapZnY=
 * @param instance_sesn_ptr
 * @return
 */
API_ENDPOINT_V1(DONATION_SUBSCRIPTION)
{
#define _THIS_PATH	"/V1/Donation/Subscription/"
#define _MOCK_JSON_REPLY "{}"

#define MESSAGE_DONATION_SUBSCRIPTION_MAX_URL_PARAMS_SZ           4
#define MESSAGE_DONATION_SUBSCRIPTION_URL_TOKEN_SUBSCRIBER_ID     3 //indexed at 0

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
  HttpSession *http_ptr = (HttpSession *)SESSION_PROTOCOL_SESSION_DATA(sesn_ptr);
  int         flags = onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));
  const char *full_path = onion_request_get_fullpath(HTTPSESN_REQUEST_PTR(http_ptr));

  UrlParamsDescriptor url_params = {
          .tokens = (UrlParamToken *[]){&(UrlParamToken){0}, &(UrlParamToken){0}, &(UrlParamToken){0}, &(UrlParamToken){0}}
  };
  TokeniseUrlParams((char *)full_path, &url_params, MESSAGE_DONATION_SUBSCRIPTION_MAX_URL_PARAMS_SZ);
  if (url_params.tokens_sz < 4) goto request_error;
  if (!IS_STR_LOADED(url_params.tokens[MESSAGE_DONATION_SUBSCRIPTION_URL_TOKEN_SUBSCRIBER_ID]->token)) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: Missing subscribe_id...", __func__, pthread_self(), sesn_ptr);
  }

  if ((flags&OR_METHODS) == OR_GET) {
    json_object  *jobj_ptr_reply = HandleActiveSubscriptionRetrievalForUser(THREAD_CONTEXT_HTTP_REQUEST_CONTEXT, SESSION_USERID(sesn_ptr), url_params.tokens[MESSAGE_DONATION_SUBSCRIPTION_URL_TOKEN_SUBSCRIBER_ID]->token);
    if (IS_PRESENT(jobj_ptr_reply)) {
      const char *jobj_ptr_str_reply = json_object_get_string(jobj_ptr_reply);
      char *final = NULL; asprintf(&final, "{\"subscription\": %s}", jobj_ptr_str_reply);
      onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(final));
      onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), final, strlen(final));
      json_object_put(jobj_ptr_reply);
      free(final);

      goto request_processed;
    }
    goto request_404;
  } else if ((flags&OR_METHODS) == OR_POST) {//this is a no-op for ufsrv, as we create the subscriber id locally
    //todo save into stripe storage
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', subscriberid:'%s'}: RECEIVED SUBSCRIPTION POST FOR SUBSCRIBERID...", __func__, pthread_self(), sesn_ptr, url_params.tokens[MESSAGE_DONATION_SUBSCRIPTION_URL_TOKEN_SUBSCRIBER_ID]->token);
    goto request_processed;
  } else if ((flags&OR_METHODS) == OR_DELETE) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', subscriberid:'%s'}: RECEIVED SUBSCRIPTION DELETE FOR SUBSCRIBERID...", __func__, pthread_self(), sesn_ptr, url_params.tokens[MESSAGE_DONATION_SUBSCRIPTION_URL_TOKEN_SUBSCRIBER_ID]->token);
    HandleDonationSubscriptionCancelled(THREAD_CONTEXT_HTTP_REQUEST_CONTEXT, SESSION_USERID(sesn_ptr), url_params.tokens[MESSAGE_DONATION_SUBSCRIPTION_URL_TOKEN_SUBSCRIBER_ID]->token, false);
    goto request_processed;
  } else {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: Unsupported HTTP Request method...", __func__, pthread_self(), sesn_ptr);
  }

  request_error:
  onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
  onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));

  request_404:
  onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 404);
  onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));

  request_processed:
  return OCS_PROCESSED;

#undef _THIS_PATH
#undef _MOCK_JSON_REPLY
#undef MESSAGE_DONATION_SUBSCRIPTION_MAX_URL_PARAMS_SZ
#undef MESSAGE_DONATION_SUBSCRIPTION_URL_TOKEN_SUBSCRIBER_ID
}

/**
 * @param instance_sesn_ptr
 * @return
 */
API_ENDPOINT_V1(DONATION_SUBSCRIPTION_LEVEL)
{
#define _THIS_PATH	"/V1/Donation/Subscription/Level"
#define _MOCK_JSON_REPLY "{}"
//https://api.unfacd.io/v1/subscription/1RWA4qMccRrsHVJjXBvL2AubvcF9KPTyr2WO3FvAwfo=/level/1/AUD/rPbgV5s6oZKejriyEQ6zSw==
#define MESSAGE_DONATION_SUBSCRIPTION_MAX_URL_PARAMS_SZ           8
#define MESSAGE_DONATION_SUBSCRIPTION_LEVEL_URL_TOKEN_SUBSCRIBER_ID     4 //indexed at 0
#define MESSAGE_DONATION_SUBSCRIPTION_LEVEL_URL_TOKEN_LEVEL_ID          5
#define MESSAGE_DONATION_SUBSCRIPTION_LEVEL_URL_TOKEN_CURRENCY_CODE     6
#define MESSAGE_DONATION_SUBSCRIPTION_LEVEL_URL_TOKEN_LEVEL_KEY         7

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
  HttpSession *http_ptr = (HttpSession *)SESSION_PROTOCOL_SESSION_DATA(sesn_ptr);
  int         flags = onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));
  const char *full_path = onion_request_get_fullpath(HTTPSESN_REQUEST_PTR(http_ptr));

  UrlParamsDescriptor url_params = {
          .tokens = (UrlParamToken *[]){&(UrlParamToken){0}, &(UrlParamToken){0}, &(UrlParamToken){0}, &(UrlParamToken){0},
                                        &(UrlParamToken){0}, &(UrlParamToken){0}, &(UrlParamToken){0}, &(UrlParamToken){0}}
};
  TokeniseUrlParams((char *)full_path, &url_params, MESSAGE_DONATION_SUBSCRIPTION_MAX_URL_PARAMS_SZ);
  if (url_params.tokens_sz < MESSAGE_DONATION_SUBSCRIPTION_MAX_URL_PARAMS_SZ) goto request_error;
  if (!IS_STR_LOADED(url_params.tokens[MESSAGE_DONATION_SUBSCRIPTION_LEVEL_URL_TOKEN_SUBSCRIBER_ID]->token)) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: Missing subscribe_id...", __func__, pthread_self(), sesn_ptr);
    goto request_error;
  }

  if ((flags&OR_METHODS) == OR_GET) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: Unsupported HTTP GET Request method...", __func__, pthread_self(), sesn_ptr);
    goto request_error;
  } else if ((flags&OR_METHODS) == OR_POST) {
    //todo save into stripe storage
    HandleActivateDonationSubscriptionLevel(THREAD_CONTEXT_HTTP_REQUEST_CONTEXT, SESSION_USERID(sesn_ptr), url_params.tokens[MESSAGE_DONATION_SUBSCRIPTION_LEVEL_URL_TOKEN_SUBSCRIBER_ID]->token, atoi(url_params.tokens[MESSAGE_DONATION_SUBSCRIPTION_LEVEL_URL_TOKEN_LEVEL_ID]->token), url_params.tokens[MESSAGE_DONATION_SUBSCRIPTION_LEVEL_URL_TOKEN_CURRENCY_CODE]->token, url_params.tokens[MESSAGE_DONATION_SUBSCRIPTION_LEVEL_URL_TOKEN_LEVEL_KEY]->token);
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', subscriberid:'%s'}: RECEIVED SUBSCRIPTION POST FOR SUBSCRIBERID...", __func__, pthread_self(), sesn_ptr, url_params.tokens[MESSAGE_DONATION_SUBSCRIPTION_LEVEL_URL_TOKEN_SUBSCRIBER_ID]->token);
    goto request_processed;
  } else if ((flags&OR_METHODS) == OR_DELETE) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', subscriberid:'%s'}: RECEIVED SUBSCRIPTION DELETE FOR SUBSCRIBERID...", __func__, pthread_self(), sesn_ptr, url_params.tokens[MESSAGE_DONATION_SUBSCRIPTION_LEVEL_URL_TOKEN_SUBSCRIBER_ID]->token);
    goto request_processed;
  } else {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: Unsupported HTTP Request method...", __func__, pthread_self(), sesn_ptr);
  }

  request_error:
  onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
  onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));

  request_processed:
  return OCS_PROCESSED;

#undef _THIS_PATH
#undef _MOCK_JSON_REPLY
#undef MESSAGE_DONATION_SUBSCRIPTION_MAX_URL_PARAMS_SZ
#undef MESSAGE_DONATION_SUBSCRIPTION_LEVEL_URL_TOKEN_SUBSCRIBER_ID
#undef MESSAGE_DONATION_SUBSCRIPTION_LEVEL_URL_TOKEN_LEVEL_ID
#undef MESSAGE_DONATION_SUBSCRIPTION_LEVEL_URL_TOKEN_CURRENCY_CODE
#undef MESSAGE_DONATION_SUBSCRIPTION_LEVEL_URL_TOKEN_LEVEL_KEY
}


API_ENDPOINT_V1(DONATION_SUBSCRIPTION_CREATE_PAYMENT_METHOD)
{
#define _THIS_PATH	"/V1/Donation/Subscription/CreatePaymentMethod"
#define _MOCK_JSON_REPLY "{}"

#define MESSAGE_DONATION_SUBSCRIPTION_MAX_URL_PARAMS_SZ           5
#define MESSAGE_DONATION_SUBSCRIPTION_URL_TOKEN_SUBSCRIBER_ID     4 //indexed at 0

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
  HttpSession *http_ptr = (HttpSession *)SESSION_PROTOCOL_SESSION_DATA(sesn_ptr);
  int         flags = onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));
  const char *full_path = onion_request_get_fullpath(HTTPSESN_REQUEST_PTR(http_ptr));

  UrlParamsDescriptor url_params = {
          .tokens = (UrlParamToken *[]){&(UrlParamToken){0}, &(UrlParamToken){0}, &(UrlParamToken){0}, &(UrlParamToken){0}, &(UrlParamToken){0}}
  };
  TokeniseUrlParams((char *)full_path, &url_params, MESSAGE_DONATION_SUBSCRIPTION_MAX_URL_PARAMS_SZ);

  if (url_params.tokens_sz < MESSAGE_DONATION_SUBSCRIPTION_MAX_URL_PARAMS_SZ) goto request_error;
  if (!IS_STR_LOADED(url_params.tokens[MESSAGE_DONATION_SUBSCRIPTION_URL_TOKEN_SUBSCRIBER_ID]->token)) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: Missing subscriber_id...", __func__, pthread_self(), sesn_ptr);
    goto request_error;
  }

  if ((flags&OR_METHODS) == OR_POST) {
    //todo save into stripe storage
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', subscriber_id:'%s'}: RECEIVED SUBSCRIPTION POST FOR SUBSCRIBER_ID...", __func__, pthread_self(), sesn_ptr, url_params.tokens[MESSAGE_DONATION_SUBSCRIPTION_URL_TOKEN_SUBSCRIBER_ID]->token);
    //todo check if this user actually owns the subscriber id
    const char *client_secret = HandleDonationPipelineInitiated(THREAD_CONTEXT_HTTP_REQUEST_CONTEXT, SESSION_USERID(sesn_ptr), url_params.tokens[MESSAGE_DONATION_SUBSCRIPTION_URL_TOKEN_SUBSCRIBER_ID]->token, PROCESSOR_STRIPE);
    if (!IS_STR_LOADED(client_secret)) goto request_error;
    char *json_str_reply = NULL; asprintf(&json_str_reply, "{\"clientSecret\":\"%s\"}", client_secret); free((char *)client_secret);
    onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(json_str_reply));
    onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),json_str_reply, strlen(json_str_reply));
    free(json_str_reply);
    goto request_processed;
  } else if ((flags&OR_METHODS) == OR_DELETE) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', subscriber_id:'%s'}: RECEIVED SUBSCRIPTION DELETE FOR SUBSCRIBER_ID...", __func__, pthread_self(), sesn_ptr, url_params.tokens[MESSAGE_DONATION_SUBSCRIPTION_URL_TOKEN_SUBSCRIBER_ID]->token);
    goto request_processed;
  } else {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: Unsupported HTTP Request method...", __func__, pthread_self(), sesn_ptr);
  }

  request_error:
  onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
  onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));

  request_processed:
  return OCS_PROCESSED;

#undef _THIS_PATH
#undef _MOCK_JSON_REPLY
#undef MESSAGE_DONATION_SUBSCRIPTION_MAX_URL_PARAMS_SZ
#undef MESSAGE_DONATION_SUBSCRIPTION_URL_TOKEN_SUBSCRIBER_ID
}

/**
 * @brief Update default payment method for existing customer.
 */
API_ENDPOINT_V1(DONATION_SUBSCRIPTION_DEFAULT_PAYMENT_METHOD)
{
#define _THIS_PATH	"/V1/Donation/Subscription/DefaultPaymentMethod"
#define _MOCK_JSON_REPLY "{}"

#define MESSAGE_DONATION_SUBSCRIPTION_MAX_URL_PARAMS_SZ           6
#define MESSAGE_DONATION_SUBSCRIPTION_URL_TOKEN_SUBSCRIBER_ID     4 //indexed at 0
#define MESSAGE_DONATION_SUBSCRIPTION_URL_TOKEN_PAYMENT_METHOD    5

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
  HttpSession *http_ptr = (HttpSession *)SESSION_PROTOCOL_SESSION_DATA(sesn_ptr);
  int         flags = onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));
  const char *full_path = onion_request_get_fullpath(HTTPSESN_REQUEST_PTR(http_ptr));

  UrlParamsDescriptor url_params = {
          .tokens = (UrlParamToken *[]){&(UrlParamToken){0}, &(UrlParamToken){0}, &(UrlParamToken){0}, &(UrlParamToken){0}, &(UrlParamToken){0}, &(UrlParamToken){0}}
  };
  TokeniseUrlParams((char *)full_path, &url_params, MESSAGE_DONATION_SUBSCRIPTION_MAX_URL_PARAMS_SZ);

  if (url_params.tokens_sz < MESSAGE_DONATION_SUBSCRIPTION_MAX_URL_PARAMS_SZ) goto request_error;
  if (!IS_STR_LOADED(url_params.tokens[MESSAGE_DONATION_SUBSCRIPTION_URL_TOKEN_SUBSCRIBER_ID]->token)) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: Missing subscriber_id...", __func__, pthread_self(), sesn_ptr);
    goto request_error;
  }
  if (!IS_STR_LOADED(url_params.tokens[MESSAGE_DONATION_SUBSCRIPTION_URL_TOKEN_PAYMENT_METHOD]->token)) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: Missing payment_method...", __func__, pthread_self(), sesn_ptr);
    goto request_error;
  }

  if ((flags&OR_METHODS) == OR_POST) {
    //todo save into stripe storage
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', subscriber_id:'%s'}: RECEIVED DefaultPaymentMethod POST FOR SUBSCRIBER_ID...", __func__, pthread_self(), sesn_ptr, url_params.tokens[MESSAGE_DONATION_SUBSCRIPTION_URL_TOKEN_SUBSCRIBER_ID]->token);
    //todo check if this user actually owns the subscriber id
    const char *response = HandleDonationSubscriptionDefaultPaymentMethod(THREAD_CONTEXT_HTTP_REQUEST_CONTEXT, SESSION_USERID(sesn_ptr), url_params.tokens[MESSAGE_DONATION_SUBSCRIPTION_URL_TOKEN_SUBSCRIBER_ID]->token, url_params.tokens[MESSAGE_DONATION_SUBSCRIPTION_URL_TOKEN_PAYMENT_METHOD]->token);
    if (IS_EMPTY(response)) goto request_error;
    goto request_processed;
  } else if ((flags&OR_METHODS) == OR_DELETE) {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', subscriber_id:'%s'}: RECEIVED SUBSCRIPTION DELETE FOR SUBSCRIBER_ID...", __func__, pthread_self(), sesn_ptr, url_params.tokens[MESSAGE_DONATION_SUBSCRIPTION_URL_TOKEN_SUBSCRIBER_ID]->token);
    goto request_processed;
  } else {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: Unsupported HTTP Request method...", __func__, pthread_self(), sesn_ptr);
  }

  request_error:
  onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
  onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));

  request_processed:
  return OCS_PROCESSED;

#undef _THIS_PATH
#undef _MOCK_JSON_REPLY
#undef MESSAGE_DONATION_SUBSCRIPTION_MAX_URL_PARAMS_SZ
#undef MESSAGE_DONATION_SUBSCRIPTION_URL_TOKEN_SUBSCRIBER_ID
#undef MESSAGE_DONATION_SUBSCRIPTION_URL_TOKEN_PAYMENT_METHOD
}

/**
 * wget -q -O - --user=3J140H9YY5H43K608000000000 --password=DGvvRuIxzBUitDv5CcnQt9UM https://api.unfacd.io/V1/Donation/Subscription/Levels
 * @param instance_sesn_ptr
 * @return
 */
API_ENDPOINT_V1(DONATION_SUBSCRIPTION_LEVELS)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
  HttpSession 				*http_ptr = (HttpSession *)SESSION_PROTOCOL_SESSION_DATA(sesn_ptr);
  struct json_object 	*jobj_msg = NULL;

  #define _THIS_PATH	"/V1/Donation/Subscription/Levels"
//  #define _MOCK_JSON_REPLY "{\"levels\":{}}"
#define _MOCK_JSON_REPLY "{\"levels\": {\"1\":{ \"name\":\"Sustainer\", \"badge\":{ \"id\":\"S\", \"category\":\"Cat1\", \"name\":\"Sustainer\", \"description\": \"Sustainer level support.\", \"sprites6\":[\"l\", \"m\", \"h\", \"x\", \"xx/shield_with_heart_24dp.png\", \"xxx\"]}, \"currencies\": {\"USD\":10, \"AUD\":15}}, \"2\":{ \"name\":\"Promoter\", \"badge\":{ \"id\":\"P\", \"category\":\"Cat1\", \"name\":\"Promoter\", \"description\": \"Promoter level support\", \"sprites6\":[\"l\", \"m\", \"h\", \"x\", \"xx/shield_with_heart_24dp.png\", \"xxx\"]}, \"currencies\": {\"USD\":20, \"AUD\":30}}}}"

  int flags = onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));

  if ((flags&OR_METHODS) == OR_GET) {
    onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(_MOCK_JSON_REPLY));
    onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), _MOCK_JSON_REPLY, strlen(_MOCK_JSON_REPLY));
    goto request_processed;
  } else {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: Unsupported HTTP Request method...", __func__, pthread_self(), sesn_ptr);
  }

  request_error:
  onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
  onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));

  request_processed:
  return OCS_PROCESSED;

#undef _THIS_PATH
#undef _MOCK_JSON_REPLY
}

/**
 * wget -q -O - --user=3J140H9YY5H43K608000000000 --password=DGvvRuIxzBUitDv5CcnQt9UM https://api.unfacd.io/V1/Donation/Subscription/Boost/Amounts
 * @param instance_sesn_ptr
 * @return
 */
API_ENDPOINT_V1(DONATION_SUBSCRIPTION_BOOST_AMOUNTS)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
  HttpSession 				*http_ptr = (HttpSession *)SESSION_PROTOCOL_SESSION_DATA(sesn_ptr);
  struct json_object 	*jobj_msg = NULL;

#define _THIS_PATH	"/V1/Donation/Subscription/Boost/Amounts"
#define _MOCK_JSON_REPLY "{\"AU\":[100, 200]}"

  int flags = onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));

  if ((flags&OR_METHODS) == OR_GET) {
    onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(_MOCK_JSON_REPLY));
    onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), _MOCK_JSON_REPLY, strlen(_MOCK_JSON_REPLY));
    goto request_processed;
  } else {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: Unsupported HTTP Request method...", __func__, pthread_self(), sesn_ptr);
  }

  request_error:
  onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
  onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));

  request_processed:
  return OCS_PROCESSED;

#undef _THIS_PATH
#undef _MOCK_JSON_REPLY
}

/**
 * wget -q -O - --user=3J140H9YY5H43K608000000000 --password=DGvvRuIxzBUitDv5CcnQt9UM https://api.unfacd.io/V1/Donation/Subscription/Boost/Badges
 * @param instance_sesn_ptr
 * @return
 */
API_ENDPOINT_V1(DONATION_SUBSCRIPTION_BOOST_BADGES)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
  HttpSession 				*http_ptr = (HttpSession *)SESSION_PROTOCOL_SESSION_DATA(sesn_ptr);
  struct json_object 	*jobj_msg = NULL;

#define _THIS_PATH	"/V1/Donation/Subscription/Boost/Badges"
#define _MOCK_JSON_REPLY "{\"levels\": {\"1\":{ \"name\":\"Sustainer\", \"badge\":{ \"id\":\"S\", \"category\":\"Cat1\", \"name\":\"Sustainer\", \"description\": \"Sustainer level support.\", \"sprites6\":[\"l\", \"m\", \"h\", \"x\", \"shield_with_heart_24dp.png\", \"xx/shield_with_heart_24dp.png\"]}, \"currencies\": {\"USD\":10, \"AUD\":30}}, \"2\":{ \"name\":\"Promoter\", \"badge\":{ \"id\":\"P\", \"category\":\"Cat1\", \"name\":\"Promoter\", \"description\": \"Promoter level support\", \"sprites6\":[\"l\", \"m\", \"h\", \"x\", \"xx/shield_with_heart_24dp.png\", \"shield_with_heart_24dp.png\"]}, \"currencies\": {\"USD\":20, \"AUD\":30}}}}"

  int flags = onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));

  if ((flags&OR_METHODS) == OR_GET) {
    onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(_MOCK_JSON_REPLY));
    onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), _MOCK_JSON_REPLY, strlen(_MOCK_JSON_REPLY));
    goto request_processed;
  } else {
    syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: Unsupported HTTP Request method...", __func__, pthread_self(), sesn_ptr);
  }

  request_error:
  onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
  onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));

  request_processed:
  return OCS_PROCESSED;

#undef _THIS_PATH
#undef _MOCK_JSON_REPLY
}

/** @} */