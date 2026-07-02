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

#include <uflib/main_types.h>
#include <donations/donations_http_utils.h>
#include <thread_context_type.h>
#include <uflib/utils_base64url.h>
#include <http_request.h>
#include <uflib/utils_crypto.h>
#include <json/json.h>
#include <misc.h>
#include <donations/donation_descriptor_type.h>
#include <donations/utils_donations.h>

extern __thread ThreadContext ufsrv_thread_context;

static void _ConfirmNoError(HttpRequestContext *http_ptr, void(^on_no_error)(void));
static bool _CheckNoErrorInResponse(HttpRequestContext *http_ptr, void(^on_no_error)(json_object *jobj));

/**
 * @brief Create a stripe customer as per https://docs.stripe.com/api/customers/create.
 * @param http_ptr[IN] Http context containing pre-allocated objects necessary for handling http request, response and processing of response.
 * @param subscriber_id[IN] subscriber id associated with a donating user.
 * @dynamic_memory IMPORTS and DEALLOCATES 'char *' by _CreateIdempotencyKey()
 * @dynamic_memory EXPORTS 'char *'

  curl https://api.stripe.com/v1/customers \
  -u "your_key..." \
  -H "Idempotency-Key: KG5LxwFBepaKHyUD"
  -d "metadata[order_id]"=6735
 */
__attribute__ ((nonnul(1, 2), access(read, 2), ownership_returns(malloc)))
char *
StripeRequestNewCustomer(HttpRequestContext *http_ptr, DonationCustomerDescriptor *customer_descriptor_ptr)
{
#define STRIPE_API_CUSTOMERS "https://api.stripe.com/v1/customers"
  char *post_data = NULL;

  char *idempotency_key = NULL;//_CreateIdempotencyKey(customer_descriptor_ptr->subscriber_id, customer_descriptor_ptr->when, CUSTOMER_CREATE);

  asprintf(&post_data, "metadata[subscriber_id]=%s", customer_descriptor_ptr->subscriber_id);
  int result = HttpRequestPostUrl(http_ptr, STRIPE_API_CUSTOMERS, post_data, PPKS, idempotency_key, "application/x-www-form-urlencoded", 0L);
  if (result == 0) {
    syslog(LOG_ERR, "%s (pid:'%lu'): ERROR: COULD NOT POST URL '%s'", __func__, pthread_self(), post_data);
    free(post_data);
    free(idempotency_key);
    return NULL;
  }

  free(post_data);
  free(idempotency_key);

  do {
    http_ptr->jobj = json_tokener_parse_ex(http_ptr->jtok, http_ptr->rb.memory, strlen(http_ptr->rb.memory));
  } while ((http_ptr->jerr = json_tokener_get_error(http_ptr->jtok)) == json_tokener_continue);

  if (http_ptr->jerr != json_tokener_success) {
    syslog(LOG_NOTICE, "%s {pid:'%lu'}: ERROR JSON TOKENISER: '%s' ", __func__, pthread_self(), json_tokener_error_desc(http_ptr->jerr));

    return NULL;
  }

  const char *json_str_access_token = json_object_to_json_string(http_ptr->jobj);
  __block char *id = NULL;
  syslog(LOG_NOTICE, "%s {pid:'%lu'}: RECEIVED STRIPE CUSTOMER RESPONSE: '%s'", __func__, pthread_self(), json_str_access_token);
  _CheckNoErrorInResponse(http_ptr, ^(json_object *jobj){
      customer_descriptor_ptr->processor.customer_id = strdup(json_object_get_string(json__get(jobj, "id")));
      customer_descriptor_ptr->processor.when = json_object_get_int64(json__get(jobj, "created"));
      customer_descriptor_ptr->processor.state = CUSTOMER_CREATE;
  });

  return id;

#undef STRIPE_API_CUSTOMERS
}

static void
_ConfirmNoError(HttpRequestContext *http_ptr, void(^on_no_error)(void))
{
  const char *error = json_object_get_string(json__get(http_ptr->jobj, "error"));
  if (!IS_STR_LOADED(error)) {
    on_no_error();
    return;
  }

  syslog(LOG_NOTICE, "%s {pid:'%lu'}: ERROR STRIPE: error:'%s', error_description:'%s'", __func__, pthread_self(), error, json_object_get_string(json__get(http_ptr->jobj, "error_description")));
}

static bool
_CheckNoErrorInResponse(HttpRequestContext *http_ptr, void(^on_no_error)(json_object *jobj))
{
  const char *error = json_object_get_string(json__get(http_ptr->jobj, "error"));
  if (!IS_STR_LOADED(error)) {
    on_no_error(http_ptr->jobj);
    return true;
  }

  syslog(LOG_NOTICE, "%s {pid:'%lu'}: ERROR RESPONSE IN STRIPE MESSAGE: error:'%s', error_description:'%s'", __func__, pthread_self(), error, json_object_get_string(json__get(http_ptr->jobj, "error_description")));
  return false;
}

/**
 * @brief Create a client secrete for a previously created stripe customer as per https://docs.stripe.com/api/setup_intents & https://docs.stripe.com/payments/setup-intents.
 * @param http_ptr[IN] Http handling context containing data objects necessary for handling http request, response and processing of response.
 * @param subscriber_id[IN] subscriber id associated with a donating user.
 * @dynamic_memory IMPORTS and DEALLOCATES 'char *' by _CreateIdempotencyKey()
 * @dynamic_memory EXPORTS 'char *'

  curl https://api.stripe.com/v1/customers \
  -u "your_key..." \
  -H "Idempotency-Key: KG5LxwFBepaKHyUD"
  -d "metadata[order_id]"=6735
 */
__attribute__ ((nonnul(1, 2), access(read, 2), ownership_returns(malloc)))
char *
StripeCreateSetupIntent(HttpRequestContext *http_ptr, DonationCustomerDescriptor *customer_descriptor_ptr)
{
#define STRIPE_API_SETUP_INTENTS "https://api.stripe.com/v1/setup_intents"
  char *post_data = NULL;

  char *idempotency_key = NULL;//_CreateIdempotencyKey(customer_descriptor_ptr->subscriber_id, customer_descriptor_ptr->when, CUSTOMER_CREATE);

  asprintf(&post_data, "customer=%s", customer_descriptor_ptr->processor.customer_id);
  int result = HttpRequestPostUrl(http_ptr, STRIPE_API_SETUP_INTENTS, post_data, PPKS, idempotency_key, "application/x-www-form-urlencoded", 0L);
  if (result == 0) {
    syslog(LOG_ERR, "%s (pid:'%lu'): ERROR: COULD NOT POST URL '%s'", __func__, pthread_self(), post_data);
    free(post_data);
    free(idempotency_key);
    return NULL;
  }

  free(post_data);
  free(idempotency_key);

  do {
    http_ptr->jobj = json_tokener_parse_ex(http_ptr->jtok, http_ptr->rb.memory, strlen(http_ptr->rb.memory));
  } while ((http_ptr->jerr = json_tokener_get_error(http_ptr->jtok)) == json_tokener_continue);

  if (http_ptr->jerr != json_tokener_success) {
    syslog(LOG_NOTICE, "%s {pid:'%lu'}: ERROR JSON TOKENISER: '%s' ", __func__, pthread_self(), json_tokener_error_desc(http_ptr->jerr));

    return NULL;
  }

  const char *json_str_access_token = json_object_to_json_string(http_ptr->jobj);
  __block char *id = NULL;
  syslog(LOG_NOTICE, "%s {pid:'%lu'}: RECEIVED STRIPE CUSTOMER RESPONSE: '%s'", __func__, pthread_self(), json_str_access_token);
  _ConfirmNoError(http_ptr, ^(){
      customer_descriptor_ptr->processor.token = strdup(json_object_get_string(json__get(http_ptr->jobj, "client_secret")));
      customer_descriptor_ptr->processor.when = json_object_get_int64(json__get(http_ptr->jobj, "created"));
      customer_descriptor_ptr->processor.state = INTENT_SETUP;
  });

  return id;

#undef STRIPE_API_SETUP_INTENTS
}

/**
 * @brief Update customer object at payment processor stripe. Handles one property at a time only for now.
 * @param http_ptr[in] Http context containing pre-allocated objects necessary for handling http request, response and processing of response.
 * @param customer_descriptor_ptr[in]
 * @param property stripe-specific property to be updated
 * @param property value to update \p property with
 * @return
 */
__attribute__ ((nonnul(1, 2), access(read, 2), ownership_returns(malloc)))
char *
StripeUpdateCustomer(HttpRequestContext *http_ptr, DonationCustomerDescriptor *customer_descriptor_ptr, const char *property, enum SubscriptionProcessorState state_processor, void (^on_no_error)(json_object *))
{
#define STRIPE_API_CUSTOMERS_WITH_ID "https://api.stripe.com/v1/customers/%s"
  char *url_params = NULL;

  char *idempotency_key = NULL;//_CreateIdempotencyKey(customer_descriptor_ptr->subscriber_id, customer_descriptor_ptr->when, state_processor);

  asprintf(&url_params, STRIPE_API_CUSTOMERS_WITH_ID, customer_descriptor_ptr->processor.customer_id);
  int result = HttpRequestPostUrl(http_ptr, url_params, property, PPKS, idempotency_key, "application/x-www-form-urlencoded", 0L);
  if (result == 0) {
    syslog(LOG_ERR, "%s (pid:'%lu'): ERROR: COULD NOT POST URL '%s'", __func__, pthread_self(), property);
    free(url_params);
    free(idempotency_key);
    return NULL;
  }

  free(url_params);
  free(idempotency_key);

  do {
    http_ptr->jobj = json_tokener_parse_ex(http_ptr->jtok, http_ptr->rb.memory, strlen(http_ptr->rb.memory));
  } while ((http_ptr->jerr = json_tokener_get_error(http_ptr->jtok)) == json_tokener_continue);

  if (http_ptr->jerr != json_tokener_success) {
    syslog(LOG_NOTICE, "%s {pid:'%lu'}: ERROR JSON TOKENISER: '%s' ", __func__, pthread_self(), json_tokener_error_desc(http_ptr->jerr));

    return NULL;
  }

  const char *json_str = json_object_to_json_string(http_ptr->jobj);
  syslog(LOG_NOTICE, "%s {pid:'%lu'}: RECEIVED STRIPE CUSTOMER RESPONSE: '%s'", __func__, pthread_self(), json_str);
 if (_CheckNoErrorInResponse(http_ptr, on_no_error)) return "";

  return NULL;

#undef STRIPE_API_CUSTOMERS_WITH_ID
}

/**
 * @brief Create a subscription for customer as per https://docs.stripe.com/api/subscriptions/create.
 * @param http_ptr[in] Http context containing pre-allocated objects necessary for handling http request, response and processing of response.
 * @param customer_descriptor_ptr[in]
 * @return subscription id saved in DonationCustomerDescriptor.processor.subscription_id
 * @dynamic_memory EXPORTS 'char *' in DonationCustomerDescriptor.processor.subscription_id
 * @dynamic_memory EXPORTS 'char *' in SubscriptionLevelDescriptor.price_info.currency_code
 */
__attribute__ ((nonnul(1, 2), access(read, 2)))
char *
StripeSubscriptionCreate(HttpRequestContext *http_ptr, DonationCustomerDescriptor *customer_descriptor_ptr, SubscriptionLevelDescriptor *subscription_descriptor_ptr)
{
#define STRIPE_API_SUBSCRIPTIONS "https://api.stripe.com/v1/subscriptions"
  char *post_data = NULL;
  char *url_params = NULL;

  asprintf(&url_params, "%s/%s", STRIPE_API_SUBSCRIPTIONS, customer_descriptor_ptr->processor.customer_id);
  asprintf(&post_data, "customer=%s&"
                       "items[0][price]=%s&"
                       "metadata[subscriber_id]=%s&"
                       "metadata[level]=%u",
                       customer_descriptor_ptr->processor.customer_id, subscription_descriptor_ptr->price_id_processor, customer_descriptor_ptr->subscriber_id, customer_descriptor_ptr->level_id);
  int result = HttpRequestPostUrl(http_ptr, STRIPE_API_SUBSCRIPTIONS, post_data, PPKS, customer_descriptor_ptr->idempotency_key, "application/x-www-form-urlencoded", 0L);
  if (result == 0) {
    syslog(LOG_ERR, "%s (pid:'%lu'): ERROR: COULD NOT POST URL '%s'", __func__, pthread_self(), post_data);
    free(url_params);
    free(post_data);
    return NULL;
  }

  free(url_params);
  free(post_data);

  do {
    http_ptr->jobj = json_tokener_parse_ex(http_ptr->jtok, http_ptr->rb.memory, strlen(http_ptr->rb.memory));
  } while ((http_ptr->jerr = json_tokener_get_error(http_ptr->jtok)) == json_tokener_continue);

  if (http_ptr->jerr != json_tokener_success) {
    syslog(LOG_NOTICE, "%s {pid:'%lu'}: ERROR JSON TOKENISER: '%s' ", __func__, pthread_self(), json_tokener_error_desc(http_ptr->jerr));

    return NULL;
  }

  const char *json_str_subscription = json_object_to_json_string(http_ptr->jobj);
  syslog(LOG_NOTICE, "%s {pid:'%lu'}: RECEIVED STRIPE SUBSCRIPTION RESPONSE: '%s'", __func__, pthread_self(), json_str_subscription);
  bool no_error = _CheckNoErrorInResponse(http_ptr, ^(json_object *jobj_ptr){
                      customer_descriptor_ptr->processor.when = json_object_get_int64(json__get(jobj_ptr, "created"));
                      customer_descriptor_ptr->processor.state = SUBSCRIPTION_CREATED;
                      customer_descriptor_ptr->processor.subscription_id = strndup(json_object_get_string(json__get(jobj_ptr, "id")), SMALLBUF);
                      SubscriptionLevelDescriptor subscription_descriptor = {0};
                      if (StripeSubscriptionGetPriceFromObject(jobj_ptr, &subscription_descriptor)) {
                        customer_descriptor_ptr->amount = subscription_descriptor_ptr->price_info.amount = subscription_descriptor.price_info.amount;
                        subscription_descriptor_ptr->price_info.currency_code = strdup(subscription_descriptor.price_info.currency_code);
                        customer_descriptor_ptr->currency_code = subscription_descriptor_ptr->price_info.currency_code;
                      }
                  });

  if (no_error) return "";

  return NULL;

#undef STRIPE_API_SUBSCRIPTIONS
}

/**
 * As per https://docs.stripe.com/api/subscriptions/retrieve
 * @param http_ptr
 * @param customer_descriptor_ptr
 * @return
 */
int
StripeSubscriptionGet(HttpRequestContext *http_ptr, DonationCustomerDescriptor *customer_descriptor_ptr, void (^on_response_available)(json_object *))
{
#define STRIPE_API_SUBSCRIPTIONS_GET "https://api.stripe.com/v1/subscriptions/"
  int http_response_code = HttpRequestGetUrlInJson(http_ptr, STRIPE_API_SUBSCRIPTIONS_GET, customer_descriptor_ptr->processor.subscription_id, PPKS);
  if (http_response_code == 200) {
    if (IS_PRESENT(on_response_available)) {
      on_response_available(http_ptr->jobj);
    }
  } else if (http_response_code > 0){
    syslog(LOG_NOTICE, "%s {pid:'%lu', http_response:'%u'}: ERROR GET RESPONSE OTHER THAN 200: '%s' ", __func__, pthread_self(), http_response_code, json_tokener_error_desc(http_ptr->jerr));
  } else {
    //curl lib error
  }

  return http_response_code;

#undef STRIPE_API_SUBSCRIPTIONS_GET
}

/**
 * As per https://docs.stripe.com/api/customers/retrieve
 * @param http_ptr
 * @param customer_descriptor_ptr
 * @param on_response_available
 * @return
 */
int
StripeCustomerGet(HttpRequestContext *http_ptr, DonationCustomerDescriptor *customer_descriptor_ptr, void (^on_response_available)(json_object *))
{
#define STRIPE_API_CUSTOMERS_GET "https://api.stripe.com/v1/customers/"
  int http_response_code = HttpRequestGetUrlInJson(http_ptr, STRIPE_API_CUSTOMERS_GET, customer_descriptor_ptr->processor.customer_id, PPKS);
  if (http_response_code == 200) {
    if (IS_PRESENT(on_response_available)) {
      on_response_available(http_ptr->jobj);
    }
  } else if (http_response_code > 0){
    syslog(LOG_NOTICE, "%s {pid:'%lu', http_response:'%u'}: ERROR GET RESPONSE OTHER THAN 200: '%s' ", __func__, pthread_self(), http_response_code, json_tokener_error_desc(http_ptr->jerr));
  } else {
    //curl lib error
  }

  return http_response_code;

#undef STRIPE_API_CUSTOMERS_GET
}

/**
 * As per https://docs.stripe.com/api/subscriptions/list
 * data[{"object":"subscription", items:{data:[{"object":"subscription", plan:{..}, price:{..}...}, {...}]}}, {...}]
 * @param customer_descriptor_ptr
 * @param subscription_descriptor_ptr
 * @param on_response_available
 * @return http response code
 */
int
StripeSubscriptionGetForCustomer(HttpRequestContext *http_ptr, DonationCustomerDescriptor *customer_descriptor_ptr, void (^on_response_available)(json_object *))
{
#define STRIPE_API_SUBSCRIPTIONS_CUSTOMER_GET "https://api.stripe.com/v1/subscriptions"
  char *customer[1] = {0};
  customer[0] = STRINGIFY_PARAMETER("customer=%s", customer_descriptor_ptr->processor.customer_id);
  CollectionDescriptor collection_query_params = {.collection=(collection_t **)customer, .collection_sz=1};

  int http_response_code = HttpRequestGetUrlWithQueryParamsInJson(http_ptr, STRIPE_API_SUBSCRIPTIONS_CUSTOMER_GET, _EMPTY_STR, PPKS, &collection_query_params);
  if (http_response_code == 200) {
    if (IS_PRESENT(on_response_available)) {
      on_response_available(http_ptr->jobj);
    }
  } else if (http_response_code > 0){
    syslog(LOG_NOTICE, "%s {pid:'%lu', http_response:'%u'}: ERROR GET RESPONSE OTHER THAN 200: jerr: '%s' ", __func__, pthread_self(), http_response_code, json_tokener_error_desc(http_ptr->jerr));
  } else {
    //curl lib error
  }

  return http_response_code;

#undef STRIPE_API_SUBSCRIPTIONS_CUSTOMER_GET
}

/** cancel_at_period_end
 * @brief Update a single property for a subscription object as per https://docs.stripe.com/api/subscriptions/update
 * @param customer_descriptor_ptr
 * @param property fully parameterised property/value in the form of "property=value"
 * @param state_processor
 * @param on_no_error
 * @return
 */
__attribute__ ((nonnul(1, 2), access(read, 2), ownership_returns(malloc)))
char *
StripeUpdateSubscription(HttpRequestContext *http_ptr, DonationCustomerDescriptor *customer_descriptor_ptr, const char *property, enum SubscriptionProcessorState state_processor, void (^on_no_error)(json_object *))
{
#define STRIPE_API_UPDATE_SUBSCRIPTION "https://api.stripe.com/v1/subscriptions/%s"
  char *url_params = NULL;

  char *idempotency_key = NULL;//_CreateIdempotencyKey(customer_descriptor_ptr->subscriber_id, customer_descriptor_ptr->when, state_processor);

  asprintf(&url_params, STRIPE_API_UPDATE_SUBSCRIPTION, customer_descriptor_ptr->processor.subscription_id);
  int result = HttpRequestPostUrl(http_ptr, url_params, property, PPKS, idempotency_key, "application/x-www-form-urlencoded", 0L);
  if (result == 0) {
    syslog(LOG_ERR, "%s (pid:'%lu'): ERROR: COULD NOT POST URL '%s'", __func__, pthread_self(), property);
    free(url_params);
    free(idempotency_key);
    return NULL;
  }

  free(url_params);
  free(idempotency_key);

  do {
    http_ptr->jobj = json_tokener_parse_ex(http_ptr->jtok, http_ptr->rb.memory, strlen(http_ptr->rb.memory));
  } while ((http_ptr->jerr = json_tokener_get_error(http_ptr->jtok)) == json_tokener_continue);

  if (http_ptr->jerr != json_tokener_success) {
    syslog(LOG_NOTICE, "%s {pid:'%lu'}: ERROR JSON TOKENISER: '%s' ", __func__, pthread_self(), json_tokener_error_desc(http_ptr->jerr));

    return NULL;
  }

  const char *json_str = json_object_to_json_string(http_ptr->jobj);
  syslog(LOG_NOTICE, "%s {pid:'%lu'}: RECEIVED STRIPE CUSTOMER RESPONSE: '%s'", __func__, pthread_self(), json_str);
  if (_CheckNoErrorInResponse(http_ptr, on_no_error)) return "";

  return NULL;

#undef STRIPE_API_UPDATE_SUBSCRIPTION
}

int
StripeProductGet(HttpRequestContext *http_ptr, DonationCustomerDescriptor *customer_descriptor_ptr, SubscriptionLevelDescriptor *subscription_descriptor_ptr, void (^on_response_available)(json_object *))
{
#define STRIPE_API_PRODUCTS_GET "https://api.stripe.com/v1/products/"
  int http_response_code = HttpRequestGetUrlInJson(http_ptr, STRIPE_API_PRODUCTS_GET, subscription_descriptor_ptr->product_id_processor, PPKS);
  if (http_response_code == 200) {
    if (IS_PRESENT(on_response_available)) {
      on_response_available(http_ptr->jobj);
    }
  } else if (http_response_code > 0){
    syslog(LOG_NOTICE, "%s {pid:'%lu', http_response:'%u'}: ERROR GET RESPONSE OTHER THAN 200: '%s' ", __func__, pthread_self(), http_response_code, json_tokener_error_desc(http_ptr->jerr));
  } else {
    //curl lib error
  }

  return http_response_code;

#undef STRIPE_API_PRODUCTS_GET
}

/**
 * @brief Get subscription level associated with processor's product id
 * @return level id as recorded at ufsrv
 *  "metadata": {
    "level_id": "1"
  }
 */
int
StripeLevelGetForProduct(HttpRequestContext *http_ptr, const char *product_id)
{
#define STRIPE_API_PRODUCTS_GET "https://api.stripe.com/v1/products/"
  int http_response_code = HttpRequestGetUrlInJson(http_ptr, STRIPE_API_PRODUCTS_GET, product_id, PPKS);
  if (http_response_code == 200) {
    json_object *jobj_ptr_metadata = json__get(http_ptr->jobj, "metadata");
    return json_object_get_int(json_object_object_get(jobj_ptr_metadata, "level_id"));
  } else if (http_response_code > 0){
    syslog(LOG_NOTICE, "%s {pid:'%lu', http_response:'%u'}: ERROR GET RESPONSE OTHER THAN 200: '%s' ", __func__, pthread_self(), http_response_code, json_tokener_error_desc(http_ptr->jerr));
  } else {
    //curl lib error
  }

  return http_response_code;

#undef STRIPE_API_PRODUCTS_GET
}