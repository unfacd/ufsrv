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

#include <thread_context_type.h>
#include <uflib/utils_crypto.h>
#include <donations/utils_donations.h>
#include <uflib/utils_base64url.h>
#include <json_attribute_names_account.h>
#include <misc.h>
#include <utils_db_account.h>
#include <user/user_backend.h>
#include <uflib/db/db_op_descriptor_type.h>
#include <uflib/db/dp_ops.h>

extern __thread ThreadContext ufsrv_thread_context;

static DonationsSubscriberId *_GenerateSubscriberId(DonationsSubscriberId *subscriber_id_ptr_out, bool is_encoded);

/**
 * @brief Provide serialised json donations  node/token initialised to defaults. Mostly for Db Account creation purpose.
 * @return serialised json OR NULL on error
 * @dynamic_memory EXPORTS 'char *' from asprintf() if is_generated_id is true.
 */
__attribute__ ((ownership_returns(malloc))) char *
ProvideDefaultDonationsDbAccount(bool is_generate_id)
{
  if (is_generate_id) {
#pragma region allocate static buffers
    DonationsSubscriberId subscriber_id = {0};
    unsigned char subscriber_id_encoded[GetBase64BufferAllocationSize(CONFIG_DONATIONS_SUBSCRIBER_ID_SZ)]; memset(subscriber_id_encoded, 0, sizeof(subscriber_id_encoded));
    unsigned char subscriber_id_raw[CONFIG_DONATIONS_SUBSCRIBER_ID_SZ] = {0};
    subscriber_id.buffer_descriptor_raw.data = (char *)subscriber_id_raw;
    subscriber_id.buffer_descriptor_raw.size = CONFIG_DONATIONS_SUBSCRIBER_ID_SZ;
    subscriber_id.buffer_descriptor_encoded.data = (char *)subscriber_id_encoded;
#pragma endregion

    if (IS_PRESENT(_GenerateSubscriberId(&subscriber_id, true))) {
      char *json_str;
      if (asprintf(&json_str, "{\"subscriber_id\":\"%s\", \"currency\": \"\", \"subscription_level\":0}", subscriber_id_encoded) > 0) {
        return json_str;
      } else return NULL;
    } else return NULL;
  }

  return "{\"subscriber_id\":\"\", \"currency\": \"\", \"subscription_level\":0}";
}

/**
 * @brief Provides serialised subscriber id.
 * @return serialised id OR NULL on error
 * @dynamic_memory EXPORTS char *
 */
__attribute__ ((ownership_returns(malloc))) char *
ProvideNewSubscriberId(void)
{
#pragma region allocate static buffers
  DonationsSubscriberId subscriber_id = {0};
  unsigned char subscriber_id_raw[CONFIG_DONATIONS_SUBSCRIBER_ID_SZ] = {0};
  subscriber_id.buffer_descriptor_raw.data = (char *)subscriber_id_raw;
  subscriber_id.buffer_descriptor_raw.size = CONFIG_DONATIONS_SUBSCRIBER_ID_SZ;
  subscriber_id.buffer_descriptor_encoded.data = (char *)calloc(1, GetBase64BufferAllocationSize(CONFIG_DONATIONS_SUBSCRIBER_ID_SZ));
#pragma endregion

  if (IS_PRESENT(_GenerateSubscriberId(&subscriber_id, true))) {
   return subscriber_id.buffer_descriptor_encoded.data;
  }

  return NULL;

}

/**
 * 	@brief Look up the subscriber id for user.
 *
 * 	@param username registration id (email)
 * 	@dynamic_memory EXPORTS char *
 */
__unused char *
GetAccountDonationsSubscriptionId(const char *username)
{
  DbAccountDataAttributeGetTextByUsername(username, "donations.subscriber_id");
  if (THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA) {
    return ((char *)THREAD_CONTEXT_UFSRV_RESULT_USERDATA);
  }

  return NULL;

}

/**
 * Caller is responsible for allocating all buffers
 * @param subscriber_id_ptr_out
 * @return
 */
DonationsSubscriberId *
_GenerateSubscriberId(DonationsSubscriberId *subscriber_id_ptr_out, bool is_encoded)
{
  if (subscriber_id_ptr_out->buffer_descriptor_raw.size != CONFIG_DONATIONS_SUBSCRIBER_ID_SZ) return NULL;
  GenerateSecureRandom((unsigned char *)subscriber_id_ptr_out->buffer_descriptor_raw.data, CONFIG_DONATIONS_SUBSCRIBER_ID_SZ);
  if (is_encoded) {
    base64url_encode((unsigned char *)subscriber_id_ptr_out->buffer_descriptor_raw.data, subscriber_id_ptr_out->buffer_descriptor_raw.size, (unsigned char *)subscriber_id_ptr_out->buffer_descriptor_encoded.data);
    subscriber_id_ptr_out->buffer_descriptor_encoded.size = strlen(subscriber_id_ptr_out->buffer_descriptor_encoded.data);
  }

  return subscriber_id_ptr_out;
}


static json_object *_TransformDonationsJsonObject(const char *json_str, bool is_struct_transfer, bool is_generate_id, DonationDescriptor *descriptor_ptr_out);

/**
 * @brief Query the DB backend and retrieve donation values.
 * @param userid sequence id representing user account
 * @param descriptor_ptr[INOUT] User allocated
 * @return NULL on error
 */
DonationDescriptor *
GetDonationsTokenForAccountUpgrade(unsigned long userid, DonationDescriptor *descriptor_ptr_out)
{
  return DbAccountGetDonations(userid, false, false, true, descriptor_ptr_out); //note no struct transfer, so no need to deallocate DonationDescriptor members
}

/**
 * @brief Provide a raw json object representing donations token initialised with defaults.
 * @param is_generate_id if true, the subscription_id will be patched into the otherwise default values
 * @return binary json object
 * @dynamic_memory IMPORTS / DEALLOCATES 'char *' from ProvideDefaultDonationsDbAccount if is_generate_id is true
 * @dynamic_memory EXPORTS 'json_object *'
 */
__attribute__ ((ownership_returns(malloc))) json_object *
ProvideDefaultDonationsJsonToken(bool is_generate_id)
{
  char *json_str = ProvideDefaultDonationsDbAccount(is_generate_id);
  if (IS_EMPTY(json_str)) return NULL;

  json_object *jobj = NULL;
  enum json_tokener_error jerr;
  struct json_tokener *jtok = json_tokener_new();

  do {
    jobj = json_tokener_parse_ex(jtok, json_str, strlen(json_str));
  } while ((jerr = json_tokener_get_error(jtok)) == json_tokener_continue);

  if (jerr != json_tokener_success) {
    syslog(LOG_NOTICE, "%s {pid:'%lu', json:'%s'}: JSON tokeniser Error: '%s'...", __func__, pthread_self(), json_tokener_error_desc(jerr), json_str);

    if (is_generate_id) free(json_str);
    return NULL;
  }

  tokeniser_success:
  if (is_generate_id) free(json_str);
  json_tokener_free(jtok);
  return jobj;
}

/**
 * @brief A utility function to retrieve and transform db-stored donations token into raw json object.
 * @param json_str[in] serialised json
 * @param is_struct_transfer is set, json values will be transferred to DonationDescriptor by 'copy'
 * @param descriptor_ptr_out[inout] Data structure representing stored donations values
 * @param is_generate_id if true, a new subscriber id will be generated if user's account didn't store one already (this is a temporary semantics)
 * @return Allocated raw json object representing supplied serialised json
 * @dynamic_memory EXPORTS 'char *' into DonationDescriptor members if is_struct_transfer is strue
 */
__attribute__ ((const, nonnull(1), access(read, 1)))  static json_object *
_TransformDonationsJsonObject(const char *json_str, bool is_struct_transfer, bool is_generate_id, DonationDescriptor *descriptor_ptr_out)
{
  struct json_object *jobj_donations = NULL;

  syslog(LOG_DEBUG, "%s {pid:'%lu', json:'%s'}: Account: donation token...", __func__, pthread_self(), json_str);

  enum json_tokener_error jerr;
  struct json_tokener *jtok = json_tokener_new();

  do {
    jobj_donations = json_tokener_parse_ex(jtok, json_str, strlen(json_str));
  } while ((jerr = json_tokener_get_error(jtok)) == json_tokener_continue);

  if (jerr != json_tokener_success) {
    syslog(LOG_NOTICE, "%s {pid:'%lu', json:'%s'}: JSON tokeniser Error: '%s'...", __func__, pthread_self(), json_tokener_error_desc(jerr), json_str);

    return NULL;
  }

  tokeniser_success:
  json_tokener_free(jtok);

#pragma region data structure transfer block
  char *subscriber_id_generated = NULL;
  const char *stored_value = json_object_get_string(json__get(jobj_donations, ACCOUNT_JSONATTR_SUBSCRIBER_ID));
  if (!IS_STR_LOADED(stored_value)) {
    if (is_generate_id) {
      json_object_object_del(jobj_donations, ACCOUNT_JSONATTR_SUBSCRIBER_ID);
      subscriber_id_generated = ProvideNewSubscriberId();
      json_object_object_add(jobj_donations, ACCOUNT_JSONATTR_SUBSCRIBER_ID, json_object_new_string(subscriber_id_generated));
      if (is_struct_transfer && IS_PRESENT(descriptor_ptr_out)) {
        descriptor_ptr_out->subscriber_id = subscriber_id_generated;//this can be deallocated
      } else free(subscriber_id_generated);
    } //else value is left null, including inside passed struct
  } else {
    if (is_struct_transfer && IS_PRESENT(descriptor_ptr_out)) {
      descriptor_ptr_out->subscriber_id = strdup(stored_value);//this can be deallocated
    }
  }

  if (is_struct_transfer && IS_PRESENT(descriptor_ptr_out)) {
    stored_value = json_object_get_string(json__get(jobj_donations, ACCOUNT_JSONATTR_CURRENCY));
    if (IS_STR_LOADED(stored_value)) descriptor_ptr_out->currency = strdup(stored_value);
    descriptor_ptr_out->subscription_id = json_object_get_int(json__get(jobj_donations, ACCOUNT_JSONATTR_SUBSCRIPTION_LEVEL));

    descriptor_ptr_out->is_struct_transfer = true;
  }
#pragma endregion

  return jobj_donations;
}

/**
 * @brief Retrieve stored donations values for a given account.
 * @param userid account identification as a sequence id
 * @param is_struct_transfer is set, json values will be transferred to the DonationDescriptor member fields by dynamic memory copy
 * @param is_serialised if set, the serialised json token as stored in the db is returned in DonationDescriptor.serialised
 * @param is_raw if set, the raw json object successfully parsed from copy as stored in the db is returned in DonationDescriptor.raw
 * @param kbs_descriptor_ptr_out[inout] User-allocated return structure, If not provided, a dynamic memory allocation will be used
 * @return DonationDescriptor on success, otherwise NULL
 * @dynamic_memory EXPORTS 'char *'  is_serialised or DonationDescriptor.serialised if either or both true
 * @dynamic_memory EXPORTS 'json_object *'  is_raw DonationDescriptor.raw if either or both true
 * @dynamic_memory EXPORTS 'DonationDescriptor *'  if descriptor_ptr_out is not provided by caller
 * @dynamic_memory EXPORTS 'char *' DonationDescriptor member fields if is_struct_transfer is true
 */
DonationDescriptor *
DbAccountGetDonations(unsigned long userid, bool is_struct_transfer, bool is_serialised, bool is_raw, DonationDescriptor *descriptor_ptr_out)
{
  DonationDescriptor *descriptor_ptr = NULL;

  if (IS_PRESENT(descriptor_ptr_out)) descriptor_ptr = descriptor_ptr_out;
  else {
    descriptor_ptr = calloc(1, sizeof(DonationDescriptor));
  }

  DbAccountDataAttributeGetText(userid, ACCOUNT_JSONATTR_DONATIONS);
  if (THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA) {
    json_object *jobj = _TransformDonationsJsonObject((char *) THREAD_CONTEXT_UFSRV_RESULT_USERDATA, is_struct_transfer, true, descriptor_ptr);
    if (IS_PRESENT(jobj)) { //successfully retrieved and tokenised
      if (is_serialised) {
        descriptor_ptr->serialised.jobj_str = THREAD_CONTEXT_UFSRV_RESULT_USERDATA; //originally from DbAccountDataUserAttributeGetText()
        descriptor_ptr->serialised.is_set = true;
      } else {
        free(THREAD_CONTEXT_UFSRV_RESULT_USERDATA);
        descriptor_ptr->serialised.is_set = false;
      }

      if (is_raw) {
        descriptor_ptr->raw.jobj = jobj;
        descriptor_ptr->raw.is_set = true;
      } else {
        json_object_put(jobj);
        descriptor_ptr->raw.is_set = false;
      }

      return descriptor_ptr;
    }
  }

  return_error:
  if (IS_EMPTY(descriptor_ptr_out)) free(descriptor_ptr);
  return NULL;
}

/**
 * @brief Perform whole-of-token update for donations
 * @param descriptor_ptr[in] user provided and loaded with relevant values
 * @param userid user sequence id
 * @return
 */
__attribute__ ((const, nonnull(2), access(read_only, 2)))  int
DbAccountUpdateDonations(unsigned long userid, DonationDescriptor *descriptor_ptr)
{
#define SQL_UPDATE_ACCOUNT_DONATIONS "UPDATE accounts SET data = JSON_MERGE_PATCH(data, '{\"donations\":{\"subscriber_id\":\"%s\", \"currency\": \"%s\", \"subscription_level\":\"%u\"}}') WHERE id = '%lu'"

  char *sql_query_str = mdsprintf(SQL_UPDATE_ACCOUNT_DONATIONS, descriptor_ptr->subscriber_id, descriptor_ptr->currency, descriptor_ptr->subscription_id, userid);

#ifdef __UF_FULLDEBUG
  syslog(LOG_DEBUG, "%s: GENERATED SQL QUERY: '%s'", __func__, sql_query_str);
#endif

  int sql_result = h_query_update(THREAD_CONTEXT_DB_BACKEND, sql_query_str);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, "%s: ERROR: COULD EXECUTE QUERY: '%s'", __func__, sql_query_str);
  }

  free(sql_query_str);

  return sql_result;

#undef SQL_UPDATE_ACCOUNT_DONATIONS
}

__attribute__ ((const, nonnull(2), access(read_only, 2))) int
DbAccountUpdateDonationsSubscriberId(unsigned long userid, DonationDescriptor *descriptor_ptr)
{
#define SQL_UPDATE_ACCOUNT_DATA_STRING 	 "UPDATE accounts SET data_user = JSON_REPLACE(data, '$.donations.subscriber_id', '%s') WHERE id = '%lu'"

  char *sql_query_str = "";

  sql_query_str = mdsprintf(SQL_UPDATE_ACCOUNT_DATA_STRING, descriptor_ptr->subscriber_id, userid);


#ifdef __UF_FULLDEBUG
  syslog(LOG_DEBUG, "%s: GENERATED SQL QUERY: '%s'", __func__, sql_query_str);
#endif

  int sql_result = h_query_update(THREAD_CONTEXT_DB_BACKEND, sql_query_str);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, "%s: ERROR: COULD EXECUTE QUERY: '%s'", __func__, sql_query_str);
  }

  if (IS_STR_LOADED(sql_query_str)) free(sql_query_str);

  return sql_result;

#undef SQL_UPDATE_ACCOUNT_DATA_STRING
}

/**
 * @brief Provide raw json node, describing donations.
 * @param sesn_ptr user session for donations
 * @return raw json
 * @dynamic_memory EXPORTS "json_object *'
 */
__attribute__ ((nonnull(1), access(read_only, 1), ownership_returns(malloc)))
struct json_object *
JsonFormatUserDonations(Session *sesn_ptr)
{
  DonationDescriptor donations_descriptor = {0};
  DbAccountGetDonations(SESSION_USERID(sesn_ptr), false, false, true, &donations_descriptor);

  return donations_descriptor.raw.jobj;
}

#include <donations/donations_http_utils.h>
#include <donations/donation_customer_descriptor_type.h>
#include <donations/donations_db_utils.h>

/**
 *
 * @param http_ctx_ptr[in] Http context containing pre-allocated objects necessary for handling http request, response and processing of response.
 * @param user_id
 * @param subscriber_id
 * @return processor specific customer id
 * @dynamic_memory EXPORTS 'char *' from customer_descriptor.processor.token
 */
const char *
HandleDonationPipelineInitiated(HttpRequestContext *http_ctx_ptr, unsigned long user_id, const char *subscriber_id, enum  PaymentProcessor payment_processor)
{
  DonationCustomerDescriptor customer_descriptor = {0};
  DbOpDescriptor db_descriptor_get_customer = {0};
  bool is_customer_exist = false;

  if (!IsDonationCustomerExist(user_id, &customer_descriptor, &db_descriptor_get_customer, ^(DonationCustomerDescriptor *customer_descriptor_ptr, DbOpDescriptor *db_descriptor_ptr) {})) {
    customer_descriptor.level_id = 1; //todo load actual
    customer_descriptor.currency_code = "AUD";
    customer_descriptor.amount = 0; //will be updated later once subscription is confirmed
    customer_descriptor.when = time(NULL);
    customer_descriptor.subscriber_id = subscriber_id;
    customer_descriptor.user_id = user_id;
    customer_descriptor.processor.token = "";
    customer_descriptor.payment_processor = payment_processor;
    StripeRequestNewCustomer(http_ctx_ptr, &customer_descriptor);
    if (customer_descriptor.processor.state == CUSTOMER_CREATE) {
      DbOpDescriptor db_descriptor = {0};
      DbBackendInsertDonationPipeline(&db_descriptor, &customer_descriptor);
    } else {
      syslog(LOG_ERR, "%s{userid:'%lu'}: ERROR: COULD NOT CREATE STRIPE CUSTOMER FOR: '%s'", __func__,  user_id, subscriber_id);
      return NULL;
    }
  } else {
    is_customer_exist = true;
    syslog(LOG_NOTICE, "%s {userid:'%lu'}: NOTICE: FOUND DONATIONS CUSTOMER CREATED: '%s'", __func__, user_id, subscriber_id);
  }

  StripeCreateSetupIntent(http_ctx_ptr, &customer_descriptor);
  if (customer_descriptor.processor.state == INTENT_SETUP) {
    DbOpDescriptor db_descriptor = {0};
    DbBackendInsertDonationPipeline(&db_descriptor, &customer_descriptor);
    DbBackendInsertDonation(&db_descriptor, &customer_descriptor);
    if (!is_customer_exist) free((char *)customer_descriptor.processor.customer_id); //other leave it to result-set clean up below: value originated from db
  } else {
    syslog(LOG_ERR, "%s: ERROR: COULD NOT SETUP INTENT FOR: '%s'", __func__, subscriber_id);
  }

  if (is_customer_exist) {
    DBOP_DESCRIPTOR_INVOKE_RESULT_FINALISER_IF_PRESENT(&db_descriptor_get_customer);
  }

  return customer_descriptor.processor.token;
}

/**
 * @brief Update default payment method for a given donation subscription by \p user_id.
 * @param http_ctx_ptr[in] Http context containing pre-allocated objects necessary for handling http request, response and processing of response.
 * @param user_id user for which update is requested
 * @param subscriber_id
 * @param payment_method processor specific token
 * @return
 */
const char *
HandleDonationSubscriptionDefaultPaymentMethod(HttpRequestContext *http_ctx_ptr, unsigned long user_id, __unused const char *subscriber_id, const char *payment_method)
{
  __block DonationCustomerDescriptor customer_descriptor = {0};
  DbOpDescriptor db_descriptor = {0};
  customer_descriptor.user_id = user_id;
  DbBackendGetDonationsSubscription(&customer_descriptor, &db_descriptor);

  //"invoice_settings": { "default_payment_method": "pm_1SBwWK0177d9EkzfsAefrSh9"}
  char *payment_method_str;
  asprintf(&payment_method_str, "invoice_settings[default_payment_method]=%s", payment_method);
  char *response = StripeUpdateCustomer(http_ctx_ptr, &customer_descriptor, payment_method_str, DEFAULT_PAYMENT_METHOD, ^(json_object *jobj) {
      customer_descriptor.processor.when = json_object_get_int64(json__get(jobj, "created"));
      customer_descriptor.processor.state = CUSTOMER_UPDATED;
      customer_descriptor.payment_method_id = payment_method;
  });
  if (IS_PRESENT(response)) {
    customer_descriptor.processor.state = DEFAULT_PAYMENT_METHOD;
    DbBackendUpdateDonationsSubscription(&customer_descriptor, &db_descriptor, "payment_method_token", payment_method);
    DbBackendInsertDonationPipeline(&db_descriptor, &customer_descriptor);
    DBOP_DESCRIPTOR_INVOKE_RESULT_FINALISER_IF_PRESENT(&db_descriptor); //subscriber_id & processor.customer_id are lost:  were copy-by-value as per DbBackendGetDonationsSubscription()
    if (THREAD_CONTEXT_UFSRV_RESULT_TYPE_ERR) {
      response = NULL;
    }
  }

  return response;
}

//Just diagnostics...
static const char * _Nullable _ConfirmCustomerIdPresent(json_object * _Nonnull jobj_ptr_subscription)
{
  json_object *jobj_array = json__get(jobj_ptr_subscription, "data");
  if (IS_PRESENT(jobj_array)) {
    json_object *jobj_entry = json_object_array_get_idx(jobj_array, 0);
    const char *customer_id_processor = json_object_get_string(json_object_object_get(jobj_entry, "customer"));
    if (IS_PRESENT(customer_id_processor)) {
      syslog(LOG_NOTICE, "%s {pid:'%lu', customer_id:'%s'}: FOUND CUSTOMER_ID IN SUBSCRIPTION JSON PAYLOAD", __func__, pthread_self(), customer_id_processor);
      return customer_id_processor;
    }
  }

  return NULL;
}

/**
 * @brief Cancel an active donation subscription.
 * @param http_ctx_ptr[in] Http context containing pre-allocated objects necessary for handling http request, response and processing of response.
 * @param user_id user for which update is requested
 * @param subscriber_id
 * @param is_immediate Option to cancel at end of subscription period, or immediately
 * @return NULL on error
 */
const char * _Nullable
HandleDonationSubscriptionCancelled(HttpRequestContext *http_ctx_ptr, unsigned long user_id, __unused const char *subscriber_id, __unused bool is_immediate)
{
  __block DonationCustomerDescriptor customer_descriptor = {0};
  __block char *response = NULL;
  __block DbOpDescriptor db_descriptor = {0};
  customer_descriptor.user_id = user_id;
  DbBackendGetDonationsSubscription(&customer_descriptor, &db_descriptor);
  if (THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA) {
    if (customer_descriptor.state == CANCELED) {
      syslog(LOG_NOTICE, "%s {pid:'%lu', userid:'%lu'}: SUBSCRIPTION WAS CANCELLED ALREADY", __func__, pthread_self(), user_id);
      return NULL;
    }

    //data[{"object":"subscription", items:{data:[{"object":"subscription", plan:{..}, price:{..}...}, {...}]}}, {...}]
    StripeSubscriptionGetForCustomer(http_ctx_ptr, &customer_descriptor, ^(json_object *jobj) {
        _ConfirmCustomerIdPresent(jobj);//todo fetch the subscription_id from the payload
        //note: json object 'jobj' from StripeSubscriptionGetForCustomer() wiped out. Create a a new HttpRequestContext to retain
        response = StripeUpdateSubscription(http_ctx_ptr, &customer_descriptor, "cancel_at_period_end=true", SUBSCRIPTION_CANCELLED, ^(json_object *jobj_ptr_error_response){});
        customer_descriptor.processor.state = SUBSCRIPTION_CANCELLED;
        customer_descriptor.processor.when = json_object_get_int64(json__get(http_ctx_ptr->jobj, "canceled_at"));
        customer_descriptor.state = CANCELED;
        DbBackendInsertDonationPipeline(&db_descriptor, &customer_descriptor);
        DbBackendUpdateDonationsSubscriptionState(&customer_descriptor, &db_descriptor);
    });

    if (IS_PRESENT(response)) {
      DBOP_DESCRIPTOR_INVOKE_RESULT_FINALISER_IF_PRESENT(&db_descriptor); //subscriber_id & processor.customer_id are lost:  were copy-by-value as per DbBackendGetDonationsSubscription()
      if (THREAD_CONTEXT_UFSRV_RESULT_TYPE_ERR) {
        response = NULL;
      }
    }
  } else {
    syslog(LOG_NOTICE, "%s {pid:'%lu', userid:'%lu'}: CUSTOMER DID NOT HAVE A SUBSCRIPTION RECORD", __func__, pthread_self(), user_id);
  }

  return response;
}

static char *_CreateIdempotencyKey(const char *subscriber_id, unsigned long timestamp, int aux,  enum SubscriptionProcessorState processor_state);

/**
 * @brief as per https://docs.stripe.com/api/idempotent_requests
 * @dynamic_memory EXPORTS 'char *'
 */
__attribute__ ((nonnul(1), access(read, 1), ownership_returns(malloc)))
static char *
_CreateIdempotencyKey(const char *subscriber_id, unsigned long timestamp, int aux, enum SubscriptionProcessorState processor_state)
{
  char *idempotency_key = NULL;
  asprintf(&idempotency_key, "Idempotency-Key: %s:%lu:%u:%u", subscriber_id, timestamp, aux, processor_state);

  return idempotency_key;
}

/**
 * @brief Main interface for creating a user donation subscription at payment processor for \p user_id.
 * @param http_ctx_ptr[in] Http context containing pre-allocated objects necessary for handling http request, response and processing of response.
 * @param user_id user for which update is requested
 * @param idempotency_key set by the client side, but it is ignored by ufsrv.
 * @return
 */
const char *
HandleActivateDonationSubscriptionLevel(HttpRequestContext *http_ctx_ptr, unsigned long user_id, __unused const char *subscriber_id, unsigned int level, const char *currency_code, const char *idempotency_key_provided)
{
  DonationCustomerDescriptor customer_descriptor = {0};
  DbOpDescriptor db_descriptor = {0};
  SubscriptionLevelDescriptor  subscription_descriptor = {0};
  DbOpDescriptor db_descriptor_catalogue = {0};

  subscription_descriptor.level_id = level;
  subscription_descriptor.state = 1;
  DbBackendGetDonationsSubscriptionLevelsCatalogue(&subscription_descriptor, &db_descriptor_catalogue);

  customer_descriptor.user_id = user_id;
  customer_descriptor.level_id = level;
  customer_descriptor.currency_code = currency_code;
  DbBackendGetDonationsSubscription(&customer_descriptor, &db_descriptor);

  char *idempotency_key = _CreateIdempotencyKey(customer_descriptor.subscriber_id, customer_descriptor.level_id, db_descriptor.insert_id, SUBSCRIPTION_CREATED);
  customer_descriptor.idempotency_key = idempotency_key;
  customer_descriptor.processor.state = SUBSCRIPTION_CREATED;
  customer_descriptor.state = ACTIVE;

  char *response = StripeSubscriptionCreate(http_ctx_ptr, &customer_descriptor, &subscription_descriptor);//prefill price info from processor object
  if (IS_PRESENT(response)) {
    DbBackendActivateDonationsSubscription(&customer_descriptor, &db_descriptor);
    DbBackendInsertDonationPipeline(&db_descriptor, &customer_descriptor);
    DBOP_DESCRIPTOR_INVOKE_RESULT_FINALISER_IF_PRESENT(&db_descriptor); //subscriber_id & processor.customer_id are lost
    DBOP_DESCRIPTOR_INVOKE_RESULT_FINALISER_IF_PRESENT(&db_descriptor_catalogue); //product_id & price_id are lost
    free(AS_CHAR_TYPE(customer_descriptor.processor.subscription_id));
    if (IS_PRESENT(subscription_descriptor.price_info.currency_code)) free(AS_CHAR_TYPE(subscription_descriptor.price_info.currency_code));
    if (THREAD_CONTEXT_UFSRV_RESULT_TYPE_ERR) { //from DbBackendInsertDonationPipeline()
      response = NULL;
    }
  }

  free(idempotency_key);

  return response;
}

#include <json-c/json_visit.h>
static int _TraverseNodesAndCheck(json_object *obj, int flags, json_object *parent, const char *key, size_t *index, void *data);

/**
 *
 * @param http_ctx_ptr
 * @param user_id
 * @param subscriber_id
 * @return
 * @dynamic_memory EXPORTS 'json_object *'
 */
json_object *
HandleActiveSubscriptionRetrievalForUser(HttpRequestContext *http_ctx_ptr, unsigned long user_id, __unused const char *subscriber_id)
{
  DonationCustomerDescriptor customer_descriptor = {0}; customer_descriptor.user_id = user_id;
  DbOpDescriptor db_descriptor = {0};
  DbBackendGetDonationsSubscription(&customer_descriptor, &db_descriptor);
  __block json_object *jobj_ptr_reply = NULL;

  if (IS_STR_LOADED(customer_descriptor.processor.subscription_id)) {
    StripeSubscriptionGet(http_ctx_ptr, &customer_descriptor,  ^(json_object *jobj_ptr) {
      jobj_ptr_reply = FormatActiveSubscriptionForJson(http_ctx_ptr, jobj_ptr);
    });
  } else {
    syslog(LOG_DEBUG, "%s {pid:'%lu', userid:'%lu'}: ERROR: COULD NOT FIND SUBSCRIPTION_ID FOR CUSTOMER", __func__, pthread_self(), user_id);
  }

  return jobj_ptr_reply;
}

#include <http_request.h>

/**
 * @brief Format subscription confirmation object
 * @param http_ctx_ptr[in]
 * @param jobj_ptr_subscription[in] Object containing processor-sourced subscription payload as per https://docs.stripe.com/api/subscriptions/object.
 * @return
 * @dynamic_memory EXPORTS 'json_object *'
 */
json_object *FormatActiveSubscriptionForJson(__unused HttpRequestContext *http_ctx_ptr, json_object *jobj_ptr_subscription)
{
  json_object *jobj_items = json__get(jobj_ptr_subscription, "items");
  json_object *jobj_array = json__get(jobj_items, "data");
  if (IS_PRESENT(jobj_array)) {
    json_object  *jobj_entry = json_object_array_get_idx(jobj_array, 0);
    json_object *jobj_ptr_price = json__get(jobj_entry, "price");
    const char *price_id_processor = json_object_get_string(json_object_object_get(jobj_ptr_price, "id"));
    const char *product_id_processor =  json_object_get_string(json_object_object_get(jobj_ptr_price, "product"));

    //This is necessary, otherwise we'd overwrite jobj_ptr_subscription which is associated with thread's http_ctx_ptr
    HttpRequestContext 	http_request_context = {0};
    InitialiseHttpRequestContext(&http_request_context, CALLFLAGS_EMPTY);
    int level_id = StripeLevelGetForProduct(&http_request_context, product_id_processor);
    DestructHttpRequestContext(&http_request_context, false);

    json_object *jobj_ptr = json_object_new_object();
    json_object_object_add(jobj_ptr, "level", json_object_new_int(level_id));
    json_object_object_add(jobj_ptr, "currency", json_object_new_string(json_object_get_string(json_object_object_get(jobj_ptr_price, "currency"))));
    json_object_object_add(jobj_ptr, "amount", json_object_new_int64(json_object_get_int64(json_object_object_get(jobj_ptr_price, "unit_amount"))));//todo investigate 'unit_amount_decimal' which is used at others server https://docs.stripe.com/api/prices/object?lang=java#price_object-unit_amount_decimal
    json_object_object_add(jobj_ptr, "endOfCurrentPeriod", json_object_new_int64(json_object_get_int64(json_object_object_get(jobj_entry, "current_period_end"))));
    json_object_object_add(jobj_ptr, "active", json_object_new_boolean(json_object_get_boolean(json_object_object_get(jobj_ptr_price, "active"))));
    json_object_object_add(jobj_ptr, "billingCycleAnchor", json_object_new_int64(json_object_get_int64(json_object_object_get(jobj_ptr_subscription, "billing_cycle_anchor")))); //UNIX Epoch Timestamp in seconds, can be used to calculate next billing date per https://stripe.com/docs/billing/subscriptions/billing-cycle
    json_object_object_add(jobj_ptr, "cancelAtPeriodEnd", json_object_new_boolean(json_object_get_boolean(json_object_object_get(jobj_ptr_subscription, "cancel_at_period_end"))));
    json_object_object_add(jobj_ptr, "status", json_object_new_string(json_object_get_string(json_object_object_get(jobj_ptr_subscription, "status"))));

    return jobj_ptr;
//    json_c_visit(jobj_ptr_subscription, 0, _TraverseNodesAndCheck, NULL);
  } else {
    syslog(LOG_DEBUG, "%s {pid:'%lu', userid:'-'}: ERROR: COULD NOT FIND DATA NODE FOR SUBSCRIPTION", __func__, pthread_self());
    return NULL;
  }
}

/**
 * @brief Extract the subscription price from a processor's subscription object.
 * @param jobj_ptr_subscription Binary representation of subscription object.
 * @param subscription_descriptor_ptr to be used as return carrier object
 * @return unit amount. 0 on error.
 */
__attribute__ ((const, nonnull(1, 2)))  unsigned int
StripeSubscriptionGetPriceFromObject(json_object *jobj_ptr_subscription, SubscriptionLevelDescriptor *subscription_descriptor_ptr)
{
  json_object *jobj_items = json__get(jobj_ptr_subscription, "items");
  json_object *jobj_array = json__get(jobj_items, "data");
  if (IS_PRESENT(jobj_array)) {
    json_object *jobj_entry = json_object_array_get_idx(jobj_array, 0);
    json_object *jobj_ptr_price = json__get(jobj_entry, "price");
    subscription_descriptor_ptr->price_info.amount = json_object_get_int(json_object_object_get(jobj_ptr_price, "unit_amount"));
    subscription_descriptor_ptr->price_info.currency_code = json_object_get_string(json_object_object_get(jobj_ptr_price, "currency")); //by ref

    return subscription_descriptor_ptr->price_info.amount;
  }

  return 0;

}


#define JSON_OBJECT_STR(obj, key) json_object_get_string(json_object_object_get(obj, key))
//invoke with json_c_visit(jobj_ptr, 0, _TraverseNodesAndCheck, NULL);
__unused static int
_TraverseNodesAndCheck(json_object *obj, int flags, json_object *parent, const char *key, size_t *index, void *data)
{
  if (!parent || flags == JSON_C_VISIT_SECOND || json_object_get_type(obj) == json_type_object || json_object_get_type(obj) == json_type_array)
    return JSON_C_VISIT_RETURN_CONTINUE;

  if (strcmp(json_object_to_json_string(obj), "price") == 0) {
    const char *price_id_processor= json_object_get_string(json_object_object_get(obj, "id"));
    syslog(LOG_DEBUG, "%s {pid:'%lu', price_id_processor:'%s'}: RETRIEVED TRAVERSAL ROUTE: price_id_processor...", __func__, pthread_self(), IS_STR_LOADED(price_id_processor)? price_id_processor : "*");
    return JSON_C_VISIT_RETURN_STOP;
  }
  return JSON_C_VISIT_RETURN_CONTINUE;
}