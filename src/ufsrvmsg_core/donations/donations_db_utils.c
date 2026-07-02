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
#include <donations/donations_db_utils.h>
#include <thread_context_type.h>
#include <uflib/db/dp_ops.h>
#include <uflib/db/db_op_descriptor_type.h>
#include <user/user_backend.h>

extern __thread ThreadContext ufsrv_thread_context;

/** \addtogroup donation_customer_subscription_pipline_insertion
*  Implement interface for inserting new donation customer
*  @{
*/
static char *_DonationPipelineDbOpUInsertProvider(intptr_t values[1]);
static UFSRVResult *_DbBackendInsertDonationPipeline(DbOpDescriptor *dbop_descriptor);

/**
 * @brief Check if donations customer already known to us.
 * @param user_id
 * @param customer_descriptor_ptr pre-allocated by user and will be filled with data if customer found
 * @param db_descriptor_ptr pre-allocated by user and to be used to clean up result-set. See warning below.
 * @param on_customer_exists an optional closure by caller
 * @return true if customer exists
 * @warn caller must invoke @code{.c} DBOP_DESCRIPTOR_INVOKE_RESULT_FINALISER_IF_PRESENT(dbop_descriptor);@endcode to release memory associated with result set
 */
bool IsDonationCustomerExist(unsigned long user_id, DonationCustomerDescriptor *customer_descriptor_ptr, DbOpDescriptor *db_descriptor_ptr, void (^on_customer_exists)(DonationCustomerDescriptor *, DbOpDescriptor *))
{
  customer_descriptor_ptr->user_id = user_id;
  DbBackendGetDonationsSubscription(customer_descriptor_ptr, db_descriptor_ptr);//this will do a good job of transferring stored record into customer_descriptor_ptr (some by ref)
  if (THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA) {
    if (IS_PRESENT(on_customer_exists)) {
      on_customer_exists(customer_descriptor_ptr, db_descriptor_ptr);
      return true;
    }
  }

  return false;
}

UFSRVResult *
DbBackendInsertDonationPipeline(DbOpDescriptor *db_descriptor, DonationCustomerDescriptor *customer_descriptor_ptr)
{
  db_descriptor->ctx_data = CLIENT_CTX_DATA(customer_descriptor_ptr);
  db_descriptor->query_statement_provider.provide = _DonationPipelineDbOpUInsertProvider;
  db_descriptor->query_statement_provider.values  = (intptr_t[]){DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->user_id),
                                                                 DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->state), DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->processor.state),
                                                                 DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->processor.customer_id), DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->processor.token),
                                                                 DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->idempotency_key), DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->processor.when), 0};
  db_descriptor->query_statement_provider.finalise = GetDefaultQueryStatementProviderFinalser();

  _DbBackendInsertDonationPipeline(db_descriptor);
  if (THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_EMPTYSET_DATA) {
    //NOOP
  }

  return THREAD_CONTEXT_UFSRV_RESULT_PTR;
}


static UFSRVResult *
_DbBackendInsertDonationPipeline(DbOpDescriptor *dbop_descriptor)
{
  GetDbResultForInsert(THREAD_CONTEXT_DB_BACKEND, dbop_descriptor);
  return ReturnUfsrvResultFromDbOpDescriptor(dbop_descriptor);
}

//provide parameterised sql statement
static char *
_DonationPipelineDbOpUInsertProvider(intptr_t values[1])
{
#define SQL_INSERT_DATA_ATTRIBUTE_STRING "INSERT INTO donations_subscriptions_pipeline (user_id, state, state_processor, customer_id_processor, token, idempotency_key, when_processor) VALUES ('%lu', '%u', '%u', '%s', '%s', '%s', FROM_UNIXTIME('%lu'))"
  char *sql_query_str = mdsprintf(SQL_INSERT_DATA_ATTRIBUTE_STRING, (unsigned long)values[0], (int)values[1], (int)values[2], (char *)values[3], (char *)values[4], (char *)values[5], (unsigned long)values[6]);
  return sql_query_str;
#undef SQL_INSERT_DATA_ATTRIBUTE_STRING
}
/** @} */

/** \addtogroup donation_customer_subscription_insertion
*  Implement interface for inserting new donation customer
*  @{
*/
static char *_DonationDbOpUInsertProvider(intptr_t values[static 1]);
static UFSRVResult *_DbBackendInsertDonation(DbOpDescriptor *dbop_descriptor);

/**
 * @brief Main interface for entering a donation subscription.
 * @param db_descriptor
 * @param customer_descriptor_ptr
 * @return
 */
UFSRVResult *
DbBackendInsertDonation(DbOpDescriptor *db_descriptor, DonationCustomerDescriptor *customer_descriptor_ptr)
{
  db_descriptor->query_statement_provider.provide = _DonationDbOpUInsertProvider;
  db_descriptor->query_statement_provider.values  = (intptr_t[]){DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->user_id), DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->subscriber_id),
                                                                 DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->level_id), DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->currency_code),
                                                                 DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->state), DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->processor.state),
                                                                 DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->processor.customer_id), DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->processor.token),
                                                                 DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->payment_processor), DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->processor.when), DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->amount), 0};
  db_descriptor->query_statement_provider.finalise = GetDefaultQueryStatementProviderFinalser();

  _DbBackendInsertDonation(db_descriptor);
  if (THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_EMPTYSET_DATA) {
    //NOOP
  }

  return THREAD_CONTEXT_UFSRV_RESULT_PTR;
}


/**
 * @brief Convenient dispatcher for invoking db insertion function
 * @return UFSRVResult object reflecting success state of the db insert operation
 */
static UFSRVResult *
_DbBackendInsertDonation(DbOpDescriptor *dbop_descriptor)
{
  GetDbResultForInsert(THREAD_CONTEXT_DB_BACKEND, dbop_descriptor);
  return ReturnUfsrvResultFromDbOpDescriptor(dbop_descriptor);
}

/**
 * @brief provide a final parameterised sql statement. The string to be deallocated with finaliser callback \ref DbOpDescriptor.query_statement_provider.finalise
 * @param values array of positional values
 * @return final query string
 * @dynamic_memory EXPORTS 'char *' which is to be deallocated with finaliser
 */
static char *
_DonationDbOpUInsertProvider(intptr_t values[static 1])
{
#define SQL_INSERT_DATA_ATTRIBUTE_STRING "INSERT INTO donations_subscriptions (user_id, subscriber_id, level_id, currency_code, state, state_processor, customer_id_processor, token, processor_id, when_processor, amount) VALUES ('%lu', '%s', '%u', '%s', '%u', '%u', '%s', '%s', '%u', FROM_UNIXTIME('%lu'), '%u') ON DUPLICATE KEY UPDATE when_processor = '%lu'"

  char *sql_query_str = mdsprintf(SQL_INSERT_DATA_ATTRIBUTE_STRING, (unsigned long)values[0], (char *)values[1], (int)values[2], (char *)values[3], (int)values[4], (int)values[5], (char *)values[6], (char *)values[7], (int)values[8], (unsigned long)values[9], (unsigned)values[10], (unsigned long)values[9]);
  return sql_query_str;

#undef SQL_INSERT_DATA_ATTRIBUTE_STRING
}
/** @} */


#pragma region customer subscription retrieval
/** \addtogroup donation_customer_subscription_retrieval
*  Implement interface for retrieving donation subscriptions
*  @{
*/
static char *_DonationsSubscriptionDbOpQueryProvider(intptr_t values[static 1]);
static int _DonationsSubscriptionDbOpTransformer(DbOpDescriptor *dbop_descriptor);
static UFSRVResult *_DbBackendDbBackendGetDonationsSubscription(DbOpDescriptor *dbop_descriptor);

/**
 * @brief Main interface for querying donations subscriptions table.
 * @param db_descriptor Empty, pre-allocated by user
 * @param customer_descriptor_ptr user provided with pre-filled values for userid
 * @return thread_context UFSRVResult
 * @warn caller must invoke @code{.c} DBOP_DESCRIPTOR_INVOKE_RESULT_FINALISER_IF_PRESENT(dbop_descriptor);@endcode to release memory associated with result set
 */
UFSRVResult *
DbBackendGetDonationsSubscription(DonationCustomerDescriptor *customer_descriptor_ptr, DbOpDescriptor *db_descriptor)
{
  db_descriptor->ctx_data = AS_CLIENT_CONTEXT_DATA(customer_descriptor_ptr);
  db_descriptor->query_statement_provider.provide = _DonationsSubscriptionDbOpQueryProvider;
  db_descriptor->query_statement_provider.values  = (intptr_t[]){DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->user_id), DBOP_QUERY_PROVIDER_VALUE(PROCESSOR_STRIPE), 0};
  db_descriptor->query_statement_provider.finalise = GetDefaultQueryStatementProviderFinalser();
  db_descriptor->transformer.transform = _DonationsSubscriptionDbOpTransformer;

  _DbBackendDbBackendGetDonationsSubscription(db_descriptor);

  if (THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA) {
    db_descriptor->finaliser.finalise = GetDefaultDbOpResultFinaliser(); //enable caller to issue result-set deallocation
  }

  return THREAD_CONTEXT_UFSRV_RESULT_PTR;
}

/**
 * @brief Convenient dispatcher for invoking standard db query function
 * @return UFRSVResult interpreted from the state of db operation
 */
static UFSRVResult *
_DbBackendDbBackendGetDonationsSubscription(DbOpDescriptor *dbop_descriptor)
{
  GetDbResultForQuery(THREAD_CONTEXT_DB_BACKEND, dbop_descriptor);
  return ReturnUfsrvResultFromDbOpDescriptor(dbop_descriptor);
}

static char *
_DonationsSubscriptionDbOpQueryProvider(intptr_t values[static 1])
{
#define SQL_SELECT_DONATIONS_SUBSCRIPTION 	 "SELECT subscription_id, subscriber_id, customer_id_processor, subscription_id_processor, level_id, currency_code, state, state_processor, processor_id, amount " \
                                             "FROM donations_subscriptions WHERE user_id = '%lu' AND processor_id = '%u'"
  char *sql_query_str = mdsprintf(SQL_SELECT_DONATIONS_SUBSCRIPTION, (unsigned long)values[0], (int)values[1]);
  return sql_query_str;
#undef SQL_SELECT_DONATIONS_SUBSCRIPTION
}

/**
 * Standard by-ref transformer for stored subscriptions
 * @param dbop_descriptor
 * @warn This copies values into DbOpDescriptor.ctx_data from result-set by ref. Retain scope until caller deallocates.
 */
static int
_DonationsSubscriptionDbOpTransformer(DbOpDescriptor *dbop_descriptor)
{
#define COLUMN_SUBSCRIPTION_ID		(((struct _h_type_int *)result->data[0][0].t_data)->value)
#define COLUMN_SUBSCRIBER_ID		(((struct _h_type_text *)result->data[0][1].t_data)->value)
#define COLUMN_CUSTOMER_ID		(((struct _h_type_text *)result->data[0][2].t_data)->value)
#define COLUMN_SUBSCRIPTION_ID_PROCESSOR_DATA ((struct _h_type_text *)result->data[0][3].t_data)
#define COLUMN_SUBSCRIPTION_ID_PROCESSOR		(((struct _h_type_text *)result->data[0][3].t_data)->value)
#define COLUMN_SUBSCRIPTION_LEVEL_ID		(((struct _h_type_int *)result->data[0][4].t_data)->value)
#define COLUMN_SUBSCRIBER_CURRENCY_CODE		(((struct _h_type_text *)result->data[0][5].t_data)->value)
#define COLUMN_SUBSCRIPTION_LEVEL_STATE		(((struct _h_type_int *)result->data[0][6].t_data)->value)
#define COLUMN_SUBSCRIPTION_LEVEL_STATE_PROCESSOR		(((struct _h_type_int *)result->data[0][7].t_data)->value)
#define COLUMN_SUBSCRIPTION_LEVEL_PROCESSOR_ID		(((struct _h_type_int *)result->data[0][8].t_data)->value)
#define COLUMN_SUBSCRIPTION_AMOUNT		(((struct _h_type_int *)result->data[0][9].t_data)->value)

  struct _h_result *result = &dbop_descriptor->result;
  DonationCustomerDescriptor *customer_descriptor_ptr = dbop_descriptor->ctx_data;

  dbop_descriptor->insert_id = COLUMN_SUBSCRIPTION_ID;
  customer_descriptor_ptr->subscriber_id = COLUMN_SUBSCRIBER_ID; //by ref
  customer_descriptor_ptr->processor.customer_id = COLUMN_CUSTOMER_ID; //by ref
  customer_descriptor_ptr->processor.subscription_id = COLUMN_SUBSCRIPTION_ID_PROCESSOR_DATA? COLUMN_SUBSCRIPTION_ID_PROCESSOR : NULL; //by ref
  customer_descriptor_ptr->level_id = COLUMN_SUBSCRIPTION_LEVEL_ID;
  customer_descriptor_ptr->currency_code = COLUMN_SUBSCRIBER_CURRENCY_CODE;
  customer_descriptor_ptr->amount = COLUMN_SUBSCRIPTION_AMOUNT;
  customer_descriptor_ptr->state = (enum  SubscriptionState)COLUMN_SUBSCRIPTION_LEVEL_STATE;
  customer_descriptor_ptr->processor.state = (enum SubscriptionProcessorState)COLUMN_SUBSCRIPTION_LEVEL_STATE_PROCESSOR;
  customer_descriptor_ptr->payment_processor = (enum PaymentProcessor)COLUMN_SUBSCRIPTION_LEVEL_PROCESSOR_ID;

  return 0;


}
/** @} */
#pragma endregion


#pragma region subscription levels catalogue
/** \addtogroup donation_customer_subscription_levels_catalogue_retrieval
*  Implement interface for retrieving donation subscriptions levels from catalogue
*  @{
*/
static char *_DonationsSubscriptionCatalogueDbOpQueryStatementProvider(intptr_t values[static 1]);
static int _DonationsSubscriptionCatalogueDbOpTransformer(DbOpDescriptor *dbop_descriptor);
static UFSRVResult *_DbBackendDbBackendGetDonationsSubscriptionCatalogue(DbOpDescriptor *dbop_descriptor);

/**
 * @brief Main interface for querying donations subscriptions levels catalogue table.
 * @param db_descriptor Empty, pre-allocated by user
 * @param subscription_descriptor_ptr user provided with pre-filled values for level_id
 * @return thread_context UFSRVResult
 * @warn caller must invoke @code{.c} DBOP_DESCRIPTOR_INVOKE_RESULT_FINALISER_IF_PRESENT(dbop_descriptor);@endcode to release memory associated with result set
 */
UFSRVResult *
DbBackendGetDonationsSubscriptionLevelsCatalogue(SubscriptionLevelDescriptor *subscription_descriptor_ptr, DbOpDescriptor *db_descriptor)
{
  db_descriptor->ctx_data = AS_CLIENT_CONTEXT_DATA(subscription_descriptor_ptr);
  db_descriptor->query_statement_provider.provide = _DonationsSubscriptionCatalogueDbOpQueryStatementProvider;
  db_descriptor->query_statement_provider.values  = (intptr_t[]){DBOP_QUERY_PROVIDER_VALUE(subscription_descriptor_ptr->level_id), DBOP_QUERY_PROVIDER_VALUE(subscription_descriptor_ptr->state), 0};
  db_descriptor->query_statement_provider.finalise = GetDefaultQueryStatementProviderFinalser();
  db_descriptor->transformer.transform = _DonationsSubscriptionCatalogueDbOpTransformer;

  _DbBackendDbBackendGetDonationsSubscriptionCatalogue(db_descriptor);

  if (THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA) {
    db_descriptor->finaliser.finalise = GetDefaultDbOpResultFinaliser(); //enable caller to issue result-set deallocation
  }

  return THREAD_CONTEXT_UFSRV_RESULT_PTR;
}

/**
 * @brief Convenient dispatcher for invoking standard db query function
 * @return UFRSVResult interpreted from the state of db operation
 */
static UFSRVResult *
_DbBackendDbBackendGetDonationsSubscriptionCatalogue(DbOpDescriptor *dbop_descriptor)
{
  GetDbResultForQuery(THREAD_CONTEXT_DB_BACKEND, dbop_descriptor);
  return ReturnUfsrvResultFromDbOpDescriptor(dbop_descriptor);
}
//SELECT level_id, donations_subscription_levels_catalogue.badge_id, product_id_processor, price_id_processor, description FROM donations_subscription_levels_catalogue JOIN donations_badges ON donations_subscription_levels_catalogue.badge_id = donations_badges.badge_id where level_id = 1 and state = 1
static char *
_DonationsSubscriptionCatalogueDbOpQueryStatementProvider(intptr_t values[static 1])
{
#define SQL_SELECT_DONATIONS_SUBSCRIPTION 	 "SELECT badge_id, product_id_processor, price_id_processor " \
                                             "FROM donations_subscription_levels_catalogue WHERE level_id = '%u' AND state = '%u'"
  char *sql_query_str = mdsprintf(SQL_SELECT_DONATIONS_SUBSCRIPTION, (int)values[0], (int)values[1]);
  return sql_query_str;
#undef SQL_SELECT_DONATIONS_SUBSCRIPTION
}

/**
 * Standard by-ref transformer for stored subscriptions
 * @param dbop_descriptor
 * @warn This copies values into DbOpDescriptor.ctx_data from result-set by ref. Retain scope until caller deallocates.
 */
static int
_DonationsSubscriptionCatalogueDbOpTransformer(DbOpDescriptor *dbop_descriptor)
{
#define COLUMN_BADGE_ID		(((struct _h_type_int *)result->data[0][0].t_data)->value)
#define COLUMN_PRODUCT_ID		(((struct _h_type_text *)result->data[0][1].t_data)->value)
#define COLUMN_PRICE_ID		(((struct _h_type_text *)result->data[0][2].t_data)->value)

  struct _h_result *result = &dbop_descriptor->result;
  SubscriptionLevelDescriptor *descriptor_ptr = dbop_descriptor->ctx_data;

  dbop_descriptor->insert_id = COLUMN_BADGE_ID;
  descriptor_ptr->product_id_processor = COLUMN_PRODUCT_ID; //by ref
  descriptor_ptr->price_id_processor = COLUMN_PRICE_ID; //by ref

  return 0;

#undef COLUMN_BADGE_ID
#undef COLUMN_PRODUCT_ID
#undef COLUMN_PRICE_ID

}
/** @} */
#pragma endregion


/** \addtogroup donation_customer_subscription_update
*  Implement interface for updating donation subscriptions
*  @{
*/

static char *_DonationsSubscriptionDbOpUpdateProviderText(intptr_t values[static 1]);
static UFSRVResult *_DbBackendUpdateDonationsSubscription(DbOpDescriptor *db_descriptor);

static char *_DonationsSubscriptionDbOpUpdateState(intptr_t values[static 1]);

UFSRVResult *
DbBackendUpdateDonationsSubscription(DonationCustomerDescriptor *customer_descriptor_ptr, DbOpDescriptor *db_descriptor, const char *field, const char *value)
{
  db_descriptor->ctx_data = AS_CLIENT_CONTEXT_DATA(customer_descriptor_ptr);
  db_descriptor->query_statement_provider.provide = _DonationsSubscriptionDbOpUpdateProviderText;
  db_descriptor->query_statement_provider.values  = (intptr_t[]){DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->user_id), DBOP_QUERY_PROVIDER_VALUE(field), DBOP_QUERY_PROVIDER_VALUE(value), DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->processor.state), DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->state), 0};
  db_descriptor->query_statement_provider.finalise = GetDefaultQueryStatementProviderFinalser();

  _DbBackendUpdateDonationsSubscription(db_descriptor);
  if (THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_EMPTYSET_DATA) {
    //NOOP
  }

  return THREAD_CONTEXT_UFSRV_RESULT_PTR;
}

/**
 * @note This only handles text value substitutions and one-at-a-time only
 */
static char *
_DonationsSubscriptionDbOpUpdateProviderText(intptr_t values[static 1])
{
#define SQL_UPDATE_DONATIONS_SUBSCRIPTION_DATA_ATTRIBUTE_STRING "UPDATE donations_subscriptions SET `%s` = '%s', state_processor = '%u', state = '%u' WHERE user_id = %lu"
  char *sql_query_str = mdsprintf(SQL_UPDATE_DONATIONS_SUBSCRIPTION_DATA_ATTRIBUTE_STRING, (char *)values[1], (char *)values[2], (int)values[3], (int)values[4], (unsigned long)values[0]);

  return sql_query_str;
#undef SQL_UPDATE_FENCE_DATA_ATTRIBUTE_STRING
}

static UFSRVResult *
_DbBackendUpdateDonationsSubscription(DbOpDescriptor *dbop_descriptor)
{
  GetDbResultForUpdate(THREAD_CONTEXT_DB_BACKEND, dbop_descriptor);
  return ReturnUfsrvResultFromDbOpDescriptor(dbop_descriptor);
}

/**
 * @brief Subscription state update only
 * @param customer_descriptor_ptr
 * @param db_descriptor
 * @return
 */
UFSRVResult *
DbBackendUpdateDonationsSubscriptionState(DonationCustomerDescriptor *customer_descriptor_ptr, DbOpDescriptor *db_descriptor)
{
  db_descriptor->ctx_data = AS_CLIENT_CONTEXT_DATA(customer_descriptor_ptr);
  db_descriptor->query_statement_provider.provide = _DonationsSubscriptionDbOpUpdateState;
  db_descriptor->query_statement_provider.values  = (intptr_t[]){DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->user_id), DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->processor.state), DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->state), DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->processor.when), 0};
  db_descriptor->query_statement_provider.finalise = GetDefaultQueryStatementProviderFinalser();

  GetDbResultForUpdate(THREAD_CONTEXT_DB_BACKEND, db_descriptor);
  return ReturnUfsrvResultFromDbOpDescriptor(db_descriptor);
}

static char *
_DonationsSubscriptionDbOpUpdateState(intptr_t values[static 1])
{
#define SQL_UPDATE_DONATIONS_SUBSCRIPTION_STATE "UPDATE donations_subscriptions SET state_processor = '%u', state = '%u', when_processor = 'FROM_UNIXTIME('%lu')' WHERE user_id = %lu"
  char *sql_query_str = mdsprintf(SQL_UPDATE_DONATIONS_SUBSCRIPTION_STATE, (int)values[1], (int)values[2], (unsigned long)values[3], (unsigned long)values[0]);

  return sql_query_str;
#undef SQL_UPDATE_DONATIONS_SUBSCRIPTION_STATE
}
//////////--//////

static char *_DbBackendActivateDonationsSubscriptionProvider(intptr_t values[static 1]);

/**
 * @brief Updated store subscription with value reflecting an activated subscription state.
 * @param customer_descriptor_ptr Pre-allocated and pre-filled
 * @param db_descriptor
 * @return
 */
UFSRVResult *
DbBackendActivateDonationsSubscription(DonationCustomerDescriptor *customer_descriptor_ptr, DbOpDescriptor *db_descriptor)
{
  db_descriptor->ctx_data = AS_CLIENT_CONTEXT_DATA(customer_descriptor_ptr);
  db_descriptor->query_statement_provider.provide = _DbBackendActivateDonationsSubscriptionProvider;
  db_descriptor->query_statement_provider.values  = (intptr_t[]){DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->user_id), DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->processor.subscription_id), DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->amount),
                                                                 DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->currency_code), DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->processor.state), DBOP_QUERY_PROVIDER_VALUE(customer_descriptor_ptr->state), 0};
  db_descriptor->query_statement_provider.finalise = GetDefaultQueryStatementProviderFinalser();

  GetDbResultForUpdate(THREAD_CONTEXT_DB_BACKEND, db_descriptor);
  ReturnUfsrvResultFromDbOpDescriptor(db_descriptor);

  if (THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_EMPTYSET_DATA) {
    //NOOP
  }

  return THREAD_CONTEXT_UFSRV_RESULT_PTR;
}

/**
 * @note This only handles text value substitutions and one-at-a-time only
 */
static char *
_DbBackendActivateDonationsSubscriptionProvider(intptr_t values[static 1])
{
#define SQL_UPDATE_DONATIONS_SUBSCRIPTION_ACTIVATE_STATEMENT "UPDATE donations_subscriptions SET `subscription_id_processor` = '%s', `amount` = '%u', `currency_code` = '%s', state_processor = '%u', state = '%u' WHERE user_id = %lu"
  char *sql_query_str = mdsprintf(SQL_UPDATE_DONATIONS_SUBSCRIPTION_ACTIVATE_STATEMENT, (char *)values[1], (unsigned int)values[2], (char *)values[3], (int)values[4], (int)values[5], (unsigned long)values[0]);

  return sql_query_str;
#undef SQL_UPDATE_DONATIONS_SUBSCRIPTION_ACTIVATE_STATEMENT
}

/** @} */

/** \addtogroup donation_customer_subscription_delete
*  Implement interface for deleting donations subscription records
*  @{
*/

UFSRVResult *
DbDeleteDonationsSubscription(unsigned long userid)
{
#define SQL_DELETE_DONATIONS_SUBSCRIPTION "DELETE FROM donations_subscriptions WHERE `user_id` = '%lu'"

  char *sql_query_str = mdsprintf(SQL_DELETE_DONATIONS_SUBSCRIPTION, userid);

  syslog(LOG_DEBUG, "%s (th_ctx:'%p'): GENERATED SQL QUERY: '%s'", __func__, THREAD_CONTEXT_PTR, sql_query_str);

  int sql_result = h_query_delete(THREAD_CONTEXT_DB_BACKEND, sql_query_str);
  free(sql_query_str);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, "%s (th_ctx:''): ERROR: COULD NOT EXECUTE QUERY: '%s'", __func__, sql_query_str);

    THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_BACKEND_CONNECTION)
  }

  THREAD_CONTEXT_RETURN_RESULT_SUCCESS(NULL, RESCODE_PROG_NULL_POINTER)

#undef SQL_DELETE_DONATIONS_SUBSCRIPTION
}

UFSRVResult *
DbDeleteDonationsSubscriptionPipeline(unsigned long userid)
{
#define SQL_DELETE_DONATIONS_SUBSCRIPTION_PIPELINE "DELETE FROM donations_subscriptions_pipeline WHERE `user_id` = '%lu'"

  char *sql_query_str = mdsprintf(SQL_DELETE_DONATIONS_SUBSCRIPTION_PIPELINE, userid);

  syslog(LOG_DEBUG, "%s (th_ctx:'%p'): GENERATED SQL QUERY: '%s'", __func__, THREAD_CONTEXT_PTR, sql_query_str);

  int sql_result = h_query_delete(THREAD_CONTEXT_DB_BACKEND, sql_query_str);
  free(sql_query_str);

  if (sql_result != H_OK) {
    syslog(LOG_DEBUG, "%s (th_ctx:''): ERROR: COULD NOT EXECUTE QUERY: '%s'", __func__, sql_query_str);

    THREAD_CONTEXT_RETURN_RESULT_ERROR(NULL, RESCODE_BACKEND_CONNECTION)
  }

  THREAD_CONTEXT_RETURN_RESULT_SUCCESS(NULL, RESCODE_PROG_NULL_POINTER)

#undef SQL_DELETE_DONATIONS_SUBSCRIPTION_PIPELINE
}

/** @} */