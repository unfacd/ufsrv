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

#ifndef UFSRV_UTILS_DONATIONS_H
#define UFSRV_UTILS_DONATIONS_H

#include <ufsrvmsg_core/donations/donations_subscriber_id_type.h>
#include <ufsrvmsg_core/donations/donation_descriptor_type.h>
#include <ufsrvmsg_core/donations/donation_customer_descriptor_type.h>
#include <ufsrvmsg_core/donations/subscription_level_descriptor_type.h>
#include <uflib/db/db_op_descriptor_type.h>
#include <session_type.h>
#include <json-c/json.h>
#include <http_session_type.h>

char *ProvideDefaultDonationsDbAccount(bool is_generate_id);
char *ProvideNewSubscriberId(void);
json_object *ProvideDefaultDonationsJsonToken(bool is_generate_id);
DonationDescriptor *GetDonationsTokenForAccountUpgrade(unsigned long userid, DonationDescriptor *descriptor_ptr_out);
DonationDescriptor *DbAccountGetDonations(unsigned long userid, bool is_struct_transfer, bool is_serialised, bool is_raw, DonationDescriptor *descriptor_ptr_out);
int DbAccountUpdateDonations(unsigned long userid, DonationDescriptor *descriptor_ptr);
int DbAccountUpdateDonationsSubscriberId(unsigned long userid, DonationDescriptor *descriptor_ptr);
json_object *JsonFormatUserDonations(Session *sesn_ptr);
const char *HandleDonationPipelineInitiated(HttpRequestContext *http_ctx_ptr, unsigned long user_id, const char *subscriber_id, enum PaymentProcessor payment_processor);
const char *HandleDonationSubscriptionDefaultPaymentMethod(HttpRequestContext *http_ctx_ptr, unsigned long user_id, const char *subscriber_id, const char *payment_method);
const char *HandleActivateDonationSubscriptionLevel(HttpRequestContext *http_ctx_ptr, unsigned long user_id, __unused const char *subscriber_id, unsigned int level, const char *currency_code, const char *idempotency_key_provided);
json_object * HandleActiveSubscriptionRetrievalForUser(HttpRequestContext *http_ctx_ptr, unsigned long user_id, __unused const char *subscriber_id);
json_object *FormatActiveSubscriptionForJson(HttpRequestContext *http_ctx_ptr, json_object *jobj_ptr_subscription);
unsigned int StripeSubscriptionGetPriceFromObject(json_object *jobj_ptr_subscription, SubscriptionLevelDescriptor *subscription_descriptor_ptr);
const char *HandleDonationSubscriptionCancelled(HttpRequestContext *http_ctx_ptr, unsigned long user_id, __unused const char *subscriber_id, bool is_immediate);

#endif //UFSRV_UTILS_DONATIONS_H
