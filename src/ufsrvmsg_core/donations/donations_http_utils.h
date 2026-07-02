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

#ifndef UFSRV_DONATIONS_HTTP_UTILS_H
#define UFSRV_DONATIONS_HTTP_UTILS_H

#include <http_request_context_type.h>
#include "donations_enum_types.h"
#include "donation_customer_descriptor_type.h"
#include "subscription_level_descriptor_type.h"

char *StripeRequestNewCustomer(HttpRequestContext *http_ptr, DonationCustomerDescriptor *customer_descriptor_ptr);
char *StripeCreateSetupIntent(HttpRequestContext *http_ptr, DonationCustomerDescriptor *customer_descriptor_ptr);
char *StripeUpdateCustomer(HttpRequestContext *http_ptr, DonationCustomerDescriptor *customer_descriptor_ptr, const char *property, enum SubscriptionProcessorState state_processor, void (^on_no_error)(json_object *));
char *StripeSubscriptionCreate(HttpRequestContext *http_ptr, DonationCustomerDescriptor *customer_descriptor_ptr, SubscriptionLevelDescriptor *subscription_descriptor_ptr);
int StripeSubscriptionGet(HttpRequestContext *http_ptr, DonationCustomerDescriptor *customer_descriptor_ptr, void (^on_response_available)(json_object *));
int StripeCustomerGet(HttpRequestContext *http_ptr, DonationCustomerDescriptor *customer_descriptor_ptr, void (^on_response_available)(json_object *));
int StripeProductGet(HttpRequestContext *http_ptr, DonationCustomerDescriptor *customer_descriptor_ptr, SubscriptionLevelDescriptor *subscription_descriptor_ptr, void (^on_response_available)(json_object *));
int StripeSubscriptionGetForCustomer(HttpRequestContext *http_ptr, DonationCustomerDescriptor *customer_descriptor_ptr, void (^on_response_available)(json_object *));
int StripeLevelGetForProduct(HttpRequestContext *http_ptr, const char *product_id);
char *StripeUpdateSubscription(HttpRequestContext *http_ptr, DonationCustomerDescriptor *customer_descriptor_ptr, const char *property, enum SubscriptionProcessorState state_processor, void (^on_no_error)(json_object *));

#endif //UFSRV_DONATIONS_HTTP_UTILS_H
