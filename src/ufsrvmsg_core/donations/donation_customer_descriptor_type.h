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

#ifndef UFSRV_DONATION_CUSTOMER_DESCRIPTOR_TYPE_H
#define UFSRV_DONATION_CUSTOMER_DESCRIPTOR_TYPE_H

#include <ufsrvmsg_core/donations/donations_enum_types.h>
#include <ufsrvmsg_core/donations/donation_descriptor_type.h>

typedef struct DonationCustomerDescriptor {
    int level_id;
    unsigned int amount;
    unsigned long user_id;
    time_t when;
    const char *subscriber_id;
    const char *currency_code;
    const char *payment_method_id; //for payment processor use
    const char *idempotency_key;
    enum  SubscriptionState state;
    enum PaymentMethod payment_method;
    enum PaymentProcessor payment_processor;
    struct {
        enum SubscriptionProcessorState state;
        const char *token, //aka secret
                   *customer_id,
                   *subscription_id;
        time_t when;
    } processor;
} DonationCustomerDescriptor;

#endif //UFSRV_DONATION_CUSTOMER_DESCRIPTOR_TYPE_H
