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

#ifndef UFSRV_DONATIONS_ENUM_TYPES_H
#define UFSRV_DONATIONS_ENUM_TYPES_H

enum SubscriptionState {
    INITIATED = 0,
    ACTIVE,
    PAUSED,
    CANCELED
};

enum SubscriptionProcessorState {
    NOT_STARTED = 0,
    UNCHANGED, ///< refer to previous state in a sequence of transitions
    CUSTOMER_CREATE, ///< Customer object created by processor
    CUSTOMER_UPDATED, ///< Customer object attribute changed by processor
    INTENT_SETUP,
    DEFAULT_PAYMENT_METHOD,  ///< Customer object attribute changed by processor
    SUBSCRIPTION_CREATED, ///< customer subscription created at payment processor
    SUBSCRIPTION_CANCELLED
};

enum PaymentMethod {
    UNKNOWN = 0,
    CARD,
    PAYPAL,
    GOOGLE_PLAY_BILLING,
    APPLE_APP_STORE
};

enum PaymentProcessor {
    PROCESSOR_UNKNOWN = 0,
    PROCESSOR_STRIPE,
    PROCESSOR_PAYPAL,
};

#endif //UFSRV_DONATIONS_ENUM_TYPES_H
