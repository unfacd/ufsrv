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

#ifndef UFSRV_DONATIONS_DB_UTILS_H
#define UFSRV_DONATIONS_DB_UTILS_H

#include <ufsrvresult_type.h>
#include <donations/donation_customer_descriptor_type.h>
#include <donations/subscription_level_descriptor_type.h>
#include <uflib/db/db_op_descriptor_type.h>

bool IsDonationCustomerExist(unsigned long user_id, DonationCustomerDescriptor *customer_descriptor_ptr, DbOpDescriptor *db_descriptor_ptr, void (^on_customer_exists)(DonationCustomerDescriptor *, DbOpDescriptor *));
UFSRVResult *DbBackendInsertDonationPipeline(DbOpDescriptor *db_descriptor, DonationCustomerDescriptor *customer_descriptor_ptr);
UFSRVResult *DbBackendInsertDonation(DbOpDescriptor *db_descriptor, DonationCustomerDescriptor *customer_descriptor_ptr);
UFSRVResult *DbBackendGetDonationsSubscription(DonationCustomerDescriptor *customer_descriptor_ptr, DbOpDescriptor *db_descriptor);
UFSRVResult *DbBackendUpdateDonationsSubscription(DonationCustomerDescriptor *customer_descriptor_ptr, DbOpDescriptor *db_descriptor, const char *field, const char *value);
UFSRVResult *DbBackendUpdateDonationsSubscriptionState(DonationCustomerDescriptor *customer_descriptor_ptr, DbOpDescriptor *db_descriptor);
UFSRVResult *DbBackendActivateDonationsSubscription(DonationCustomerDescriptor *customer_descriptor_ptr, DbOpDescriptor *db_descriptor);
UFSRVResult *DbBackendGetDonationsSubscriptionLevelsCatalogue(SubscriptionLevelDescriptor *subscription_descriptor_ptr, DbOpDescriptor *db_descriptor);
UFSRVResult *DbDeleteDonationsSubscription(unsigned long userid);
UFSRVResult *DbDeleteDonationsSubscriptionPipeline(unsigned long userid);

#endif //UFSRV_DONATIONS_DB_UTILS_H
