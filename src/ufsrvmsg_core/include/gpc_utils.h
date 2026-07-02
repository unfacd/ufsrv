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

#ifndef UFSRV_GPC_UTILS_H
#define UFSRV_GPC_UTILS_H

#include <uflib/scheduled_jobs/scheduled_jobs.h>
#include <cloud_authorization_token_type.h>
#include <gpc_service_request_descriptor.h>
#include <cloud_authenticator_descriptor_type.h>

ScheduledJob * InitialiseScheduledJobTypeForGpcAuthenticatorIntegrityApi(void);
ScheduledJob * InitialiseScheduledJobTypeForGpcAuthenticatorFcmMessaging(void);
void InitialiseScheduledJobTypeForGpcAuthenticator(void);
ScheduledJob *GetScheduledJobForGpcAuthenticator(void);
const GpcServiceRequestDescriptor *const ProvideGpcServiceRequestDescriptorForFirebaseMessaging(void);
const GpcServiceRequestDescriptor *const ProvideGpcServiceRequestDescriptorForIntegrityApi(void);
CloudAuthorizationDescriptor *ProvideGpcAuthenticatorDescriptorForIntegrityApi();
CloudAuthorizationDescriptor *ProvideGpcAuthenticatorDescriptorForFcmMessaging();
CloudAuthorizationTokenState *SetGpcAuthorizationToken(CloudAuthorizationToken *authorization_token_ptr, CloudAuthorizationTokenState *authorization_token_state_ptr_out);
CloudAuthorizationTokenState *ProvideGpcAuthorizationToken(CloudAuthorizationToken *authorization_token_ptr, enum AccessBlockingMode blocking_mode, CloudAuthorizationTokenState *authorization_token_state_ptr_out);

#endif //UFSRV_GPC_UTILS_H
