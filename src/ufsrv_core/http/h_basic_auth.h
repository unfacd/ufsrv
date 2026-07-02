
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

#ifndef __ONION_HANDLER_AUTH_PAM__
#define __ONION_HANDLER_AUTH_PAM__

#include <ufsrvresult_type.h>
#include <uflib/recycler/instance_type.h>
#include  <ufsrv_core/http/http_request_handler.h>
#include <session.h>

typedef InstanceHolder InstanceHolderForBasicAuthDescriptor;

typedef struct BasicAuthDescriptor {
	unsigned long userid;
	char b64encoded[SMBUF];
	char decoded[SMBUF];
}	BasicAuthDescriptor;

typedef struct onion_handler_auth_pam_data_t onion_handler_auth_pam_data;

#define AS_BASIC_AUTH_DESCRIPTOR(x) ((BasicAuthDescriptor *)(x))
#define INVALIDATE_CACHEBACKEND true

int CacheValidateBasicAuth(const char *basicauth_b64encoded, const char *basicauth_decoded, unsigned long *);
int CacheInvalidateBasicAuth(unsigned long userid, bool is_invalidate_backend);
/// Creates an auth handler that do not allow to pass unless user is authenticated using a pam name.
onion_handler *onion_handler_auth_pam(const char *realm, const char *pamname, onion_handler *inside_level);
int onion_handler_auth_pam_handler(InstanceHolderForSession *, onion_handler_auth_pam_data *d, onion_request *request, onion_response *res);
void InitialiseBasicAuthLruCache(void);

void InitBasicAuthDescriptorRecyclerTypePool();
void BasicAuthDescriptorIncrementReference(BasicAuthDescriptor *descriptor_ptr, int multiples);
void BasicAuthDescriptorDecrementReference(BasicAuthDescriptor *descriptor_ptr, int multiples);
unsigned BasicAuthDescriptorPoolTypeNumber();
InstanceHolder *BasicAuthDescriptorGetInstance(ContextData *ctx_data_ptr, unsigned long call_flags);
void BasicAuthDescriptorReturnToRecycler(InstanceHolder *, ContextData *ctx_data_ptr, unsigned long call_flags);


#endif
