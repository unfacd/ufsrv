/*
	Onion HTTP server library
	Copyright (C) 2010-2016 David Moreno Montero and others

	This library is free software; you can redistribute it and/or
	modify it under the terms of, at your choice:
	
	a. the Apache License Version 2.0. 
	
	b. the GNU General Public License as published by the 
		Free Software Foundation; either version 2.0 of the License, 
		or (at your option) any later version.
	 
	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of both libraries, if not see 
	<http://www.gnu.org/licenses/> and 
	<http://www.apache.org/licenses/LICENSE-2.0>.
	*/

#ifndef __ONION_HANDLER_AUTH_PAM__
#define __ONION_HANDLER_AUTH_PAM__

#include <ufsrvresult_type.h>
#include <instance_type.h>
#include  <http_request_handler.h>
#include <session.h>

typedef InstanceHolder InstanceHolderForBasicAuthDescriptor;

typedef struct BasicAuthDescriptor {
	unsigned long userid;
	char b64encoded[SMBUF];
	char decoded[SMBUF];
}	BasicAuthDescriptor;

typedef struct onion_handler_auth_pam_data_t onion_handler_auth_pam_data;

int CacheValidateBasicAuth (Session *sesn_ptr, const char *basicauth_b64encoded, const char *basicauth_decoded, unsigned long *);
//UFSRVResult *CacheBackendGetDecodedBasicAuth (Session *sesn_ptr, const char *basicauth_b64encoded);
//UFSRVResult *CacheBackendSetDecodedBasicAuth (Session *sesn_ptr, const char *basicauth_b64encoded, const char *basicauth_decoded, unsigned long);
/// Creates an auth handler that do not allow to pass unless user is authenticated using a pam name.
onion_handler *onion_handler_auth_pam(const char *realm, const char *pamname, onion_handler *inside_level);
int onion_handler_auth_pam_handler(Session *sesn_ptr, onion_handler_auth_pam_data *d, onion_request *request, onion_response *res);
void InitialiseBasicAuthLruCache (void);

void InitBasicAuthDescriptorRecyclerTypePool ();
void BasicAuthDescriptorIncrementReference (BasicAuthDescriptor *descriptor_ptr, int multiples);
void BasicAuthDescriptorDecrementReference (BasicAuthDescriptor *descriptor_ptr, int multiples);
unsigned BasicAuthDescriptorPoolTypeNumber();
InstanceHolder *BasicAuthDescriptorGetInstance (ContextData *ctx_data_ptr, unsigned long call_flags);
void BasicAuthDescriptorReturnToRecycler (InstanceHolder *, ContextData *ctx_data_ptr, unsigned long call_flags);


#endif
