/*
 * ufsrvapi_endpoints.h
 *
 *  Created on: 21 Jul 2016
 *      Author: ayman
 */

#ifndef UFCLT_UFSRVAPI_ENDPOINTS_H_
#define UFCLT_UFSRVAPI_ENDPOINTS_H_
#include <session.h>

int
BackendGenerateAuthenticationCookie (Session *sesn_ptr);
int
BackendSignUpUser (Session *sesn_ptr);
int
BackendValidateUser (Session *sesn_ptr);
void BackendGetCurrentUserInfo (Session *sesn_ptr);


#endif /* UFCLT_UFSRVAPI_ENDPOINTS_H_ */
