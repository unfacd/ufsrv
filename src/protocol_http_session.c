/*
 * protocol_http_session.c
 *
 *  Created on: 9 Nov 2016
 *      Author: ayman
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <utils.h>
#include <pthread.h>
#include <json/json.h>
#include <persistance.h>
#include <sessions_delegator_type.h>
#include <protocol_http.h>
#include <protocol_http_user.h>
#include <protocol_http_session.h>

extern SessionsDelegator	*const sessions_delegator_ptr;

