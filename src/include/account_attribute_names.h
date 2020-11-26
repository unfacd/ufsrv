/**
 * Copyright (C) 2015-2020 unfacd works
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

//
// Created by devops on 10/8/20.
//

#ifndef UFSRV_ACCOUNT_ATTRIBUTE_NAMES_H
#define UFSRV_ACCOUNT_ATTRIBUTE_NAMES_H

#define AUTHENTICATED_DEVICE 					0
#define ACCOUNT_JSONATTR_ID						"id"
#define ACCOUNT_JSONATTR_ACCOUNT_STATE  "account_state"
#define ACCOUNT_JSONATTR_SESSION_STATE  "session_state"
#define ACCOUNT_JSONATTR_USERID				"userid"
#define ACCOUNT_JSONATTR_EID  				"eid"
#define ACCOUNT_JSONATTR_EVENTS_COUNTER "events_counter"
#define ACCOUNT_JSONATTR_UFSRVUID			"ufsrvuid"
#define ACCOUNT_JSONATTR_UUID			    "uuid"
#define ACCOUNT_JSONATTR_REGO_ID			"registration_id"
#define ACCOUNT_JSONATTR_AUTH_TOKEN		"authentication_token"
#define ACCOUNT_JSONATTR_SALT					"salt"
#define ACCOUNT_JSONATTR_COOKIE				"cookie"
#define ACCOUNT_JSONATTR_SIGNED_PREKY	"signed_prekey"
#define ACCOUNT_JSONATTR_GCM_ID				"gcm_id"
#define ACCOUNT_FETCHES_MSG						"fetches_messages"
#define ACCOUNT_JSONATTR_NUMBER 			"number"
#define ACCOUNT_JSONATTR_CREATED			"created"
#define ACCOUNT_JSONATTR_LASTSEEN			"lastseen"
#define ACCOUNT_JSONATTR_USER_AGENT		"user_agent"
#define ACCOUNT_JSONATTR_IDENTITY_KEY	"identityKey"
#define ACCOUNT_JSONATTR_NICKNAME			"nickname"
#define ACCOUNT_JSONATTR_PROFILE_KEY	"profile_key"
#define ACCOUNT_JSONATTR_PROFILE_COMMITMENT	"profile_commitment"
#define ACCOUNT_JSONATTR_PROFILE_VERSION	"profile_version"
#define ACCOUNT_JSONATTR_ACCESS_TOKEN	"access_token" //user access token derived from profile key provided by owner during registration. Otherusers can derive to prove knowledge of profile
#define ACCOUNT_JSONATTR_REGO_STATUS	"rego_status"
#define ACCOUNT_JSONATTR_AVATAR       "avatar"
#define ACCOUNT_JSONATTR_PREFS_BOOL   "prefs_bool"
#define ACCOUNT_JSONATTR_E164NUMBER 	"e164number"
#define ACCOUNT_JSONATTR_USERNAME 		"username"
#define ACCOUNT_JSONATTR_PASSWORD     "password"
#define ACCOUNT_JSONATTR_NONCE        "nonce"
#define ACCOUNT_JSONATTR_E164NUMBER 	"e164number"
#define ACCOUNT_JSONATTR_REGO_PIN     "rego_pin"
#define ACCOUNT_JSONATTR_BASELOC_ZONE  "baseloc_zone"
#define ACCOUNT_JSONATTR_GEOLOC_TRIGGER "geoloc_trigger"
#define ACCOUNT_JSONATTR_UNSOLICITED_CONTACT  "unsolicited_contact"
#define ACCOUNT_JSONATTR_GUARDIAN_UID  "guardian_uid"
#define ACCOUNT_JSONATTR_TYPE						"type"
#define ACCOUNT_JSONATTR_CREDENTIAL     "credential"

#endif //UFSRV_ACCOUNT_ATTRIBUTE_NAMES_H
