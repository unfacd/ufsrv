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

#ifndef UFSRV_SYNCHRONISED_CONFIG_NONPUBLIC_H
#define UFSRV_SYNCHRONISED_CONFIG_NONPUBLIC_H

#define TESTUSER_NAME     "+61412345678"
#define TESTUSER_NAME_PLAYSTORE     "undefined"
#define APIKEY_GOOGLE_GCM "undefined"
#define APIURL_GOOGLE_GCM "https://undefined"

#define APIKEY_GEOCODING "undefined"
#define APIURL_GEOCODING "https://undefined"

#define APIURL_SMS_PROD					"https://undefined"
#define APIURL_SMS_MOCK					"https://undefined"
#define APIURL_VOICE_PROD				"https://undefined"
#define APIURL_VOICE_MOCK				"https://undefined"
#define APITOKEN_SMSVOICE_PROD	"undefined"
#define APITOKEN_SMSVOICE_MOCK	"undefined"
#define	API_FROM_SMSVOICE_PROD	"+614undefined"
#define	API_FROM_SMSVOICE_MOCK	"+15005550006"

#define SERVER_PRIVATEKEY       "undefined"
#define SERVER_PUBLICKEY        "undefined"
#define SERVER_PUBLICKEY_SERIALISED "undefined"
#define SERVER_KEYID            1

#define PRIVATE_SERVER_PARAM   "undefined"
#define PUBLIC_SERVER_PARAM    "undefined"

#define API_EMAIL_KEY   "undefined"
#define API_EMAIL_URL   "undefined"

#define GPC_INTEGRITY_API_OAUTH_JWT_HEADER "{}"
#define GPC_INTEGRITY_API_OAUTH_JWT_HEADER_B64_ENCODED ""
#define GPC_INTEGRITY_API_OAUTH_JWT_CLAIM_SET "{ %s %lu %lu}"

#define GPC_FIREBASE_MESSAGING_OAUTH_JWT_HEADER "{\"alg\":\"RS256\",\"typ\":\"JWT\", \"kid\":\"e4\"}"
#define GPC_FIREBASE_MESSAGING_OAUTH_JWT_HEADER_B64_ENCODED "e0"
#define GPC_FIREBASE_MESSAGING_OAUTH_JWT_CLAIM_SET "{ \"iss\":\"unfacount.com\", \"scope\": \"https://www.googleapis.com/auth/playintegrity\", \"aud\": \"https://oauth2.googleapis.com/token\", \"access_type\":\"%s\", \"exp\": %lu, \"iat\": %lu}"

#define GOOGLE_OAUTH_PK ""
#define GOOGLE_OAUTH_PUBK ""

#define PPKS	"undefined"

#endif //UFSRV_SYNCHRONISED_CONFIG_NONPUBLIC_H