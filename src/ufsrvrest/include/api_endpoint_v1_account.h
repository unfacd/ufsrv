/**
 * Copyright (C) 2015-2019 unfacd works
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

#ifndef SRC_API_ENDPOINT_V1_ACCOUNT_H_
#define SRC_API_ENDPOINT_V1_ACCOUNT_H_
#include <recycler/instance_type.h>
#include <json/json.h>

#define API_ENDPOINT_V1(x) int x (InstanceHolder *instance_sesn_ptr)

API_ENDPOINT_V1(ACCOUNT_SIGNON);
API_ENDPOINT_V1(ACCOUNT_CREATENEW);
API_ENDPOINT_V1(NONCE);
API_ENDPOINT_V1(ACCOUNT_NONCE);
API_ENDPOINT_V1(ACCOUNT_GENERATEPASSWORDHASH);
API_ENDPOINT_V1(ACCOUNT_VERIFYNEW_VOICE);
API_ENDPOINT_V1(ACCOUNT_VERIFYNEW_VOICESCRIPT);
API_ENDPOINT_V1(ACCOUNT_VERIFYSTATUS);
API_ENDPOINT_V1(ACCOUNT_VERIFYNEW);
API_ENDPOINT_V1(ACCOUNT_ATTACHMENT);
API_ENDPOINT_V1(ACCOUNT_KEYS);
API_ENDPOINT_V1(ACCOUNT_KEYS_SIGNED);
API_ENDPOINT_V1(ACCOUNT_KEYS_STATUS);
API_ENDPOINT_V1(ACCOUNT_KEYS_PREKEYS);
API_ENDPOINT_V1(ACCOUNT_DEVICES);
API_ENDPOINT_V1(ACCOUNT_GCM);
API_ENDPOINT_V1(PREFS);
API_ENDPOINT_V1(PREFSGROUP);
API_ENDPOINT_V1(PROFILE);
API_ENDPOINT_V1(PREFSSTICKY_GEOGROUP);
API_ENDPOINT_V1(ACCOUNT_SHARED_CONTACTS);
API_ENDPOINT_V1(ACCOUNT_USERATTRIBUTES);
API_ENDPOINT_V1(NICKNAME);
API_ENDPOINT_V1(STATESYNC);
API_ENDPOINT_V1(CAPTCHA);
API_ENDPOINT_V1(CERTIFICATE_DELIVERY);


#endif /* SRC_API_ENDPOINT_V1_ACCOUNT_H_ */
