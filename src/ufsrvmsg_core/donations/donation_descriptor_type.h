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

#ifndef UFSRV_DONATION_DESCRIPTOR_TYPE_H
#define UFSRV_DONATION_DESCRIPTOR_TYPE_H

#include "uflib/standard_c_includes.h"
#include <ufsrvmsg_core/donations/donations_enum_types.h>
#include <json-c/json.h>

/**
 * Key Backup Service key data encapsulation model.
 */
struct DonationDescriptor {
    bool is_struct_transfer; ///< whether structure members have been value-filled
    unsigned int subscription_id;
    const char *subscriber_id,
               *currency;
    struct {
        bool is_set; ///< if set, a raw json object will be returned
        json_object *jobj;
    } raw;
    struct {
        bool is_set; ///< if set, a serialised json object will be returned
        char *jobj_str;
    } serialised;
};
typedef struct DonationDescriptor DonationDescriptor;

#endif //UFSRV_DONATION_DESCRIPTOR_TYPE_H
