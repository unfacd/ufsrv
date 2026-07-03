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

#ifndef UFSRV_KBS_DESCRIPTOR_TYPE_H
#define UFSRV_KBS_DESCRIPTOR_TYPE_H

/**
 * Key Backup Service key data encapsulation model.
 */
struct KbsDescriptor {
    bool is_struct_transfer; ///< whether structure members have been value-filled
    const char *masterkey,
               *hash,
               *pin,
               *rego_lock,
               *ciphertext;
    struct {
        bool is_set; ///< if set by user, a raw json object will be returned
        json_object *jobj;
    } raw;
    struct {
        bool is_set; ///< if set by user, a serialised json object will be returned
        char *jobj_str;
    } serialised;
};
typedef struct KbsDescriptor KbsDescriptor;

#endif //UFSRV_KBS_DESCRIPTOR_TYPE_H
