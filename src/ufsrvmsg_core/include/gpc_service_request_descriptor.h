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

#ifndef UFSRV_GPC_SERVICE_REQUEST_DESCRIPTOR_H
#define UFSRV_GPC_SERVICE_REQUEST_DESCRIPTOR_H

#include <stdbool.h>

enum PrivateKeyManifestation {
    FILE_SYSTEM,
    MEMORY_BUFFER
};

//convenient grouping of GPC service request parameters
struct GpcServiceRequestDescriptor {
    bool is_refresh_token; ///> access_type=offline to get a refresh token
    const char *jwt_header_encoded;
    const char *claim_set_template;
    enum PrivateKeyManifestation private_key_manifestation;
    union {
        const char *file_name;///> full path to private key file
        const unsigned char *raw_content;///> memory buffer containing private key
    } private_key;
};
typedef struct GpcServiceRequestDescriptor GpcServiceRequestDescriptor;

#endif //UFSRV_GPC_SERVICE_REQUEST_DESCRIPTOR_H
