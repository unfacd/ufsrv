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

#ifndef UFSRV_PROFILE_KEY_STORE_TYPE_H
#define UFSRV_PROFILE_KEY_STORE_TYPE_H

#include <config.h>

typedef struct ProfileKeyStore {
  char serialised[CONFIG_USER_PROFILEKEY_MAX_SIZE_ENCODED + 1];
  unsigned char *raw;
  size_t raw_sz;
} ProfileKeyStore;

enum ProfileKeyFormattingCode {
  KEY_RAW,
  KEY_B64_SERIALISED
};

#endif //UFSRV_PROFILE_KEY_STORE_TYPE_H
