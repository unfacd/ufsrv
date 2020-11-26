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

#ifndef SRC_INCLUDE_USER_PREFERENCES_TYPE_H_
#define SRC_INCLUDE_USER_PREFERENCES_TYPE_H_

 #include <ufsrv_core/user/user_preference_descriptor_type.h>
#include <ufsrvresult_type.h>

//two types of preference sources: pure user-related and user-related but relative to a give fence
enum PrefType {
	PREFTYPE_USER=0,
	PREFTYPE_FENCEUSER
};

typedef unsigned long UserPrefOffset;

typedef struct UserPreferencesTypeOps {
	UFSRVResult * (*intra_msg_handler)(ClientContextData *, CommandContextData *);

}UserPreferencesTypeOps;

typedef struct UserPreferences {
	size_t 										prefs_table_sz;
	UserPreferenceDescriptor 	**prefs_table;
	UserPreferencesTypeOps		type_ops;
} UserPreferences;


typedef struct UserPreferencesRegistry {
	UserPreferences *master_pref;
	size_t master_pref_size;
} UserPreferencesRegistry;

#endif /* SRC_INCLUDE_USER_PREFERENCES_TYPE_H_ */
