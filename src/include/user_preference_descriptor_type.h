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

#ifndef SRC_INCLUDE_USER_PREFERENCE_DESCRIPTOR_TYPE_H_
#define SRC_INCLUDE_USER_PREFERENCE_DESCRIPTOR_TYPE_H_

#include <user_type.h>//for UserPrefsOffsets
#include <fence_event_type.h>

typedef enum PrefValueType{
	PREFVALUETYPE_BOOL=0,
	PREFVALUETYPE_INT,
	PREFVALUETYPE_STR,
	PREFVALUETYPE_INT_MULTI, //array of ints
	PREFVALUETYPE_STR_MULTI,
	PREFVALUETYPE_BLOB,
	PREFVALUETYPE_BLOB_MULTI,
	PREFVALUETYPE_INVALID,
} PrefValueType;

//used to specify where to retriev the stored pre value from, ostly to enable testing and debugging
typedef enum PrefsStore {
  PREFSTORE_DEFAULT=0,
	PREFSTORE_MEM=1,
	PREFSTORE_CACHED,
	PREFSTORE_PERSISTED,
	PREFSTORE_EVERYWHERE
} PrefsStore;

//typedef void  ClientContextData;
//typedef	void 	CommandContextData;

typedef struct UserPreferenceDescriptor UserPreferenceDescriptor;

typedef UserPreferenceDescriptor * (*UserPreferenceOpSet)(ClientContextData *, UserPreferenceDescriptor *, PrefsStore, UfsrvEvent *);
typedef UserPreferenceDescriptor * (*UserPreferenceOpGet)(ClientContextData *, UserPreferenceDescriptor *, PrefsStore, UserPreferenceDescriptor *);
typedef UserPreferenceDescriptor * (*UserPreferenceValidate)(ClientContextData *,  UserPreferenceDescriptor *);
typedef UserPreferenceDescriptor * (*UserPreferenceOpSetLocal)(ClientContextData *,  UserPreferenceDescriptor *);
typedef UserPreferenceDescriptor * (*UserPreferenceOpGetLocal)(ClientContextData *,  UserPreferenceDescriptor *);

typedef struct UserPreferenceOps {
	UserPreferenceDescriptor * (*pref_set)(ClientContextData *, UserPreferenceDescriptor *, PrefsStore,  UfsrvEvent *out);
	UserPreferenceDescriptor * (*pref_get)(ClientContextData *, UserPreferenceDescriptor *, PrefsStore, UserPreferenceDescriptor *out);
	UserPreferenceDescriptor * (*pref_set_local)(ClientContextData *, UserPreferenceDescriptor *);
  UserPreferenceDescriptor * (*pref_get_local)(ClientContextData *, UserPreferenceDescriptor *);
} UserPreferenceOps;

struct UserPreferenceDescriptor {
	unsigned long					pref_id;	//for bool 0-63 are reserved, inline with offset
	const char 						*pref_name;//pointer to static name

	PrefValueType 				pref_value_type;

	union {
	bool 					pref_value_bool;
	unsigned long	pref_value_int;
	char 		*pref_value_str;
	void    *pref_value_blob;
	void 		**pref_value_multi;
	} value;

	UserPreferenceDescriptor * (*pref_validate)(ClientContextData *, UserPreferenceDescriptor *);
	ClientContextData * (*pref_value_formatter)(ClientContextData *, UserPreferenceDescriptor *, ClientContextData *);

	const UserPreferenceOps *pref_ops;
} ;



#endif /* SRC_INCLUDE_USER_PREFERENCE_DESCRIPTOR_TYPE_H_ */
