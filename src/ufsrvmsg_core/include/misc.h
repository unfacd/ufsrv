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

#ifndef MISC_H
# define MISC_H

 typedef void signal_f(int);

 signal_f *nsignal(int, signal_f *);
 void InitSignals(void);
 void dummy(void);
 int ValidateRequiredVersion(const char *);
 char *LUA_GetFieldToString(const char *key);
 int LUA_GetFieldToInteger(const char *key);

 void SetCpuAffinity(int cpu);

#include <json-c/json.h>
 static inline struct json_object *json__get(json_object *rootObj, const char* key);
 static inline json_object *
 json__get(json_object *rootObj, const char *key)
 {
     struct json_object *returnObj;
     if (json_object_object_get_ex(rootObj, key, &returnObj)) {
       return returnObj;
     }

     return NULL;
 }

 #endif

