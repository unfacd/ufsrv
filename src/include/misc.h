/*
**
MODULEID("$Id: misc.h,v 1.1 1999/07/26 01:46:59 ayman Exp $")
**
*/

#ifndef MISC_H
# define MISC_H
#include <json-c/json.h>

 typedef void signal_f(int);

 signal_f *nsignal (int, signal_f *);
 void InitSignals (void);
 void dummy (void);
 int ValidateRequiredVesrion (const char *);
 char *LUA_GetFieldToString (const char *key);
 int LUA_GetFieldToInteger (const char *key);
 char *
 thread_error (int error);
 char *
 thread_error_wrlock (int error);
 void SetCpuAffinity (int cpu);
 static inline struct json_object *json__get(json_object *rootObj, const char* key);

 static inline struct json_object *
 json__get(struct json_object *rootObj, const char *key)
 {
     struct json_object *returnObj;
     if (json_object_object_get_ex(rootObj, key, &returnObj))
     {
         return returnObj;
     }

     return NULL;
 }
#endif

