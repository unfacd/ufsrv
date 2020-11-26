

#ifndef SESSION_UTILS_H
# define SESSION_UTILS_H

#include <session_type.h>
#include <json/json.h>

json_object *GetPresenceInformation (Session *sesn_ptr, struct json_object *jobj_contacts);

#endif