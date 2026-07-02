#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>

#include <json/json.h>
#include "ufclt_commands.h"

//{"_cmdidx":"7","long":151.0231748,"lat":-33.8492348,"locl":"Auburn","count":"Australia","admina":"New South Wales","_reqid":38,"_method":"void","cid":27723264}
//'{"_cmdidx":"7","long":151.0231741,"lat":-33.8492354,"locl":"Auburn","count":"Australia","admina":"New South Wales","_reqid":29,"_method":"void","cid":174710552}'
char *
ufcltSendLocation (Session *sesn_ptr)
{

	if (sesn_ptr)
	{
		json_object *jobj;

		jobj=json_object_new_object();
		json_object_object_add (jobj,"_cmdidx", json_object_new_string("7"));
		json_object_object_add (jobj,"cid", json_object_new_int(sesn_ptr->session_id));
		//json_object_object_add (jobj,"status", json_object_new_string("partial"));
		json_object_object_add (jobj,"lat", json_object_new_double(-33.8492348));
		json_object_object_add (jobj,"long", json_object_new_double(151.0231748));
		json_object_object_add (jobj,"locl", json_object_new_string("Auburn"));
		json_object_object_add (jobj,"count", json_object_new_string("Australia"));
		json_object_object_add (jobj,"admina", json_object_new_string("New South Wales"));

		//printf("ParseServerCommand (pid:'%lu' cid:'%lu'): SENDING '%s'/n",
				//pthread_self(), sesn_ptr->session_id, json_object_to_json_string(jobj));

		//		if ((MarshalRequest(sesn_ptr, jobj))<0)
		{

		}
		//json_object_object_add (jobj,"_req", json_object_new_int(SESSION_SERVICE_USER_DETAILS(sesn_ptr).email));
	}
}


//sending '{ "_cmdidx": 5, "bid": 65534256, "to": "Australia", "msg": "Hello", "_creqid": 2, "from": "t", "timestamp": 1442574852, "eid": 1, "type": "musrmsg", "self": true, "_reqid": 66, "_sreqid": 9, "cid": 1685644378 }'
//{"_cmdidx":5,"cid":1685644378,"bid":65534256,"to":"Australia","msg":"Hello","_reqid":66,"_method":"say"}'
char *
ufcltSendUserMessage (Session *sesn_ptr, char *msg)
{

	if (sesn_ptr)
	{
		json_object *jobj;
		Fence *f_ptr;

		jobj=json_object_new_object();
		json_object_object_add (jobj,"_cmdidx", json_object_new_string("5"));
		ListEntry *eptr;
		char *temp_string;
		for (eptr=sesn_ptr->sservice.session_user_fence_list.head; eptr && eptr->whatever; eptr=eptr->next)
		{
			Fence *f_ptr=(Fence *)eptr->whatever;
			json_object_object_add (jobj,"bid", json_object_new_int(f_ptr->fence_id));
			json_object_object_add (jobj,"to", json_object_new_string(f_ptr->fence_location.display_banner_name));
			if (msg)
			{
				temp_string=msg;
				json_object_object_add (jobj,"msg", json_object_new_string(temp_string));
			}
			else
			{
				asprintf(&temp_string, "Hello, I am %s", sesn_ptr->sservice.user.user_details.user_name);
				json_object_object_add (jobj,"msg", json_object_new_string(temp_string));
				free (temp_string);
			}
		}
		//create st;
		//printf("ParseServerCommand (pid:'%lu' cid:'%lu'): SENDING '%s'/n",
				//pthread_self(), sesn_ptr->session_id, json_object_to_json_string(jobj));
		//if ((MarshalRequest(sesn_ptr, jobj))<0)
		{

		}
		//json_object_object_add (jobj,"_req", json_object_new_int(SESSION_SERVICE_USER_DETAILS(sesn_ptr).email));
	}
}
