/*
 * ufsrv_command.c
 *
 *  Created on: 25 Aug 2015
 *      Author: ayman
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <misc.h>
#include <session.h>
#include <json/json.h>
#include <ufsrvmsg_core/fence/fence_type.h>
#include <ufsrvwebsock/include/WebSocketMessage.pb-c.h>

static const char  *ufsrv_authenticated_user (Session *sesn_ptr, json_object *jobj);
static const char  *ufsrv_backlog_complete (Session *sesn_ptr, json_object *jobj);
static const char *ufsrv_loc_update (Session *sesn_ptr, json_object *jobj);
static const char *ufsrv_makebuffer (Session *sesn_ptr, json_object *jobj);
static const char *ufsrv_fence_config (Session *sesn_ptr, json_object *jobj);
static const char *ufsrv_parted_fence (Session *sesn_ptr, json_object *jobj);
static const char *ufsrv_usrmsg (Session *sesn_ptr, json_object *jobj);

static struct json_object *DecodeJsonFormattedData (const char *json_formatted_data, size_t data_size);
static UFSRVResult *V1StateSync (Session *sesn_ptr, WebSocketMessage *);

UFSRVResult *ParseServerCommand(Session *sesn_ptr, SocketMessage *sock_msg_ptr, unsigned frame_offset, size_t len);

typedef struct {
	 const char *identifier;
	 UFSRVResult * (*answer) (Session *, WebSocketMessage *);
} ServerCommand;

static ServerCommand ServerCommands[] = {
	{"/v1/StateSync", V1StateSync},
	//{NULL, NULL}
};

#if 0
static ServerCommand ServerCommands[] = {
	{"authenticated_user", ufsrv_authenticated_user},
	{"backlog_complete", ufsrv_backlog_complete},
	{"fence_config", ufsrv_fence_config},
	{"loc_update", ufsrv_loc_update},
	{"makebuffer", ufsrv_makebuffer},
	{"mparted_fence", ufsrv_parted_fence},
	{"parted_fence", ufsrv_parted_fence},
	{"usrmsg", ufsrv_usrmsg},
	{"musrmsg", ufsrv_usrmsg},
	{"/v1/StateSync", V1StateSync},
	//{NULL, NULL}
};
#endif

//'{ "type": "authenticated_user", "verified": true, "id": 3017, "name": "test-140663844726528", "email": "test-140663844726528@unfacd.com", "bid": 1,
//"_sreqid": 6, "_reqid": 0, "cid": 133362368 }'
const unsigned int nr_ufsrv_cmd = sizeof(ServerCommands)/sizeof(ServerCommand);

static const char  *ufsrv_authenticated_user (Session *sesn_ptr, json_object *jobj)
{
#if 0
	if (sesn_ptr && jobj)
	{
		unsigned long session_id=json_object_get_int(json__get(jobj, "cid"));
		sesn_ptr->session_id=session_id;

		User *u_ptr=AddUser(&(sesn_ptr->sservice.users), json_object_get_int(json__get(jobj, "id")));

		if (u_ptr)
		{
			//in global list
			u_ptr->user_details.user_name=(strdup(json_object_get_string(json__get(jobj, "name"))));

			//session owner
			sesn_ptr->sservice.user.user_details.user_id=json_object_get_int(json__get(jobj, "id"));
			sesn_ptr->sservice.user.user_details.user_name=strdup(json_object_get_string(json__get(jobj, "name")));

			fprintf(stderr, "ufsrv_authenticated_user (pid:'%lu' cid:'%lu'): ADDED NEW USER '%s' of UID '%lu' TO CLIENT GLOBAL USER LIST. Global user count '%lu'\n",
					pthread_self(), sesn_ptr->session_id,u_ptr->user_details.user_name, u_ptr->user_details.user_id, sesn_ptr->sservice.users.nEntries);

			ufcltSendLocation (sesn_ptr);
		}
		else
		{
			fprintf(stderr, "ufsrv_authenticated_user (pid:'%lu' cid:'%lu'): ERRO COUL NOT ADD NEW USER '%s' of UID '%lu' TO CLIENT GLOBAL USER LIST. Global user count '%lu'\n",
								pthread_self(), sesn_ptr->session_id,json_object_get_string(json__get(jobj, "name")),
								json_object_get_int(json__get(jobj, "id")), sesn_ptr->sservice.users.nEntries);
		}



		return NULL; //do nothing
	}
#endif
	return NULL;
}

static const char  *ufsrv_backlog_complete (Session *sesn_ptr, json_object *jobj)
{
	if (sesn_ptr && jobj)
	{
		return NULL; //do nothing
	}

	return NULL;
}

/*
 * { "lat": -33.849235, "long": 151.023175, "_reqid": 1, "_creqid": 1, "status": "ok", "origin": "server",
 * "country": "Singapore", "admin_area": "", "locality": "", "longitude": 103.800000, "latitude": 1.367000,
 * "type": "loc_update", "_sreqid": 3, "cid": 769289740 }'
 */
static const char *ufsrv_loc_update (Session *sesn_ptr, json_object *jobj)
{
	if (sesn_ptr && jobj)
		{
			return NULL; //do nothing
		}
	return NULL;
}

/*
 * { "lat": -33.849235, "long": 151.023175, "_reqid": 1, "_creqid": 1, "longitude": 103.800000, "latitude": 1.367000, "type": "makebuffer", "bid": 529527072,
 * "buffer_type": "channel", "ftype": "UFFENCE", "name": "Singapore", "cfbanner": "Singapore::", "_sreqid": 4, "cid": 769289740 }
 */
static const char *ufsrv_makebuffer (Session *sesn_ptr, json_object *jobj)
{
#if 0
	if (sesn_ptr && jobj) {
			unsigned long bid     =json_object_get_int(json__get(jobj, "bid"));
			const char *fence_name=json_object_get_string(json__get(jobj, "name"));

			Fence *f_ptr;
			if ((f_ptr = AmIMemberOfFence(SESSION_FENCE_LIST_PTR(sesn_ptr), bid))) {
				fprintf(stderr, "ufsrv_makebuffer (pid:'%lu' cid:'%lu'): I AM ALREADY IN FENCE '%s' of BID '%lu'. Total users in Fence:'%lu'\n", pthread_self(), sesn_ptr->session_id,
					f_ptr->fence_location.display_banner_name, f_ptr->fence_id, f_ptr->fence_user_sessions_list.nEntries);

				return NULL;
			}

			//ONLY links Fence to Users FenceList. Fence List does not have User in its UserList. This happens in fence_config. But user is already in Global USERLIST
			f_ptr = CreateUserFenceAndLinkToUser (&(sesn_ptr->sservice), fence_name, json_object_get_string(json__get(jobj, "cfbanner")));
			if (f_ptr) {
				f_ptr->fence_id = bid;
				fprintf(stderr, "ufsrv_makebuffer (pid:'%lu' cid:'%lu'): JOINING '%s' of BID '%lu'\n", pthread_self(), sesn_ptr->session_id, f_ptr->fence_location.display_banner_name, f_ptr->fence_id);
			} else {
				fprintf(stderr, "ufsrv_makebuffer (pid:'%lu' cid:'%lu'): ERROR COUKD NOT JOIN  '%s' of BID '%lu'\n", pthread_self(), sesn_ptr->session_id, fence_name, bid);
			}


			return NULL; //do nothing
		}
#endif
	return NULL;
}


/*
 * { "type": "fence_config", "bid": 33043456, "chan": "Singapore", "members": [ { "nick": "test-140607840519936", "uid": 759, "locality": "", "latitude": 1.367000, "longitude": 103.800000, "mode": "+r" } ],
 *  "_sreqid": 25, "_reqid": 1, "cid": 432391390 }'
 */
static const char *ufsrv_fence_config (Session *sesn_ptr, json_object *jobj)
{
#if 0
	if (sesn_ptr && jobj)
		{
			unsigned long bid=json_object_get_int(json__get(jobj, "bid"));
			const char *fence_name=json_object_get_string(json__get(jobj, "chan"));
			json_object *jobj_array=json__get(jobj, "members");//array

			//check bid in clients FenceList
			//this should have been established in make_buffer
			Fence *f_ptr = AmIMemberOfFence(SESSION_FENCE_LIST_PTR(sesn_ptr), bid);
			if (!f_ptr)
			{
				fprintf(stderr, "ufsrv_fence_config: ERROR: COULD NOT LOCATE FENCE: '%s' of BID: '%lu'\n", fence_name, bid);
				return NULL;
			}

			if (!jobj_array)
			{
				fprintf(stderr, "ufsrv_fence_config: ERROR: COULD NOT FETCH MEMBERS ARRAY\n");
				return NULL;
			}

			int jobj_array_len = json_object_array_length(jobj_array);
			//enum json_type=json_object_get_type (jobj_array);
			fprintf (stderr, "ufsrv_fence_config (pid:'%lu' cid:'%lu'): FENCE CONFIG HAS: '%d' MEMBERS. USER IS MEMBER OF: '%d' FENCES... \n",pthread_self(), sesn_ptr->session_id, jobj_array_len, SESSION_FENCE_LIST_SIZE(sesn_ptr));

			int idx;
			for (idx=0; idx<jobj_array_len; idx++)
			{
				json_object *jobj_user=json_object_array_get_idx (jobj_array, idx);//results
				//fprintf(stderr, "ufsrv_fence_config (pid:'%lu' cid:'%lu'): (idx='%d') FOUND USER: '%s' in SERVER FENCE LIST: '%s' of BID: '%lu'\n",
					// pthread_self(), sesn_ptr->session_id, idx,json_object_get_string(json__get(jobj_user, "nick")), fence_name, bid);

				//Add user to client global lists of users
				User *u_ptr=AddUser(&(sesn_ptr->sservice.users), json_object_get_int(json__get(jobj_user, "uid")));//bid);
				if (u_ptr)//new user
				{
					u_ptr->user_details.user_name=strdup(json_object_get_string(json__get(jobj_user, "nick")));

					if (!IsUserMemberOfFenceByUserId (&(f_ptr->fence_user_sessions_list), json_object_get_int(json__get(jobj_user, "uid"))))
					{
						AddThisToList (&(f_ptr->fence_user_sessions_list), u_ptr);
						fprintf(stderr, "ufsrv_fence_config (pid:'%lu' cid:'%lu'): (idx='%d') ADDED NEW GLOBAL USER: '%s' TO FENCE: '%s' of BID: '%lu'\n",
								 pthread_self(), sesn_ptr->session_id, idx, u_ptr->user_details.user_name, fence_name, bid);
					}
				}
				else
				{//existing user in global list but notnecessarily fence list
					if (json_object_get_int(json__get(jobj_user, "uid"))==sesn_ptr->sservice.user.user_details.user_id)
					{
						fprintf(stderr, "ufsrv_fence_config (pid:'%lu' cid:'%lu'): I AM ALREADY IN FENCE: NOT ADDING MYSELF TO FENCE\n",
										 pthread_self(), sesn_ptr->session_id);
						//continue;
					}

					if (!IsUserMemberOfFenceByUserId (&(f_ptr->fence_user_sessions_list), json_object_get_int(json__get(jobj_user, "uid"))))
					{
						AddThisToList (&(f_ptr->fence_user_sessions_list), u_ptr);
						fprintf(stderr, "ufsrv_fence_config (pid:'%lu' cid:'%lu'): (idx='%d') ADDED GLOBALLY EXISTING USER: '%s' TO FENCE: '%s' of BID: '%lu'\n",
							pthread_self(), sesn_ptr->session_id, idx, json_object_get_string(json__get(jobj_user, "nick")), fence_name, bid);
					}
					else
					{
						fprintf(stderr, "ufsrv_fence_config (pid:'%lu' cid:'%lu'): USER '%lu' ALREADY IN FENCE: NOT ADDING USER TO FENCE\n",
							 pthread_self(), sesn_ptr->session_id, json_object_get_int(json__get(jobj_user, "uid")));
					}
				}
			}//for

			fprintf(stderr, "ufsrv_fence_config (pid:'%lu' cid:'%lu'): FENCE '%s' has '%d' USERS \n\n", pthread_self(), sesn_ptr->session_id,
					f_ptr->fence_location.canonical_name, f_ptr->fence_user_sessions_list.nEntries);

			ufcltSendUserMessage(sesn_ptr, NULL);

			return NULL; //do nothing
		}
#endif
	return NULL;
}


//{"_cmdidx":5,"cid":1685644378,"bid":65534256,"to":"Australia","msg":"Hello","_reqid":66,"_method":"say"}'
//sending '{ "_cmdidx": 5, "bid": 65534256, "to": "Australia", "msg": "Hello", "_creqid": 2, "from": "t", "timestamp": 1442574852, "eid": 1, "type": "musrmsg", "self": true, "_reqid": 66, "_sreqid": 9, "cid": 1685644378 }'
static const char *ufsrv_usrmsg (Session *sesn_ptr, json_object *jobj)
{
#if 0
	if (sesn_ptr && jobj)
		{
			char *tmp_msg;
			unsigned long bid=json_object_get_int(json__get(jobj, "bid"));
			const char *fence_name=json_object_get_string(json__get(jobj, "to"));
			const char *to_user=json_object_get_string(json__get(jobj, "from"));
			//fprintf(stderr, "ufsrv_usrmsg (pid:'%lu' cid:'%lu'): joining '%s'\n", pthread_self(), sesn_ptr->session_id, fence_name);

			asprintf(&tmp_msg, "Hello, '%s'! I am '%s'. Nice to meet you.", to_user, sesn_ptr->sservice.user.user_details.user_name);
			json_object_object_add (jobj,"msg", json_object_new_string(tmp_msg));

			ufcltSendUserMessage (sesn_ptr, tmp_msg);
			free (tmp_msg);

			return NULL; //do nothing
		}
#endif
	return NULL;
}


//{ "bid": 1696852426, "channel": "Auburn", "fbanner": "Auburn", "cfbanner": "Auburn", "_cmdidx": "3", "_creqid": 7, "nick": "t", "hostmask": "*@*.*", "uid": 312,
//"type": "delete_buffer", "_sreqid": 32, "_reqid": 68, "cid": 510807088 }

// sending '{ "bid": 1696852426, "channel": "Auburn", "fbanner": "Auburn", "cfbanner": "Auburn", "_cmdidx": "3", "_method": "part", "_creqid": 7, "nick": "t", "hostmask": "*@*.*", "eid": 1, "uid": 312,
//"type": "mparted_fence", "_reqid": 68, "_sreqid": 31, "cid": 510807088 }'

//client initiated
//'{"cid":510807088,"bid":1696852426,"channel":"Auburn","fbanner":"Auburn","cfbanner":"Auburn","_cmdidx":"3","_reqid":68,"_method":"part"}'

static const char *ufsrv_parted_fence (Session *sesn_ptr, json_object *jobj)
{
#if 0
	if (sesn_ptr && jobj)
		{
			unsigned long bid=json_object_get_int(json__get(jobj, "bid"));
			const char *fence_name=json_object_get_string(json__get(jobj, "channel"));
			unsigned long uid=json_object_get_int(json__get(jobj, "uid"));

			Fence *f_ptr = AmIMemberOfFence(SESSION_FENCE_LIST_PTR(sesn_ptr), bid);
			if (!f_ptr)
			{
				fprintf(stderr, "ufsrv_parted_fence: ERROR: COULD NOT LOCATE USER '%uid' IN FENCE: '%s' of BID: '%lu'\n", uid, fence_name, bid);
				return NULL;
			}

			if (sesn_ptr->sservice.user.user_details.user_id==uid)
			{

				fprintf(stderr, "ufsrv_parted_fence (pid:'%lu' cid:'%lu'): I AM LEAVING  '%s'\n", pthread_self(), sesn_ptr->session_id, fence_name);
			}



			return NULL; //do nothing
		}
#endif
	return NULL;
}

//{ "accountState": true, "uid": 260, "uname": "672056174", "cid": 305882430500246859, "sid": 69976, "queue_size": 0, "location": { "origin": "server", "country": "Singapore", "adminArea": "", "locality": "", "longitude": 103.8, "latitude": 1.367 } }
static UFSRVResult *V1StateSync (Session *sesn_ptr, WebSocketMessage *wsm_ptr)
{
	if (unlikely(sesn_ptr == NULL || wsm_ptr == NULL))	return NULL;

	if (wsm_ptr->type == WEB_SOCKET_MESSAGE__TYPE__REQUEST)
	{
		WebSocketRequestMessage *wsm_req_ptr=wsm_ptr->request;
		if (unlikely(wsm_req_ptr==NULL))	_RETURN_RESULT_SESN(sesn_ptr, NULL, RESULT_TYPE_SUCCESS, RESCODE_PROG_NULL_POINTER);

		struct json_object *jobj=DecodeJsonFormattedData(wsm_req_ptr->path, strlen(wsm_req_ptr->path));
		syslog (LOG_DEBUG, "%s: My CId with teh server is: '%lu'", json_object_get_int64(json__get(jobj, "cid")));
	}

	return NULL;
}


struct json_object *DecodeJsonFormattedData (const char *json_formatted_data, size_t data_size)

{
	if (json_formatted_data)
	{
		enum json_tokener_error jerr;
		struct json_tokener 	*jtok;
		struct json_object 		*jobj	= NULL;

		#if 1

		jtok=json_tokener_new();

		do
		{
			jobj=json_tokener_parse_ex(jtok, json_formatted_data, data_size);
		}
		while ((jerr=json_tokener_get_error(jtok))==json_tokener_continue);

		if (jerr!=json_tokener_success)
		{
			jobj=NULL;
		}

		json_tokener_free(jtok);

		#endif

		return jobj;

	}//if

	return NULL;
}



UFSRVResult *ParseServerCommand(Session *sesn_ptr, SocketMessage *sock_msg_ptr, unsigned frame_offset, size_t len)
{
	WebSocketMessage *wsm_ptr;

	syslog(LOG_DEBUG, "%s: (pid:'%lu' cid:'%lu'): >> UNPAKING FRAMEOFFSET: '%d' LEN: '%lu", __func__,
				sesn_ptr->pid, SESSION_ID(sesn_ptr), frame_offset, len);

	wsm_ptr = web_socket_message__unpack(NULL, len, sock_msg_ptr->_processed_msg+frame_offset);
	if (wsm_ptr) {
		char *command = wsm_ptr->command;
		if (!command || !*command ) {
			syslog(LOG_DEBUG, "%s: (pid:'%lu' cid:'%lu'): >> NOTICE: RECEIVED EMPTY COMMAND...",  __func__,
						sesn_ptr->pid, SESSION_ID(sesn_ptr));

			__RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_ERR, RESCODE_LOGIC_NOCMND);
		}

		switch (wsm_ptr->type)
		{
		case WEB_SOCKET_MESSAGE__TYPE__REQUEST:
			syslog(LOG_DEBUG, "%s: (pid:'%lu' cid:'%lu'): >> WEB_SOCKET_REQUEST COMMAND: '%s' id: '%lu'", __func__,
				SESSION_PID(sesn_ptr), SESSION_ID(sesn_ptr), command, wsm_ptr->request->id);

		int i = 0;//=nr_ufsrv_cmd;

		while(i++ < nr_ufsrv_cmd)
		{
			ServerCommand *p = (ServerCommands + (i-1));
			//fprintf(stderr, "COMPARING '%d:%s'\n", i-1, p->identifier);

			if(!strcmp(command, p->identifier)) {
				//ServerCommand *p=(ServerCommands+(i));

				char *str = (*p->answer)(sesn_ptr, NULL/*jobj*/);

				//json_object_put(jobj);
			} else {
				fprintf(stderr, "%s (pid:'%lu' cid:'%lu'): ERROR: COMMAND IDENTIFIER NOT RECOGNISED: '%s'\n",  __func__, pthread_self(), sesn_ptr->session_id, command);
			}
		}
#if 0
			//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
			//int cmdidx=UfsrvCommandIndexGet(sesn_ptr, command);//wsm_ptr->request->path);
			//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

			syslog(LOG_DEBUG, "%s: (pid:'%lu' cid:'%lu'): >> PATH '%s' HAS CMDIDX: '%d'", __func__,
					sesn_ptr->pid, SESSION_ID(sesn_ptr), wsm_ptr->request->path, cmdidx);

			_UfsrvCommandInvokeCommandCallback (sesn_ptr, wsm_ptr, cmdidx);
#endif
		break;

		//TODO: this shuld be merged with request. It is separated for debugging and semantics testing only
		case WEB_SOCKET_MESSAGE__TYPE__RESPONSE:
			syslog(LOG_DEBUG, "%s: (pid:'%lu' o, :'%p', cid:'%lu'): >> WEB_SOCKET_MESSAGE__TYPE__RESPONSE MESSAGE '%s'", __func__, sesn_ptr->pid, sesn_ptr, SESSION_ID(sesn_ptr), wsm_ptr->response->message);
			break;

		default:
			syslog(LOG_DEBUG, "%s: (pid:'%lu' cid:'%lu'): >> WEB_SOCKET_MESSAGE__TYPE__UNKNOWN...", __func__, sesn_ptr->pid, SESSION_ID(sesn_ptr));

		}
		web_socket_message__free_unpacked(wsm_ptr, NULL);

		//return 1;
		__RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_SUCCESS, RESCODE_IO_MSGPARSED);
	}
	else
	{
		syslog(LOG_NOTICE, "%s: (pid:'%lu' cid:'%lu'): ERROR: COULD NOOT UNPACK WEBSOCKETMESSAGE... frame_offset: '%d' payload_length: '%lu'",
				__func__,sesn_ptr->pid, SESSION_ID(sesn_ptr), frame_offset, len);

		//return 0;
		__RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_ERR, RESCODE_IO_PROTOUNPACKING);
	}

	__RETURN_RESULT(sesn_ptr->sservice, NULL, RESULT_TYPE_NOOP, RESCODE_PROG_NULL_POINTER);


}


#if 0
char * ParseServerCommand(Session *sesn_ptr, int frame_offset)//, json_object *jobj, const char *cmd)
{
	json_object *jobj;

	//start of json tokeniser block
	{
		register const char *aux;
		enum json_tokener_error jerr;
		struct json_tokener *jtok;

		//retrieve decoded buffer from socket
		aux=sesn_ptr->ssptr->msg_out2;//+2;
		aux+=frame_offset;

		//fprintf(stderr, "ParseServerCommand (pid:'%lu' cid:'%lu'): tokensing: '%s'\n", pthread_self(), sesn_ptr->session_id, aux);

		jtok=json_tokener_new();

		do
		{
			jobj=json_tokener_parse_ex(jtok, aux, strlen(aux));
		}
		while ((jerr=json_tokener_get_error(jtok))==json_tokener_continue);

		if (jerr!=json_tokener_success)
		{
			fprintf(stderr, "ParseServerCommand (pid:'%lu' cid:'%lu'): JSON tokeniser Error: '%s'. Terminating.\n",
				 pthread_self(), sesn_ptr->session_id, json_tokener_error_desc(jerr));

			json_tokener_free(jtok);
			return 0; //session will be destructed

		}

		json_tokener_free(jtok);
	}//end of json tokeniser block. we now have jobj to query

	char *ufsrv_command=json_object_get_string(json__get(jobj, "type"));
	if (!ufsrv_command || (strlen(ufsrv_command)==0))
	{
		fprintf(stderr, "ParseServerCommand (pid:'%lu' cid:'%lu'): ERROR: TYPE COMMAND IDENTIFIER NOT SPECIFIED\n", pthread_self(), sesn_ptr->session_id);
		return 0;
	}

	//fprintf(stderr, "ParseServerCommand (pid:'%lu' cid:'%lu'): SUCCESS ('%d'): COMMAND IDENTIFIER: '%s'\n",  pthread_self(), sesn_ptr->session_id, nr_ufsrv_cmd, ufsrv_command);

    int i=0;//=nr_ufsrv_cmd;

    while(i++<nr_ufsrv_cmd)
    {

    	ServerCommand *p=(ServerCommands+(i-1));
    	//fprintf(stderr, "COMPARING '%d:%s'\n", i-1, p->identifier);

        if(!strcmp(ufsrv_command, p->identifier))
        {
        	//ServerCommand *p=(ServerCommands+(i));

        	char *str=(*p->answer)(sesn_ptr, jobj);

        	json_object_put(jobj);

        	return str;
        }
        else
        {
        	//fprintf(stderr, "ParseServerCommand (pid:'%lu' cid:'%lu'): ERROR: COMMAND IDENTIFIER NOT RECOGNISED: '%s'\n",  pthread_self(), sesn_ptr->session_id, ufsrv_command);
        }
    }
}
#endif
