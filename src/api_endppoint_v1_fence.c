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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <thread_context_type.h>
#include <misc.h>
#include <utils.h>
#include <utils_crypto.h>
#include <api_endpoint_v1_fence.h>
#include <fence.h>
#include <fence_utils.h>
#include <fence_proto.h>
#include <user_backend.h>
#include <http_request_handler.h>
#include <h_handler.h>
#include <response.h>
#include <url.h>
#include <http_session_type.h>
#include <json/json.h>
#include <transmission_message_type.h>
#include <protocol_http.h>
#include <dictionary.h>
#include <SignalService.pb-c.h>
#include <ufsrv_msgcmd_type_enum.h>
#include <lzf/lzf.h>

extern __thread ThreadContext ufsrv_thread_context;

static const char *err="Server unable to complete request.";

/**
 * 	@brief: This endpoint manipulates the hashstore ACCOUNTS_DIRECTORY in the redis backend.
 * 	Each account, upon successful registration will have its verified number encoded and stored in this directory,
 * 	which is primarily used to cache users for quick look up if they are registred and also to perform intersection between user shared
 * 	accounts.
 *
 * 	GET: return a previously stored, encoded user number.
 * 	curl -u a:a -X GET "https://api.unfacd.io:20080/V1/Registry/UserToken/eG1eChJyw5d\/I"
{ "token": "eG1eChJyw5d\/I" }

	Only available in trusted/dev mode
 	 POST/PUT: both idempotent. The passed number will be encoded and stored in the backend
 * 	curl -u a:a -X POST "https://api.unfacd.io:20080/V1/Registry/UserToken/%2B+61xxxxx"
{ "token": "eG1eChJyw5d\/I" }

	Only available in trusted/dev mode
	DELETE: Delete previously stored token. 200 retuned upon success.
	 '{"destination":"+61414821358","messages":[{"body":"Mwi..3voB","content":null,"destinationDeviceId":1,"destinationRegistrationId":0,"type":3}],"relay":null,"timestamp":1471608758401}'
 */
API_ENDPOINT_V1(FENCE)
{
	HttpSession 		*http_ptr;
	struct json_object	*jobj_msg	= NULL;

	#define _THIS_PATH_FENCE	"/V1/Fence"

	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);
	jobj_msg=HTTPSESN_JSONDATA(((HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr)));

	if (unlikely(IS_EMPTY(jobj_msg)))	goto request_error;

	size_t pathprefix_len=strlen( _THIS_PATH_FENCE);
	const char *full_path=onion_request_get_fullpath(HTTPSESN_REQUEST_PTR(http_ptr));

	if (strlen(full_path)<pathprefix_len)	goto request_error;

	int flags=onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));

	if ((flags&OR_METHODS)==OR_POST) {
		//TODO: check if device is still active
		{
			//fetch the messages
			int 				jobj_array_size		= 0;
			const char 	*destination			= json_object_get_string(json__get(jobj_msg, "destination"));
			time_t 			msg_timestamp			= json_object_get_int64(json__get(jobj_msg, "timestamp"));
			struct json_object	*jobj_messages_array	= json__get(jobj_msg, "messages");

			if (unlikely((jobj_messages_array==NULL))) {
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: No message found", __func__, pthread_self(), sesn_ptr);
				goto request_error;
			}
			if  (unlikely((jobj_array_size=json_object_array_length(jobj_messages_array))==0)) {
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: zero message list found", __func__, pthread_self(), sesn_ptr);
				goto request_error;
			}

			//TODO: validate rego id
			int					i;
			struct json_object	*jobj_entry=NULL;

			for (i=0; i<jobj_array_size; i++) {
				jobj_entry=json_object_array_get_idx (jobj_messages_array, i);
				if (jobj_entry) {
					int device_id	= json_object_get_int(json__get(jobj_entry, "destinationDeviceId"));
					int rego_id		= json_object_get_int(json__get(jobj_entry, "destinationRegistrationId"));

#ifdef __UF_FULLDEBUG
					syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', destination_number:'%s', device_id:'%d', rego_id:'%d'}: Found destination details...", __func__, pthread_self(), sesn_ptr, destination_number, device_id, rego_id);
#endif
					DataMessage data_msg=DATA_MESSAGE__INIT;

					const char *msg_body_b64=json_object_get_string(json__get(jobj_entry, "content"));//legacy optional

					char *msg_content_decoded=NULL;
					if (IS_EMPTY(msg_body_b64)) {
						syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', device_id:'%d', rego_id:'%d'}: ERROR: MSG BODY IS MISSING...", __func__, pthread_self(), sesn_ptr, device_id, rego_id);
						goto request_error;
					}

#ifdef __FULL_DEBUG
					syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', destination_number:'%s', b64_msg:'%s'}: B64 encoded message...", __func__, pthread_self(), sesn_ptr, destination_number, msg_body_b64);
#endif
					int rc_len=0;
					msg_content_decoded=(char *)base64_decode((unsigned char *)msg_body_b64, strlen(msg_body_b64), &rc_len);
					if (IS_EMPTY(msg_content_decoded)) {
						syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', device_id:'%d', rego_id:'%d'}: ERROR: COULD NOT b64-DECODE BODY MSG...", __func__, pthread_self(), sesn_ptr, device_id, rego_id);
						goto request_error;
					}

#ifdef __FULL_DEBUG
					syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', destination_number:'%s', b64_msg:'%s'}: B64 decoded message...", __func__, pthread_self(), sesn_ptr, destination_number, msg_content_decoded);
#endif

					DataMessage *dm_ptr=NULL;

					dm_ptr=data_message__unpack(NULL, rc_len, (unsigned char *)msg_content_decoded);
					if (unlikely(IS_EMPTY(dm_ptr))) {
						free (msg_content_decoded);
						syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', device_id:'%d', rego_id:'%d'}: ERROR: COULD NOT PROTOBUF-UNPACK DataMessage...", __func__, pthread_self(), sesn_ptr, device_id, rego_id);
						goto request_error;
					}

					GroupContext *gctx_ptr=dm_ptr->group;
					FenceCommand *fcmd_ptr=dm_ptr->ufsrvcommand->fencecommand;
					AttachmentPointer *atch_ptr=NULL;

					if (!(IS_EMPTY(fcmd_ptr))) {
#ifdef __UF_FULLDEBUG

						if (fcmd_ptr->n_fences) {
							syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', destination_number:'%s', device_id:'%d', rego_id:'%d', fence_cmd:'%d', cmd_args:'%d', group_name:'%s', members_sz:'%lu'}: RECIEVED GROUP CONTEXT", __func__, pthread_self(), sesn_ptr, destination_number, device_id, rego_id, fcmd_ptr->header->command, fcmd_ptr->header->args, fcmd_ptr->fences[0]->fname, fcmd_ptr->fences[0]->n_members);
						}

						if (dm_ptr->n_attachments) {
							atch_ptr=dm_ptr->attachments[0];
							syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', destination_number:'%s', device_id:'%d', group_name:'%s' attachment_id:'%s', content_type:'%s' thumbnail:'%d' key:'%d'}: RECIEVED ATTACHMENT", __func__, pthread_self(), sesn_ptr, destination_number, device_id, fcmd_ptr->fences[0]->fname, atch_ptr->ufid, atch_ptr->contenttype, atch_ptr->has_thumbnail, atch_ptr->has_key);
						}

						if (gctx_ptr->avatar) {
							atch_ptr=gctx_ptr->avatar;
							syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', destination_number:'%s', device_id:'%d', group_name:'%s' attachment_id:'%s', content_type:'%s' thumbnail:'%d' key:'%d'}: RECIEVED GROUP AVATAR", __func__, pthread_self(), sesn_ptr, destination_number, device_id, fcmd_ptr->fences[0]->fname, atch_ptr->ufid, atch_ptr->contenttype, atch_ptr->has_thumbnail, atch_ptr->has_key);
						}
#endif
						UfsrvApiIntraBroadcastMessage (sesn_ptr, _WIRE_PROTOCOL_DATA(dm_ptr), MSGCMD_FENCE, INTRA_SEMANTICS, (const unsigned char *)msg_body_b64);
					} else {
						syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', device_id:'%d'}: ERROR: NO FENCE COMMAND WAS PRESENT", __func__, pthread_self(), sesn_ptr, device_id);
						data_message__free_unpacked (dm_ptr, NULL);
						goto request_error;
					}

					data_message__free_unpacked (dm_ptr, NULL);
				}//jobj_entry

			}//for
		}//block

		//if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))
		{
			struct json_object *jobj_reply=json_object_new_object();
			json_object_object_add (jobj_reply, "needsSync", json_object_new_boolean(0));

			const char *jobj_reply_str=json_object_to_json_string(jobj_reply);

			onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(jobj_reply_str));
			onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),jobj_reply_str, strlen(jobj_reply_str));

			free (SESSION_RESULT_USERDATA(sesn_ptr));
			json_object_put(jobj_reply);

			goto request_processed;
		}

	}//post

	request_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
	onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));

    request_processed:
    return OCS_PROCESSED;

#undef _THIS_PATH_FENCE

}


/**
 *
 * 	@dynamic_memory char *: IMPORTS/DEALLOCATES buffer	in BufferDescriptor
 */
API_ENDPOINT_V1(FENCE_NEARBY)
{
	HttpSession *http_ptr;
	float longitude;
	float	latitude;

	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);

	if (HTTPSESN_JSONDATA(((HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr))))
	{

		struct json_object *jobj=HTTPSESN_JSONDATA(((HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr)));

		longitude=json_object_get_double(json__get(jobj, "longitude"));
		latitude=json_object_get_double(json__get(jobj, "latitude"));

		BufferDescriptor buffer_packed_msg={0};
		if (IS_PRESENT(MakeFencesNearByInProtoPacked (sesn_ptr, longitude, latitude, 50, &buffer_packed_msg)))
		{
			struct json_object *jobj_result=json_object_new_object();

#if 0 //def __UF_COMPRESS
			unsigned char payload_compressed[buffer_packed_msg.size];
			memset(payload_compressed, 0, sizeof(payload_compressed));
			size_t compressed_sz=lzf_compress (buffer_packed_msg.data, buffer_packed_msg.size, payload_compressed, buffer_packed_msg.size);

			unsigned char payload_compressed_b64encoded[GetBase64BufferAllocationSize(compressed_sz)];
			memset(payload_compressed_b64encoded, 0, sizeof(payload_compressed_b64encoded));
			base64_encode((unsigned char *)payload_compressed, compressed_sz, payload_compressed_b64encoded);

#if 0 //testing block
			{
				int b64decoded_sz_returned=0;
				unsigned char *fences_newby_raw = base64_decode (payload_compressed_b64encoded, strlen(payload_compressed_b64encoded), &b64decoded_sz_returned);
				unsigned char payload_compressed_test[buffer_packed_msg.size];
				memset(payload_compressed_test, 0, sizeof(payload_compressed_test));
				size_t uncompressed_sz = lzf_decompress(fences_newby_raw, compressed_sz, payload_compressed_test, buffer_packed_msg.size);
				FencesNearBy *fences_nearby= fences_near_by__unpack(NULL, uncompressed_sz, payload_compressed_test);
				syslog(LOG_DEBUG, "%s (pid:'%lu') FencesNearBy: Test B64Decoding/Decompression: n_fences:'%lu'", __func__, pthread_self(), fences_nearby->n_fences);
				fences_near_by__free_unpacked(fences_nearby, NULL);
				free (fences_newby_raw);
			}

			json_object_object_add (jobj_result,"success", json_object_new_int(buffer_packed_msg.size_max));//number of elements
			json_object_object_add (jobj_result,"payload", json_object_new_string((const char *)payload_compressed_b64encoded));
#endif

#else
			//no compression option
			unsigned char payload_b64encoded[GetBase64BufferAllocationSize(buffer_packed_msg.size)];
			memset(payload_b64encoded, 0, sizeof(payload_b64encoded));
			base64_encode((unsigned char *)buffer_packed_msg.data, buffer_packed_msg.size, payload_b64encoded);

#if 1	//testing block
			{
				int decoded_sz_out=0;
				unsigned char *fences_newby_raw = base64_decode (payload_b64encoded, strlen((const char *)payload_b64encoded), &decoded_sz_out);
				FencesNearBy *fences_nearby= fences_near_by__unpack(NULL, decoded_sz_out, fences_newby_raw);
				if (fences_nearby)
				{
					syslog(LOG_DEBUG, "%s (pid:'%lu') FencesNearBy: SUCCESS B64DECODED/PROTO_INFLATED: n_fences:'%lu'. lat:'%f'", __func__, pthread_self(), fences_nearby->n_fences, fences_nearby->location->latitude);
					fences_near_by__free_unpacked(fences_nearby, NULL);
				}
				else syslog(LOG_DEBUG, "%s (pid:'%lu', decoded_sz:'%d', orig_sz:'%lu', strlen:'%lu') FencesNearBy: ERROR DECODING B64 to proto (%s)", __func__, pthread_self(),
										decoded_sz_out, buffer_packed_msg.size, strlen((const char *)payload_b64encoded), payload_b64encoded);
				free (fences_newby_raw);
			}
#endif

			json_object_object_add (jobj_result,"success", json_object_new_int(buffer_packed_msg.size_max));//number of elements
			json_object_object_add (jobj_result,"payload", json_object_new_string((const char *)payload_b64encoded));
#endif

			const char *jobj_str_reply=json_object_to_json_string(jobj_result);

			onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(jobj_str_reply));
			onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),jobj_str_reply, strlen(jobj_str_reply));

			free (buffer_packed_msg.data);
			json_object_put(jobj_result);
		}
		else
		{
#define	EMPTY_NEARBY_SET "{\"success\":0}"
			onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), EMPTY_NEARBY_SET, sizeof(EMPTY_NEARBY_SET)-1);
		}

		return OCS_PROCESSED;
	}//json

	request_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
	onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));
	return OCS_PROCESSED;

}


API_ENDPOINT_V1(FENCE_SEARCH)
{
#define _THIS_PATH_FENCE_NEARBY_SEARCH	"/V1/Fence/Search"
	HttpSession *http_ptr			=	(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);
	char 				*full_path		=	(char *)onion_request_get_fullpath(HTTPSESN_REQUEST_PTR(http_ptr));
	char				*search_text;

	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);

	search_text=full_path+sizeof(_THIS_PATH_FENCE_NEARBY_SEARCH);//this should take us past '/' as a side effect of sizeof, which is meant to includes 'null'
	if (!*search_text)
	{
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', full_path:'%s')ERROR: THERE WAS NO SEARCH STRING", __func__, pthread_self(), sesn_ptr, full_path);
		goto request_error;
	}

	BufferDescriptor 						buffer_packed_msg={0};
	SearchMatchingFencesWithRawResultsPacked (sesn_ptr, search_text, 100, &buffer_packed_msg);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))
	{
		if (buffer_packed_msg.size_max==0)	goto return_empty_set;

		struct json_object *jobj_result=json_object_new_object();

#if 0 //def __UF_COMPRESS
		unsigned char payload_compressed[buffer_packed_msg.size];
		memset(payload_compressed, 0, sizeof(payload_compressed));
		size_t compressed_sz=lzf_compress (buffer_packed_msg.data, buffer_packed_msg.size, payload_compressed, buffer_packed_msg.size);

		unsigned char payload_compressed_b64encoded[GetBase64BufferAllocationSize(compressed_sz)];
		memset(payload_compressed_b64encoded, 0, sizeof(payload_compressed_b64encoded));
		base64_encode((unsigned char *)payload_compressed, compressed_sz, payload_compressed_b64encoded);

#if 0 //testing block
		{
			int b64decoded_sz_returned=0;
			unsigned char *fences_newby_raw = base64_decode (payload_compressed_b64encoded, strlen(payload_compressed_b64encoded), &b64decoded_sz_returned);
			unsigned char payload_compressed_test[buffer_packed_msg.size];
			memset(payload_compressed_test, 0, sizeof(payload_compressed_test));
			size_t uncompressed_sz = lzf_decompress(fences_newby_raw, compressed_sz, payload_compressed_test, buffer_packed_msg.size);
			FencesNearBy *fences_nearby= fences_near_by__unpack(NULL, uncompressed_sz, payload_compressed_test);
			syslog(LOG_DEBUG, "%s (pid:'%lu') FencesNearBy: Test B64Decoding/Decompression: n_fences:'%lu'", __func__, pthread_self(), fences_nearby->n_fences);
			fences_near_by__free_unpacked(fences_nearby, NULL);
			free (fences_newby_raw);
		}

		json_object_object_add (jobj_result,"success", json_object_new_int(buffer_packed_msg.size_max));//number of elements
		json_object_object_add (jobj_result,"payload", json_object_new_string((const char *)payload_compressed_b64encoded));
#endif

#else
		//no compression option
		unsigned char payload_b64encoded[GetBase64BufferAllocationSize(buffer_packed_msg.size)];
		memset(payload_b64encoded, 0, sizeof(payload_b64encoded));
		base64_encode((unsigned char *)buffer_packed_msg.data, buffer_packed_msg.size, payload_b64encoded);

#if 1	//testing block
		{
			int decoded_sz_out=0;
			unsigned char *fences_search_raw = base64_decode (payload_b64encoded, strlen((const char *)payload_b64encoded), &decoded_sz_out);
			FencesSearch *fences_search= fences_search__unpack(NULL, decoded_sz_out, fences_search_raw);
			if (fences_search_raw)
			{
				syslog(LOG_DEBUG, "%s (pid:'%lu') FencesSearch: SUCCESS B64DECODED/PROTO_INFLATED: n_raw_results:'%lu'", __func__, pthread_self(), fences_search->n_raw_results);
				fences_search__free_unpacked(fences_search, NULL);
			}
			else syslog(LOG_DEBUG, "%s (pid:'%lu', decoded_sz:'%d', orig_sz:'%lu', strlen:'%lu') FencesSearch: ERROR DECODING B64 to proto (%s)", __func__, pthread_self(),
									decoded_sz_out, buffer_packed_msg.size, strlen((const char *)payload_b64encoded), payload_b64encoded);
			free (fences_search_raw);
		}
#endif

		json_object_object_add (jobj_result,"success", json_object_new_int(buffer_packed_msg.size_max));//number of elements
		json_object_object_add (jobj_result,"payload", json_object_new_string((const char *)payload_b64encoded));
#endif

		const char *jobj_str_reply=json_object_to_json_string(jobj_result);

		onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(jobj_str_reply));
		onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),jobj_str_reply, strlen(jobj_str_reply));

		free (buffer_packed_msg.data);
		json_object_put(jobj_result);

		return OCS_PROCESSED;
	}


	return_empty_set:
#define	EMPTY_FENCE_SEARCH_SET "{\"success\":0}"
		onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), EMPTY_FENCE_SEARCH_SET, sizeof(EMPTY_FENCE_SEARCH_SET)-1);
		return OCS_PROCESSED;

	request_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
	onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));
	return OCS_PROCESSED;

#undef	EMPTY_FENCE_SEARCH_SET
}
