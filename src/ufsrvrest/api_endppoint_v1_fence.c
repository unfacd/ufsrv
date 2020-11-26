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

#include <thread_context_type.h>
#include <misc.h>
#include <utils.h>
#include <api_endpoint_v1_fence.h>
#include <fence.h>
#include <ufsrv_core/fence/fence_utils.h>
#include <ufsrvwebsock/include/fence_proto.h>
#include <http_request_handler.h>
#include <response.h>
#include <session_type.h>
#include <http_session_type.h>
#include <json/json.h>
#include <protocol_http.h>
#include <ufsrv_core/SignalService.pb-c.h>
#include <ufsrv_core/msgqueue_backend/ufsrv_msgcmd_type_enum.h>
#include <uflib/include/utils_urls.h>
#include <zkgroup_utils/credential_response_type.h>
#include <include/rest_request_descriptor_type.h>
#include <fence_zkgroup_utils.h>
#include <ufsrv_core/user/user_profile.h>
#include <zkgroup_utils/group_credential_type.h>

extern ufsrv							*const masterptr;
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
#define _THIS_PATH_FENCE	"/V1/Fence"
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
	HttpSession 		*http_ptr = (HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);

	int flags = onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));

	if ((flags&OR_METHODS) == OR_POST) {
			//fetch the messages
    json_object	*jobj_msg	= HTTPSESN_JSONDATA(((HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr)));
    if (unlikely(IS_EMPTY(jobj_msg)))	goto request_error;

    int 				jobj_array_size		= 0;
    json_object	*jobj_messages_array	= json__get(jobj_msg, "messages");

			if (unlikely((jobj_messages_array == NULL))) {
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: No message found", __func__, pthread_self(), sesn_ptr);
				goto request_error;
			}
			if  (unlikely((jobj_array_size = json_object_array_length(jobj_messages_array)) == 0)) {
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: zero message list found", __func__, pthread_self(), sesn_ptr);
				goto request_error;
			}

			//TODO: validate rego id
			int					i;
			struct json_object	*jobj_entry = NULL;

			for (i=0; i<jobj_array_size; i++) {
				jobj_entry = json_object_array_get_idx (jobj_messages_array, i);
				if (jobj_entry) {
					int device_id	= json_object_get_int(json__get(jobj_entry, "destinationDeviceId"));
					int rego_id		= json_object_get_int(json__get(jobj_entry, "destinationRegistrationId"));

					DataMessage data_msg = DATA_MESSAGE__INIT;

					const char *msg_body_b64 = json_object_get_string(json__get(jobj_entry, "content"));//legacy optional

					char *msg_content_decoded = NULL;
					if (IS_EMPTY(msg_body_b64)) {
						syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', device_id:'%d', rego_id:'%d'}: ERROR: MSG BODY IS MISSING...", __func__, pthread_self(), sesn_ptr, device_id, rego_id);
						goto request_error;
					}

					int rc_len = 0;
					msg_content_decoded = (char *)base64_decode((unsigned char *)msg_body_b64, strlen(msg_body_b64), &rc_len);
					if (IS_EMPTY(msg_content_decoded)) {
						syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', device_id:'%d', rego_id:'%d'}: ERROR: COULD NOT b64-DECODE BODY MSG...", __func__, pthread_self(), sesn_ptr, device_id, rego_id);
						goto request_error;
					}

          DataMessage *dm_ptr = data_message__unpack(NULL, rc_len, (unsigned char *)msg_content_decoded);
					if (unlikely(IS_EMPTY(dm_ptr))) {
						free (msg_content_decoded);
						syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', device_id:'%d', rego_id:'%d'}: ERROR: COULD NOT PROTOBUF-UNPACK DataMessage...", __func__, pthread_self(), sesn_ptr, device_id, rego_id);
						goto request_error;
					}

					if (IS_PRESENT(dm_ptr->ufsrvcommand) && IS_PRESENT(dm_ptr->ufsrvcommand->fencecommand)) {
						UfsrvApiIntraBroadcastMessage(sesn_ptr, _WIRE_PROTOCOL_DATA(dm_ptr), MSGCMD_FENCE, INTRA_SEMANTICS, (const unsigned char *)msg_body_b64);
					} else {
						syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', device_id:'%d'}: ERROR: NO FENCE COMMAND WAS PRESENT", __func__, pthread_self(), sesn_ptr, device_id);
						data_message__free_unpacked (dm_ptr, NULL);
						goto request_error;
					}

					data_message__free_unpacked (dm_ptr, NULL);
				}
			}

		//if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))
		{
			struct json_object *jobj_reply = json_object_new_object();
			json_object_object_add (jobj_reply, "needsSync", json_object_new_boolean(0));

			const char *jobj_reply_str = json_object_to_json_string(jobj_reply);

			onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(jobj_reply_str));
			onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),jobj_reply_str, strlen(jobj_reply_str));

			free (SESSION_RESULT_USERDATA(sesn_ptr));
			json_object_put(jobj_reply);

			goto request_processed;
		}
	} else if ((flags&OR_METHODS) == OR_GET) {
    const char *full_path = onion_request_get_fullpath(HTTPSESN_REQUEST_PTR(http_ptr));
    if (strlen(full_path) > sizeof(_THIS_PATH_FENCE) + UINT64_LONGEST_STR_SZ) goto request_error; //includes allownce for '/' since we did not deduct -1 from sizeof for '\0' string terminator

    char *fid_point = strrchr(full_path, '/');
    if (IS_STR_LOADED(fid_point)) {
      unsigned long fid = strtoul(++fid_point, NULL, 10);
      if (fid) {
        json_object *jobj_fence = JsonFormatFenceDescriptor(sesn_ptr, fid, DIGESTMODE_BRIEF);
        if (IS_PRESENT(jobj_fence)) {
          const char *jobj_reply_str_fence = json_object_to_json_string(jobj_fence);

          onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(jobj_reply_str_fence));
          onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), jobj_reply_str_fence,
                               strlen(jobj_reply_str_fence));

          free(SESSION_RESULT_USERDATA(sesn_ptr));
          json_object_put(jobj_fence);

          goto request_processed;
        }
      }
    }
	}

	request_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
	onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));

  request_processed:
  return OCS_PROCESSED;

#undef _THIS_PATH_FENCE

}

#include <K12/KangarooTwelve.h>

API_ENDPOINT_V1(FENCE_CERTIFICATE)
{
  int return_code = 409;

  Session *sesn_ptr     = SessionOffInstanceHolder(instance_sesn_ptr);
  HttpSession *http_ptr = (HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);
  int flags             = onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));
#define _THIS_PATH_FENCE_CERTIFICATE	"/V1/Fence/Certificate"
#define PROFILE_MAX_URL_PARAMS_SZ 5
#define PROFILE_URL_TOKEN_REDEMPTION_TIME_START 3
#define PROFILE_URL_TOKEN_REDEMPTION_TIME_END  4
#define CREDENTIALS_REDEMPTION_PERIOD_MAX 7

  const char *full_path = onion_request_get_fullpath(HTTPSESN_REQUEST_PTR(http_ptr));
  size_t redemption_period = CREDENTIALS_REDEMPTION_PERIOD_MAX;
  UrlParamsDescriptor url_params = {
          .tokens = (UrlParamToken *[]){&(UrlParamToken){0}, &(UrlParamToken){0}, &(UrlParamToken){0}, &(UrlParamToken){0}, &(UrlParamToken){0}}
  };
  TokeniseUrlParams((char *)full_path, &url_params, PROFILE_MAX_URL_PARAMS_SZ);
  if (url_params.tokens_sz < 5) goto request_error;

  size_t redemption_start_time, redemption_end_time;

  if (IS_STR_LOADED(url_params.tokens[PROFILE_URL_TOKEN_REDEMPTION_TIME_START]->token)) {
    redemption_start_time = strtoul(url_params.tokens[PROFILE_URL_TOKEN_REDEMPTION_TIME_START]->token, NULL, 10);

    if (IS_STR_LOADED(url_params.tokens[PROFILE_URL_TOKEN_REDEMPTION_TIME_END]->token)) {
      redemption_end_time = strtoul(url_params.tokens[PROFILE_URL_TOKEN_REDEMPTION_TIME_END]->token, NULL, 10);
      redemption_period = redemption_end_time - redemption_start_time;
      if (redemption_end_time > redemption_start_time && redemption_period <= CREDENTIALS_REDEMPTION_PERIOD_MAX) {
        goto request_handling_block;
      }
    }
  }

  goto request_error;

  request_handling_block:
  if ((flags&OR_METHODS) == OR_GET) {
    CollectionDescriptor collection = {0};
    GroupCredential group_credentials[redemption_period + 1]; memset(group_credentials, 0, sizeof(group_credentials));
    collection.collection = AS_COLLECTION_TYPE(group_credentials); collection.collection_sz = redemption_period + 1;//to be all-inclusive of provided end period, add one additional bucket ie loop 8 times

    json_object *jobj = json_object_new_object();
    RestRequestDescriptor rest_descriptor = {.requester.jobj=jobj, .requester.initial_ctx=&(InstanceContextForSession){.instance_sesn_ptr=instance_sesn_ptr, .sesn_ptr=sesn_ptr},
                                             .handler.ctx_data=CLIENT_CTX_DATA(&collection)};

    Uuid    uuid                        = {0};
    DbOpDescriptor dbop_descriptor_uuid = {.ctx_data=&uuid};
    GetUuidByUserId(SESSION_USERID(sesn_ptr), &uuid, &dbop_descriptor_uuid);

    int handling_result = HandleCredentialRequest(MASTER_CONF_SERVER_PRIVATE_PARAMS, &uuid, redemption_start_time, redemption_end_time, &collection, JsonFormatCredentialResponse, &rest_descriptor);
    DBOP_DESCRIPTOR_INVOKE_RESULT_FINALISER(&dbop_descriptor_uuid);

    if (handling_result == 0) {
      const char *json_str_reply = json_object_to_json_string(jobj);

      onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(json_str_reply));
      onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), json_str_reply,
                           strlen(json_str_reply));

      json_object_put(jobj);
      goto request_success;
    }

    json_object_put(jobj);
    goto request_error;
  } else if ((flags&OR_METHODS) == OR_POST) {
    return_code = 405;//405 Method Not Allowed
    goto request_error;
  } else if ((flags&OR_METHODS) == OR_DELETE) {
    return_code = 405;//405 Method Not Allowed
    goto request_error;
  }

  request_success:
  return OCS_PROCESSED;

  request_error:
  onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), return_code);
  onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));
  return OCS_PROCESSED;

#undef _THIS_PATH_FENCE_CERTIFICATE
}

#include <base32.h>
API_ENDPOINT_V1(FENCE_ZKGROUP) {
  int return_code = 409;

  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);
  HttpSession *http_ptr = (HttpSession *) SESSION_PROTOCOLSESSION(sesn_ptr);
  int flags = onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));

  if ((flags&OR_METHODS) == OR_GET) {
    return_code = 405;//405 Method Not Allowed
  } else if ((flags&OR_METHODS) == OR_PUT) {
    return_code = 405; goto request_error;
  } else if ((flags&OR_METHODS) == OR_POST) {
    const char *group_authorization = onion_request_get_header(HTTPSESN_REQUEST_PTR(http_ptr), _ZKGROUP_AUTHORIZATION);
    if (IS_EMPTY(group_authorization)) goto request_error;
    syslog(LOG_DEBUG, "%s: Received X-Group-Authorization header: '%s'", __FUNCTION__, group_authorization);
    uint8_t hashed_authorization[16] = {0};
    int hash_result = KangarooTwelve((const unsigned char *)group_authorization, strlen(group_authorization), hashed_authorization, 16, NULL, 0);
    if (hash_result == 0) {
      uint8_t serialised_hashed_authorization[27] = {0};
      size_t encoded_sz = base32enc((char *)serialised_hashed_authorization, hashed_authorization, 16);
      syslog(LOG_DEBUG, "%s: Hashed Group Authorization (sz:'%lu'): '%s'", __FUNCTION__, encoded_sz, AS_CONST_CHAR_TYPE(serialised_hashed_authorization));
    }

    const char *content_type = onion_request_get_header(HTTPSESN_REQUEST_PTR(http_ptr), "Content-Type");
    if (IS_PRESENT(content_type) && IS_PRESENT(strstr(content_type, "application/x-protobuf"))) {
      const onion_block *request_data = onion_request_get_data(HTTPSESN_REQUEST_PTR(http_ptr));

      if (IS_PRESENT(request_data)) {
        syslog(LOG_DEBUG, "%s: Received Group protobuf (sz:'%d'): '%s'", __FUNCTION__, request_data->size, request_data->data);
        goto request_success;
      }
    }

//    json_object 	*jobj_msg = HTTPSESN_JSONDATA(((HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr)));
  } else if ((flags&OR_METHODS) == OR_DELETE) {
    return_code = 405;//405 Method Not Allowed
    goto request_error;
  }

  request_error:
  return return_code;

  request_success:
  return OCS_PROCESSED;
}

/**
 *
 * 	@dynamic_memory char *: IMPORTS/DEALLOCATES buffer	in BufferDescriptor
 */
API_ENDPOINT_V1(FENCE_NEARBY)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	HttpSession *http_ptr;
	float longitude;
	float	latitude;

	http_ptr = (HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);

	if (HTTPSESN_JSONDATA(((HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr)))) {
		json_object *jobj = HTTPSESN_JSONDATA(((HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr)));

		longitude = json_object_get_double(json__get(jobj, "longitude"));
		latitude = json_object_get_double(json__get(jobj, "latitude"));

		BufferDescriptor buffer_packed_msg = {0};
		if (IS_PRESENT(MakeFencesNearByInProtoPacked(sesn_ptr, longitude, latitude, 50, &buffer_packed_msg))) {
			json_object *jobj_result = json_object_new_object();

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
				int decoded_sz_out = 0;
				unsigned char *fences_newby_raw = base64_decode(payload_b64encoded, strlen((const char *)payload_b64encoded), &decoded_sz_out);
				FencesNearBy *fences_nearby = fences_near_by__unpack(NULL, decoded_sz_out, fences_newby_raw);
				if (fences_nearby) {
					syslog(LOG_DEBUG, "%s (pid:'%lu') FencesNearBy: SUCCESS B64DECODED/PROTO_INFLATED: n_fences:'%lu'. lat:'%f'", __func__, pthread_self(), fences_nearby->n_fences, fences_nearby->location->latitude);
					fences_near_by__free_unpacked(fences_nearby, NULL);
				} else syslog(LOG_DEBUG, "%s (pid:'%lu', decoded_sz:'%d', orig_sz:'%lu', strlen:'%lu') FencesNearBy: ERROR DECODING B64 to proto (%s)", __func__, pthread_self(),
										decoded_sz_out, buffer_packed_msg.size, strlen((const char *)payload_b64encoded), payload_b64encoded);
				free (fences_newby_raw);
			}
#endif

			json_object_object_add (jobj_result,"success", json_object_new_int(buffer_packed_msg.size_max));//number of elements
			json_object_object_add (jobj_result,"payload", json_object_new_string((const char *)payload_b64encoded));
#endif

			const char *jobj_str_reply = json_object_to_json_string(jobj_result);

			onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(jobj_str_reply));
			onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),jobj_str_reply, strlen(jobj_str_reply));

			free (buffer_packed_msg.data);
			json_object_put(jobj_result);
		}
		else
		{
#define	EMPTY_NEARBY_SET "{\"success\":0}"
			onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), EMPTY_NEARBY_SET, sizeof(EMPTY_NEARBY_SET)-1);
		}

		return OCS_PROCESSED;
	}//json

	request_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
	onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));
	return OCS_PROCESSED;

}

API_ENDPOINT_V1(FENCE_SEARCH)
{
#define _THIS_PATH_FENCE_NEARBY_SEARCH	"/V1/Fence/Search"
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	HttpSession *http_ptr			=	(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);
	char 				*full_path		=	(char *)onion_request_get_fullpath(HTTPSESN_REQUEST_PTR(http_ptr));
	char				*search_text;

	http_ptr = (HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);

	search_text = full_path + sizeof(_THIS_PATH_FENCE_NEARBY_SEARCH);//this should take us past '/' as a side effect of sizeof, which is meant to includes 'null'
	if (!*search_text) {
		syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', full_path:'%s')ERROR: THERE WAS NO SEARCH STRING", __func__, pthread_self(), sesn_ptr, full_path);
		goto request_error;
	}

	BufferDescriptor 						buffer_packed_msg = {0};
	SearchMatchingFencesWithRawResultsPacked (sesn_ptr, search_text, 100, &buffer_packed_msg);
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
		if (buffer_packed_msg.size_max == 0)	goto return_empty_set;

		struct json_object *jobj_result = json_object_new_object();

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
			FencesSearch *fences_search = fences_search__unpack(NULL, decoded_sz_out, fences_search_raw);
			if (fences_search_raw) {
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

		const char *jobj_str_reply = json_object_to_json_string(jobj_result);

		onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(jobj_str_reply));
		onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),jobj_str_reply, strlen(jobj_str_reply));

		free (buffer_packed_msg.data);
		json_object_put(jobj_result);

		return OCS_PROCESSED;
	}


	return_empty_set:
#define	EMPTY_FENCE_SEARCH_SET "{\"success\":0}"
		onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), EMPTY_FENCE_SEARCH_SET, sizeof(EMPTY_FENCE_SEARCH_SET)-1);
		return OCS_PROCESSED;

	request_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
	onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));
	return OCS_PROCESSED;

#undef	EMPTY_FENCE_SEARCH_SET
}
