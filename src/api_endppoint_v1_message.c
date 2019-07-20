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
#include <misc.h>
#include <utils_crypto.h>
#include <api_endpoint_v1_message.h>
#include <user_backend.h>
#include <http_request_handler.h>
#include <protocol_http.h>
#include <h_handler.h>
#include <response.h>
#include <url.h>
#include <http_session_type.h>
#include <json/json.h>
#include <transmission_message_type.h>
#include <message.h>
#include <dictionary.h>
#include <SignalService.pb-c.h>
#include <ufsrv_msgcmd_type_enum.h>
#include <ufsrvuid.h>


static const char *err="Server unable to complete request.";
inline static int _HandleMessageGetRequest (Session *sesn_ptr, const UfsrvUid *);

/**
 * 	@brief: This endpoint is for posting and retrieving stored messages
 *
 * 	@test_url: retrieve messages
 * 	curl -Ss -u '+61xxxxx:wI69bfdVnVd5WooFYXblX+DV'  'https://api.unfacd.io:20080/V1/Message/%2B61xxx'
 */
API_ENDPOINT_V1(MESSAGE)
{
	HttpSession 				*http_ptr;
	struct json_object 	*jobj_msg=NULL;

	#define _THIS_PATH	"/V1/Message"

	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);

	const char *destination_number	=	SESSION_USERNAME(sesn_ptr);

	int flags=onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));

	if ((flags&OR_METHODS) == OR_POST) {
		jobj_msg = HTTPSESN_JSONDATA(((HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr)));
		if (unlikely(IS_EMPTY(jobj_msg)))	goto request_error;

		struct json_object *jobj_account=DbGetAccountInJson (sesn_ptr, &(SESSION_UFSRVUIDSTORE(sesn_ptr)));
		if (IS_EMPTY(jobj_account)) {
			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', destination_number:'%s'}: ERROR: Destination not valid", __func__, pthread_self(), sesn_ptr, destination_number);

			goto request_error;
		}

		//TODO: check if device is still active
		{
			//fetch the messages
			int jobj_array_size = 0;
			json_object *jobj_messages_array	=	json__get(jobj_msg, "messages");
			time_t 			msg_timestamp					=	json_object_get_int64(json__get(jobj_msg, "timestamp"));
			const char 	*destination					=	json_object_get_string(json__get(jobj_msg, "destination"));

			if (unlikely((IS_EMPTY(jobj_messages_array)))) {
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', destination_number:'%s'}: ERROR: No message found", __func__, pthread_self(), sesn_ptr, destination_number);
				goto request_error;
			}
			if (unlikely((jobj_array_size = json_object_array_length(jobj_messages_array)) == 0)) {
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', destination_number:'%s'}: ERROR: zero message list found", __func__, pthread_self(), sesn_ptr, destination_number);
				goto request_error;
			}

			//TODO: validate rego id
			int i;
			struct json_object *jobj_entry=NULL;
			for (i=0; i<jobj_array_size; i++) {
				jobj_entry = json_object_array_get_idx (jobj_messages_array, i);
				if (!IS_EMPTY(jobj_entry)) {
					int device_id = json_object_get_int(json__get(jobj_entry, "destinationDeviceId"));
					int rego_id   = json_object_get_int(json__get(jobj_entry, "destinationRegistrationId"));

					const char *msg_body_b64 = json_object_get_string(json__get(jobj_entry, "content"));

					char *msg_content_decoded=NULL;
					if (IS_EMPTY(msg_body_b64)) {
						syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', destination_number:'%s', device_id:'%d', rego_id:'%d'}: ERROR: MSG BODY IS MISSING...", __func__, pthread_self(), sesn_ptr, destination_number, device_id, rego_id);
						goto request_error;
					}

					int rc_len  = 0;
					msg_content_decoded = (char *)base64_decode((unsigned char *)msg_body_b64, strlen(msg_body_b64), &rc_len);
					if (IS_EMPTY(msg_content_decoded)) {
						syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', destination_number:'%s', device_id:'%d', rego_id:'%d'}: ERROR: COULD NOT b64-DECODE BODY MSG...", __func__, pthread_self(), sesn_ptr, destination_number, device_id, rego_id);
						goto request_error;
					}

#ifdef __UF_FULLDEBUG
					syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', destination_number:'%s', b64_msg:'%s'}: B64 decoded message...", __func__, pthread_self(), sesn_ptr, destination_number, msg_content_decoded);
#endif
					DataMessage *dm_ptr = NULL;

					dm_ptr = data_message__unpack(NULL, rc_len, (unsigned char *)msg_content_decoded);
					if (IS_EMPTY(dm_ptr)) {
						free (msg_content_decoded);
						syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', destination_number:'%s', device_id:'%d', rego_id:'%d'}: ERROR: COULD NOT PROTOBUF-UNPACK DataMessage...", __func__, pthread_self(), sesn_ptr, destination_number, device_id, rego_id);
						goto request_error;
					}

					MessageCommand 		*mcmd_ptr = dm_ptr->ufsrvcommand->msgcommand;

					//as per above statement we now explicitly reference the object in DataMessage as opposed to opaque object
					//FenceCommand *fcmd_ptr=fence_command__unpack(NULL, dm_ptr->ufsrvmessage.len, dm_ptr->ufsrvmessage.data);

					if (IS_PRESENT(mcmd_ptr)) {
						UfsrvApiIntraBroadcastMessage (sesn_ptr, _WIRE_PROTOCOL_DATA(dm_ptr), MSGCMD_MESSAGE, INTRA_SEMANTICS, (const unsigned char *)msg_body_b64);
					} else {
						syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', destination_number:'%s', device_id:'%d'}: ERROR: NO MESSAGE COMMAND WAS PRESENT", __func__, pthread_self(), sesn_ptr, destination_number, device_id);
						//data_message__free_unpacked (dm_ptr, NULL);//TODO: to be tightened later we need to let requests through now
						//goto request_error;
					}

					data_message__free_unpacked (dm_ptr, NULL);
				}
			}
		}

		//if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr))
		{
			struct json_object *jobj_reply=json_object_new_object();
			json_object_object_add (jobj_reply, "needsSync", json_object_new_boolean(0));

			const char *jobj_reply_str=json_object_to_json_string(jobj_reply);

			onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(jobj_reply_str));
			onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),jobj_reply_str, strlen(jobj_reply_str));

			//free (SESSION_RESULT_USERDATA(sesn_ptr));//TODO: not sure what is this doing here
			json_object_put(jobj_reply);

			goto request_processed;
		}

	} else	if ((flags&OR_METHODS) == OR_GET) {
		return (_HandleMessageGetRequest(sesn_ptr, &(SESSION_UFSRVUIDSTORE(sesn_ptr))));
	} else {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: Unsupported HTTP Request method...", __func__, pthread_self(), sesn_ptr);
	}


	request_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
	onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));

    request_processed:
    return OCS_PROCESSED;

}

inline static int
_HandleMessageGetRequest (Session *sesn_ptr, const UfsrvUid *uid_ptr)
{
	HttpSession *http_ptr			=	(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);
	json_object *jobj_messages;

	GetStagedMessageCacheRecordsForUserInJson (sesn_ptr, UfsrvUidGetSequenceId(uid_ptr));
	if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
		jobj_messages=SESSION_RESULT_USERDATA(sesn_ptr);
		const char *jobj_messages_str=json_object_to_json_string(jobj_messages);

		onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(jobj_messages_str));
		onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),jobj_messages_str, strlen(jobj_messages_str));

		json_object_put(jobj_messages);
	} else {
		onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),"{\"messages\":[]}", 15);
	}


	request_processed:
	return OCS_PROCESSED;

	request_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
	onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));
	return OCS_PROCESSED;

}

#ifdef __UF_TESTING

#if 0
$ curl -u \+61xxxxx:2\/8TC5jS1kI7MShRwIf\+yWQP --header "Content-Type:application/json" -X GET https://api.unfacd.io/V1/Encrypt -d {"\"signalingKey\":\"TrZTxq3y7v/kd5cy0gbqWpm2r9lq+5xBJcNao0v41H4/SjpYmhclKC37B8nxsX7DD9n6tg==\", \"message\":\"hello\"}"
{ "encrypted_msg": "fq\/2q6C0Xy61ARamF+SwD1VdpMzZUoj8FUkCUZkKz7A=", "hmac": "g;\u0011\u000f\/y▒S▒▒\u001d-ýk#▒sZ▒FHM▒˪*B▒\u0012▒▒", "final_msg": "AX6v9qugtF8utQEWphfksA9VXaTM2VKI\/BVJAlGZCs+wZzsRDy95o1PJwA==" }%
devops at db in ~
$ curl -u \+61xxxxx:2\/8TC5jS1kI7MShRwIf\+yWQP --header "Content-Type:application/json" -X GET https://api.unfacd.io/V1/Decrypt -d {"\"signalingKey\":\"TrZTxq3y7v/kd5cy0gbqWpm2r9lq+5xBJcNao0v41H4/SjpYmhclKC37B8nxsX7DD9n6tg==\", \"message\":\"AX6v9qugtF8utQEWphfksA9VXaTM2VKI\/BVJAlGZCs+wZzsRDy95o1PJwA==\"}"
{ "decrypted_msg": "hello" }%
#endif

API_ENDPOINT_V1(MESSAGE_ENCRYPT)
{
	HttpSession *http_ptr;
	const char  *signaling_key;
	const char  *cleartext_msg;

	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);

	if (HTTPSESN_JSONDATA(((HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr)))) {
		struct json_object *jobj=HTTPSESN_JSONDATA(((HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr)));

		signaling_key=json_object_get_string(json__get(jobj, "signalingKey"));
		cleartext_msg=json_object_get_string(json__get(jobj, "message"));

		EncryptedMessage *ciphertext_msg_ptr=EncryptWithSignallingKey ((const unsigned char *)cleartext_msg, strlen(cleartext_msg), (unsigned char *)signaling_key, true);
		if (!IS_EMPTY(ciphertext_msg_ptr)) {
			struct json_object *jobj_result=json_object_new_object();

			//unsigned char *ciphertext_msg_b64=base64_encode(ciphertext_msg_ptr->msg.msg_b64, ciphertext_msg_ptr->size);
			json_object_object_add (jobj_result,"encrypted_msg", json_object_new_string((const char *)ciphertext_msg_ptr->msg.msg_b64));
			json_object_object_add (jobj_result,"hmac", json_object_new_string((const char *)ciphertext_msg_ptr->hmac));
			json_object_object_add (jobj_result,"final_msg", json_object_new_string((const char *)ciphertext_msg_ptr->final_message_b64));

			const char *jobj_str_reply=json_object_to_json_string(jobj_result);

			onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(jobj_str_reply));
			onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),jobj_str_reply, strlen(jobj_str_reply));

			json_object_put(jobj_result);
			EncryptedMessageDestruct (ciphertext_msg_ptr, true);
		} else {
			goto request_error;
		}

		return OCS_PROCESSED;
	}

	request_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
	onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));
	return OCS_PROCESSED;

}

API_ENDPOINT_V1(MESSAGE_DECRYPT)
{
	HttpSession *http_ptr;
	const char  *signaling_key;
	const char  *ciphertext_msg;

	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);

	if (HTTPSESN_JSONDATA(((HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr)))) {

		struct json_object *jobj=HTTPSESN_JSONDATA(((HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr)));

		signaling_key=json_object_get_string(json__get(jobj, "signalingKey"));
		ciphertext_msg=json_object_get_string(json__get(jobj, "message"));

		DecryptedMessage *cleartext_msg_ptr=DecryptWithSignallingKey ((unsigned char *)ciphertext_msg, strlen(ciphertext_msg), (unsigned char *)signaling_key, true);
		if (cleartext_msg_ptr) {
			struct json_object *jobj_result=json_object_new_object();

			json_object_object_add (jobj_result,"decrypted_msg", json_object_new_string((const char *)cleartext_msg_ptr->msg.msg_clear));
			const char *jobj_str_reply=json_object_to_json_string(jobj_result);

			onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(jobj_str_reply));
			onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),jobj_str_reply, strlen(jobj_str_reply));

			json_object_put(jobj_result);
			DecryptedMessageDestruct (cleartext_msg_ptr, true);
		} else {
			goto request_error;
		}

		return OCS_PROCESSED;
	}

	request_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
	onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));
	return OCS_PROCESSED;

}

#endif
