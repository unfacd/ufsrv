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
#include <api_endpoint_v1_receipt.h>
#include <ufsrv_core/user/user_backend.h>
#include <http_request_handler.h>
#include <protocol_http.h>
#include <response.h>
#include <http_session_type.h>
#include <session_type.h>
#include <message.h>
#include <ufsrv_core/SignalService.pb-c.h>
#include <ufsrv_core/msgqueue_backend/ufsrv_msgcmd_type_enum.h>

extern __thread ThreadContext ufsrv_thread_context;

static const char *err = "Server unable to complete request.";

/**
 * 	@brief: This endpoint is for processing acknowledgement or sync receipts by users
 *
 * 	@test_url: retrieve messages
 * 	curl -Ss -u '+61xxxxx:wI69bfdVnVd5WooFYXblX+DV'  'https://api.unfacd.io:20080/V1/Message/%2B+61xxxxx'
 */
API_ENDPOINT_V1(RECEIPT)
{
  Session *sesn_ptr = SessionOffInstanceHolder(instance_sesn_ptr);

	HttpSession 				*http_ptr;
	struct json_object 	*jobj_msg=NULL;

	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);
	#define _THIS_PATH	"/V1/Receipt"

	http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);

	int flags=onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));

	if ((flags&OR_METHODS) == OR_POST) {
		jobj_msg=HTTPSESN_JSONDATA(((HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr)));
		if (unlikely(jobj_msg == NULL))	goto request_error;

//		struct json_object *jobj_account=DbGetAccountInJson (sesn_ptr, destination_number);
//		if (jobj_account==NULL)
//		{
//			syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: Destination not valid", __func__, pthread_self(), sesn_ptr);
//
//			goto request_error;
//		}

		//TODO: check if device is still active
		{
			//fetch the messages
			int 		jobj_array_size=0;
			struct 	json_object *jobj_messages_array=json__get(jobj_msg, "messages");
			time_t msg_timestamp=json_object_get_int64(json__get(jobj_msg, "timestamp"));
			const char *destination=json_object_get_string(json__get(jobj_msg, "destination"));

			if (unlikely((jobj_messages_array == NULL))) {
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: No message found", __func__, pthread_self(), sesn_ptr);
				goto request_error;
			}
			if(unlikely((jobj_array_size = json_object_array_length(jobj_messages_array)) == 0)) {
				syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: ERROR: zero message list found", __func__, pthread_self(), sesn_ptr);
				goto request_error;
			}

			//TODO: validate rego id
			int i;
			struct json_object *jobj_entry = NULL;
			for (i=0; i<jobj_array_size; i++) {
				jobj_entry = json_object_array_get_idx(jobj_messages_array, i);
				if (jobj_entry) {
					int device_id = json_object_get_int(json__get(jobj_entry, "destinationDeviceId"));
					int rego_id = json_object_get_int(json__get(jobj_entry, "destinationRegistrationId"));

					Envelope 		msg				=	ENVELOPE__INIT;
					DataMessage data_msg	=	DATA_MESSAGE__INIT;

					const char *msg_body_b64 = json_object_get_string(json__get(jobj_entry, "content"));//legacy field at device side

					char *msg_content_decoded = NULL;
					if (IS_EMPTY(msg_body_b64)) {
						syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', device_id:'%d', rego_id:'%d'}: ERROR: MSG BODY IS MISSING...", __func__, pthread_self(), sesn_ptr, device_id, rego_id);
						goto request_error;
					}

					int rc_len = 0;
					msg_content_decoded = (char *)base64_decode((unsigned char *)msg_body_b64, strlen(msg_body_b64), &rc_len);
					if (msg_content_decoded == NULL) {
						syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', device_id:'%d', rego_id:'%d'}: ERROR: COULD NOT b64-DECODE BODY MSG...", __func__, pthread_self(), sesn_ptr, device_id, rego_id);
						goto request_error;
					}

					DataMessage *dm_ptr_unpacked = NULL;

					dm_ptr_unpacked = data_message__unpack(NULL, rc_len, (unsigned char *)msg_content_decoded);
					if (IS_EMPTY(dm_ptr_unpacked)) {
						free (msg_content_decoded);
						syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', device_id:'%d', rego_id:'%d'}: ERROR: COULD NOT PROTOBUF-UNPACK DataMessage...", __func__, pthread_self(), sesn_ptr, device_id, rego_id);
						goto request_error;
					}

					ReceiptCommand 		*mcmd_ptr;

					if (IS_PRESENT(dm_ptr_unpacked->ufsrvcommand) && IS_PRESENT((mcmd_ptr = dm_ptr_unpacked->ufsrvcommand->receiptcommand))) {
						syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', device_id:'%d', rego_id:'%d', comand_type:'%d', cmd_args:'%d', fid:'%lu'}: RECIEVED Receipt command", __func__, pthread_self(), sesn_ptr, device_id, rego_id, mcmd_ptr->header->command, mcmd_ptr->header->args, mcmd_ptr->fid);

						UfsrvApiIntraBroadcastMessage (sesn_ptr, _WIRE_PROTOCOL_DATA(dm_ptr_unpacked), MSGCMD_RECEIPT, INTRA_SEMANTICS, (const unsigned char *)msg_body_b64);
					} else {
						syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', device_id:'%d'}: ERROR: NO MESSAGE COMMAND WAS PRESENT", __func__, pthread_self(), sesn_ptr, device_id);

						//TODO: to be tightened later we need to let requests through now
						//data_message__free_unpacked (dm_ptr, NULL);
						//goto request_error;
					}

					data_message__free_unpacked (dm_ptr_unpacked, NULL);
				}
			}
		}

		if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr)) {
			struct json_object *jobj_reply=json_object_new_object();
			json_object_object_add (jobj_reply, "needsSync", json_object_new_boolean(0));

			const char *jobj_reply_str=json_object_to_json_string(jobj_reply);

      onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 200);
			onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(jobj_reply_str));
			onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),jobj_reply_str, strlen(jobj_reply_str));

			//free (SESSION_RESULT_USERDATA(sesn_ptr));//TODO: not sure what is this doing here
			json_object_put(jobj_reply);

			goto request_processed;
		}

	} else	if ((flags&OR_METHODS)==OR_GET) {
	} else {
		syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p'}: Unsupported HTTP Request method...", __func__, pthread_self(), sesn_ptr);
	}


	request_error:
	onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
	onion_response_write(instance_sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr), err, strlen(err));

	request_processed:
	return OCS_PROCESSED;
#undef _THIS_PATH
}



