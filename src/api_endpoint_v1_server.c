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
#include <utils.h>
#include <utils_crypto.h>
#include <api_endpoint_v1_server.h>
#include <http_request_handler.h>
#include <protocol_http_io.h>
#include <h_handler.h>
#include <response.h>
#include <url.h>
#include <http_session_type.h>
#include <json/json.h>
#include <protocol_http_attachments.h>
#include <protocol_http.h>
#include <protocol_http_user.h>
#include <ufsrvuid.h>
#include <dictionary.h>

extern __thread ThreadContext ufsrv_thread_context;

static const char *err="Server unable to complete request.";


#include <crypto_certificates.pb-c.h>
#include <users_proto.h>
#include <include/utils_crypto.h>

static inline const char *_ServerCertificateNewMakeResultByJson(const KeyCertificateContext *key_cert_ctx_ptr,
                                                                struct json_object *jobj_pref)  __attribute__((nonnull));
static inline const char *_ServerCertificateMakeResultByJson(const KeyCertificateContext *key_cert_ctx_ptr,
                                                             struct json_object *jobj_pref)  __attribute__((nonnull));

typedef enum CertificateOp {
  CERTIFICATEOP_QUERY,
  CERTIFICATEOP_NEW,
  CERTIFICATEOP_REVOKE
} CertificateOp;

/**
 * Administrative endpoint to manage server certificates.
 * @note test url curl -Ss -u +xxx:a https://api.unfacd.io/V1/Server/Certificate
 * @note test url curl -Ss -X POST -u +xxx:a https://api.unfacd.io/V1/Server/Certificate/New/2
 * @param sesn_ptr
 * @return json formatted information based on requested operation
 * @endpoint /V1/Server/Certificate get currently in-use certificate
 * @endpoint /V1/Server/Certificate/New[/id] Generate new certificate and optionally supply and id, otherwise previous id is incremented
 * @endpoint /V1/Server/Certificate/Revoke/<id> Revoke certifictae id
 *
 */
API_ENDPOINT_V1(SERVER_CERTIFICATE)
{
  HttpSession 		*http_ptr;
  json_object 		*jobj_pref = NULL;

  http_ptr=(HttpSession *)SESSION_PROTOCOLSESSION(sesn_ptr);
#define _THIS_PATH_CERT	"/V1/Server/Certificate"

  const char	*json_str_reply;
  CertificateOp certificate_op = CERTIFICATEOP_QUERY;
  size_t pathprefix_len=strlen( _THIS_PATH_CERT);
  char *full_path=strndupa(onion_request_get_fullpath(HTTPSESN_REQUEST_PTR(http_ptr)), MBUF); //TODO: is extra copying necessary just to please compiler
  int flags=onion_request_get_flags(HTTPSESN_REQUEST_PTR(http_ptr));

  if (strlen(full_path)<pathprefix_len)	goto return_error;

  ///V1/Server/Certificate/New
  char *op_name, *arg="";
  if (strlen(full_path)> pathprefix_len+2) {// angling for '/' plus at least one more char after that 'Attachment/xxx'
    op_name=full_path+pathprefix_len+1;
    if ((arg=strchr(op_name, '/'))) {//New/0
      *arg++='\0'; //holds key id
    }

    if ((strcmp(op_name, "New")==0))          certificate_op = CERTIFICATEOP_NEW;
    else if ((strcmp(op_name, "Revoke")==0))  certificate_op = CERTIFICATEOP_REVOKE;
  } //else default to CERTIFICATEOP_QUERY

  if ((flags&OR_METHODS)==OR_GET) {
    if (certificate_op!=CERTIFICATEOP_QUERY) {
      goto return_error;
    }

    //TODO: certificates are not managed in a registry yet
    size_t key_id=SERVER_KEYID;
    if (*arg!='\0') {
      key_id=strtoul(arg, NULL, 10);
      if (key_id==0) key_id = SERVER_KEYID;
    }

    jobj_pref                                 = json_object_new_object();
    KeyCertificateContext certificate_context = {0};

    certificate_context.key_id                        = key_id;
    certificate_context.encoded.public_key            = SERVER_PUBLICKEY;
    certificate_context.encoded.public_key_serialised = SERVER_PUBLICKEY_SERIALISED;
    json_str_reply = _ServerCertificateMakeResultByJson(&certificate_context, jobj_pref);

    goto return_reply;
  } else if ((flags&OR_METHODS)==OR_POST) {
    if (certificate_op!=CERTIFICATEOP_NEW) {
      goto return_error;
    }

    size_t key_id=0;
    if (*arg!='\0') {
      key_id=strtoul(arg, NULL, 10);
    }

    jobj_pref                                 = json_object_new_object();
    KeyCertificateContext certificate_context = {0};
    certificate_context.key_id                = key_id;

    if ((GenerateNewServerCertificate(&certificate_context)==0)) {
      json_str_reply = _ServerCertificateNewMakeResultByJson(&certificate_context, jobj_pref);
      DestructServerCertificate(&certificate_context, false);

      goto return_reply;
    }
  } else if ((flags&OR_METHODS)==OR_DELETE) {
    if (certificate_op!=CERTIFICATEOP_REVOKE) {
      goto return_error;
    }
    //add code
  } else {
      syslog(LOG_DEBUG, "%s {pid:'%lu', o:'%p', request_flags:'%d'}: ERROR: UNSUPPORTED HTTP REQUEST TYPE...", __func__, pthread_self(), sesn_ptr, flags);
      goto return_error;
  }

  return_error:
  onion_response_set_code(HTTPSESN_RESPONSE_PTR(http_ptr), 409);
  return OCS_PROCESSED;

  return_reply:
//  onion_response_set_length(HTTPSESN_RESPONSE_PTR(http_ptr), strlen(json_str_reply));
  onion_response_write(sesn_ptr, HTTPSESN_RESPONSE_PTR(http_ptr),json_str_reply, strlen(json_str_reply));
  if (IS_PRESENT(jobj_pref))	json_object_put(jobj_pref);
  return OCS_PROCESSED;

#undef _THIS_PATH_CERT
}


static inline const char *
_ServerCertificateMakeResultByJson(const KeyCertificateContext *key_cert_ctx_ptr, struct json_object *jobj_pref)
{
  json_object_object_add (jobj_pref, "key_id", json_object_new_int64(key_cert_ctx_ptr->key_id));
  json_object_object_add (jobj_pref, "public_key", json_object_new_string(key_cert_ctx_ptr->encoded.public_key));
  json_object_object_add (jobj_pref, "public_key_serialised", json_object_new_string(key_cert_ctx_ptr->encoded.public_key_serialised));
  json_object_object_add (jobj_pref, "private_key", json_object_new_string("not_allowed"/*key_cert_ctx_ptr->encoded.private_key)*/));

  const char *json_str_reply=json_object_to_json_string(jobj_pref);

  return json_str_reply;
}

static inline const char *
_ServerCertificateNewMakeResultByJson(const KeyCertificateContext *key_cert_ctx_ptr, struct json_object *jobj_pref)
{
  json_object_object_add (jobj_pref, "key_id", json_object_new_int64(key_cert_ctx_ptr->key_id)); //TODO: implement keyid for server key
  json_object_object_add (jobj_pref, "public_key", json_object_new_string(key_cert_ctx_ptr->encoded.public_key));
  json_object_object_add (jobj_pref, "public_key_serialised", json_object_new_string(key_cert_ctx_ptr->encoded.public_key_serialised));
  json_object_object_add (jobj_pref, "private_key", json_object_new_string(key_cert_ctx_ptr->encoded.private_key));

  const char *json_str_reply=json_object_to_json_string(jobj_pref);

  return json_str_reply;
}