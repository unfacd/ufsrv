/**
 * Copyright (C) 2015-2021 unfacd works
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

#include <uflib/standard_c_includes.h>
#include <uflib/standard_defs.h>
#include <uflib/uuid_type.h>
#include <uflib/utils_crypto.h>
#include <utils_zkgroup.h>
#include <uflib/utils_base64.h>
#include <json/json.h>
#include <zkgroup_params_type.h>
#include <zkgroup_masterkey_type.h>

/**
 * Provide time-limited authentication credentials for a user against their own Uuid. Used in the context of "anonymous authentication" (anonymous to the processing server). This provides a
 * proof that the presenter of such credentials owns, or knows the underlying unique Uuid issued which the creds were issued for. This works in a closed system, containing group elements, true identity
 * of which are anonymous to the server managing the system. Providing the auth credentials proves to the server you're a member of that closed-system.
 * @param server_private_param This server's private component of the public-key cryprography used for zkgroups
 * @param uuid The uuid for which authentication credentials are being issued
 * @param redemption_time
 * @param group_credential_in
 * @return
 */
AuthenticationCredential *  __attribute__((nonnull(1, 2), access(read_only, 2), access(write_only, 4)))
IssueAuthCredentials(const uint8_t *server_private_param, const Uuid *uuid, int redemption_time, AuthenticationCredential *auth_credential_in)
{
  AuthenticationCredential *auth_credential = NULL;

  if (IS_EMPTY(auth_credential_in)) auth_credential = calloc(1, sizeof(AuthenticationCredential));
  else auth_credential = auth_credential_in;

  uint8_t random_bytes[RANDOMNESS_SIZE] = {0};
  GenerateSecureRandom(random_bytes, RANDOMNESS_SIZE);

  SignalFfiError *error_code = signal_server_secret_params_issue_auth_credential_deterministic(&auth_credential_in->credential.raw.by_value, server_private_param, &random_bytes, uuid->raw.by_ref, redemption_time);

  if (IS_EMPTY(error_code)) {
    auth_credential->redemption_time = redemption_time;
    return auth_credential;
  }

  if (IS_EMPTY(auth_credential_in)) {
    free(auth_credential);
  }

  syslog(LOG_DEBUG, "%s: ERROR (FFI: '%d'): COULD NOT ISSUE AUTH CREDENTIALS: ''", __func__, signal_error_get_type(error_code));
  signal_error_free(error_code);

  return NULL;

}

ZKGroupServerParams *
GenerateZKGroupServerParams(ZKGroupServerParams *server_params_in)
{
  uint8_t random_bytes[RANDOMNESS_SIZE] = {0};
  ZKGroupServerParams *server_params;

  if (IS_EMPTY(server_params_in)) server_params = calloc(1, sizeof(ZKGroupServerParams));
  else server_params = server_params_in;

  GenerateSecureRandom(random_bytes, RANDOMNESS_SIZE);

  SignalFfiError *error_code_pub_params = NULL;
  SignalFfiError *error_code = signal_server_secret_params_generate_deterministic(&server_params->secret_param.raw, &random_bytes);
  if (IS_EMPTY(error_code)) {
    signal_server_secret_params_check_valid_contents(&server_params->secret_param.raw);
    base64_encode(server_params->secret_param.raw, SERVER_SECRET_PARAMS_SIZE, server_params->secret_param.encoded);

    error_code_pub_params = signal_server_secret_params_get_public_params(&server_params->public_param.raw, &server_params->secret_param.raw);
    if (IS_EMPTY(error_code_pub_params)) {
      base64_encode(server_params->public_param.raw, SERVER_PUBLIC_PARAMS_SIZE, server_params->public_param.encoded);

      syslog(LOG_DEBUG, "%s: GENERATED SERVER ZKGROUP PARAMS: secret: '%s', public: '%s'", __func__, server_params->secret_param.encoded, server_params->public_param.encoded);
      return server_params;
    } else goto pub_param_error;
  } else goto secret_param_error;

  pub_param_error:
  syslog(LOG_DEBUG, "%s: ERROR (FFI: '%d'): COULD NOT GENERATE SERVER ZKGROUP PUBLIC PARAMS: secret: '%s'", __func__, signal_error_get_type(error_code_pub_params), server_params->secret_param.encoded);
  signal_error_free(error_code_pub_params);
  goto return_null;

  secret_param_error:
  signal_error_free(error_code);
  syslog(LOG_DEBUG, "%s: ERROR (FFI: '%d'): COULD NOT GENERATE SERVER ZKGROUP SECRET PARAMS",  __func__, signal_error_get_type(error_code));

  return_null:
  return NULL;

}

MessageSignedWithServerParams *
SignUsingZKGroupServerParams(ZKGroupServerParams *server_params, uint8_t *message, size_t message_sz, MessageSignedWithServerParams *signed_message_in) {
  uint8_t random_bytes[RANDOMNESS_SIZE] = {0};
  GenerateSecureRandom(random_bytes, RANDOMNESS_SIZE);

  MessageSignedWithServerParams *signed_message;
  if (IS_EMPTY(signed_message_in)) signed_message = calloc(1, sizeof(MessageSignedWithServerParams));
  else signed_message = signed_message_in;

  signed_message->server_param = server_params;
  SignalFfiError *error_code = signal_server_secret_params_sign_deterministic(&signed_message->notary_signature.raw, &server_params->secret_param.raw, &random_bytes, signed_message->notary_signature.raw, SIGNATURE_SIZE);

  if (IS_EMPTY(error_code)) {
    return signed_message;
  }

  signing_error:
  syslog(LOG_DEBUG, "%s: ERROR (FFI: '%d'): COULD NOT SIGN MESSAGE",  __func__, signal_error_get_type(error_code));
  if (IS_EMPTY(signed_message_in)) free(signed_message);
  signal_error_free(error_code);

  return NULL;

}

const char *
ZKGroupServerParamsMakeResultByJson(const ZKGroupServerParams *server_params, json_object *jobj)
{
  json_object_object_add(jobj, "public", json_object_new_string((const char *)server_params->public_param.encoded));
  json_object_object_add(jobj, "private", json_object_new_string((const char *)server_params->secret_param.encoded));
  json_object_object_add(jobj, "SERVER_SECRET_PARAMS_SIZE", json_object_new_int(SERVER_SECRET_PARAMS_SIZE));
  json_object_object_add(jobj, "SERVER_PUBLIC_PARAMS_SIZE", json_object_new_int(SERVER_PUBLIC_PARAMS_SIZE));

  const char *json_str_reply = json_object_to_json_string(jobj);

  return json_str_reply;
}

ZKGroupParams *
GenerateZKGroupSecretParams(ZKGroupParams *zkgroup_params_in) {
  ZKGroupParams *zkgroup_params = NULL;

  if (IS_EMPTY(zkgroup_params_in)) zkgroup_params = calloc(1, sizeof(ZKGroupParams));
  else zkgroup_params = zkgroup_params_in;

  uint8_t random_bytes[RANDOMNESS_SIZE] = {0};
  GenerateSecureRandom(random_bytes, RANDOMNESS_SIZE);

  SignalFfiError *error_code = signal_group_secret_params_generate_deterministic(&zkgroup_params->secret_param.raw, &random_bytes);
  if (IS_EMPTY(error_code)) {
    return zkgroup_params;
  }

  if (IS_EMPTY(zkgroup_params_in)) {
    free(zkgroup_params);
  }

  signal_error_free(error_code);

  return NULL;
}

ZKGroupParams * __attribute__((nonnull(1), access(read_only, 1)))
DeriveZKGroupSecretParamsFromMasterKey(ZKGroupMasterKey *zkgroup_masterkey, ZKGroupParams *zkgroup_params_in) {
  ZKGroupParams *zkgroup_params = NULL;

  if (IS_EMPTY(zkgroup_params_in)) zkgroup_params = calloc(1, sizeof(ZKGroupParams));
  else zkgroup_params = zkgroup_params_in;

  SignalFfiError *error_code = signal_group_secret_params_derive_from_master_key(&zkgroup_params->secret_param.raw, &zkgroup_masterkey->raw.bytes);
  if (IS_EMPTY(error_code)) {
    return zkgroup_params;
  }

  if (IS_EMPTY(zkgroup_params_in)) {
    free(zkgroup_params);
  }

  syslog(LOG_ERR, "%s (pid:'%lu'): ERROR: COULD NOT DERIVE GroupSecretParams.", __func__, pthread_self());

  signal_error_free(error_code);

  return NULL;

}

ZKGroupParams * __attribute__((nonnull(1)))
ZKGroupGetPublicParams(ZKGroupParams *zkgroup_params) {
  SignalFfiError *error_code_content = NULL;
  SignalFfiError *error_code = signal_group_secret_params_get_public_params(&zkgroup_params->public_param.raw, &zkgroup_params->secret_param.raw);
  if (IS_EMPTY(error_code)) {
    error_code_content = signal_group_public_params_check_valid_contents(&zkgroup_params->public_param.raw);
    if (IS_EMPTY(error_code_content)) {
      return zkgroup_params;
    }

    goto exit_validation_error;
  }

  exit_generation_error:
  syslog(LOG_ERR, "%s (pid:'%lu', ffi_code:'%d'): ERROR: COULD NOT GET ZKGroupGetPublicParams.", __func__, pthread_self(), signal_error_get_type(error_code_content));
  goto exit_error;

  exit_validation_error:
  syslog(LOG_ERR, "%s (pid:'%lu', ffi_code:'%d'): ERROR: COULD NOT VALIDATE ZKGroupGetPublicParams.", __func__, pthread_self(), signal_error_get_type(error_code_content));
  goto exit_error;

  exit_error:
  return NULL;

}

ZKGroupMasterKey * __attribute__((nonnull(1), access(read_only, 1)))
GetMasterKey(ZKGroupParams *zkgroup_params, ZKGroupMasterKey *zkgroup_masterkey_in) {
  ZKGroupMasterKey *zkgroup_masterkey = NULL;

  if (IS_EMPTY(zkgroup_masterkey_in)) zkgroup_masterkey = calloc(1, sizeof(ZKGroupMasterKey));
  else zkgroup_masterkey = zkgroup_masterkey_in;

  SignalFfiError *error_code = signal_group_secret_params_get_master_key(&zkgroup_masterkey->raw.bytes, &zkgroup_params->secret_param.raw);
  if (IS_EMPTY(error_code)) {
    return zkgroup_masterkey;
  }

  if (IS_EMPTY(zkgroup_masterkey_in)) {
    free(zkgroup_masterkey);
  }

  syslog(LOG_ERR, "%s (pid:'%lu', ffi_code:'%d'): ERROR: COULD NOT GET ZKGroup MasterKey.", __func__, pthread_self(), signal_error_get_type(error_code));

  signal_error_free(error_code);

  return NULL;

}

ZKGroupParams * __attribute__((nonnull(1), access(read_write, 1)))
ZKGroupGetGroupIdentifier(ZKGroupParams *zkgroup_params) {
  SignalFfiError *errr_code = signal_group_public_params_get_group_identifier(&zkgroup_params->public_identifier.raw, &zkgroup_params->public_param.raw);
  if (IS_EMPTY(errr_code)) {
    return zkgroup_params;
  }

  syslog(LOG_ERR, "%s (pid:'%lu', ffi_code:'%d'): ERROR: COULD NOT GET ZKGroup PublicIdentifier", __func__, pthread_self(), signal_error_get_type(errr_code));
  signal_error_free(errr_code);

  return NULL;
}