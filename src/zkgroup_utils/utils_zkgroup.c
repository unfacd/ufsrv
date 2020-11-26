/**
 * Copyright (C) 2015-2020 unfacd works
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

#include <standard_c_includes.h>
#include <standard_defs.h>
#include <uuid_type.h>
#include <utils_crypto.h>
#include <zkgroup.h>
#include <utils_zkgroup.h>
#include <utils_b64.h>
#include <json/json.h>

GroupCredential *  __attribute__((nonnull(1, 2)))
IssueAuthCredentials(uint8_t *server_private_param, Uuid *uuid, int redemption_time, GroupCredential *group_credential_in)
{
  GroupCredential *group_credential = NULL;

  if (IS_EMPTY(group_credential_in)) group_credential = calloc(1, sizeof(GroupCredential));
  else group_credential = group_credential_in;

  uint8_t random_bytes[RANDOMNESS_LEN] = {0};
  GenerateSecureRandom(random_bytes, RANDOMNESS_LEN);

  int issue_result = FFI_ServerSecretParams_issueAuthCredentialDeterministic(server_private_param, SERVER_SECRET_PARAMS_LEN,
                                                                              random_bytes, RANDOMNESS_LEN,
                                                                              (uint8_t  *)uuid->raw.by_ref, UUID_LEN,
                                                                              redemption_time,
                                                                              group_credential_in->credential.raw.by_value, AUTH_CREDENTIAL_RESPONSE_LEN);

  if (issue_result == FFI_RETURN_OK) {
    group_credential->redemption_time = redemption_time;
    return group_credential;
  }

  if (IS_EMPTY(group_credential_in)) {
    free(group_credential);
  }

  return NULL;

}

ZKGroupServerParams *
GenerateZKGroupServerParams(ZKGroupServerParams *server_params_in)
{
  uint8_t random_bytes[RANDOMNESS_LEN] = {0};
  ZKGroupServerParams *server_params;

  if (IS_EMPTY(server_params_in)) server_params = calloc(1, sizeof(ZKGroupServerParams));
  else server_params = server_params_in;

  GenerateSecureRandom(random_bytes, RANDOMNESS_LEN);

  int32_t returned = FFI_ServerSecretParams_generateDeterministic(random_bytes, RANDOMNESS_LEN, server_params->secret_param.raw, SERVER_SECRET_PARAM_SIZE);
  if (returned == FFI_RETURN_OK) {
    FFI_ServerSecretParams_checkValidContents(server_params->secret_param.raw, SERVER_SECRET_PARAM_SIZE);
    base64_encode(server_params->secret_param.raw, SERVER_SECRET_PARAM_SIZE, server_params->secret_param.encoded);

    returned = FFI_ServerSecretParams_getPublicParams(server_params->secret_param.raw, SERVER_SECRET_PARAM_SIZE, server_params->public_param.raw, SERVER_PUB_PARAM_SIZE);
    if (returned == FFI_RETURN_OK) {
      base64_encode(server_params->public_param.raw, SERVER_PUB_PARAM_SIZE, server_params->public_param.encoded);

      syslog(LOG_DEBUG, "%s: GENERATED SERVER ZKGROUP PARAMS: secret: '%s', public: '%s'", __func__, server_params->secret_param.encoded, server_params->public_param.encoded);
      return server_params;
    } else goto pub_param_error;
  } else goto secret_param_error;

  pub_param_error:
  syslog(LOG_DEBUG, "%s: ERROR (FFI: '%d'): COULD NOT GENERATE SERVER ZKGROUP PUBLIC PARAMS: secret: '%s'", __func__, returned, server_params->secret_param.encoded);
  goto return_null;

  secret_param_error:
  syslog(LOG_DEBUG, "%s: ERROR (FFI: '%d'): COULD NOT GENERATE SERVER ZKGROUP SECRET PARAMS",  __func__, returned);

  return_null:
  return NULL;

}

MessageSignedWithServerParams *
SignUsingZKGroupServerParams(ZKGroupServerParams *server_params, uint8_t *message, size_t message_sz, MessageSignedWithServerParams *signed_message_in) {
  uint8_t random_bytes[RANDOMNESS_LEN] = {0};
  GenerateSecureRandom(random_bytes, RANDOMNESS_LEN);

  MessageSignedWithServerParams *signed_message;
  if (IS_EMPTY(signed_message_in)) signed_message = calloc(1, sizeof(MessageSignedWithServerParams));
  else signed_message = signed_message_in;

  signed_message->server_param = server_params;
  int32_t returned = FFI_ServerSecretParams_signDeterministic(server_params->secret_param.raw, SERVER_SECRET_PARAM_SIZE, random_bytes, RANDOMNESS_LEN, message, message_sz, signed_message->notary_signature.raw, SIGNATURE_LEN);

  if (returned == FFI_RETURN_OK) {
    return signed_message;
  }

  signing_error:
  syslog(LOG_DEBUG, "%s: ERROR (FFI: '%d'): COULD NOT SIGN MESSAGE",  __func__, returned);
  if (IS_EMPTY(signed_message_in)) free(signed_message);

  return NULL;

}

const char *
ZKGroupServerParamsMakeResultByJson(const ZKGroupServerParams *server_params, json_object *jobj)
{
  json_object_object_add(jobj, "public", json_object_new_string((const char *)server_params->public_param.encoded));
  json_object_object_add(jobj, "private", json_object_new_string((const char *)server_params->secret_param.encoded));

  const char *json_str_reply = json_object_to_json_string(jobj);

  return json_str_reply;
}
