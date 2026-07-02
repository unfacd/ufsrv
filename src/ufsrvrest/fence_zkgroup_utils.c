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

#include <fence_zkgroup_utils.h>
#include <zkgroup_utils/utils_zkgroup.h>

/**
 *
 * @param server_private_param
 * @param uuid
 * @param redemption_start_time
 * @param redemption_end_time
 * @param collection
 * @param executor A callback to run when request is handled
 * @param ctx_data a private data object to hand into the @param executor
 * @return
 */
int HandleCredentialRequest(const uint8_t *server_private_param, const Uuid *uuid, size_t redemption_start_time, size_t redemption_end_time, CollectionDescriptor *collection, on_request_handled executor, ClientContextData *ctx_data)
{
  size_t  idx = 0;
  AuthenticationCredential *auth_credential;

  //loop inclusive of the endtime
  for (size_t redemption_time=redemption_start_time; redemption_time <= redemption_end_time; redemption_time++) {
    auth_credential = (AuthenticationCredential *)(((uintptr_t)collection->collection) + (idx * sizeof(AuthenticationCredential)));
    if (IS_EMPTY(IssueAuthCredentials(server_private_param, uuid, redemption_time, auth_credential))) break;

    idx++;
  }

  if (idx == collection->collection_sz) {
    return executor(SUCCESS_STATE, ctx_data);
  } else {
    syslog(LOG_ERR, "ERROR in handling CredentialResponses");
    return executor(ERROR_STATE, ctx_data);
  }

}

static unsigned char *
_SerialiseCredential(AuthenticationCredential *group_credential, uint8_t *value_in)
{
  uint8_t *value = IS_PRESENT(value_in) ? value_in : group_credential->credential.serialised.by_value;

  return base64_encode(group_credential->credential.raw.by_value, AUTH_CREDENTIAL_RESPONSE_SIZE, value);
}

/**
 * @brief A callback handler for authorization credentials json formatting.
 * { credentials[]={ {credential:"xxx", redemptionTime:"yyy"}, {credential:"xxx", redemptionTime:"yyy"}, {...} }
 * }
 * @param state success state of the calling request handler
 * @param rest_descriptor A convenient encapsulation of data objects necessary to complete the callback passed from the calling request handler.
 * @return
 */
int
JsonFormatCredentialResponseCallback(RestRequestHandlingState state, RestRequestDescriptor *rest_descriptor)
{
  if (state == SUCCESS_STATE) {
    AuthenticationCredential *group_credential;
    CollectionDescriptor *collection = (CollectionDescriptor *)rest_descriptor->handler.ctx_data;
    json_object *jobj_credentials = json_object_new_array();

    for (size_t idx=0; idx<collection->collection_sz; idx++) {
      json_object *jobj_credential = json_object_new_object();
      group_credential = (AuthenticationCredential *)(((uintptr_t)collection->collection) + (idx * sizeof(AuthenticationCredential)));
      json_object_object_add(jobj_credential, "credential", json_object_new_string(AS_CONST_CHAR_TYPE(_SerialiseCredential(group_credential, NULL))));
      json_object_object_add(jobj_credential, "redemptionTime", json_object_new_int(group_credential->redemption_time));

      json_object_array_add(jobj_credentials, jobj_credential);
    }

    json_object_object_add(rest_descriptor->requester.jobj,"credentials", jobj_credentials);
    goto return_success;

  } else {
    return -1;
  }

  return_success:
  return 0;
}
