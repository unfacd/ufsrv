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

#include <fence_zkgroup_utils.h>
#include <zkgroup_utils/utils_zkgroup.h>

int HandleCredentialRequest(uint8_t *server_private_param, Uuid *uuid, size_t redemption_start_time, size_t redemption_end_time, CollectionDescriptor *collection, on_request_handled executor, ClientContextData *ctx_data)
{
  size_t  idx = 0;
  GroupCredential *group_credential;

  //loop inclusive of the endtime
  for (size_t redemption_time=redemption_start_time; redemption_time<=redemption_end_time; redemption_time++) {
    group_credential = (GroupCredential *)(((uintptr_t)collection->collection) + (idx * sizeof(GroupCredential)));
    if (IS_EMPTY(IssueAuthCredentials(server_private_param, uuid, redemption_time, group_credential))) break;

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
_SerialiseCredential(GroupCredential *group_credential, uint8_t *value_in)
{
  uint8_t *value = IS_PRESENT(value_in) ? value_in : group_credential->credential.serialised.by_value;

  return base64_encode(group_credential->credential.raw.by_value, AUTH_CREDENTIAL_RESPONSE_LEN, value);
}

/**
 * { credentials[]={ {credential:"xxx", redemptionTime:"yyy"}, {credential:"xxx", redemptionTime:"yyy"}, {...} }
 * }
 * @param cred_response
 * @param jobj
 * @return
 */
int
JsonFormatCredentialResponse(RestRequestHandlingState state, RestRequestDescriptor *rest_descriptor)
{
  if (state == SUCCESS_STATE) {
    GroupCredential *group_credential;
    CollectionDescriptor *collection = (CollectionDescriptor *)rest_descriptor->handler.ctx_data;
    json_object *jobj_credentials = json_object_new_array();

    for (size_t idx=0; idx<collection->collection_sz; idx++) {
      json_object *jobj_credential = json_object_new_object();
      group_credential = (GroupCredential *)(((uintptr_t)collection->collection) + (idx * sizeof(GroupCredential)));
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
