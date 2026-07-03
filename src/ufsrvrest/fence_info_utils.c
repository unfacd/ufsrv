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

#include <fence_info_utils.h>
#include <ufsrvmsg_core/fence/fence.h>
#include <json_attribute_names_fence.h>
#include <ufsrvmsg_core/fence/fence_permission.h>
#include <json/json.h>
#include <hiredis.h>

extern __thread ThreadContext ufsrv_thread_context;

/**
 *
 * @param fid Fence id
 * @param target_userid user for which fence related user attributes can be queried; eg membership etc...
 * @param executor callback supplied by caller which is to be invoked with success state and context data provided by the caller
 * @param ctx_data ontext data provided by the caller
 * @return
 * @dynamic_memory: IMPORTS redisReply *
 */
int
HandleFenceInfoRequest(unsigned long fid, unsigned long target_userid, on_request_handled executor, ClientContextData *ctx_data)
{
  CacheBackendLoadRecordForFence(fid);
  if (!THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA)	return executor(ERROR_STATE, ctx_data);
  redisReply 	*redis_ptr	=	(redisReply *)THREAD_CONTEXT_UFSRV_RESULT_USERDATA;

  CacheBackendGetFenceMembersListSize(fid, MEMBER_FENCES);
  if (!THREAD_CONTEXT_UFSRV_RESULT_IS_SUCCESS_WITH_BACKEND_DATA)	{
    freeReplyObject(redis_ptr);
    return executor(ERROR_STATE, ctx_data);
  }

  RestRequestDescriptor *descriptor_ptr = AS_REST_REQUEST_DESCRIPTOR(ctx_data);
  size_t list_sz = (size_t)(intptr_t)THREAD_CONTEXT_UFSRV_RESULT_USERDATA;
  Fence *f_ptr = AS_FENCE(descriptor_ptr->handler.ctx_data);
  FENCE_ID(f_ptr) = fid;
  FENCE_EID(f_ptr) = strtoul(redis_ptr->element[REDIS_KEY_EVENT_COUNTER]->str, NULL, 10);
  FENCE_WHEN_CREATED(f_ptr) = strtoul(redis_ptr->element[REDIS_KEY_FENCE_WHEN_CREATED]->str, NULL, 10);
  FENCE_DNAME(f_ptr) = redis_ptr->element[REDIS_KEY_FENCE_DNAME]->str;
  FENCE_CNAME(f_ptr) = redis_ptr->element[REDIS_KEY_FENCE_CNAME]->str;
  if (redis_ptr->element[REDIS_KEY_FENCE_AVATAR]->str && *redis_ptr->element[REDIS_KEY_EVENT_COUNTER]->str != '*') {
    FENCE_AVATAR(f_ptr) = redis_ptr->element[REDIS_KEY_FENCE_AVATAR]->str;
  }
  FENCE_USERS_COUNT(f_ptr) = list_sz;

  if (IS_STR_LOADED(redis_ptr->element[REDIS_KEY_LIST_SEMANTICS]->str)) MapPermissionsListSemanticsFromBackendPersistence(f_ptr, (int) strtoul(redis_ptr->element[REDIS_KEY_LIST_SEMANTICS]->str, NULL, 10));
  CacheBackendPermissionMembersIsMember(fid, FENCE_PERMISSIONS_MEMBERSHIP_PTR(f_ptr), 0);
  //todo potentially call IsUserOnFencePermissionList(FENCE_PERMISSIONS_MEMBERSHIP_PTR(f_ptr),) to check if user is allowed to admit link-join-requesting members.

  int ret_code = executor(SUCCESS_STATE, ctx_data);
  freeReplyObject(redis_ptr);

  return ret_code;
}

/**
 * @brief A callback handler for for formatting fence information.
 * @param state success state of the calling request handler. SUCCESS_STATE implies the caller has successfully processed the request.
 * @param rest_descriptor A convenient encapsulation of data objects necessary to complete the callback passed from the calling request handler.
 * @return
 */
int
JsonFormatFenceInfoResponseCallback(RestRequestHandlingState state, RestRequestDescriptor *rest_descriptor)
{
  if (state == SUCCESS_STATE) {
    Fence *f_ptr = AS_FENCE(rest_descriptor->handler.ctx_data);
    json_object_object_add(rest_descriptor->requester.jobj, FENCE_JSONATTR_ID, json_object_new_int64(FENCE_ID(f_ptr)));
    json_object_object_add(rest_descriptor->requester.jobj, FENCE_JSONATTR_EID, json_object_new_int64(FENCE_EID(f_ptr)));
    json_object_object_add(rest_descriptor->requester.jobj, FENCE_JSONATTR_WHEN_CREATED, json_object_new_int64(FENCE_WHEN_CREATED(f_ptr)));
    json_object_object_add(rest_descriptor->requester.jobj, FENCE_JSONATTR_MEMBERS_COUNT, json_object_new_int64(FENCE_USERS_COUNT(f_ptr)));
    json_object_object_add(rest_descriptor->requester.jobj, FENCE_JSONATTR_CNAME, json_object_new_string(FENCE_CNAME(f_ptr)));
    json_object_object_add(rest_descriptor->requester.jobj, FENCE_JSONATTR_DNAME, json_object_new_string(FENCE_DNAME(f_ptr)));
    json_object_object_add(rest_descriptor->requester.jobj, FENCE_JSONATTR_AVATAR, json_object_new_string(FENCE_AVATAR(f_ptr)));
    //if default blacklist semantics is on, we assume user is allowed to admit users to fence (todo even though we did not check if user was on permissions nenbers list).
    if (!FENCE_PERMISSIONS_MEMBERSHIP(f_ptr).config.whitelist) json_object_object_add(rest_descriptor->requester.jobj, FENCE_JSONATTR_FENCE_PERMS_MEMBERSHIP, json_object_new_boolean(1));

    goto return_success;

  } else {
    return -1;
  }

  return_success:
  return 0;
}