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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "fence_protobuf.h"
#include <main.h>
#include <attachments.h>
#include <ufsrv_core/fence/fence_protobuf.h>
#include <ufsrv_core/user/user_type.h>
#include <fence.h>
#include <ufsrv_core/fence/fence_utils.h>
#include <sessions_delegator_type.h>
#include <ufsrv_core/fence/fence_permission.h>
#include <recycler/recycler.h>

static FenceRecord *_MakefenceRecordFromBackendCacheRecord (Session *, redisReply *redis_ptr, FenceRecord 		*fence_record_ptr_out, LocationRecord *location_record_ptr_out, AttachmentRecord *);

/**
 * 	@brief: for efficiency reasons and to keep copying to minimum we return a final packed payload. Which means this function
 * 	does a bit too much.
 *
 * 	@dynamic_memory packed:	EXPORTS
 * 	@dynamic_memory: WATCH OUT FOR STACK OVERFLOW DUE TO VLA arrays
 */
BufferDescriptor *
MakeFencesNearByInProtoPacked (Session *sesn_ptr_carrier, float longitude, float latitude, size_t setsize_requested, BufferDescriptor *buffer_descriptor_ptr_out)
{
  CollectionDescriptor fence_nearby_collection = {0};

  redisReply 	*redis_ptr	=	NULL;

  GetFencesNearByIndexRecords (sesn_ptr_carrier, longitude, latitude, setsize_requested, 0);
  if (SESSION_RESULT_TYPE_SUCCESS(sesn_ptr_carrier) && IS_PRESENT((redis_ptr = (redisReply *)SESSION_RESULT_USERDATA(sesn_ptr_carrier)))) {
    size_t					setsize				=	redis_ptr->elements;
    FencesNearBy		fences_nearby	=	FENCES_NEAR_BY__INIT;

    FenceRecord				*fence_records_ptr[redis_ptr->elements];
//		LocationRecord		*location_records_ptr[redis_ptr->elements] __unused;
//		AttachmentRecord	*attachment_records_ptr[redis_ptr->elements] __unused;

    //WARNING STACKOVERFLOW risk
    FenceRecord 		fence_records[redis_ptr->elements]; 				memset (fence_records, 0, sizeof(fence_records));
    LocationRecord	location_records[redis_ptr->elements];			memset (location_records, 0, sizeof(location_records));
    AttachmentRecord	attachment_records[redis_ptr->elements];	memset (attachment_records, 0, sizeof(attachment_records));

    //size_t true_i;
    for (size_t i=0, true_i=0; i<redis_ptr->elements; true_i=++i) {
      if (unlikely(IS_EMPTY(redis_ptr->element[i])))	{
        setsize--; true_i = i - 1;
        continue;
      }

      //TODO: Test what happens when the collection contains a null fence will the protobuf packing succeed?
      fence_records_ptr[i] = &fence_records[i];
      _MakefenceRecordFromBackendCacheRecord (sesn_ptr_carrier, redis_ptr->element[i], fence_records_ptr[true_i], &location_records[true_i], &attachment_records[true_i]);
    }

    LocationRecord	location_record_supplied	=	LOCATION_RECORD__INIT;
    fences_nearby.fences		=	fence_records_ptr;
    fences_nearby.n_fences	=	setsize;

    fences_nearby.location	=	&location_record_supplied;
    location_record_supplied.longitude	=	longitude;
    location_record_supplied.latitude		=	latitude;

    buffer_descriptor_ptr_out->size = fences_near_by__get_packed_size(&fences_nearby);
    buffer_descriptor_ptr_out->data = calloc(1, buffer_descriptor_ptr_out->size);
    fences_near_by__pack (&fences_nearby, (unsigned char *)buffer_descriptor_ptr_out->data);
    buffer_descriptor_ptr_out->size_max = setsize;

    return buffer_descriptor_ptr_out;
  }

  return NULL;
}

/**
 * 	@warning: ufsrvapi function
 */
static FenceRecord *
_MakefenceRecordFromBackendCacheRecord (Session *sesn_ptr_carrier, redisReply *redis_ptr, FenceRecord *fence_record_ptr_out, LocationRecord *location_record_ptr_out, AttachmentRecord *attachment_record_ptr_out)
{
  FenceRecord 			*fence_record_ptr;
  LocationRecord 		*location_record_ptr;
  AttachmentRecord 	*attachment_record_ptr;

  if (IS_PRESENT(fence_record_ptr_out))			fence_record_ptr = fence_record_ptr_out;
  else																			fence_record_ptr = calloc(1, sizeof(FenceRecord));

  if (IS_PRESENT(location_record_ptr_out))	location_record_ptr = location_record_ptr_out;
  else																			location_record_ptr = calloc(1, sizeof(LocationRecord));

  if (IS_PRESENT(attachment_record_ptr_out))	attachment_record_ptr = attachment_record_ptr_out;
  else																				attachment_record_ptr = calloc(1, sizeof(AttachmentRecord));

  location_record__init(location_record_ptr);
  fence_record__init(fence_record_ptr);
  //attachment_record__init(attachment_record_ptr); //this is done in MakeAttachmentRecordInProto() below

  fence_record_ptr->fid						=	strtoul(redis_ptr->element[REDIS_KEY_FENCE_ID]->str, NULL, 10); 			fence_record_ptr->has_fid=1;
  fence_record_ptr->eid						=	strtoul(redis_ptr->element[REDIS_KEY_EVENT_COUNTER]->str, NULL, 10);	fence_record_ptr->has_eid=1;
  fence_record_ptr->fname					=	redis_ptr->element[REDIS_KEY_FENCE_DNAME]->str;

  fence_record_ptr->location			=	location_record_ptr;
  location_record_ptr->longitude	=	strtof(redis_ptr->element[REDIS_KEY_FENCE_LONG]->str, NULL);
  location_record_ptr->latitude		=	strtof(redis_ptr->element[REDIS_KEY_FENCE_LAT]->str, NULL);

  if (IS_STR_LOADED(redis_ptr->element[REDIS_KEY_FENCE_AVATAR]->str) && *redis_ptr->element[REDIS_KEY_FENCE_AVATAR]->str != '*') {
    AttachmentDescriptor *attachment_ptr	=	NULL; //this is a lru instance
    if (IS_PRESENT((attachment_ptr = GetAttachmentDescriptor (sesn_ptr_carrier, redis_ptr->element[REDIS_KEY_FENCE_AVATAR]->str, true)))) {
      MakeAttachmentRecordInProto(attachment_ptr, attachment_record_ptr, false);
      fence_record_ptr->avatar		=	attachment_record_ptr;
    }
  }

  return fence_record_ptr;

}
