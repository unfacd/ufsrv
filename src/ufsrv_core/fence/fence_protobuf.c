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

#include <standard_defs.h>
#include <standard_c_includes.h>
#include "fence_protobuf.h"
#include <utils_b64.h>

/**
 * 	@brief: Instantiate a standard AttachmentRecord from AttachmentDescriptor source. The instantiation is by reference, so make sure
 * 	the original AttachmentDescriptor remains in scope until needed, unless flag_dup is set, in which the user must destroy the object.
 *
 * 	@dynamic_memory: various fields are EXPORTED must be deallocated with DestructAttachmentRecord()
 */
AttachmentRecord *
MakeAttachmentRecordInProto (AttachmentDescriptor *attachment_ptr, AttachmentRecord *attachment_record_ptr_out, bool flag_dup)
{
  AttachmentRecord 			*attachment_record_ptr;
  AttachmentDescriptor 	*attachment_descriptor_ptr __unused;

  if (IS_PRESENT(attachment_record_ptr_out))	attachment_record_ptr	=	attachment_record_ptr_out;
  else 																				attachment_record_ptr	=	calloc(1, sizeof(AttachmentRecord));

  attachment_record__init(attachment_record_ptr);

  //TODO: this is not supported coming out of the db in raw, as key sizes are not transmitted yet in db we always store as b64 encoded
  if (IS_STR_LOADED(attachment_ptr->key))
  {
    if (!flag_dup)	attachment_record_ptr->key.data					=	(unsigned char *)attachment_ptr->key;
    else						{
      attachment_record_ptr->key.data												=	calloc(attachment_ptr->key_sz, sizeof(unsigned char));
      memcpy (attachment_record_ptr->key.data, attachment_ptr->key, attachment_ptr->key_sz);
    }
    attachment_record_ptr->key.len													=	attachment_ptr->key_sz;
    attachment_record_ptr->has_key													=	1;
  }
  else
  if (IS_STR_LOADED(attachment_ptr->key_encoded))
  {
    int decoded_sz_out							=	0;
    unsigned char *key_raw 					= base64_decode ((const unsigned char *)attachment_ptr->key_encoded, strlen((const char *)attachment_ptr->key_encoded), &decoded_sz_out);
    attachment_record_ptr->key.data	=	key_raw;
    attachment_record_ptr->key.len	=	decoded_sz_out;
    attachment_record_ptr->has_key	=	1;
  }

  if (IS_STR_LOADED(attachment_ptr->digest)) {
    if (!flag_dup)	attachment_record_ptr->digest.data					=	(unsigned char *)attachment_ptr->digest;
    else						{
      attachment_record_ptr->digest.data												=	calloc(attachment_ptr->digest_sz, sizeof(unsigned char));
      memcpy (attachment_record_ptr->digest.data, attachment_ptr->digest, attachment_ptr->digest_sz);
    }
    attachment_record_ptr->digest.len													=	attachment_ptr->digest_sz;
    attachment_record_ptr->has_digest													=	1;
  }
  else
  if (IS_STR_LOADED(attachment_ptr->digest_encoded)) {
    int decoded_sz_out									=	0;
    unsigned char *digest_raw 					= base64_decode ((const unsigned char *)attachment_ptr->digest_encoded, strlen((const char *)attachment_ptr->digest_encoded), &decoded_sz_out);
    attachment_record_ptr->digest.data	=	digest_raw;
    attachment_record_ptr->digest.len		=	decoded_sz_out;
    attachment_record_ptr->has_digest		=	1;
  }

  if (attachment_ptr->width > 0) {
    attachment_record_ptr->width		 = attachment_ptr->width;
    attachment_record_ptr->has_width = 1;
  }

  if (attachment_ptr->height > 0) {
    attachment_record_ptr->height		 = attachment_ptr->height;
    attachment_record_ptr->has_height = 1;
  }

  attachment_record_ptr->size															=	attachment_ptr->size;				attachment_record_ptr->has_size				=	1;

  if (attachment_record_ptr->has_thumbnail)
  {
    if (!flag_dup)	attachment_record_ptr->thumbnail.data		=	attachment_ptr->thumbnail;
    else						attachment_record_ptr->thumbnail.data		=	(unsigned char *)strdup((const char *)attachment_ptr->thumbnail);
    attachment_record_ptr->thumbnail.len										=	strlen((const char *)attachment_ptr->thumbnail);//b64 encoded
    attachment_record_ptr->has_thumbnail										=	1;
  }

  if (!flag_dup)	attachment_record_ptr->contenttype			=	attachment_ptr->mime_type;
  else						attachment_record_ptr->contenttype			=	strdup(attachment_ptr->mime_type);

  if (!flag_dup)	attachment_record_ptr->id								=	attachment_ptr->id;
  else						attachment_record_ptr->id								=	strdup(attachment_ptr->id);

  return attachment_record_ptr;

}

void
DestructAttachmentRecord (AttachmentRecord  *attachment_record_ptr, bool flag_self_destruct)
{
  if (IS_PRESENT(attachment_record_ptr->key.data))					free (attachment_record_ptr->key.data);
  if (IS_PRESENT(attachment_record_ptr->digest.data))					free (attachment_record_ptr->digest.data);
  if (IS_PRESENT(attachment_record_ptr->thumbnail.data))		free (attachment_record_ptr->thumbnail.data);
  if (IS_PRESENT(attachment_record_ptr->contenttype))				free (attachment_record_ptr->contenttype);
  if (IS_PRESENT(attachment_record_ptr->id))								free (attachment_record_ptr->id);

  memset(attachment_record_ptr, 0,sizeof(AttachmentRecord));

  if (flag_self_destruct)	free(attachment_record_ptr);

}
