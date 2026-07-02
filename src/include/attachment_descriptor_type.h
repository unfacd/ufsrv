/**
 * Copyright (C) 2015-2023 unfacd works
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


#ifndef SRC_INCLUDE_ATTACHMENT_DESCRIPTOR_TYPE_H_
#define SRC_INCLUDE_ATTACHMENT_DESCRIPTOR_TYPE_H_


typedef struct AttachmentDescriptor {
	char			id[MBUF];
	char			key[MBUF];
	char			digest[MBUF];
	char			*key_encoded,
	          *digest_encoded,
            *blurhash,
            *caption;
	char			mime_type[TINYTINYBUF];
	unsigned char	*thumbnail;

  unsigned int  flags;
	size_t 			  width,
							  height;
	size_t			  size;
	size_t			  key_sz,
	              digest_sz;
	size_t			  eid;
} AttachmentDescriptor;
//
//typedef struct AttachmentDescription {
//	char *nonce;
//	char *path;
//} AttachmentDescription;


#endif /* SRC_INCLUDE_ATTACHMENT_DESCRIPTOR_TYPE_H_ */
