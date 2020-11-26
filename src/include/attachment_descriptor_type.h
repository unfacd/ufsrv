/*
 * attachment_descriptor_type.h
 *
 *  Created on: 19 Oct 2016
 *      Author: ayman
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
	char			mime_type[SBUF];
	unsigned char	*thumbnail;

	size_t 			width,
							height;
	size_t			size;
	size_t			key_sz,
	            digest_sz;
	size_t			eid;
} AttachmentDescriptor;
//
//typedef struct AttachmentDescription {
//	char *nonce;
//	char *path;
//} AttachmentDescription;


#endif /* SRC_INCLUDE_ATTACHMENT_DESCRIPTOR_TYPE_H_ */
