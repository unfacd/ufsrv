/*
 * protocol_http_attachments.h
 *
 *  Created on: 4Apr.,2017
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_PROTOCOL_HTTP_ATTACHMENTS_H_
#define SRC_INCLUDE_PROTOCOL_HTTP_ATTACHMENTS_H_


typedef struct AttachmentDescription {
	char *nonce;
	char *path;
} AttachmentDescription;


//_ATTCHMENT_DOWNLOAD_PREFIX (_USERBLOB), id, location
#define REDIS_CMD_ATTCHMENT_DOWNLOAD_SET	"SET %s:%s %s"

AttachmentDescription *BackendAttachmentGenerate(Session *sesn_ptr);
void AttachementDescriptionDestruct (AttachmentDescription *, bool);

UFSRVResult *BackendAttachmentStoreLocationId (Session *sesn_ptr_target, const char *id, const char *location);
UFSRVResult *BackendAttachmentGetFileLocation (Session *sesn_ptr, const char *id);
bool IsAttachmentDescriptionValid (Session *sesn_ptr, const char *nonce, const char *path);

#endif /* SRC_INCLUDE_PROTOCOL_HTTP_ATTACHMENTS_H_ */
