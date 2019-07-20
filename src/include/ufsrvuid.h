//
// Created by devops on 10/25/18.
//

#ifndef UFSRV_ULID_H
#define UFSRV_ULID_H

#include <ufsrvuid_type.h>

//yields sequence id 1 {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00}
#define UFSRV_SYSTEMUSER_UID "00000000000000200000000000"

UfsrvUid *UfsrvUidGenerate (const UfsrvUidGeneratorDescriptor *descriptor_ptr, UfsrvUid *ulid_out);
UfsrvUid *UfsrvUidCreateFromBinary (const uint8_t b[16], UfsrvUid *ulid_out);
UfsrvUid *UfsrvUidCreateFromEncodedText(const char *str, UfsrvUid *uid_ptr_out);
uint8_t *UfsrvUidConvertToBinary (const UfsrvUid *ulid, uint8_t dst[16]);
char *UfsrvUidConvertToString (const UfsrvUid *ulid, char *dst_out);

unsigned long UfsrvUidGetSequenceId (const UfsrvUid *uid_ptr);
unsigned long UfsrvUidGetSequenceIdFromEncoded (const char *ufsrvuid_encoded);
unsigned int UfsrvUidGetInstanceId (const UfsrvUid *uid_ptr);
unsigned long UfsrvUidGetTimestamp (const UfsrvUid *uid_ptr);
bool UfsrvUidIsEqual (const UfsrvUid *uid_ptr1, const UfsrvUid *uid_ptr2);
bool UfsrvUidIsSystemUser (const UfsrvUid *uid_ptr);
void UfsrvUidCopy (const UfsrvUid *uid_ptr_src, UfsrvUid *uid_ptr_dest);

#endif //UFSRV_ULID_H
