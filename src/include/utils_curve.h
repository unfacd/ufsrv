#ifndef __INCLUDE_FILE_UTILS_CURVE__H__
#define __INCLUDE_FILE_UTILS_CURVE__H__

#include <stdint.h>
#include <protobuf-c/protobuf-c.h>
#include <curve25519/curve25519-donna.h>
#include <curve25519/ed25519/additions/curve_sigs.h>
#include <curve25519/ed25519/additions/generalized/gen_x.h>
#include <curve25519/ed25519/tests/internal_fast_tests.h>

#define CURVE_SIGNATURE_LEN 64
#define VRF_SIGNATURE_LEN   96

#define DJB_TYPE 0x05
#define DJB_KEY_LEN 32
#define VRF_VERIFY_LEN 32

#define ERR_INVALID_KEY           -1
#define ERR_NOMEM                 -2
#define ERR_INVAL                 -3
#define ERR_UNKNOWN               -4
#define ERR_VRF_SIG_VERIF_FAILED  -5

typedef struct data_buffer {
  size_t len;
  uint8_t data[];
} data_buffer;

typedef  struct ec_public_key
{
  uint8_t data[DJB_KEY_LEN+1]; //extra byte to accommodate serialised keys
} ec_public_key;

typedef struct ec_private_key
{
  uint8_t data[DJB_KEY_LEN];
} ec_private_key;

typedef struct ec_key_pair
{
  ec_public_key *public_key;
  ec_private_key *private_key;
} ec_key_pair;

data_buffer *buffer_alloc(size_t len);
data_buffer *signal_buffer_create(const uint8_t *data, size_t len);
data_buffer *signal_buffer_n_copy(const data_buffer *buffer, size_t n);
data_buffer *signal_buffer_append(data_buffer *buffer, const uint8_t *data, size_t len);
uint8_t *buffer_data(data_buffer *buffer);
size_t buffer_len(data_buffer *buffer);
void buffer_free(data_buffer *buffer);

int curve_decode_point(ec_public_key **public_key, const uint8_t *key_data, size_t key_len);
int ec_public_key_compare(const ec_public_key *key1, const ec_public_key *key2);
int ec_public_key_memcmp(const ec_public_key *key1, const ec_public_key *key2);
int ec_public_key_serialize(data_buffer **buffer, const ec_public_key *key);
int ec_public_key_serialize_protobuf(ProtobufCBinaryData *buffer, const ec_public_key *key);
void ec_public_key_destroy(ec_public_key *public_key);
int curve_decode_private_point(ec_private_key **private_key, const uint8_t *key_data, size_t key_len);
int ec_private_key_compare(const ec_private_key *key1, const ec_private_key *key2);
int ec_private_key_serialize(data_buffer **buffer, const ec_private_key *key);
int ec_private_key_serialize_protobuf(ProtobufCBinaryData *buffer, const ec_private_key *key);
void ec_private_key_destroy(ec_private_key *private_key);
int ec_key_pair_create(ec_key_pair **key_pair, ec_public_key *public_key, ec_private_key *private_key);
ec_public_key *ec_key_pair_get_public(const ec_key_pair *key_pair);
ec_private_key *ec_key_pair_get_private(const ec_key_pair *key_pair);
void ec_key_pair_destroy(ec_key_pair *key_pair);
int curve_generate_private_key(ec_private_key **private_key);
int curve_generate_public_key(ec_public_key **public_key, const ec_private_key *private_key);
int curve_generate_key_pair(ec_key_pair **key_pair);
int curve_calculate_agreement(uint8_t **shared_key_data, const ec_public_key *public_key, const ec_private_key *private_key);
int curve_verify_signature(const ec_public_key *signing_key, const uint8_t *message_data, size_t message_len, const uint8_t *signature_data, size_t signature_len);
int curve_calculate_signature(data_buffer **signature, const ec_private_key *signing_key, const uint8_t *message_data, size_t message_len);
int curve_verify_vrf_signature(data_buffer **vrf_output, const ec_public_key *signing_key, const uint8_t *message_data, size_t message_len, const uint8_t *signature_data, size_t signature_len);
int curve_calculate_vrf_signature(data_buffer **signature, const ec_private_key *signing_key, const uint8_t *message_data, size_t message_len);

#endif