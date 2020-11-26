/*
** Origin as per https://github.com/signalapp/libsignal-protocol-c/blob/master/src/curve.c
**
*/

#include <standard_c_includes.h>
#include <standard_defs.h>

#include <utils_crypto.h>
#include <utils_curve.h>
#include <curve25519/curve25519-donna.h>
#include <sys/param.h> //MIN

data_buffer *buffer_alloc(size_t len)
{
  data_buffer *buffer;
  if(len > (SIZE_MAX - sizeof(data_buffer)) / sizeof(uint8_t)) {
    return 0;
  }

  buffer = calloc(1, sizeof(data_buffer) + (sizeof(uint8_t) * len));
  if(buffer) {
    buffer->len = len;
  }
  
  return buffer;
}

data_buffer *signal_buffer_create(const uint8_t *data, size_t len)
{
  data_buffer *buffer = buffer_alloc(len);
  if(!buffer) {
    return 0;
  }

  memcpy(buffer->data, data, len);
  return buffer;
}

data_buffer *signal_buffer_n_copy(const data_buffer *buffer, size_t n)
{
  size_t len = MIN(buffer->len, n);
  return signal_buffer_create(buffer->data, len);
}

data_buffer *signal_buffer_append(data_buffer *buffer, const uint8_t *data, size_t len)
{
  data_buffer *tmp_buffer;
  size_t previous_size = buffer->len;
  size_t previous_alloc = sizeof(struct data_buffer) + (sizeof(uint8_t) * previous_size);

  if(len > (SIZE_MAX - previous_alloc)) {
    return 0;
  }

  tmp_buffer = realloc(buffer, previous_alloc + (sizeof(uint8_t) * len));
  if(!tmp_buffer) {
    return 0;
  }

  memcpy(tmp_buffer->data + previous_size, data, len);
  tmp_buffer->len = previous_size + len;
  return tmp_buffer;
}

uint8_t *buffer_data(data_buffer *buffer)
{
  return buffer->data;
}

size_t buffer_len(data_buffer *buffer)
{
  return buffer->len;
}

void buffer_free(data_buffer *buffer)
{
  if(buffer) {
    free(buffer);
  }
}

int curve_decode_point(ec_public_key **public_key, const uint8_t *key_data, size_t key_len)
{
  ec_public_key *key = 0;

  if(key_len > 0 && key_data[0] != DJB_TYPE) {
    syslog (LOG_ERR, "Invalid key type: %d", key_data[0]);
    return ERR_INVALID_KEY;
  }

  if(key_len != DJB_KEY_LEN + 1) {
    syslog(LOG_ERR, "Invalid key length: %lu", key_len);
    return ERR_INVALID_KEY;
  }

  key = malloc(sizeof(ec_public_key));
  if(!key) {
    return ERR_NOMEM;
  }

  memcpy(key->data, key_data + 1, DJB_KEY_LEN);

  *public_key = key;

  return 0;
}

int ec_public_key_compare(const ec_public_key *key1, const ec_public_key *key2)
{
  if(key1 == key2) {
    return 0;
  }
  else if(key1 == 0 && key2 != 0) {
    return -1;
  }
  else if(key1 != 0 && key2 == 0) {
    return 1;
  }
  else {
    return memcpy_constant_time (key1->data, key2->data, DJB_KEY_LEN);
  }
}

int ec_public_key_memcmp(const ec_public_key *key1, const ec_public_key *key2)
{
  if(key1 == key2) {
    return 0;
  }
  else if(key1 == 0 && key2 != 0) {
    return -1;
  }
  else if(key1 != 0 && key2 == 0) {
    return 1;
  }
  else {
    return memcmp(key1->data, key2->data, DJB_KEY_LEN);
  }
}

int ec_public_key_serialize(data_buffer **buffer, const ec_public_key *key)
{
  data_buffer *buf = 0;
  uint8_t *data = 0;

  if(!key) {
    return ERR_INVAL;
  }

  buf = buffer_alloc(sizeof(uint8_t) * (DJB_KEY_LEN + 1));
  if(!buf) {
    return ERR_NOMEM;
  }

  data = buffer_data(buf);
  data[0] = DJB_TYPE;
  memcpy(data + 1, key->data, DJB_KEY_LEN);

  *buffer = buf;

  return 0;
}

int ec_public_key_serialize_protobuf(ProtobufCBinaryData *buffer, const ec_public_key *key)
{
  size_t len = 0;
  uint8_t *data = 0;

  assert(buffer);
  assert(key);

  len = sizeof(uint8_t) * (DJB_KEY_LEN + 1);
  data = malloc(len);
  if(!data) {
    return ERR_NOMEM;
  }

  data[0] = DJB_TYPE;
  memcpy(data + 1, key->data, DJB_KEY_LEN);

  buffer->data = data;
  buffer->len = len;
  return 0;
}

void ec_public_key_destroy(ec_public_key *public_key)
{
  free(public_key);
}

int curve_decode_private_point(ec_private_key **private_key, const uint8_t *key_data, size_t key_len)
{
  ec_private_key *key = 0;

  if(key_len != DJB_KEY_LEN) {
   syslog(LOG_ERR, "Invalid key length: %lu", key_len);
    return ERR_INVALID_KEY;
  }

  key = malloc(sizeof(ec_private_key));
  if(!key) {
    return ERR_NOMEM;
  }

  memcpy(key->data, key_data, DJB_KEY_LEN);

  *private_key = key;

  return 0;
}

int ec_private_key_compare(const ec_private_key *key1, const ec_private_key *key2)
{
  if(key1 == key2) {
    return 0;
  }
  else if(key1 == 0 && key2 != 0) {
    return -1;
  }
  else if(key1 != 0 && key2 == 0) {
    return 1;
  }
  else {
    return memcmp_constant_time (key1->data, key2->data, DJB_KEY_LEN);
  }
}

int ec_private_key_serialize(data_buffer **buffer, const ec_private_key *key)
{
  data_buffer *buf = 0;
  uint8_t *data = 0 ;

  buf = buffer_alloc(sizeof(uint8_t) * DJB_KEY_LEN);
  if(!buf) {
    return ERR_NOMEM;
  }

  data = buffer_data(buf);
  memcpy(data, key->data, DJB_KEY_LEN);

  *buffer = buf;

  return 0;
}

int ec_private_key_serialize_protobuf(ProtobufCBinaryData *buffer, const ec_private_key *key)
{
  size_t len = 0;
  uint8_t *data = 0;

  assert(buffer);
  assert(key);

  len = sizeof(uint8_t) * DJB_KEY_LEN;
  data = malloc(len);
  if(!data) {
    return ERR_NOMEM;
  }

  memcpy(data, key->data, DJB_KEY_LEN);

  buffer->data = data;
  buffer->len = len;
  return 0;
}

void ec_private_key_destroy(ec_private_key *private_key)
{
//  memset_s(private_key, sizeof(ec_private_key), 0, sizeof(ec_private_key));
  memset(private_key, 0, sizeof(ec_private_key));
  free(private_key);
}

int ec_key_pair_create(ec_key_pair **key_pair, ec_public_key *public_key, ec_private_key *private_key)
{
  ec_key_pair *result = malloc(sizeof(ec_key_pair));
  if(!result) {
    return ERR_NOMEM;
  }

  result->public_key = public_key;
  result->private_key = private_key;

  *key_pair = result;

  return 0;
}

ec_public_key *ec_key_pair_get_public(const ec_key_pair *key_pair)
{
  return key_pair->public_key;
}

ec_private_key *ec_key_pair_get_private(const ec_key_pair *key_pair)
{
  return key_pair->private_key;
}

void ec_key_pair_destroy(ec_key_pair *key_pair)
{
  free(key_pair);
}

int curve_generate_private_key(ec_private_key **private_key)
{
  int result = 0;
  ec_private_key *key = 0;

  key = malloc(sizeof(ec_private_key));
  if(!key) {
    result = ERR_NOMEM;
    goto complete;
  }

  result = GenerateSecureRandom (key->data, DJB_KEY_LEN);
  if(result < 0) {
    goto complete;
  }

  key->data[0] &= 248;
  key->data[31] &= 127;
  key->data[31] |= 64;

  complete:
  if(result < 0) {
  }
  else {
    *private_key = key;
  }

  return result;
}

int curve_generate_public_key(ec_public_key **public_key, const ec_private_key *private_key)
{
  static const uint8_t basepoint[32] = {9};
  int result = 0;

  ec_public_key *key = malloc(sizeof(ec_public_key));
  if(!key) {
    return ERR_NOMEM;
  }

  result = curve25519_donna(key->data, private_key->data, basepoint);

  if(result == 0) {
    *public_key = key;
    return 0;
  }
  else {
    return ERR_UNKNOWN;
  }
}

int curve_generate_key_pair(ec_key_pair **key_pair)
{
  int result = 0;
  ec_key_pair *pair_result = 0;
  ec_private_key *key_private = 0;
  ec_public_key *key_public = 0;

  result = curve_generate_private_key(&key_private);
  if(result < 0) {
    goto complete;
  }

  result = curve_generate_public_key(&key_public, key_private);
  if(result < 0) {
    goto complete;
  }

  result = ec_key_pair_create(&pair_result, key_public, key_private);
  if(result < 0) {
    goto complete;
  }

  complete:
  if(result < 0) {
  }
  else {
    *key_pair = pair_result;
  }

  return result;
}

/*ec_public_key_list *ec_public_key_list_alloc()
{
  int result = 0;
  ec_public_key_list *list = malloc(sizeof(ec_public_key_list));
  if(!list) {
    result = ERR_NOMEM;
    goto complete;
  }

  memset(list, 0, sizeof(ec_public_key_list));

  utarray_new(list->values, &ut_ptr_icd);

  complete:
  if(result < 0) {
    if(list) {
      free(list);
    }
    return 0;
  }
  else {
    return list;
  }
}

ec_public_key_list *ec_public_key_list_copy(const ec_public_key_list *list)
{
  int result = 0;
  ec_public_key_list *result_list = 0;
  unsigned int size;
  unsigned int i;
  ec_public_key **p;

  result_list = ec_public_key_list_alloc();
  if(!result_list) {
    result = ERR_NOMEM;
    goto complete;
  }

  size = utarray_len(list->values);

  utarray_reserve(result_list->values, size);

  for (i = 0; i < size; i++) {
    p = (ec_public_key **)utarray_eltptr(list->values, i);
    result = ec_public_key_list_push_back(result_list, *p);
    if(result < 0) {
      goto complete;
    }
  }

  complete:
  if(result < 0) {
    if(result_list) {
      ec_public_key_list_free(result_list);
    }
    return 0;
  }
  else {
    return result_list;
  }
}

int ec_public_key_list_push_back(ec_public_key_list *list, ec_public_key *value)
{
  int result = 0;
  assert(list);
  assert(value);

  utarray_push_back(list->values, &value);
  SIGNAL_REF(value);

  complete:
  return result;
}

unsigned int ec_public_key_list_size(const ec_public_key_list *list)
{
  assert(list);
  return utarray_len(list->values);
}

ec_public_key *ec_public_key_list_at(const ec_public_key_list *list, unsigned int index)
{
  ec_public_key **value = 0;

  assert(list);
  assert(index < utarray_len(list->values));

  value = (ec_public_key **)utarray_eltptr(list->values, index);

  assert(*value);

  return *value;
}

int ec_public_key_list_sort_comparator(const void *a, const void *b)
{
  const ec_public_key *key1 = *((const ec_public_key **)a);
  const ec_public_key *key2 = *((const ec_public_key **)b);
  return ec_public_key_memcmp(key1, key2);
}

void ec_public_key_list_sort(ec_public_key_list *list)
{
  assert(list);
  utarray_sort(list->values, ec_public_key_list_sort_comparator);
}

void ec_public_key_list_free(ec_public_key_list *list)
{
  unsigned int size;
  unsigned int i;
  ec_public_key **p;
  if(list) {
    size = utarray_len(list->values);
    for (i = 0; i < size; i++) {
      p = (ec_public_key **)utarray_eltptr(list->values, i);
      SIGNAL_UNREF(*p);
    }
    utarray_free(list->values);
    free(list);
  }
}*/


//create a shared secret key  between a private and a public key
int curve_calculate_agreement(uint8_t **shared_key_data, const ec_public_key *public_key, const ec_private_key *private_key)
{
  uint8_t *key = 0;
  int result = 0;

  if(!public_key || !private_key) {
    return ERR_INVALID_KEY;
  }

  key = malloc(DJB_KEY_LEN);
  if(!key) {
    return ERR_NOMEM;
  }

  result = curve25519_donna(key, private_key->data, public_key->data);

  if(result == 0) {
    *shared_key_data = key;
    return DJB_KEY_LEN;
  }
  else {
    if(key) {
      free(key);
    }
    return ERR_UNKNOWN;
  }
}

int curve_verify_signature(const ec_public_key *signing_key,
                           const uint8_t *message_data, size_t message_len,
                           const uint8_t *signature_data, size_t signature_len)
{
  if(signature_len != CURVE_SIGNATURE_LEN) {
    return ERR_INVAL;
  }

  return curve25519_verify(signature_data, signing_key->data, message_data, message_len) == 0;
}

int curve_calculate_signature(data_buffer **signature, const ec_private_key *signing_key, const uint8_t *message_data, size_t message_len)
{
  int result = 0;
  uint8_t random_data[CURVE_SIGNATURE_LEN];
  data_buffer *buffer = 0;

  result = GenerateSecureRandom(random_data, sizeof(random_data));
  if(result < 0) {
    goto complete;
  }

  buffer = buffer_alloc(CURVE_SIGNATURE_LEN);
  if(!buffer) {
    result = ERR_NOMEM;
    goto complete;
  }

  result = curve25519_sign(buffer_data(buffer), signing_key->data, message_data, message_len, random_data);

  complete:
  if(result < 0) {
    if(buffer) {
      buffer_free(buffer);
    }
  }
  else {
    *signature = buffer;
  }
  return result;
}

//VRF (Verifiable Random Function) signatures.
int curve_verify_vrf_signature(data_buffer **vrf_output, const ec_public_key *signing_key, const uint8_t *message_data, size_t message_len,
                               const uint8_t *signature_data, size_t signature_len)
{
  int result = 0;
  data_buffer *buffer = 0;

  if(!signing_key) {
    return ERR_INVAL;
  }

  if(!message_data || !signature_data || signature_len != VRF_SIGNATURE_LEN) {
    syslog(LOG_ERR, "Invalid message or signature format");
    return ERR_VRF_SIG_VERIF_FAILED;
  }

  buffer = buffer_alloc(VRF_VERIFY_LEN);
  if(!buffer) {
    result = ERR_NOMEM;
    goto complete;
  }

  result = generalized_xveddsa_25519_verify(buffer_data(buffer),
                                            signature_data, signing_key->data,
                                            message_data, message_len, NULL, 0);
  if(result != 0) {
    syslog(LOG_ERR, "Invalid signature");
    result = ERR_VRF_SIG_VERIF_FAILED;
  }

  complete:
  if(result < 0) {
    buffer_free(buffer);
  }
  else {
    *vrf_output = buffer;
  }
  return result;
}

//VRF (Verifiable Random Function) signatures.
int curve_calculate_vrf_signature(data_buffer **signature, const ec_private_key *signing_key, const uint8_t *message_data, size_t message_len)
{
  int result = 0;
  uint8_t random_data[64];
  data_buffer *buffer = 0;

  result = GenerateSecureRandom(random_data, sizeof(random_data));
  if(result < 0) {
    goto complete;
  }

  buffer = buffer_alloc(VRF_SIGNATURE_LEN);
  if(!buffer) {
    result = ERR_NOMEM;
    goto complete;
  }

  result = generalized_xveddsa_25519_sign(buffer_data(buffer),
                                          signing_key->data,
                                          message_data, message_len, random_data, NULL, 0);
  if(result != 0) {
    syslog(LOG_ERR, "Signature failed!");
    result = ERR_UNKNOWN;
  }

  complete:
  if(result < 0) {
    buffer_free(buffer);
  }
  else {
    *signature = buffer;
  }
  return result;
}
