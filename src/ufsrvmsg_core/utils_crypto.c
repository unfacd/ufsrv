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

#include <uflib/standard_c_includes.h>
#include <uflib/standard_defs.h>

#include <bsd/stdlib.h>

#include <ufsrvmsg_core/include/utils_crypto.h>
#include <openssl/rand.h>//crypto random number generator
#include <uflib/utils_base64.h>

#include <ufsrvmsg_core/include/crypto_certificates.pb-c.h>

/**
 *
 * @param cert_server_ptr
 * @param cert_key_ptr
 * @return
 * @dynamic_memory: EXPORTS data_buffer.data into the protobuf member. Since .data doesnt point to the malloced pointer
 * it must be offset by '- sizeof(data_buffer)' to free the actual malloc'ed pointer
 * @dynamic_memory: EXPORTS buffer allocated for certificate
 */
int
GetSignedServerCertificate(ec_private_key *private_ky, ec_public_key *public_key, ServerCertificate *cert_server_ptr, Certificate *cert_key_ptr, uint32_t server_key_id)
{
	ec_private_key *ec_private_key  = private_ky;
  ec_public_key *ec_public_key    = public_key;

  cert_key_ptr->id        = server_key_id; cert_key_ptr->has_id = 1;
  cert_key_ptr->key.data  = ec_public_key->data;
  cert_key_ptr->key.len   = DJB_KEY_LEN + 1; //byte[0] is used to encode curve type (DJB 0x05)
  cert_key_ptr->has_key   = 1;

  size_t certificate_packed_sz = certificate__get_packed_size(cert_key_ptr);
	uint8_t *certificate_packed  = calloc(1, certificate_packed_sz);
  certificate__pack(cert_key_ptr, certificate_packed);

  data_buffer *cert_key_signature = 0;
  int result = curve_calculate_signature(&cert_key_signature, ec_private_key, certificate_packed, certificate_packed_sz);
  if (result != 0) {
    syslog(LOG_DEBUG, "%s (pid:'%lu'): ERROR COULD NOT CALCULATE SIGNATURE", __func__, pthread_self());
    return -1;
  }

  cert_server_ptr->certificate.data	= certificate_packed;
  cert_server_ptr->certificate.len	=	certificate_packed_sz;
  cert_server_ptr->has_certificate	= 1;
  cert_server_ptr->signature.data  	= buffer_data(cert_key_signature);
  cert_server_ptr->signature.len   	= buffer_len(cert_key_signature);
  cert_server_ptr->has_signature   	= 1;

  return 0;
}

/**
 *
 * @param key_cert_ctx_ptr
 * @return
 * @dynamic_memory ALLOCATES storage for all members of KeyCertificateContext
 */
int
GenerateNewServerCertificate(KeyCertificateContext *key_cert_ctx_ptr)
{
  ec_key_pair *key_pair = key_cert_ctx_ptr->raw.key_pair;
  int result = curve_generate_key_pair(&key_pair);
  if (result != 0) {
    printf("Error generating keys\n");
    return -1;
  }

  ec_private_key *ec_private_key_returned = ec_key_pair_get_private(key_pair);
  key_cert_ctx_ptr->encoded.private_key = (char *)base64_encode(ec_private_key_returned->data, DJB_KEY_LEN, NULL);

  ec_public_key *ec_public_key_returned = ec_key_pair_get_public(key_pair);
  key_cert_ctx_ptr->encoded.public_key = (char *)base64_encode(ec_public_key_returned->data, DJB_KEY_LEN, NULL);

  data_buffer *public_key_serialised;
  ec_public_key_serialize(&public_key_serialised, ec_key_pair_get_public(key_pair));
  key_cert_ctx_ptr->encoded.public_key_serialised = (char *)base64_encode(public_key_serialised->data, DJB_KEY_LEN+1, NULL);
  buffer_free(public_key_serialised);

  if (key_cert_ctx_ptr->key_id) {
  //todo: implement key_id assignment
  }

  return 0;
}

void
DestructServerCertificate(KeyCertificateContext *key_cert_ctx_ptr, bool is_self_destruct)
{
  if (IS_PRESENT(key_cert_ctx_ptr->raw.key_pair)) {
    ec_private_key_destroy(ec_key_pair_get_private(key_cert_ctx_ptr->raw.key_pair));
    ec_public_key_destroy(ec_key_pair_get_public(key_cert_ctx_ptr->raw.key_pair));
    ec_key_pair_destroy(key_cert_ctx_ptr->raw.key_pair);
  }

  if (IS_PRESENT(key_cert_ctx_ptr->encoded.public_key_serialised))  free(key_cert_ctx_ptr->encoded.public_key_serialised);
  if (IS_PRESENT(key_cert_ctx_ptr->encoded.public_key))  free(key_cert_ctx_ptr->encoded.public_key);
  if (IS_PRESENT(key_cert_ctx_ptr->encoded.public_key)) {
    memset(key_cert_ctx_ptr->encoded.private_key, '\0', DJB_KEY_LEN);
    free(key_cert_ctx_ptr->encoded.private_key);
  }

  if (is_self_destruct) free (key_cert_ctx_ptr);
}

