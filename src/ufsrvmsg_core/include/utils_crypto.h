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

#ifndef __INCLUDE_FILE_UTILS_CRYPTO__H__
#define __INCLUDE_FILE_UTILS_CRYPTO__H__

#include <stddef.h>
#include "crypto_certificates.pb-c.h"
#include "utils_curve.h"

typedef struct KeyCertificateContext {
  struct {
    char  *public_key,
          *private_key,
          *public_key_serialised;
  } encoded;
  struct {
    ec_key_pair *key_pair;
  } raw;

  unsigned long key_id;
} KeyCertificateContext;

int GetSignedServerCertificate (ec_private_key *, ec_public_key *, ServerCertificate *cert_server_ptr, Certificate *cert_key_ptr, uint32_t) __attribute__((nonnull));
int GenerateNewServerCertificate (KeyCertificateContext *key_cert_ctx_ptr) __attribute__((nonnull));
void DestructServerCertificate (KeyCertificateContext *key_cert_ctx_ptr, bool is_self_destruct) __attribute__((nonnull));

#endif
