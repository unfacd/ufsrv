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

#ifndef UFSRV_USER_PROFILE_TYPE_H
#define UFSRV_USER_PROFILE_TYPE_H

#include <stdint.h>
#include <uuid_type.h>
#include <zkgroup.h>

#define PROFILE_KEY_PROFILE_SERIALISED_LEN ((((PROFILE_KEY_LEN + 2) / 3) * 5))
#define PROFILE_KEY_COMMITMENT_SERIALISED_LEN (((PROFILE_KEY_COMMITMENT_LEN + 2) / 3) * 5)
#define PROFILE_KEY_VERSION_SERIALISED_LEN (PROFILE_KEY_VERSION_ENCODED_LEN)

#define PROFILE_KEY_CREDENTIAL_RESPONSE_SERIALISED_LEN (PROFILE_KEY_CREDENTIAL_RESPONSE_LEN * 2) //hex encoded
#define PROFILE_KEY_CREDENTIAL_REQUEST_SERIALISED_LEN ((((PROFILE_KEY_CREDENTIAL_REQUEST_LEN + 2) / 3) * 5))

typedef struct UserProfileAuthDescriptor UserProfileAuthDescriptor;
typedef struct ProfileCredentialRequest ProfileCredentialRequest;

typedef const uint8_t * (*profile_key_serialised_getter)(const struct UserProfileAuthDescriptor *);
typedef const uint8_t * (*commitment_serialised_getter)(const struct UserProfileAuthDescriptor *);
typedef const uint8_t * (*version_serialised_getter)(const struct UserProfileAuthDescriptor *);
typedef const uint8_t * (*credreq_serialised_getter)(const struct ProfileCredentialRequest *);

typedef struct UserProfileAuthDescriptor {
  struct {
    uint8_t raw[PROFILE_KEY_LEN];
    uint8_t serialised[PROFILE_KEY_PROFILE_SERIALISED_LEN + 1];
    uint8_t *serialised_ref;
    struct {
      profile_key_serialised_getter get_serialised;
    } accessor;
  } profile_key;

  struct {
    uint8_t raw[PROFILE_KEY_COMMITMENT_LEN];
    uint8_t serialised[PROFILE_KEY_COMMITMENT_SERIALISED_LEN + 1];
    uint8_t *serialised_ref;
    struct {
      commitment_serialised_getter get_serialised;
    } accessor;
  } commitment;

  struct {
    uint8_t serialised[PROFILE_KEY_VERSION_SERIALISED_LEN + 1];
    uint8_t *serialised_ref;
    struct {
      version_serialised_getter get_serialised;
    } accessor;
  } version;

  Uuid uuid;
} UserProfileAuthDescriptor;

typedef struct ProfileCredentialRequest {
  struct {
    uint8_t raw[PROFILE_KEY_CREDENTIAL_REQUEST_LEN];
    uint8_t serialised[PROFILE_KEY_CREDENTIAL_REQUEST_SERIALISED_LEN + 1];//typically would be hex encoded if provided via url params
    uint8_t *serialised_ref;
    struct {
      credreq_serialised_getter get_serialised;
    } accessor;
  } request;
} ProfileCredentialRequest;

typedef struct ProfileCredentialResponse {
  struct {
    uint8_t raw[PROFILE_KEY_CREDENTIAL_RESPONSE_LEN];
    uint8_t serialised[PROFILE_KEY_CREDENTIAL_RESPONSE_SERIALISED_LEN + 1];
    uint8_t *serialised_ref;
    struct {
      credreq_serialised_getter get_serialised;
    } accessor;
  } response;
} ProfileCredentialResponse;


#endif //UFSRV_USER_PROFILE_TYPE_H
