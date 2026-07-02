/**
 * Copyright (C) 2015-2024 unfacd works
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

#include <gpc_http_utils.h>
#include <thread_context_type.h>
#include <uflib/utils_base64url.h>
#include <http_request.h>
#include <uflib/utils_crypto.h>
#include <json/json.h>
#include <misc.h>

extern __thread ThreadContext ufsrv_thread_context;

EVP_PKEY *ReadGPCPrivateKeyFromFile(const char *file_name_and_location);
EVP_PKEY *ReadGPCPublicKeyFromFile();

/**
 * @brief Perform standard GPC OAuth2.0 flow to get an access token for API use authorization.
 *
 * \image html https://developers.google.com/static/identity/protocols/oauth2/images/flows/jwt.png "GPC access token request flow"
 * @param[in] http_ptr Http handling context containing data objects necessary for handling http request, response and processing of response
 * @return fully formed access token
 * @dynamic_memory EXPORTS string
 */
char *
GetGoogleAccessCodeAuthorization(HttpRequestContext *http_ptr, const GpcServiceRequestDescriptor *const gpc_request_descriptor_ptr)
{
  char *gpc_access_token = NULL;

  char *jwt_final = GenerateSignedJWT(NULL, gpc_request_descriptor_ptr);
  if (IS_PRESENT(jwt_final)) {
    gpc_access_token = RequestGoogleAccessToken(http_ptr, jwt_final);
    if (IS_PRESENT(gpc_access_token)) {
      //NOOP
    } else {
      syslog(LOG_ERR, "%s {pid:'%lu', th_ctx:'%p'}: ERROR COULD NOT REQUEST GPC ACCESS TOKEN: JWT:'%s'", __func__, pthread_self(), THREAD_CONTEXT_PTR, jwt_final);
    }
    free(jwt_final);
  }

  return gpc_access_token;
}

static void _ConfirmNoError(HttpRequestContext *http_ptr, void(^on_no_error)(void));

/**
 * '{ "error": "invalid_grant", "error_description": "java.security.SignatureException: Invalid signature for token: eyJhbGciOiJSU0=.eyAiaXTZ9.btweB7Q==" }'
 * '{ "access_token": "ya29.c.c0", "expires_in": 3599, "token_type": "Bearer" }'
 * @param http_tr
 */
static void
_ConfirmNoError(HttpRequestContext *http_ptr, void(^on_no_error)(void))
{
  const char *error = json_object_get_string(json__get(http_ptr->jobj, "error"));
  if (!IS_STR_LOADED(error)) {
    on_no_error();
    return;
  }

  syslog(LOG_NOTICE, "%s {pid:'%lu'}: ERROR GCP ACCESS TOKEN: error:'%s', error_description:'%s'", __func__, pthread_self(), error, json_object_get_string(json__get(http_ptr->jobj, "error_description")));
}

/**
 * @brief Request a GPC access token, authorising ufsrv to use service account on GPC which was previously configured to use Play Integrity API.
 * @param http_ptr[IN] Http handling context containing data objects necessary for handling http request, response and processing of response.
 * @param jwt_encoded[IN] previously form JWT token, base64 encoded and ready for insertion into HTTP request.
 * @dynamic_memory user must delallocate returned string
 * {
  "access_token": "1/8xbJqaOZXSUZbHLl5EOtu1pxz3fmmetKx9W8CV4t79M",
  "scope": "https://www.googleapis.com/auth/prediction"
  "token_type": "Bearer",
  "expires_in": 3600
}
 */
char *
RequestGoogleAccessToken(HttpRequestContext *http_ptr, const char *jwt_encoded)
{
#define GOOGLE_TOKEN_ACCESS_SERVER "https://oauth2.googleapis.com/token"
  char *post_data = NULL;

  asprintf(&post_data, "grant_type=%s&assertion=%s", "urn:ietf:params:oauth:grant-type:jwt-bearer", jwt_encoded);
  int result = HttpRequestPostUrl(http_ptr, GOOGLE_TOKEN_ACCESS_SERVER, post_data, APITOKEN_SMSVOICE_PROD, NULL, "application/x-www-form-urlencoded", 0L);
  if (result == 0) {
    syslog(LOG_ERR, "%s (pid:'%lu'): ERROR: COULD NOT POST URL '%s'", __func__, pthread_self(), post_data);
    free(post_data);
    return NULL;
  }

  free(post_data);

  do {
    http_ptr->jobj = json_tokener_parse_ex(http_ptr->jtok, http_ptr->rb.memory, strlen(http_ptr->rb.memory));
  } while ((http_ptr->jerr = json_tokener_get_error(http_ptr->jtok)) == json_tokener_continue);

  if (http_ptr->jerr != json_tokener_success) {
    syslog(LOG_NOTICE, "%s {pid:'%lu'}: ERROR JSON TOKENISER: '%s' ", __func__, pthread_self(), json_tokener_error_desc(http_ptr->jerr));

    return NULL;
  }

  const char *json_str_access_token = json_object_to_json_string(http_ptr->jobj);
  __block char *access_token = NULL;
  syslog(LOG_NOTICE, "%s {pid:'%lu'}: RECEIVED GCP ACCESS TOKEN RESPONSE: '%s'", __func__, pthread_self(), json_str_access_token);
  _ConfirmNoError(http_ptr, ^(){
      access_token = strdup(json_object_get_string(json__get(http_ptr->jobj, "access_token")));
  });

  return access_token;

}

static int _ComputeSHA256Digest(char *jwt_header_plus_claim_str, size_t str_len, unsigned char *sha256_hashed_str);

/**
 * @brief In order to access Google Cloud Platform (GCP) resources (e.g API access to the Play Integrity API) the ufsrv application must request authorisation using own service account
 * credentials created on google cloud console (under the 'unfacd' project) and obtain an access token from google's OAauth2.0 server. The authorisation is initiated by providing a signed Json Web Token (JWT).
 * JWT is composed of the following three distinct parts: {Base64url encoded header}.{Base64url encoded claim set}.{Base64url encoded signature}
 * Header: Mostly fixed for the google service account. use XXX_GOOGLE_OAUTH_JWT_HEADER
 * Claim set: XXX_OAUTH_JWT_CLAIM_SET
 * Signature: The input for the signature is the byte array of the following content: Base64url encoded header}.{Base64url encoded claim set}, signed with private key previously supplied by GPC which is also associated with
 * the service account used for this call. Encryption is not required. The signature must then be Base64url encoded.
 *
 * @note refer to flow described in https://developers.google.com/identity/protocols/oauth2/service-account#httprest
 * @note for openssl stuff see reference implementation at https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying#Signing
 * @param http_ptr[in] Http handling context, containing data objects necessary for handling http request, response and processing of response.
 * @dynamic_memory returned str must be freed by user
 * @return
 */
char *
GenerateSignedJWT(HttpRequestContext *http_ptr, const GpcServiceRequestDescriptor *const gpc_request_descriptor_ptr)
{
#define ONE_HOUR_IN_SECONDS (60 * 60)
  time_t assertion_issue_time       = time(NULL);
  time_t assertion_expiration_time  = time(NULL) + ONE_HOUR_IN_SECONDS; //current google specs support max of 1 hour from issue time

//  size_t encoded_string_sz      = 0;
  char *claim_set_str           = NULL;
  char *jwt_signature_input_str = NULL;
  char *jwt_final               = NULL;

  //create base64 representation of the claim set. The header part is fixed and pre-calculated.
  asprintf(&claim_set_str, gpc_request_descriptor_ptr->claim_set_template, gpc_request_descriptor_ptr->is_refresh_token? "offline" : "online", assertion_expiration_time, assertion_issue_time);//this doesn't work for service accounts for server-to-server interactions aka "two-legged OAuth"
  unsigned char claim_set_str_b64_encoded[GetBase64BufferAllocationSize(strlen(claim_set_str))]; memset(claim_set_str_b64_encoded, 0, sizeof(claim_set_str_b64_encoded));
  base64url_encode((unsigned char *)claim_set_str, strlen(claim_set_str), claim_set_str_b64_encoded);
  asprintf(&jwt_signature_input_str, "%s.%s", gpc_request_descriptor_ptr->jwt_header_encoded, claim_set_str_b64_encoded);
  free(claim_set_str);

  EVP_PKEY *key = ReadGPCPrivateKeyFromFile(gpc_request_descriptor_ptr->private_key.file_name);//convert private key from PEM format stored in a system file
//  EVP_MD_CTX *mdctx  = EVP_MD_CTX_create(); // EVP_MD_CTX_destroy(mdctx); crashes when pointer is used
  EVP_MD_CTX mdctx;  EVP_MD_CTX_init(&mdctx);

  if (EVP_DigestSignInit(&mdctx, NULL, EVP_get_digestbyname("SHA256"), NULL, key) <= 0) {
    syslog(LOG_INFO, "%s (pid:'%lu'): ERROR: COULD NOT INITIALISE DIGEST SIGNING (%s)", __func__, pthread_self(), ERR_error_string(ERR_get_error(), NULL));
    free(jwt_signature_input_str);
    EVP_PKEY_free(key);
    EVP_MD_CTX_cleanup(&mdctx); //EVP_MD_CTX_destroy(mdctx);
    return NULL;
  }

  if (EVP_DigestSignUpdate(&mdctx, jwt_signature_input_str, strlen((const char *)jwt_signature_input_str)) != 1) { //Call update with the message
    syslog(LOG_INFO, "%s (pid:'%lu', digest_type:'%d'): ERROR: COULD NOT GENERATE DIGEST (%s)", __func__, pthread_self(), EVP_MD_type(EVP_MD_CTX_md(&mdctx)), ERR_error_string(ERR_get_error(), NULL));
    free(jwt_signature_input_str);
    EVP_PKEY_free(key);
    EVP_MD_CTX_cleanup(&mdctx); //EVP_MD_CTX_destroy(mdctx);
    return NULL;
  }

  //call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the signature
  size_t signature_len = 0;
  if (EVP_DigestSignFinal(&mdctx, NULL, &signature_len) != 1) {
    syslog(LOG_INFO, "%s (pid:'%lu'): ERROR: COULD NOT RETRIEVE SIGNATURE LENGTH (%s)", __func__, pthread_self(), ERR_error_string(ERR_get_error(), NULL));
    free(jwt_signature_input_str);
    EVP_PKEY_free(key);
    EVP_MD_CTX_cleanup(&mdctx); //EVP_MD_CTX_destroy(mdctx);
    return NULL;
  }

  unsigned char *rsa_signature = OPENSSL_malloc(sizeof(unsigned char) * signature_len);

  if (1 != EVP_DigestSignFinal(&mdctx, rsa_signature, &signature_len)) {
    syslog(LOG_INFO, "%s (pid:'%lu'): ERROR: COULD NOT GENERATE SIGNATURE (%s)", __func__, pthread_self(), ERR_error_string(ERR_get_error(), NULL));
    free(jwt_signature_input_str);
    OPENSSL_free(rsa_signature);
    EVP_PKEY_free(key);
    EVP_MD_CTX_cleanup(&mdctx); //EVP_MD_CTX_destroy(mdctx);
    return NULL;
  }

//  free(jwt_signature_input_str); //keep it off now to enable the VerifySignedJWT() to go ahead

  //generate final concatenated payload
  unsigned char jwt_signature_str_b64_encoded[GetBase64BufferAllocationSize(signature_len)]; memset(jwt_signature_str_b64_encoded, 0, sizeof(jwt_signature_str_b64_encoded));
  base64url_encode((unsigned char *)rsa_signature, signature_len, jwt_signature_str_b64_encoded);
  asprintf(&jwt_final, "%s.%s.%s", gpc_request_descriptor_ptr->jwt_header_encoded, claim_set_str_b64_encoded, jwt_signature_str_b64_encoded);

  //disabled
//  int sig_verification_code = VerifySignedJWT(jwt_signature_input_str, (const char *)jwt_signature_str_b64_encoded);
//  syslog(LOG_INFO, "%s (pid:'%lu', verification_code:'%d'): JWT Final: '%s'", __func__, pthread_self(), sig_verification_code, jwt_final);

  clean_up_return:
  free(jwt_signature_input_str);
  OPENSSL_free(rsa_signature);
  EVP_PKEY_free(key);
  EVP_MD_CTX_cleanup(&mdctx); //EVP_MD_CTX_destroy(mdctx);

  return jwt_final;

#if 0
  //SHA256 hash base64 representation of header.claim_set inpreparation for signing using own private key
  unsigned char sha256_hashed_buffer[SHA256_DIGEST_LENGTH] = {0};
  _ComputeSHA256Digest(jwt_signature_input_str, strlen(jwt_signature_input_str), sha256_hashed_buffer);


  RSA *rsa_key = EVP_PKEY_get1_RSA(key);//refcount +1

  if (IS_EMPTY(rsa_key)) {
    syslog(LOG_INFO, "%s (pid:'%lu'): ERROR: COULD NOT READ PK: '%s'", __func__, pthread_self(), ERR_error_string(ERR_get_error(), NULL));
    EVP_PKEY_free(key);
    free(claim_set_str);
    free(jwt_signature_input_str);
    return NULL;
  }

  //alternative block that reads from a preprocessor define GOOGLE_OAUTH_PK
#if 0
  BIO *b       = BIO_new_mem_buf(GOOGLE_OAUTH_PK, strlen(GOOGLE_OAUTH_PK));
  RSA *rsa_key = PEM_read_bio_RSAPrivateKey(b, NULL, NULL, NULL);

  if (IS_EMPTY(rsa_key)) {
    syslog(LOG_INFO, "%s (pid:'%lu'): ERROR: COULD NOT READ PK: '%s'", __func__, pthread_self(), ERR_error_string(ERR_get_error(), NULL));
    if (NULL != b) BIO_free(b);
    free(claim_set_str);
    free(jwt_signature_input_str);
    return NULL;
  }
#endif

  //generate signature on header_b64.claim_b64 string representation
  unsigned int signature_len = 0;
  unsigned char  *rsa_returned = calloc(1, RSA_size(rsa_key));
  int ret_code = RSA_sign(NID_sha256, sha256_hashed_buffer, SHA256_DIGEST_LENGTH, rsa_returned, &signature_len, rsa_key);
  if (ret_code == 1) {
    //generate final concatenated payload
    unsigned char jwt_signature_str_b64_encoded[GetBase64BufferAllocationSize(signature_len)]; memset(jwt_signature_str_b64_encoded, 0, sizeof(jwt_signature_str_b64_encoded));
    base64_encode((unsigned char *)rsa_returned, signature_len, jwt_signature_str_b64_encoded);
    asprintf(&jwt_final, "%s.%s.%s", GPC_INTEGRITY_API_OAUTH_JWT_HEADER_B64_ENCODED, claim_set_str_b64_encoded, jwt_signature_str_b64_encoded);

    int sig_verification_code = VerifySignedJWT(jwt_signature_input_str, (const char *)jwt_signature_str_b64_encoded);
    syslog(LOG_INFO, "%s (pid:'%lu', verification_code:'%d'): JWT Final: '%s'", __func__, pthread_self(), sig_verification_code, jwt_final);
  } else {
    syslog(LOG_INFO, "%s (pid:'%lu'): ERROR: COULD NOT SIGH JWT HEADER:CLAIM_SET: SSL error: '%s'", __func__, pthread_self(), ERR_error_string(ERR_get_error(), NULL));
  }

  clean_up:
  free(rsa_returned);
  if (NULL != rsa_key) RSA_free(rsa_key);
  if (key != NULL) EVP_PKEY_free(key);
  if (!IS_EMPTY(claim_set_str)) free(claim_set_str);
  if (!IS_EMPTY(jwt_signature_input_str)) free(jwt_signature_input_str);

  return jwt_final;
#endif
}

//alternative implementation
#if 0
char *
GenerateSignedJWT(HttpRequestContext *http_ptr)
{
#define ONE_HOUR_IN_SECONDS (60 * 60)
  time_t assertion_issue_time       = time(NULL);
  time_t assertion_expiration_time  = time(NULL) + ONE_HOUR_IN_SECONDS;

  char *claim_set_str           = NULL;
  char *jwt_signature_input_str = NULL;
  char *jwt_final               = NULL;

  //create base64 representation of the claim set. The header part is fixed and pre-calculated.
  asprintf(&claim_set_str, GPC_INTEGRITY_API_OAUTH_JWT_CLAIM_SET, assertion_expiration_time, assertion_issue_time);
  unsigned char claim_set_str_b64_encoded[GetBase64BufferAllocationSize(strlen(claim_set_str))];
  memset(claim_set_str_b64_encoded, 0, sizeof(claim_set_str_b64_encoded));
  base64_encode((unsigned char *)claim_set_str, strlen(claim_set_str), claim_set_str_b64_encoded);
  asprintf(&jwt_signature_input_str, "%s.%s", GPC_INTEGRITY_API_OAUTH_JWT_HEADER_B64_ENCODED, claim_set_str_b64_encoded);

  //SHA256 hash base64 representation of header.claim_set inpreparation for signing using own private key
  unsigned char sha256_hashed_buffer[SHA256_DIGEST_LENGTH] = {0};
  _ComputeSHA256Digest(jwt_signature_input_str, strlen(jwt_signature_input_str), sha256_hashed_buffer);

  //convert private key from PEM format stored in a system file
  EVP_PKEY *key = ReadGPCKeyFromFile();
  RSA *rsa_key = EVP_PKEY_get1_RSA(key);//refcount +1

  if (IS_EMPTY(rsa_key)) {
    syslog(LOG_INFO, "%s (pid:'%lu'): ERROR: COULD NOT READ PK: '%s'", __func__, pthread_self(), ERR_error_string(ERR_get_error(), NULL));
    EVP_PKEY_free(key);
    free(claim_set_str);
    free(jwt_signature_input_str);
    return NULL;
  }

  //alternative block that reads from a preprocessor define GOOGLE_OAUTH_PK
#if 0
  BIO *b       = BIO_new_mem_buf(GOOGLE_OAUTH_PK, strlen(GOOGLE_OAUTH_PK));
  RSA *rsa_key = PEM_read_bio_RSAPrivateKey(b, NULL, NULL, NULL);

  if (IS_EMPTY(rsa_key)) {
    syslog(LOG_INFO, "%s (pid:'%lu'): ERROR: COULD NOT READ PK: '%s'", __func__, pthread_self(), ERR_error_string(ERR_get_error(), NULL));
    if (NULL != b) BIO_free(b);
    free(claim_set_str);
    free(jwt_signature_input_str);
    return NULL;
  }
#endif

  //generate signature on header_b64.claim_b64 string representation
  unsigned int signature_len = 0;
  unsigned char  *rsa_returned = calloc(1, RSA_size(rsa_key));
  int ret_code = RSA_sign(NID_sha256, sha256_hashed_buffer, SHA256_DIGEST_LENGTH, rsa_returned, &signature_len, rsa_key);
  if (ret_code == 1) {
    //generate final concatenated payload
    unsigned char jwt_signature_str_b64_encoded[GetBase64BufferAllocationSize(signature_len)]; memset(jwt_signature_str_b64_encoded, 0, sizeof(jwt_signature_str_b64_encoded));
    base64_encode((unsigned char *)rsa_returned, signature_len, jwt_signature_str_b64_encoded);
    asprintf(&jwt_final, "%s.%s.%s", GPC_INTEGRITY_API_OAUTH_JWT_HEADER_B64_ENCODED, claim_set_str_b64_encoded, jwt_signature_str_b64_encoded);

    int sig_verification_code = VerifySignedJWT(jwt_signature_input_str, (const char *)jwt_signature_str_b64_encoded);
    syslog(LOG_INFO, "%s (pid:'%lu', verification_code:'%d'): JWT Final: '%s'", __func__, pthread_self(), sig_verification_code, jwt_final);
  } else {
    syslog(LOG_INFO, "%s (pid:'%lu'): ERROR: COULD NOT SIGH JWT HEADER:CLAIM_SET: SSL error: '%s'", __func__, pthread_self(), ERR_error_string(ERR_get_error(), NULL));
  }

  clean_up:
  free(rsa_returned);
  if (NULL != rsa_key) RSA_free(rsa_key);
  if (key != NULL) EVP_PKEY_free(key);
  if (!IS_EMPTY(claim_set_str)) free(claim_set_str);
  if (!IS_EMPTY(jwt_signature_input_str)) free(jwt_signature_input_str);

  return jwt_final;

}
#endif

/**
 * @brief Verify a signed JWT
 * @param jwt_signature_input_str[IN] base64 representation of JWT header and claim set in the format of "<heade>.<claim_set>"
 * @param signature[IN] base64 representation of signature block
 * @param public_key_pem[IN] the public key associate with the private key used to generate the signature in PEM format
 * @return 0 on success
 */
int
VerifySignedJWT(char *jwt_signature_input_str,  const char *signature)
{
  int ret_code = 0;
  //  EVP_MD_CTX *mdctx  = EVP_MD_CTX_create(); // EVP_MD_CTX_destroy(mdctx); crashes when pointer is used
  EVP_MD_CTX mdctx;  EVP_MD_CTX_init(&mdctx);
  EVP_PKEY    *key    = ReadGPCPublicKeyFromFile();

  if (EVP_DigestInit_ex(&mdctx,  EVP_get_digestbyname("SHA256"), NULL) <= 0) {
    syslog(LOG_INFO, "%s (pid:'%lu'): ERROR: COULD NOT INITIALISE DIGEST SIGNING (%s)", __func__, pthread_self(), ERR_error_string(ERR_get_error(), NULL));
    ret_code = -1; goto return_code_final;
  }

  if (1 != EVP_DigestVerifyUpdate(&mdctx, jwt_signature_input_str, strlen(jwt_signature_input_str))) {//Initialize `key` with a public key
    syslog(LOG_INFO, "%s (pid:'%lu'): ERROR: COULD NOT INITIALISE PUBLIC KEY (%s)", __func__, pthread_self(), ERR_error_string(ERR_get_error(), NULL));
    ret_code = -2; goto return_code_final;
  }

  if (1 == EVP_DigestVerifyFinal(&mdctx, (const unsigned char *)signature, strlen(signature))) {
    ret_code = 0; goto return_code_final;
  }

  ret_code = -3;
  syslog(LOG_INFO, "%s (pid:'%lu'): ERROR: COULD NOT VERIFY SIGNED JWT HEADER:CLAIM_SET: SSL error: '%s'", __func__, pthread_self(), ERR_error_string(ERR_get_error(), NULL));

  return_code_final:
  EVP_PKEY_free(key);
  EVP_MD_CTX_cleanup(&mdctx); //EVP_MD_CTX_destroy(mdctx);EVP_MD_CTX_destroy(mdctx);
  return ret_code;

  //older implementation
#if 0
  //SHA256 hash base64 representation of header.claim_set
  unsigned char sha256_hashed_buffer[SHA256_DIGEST_LENGTH] = {0};
  _ComputeSHA256Digest(jwt_signature_input_str, strlen(jwt_signature_input_str), sha256_hashed_buffer);

  int signature_sz = 0;
  unsigned char *signature_raw_buffer = base64_decode((const unsigned char *)signature, strlen(signature), &signature_sz);
  if (signature_sz == 0) {
    syslog(LOG_INFO, "%s (pid:'%lu'): ERROR: COULD NOT decode base64 provided signature: '%s'", __func__, pthread_self(), signature);
    return -1;
  }

  //convert private key from PEM format
  BIO *b       = BIO_new_mem_buf(public_key_pem, strlen(public_key_pem));
  RSA *rsa_key = PEM_read_bio_RSAPublicKey(b, NULL, NULL, NULL);
  if (IS_EMPTY(rsa_key)) {
    syslog(LOG_INFO, "%s (pid:'%lu'): ERROR: COULD NOT READ PUBK: '%s'", __func__, pthread_self(), ERR_error_string(ERR_get_error(), NULL));
    if (NULL != b) BIO_free(b);
    free(signature_raw_buffer);
    return -1;
  }

  int ret_code = RSA_verify(NID_sha256, (unsigned char *) jwt_signature_input_str, strlen(jwt_signature_input_str), signature_raw_buffer, signature_sz, rsa_key);
  if (ret_code != 1) {
    syslog(LOG_INFO, "%s (pid:'%lu'): ERROR: COULD NOT VERIFY SIGNED JWT HEADER:CLAIM_SET: SSL error: '%s'", __func__, pthread_self(), ERR_error_string(ERR_get_error(), NULL));
    ret_code = -2;
  } else ret_code = 0;

  if (NULL != rsa_key) RSA_free(rsa_key);
  if (NULL != b) BIO_free(b);
  free(signature_raw_buffer);

  return ret_code;
#endif

  /* SHA256_CTX sha256 = {0};
   unsigned char digest[SHA_DIGEST_LENGTH];

   SHA256_Init(&sha256);
   SHA256_Update(&sha256, buf, buf_len);
   SHA256_Final(digest, &sha256);

   BIO *b = NULL;
   X509 *c;
   EVP_PKEY *k = NULL;*/

#if 0
  https://www.bmt-online.org/rsa-verify.html
  Now that we have signed our content, we want to verify its signature. The method for this action is (of course) RSA_verify(). The inputs to the action are the content itself as a buffer buf of bytes or size buf_len, the signature block sig of size sig_len as generated by RSA_sign(), and the X509 certificate corresponding to the private key used for the signature. We will use the DER representation of the cert, in its own buffer cert of bytes of size cert_len.

Therefore, our signature verification function will look something like this:

int verify_data(
        const void *buf,    /* input data: byte array */
        size_t buf_len,
        const void *sig,    /* signature block: byte array */
        size_t sig_len,
        const void *cert,   /* input cert: byte array of the DER representation */
        size_t cert_len) {
int status = EXIT_SUCCESS; int rc = 1; /* OpenSSL return code */
As for the signature case, the first step is to hash the data:

    SHA_CTX sha_ctx = { 0 };
    unsigned char digest[SHA_DIGEST_LENGTH];

    rc = SHA1_Init(&sha_ctx);
    if (1 != rc) { handle_it(); status = EXIT_FAILURE; goto end; }

    rc = SHA1_Update(&sha_ctx, buf, buf_len);
    if (1 != rc) { handle_it(); status = EXIT_FAILURE; goto end; }

    rc = SHA1_Final(digest, &sha_ctx);
    if (1 != rc) { handle_it(); status = EXIT_FAILURE; goto end; }
The next step is to extract the RSA * form of the public key from the X509 certificate, as expected by the RSA_verify() function. This is a little less immediate as for getting the RSA private key from its PEM representation:

#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/evp_pkey.h>

...

    BIO *b = NULL;
    X509 *c;
    EVP_PKEY *k = NULL;

...

    b = BIO_new_mem_buf(cert, cert_len);
    if (1 != rc) { handle_it(); status = EXIT_FAILURE; goto end; }

    c = d2i_X509_bio(b, NULL);
    if (1 != rc) { handle_it(); status = EXIT_FAILURE; goto end; }

    k = X509_get_pubkey(c);
    if (1 != rc) { handle_it(); status = EXIT_FAILURE; goto end; }

    /* make sure that the public key from the cert is an RSA key */
    if (EVP_PKEY_RSA != EVP_PKEY_type(k->type)) { handle_it(); status = EXIT_FAILURE; goto end; }
We have now gathered all the elements needed for the verification of the signature: the data digest digest, the signature block sig and the RSA public key corresponding to the private key used to sign the data EVP_PKEY_get1_RSA(k). All that's left to do is to perform the signature verification with RSA_verify():

    rc = RSA_verify(NID_sha1, digest, sizeof digest, sig, sig_len, EVP_PKEY_get1_RSA(k));
    if (1 != rc) { handle_it(); status = EXIT_FAILURE; goto end; }
To finish, let's tie up the loose ends and handle the error cases:

end:
    if (NULL != k) EVP_PKEY_free(k);
    if (NULL != b) BIO_free(b);

    if (1 != rc) fprintf(stderr, "OpenSSL error: %s\n", ERR_error_string(ERR_get_error()));

    return status;
}
#endif

  return 0;
}

/**
 *
 * @return
 * @dynamic_memory EXPORTS 'EVP_PKEY *'. free with EVP_PKEY_free()
 */
EVP_PKEY *
ReadGPCPrivateKeyFromFile(const char *file_name_and_location)
{
  EVP_PKEY *key = NULL;

  BIO *in = BIO_new(BIO_s_file());
  if (IS_EMPTY(in)) {
    syslog(LOG_INFO, "%s (pid:'%lu'): ERROR: COULD NOT OPEN BIO STREAM FOR READING: '%s'", __func__, pthread_self(), ERR_error_string(ERR_get_error(), NULL));
    goto return_error;
  }

  if (BIO_read_filename(in, file_name_and_location) <= 0) {
    syslog(LOG_INFO, "%s (pid:'%lu', key_file:'%s'): ERROR: COULD NOT OPEN KEY FILE: '%s'", __func__, pthread_self(), file_name_and_location, ERR_error_string(ERR_get_error(), NULL));
    goto return_error;
  }

  //Read Private Key. Can also use  PEM_read_bio_RSAPrivateKey to get RSA directly
  key = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
  if (IS_PRESENT(key)) {
    BIO_free(in);
    return key;//(EVP_PKEY_get1_RSA(key));
  }

  return_error:
  return NULL;
}

/**
 *
 * @return
 * @dynamic_memory EXPORTS 'EVP_PKEY *'. free with EVP_PKEY_free()
 */
EVP_PKEY *
ReadGPCPublicKeyFromFile()
{
  EVP_PKEY *key = NULL;

  BIO *in = BIO_new(BIO_s_file());
  if (IS_EMPTY(in)) {
    syslog(LOG_INFO, "%s (pid:'%lu'): ERROR: COULD NOT OPEN BIO STREAM FOR READING: '%s'", __func__, pthread_self(), ERR_error_string(ERR_get_error(), NULL));
    goto return_error;
  }

  if (BIO_read_filename(in, "/opt/ufsrv/etc/gcp_service_account_unfacd_integrity_id_rsa.pub") <= 0) {
    syslog(LOG_INFO, "%s (pid:'%lu', key_file:'%s'): ERROR: COULD NOT OPEN KEY FILE: '%s'", __func__, pthread_self(), "/opt/ufsrv/etc/gcp_service_account_unfacd_integrity_id_rsa.pub", ERR_error_string(ERR_get_error(), NULL));
    goto return_error;
  }

  //Read Private Key. Can also use  PEM_read_bio_RSAPrivateKey to get RSA directly
  key = PEM_read_bio_PUBKEY(in, NULL, NULL, NULL);
  if (IS_PRESENT(key)) {
    BIO_free(in);
    return key;
  }

  return_error:
  return NULL;
}

/**
 * @deprecated
 * @param jwt_header_plus_claim_str
 * @param str_len
 * @param sha256_hashed_buffer
 * @return
 */
__unused static int
_ComputeSHA256Digest(char *jwt_header_plus_claim_str, size_t str_len, unsigned char *sha256_hashed_buffer)
{
  int ret_code;
  SHA256_CTX sha256 = {0};

  if ((ret_code = SHA256_Init(&sha256)) == 1) {
    if ((ret_code = SHA256_Update(&sha256, jwt_header_plus_claim_str, str_len)) == 1) {
      if ((ret_code = SHA256_Final(sha256_hashed_buffer, &sha256)) == 1) {
        return 0;
      }
    }
  }

  return ret_code;
}

/**
 * @brief This implementation uses the new style of openssl digest generation, where the underlying engine is abstracted out.
 * See legacy implementation \ref _ComputeSHA256Digest
 * @param message message to be digested
 * @param message_sz size of message
 * @param message_hashed_out user allocated buffer of size EVP_MAX_MD_SIZE
 * @return
 */
void
ComputeMessageDigest(unsigned char *message, size_t message_sz, unsigned char *message_hashed_out, unsigned int *message_hashed_out_sz)
{
  // Create a Message Digest Context for the operations
  const EVP_MD *md = EVP_get_digestbyname("SHA256");
  EVP_MD_CTX mdctx;  EVP_MD_CTX_init(&mdctx);// EVP_MD_CTX *mdctx = EVP_MD_CTX_new(); //where pointer is used

  // Sets up the Message Digest Context to be used with the engine, in this case
  // NULL which means the default implmentation for the Message Digest Type will be used
  ENGINE* engine = NULL;
  EVP_DigestInit_ex(&mdctx, md, engine);

  // Hash the passed in message and add it to mdctx->md_data
  EVP_DigestUpdate(&mdctx, message, message_sz);//this can be called again on another message

  int ret_code = EVP_DigestFinal(&mdctx, message_hashed_out, message_hashed_out_sz);//EVP_MD_CTX_cleanup(&mdctx) automatically done. The version EVP_DigestFinal_ex() doesn't do that
  if (ret_code == 1) {
    unsigned char *message_digest_hexed = hex_print(message_hashed_out, EVP_MAX_MD_SIZE, NULL);
    syslog(LOG_INFO, "%s (pid:'%lu', md_type:'%d', md_len:'%i', EVP_MD_CTX_size:'%d', EVP_MD_size:'%d'):digest: '%s' ", __func__, pthread_self(), EVP_MD_type(md), *message_hashed_out_sz, EVP_MD_CTX_size(&mdctx), EVP_MD_size(md), message_digest_hexed);
    free(message_digest_hexed);
  }

  //unused extra diagnostics
#if 0
  const EVP_MD* md_ptr = EVP_MD_CTX_md(&mdctx);
  printf("md_ptr = %lu\n", EVP_MD_meth_get_flags(md_ptr));

  int r = EVP_MD_CTX_test_flags(&mdctx, EVP_MD_FLAG_DIGALGID_MASK);
  printf("r =%d\n", r);
#endif

}
