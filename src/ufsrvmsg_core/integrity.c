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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <nportredird.h>
#include <integrity.h>
#include <gpc_utils.h>
#include <gpc_http_utils.h>
#include <thread_context_type.h>
#include <http_request.h>
#include <json/json.h>
#include <uflib/utils_crypto.h>
#include <uflib/utils_base64url.h>

extern __thread ThreadContext ufsrv_thread_context;

/**
 * @brief Submit a preformatted integrity verdict request to google.
 * @param http_ptr[IN] Http handling context containing data objects necessary for handling http request, response and processing of response
 * @note check https://developers.google.com/identity/sign-in/web/server-side-flow for oauth2 handling, as the call below will fail without it
 * @param integrity_token[IN] previously acquired integrity token
 * @return 0 on success
 * @url //curl playintegrity.googleapis.com/v1/unfacd:decodeIntegrityToken -d '{ "integrity_token": "INTEGRITY_TOKEN" }'
 * { "tokenPayloadExternal": { "requestDetails": { "requestPackageName": "com.unfacd.android.debug", "timestampMillis": "1725099936456", "requestHash": "660d4942502883584065ed5cb68c6538d0766674d53dfac5a50f3fb7be525434" }, "appIntegrity": { "appRecognitionVerdict": "UNRECOGNIZED_VERSION", "packageName": "com.unfacd.android.debug", "certificateSha256Digest": [ "RIyAfqhCrsbF_26eEtgyXA7JsUh1xDjxuCM1sLcFJiQ" ], "versionCode": "7902" }, "deviceIntegrity": { "deviceRecognitionVerdict": [ "MEETS_DEVICE_INTEGRITY" ] }, "accountDetails": { "appLicensingVerdict": "UNEVALUATED" } } }
 */
int
GetGoogleIntegrityVerdictResponse(HttpRequestContext *http_ptr, const char *integrity_token, IntegrityVerdictDescriptor *verdict_descriptor_out, const GpcServiceRequestDescriptor *const gpc_request_descriptor_ptr)
{
#define GOOGLE_INTEGRITY_SERVER "https://playintegrity.googleapis.com/v1/com.unfacd.android:decodeIntegrityToken" //https://developer.android.com/google/play/integrity/classic#decrypt-verify-google-servers
#define GOOGLE_API_AUTHORIZATION "Authorization: Bearer %s"
  
  char *post_data = NULL;
 /* char *gpc_access_token = GetGoogleAccessCodeAuthorization(http_ptr, gpc_request_descriptor_ptr);
  if (IS_EMPTY(gpc_access_token)) return 0;

  char *authorization_str = NULL;
  asprintf(&authorization_str, GOOGLE_API_AUTHORIZATION, gpc_access_token);
  free(gpc_access_token);*/

  CloudAuthorizationTokenState gpc_token_state = {0};
  if (IS_EMPTY(ProvideGpcAuthorizationToken(GetUfsrvCloudAuthorizationTokenForIntegrityApi(), BLOCKING, &gpc_token_state))) {
    return 0;
  }
  char *authorization_str = NULL;
  asprintf(&authorization_str, GOOGLE_API_AUTHORIZATION, gpc_token_state.authorization_token);
  free(gpc_token_state.authorization_token);

  if (asprintf(&post_data, "{ \"integrity_token\": \"%s\" }", integrity_token) > 0) {
#ifdef __UF_TESTING
    syslog(LOG_INFO, "%s {pid:'%lu', th_ctx:'%p'}: Requesting Integrity Verdict for token: '%s'...", __func__, pthread_self(), THREAD_CONTEXT_PTR, post_data);
#endif

  ResetHttpRequestContext(http_ptr);
  struct curl_slist *headers_dictionary = NULL;

  headers_dictionary = curl_slist_append(headers_dictionary, authorization_str);
  curl_slist_append(headers_dictionary, "Content-Type: application/json");
  curl_slist_append(headers_dictionary,  "Accept: application/json");

  curl_easy_setopt(http_ptr->curl, CURLOPT_CUSTOMREQUEST, "POST");
  curl_easy_setopt(http_ptr->curl, CURLOPT_HTTPHEADER, headers_dictionary);
  curl_easy_setopt(http_ptr->curl, CURLOPT_POSTFIELDS, post_data);
  curl_easy_setopt(http_ptr->curl, CURLOPT_URL, GOOGLE_INTEGRITY_SERVER);

  if ((http_ptr->curl_code = curl_easy_perform(http_ptr->curl)) != CURLE_OK) {
    syslog(LOG_ERR, "%s (pid:'%lu'): ERROR COULD NOT POST REQUEST '%s'. Error: '%s'", __func__, pthread_self(), post_data, http_ptr->curl_error_str);
    free(post_data);
    free(authorization_str);
    //no clean up we just rely n reset upon subsequent calls ro get url
    return -1;
  }

  free(post_data);
  free(authorization_str);

  //fetch http response code. 200 is success
  long http_code = 0;
  curl_easy_getinfo(http_ptr->curl, CURLINFO_RESPONSE_CODE, &http_code);

  if ((ExtractJsonResponse(http_ptr)) == 0) {
#ifdef __UF_TESTING
    const char *json_str_verdict = json_object_to_json_string(http_ptr->jobj);
    syslog(LOG_INFO, "%s (pid:'%lu'): Received IntegrityVerdict from Google '%s'", __func__, pthread_self(), json_str_verdict);
#endif

    ParseIntegrityVerdictResponse(http_ptr->jobj, verdict_descriptor_out);
  }
  //todo 8/31/24 devops:
  //examine property "appIntegrity"
   //examine "deviceIntegrity": { "deviceRecognitionVerdict": [ "MEETS_DEVICE_INTEGRITY" ] }
//    int success = json_object_get_int(json__get(http_ptr->jobj, "success"));
  }

  return 0;

}

IntegrityVerdictDescriptor *
ParseIntegrityVerdictResponse(json_object *jobj_ptr, IntegrityVerdictDescriptor *verdict_descriptor_ptr_out)
{
  json_object *jobj_token_payload = json_object_object_get(jobj_ptr, "tokenPayloadExternal");
  if (IS_PRESENT(jobj_token_payload)) {
    json_object *jobj_request_hash = json_object_object_get(json_object_object_get(jobj_ptr, "requestDetails"), "requestHash");
    if (IS_PRESENT(jobj_request_hash)) {
      verdict_descriptor_ptr_out->request_hash = (char *)json_object_to_json_string(jobj_request_hash);
    }
    json_object *jobj_app_integrity = json_object_object_get(json_object_object_get(jobj_ptr, "appIntegrity"), "appRecognitionVerdict");
    array_list *jobj_array_device_integrity = json_object_get_array(json_object_object_get(json_object_object_get(jobj_ptr, "deviceIntegrity"), "deviceRecognitionVerdict"));

    return verdict_descriptor_ptr_out;
  }

  return NULL;
}

//google sample output
#if 0
{
  "tokenPayloadExternal": {
      "accountDetails": {
          "appLicensingVerdict": "LICENSED"
      },
      "appIntegrity": {
          "appRecognitionVerdict": "PLAY_RECOGNIZED",
          "certificateSha256Digest": ["pnpa8e8eCArtvmaf49bJE1f5iG5-XLSU6w1U9ZvI96g"],
          "packageName": "com.test.android.integritysample",
          "versionCode": "4"
      },
      "deviceIntegrity": {
          "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"]
      },
      "requestDetails": {
          "nonce": "SafetyNetSample1654058651834",
          "requestPackageName": "com.test.android.integritysample",
          "timestampMillis": "1654058657132"
      }
  }
}
#endif