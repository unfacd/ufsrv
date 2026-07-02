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

#include <gpc_utils.h>
#include <uflib/utils_time.h>
#include "ufsrv_core/include/delegator_session_worker_thread.h"
#include <gpc_http_utils.h>

/**
 * Reflect the state of a locking operation.
 */
enum LockRequestState {
    LOCK_STATE_LOCKED,
    LOCK_STATE_WONT_LOCK,
    LOCK_STATE_UNLOCKED,
    LOCK_STATE_ERROR
};

static inline enum LockRequestState _LockRD(pthread_rwlock_t  *rwlock_ptr, int try_flag);
static inline enum LockRequestState _LockRW(pthread_rwlock_t  *rwlock_ptr, int try_flag);
static inline enum LockRequestState _UnLock(pthread_rwlock_t  *rwlock_ptr);

static ScheduledJobType *_GetScheduledJobTypeForGpcAuthenticatorIntegrityApi(void);
static ScheduledJobType *_GetScheduledJobTypeForGpcAuthenticatorFcmMessaging(void);
static int _RequestGpcAuthenticationFcmMessaging(ScheduledJob *scheduled_job, void *arg);
static int _RequestGpcAuthenticationIntegrityApi(ScheduledJob *scheduled_job, void *arg);
static int _SchedulerCallbackOnFirstInsertedGpcAuthentication(ScheduledJob *scheduled_job, void *arg);
static ScheduledJob *_GetScheduledJobForGpcAuthenticatorIntegrityApi(void);
static ScheduledJob *_GetScheduledJobForGpcAuthenticatorFcmMessaging(void);
static CloudAuthorizationToken * _ProvideCloudAuthorizationToken(const ScheduledJob *scheduled_job_ptr) __attribute_const__;

/**
 * @brief Configure and initialise a scheduler job to refresh the GPC authenticator token for accessing Integrity API
 * @return statically allocated ScheduledJob *
 */
ScheduledJob *
InitialiseScheduledJobTypeForGpcAuthenticatorIntegrityApi(void)
{
  ScheduledJob *scheduled_job_ptr = _GetScheduledJobForGpcAuthenticatorIntegrityApi();
  RegisterScheduledJobType(GetScheduledJobsStore(), _GetScheduledJobTypeForGpcAuthenticatorIntegrityApi());
  InsertScheduledJob(GetScheduledJobsStore(), scheduled_job_ptr);//this will trigger the retrieval of the token

  return scheduled_job_ptr;
}

/**
 * @brief Configure and initialise a scheduler job to refresh the GPC authenticator token for accessing FCM Messaging
 * @return statically allocated ScheduledJob *
 */
ScheduledJob *
InitialiseScheduledJobTypeForGpcAuthenticatorFcmMessaging(void)
{
  ScheduledJob *scheduled_job_ptr = _GetScheduledJobForGpcAuthenticatorFcmMessaging();
  RegisterScheduledJobType(GetScheduledJobsStore(), _GetScheduledJobTypeForGpcAuthenticatorFcmMessaging());
  InsertScheduledJob(GetScheduledJobsStore(), scheduled_job_ptr);//this will trigger the retrieval of the token

  return scheduled_job_ptr;
}

__unused static CloudAuthorizationToken *
_ProvideCloudAuthorizationToken(const ScheduledJob *scheduled_job_ptr)
{
  return AS_CLOUD_AUTHORIZATION_TOKEN(scheduled_job_ptr->context_data);
}
/**
 * @brief Static type initialiser for the authenticator refresh job
 * @return statically allocated ScheduledJob *
 */
__attribute__ ((const)) static ScheduledJobType *
_GetScheduledJobTypeForGpcAuthenticatorIntegrityApi(void)
{
  static ScheduledJobType job_type_session_timeout = {
          .type_name				=	"GPC OAuth2.0 Authenticator for Integrity API",
          .type_id					=	0,//gets assigned by type registry
          .frequency_mode		=	PERIODIC,
          .concurrency_mode	=	SINGLE_INSTANCE,
          .frequency				=	_CONFIGDEFAULT_GPC_AUTHENTICATOR_CHECK_FREQUENCY,
          .callbacks					=	{
                  .on_compare_keys	= (CallbackOnCompareKeys)TimeValueComparator,
                  .on_error				  =	NULL,
                  .on_run					  =	(CallbackOnRun)_RequestGpcAuthenticationIntegrityApi,
                  .on_get_time      = GetTimeNowInMicros,
                  .on_first_insert  = (CallbackOnInsert) _SchedulerCallbackOnFirstInsertedGpcAuthentication
          }
  };

  return &job_type_session_timeout;

}

/**
 * @brief Static type initialiser for the authenticator refresh job
 * @return statically allocated ScheduledJob *
 */
__attribute__ ((const)) static ScheduledJobType *
_GetScheduledJobTypeForGpcAuthenticatorFcmMessaging(void)
{
  static ScheduledJobType job_type_session_timeout = {
          .type_name				=	"GPC OAuth2.0 Authenticator for FCM Messaging",
          .type_id					=	0,//gets assigned by type registry
          .frequency_mode		=	PERIODIC,
          .concurrency_mode	=	SINGLE_INSTANCE,
          .frequency				=	_CONFIGDEFAULT_GPC_AUTHENTICATOR_CHECK_FREQUENCY,
          .callbacks					=	{
                  .on_compare_keys	= (CallbackOnCompareKeys)TimeValueComparator,
                  .on_error				  =	NULL,
                  .on_run					  =	(CallbackOnRun)_RequestGpcAuthenticationFcmMessaging,
                  .on_get_time      = GetTimeNowInMicros,
                  .on_first_insert  = (CallbackOnInsert) _SchedulerCallbackOnFirstInsertedGpcAuthentication
          }
  };

  return &job_type_session_timeout;

}

static int _InitialiseConcurrencyControl(pthread_rwlock_t *rwlock_ptr);
/**
 * @brief A helper method to initialise the mutex
 * @return 0 on success, or errno associated with the request.
 */
static int
_InitialiseConcurrencyControl(pthread_rwlock_t *rwlock_ptr)
{
  pthread_rwlockattr_t  rwattr = {0};
  pthread_rwlockattr_init(&rwattr);

  int rc = pthread_rwlock_init(rwlock_ptr, &rwattr);//==0 on success

  if (unlikely(rc != 0)) {
    char error_str[250] = {0};
    strerror_r(errno, error_str, 250);

    syslog(LOG_ERR, "%s: ERROR: (pid:'%lu', errno: '%d', error:'%s'): COULD NOT INITIALISE rwlock...", __func__, pthread_self(), errno, error_str);

    return 1;
  }

  return 0;
}

/**
 * @brief Main initialiser for the data structures holding state information on the GPC authenticator token for Google's Integrity API access.
 *
 * This should only be called once per ufsrv instance. This is designed around single-producer-multiple consumer model. Once initialised, accessing the token
 * CloudAuthorizationDescriptor.authorization_token should be delegated via the prescribed "getter" function. Only the producer locks the mutex.
 *
 * @return static allocation and initialisation of CloudAuthorizationDescriptor
 */
CloudAuthorizationDescriptor *
ProvideGpcAuthenticatorDescriptorForIntegrityApi()
{
  static CloudAuthorizationDescriptor authenticator_descriptor_integrity_api = {0};
  authenticator_descriptor_integrity_api.service_request_descriptor_ptr = ProvideGpcServiceRequestDescriptorForIntegrityApi();
  _InitialiseConcurrencyControl(&authenticator_descriptor_integrity_api.concurrency_control.rwlock);

  return &authenticator_descriptor_integrity_api;
}

CloudAuthorizationDescriptor *
ProvideGpcAuthenticatorDescriptorForFcmMessaging()
{
  static CloudAuthorizationDescriptor authenticator_descriptor_integrity_fcm_messaging = {0};

  authenticator_descriptor_integrity_fcm_messaging.service_request_descriptor_ptr = ProvideGpcServiceRequestDescriptorForFirebaseMessaging();
  _InitialiseConcurrencyControl(&authenticator_descriptor_integrity_fcm_messaging.concurrency_control.rwlock);

  return &authenticator_descriptor_integrity_fcm_messaging;
}

/**
 * @brief static type initialiser
 */
const GpcServiceRequestDescriptor *const
ProvideGpcServiceRequestDescriptorForFirebaseMessaging(void)
{
  static GpcServiceRequestDescriptor gpc_service_request_descriptor = {.is_refresh_token=true, .claim_set_template=GPC_FIREBASE_MESSAGING_OAUTH_JWT_CLAIM_SET, .jwt_header_encoded=GPC_FIREBASE_MESSAGING_OAUTH_JWT_HEADER_B64_ENCODED, .private_key_manifestation=FILE_SYSTEM, .private_key.file_name="/opt/ufsrv/etc/gcp_service_account_ufsrv_firebase_messaging_id_rsa"};

  return &gpc_service_request_descriptor;
}

/**
 * @brief static type initialiser
 */
const GpcServiceRequestDescriptor *const
ProvideGpcServiceRequestDescriptorForIntegrityApi(void)
{
  static GpcServiceRequestDescriptor gpc_service_request_descriptor = {.is_refresh_token=true, .claim_set_template=GPC_INTEGRITY_API_OAUTH_JWT_CLAIM_SET, .jwt_header_encoded=GPC_INTEGRITY_API_OAUTH_JWT_HEADER_B64_ENCODED, .private_key_manifestation=FILE_SYSTEM, .private_key.file_name="/opt/ufsrv/etc/gcp_service_account_unfacd_integrity_id_rsa"};

  return &gpc_service_request_descriptor;
}

#include <uflib/utils_threads.h>
/**
 * @brief Delegates access to the GPC authorization token associated with a given GPC service account.
 *
 * @param blocking_mode
 * @param authorization_token_state_ptr_out[in/out] user allocated and returned back with current state information as directed by blocking_mode
 * @return Mutated copy of the Authorization token.
 * @dynamic_memory: EXPORTS 'char *'
 */
CloudAuthorizationTokenState *
ProvideGpcAuthorizationToken(CloudAuthorizationToken *authorization_token_ptr, enum AccessBlockingMode blocking_mode, CloudAuthorizationTokenState *authorization_token_state_ptr_out)
{
  if (!AS_CLOUD_AUTHORIZATION_DESCRIPTOR(authorization_token_ptr)->is_initialised) {
    authorization_token_state_ptr_out->access_blocking_mode = UNINITIALISED;
    return authorization_token_state_ptr_out;
  }

  enum LockRequestState lock_request_state;

  switch(blocking_mode) {
    case FORCED:
      authorization_token_state_ptr_out->access_blocking_mode = FORCED;
      authorization_token_state_ptr_out->authorization_token = strdup(AS_CLOUD_AUTHORIZATION_DESCRIPTOR(authorization_token_ptr)->authorization_token);
      return authorization_token_state_ptr_out;

    case BLOCKING:
      authorization_token_state_ptr_out->access_blocking_mode = BLOCKING;
      lock_request_state = _LockRD(&(AS_CLOUD_AUTHORIZATION_DESCRIPTOR(authorization_token_ptr)->concurrency_control.rwlock), false);
      if (lock_request_state == LOCK_STATE_LOCKED) {
#ifdef __UF_FULLDEBUG
        syslog(LOG_DEBUG, "%s: {pid'%lu', th_ctx:'%lu', cid:'%lu'  o:'%p'}: SUCCESS:  MUTEX lock for cloud authenticator concurrency control mutex acquired...", __func__, pthread_self(), THREAD_CONTEXT_PTR, SESSION_ID(sesn_ptr), sesn_ptr);
#endif
        authorization_token_state_ptr_out->authorization_token = strdup(AS_CLOUD_AUTHORIZATION_DESCRIPTOR(authorization_token_ptr)->authorization_token);
        _UnLock(&(AS_CLOUD_AUTHORIZATION_DESCRIPTOR(authorization_token_ptr)->concurrency_control.rwlock));
        return authorization_token_state_ptr_out;
      } else {
        char *err_str = thread_error(errno);
        syslog(LOG_DEBUG, "%s: {pid'%lu', th_ctx:'%lu'}: ERROR: COULD NOT acquire MUTEX lock for cloud authenticator concurrency control mutex (errno='%d'): '%s'", __func__, pthread_self(), 0UL, errno, err_str);
        authorization_token_state_ptr_out->authorization_token = NULL;
        return authorization_token_state_ptr_out;
      }

    case NON_BLOCKING:
      authorization_token_state_ptr_out->access_blocking_mode = NON_BLOCKING;
      lock_request_state = _LockRD(&(AS_CLOUD_AUTHORIZATION_DESCRIPTOR(authorization_token_ptr)->concurrency_control.rwlock), true);
      if (lock_request_state == LOCK_STATE_LOCKED) {
#ifdef __UF_FULLDEBUG
        syslog(LOG_DEBUG, "%s: {pid'%lu', th_ctx:'%lu', cid:'%lu'  o:'%p'}: SUCCESS: MUTEX TRY-LOCK for Mcloud authenticator concurrency control mutex acquired...", __func__, pthread_self(), THREAD_CONTEXT_PTR, SESSION_ID(sesn_ptr), sesn_ptr);
#endif
        authorization_token_state_ptr_out->authorization_token = strdup(AS_CLOUD_AUTHORIZATION_DESCRIPTOR(authorization_token_ptr)->authorization_token);
        _UnLock(&(AS_CLOUD_AUTHORIZATION_DESCRIPTOR(authorization_token_ptr)->concurrency_control.rwlock));
        return authorization_token_state_ptr_out;
      } else {
        char *err_str = thread_error(errno);
        syslog(LOG_DEBUG, "%s: {pid'%lu', th_ctx:'%lu'}: ERROR: COULD NOT acquire MUTEX lock for cloud authenticator concurrency control mutex (errno='%d'):  '%s'", __func__, pthread_self(), 0UL, errno, err_str);
        authorization_token_state_ptr_out->authorization_token = NULL;
        return authorization_token_state_ptr_out;
      }

    default:
      ;
  }

  return authorization_token_state_ptr_out;

}

/**
 * @brief Update the currently stored value of the authorization token.
 * @note This is a mutex locking function.
 * @param authorization_token_ptr Opaque type representing CloudAuthorizationDescriptor
 * @param authorization_token_state_ptr_out Carrier for the anew authorization token
 * @return CloudAuthorizationTokenState *
 */
CloudAuthorizationTokenState *
SetGpcAuthorizationToken(CloudAuthorizationToken *authorization_token_ptr, CloudAuthorizationTokenState *authorization_token_state_ptr_out) {
  CloudAuthorizationDescriptor *authorization_descriptor_ptr = AS_CLOUD_AUTHORIZATION_DESCRIPTOR(authorization_token_ptr);

  enum LockRequestState lock_request_state = _LockRW(&authorization_descriptor_ptr->concurrency_control.rwlock, false);
  if (lock_request_state == LOCK_STATE_LOCKED) {
#ifdef __UF_FULLDEBUG
    syslog(LOG_DEBUG, "%s: {pid'%lu', th_ctx:'%lu', cid:'%lu'  o:'%p'}: SUCCESS:  MUTEX lock for cloud authenticator concurrency control mutex acquired...", __func__, pthread_self(), THREAD_CONTEXT_PTR, SESSION_ID(sesn_ptr), sesn_ptr);
#endif
    if (IS_PRESENT(authorization_descriptor_ptr->authorization_token)) free(authorization_descriptor_ptr->authorization_token);
    authorization_descriptor_ptr->authorization_token = authorization_token_state_ptr_out->authorization_token;
    authorization_descriptor_ptr->when_last_refresh = time(NULL);
    _UnLock(&authorization_descriptor_ptr->concurrency_control.rwlock);
    return authorization_token_state_ptr_out;
  } else {
    char *err_str = thread_error(errno);
    syslog(LOG_DEBUG, "%s: {pid'%lu', th_ctx:'%lu'}: ERROR: COULD NOT acquire MUTEX lock for cloud authenticator concurrency control mutex (errno='%d'): '%s'", __func__, pthread_self(), 0UL, errno, err_str);
    authorization_token_state_ptr_out->authorization_token = NULL;
    return authorization_token_state_ptr_out;
  }
}

/**
 * 	@brief Initialise scheduling state data
 * 	@note Since this job type does not allow concurrent scheduling, ie one job of this type can ever exist in the scheduler
 * 	we can get away with allocating a single static reference.
 */
static ScheduledJob *
_GetScheduledJobForGpcAuthenticatorIntegrityApi(void)
{
  static ScheduledJob job_gpc_authenticator;

  job_gpc_authenticator.job_type_ptr = _GetScheduledJobTypeForGpcAuthenticatorIntegrityApi();
  job_gpc_authenticator.context_data = ProvideGpcAuthenticatorDescriptorForIntegrityApi();

  return &job_gpc_authenticator;
}

/**
 * 	@brief Initialise scheduling state data
 * 	@note Since this job type does not allow concurrent scheduling, ie one job of this type can ever exist in the scheduler
 * 	we can get away with allocating a single static reference.
 */
static ScheduledJob *
_GetScheduledJobForGpcAuthenticatorFcmMessaging(void)
{
  static ScheduledJob job_gpc_authenticator;

  job_gpc_authenticator.job_type_ptr = _GetScheduledJobTypeForGpcAuthenticatorFcmMessaging();
  job_gpc_authenticator.context_data = ProvideGpcAuthenticatorDescriptorForFcmMessaging();

  return &job_gpc_authenticator;
}

static int _RequestGpcAuthorizationToken(HttpRequestContext *http_ctx_ptr, const GpcServiceRequestDescriptor *service_request_descriptor_ptr, CloudAuthorizationDescriptor *authorization_descriptor_ptr_out);

/**
 * @brief Request authorization token from GPC backend
 * @param http_ctx_ptr[in]
 * @param service_request_descriptor_ptr[in]
 * @param authorization_descriptor_ptr_out[in/out] Carrier to store returned token value
 * @return 0 on success
 */
static int
_RequestGpcAuthorizationToken(HttpRequestContext *http_ctx_ptr, const GpcServiceRequestDescriptor *service_request_descriptor_ptr, CloudAuthorizationDescriptor *authorization_descriptor_ptr_out)
{
  char *authorization_code = GetGoogleAccessCodeAuthorization(http_ctx_ptr, service_request_descriptor_ptr);
  if (IS_PRESENT(authorization_code)) {
    if (SetGpcAuthorizationToken(AS_CLOUD_AUTHORIZATION_TOKEN(authorization_descriptor_ptr_out), &(CloudAuthorizationTokenState){.authorization_token=authorization_code})) {
      authorization_descriptor_ptr_out->when_last_refresh = time(NULL);
      return 0;
    }
  }

  return -1;
}

/**
 * @brief Scheduler on insert callback. This callback will cause the token to be retrieved immediately upon scheduler insert.
 * @param scheduled_job Job definition
 * @param arg Client-context data, in this instance CloudAuthorizationDescriptor
 * @return
 * @dynamic EXPORTS char *
 */
static int
_SchedulerCallbackOnFirstInsertedGpcAuthentication(ScheduledJob *scheduled_job, void *arg)
{
  int return_value = 0;
  CloudAuthorizationDescriptor *authorization_descriptor_ptr = (CloudAuthorizationDescriptor *)arg;
  WorkersConfigDescriptor *jobworkers_config = GetJobWorkersConfigurationDescriptor();
  if (_RequestGpcAuthorizationToken(pthread_getspecific(jobworkers_config->ufsrv_http_request_context_key), authorization_descriptor_ptr->service_request_descriptor_ptr, authorization_descriptor_ptr) == 0) {
    authorization_descriptor_ptr->is_initialised = 1;

#ifdef __UF_TESTING
    syslog(LOG_INFO, "%s {pid:'%lu', last_refresh:'%lu', token:'%s'}: LOADED GPC Authorization token for '%s':'...", __func__, pthread_self(), authorization_descriptor_ptr->when_last_refresh, authorization_descriptor_ptr->authorization_token, scheduled_job->job_type_ptr->type_name);
#endif
   goto exit_with_return_value;
  }

  return_value = -1;

  exit_with_return_value:
  return return_value;
}

/**
 * @brief Schedule runtime callback
 * @param scheduled_job
 * @param arg
 * @return
 */
static int
_RequestGpcAuthenticationIntegrityApi(ScheduledJob *scheduled_job, void *arg)
{
  int return_value = 0;
  CloudAuthorizationDescriptor *authorization_descriptor_ptr = (CloudAuthorizationDescriptor *)arg;
  WorkersConfigDescriptor *jobworkers_config = GetJobWorkersConfigurationDescriptor();
  if (_RequestGpcAuthorizationToken(pthread_getspecific(jobworkers_config->ufsrv_http_request_context_key), authorization_descriptor_ptr->service_request_descriptor_ptr, authorization_descriptor_ptr) == 0) {

#ifdef __UF_TESTING
    syslog(LOG_INFO, "%s {pid:'%lu', last_refresh:'%lu', token:'%s'}: REFRESHED GPC Authorization token for '%s':'...", __func__, pthread_self(), authorization_descriptor_ptr->when_last_refresh, authorization_descriptor_ptr->authorization_token, scheduled_job->job_type_ptr->type_name);
#endif
    goto  exit_with_return_value;
  }

  return_value = -1;

  exit_with_return_value:
  return return_value;
}

/**
 * @brief Schedule runtime callback
 * @param scheduled_job
 * @param arg
 * @return
 */
static int
_RequestGpcAuthenticationFcmMessaging(ScheduledJob *scheduled_job, void *arg)
{
  return _RequestGpcAuthenticationIntegrityApi(scheduled_job, arg);//currently the implementation is generic, so distinction is required
}

static inline enum LockRequestState
_LockRD(pthread_rwlock_t  *rwlock_ptr, int try_flag)
{
  int lock_state;

  if (try_flag) {//The calling thread acquires the read lock if a writer does not hold the lock and there are no writers blocked on the lock.
    lock_state = pthread_rwlock_tryrdlock(rwlock_ptr);
    if (lock_state == 0) {
#ifdef __UF_FULLDEBUG
      syslog(LOG_DEBUG, "%s (pid:'%lu', try:'1'): SUCCESS: TRY-READ lock acquired...",__func__, pthread_self());
#endif
      goto return_locked;
    } else {
      char *err_str = thread_error(errno);
      syslog(LOG_DEBUG, "%s (pid:'%lu', try:'1'): ERROR: COULD NOT acquire TRY-READ lock (errno='%d'): '%s'", __func__, pthread_self(), errno, err_str);
      goto return_wont_lock;
    }
  } else {
    lock_state = pthread_rwlock_rdlock(rwlock_ptr);
    if (lock_state == 0) {
#ifdef __UF_FULLDEBUG
      syslog(LOG_DEBUG, "%s (pid:'%lu'): SUCCESS: READ lock for Fence events acquired...", __func__, pthread_self());
#endif
      goto return_locked;
    } else {
      char *err_str = thread_error(errno);
      syslog(LOG_DEBUG, "%s (pid:'%lu'): ERROR: COULD NOT acquire READ lock (errno='%d'): '%s'", __func__, pthread_self(), errno, err_str);
      goto return_wont_lock;
    }
  }

  return_wont_lock:
  return LOCK_STATE_WONT_LOCK;

  return_locked:
  return LOCK_STATE_LOCKED;

}

static inline enum LockRequestState
_LockRW(pthread_rwlock_t  *rwlock_ptr, int try_flag)
{
  int lock_state;

  if (try_flag) {
    lock_state = pthread_rwlock_trywrlock(rwlock_ptr);
    if (lock_state == 0) {
#ifdef __UF_FULLDEBUG
      syslog(LOG_DEBUG, "%s (pid:'%lu', o:'%p', ctx:'%p', try:'1', func:'%s'): SUCCESS: TRY-WRITE/READ lock for Fence events acquired...", __func__, pthread_self(), f_ptr, IS_PRESENT(thread_ctx_ptr)?thread_ctx_ptr:0, func);
#endif
      goto return_locked;
    } else {
      char *err_str = thread_error(errno);
      syslog(LOG_DEBUG, "%s (pid:'%lu', try:'1'): ERROR: COULD NOT acquire TRY-WRITE/READ lock (errno='%d'): '%s'", __func__, pthread_self(),  errno, err_str);
      goto return_wont_lock;
    }
  } else {
    lock_state = pthread_rwlock_wrlock(rwlock_ptr);
    if (lock_state == 0) {
#ifdef __UF_FULLDEBUG
      syslog (LOG_DEBUG, "%s (pid:'%lu'): SUCCESS: WRITE/READ lock for Fence events acquired...",__func__, pthread_self());
#endif
      goto return_locked;
    } else {
      char *err_str = thread_error(errno);
      syslog (LOG_DEBUG, "%s (pid:'%lu'): ERROR: COULD NOT acquire WRITE/READ lock for Fence events (errno='%d'): '%s'", __func__, pthread_self(), errno, err_str);
      goto return_wont_lock;
    }
  }

  return_wont_lock:
  return LOCK_STATE_WONT_LOCK;

  return_locked:
  return LOCK_STATE_LOCKED;

}

static inline enum LockRequestState
_UnLock(pthread_rwlock_t  *rwlock_ptr)
{
  int lock_state = pthread_rwlock_unlock(rwlock_ptr);
  if (lock_state == 0) {
#ifdef __UF_FULLDEBUG
    syslog(LOG_DEBUG, "%s: (pid:'%lu'): SUCCESS: RELEASED WRITE/READ lock for Fence events...", __func__, pthread_self(), );
#endif
    return LOCK_STATE_UNLOCKED;
  } else {
    char *err_str = thread_error(errno);
    syslog(LOG_DEBUG, "%s: (pid:'%lu'): ERROR: COULD NOT RELEASE WRITE/READ lock for Fence events (errno='%d'): '%s'", __func__, pthread_self(),  errno, err_str);
  }

  return LOCK_STATE_ERROR;

}

