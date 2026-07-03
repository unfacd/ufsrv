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
#include <session.h>
#include <ufsrvsfu/sa/re_sa.h>
#include <ufsrvsfu/fmt/re_fmt.h>
#include <ufsrvsfu/ice/re_ice.h>
#include <ufsrvsfu/stun_agent/stun_agent.h>
#include <jobworkers/user_callback_job_descriptor_type.h>
#include <jobworkers/worker_ufsrv_thread.h>
#include <ufsrvsfu/delegator_sfu_worker_thread.h>
#include <sfu_session_provider.h>
#include <re_net.h>
#include <re_dns.h>
#include <re_mem.h>
#include <re_udp.h>
#include <session_worker_sfu_thread.h>
#include <timeout_scheduled_job_provider.h>
#include <ice.h>

_Pragma("GCC diagnostic push")
_Pragma("GCC diagnostic ignored \"-Wunused-but-set-variable\"")
_Pragma("GCC diagnostic ignored \"-Wunused-function\"")

extern __thread BaseThreadContext *base_thread_context;

static void agent_connchk_handler(int err, bool update, void *arg);
static int icem_gather_srflx(InstanceContextForSession *instance_context, StunAgent *stun_agent, const struct sa *srv);
static void stun_resp_handler(int err, uint16_t scode, const char *reason, const struct stun_msg *msg, void *arg);
static void agent_gather_handler(int err, uint16_t scode, const char *reason, void *arg);
static void _ReclaimICEAgentJob (UserCallbackJobDescriptor *callback_job_descriptor);
static void icetest_check_connchecks(struct StunAgent *agent);
static int send_sdp(StunAgent *agent);
static int agent_encode_sdp(StunAgent *ag);
static int agent_verify_outgoing_sdp(const StunAgent *agent);
static int agent_start(StunAgent *agent);
static int attr_add(struct attrs *attrs, const char *name, const char *value, ...);
static const char *attr_find(const struct attrs *attrs, const char *name);
static int dns_init(StunAgent *stun_agent);
static void stun_dns_handler(int err, const struct sa *srv, void *arg);

static int _EnableSessionForIoNotifications(StunAgent *stun_agent, struct sa *sa);
static int _SufSessionTimeoutHandler(ScheduledJob *scheduled_job, InstanceHolderForSession *instance_session);

/**
 * Helper function to build job execution context for gathering ICE candidates with a remote agent
 * @param callback_job_descriptor_provided
 * @return
 */
UserCallbackJobDescriptor *
BuildICEAgentJob(UserCallbackJobDescriptor *callback_job_descriptor_provided, InstanceHolder *instance_session)
{
  UserCallbackJobDescriptor *callback_job_descriptor;
  if (IS_EMPTY(callback_job_descriptor_provided)) callback_job_descriptor = calloc(1, sizeof(UserCallbackJobDescriptor));
  else callback_job_descriptor = callback_job_descriptor_provided;

  callback_job_descriptor->callback_args    = BuildIceAgentDescriptor(NULL, true);
  callback_job_descriptor->handler          = (user_callback)ContactStunServer;
  callback_job_descriptor->finaliser        = (user_callback_on_finish)_ReclaimICEAgentJob;
  callback_job_descriptor->instance_session = instance_session;

  return callback_job_descriptor;
}

/**
 * @brief Helper-getter function to build definittion for ICEAgent
 * @param ice_agent_descriptor_provided use if preallocated by user, otherwise allocate storage on behalf of user
 * @param is_fallback_stun_server if on, use default values for stun server HostNameDescriptor
 * @return
 * @dynamic_memory: EXPORTS ICEAgentDescriptor * if no pre-allocation was provided by user.
 */
ICEAgentDescriptor *
BuildIceAgentDescriptor(ICEAgentDescriptor *ice_agent_descriptor_provided, bool is_fallback_stun_server)
{
  ICEAgentDescriptor *ice_agent_descriptor = NULL;

  if (IS_EMPTY(ice_agent_descriptor_provided)) ice_agent_descriptor = calloc(1, sizeof(ICEAgentDescriptor));
  else ice_agent_descriptor = ice_agent_descriptor_provided;

  if (is_fallback_stun_server) {
    ice_agent_descriptor->stun_server = GetFallbackStunServer(NULL);
  } else {
    ice_agent_descriptor->stun_server = GetEmptyStunServer(NULL);
  }

  return ice_agent_descriptor;
}

__attribute__((const)) const HostNameDescriptor  *const
GetFallbackStunServerHostName()
{
  static HostNameDescriptor fallback_stun_server_hostname = {
          .port = 19302,//3478,//19302,
          .name = "stun.l.google.com"//"stun.ekiga.net"//"stun.l.google.com"
  };

  return &fallback_stun_server_hostname;
}

/**
 * @brief Helper-getter function to build an StunServer instance initialised with default StunServer values.
 * @param stun_server_provided if present, must be prior allocated by user, otherwise storage will be allocated on behalf of user.
 * @return built instance with initialised default values.
 * @dynamic_memory: EXPORTS StunServer * if no pre-allocation was provided by user.
 */
__attribute__((const)) StunServer  *
GetFallbackStunServer(StunServer *stun_server_provided)
{
  StunServer *stun_server = NULL;

  if (IS_EMPTY(stun_server_provided)) stun_server = calloc(1, sizeof (StunServer));
  else stun_server = stun_server_provided;

  stun_server->server_name_descriptor.port = GetFallbackStunServerHostName()->port;
  stun_server->server_name_descriptor.name = GetFallbackStunServerHostName()->name;

  return stun_server;
}

/**
 * @brief Allocate a blank instance of the StunServer object.
 * @param stun_server_provided If provided, no memory allocation is performed and as a convinience, server is initialised to zero.
 * @return StunServer instance
 */
__attribute__((const)) StunServer  *
GetEmptyStunServer(StunServer *stun_server_provided)
{
  StunServer *stun_server = NULL;

  if (IS_EMPTY(stun_server_provided)) stun_server = calloc(1, sizeof (StunServer));
  else {
    stun_server = stun_server_provided;
    memset(stun_server, '\0', sizeof(StunServer));
  }

  return stun_server;
}

__attribute__((nonnull(1)))
static void _ReclaimICEAgentJob(UserCallbackJobDescriptor *callback_job_descriptor)
{
  free(callback_job_descriptor->callback_args);
}

/**
 * @brief Jumpf off the STUN request
 * @param ice_agent pre-allocated
 * @param instance_session new, unconnected session
 * @return
 */
UFSRVResult * __attribute__((nonnull(1)))
ContactStunServer(ICEAgentDescriptor *ice_agent, InstanceHolder *instance_session)
{
  int compid = 7;
  StunAgent *stun_agent = &ice_agent->stun_agent;
  StunServer *stun_server = ice_agent->stun_server;
  Session *session = SessionOffInstanceHolder(instance_session);
  SESSION_PROTOCOL_SESSION_DATA(session) = AS_PROTOCOL_SESSION_DATA(ice_agent);

  char resolvedStunServerAddress[MAXHOSTLEN] = {0};
  GenericDnsResolve(stun_server->server_name_descriptor.name, resolvedStunServerAddress, sizeof resolvedStunServerAddress);
  if (*resolvedStunServerAddress == '\0') {
    syslog(LOG_ERR, "%s (address:'%s'): ERROR: COULD NOT RESOLVE ADDRESS", __func__, stun_server->server_name_descriptor.name);
    _RETURN_RESULT_RES(&(base_thread_context->ufsrv_result), NULL, RESULT_TYPE_ERR, RECODE_NONE)
  }
  //not needed.. just for demo
  sa_set_str((struct sa *)&stun_server->socket_address, resolvedStunServerAddress, stun_server->server_name_descriptor.port);

//  dns_init(stun_agent);//auto discovery of stun server

  sa_set_str(&stun_agent->laddr, resolvedStunServerAddress, stun_server->server_name_descriptor.port);
//AA should be already define in agent
  re_snprintf(stun_agent->lufrag, sizeof(stun_agent->lufrag), "ufrag-%s", "ufsrv");
  re_snprintf(stun_agent->lpwd, sizeof(stun_agent->lpwd), "password-0123456789abcdef-%s", "ufsrv");

  int err = udp_listen(&stun_agent->us, &stun_agent->laddr, 0, 0);
  if (err) {
    _RETURN_RESULT_RES(&(base_thread_context->ufsrv_result), NULL, RESULT_TYPE_ERR, RECODE_NONE)
  }
//  udp_local_get(stun_agent->us, &stun_agent->laddr); //AA-

  //AA 2 for being offerer
  icem_alloc(&stun_agent->icem, ICE_MODE_FULL, ICE_ROLE_CONTROLLING, IPPROTO_UDP, 0,
             2, stun_agent->lufrag, stun_agent->lpwd, agent_connchk_handler, stun_agent);
  icem_set_name(stun_agent->icem, "ufsrv");
  icem_comp_add(stun_agent->icem, compid, stun_agent->us);

  struct sa temp_sa = {0}; char addr[MAXHOSTLEN] = {0};
  net_default_source_addr_get(AF_INET, &temp_sa);
  (void)re_snprintf(addr, sizeof(addr), "%H", sa_print_addr, &temp_sa);
  icem_cand_add(stun_agent->icem, compid, 0, "eth0", &temp_sa);//&stun_agent->laddr);

  SESSION_EVENT_HANDLER_ON_READ(session) = StunResponseHandler;
  SESSION_WHEN_SERVICE_STARTED(session) = GetTimeNowInMillis();
  AddSessionWorkerScheduledJobForTimeout(GetScheduledJobForSfuSessionTimeout((CallbackOnRun)_SufSessionTimeoutHandler, AS_CLIENT_CONTEXT_DATA(instance_session)));//timeout on session in 1 minute from now
  icem_gather_srflx(&(InstanceContextForSession){.instance_sesn_ptr=instance_session, .sesn_ptr=session}, stun_agent, &stun_agent->laddr);

  _RETURN_RESULT_RES(&(base_thread_context->ufsrv_result), NULL, RESULT_TYPE_SUCCESS, RECODE_NONE)

}

/**
 * @brief callback handler for SfuSessions timeout timers.
 * @param scheduled_job the job context created for this timer
 * @param instance_session Argument passed in via executor for the session that has just timedout
 * @return
 */
static int
_SufSessionTimeoutHandler(ScheduledJob *scheduled_job, InstanceHolderForSession *instance_session) {
  Session *session = SessionOffInstanceHolder(instance_session);
  /*int service_duration = SESSION_WHEN_SERVICED(session) - SESSION_WHEN_SERVICE_STARTED(session);
  if (service_duration >= 1000 || service_duration < 0) {
    int res = DisableIoEventsNotification(GetWorkerDelegatorEventsHandler(), instance_session);
    SfuSessionReturnToRecycler(instance_session, NO_CONTEXT_DATA, CALLFLAGS_EMPTY);

    //reclaim scheduled_job if dynamically allocated
  }*/

  ICEAgentDescriptor *agent = AS_ICE_AGENT_DESCRIPTOR(SESSION_PROTOCOL_SESSION_DATA(session));

  return 0;
}

int
StunResponseHandler(InstanceHolderForSession *instance_session, enum IOHandlerEventStage event_stage)
{
  Session *session = SessionOffInstanceHolder(instance_session);
  ICEAgentDescriptor *ice_agent = (ICEAgentDescriptor *)SESSION_PROTOCOL_SESSION_DATA(session);
  if (event_stage == PRE_HANDLER) {
    udp_read(ice_agent->stun_agent.us, -1);
    SESSION_WHEN_SERVICED(session) = GetTimeNowInMillis();
  }

  return 0;
}

static void agent_connchk_handler(int err, bool update, void *arg)
{
  struct StunAgent *agent = arg;
  struct StunAgent *other = (agent);
  const struct sa *laddr, *raddr;

  if (err) {
    /*if (err != ENOMEM) {
      DEBUG_WARNING("%s: connectivity checks failed: %m\n",
                    agent->name, err);
    }

    complete_test(agent->it, err);*/
    return;
  }

  if (agent->offerer ^ update) {
    syslog(LOG_WARNING, "error in update flag\n");
//    complete_test(agent->it, EPROTO);
    return;
  }

  agent->conncheck_ok = true;

  icetest_check_connchecks(agent);
  /* verify ICE states */
//  TEST_ASSERT(!icem_mismatch(agent->icem));

  /* after connectivity checks are complete we expect:
   *   1 local candidate
   *   1 remote candidates
   */
 /* TEST_EQUALS(agent->n_cand, list_count(icem_lcandl(agent->icem)));
  TEST_EQUALS(other->n_cand, list_count(icem_rcandl(agent->icem)));
  TEST_EQUALS(0, list_count(icem_checkl(agent->icem)));
  TEST_EQUALS(agent->n_cand * other->n_cand,
              list_count(icem_validl(agent->icem)));

  laddr = icem_selected_laddr(agent->icem, agent->compid);
  raddr = &agent_other(agent)->laddr;

  if (!sa_cmp(&agent->laddr, laddr, SA_ALL)) {
    DEBUG_WARNING("unexpected selected address: %J\n", laddr);
    complete_test(agent->it, EPROTO);
    return;
  }

  if (!icem_verify_support(agent->icem, agent->compid, raddr)) {
    complete_test(agent->it, EPROTO);
    return;
  }

#if 0
  (void)re_printf("Agent %s -- Selected address: local=%J  remote=%J\n",
			agent->name, laddr, raddr);
#endif

  icetest_check_connchecks(agent->it);

  out:
  if (err)
    complete_test(agent->it, err);*/
}

static void icetest_check_connchecks(struct StunAgent *agent)
{
  if (agent->mode == ICE_MODE_FULL && !agent->conncheck_ok)
    return;
//  if (it->b->mode == ICE_MODE_FULL && !it->b->conncheck_ok)
//    return;

  /* start an async timer to let the socket traffic complete */
//  tmr_start(&it->tmr, 1, tmr_handler, it);
}

//https://github.com/darcyg/restunc/blob/404b4619339b5cc2ca98fa274fded7acac8cf5ef/src/main.c
static void stun_dns_handler(int err, const struct sa *srv, void *arg)
{
  StunAgent  *stun_agent = arg;

  if (err) {
    syslog(LOG_ERR, "Could not resolve STUN server %s (%d)\n",
                  stun_agent->stun_server->server_name_descriptor.name, err);
//    req.flags = 0;
    goto out;
  }

  /* Copy STUN Server address */
  sa_cpy(&stun_agent->laddr, srv);
  char bufx[128] = {0};
  (void)re_snprintf(bufx, sizeof bufx, "Resolved STUN server: %J\n", &stun_agent->laddr);
  syslog(LOG_INFO, "%s: Resolved stun server to: '%s'", __func__, bufx);

  out:
  stun_agent->dns = mem_deref(stun_agent->dns);
}

static int dns_init(StunAgent *stun_agent)
{
  struct sa nsv[4];
  uint32_t nsn;
  int err;

  nsn = ARRAY_SIZE(nsv);

  err = dns_srv_get(NULL, 0, nsv, &nsn);
  if (err) {
    syslog(LOG_ERR, "dns_srv_get: %d\n", err);
    goto out;
  }

  err = dnsc_alloc(&stun_agent->dnsc, NULL, nsv, nsn);
  if (err) {
    syslog(LOG_ERR,"dnsc_alloc: %d\n", err);
    goto out;
  }

  err = stun_server_discover(&stun_agent->dns, stun_agent->dnsc, "stuns", "udp",
                             AF_INET, "unfacd.io", 0,
                             stun_dns_handler, stun_agent);
  if (err) {
    syslog(LOG_ERR, "stun_server_discover failed (%d)\n", err);
    goto out;
  }

  out:
  return err;
}

/**
 *
 * @param stun_agent
 * @param srv socket address representing the destination STUN server
 * @return
 */
static int icem_gather_srflx(InstanceContextForSession *instance_context, StunAgent *stun_agent, const struct sa *srv)
{
  int err;

  err = stun_request(AS_INSTANCE_CONTEXT(instance_context), &stun_agent->ct_gath, icem_stun(stun_agent->icem), IPPROTO_UDP,
                     stun_agent->us, srv, 0,
                     STUN_METHOD_BINDING,
                     NULL, false, 0,
                     stun_resp_handler, stun_agent, 1,
                     STUN_ATTR_SOFTWARE, stun_software);
  if (err)
    return err;

  return 0;
}

//static ssize_t agent_check_completed(StunAgent *stun_agent, struct msghdr *msghdr);
//static async wait_agent_check(StunAgent *stun_agent, struct msghdr *msghdr, struct async *async_udp_read, size_t timeout);

#include <session.h>
#include <uflib/recycler/recycler.h>
#include <protocol_sfu.h>
#include <sfu_session_provider.h>
#include <nportredird.h>

//AA after header was deocded and client transaction deallocated
static void stun_resp_handler(int err, uint16_t scode, const char *reason, const struct stun_msg *msg, void *arg)
{
  StunAgent *ag = arg;
  struct stun_attr *attr;
  struct ice_cand *lcand;

  if (err || scode > 0) {
    syslog(LOG_WARNING, "STUN Request failed: %d\n", err);
    goto out;
  }

  /* base candidate */
  lcand = icem_cand_find(icem_lcandl(ag->icem), ag->compid, NULL);
  if (!lcand)
    goto out;

  attr = stun_msg_attr(msg, STUN_ATTR_XOR_MAPPED_ADDR);
  if (!attr)
    attr = stun_msg_attr(msg, STUN_ATTR_MAPPED_ADDR);
  if (!attr) {
    syslog(LOG_WARNING, "no Mapped Address in Response");
    err = EPROTO;
    goto out;
  }

  err = icem_lcand_add(ag->icem, icem_lcand_base(lcand), ICE_CAND_TYPE_SRFLX, &attr->v.sa);
  //AA+
  char bufx[512]={0};
  re_snprintf(bufx, sizeof bufx, "%J", &attr->v.sa);
  syslog(LOG_DEBUG, "%s: ICE_CAND_TYPE_SRFLX: '%s'", __func__ , bufx);
  HostNameDescriptor *hostname = GetSocketAddress(udp_get_soc(ag->us), NULL);
  if (IS_PRESENT(hostname)) {
    syslog(LOG_DEBUG, "%s: LOCAL ADDRESS: '%s:%d'", __func__ , hostname->name, hostname->port);
    free(hostname);
  }

  out:
  agent_gather_handler(err, scode, reason, ag);
}

static int
_EnableSessionForIoNotifications(StunAgent *stun_agent, struct sa *sa)
{
  InstanceHolderForSession *session_instance = (InstanceHolderForSfuSession *)RecyclerGet(SfuSessionPoolTypeNumber(), NULL, CALLFLAGS_EMPTY);
  Session *session = SessionOffInstanceHolder(session_instance);
  //int sock_fd = SetupListeningSocket(GetMainListenerAddress(), sa_port(sa), SOCK_UDP, 0);
  int sock_fd = udp_get_soc(stun_agent->us);
  if (sock_fd > 0) {
    session->ssptr->sock = sock_fd;//udp_get_soc(stun_agent->us);
    session->ssptr->port = sa_port(sa);
    sa_ntop(sa, session->ssptr->address, sizeof session->ssptr->address);
    syslog(LOG_DEBUG, "%s (socket:'%d', port:'%d'): Requesting UDP listening socket notifications", __func__ , sock_fd, sa_port(sa));
    return EnableIoEventsNotification(GetWorkerDelegatorEventsHandler(), session_instance);
  } else {
    syslog(LOG_ERR, "%s (errno:'%d', port:'%d'): ERROR COULD NOT SETUP LISTENING SOCKET", __func__ , errno, sa_port(sa));
  }

  return -1;
}

/*static async
wait_agent_check(StunAgent *stun_agent, struct msghdr *msghdr, struct async *async_udp_read, size_t timeout_in_seconds)
{
  ssize_t read_size = 0;
  SimpleTimer timeout_timer = {0};
  SimpleTimerSet(&timeout_timer, SECONDS_TO_MICRO_SECONDS(timeout_in_seconds));
  async_begin(async_udp_read);

  while (1) {
    await(agent_check_completed(stun_agent, msghdr)  || SimpleTimerIsExpired(&timeout_timer));
    read_size = msghdr->msg_iov[0].iov_len;
    if (read_size > 0) {
      syslog(LOG_INFO, "%s (read_sz:'%lu'): READ REFLEXIVE: '%s'", __func__, read_size, (char *)msghdr->msg_iov[0].iov_base);
    } else {
      syslog(LOG_INFO, "%s (read_sz:'%lu', errno:'%d'): NO READ REFLEXIVE", __func__, read_size, errno);
    }
  }

  async_end;

}

static ssize_t agent_check_completed(StunAgent *stun_agent, struct msghdr *msghdr)
{
  int res = recvmsg(udp_get_soc(stun_agent->us), msghdr, 0);
  if (res > 1) {
    syslog(LOG_INFO, "STUN CONNECTED: sz:'%lu', msg:'%s'", msghdr->msg_iov->iov_len, (char *)msghdr->msg_iov->iov_base);
    return msghdr->msg_iov->iov_len;
  }  else if (res < 0) {
    if (errno == EAGAIN || errno == EINTR) {
      syslog(LOG_INFO, "STUN NONBLOKING....");
      return 0;//return
    }
  }

  return 0;//error
}*/

static void agent_gather_handler(int err, uint16_t scode, const char *reason, void *arg)
{
  StunAgent *agent = arg;

  if (err)
    ;
//    goto out;
  if (scode) {
    syslog(LOG_WARNING,"gathering failed: %u %s\n", scode, reason);
//    complete_test(agent->it, EPROTO);
    return;
  }

  /* Eliminate redundant local candidates */
  icem_cand_redund_elim(agent->icem);

  err = icem_comps_set_default_cand(agent->icem);
  if (err) {
    syslog(LOG_WARNING, "ice: set default cands failed (%d)\n", err);
//    goto out;
  }

  agent->gathering_ok = true;

  err = send_sdp(agent);
  if (err)
//    goto out;

//  icetest_check_gatherings(agent->it);

  return;

//  out:
//  complete_test(agent->it, err);
}

static int send_sdp(StunAgent *agent)
{
  int err;

  /* verify ICE states */
//  TEST_ASSERT(!icem_mismatch(agent->icem));

  /* after gathering is complete we expect:
   *   1 local candidate
   *   0 remote candidates
   *   checklist and validlist is empty
   */
//  TEST_EQUALS(agent->n_cand, list_count(icem_lcandl(agent->icem)));
//  TEST_EQUALS(0, list_count(icem_rcandl(agent->icem)));
//  TEST_EQUALS(0, list_count(icem_checkl(agent->icem)));
//  TEST_EQUALS(0, list_count(icem_validl(agent->icem)));

  if (agent->use_turn) {
    /* verify that default candidate is the relayed address */
//    TEST_SACMP(&agent->turn->relay,
//               icem_cand_default(agent->icem, agent->compid),
//               SA_ALL);
  }
  else {
    /* verify that default candidate is our local address */
//    TEST_SACMP(&agent->laddr,
//               icem_cand_default(agent->icem, agent->compid),
//               SA_ALL);
  }

  /* we should not have selected candidate-pairs yet */
//  TEST_ASSERT(!icem_selected_laddr(agent->icem, agent->compid));

  err = agent_encode_sdp(agent);
  if (err)
    return err;

  err = agent_verify_outgoing_sdp(agent);
  if (err)
    return err;

  out:
  return err;
}

static int agent_encode_sdp(StunAgent *ag)
{
  struct le *le;
  int err = 0;

  for (le = icem_lcandl(ag->icem)->head; le; le = le->next) {

    struct cand *cand = le->data;

    err = attr_add(&ag->attr_m, "candidate", "%H", ice_cand_encode, cand);
    if (err)
      break;
  }

  err |= attr_add(&ag->attr_m, "ice-ufrag", ag->lufrag);
  err |= attr_add(&ag->attr_m, "ice-pwd", ag->lpwd);

  return err;
}

static int agent_verify_outgoing_sdp(const StunAgent *agent)
{
  __unused const char *cand, *ufrag, *pwd;
  char buf[1024];
  int err = 0;

  if (re_snprintf(buf, sizeof(buf),
                  "7f000001 %u UDP 2113929465 127.0.0.1 %u typ host",
                  agent->compid, sa_port(&agent->laddr)) < 0) {
    return ENOMEM;
  }
  cand = attr_find(&agent->attr_m, "candidate");
//  TEST_STRCMP(buf, str_len(buf), cand, str_len(cand));

  ufrag = attr_find(&agent->attr_m, "ice-ufrag");
  pwd   = attr_find(&agent->attr_m, "ice-pwd");
//  TEST_STRCMP(agent->lufrag, str_len(agent->lufrag),
//              ufrag, str_len(ufrag));
//  TEST_STRCMP(agent->lpwd, str_len(agent->lpwd),
//              pwd, str_len(pwd));

  if (agent->mode == ICE_MODE_FULL) {
//    TEST_ASSERT(NULL == attr_find(&agent->attr_s, "ice-lite"));
  }

  out:
  return err;
}

static void icetest_check_gatherings(struct StunAgent *agent)
{
  int err;

  if (agent->mode == ICE_MODE_FULL && !agent->gathering_ok)
    return;
//  if (it->b->mode == ICE_MODE_FULL && !it->b->gathering_ok)
//    return;

  /* both gatherings are complete
   * exchange SDP and start conncheck
   */

//  err = agent_decode_sdp(it->a, it->b);
//  if (err)
//    goto out;
//  err = agent_decode_sdp(it->b, it->a);
//  if (err)
//    goto out;
//
//  err = verify_after_sdp_exchange(it->a);
//  if (err)
//    goto error;
//  err = verify_after_sdp_exchange(it->b);
//  if (err)
//    goto error;

  err  = agent_start(agent);
//  if (err)
//    goto out;
//  err = agent_start(it->b);
//  if (err)
//    goto out;

  return;

//  out:
//  error:
//  complete_test(it, err);
}

static int agent_decode_sdp(struct StunAgent *agent, struct StunAgent *other)
{
  unsigned i;
  int err = 0;

  for (i=0; i<other->attr_s.attrc; i++) {
    struct attr *attr = &other->attr_s.attrv[i];
    err = ice_sdp_decode(agent->icem, attr->name, attr->value);
    if (err)
      return err;
  }

  for (i=0; i<other->attr_m.attrc; i++) {
    struct attr *attr = &other->attr_m.attrv[i];
    err = icem_sdp_decode(agent->icem, attr->name, attr->value);
    if (err)
      return err;
  }

  return err;
}

static int verify_after_sdp_exchange(struct StunAgent *agent)
{
  struct StunAgent *other = (agent);
  int err = 0;

  /* verify remote mode (after SDP exchange) */
  if (other->mode == ICE_MODE_FULL) {
//    TEST_ASSERT(find_debug_string(agent->icem,
//                                  "remote_mode=Full"));
  }

  /* verify ICE states */
//  TEST_ASSERT(!icem_mismatch(agent->icem));

  /* after SDP was exchanged, we expect:
   *   1 local candidate
   *   1 remote candidates
   *   checklist and validlist is empty
   */
//  TEST_EQUALS(agent->n_cand, list_count(icem_lcandl(agent->icem)));
//  TEST_EQUALS(other->n_cand, list_count(icem_rcandl(agent->icem)));
//  TEST_EQUALS(0, list_count(icem_checkl(agent->icem)));
//  TEST_EQUALS(0, list_count(icem_validl(agent->icem)));

  if (agent->use_turn) {
    /* verify that default candidate is the relayed address */
//    TEST_SACMP(&agent->turn->relay,
//               icem_cand_default(agent->icem, agent->compid),
//               SA_ALL);
  }
  else {
    /* verify that default candidate is our local address */
//    TEST_SACMP(&agent->laddr,
//               icem_cand_default(agent->icem, agent->compid),
//               SA_ALL);
  }

  /* we should not have selected candidate-pairs yet */
//  TEST_ASSERT(!icem_selected_laddr(agent->icem, agent->compid));

  out:
  if (err) {
    syslog(LOG_WARNING, "agent %s failed\n", agent->name);
  }
  return err;
}

static int agent_start(StunAgent *agent)
{
  struct StunAgent *other = (agent);
  int err = 0;

  /* verify that check-list is empty before we start */
//  TEST_EQUALS(0, list_count(icem_checkl(agent->icem)));
//  TEST_EQUALS(0, list_count(icem_validl(agent->icem)));

  if (agent->mode == ICE_MODE_FULL) {

    err = icem_conncheck_start(agent->icem);
    if (err)
      return err;

//    TEST_EQUALS(agent->n_cand * other->n_cand, list_count(icem_checkl(agent->icem)));
  }

//  TEST_EQUALS(0, list_count(icem_validl(agent->icem)));

  out:
  return err;
}

static int attr_add(struct attrs *attrs, const char *name,
                    const char *value, ...)
{
  struct attr *attr = &attrs->attrv[attrs->attrc];
  va_list ap;
  int r, err = 0;

//  TEST_ASSERT(attrs->attrc <= ARRAY_SIZE(attrs->attrv));

//  TEST_ASSERT(strlen(name) < sizeof(attr->name));
  str_ncpy(attr->name, name, sizeof(attr->name));

  if (value) {
    va_start(ap, value);
    r = re_vsnprintf(attr->value, sizeof(attr->value), value, ap);
    va_end(ap);
//    TEST_ASSERT(r > 0);
  }

  attrs->attrc++;

  out:
  return err;
}

static const char *attr_find(const struct attrs *attrs, const char *name)
{
  unsigned i;

  if (!attrs || !name)
    return NULL;

  for (i=0; i<attrs->attrc; i++) {
    const struct attr *attr = &attrs->attrv[i];

    if (0 == str_casecmp(attr->name, name))
      return attr->value;
  }

  return NULL;
}

_Pragma("GCC diagnostic pop")