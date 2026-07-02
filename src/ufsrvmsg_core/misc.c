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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <main.h>
#include <error.h>
#include <nportredird.h>
#include <signal.h>
#include <misc.h>
#include <sockets.h>
#include <sched.h>

extern ufsrv *const masterptr;
static void sigShutdownHandler(int);

 signal_f *
 nsignal(int signo, signal_f *func)
 {
  struct sigaction  sa, osa;

  memset(&sa, 0, sizeof(sa));
  memset(&osa, 0, sizeof(osa));

   sa.sa_handler = func;
   sigemptyset(&sa.sa_mask);
   sa.sa_flags |= SA_RESTART;

    if (sigaction(signo, &sa, &osa) < 0) {
      return (SIG_ERR);
     }

   return (osa.sa_handler);

 }  /**/

 static void
 sigShutdownHandler(int sig)
 {
     char *msg __attribute__((unused));

     switch (sig) {
     case SIGINT:
         msg = "Received SIGINT scheduling shutdown...";
         break;
     case SIGTERM:
         msg = "Received SIGTERM scheduling shutdown...";
         break;
     default:
         msg = "Received shutdown signal, scheduling shutdown...";
     };

     /* SIGINT is often delivered via Ctrl+C in an interactive session.
      * If we receive the signal the second time, we interpret this as
      * the user really wanting to quit ASAP without waiting to persist
      * on disk. */
     //if (server.shutdown_asap && sig == SIGINT) {
//         rdbRemoveTempFile(getpid());
         exit(1); /* Exit with an error since this was not a clean shutdown. */
     //}
     /*else
	 if (server.loading)
	 {
         exit(0);
     }

     masterptr->*/

 }

 void
 InitSignals(void)
 {
	 if (nsignal(SIGPIPE, SIG_IGN) == SIG_ERR) {
	  psignal(SIGPIPE, "Couldn't install signal handler");
	  exit (1);
	 }

	 if (nsignal(SIGHUP, SIG_IGN) == SIG_ERR) {
	  psignal (SIGHUP, "Couldn't install signal handler");
	  exit (1);
	}

	 struct sigaction act;

	 /* When the SA_SIGINFO flag is set in sa_flags then sa_sigaction is used.
	  * Otherwise, sa_handler is used. */
	 sigemptyset(&act.sa_mask);
	 act.sa_flags = 0;
	 act.sa_handler = sigShutdownHandler;
	 sigaction(SIGTERM, &act, NULL);
	 sigaction(SIGINT, &act, NULL);

	 return;

 }  /**/

 /*
 ** "+x.y" --> c_version >= "x.y"
 ** "-x.y" --> c_version <= "x.y"
 ** "x.y" --> c_version == "x.y"
 ** return 1 if any of the above conditions is true
 */
 int ValidateRequiredVersion(const char *s)
 {
  char per=0;
  const char *p;
  extern const char *ufsrv_version;

	if (IS_STR_LOADED(s)) {
      float cv, /*current version*/
            v;

       p = s;
	   sscanf(p, "%f", &v);
	   sscanf(ufsrv_version, "%f", &cv);
 
		if ((*p=='+') || (*p=='-'))  per = *p++;

		if (!per) {
		   return (!(strcmp(ufsrv_version, p)));
		 } else {
			if (per == '+')  return (cv >= v);
			else  return (cv <= v);
		 }
	 } 

   return 0;

 } /**/

 void dummy(void)

 {
 }  /**/

 //caller must free

char *
LUA_GetFieldToString(const char *key)
{
	lua_pushstring(LUA_CTX, key);
	lua_gettable(LUA_CTX, -2);  /* get background[key] */

	if (!lua_isstring(LUA_CTX, -1))
	//error(LUA_CTX, "LUA_GetFieldToString: invalid component in table");
		return "";

	char *result = mystrdup(lua_tostring(LUA_CTX, -1));

	lua_pop(LUA_CTX, 1);  /* remove number */

	return result;

}

/* assume that table is on the stack top */
int LUA_GetFieldToInteger(const char *key)
{
	int result;

	lua_pushstring(LUA_CTX, key);
	lua_gettable(LUA_CTX, -2);  /* get background[key] */

	if (!lua_isnumber(LUA_CTX, -1))return -1;
	//error(LUA_CTX, "LUA_GetFieldToInteger: invalid component in table");

	result = (int)lua_tonumber(LUA_CTX, -1);

	lua_pop(LUA_CTX, 1);  /* remove number */

	return result;
}

#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 30
#include <sys/syscall.h>
static pid_t gettid (void);
static pid_t gettid (void)
{
    return syscall( __NR_gettid );
}
#endif

void SetCpuAffinity(int cpu)
{
	// Getting number of CPUs
	    int cpu_count = (int)sysconf( _SC_NPROCESSORS_ONLN );
	    if (cpu_count < 0)
	    {
	        perror( "sysconf could not get cpu count" );
	        exit (-1);
	    }
	    if (cpu>cpu_count || cpu<0)
	    {
	    	error( -1, errno, "could not set cpu affinity to: '%d'. system only have '%d' cpu", cpu, cpu_count);
	    }

	    cpu_set_t set;
		CPU_ZERO(&set);
		CPU_SET(cpu, &set );
		if (sched_setaffinity( gettid(), sizeof( cpu_set_t ), &set ))
		{
			error(-1, errno,  "sched_setaffinity error" );
		}

		syslog (LOG_INFO, "SetCpuAffinity: SUCCESSFULLY set cpu affinity for this priceess to '%d'. Total cpu in this machine: '%d'", cpu, cpu_count);

}

