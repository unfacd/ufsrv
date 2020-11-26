/**
 * Copyright (C) 2015-2019 unfacd works
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
#include <utils_crypto.h>
#include <sockets.h>
#include <uflib/adt/adt_linkedlist.h>
#include <session.h>
#include <misc.h>
#include <nportredird.h>
#include <signal.h>
#include <ufsrv_core/protocol/protocol.h>
#include <command_console_thread.h>
#include <sessions_delegator_type.h>
#include <ufsrv_core/msgqueue_backend/ufsrvmsgqueue.h>

static void Banner (void) __attribute__ ((unused));
static void GoDaemon (void);

const char *c_version	= "3.0";

extern 			ufsrv 						*const masterptr;
extern 			SessionsDelegator *const sessions_delegator_ptr;
extern const Protocol 					*const protocols_registry_ptr;

int main (int argc, char *argv[])
{
 extern int ProcessConfigfile (const char *);
 Socket *s_ptr_console	=	NULL;
 Socket *s_ptr_main_listener;
 char 	*clientid;

	//set_time(&(masterptr->ufsrv_time));
	SetConfigurationDefaults ();

	CheckCommandLine (argc, argv);

	SeedRandom (&(masterptr->ufsrv_time));
	masterptr->serverid = (int)GenerateRandomNumber()/10000;
	asprintf (&(masterptr->server_descriptive_name), "%s-%d-%d", masterptr->server_class, masterptr->serverid_by_user, masterptr->serverid);

	{
		asprintf(&clientid, "%s-%d", masterptr->server_class, masterptr->serverid_by_user);
		openlog(clientid, LOG_NDELAY, LOG_USER);

		//DO NOT free it is retained by openlog
		//free (clientid);
	}

	#include "version.c"
	syslog(LOG_INFO, "-:::::::::: ufsrvapi (%s) ::::::::::- {serverid:'%d', compiled: '%s', by: '%s'}", ufsrv_version, masterptr->serverid, t_compiled, u_compiled);

	ProcessConfigfile (NULL);

	masterptr->when = time(NULL);
	if (masterptr->server_cpu_affinity > 0)	SetCpuAffinity(masterptr->server_cpu_affinity);

	InitProtocols ();

 	InitSignals ();

 	if (masterptr->running_mode == RUNNING_MODE_DAEMON)  GoDaemon ();

 	masterptr->serverpid = getpid();
	sd_notifyf(0, "STATUS=Starting ufsrv instance '%s'…\n", masterptr->server_descriptive_name);

	{
		char *pid_file;
		asprintf(&pid_file, "%s/%s.pid", CONFIG_PID_DIR, masterptr->server_class);
		if ((MakePidFile(pid_file, masterptr->serverpid)) != 0) {
		 syslog(LOG_ERR, "%s: COULD NOT WRITE OUT PID FILE:'%s'", __func__, pid_file);
		}

	 free (pid_file);
	}

	s_ptr_console = SetupCommandConsole();

	//InitWorkersDelegator (masterptr->main_listener_protoid);//CreateSessionsDelegatorThread ();

	if (_PROTOCOL_CTL_MSGQUEUE_SUSCRIBER(protocols_registry_ptr, masterptr->main_listener_protoid)) {
		CreateMessageQueueSubscriberListenerThread ();
	}

	if (_PROTOCOL_CTL_MAIN_LISTENER_SEMANTICS(protocols_registry_ptr, masterptr->main_listener_protoid)) {
		if (_CONF_SERVER_RUNMODE(masterptr) != RUNMODE_SHADOW) {
			s_ptr_main_listener = InitMainListener(masterptr->main_listener_protoid);
			if (unlikely(IS_EMPTY(s_ptr_main_listener))) {
				syslog(LOG_ERR, "%s: COULD NOT INITIALISE MAINLISTENER", __func__);
				sd_notifyf(0, "STOPPING=1\n"
											"STATUS=Failed to start up Main Listener...\n");
				_exit(-1);
			}

			InvokeMainListener(masterptr->main_listener_protoid, s_ptr_main_listener, (ClientContextData *) s_ptr_console);
		} else {
			syslog(LOG_NOTICE, "%s: SHADOW_MODE ENABLED: MAIN LISTENING PORT IS CLOSED", __func__);
		}
	}

	//stay put in case there is no Main listener defined
	for (size_t i=0; i<sessions_delegator_ptr->setsize; i++) {
		pthread_join(sessions_delegator_ptr->session_worker_ths[i], NULL);
	}

 return 0; /*should never return*/

}

static void GoDaemon (void)
 {
		int pid;

    if (fork()) {
      fflush (stdin);
      fflush (stdout);
      fflush (stderr);

      _exit (0);
     }

    umask(0);

	if (setsid ()==-1) {
		syslog (LOG_ERR, "%s: ERROR: failed to become a session leader(errno=%d): EXITING...", __func__, errno);

		_exit (-1);
	}

	signal(SIGHUP, SIG_IGN);

	pid=fork();
	if (pid == -1) {
		syslog (LOG_ERR, "%s: ERROR: failed the second fork (errno=%d): EXITING...", __func__, errno);
		_exit (-1);
	} else if (pid != 0) {
		_exit(0);
	}

	if (chdir("/") < 0) {
		syslog (LOG_ERR, "%s: ERROR: failed to unmount inherited filesystem: EXITING...", __func__);
		_exit (-1);
	}

   freopen ("/dev/null", "r", stdin);  /* Yes! */
   freopen ("/dev/null", "w", stdout);
   freopen ("/dev/null", "w", stderr);

 }

static void Banner (void)
 {
   say ("*** usrv %s.\n", c_version);

 }

void SetConfigurationDefaults (void)
 {
		masterptr->serverid=0;
    if (!masterptr->log_mode)  			masterptr->log_mode=LOG_MODE_SYSLOG;
    if (!masterptr->running_mode)  	masterptr->running_mode=RUNNING_MODE_DAEMON;
    if (!*masterptr->config_dir)		mstrncpy(masterptr->config_dir, CONFIG_DIR, _POSIX_PATH_MAX);
    if (!*masterptr->config_file)		mstrncpy(masterptr->config_file, CONFIG_FILE_NAME, _POSIX_PATH_MAX);

 }

void Help (void)
 {
   printf (" 			 ufsrv [-h]\n"
           "             [-v]\n"
           "             [-f config_file]\n"
           "             [-c config_dir]\n"
           "             [-d 1|0]\n"
           " Default invocation parameters: -f nportredird.conf -c /etc/nportredird -d 1\n" 
          );

   _exit (1);

 }

void CheckCommandLine (int argc, char *argv[])
  {
  int i, 
      j=1,
      cnt=0;
  extern char *u_compiled,
              *t_compiled;

    if (argc==1) {
      /*SetConfigurationDefaults ();*/

      return;
     }
    
    for (i=1; i<argc; i++) {
      switch (argv[i][0])
       { 
        case '-':
          while ((j)&&(argv[i][j]))
		   {
			switch (argv[i][j])
			 {
			  case 'h':
			  case 'H':
			  case '?':
			  Help ();

			  case 'v':
			  case 'V':
			   fprintf (stdout,
	"nportredird %s (%s %s)\n"
	"Copyright (C) 1999-2001  Ayman Akt <ayman@pobox.com>\n\n"
	"nportredird is free software, covered by the GNU General Public License,\n"
	"and you are welcome to change it and/or distribute copies of it under\n"
	"certain conditions.\n"
	"There is absolutely no warranty for nportredird.\n\n",
				c_version, u_compiled, t_compiled);

			   _exit (1);

			  case 'd': /* -d 1|0 */
				 i++;
				 j--;
				if (argv[i])
				 {
				   if (atoi(argv[i]))  masterptr->running_mode=RUNNING_MODE_DAEMON;
				   else  masterptr->running_mode=RUNNING_MODE_TERM;
				 }
			  break;

			  case 'i': /* i xxxx integer */
				   i++;
				   j--;
				//if (i<argc)
				 {
					 masterptr->serverid_by_user=atoi(argv[i]);
					 //syslog (LOG_INFO, "Server id set to '%d' --> '%s'", masterptr->serverid, argv[i]);

				 }
				   break;


			  case 'c':
			   i++;
			   j--;
				if (argv[i])
				 {
				  mstrncpy (masterptr->config_dir, argv[i], MBUF);
				  syslog (LOG_INFO, "Configuration dir set to '%s'", masterptr->config_dir);
				 }
			   break;

			  case 'f':
			   i++;
			   j--;
				if (argv[i])
				 {
				  mstrncpy (masterptr->config_file, argv[i], MBUF);
				  syslog (LOG_INFO, "Configuration file set to '%s'", masterptr->config_file);
				 }
			   break;

			  case 's'://class of servers
			   i++;
			   j--;
				if (argv[i])
				 {
				  strncpy (masterptr->server_class, argv[i], MINIBUF-1);
				  syslog (LOG_INFO, "Server class name set set to '%s'", masterptr->server_class);
				 }
			   break;
			  default:
			   j--;
			   break;
			 }//inner switch
			j++;
			break;
		   }//while
         break;  

        default:
        	cnt++;
        	j=1;
			 switch (cnt)
			  {
			   case 1:
				break;

			   case 2:
				break;

			   default:
				break;
			  }
       }//switch
     } //for

 }

