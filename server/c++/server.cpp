/*
   collabREate server.cpp
   Copyright (C) 2012 Chris Eagle <cseagle at gmail d0t com>
   Copyright (C) 2012 Tim Vidas <tvidas at gmail d0t com>

   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the Free
   Software Foundation; either version 2 of the License, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
   FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
   more details.

   You should have received a copy of the GNU General Public License along with
   this program; if not, write to the Free Software Foundation, Inc., 59 Temple
   Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <err.h>
#include <errno.h>
#include <pthread.h>

#include "utils.h"
#include "db_support.h"
#include "mgr_helper.h"
#include "client.h"

#define ERROR_NO_USER "Failed to find user %s"
#define ERROR_NO_PRIVS "drop_privs failed!"
#define ERROR_BAD_GID "setgid current gid: %d target gid: %d\n"   
#define ERROR_BAD_UID "setuid current uid: %d target uid: %d\n"   
#define ERROR_SET_SIGCHLD "Unable to set SIGCHLD handler"

//change the following to the unprivileged user this
//service drops privs to
const char *svc_user = "collab";

map<string,string> *conf = NULL;

/*
 * This farms exit status from forked children to avoid
 * having any zombie processes lying around
 */
void sigchld(int sig) {
   int status;
//   while (waitpid(-1, &status, WNOHANG) > 0);
   while (wait4(-1, &status, WNOHANG, NULL) > 0) {
//      fprintf(stderr, "wait4 called\n");
   }
//   fprintf(stderr, "sigchld returning\n");
}

/*
 * Enter a threaded accept loop.  Create a new thread using the
 * client_callback function for each new client connection.  If 
 * the client thread crashes, the entire server crashes.
 */
void loop(NetworkService *svc) {
   //should choose between Basic and Database connection managers here
   DatabaseConnectionManager mgr(conf);
   mgr.start();
   //need to instantiate a ManagerHelper here as well
   ManagerHelper helper(&mgr, conf);
   helper.start();
   while (true) {
      NetworkIO *nio = svc->accept();
      if (nio) {
         mgr.add(nio);
      }   
   }
}

/*
 * Do the real work of dropping privileges.  Checks to
 * see what the current uid/gid are, sets res gid and
 * uid to the specified user's uid/gid and verifies
 * that privs can't be restored to the initial uid/gid
 */
int drop_privs(struct passwd *pw) {
   char *dir;
   int uid = getuid();
   int gid = getgid();
   int result = -1;
#if defined DO_CHROOT
   dir = "/";
   if (chroot(pw->pw_dir) == -1) {;
#ifdef DEBUG      
      perror("chroot");
      fprintf(stderr, "Failed chroot to %s", pw->pw_dir);
#endif
      return -1;
   }
#else
   dir = pw->pw_dir;
#endif
   initgroups(pw->pw_name, pw->pw_gid);
   if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) < 0) return -1;
   if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) < 0) return -1;
   if (pw->pw_gid != gid && (setgid(gid) != -1 || setegid(gid) != -1)) {
#ifdef DEBUG      
      printf(ERROR_BAD_GID, getgid(), pw->pw_gid);
#endif
      return -1;
   }
   if (pw->pw_uid != uid && (setuid(uid) != -1 || seteuid(uid) != -1)) {
#ifdef DEBUG      
      printf(ERROR_BAD_UID, getuid(), pw->pw_uid);
#endif
      return -1;
   }
   if (getgid() != pw->pw_gid || getegid() != pw->pw_gid) return -1;
   if (getuid() != pw->pw_uid || geteuid() != pw->pw_uid) return -1;

   if (chdir(dir) == -1) {;
#ifdef DEBUG      
      perror("chdir");
      fprintf(stderr, "Failed chdir to %s", dir);
#endif
      return -1;
   }
   return 0;
}

/*
 * Drop privileges to the specified user account
 */
int drop_privs_user(const char *user_name) {
   struct passwd *pw = getpwnam(user_name);
   if (pw == NULL) {
#ifdef DEBUG      
      err(-1, ERROR_NO_USER, user_name);
#else
      exit(-1);
#endif
   }
   if (drop_privs(pw) == -1) {
#ifdef DEBUG      
      err(-1, ERROR_NO_PRIVS);
#else
      exit(-1);
#endif
   }
   return 0;
}

void writePidFile() {
   string pidFile = getStringOption(conf, "PIDFILE", "/var/run/collab/collab.pid");
   FILE *f = fopen(pidFile.c_str(), "w");
   if (f == NULL) {
      //this is a problem
   }
   else {
      pid_t pid = getpid();
      fprintf(f, "%d", pid);
      fclose(f);
   }
}

/*
 * main function creates a socket, drops privileges
 * then calls a function to accept incoming connections in a loop.
 */
int main(int argc, char **argv, char **envp) {
   Tcp6Service *svc;
   srand(time(NULL));
   if (signal(SIGCHLD, sigchld) == SIG_ERR) {
#ifdef DEBUG      
      err(-1, ERROR_SET_SIGCHLD);
#else
      exit(-1);
#endif
   }
   int opt;
   while ((opt = getopt(argc, argv, "c:")) != -1) {
      switch (opt) {
         case 'c':
            conf = parseConf(optarg);
            break;
         default:
            break;
      }
   }
   short svc_port = getShortOption(conf, "SERVER_PORT", 5042);
   string svc_host = getStringOption(conf, "SERVER_HOST", "");
   try {
      if (svc_host.length() == 0) {
         svc = new Tcp6Service(svc_port);
      }
      else {
         svc = new Tcp6Service(svc_host.c_str(), svc_port);
      }
   } catch (int e) {
      exit(e);
   }
   drop_privs_user(svc_user);
   daemon(1, 0);
   writePidFile();
   loop(svc);
   return 0;
}

