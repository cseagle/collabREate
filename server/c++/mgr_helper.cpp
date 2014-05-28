/*
   collabREate mgr_helper.cpp
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

#include <map>
#include <string>
#include <pthread.h>

#include "utils.h"
#include "cli_mgr.h"
#include "client.h"
#include "buffer.h"
#include "mgr_helper.h"

using namespace std;

/**
 * ManagerHelper
 * This class is intented to facilitate getting current status information to
 * the ServerManager class.
 * @author Tim Vidas
 * @author Chris Eagle
 * @version 0.4.0, August 2012
 */

#define DEFAULT_PORT 5043
#define DEFAULT_LOCAL true

/**
 * very similary to the other constructor, execpt config paramters are attempted
 * to be read from a properties object p
 * @param connm the connectionManager associated with this ManagerHelper
 * @param p a propertied object (config file)
 */
ManagerHelper::ManagerHelper(ConnectionManagerBase *connm, map<string,string> *p) {
   cm = connm;
   pidForUpdates = 0;
   props = p;
   initCommon();
}

/**
 * instantiates a new ManagerHelper with default parameters, the ManagerHelper
 * facilitates getting server state information to the ServerManager
 * @param connm the connectionManager associated with this ManagerHelper
 */
ManagerHelper::ManagerHelper(ConnectionManagerBase *connm) {
   cm = connm;
   props = NULL;
   pidForUpdates = 0;
   initCommon();
}

void ManagerHelper::initCommon() {
   bool localonly = DEFAULT_LOCAL;
   bool dbMode = false;
   int port = DEFAULT_PORT;
   const char *mgr_host = NULL;
   if (props) {
      port = getIntOption(props, "MANAGE_PORT", DEFAULT_PORT);
      localonly = getIntOption(props, "MANAGE_LOCAL", 1) == 1;
      mgr_host = getCharOption(props, "MANAGE_HOST", NULL);
   }
   if (localonly) {
      ss = new Tcp6Service("localhost", port);
   }
   else if (mgr_host == NULL) {
      ss = new Tcp6Service(port);
   }
   else {
      ss = new Tcp6Service(mgr_host, port);
   }      
}

/**
 * send_data constructs the packet and sends it to the ServerManager
 * @param command the server command to send
 * @param data the data relevant to be sent with command
 */
void ManagerHelper::send_data(int command, uint8_t *data, int dlen) {
   if (command >= MNG_CONTROL_FIRST) {
      nio->writeInt(8 + dlen);
      nio->writeInt(command);
      nio->write(data, dlen);
//         logln("send_data- cmd: " + command + " datasize: " + data.length, LDEBUG);
   }
   else {
//         logln("post should be used for command " + command + ", not send_data.  Data not sent.", LERROR);
   }
}

/**
 * run kicks off a thread that perpetually waits for a single connection, if the connection is dropped
 * it waits again, once connected, the ManagerHelper processes commands similar to the server.
 */
void *ManagerHelper::run(void *arg) {
   ManagerHelper *mh = (ManagerHelper*)arg;
   mh->logln("ManagerHelper running...", LINFO);
   //just accept a single connection, loop back if the connection drops
   while (true) {
      mh->nio = mh->ss->accept();
//         logln("New Management connection: " + s.getInetAddress().getHostAddress() + ":" + s.getPort(), LINFO);
      try {
         while (true) {
            Buffer os;
            int len = mh->nio->readInt();
            int cmd = mh->nio->readInt();

            switch(cmd) {
               case MNG_GET_CONNECTIONS: {
                  mh->logln("sending connections", LINFO3);
                  string c = mh->cm->listConnections();
                  os.writeUTF(c.c_str());
                  mh->send_data(MNG_CONNECTIONS, os.get_buf(), os.size());
                  break;
               }
               case MNG_GET_STATS: {
                  mh->logln("sending stats", LINFO3);
                  string c = mh->cm->dumpStats();
                  os.writeUTF(c.c_str());
                  mh->send_data(MNG_STATS, os.get_buf(), os.size());
                  break;
               }
               case MNG_SHUTDOWN: {
                  mh->logln("client requested server shutdown", LINFO);
                  mh->cm->Shutdown();
                  break;
               }
               case MNG_PROJECT_MIGRATE: {
                  mh->logln("client requested a project migrate", LINFO);
                  //Client c = new Client(cm,new Socket());
                  uint8_t md5_bytes[MD5_SIZE];
                  uint8_t gpid_bytes[GPID_SIZE];
                  int status = MNG_MIGRATE_REPLY_FAIL;
                  int uid = mh->nio->readInt();
                  mh->nio->readFully(gpid_bytes, GPID_SIZE);
                  string gpid = toHexString(gpid_bytes, GPID_SIZE);
                  mh->nio->readFully(md5_bytes, MD5_SIZE);
                  string hash = toHexString(md5_bytes, MD5_SIZE);
                  string desc = mh->nio->readUTF();
                  uint64_t pub = mh->nio->readLong() & 0x7FFFFFFF;
                  uint64_t sub = mh->nio->readLong() & 0x7FFFFFFF;

                  int newpid = mh->cm->migrateProject(uid, gpid, hash, desc, pub, sub);
                  if (newpid > 0) {
//                        logln("Added new project " + newpid + " via project migration from another server");
                     status = MNG_MIGRATE_REPLY_SUCCESS;
                     mh->pidForUpdates = newpid;  //store globally for any updates that may come in
                  }
                  else {
//                        logln("migrate project failed for gpid " + gpid + " hash " + hash);
                     status = MNG_MIGRATE_REPLY_FAIL;
                  }
                  os.writeInt(status);
                  mh->send_data(MNG_PROJECT_MIGRATE_REPLY, os.get_buf(), os.size());
                  break;
               }
               case MNG_MIGRATE_UPDATE: {
                  mh->logln("in MNG_MIGRATE_UPDATE", LERROR);
                  int uid = mh->nio->readInt();
//                     logln("... got uid" + uid, LERROR);
                  int pid = mh->nio->readInt();
//                     logln("... got pid" + pid, LERROR);
                  int ucmd = mh->nio->readInt();
//                     logln("... got cmd" + ucmd, LERROR);
                  int datalen = mh->nio->readInt();
//                     logln("... got datalen" + datalen, LERROR);
                  uint8_t *data = new uint8_t[datalen];
                  mh->nio->readFully(data, datalen);
                  mh->logln("... got data", LERROR);
                  mh->cm->migrateUpdate(uid, mh->pidForUpdates, ucmd, data, datalen);
                  delete [] data;
                  break;
               }
               default: {
                  mh->logln("unkown command", LERROR);
//The ServerManager has no means of processing this message as it is very much
//a synchronous protocol: Send Command -> Process Reply.  If we don't recognize
//their command we can easily drop it, but they are not likely to be looking
//for our reply
//                        os.writeUTF("bad command received:" + cmd);
//                        mh->send_data(MNG_CONNECTIONS, os.get_buf(), os.size());
               }
            }
         }
      } catch (IOException ex) {
         mh->nio->close();
      }
   }
}

/**
 * closes the socket
 */
void ManagerHelper::terminate() {
   ss->close();
}

/**
 * logs a message to the configured log file (in the ConnectionManager)
 * @param msg the string to log
 * @param v apply a verbosity level to the msg
 */
void ManagerHelper::log(const string &msg, int v) {
   cm->log("[MNG]" +  msg, v);
}

/**
 * logs a message using log() (with newline)
 * @param msg the string to log
 * @param v apply a verbosity level to the msg
 */
void ManagerHelper::logln(const string &msg, int v) {
   log(msg + "\n", v);
}

void ManagerHelper::start() {
   pthread_attr_t attr;
   pthread_attr_init(&attr);
   pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
   pthread_t tid;
   pthread_create(&tid, &attr, run, (void*)this);
}

