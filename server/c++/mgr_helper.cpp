/*
   collabREate mgr_helper.cpp
   Copyright (C) 2018 Chris Eagle <cseagle at gmail d0t com>
   Copyright (C) 2018 Tim Vidas <tvidas at gmail d0t com>

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

#include <string.h>
#include <map>
#include <string>
#include <pthread.h>

#include "utils.h"
#include "cli_mgr.h"
#include "client.h"
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

map<string,MsgHandler> *ManagerHelper::handlers;

/**
 * very similary to the other constructor, execpt config paramters are attempted
 * to be read from a properties object p
 * @param connm the connectionManager associated with this ManagerHelper
 * @param p a propertied object (config file)
 */
ManagerHelper::ManagerHelper(ConnectionManagerBase *conn, json_object *conf) {
   cm = conn;
   pidForUpdates = 0;
   this->conf = conf;
   initCommon();
}

/**
 * instantiates a new ManagerHelper with default parameters, the ManagerHelper
 * facilitates getting server state information to the ServerManager
 * @param connm the connectionManager associated with this ManagerHelper
 */
ManagerHelper::ManagerHelper(ConnectionManagerBase *conn) {
   cm = conn;
   conf = NULL;
   pidForUpdates = 0;
   initCommon();
}

void ManagerHelper::initCommon() {
   if (handlers == NULL) {
      init_handlers();
   }
   done = false;
   quit = false;
   bool localonly = DEFAULT_LOCAL;
   bool dbMode = false;
   int port = DEFAULT_PORT;
   const char *mgr_host = NULL;
   if (conf) {
      port = getIntOption(conf, "MANAGE_PORT", DEFAULT_PORT);
      localonly = getIntOption(conf, "MANAGE_LOCAL", 1) == 1;
      mgr_host = getCstringOption(conf, "MANAGE_HOST", NULL);
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
void ManagerHelper::send_data(const char *command, json_object *obj) {
   if (strncmp(command, "mng_", 4) == 0) {
      if (obj == NULL) {
         obj = json_object_new_object();
      }
      json_object_object_add_ex(obj, "type", json_object_new_string(command), JSON_NEW_CONST_KEY);

      nio->writeJson(obj);   //calls json_object_put
//      json_object_put(obj);
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
   while (!mh->done) {
      mh->nio = mh->ss->accept();
//         logln("New Management connection: " + s.getInetAddress().getHostAddress() + ":" + s.getPort(), LINFO);
      try {
         while (!mh->done) {
            json_object *obj = mh->nio->readJson();
            if (obj == NULL) {
               delete mh->nio;
               break;
            }
            const char *cmd = string_from_json(obj, "type");
            map<string,MsgHandler>::iterator i = handlers->find(cmd);
            if (i != handlers->end()) {
               MsgHandler h = i->second;
               (*h)(obj, mh);
            }
            else {
               mh->logln("unkown command", LERROR);
//The ServerManager has no means of processing this message as it is very much
//a synchronous protocol: Send Command -> Process Reply.  If we don't recognize
//their command we can easily drop it, but they are not likely to be looking
//for our reply
//                        json_object *resp = json_object_new_object();
//                        append_json_string_val(resp, "error", ("bad command received:" + string(cmd)).c_str());
//                        mh->send_data(MNG_CONNECTIONS, resp);
            }
            json_object_put(obj);
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

void ManagerHelper::init_handlers() {
   handlers = new map<string,MsgHandler>;
   (*handlers)["mng_get_connections"] = mng_get_connections;
   (*handlers)["mng_get_stats"] = mng_get_stats;
   (*handlers)["mng_shutdown"] = mng_shutdown;
   (*handlers)["mng_project_migrate"] = mng_project_migrate;
   (*handlers)["mng_migrate_update"] = mng_migrate_update;
}

void ManagerHelper::mng_get_connections(json_object *obj, ManagerHelper *mh) {
   mh->logln("sending connections", LINFO3);
   string c = mh->cm->listConnections();
   json_object *out = json_object_new_object();
   json_object_object_add_ex(out, "connections", json_object_new_string(c.c_str()), JSON_NEW_CONST_KEY);
   mh->send_data(MNG_CONNECTIONS, out);
}

void ManagerHelper::mng_get_stats(json_object *obj, ManagerHelper *mh) {
   mh->logln("sending stats", LINFO3);
   string c = mh->cm->dumpStats();
   json_object *out = json_object_new_object();
   json_object_object_add_ex(out, "stats", json_object_new_string(c.c_str()), JSON_NEW_CONST_KEY);
   mh->send_data(MNG_STATS, out);
}

void ManagerHelper::shutdown() {
   done = true;
   logln("client requested server shutdown", LINFO);
   cm->Shutdown();
   delete cm;
   cm = NULL;
   delete nio;
   quit = true;
   exit(0);
}

void ManagerHelper::mng_shutdown(json_object *obj, ManagerHelper *mh) {
   mh->shutdown();
}

void ManagerHelper::mng_project_migrate(json_object *obj, ManagerHelper *mh) {
   mh->logln("client requested a project migrate", LINFO);
   int status = MNG_MIGRATE_REPLY_FAIL;
   
   const char *uid = string_from_json(obj, "newowner");
   const char *gpid = string_from_json(obj, "gpid");
   const char *hash = string_from_json(obj, "hash");
   const char *desc = string_from_json(obj, "description");
   uint64_t pub, sub;
   uint64_from_json(obj, "publish", &pub);
   uint64_from_json(obj, "subscribe", &sub);

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
   json_object *resp = json_object_new_object();
   append_json_int32_val(resp, "status", status);
   mh->send_data(MNG_PROJECT_MIGRATE_REPLY, resp);
}

void ManagerHelper::mng_migrate_update(json_object *obj, ManagerHelper *mh) {
   mh->logln("in MNG_MIGRATE_UPDATE", LERROR);
   const char *uid = string_from_json(obj, "newowner");
   const char *inner_json = string_from_json(obj, "update");
   json_object *inner = json_tokener_parse(inner_json);
   const char *cmd = string_from_json(inner, "type");
   mh->logln("... got data", LERROR);
   mh->cm->migrateUpdate(uid, mh->pidForUpdates, cmd, inner);
   json_object_put(inner);
}
