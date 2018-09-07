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
#include "proj_info.h"
#include "mgr_helper.h"
#include "basic_mgr.h"

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
ManagerHelper::ManagerHelper(ConnectionManager *conn, json_object *conf) {
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
ManagerHelper::ManagerHelper(ConnectionManager *conn) {
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
//         log(LDEBUG, "send_data- cmd: %s\n", command);
   }
   else {
//      log(LERROR, "post should be used for command %s, not send_data.  Data not sent.", command);
   }
}

/**
 * run kicks off a thread that perpetually waits for a single connection, if the connection is dropped
 * it waits again, once connected, the ManagerHelper processes commands similar to the server.
 */
void *ManagerHelper::run(void *arg) {
   ManagerHelper *mh = (ManagerHelper*)arg;
   log(LINFO, "ManagerHelper running...\n");
   //just accept a single connection, loop back if the connection drops
   while (!mh->done) {
      mh->nio = mh->ss->accept();
//      log(LINFO, "New Management connection: %s:%u\n", s.getInetAddress().getHostAddress(), s.getPort());
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
               log(LERROR, "unkown command\n");
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
   return NULL;
}

/**
 * closes the socket
 */
void ManagerHelper::terminate() {
   ss->close();
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
   (*handlers)[MNG_GET_CONNECTIONS] = mng_get_connections;
   (*handlers)[MNG_GET_STATS] = mng_get_stats;
   (*handlers)[MNG_SHUTDOWN] = mng_shutdown;
   (*handlers)[MNG_PROJECT_IMPORT] = mng_project_import;
   (*handlers)[MNG_IMPORT_UPDATE] = mng_import_update;
   (*handlers)[MNG_PROJECT_LIST] = mng_project_list;
   (*handlers)[MNG_PROJECT_EXPORT] = mng_project_export;
}

void ManagerHelper::mng_get_connections(json_object *obj, ManagerHelper *mh) {
   log(LINFO3, "sending connections");
   string c = mh->cm->listConnections();
   json_object *out = json_object_new_object();
   json_object_object_add_ex(out, "connections", json_object_new_string(c.c_str()), JSON_NEW_CONST_KEY);
   mh->send_data(MNG_CONNECTIONS, out);
}

void ManagerHelper::mng_get_stats(json_object *obj, ManagerHelper *mh) {
   log(LINFO3, "sending stats\n");
   string c = mh->cm->dumpStats();
   json_object *out = json_object_new_object();
   json_object_object_add_ex(out, "stats", json_object_new_string(c.c_str()), JSON_NEW_CONST_KEY);
   mh->send_data(MNG_STATS, out);
}

void ManagerHelper::shutdown() {
   done = true;
   log(LINFO, "client requested server shutdown\n");
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

void ManagerHelper::mng_project_import(json_object *obj, ManagerHelper *mh) {
   log(LINFO, "client requested a project migrate\n");
   int status = MNG_MIGRATE_REPLY_FAIL;

   const char *uid = string_from_json(obj, "newowner");
   const char *gpid = string_from_json(obj, "gpid");
   const char *hash = string_from_json(obj, "hash");
   const char *desc = string_from_json(obj, "description");
   uint64_t pub, sub;
   uint64_from_json(obj, "publish", &pub);
   uint64_from_json(obj, "subscribe", &sub);

   int newpid = mh->cm->importProject(uid, gpid, hash, desc, pub, sub);
   if (newpid > 0) {
//      log(LINFO4, "Added new project %d via project migration from another server\n", newpid);
      status = MNG_MIGRATE_REPLY_SUCCESS;
      mh->pidForUpdates = newpid;  //store globally for any updates that may come in
   }
   else {
//      log("migrate project failed for gpid %s hash %s\n", gpid, hash);
      status = MNG_MIGRATE_REPLY_FAIL;
   }
   json_object *resp = json_object_new_object();
   append_json_int32_val(resp, "status", status);
   mh->send_data(MNG_PROJECT_IMPORT_REPLY, resp);
}

void ManagerHelper::mng_import_update(json_object *obj, ManagerHelper *mh) {
/*
   log(LDEBUG, "in MNG_IMPORT_UPDATE\n");
   const char *uid = string_from_json(obj, "newowner");
   const char *inner_json = string_from_json(obj, "update");
   json_object *inner = json_tokener_parse(inner_json);
   const char *cmd = string_from_json(inner, "type");
   log(LDEBUG, "... got data\n");
   mh->cm->importUpdate(uid, mh->pidForUpdates, cmd, inner);
   json_object_put(inner);
*/
   log(LDEBUG, "in MNG_IMPORT_UPDATE\n");
   const char *uid = strdup(string_from_json(obj, "newowner"));
   json_object_object_del(obj, "newowner");
   const char *cmd = string_from_json(obj, "utype");
   json_object_object_add_ex(obj, "type", json_object_new_string(cmd), JSON_C_OBJECT_KEY_IS_CONSTANT);
   json_object_object_del(obj, "utype");
   cmd = string_from_json(obj, "type");
   json_object_object_add_ex(obj, "pid", json_object_new_int64(mh->pidForUpdates), JSON_C_OBJECT_KEY_IS_CONSTANT);

   log(LDEBUG, "... got data\n");
   mh->cm->importUpdate(uid, mh->pidForUpdates, cmd, obj);
   free((void*)uid);
}

void ManagerHelper::mng_project_list(json_object *obj, ManagerHelper *mh) {
   json_object *list = json_object_new_array();
   vector<ProjectInfo*> *all = mh->cm->getAllProjects();
   if (all) {
      map<string,vector<ProjectInfo*>*>::iterator pi;
      for (vector<ProjectInfo*>::iterator vi = all->begin(); vi != all->end(); vi++) {
         ProjectInfo *p = *vi;
         json_object *proj = json_object_new_object();
         append_json_string_val(proj, "description", p->desc);
         append_json_string_val(proj, "hash", p->hash);
         append_json_uint32_val(proj, "pid", p->lpid);
         append_json_string_val(proj, "gpid", p->gpid);
         append_json_uint64_val(proj, "pub", p->pub);
         append_json_uint64_val(proj, "sub", p->sub);
         json_object_array_add(list, proj);
      }
   }
   json_object *projects = json_object_new_object();
   json_object_object_add_ex(projects, "projects", list, JSON_NEW_CONST_KEY);
   mh->send_data(MNG_PROJECT_LIST_REPLY, projects);
   delete all;
}

void ManagerHelper::mng_project_export(json_object *obj, ManagerHelper *mh) {
   uint32_t pid;
   json_object *reply = json_object_new_object();
   if (uint32_from_json(obj, "pid", &pid)) {
      json_object *updates = mh->cm->exportProject(pid);
      json_object_object_add_ex(reply, "updates", updates, JSON_NEW_CONST_KEY);
      mh->send_data(MNG_EXPORT_UPDATES, reply);
   }
   else {
      append_json_string_val(reply, "msg", "Missing pid in project export request");
      mh->send_data(MSG_ERROR, reply);
   }
}
