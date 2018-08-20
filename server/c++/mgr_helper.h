/*
   collabREate mgr_helper.h
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

#ifndef __MANAGER_HELPER_H
#define __MANAGER_HELPER_H

#include <map>
#include <string>
#include <json-c/json.h>

#include "utils.h"
#include "client.h"
#include "mgr_helper.h"

using namespace std;

class ConnectionManagerBase;
class ManagerHelper;

typedef void (*MsgHandler)(json_object *obj, ManagerHelper *mh);

/**
 * ManagerHelper
 * This class is intented to facilitate getting current status information to
 * the ServerManager class.
 * @author Tim Vidas
 * @author Chris Eagle
 * @version 0.4.0, August 2012
 */

class ManagerHelper {
private:
   NetworkIO *nio;
   Tcp6Service *ss;
   json_object *conf;
   ConnectionManagerBase *cm;
   int pidForUpdates;
   static map<string,MsgHandler> *handlers;

public:
   /**
    * very similary to the other constructor, execpt config paramters are attempted
    * to be read from a properties object p
    * @param conn the connectionManager associated with this ManagerHelper
    * @param p a propertied object (config file)
    */
   ManagerHelper(ConnectionManagerBase *conn, json_object *conf);

   /**
    * instantiates a new ManagerHelper with default parameters, the ManagerHelper
    * facilitates getting server state information to the ServerManager
    * @param conn the connectionManager associated with this ManagerHelper
    */
   ManagerHelper(ConnectionManagerBase *conn);

   void shutdown();

private:
   void initCommon();

   /**
    * send_data constructs the packet and sends it to the ServerManager
    * @param command the server command to send
    * @param obj the data relevant to be sent with command
    */
   void send_data(const char *command, json_object *obj = NULL);

   /**
    * run kicks off a thread that perpetually waits for a single connection, if the connection is dropped
    * it waits again, once connected, the ManagerHelper processes commands similar to the server.
    */
   static void *run(void *arg);

   /**
    * closes the socket
    */
   void terminate();

   static void mng_get_connections(json_object *obj, ManagerHelper *mh);
   static void mng_get_stats(json_object *obj, ManagerHelper *mh);
   static void mng_shutdown(json_object *obj, ManagerHelper *mh);
   static void mng_project_migrate(json_object *obj, ManagerHelper *mh);
   static void mng_migrate_update(json_object *obj, ManagerHelper *mh);

   void init_handlers();

public:
   void start();

   bool done;
   bool quit;

};

#endif


