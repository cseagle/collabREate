/*
   collabREate server_mgr.h
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

#ifndef __SERVER_MGR_H
#define __SERVER_MGR_H

#include <string>
#include <vector>
#include <sys/stat.h>
#include <ctype.h>
#include <libpq-fe.h>
#include <json-c/json.h>
#include "client.h"
#include "utils.h"

using namespace std;

class ProjectInfo;

/**
 * ServerManager
 * This class is responsible for routine server related operations
 * @author Tim Vidas
 * @author Chris Eagle
 * @version 0.4.0, August 2012
 */

class ServerManager {
private:
   bool done;
   json_object *config;
   PGconn *dbConn;
   int port;
   string host;

   NetworkIO *s;
   int mode;

   vector<ProjectInfo*> plist;

public:
   ServerManager(json_object *p);

private:

   /**
    * deleteProject deletes a local project
    * @param pid the local project id to delete
    */
   void deleteProject(int pid);

   /**
    * addUsers adds a user to this server
    * @param username the username to add
    * @param password the password for the user (hashed)
    * @param pub the publish permission bitmask
    * @param sub the subscribe permission bitmask
    * @return the userid of the added user, -1 on error
    */
   int addUser(string username, string password, uint64_t pub, uint64_t sub);

   /**
    * updateUser updates a user on this server
    * @param username the username to update
    * @param password the password for the user (hashed)
    * @param pub the publish permission bitmask
    * @param sub the subscribe permission bitmask
    * @param uid the userid of the record to apply the other values to
    * @return the userid of the added user, -1 on error
    */
   int updateUser(string username, string password, uint64_t pub, uint64_t sub, int uid);

   /**
    * terminate terminates the server manager
    */
   void terminate();

   /**
    * connectToHelper connects to the managerHelper on the server on MANAGE_PORT,
    * by default this must be a local connection.
    */
   void connectToHelper();
   
   void initQueries();
   
   /**
    * similar to post in Client, but does not check subscription status, and takes command as a arg
    * This function should ONLY be called for message id >= MNG_CONTROL_FIRST
    * because these messages do not contain an updateid and send only management data
    * @param command the command to send
    * @param data the data associated with the command
    */
   void send_data(const char *command, json_object *obj = NULL);

   /**
    * dumpStats dumps rx/tx stats for this server
    * this requires ServerHelper to be running
    */

   void dumpStats();

   /**
    * shutdownServer sends a request to the server to shutdown the server nicely
    * this requires ServerHelper to be running
    */

   void shutdownServer();

   /**
    * getProjectInfo gets project information for a previously listed project
    * @param lpid the local PID for the project to get info on
    * @param pinfo a project info object to populate with information
    * @return 0 on success
    */
   int getProjectInfo(int lpid, ProjectInfo *pinfo);

   /**
    * exportProject exports a project to a binary final
    * @param lpid the local PID for the project to export
    * @param efile the filename to export to
    * @return 0 on success
    */
   int exportProject(int lpid, const char *efile);

   /**
    * importProject imports a project from a binary final
    * @param ifile the file descriptor to import from
    * @param newowner the local uid to be the owner of the new project
    */
   int importProject(int ifile, const char *newowner);

   /**
    * getconfig is an inspector that gets the current operation mode of the connection manager
    * @return a Properites object
    */
   json_object *getConfig();

   /**
    * getMode is an inspector that gets the current operation mode of the connection manager
    * @return the mode
    */
   int getMode();

   /**
    * listConnections lists the current connections to this server
    * this requires ServerHelper to be running
    */
   void listConnections();

   /**
    * listUsers lists the users on this server
    */
   void listUsers();

   /**
    * listProjects lists the projects on this server
    */
   void listProjects();

   /**
    * closeDB closes all the database queries and the database connection
    */
   void closeDB();

   string getPermHeaderString( int colWidth);
   
   string getPermHeaderString(int colWidth, bool number);

   string getPermRowString(uint64_t p, uint64_t s, int colWidth);

public:
   /**
    * exec provides the cli interface for managing collabreate
    */
   static void exec(int argc, char **argv);
};

#endif
