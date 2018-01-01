/*
   collabREate server_mgr.cpp
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
#include <vector>
#include <sys/stat.h>
#include <ctype.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <inttypes.h>
#include <json.h>
#include "client.h"
#include "utils.h"
#include "proj_info.h"
#include "server_mgr.h"

using namespace std;

/**
 * ServerManager
 * This class is responsible for routine server related operations
 * @author Tim Vidas
 * @author Chris Eagle
 * @version 0.4.0, August 2012
 */

#define DEFAULT_PORT 5043
#define DEFAULT_HOST "localhost"

char *readLine(char *buf, int sz) {
   if (fgets(buf, sz, stdin) == NULL) {
      return NULL;
   }
   char *ptr = strchr(buf, '\r');
   if (ptr) *ptr = 0;
   ptr = strchr(buf, '\n');
   if (ptr) *ptr = 0;
   return buf; 
}

/**
 * askyn requires the user to enter yes or no
 * @return true for yes, false for no
 */
bool askyn() {
   char resp[64];
   *resp = 0;
   if (readLine(resp, sizeof(resp)) == NULL) {
      return false;
   }
   while (strcmp(resp, "yes") && strcmp(resp, "no")) {
      printf("(yes/no) ? ");
      if (readLine(resp, sizeof(resp)) == NULL) {
         break;
      }
   }
   return strcmp(resp, "yes") == 0;
}

ServerManager::ServerManager(json_object *p) {
   done = false;
   config = p;
   dbConn = NULL;
   port = getShortOption(config, "MANAGE_PORT", 5043);
   host = getStringOption(config, "MANAGE_HOST", DEFAULT_HOST);
   mode = getStringOption(config, "SERVER_MODE", "basic") == "database" ? MODE_DB : MODE_BASIC;
   if (mode == MODE_DB) {
      map<string,string> dbkeys;

      string dbHost = getStringOption(config, "DB_HOST", "");
      if (dbHost.length() > 0) {
         dbkeys["hostaddr"] = dbHost; 
      }
      string dbName = getStringOption(config, "DB_NAME", "");
      if (dbName.length() > 0) {
         dbkeys["dbname"] = dbName; 
      }
      string dbUser = getStringOption(config, "DB_USER", "");
      if (dbUser.length() > 0) {
         dbkeys["user"] = dbUser; 
      }
      string dbPass = getStringOption(config, "DB_PASS", "");
      if (dbPass.length() > 0) {
         dbkeys["password"] = dbPass; 
      }
      
      char const **keywords = new char const *[dbkeys.size() + 1];
      char const **values = new char const *[dbkeys.size() + 1];
      int idx = 0;
      for (map<string,string>::iterator i = dbkeys.begin(); i != dbkeys.end(); i++, idx++) {
         fprintf(stderr, "%s:%s\n", (*i).first.c_str(), (*i).second.c_str());
         keywords[idx] = (*i).first.c_str();
         values[idx] = (*i).second.c_str();
         fprintf(stderr, "%s:%s\n", (*i).first.c_str(), (*i).second.c_str());
      }
      keywords[idx] = values[idx] = NULL;
      dbConn = PQconnectdbParams(keywords, values, 0);

      /* Check to see that the backend connection was successfully made */
      if (PQstatus(dbConn) != CONNECTION_OK) {
         fprintf(stderr, "Connection to database failed: %s\n", PQerrorMessage(dbConn));
         PQfinish(dbConn);
         dbConn = NULL;
         mode = MODE_BASIC;
      }
      else {
         printf("Database connected.\n");
         initQueries();
      }
      delete [] keywords;
      delete [] values;
   }
   else {
      fprintf(stderr, "Starting in BASIC mode\n");
   }
   s = NULL;
   connectToHelper();
}

/**
 * deleteProject deletes a local project
 * @param pid the local project id to delete
 */
void ServerManager::deleteProject(int pid) {
   if (mode == MODE_DB) {
      static const int plens[1] = {4};
      static const int pformats[1] = {1};
      //insert into files values(stream_id, fname);
      const char * const parms[1] = {(char*)&pid};
      pid = htonl(pid);
      PGresult *rset = PQexecPrepared(dbConn, "deleteUpdatesByPID",
                          1, //int nParams,   size of arrays that follow
                          parms, //parms,  //const char * const *paramValues, array of string values
                          plens, //const int *paramLengths,
                          pformats, //const int *paramFormats,
                          1); //int resultFormat); 0 == text, 1 == binary
   
      ExecStatusType qres = PQresultStatus(rset);
      if (qres != PGRES_COMMAND_OK) {
         fprintf(stderr, "deleteUpdatesByPID: %s\n", PQerrorMessage(dbConn));
      }
      PQclear(rset);
      rset = PQexecPrepared(dbConn, "deleteProjectByPID",
                          1, //int nParams,   size of arrays that follow
                          parms, //parms,  //const char * const *paramValues, array of string values
                          plens, //const int *paramLengths,
                          pformats, //const int *paramFormats,
                          1); //int resultFormat); 0 == text, 1 == binary
   
      qres = PQresultStatus(rset);
      if (qres != PGRES_COMMAND_OK) {
         fprintf(stderr, "deleteProjectByPID: %s\n", PQerrorMessage(dbConn));
      }
      PQclear(rset);
   }
   else {
      fprintf(stderr, "it appears that the server is configured for BASIC mode\n");
   }
}

/**
 * addUsers adds a user to this server
 * @param username the username to add
 * @param password the password for the user (hashed)
 * @param pub the publish permission bitmask
 * @param sub the subscribe permission bitmask
 * @return the userid of the added user, -1 on error
 */
int ServerManager::addUser(string username, string password, uint64_t pub, uint64_t sub) {
   int rval = -1;
   if (mode == MODE_DB) {
      static int plens[4] = {0, 0, 8, 8};
      static const int pformats[4] = {0, 0, 1, 1};
   
      pub = htonll(pub);
      sub = htonll(sub);
      const char * const parms[4] = {username.c_str(), password.c_str(), (char*)&pub, (char*)&sub};
   
      PGresult *rset = PQexecPrepared(dbConn, "addUser",
                          4, //int nParams,   size of arrays that follow
                          parms, //parms,  //const char * const *paramValues, array of string values
                          plens, //const int *paramLengths,
                          pformats, //const int *paramFormats,
                          1); //int resultFormat); 0 == text, 1 == binary
      ExecStatusType qres = PQresultStatus(rset);
      if (qres != PGRES_TUPLES_OK && qres != PGRES_COMMAND_OK) {
         fprintf(stderr, "Error Adding user %s: %s\n", username.c_str(), PQerrorMessage(dbConn));
      }
      else {
         rval = ntohl(*(int*)PQgetvalue(rset, 0, 0));
      }
   }
   else {
      fprintf(stderr, "it appears that the server is configured for BASIC mode\n");
   }
   return rval;
}

/**
 * updateUser updates a user on this server
 * @param username the username to update
 * @param password the password for the user (hashed)
 * @param pub the publish permission bitmask
 * @param sub the subscribe permission bitmask
 * @param uid the userid of the record to apply the other values to
 * @return the userid of the added user, -1 on error
 */
int ServerManager::updateUser(string username, string password, uint64_t pub, uint64_t sub, int uid) {
   int rval = -1;
   if (mode == MODE_DB) {
      static const int plens[5] = {0, 0, 8, 8, 4};
      static const int pformats[5] = {0, 0, 1, 1, 1};
   
      pub = htonll(pub);
      sub = htonll(sub);
      uid = htonl(uid);
      const char * const parms[5] = {username.c_str(), password.c_str(), (char*)&pub, (char*)&sub, (char*)&uid};

      PGresult *rset = PQexecPrepared(dbConn, "updateUser",
                          5, //int nParams,   size of arrays that follow
                          parms, //parms,  //const char * const *paramValues, array of string values
                          plens, //const int *paramLengths,
                          pformats, //const int *paramFormats,
                          1); //int resultFormat); 0 == text, 1 == binary
      ExecStatusType qres = PQresultStatus(rset);
      if (qres != PGRES_TUPLES_OK && qres != PGRES_COMMAND_OK) {
         fprintf(stderr, "Error updating uid %d: %s\n", uid, PQerrorMessage(dbConn));
      }
      else {
         rval = ntohl(*(int*)PQgetvalue(rset, 0, 0));
      }
   }
   else {
      fprintf(stderr, "it appears that the server is configured for BASIC mode\n");
   }
   return rval;
}


/**
 * parsePerms attempts to interpret decimal and hex content as collabREate permissions
 * @param s the string to interpret
 * @param def the default permissions
 * @return the parsed permissions or def
 */
uint64_t parsePerms(const char *perms, uint64_t def) {
   uint64_t rval;
   char *endval;
   rval = strtoull(perms, &endval, 0);
   if (*endval || endval == perms) {
      rval = strtoull(perms, &endval, 16);
      if (*endval || endval == perms) {
         rval = def;
      }
   }
   return rval;
}

/**
 * terminate terminates the server manager
 */
void ServerManager::terminate() {
   printf("ServerManager terminating\n");
   done = true;
   closeDB();
   s->close();
   json_object_put(config);
}

/**
 * connectToHelper connects to the managerHelper on the server on MANAGE_PORT,
 * by default this must be a local connection.
 */
void ServerManager::connectToHelper() {
   if (s != NULL) {
      s->close();
   }
   try {
      //s = new Socket("127.0.0.1",port);
      //s = new Socket("localhost",port);
      s = new NetworkIO(host.c_str(), port);
      printf("Connection to ManagerHelper established. Ready to process commands\n");
   //} catch (UnknownHostException e) {
   } catch (IOException e) {
      fprintf(stderr, "Couldn't connect to ManagerHelper on %s:%d, is the server running?", host.c_str(), port);
   }
}

void ServerManager::initQueries() {
   if (mode == MODE_DB) {
      PGresult *res = PQprepare(dbConn, "listUsers", 
                          "select userid,username,pub,sub from users order by userid asc;",
                          0, NULL);
      if (PQresultStatus(res) != PGRES_COMMAND_OK) {
         fprintf(stderr, "listUsers: %s\n", PQerrorMessage(dbConn));
      }
      PQclear(res);
      res = PQprepare(dbConn, "listProjects", 
                      "select p.pid,p.gpid,p.hash,p.pub,p.sub,f.parent,p.description,q.description,p.snapupdateid from projects p left join (forklist f left join projects q on f.parent=q.pid) on p.pid = f.child order by p.pid asc;",
                      0, NULL);
      if (PQresultStatus(res) != PGRES_COMMAND_OK) {
         fprintf(stderr, "listProjects: %s\n", PQerrorMessage(dbConn));
      }
      PQclear(res);
      res = PQprepare(dbConn, "findUserByUID", 
                      "select username,pwhash,pub,sub from users where userid=$1",
                      0, NULL);
      if (PQresultStatus(res) != PGRES_COMMAND_OK) {
         fprintf(stderr, "findUserByUID: %s\n", PQerrorMessage(dbConn));
      }
      PQclear(res);
      res = PQprepare(dbConn, "getAllUpdates", 
                      "select updateid,username,pid,json,created from updates where pid=$1 order by updateid asc",
                      0, NULL);
      if (PQresultStatus(res) != PGRES_COMMAND_OK) {
         fprintf(stderr, "getAllUpdates: %s\n", PQerrorMessage(dbConn));
      }
      PQclear(res);
      res = PQprepare(dbConn, "deleteUpdatesByPID", 
                      "delete from updates where pid=$1",
                      0, NULL);
      if (PQresultStatus(res) != PGRES_COMMAND_OK) {
         fprintf(stderr, "deleteUpdatesByPID: %s\n", PQerrorMessage(dbConn));
      }
      PQclear(res);
      res = PQprepare(dbConn, "deleteProjectByPID", 
                      "delete from projects where pid=$1",
                      0, NULL);
      if (PQresultStatus(res) != PGRES_COMMAND_OK) {
         fprintf(stderr, "deleteProjectByPID: %s\n", PQerrorMessage(dbConn));
      }
      PQclear(res);
      res = PQprepare(dbConn, "addUser", 
                      "insert into users (username,pwhash,pub,sub) values ($1,$2,$3,$4) returning userid;",
                      0, NULL);
      if (PQresultStatus(res) != PGRES_COMMAND_OK) {
         fprintf(stderr, "addUser: %s\n", PQerrorMessage(dbConn));
      }
      PQclear(res);
      res = PQprepare(dbConn, "updateUser", 
                      "update users set username=$1,pwhash=$2,pub=$3,sub=$4 where userid=$5 returning userid;",
                      0, NULL);
      if (PQresultStatus(res) != PGRES_COMMAND_OK) {
         fprintf(stderr, "updateUser: %s\n", PQerrorMessage(dbConn));
      }
      PQclear(res);
   }
}


/**
 * similar to post in Client, but does not check subscription status, and takes command as an arg
 * This function should ONLY be called for message id >= MNG_CONTROL_FIRST
 * because these messages do not contain an updateid and send only management data
 * @param command the command to send
 * @param data the data associated with the command
 */
void ServerManager::send_data(const char *command, json_object *obj) {
   try {
      if (strncmp(command, "mng_", 4) == 0) {
         if (obj == NULL) {
            obj = json_object_new_object();
         }
         json_object_object_add_ex(obj, "type", json_object_new_string(command), JSON_NEW_CONST_KEY);

         s->writeJson(obj);   //this will call json_object_put
         //fprintf(stderr, "send_data- cmd: " + command + " datasize: " + data.length);
//         json_object_put(obj);
      }
      else {
         fprintf(stderr, "post should be used for command %s, not send_data.  Data not sent.", command);
      }
   } catch (IOException ex) {
   }
}

/**
 * dumpStats dumps rx/tx stats for this server
 * this requires ServerHelper to be running
 */

void ServerManager::dumpStats() {
   int tries = 2;
   while (tries > 0) {
      try {
         tries--;
         send_data(MNG_GET_STATS);
         json_object *obj = s->readJson();
         json_object *stats = json_object_object_get(obj, "stats");

         //This requires that the server immediately replies !!!
         //otherwise we might get stuck here and have to kill the app
         printf("\nCollabREate Stats\n");
         printf("%s\n", json_object_get_string(stats));
         json_object_put(obj);
         break;
      } catch (IOException e) {
         connectToHelper();
      }
   }
}

/**
 * shutdownServer sends a request to the server to shutdown the server nicely
 * this requires ServerHelper to be running
 */

void ServerManager::shutdownServer() {
   int tries = 2;
   while (tries > 0) {
      try {
         tries--;
         //sending shutdown request, there is no expected reply
         send_data(MNG_SHUTDOWN);
         break;
      } catch (IOException e) {
         connectToHelper();
      }
   }
}

/**
 * getProjectInfo gets project information for a previously listed project
 * @param lpid the local PID for the project to get info on
 * @param pinfo a project info object to populate with information
 * @return 0 on success
 */
int ServerManager::getProjectInfo(int lpid, ProjectInfo *pinfo) {
   int rval = -1;
   for (vector<ProjectInfo*>::iterator it = plist.begin(); it != plist.end(); it++) {
      ProjectInfo *pi = *it;
      if (pi->lpid == lpid ) {
         pinfo->lpid = pi->lpid;
         pinfo->desc = pi->desc;
         pinfo->parent = pi->parent;
         pinfo->pdesc = pi->desc;
         pinfo->snapupdateid = pi->snapupdateid;
         pinfo->pub = pi->pub;
         pinfo->sub = pi->sub;
         pinfo->owner = pi->owner;
         pinfo->hash = pi->hash;
         pinfo->gpid = pi->gpid;
         rval = 0;
         break;
      }
   }
   return rval;
}

//C API value for 2000-01-01
#define MILLENIUM 946713600
static u_int32_t millenium = MILLENIUM;

/* swap the order of the eight bytes at the given location */
static void double_swap(double *d) {
   u_int32_t *p = (u_int32_t*)d;
   u_int32_t temp = ntohl(p[1]);
   p[1] = ntohl(p[0]);
   p[0] = temp;
}

static time_t PQ_to_time_t(double pqtime) {
   double_swap(&pqtime);              //convert to host order
   return millenium + (time_t)pqtime; //normalize to C API reference time
}

/**
 * exportProject exports a project to a binary file
 * @param lpid the local PID for the project to export
 * @param efile the filename to export to
 * @return 0 on success
 */
int ServerManager::exportProject(int lpid, const char *efile) {
   int rval = -1;
   if (mode == MODE_DB) {
      ProjectInfo pi(1, "none");
      if (getProjectInfo(lpid, &pi) == 0) {
         if (pi.snapupdateid > 0 ) {
            fprintf(stderr, "snapshot exporting is currently not implimented\n");
            return -1;
         }
         printf("exporting %d (%s)\n", lpid, pi.gpid.c_str());
         if (pi.parent > 0 ) {
            fprintf(stderr, "This project was forked.  Note: lineage is not preserved with export.\n");
         }
         FILE *f = fopen(efile, "wb");
         fprintf(f, "%s\n", FILE_SIG);

         json_object *obj = json_object_new_object();
         append_json_int32_val(obj, "version", FILE_VER);
         append_json_string_val(obj, "gpid", pi.gpid);
         append_json_string_val(obj, "hash", pi.hash);
         append_json_uint64_val(obj, "subscribe", pi.sub);
         append_json_uint64_val(obj, "publish", pi.pub);
         append_json_string_val(obj, "description", pi.desc);

         size_t jlen;
         const char *json = json_object_to_json_string_length(obj, JSON_C_TO_STRING_PLAIN, &jlen);

         fprintf(f, "%s\n", json);
         json_object_put(obj);
         
         static const int plens[1] = {4};
         static const int pformats[1] = {1};
         //insert into files values(stream_id, fname);
         const char * const parms[1] = {(char*)&lpid};
         lpid = htonl(lpid);
         PGresult *rset = PQexecPrepared(dbConn, "getAllUpdates",
                             1, //int nParams,   size of arrays that follow
                             parms, //parms,  //const char * const *paramValues, array of string values
                             plens, //const int *paramLengths,
                             pformats, //const int *paramFormats,
                             1); //int resultFormat); 0 == text, 1 == binary
      
         ExecStatusType qres = PQresultStatus(rset);
         if (qres != PGRES_TUPLES_OK && qres != PGRES_COMMAND_OK) {
            fprintf(stderr, "getAllUpdates: %s\n", PQerrorMessage(dbConn));
         }
         else {
            printf("processing updates\n");
            int rows = PQntuples(rset);
            for (int i = 0; i < rows; i++) {
               //printf("processing update %d...", (i + 1));
               printf(".");
               uint64_t updateid = *((uint64_t*)PQgetvalue(rset, i, 0));
               const char *uid = PQgetvalue(rset, i, 1);
               int pid = ntohl(*(int*)PQgetvalue(rset, i, 2));
               const char *json = (const char*)PQgetvalue(rset, i, 3);

               double created_d = *(double*)PQgetvalue(rset, i, 4);
               time_t created = PQ_to_time_t(created_d);

               json_object *update = json_tokener_parse(json);
               append_json_uint64_val(update, "updateid", updateid);
               append_json_string_val(update, "uid", uid);
               append_json_int32_val(update, "pid", pid);

               //write timestamp?
               json = json_object_to_json_string_length(update, JSON_C_TO_STRING_PLAIN, &jlen);
      
               fprintf(f, "%s\n", json);
               json_object_put(update);
            }
            fclose(f);
            if (rows == 0 ) {
               printf("NO UPDATES FOUND FOR EXPORTING\n");
            }
            else {
               printf("Processed %d updates\n", rows);
            }
            rval = 0;
         }
         PQclear(rset);
      }
      else {
         printf("Project %d not found.\n", ntohl(lpid));
      }
      printf("\n");
   }
   else {
      fprintf(stderr, "it appears that the server is configured for BASIC mode\n");
   }
   return rval;
}

/**
 * importProject imports a project from a binary file
 * @param ifile the filename to import from
 * @param newowner the local uid to be the owner of the new project
 */
int ServerManager::importProject(FILE *ifile, const char *newowner) {
   int rval = -1;
   if (mode == MODE_DB) {
      try {
         ProjectInfo pi(1, "none");

         FileIO fdis;
         fdis.setFileDescriptor(fileno(ifile));

         if (fdis.readLine() == FILE_SIG) {
            printf("Magic matched\n");
         }
         else {
            printf("This doesn't appear to be a collabREate dump file\n");
            return -1;
         }
         json_object *obj = fdis.readJson();
         //addproject
         //set the new project owner
         append_json_string_val(obj, "newowner", newowner);
         send_data(MNG_PROJECT_MIGRATE, obj);

         // this is really a throwaway, since we are expecting a specific message here
         obj = s->readJson();
         const char *type = string_from_json(obj, "type");

         if (strcmp(type, MNG_PROJECT_MIGRATE_REPLY)) {
            fprintf(stderr, "protocol dictates PROJECT_MIGRATE_REPLY, but recieved: %s\n", type);
            json_object_put(obj);
            return rval;
         }
         int status;
         if (!int32_from_json(obj, "status", &status) || status != MNG_MIGRATE_REPLY_SUCCESS) {
            fprintf(stderr, "Project migrate did not succeed on server, check server logs for more info\n");
            json_object_put(obj);
            return rval;
         }
         else {
            printf("Project creation succeeded on server\n");
         }
         json_object_put(obj);

         string line;
         while (fdis.readLine(line)) {
            json_object *update = json_tokener_parse(line.c_str());
            //printf("update:" + updateid + " orig uid " + uid + " oldpid " + pid + " cmd " + cmd + " datalen " + datalen );
            printf(".");

            //insertUpdate
            append_json_string_val(update, "newowner", newowner);

            obj = json_object_new_object();
            size_t jlen;
            append_json_string_val(obj, "update", json_object_to_json_string_length(update, JSON_C_TO_STRING_PLAIN, &jlen));
            send_data(MNG_MIGRATE_UPDATE, obj);
            json_object_put(update);
         }
         rval = 0;
         fdis.close();
      } catch (IOException ex) {
         fprintf(stderr, "Error importing project\n");
      }
      printf("\n");
   }
   else {
      fprintf(stderr, "it appears that the server is configured for BASIC mode\n");
   }
   return rval;
}

/**
 * getConfig is an inspector that gets the current operation mode of the connection manager
 * @return a Properites object
 */
json_object *ServerManager::getConfig() {
   return config;
}

/**
 * getMode is an inspector that gets the current operation mode of the connection manager
 * @return the mode
 */
int ServerManager::getMode() {
   return mode;
}

/**
 * listConnections lists the current connections to this server
 * this requires ServerHelper to be running
 */
void ServerManager::listConnections() {
   printf("\npre\n");
   send_data(MNG_GET_CONNECTIONS);
   printf("\npost\n");

   //This requires that the server immediately replies !!!
   //otherwise we might get stuck here and have to kill the app
   json_object *obj = s->readJson();
   json_object *conns = json_object_object_get(obj, "connections");

   printf("\nCollabREate Connections\n");
   printf("%s\n", json_object_get_string(conns));
   json_object_put(obj);
}

/**
 * listUsers lists the users on this server
 */
void ServerManager::listUsers() {
   if (mode == MODE_DB) {
      printf("\nCollabREate Users\n");
      printf("%-4s%-10s%-10s%-10s %s\n", "UID", "Username", "Pub", "Sub", getPermHeaderString(8).c_str());

      PGresult *rset = PQexecPrepared(dbConn, "listUsers",
                          0, //int nParams,   size of arrays that follow
                          NULL, //parms,  //const char * const *paramValues, array of string values
                          NULL, //const int *paramLengths,
                          NULL, //const int *paramFormats,
                          1); //int resultFormat); 0 == text, 1 == binary
   
      ExecStatusType qres = PQresultStatus(rset);
      if (qres != PGRES_TUPLES_OK && qres != PGRES_COMMAND_OK) {
         fprintf(stderr, "listUsers: %s\n", PQerrorMessage(dbConn));
      }
      else {
         //"select userid,username,pub,sub from users order by userid asc;",

         int rows = PQntuples(rset);
         for (int i = 0; i < rows; i++) {
            //printf("processing update %d...", (i + 1));
            printf(".");
            int uid = ntohl(*(int*)PQgetvalue(rset, i, 0));
            const char *user = PQgetvalue(rset, i, 1);
            uint64_t pub = ntohll(*((uint64_t*)PQgetvalue(rset, i, 2)));
            uint64_t sub = ntohll(*((uint64_t*)PQgetvalue(rset, i, 3)));
            printf("%-4d%-10s%-10" PRIx64 "%-10" PRIx64 " %s\n", uid, user, pub, sub, getPermRowString(pub, sub,8).c_str());
         }
      }
      PQclear(rset);
   }
   else {
      fprintf(stderr, "it appears that the server is configured for BASIC mode\n");
   }
}

/**
 * listProjects lists the projects on this server
 */
void ServerManager::listProjects() {
   if (mode == MODE_DB) {
      string lastHash = "";
      printf("\nCollabREate projects\n");
      printf("%-4s %-4s %-4s %-10s %-10s %s %s\n", "PID", "PPID", "snap", "Pub", "Sub", getPermHeaderString(6).c_str(), "Description");

      //         listProjectsQuery = con.prepareStatement("select p.pid,p.gpid,p.hash,p.pub,p.sub,f.parent,p.description,q.description from projects p left join (forklist f left join projects q on f.parent=q.pid) on p.pid = f.child order by p.pid asc;");
      //                                                            1      2      3     4     5      6          7             8

      PGresult *rset = PQexecPrepared(dbConn, "listProjects",
                          0, //int nParams,   size of arrays that follow
                          NULL, //parms,  //const char * const *paramValues, array of string values
                          NULL, //const int *paramLengths,
                          NULL, //const int *paramFormats,
                          1); //int resultFormat); 0 == text, 1 == binary
   
      ExecStatusType qres = PQresultStatus(rset);
      if (qres != PGRES_TUPLES_OK && qres != PGRES_COMMAND_OK) {
         fprintf(stderr, "listUsers: %s\n", PQerrorMessage(dbConn));
      }
      else {
         //"select p.pid,p.gpid,p.hash,p.pub,p.sub,f.parent,p.description,q.description,p.snapupdateid from projects p left join (forklist f left join projects q on f.parent=q.pid) on p.pid = f.child order by p.pid asc;",

         int rows = PQntuples(rset);
         for (int i = 0; i < rows; i++) {
            //printf("processing update %d...", (i + 1));
            printf(".");
            int pid = ntohl(*(int*)PQgetvalue(rset, i, 0));
            uint64_t pub = ntohll(*((uint64_t*)PQgetvalue(rset, i, 3)));
            uint64_t sub = ntohll(*((uint64_t*)PQgetvalue(rset, i, 4)));
            uint64_t snapupdateid = ntohll(*((uint64_t*)PQgetvalue(rset, i, 8)));
            int ppid = ntohl(*(int*)PQgetvalue(rset, i, 5));
            const char *desc = PQgetvalue(rset, i, 6);

            string hash = PQgetvalue(rset, i, 2);
            if (hash != lastHash) {
               //printf(hash);
               lastHash = hash;
            }
            ProjectInfo *temppi = new ProjectInfo(pid, desc);
            const char *isSnap = (snapupdateid > 0) ? " X " : "   ";
            printf("%-4d %-4d %-4s %-10" PRIx64 " %-10" PRIx64 " %s %s\n", pid, ppid, isSnap, pub, sub, getPermRowString(pub, sub, 6).c_str(), desc);
            temppi->parent = ppid;
            temppi->pdesc = PQgetvalue(rset, i, 7);
            temppi->snapupdateid = snapupdateid;
            temppi->pub = pub;
            temppi->sub = sub;
            temppi->hash = PQgetvalue(rset, i, 2);
            temppi->gpid = PQgetvalue(rset, i, 1);
            plist.push_back(temppi);
         }
      }
      PQclear(rset);
   }
   else {
      fprintf(stderr, "it appears that the server is configured for BASIC mode\n");
   }
}

/**
 * closeDB closes all the database queries and the database connection
 */
void ServerManager::closeDB() {
   if (mode == MODE_DB && dbConn != NULL) {
      printf("Closing database connection\n");
      PGresult *res = PQexec(dbConn, "DEALLOCATE listUsers;");
      PQclear(res);
      res = PQexec(dbConn, "DEALLOCATE listProjects;");
      PQclear(res);
      res = PQexec(dbConn, "DEALLOCATE addUser;");
      PQclear(res);
      res = PQexec(dbConn, "DEALLOCATE updateUser;");
      PQclear(res);
      res = PQexec(dbConn, "DEALLOCATE findUserByUID;");
      PQclear(res);
      res = PQexec(dbConn, "DEALLOCATE getAllUpdates;");
      PQclear(res);
      res = PQexec(dbConn, "DEALLOCATE deleteUpdatesByPID;");
      PQclear(res);
      res = PQexec(dbConn, "DEALLOCATE deleteProjectByPID;");
      PQclear(res);
      PQfinish(dbConn);
      dbConn = NULL;
   }
}

string ServerManager::getPermHeaderString(int colWidth) {
   return getPermHeaderString(colWidth, false);
}

string ServerManager::getPermHeaderString(int colWidth, bool number) {
   char buf[128];
   char rval[128];
   char *p = rval;
   for (int i = 0; i < permStringsLength; i++) {
      if (number) {
         snprintf(buf, sizeof(buf), "%d %s", i, permStrings[i]);
      }
      else {
         snprintf(buf, sizeof(buf), "%s", permStrings[i]);
      }
      if (strlen(buf) < colWidth) {
         p += snprintf(p, sizeof(rval) - (p - rval), "%-*s|", colWidth, buf);
      }
      else {
         buf[colWidth] = 0;  //truncate to colWidth
         p += snprintf(p, sizeof(rval) - (p - rval), "%s|", buf);
      }
   }
   return rval;
}

string ServerManager::getPermRowString(uint64_t p, uint64_t s, int colWidth) {
   char rval[128];
   char buf[128];
   string fp = "";
   string fs = "";
   for (int i = 0; i < permStringsLength; i++) {
      if ((p & 1) == 1) {
         fp = "P";
      }
      else {
         fp = " ";
      }
      if ((s & 1) == 1) {
         fs = "S";
      }
      else {
         fs = " ";
      }
      snprintf(buf, sizeof(buf), " %s %s", fp.c_str(), fs.c_str());
      snprintf(rval, sizeof(rval), "%-*s|", colWidth, buf);
      p = p >> 1;
      s = s >> 1;
   }
   return rval;
}

/**
 * main provides the cli interface for managing collabreate
 */
void ServerManager::exec(int argc, char **argv) {
   ServerManager *sm = NULL;
   json_object *p = NULL;
   printf("Got %d args\n", argc);
   if (argc >= 2) {
      //user specified a config file
      p = parseConf(argv[1]);
      sm = new ServerManager(p);
   }
   else {
      fprintf(stderr, "Could not read config file!\n");
      //not enough args
   }
   //special case for shutdown via init.d script
   if (argc >= 3) {
      if (!strcmp("shutdown", argv[1]) || !strcmp("shutdown", argv[2])) {
         sm->shutdownServer();
         sm->terminate();
         exit(0);
      }
   }
   char resp[128];
   while (true) {
      printf("\n");
      printf("CollabREate Server Menu:\n");
      printf("1)  Add user\n");
      printf("2)  List users\n");
      printf("3)  List Projects\n");
      printf("4)  Edit user\n");
      printf("5)  List Connections *\n");
      printf("6)  Show tx/rx stats *\n");
      printf("7)  Export a Project to file *\n");
      printf("8)  Import a Project from file *\n");
      printf("9)  Delete a Project\n");
      printf("10) Quit\n");
      printf("\n");
      printf(" * requires CollabREate Server to be running\n");
      printf("   others commands only require the database to be running \n");
      printf("Enter command: ");
      if (readLine(resp, sizeof(resp)) == NULL) {
         break;
      }
//         resp = resp.trim();
      if (!strcmp(resp, "1")) {
         if (sm->getMode() != MODE_DB ) {
            printf("this only makes sense in DB MODE !\n");
            continue;
         }
         printf("Note: the password typed in the interface is not masked\n");
         printf("Username: ");
         if (readLine(resp, sizeof(resp)) == NULL) {
            break;
         }
         string username = resp;
         if (!isAlphaNumeric(username)) {
            fprintf(stderr, "bad username\n");
            continue;
         }
         //any password is ok, including empty
         printf("Password: ");
         if (readLine(resp, sizeof(resp)) == NULL) {
            break;
         }
         string pass1 = resp;
         printf(" (again): ");
         if (readLine(resp, sizeof(resp)) == NULL) {
            break;
         }
         string pass2 = resp;
         if (pass1 != pass2) {
            fprintf(stderr, "passwords didn't match, not adding %s\n", username.c_str());
            continue;
         }

         printf("Subscribe permission bitfield (default: 0x%" PRIx64 "): ", (uint64_t)default_sub);
         if (readLine(resp, sizeof(resp)) == NULL) {
            break;
         }
         uint64_t sub = parsePerms(resp, default_pub);
         printf("Publish permission bitfield (default: 0x%" PRIx64 "): ", (uint64_t)default_pub);
         if (readLine(resp, sizeof(resp)) == NULL) {
            break;
         }
         uint64_t pub = parsePerms(resp, default_pub);

         string md5 = getMD5(pass1);
         printf("%s %s %s 0x%" PRIx64 " 0x%" PRIx64 "\n", username.c_str(), pass1.c_str(), md5.c_str(), pub, sub);
         
         sm->addUser(username, md5, pub, sub);
      }
      else if (!strcmp(resp, "2")) {
         if (sm->getMode() != MODE_DB ) {
            printf("this only makes sense in DB MODE !\n");
            continue;
         }
         sm->listUsers();
      }
      else if (!strcmp(resp, "3")) {
         if (sm->getMode() != MODE_DB ) {
            printf("this only makes sense in DB MODE !\n");
            continue;
         }
         sm->listProjects();
      }
      else if (!strcmp(resp, "4")) {
         if (sm->getMode() != MODE_DB ) {
            printf("this only makes sense in DB MODE !\n");
            continue;
         }
         int uid;
         string username;
         string password;
         uint64_t pub;
         uint64_t sub;
         string ousername;
         string opassword;
         uint64_t opub;
         uint64_t osub;
         char *endptr;
         sm->listUsers();
         printf("Which user (uid) would you like to edit? ");
         if (readLine(resp, sizeof(resp)) == NULL) {
            break;
         }
         uid = strtoul(resp, &endptr, 10);  //obviously doesn't check for valid uid
         if (*endptr || endptr == resp) {
            fprintf(stderr, "You must enter a valid user id number\n");
            continue;
         }

         static const int plens[1] = {4};
         static const int pformats[1] = {1};
         //insert into files values(stream_id, fname);
         int tuid = htonl(uid);
         const char * const parms[1] = {(char*)&tuid};
         PGresult *rset = PQexecPrepared(sm->dbConn, "findUserByUID",
                             1, //int nParams,   size of arrays that follow
                             parms, //parms,  //const char * const *paramValues, array of string values
                             plens, //const int *paramLengths,
                             pformats, //const int *paramFormats,
                             1); //int resultFormat); 0 == text, 1 == binary
      
         ExecStatusType qres = PQresultStatus(rset);
         if (qres != PGRES_TUPLES_OK && qres != PGRES_COMMAND_OK) {
            fprintf(stderr, "Userid %d not found!\n", uid);
            fprintf(stderr, "findUserByUID: %s\n", PQerrorMessage(sm->dbConn));
         }
         else {
            //"select username,pwhash,pub,sub from users where userid=$1",
            username = PQgetvalue(rset, 0, 0);
            password = PQgetvalue(rset, 0, 1);
            pub = ntohll(*(uint64_t*)PQgetvalue(rset, 0, 2));
            sub = ntohll(*(uint64_t*)PQgetvalue(rset, 0, 3));
            ousername = username;
            opassword = password;
            opub = pub;
            osub = sub;

            printf("Would you like to change the username? ");
            if (askyn()) {
               printf("Enter new username (%s):", username.c_str());
               if (readLine(resp, sizeof(resp)) == NULL) {
                  break;
               }
               string tempuser = resp;
               if (tempuser.length() > 0) {
                  username = tempuser;
               }
            }
            printf("Would you like to create a new password? ");
            if (askyn()) {
               printf("Password: ");
               if (readLine(resp, sizeof(resp)) == NULL) {
                  break;
               }
               string pass1 = resp;
               printf(" (again): ");
               if (readLine(resp, sizeof(resp)) == NULL) {
                  break;
               }
               string pass2 = resp;
               if (pass1 != pass2) {
                  fprintf(stderr, "passwords didn't match, not changing password\n");
               }
               else {
                  password = getMD5(pass1);
               }
            }
            printf("Would you like to change the permissions? ");
            if (askyn()) {
               printf("Would you like to change the permissions by specifying numeric values? ");
               if (askyn()) {
                  printf("Enter new publish permissions (0x%" PRIx64 "): ", pub);
                  if (readLine(resp, sizeof(resp)) == NULL) {
                     break;
                  }
                  pub = parsePerms(resp, pub);
                  printf("Enter new subscribe permissions (0x%" PRIx64 "): ", sub);
                  if (readLine(resp, sizeof(resp)) == NULL) {
                     break;
                  }
                  sub = parsePerms(resp, sub);
               }
               else {
                  printf("Would you like to change the permissions one at a time? ");
                  if (askyn()) {
                     string userdata;
                     while (userdata != "q") {
                        printf("%s\n", sm->getPermHeaderString(12, true).c_str());
                        printf("%s\n", sm->getPermRowString(pub, 0, 12).c_str());
                        printf("Press the column number for the publish permission you'd like to toggle (q to exit): ");
                        if (readLine(resp, sizeof(resp)) == NULL) {
                           break;
                        }
                        userdata = resp;
                        if (isNumeric(resp)) {
                           uint32_t val = strtoul(resp, NULL, 0);
                           if (permStringsLength > val) {
                              if (((pub >> val) & 1) == 1) {
                                 pub = pub ^ (1 << val);
                              }
                              else {
                                 pub = pub | (1 << val);
                              }
                           }
                        }
                     }
                     userdata = "";
                     while (userdata != "q") {
                        printf("%s\n", sm->getPermHeaderString(12, true).c_str());
                        printf("%s\n", sm->getPermRowString(sub, 0, 12).c_str());
                        printf("Press the column number for the subscribe permission you'd like to toggle (q to exit): ");
                        if (readLine(resp, sizeof(resp)) == NULL) {
                           break;
                        }
                        userdata = resp;
                        if (isNumeric(resp)) {
                           uint32_t val = strtoul(resp, NULL, 0);
                           if (permStringsLength > val) {
                              if (((sub >> val) & 1) == 1) {
                                 sub = sub ^ (1 << val);
                              }
                              else {
                                 sub = sub | (1 << val);
                              }
                           }
                        }
                     }
                  }
               }
            }
            if (!(username == ousername && password == opassword && pub == opub && sub == osub)) {
               sm->updateUser(username, password, pub, sub, uid);
            }
            else {
               printf("No changes made!\n");
            }
         }
         PQclear(rset);
      }
      else if (!strcmp(resp, "5")) {
         sm->listConnections();
      }
      else if (!strcmp(resp, "6")) {
         sm->dumpStats();
      }
      else if (!strcmp(resp, "7")) {
         if (sm->getMode() != MODE_DB ) {
            printf("this only makes sense in DB MODE !\n");
            continue;
         }
         sm->listProjects();
         printf("Which project would you like to export (enter PID)? : ");
         if (readLine(resp, sizeof(resp)) == NULL) {
            break;
         }
         if (isNumeric(resp)) {
            int lpid = strtoul(resp, NULL, 0);
            printf("Enter the filename to export to: ");
            if (readLine(resp, sizeof(resp)) == NULL) {
               break;
            }
            struct stat sbuf;
            if (stat(resp, &sbuf) == 0) {
               printf("file %s exists, overwrite? ", resp);
               if (!askyn()) {
                 printf("continuing\n");
                 continue;
               }
            }
            if (sm->exportProject(lpid, resp) != 0) {
               fprintf(stderr, "export did not fully comply successfully\n");
            }
         }
      }
      else if (!strcmp(resp, "8")) {
         if (sm->getMode() != MODE_DB ) {
            printf("this only makes sense in DB MODE !\n");
            continue;
         }
         printf("Enter the filename to import from: ");
         if (readLine(resp, sizeof(resp)) == NULL) {
            break;
         }
         FILE *f = fopen(resp, "r");
         if (f != NULL) {
            char username[64];
            sm->listUsers();
            printf("Which user (name) should be the new owner? ");
            if (readLine(username, sizeof(username)) == NULL) {
               break;
            }
            //obviously doesn't check for valid uid
            if (sm->importProject(f, username) != 0) {
               fprintf(stderr, "import from %s did not complete successfully\n", resp);
            }
            fclose(f);
         }
         else {
            printf("file %s not found.\n", resp);
         }
      }
      else if (!strcmp(resp, "9")) {
         if (sm->getMode() != MODE_DB ) {
            printf("this only makes sense in DB MODE !\n");
            continue;
         }
         string userdata = "";
         sm->listProjects();
         printf("Which project would you like to permenantly delete? : ");
         if (readLine(resp, sizeof(resp)) == NULL) {
            break;
         }
         if (isNumeric(resp)) {
            uint32_t lpid = strtoul(resp, NULL, 0);
            printf("Are you sure you want to delete project %d (and all associated updates?)\n", lpid);
            printf("Note: this does current support projects with related snapshots or forks\n");
            printf("(yes/no) ? ");
            if (askyn()) {
               sm->deleteProject(lpid);
            }
         }
      }
      else if (!strcmp(resp, "10")) {
         sm->terminate();
         break;
      }
      else if (!strcmp(resp, "11")) {
         printf("Use of server startup/shutdown scripts (ie. /etc/init.d) is recommended.\n");
         printf("Are you sure you want to shutdown the server? ");
         if (askyn()) {
            sm->shutdownServer();
         }
      }
   }
}

int main(int argc, char **argv) {
   ServerManager::exec(argc, argv);
   return 0;
}

