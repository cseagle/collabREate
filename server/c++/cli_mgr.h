/*
   collabREate cli_mgr.h
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

#ifndef __CONNECTION_MGR_H
#define __CONNECTION_MGR_H

#include <map>
#include <vector>
#include <set>
#include <string>
#include <stdint.h>
#include <sys/types.h>
#include <semaphore.h>
#include <json-c/json.h>

#include "projectmap.h"

using namespace std;

class ProjectInfo;
class NetworkIO;

typedef set<Client*>::iterator Client_it;
typedef map<int,set<Client*>*>::iterator Projects_it;

/**
 * Packet is a helper class to represent a tuple pairing a client
 * with a command posted by that client
 */
class Packet {
public:
   Client *c;
   const char *cmd;
   json_object *obj;
   uint64_t uid;
   Packet(Client *src, const char *cmd, json_object *obj, uint64_t updateid);
};


class ConnectionManagerBase {
public:

   static const char * const EMPTY_GPID;
   ProjectMap projects;
   bool done;

protected:
   vector<Packet*> queue;
   sem_t pidLock;
   
   //counting semephore for incoming packets from the server
   sem_t queueSem;
   sem_t queueMutex;

public:
   ConnectionManagerBase(json_object *conf, bool mode);
   void start();

   /**
    * Add a new connection
    * @param s the socket to create new client for
    */
   void add(NetworkIO *s);

   /**
    * remove removes a client from a currently reflecting project 
    * @param c the client to remove (from whatever project it is already connected to)
    */
   void remove(Client *c);

   /**
    * logs a message to the configured log file (server.conf)
    * @param msg the string to log
    * @param verbosity apply a verbosity level to the msg
    */
   void log(const string &msg, int verbosity = 0);

   /**
    * logs a message to the configured log file (server.conf) (with newline)
    * @param msg the string to log
    * @param verbosity apply a verbosity level to the msg
    */
   void logln(const string &msg, int verbosity = 0);

   /**
    * terminate terminates the connection manager
    * it terminates all clients connected to all projects 
    */
   virtual void terminate();


   /**
    * calls the terminate function of the associated CollabreateServer
    */
   void Shutdown() {
      terminate();
   }

   /**
    * authenticate authenticates a user (for use in database mode)
    * bacially this is standard CHAP with HMAC (md5)
    * @param user the user to authenticate
    * @param challenge the randomly generated challenge send to the plugin
    * @param response the calculated response from the plugin to check 
    * @return the user id of an authenticated user, or INVALID_USER
    */
   virtual int authenticate(Client *c, const char *user, const uint8_t *challenge, uint32_t clen, const uint8_t *response, uint32_t rlen) = 0;

   /**
    * migrateUpdate is very similar to 'post', migrateUpdate only 
    * archives the udpate in the database so that future clients can receive it 
    * @param newowner the new uid to attribute the update to
    * @param pid the local project id for the migrated project
    * @param cmd the 'command' that was performed (comment, rename, etc)
    * @param data the 'data' portion of the command (the comment text, etc)
    */
   virtual void migrateUpdate(const char *newowner, int pid, const char *cmd, json_object *obj) = 0;

   /**
    * post both queues a newly received update to be sent to other clients and (if in DB mode)
    * archives the udpate in the database so that future clients can receive it 
    * @param src the client that made the update
    * @param cmd the 'command' that was performed (comment, rename, etc)
    * @param data the 'data' portion of the command (the comment text, etc)
    */
   virtual void post(Client *src, const char *cmd, json_object *obj) = 0;

   /**
    * dumpStats dumps send / receive stats for each connected client 
    */
   string dumpStats();

   /**
    * sendLatestUpdates sends updates from LastUpdate to current 
    * it is expected that the client has already joined a project before calling this function
    * it is expected that the client has already received updates from 0 - lastUpdate 
    * this function is typically called when a user is re-joining a project that they had previously worked on
    * @param c the client requesting updates 
    * @param lastUpdate the last update the client received 
    */
   virtual void sendLatestUpdates(Client *c, uint64_t lastUpdate) = 0;

   /**
    * getProjectInfo gets information related to a local project
    * @param pid the local pid of a project to get info on
    * @return a  project info object for the provided pid, caller needs to delete this
    */
   virtual ProjectInfo *getProjectInfo(int pid) = 0;

   /**
    * getProjectList generates a list of projects on this server, each list (vector) item is 
    * actually a pinfo (project info) object, the list does NOT contain all projects, but
    * only contains projects relevant to the binary that is currently loaded in IDA
    * @param phash the IDA generated hash that is unique among the analysis files
    * @return a vector of project info objects for the provided phash
    */
   virtual vector<ProjectInfo*> *getProjectList(const string &phash) = 0;

   /**
    * listConnection displays the current connections to the collabREate connection manager 
    */
   string listConnections();

   /**
    * joinProject joings a particular client to a project so that it can participate in collabREation 
    * @param c the client attempting to join 
    * @param lpid the local project id of the project on this server 
    * @return 0 on success, negative value on failure
    */
   virtual int joinProject(Client *c, int lpid) = 0;
 
   /**
    * snapProject adds a snapshop for a project, this does not change the client's 
    * current project, nor copy any updates, it simply marks a point-in-time (updateid wise)
    * this point-in-time can later be used as a project fork point if desired 
    * @param c the client invoking the snapshot
    * @param lastupdateid the point-in-time the client wishes to save in the snapshot
    * @param desc a user provided description of the snapshot
    * @return the snapshotid on success, -1 on failure
    */
   virtual int snapProject(Client *c, uint64_t lastupdateid, const string &desc) = 0;

   /**
    * forkProject  forks a project - creats new project and copies all updates to point to the new project,
    * publish and subscribe values are inherited
    * @param c client object invoking the fork
    * @param lastupdateid the updateid value the fork is to occur at
    * @param desc user provided description of the fork
    * @return the new projectid on success, -1 on failure
    */

   virtual int forkProject(Client *c, uint64_t lastupdateid, const string &desc) = 0;


   /**
    * forkProject  forks a project - creats new project and copies all updates to point to the new project
    * @param c client object invoking the fork
    * @param lastupdateid the updateid value the fork is to occur at
    * @param desc user provided description of the fork
    * @param pub specified publish permissions
    * @param sub specified subscribe permissions
    * @return the new projectid on success, -1 on failure
    */
   virtual int forkProject(Client *c, uint64_t lastupdateid, const string &desc, uint64_t pub, uint64_t sub) = 0;

   /**
    * sendForkFollows sends a special "follow fork" message to all clients working on
    * a project that has been forked, this allows the user to decide if they would like
    * to continue to work on the existing project, or change to the newly created project
    * @param originator the client that instigated the fork
    * @param oldlpid the local pid of the original project
    * @param lastupdateid the last update processed prior to fork (if your database is different you can't change to the new project)
    * @param desc the description of the new project, so the user can make a more educated descision
    */
   virtual void sendForkFollows(Client *originator, int oldlpid, uint64_t lastupdateid, const string &desc) = 0;

   /**
    * snapforkProject -  this is a special version of forkProject that is designed to work
    * on snapshots (instead of existing projects) this works exactly like forkProject, execpt
    * updates are copied from the 'parent' of the snapshot instead of the client's currently 
    * associated project, also updates are copied until the lastupdateid from the snapshot, 
    * not from the plugin (last received update is stored in the idb)
    * @param c client invoking the snapforkProject
    * @param spid the pid of the project that is being snapshotted
    * @param desc the user provided description for the snapshot
    * @return the new project id on success, -1 on failure
    */

   virtual int snapforkProject(Client *c, int spid, const string &desc, uint64_t pub, uint64_t sub) = 0;

   /**
    * migrateProject adds a project to the database  
    * fairly similar to addProject
    * @param owner the uid to be the owner of the new project
    * @param gpid unique global id for the incoming project
    * @param hash unique hash for the binary file originally generated by IDA
    * @param desc user provided description of the project 
    * @param pub the publish permissions for the project
    * @param sub the subscribe permissions for the project
    * @return the new project id on success, -1 on failure
    */

   virtual int migrateProject(const char *owner, const string &gpid, const string &hash, const string &desc, uint64_t pub, uint64_t sub) = 0;

   /**
    * addProject adds a project to the database and reflector (or merely a reflector in non-DB mode) 
    * @param c cliend invoking the addProject
    * @param hash unique hash for the binary file originally generated by IDA
    * @param desc user provided description of the project 
    * @param pub the publish permissions for the project
    * @param sub the subscribe permissions for the project
    * @return the new project id on success, -1 on failure
    */

   virtual int addProject(Client *c, const string &hash, const string &desc, uint64_t pub, uint64_t sub) = 0;

   /**
    * updateProjectPerms updates the publish and subscribe values in the database, it also iterates
    * across all clients connected the project and updates the effective permissions accordingly
    * @param pub the publish permissions to set
    * @param sub the subscribe permissions to set
    */
   virtual void updateProjectPerms(Client *c, uint64_t pub, uint64_t sub) = 0;

   /**
    * gpid2lpid converts a gpid (which is unique across all projects on all servers)
    * to an lpid (pid local to a particular server instance) 
    * @param gpid global pid 
    * @return the local pid
    */
   virtual int gpid2lpid(const string &gpid) = 0;

   /**
    * lpid2gpid converts an lpid (pid local to a particular server instance) 
    * to a gpid (which is unique across all projects on all servers)
    * @param lpid the local pid for this particular server 
    * @return the glocabl pid
    */
   virtual string lpid2gpid(int lpid) = 0;

protected:
   static void *run(void *arg);

private:
   json_object *conf;

   bool basicMode;

};


#endif
