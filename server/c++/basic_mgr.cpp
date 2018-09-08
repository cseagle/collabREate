/*
   collabREate basic_mgr.cpp
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
#include <string>
#include <map>
#include <vector>
#include "utils.h"
#include "proj_info.h"
#include "client.h"
#include "basic_mgr.h"
#include "projectmap.h"
#include "clientset.h"

using namespace std;

/**
 * BasicConnectionManager
 * This class is responsible for routing incoming packets to all
 * interested clients
 * @author Tim Vidas
 * @author Chris Eagle
 * @version 0.4.0, August 2012
 */


BasicConnectionManager::BasicConnectionManager(json_object *conf) : ConnectionManager(conf) {
   basicmodepid = 500;
   basic_mode_uid = 1;
   sem_init(&pidLock, 0, 1);
   sem_init(&uidLock, 0, 1);
   sem_init(&mapLock, 0, 1);
}

BasicConnectionManager::~BasicConnectionManager() {
   for (map<string,vector<BasicProject*>*>::iterator mi = basicProjects.begin(); mi != basicProjects.end(); mi++) {
      vector<BasicProject*>* v = mi->second;
      for (vector<BasicProject*>::iterator vi = v->begin(); vi != v->end(); vi++) {
         delete *vi;
      }
      delete v;
   }
}

map<uint32_t,string> basic_mode_users;
uint32_t BasicConnectionManager::uid_for_user(const char *user) {
   if (basic_mode_users.find(user) == basic_mode_users.end()) {
      sem_wait(&uidLock);
      basic_mode_users[user] = basic_mode_uid++;
      sem_post(&uidLock);
   }
   return basic_mode_users[user];
}

uint32_t BasicConnectionManager::doAuth(NetworkIO *nio) {
   uint64_t challenge[4] = {0xdeadbeefdeadbeefll, 0xdeadbeefdeadbeefll, 0xdeadbeefdeadbeefll, 0xdeadbeefdeadbeefll};
   json_object *obj = json_object_new_object();
   append_json_hex_val(obj, "challenge", (uint8_t*)challenge, CHALLENGE_SIZE);
   append_json_string_val(obj, "type", MSG_INITIAL_CHALLENGE);
   log(LINFO4, "Sending initial challenge\n");
   nio->writeJson(obj);

   obj = nio->readJson();
   if (obj == NULL) {
      return AUTH_FAIL;
   }

   int pluginversion;
   int32_from_json(obj, "protocol", &pluginversion);
   if (pluginversion != PROTOCOL_VERSION) {
      char buf[256];
      snprintf(buf, sizeof(buf), "Version mismatch. plugin: %d server: %d", pluginversion, PROTOCOL_VERSION);
      json_object_put(obj);
      obj = json_object_new_object();
      append_json_string_val(obj, "error", buf);
      append_json_string_val(obj, "type", MSG_ERROR);
      nio->writeJson(obj);
      return AUTH_INVALID_PROTO;
   }

   uint32_t rlen;
   const char *type = string_from_json(obj, "type");
   uint8_t *response = hex_from_json(obj, "hmac", &rlen);
   const char *user = string_from_json(obj, "user");
   json_object_put(obj);
   if (strcmp(type, MSG_AUTH_REQUEST) || response == NULL || user == NULL || rlen != MD5_SIZE) {
      return AUTH_INVALID_PROTO;
   }
   uint32_t result = AUTH_FAIL;
   uint32_t uid = uid_for_user(user);
   if (response != NULL) {  //no memcmp here in basic mode
      result = uid;
      user_map[uid] = UserInfo(user, uid, FULL_PERMISSIONS, FULL_PERMISSIONS);
      delete [] response;
   }
   else {
      //reply should have included a "hmac" field
      result = AUTH_INVALID_PROTO;
   }
   return result;
}

/**
 * importUpdate is very similar to 'post', importUpdate only
 * archives the udpate in the database so that future clients can receive it
 * @param newowner the new uid to attribute the update to
 * @param pid the local project id for the migrated project
 * @param cmd the 'command' that was performed (comment, rename, etc)
 * @param data the 'data' portion of the command (the comment text, etc)
 */
void BasicConnectionManager::importUpdate(const char *newowner, int pid, const char *cmd, json_object *obj) {
   BasicProject *p = findProject(pid);
   if (p != NULL) {
      const char *json = json_object_to_json_string(obj);
      p->append_update(json);
   }
}

/**
 * post both queues a newly received update to be sent to other clients and (if in DB mode)
 * archives the udpate in the database so that future clients can receive it
 * @param src the client that made the update
 * @param cmd the 'command' that was performed (comment, rename, etc)
 * @param data the 'data' portion of the command (the comment text, etc)
 */
void BasicConnectionManager::post(Client *src, const char * cmd, json_object *obj) {
   BasicProject *p = findProject(src->getPid());
   if (p) {
      Packet *pkt = new Packet(src, cmd, obj, p->next_uid());
      const char *json = json_object_to_json_string(pkt->obj);
      sem_wait(&queueMutex);  //prevent simultaneous update to these storage structures
      p->append_update(json);
      queue.push_back(pkt);   //add a new packet with the binary data to the queue
      sem_post(&queueMutex);
      sem_post(&queueSem);  //notify is the compliment to wait
   }
}

/**
 * sendLatestUpdates sends updates from LastUpdate to current
 * it is expected that the client has already joined a project before calling this function
 * it is expected that the client has already received updates from 0 - lastUpdate
 * this function is typically called when a user is re-joining a project that they had previously worked on
 * @param c the client requesting updates
 * @param lastUpdate the last update the client received
 */
void BasicConnectionManager::sendLatestUpdates(Client *c, uint64_t lastUpdate) {
   BasicProject *p = findProject(c->getPid());
   if (p) {
      const vector<char*> &updates = p->get_updates();
      for (vector<char*>::const_iterator i = updates.cbegin(); i != updates.cend(); i++) {
         json_object *obj = json_tokener_parse(*i);
         uint64_t uid;
         if (uint64_from_json(obj, "updateid", &uid) && uid > lastUpdate) {
            const char *cmd = string_from_json(obj, "type");
            if (cmd) {
               c->post(cmd, obj);
            }
         }
      }
   }
}

/**
 * getProject gets information related to a local project
 * @param pid the local pid of a project to get info on
 * @return a  project info object for the provided pid
 *            caller must delete the returned pointer
 */
const Project *BasicConnectionManager::getProject(uint32_t pid) {
   //just use findProject and return as a const *
   return findProject(pid);
}

/**
 * getAllProjects generates a list of projects on this server, each list item is
 * a pointer to a Project object
 * @return a vector of project info objects
 */
vector<Project*> *BasicConnectionManager::getAllProjects() {
   vector<Project*> *plist = new vector<Project*>;
   map<uint32_t,BasicProject*>::iterator pi;
   sem_wait(&mapLock);
   for (pi = pid_project_map.begin(); pi != pid_project_map.end(); pi++) {
      plist->push_back((*pi).second);
   }
   sem_post(&mapLock);
   return plist;
}

/**
 * getProjectList generates a list of projects on this server, each list item is
 * actually a pointer to a Project object, the list does NOT contain all projects, but
 * only contains projects relevant to the binary that is currently loaded in IDA
 * @param phash the IDA generated hash that is unique among the analysis files
 * @return a vector of project info objects for the provided phash
 */
vector<const Project*> *BasicConnectionManager::getProjectList(const string &phash) {
   vector<const Project*> *plist = NULL;
   //build a basic mode project list
   map<string,vector<BasicProject*>*>::iterator bi = basicProjects.find(phash);
   if (bi != basicProjects.end()) {
      plist = new vector<const Project*>;
      vector<BasicProject*> *bpv = (*bi).second;
      for (vector<BasicProject*>::iterator it = bpv->begin(); it != bpv->end(); it++) {
         //get the current Client count for this project
         ClientSet *cs = projects.get((*it)->lpid);
         (*it)->connected = cs ? cs->size() : 0;
         plist->push_back(*it);
      }
   }
   return plist;
}

/**
 * joinProject joings a particular client to a project so that it can participate in collabREation
 * @param c the client attempting to join
 * @param lpid the local project id of the project on this server
 * @return 0 on success, negative value on failure
 */
int BasicConnectionManager::joinProject(Client *c, uint32_t lpid) {
   int rval = -1;
   log(LDEBUG, "joining in basic mode\n");
   BasicProject *p = findProject(lpid);
   if (p) {
      c->setGpid(lpid2gpid(lpid));
      c->setPid(lpid);
      log(LDEBUG, "BASIC mode has no notion of users, setting permissions based on REQ\n");
      //c->setPub(c.getReqPub());
      //c->setSub(c.getReqSub());
      c->setPub(FULL_PERMISSIONS);
      c->setSub(FULL_PERMISSIONS);
      projects.addClient(c);
      rval = 0;
   }
   else {
//     log(LERROR, "ERROR: attempt to join a non-existant project: %u\n", lpid);
     log(LERROR, "couldn't find current project\n");
   }
   return rval;
}

/**
 * snapProject adds a snapshop for a project, this does not change the client's
 * current project, nor copy any updates, it simply marks a point-in-time (updateid wise)
 * this point-in-time can later be used as a project fork point if desired
 * @param c the client invoking the snapshot
 * @param lastupdateid the point-in-time the client wishes to save in the snapshot
 * @param desc a user provided description of the snapshot
 * @return the snapshotid on success, -1 on failure
 */
int BasicConnectionManager::snapProject(Client *c, uint64_t lastupdateid, const string &desc) {
   c->send_error("Server is in basic mode, snapshots cannot be made");
   return -1;
}


/**
 * forkProject  forks a project - creats new project and copies all updates to point to the new project,
 * publish and subscribe values are inherited
 * @param c client object invoking the fork
 * @param lastupdateid the updateid value the fork is to occur at
 * @param desc user provided description of the fork
 * @return the new projectid on success, -1 on failure
 */

int BasicConnectionManager::forkProject(Client *c, uint64_t lastupdateid, const string &desc) {
   c->send_error("Server is in basic mode, forking is not available");
   return -1;
}


/**
 * forkProject  forks a project - creats new project and copies all updates to point to the new project
 * @param c client object invoking the fork
 * @param lastupdateid the updateid value the fork is to occur at
 * @param desc user provided description of the fork
 * @param pub specified publish permissions
 * @param sub specified subscribe permissions
 * @return the new projectid on success, -1 on failure
 */
int BasicConnectionManager::forkProject(Client *c, uint64_t lastupdateid, const string &desc, uint64_t pub, uint64_t sub) {
   c->send_error("Server is in basic mode, forking is not available");
   return -1;
}

/**
 * sendForkFollows sends a special "follow fork" message to all clients working on
 * a project that has been forked, this allows the user to decide if they would like
 * to continue to work on the existing project, or change to the newly created project
 * @param originator the client that instigated the fork
 * @param oldlpid the local pid of the original project
 * @param lastupdateid the last update processed prior to fork (if your database is different you can't change to the new project)
 * @param desc the description of the new project, so the user can make a more educated descision
 */
void BasicConnectionManager::sendForkFollows(Client *originator, int oldlpid, uint64_t lastupdateid, const string &desc) {
   originator->send_error("Server is in basic mode, follow forking is not available");
}


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

int BasicConnectionManager::snapforkProject(Client *c, int spid, const string &desc, uint64_t pub, uint64_t sub) {
   c->send_error("Server is in basic mode, forking snapshots is not available");
   return -1;
}

/**
 * importProject adds a project to the database
 * fairly similar to addProject
 * @param owner the uid to be the owner of the new project
 * @param gpid unique global id for the incoming project
 * @param hash unique hash for the binary file originally generated by IDA
 * @param desc user provided description of the project
 * @param pub the publish permissions for the project
 * @param sub the subscribe permissions for the project
 * @return the new project id on success, -1 on failure
 */

int BasicConnectionManager::importProject(const char *owner, const string &gpid, const string &hash, const string &desc, uint64_t pub, uint64_t sub) {
   sem_wait(&pidLock);
   int lpid = basicmodepid++;
   map<string,vector<BasicProject*>*>::iterator bi = basicProjects.find(hash);
   vector<BasicProject*> *vpi;
   if (bi != basicProjects.end()) {
      vpi = (*bi).second;
   }
   else {
      vpi = new vector<BasicProject*>;
      basicProjects[hash] = vpi;
   }
   BasicProject *p = new BasicProject(lpid, desc);
   vpi->push_back(p);
   gpid_lpid_map[gpid] = lpid;
   lpid_gpid_map[lpid] = gpid;
   pid_project_map[lpid] = p;
   sem_post(&pidLock);

   p->pub = pub;
   p->sub = sub;
   p->hash = hash;
   p->gpid = gpid;

   return lpid;
}

/**
 * exportProject dumps all project updates
 * @param pid the local project id of the prject to be exported
 */

json_object *BasicConnectionManager::exportProject(uint32_t pid) {
   BasicProject *p = findProject(pid);
   if (p == NULL) {
      return NULL;
   }
   json_object *updates = json_object_new_array();
   const vector<char*> &vu = p->get_updates();
   for (vector<char*>::const_iterator vi = vu.cbegin(); vi != vu.cend(); vi++) {
      json_object *obj = json_tokener_parse(*vi);
      json_object_array_add(updates, obj);
   }
   return updates;
}

//Find a project given only an lpid
BasicProject *BasicConnectionManager::findProject(uint32_t lpid) {
   BasicProject *p = NULL;
   sem_wait(&mapLock);
   map<uint32_t,BasicProject*>::iterator pi = pid_project_map.find(lpid);
   if (pi != pid_project_map.end()) {
      p = (*pi).second;
   }
   sem_wait(&mapLock);
   return p;
}

/**
 * addProject adds a project to the database and reflector (or merely a reflector in non-DB mode)
 * @param c cliend invoking the addProject
 * @param hash unique hash for the binary file originally generated by IDA
 * @param desc user provided description of the project
 * @param pub the publish permissions for the project
 * @param sub the subscribe permissions for the project
 * @return the new project id on success, -1 on failure
 */

int BasicConnectionManager::addProject(Client *c, const string &hash, const string &desc, uint64_t pub, uint64_t sub) {
   log(LDEBUG, "in addProject, hash = %s\n", hash.c_str());
   int lpid;
//   int uid = c->getUid();
   string gpid;
   //log(LINFO1, "incrementing basic mode pid to : %u\n", basicmodepid);
   sem_wait(&pidLock);
   lpid = basicmodepid++;
   map<string,vector<BasicProject*>*>::iterator bi = basicProjects.find(hash);
   vector<BasicProject*> *vpi;
   if (bi != basicProjects.end()) {
      vpi = (*bi).second;
   }
   else {
      vpi = new vector<BasicProject*>;
      basicProjects[hash] = vpi;
   }
   BasicProject *p = new BasicProject(lpid, desc);
   vpi->push_back(p);
   gpid_lpid_map[gpid] = lpid;
   lpid_gpid_map[lpid] = gpid;
   pid_project_map[lpid] = p;
   sem_post(&pidLock);

   p->pub = pub;
   p->sub = sub;
   p->hash = hash;

   uint8_t gpid_bytes[32];
   fill_random(gpid_bytes, sizeof(gpid_bytes));
   gpid = toHexString(gpid_bytes, sizeof(gpid_bytes));
   p->gpid = gpid;

   log(LINFO, "BASIC mode has no notion of users, setting permissions based on REQ\n");
   c->setGpid(gpid);
   c->setPid(lpid);
   c->setPub(FULL_PERMISSIONS);
   c->setSub(FULL_PERMISSIONS);
   c->setUserPub(FULL_PERMISSIONS);
   c->setUserSub(FULL_PERMISSIONS);
   c->setReqPub(FULL_PERMISSIONS);
   c->setReqSub(FULL_PERMISSIONS);

   if (lpid != -1) {
      projects.addClient(c);
   }

   return lpid;
}

/**
 * lpid2gpid converts an lpid (pid local to a particular server instance)
 * to a gpid (which is unique across all projects on all servers)
 * @param lpid the local pid for this particular server
 * @return the glocabl pid
 */
string BasicConnectionManager::lpid2gpid(int lpid) {
   string gpid;
   sem_wait(&mapLock);
   if (lpid_gpid_map.find(lpid) != lpid_gpid_map.end()) {
      gpid = lpid_gpid_map[lpid];
   }
   sem_post(&mapLock);
   return gpid;
}

int BasicConnectionManager::gpid2lpid(const string &gpid) {
   uint32_t lpid = INVALID_PID;
   sem_wait(&mapLock);
   if (gpid_lpid_map.find(gpid) != gpid_lpid_map.end()) {
      lpid = gpid_lpid_map[gpid];
   }
   sem_post(&mapLock);
   return lpid;
}

