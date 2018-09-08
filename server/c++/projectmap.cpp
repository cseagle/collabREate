/*
   collabREate projectmap.cpp
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

#include "client.h"
#include "projectmap.h"
#include "clientset.h"

ProjectMap::ProjectMap() {
   pthread_mutexattr_t attr;
   pthread_mutexattr_init(&attr);
   pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
   pthread_mutex_init(&mutex, &attr);
   pthread_mutexattr_destroy(&attr);
}

ProjectMap::~ProjectMap() {
   pthread_mutex_destroy(&mutex);
}

//iterate over all projects in the set
void ProjectMap::loop(pcb func, void *user) {
   pthread_mutex_lock(&mutex);
   for (map<uint32_t,ClientSet*>::iterator i = projects.begin(); i != projects.end(); i++) {
      ClientSet *s = (*i).second;
      if (!(*func)(s, user)) {
         break;
      }
   }
   pthread_mutex_unlock(&mutex);
}

//loop across all clients in a single project
void ProjectMap::loopProject(uint32_t key, ccb func, void *user) {
   ClientSet *s = get(key);
   if (s) {
      s->loop(func, user);
   }
}

//loop across all clients in all projects
void ProjectMap::loopClients(ccb func, void *user) {
   pthread_mutex_lock(&mutex);
   for (map<uint32_t,ClientSet*>::iterator i = projects.begin(); i != projects.end(); i++) {
      ClientSet *s = (*i).second;
      s->loop(func, user);
   }
   pthread_mutex_unlock(&mutex);
}

//add a new project
void ProjectMap::put(uint32_t key, ClientSet *val) {
   pthread_mutex_lock(&mutex);
   projects[key] = val;
   pthread_mutex_unlock(&mutex);
}

//call this only if you already hold a lock
ClientSet *ProjectMap::getPriv(uint32_t key) {
   ClientSet *res = NULL;
   map<uint32_t,ClientSet*>::iterator it = projects.find(key);
   if (it != projects.end()) {
      res = (*it).second;
   }
   return res;
}

//add client to the given project
void ProjectMap::addClient(uint32_t key, Client *c) {
   pthread_mutex_lock(&mutex);
   ClientSet *proj = getPriv(key);
   if (proj == NULL) {
      proj = new ClientSet;
      //already have a lock don't neet to call put
      projects[key] = proj;
   }
   proj->add(c);
   pthread_mutex_unlock(&mutex);
}

//add client to the given project
void ProjectMap::addClient(Client *c) {
   pthread_mutex_lock(&mutex);
   ClientSet *proj = getPriv(c->getPid());
   if (proj == NULL) {
      proj = new ClientSet;
      //already have a lock don't neet to call put
      projects[c->getPid()] = proj;
   }
   proj->add(c);
   pthread_mutex_unlock(&mutex);
}

//add client to the given project
void ProjectMap::removeClient(Client *c) {
   pthread_mutex_lock(&mutex);
   ClientSet *proj = getPriv(c->getPid());
   if (proj != NULL) {
      proj->remove(c);
   }
   pthread_mutex_unlock(&mutex);
}

//number of clients connected to the given project
int ProjectMap::numClients(uint32_t key) {
   int res = 0;
   pthread_mutex_lock(&mutex);
   ClientSet *proj = getPriv(key);
   if (proj != NULL) {
      res = proj->size();
   }
   pthread_mutex_unlock(&mutex);
   return res;
}

//get the list of clients connected to the given project
//should this be a cloned set ?? probably
ClientSet *ProjectMap::get(uint32_t key) {
   ClientSet *res = NULL;
   pthread_mutex_lock(&mutex);
   map<uint32_t,ClientSet*>::iterator it = projects.find(key);
   if (it != projects.end()) {
      res = (*it).second;
   }
   pthread_mutex_unlock(&mutex);
   return res;
}

