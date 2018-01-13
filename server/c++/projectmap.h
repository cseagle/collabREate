/*
   collabREate projectmap.h
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

#ifndef __PROJECT_MAP_H
#define __PROJECT_MAP_H

#include <map>
#include <vector>
#include <set>
#include <string>
#include <stdint.h>
#include <sys/types.h>
#include <pthread.h>

class ClientSet;
class Client;

using namespace std;

//project callback function
typedef bool (*pcb)(ClientSet *c, void *user);
//client callback function
typedef bool (*ccb)(Client *c, void *user);

class ProjectMap {
private:
   map<int,ClientSet*> projects;
   pthread_mutex_t mutex;

   ClientSet *getPriv(int key);

public:
   ProjectMap();
   ~ProjectMap();

   void put(int key, ClientSet *val);
   void addClient(int key, Client *c);
   void addClient(Client *c);
   void removeClient(Client *c);
   ClientSet *get(int key);
   int numClients(int key);
   //loop across all projects
   void loop(pcb func, void *user);
   //loop across all clients in a single project
   void loopProject(int key, ccb func, void *user);
   //loop across all clients in all projects
   void loopClients(ccb func, void *user);

};

#endif
