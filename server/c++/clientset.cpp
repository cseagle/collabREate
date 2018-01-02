/*
   collabREate clientset.cpp
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
#include "clientset.h"

typedef set<Client*>::iterator Client_it;

ClientSet::ClientSet() {
   pthread_mutexattr_t attr;
   pthread_mutexattr_init(&attr);
   pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
   pthread_mutex_init(&mutex, &attr); 
   pthread_mutexattr_destroy(&attr);
}

ClientSet::~ClientSet() {
   pthread_mutex_destroy(&mutex);
}

//add a new client
void ClientSet::add(Client *c) {
   pthread_mutex_lock(&mutex);
   clients.insert(c);
   pthread_mutex_unlock(&mutex);
}

//remove a client
void ClientSet::remove(Client *c) {
   pthread_mutex_lock(&mutex);
   clients.erase(c);
   pthread_mutex_unlock(&mutex);
}

//iterate over all clients in the set
void ClientSet::loop(cb func, void *user) {
   pthread_mutex_lock(&mutex);
   for (Client_it i = clients.begin(); i != clients.end(); i++) {
      Client *c = *i;
      if (!(*func)(c, user)) {
         break;
      }
   }
   pthread_mutex_unlock(&mutex);
}

//return the size of the client set
int ClientSet::size() {
   pthread_mutex_lock(&mutex);
   int res = clients.size();
   pthread_mutex_unlock(&mutex);
   return res;
}

