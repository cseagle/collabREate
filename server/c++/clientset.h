/*
   collabREate clientset.h
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

#ifndef __CLIENT_SET_H
#define __CLIENT_SET_H


#include <map>
#include <vector>
#include <set>
#include <string>
#include <stdint.h>
#include <sys/types.h>
#include <pthread.h>

class Client;

using namespace std;

typedef bool (*cb)(Client *c, void *user);

class ClientSet {
private:
   set<Client*> clients;
   pthread_mutex_t mutex;
   
public:
   ClientSet();
   ~ClientSet();

   void add(Client *c);
   void remove(Client *c);
   void loop(cb func, void *user);
   int size();

};


#endif
