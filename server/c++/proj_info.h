/*
   collabREate proj_info.h
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

#ifndef __PROJ_INFO_H
#define __PROJ_INFO_H

#include <stdint.h>
#include <semaphore.h>
#include <string>
#include <vector>

using namespace std;

class ProjectInfo {
public:
   uint32_t lpid;
   string desc;
   uint32_t connected;
   int32_t parent;
   string pdesc;
   uint64_t snapupdateid;
   uint64_t pub;
   uint64_t sub;
   string owner;
   uint32_t proto;
   string hash;
   string gpid;

   ProjectInfo(uint32_t localpid, const string &description, uint32_t currentlyconnected = 0, uint64_t init_uid = 0);
   ProjectInfo(const ProjectInfo &pi);
   ~ProjectInfo();

   uint64_t next_uid();
   uint64_t curr_uid();

   void append_update(const char *update);
   const vector<char*> &get_updates() {return updates;};

private:
   sem_t uidMutex;
   uint64_t updateid;

   vector<char*> updates;

};

#endif
