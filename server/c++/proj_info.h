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

#ifndef __HANDLER_H
#define __HANDLER_H

#include <stdint.h>
#include <string>

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

   ProjectInfo(uint32_t localpid, const string &description, uint32_t currentlyconnected = 0);
   ProjectInfo(const ProjectInfo &pi);
   
};

#endif
