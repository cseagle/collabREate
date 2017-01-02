/*
   collabREate proj_info.cpp
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

#include "proj_info.h"

ProjectInfo::ProjectInfo(uint32_t localpid, const string &description, uint32_t currentlyconnected) {
   lpid = localpid;
   desc = description;
   connected = currentlyconnected;
   parent = 0;
   pdesc = "";
   snapupdateid = 0;
   pub = sub = 0;
   proto = 0;
   hash = "";
   gpid = "";
}

ProjectInfo::ProjectInfo(const ProjectInfo &pi) {
   *this = pi;
}
