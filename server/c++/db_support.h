/*
   collabREate db_support.h
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

#ifndef __DB_SUPPORT_H
#define __DB_SUPPORT_H

#include <map>
#include <stdint.h>
#include <libpq-fe.h>
#include <semaphore.h>

#include "cli_mgr.h"
#include "client.h"
#include "proj_info.h"

using namespace std;

class DatabaseConnectionManager : public ConnectionManagerBase {
public:
   DatabaseConnectionManager(map<string,string> *p);
   ~DatabaseConnectionManager();
   
   int authenticate(Client *c, const char *user, const uint8_t *challenge, uint32_t clen, const uint8_t *response, uint32_t rlen);
   void migrateUpdate(int newowner, int pid, int cmd, const uint8_t *data, int dlen);
   void post(Client *src, int cmd, uint8_t *data, int dlen);
   void sendLatestUpdates(Client *c, uint64_t lastUpdate);
   ProjectInfo *getProjectInfo(int pid);

   vector<ProjectInfo*> *getProjectList(const string & phash);
   int joinProject(Client *c, int lpid);
   int snapProject(Client *c, uint64_t lastupdateid, const string &desc);
   int forkProject(Client *c, uint64_t lastupdateid, const string &desc);
   int forkProject(Client *c, uint64_t lastupdateid, const string &desc, uint64_t pub, uint64_t sub);
   void sendForkFollows(Client *originator, int oldlpid, uint64_t lastupdateid, const string &desc);
   int snapforkProject(Client *c, int spid, const string &desc, uint64_t pub, uint64_t sub);
   int migrateProject(int owner, const string &gpid, const string &hash, const string &desc, uint64_t pub, uint64_t sub);
   int addProject(Client *c, const string &hash, const string &desc, uint64_t pub, uint64_t sub);
   void updateProjectPerms(Client *c, uint64_t pub, uint64_t sub);
   int gpid2lpid(const string &gpid);
   string lpid2gpid(int lpid);

private:
   void init_queries();
   
   sem_t pu_sem;
   sem_t ap_sem;
   sem_t aps_sem;
   sem_t apf_sem;
   sem_t fpbh_sem;
   sem_t fpbp_sem;
   sem_t fpbg_sem;
   sem_t gui_sem;
   sem_t glu_sem;
   sem_t cu_sem;
   sem_t ppu_sem;

   PGconn *dbConn;
};

#endif

