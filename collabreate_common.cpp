/*
    Collabreate common user interface functions
    Copyright (C) 2008 Chris Eagle <cseagle at gmail d0t com>
    Copyright (C) 2008 Tim Vidas <tvidas at gmail d0t com>


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

#include "collabreate.h"

#include <pro.h>
#include <kernwin.hpp>

#include <string.h>
#include <netnode.hpp>
#include <nalt.hpp>
#include <md5.h>

#include "sdk_versions.h"

#if IDA_SDK_VERSION < 500
#include <fpro.h>
#endif

bool publish  = true;
bool userPublish  = true;
bool subscribe = true;

char username[64];
static unsigned char pwhash[16];

//global pointer to the incoming project list buffer.  Used to fill
//the project list dialog
//static Buffer *projectBuffer;

//global buffer that receives the description of the project selected
//by the user.
static char description[1024];
//global array of integer project ids that map to the project 
//descriptions sent by the server.
int *projects;
uint64_t *snapUpdateIDs;
Options *optMasks;
int numProjectsGlobal = 0;
int isSnapShotGlobal = 0;
int numOptionsGlobal = 0;

char **optLabels = NULL;

//global used to hold user's selected project permissions
Options userOpts = { {0xffffffffffffffffll}, {0xffffffffffffffffll}};
Options tempOpts; //temporary

//Caution: returns a pointer to a static string
char *formatOptVal(OptVal *val) {
   static char buf[24];
   ::qsnprintf(buf, sizeof(buf), "%08x%08x", val->ii[1], val->ii[0]);
   return buf;
}

char *formatLongLong(uint64_t val) {
   OptVal v;
   v.ll = val;
   return formatOptVal(&v);
}

//Caution: returns a pointer to a static string
char *formatOptVal(OptVal *val, char *buf) {
   ::qsnprintf(buf, sizeof(buf), "%08x%08x", val->ii[1], val->ii[0]);
   return buf;
}

char *formatLongLong(uint64_t val, char *buf) {
   OptVal v;
   v.ll = val;
   return formatOptVal(&v, buf);
}

/*
 * Function: hmac_md5
 */

void hmac_md5(unsigned char *msg, int msg_len, 
              unsigned char *key, int key_len,
              unsigned char *digest) {
   MD5Context ctx;
   unsigned char ipad[64];
   unsigned char opad[64];
   unsigned char tk[MD5_LEN];
   int i;
   if (key_len > 64) {
      MD5Init(&ctx);
      MD5Update(&ctx, key, key_len);
      MD5Final(tk, &ctx);
      key = tk;
      key_len = MD5_LEN;
   }
   
   /* start out by storing key in pads */
   memset(ipad, 0, sizeof(ipad));
   memcpy(ipad, key, key_len);
   memcpy(opad, ipad, sizeof(opad));
   
   /* XOR key with ipad and opad values */
   for (i = 0; i < 64; i++) {
      ipad[i] ^= 0x36;
      opad[i] ^= 0x5c;
   }
   /*
   * perform inner MD5
   */
   MD5Init(&ctx);
   MD5Update(&ctx, ipad, 64);
   MD5Update(&ctx, msg, msg_len);
   MD5Final(digest, &ctx);
   /*
   * perform outer MD5
   */
   MD5Init(&ctx);
   MD5Update(&ctx, opad, 64);
   MD5Update(&ctx, digest, MD5_LEN);
   MD5Final(digest, &ctx);
   memset(ipad, 0, sizeof(ipad));
   memset(opad, 0, sizeof(opad));
}

void saveAuthData(char *user, char *pass) {
   ::qstrncpy(username, user, sizeof(username));

   cnn.supset(LAST_USER_SUPVAL, user);

   size_t pwlen = strlen(pass);

   MD5Context ctx;
   MD5Init(&ctx);
   MD5Update(&ctx, (unsigned char*)pass, pwlen);
   MD5Final(pwhash, &ctx);
}

int chooseProject(int index, char *desc) {
   if (index == 0) { // new project
      ::qstrncpy(description, desc, sizeof(description));
   }
   if (index > 0) {
      if (numProjectsGlobal > 1) {
         if (snapUpdateIDs[index - 1] > 0) {
            ::qstrncpy(description, desc, sizeof(description));               
            isSnapShotGlobal = 1;
         }
      }
      index = projects[index - 1];
   }

   //there is still some value in keeping these as they limit the
   //amount of traffic the client will generate to some extent
#ifdef DEBUG
   msg("   publish bits are 0x%s\n", formatOptVal(&userOpts.pub));
   msg("   subscribe bits are 0x%s\n", formatOptVal(&userOpts.sub));
#endif
   publish = userPublish = userOpts.pub.ll != 0;
   subscribe = userOpts.sub.ll != 0;
   //remember these as the current options
   setUserOpts(userOpts);
   return index;
}

bool changeProject(int index) {
   bool result = true;    //whether to enable description or not
   if (index == 0) {   //New project
      //enable all persmissions for new projects
      memset(&userOpts, 0xFF, sizeof(userOpts));
   }
   else if (numProjectsGlobal > 0) {
      if (snapUpdateIDs[index - 1] != 0) {
         //enable all persmissions for new projects
         memset(&userOpts, 0xFF, sizeof(userOpts));
      }
      else {
         userOpts = optMasks[index - 1];
         result = false;
      }
   }
   else {
      //unreachable?
      msg(PLUGIN_NAME": unknown desc window state entered, please tell developers\n");
      result = false;
   }
   return result;
}

//the order of these is important, the callback returns the ordinal of the selected string
const char *runCommands[] = {
   "Fork project",
   "Set checkpoint",
   "Manage requested permissions",
   "Manage project permissions (owner only)",
#ifdef DEBUG
   "Disconnect from server",
   "Show collab netnode",
   "Clean collab netnode"
#else
   "Disconnect from server"
#endif
};

const char *getRunCommand(int i) {
   int max = sizeof(runCommands) / sizeof(runCommands[0]);
   if (i < 0 || i >= max) {
      return NULL;
   }
   return runCommands[i];
}

//sz should be 32 and gpid should be large enough
//returns -1 if no value exists
int getGpid(unsigned char *gpid, int sz) {
   return (int)cnn.supval(GPID_SUPVAL, gpid, sz);
}

//sz should be 32 and gpid should be large enough
void setGpid(unsigned char *gpid, int sz) {
   cnn.supset(GPID_SUPVAL, gpid, sz);
}

bool getFileMd5(unsigned char *md5, int len) {
   if (len < MD5_LEN) {
      return false;
   }
   
#if IDA_SDK_VERSION >= 500
   retrieve_input_file_md5(md5);
#else
#define RIDX_MD5                  1302  //MD5 of the input file
   if (RootNode.supval(RIDX_MD5, md5, MD5_LEN) != MD5_LEN) {
      char buf[512];
      get_input_file_path(buf, sizeof(buf));
      FILE *f = qfopen(buf, "rb");
      if (f) {
         MD5Context ctx;
         MD5Init(&ctx);
         int len;
         while ((len = qfread(f, buf, sizeof(buf))) > 0) {
            MD5Update(&ctx, (unsigned char*)buf, len);
         }
         MD5Final(md5, &ctx);
         RootNode.supset(RIDX_MD5, md5, MD5_LEN);
         qfclose(f);
      }
      else {
         //failed to open input file
         return false;
      }
   }
#endif
   return true;
}

void do_project_rejoin() { //(unsigned char * gpid) {
   Buffer b;
   b.writeInt(MSG_PROJECT_REJOIN_REQUEST);
   unsigned char gpid[GPID_SIZE];
   if (getGpid(gpid, sizeof(gpid)) && getUserOpts(userOpts)) {
      b.write(gpid, sizeof(gpid));
      b.writeLong(userOpts.pub.ll);
      b.writeLong(userOpts.sub.ll);
      send_data(b);
   }
}

void sendProjectLeave() {
   Buffer b;
   b.writeInt(MSG_PROJECT_LEAVE);
   send_data(b);
}

void do_project_leave() {
   sendProjectLeave();
}

//void do_clean_netnode( void ) {
//}

void sendProjectChoice(int project) {
   Buffer b;
   b.writeInt(MSG_PROJECT_JOIN_REQUEST);
   b.writeInt(project);
   b.writeLong(userOpts.pub.ll);
   b.writeLong(userOpts.sub.ll);
   send_data(b);
}

void sendProjectSnapFork(int project, char *desc) {
   Buffer b;
   b.writeInt(MSG_PROJECT_SNAPFORK_REQUEST);
   b.writeInt(project);
   b.writeUTF8(desc);
   b.writeLong(userOpts.pub.ll);
   b.writeLong(userOpts.sub.ll);
   send_data(b);
}

void sendProjectGetList() {
   Buffer b;
   b.writeInt(MSG_PROJECT_LIST);
   unsigned char md5[MD5_LEN];
   if (getFileMd5(md5, sizeof(md5))) {
      b.write(md5, sizeof(md5));
      send_data(b);
   }
}

void sendNewProjectCreate(char *description) {
   Buffer b;
   b.writeInt(MSG_PROJECT_NEW_REQUEST);
   unsigned char md5[MD5_LEN];
   if (getFileMd5(md5, sizeof(md5))) {
      b.write(md5, sizeof(md5));
      b.writeUTF8(description);
      b.writeLong(userOpts.pub.ll);
      b.writeLong(userOpts.sub.ll);
      send_data(b);
   }
}

void sendReqPermsChoice() {
   Buffer b;
   b.writeInt(MSG_SET_REQ_PERMS);
   b.writeLong(tempOpts.pub.ll);
   b.writeLong(tempOpts.sub.ll);
   send_data(b);
}

void sendProjPermsChoice() {
   Buffer b;
   b.writeInt(MSG_SET_PROJ_PERMS);
   b.writeLong(tempOpts.pub.ll);
   b.writeLong(tempOpts.sub.ll);
   send_data(b);
}

void freeProjectFields() {
   qfree(snapUpdateIDs);
   snapUpdateIDs = NULL;
   qfree(projects);
   projects = NULL;
   qfree(optMasks);
   optMasks = NULL;

   for (int i = 0; i < numOptionsGlobal; i++) {
      qfree(optLabels[i]);
   }
   qfree(optLabels);
   optLabels = NULL;
}

void selectProject(int index) {
   if (index == NEW_PROJECT_INDEX) {
#ifdef DEBUG
      msg(PLUGIN_NAME": new project selected: %s\n", description);
#endif
      sendNewProjectCreate(description);
   }
   //else if (snapUpdateIDs[index + 1] != 0) {
   else if (isSnapShotGlobal == 1) {
#ifdef DEBUG
      msg(PLUGIN_NAME": snapshot %d selected\n", index);
#endif
      sendProjectSnapFork(index, description);
   }
   else {
#ifdef DEBUG
      msg(PLUGIN_NAME": project %d selected\n", index);
#endif
      sendProjectChoice(index);
   }
}

//pwhash and username must be set previously
void sendAuthData(unsigned char *challenge, int challenge_len) {
   uchar hmac[16];
#ifdef DEBUG
   msg(PLUGIN_NAME": computing hmac\n");
#endif   
   hmac_md5(challenge, challenge_len, pwhash, sizeof(pwhash), hmac);
   memset(pwhash, 0, sizeof(pwhash));
   
   //connection to server successful.
   Buffer auth;
   auth.writeInt(MSG_AUTH_REQUEST);
   //send plugin protocol version
   auth.writeInt(PROTOCOL_VERSION);
   //send user name
   auth.writeUTF8(username);
   //send hmac
   auth.write(hmac, sizeof(hmac));
#ifdef DEBUG
   msg(PLUGIN_NAME": sending auth data buffer\n");
#endif   
   send_data(auth);
}

void do_get_req_perms(Buffer &b) {
   //display permission selection UI
   //tempOpts.pub = 0xAAAAAAAA;
   //tempOpts.sub = 0x55555555;
   if (do_choose_perms(b)) {
      sendReqPermsChoice();
   }
}

void do_get_proj_perms(Buffer &b) {
   //display permission selection UI
   //tempOpts.pub = 0xAAAAAAAA;
   //tempOpts.sub = 0x55555555;
//   Options oldOpts = tempOpts;
   if (do_choose_perms(b)) {
      //only call this if perms actually changed
      sendProjPermsChoice();
   }
}

void do_send_user_message(const char *msg) {
   Buffer b;
   uint32_t len = 80 + strlen(msg);
   char *m = new char[len];
   ::qsnprintf(m, len, "< %s> %s", username, msg);
   char *cr = m + strlen(m) - 1;
   while (*cr == '\n' || *cr == '\r') {
      *cr-- = 0;
   }
   b.writeInt(COMMAND_USER_MESSAGE);
   time_t t;
   time(&t);
   b.writeInt((int)t);
   b.writeUTF8(m);
   delete [] m;
   send_data(b);
}

