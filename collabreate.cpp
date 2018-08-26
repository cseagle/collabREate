/*
    IDA Pro Collabreation/Synchronization Plugin
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
/*
 *  This is the collabREate plugin
 *
 *  It is known to compile with
 *
 *   Microsoft Visual C++ 2013+
 *   Linux/OSX make and g++/clang
 *
 */

#include "collabreate.h"

#ifdef _WIN32
#include <windows.h>
#endif

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <netnode.hpp>
#include <typeinf.hpp>
#include <struct.hpp>
#if IDA_SDK_VERSION < 700
#include <area.hpp>
#else
#include <range.hpp>
#endif
#include <frame.hpp>
#include <segment.hpp>
#include <enum.hpp>
#include <xref.hpp>
#include <nalt.hpp>
#include <offset.hpp>
#include <auto.hpp>

#include <json-c/json.h>

#include <map>
#include <string>
using std::map;
using std::string;

#include "collabreate_ui.h"

bool authenticated = false;
bool fork_pending = false;

//bool supress = false;

static bool isHooked = false;
void hookAll();
void unhookAll();

//where we stash collab specific infoze
netnode cnn(COLLABREATE_NETNODE, 0, true);
qstrvec_t msgHistory;
qstring *changeCache = NULL;

#ifndef DEBUG
//#define DEBUG 1
#endif

//Save the user options bits into our netnode
bool setUserOpts(Options &user) {
   return cnn.supset(OPTIONS_SUPVAL, &user, sizeof(Options));
}

//Load the user options bits from our netnode
bool getUserOpts(Options &user) {
   return cnn.supval(OPTIONS_SUPVAL, &user, sizeof(Options)) != 0;
}

//Load the last update id from our netnode
uint64_t getLastUpdate() {
   uint64_t val = 0;
   cnn.supval(LASTUPDATE_SUPVAL, &val, sizeof(val));
#ifdef DEBUG
   msg(PLUGIN_NAME": lastupdate supval is 0x%s\n", formatLongLong(val));
#endif
   return val;
}

//localize writes to LASTUPDATE_SUPVAL to a single function
void writeUpdateValue(uint64_t uid) {
   cnn.supset(LASTUPDATE_SUPVAL, &uid, sizeof(uid));
}

//Save an update id only if it is larger than the most recently saved id
void setLastUpdate(uint64_t uid) {
   if (uid > getLastUpdate()) {
#ifdef DEBUG
      msg(PLUGIN_NAME": ## setting last update to 0x%s ##\n", formatLongLong(uid));
#endif
      writeUpdateValue(uid);
   }
}

//array that holds counters of all the commands that have been sent and
//received in the current session
int stats[2][MSG_IDA_MAX + 1];

//hook to all ida notification types
void hookAll() {
   if (isHooked) return;
   if (userPublish) { //the only reason to hook is if we are publishing
      hook_to_notification_point(HT_IDP, idp_hook, NULL);
//      hook_to_notification_point(HT_UI, ui_hook, NULL);
      hook_to_notification_point(HT_IDB, idb_hook, NULL);
   }
   isHooked = true;
}

//unhook from all ida notification types
void unhookAll() {
//   msg("unhookAll called\n");
   if (!isHooked) return;
   if (userPublish) { //the only reason to unhook is if we are publishing
      unhook_from_notification_point(HT_IDP, idp_hook, NULL);
//      unhook_from_notification_point(HT_UI, ui_hook, NULL);
      unhook_from_notification_point(HT_IDB, idb_hook, NULL);
   }
   isHooked = false;
}

//--------------------------------------------------------------------------
//
//      Initialize.
//
//      IDA will call this function only once.
//      If this function returns PLGUIN_SKIP, IDA will never load it again.
//      If this function returns PLUGIN_OK, IDA will unload the plugin but
//      remember that the plugin agreed to work with the database.
//      The plugin will be loaded again if the user invokes it by
//      pressing the hotkey or selecting it from the menu.
//      After the second load the plugin will stay on memory.
//      If this function returns PLUGIN_KEEP, IDA will keep the plugin
//      in the memory. In this case the initialization function can hook
//      into the processor module and user interface notification points.
//      See the hook_to_notification_point() function.
//
//      In this example we check the input file format and make the decision.
//      You may or may not check any other conditions to decide what you do:
//      whether you agree to work with the database or not.
//
int idaapi init(void) {
   unsigned char md5[MD5_LEN];
   msg(PLUGIN_NAME": collabREate has been loaded\n");
   //while the md5 is not used here, it has the side effect of ensuring
   //that the md5 is taken at the earliest opportunity for storage in
   //the database in the event that the original binary is deleted
   getFileMd5(md5, sizeof(md5));
   unsigned char gpid[GPID_SIZE];
   ssize_t sz = getGpid(gpid, sizeof(gpid));
   if (sz > 0) {
      msg(PLUGIN_NAME": Operating in caching mode until connected.\n");
      if (changeCache == NULL) {
         size_t sz;
         void *tcache = cnn.getblob(NULL, &sz, 1, COLLABREATE_CACHE_TAG);
         if (sz > 0) {
            changeCache = new qstring((char*)tcache);
         }
         else {
            changeCache = new qstring();
         }
         qfree(tcache);
         hookAll();
      }
   }
   if (msgHistory.size() == 0) {
      size_t sz;
      void *thist = cnn.getblob(NULL, &sz, 1, COLLABREATE_MSGHISTORY_TAG);
      if (sz > 1) {
         char *sptr, *endp;
         sptr = (char*)thist;
         while ((endp = strchr(sptr, '\n')) != NULL) {
            msgHistory.push_back(qstring(sptr, endp - sptr));
            sptr = endp + 1;
         }
      }
      qfree(thist);
   }
   build_handler_map();
   if (init_network()) {
      return PLUGIN_KEEP;
   }
   else {
      return PLUGIN_SKIP;
   }
}

//--------------------------------------------------------------------------
//      Terminate.
//      Usually this callback is empty.
//      The plugin should unhook from the notification lists if
//      hook_to_notification_point() was used.
//
//      IDA will call this function when the user asks to exit.
//      This function won't be called in the case of emergency exits.

void idaapi term(void) {
   msg(PLUGIN_NAME": collabREate is being unloaded\n");
   authenticated = false;
   if (is_connected()) {
      msg(PLUGIN_NAME": calling cleanup\n");
      cleanup();
      msg(PLUGIN_NAME": back from cleanup\n");
   }
   msg(PLUGIN_NAME": closing status form\n");
   close_chooser("Collab form:1");
   msg(PLUGIN_NAME": status form closed\n");
   if (msgHistory.size() > 0) {
      qstring temp;
      for (unsigned int i = 0; i < msgHistory.size(); i++) {
         temp += msgHistory[i];
         temp += '\n';
      }
      cnn.setblob(temp.c_str(), temp.length() + 1, 1, COLLABREATE_MSGHISTORY_TAG);
      msgHistory.clear();
   }
   if (changeCache != NULL && changeCache->length() > 0) {
      cnn.setblob(changeCache->c_str(), changeCache->length() + 1, 1, COLLABREATE_CACHE_TAG);
      delete changeCache;
      changeCache = NULL;
   }
   unhookAll();
}

//--------------------------------------------------------------------------
//
//      The plugin method
//
//      This is the main function of plugin.
//
//      It will be called when the user activates the plugin.
//
//              arg - the input argument, it can be specified in
//                    plugins.cfg file. The default is zero.

#if IDA_SDK_VERSION < 700
void idaapi run(int /*arg*/) {
#else
bool idaapi run(size_t /*arg*/) {
#endif
   bool result = true;
   if (is_connected()) {
#if IDA_SDK_VERSION < 700
      char *desc;
#else
      qstring desc;
#endif
      int cmd = do_choose_command();
      msg("User chose command %d\n", cmd);
      switch (cmd) {
         case USER_FORK:
#if IDA_SDK_VERSION < 700
            desc = askstr(HIST_CMT, "", "Please enter a forked project description");
            if (desc) {
#else
            if (ask_str(&desc, HIST_CMT, "Please enter a forked project description")) {
#endif
               json_object *obj = json_object_new_object();
               append_json_uint64_val(obj, "last_update", getLastUpdate());
               append_json_string_val(obj, "description", desc);
               send_json(MSG_PROJECT_FORK_REQUEST, obj);
               fork_pending = true;  //flag to temporarily disable updates
               unhookAll();  //will rehook when new project is joined
            }
            msg(PLUGIN_NAME": Fork request sent.\n");
            break;
         case USER_CHECKPOINT:
#if IDA_SDK_VERSION < 700
            desc = askstr(HIST_CMT, "", "Please enter a checkpoint description");
            if (desc) {
#else
            if (ask_str(&desc, HIST_CMT, "Please enter a checkpoint description")) {
#endif
               json_object *obj = json_object_new_object();
               append_json_uint64_val(obj, "last_update", getLastUpdate());
               append_json_string_val(obj, "description", desc);
               send_json(MSG_PROJECT_SNAPSHOT_REQUEST, obj);
            }
            msg(PLUGIN_NAME": Checkpoint request sent.\n");
            break;
         case USER_PERMS: {
            json_object *obj = json_object_new_object();
            send_json(MSG_GET_REQ_PERMS, obj);
            //allow user to edit their requested permissions for the project
            break;
         }
         case PROJECT_PERMS: {
            json_object *obj = json_object_new_object();
            send_json(MSG_GET_PROJ_PERMS, obj);
            //allow an owner to edit the default permissions for the project
            break;
         }
#ifdef DEBUG
         case SHOW_NETNODE: {
            unsigned char sgpid[GPID_SIZE];
            memset( sgpid, 0, sizeof(sgpid));
            ssize_t sz= getGpid(sgpid, sizeof(sgpid));
            if (sz > 0) {
               msg(PLUGIN_NAME": Netnode gpid: ");
               unsigned char * gpidptr = sgpid;
               for(uint32_t i = 0; i < sizeof(sgpid); i++) {
                  msg("%x", *gpidptr++);
               }
               msg("\n");
               uint64_t last = getLastUpdate();
               msg(PLUGIN_NAME": Netnode lastUpdate: %s\n", formatLongLong(last));
            }
            else {
               msg(PLUGIN_NAME": GPID not found in netnode. hrm...\n");
            }
            break;
         }
         case CLEAN_NETNODE: {
            unsigned char egpid[GPID_SIZE];
            memset( egpid, 0, sizeof(egpid));
            setGpid(egpid, sizeof(egpid));
            writeUpdateValue(0);
            //do_clean_netnode();  //maybe put in _ui.cpp
            break;
         }
#endif
         case USER_DISCONNECT: {
            authenticated = false;
            msg(PLUGIN_NAME": De-activating collabREate\n");
            cleanup();
            unhookAll();
            msg(PLUGIN_NAME": command   rx   tx\n");
            for (int i = 0; i <= MSG_IDA_MAX; i++) {
               if (stats[0][i] || stats[1][i]) {
                  msg(PLUGIN_NAME": %5d   %4d %4d\n", i, stats[0][i], stats[1][i]);
               }
            }
            break;
         }
      }
   }
   else {
      authenticated = false;
      memset(stats, 0, sizeof(stats));
      if (do_connect(msg_dispatcher)) {
         msg(PLUGIN_NAME": collabREate activated\n");
#if IDA_SDK_VERSION >= 600
         createCollabStatus();
#endif
      }
      else {
         warning("collabREate failed to connect to server\n");
         result = false;
      }
   }
#if IDA_SDK_VERSION >= 700
   return result;
#endif
}

//--------------------------------------------------------------------------
//char comment[] = "This is a skeleton plugin. It doesn't do a thing.";
char *comment = NULL;
char *help = NULL;

//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

char wanted_name[] = "collabREate";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overriden in plugins.cfg file
// Note: IDA won't tell you if the hotkey is not correct
//       It will just disable the hotkey.

char wanted_hotkey[] = "Alt-F6";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN = {
  IDP_INTERFACE_VERSION,
  0,                    // plugin flags
  init,                 // initialize
  term,                 // terminate. this pointer may be NULL.
  run,                  // invoke plugin
  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint
  help,                 // multiline help about the plugin
  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
