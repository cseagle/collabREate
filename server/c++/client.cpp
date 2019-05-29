/*
   collabREate client.cpp
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

#include <stdio.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <map>
#include <json-c/json.h>

#include "client.h"
#include "utils.h"
#include "proj_info.h"
#include "cli_mgr.h"

map<string,ClientMsgHandler> *Client::handlers;
map<string,uint32_t> perms_map;

/**
 * Client
 * This class is responsible for a single client connection
 * It handles the initial client interaction, then reads
 * incoming client commands and kicks them up to the ConnectionManager
 * which farms the commands out to all interested clients
 * @author Tim Vidas
 * @author Chris Eagle
 * @version 0.4.0, August 2012
 */

Client::Client(ConnectionManager *mgr, NetworkIO *s, uint32_t uid) {
   if (handlers == NULL) {
      init_handlers();
   }
   const UserInfo &ui = mgr->getUserInfo(uid);

   hash = "";
   //effective, combined permissions (project & user & requested), used for checks
   publish = 0;
   subscribe = 0;
   //the permissions for the user account, read from database
   upublish = ui.pub;
   usubscribe = ui.sub;
   //the requested permissions sent from the plugin
   rpublish = 0;
   rsubscribe = 0;

   this->uid = ui.uid;  //user id associated with this connection
   username = ui.username;
   pid = INVALID_PID;  //not associated with a project yet

   cm = mgr;
   conn = s;

   //the dummy gpid need to consist entirely of hex values.
   gpid = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
}

void Client::setChallenge(const uint8_t *data, uint32_t len) {
   memcpy(challenge, data, len < CHALLENGE_SIZE ? len : CHALLENGE_SIZE);
}

/**
 * logs a message to the configured log file (in the ConnectionManager)
 * @param msg the string to log
 * @param v apply a verbosity level to the msg
 */
void Client::clog(int verbosity, const string &msg) {
   log(verbosity, "[%s:%d (%s:%u)] %s\n", conn->getPeerAddr().c_str(), conn->getPeerPort(), username.c_str(), uid, msg.c_str());
}

/**
 * logs a message to the configured log file (in the ConnectionManager)
 * @param msg the string to log
 * @param v apply a verbosity level to the msg
 */
void Client::clog(int verbosity, const char *format, ...) {
   char *ptr = NULL;
   va_list argp;
   va_start(argp, format);
   if (vasprintf(&ptr, format, argp) != -1 && ptr != NULL) {
      string msg(ptr);
      clog(verbosity, msg);
      free(ptr);
   }
   va_end(argp);
}

/**
 * post is the function that actually posts updates to clients (if subscribing)
 * @param data the bytearray containing the update to send
 */
void Client::post(const char *msg, json_object *obj) {
   if (checkPermissions(msg, subscribe)) {
      //only post if client is subscribing and is allowed to recieve that particular command
      log(LDEBUG, "post- %s\n", json_object_to_json_string(obj));
      const char *cmd = string_from_json(obj, "type");
      rx_stats[cmd]++;
      conn->writeJson(obj);
   }
   else {
/*
      log(LINFO3, "Client %s:%s:%d failed to post data. (probably subscribe permission: "
                         + parseCommand(data) + ")", hash.c_str(), conn->getInetAddress().getHostAddress(), conn->getPeerPort());
*/
   }
}


/**
 * similar to post, but does not check subscription status, and takes command as a arg
 * This function should ONLY be called for message id >= MSG_CONTROL_FIRST
 * because these messages do not contain an updateid
 * @param command the command to send
 * @param data the data associated with the command
 */
void Client::send_data(const char *command, json_object *obj) {
   //it would be nice to check that command is a valid control message
   //maybe prefix all control messages with "ctrl_"
//   if (strncmp(command, "mng_", 4) == 0) {
      if (obj == NULL) {
         obj = json_object_new_object();
      }
      json_object_object_add_ex(obj, "type", json_object_new_string(command), JSON_NEW_CONST_KEY);

      log(LDEBUG, "Client::send_data calling conn->writeJson\n");
      conn->writeJson(obj);  //calls json_object_put
      //fprintf(stderr, "send_data- cmd: %s\n");
      rx_stats[command]++;
/*
   }
   else {
      log(LINFO, "post should be used for command %s, not send_data.  Data not sent.\n", command);
   }
*/
}

/**
 * sendForkFollow sends a FORKFOLLOW message to the client, this occurs when another
 * user on the project decided to fork, the plugin is expected to give the user the
 * option of joining the new project or not
 * @param fuser the user that initiated the fork
 * @param gpid the global pid of the new project
 * @param lastupdateid the updateid that the project forked at
 * @param desc a description of the newly forked project
 */
void Client::sendForkFollow(string fuser, string gpid, uint64_t lastupdateid, string desc) {
   json_object *obj = json_object_new_object();
//   log(LINFO2, "Sending forkfollow for %s initiated by %s at updateid %llu\n", gpid.c_str(), fuser.c_str(), lastupdateid);
   append_json_string_val(obj, "user", fuser);
   append_json_string_val(obj, "gpid", gpid);
   append_json_uint64_val(obj, "lastupdateid", lastupdateid);
   append_json_string_val(obj, "description", desc);
   send_data(MSG_PROJECT_FORK_FOLLOW, obj);
}

void Client::send_error_msg(string theerror, const char *type) {
   json_object *obj = json_object_new_object();
//   log(LERROR, "Protocol error detected: %s\n", theerror.c_str());
   append_json_string_val(obj, "error", theerror);
   send_data(type, obj);
}

/**
 * terminate closes the client's connection, removes this client from the connection manager
 */
void Client::terminate() {
//   log(LINFO, "Client %s:%s:%d terminating\n", hash.c_str(), conn->getPeerAddr().c_str(), conn->getPeerPort());
   conn->close();
   cm->remove(this);
}

/**
 * dumpStats displays the receive / transmit stats for each command
 */
string Client::dumpStats() {
   string sb = "Stats for " + hash + ":" + conn->getPeerAddr() + "\n";
   sb += "rx     tx     command\n";
   for (map<string,int>::iterator mi = tx_stats.begin(); mi != tx_stats.end(); mi++) {
      if (rx_stats[mi->first] == 0) {
         char buf[128];
         snprintf(buf, sizeof(buf), "%-7d%-7d%s\n", 0, mi->second, mi->first.c_str());
         sb += buf;
      }
   }
   for (map<string,int>::iterator mi = rx_stats.begin(); mi != rx_stats.end(); mi++) {
      char buf[128];
      snprintf(buf, sizeof(buf), "%-7d%-7d%s\n", mi->second, tx_stats[mi->first], mi->first.c_str());
      sb += buf;
   }
   return sb;
}

/**
 * checkPermissions checks to see if the current client has permissions to perform an operation
 * @param command the command to check permissions on
 * @param permType the permission types to check (publish/subscribe)
 */
/* These are grouped into 'collabREate' permissions, just so there are fewer permissions to manage
 * for example all the segment operations (add, del, start/end change, etc) are grouped into
 * 'segment' permissions.
 */
bool Client::checkPermissions(const char *command, uint64_t permType) {
   bool isallowed = false;
//   log(LDEBUG, "checking for permission %n", command);
   map<string,uint32_t>::iterator mi = perms_map.find(command);

   if (mi != perms_map.end()) {
      uint32_t mask = mi->second;
      isallowed = ((permType & mask) > 0) ?  true : false;
   }  //end command switch
   else {
      log(LERROR, "unmatched command %s found in publish switch\n", command);
   }
   return isallowed;
}

uint32_t Client::getPeerPort() {
   return conn->getPeerPort();
}

string Client::getPeerAddr() {
   return conn->getPeerAddr();
}

/*
 * Callback for use with threaded server.  Customize this to
 * define behavior of the server.  Make sure to -DTHREADED in
 * the makefile
 */
/**
 * run this is the main thread for the Client class, it continually loops, receiving commands
 * and performing appropriate actions for each command. Note that to get here, client must
 * have successfully authenticated already
 */
void Client::run() {
   //in here read and write from/to the socket in order
   //to give the service some functionality
   try {
      bool done = false;
      while (!done) {
         json_object *obj = conn->readJson();
         if (obj == NULL) {
            log(LINFO, "json_object parsing failed in client loop\n");
            //received something that can't be parsed, bail
            break;
         }
         const char *cmd = string_from_json(obj, "type");
         log(LINFO, "processing %s\n", cmd);
         map<string,ClientMsgHandler>::iterator i = handlers->find(cmd);
         if (i != handlers->end()) {
            ClientMsgHandler h = i->second;
            done = (*h)(obj, this);
            json_object_put(obj);
         }
         else if (pid == INVALID_PID) {
            send_error("Not allowed to send project updates before joining a project\n");
         }
         else {
            //no handler found so this is not a control message, post it
            //only accept commands if the client is
            if (publish > 0) {
               //only post if this client chose to publish,
               //(though they really shouldn't have sent any data if they are not publishing)
               if (checkPermissions(cmd, publish)) {
                  cm->post(this, cmd, obj);
               }
               else {
                  log(LINFO, "Skipping update no permissions\n");
                  json_object_put(obj);
               }
            }
            else {
               log(LINFO, "Skipping update. publish: 0x%X\n", (uint32_t)publish);
               json_object_put(obj);
            }
         }
         log(LDEBUG, "received cmd: %s\n", cmd);
         tx_stats[cmd]++;
      }
   } catch (IOException ex) {
      log(LERROR, "An IOException occurred: %s\n", ex.getMessage().c_str());
   }
   log(LINFO, "Client loop has ended\n");
   terminate();
}

void Client::init_handlers() {
   handlers = new map<string,ClientMsgHandler>;
   (*handlers)[MSG_PROJECT_NEW_REQUEST] = msg_project_new_request;
   (*handlers)[MSG_PROJECT_JOIN_REQUEST] = msg_project_join_request;
   (*handlers)[MSG_PROJECT_REJOIN_REQUEST] = msg_project_rejoin_request;
   (*handlers)[MSG_PROJECT_SNAPSHOT_REQUEST] = msg_project_snapshot_request;
   (*handlers)[MSG_PROJECT_FORK_REQUEST] = msg_project_fork_request;
   (*handlers)[MSG_PROJECT_SNAPFORK_REQUEST] = msg_project_snapfork_request;
   (*handlers)[MSG_PROJECT_LEAVE] = msg_project_leave;
   (*handlers)[MSG_PROJECT_JOIN_REPLY] = msg_project_join_reply;
   (*handlers)[MSG_AUTH_REQUEST] = msg_auth_request;
   (*handlers)[MSG_PROJECT_LIST] = msg_project_list;
   (*handlers)[MSG_SEND_UPDATES] = msg_send_updates;
   (*handlers)[MSG_SET_REQ_PERMS] = msg_set_req_perms;
   (*handlers)[MSG_GET_REQ_PERMS] = msg_get_req_perms;
   (*handlers)[MSG_GET_PROJ_PERMS] = msg_get_proj_perms;
   (*handlers)[MSG_SET_PROJ_PERMS] = msg_set_proj_perms;

   perms_map[COMMAND_UNDEFINE] = MASK_UNDEFINE;
   perms_map[COMMAND_MAKE_CODE] = MASK_MAKE_CODE;
   perms_map[COMMAND_MAKE_DATA] = MASK_MAKE_DATA;

   perms_map[COMMAND_SEGM_ADDED] = MASK_SEGMENTS;
   perms_map[COMMAND_SEGM_DELETED] = MASK_SEGMENTS;
   perms_map[COMMAND_SEGM_START_CHANGED] = MASK_SEGMENTS;
   perms_map[COMMAND_SEGM_END_CHANGED] = MASK_SEGMENTS;
   perms_map[COMMAND_SEGM_MOVED] = MASK_SEGMENTS;
   perms_map[COMMAND_MOVE_SEGM] = MASK_SEGMENTS;

   perms_map[COMMAND_SET_STACK_VAR_NAME] = MASK_RENAME;
   perms_map[COMMAND_RENAMED] = MASK_RENAME;

   perms_map[COMMAND_FUNC_TAIL_APPENDED] = MASK_FUNCTIONS;
   perms_map[COMMAND_FUNC_TAIL_REMOVED] = MASK_FUNCTIONS;
   perms_map[COMMAND_TAIL_OWNER_CHANGED] = MASK_FUNCTIONS;
   perms_map[COMMAND_FUNC_NORET_CHANGED] = MASK_FUNCTIONS;
   perms_map[COMMAND_ADD_FUNC] = MASK_FUNCTIONS;
   perms_map[COMMAND_DEL_FUNC] = MASK_FUNCTIONS;
   perms_map[COMMAND_SET_FUNC_START] = MASK_FUNCTIONS;
   perms_map[COMMAND_SET_FUNC_END] = MASK_FUNCTIONS;

   perms_map[COMMAND_BYTE_PATCHED] = MASK_BYTE_PATCH;

   perms_map[COMMAND_AREA_CMT_CHANGED] = MASK_COMMENTS;
   perms_map[COMMAND_CMT_CHANGED] = MASK_COMMENTS;

   perms_map[COMMAND_TI_CHANGED] = MASK_OPTYPES;
   perms_map[COMMAND_OP_TI_CHANGED] = MASK_OPTYPES;
   perms_map[COMMAND_OP_TYPE_CHANGED] = MASK_OPTYPES;

   perms_map[COMMAND_ENUM_CREATED] = MASK_ENUMS;
   perms_map[COMMAND_ENUM_DELETED] = MASK_ENUMS;
   perms_map[COMMAND_ENUM_BF_CHANGED] = MASK_ENUMS;
   perms_map[COMMAND_ENUM_RENAMED] = MASK_ENUMS;
   perms_map[COMMAND_ENUM_CMT_CHANGED] = MASK_ENUMS;
   perms_map[COMMAND_ENUM_CONST_CREATED] = MASK_ENUMS;
   perms_map[COMMAND_ENUM_CONST_DELETED] = MASK_ENUMS;

   perms_map[COMMAND_STRUC_CREATED] = MASK_STRUCTS;
   perms_map[COMMAND_STRUC_DELETED] = MASK_STRUCTS;
   perms_map[COMMAND_STRUC_RENAMED] = MASK_STRUCTS;
   perms_map[COMMAND_STRUC_EXPANDED] = MASK_STRUCTS;
   perms_map[COMMAND_STRUC_CMT_CHANGED] = MASK_STRUCTS;
   perms_map[COMMAND_CREATE_STRUC_MEMBER_DATA] = MASK_STRUCTS;
   perms_map[COMMAND_CREATE_STRUC_MEMBER_STRUCT] = MASK_STRUCTS;
   perms_map[COMMAND_CREATE_STRUC_MEMBER_REF] = MASK_STRUCTS;
   perms_map[COMMAND_CREATE_STRUC_MEMBER_STROFF] = MASK_STRUCTS;
   perms_map[COMMAND_CREATE_STRUC_MEMBER_STR] = MASK_STRUCTS;
   perms_map[COMMAND_CREATE_STRUC_MEMBER_ENUM] = MASK_STRUCTS;
   perms_map[COMMAND_STRUC_MEMBER_DELETED] = MASK_STRUCTS;
   perms_map[COMMAND_SET_STRUCT_MEMBER_NAME] = MASK_STRUCTS;
   perms_map[COMMAND_STRUC_MEMBER_CHANGED_DATA] = MASK_STRUCTS;
   perms_map[COMMAND_STRUC_MEMBER_CHANGED_STRUCT] = MASK_STRUCTS;
   perms_map[COMMAND_STRUC_MEMBER_CHANGED_STR] = MASK_STRUCTS;
   perms_map[COMMAND_STRUC_MEMBER_CHANGED_OFFSET] = MASK_STRUCTS;
   perms_map[COMMAND_STRUC_MEMBER_CHANGED_ENUM] = MASK_STRUCTS;
   perms_map[COMMAND_CREATE_STRUC_MEMBER_OFFSET] = MASK_STRUCTS;

   perms_map[COMMAND_VALIDATE_FLIRT_FUNC] = MASK_FLIRT;

   perms_map[COMMAND_THUNK_CREATED] = MASK_THUNK;

   perms_map[COMMAND_ADD_CREF] = MASK_XREF;
   perms_map[COMMAND_ADD_DREF] = MASK_XREF;
   perms_map[COMMAND_DEL_CREF] = MASK_XREF;
   perms_map[COMMAND_DEL_DREF] = MASK_XREF;

   perms_map[COMMAND_USER_MESSAGE] = MASK_MESSAGE;
}

bool Client::msg_project_new_request(json_object *obj, Client *c) {
   c->hash = string_from_json(obj, "md5");
   c->clog(LDEBUG, "in NEW PROJECT REQUEST, hash is %s\n", c->hash.c_str());
   string desc = string_from_json(obj, "description");
   c->clog(LDEBUG, "in NEW PROJECT REQUEST, description is %s\n", desc.c_str());
   uint64_t pub, sub;
   uint64_from_json(obj, "pub", &pub);
   pub &= 0x7FFFFFFF;
   uint64_from_json(obj, "sub", &sub);
   sub &= 0x7FFFFFFF;

//   c->clogln(LDEBUG, "desired new project pub " + pub + ", and sub " + sub);
   int lpid = c->cm->addProject(c, c->hash, desc, pub, sub);
   json_object *resp = json_object_new_object();
   if (lpid >= 0) {
//      c->clog(LDEBUG, "NEW PROJECT REQUEST success\n");
      append_json_int32_val(resp, "reply", JOIN_REPLY_SUCCESS);
      append_json_string_val(resp, "gpid", c->gpid);
   }
   else {
      c->clog(LINFO, "NEW PROJECT REQUEST fail\n");
      append_json_int32_val(resp, "reply", JOIN_REPLY_FAIL);
   }
   c->send_data(MSG_PROJECT_JOIN_REPLY, resp);
   return false;
}

bool Client::msg_project_join_request(json_object *obj, Client *c) {
   int lpid;
   int32_from_json(obj, "project", &lpid);

   uint64_from_json(obj, "pub", &c->rpublish);
   c->rpublish &= 0x7FFFFFFF;
   uint64_from_json(obj, "sub", &c->rsubscribe);
   c->rsubscribe &= 0x7FFFFFFF;

//   c->clog(LINFO, "attempting to join project " + lpid);
   json_object *resp = json_object_new_object();
   if (c->cm->joinProject(c, lpid) >= 0 ) {
      append_json_int32_val(resp, "reply", JOIN_REPLY_SUCCESS);
      append_json_string_val(resp, "gpid", c->gpid);
//      c->clogln(LINFO, "...success" + lpid);
   }
   else {
      append_json_int32_val(resp, "reply", JOIN_REPLY_FAIL);
//      c->clogln(LINFO, "...failed" + lpid);
   }
   c->send_data(MSG_PROJECT_JOIN_REPLY, resp);
   return false;
}

bool Client::msg_project_rejoin_request(json_object *obj, Client *c) {
//   c->clog(LDEBUG, "in PROJECT_REJOIN_REQUEST\n");
   bool res = false;
//   int rejoingbasic = 0;
   string gpid = string_from_json(obj, "gpid");
   int lpid = c->cm->gpid2lpid(gpid);
   if (lpid < 0) {
      c->clog(LERROR, "Invalid gpid received for project rejoin request\n");
      c->send_error("Invalid gpid");
      return false;
   }
   uint64_t tpub, tsub;
   uint64_from_json(obj, "pub", &tpub);
   tpub &= 0x7FFFFFFF;
   uint64_from_json(obj, "sub", &tsub);
   tsub &= 0x7FFFFFFF;

   c->rpublish = tpub;
   c->rsubscribe = tsub;
//   c->clog(LDEBUG, "plugin requested rpub: " + rpublish + " rsub: " + rsubscribe);
   json_object *resp = json_object_new_object();
   if (c->cm->joinProject(c, lpid) >= 0 ) {
      append_json_int32_val(resp, "reply", JOIN_REPLY_SUCCESS);
      append_json_string_val(resp, "gpid", gpid);
      c->send_data(MSG_PROJECT_JOIN_REPLY, resp);
   }
   else {
      append_json_int32_val(resp, "reply", JOIN_REPLY_FAIL);
      c->send_data(MSG_PROJECT_JOIN_REPLY, resp);
      c->send_error("Tried to join a project that doesn't exist on this server:" + gpid);
      c->send_fatal("This idb is associated with a project not found on this server.\n Maybe you connected to the wrong collabREate server,\n or maybe the project has been deleted...");
      res = true;
   }
   return res;
}

bool Client::msg_project_snapshot_request(json_object *obj, Client *c) {
//   c->clog(LDEBUG, "in SNAPSHOT REQ\n");
   string desc = string_from_json(obj, "description");
   int response = PROJECT_SNAPSHOT_FAIL;
   uint64_t lastupdateid;
   uint64_from_json(obj, "last_update", &lastupdateid);
   if (lastupdateid <= 0 ) {
      c->clog(LINFO, "attempt to add snapshot with 0 or less updates applied\n");
      c->send_error("snapshots with 0 or less updates are not allowed - start a new project instead");
   }
   else if (c->cm->snapProject(c, lastupdateid, desc) >= 0) {
      response = PROJECT_SNAPSHOT_SUCCESS;
   }
   json_object *resp = json_object_new_object();
   append_json_int32_val(resp, "reply", response);
   c->send_data(MSG_PROJECT_SNAPSHOT_REPLY, obj);
   return false;
}

bool Client::msg_project_fork_request(json_object *obj, Client *c) {
   string desc = string_from_json(obj, "description");
   int response = JOIN_REPLY_FAIL;
   uint64_t lastupdateid;
   uint64_from_json(obj, "last_update", &lastupdateid);
//                 logln("in FORK REQUEST", LDEBUG);
   json_object *resp = json_object_new_object();

   //if the user set these at the time of the fork
   //they would be read here.  Instead we allow the owner to
   //manage permissions at any time via the modal dialog box
   if (c->cm->forkProject(c, lastupdateid, desc) >= 0) {
      //on successfull fork, join the 'new' project automatically
      response = JOIN_REPLY_SUCCESS;
      append_json_string_val(resp, "gpid", c->gpid);
   }
   append_json_int32_val(resp, "reply", response);
   c->send_data(MSG_PROJECT_JOIN_REPLY, resp);
   return false;
}

bool Client::msg_project_snapfork_request(json_object *obj, Client *c) {
//   c->clog(LDEBUG, "in SNAPFORK REQUEST\n");
   string desc = string_from_json(obj, "description");
   uint64_t pub, sub;
   uint64_from_json(obj, "pub", &pub);
   pub &= 0x7FFFFFFF;
   uint64_from_json(obj, "sub", &sub);
   sub &= 0x7FFFFFFF;
   int response = JOIN_REPLY_FAIL;
//                 logln("in FORK REQUEST", LDEBUG);
   json_object *resp = json_object_new_object();

   int lpid;
   int32_from_json(obj, "lpid", &lpid);
   if (c->cm->snapforkProject(c, lpid, desc, pub, sub) >= 0) {
      //on successfull fork from snapshop, join the 'new' project automatically
      response = JOIN_REPLY_SUCCESS;
      append_json_string_val(resp, "gpid", c->gpid);
   }
   append_json_int32_val(resp, "reply", response);
   c->send_data(MSG_PROJECT_JOIN_REPLY, resp);
   return false;
}

bool Client::msg_project_leave(json_object *obj, Client *c) {
   c->clog(LDEBUG, "in PROJECT LEAVE\n");
   c->cm->remove(c);
   return false;
}

bool Client::msg_project_join_reply(json_object *obj, Client *c) {
   return false;
}

bool Client::msg_auth_request(json_object *obj, Client *c) {
   c->clog(LERROR, "recv AUTH REQUEST when already authenticated\n");
   c->send_error("MSG_AUTH_REQUEST ignored after initial auth");
   return false;
}

bool Client::msg_project_list(json_object *obj, Client *c) {
   c->hash = string_from_json(obj, "md5");
//   c->clog(LINFO4, "project hash: %s\n", c->hash.c_str());
   json_object *projects = json_object_new_array();
   vector<const Project*> *plist = c->cm->getProjectList(c->hash);
//   int nump = plist->size();
//   c->clog(LINFO3, " Found %u projects\n", nump);
   //create list of projects
   if (plist) {
      for (vector<const Project*>::iterator pi = plist->begin(); pi != plist->end(); pi++) {
   //      c->clog(LINFO4, " " + pi.lpid + " "+ pi.desc, LINFO4);
         char buf[256];
         json_object *proj = json_object_new_object();
         append_json_int32_val(proj, "id", (*pi)->lpid);
         append_json_uint64_val(proj, "snap_id", (*pi)->snapupdateid);
         if ((*pi)->parent > 0) {
            if ((*pi)->snapupdateid > 0) {
               snprintf(buf, sizeof(buf), "[-] %s (SNAP of '%s'@%" PRIu64 " updates])", (*pi)->desc.c_str(), (*pi)->pdesc.c_str(), (*pi)->snapupdateid);
   //            log("[-] " + pi.desc + " (snapshot of (" + pi.parent + ")'" + pi.pdesc+"' ["+ pi.snapupdateid + " updates]) ", LDEBUG);
            }
            else {
               snprintf(buf, sizeof(buf), "[%d] %s (FORK of '%s')", (*pi)->connected, (*pi)->desc.c_str(), (*pi)->pdesc.c_str());
   //            log("[" + pi.connected + "] " + pi.desc + " (forked from (" + pi.parent + ") '" + pi.pdesc +"')", LDEBUG);
            }
         }
         else {
            snprintf(buf, sizeof(buf), "[%d] %s", (*pi)->connected, (*pi)->desc.c_str());
         }
         append_json_string_val(proj, "description", buf);
         //since the user permissions may already limit the eventual effective permissions
         //only show the user the maximum attainable by this particular user (mask)
         //upublish = usubscribe = FULL_PERMISSIONS;  //quick BASIC mode test
         append_json_uint64_val(proj, "pub_mask", (*pi)->pub & c->upublish);
         append_json_uint64_val(proj, "sub_mask", (*pi)->sub & c->usubscribe);

         json_object_array_add(projects, proj);
   //                    logln("", LDEBUG);
   //                    logln("pP " + (*pi)->pub + " pS " + (*pi)->sub, LINFO4);
   //                    logln("uP " + c->upublish + " uS " + c->usubscribe, LINFO4);
      }
      delete plist;
   }

   //also append list of permissions supported by this server
   json_object *options = json_object_new_array();
   for ( int i = 0; permStrings[i]; i++) {
      json_object_array_add(options, json_object_new_string(permStrings[i]));
   }

   json_object *resp = json_object_new_object();
   json_object_object_add_ex(resp, "projects", projects, JSON_NEW_CONST_KEY);
   json_object_object_add_ex(resp, "options", options, JSON_NEW_CONST_KEY);

   c->send_data(MSG_PROJECT_LIST, resp);
   return false;
}

bool Client::msg_send_updates(json_object *obj, Client *c) {
   uint64_t lastupdate;
   uint64_from_json(obj, "last_update", &lastupdate);
//      c->clogln(LINFO1, "Received client->send_UPDATES request for %llu to current", lastupdate);
   c->cm->sendLatestUpdates(c, lastupdate);
   return false;
}

bool Client::msg_set_req_perms(json_object *obj, Client *c) {
//                 logln("Received SET_REQ_PERMS request", LINFO1);
   uint64_from_json(obj, "pub", &c->rpublish);
   c->rpublish &= 0x7FFFFFFF;
   uint64_from_json(obj, "sub", &c->rsubscribe);
   c->rsubscribe &= 0x7FFFFFFF;

   const Project *pi = c->cm->getProject(c->pid);
/*
  logln("effective publish  : " +
         uint64_t.toHexString(pi.pub) + " & " +
         uint64_t.toHexString(rpublish) + " & " +
         uint64_t.toHexString(upublish) + " = " +
         uint64_t.toHexString(pi.pub & upublish & rpublish),LINFO1);
  logln("effective subscribe: " +
         uint64_t.toHexString(pi.sub) + " & " +
         uint64_t.toHexString(rsubscribe) + " & " +
         uint64_t.toHexString(usubscribe) + " = " +
         uint64_t.toHexString(pi.sub & usubscribe & rsubscribe),LINFO1);
*/
   if (pi) {
      if ( c->username != pi->owner ) {
         c->setPub(pi->pub & c->upublish & c->rpublish);
         c->setSub(pi->sub & c->usubscribe & c->rsubscribe);
      }
      else {
         c->clog(LINFO, "not honoring SET_REQ_PERMS for owner\n");
         c->send_error("You are the owner.  FULL permissions granted.");
      }
   }
   else {
      //something is really wrong
   }
   return false;
}

bool Client::msg_get_req_perms(json_object *obj, Client *c) {
//                 logln("Received GET_REQ_PERMS request", LINFO1);
   //send the two requested permissions
   json_object *resp = json_object_new_object();
   append_json_uint64_val(resp, "pub", c->rpublish);
   append_json_uint64_val(resp, "sub", c->rsubscribe);

   //send the max possible values for requested permissions (mask)
   const Project *pi = c->cm->getProject(c->pid);

   if (pi) {
      append_json_uint64_val(resp, "pub_mask", pi->pub & c->upublish);
      append_json_uint64_val(resp, "sub_mask", pi->sub & c->usubscribe);

      //also append list of permissions supported by this server
      json_object *perms = json_object_new_array();
      for ( int i = 0; permStrings[i]; i++) {
         json_object_array_add(perms, json_object_new_string(permStrings[i]));
      }

      json_object_object_add_ex(resp, "perms", perms, JSON_NEW_CONST_KEY);

      c->send_data(MSG_GET_REQ_PERMS_REPLY, resp);
   }
   else {
      //something is really wrong
   }
   return false;
}

bool Client::msg_get_proj_perms(json_object *obj, Client *c) {
//                 logln("Received GET_PROJ_PERMS request", LINFO1);
   const Project *pi = c->cm->getProject(c->pid);
   if (pi) {
      if (c->username == pi->owner) {
         json_object *resp = json_object_new_object();
         //send the two project permissions
         append_json_uint64_val(resp, "pub", pi->pub);
         append_json_uint64_val(resp, "sub", pi->sub);
         //since this is the owner managing possible values for requested permissions (mask) is full
         append_json_uint64_val(resp, "pub_mask", FULL_PERMISSIONS);
         append_json_uint64_val(resp, "sub_mask", FULL_PERMISSIONS);

         //also append list of permissions supported by this server
         json_object *perms = json_object_new_array();
         for ( int i = 0; permStrings[i]; i++) {
            json_object_array_add(perms, json_object_new_string(permStrings[i]));
         }

         json_object_object_add_ex(resp, "perms", perms, JSON_NEW_CONST_KEY);

        c->send_data(MSG_GET_PROJ_PERMS_REPLY, resp);
      }
      else {
         c->send_error("You are not the owner!");
      }
   }
   else {
      //something is relly wrong
   }
   return false;
}

bool Client::msg_set_proj_perms(json_object *obj, Client *c) {
//                 logln("Received GET_PROJ_PERMS request", LINFO1);
   uint64_t pub, sub;
   uint64_from_json(obj, "pub", &pub);
   pub &= 0x7FFFFFFF;
   uint64_from_json(obj, "sub", &sub);
   sub &= 0x7FFFFFFF;
   const Project *pi = c->cm->getProject(c->pid);
   if (pi) {
      if (c->username == pi->owner) {
         c->cm->updateProjectPerms(c, pub, sub);
      }
      else {
         c->send_error("You are not the owner!");
      }
   }
   else {
      //something is really wrong
   }
   return false;
}
