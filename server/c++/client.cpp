/*
   collabREate client.cpp
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

#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <map>
#include <json.h>

#include "utils.h"
#include "proj_info.h"
#include "client.h"
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

Client::Client(ConnectionManagerBase *mgr, NetworkIO *s, bool basic) {
   if (handlers == NULL) {
      init_handlers();
   }
   hash = "";
   //effective, combined permissions (project & user & requested), used for checks
   publish = 0;
   subscribe = 0;
   //the permissions for the user account, read from database
   upublish = 0;
   usubscribe = 0;
   //the requested permissions sent from the plugin
   rpublish = 0;
   rsubscribe = 0;
   authenticated = false;

   uid = -1;  //user id associated with this connection
   pid = -1;
   authTries = 3;
   gpid = "";  //project id associated with this connection

   memset(challenge, 0, sizeof(challenge));
   memset(stats, 0, sizeof(stats));

   cm = mgr;
   conn = s;
   basicMode = basic;
   fprintf(stderr, "basicMode is: %u\n", basicMode);

//   ::logln("New Connection", LINFO);

   if (!basicMode) {
     fill_random(challenge, CHALLENGE_SIZE);
     json_object *obj = json_object_new_object();
     append_json_hex_val(obj, "challenge", challenge, CHALLENGE_SIZE);
     fprintf(stderr, "Sending initial challenge\n");
     send_data(MSG_INITIAL_CHALLENGE, obj);
   }
   else {
      //these are used only for the 'auto auth' in BASIC mode
//      ::logln("sending AUTH_CONNECTED");
      cm->authenticate(this, NULL, NULL, 0, NULL, 0);
      authenticated = true;
      json_object *auth = json_object_new_object();
      append_json_int32_val(auth, "reply", AUTH_REPLY_SUCCESS);
      send_data(MSG_AUTH_REPLY, auth);
   }
   //the dummy gpid need to consist entirely of hex values.
   gpid = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
}


/**
 * logs a message to the configured log file (in the ConnectionManager)
 * @param msg the string to log
 * @param v apply a verbosity level to the msg
 */
void Client::log(const string &msg, int v) {
   char buf[256];
   snprintf(buf, sizeof(buf), "[%s:%d (%s:%d)] %s", conn->getPeerAddr().c_str(), conn->getPeerPort(), username.c_str(), uid, msg.c_str());
   cm->log(buf, v);
}

/**
 * post is the function that actually posts updates to clients (if subscribing)
 * @param data the bytearray containing the update to send
 */
void Client::post(const char *msg, json_object *obj) {
   if (checkPermissions(msg, subscribe)) {
      //only post if client is subscribing and is allowed to recieve that particular command
      conn->writeJson(obj);
      //::logln("post- datasize: " + data.length);
//      stats[0][data[7] & 0xff]++;
   }
   else {
/*
      ::logln("Client " + hash + ":" + conn->getInetAddress().getHostAddress()
                         + ":" + conn->getPeerPort() + " failed to post data. "
                         + " (probably subscribe permission: "
                         + parseCommand(data) + ")", LINFO3);
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

      fprintf(stderr, "Client::send_data calling conn->writeJson\n");
      conn->writeJson(obj);  //calls json_object_put
      //fprintf(stderr, "send_data- cmd: %s\n");
//      json_object_put(obj);
//      stats[0][command]++;    //figure out way to count messages - map???
/*
   }
   else {
      fprintf(stderr, "post should be used for command %s, not send_data.  Data not sent.\n", command);
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
//   ::logln("Sending forkfollow for " + gpid + " initiated by " + fuser + " at updateid " + lastupdateid, LINFO2);
   append_json_string_val(obj, "user", fuser);
   append_json_string_val(obj, "gpid", gpid);
   append_json_uint64_val(obj, "lastupdateid", lastupdateid);
   append_json_string_val(obj, "description", desc);
   send_data(MSG_PROJECT_FORK_FOLLOW, obj);
}

void Client::send_error_msg(string theerror, const char *type) {
   json_object *obj = json_object_new_object();
//   ::logln("Protocol error detected: " + theerror, LERROR);
   append_json_string_val(obj, "error", theerror);
   send_data(type, obj);
}

/**
 * terminate closes the client's connection, removes this client from the connection manager
 */
void Client::terminate() {
//   ::logln("Client " + hash + ":" + conn->getPeerAddr()
//                      + ":" + conn->getPeerPort() + " terminating", LINFO);
   conn->close();
   cm->remove(this);
}

/**
 * dumpStats displace the receive / transmit stats for each command
 */
string Client::dumpStats() {
//   string sb = "Stats for " + hash + ":" + conn->getPeerAddr() + ":" + conn.getPeerPort() + "\n";
   string sb = "Stats for " + hash + ":" + conn->getPeerAddr() + "\n";
   sb += "command     rx     tx\n";
   for (int i = 0; i < 256; i++) {
      if (stats[0][i] != 0 || stats[1][i] != 0) {
         char buf[128];
         snprintf(buf, sizeof(buf), "%5d %7d %7d\n", i, stats[0][i], stats[1][i]);
         sb += buf;
      }
   }
   return sb;
}



/**
 * checkPermissions checks to see if the current client has permissions to perform an operation
 * @param command the command to check permissions on
 * @param permType the permission types to check (publish/subscribe)
 */
/* These are grouped into 'collabREate' permissions, just so there are less permissions to manage
 * for example all the segment operations (add, del, start/end change, etc) are grouped into
 * 'segment' permissions.
 */
bool Client::checkPermissions(const char *command, uint64_t permType) {
   bool isallowed = false;
//   ::logln("checking for permission " + command, LDEBUG);
   map<string,uint32_t>::iterator mi = perms_map.find(command);
   
   if (mi != perms_map.end()) {
      uint32_t mask = mi->second;
      isallowed = ((permType & mask) > 0) ?  true : false;
   }  //end command switch
   else {
      //logln("unmatched command " + command + " found in publish switch", LERROR);
   }      
   return isallowed;
}

uint32_t Client::getPeerPort() {
   return conn->getPeerPort();
}

string Client::getPeerAddr() {
   return conn->getPeerAddr();
}

void Client::start() {
   pthread_attr_t attr;
   pthread_attr_init(&attr);
   pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
   pthread_t tid;
   pthread_create(&tid, &attr, run, (void*)this);
}

/*
 * Callback for use with threaded server.  Customize this to
 * define behavior of the server.  Make sure to -DTHREADED in
 * the makefile
 */
/**
 * run this is the main thread for the Client class, it continually loops, receiving commands
 * and performing appropriate actions for each command
 */
void *Client::run(void *arg) {
   //in here read and write from/to the socket in order
   //to give the service some functionality
   Client *client = (Client*)arg;
   try {
      bool done = false;
      while (!done) {
         json_object *obj = client->conn->readJson();
         if (obj == NULL) {
            fprintf(stderr, "json_object parsing failed\n");
            //received something that can't be parsed, bail
            break;
         }
         const char *cmd = string_from_json(obj, "type");
         fprintf(stderr, "processing %s\n", cmd);
         map<string,ClientMsgHandler>::iterator i = handlers->find(cmd);
         if (i != handlers->end()) {
            ClientMsgHandler h = i->second;
            done = (*h)(obj, client);
            json_object_put(obj);
         }
         else {
            //no handler found so this is not a control message, post it
            //only accept commands if the client is authenticated
            fprintf(stderr, "no handler found for %s\n", cmd);
            if (client->authenticated && (client->publish > 0)) {
               //only post if this client chose to publish,
               //(though they really shouldn't have sent any data if they are not publishing)
               if (client->checkPermissions(cmd, client->publish)) {
   //               ::logln("posting command " + command + " (allowed to  publish) ", LDEBUG);
                  client->cm->post(client, cmd, obj);
               }
               else {
                  fprintf(stderr, "Skipping update no permissions\n");
   //               ::logln("not allowed to perform command: " + command, LINFO);
                      // if (errorAlreadySentMask
                      // send_error("you are not allowed to byte patch");
                      // errorAlreadySentMask |= MASK_BYTE_PATCHED;
                      // ::logln("sent errors is " + errorAlreadySentMask);
                  json_object_put(obj);
               }
            }
            else {
               fprintf(stderr, "Skipping update authenticated: %d, publish: 0x%X\n", client->authenticated, (uint32_t)client->publish);
   /*
               ::logln("Client " + hash + ":" + conn.getInetAddress().getHostAddress()
                                  + ":" + conn.getPeerPort() + " skipping post command.", LINFO);
   */
               json_object_put(obj);
            }
         }

/*
#ifdef DEBUG
         fprintf(stderr, "received data len: %d, cmd: %d\n", len, command);
#endif
//      ::logln("received data len: " + len + ", cmd: " + command, LDEBUG);
         if (command < MAX_COMMAND && command > 0) {
            client->stats[1][command]++;
         }
         if (command < MSG_CONTROL_FIRST) {
         }
*/
      }
   } catch (IOException ex) {
      fprintf(stderr, "An IOException occurred: %s\n", ex.getMessage().c_str());
   }
end_loop:
   fprintf(stderr, "Client loop has ended\n");
   client->terminate();
   delete client;
   return NULL;
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

}

bool Client::msg_project_new_request(json_object *obj, Client *c) {
//                  ::logln("in NEW PROJECT REQUEST", LDEBUG);
   if (!c->authenticated) {
      //nice try!!
      return false;
   }
   c->hash = string_from_json(obj, "md5");
   string desc = string_from_json(obj, "description");
   uint64_t pub, sub;
   uint64_from_json(obj, "pub", &pub);
   pub &= 0x7FFFFFFF;
   uint64_from_json(obj, "sub", &sub);
   sub &= 0x7FFFFFFF;

//                  ::logln("desired new project pub " + pub + ", and sub " + sub);
   int lpid = c->cm->addProject(c, c->hash, desc, pub, sub);
   json_object *resp = json_object_new_object();
   if (lpid >= 0) {
//                     ::logln("NEW PROJECT REQUEST success", LINFO);
      append_json_int32_val(resp, "reply", JOIN_REPLY_SUCCESS);
      append_json_string_val(resp, "gpid", c->gpid);
   }
   else {
//                     ::logln("NEW PROJECT REQUEST fail", LINFO);
      append_json_int32_val(resp, "reply", JOIN_REPLY_FAIL);
   }
   c->send_data(MSG_PROJECT_JOIN_REPLY, resp);
   return false;
}

bool Client::msg_project_join_request(json_object *obj, Client *c) {
   if (!c->authenticated) {
      //nice try!!
      return false;
   }
   int lpid;
   int32_from_json(obj, "project", &lpid);

   uint64_from_json(obj, "pub", &c->rpublish);
   c->rpublish &= 0x7FFFFFFF;
   uint64_from_json(obj, "sub", &c->rsubscribe);
   c->rsubscribe &= 0x7FFFFFFF;

//               ::logln("attempting to join project " + lpid, LINFO);
   json_object *resp = json_object_new_object();
   if (c->cm->joinProject(c, lpid) >= 0 ) {
      append_json_int32_val(resp, "reply", JOIN_REPLY_SUCCESS);
      append_json_string_val(resp, "gpid", c->gpid);
//                  ::logln("...success" + lpid, LINFO);
   }
   else {
      append_json_int32_val(resp, "reply", JOIN_REPLY_FAIL);
//                  ::logln("...failed" + lpid, LINFO);
   }
   c->send_data(MSG_PROJECT_JOIN_REPLY, resp);
   return false;
}

bool Client::msg_project_rejoin_request(json_object *obj, Client *c) {
//                  ::logln("in PROJECT_REJOIN_REQUEST", LDEBUG);
   bool res = false;
   int rejoingbasic = 0;
   string gpid = string_from_json(obj, "gpid");
   if ( isNumeric(gpid) ) {
      uint32_t gpi = -1;
      sscanf(gpid.c_str(), "%d", &gpi);
      if ( gpi == 0 ) {
         //basic mode pid was stored in netnode
         c->send_error("This instance of IDA connected in basic mode, cannot reconnect.");
         return res;
      }
   }
   int lpid = c->cm->gpid2lpid(gpid);
   if (lpid < 0) {
      ::logln("Invalid gpid received for project rejoin request", LERROR);
      c->send_error("Invalid gpid");      
      return false;
   }
   uint64_t tpub, tsub;
   uint64_from_json(obj, "pub", &tpub);
   tpub &= 0x7FFFFFFF;
   uint64_from_json(obj, "sub", &tsub);
   tsub &= 0x7FFFFFFF;

   if (!c->authenticated) {
      ::logln("unauthorized project rejoin request", LERROR);
      c->send_error("Authenication required for this operation");
      return res;
   }
   c->rpublish = tpub;
   c->rsubscribe = tsub;
//                  ::logln("plugin requested rpub: " + rpublish + " rsub: " + rsubscribe);
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
//                  ::logln("in SNAPSHOT REQ", LDEBUG);
   string desc = string_from_json(obj, "description");
   int response = PROJECT_SNAPSHOT_FAIL;
   uint64_t lastupdateid;
   uint64_from_json(obj, "last_update", &lastupdateid);
   if (!c->authenticated) {
      ::logln("unauthorized project snapshot request", LERROR);
      c->send_error("Authenication required for this operation");
   }
   else if (lastupdateid <= 0 ) {
      ::logln("attempt to add snapshot with 0 or less updates applied", LINFO);
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
//                  ::logln("in FORK REQUEST", LDEBUG);
   json_object *resp = json_object_new_object();
   if (!c->authenticated) {
      ::logln("unauthorized project fork request", LERROR);
      c->send_error("Authenication required for this operation");
   }

   //if the user set these at the time of the fork
   //they would be read here.  Instead we allow the owner to
   //manage permissions at any time via the modal dialog box
   else if (c->cm->forkProject(c, lastupdateid, desc) >= 0) {
      //on successfull fork, join the 'new' project automatically
      response = JOIN_REPLY_SUCCESS;
      append_json_string_val(resp, "gpid", c->gpid);
   }
   append_json_int32_val(resp, "reply", response);
   c->send_data(MSG_PROJECT_JOIN_REPLY, resp);
   return false;
}

bool Client::msg_project_snapfork_request(json_object *obj, Client *c) {
//                  ::logln("in SNAPFORK REQUEST", LDEBUG);
   string desc = string_from_json(obj, "description");
   uint64_t pub, sub;
   uint64_from_json(obj, "pub", &pub);
   pub &= 0x7FFFFFFF;
   uint64_from_json(obj, "sub", &sub);
   sub &= 0x7FFFFFFF;
   int response = JOIN_REPLY_FAIL;
//                  ::logln("in FORK REQUEST", LDEBUG);
   json_object *resp = json_object_new_object();

   int lpid;
   int32_from_json(obj, "lpid", &lpid);
   if (!c->authenticated) {
      ::logln("unauthorized project snapfork request", LERROR);
      c->send_error("Authenication required for this operation");
   }
//               ::logln("got " + lpid + ": " + desc, LDEBUG);
   else if (c->cm->snapforkProject(c, lpid, desc, pub, sub) >= 0) {
      //on successfull fork from snapshop, join the 'new' project automatically
      response = JOIN_REPLY_SUCCESS;
      append_json_string_val(resp, "gpid", c->gpid);
   }
   append_json_int32_val(resp, "reply", response);
   c->send_data(MSG_PROJECT_JOIN_REPLY, resp);
   return false;
}

bool Client::msg_project_leave(json_object *obj, Client *c) {
//                  ::logln("in PROJECT LEAVE", LDEBUG);
   if (!c->authenticated) {
      ::logln("unauthorized project leave request", LERROR);
      c->send_error("Authenication required for this operation");
   }
   else {
      c->cm->remove(c);
   }
   return false;
}

bool Client::msg_project_join_reply(json_object *obj, Client *c) {
   return false;
}

bool Client::msg_auth_request(json_object *obj, Client *c) {
//                  ::logln("in AUTH REQUEST", LDEBUG);
   int pluginversion;
   int32_from_json(obj, "protocol", &pluginversion);
   if (pluginversion != PROTOCOL_VERSION) {
      char buf[256];
      snprintf(buf, sizeof(buf), "Version mismatch. plugin: %d server: %d", pluginversion, PROTOCOL_VERSION);
#ifdef DEBUG
      fprintf(stderr, "%s\n", buf);
#endif
      c->send_error(buf);
//                  ::logln("Version mismatch. plugin: " + pluginversion + " server: " + PROTOCOL_VERSION, LERROR);
      return true;
   }
   if (!c->authenticated) {
      uint32_t rsize;
      uint8_t *hmac = hex_from_json(obj, "hmac", &rsize);
      c->username = string_from_json(obj, "user");
//                     ::logln("got user: " + client->username, LDEBUG);
      if (rsize != MD5_SIZE) {
         ::logln("Malformed AUTH REQUEST - failed to read hmac response", LERROR);
         c->send_error("Malformed AUTH_REQUEST");
         return true;  //disconnect
      }

      c->uid = c->cm->authenticate(c, c->username.c_str(), c->challenge, CHALLENGE_SIZE, hmac, MD5_SIZE);
      delete [] hmac;
      json_object *response = json_object_new_object();
      int reply = AUTH_REPLY_FAIL;
      if (c->uid != INVALID_USER) {
         c->authenticated = true;
#ifdef DEBUG
         fprintf(stderr, "uid set to %d\n", c->uid);
#endif
         //::logln("uid set to "+ uid);
         reply = AUTH_REPLY_SUCCESS;
      }
      else {
#ifdef DEBUG
         ::logln("AUTH_REPLY_FAIL");
#endif
         c->authTries--;
      }
      append_json_int32_val(response, "reply", reply);
      c->send_data(MSG_AUTH_REPLY, response);
      if (c->authTries == 0) {
         ::logln("too many auth attempts for " + c->getUser(), LERROR);
         return true;
      }
   }
   else {
      ::logln("recv AUTH REQUEST when already authenticated", LERROR);
      c->send_error("Attempt to Authenticate, when already authenticated");
   }
   return false;
}

bool Client::msg_project_list(json_object *obj, Client *c) {
   if (!c->authenticated) {
      //nice try!!
      return false;
   }
   c->hash = string_from_json(obj, "md5");
//                     ::logln("project hash: " + c->hash, LINFO4);
   vector<ProjectInfo*> *plist = c->cm->getProjectList(c->hash);
   int nump = plist->size();
   json_object *projects = json_object_new_array();
//                  ::logln(" Found  " + nump + " projects", LINFO3);
   //create list of projects
   for (vector<ProjectInfo*>::iterator pi = plist->begin(); pi != plist->end(); pi++) {
//                     log(" " + pi.lpid + " "+ pi.desc, LINFO4);
      json_object *proj = json_object_new_object();
      append_json_int32_val(proj, "id", (*pi)->lpid);
      append_json_uint64_val(proj, "snap_id", (*pi)->snapupdateid);
      if ((*pi)->parent > 0) {
         char buf[256];
         if ((*pi)->snapupdateid > 0) {
            snprintf(buf, sizeof(buf), "[-] %s (SNAP of '%s'@%"PRIu64" updates])", (*pi)->desc.c_str(), (*pi)->pdesc.c_str(), (*pi)->snapupdateid);
//                           log("[-] " + pi.desc + " (snapshot of (" + pi.parent + ")'" + pi.pdesc+"' ["+ pi.snapupdateid + " updates]) ", LDEBUG);
         }
         else {
            snprintf(buf, sizeof(buf), "[%d] %s (FORK of '%s')", (*pi)->connected, (*pi)->desc.c_str(), (*pi)->pdesc.c_str());
//                           log("[" + pi.connected + "] " + pi.desc + " (forked from (" + pi.parent + ") '" + pi.pdesc +"')", LDEBUG);
         }
         append_json_string_val(proj, "description", buf);
      }
      else {
         char buf[128];
         snprintf(buf, sizeof(buf), "[%d] %s", (*pi)->connected, (*pi)->desc.c_str());
         append_json_string_val(proj, "description", buf);
      }
      //since the user permissions may already limit the eventual effective permissions
      //only show the user the maximum attainable by this particular user (mask)
      //upublish = usubscribe = FULL_PERMISSIONS;  //quick BASIC mode test
      append_json_uint64_val(proj, "pub_mask", (*pi)->pub & c->upublish);
      append_json_uint64_val(proj, "sub_mask", (*pi)->sub & c->usubscribe);

      json_object_array_add(projects, proj);
//                     ::logln("", LDEBUG);
//                     ::logln("pP " + (*pi)->pub + " pS " + (*pi)->sub, LINFO4);
//                     ::logln("uP " + c->upublish + " uS " + c->usubscribe, LINFO4);
      delete *pi;
   }
   delete plist;

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
   if (c->authenticated) {
//      ::logln("Received client->send_UPDATES request for " + lastupdate + " to current", LINFO1);
      uint64_t lastupdate;
      uint64_from_json(obj, "last_update", &lastupdate);
      c->cm->sendLatestUpdates(c, lastupdate);
   }
   return false;
}

bool Client::msg_set_req_perms(json_object *obj, Client *c) {
//                  ::logln("Received SET_REQ_PERMS request", LINFO1);
   if (!c->authenticated) {
      ::logln("unauthorized get req perms request",LERROR);
      c->send_error("Authenication required for this operation");
      return false;
   }

   uint64_from_json(obj, "pub", &c->rpublish);
   c->rpublish &= 0x7FFFFFFF;
   uint64_from_json(obj, "sub", &c->rsubscribe);
   c->rsubscribe &= 0x7FFFFFFF;

   ProjectInfo *pi = c->cm->getProjectInfo(c->pid);
/*
   ::logln("effective publish  : " +
         uint64_t.toHexString(pi.pub) + " & " +
         uint64_t.toHexString(rpublish) + " & " +
         uint64_t.toHexString(upublish) + " = " +
         uint64_t.toHexString(pi.pub & upublish & rpublish),LINFO1);
   ::logln("effective subscribe: " +
         uint64_t.toHexString(pi.sub) + " & " +
         uint64_t.toHexString(rsubscribe) + " & " +
         uint64_t.toHexString(usubscribe) + " = " +
         uint64_t.toHexString(pi.sub & usubscribe & rsubscribe),LINFO1);
*/
   if ( c->username != pi->owner ) {
      c->setPub(pi->pub & c->upublish & c->rpublish);
      c->setSub(pi->sub & c->usubscribe & c->rsubscribe);
   }
   else {
      ::logln("not honoring SET_REQ_PERMS for owner", LINFO1);
      c->send_error("You are the owner.  FULL permissions granted.");
   }
   delete pi;
   return false;
}

bool Client::msg_get_req_perms(json_object *obj, Client *c) {
//                  ::logln("Received GET_REQ_PERMS request", LINFO1);
   if (!c->authenticated) {
      ::logln("unauthorized get req perms request",LERROR);
      c->send_error("Authenication required for this operation");
      return false;
   }
   //send the two requested permissions
   json_object *resp = json_object_new_object();
   append_json_uint64_val(resp, "pub", c->rpublish);
   append_json_uint64_val(resp, "sub", c->rsubscribe);

   //send the max possible values for requested permissions (mask)
   ProjectInfo *pi = c->cm->getProjectInfo(c->pid);

   append_json_uint64_val(resp, "pub_mask", pi->pub & c->upublish);
   append_json_uint64_val(resp, "sub_mask", pi->sub & c->usubscribe);

   //also append list of permissions supported by this server
   json_object *perms = json_object_new_array();
   for ( int i = 0; permStrings[i]; i++) {
      json_object_array_add(perms, json_object_new_string(permStrings[i]));
   }

   json_object_object_add_ex(resp, "perms", perms, JSON_NEW_CONST_KEY);

   c->send_data(MSG_GET_REQ_PERMS_REPLY, resp);
   delete pi;
   return false;
}

bool Client::msg_get_proj_perms(json_object *obj, Client *c) {
//                  ::logln("Received GET_PROJ_PERMS request", LINFO1);
   if (!c->authenticated) {
      ::logln("unauthorized get project perms request",LERROR);
      c->send_error("Authenication required for this operation");
      return false;
   }
   ProjectInfo *pi = c->cm->getProjectInfo(c->pid);
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
   delete pi;
   return false;
}

bool Client::msg_set_proj_perms(json_object *obj, Client *c) {
//                  ::logln("Received GET_PROJ_PERMS request", LINFO1);
   if (!c->authenticated) {
      ::logln("unauthorized get project perms request",LERROR);
      c->send_error("Authenication required for this operation");
      return false;
   }
   uint64_t pub, sub;
   uint64_from_json(obj, "pub", &pub);
   pub &= 0x7FFFFFFF;
   uint64_from_json(obj, "sub", &sub);
   sub &= 0x7FFFFFFF;
   ProjectInfo *pi = c->cm->getProjectInfo(c->pid);
   if (c->username == pi->owner) {
      c->cm->updateProjectPerms(c, pub, sub);
   }
   else {
      c->send_error("You are not the owner!");
   }
   delete pi;
   return false;
}
