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

#include "utils.h"
#include "proj_info.h"
#include "client.h"
#include "cli_mgr.h"
#include "buffer.h"

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

   basicMode = true;

   cm = mgr;
   conn = s;
   basicMode = basic;
   
//   ::logln("New Connection", LINFO);

   if (!basicMode) {
     fill_random(challenge, CHALLENGE_SIZE);
     send_data(MSG_INITIAL_CHALLENGE, challenge, CHALLENGE_SIZE);
   }
   else {
      //these are used only for the 'auto auth' in BASIC mode
      Buffer authos;
//      ::logln("sending AUTH_CONNECTED");
      cm->authenticate(this, NULL, NULL, 0, NULL, 0);
      authenticated = true;
      authos.writeInt(AUTH_REPLY_SUCCESS);
      send_data(MSG_AUTH_REPLY, authos.get_buf(), authos.size());
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
void Client::post(const uint8_t *data, int dlen) {
   if (checkPermissions(parseCommand(data, dlen), subscribe)) { 
      //only post if client is subscribing and is allowed to recieve that particular command
      conn->sendAll(data, dlen);
      //::logln("post- datasize: " + data.length);
      stats[0][data[7] & 0xff]++;
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
void Client::send_data(int command, uint8_t *data, int dlen) {
   if (command >= MSG_CONTROL_FIRST) {
      conn->writeInt(8 + dlen);
      conn->writeInt(command);
      conn->write(data, dlen);
//      ::logln("send_data- cmd: " + command + " datasize: " + dlen, LINFO3);
      stats[0][command]++;
   }
   else {
//      ::logln("post should be used for command " + command + ", not send_data.  Data not sent.", LERROR);
   }
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
   Buffer cos;
//   ::logln("Sending forkfollow for " + gpid + " initiated by " + fuser + " at updateid " + lastupdateid, LINFO2);
   cos.writeUTF(fuser.c_str());
   cos.write(gpid.c_str(), gpid.length());
   cos.writeLong(lastupdateid);
   cos.writeUTF(desc.c_str());
   send_data(MSG_PROJECT_FORK_FOLLOW, cos.get_buf(), cos.size());
}

void Client::send_error_msg(string theerror, int type) {
   ::logln("Protocol error detected: " + theerror, LERROR);
   Buffer os;
   os.writeUTF(theerror.c_str());
   uint32_t d = htonl(8 + os.size());
   conn->sendAll(&d, sizeof(d));
   type = htonl(type);
   conn->sendAll(&type, sizeof(type));
   conn->sendAll(os.get_buf(), os.size());
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

int Client::parseCommand(const uint8_t *data, int dlen) {
   return ntohl(*(int*)(data + 4));
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
bool Client::checkPermissions(uint32_t command, uint64_t permType) { 
   bool isallowed = false;
//   ::logln("checking for permission " + command, LDEBUG);
   switch(command) {
      case COMMAND_UNDEFINE: {
         isallowed = ((permType & MASK_UNDEFINE) > 0) ?  true : false; 
         break; 
      }
      case COMMAND_MAKE_CODE: {
         isallowed = ((permType & MASK_MAKE_CODE) > 0) ?  true : false; 
         break; 
      }
      case COMMAND_MAKE_DATA: {
         isallowed = ((permType & MASK_MAKE_DATA) > 0) ?  true : false; 
         break; 
      }
      case COMMAND_SEGM_ADDED:
      case COMMAND_SEGM_DELETED:
      case COMMAND_SEGM_START_CHANGED:
      case COMMAND_SEGM_END_CHANGED:
      case COMMAND_SEGM_MOVED:
      case COMMAND_MOVE_SEGM: {
         isallowed = ((permType & MASK_SEGMENTS) > 0) ?  true : false; 
         break; 
      }
      case COMMAND_SET_STACK_VAR_NAME:  //what category?
      case COMMAND_RENAMED: {
         isallowed = ((permType & MASK_RENAME) > 0) ?  true : false; 
         break; 
      }
      case COMMAND_FUNC_TAIL_APPENDED:
      case COMMAND_FUNC_TAIL_REMOVED:
      case COMMAND_TAIL_OWNER_CHANGED:
      case COMMAND_FUNC_NORET_CHANGED:
      case COMMAND_ADD_FUNC:
      case COMMAND_DEL_FUNC:
      case COMMAND_SET_FUNC_START:
      case COMMAND_SET_FUNC_END: {
         isallowed = ((permType & MASK_FUNCTIONS) > 0) ?  true : false; 
         break; 
      }
      case COMMAND_BYTE_PATCHED: {
         isallowed = ((permType & MASK_BYTE_PATCH) > 0) ?  true : false; 
         break; 
      }
      case COMMAND_AREA_CMT_CHANGED:
      case COMMAND_CMT_CHANGED: {
         isallowed = ((permType & MASK_COMMENTS) > 0) ?  true : false; 
         break; 
      }
      case COMMAND_TI_CHANGED: //?  //what category?
      case COMMAND_OP_TI_CHANGED: //? //what category?
      case COMMAND_OP_TYPE_CHANGED: {
         isallowed = ((permType & MASK_OPTYPES) > 0) ?  true : false; 
         break; 
      }
      case COMMAND_ENUM_CREATED:
      case COMMAND_ENUM_DELETED:
      case COMMAND_ENUM_BF_CHANGED:
      case COMMAND_ENUM_RENAMED:
      case COMMAND_ENUM_CMT_CHANGED:
      case COMMAND_ENUM_CONST_CREATED:
      case COMMAND_ENUM_CONST_DELETED: {
         isallowed = ((permType & MASK_ENUMS) > 0) ?  true : false; 
         break; 
      }
      case COMMAND_STRUC_CREATED:
      case COMMAND_STRUC_DELETED:
      case COMMAND_STRUC_RENAMED:
      case COMMAND_STRUC_EXPANDED:
      case COMMAND_STRUC_CMT_CHANGED:
      case COMMAND_CREATE_STRUC_MEMBER_DATA:
      case COMMAND_CREATE_STRUC_MEMBER_STRUCT:
      case COMMAND_CREATE_STRUC_MEMBER_REF:
      case COMMAND_CREATE_STRUC_MEMBER_STROFF:
      case COMMAND_CREATE_STRUC_MEMBER_STR:
      case COMMAND_CREATE_STRUC_MEMBER_ENUM: 
      case COMMAND_STRUC_MEMBER_DELETED:
      case COMMAND_SET_STRUCT_MEMBER_NAME:
      case COMMAND_STRUC_MEMBER_CHANGED_DATA:
      case COMMAND_STRUC_MEMBER_CHANGED_STRUCT:
      case COMMAND_STRUC_MEMBER_CHANGED_STR:
      case COMMAND_STRUC_MEMBER_CHANGED_OFFSET:
      case COMMAND_STRUC_MEMBER_CHANGED_ENUM: 
      case COMMAND_CREATE_STRUC_MEMBER_OFFSET: {
         isallowed = ((permType & MASK_STRUCTS) > 0) ?  true : false; 
         break; 
      }
      case COMMAND_VALIDATE_FLIRT_FUNC: {
         isallowed = ((permType & MASK_FLIRT) > 0) ?  true : false; 
         break; 
      }
      case COMMAND_THUNK_CREATED: { 
         isallowed = ((permType & MASK_THUNK) > 0) ?  true : false; 
         break; 
      }
      case COMMAND_ADD_CREF:
      case COMMAND_ADD_DREF:
      case COMMAND_DEL_CREF:
      case COMMAND_DEL_DREF: {
         isallowed = ((permType & MASK_XREF) > 0) ?  true : false; 
         break; 
      }
      default:
         //logln("unmatched command " + command + " found in publish switch", LERROR);
         break;
   } //end command switch
   
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
      while (true) {
         Buffer os;
         int len = client->conn->readInt();
         int command = client->conn->readInt();
#ifdef DEBUG
         fprintf(stderr, "received data len: %d, cmd: %d\n", len, command);
#endif
//      ::logln("received data len: " + len + ", cmd: " + command, LDEBUG);
         if (command < MAX_COMMAND && command > 0) {
            client->stats[1][command]++;
         }
         len -= 8;
         if (command < MSG_CONTROL_FIRST) {
            uint8_t *data = new uint8_t[len];
            client->conn->readFully(data, len);
            os.writeInt(len + 16);
            os.writeInt(command);
            os.writeLong(0);  //this is where the updateid will get inserted
            os.write(data, len);
            delete [] data;
            //only accept commands if the client is authenticated
            if (client->authenticated && (client->publish > 0)) {
               //only post if this client chose to publish, 
               //(though they really shouldn't have sent any data if they are not publishing)
               if (client->checkPermissions(command, client->publish)) { 
   //               ::logln("posting command " + command + " (allowed to  publish) ", LDEBUG);
                  client->cm->post(client, command, os.get_buf(), os.size());
               }
               else {
   //               ::logln("not allowed to perform command: " + command, LINFO);
                      // if (errorAlreadySentMask
                      // send_error("you are not allowed to byte patch");
                      // errorAlreadySentMask |= MASK_BYTE_PATCHED;
                      // ::logln("sent errors is " + errorAlreadySentMask);
               }
            }
            else {
   /*
               ::logln("Client " + hash + ":" + conn.getInetAddress().getHostAddress()
                                  + ":" + conn.getPeerPort() + " skipping post command.", LINFO);
   */
            }
         }
         else { //server only command
            switch (command) {
               case MSG_PROJECT_NEW_REQUEST: {
//                  ::logln("in NEW PROJECT REQUEST", LDEBUG);
                  uint8_t md5[MD5_SIZE];
                  client->conn->readFully(md5, MD5_SIZE);
                  client->hash = toHexString(md5, MD5_SIZE);
                  string desc = client->conn->readUTF();
                  uint64_t pub = client->conn->readLong() & 0x7FFFFFFF;
                  uint64_t sub = client->conn->readLong() & 0x7FFFFFFF;
                  if (!client->authenticated) {
                     //nice try!!
                     break;
                  }
   //                  ::logln("desired new project pub " + pub + ", and sub " + sub);
                  int lpid = client->cm->addProject(client, client->hash, desc, pub, sub);
                  if (lpid >= 0) {
//                     ::logln("NEW PROJECT REQUEST success", LINFO);
                     os.writeInt(JOIN_REPLY_SUCCESS);
                     uint8_t *gp = toByteArray(client->gpid);
                     os.write(gp, client->gpid.length() / 2);
                     delete [] gp;
                  }
                  else {
//                     ::logln("NEW PROJECT REQUEST fail", LINFO);
                     os.writeInt(JOIN_REPLY_FAIL);
                  }
                  client->send_data(MSG_PROJECT_JOIN_REPLY, os.get_buf(), os.size());
                  break;
               }
               case MSG_PROJECT_JOIN_REQUEST: {
                  int lpid = client->conn->readInt();
                  uint64_t tpub = client->conn->readLong() & 0x7FFFFFFF;
                  uint64_t tsub = client->conn->readLong() & 0x7FFFFFFF; 
                  if (!client->authenticated) {
                     //nice try!!
                     break;
                  }
                  client->rpublish = tpub;
                  client->rsubscribe = tsub;
   //               ::logln("attempting to join project " + lpid, LINFO);
                  if (client->cm->joinProject(client, lpid) >= 0 ) {
                     os.writeInt(JOIN_REPLY_SUCCESS);
                     uint8_t *gp = toByteArray(client->gpid);
                     os.write(gp, client->gpid.length() / 2);
                     delete [] gp;
   //                  ::logln("...success" + lpid, LINFO);
                  }
                  else {
                     os.writeInt(JOIN_REPLY_FAIL);
   //                  ::logln("...failed" + lpid, LINFO);
                  }
                  client->send_data(MSG_PROJECT_JOIN_REPLY, os.get_buf(), os.size());
                  break;               
               }
               case MSG_PROJECT_REJOIN_REQUEST: {
//                  ::logln("in PROJECT_REJOIN_REQUEST", LDEBUG);
                  uint8_t gp[GPID_SIZE];
                  int rejoingbasic = 0;
                  client->conn->readFully(gp, GPID_SIZE);
                  string gpid = toHexString(gp, GPID_SIZE);
                  if ( isNumeric(gpid) ) {
                     uint32_t gpi = -1;
                     sscanf(gpid.c_str(), "%d", &gpi);
                     if ( gpi == 0 ) { 
                        //basic mode pid was stored in netnode
                        client->send_error("This instance of IDA connected in basic mode, cannot reconnect.");
                        break;
                     }
                  }
                  int lpid = client->cm->gpid2lpid(gpid);
                  uint64_t tpub = client->conn->readLong() & 0x7FFFFFFF;
                  uint64_t tsub = client->conn->readLong() & 0x7FFFFFFF; 
                  if (!client->authenticated) {
                     ::logln("unauthorized project rejoin request", LERROR);
                     client->send_error("Authenication required for this operation");
                     break;
                  }
                  client->rpublish = tpub;
                  client->rsubscribe = tsub; 
   //                  ::logln("plugin requested rpub: " + rpublish + " rsub: " + rsubscribe);
                  if (client->cm->joinProject(client, lpid) >= 0 ) {
                     os.writeInt(JOIN_REPLY_SUCCESS);
                     os.write(gp, sizeof(gp));
                     client->send_data(MSG_PROJECT_JOIN_REPLY, os.get_buf(), os.size());
                  }
                  else {
                     os.writeInt(JOIN_REPLY_FAIL);
                     client->send_data(MSG_PROJECT_JOIN_REPLY, os.get_buf(), os.size());
                     client->send_error("Tried to join a project that doesn't exist on this server:" + gpid);
                     client->send_fatal("This idb is associated with a project not found on this server.\n Maybe you connected to the wrong collabREate server,\n or maybe the project has been deleted...");
                     goto end_loop;
                  }
                  break;               
               }
               case MSG_PROJECT_SNAPSHOT_REQUEST: {
//                  ::logln("in SNAPSHOT REQ", LDEBUG);
                  string desc = client->conn->readUTF();
                  uint64_t lastupdateid = client->conn->readLong();
                  if (!client->authenticated) {
                     ::logln("unauthorized project snapshot request", LERROR);
                     client->send_error("Authenication required for this operation");
                     os.writeInt(PROJECT_SNAPSHOT_FAIL);
                     client->send_data(MSG_PROJECT_SNAPSHOT_REPLY, os.get_buf(), os.size());
                     break;
                  }
                  if (lastupdateid <= 0 ) {
                     ::logln("attempt to add snapshot with 0 or less updates applied", LINFO);
                     client->send_error("snapshots with 0 or less updates are not allowed - start a new project instead");
                     os.writeInt(PROJECT_SNAPSHOT_FAIL);
                     client->send_data(MSG_PROJECT_SNAPSHOT_REPLY, os.get_buf(), os.size());
                     break;
                  }
                  if (client->cm->snapProject(client, lastupdateid, desc) >= 0) { 
                     os.writeInt(PROJECT_SNAPSHOT_SUCCESS);
                  }
                  else {
                     os.writeInt(PROJECT_SNAPSHOT_FAIL);
                  }
                  client->send_data(MSG_PROJECT_SNAPSHOT_REPLY, os.get_buf(), os.size());
                  break;
               }
               case MSG_PROJECT_FORK_REQUEST: {
                  uint64_t lastupdateid = client->conn->readLong();
                  string desc = client->conn->readUTF();
//                  ::logln("in FORK REQUEST", LDEBUG);
                  if (!client->authenticated) {
                     ::logln("unauthorized project fork request", LERROR);
                     client->send_error("Authenication required for this operation");
                     os.writeInt(JOIN_REPLY_FAIL);
                     client->send_data(MSG_PROJECT_JOIN_REPLY, os.get_buf(), os.size());
                     break;
                  }
   
                  //if the user set these at the time of the fork
                  //they would be read here.  Instead we allow the owner to
                  //manage permissions at any time via the modal dialog box
                  //uint64_t pub = client->conn->readLong() & 0x7FFFFFFF;
                  //uint64_t sub = client->conn->readLong() & 0x7FFFFFFF;
                  //if (client->cm->forkProject(client, lastupdateid, desc, pub, sub) >= 0) { 
                  if (client->cm->forkProject(client, lastupdateid, desc) >= 0) { 
                     //on successfull fork, join the 'new' project automatically
                     os.writeInt(JOIN_REPLY_SUCCESS);
                     uint8_t *gp = toByteArray(client->gpid);
                     os.write(gp, client->gpid.length() / 2);
                     delete [] gp;
                  }
                  else {
                     os.writeInt(JOIN_REPLY_FAIL);
                  }
                  client->send_data(MSG_PROJECT_JOIN_REPLY, os.get_buf(), os.size());
                  break;
               }
               case MSG_PROJECT_SNAPFORK_REQUEST: {
//                  ::logln("in SNAPFORK REQUEST", LDEBUG);
                  int lpid = client->conn->readInt();
                  string desc = client->conn->readUTF();
                  uint64_t pub = client->conn->readLong() & 0x7FFFFFFF;
                  uint64_t sub = client->conn->readLong() & 0x7FFFFFFF;
                  if (!client->authenticated) {
                     ::logln("unauthorized project snapfork request", LERROR);
                     client->send_error("Authenication required for this operation");
                     os.writeInt(JOIN_REPLY_FAIL);
                     client->send_data(MSG_PROJECT_JOIN_REPLY, os.get_buf(), os.size());
                     break;
                  }
   //               ::logln("got " + lpid + ": " + desc, LDEBUG);
                  if (client->cm->snapforkProject(client, lpid, desc, pub, sub) >= 0) { 
                     //on successfull fork from snapshop, join the 'new' project automatically
                     os.writeInt(JOIN_REPLY_SUCCESS);
                     uint8_t *gp = toByteArray(client->gpid);
                     os.write(gp, client->gpid.length() / 2);
                     delete [] gp;
                  }
                  else {
                     os.writeInt(JOIN_REPLY_FAIL);
                  }
                  client->send_data(MSG_PROJECT_JOIN_REPLY, os.get_buf(), os.size());
                  break;
               }
               case MSG_PROJECT_LEAVE: {
//                  ::logln("in PROJECT LEAVE", LDEBUG);
                  if (!client->authenticated) {
                     ::logln("unauthorized project leave request", LERROR);
                     client->send_error("Authenication required for this operation");
                     break;
                  }
                  client->cm->remove(client);
                  break;
               }
               case MSG_PROJECT_JOIN_REPLY:                 
                  break;
               case MSG_AUTH_REQUEST: {
//                  ::logln("in AUTH REQUEST", LDEBUG);
                  int pluginversion = client->conn->readInt();
                  if (pluginversion != PROTOCOL_VERSION) {
                     char buf[256];
                     snprintf(buf, sizeof(buf), "Version mismatch. plugin: %d server: %d", pluginversion, PROTOCOL_VERSION);
   #ifdef DEBUG
                     fprintf(stderr, "%s\n", buf);
   #endif
                     client->send_error(buf);
   //                  ::logln("Version mismatch. plugin: " + pluginversion + " server: " + PROTOCOL_VERSION, LERROR);
                     goto end_loop;
                  }
                  if (!client->authenticated) {
                     uint8_t resp[MD5_SIZE];
                     client->username = client->conn->readUTF();
//                     ::logln("got user: " + client->username, LDEBUG);
                     if (client->conn->readFully(resp, sizeof(resp)) != MD5_SIZE) {
                        ::logln("Malformed AUTH REQUEST - failed to read hmac response", LERROR);
                        client->send_error("Malformed AUTH_REQUEST");
                        goto end_loop;  //disconnect
                     }
   
                     client->uid = client->cm->authenticate(client, client->username.c_str(), client->challenge, CHALLENGE_SIZE, resp, MD5_SIZE);
                     if (client->uid != INVALID_USER) {
                        client->authenticated = true;
   #ifdef DEBUG
                        fprintf(stderr, "uid set to %d\n", client->uid);
   #endif
                        //::logln("uid set to "+ uid);
                        os.writeInt(AUTH_REPLY_SUCCESS);
                     }
                     else {
   #ifdef DEBUG
                        ::logln("AUTH_REPLY_FAIL");
   #endif
                        os.writeInt(AUTH_REPLY_FAIL);
                        client->authTries--;
                     }
                     client->send_data(MSG_AUTH_REPLY, os.get_buf(), os.size());
                     if (client->authTries == 0) {
                        ::logln("too many auth attempts for " + client->getUser(), LERROR);
                        goto end_loop;
                     }
                  }
                  else {
                     ::logln("recv AUTH REQUEST when already authenticated", LERROR);
                     client->send_error("Attempt to Authenticate, when already authenticated");
                  }                     
                  break;
               }
               case MSG_PROJECT_LIST:
                  if (len != MD5_SIZE) { //len + cmd alread accounted for
                     client->send_error("Malformed Project getlist request");
                  }
                  else {
                     uint8_t md5[MD5_SIZE];
                     if (client->conn->readFully(md5, sizeof(md5)) != MD5_SIZE) {
                        ::logln("Malformed MSG_PROJECT_LIST - failed to read file md5", LERROR);
                        client->send_error("Malformed MSG_PROJECT_LIST");
                        goto end_loop;  //disconnect
                     }
                     if (!client->authenticated) {
                        //nice try!!
                        break;
                     }
                     client->hash = toHexString(md5, MD5_SIZE);
//                     ::logln("project hash: " + client->hash, LINFO4);                     
                     vector<ProjectInfo*> *plist = client->cm->getProjectList(client->hash);
                     int nump = plist->size();
                     os.writeInt(nump);   //send number of elements to come
   //                  ::logln(" Found  " + nump + " projects", LINFO3);
                     //create list of projects
                     for (vector<ProjectInfo*>::iterator pi = plist->begin(); pi != plist->end(); pi++) {
   //                     log(" " + pi.lpid + " "+ pi.desc, LINFO4);
                        os.writeInt((*pi)->lpid);
                        os.writeLong((*pi)->snapupdateid);
                        if ((*pi)->parent > 0) {
                           if ((*pi)->snapupdateid > 0) {
                              char buf[256];
                              snprintf(buf, sizeof(buf), "[-] %s (SNAP of '%s'@%lld updates])", (*pi)->desc.c_str(), (*pi)->pdesc.c_str(), (*pi)->snapupdateid);
                              os.writeUTF(buf); 
   //                           log("[-] " + pi.desc + " (snapshot of (" + pi.parent + ")'" + pi.pdesc+"' ["+ pi.snapupdateid + " updates]) ", LDEBUG); 
                           }
                           else {
                              char buf[256];
                              snprintf(buf, sizeof(buf), "[%d] %s (FORK of '%s')", (*pi)->connected, (*pi)->desc.c_str(), (*pi)->pdesc.c_str());
                              os.writeUTF(buf); 
   //                           log("[" + pi.connected + "] " + pi.desc + " (forked from (" + pi.parent + ") '" + pi.pdesc +"')", LDEBUG); 
                           }
                        }
                        else {
                           char buf[128];
                           snprintf(buf, sizeof(buf), "[%d] %s", (*pi)->connected, (*pi)->desc.c_str());
                           os.writeUTF(buf);
                        }
                        //since the user permissions may already limit the eventual effective permissions
                        //only show the user the maximum attainable by this particular user (mask)
                        //upublish = usubscribe = FULL_PERMISSIONS;  //quick BASIC mode test
                        os.writeLong((*pi)->pub & client->upublish);
                        os.writeLong((*pi)->sub & client->usubscribe);
   //                     ::logln("", LDEBUG);
   //                     ::logln("pP " + (*pi)->pub + " pS " + (*pi)->sub, LINFO4);
   //                     ::logln("uP " + client->upublish + " uS " + client->usubscribe, LINFO4);
                        delete *pi;
                     }
                     delete plist;
                     //also append list of permissions supported by this server
                     os.writeInt(permStringsLength);
                     for ( int i = 0; permStrings[i]; i++) {
                        os.writeUTF(permStrings[i]);
                     }
   
                     client->send_data(MSG_PROJECT_LIST, os.get_buf(), os.size());
                  }
                  break;
               case MSG_SEND_UPDATES: {
                  uint64_t lastupdate = client->conn->readLong();
                  if (!client->authenticated) {
                     //nice try!!
                     break;
                  }
   //               ::logln("Received client->send_UPDATES request for " + lastupdate + " to current", LINFO1);
                  client->cm->sendLatestUpdates(client, lastupdate);
                     
                  break;
               }
               case MSG_SET_REQ_PERMS: {
//                  ::logln("Received SET_REQ_PERMS request", LINFO1);
                  uint64_t tpub = client->conn->readLong() & 0x7FFFFFFF;
                  uint64_t tsub = client->conn->readLong() & 0x7FFFFFFF;
                  if (!client->authenticated) {
                     ::logln("unauthorized get req perms request",LERROR);
                     client->send_error("Authenication required for this operation");
                     break;
                  }
   
                  client->rpublish = tpub;
                  client->rsubscribe = tsub;
                  ProjectInfo *pi = client->cm->getProjectInfo(client->pid);
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
                  if ( client->uid != pi->owner ) {
                     client->setPub(pi->pub & client->upublish & client->rpublish);
                     client->setSub(pi->sub & client->usubscribe & client->rsubscribe);
                  }
                  else {
                     ::logln("not honoring SET_REQ_PERMS for owner", LINFO1);
                     client->send_error("You are the owner.  FULL permissions granted.");
                  }
                  delete pi;
                  break;
               }
               case MSG_GET_REQ_PERMS: {
//                  ::logln("Received GET_REQ_PERMS request", LINFO1);
                  if (!client->authenticated) {
                     ::logln("unauthorized get req perms request",LERROR);
                     client->send_error("Authenication required for this operation");
                     break;
                  }
                  //send the two requested permissions
                  os.writeLong(client->rpublish);
                  os.writeLong(client->rsubscribe); 
                  //send the max possible values for requested permissions (mask)
                  ProjectInfo *pi = client->cm->getProjectInfo(client->pid);
                  os.writeLong(pi->pub & client->upublish);
                  os.writeLong(pi->sub & client->usubscribe);
                  //also append list of permissions supported by this server
                  os.writeInt(permStringsLength);
                  for (int i = 0; permStrings[i]; i++) {
                     os.writeUTF(permStrings[i]);
                  }
                  client->send_data(MSG_GET_REQ_PERMS_REPLY, os.get_buf(), os.size());
                  delete pi;
                  break;
               }
               case MSG_GET_PROJ_PERMS: {
//                  ::logln("Received GET_PROJ_PERMS request", LINFO1);
                  if (!client->authenticated) {
                     ::logln("unauthorized get project perms request",LERROR);
                     client->send_error("Authenication required for this operation");
                     break;
                  }
                  ProjectInfo *pi = client->cm->getProjectInfo(client->pid);
                  if (client->uid == pi->owner) {
                     //send the two project permissions
                     os.writeLong(pi->pub);
                     os.writeLong(pi->sub); 
                     //sing this is the owner managing possible values for requested permissions (mask) is full
                     os.writeLong(FULL_PERMISSIONS);
                     os.writeLong(FULL_PERMISSIONS);
                     //also appent list of permissions supported by this server
                     os.writeInt(permStringsLength);
                     for (int i = 0; permStrings[i]; i++) {
                        os.writeUTF(permStrings[i]);
                     }
                     client->send_data(MSG_GET_PROJ_PERMS_REPLY, os.get_buf(), os.size());
                  }
                  else {
                     client->send_error("You are not the owner!");
                  }
                  delete pi;
                  break;
               }
               case MSG_SET_PROJ_PERMS: {
//                  ::logln("Received GET_PROJ_PERMS request", LINFO1);
                  uint64_t pub = client->conn->readLong() & 0x7FFFFFFF;
                  uint64_t sub = client->conn->readLong() & 0x7FFFFFFF;
                  if (!client->authenticated) {
                     ::logln("unauthorized get project perms request",LERROR);
                     client->send_error("Authenication required for this operation");
                     break;
                  }
                  ProjectInfo *pi = client->cm->getProjectInfo(client->pid);
                  if (client->uid == pi->owner) {
                     client->cm->updateProjectPerms(client, pub, sub);
                  }
                  else {
                     client->send_error("You are not the owner!");
                  }
                  delete pi;
                  break;
               }
               default:
   //               ::logln("Unknown MSG command " + command + " ignoring.", LINFO1);
                  break;
            }
         }
      }
   } catch (IOException ex) {
   }
end_loop:
   client->terminate();
   delete client;   
   return NULL;
}
