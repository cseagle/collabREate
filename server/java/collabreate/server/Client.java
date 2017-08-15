/*
    collabREate Client
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

package collabreate.server;

import java.io.*;
import java.net.*;
import java.sql.*;
import java.util.*;
import com.google.gson.*;

/**
 * Client
 * This class is responsible for a single client connection
 * It handles the initial client interaction, then reads
 * incoming client commands and kicks them up to the ConnectionManager
 * which farms the commands out to all interested clients
 * @author Tim Vidas
 * @author Chris Eagle
 * @version 0.2.0, January 2017
 */


public class Client extends Thread implements CollabreateConstants {

   private interface ClientMsgHandler {
      public boolean handle(JsonObject obj, Client c);
   }

   private static Hashtable<String,ClientMsgHandler> handlers;
   private static Hashtable<String,Long> perms_map;
   
   static {
      init_handlers();
   }

   /**
    * Constant to check for an invalid uid
    */
   public static final int INVALID_USER = -1;
   /**
    * Constant to use for uid when in BASIC_MODE
    */
   public static final int BASIC_USER = 0;

   public static Gson gson = new Gson();

   private Socket conn;
   private String hash = "";
   private String username;
   public JsonStreamParser parser;
   private PrintStream ps;
   //effective, combined permissions (project & user & requested), used for checks
   private long publish = 0;
   private long subscribe = 0;
   //the permissions for the user account, read from database
   private long upublish = 0;
   private long usubscribe = 0;
   //the requested permissions sent from the plugin
   private long rpublish = 0;
   private long rsubscribe = 0;
   private boolean authenticated = false;
   private static final byte[] ok = {(byte)'O', (byte)'K', (byte)0};
   private static final byte[] fail = {(byte)'F', (byte)'A', (byte)'I', (byte)'L', (byte)0};

   private int uid = -1;  //user id associated with this connection
   private int pid = -1;
   private int authTries = 3;
   private String gpid = "";  //project id associated with this connection
   private byte[] challenge = new byte[CHALLENGE_SIZE];

   private ConnectionManagerBase cm;

   private int stats[][] = new int[2][MAX_COMMAND];

   private boolean basicMode = true;

   public Client(ConnectionManagerBase mgr, Socket s, boolean basic) throws Exception {
      cm = mgr;
      conn = s;
      parser = new JsonStreamParser(new InputStreamReader(s.getInputStream()));
      ps = new PrintStream(s.getOutputStream(), true);
      basicMode = basic;

      logln("New Connection", LINFO);

      if (!basicMode) {
         challenge = Utils.getRandom(CHALLENGE_SIZE);
         String hex = Utils.toHexString(challenge);
         JsonObject json = new JsonObject();
         json.addProperty("challenge", hex);
         send_data(MSG_INITIAL_CHALLENGE, json);
      }
      else {
         //these are used only for the 'auto auth' in BASIC mode
         logln("sending AUTH_CONNECTED");
         cm.authenticate(this, null, null, null);
         authenticated = true;
         JsonObject json = new JsonObject();
         json.addProperty("reply", AUTH_REPLY_SUCCESS);
         send_data(MSG_AUTH_REPLY, json);
      }
      //the dummy gpid need to consist entirely of hex values.
      gpid = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
   }

   public void send_json(JsonObject json) {
      ps.println(json.toString());
   }

   /**
    * logs a message to the configured log file (in the ConnectionManager)
    * @param msg the string to log
    */
   protected void log(String msg) {
      log(msg, 0);
   }

   /**
    * logs a message to the configured log file (in the ConnectionManager)
    * @param msg the string to log
    * @param v apply a verbosity level to the msg
    */
   protected void log(String msg, int v) {
      String clientIP = null;
      String user = "";
      try {
         clientIP = conn.getInetAddress().getHostAddress() + ":" + conn.getPort();
      } catch (Exception ex) {
      }
      if (username != null) {
         user = " (" + username + ":" + uid + ")";
      }
      cm.log("[" + clientIP + user + "] " + msg, v);
   }

   /**
    * logs a message using log() (with newline)
    * @param msg the string to log
    * @param v apply a verbosity level to the msg
    */
   protected void logln(String msg, int v) {
      log(msg + "\n", v);
   }

   /**
    * logs a message using log() (with newline)
    * @param msg the string to log
    */
   protected void logln(String msg) {
      logln(msg, 0);
   }

   /**
    * logs an exception to the configured log file (in the ConnectionManager)
    * @param ex the execption to log
    * @param v apply a verbosity level to the ex
    */
   protected void logex(Exception ex, int v) {
      logln("Exception, trace follows:", v);
      cm.logex(ex, v);
   }

   /**
    * logs an exception to the configured log file (in the ConnectionManager)
    * @param ex the execption to log
    */
   protected void logex(Exception ex) {
      logex(ex, 0);
   }

   /**
    * getHash inspector to get the hash value (unique per binary in IDA, generated by IDA) of the client
    * @return the hash
    */
   protected String getHash() {
      return hash;
   }

   /**
    * setHash mutator function to set the hash value (uniqure per binary in IDA, generated by IDA) of the client
    * @param phash the hash value
    */
   protected void setHash(String phash) {
      hash = phash;
   }

   /**
    * getGpid inspector to get the gpid (global project id unique across server instances) value
    * @return the global pid
    */
   protected String getGpid() {
      return gpid;
   }

   /**
    * getGpid mutator to set the gpid (global project id unique across server instances) value
    * @param gpid the global pid value
    */
   protected void setGpid(String gpid) {
      this.gpid = gpid;
   }

   /**
    * getPid inspector to get the pid (local project id, unigue to this server instance only) value
    * @return pid this local pid
    */
   protected int getPid() {
      return pid;
   }

   /**
    * getPid mutator to set the pid (local project id, unigue to this server instance only) value
    * @param p the project pid
    */
   protected void setPid(int p) {
      logln("set client pid to " + p, LINFO1);
      pid = p;
   }

   /**
    * getUid inspector to get the user id associated with this server
    * @return the user id
    */
   protected int getUid() {
      return uid;
   }

   /**
    * getUid mutator to set the user id associated with this server
    * @param u the userid
    */
   protected void setUid(int u) {
      uid = u;
   }

   /**
    * post is the function that actually posts updates to clients (if subscribing)
    * @param data the bytearray containing the update to send
    */
   public void post(String msg, JsonObject json) throws Exception {
      if (checkPermissions(msg, subscribe)) {
         //only post if client is subscribing and is allowed to recieve that particular command
         send_json(json);
         //logln("post- datasize: " + data.length);
//         stats[0][data[7] & 0xff]++;
      }
      else {
         logln("Client " + hash + ":" + conn.getInetAddress().getHostAddress()
                            + ":" + conn.getPort() + " failed to post data. "
                            + " (probably subscribe permission: "
                            + msg + ")", LINFO3);
      }
   }

   /**
    * similar to post, but does not check subscription status, and takes command as a arg
    * This function should ONLY be called for message id >= MSG_CONTROL_FIRST
    * because these messages do not contain an updateid
    * @param command the command to send
    * @param data the data associated with the command
    */
   protected void send_data(String command, JsonObject json) {
      try {
         json.addProperty("type", command);
         send_json(json);
/*
         if (command >= MSG_CONTROL_FIRST) {
            data = "{" + String.format("\"command\":%u", command) + "," + data.substring(1);
            dos.writeInt(data.length());
            dos.write(data);
            dos.flush();
            logln("send_data- cmd: " + data, LINFO3);
//            stats[0][command]++;
         }
         else {
            logln("post should be used for command " + command + ", not send_data.  Data not sent.", LERROR);
         }
*/
      } catch (Exception ex) {
         logex(ex);
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
   protected void sendForkFollow(String fuser, String gpid, long lastupdateid, String desc) {
      try {
         logln("Sending forkfollow for " + gpid + " initiated by " + fuser + " at updateid " + lastupdateid, LINFO2);
         JsonObject json = new JsonObject();
         json.addProperty("user", fuser);
         json.addProperty("gpid", gpid);
         json.addProperty("lastupdateid", lastupdateid);
         json.addProperty("description", desc);
         send_data(MSG_PROJECT_FORK_FOLLOW, json);
      } catch ( Exception ex) {
         logex(ex);
      }
   }

   protected void send_error_msg(String theerror, String type) {
      try {
         logln("Protocol error detected: " + theerror,LERROR);
         JsonObject json = new JsonObject();
         json.addProperty("error", theerror);
         send_data(type, json);
      } catch ( Exception ex) {
         logex(ex);
      }
   }

   /**
    * send_error sends an error string to the plugin
    * @param theerror this error string to send
    */
   protected void send_error(String theerror) {
      try {
         send_error_msg(theerror, MSG_ERROR);
      } catch ( Exception ex) {
         logex(ex);
      }
   }

   /**
    * send_fatal sends an error string to the plugin, this is idential to send_error except
    * for the message type, the intent is that the semantics on the plugin side are different
    * @param theerror this error string to send
    */
   protected void send_fatal(String theerror) {
      try {
         send_error_msg(theerror, MSG_FATAL);
      } catch ( Exception ex) {
         logex(ex);
      }
   }

   /**
    * terminate closes the client's connection, removes this client from the connection manager
    */
   protected void terminate() {
      try {
         logln("Client " + hash + ":" + conn.getInetAddress().getHostAddress()
                            + ":" + conn.getPort() + " terminating", LINFO);
         conn.close();
      } catch (Exception ex) {
         logex(ex);
      }
      cm.remove(this);
   }

   /**
    * run this is the main thread for the Client class, it continually loops, receiving commands
    * and performing appropriate actions for each command
    */
   public void run() {
      try {
         main_loop:
         while (true) {
            JsonElement json_e = parser.next();
            if (!json_e.isJsonObject()) {
               break;
            }
            JsonObject json = (JsonObject)json_e;
            String command = json.getAsJsonPrimitive("type").getAsString();
            if (handlers.containsKey(command)) {
               ClientMsgHandler cmh = handlers.get(command);
               if (cmh.handle(json, this)) {
                  break;
               }
            }
            else if (authenticated && (publish > 0)) {
               //only accept commands if the client is authenticated
               //only post if this client chose to publish,
               //(though they really shouldn't have sent any data if they are not publishing)
               if (checkPermissions(command, publish)) {
                  logln("posting command " + command + " (allowed to  publish) ", LDEBUG);
                  cm.post(this, command, json);
               }
               else {
                  logln("not allowed to perform command: " + command, LINFO);
                      // if (errorAlreadySentMask
                      // send_error("you are not allowed to byte patch");
                      // errorAlreadySentMask |= MASK_BYTE_PATCHED;
                      // logln("sent errors is " + errorAlreadySentMask);
               }
            }
            else {
               logln("Client " + hash + ":" + conn.getInetAddress().getHostAddress()
                                  + ":" + conn.getPort() + " skipping post command.", LINFO);
            }
         }
      } catch (Exception ex) {
         logln("printing stack trace:\n", LERROR);
         logex(ex);
      }
      terminate();
   }

   /**
    * dumpStats displace the receive / transmit stats for each command
    */
   protected String dumpStats() {
      StringBuffer sb = new StringBuffer();
      sb.append("Stats for " + hash + ":" + conn.getInetAddress().getHostAddress() + ":" + conn.getPort() + "\n");
      sb.append("command     rx     tx\n");
      for (int i = 0; i < 256; i++) {
         if (stats[0][i] != 0 || stats[1][i] != 0) {
            String c = "     " + i;
            c = c.substring(c.length() - 5);
            String in = "       " + stats[0][i];
            in = in.substring(in.length() - 7);
            String out = "       " + stats[1][i];
            out = out.substring(out.length() - 7);
            sb.append(c + " " + in + " " + out + "\n");
         }
      }
      return sb.toString();
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
   private boolean checkPermissions(String command, long permType) {
      boolean isallowed = false;
      logln("checking for permission " + command, LDEBUG);
      if (perms_map.containsKey(command)) {
         long mask = perms_map.get(command);
         isallowed = (permType & mask) > 0;         
      }
      else {
         logln("unmatched command " + command + " found in checkPermissions", LERROR);
      }
      return isallowed;
   }

   /**
    * getPort inspector to get the TCP port number of the connection
    * @return the TCP port
    */
   protected int getPort() {
      return conn.getPort();
   }

   /**
    * getAddr inspector to get the IP address of the connection
    * @return the IP address
    */
   protected String getAddr() {
      return conn.getInetAddress().getHostAddress();
   }

   /**
    * setReqPub mutator to set the publish status of the session requested perms stored in the client
    * @param p the users req publish status
    */
   protected void setReqPub(long p) {
      rpublish = p;
   }

   /**
    * setReqSub mutator to set the subscription status of the session requested perms stored in the client
    * @param s the users req subscribe status
    */
   protected void setReqSub(long s) {
      rsubscribe = s;
   }
   /**
    * getReqPub inspector to get the publish status of the session requested perms stored in the client
    * @return the users req publish status
    */
   protected long getReqPub() {
      return rpublish;
   }

   /**
    * getReqSub inspector to get the subscription status of the session requested perms stored in the client
    * @return the users req subscribe status
    */
   protected long getReqSub() {
      return rsubscribe;
   }
   /**
    * setUserPub mutator to set the publish status of the user stored in the client
    * @param p the users publish status
    */
   protected void setUserPub(long p) {
      upublish = p;
   }

   /**
    * setUserSub mutator to set the subscription status of the user stored in the client
    * @param s the users subscribe status
    */
   protected void setUserSub(long s) {
      usubscribe = s;
   }
   /**
    * getUserPub inspector to get the publish status of the user stored in the client
    * @return the users publish status
    */
   protected long getUserPub() {
      return upublish;
   }

   /**
    * getUserSub inspector to get the subscription status of the user stored in the client
    * @return the users subscribe status
    */
   protected long getUserSub() {
      return usubscribe;
   }

   /**
    * setPub mutator to set the effective publish status of the client
    * @param p the publish status
    */
   protected void setPub(long p) {
      publish = p;
   }

   /**
    * setSub mutator to set the effective subscription status of the client
    * @param s the subscribe status
    */
   protected void setSub(long s) {
      subscribe = s;
   }
   /**
    * getPub inspector to get the effective publish status of the client
    * @return the publish status
    */
   protected long getPub() {
      return publish;
   }

   /**
    * getSub inspector to get the effective subscription status of the client
    * @return the subscribe status
    */
   protected long getSub() {
      return subscribe;
   }

   /**
    * getUser inspector to get the Username assocaited with the client
    * @return the username
    */
   protected String getUser() {
      return username;
   }

   //protected void sendProjectJoinReply(int lpid) {
   //   return;
   //}

   private static class msg_project_new_request implements ClientMsgHandler {
      public boolean handle(JsonObject json, Client c) {
         c.logln("in NEW PROJECT REQUEST", LDEBUG);
         try {
            c.hash = json.getAsJsonPrimitive("md5").getAsString();
            String desc = json.getAsJsonPrimitive("description").getAsString();
            long pub = json.getAsJsonPrimitive("pub").getAsLong() & 0x7FFFFFFF;
            long sub = json.getAsJsonPrimitive("sub").getAsLong() & 0x7FFFFFFF;
            if (c.authenticated) {
               JsonObject resp = new JsonObject();
               c.logln("desired new project pub " + pub + ", and sub " + sub);
               int lpid = c.cm.addProject(c, c.hash, desc, pub, sub);
               if (lpid >= 0) {
                  c.logln("NEW PROJECT REQUEST success", LINFO);
                  resp.addProperty("reply", JOIN_REPLY_SUCCESS);
                  resp.addProperty("gpid", c.gpid);
               }
               else {
                  c.logln("NEW PROJECT REQUEST fail", LINFO);
                  resp.addProperty("reply", JOIN_REPLY_FAIL);
               }
               c.send_data(MSG_PROJECT_JOIN_REPLY, resp);
            }
         } catch (Exception ex) {
            c.logln("Malformed NEW PROJECT REQUEST - failed to read md5", LERROR);
            c.send_error("Malformed NEW_PROJECT_REQUEST");
         }
         return false;
      }
   }

   private static class msg_project_join_request implements ClientMsgHandler {
      public boolean handle(JsonObject json, Client c) {
         if (c.authenticated) {
            int lpid = json.getAsJsonPrimitive("project").getAsInt();
            long tpub = json.getAsJsonPrimitive("pub").getAsLong() & 0x7FFFFFFF;
            long tsub = json.getAsJsonPrimitive("sub").getAsLong() & 0x7FFFFFFF;
            JsonObject resp = new JsonObject();
            c.rpublish = tpub;
            c.rsubscribe = tsub;
            c.logln("attempting to join project " + lpid, LINFO);
            if (c.cm.joinProject(c, lpid) >= 0 ) {
               resp.addProperty("reply", JOIN_REPLY_SUCCESS);
               resp.addProperty("gpid", c.gpid);
               c.logln("...success" + lpid, LINFO);
            }
            else {
               resp.addProperty("reply", JOIN_REPLY_FAIL);
               c.logln("...failed" + lpid, LINFO);
            }
            c.send_data(MSG_PROJECT_JOIN_REPLY, resp);
         }
         return false;
      }
   }

   private static class msg_project_rejoin_request implements ClientMsgHandler {
      public boolean handle(JsonObject json, Client c) {
         c.logln("in PROJECT_REJOIN_REQUEST", LDEBUG);
         String _gpid = json.getAsJsonPrimitive("gpid").getAsString();
         int rejoingbasic = 0;
         try {
            if ( Utils.isNumeric(_gpid) && Integer.parseInt(_gpid) == 0 ) {
               //basic mode pid was stored in netnode
               c.send_error("This instance of IDA connected in basic mode, cannot reconnect.");
            }
            else {
               if (!c.authenticated) {
                  c.logln("unauthorized project rejoin request", LERROR);
                  c.send_error("Authenication required for this operation");
               }
               else {
                  int lpid = c.cm.gpid2lpid(_gpid);
                  c.rpublish = json.getAsJsonPrimitive("pub").getAsLong() & 0x7FFFFFFF;;
                  c.rsubscribe = json.getAsJsonPrimitive("sub").getAsLong() & 0x7FFFFFFF;
                  c.logln("plugin requested rpub: " + c.rpublish + " rsub: " + c.rsubscribe);
                  JsonObject resp = new JsonObject();
                  if (c.cm.joinProject(c, lpid) >= 0 ) {
                     resp.addProperty("reply", JOIN_REPLY_SUCCESS);
                     resp.addProperty("gpid", _gpid);
                     c.send_data(MSG_PROJECT_JOIN_REPLY, resp);
                  }
                  else {
                     resp.addProperty("reply", JOIN_REPLY_FAIL);
                     c.send_data(MSG_PROJECT_JOIN_REPLY, resp);
                     c.send_error("Tried to join a project that doesn't exist on this server:" + _gpid);
                     c.send_fatal("This idb is associated with a project not found on this server.\n Maybe you connected to the wrong collabREate server,\n or maybe the project has been deleted...");
                     return true;
                  }
               }
            }
         } catch (Exception e) {
            c.logln("Malformed REJOIN REQUEST - failed to read gpid", LERROR);
            c.send_error("Malformed PROJECT_REJOIN");
         }
         return false;
      }
   }

   private static class msg_project_snapshot_request implements ClientMsgHandler {
      public boolean handle(JsonObject json, Client c) {
         c.logln("in SNAPSHOT REQ", LDEBUG);
         String desc = json.getAsJsonPrimitive("description").getAsString();
         long lastupdateid = json.getAsJsonPrimitive("last_update").getAsLong();
         JsonObject resp = new JsonObject();
         if (!c.authenticated) {
            c.logln("unauthorized project snapshot request", LERROR);
            c.send_error("Authenication required for this operation");
            resp.addProperty("reply", PROJECT_SNAPSHOT_FAIL);
            c.send_data(MSG_PROJECT_SNAPSHOT_REPLY, resp);
         }
         else if (lastupdateid <= 0 ) {
            c.logln("attempt to add snapshot with 0 or less updates applied", LINFO);
            c.send_error("snapshots with 0 or less updates are not allowed - start a new project instead");
            resp.addProperty("reply", PROJECT_SNAPSHOT_FAIL);
            c.send_data(MSG_PROJECT_SNAPSHOT_REPLY, resp);
         }
         else {
            if (c.cm.snapProject(c, lastupdateid, desc) >= 0) {
               resp.addProperty("reply", PROJECT_SNAPSHOT_SUCCESS);
            }
            else {
               resp.addProperty("reply", PROJECT_SNAPSHOT_FAIL);
            }
            c.send_data(MSG_PROJECT_SNAPSHOT_REPLY, resp);
         }
         return false;
      }
   }

   private static class msg_project_fork_request implements ClientMsgHandler {
      public boolean handle(JsonObject json, Client c) {
         JsonObject resp = new JsonObject();
         String desc = json.getAsJsonPrimitive("description").getAsString();
         long lastupdateid = json.getAsJsonPrimitive("last_update").getAsLong();
         c.logln("in FORK REQUEST", LDEBUG);
         if (!c.authenticated) {
            c.logln("unauthorized project fork request", LERROR);
            c.send_error("Authenication required for this operation");
            resp.addProperty("reply", JOIN_REPLY_FAIL);
         }
         else if (c.cm.forkProject(c, lastupdateid, desc) >= 0) {
            //on successfull fork, join the 'new' project automatically
            resp.addProperty("reply", JOIN_REPLY_SUCCESS);
            resp.addProperty("gpid", c.gpid);
         }
         else {
            resp.addProperty("reply", JOIN_REPLY_FAIL);
         }
         c.send_data(MSG_PROJECT_JOIN_REPLY, resp);
         return false;
      }
   }

   private static class msg_project_snapfork_request implements ClientMsgHandler {
      public boolean handle(JsonObject json, Client c) {
         JsonObject resp = new JsonObject();
         String desc = json.getAsJsonPrimitive("description").getAsString();
         int lpid = json.getAsJsonPrimitive("lpid").getAsInt();
         long pub = json.getAsJsonPrimitive("pub").getAsLong() & 0x7FFFFFFF;
         long sub = json.getAsJsonPrimitive("sub").getAsLong() & 0x7FFFFFFF;
         if (!c.authenticated) {
            c.logln("unauthorized project snapfork request", LERROR);
            c.send_error("Authenication required for this operation");
            resp.addProperty("reply", JOIN_REPLY_FAIL);
         }
//                  logln("got " + lpid + ": " + desc, LDEBUG);
         else if (c.cm.snapforkProject(c, lpid, desc, pub, sub) >= 0) {
            //on successfull fork from snapshop, join the 'new' project automatically
            resp.addProperty("reply", JOIN_REPLY_SUCCESS);
            resp.addProperty("gpid", c.gpid);
         }
         else {
            resp.addProperty("reply", JOIN_REPLY_FAIL);
         }
         c.send_data(MSG_PROJECT_JOIN_REPLY, resp);
         return false;
      }
   }

   private static class msg_project_leave implements ClientMsgHandler {
      public boolean handle(JsonObject json, Client c) {
         c.logln("in PROJECT LEAVE", LDEBUG);
         if (!c.authenticated) {
            c.logln("unauthorized project leave request", LERROR);
            c.send_error("Authenication required for this operation");
         }
         c.cm.remove(c);
         return false;
      }
   }

   private static class msg_project_join_reply implements ClientMsgHandler {
      public boolean handle(JsonObject json, Client c) {
         return false;
      }
   }

   private static class msg_auth_request implements ClientMsgHandler {
      public boolean handle(JsonObject json, Client c) {
         c.logln("in AUTH REQUEST", LDEBUG);
         int pluginversion = json.getAsJsonPrimitive("protocol").getAsInt();
         if (pluginversion != PROTOCOL_VERSION) {
            c.send_error("Version mismatch. plugin: " + pluginversion + " server: " + PROTOCOL_VERSION);
            c.logln("Version mismatch. plugin: " + pluginversion + " server: " + PROTOCOL_VERSION, LERROR);
            return true;
         }
         if (!c.authenticated) {
            JsonObject resp = new JsonObject();
            String response = json.getAsJsonPrimitive("hmac").getAsString();
            c.username = json.getAsJsonPrimitive("user").getAsString();
            c.logln("got user" + c.username, LDEBUG);
            c.uid = c.cm.authenticate(c, c.username, c.challenge, Utils.toByteArray(response));
            if (c.uid != INVALID_USER) {
               c.authenticated = true;
               //logln("uid set to "+ uid);
               resp.addProperty("reply", AUTH_REPLY_SUCCESS);
            }
            else {
               resp.addProperty("reply", AUTH_REPLY_FAIL);
               c.authTries--;
            }
            c.send_data(MSG_AUTH_REPLY, resp);
            if (c.authTries == 0) {
               c.logln("too many auth attempts for " + c.getUser(), LERROR);
               return true;
            }
         }
         else {
            c.logln("recv AUTH REQUEST when already authenticated", LERROR);
            c.send_error("Attempt to Authenticate, when already authenticated");
         }
         return false;
      }
   }

   private static class msg_project_list implements ClientMsgHandler {
      public boolean handle(JsonObject json, Client c) {
         c.hash = json.getAsJsonPrimitive("md5").getAsString();
         if (c.authenticated) {
            JsonObject resp = new JsonObject();
            c.logln("project hash: " + c.hash, LINFO4);
            Vector<ProjectInfo> plist = c.cm.getProjectList(c.hash);
            int nump = plist.size();
            JsonArray projects = new JsonArray();
            c.logln(" Found  " + nump + " projects", LINFO3);
            //create list of projects
            for (ProjectInfo pi : plist) {
               JsonObject proj = new JsonObject();
               c.log(" " + pi.lpid + " "+ pi.desc, LINFO4);
               proj.addProperty("id", pi.lpid);
               proj.addProperty("snap_id", pi.snapupdateid);
               String description = null;
               if (pi.parent > 0) {
                  if (pi.snapupdateid > 0) {
                     description = "[-] " + pi.desc + " (SNAP of '" + pi.pdesc + "'@"+ pi.snapupdateid + " updates])";
                     c.log("[-] " + pi.desc + " (snapshot of (" + pi.parent + ")'" + pi.pdesc+"' ["+ pi.snapupdateid + " updates]) ", LDEBUG);
                  }
                  else {
                     description = "[" + pi.connected + "] " + pi.desc + " (FORK of '" + pi.pdesc + "')";
                     c.log("[" + pi.connected + "] " + pi.desc + " (forked from (" + pi.parent + ") '" + pi.pdesc +"')", LDEBUG);
                  }
               }
               else {
                  description = "[" + pi.connected + "] " + pi.desc;
               }
               proj.addProperty("description", description);
               //since the user permissions may already limit the eventual effective permissions
               //only show the user the maximum attainable by this particular user (mask)
               //upublish = usubscribe = FULL_PERMISSIONS;  //quick BASIC mode test
               proj.addProperty("pub_mask", pi.pub & c.upublish);
               proj.addProperty("sub_mask", pi.sub & c.usubscribe);
               projects.add(proj);
               c.logln("", LDEBUG);
               c.logln("pP " + pi.pub + " pS " + pi.sub, LINFO4);
               c.logln("uP " + c.upublish + " uS " + c.usubscribe, LINFO4);
            }
            //also append list of permissions supported by this server
            JsonArray options = new JsonArray();
            for ( int i = 0; i < permStrings.length; i++) {
               options.add(permStrings[i]);
            }
            resp.add("projects", projects);
            resp.add("options", options);

            c.send_data(MSG_PROJECT_LIST, resp);
         }
         return false;
      }
   }

   private static class msg_send_updates implements ClientMsgHandler {
      public boolean handle(JsonObject json, Client c) {
         if (c.authenticated) {
            long lastupdate = json.getAsJsonPrimitive("last_update").getAsLong();
            c.logln("Received SEND_UPDATES request for " + lastupdate + " to current", LINFO1);
            c.cm.sendLatestUpdates(c, lastupdate);
         }
         return false;
      }
   }

   private static class msg_set_req_perms implements ClientMsgHandler {
      public boolean handle(JsonObject json, Client c) {
         c.logln("Received SET_REQ_PERMS request", LINFO1);
         if (!c.authenticated) {
            c.logln("unauthorized get req perms request",LERROR);
            c.send_error("Authenication required for this operation");
         }
         else {
            c.rpublish = json.getAsJsonPrimitive("pub").getAsLong() & 0x7FFFFFFF;
            c.rsubscribe = json.getAsJsonPrimitive("sub").getAsLong() & 0x7FFFFFFF;
            ProjectInfo pi = c.cm.getProjectInfo(c.pid);
            c.logln("effective publish  : " +
                  Long.toHexString(pi.pub) + " & " +
                  Long.toHexString(c.rpublish) + " & " +
                  Long.toHexString(c.upublish) + " = " +
                  Long.toHexString(pi.pub & c.upublish & c.rpublish),LINFO1);
            c.logln("effective subscribe: " +
                  Long.toHexString(pi.sub) + " & " +
                  Long.toHexString(c.rsubscribe) + " & " +
                  Long.toHexString(c.usubscribe) + " = " +
                  Long.toHexString(pi.sub & c.usubscribe & c.rsubscribe),LINFO1);

            if ( c.username != pi.owner ) {
               c.setPub(pi.pub & c.upublish & c.rpublish);
               c.setSub(pi.sub & c.usubscribe & c.rsubscribe);
            }
            else {
               c.logln("not honoring SET_REQ_PERMS for owner", LINFO1);
               c.send_error("You are the owner.  FULL permissions granted.");
            }
         }
         return false;
      }
   }

   private static class msg_get_req_perms implements ClientMsgHandler {
      public boolean handle(JsonObject json, Client c) {
         c.logln("Received GET_REQ_PERMS request", LINFO1);
         if (!c.authenticated) {
            c.logln("unauthorized get req perms request",LERROR);
            c.send_error("Authenication required for this operation");
         }
         else {
            JsonObject resp = new JsonObject();
            //send the two requested permissions
            resp.addProperty("pub", c.rpublish);
            resp.addProperty("sub", c.rsubscribe);
            //send the max possible values for requested permissions (mask)
            ProjectInfo pi = c.cm.getProjectInfo(c.pid);
            resp.addProperty("pub_mask", pi.pub & c.upublish);
            resp.addProperty("sub_mask", pi.sub & c.usubscribe);
            //also append list of permissions supported by this server
            JsonArray perms = new JsonArray();
            for (int i = 0; i < permStrings.length; i++) {
               perms.add(permStrings[i]);
            }
            resp.add("perms", perms);
            c.send_data(MSG_GET_REQ_PERMS_REPLY, resp);
         }
         return false;
      }
   }

   private static class msg_get_proj_perms implements ClientMsgHandler {
      public boolean handle(JsonObject json, Client c) {
         c.logln("Received GET_PROJ_PERMS request", LINFO1);
         if (!c.authenticated) {
            c.logln("unauthorized get project perms request",LERROR);
            c.send_error("Authenication required for this operation");
         }
         else {
            JsonObject resp = new JsonObject();
            ProjectInfo pi = c.cm.getProjectInfo(c.pid);
            if (c.username == pi.owner) {
               //send the two project permissions
               resp.addProperty("pub", pi.pub);
               resp.addProperty("sub", pi.sub);
               //since this is the owner managing possible values for requested permissions (mask) is full
               resp.addProperty("pub_mask", FULL_PERMISSIONS);
               resp.addProperty("sub_mask", FULL_PERMISSIONS);
               //also append list of permissions supported by this server
               JsonArray perms = new JsonArray();
               for (int i = 0; i < permStrings.length; i++) {
                  perms.add(permStrings[i]);
               }
               resp.add("perms", perms);
               c.send_data(MSG_GET_PROJ_PERMS_REPLY, resp);
            }
            else {
               c.send_error("You are not the owner!");
            }
         }
         return false;
      }
   }

   private static class msg_set_proj_perms implements ClientMsgHandler {
      public boolean handle(JsonObject json, Client c) {
         c.logln("Received SET_PROJ_PERMS request", LINFO1);
         if (!c.authenticated) {
            c.logln("unauthorized get project perms request",LERROR);
            c.send_error("Authenication required for this operation");
         }
         else {
            long pub = json.getAsJsonPrimitive("pub").getAsLong() & 0x7FFFFFFF;
            long sub = json.getAsJsonPrimitive("sub").getAsLong() & 0x7FFFFFFF;
            ProjectInfo pi = c.cm.getProjectInfo(c.pid);
            if (c.username == pi.owner) {
               c.cm.updateProjectPerms(c, pub, sub);
            }
            else {
               c.send_error("You are not the owner!");
            }
         }
         return false;
      }
   }

   public static void init_handlers() {
      handlers = new Hashtable<String,ClientMsgHandler>();
      perms_map = new Hashtable<String,Long>();
      handlers.put(MSG_PROJECT_NEW_REQUEST, new msg_project_new_request());
      handlers.put(MSG_PROJECT_JOIN_REQUEST, new msg_project_join_request());
      handlers.put(MSG_PROJECT_REJOIN_REQUEST, new msg_project_rejoin_request());
      handlers.put(MSG_PROJECT_SNAPSHOT_REQUEST, new msg_project_snapshot_request());
      handlers.put(MSG_PROJECT_FORK_REQUEST, new msg_project_fork_request());
      handlers.put(MSG_PROJECT_SNAPFORK_REQUEST, new msg_project_snapfork_request());
      handlers.put(MSG_PROJECT_LEAVE, new msg_project_leave());
      handlers.put(MSG_PROJECT_JOIN_REPLY, new msg_project_join_reply());
      handlers.put(MSG_AUTH_REQUEST, new msg_auth_request());
      handlers.put(MSG_PROJECT_LIST, new msg_project_list());
      handlers.put(MSG_SEND_UPDATES, new msg_send_updates());
      handlers.put(MSG_SET_REQ_PERMS, new msg_set_req_perms());
      handlers.put(MSG_GET_REQ_PERMS, new msg_get_req_perms());
      handlers.put(MSG_GET_PROJ_PERMS, new msg_get_proj_perms());
      handlers.put(MSG_SET_PROJ_PERMS, new msg_set_proj_perms());
   
      perms_map.put(COMMAND_UNDEFINE, MASK_UNDEFINE);
      perms_map.put(COMMAND_MAKE_CODE, MASK_MAKE_CODE);
      perms_map.put(COMMAND_MAKE_DATA, MASK_MAKE_DATA);
   
      perms_map.put(COMMAND_SEGM_ADDED, MASK_SEGMENTS);
      perms_map.put(COMMAND_SEGM_DELETED, MASK_SEGMENTS);
      perms_map.put(COMMAND_SEGM_START_CHANGED, MASK_SEGMENTS);
      perms_map.put(COMMAND_SEGM_END_CHANGED, MASK_SEGMENTS);
      perms_map.put(COMMAND_SEGM_MOVED, MASK_SEGMENTS);
      perms_map.put(COMMAND_MOVE_SEGM, MASK_SEGMENTS);
   
   
      perms_map.put(COMMAND_SET_STACK_VAR_NAME, MASK_RENAME);
      perms_map.put(COMMAND_RENAMED, MASK_RENAME);
   
      perms_map.put(COMMAND_FUNC_TAIL_APPENDED, MASK_FUNCTIONS);
      perms_map.put(COMMAND_FUNC_TAIL_REMOVED, MASK_FUNCTIONS);
      perms_map.put(COMMAND_TAIL_OWNER_CHANGED, MASK_FUNCTIONS);
      perms_map.put(COMMAND_FUNC_NORET_CHANGED, MASK_FUNCTIONS);
      perms_map.put(COMMAND_ADD_FUNC, MASK_FUNCTIONS);
      perms_map.put(COMMAND_DEL_FUNC, MASK_FUNCTIONS);
      perms_map.put(COMMAND_SET_FUNC_START, MASK_FUNCTIONS);
      perms_map.put(COMMAND_SET_FUNC_END, MASK_FUNCTIONS);
   
      perms_map.put(COMMAND_BYTE_PATCHED, MASK_BYTE_PATCH);
   
      perms_map.put(COMMAND_AREA_CMT_CHANGED, MASK_COMMENTS);
      perms_map.put(COMMAND_CMT_CHANGED, MASK_COMMENTS);
   
      perms_map.put(COMMAND_TI_CHANGED, MASK_OPTYPES);
      perms_map.put(COMMAND_OP_TI_CHANGED, MASK_OPTYPES);
      perms_map.put(COMMAND_OP_TYPE_CHANGED, MASK_OPTYPES);
   
      perms_map.put(COMMAND_ENUM_CREATED, MASK_ENUMS);
      perms_map.put(COMMAND_ENUM_DELETED, MASK_ENUMS);
      perms_map.put(COMMAND_ENUM_BF_CHANGED, MASK_ENUMS);
      perms_map.put(COMMAND_ENUM_RENAMED, MASK_ENUMS);
      perms_map.put(COMMAND_ENUM_CMT_CHANGED, MASK_ENUMS);
      perms_map.put(COMMAND_ENUM_CONST_CREATED, MASK_ENUMS);
      perms_map.put(COMMAND_ENUM_CONST_DELETED, MASK_ENUMS);
   
      perms_map.put(COMMAND_STRUC_CREATED, MASK_STRUCTS);
      perms_map.put(COMMAND_STRUC_DELETED, MASK_STRUCTS);
      perms_map.put(COMMAND_STRUC_RENAMED, MASK_STRUCTS);
      perms_map.put(COMMAND_STRUC_EXPANDED, MASK_STRUCTS);
      perms_map.put(COMMAND_STRUC_CMT_CHANGED, MASK_STRUCTS);
      perms_map.put(COMMAND_CREATE_STRUC_MEMBER_DATA, MASK_STRUCTS);
      perms_map.put(COMMAND_CREATE_STRUC_MEMBER_STRUCT, MASK_STRUCTS);
      perms_map.put(COMMAND_CREATE_STRUC_MEMBER_REF, MASK_STRUCTS);
      perms_map.put(COMMAND_CREATE_STRUC_MEMBER_STROFF, MASK_STRUCTS);
      perms_map.put(COMMAND_CREATE_STRUC_MEMBER_STR, MASK_STRUCTS);
      perms_map.put(COMMAND_CREATE_STRUC_MEMBER_ENUM, MASK_STRUCTS);
      perms_map.put(COMMAND_STRUC_MEMBER_DELETED, MASK_STRUCTS);
      perms_map.put(COMMAND_SET_STRUCT_MEMBER_NAME, MASK_STRUCTS);
      perms_map.put(COMMAND_STRUC_MEMBER_CHANGED_DATA, MASK_STRUCTS);
      perms_map.put(COMMAND_STRUC_MEMBER_CHANGED_STRUCT, MASK_STRUCTS);
      perms_map.put(COMMAND_STRUC_MEMBER_CHANGED_STR, MASK_STRUCTS);
      perms_map.put(COMMAND_STRUC_MEMBER_CHANGED_OFFSET, MASK_STRUCTS);
      perms_map.put(COMMAND_STRUC_MEMBER_CHANGED_ENUM, MASK_STRUCTS);
      perms_map.put(COMMAND_CREATE_STRUC_MEMBER_OFFSET, MASK_STRUCTS);
   
      perms_map.put(COMMAND_VALIDATE_FLIRT_FUNC, MASK_FLIRT);
   
      perms_map.put(COMMAND_THUNK_CREATED, MASK_THUNK);
   
      perms_map.put(COMMAND_ADD_CREF, MASK_XREF);
      perms_map.put(COMMAND_ADD_DREF, MASK_XREF);
      perms_map.put(COMMAND_DEL_CREF, MASK_XREF);
      perms_map.put(COMMAND_DEL_DREF, MASK_XREF);
   
   }



}

