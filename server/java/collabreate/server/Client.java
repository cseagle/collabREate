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

/**
 * Client
 * This class is responsible for a single client connection
 * It handles the initial client interaction, then reads
 * incoming client commands and kicks them up to the ConnectionManager
 * which farms the commands out to all interested clients
 * @author Tim Vidas
 * @author Chris Eagle
 * @version 0.1.0, August 2008
 */


public class Client extends Thread implements CollabreateConstants {

   /**
    * Constant to check for an invalid uid
    */
   public static final int INVALID_USER = -1;
   /**
    * Constant to use for uid when in BASIC_MODE 
    */
   public static final int BASIC_USER = 0;

   private Socket conn;
   private String hash = "";
   private String username;
   private DataInputStream dis;
   private DataOutputStream dos;
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
      dis = new DataInputStream(new BufferedInputStream(s.getInputStream()));
      dos = new DataOutputStream(s.getOutputStream());
      basicMode = basic;
      
      logln("New Connection", LINFO);

      if (!basicMode) {
        challenge = Utils.getRandom(CHALLENGE_SIZE);
        send_data(MSG_INITIAL_CHALLENGE, challenge);
      }
      else {
         //these are used only for the 'auto auth' in BASIC mode
         CollabreateOutputStream authos = new CollabreateOutputStream();
         logln("sending AUTH_CONNECTED");
         cm.authenticate(this, null, null, null);
         authenticated = true;
         authos.writeInt(AUTH_REPLY_SUCCESS);
         send_data(MSG_AUTH_REPLY, authos.toByteArray());
      }
      //the dummy gpid need to consist entirely of hex values.
      gpid = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
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

   private int parseCommand(byte[] data) {
        return (data[4] << 24)
                + ((data[5] & 0xFF) << 16)
                + ((data[6] & 0xFF) << 8)
                + (data[7] & 0xFF);

   }

   /**
    * post is the function that actually posts updates to clients (if subscribing)
    * @param data the bytearray containing the update to send
    */
   public void post(byte[] data) throws Exception {
      if (checkPermissions(parseCommand(data), subscribe)) { 
         //only post if client is subscribing and is allowed to recieve that particular command
         dos.write(data);
         dos.flush();
         //logln("post- datasize: " + data.length);
         stats[0][data[7] & 0xff]++;
      }
      else {
         logln("Client " + hash + ":" + conn.getInetAddress().getHostAddress()
                            + ":" + conn.getPort() + " failed to post data. "
                            + " (probably subscribe permission: "
                            + parseCommand(data) + ")", LINFO3);
      }
   }

   /**
    * similar to post, but does not check subscription status, and takes command as a arg
    * This function should ONLY be called for message id >= MSG_CONTROL_FIRST
    * because these messages do not contain an updateid
    * @param command the command to send
    * @param data the data associated with the command
    */
   protected void send_data(int command, byte[] data) {
      try {
         if (command >= MSG_CONTROL_FIRST) {
            dos.writeInt(8 + data.length);
            dos.writeInt(command);
            dos.write(data);
            dos.flush();
            logln("send_data- cmd: " + command + " datasize: " + data.length, LINFO3);
            stats[0][command]++;
         }
         else {
            logln("post should be used for command " + command + ", not send_data.  Data not sent.", LERROR);
         }
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
         CollabreateOutputStream cos = new CollabreateOutputStream();
         logln("Sending forkfollow for " + gpid + " initiated by " + fuser + " at updateid " + lastupdateid, LINFO2);
         cos.writeUTF(fuser);
         cos.write(Utils.toByteArray(gpid));
         cos.writeLong(lastupdateid);
         cos.writeUTF(desc);
         send_data(MSG_PROJECT_FORK_FOLLOW, cos.toByteArray());
      } catch ( Exception ex) {
         logex(ex);
      }
   }

   protected void send_error_msg(String theerror,int type) {
      try {
         logln("Protocol error detected: " + theerror,LERROR);
         CollabreateOutputStream os = new CollabreateOutputStream();
         os.writeUTF(theerror);
         byte[] theerrorba = os.toByteArray(); 
         dos.writeInt(8 + theerrorba.length);
         dos.writeInt(type);
         dos.write(theerrorba);
         dos.flush();
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
            CollabreateOutputStream os = new CollabreateOutputStream();
            int len = dis.readInt();
            int command = dis.readInt();
            logln("received data len: " + len + ", cmd: " + command, LDEBUG);
            if (command < MAX_COMMAND && command > 0) {
               stats[1][command]++;
            }
            len -= 8;
            if (command < MSG_CONTROL_FIRST) {
               byte[] data = new byte[len];
               dis.readFully(data);
               os.writeInt(len + 16);
               os.writeInt(command);
               os.writeLong(0);  //this is where the updateid will get inserted
               os.write(data);
               //only accept commands if the client is authenticated
               if (authenticated && (publish > 0)) {
                  //only post if this client chose to publish, 
                  //(though they really shouldn't have sent any data if they are not publishing)
                  if (checkPermissions(command, publish)) { 
                     logln("posting command " + command + " (allowed to  publish) ", LDEBUG);
                     cm.post(this, command, os.toByteArray());
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
            else { //server only command
               switch (command) {
                  case MSG_PROJECT_NEW_REQUEST: {
                     logln("in NEW PROJECT REQUEST", LDEBUG);
                     byte[] md5 = new byte[MD5_SIZE];
                     try {
                        dis.readFully(md5);
                        hash = Utils.toHexString(md5);
                        String desc = dis.readUTF();
                        long pub = dis.readLong() & 0x7FFFFFFF;
                        long sub = dis.readLong() & 0x7FFFFFFF;
                        if (!authenticated) {
                           //nice try!!
                           break;
                        }
                        logln("desired new project pub " + pub + ", and sub " + sub);
                        int lpid = cm.addProject(this, hash, desc, pub, sub);
                        if (lpid >= 0) {
                           logln("NEW PROJECT REQUEST success", LINFO);
                           os.writeInt(JOIN_REPLY_SUCCESS);
                           os.write(Utils.toByteArray(gpid));
                        }
                        else {
                           logln("NEW PROJECT REQUEST fail", LINFO);
                           os.writeInt(JOIN_REPLY_FAIL);
                        }
                        send_data(MSG_PROJECT_JOIN_REPLY, os.toByteArray());
                     } catch (Exception ex) {
                        logln("Malformed NEW PROJECT REQUEST - failed to read md5", LERROR);
                        send_error("Malformed NEW_PROJECT_REQUEST");
                        break;
                     }
                     break;
                  }
                  case MSG_PROJECT_JOIN_REQUEST: {
                     int lpid = dis.readInt();
                     long tpub = dis.readLong() & 0x7FFFFFFF;
                     long tsub = dis.readLong() & 0x7FFFFFFF; 
                     if (!authenticated) {
                        //nice try!!
                        break;
                     }
                     rpublish = tpub;
                     rsubscribe = tsub;
                     logln("attempting to join project " + lpid, LINFO);
                     if (cm.joinProject(this, lpid) >= 0 ) {
                        os.writeInt(JOIN_REPLY_SUCCESS);
                        byte gp[] = new byte[GPID_SIZE];
                        gp = Utils.toByteArray(gpid); 
                        os.write(gp);
                        logln("...success" + lpid, LINFO);
                     }
                     else {
                        os.writeInt(JOIN_REPLY_FAIL);
                        logln("...failed" + lpid, LINFO);
                     }
                     send_data(MSG_PROJECT_JOIN_REPLY, os.toByteArray());
                     break;               
                  }
                  case MSG_PROJECT_REJOIN_REQUEST: {
                     logln("in PROJECT_REJOIN_REQUEST", LDEBUG);
                     byte gp[] = new byte[GPID_SIZE];
                     int rejoingbasic = 0;
                     try {
                        dis.readFully(gp);
                        String gpid = Utils.toHexString(gp);
                        if ( Utils.isNumeric(gpid) ) {
                           if ( Integer.parseInt(gpid) == 0 ) { 
                              //basic mode pid was stored in netnode
                              send_error("This instance of IDA connected in basic mode, cannot reconnect.");
                              break;
                           }
                        }
                        int lpid = cm.gpid2lpid(gpid);
                        long tpub = dis.readLong() & 0x7FFFFFFF;
                        long tsub = dis.readLong() & 0x7FFFFFFF; 
                        if (!authenticated) {
                           logln("unauthorized project rejoin request", LERROR);
                           send_error("Authenication required for this operation");
                           break;
                        }
                        rpublish = tpub;
                        rsubscribe = tsub; 
                        logln("plugin requested rpub: " + rpublish + " rsub: " + rsubscribe);
                        if (cm.joinProject(this, lpid) >= 0 ) {
                           os.writeInt(JOIN_REPLY_SUCCESS);
                           os.write(gp);
                           send_data(MSG_PROJECT_JOIN_REPLY, os.toByteArray());
                        }
                        else {
                           os.writeInt(JOIN_REPLY_FAIL);
                           send_data(MSG_PROJECT_JOIN_REPLY, os.toByteArray());
                           send_error("Tried to join a project that doesn't exist on this server:" + gpid);
                           send_fatal("This idb is associated with a project not found on this server.\n Maybe you connected to the wrong collabREate server,\n or maybe the project has been deleted...");
                           break main_loop;
                        }
                     } catch (Exception e) {
                        logln("Malformed REJOIN REQUEST - failed to read gpid", LERROR);
                        send_error("Malformed PROJECT_REJOIN");
                     }
                     break;               
                  }
                  case MSG_PROJECT_SNAPSHOT_REQUEST: {
                     logln("in SNAPSHOT REQ", LDEBUG);
                     String desc = dis.readUTF();
                     long lastupdateid = dis.readLong();
                     if (!authenticated) {
                        logln("unauthorized project snapshot request", LERROR);
                        send_error("Authenication required for this operation");
                        os.writeInt(PROJECT_SNAPSHOT_FAIL);
                        send_data(MSG_PROJECT_SNAPSHOT_REPLY, os.toByteArray());
                        break;
                     }
                     if (lastupdateid <= 0 ) {
                        logln("attempt to add snapshot with 0 or less updates applied", LINFO);
                        send_error("snapshots with 0 or less updates are not allowed - start a new project instead");
                        os.writeInt(PROJECT_SNAPSHOT_FAIL);
                        send_data(MSG_PROJECT_SNAPSHOT_REPLY, os.toByteArray());
                        break;
                     }
                     if (cm.snapProject(this, lastupdateid, desc) >= 0) { 
                        os.writeInt(PROJECT_SNAPSHOT_SUCCESS);
                     }
                     else {
                        os.writeInt(PROJECT_SNAPSHOT_FAIL);
                     }
                     send_data(MSG_PROJECT_SNAPSHOT_REPLY, os.toByteArray());
                     break;
                  }
                  case MSG_PROJECT_FORK_REQUEST: {
                     long lastupdateid = dis.readLong();
                     String desc = dis.readUTF();
                     logln("in FORK REQUEST", LDEBUG);
                     if (!authenticated) {
                        logln("unauthorized project fork request", LERROR);
                        send_error("Authenication required for this operation");
                        os.writeInt(JOIN_REPLY_FAIL);
                        send_data(MSG_PROJECT_JOIN_REPLY, os.toByteArray());
                        break;
                     }

                     //if the user set these at the time of the fork
                     //they would be read here.  Instead we allow the owner to
                     //manage permissions at any time via the modal dialog box
                     //long pub = dis.readLong() & 0x7FFFFFFF;
                     //long sub = dis.readLong() & 0x7FFFFFFF;
                     //if (cm.forkProject(this, lastupdateid, desc, pub, sub) >= 0) { 
                     if (cm.forkProject(this, lastupdateid, desc) >= 0) { 
                        //on successfull fork, join the 'new' project automatically
                        os.writeInt(JOIN_REPLY_SUCCESS);
                        os.write(Utils.toByteArray(gpid));
                     }
                     else {
                        os.writeInt(JOIN_REPLY_FAIL);
                     }
                     send_data(MSG_PROJECT_JOIN_REPLY, os.toByteArray());
                     break;
                  }
                  case MSG_PROJECT_SNAPFORK_REQUEST: {
                     logln("in SNAPFORK REQUEST", LDEBUG);
                     int lpid = dis.readInt();
                     String desc = dis.readUTF();
                     long pub = dis.readLong() & 0x7FFFFFFF;
                     long sub = dis.readLong() & 0x7FFFFFFF;
                     if (!authenticated) {
                        logln("unauthorized project snapfork request", LERROR);
                        send_error("Authenication required for this operation");
                        os.writeInt(JOIN_REPLY_FAIL);
                        send_data(MSG_PROJECT_JOIN_REPLY, os.toByteArray());
                        break;
                     }
                     logln("got " + lpid + ": " + desc, LDEBUG);
                     if (cm.snapforkProject(this, lpid, desc, pub, sub) >= 0) { 
                        //on successfull fork from snapshop, join the 'new' project automatically
                        os.writeInt(JOIN_REPLY_SUCCESS);
                        os.write(Utils.toByteArray(gpid));
                     }
                     else {
                        os.writeInt(JOIN_REPLY_FAIL);
                     }
                     send_data(MSG_PROJECT_JOIN_REPLY, os.toByteArray());
                     break;
                  }
                  case MSG_PROJECT_LEAVE: {
                     logln("in PROJECT LEAVE", LDEBUG);
                     if (!authenticated) {
                        logln("unauthorized project leave request", LERROR);
                        send_error("Authenication required for this operation");
                        break;
                     }
                     cm.remove(this);
                     break;
                  }
                  case MSG_PROJECT_JOIN_REPLY:                 
                     break;
                  case MSG_AUTH_REQUEST:
                     logln("in AUTH REQUEST", LDEBUG);
                     int pluginversion = dis.readInt();
                     if (pluginversion != PROTOCOL_VERSION) {
                        send_error("Version mismatch. plugin: " + pluginversion + " server: " + PROTOCOL_VERSION);
                        logln("Version mismatch. plugin: " + pluginversion + " server: " + PROTOCOL_VERSION, LERROR);
                        break main_loop;
                     }
                     if (!authenticated) {
                        byte resp[] = new byte[MD5_SIZE];
                        username = dis.readUTF();
                        logln("got user" + username, LDEBUG);
                        try {
                           dis.readFully(resp);
                        } catch (Exception ex) {
                           logln("Malformed AUTH REQUEST - failed to read hmac response", LERROR);
                           send_error("Malformed AUTH_REQUEST");
                           break main_loop;  //disconnect
                        }

                        uid = cm.authenticate(this, username, challenge, resp);
                        if (uid != INVALID_USER) {
                           authenticated = true;
                           //logln("uid set to "+ uid);
                           os.writeInt(AUTH_REPLY_SUCCESS);
                        }
                        else {
                           os.writeInt(AUTH_REPLY_FAIL);
                           authTries--;
                        }
                        send_data(MSG_AUTH_REPLY, os.toByteArray());
                        if (authTries == 0) {
                           logln("too many auth attempts for " + this.getUser(), LERROR);
                           break main_loop;
                        }
                     }
                     else {
                        logln("recv AUTH REQUEST when already authenticated", LERROR);
                        send_error("Attempt to Authenticate, when already authenticated");
                     }                     
                     break;
                  case MSG_PROJECT_LIST:
                     if (len != MD5_SIZE) { //len + cmd alread accounted for
                        send_error("Malformed Project getlist request");
                     }
                     else {
                        byte[] md5 = new byte[MD5_SIZE];
                        try {
                           dis.readFully(md5);
                        } catch (Exception ex) {
                           logln("Malformed MSG_PROJECT_LIST - failed to read file md5", LERROR);
                           send_error("Malformed MSG_PROJECT_LIST");
                           break main_loop;  //disconnect
                        }
                        if (!authenticated) {
                           //nice try!!
                           break;
                        }
                        hash = Utils.toHexString(md5);
                        logln("project hash: " + hash, LINFO4);                     
                        Vector<ProjectInfo> plist = cm.getProjectList(hash);
                        int nump = plist.size();
                        os.writeInt(nump);   //send number of elements to come
                        logln(" Found  " + nump + " projects", LINFO3);
                        //create list of projects
                        for (ProjectInfo pi : plist) {
                           log(" " + pi.lpid + " "+ pi.desc, LINFO4);
                           os.writeInt(pi.lpid);
                           os.writeLong(pi.snapupdateid);
                           if (pi.parent > 0) {
                              if (pi.snapupdateid > 0) {
                                 os.writeUTF("[-] " + pi.desc + " (SNAP of '" + pi.pdesc + "'@"+ pi.snapupdateid + " updates])"); 
                                 log("[-] " + pi.desc + " (snapshot of (" + pi.parent + ")'" + pi.pdesc+"' ["+ pi.snapupdateid + " updates]) ", LDEBUG); 
                              }
                              else {
                                 os.writeUTF("[" + pi.connected + "] " + pi.desc + " (FORK of '" + pi.pdesc + "')"); 
                                 log("[" + pi.connected + "] " + pi.desc + " (forked from (" + pi.parent + ") '" + pi.pdesc +"')", LDEBUG); 
                              }
                           }
                           else {
                              os.writeUTF("[" + pi.connected + "] " + pi.desc);
                           }
                           //since the user permissions may already limit the eventual effective permissions
                           //only show the user the maximum attainable by this particular user (mask)
                           //upublish = usubscribe = FULL_PERMISSIONS;  //quick BASIC mode test
                           os.writeLong(pi.pub & upublish);
                           os.writeLong(pi.sub & usubscribe);
                           logln("", LDEBUG);
                           logln("pP " + pi.pub + " pS " + pi.sub, LINFO4);
                           logln("uP " + upublish + " uS " + usubscribe, LINFO4);
                        }
                        //also append list of permissions supported by this server
                        os.writeInt(permStrings.length);
                        for ( int i = 0; i < permStrings.length; i++) {
                           os.writeUTF(permStrings[i]);
                        }

                        send_data(MSG_PROJECT_LIST, os.toByteArray());
                     }
                     break;
                  case MSG_SEND_UPDATES: {
                     long lastupdate = dis.readLong();
                     if (!authenticated) {
                        //nice try!!
                        break;
                     }
                     logln("Received SEND_UPDATES request for " + lastupdate + " to current", LINFO1);
                     cm.sendLatestUpdates(this, lastupdate);
                        
                     break;
                  }
                  case MSG_SET_REQ_PERMS: {
                     logln("Received SET_REQ_PERMS request", LINFO1);
                     long tpub = dis.readLong() & 0x7FFFFFFF;
                     long tsub = dis.readLong() & 0x7FFFFFFF;
                     if (!authenticated) {
                        logln("unauthorized get req perms request",LERROR);
                        send_error("Authenication required for this operation");
                        break;
                     }

                     rpublish = tpub;
                     rsubscribe = tsub;
                     ProjectInfo pi = cm.getProjectInfo(pid);
                     logln("effective publish  : " + 
                           Long.toHexString(pi.pub) + " & " + 
                           Long.toHexString(rpublish) + " & " + 
                           Long.toHexString(upublish) + " = " + 
                           Long.toHexString(pi.pub & upublish & rpublish),LINFO1);
                     logln("effective subscribe: " + 
                           Long.toHexString(pi.sub) + " & " + 
                           Long.toHexString(rsubscribe) + " & " + 
                           Long.toHexString(usubscribe) + " = " + 
                           Long.toHexString(pi.sub & usubscribe & rsubscribe),LINFO1);

                     if ( uid != pi.owner ) {
                        setPub(pi.pub & upublish & rpublish);
                        setSub(pi.sub & usubscribe & rsubscribe);
                     }
                     else {
                        logln("not honoring SET_REQ_PERMS for owner", LINFO1);
                        send_error("You are the owner.  FULL permissions granted.");
                     }

                     break;
                  }
                  case MSG_GET_REQ_PERMS: {
                     logln("Received GET_REQ_PERMS request", LINFO1);
                     if (!authenticated) {
                        logln("unauthorized get req perms request",LERROR);
                        send_error("Authenication required for this operation");
                        break;
                     }
                     //send the two requested permissions
                     os.writeLong(rpublish);
                     os.writeLong(rsubscribe); 
                     //send the max possible values for requested permissions (mask)
                     ProjectInfo pi = cm.getProjectInfo(pid);
                     os.writeLong(pi.pub & upublish);
                     os.writeLong(pi.sub & usubscribe);
                     //also append list of permissions supported by this server
                     os.writeInt(permStrings.length);
                     for (int i = 0; i < permStrings.length; i++) {
                        os.writeUTF(permStrings[i]);
                     }
                     send_data(MSG_GET_REQ_PERMS_REPLY, os.toByteArray());
                     break;
                  }
                  case MSG_GET_PROJ_PERMS: {
                     logln("Received GET_PROJ_PERMS request", LINFO1);
                     if (!authenticated) {
                        logln("unauthorized get project perms request",LERROR);
                        send_error("Authenication required for this operation");
                        break;
                     }
                     ProjectInfo pi = cm.getProjectInfo(pid);
                     if (uid == pi.owner) {
                        //send the two project permissions
                        os.writeLong(pi.pub);
                        os.writeLong(pi.sub); 
                        //sing this is the owner managing possible values for requested permissions (mask) is full
                        os.writeLong(FULL_PERMISSIONS);
                        os.writeLong(FULL_PERMISSIONS);
                        //also appent list of permissions supported by this server
                        os.writeInt(permStrings.length);
                        for (int i = 0; i < permStrings.length; i++) {
                           os.writeUTF(permStrings[i]);
                        }
                        send_data(MSG_GET_PROJ_PERMS_REPLY, os.toByteArray());
                     }
                     else {
                        send_error("You are not the owner!");
                     }
                     break;
                  }
                  case MSG_SET_PROJ_PERMS: {
                     logln("Received SET_PROJ_PERMS request", LINFO1);
                     long pub = dis.readLong() & 0x7FFFFFFF;
                     long sub = dis.readLong() & 0x7FFFFFFF;
                     if (!authenticated) {
                        logln("unauthorized get project perms request",LERROR);
                        send_error("Authenication required for this operation");
                        break;
                     }
                     ProjectInfo pi = cm.getProjectInfo(pid);
                     if (uid == pi.owner) {
                        cm.updateProjectPerms(this, pub, sub);
                     }
                     else {
                        send_error("You are not the owner!");
                     }
                     break;
                  }
                  default:
                     logln("Unknown MSG command " + command + " ignoring.", LINFO1);
                     break;
               }
            }
         }
      } catch (EOFException eeof) {
         //logln("EOF error :" + eeof.getMessage());
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
   private boolean checkPermissions(int command, long permType) { 
      boolean isallowed = false;
      logln("checking for permission " + command, LDEBUG);
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
         case COMMAND_USER_MESSAGE:
            isallowed = true;
            break;
         default:
            logln("unmatched command " + command + " found in publish switch", LERROR);
      } //end command switch
      
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
}

