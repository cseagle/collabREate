/*
    collabREate ManagerHelper
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
 * ManagerHelper
 * This class is intented to facilitate getting current status information to
 * the ServerManager class.
 * @author Tim Vidas
 * @author Chris Eagle
 * @version 0.2.0, January 2017
 */

public class ManagerHelper extends Thread implements CollabreateConstants {

   private static final int DEFAULT_PORT = 5043;
   private static final int DEFAULT_LOCAL = 1;

   private JsonStreamParser parser;
   private PrintStream ps;
   private ServerSocket ss;
   private JsonObject config = new JsonObject();
   private ConnectionManagerBase cm;
   private int pidForUpdates;
   private boolean dbMode;


   /**
    * very similary to the other constructor, execpt config paramters are attempted
    * to be read from a properties object p
    * @param connm the connectionManager associated with this ManagerHelper
    * @param p a propertied object (config file)
    */
   public ManagerHelper(ConnectionManagerBase connm, JsonObject conf) throws Exception {
      cm = connm;
      pidForUpdates = 0;
      config = conf;
      initCommon();
   }

   /**
    * instantiates a new ManagerHelper with default parameters, the ManagerHelper
    * facilitates getting server state information to the ServerManager
    * @param connm the connectionManager associated with this ManagerHelper
    */
   public ManagerHelper(ConnectionManagerBase connm) throws Exception {
      cm = connm;
      pidForUpdates = 0;
      initCommon();
   }

   private String getConfigString(String key, String default_value) {
      if (config.has(key)) {
         return config.getAsJsonPrimitive(key).getAsString();
      }
      return default_value;
   }

   private int getConfigInt(String key, int default_value) {
      if (config.has(key)) {
         return config.getAsJsonPrimitive(key).getAsInt();
      }
      return default_value;
   }

   private boolean getConfigBoolean(String key, boolean default_value) {
      if (config.has(key)) {
         return config.getAsJsonPrimitive(key).getAsBoolean();
      }
      return default_value;
   }

   private void initCommon() throws Exception {
      try {
         int port = getConfigInt("MANAGE_PORT", DEFAULT_PORT);
         boolean localonly = getConfigBoolean("MANAGE_LOCAL", true);
         if (!localonly) {
            ss = new ServerSocket(port);  //bind any
         }
         else {
            ss = new ServerSocket(port,1,InetAddress.getByName("127.0.0.1"));
         }
      } catch (Exception e) {
         logln("Could not setup ManagerHelper socket\n" + e.getMessage());
      }
      dbMode = getConfigString("SERVER_MODE", "database").equals("database");
   }

   /**
    * send_data constructs the packet and sends it to the ServerManager
    * @param command the server command to send
    * @param data the data relevant to be sent with command
    */
   protected void send_data(String command, JsonObject json) {
      try {
         json.addProperty("type", command);
         ps.println(json.toString());
      } catch (Exception ex) {
      }
/*
      try {
         if (command >= MNG_CONTROL_FIRST) {
            dos.writeInt(8 + data.length);
            dos.writeInt(command);
            dos.write(data);
            dos.flush();
            logln("send_data- cmd: " + command + " datasize: " + data.length, LDEBUG);
         }
         else {
            logln("post should be used for command " + command + ", not send_data.  Data not sent.", LERROR);
         }
      } catch (Exception ex) {
      }
*/
   }

   /**
    * run kicks off a thread that perpetually waits for a single connection, if the connection is dropped
    * it waits again, once connected, the ManagerHelper processes commands similar to the server.
    */
   public void run() {
      try {
         logln("ManagerHelper running...", LINFO);
         //just accept a single connection, loop back if the connection drops
         while (true) {
            try {
               Socket s = ss.accept();
               parser = new JsonStreamParser(new InputStreamReader(s.getInputStream()));
               ps = new PrintStream(s.getOutputStream(), true);
               logln("New Management connection: " + s.getInetAddress().getHostAddress() + ":" + s.getPort(), LINFO);
               while (true) {
                  JsonElement json_e = parser.next();
                  if (!json_e.isJsonObject()) {
                     break;
                  }
                  JsonObject json = (JsonObject)json_e;
                  String cmd = json.getAsJsonPrimitive("type").getAsString();
                  JsonObject resp = new JsonObject();
                  if (cmd.equals(MNG_GET_CONNECTIONS)) {
                     logln("sending connections", LINFO3);
                     String c = cm.listConnections();
                     resp.addProperty("connections", c);
                     send_data(MNG_CONNECTIONS, resp);
                  }
                  else if (cmd.equals(MNG_GET_STATS)) {
                     logln("sending stats", LINFO3);
                     String c = cm.dumpStats();
                     resp.addProperty("stats", c);
                     send_data(MNG_STATS, resp);
                  }
                  else if (cmd.equals(MNG_SHUTDOWN)) {
                     logln("client requested server shutdown", LINFO);
                     cm.Shutdown();
                  }
                  else if (cmd.equals(MNG_PROJECT_MIGRATE)) {
                     logln("client requested a project migrate", LINFO);
                     //Client c = new Client(cm,new Socket());
                     int status = MNG_MIGRATE_REPLY_FAIL;
                     try {
                        String username = json.getAsJsonPrimitive("newowner").getAsString();
                        String gpid = json.getAsJsonPrimitive("gpid").getAsString();
                        String hash = json.getAsJsonPrimitive("hash").getAsString();
                        String desc = json.getAsJsonPrimitive("description").getAsString();
                        long pub = json.getAsJsonPrimitive("publish").getAsLong() & 0x7FFFFFFF;
                        long sub = json.getAsJsonPrimitive("subscribe").getAsLong() & 0x7FFFFFFF;

                        int newpid = cm.migrateProject(username,gpid,hash,desc,pub,sub);
                        if (newpid > 0) {
                           logln("Added new project " + newpid + " via project migration from another server");
                           status = MNG_MIGRATE_REPLY_SUCCESS;
                           pidForUpdates = newpid;  //store globally for any updates that may come in
                        }
                        else {
                           logln("migrate project failed for gpid " + gpid + " hash " + hash);
                           status = MNG_MIGRATE_REPLY_FAIL;
                        }
                        resp.addProperty("status", status);
                        send_data(MNG_PROJECT_MIGRATE_REPLY, resp);
                     } catch (Exception ex) {
                        logln("Malformed PROJECT MIGRATE", LERROR);
                     }
                  }
                  else if (cmd.equals(MNG_MIGRATE_UPDATE)) {
                     logln("in MNG_MIGRATE_UPDATE", LERROR);
                     String username = json.getAsJsonPrimitive("newowner").getAsString();
                     logln("... got username" + username, LERROR);
                     String inner = json.getAsJsonPrimitive("update").getAsString();
                     JsonParser jp = new JsonParser();
                     JsonElement inner_element = jp.parse(inner);
                     if (inner_element.isJsonObject()) {
                        JsonObject inner_json = (JsonObject)inner_element;
                        String ucmd = inner_json.getAsJsonPrimitive("type").getAsString();
                        logln("... got cmd" + ucmd, LERROR);
                        cm.migrateUpdate(username, pidForUpdates, ucmd, inner_json);
                     }
                     else {
                        //bad inner json
                     }
                  }
                  else {
                     logln("unkown command", LERROR);
//The ServerManager has no means of processing this message as it is very much
//a synchronous protocol: Send Command -> Process Reply.  If we don't recognize
//their command we can easily drop it, but they are not likely to be looking
//for our reply
                  }
               }
            } catch (EOFException e) {
               logln("Manager connection dropped ", LINFO);
               continue;
            }
         }
      } catch (Exception ex) {
         logln("ManagerHelper terminating: " + ex.getMessage(), LINFO);
         ex.printStackTrace();
      }
   }

   /**
    * closes the socket
    */
   protected void terminate() {
      try {
         ss.close();
      } catch (Exception ex) {
      }
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
      cm.log("[MNG]" +  msg, v);
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

}

