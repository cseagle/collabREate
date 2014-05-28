/*
   collabREate ServerManager
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

//JDBC

package collabreate.server;

import java.io.*;
import java.net.*;
import java.sql.*;
import java.util.*;

/**
 * ServerManager
 * This class is responsible for routine server related operations
 * @author Tim Vidas
 * @author Chris Eagle
 * @version 0.1.0, August 2008
 */


public class ServerManager implements CollabreateConstants {

   private boolean done = false;

   private Properties props;

   private Connection con   = null;

   private boolean useMysql = false;

   private PreparedStatement listUsersQuery;
   private PreparedStatement listProjectsQuery;
   private PreparedStatement addUserQuery;
   private PreparedStatement updateUserQuery;
   private PreparedStatement findUserByUIDQuery;
   private PreparedStatement getAllUpdatesQuery;
   private PreparedStatement deleteUpdatesByPIDQuery;
   private PreparedStatement deleteProjectByPIDQuery;

   private static final String DEFAULT_PORT = "5043";
   private static final String DEFAULT_HOST = "localhost";
   private int port;
   private String host;

   private DataInputStream dis;
   private DataOutputStream dos;
   private Socket s;
   private byte[] emptyPayload = new byte[0];
   private static int mode = MODE_DB;

   private Vector<ProjectInfo> plist;

   public ServerManager(Properties p) {
      props = p;
      mode  = props.getProperty("SERVER_MODE", "database").equals("database") ? MODE_DB : MODE_BASIC;
      if (mode == MODE_DB) {
         con = getJDBCConnection(this);
         if (con != null) {
            System.out.println("Database connected.");
            initQueries();
         }
         else {
            System.err.println("Could not establish jdbc connection");
            mode = MODE_BASIC;
         }
      }
      else {
         System.err.println("Starting in BASIC mode");
      }
      plist = new Vector<ProjectInfo>();
      connectToHelper();
   }

   protected void setuseMysql(boolean val) {
      useMysql = val;
   }

   private Connection getJDBCConnection(ServerManager sm) {
      Connection c = null;
      if (mode == MODE_DB) {
	 c = dbUtils.getJDBCConnection(sm);
      }
      else {
         System.err.println("it appears that the server is configured for BASIC mode");
      }
      return c;
   }


   /**
    * runInsertInt is a database insert helper function, it runs an insert and returns
    * a Int value based on the result of the query - Statements must return a value to
    * be used with this function
    * @param s a prepared statement that provides a return value
    * @return integer return of the insert query
    */
   private int runInsertInt(PreparedStatement s) {
      int rval = -1;
      if (mode == MODE_DB) {
         rval = dbUtils.runInsertInt(s);
      }
      else {
         System.err.println("it appears that the server is configured for BASIC mode");
      }
      return rval;
   }

   private long runInsertLong(PreparedStatement s) {
      long rval = -1;
      if (mode == MODE_DB) {
         rval = dbUtils.runInsertLong(s);
      }
      else {
         System.err.println("it appears that the server is configured for BASIC mode");
      }
      return rval;
   }

   /**
    * deleteProject deletes a local project
    * @param pid the local project id to delete
    */
   protected synchronized void deleteProject (int pid) {
      if (mode == MODE_DB) {
         try {
            deleteUpdatesByPIDQuery.setInt(1, pid);
            deleteUpdatesByPIDQuery.execute();  //no Result Set expected

            deleteProjectByPIDQuery.setInt(1, pid);
            deleteProjectByPIDQuery.execute();  //no Result Set expected
         } catch (Exception ex) {
            System.err.println("Error deleting project" + pid + ": " + ex.getMessage());
         }
      }
      else {
         System.err.println("it appears that the server is configured for BASIC mode");
      }
   }

   /**
    * addUsers adds a user to this server
    * @param username the username to add
    * @param password the password for the user (hashed)
    * @param pub the publish permission bitmask
    * @param sub the subscribe permission bitmask
    * @return the userid of the added user, -1 on error
    */
   protected synchronized int addUser(String username, String password, long pub, long sub) {
      int rval = -1;
      if (mode == MODE_DB) {
         try {
            addUserQuery.setString(1, username);
            addUserQuery.setString(2, password);
            addUserQuery.setLong(3, pub);
            addUserQuery.setLong(4, sub);
            rval = runInsertInt(addUserQuery);
         } catch (Exception ex) {
            System.err.println("Error Adding user " + username + ": " + ex.getMessage());
         }
      }
      else {
         System.err.println("it appears that the server is configured for BASIC mode");
      }
      return rval;
   }

   /**
    * updateUser updates a user on this server
    * @param username the username to update
    * @param password the password for the user (hashed)
    * @param pub the publish permission bitmask
    * @param sub the subscribe permission bitmask
    * @param uid the userid of the record to apply the other values to
    * @return the userid of the added user, -1 on error
    */
   protected synchronized int updateUser(String username, String password, long pub, long sub, int uid) {
      int rval = -1;
      if (mode == MODE_DB) {
         try {
            updateUserQuery.setString(1, username);
            updateUserQuery.setString(2, password);
            updateUserQuery.setLong(3, pub);
            updateUserQuery.setLong(4, sub);
            updateUserQuery.setInt(5, uid);
            rval = runInsertInt(updateUserQuery);
         } catch (Exception ex) {
            System.err.println("Error updating uid " + uid + ": " + ex.getMessage());
         }
      }
      else {
         System.err.println("it appears that the server is configured for BASIC mode");
      }
      return rval;
   }


   /**
    * parsePerms attempts to interpret decimal and hex content as collabREate permissions
    * @param s the string to interpret
    * @param def the default permissions
    * @return the parsed permissions or def
    */
   protected static long parsePerms(String s, long def) {
      long rval;
      if (s.startsWith("0x")) {
         System.err.println("explicit hex");
         rval = Long.parseLong(s.substring(2, s.length()), 16);
      }
      else if (Utils.isNumeric(s)) {
         System.err.println("implicit dec");
         rval = Long.parseLong(s);
      }
      else if (Utils.isHex(s)) {
         System.err.println("implicit hex");
         rval = Long.parseLong(s, 16);
      }
      else {
         System.out.println("using default value of : 0x" + Long.toHexString(def) + " (got " + s + ")");
         rval = def;
      }
      return rval;
   }

   /**
    * terminate terminates the server manager
    */
   protected void terminate() {
      try {
         System.out.println("ServerManager terminating");
         done = true;
         closeDB();
         s.close();
      } catch (Exception e) {
      }
   }

   /**
    * connectToHelper connects to the managerHelper on the server on MANAGE_PORT,
    * by default this must be a local connection.
    */
   protected void connectToHelper() {
      port  = Integer.parseInt(props.getProperty("MANAGE_PORT", DEFAULT_PORT));
      host = props.getProperty("MANAGE_HOST", DEFAULT_HOST);
      if (s != null) {
         try {
            s.close();
         } catch (Exception ex) {
         }
      }
      try {
         //s = new Socket("127.0.0.1",port);
         //s = new Socket("localhost",port);
         s = new Socket(host,port);
         dis = new DataInputStream(new BufferedInputStream(s.getInputStream()));
         dos = new DataOutputStream(s.getOutputStream());
         System.out.println("Connection to ManagerHelper established. Ready to process commands");
      //} catch (UnknownHostException e) {
      } catch (Exception e) {
         System.err.println("Couldn't connect to ManagerHelper on " + host + ":" + port + ", is the server running?");
      }
   }


   /**
    * initQueries sets up all the prepared statements for later use
    */
   private void initQueries() {
     if (mode == MODE_DB) {
         try {
            listUsersQuery = con.prepareStatement("select userid,username,pub,sub from users order by userid asc;");
            listProjectsQuery = con.prepareStatement("select p.pid,p.gpid,p.hash,p.pub,p.sub,f.parent,p.description,q.description,p.snapupdateid from projects p left join (forklist f left join projects q on f.parent=q.pid) on p.pid = f.child order by p.pid asc;");
            findUserByUIDQuery = con.prepareStatement("select username,pwhash,pub,sub from users where userid=?");
            getAllUpdatesQuery = con.prepareStatement("select updateid,userid,pid,cmd,data,created from updates where pid=? order by updateid asc");
            deleteUpdatesByPIDQuery = con.prepareStatement("delete from updates where pid=?");
            deleteProjectByPIDQuery = con.prepareStatement("delete from projects where pid=?");

            if (useMysql) {
               addUserQuery = con.prepareStatement("select addUserQuery(?,?,?,?);");
               updateUserQuery = con.prepareStatement("select updateUserQuery(?,?,?,?,?);");
            }
            else {
               addUserQuery = con.prepareStatement("insert into users (username,pwhash,pub,sub) values (?,?,?,?) returning userid;");
               updateUserQuery = con.prepareStatement("update users set username=?,pwhash=?,pub=?,sub=? where userid=? returning userid;");
            }
         } catch (Exception ex) {
            System.err.println("Failed to initialize prepared queries");
            ex.printStackTrace();
         }
      }
   }



   /**
    * similar to post in Client, but does not check subscription status, and takes command as a arg
    * This function should ONLY be called for message id >= MNG_CONTROL_FIRST
    * because these messages do not contain an updateid and send only management data
    * @param command the command to send
    * @param data the data associated with the command
    */
   protected void send_data(int command, byte[] data) {
      try {
         if (command >= MNG_CONTROL_FIRST) {
            dos.writeInt(8 + data.length);
            dos.writeInt(command);
            dos.write(data);
            dos.flush();
            //System.err.println("send_data- cmd: " + command + " datasize: " + data.length);
         }
         else {
            System.err.println("post should be used for command " + command + ", not send_data.  Data not sent.");
         }
      } catch (Exception ex) {
      }
   }

   /**
    * dumpStats dumps rx/tx stats for this server
    * this requires ServerHelper to be running
    */

   protected void dumpStats() {
      int tries = 2;
      while (tries > 0) {
         try {
            tries--;
            send_data(MNG_GET_STATS, emptyPayload);

            //This requires that the server immediately replies !!!
            //otherwise we might get stuck here and have to kill the app
            int len = dis.readInt();
            int cmd = dis.readInt();
            String thelist = dis.readUTF();
            System.out.println("\nCollabREate Stats");
            System.out.println(thelist);
            break;
         } catch (NullPointerException e) {
            connectToHelper();
         } catch (EOFException e) {
            connectToHelper();
         } catch (Exception ex) {
            System.err.println("Error Dumping Stats" + ex.getMessage());
            ex.printStackTrace();
         }
      }
   }

   /**
    * shutdownServer sends a request to the server to shutdown the server nicely
    * this requires ServerHelper to be running
    */

   protected void shutdownServer() {
      int tries = 2;
      while (tries > 0) {
         try {
            tries--;
            //sending shutdown request, there is no expected reply
            send_data(MNG_SHUTDOWN, emptyPayload);

            break;
         } catch (NullPointerException e) {
            connectToHelper();
         } catch (Exception ex) {
            System.err.println("Error shutting down server" + ex.getMessage());
            ex.printStackTrace();
         }
      }
   }
   /**
    * getProjectInfo gets project information for a previously listed project
    * @param lpid the local PID for the project to get info on
    * @param pinfo a project info object to populate with information
    * @return 0 on success
    */
   protected int getProjectInfo(int lpid, ProjectInfo pinfo) {
      int rval = -1;
      try {
         if (plist != null) {
            for (ProjectInfo pi : plist) {
               if (pi.lpid == lpid) {
                  pinfo.lpid = pi.lpid;
                  pinfo.desc = pi.desc;
                  pinfo.parent = pi.parent;
                  pinfo.pdesc = pi.desc;
                  pinfo.snapupdateid = pi.snapupdateid;
                  pinfo.pub = pi.pub;
                  pinfo.sub = pi.sub;
                  pinfo.owner = pi.owner;
                  pinfo.hash = pi.hash;
                  pinfo.gpid = pi.gpid;
                  rval = 0;
               }
            }
         }
      } catch (Exception ex) {
         System.err.println("Error exporting project" + lpid + ": " + ex.getMessage());
         ex.printStackTrace();
      }
      return rval;
   }
   /**
    * exportProject exports a project to a binary final
    * @param lpid the local PID for the project to export
    * @param efile the filename to export to
    * @return 0 on success
    */
   protected int exportProject(int lpid, File efile) {
      int rval = -1;
      if (mode == MODE_DB) {
         try {
            ProjectInfo pi = new ProjectInfo(1, "none");
            if (getProjectInfo(lpid, pi) == 0) {
               if (pi.snapupdateid > 0) {
                  System.err.println("snapshot exporting is currently not implimented");
                  return -1;
               }
               System.out.println("exporting " + lpid + " (" + pi.gpid + ")");
               if (pi.parent > 0) {
                  System.err.println("This project was forked.  Note: lineage is not preserved with export.");
               }
               FileOutputStream fos = new FileOutputStream(efile);
               CollabreateOutputStream os = new CollabreateOutputStream();

               os.writeBytes(FILE_SIG);
               os.writeInt(FILE_VER);
               os.write(Utils.toByteArray(pi.gpid)); //should probably garuntee GPID_SIZE write
               os.write(Utils.toByteArray(pi.hash)); //should probably garuntee MD5_SIZE write
               os.writeLong(pi.sub);
               os.writeLong(pi.pub);
               os.writeUTF(pi.desc);  // at this point data is no longer at pre-known offsetsS

               //append all updates
               getAllUpdatesQuery.setInt(1, lpid);
               ResultSet rs = getAllUpdatesQuery.executeQuery();
               int numupdates = 0;
               System.out.println("processing updates");
               while (rs.next()) {
                  ++numupdates;
                  //System.out.println("processing update " + numupdates + "...");
                  System.out.print(".");
                  long updateid = rs.getLong(1);
                  int uid = rs.getInt(2);
                  int pid = rs.getInt(3);
                  int cmd = rs.getInt(4);
                  byte[] data = rs.getBytes(5); //varies based on particular update
                  Timestamp created = rs.getTimestamp(6);

                  os.writeInt(TAG);
                  os.writeLong(updateid);
                  os.writeInt(uid);
                  os.writeInt(pid);
                  os.writeInt(cmd);
                  os.writeInt(data.length);
                  os.write(data);
                  //write timestamp?
               }
               os.writeInt(ENDTAG);
               fos.write(os.toByteArray());
               fos.flush();
               fos.close();
               if (numupdates == 0) {
                  System.out.println("NO UPDATES FOUND FOR EXPORTING");
               }
               else {
                  System.out.println("Processed " + numupdates + " updates");
               }
               rval = 0;
            }
            else {
               System.out.println("Project " + lpid + " not found.");
            }
         } catch (Exception ex) {
            System.err.println("Error exporting project" + lpid + ": " + ex.getMessage());
            ex.printStackTrace();
         }
         System.out.println("");
      }
      else {
         System.err.println("it appears that the server is configured for BASIC mode");
      }
      return rval;
   }
   /**
    * importProject imports a project from a binary final
    * @param ifile the filename to import from
    * @param newowner the local uid to be the owner of the new project
    */
   protected int importProject(File ifile, int newowner) {
      int rval = -1;
      if (mode == MODE_DB) {
         try {
            ProjectInfo pi = new ProjectInfo(1,"none");
            FileInputStream fis = new FileInputStream(ifile);

            DataInputStream fdis;
            fdis = new DataInputStream(new BufferedInputStream(fis));

            byte[] sig = new byte[8];
            fdis.readFully(sig);
            if (FILE_SIG.equals(new String(sig))) {
               System.out.println("Magic matched");
            }
            else {
               System.out.println("This doesn't appear to be a collabREate binary file");
               return -1;
            }
            int ver = fdis.readInt();
            System.out.println("File format version " + ver);
            byte[] gpid = new byte[GPID_SIZE];
            fdis.readFully(gpid);
            System.out.println("importing " + Utils.toHexString(gpid));
            byte[] hash = new byte[MD5_SIZE];
            fdis.readFully(hash);
            System.out.println("(" + Utils.toHexString(hash) + ")");
            long sub = fdis.readLong();
            long pub = fdis.readLong();
            System.out.println("s " + sub + " p " + pub);
            String desc = fdis.readUTF();
            System.out.println("desc: " + desc);

            //addproject
            CollabreateOutputStream os = new CollabreateOutputStream();
            os.writeInt(newowner);
            os.write(gpid);
            os.write(hash);
            os.writeUTF(desc);
            os.writeLong(pub);
            os.writeLong(sub);
            send_data(MNG_PROJECT_MIGRATE, os.toByteArray());

            //slightly dangerous to assume the next message, but hey, it's the managment app...
            //(this could wait for this message forever)

            // this is really a throwaway, since we are expecting a specific message here
            int messagesize = dis.readInt();
            if (messagesize != 12) {
               System.err.println("protocol dictates 12 byte PROJECT_MIGRATE_REPLY, but recieved: " + messagesize);
               return rval;
            }

            int testcmd = dis.readInt();
            if (testcmd != MNG_PROJECT_MIGRATE_REPLY) {
               System.err.println("protocol dictates PROJECT_MIGRATE_REPLY, but recieved: " + testcmd);
               return rval;
            }
            int status = dis.readInt();
            if (status != MNG_MIGRATE_REPLY_SUCCESS) {
               System.err.println("Project migrate did not succeed on server, check server logs for more info");
               return rval;
            }
            else {
               System.out.println("Project creation succeeded on server");
            }

            int tag = fdis.readInt();
            while (tag == TAG) {
               long updateid = fdis.readLong();
               int uid = fdis.readInt();
               int pid = fdis.readInt();
               int cmd = fdis.readInt();
               int datalen = fdis.readInt();
               byte[] data = new byte[datalen];
               fdis.readFully(data);
               //read timestamp?

               //System.out.println("update:" + updateid + " orig uid " + uid + " oldpid " + pid + " cmd " + cmd + " datalen " + datalen);
               System.out.print(".");

               //insertUpdate
               CollabreateOutputStream cos = new CollabreateOutputStream();
               cos.writeInt(newowner);  //this is required becuase the original uid may
               //os.writeInt(uid);      //not be present on the new server (users aren't migrated yet)
               //cos.writeInt(newpid);  //similary, we could specify the newly created project
               cos.writeInt(pid);       //instead the Helper ignores pid and uses the last successfully migrated project from this session
               cos.writeInt(cmd);
               cos.writeInt(data.length);
               cos.write(data);
               send_data(MNG_MIGRATE_UPDATE, cos.toByteArray());

               tag = fdis.readInt();
            }
            if (tag != ENDTAG) {
               System.err.println("Error: didn't end update processing loop with ENDTAG");
            }
            else {
               rval = 0;
            }
            fdis.close();
            fis.close();
         } catch (Exception ex) {
            System.err.println("Error importing project from " + ifile.getAbsolutePath() + ": " + ex.getMessage());
            ex.printStackTrace();
         }
         System.out.println("");
      }
      else {
         System.err.println("it appears that the server is configured for BASIC mode");
      }
      return rval;
   }
   /**
    * getProps is an inspector that gets the current operation mode of the connection manager
    * @return a Properites object
    */
   protected Properties getProps() {
      return props;
   }

   /**
    * getMode is an inspector that gets the current operation mode of the connection manager
    * @return the mode
    */
   protected static int getMode() {
      return mode;
   }

   /**
    * listConnections lists the current connections to this server
    * this requires ServerHelper to be running
    */
   protected void listConnections() {
      int tries = 2;
      while (tries > 0) {
         try {
            tries--;
            System.out.println("\npre");
            send_data(MNG_GET_CONNECTIONS, emptyPayload);
            System.out.println("\npost");

            //This requires that the server immediately replies !!!
            //otherwise we might get stuck here and have to kill the app
            int len = dis.readInt();
            int cmd = dis.readInt();
            String thelist = dis.readUTF();
            System.out.println("\nCollabREate Connections");
            System.out.println(thelist);
            break;
         } catch (NullPointerException e) {
            connectToHelper();
         } catch (EOFException e) {
            connectToHelper();
         } catch (Exception ex) {
            System.err.println("Error Listing Connections " + ex.getMessage());
            ex.printStackTrace();
         }
      }
   }

   /**
    * listUsers lists the users on this server
    */
   protected void listUsers() {
      if (mode == MODE_DB) {
         try {
            System.out.println("\nCollabREate Users");
            System.out.println(String.format("%-4s%-10s%-10s%-10s %s", "UID", "Username", "Pub", "Sub", getPermHeaderString(8)));

            ResultSet rs = listUsersQuery.executeQuery();
            while (rs.next()) {
               System.out.println(String.format("%-4d%-10s%-10x%-10x %s", rs.getInt(1), rs.getString(2), rs.getLong(3), rs.getLong(4), getPermRowString(rs.getLong(3),rs.getLong(4),8)));
            }
            rs.close();
         } catch (Exception ex) {
            System.err.println("Error Listing users " + ex.getMessage());
            ex.printStackTrace();
         }
      }
      else {
         System.err.println("it appears that the server is configured for BASIC mode");
      }
   }

   /**
    * listProjects lists the projects on this server
    */
   protected void listProjects() {
      if (mode == MODE_DB) {
         try {
            String lastHash = "";
            System.out.println("\nCollabREate projects");
            System.out.println(String.format("%-4s %-4s %-4s %-10s %-10s %s %s\n", "PID", "PPID", "snap", "Pub", "Sub", getPermHeaderString(6), "Description"));

            //         listProjectsQuery = con.prepareStatement("select p.pid,p.gpid,p.hash,p.pub,p.sub,f.parent,p.description,q.description from projects p left join (forklist f left join projects q on f.parent=q.pid) on p.pid = f.child order by p.pid asc;");
            //                                                            1      2      3     4     5      6          7             8
            ResultSet rs = listProjectsQuery.executeQuery();
            while (rs.next()) {
               String hash = rs.getString(3);
               if (!hash.equals(lastHash)) {
                  //System.out.println(hash);
                  lastHash = hash;
               }
               String isSnap = (rs.getLong(9) > 0) ? " X " : "   ";
               System.out.println(String.format("%-4d %-4d %-4s %-10x %-10x %s %s", rs.getInt(1), rs.getInt(6), isSnap, rs.getLong(4), rs.getLong(5), getPermRowString(rs.getLong(4),rs.getLong(5),6), rs.getString(7)));
               ProjectInfo temppi = new ProjectInfo(rs.getInt(1),rs.getString(7));
               temppi.parent = rs.getInt(6);
               temppi.pdesc = rs.getString(8);
               temppi.snapupdateid = rs.getLong(9);
               temppi.pub = rs.getInt(4);
               temppi.sub = rs.getInt(5);
               temppi.owner = 0;
               temppi.hash = rs.getString(3);
               temppi.gpid = rs.getString(2);
               plist.add(temppi);
            }
            rs.close();
         } catch (Exception ex) {
            ex.printStackTrace();
         }
      }
      else {
         System.err.println("it appears that the server is configured for BASIC mode");
      }
   }

   /**
    * closeDB closes all the database queries and the database connection
    */
   private void closeDB() {
      if (mode == MODE_DB) {
         System.out.println("Closing database connection");
         try {
            if (con != null) {
               listUsersQuery.close();
               listProjectsQuery.close();
               addUserQuery.close();
               updateUserQuery.close();
               findUserByUIDQuery.close();
               getAllUpdatesQuery.close();
               deleteUpdatesByPIDQuery.close();
               deleteProjectByPIDQuery.close();
               s.close();
               con.close();
               con = null;
            }
         } catch (Exception e) {
         }
      }
   }

   /**
    * askyn requires the user to enter yes or no on the supplied BufferedReader
    * @param br the BufferedReader to force an answer on
    * @return true for yes, false for no
    */
   protected static boolean askyn(BufferedReader br) {
      try {
         String input = br.readLine();
         while (!("yes".equals(input) || "no".equals(input))) {
            System.out.println("yes/no?");
            input = br.readLine();
         }
         if ("yes".equals(input)) {
            return true;
         }
      } catch (Exception e) {
      }
      return false;
   }

   private String getPermHeaderString(int colWidth) {
      return getPermHeaderString(colWidth, false);
   }

   private String getPermHeaderString(int colWidth, boolean number) {
      String rval = "";
      String temp;
      for (int i = 0; i < permStrings.length; i++) {
         temp = (number)? "" + i + " " + permStrings[i] : permStrings[i];
         if (temp.length() < colWidth) {
            rval = rval + String.format("%-" + colWidth +"s|", temp);
         }
         else {
            rval = rval + String.format("%-" + colWidth +"s|", temp.substring(0, colWidth));
         }
      }
      return rval;
   }

   private String getPermRowString(long p, long s, int colWidth) {
      String rval = "";
      String fp = "";
      String fs = "";
      try {
         for (int i = 0; i < permStrings.length; i++) {
            if ((p & 1) == 1) {
               fp = "P";
            }
            else {
               fp = " ";
            }
            if ((s & 1) == 1) {
               fs = "S";
            }
            else {
               fs = " ";
            }
            rval = rval + String.format("%-" + colWidth +"s|", String.format(" %s %s", fp, fs));
            p = p >>> 1;
            s = s >>> 1;
         }
      } catch (Exception ex) {
         ex.printStackTrace();
      }
      return rval;
   }

   /**
    * main provides the cli interface for managing collabreate
    */
   public static void main(String args[]) throws Exception {
      ServerManager sm = null;
      System.out.println("Got " + args.length + " args");
      if (args.length >= 1) {
         //user specified a config file
         Properties p = new Properties();
         p.load(new FileInputStream(args[0]));
         sm = new ServerManager(p);
      }
      else {
         System.err.println("Could not read config file!");
         //not enough args
      }
      //special case for shutdown via init.d script
      if (args.length >= 2) {
         if ("shutdown".equals(args[0]) || "shutdown".equals(args[1])) {
           sm.shutdownServer();
           sm.terminate();
           System.exit(0);
         }
      }
      BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
      while (true) {
         System.out.println("");
         System.out.println("CollabREate Server Menu:");
         System.out.println("1)  Add user");
         System.out.println("2)  List users");
         System.out.println("3)  List Projects");
         System.out.println("4)  Edit user");
         System.out.println("5)  List Connections *");
         System.out.println("6)  Show tx/rx stats *");
         System.out.println("7)  Export a Project to file *");
         System.out.println("8)  Import a Project from file *");
         System.out.println("9)  Delete a Project");
         System.out.println("10) Quit");
         System.out.println("");
         System.out.println(" * requires CollabREate Server to be running");
         System.out.println("   others commands only require the database to be running ");
         System.out.print("Enter command: ");
         String resp = br.readLine();
         if (resp == null) {
            break;
         }
         resp = resp.trim();
         if ("1".equals(resp)) {
            if (getMode() != MODE_DB) {
               System.out.println("this only makes sense in DB MODE !");
               continue;
            }
            System.out.println("Note: the password typed in the interface is not masked ");
            System.out.print("Username: ");
            String username = br.readLine();
            if (!Utils.isAlphaNumeric(username)) {
               System.err.println("bad username");
               continue;
            }
            //any password is ok, including empty
            System.out.print("Password: ");
            String pass1 = br.readLine();
            System.out.print(" (again): ");
            String pass2 = br.readLine();
            if (!pass1.equals(pass2)) {
               System.err.println("passwords didn't match, not adding " + username);
               continue;
            }

            System.out.print("Subscribe permission bitfield (default: 0x" + Long.toHexString(default_sub) + "): ");
            //long sub = parsePerms(br.readLine().substring(0, 6));
            long sub = parsePerms(br.readLine(), default_pub);
            System.out.print("Publish permission bitfield (default: 0x" + Long.toHexString(default_pub) + "): ");
            long pub = parsePerms(br.readLine(), default_pub);

            System.out.print(""  + username + " " + pass1  + " "  + Utils.getMD5(pass1) + " " + pub + " " + sub);
            sm.addUser(username, Utils.getMD5(pass1), pub, sub);
         }
         else if ("2".equals(resp)) {
            if (getMode() != MODE_DB) {
               System.out.println("this only makes sense in DB MODE !");
               continue;
            }
            sm.listUsers();
         }
         else if ("3".equals(resp)) {
            if (getMode() != MODE_DB) {
               System.out.println("this only makes sense in DB MODE !");
               continue;
            }
            sm.listProjects();
         }
         else if ("4".equals(resp)) {
            if (getMode() != MODE_DB) {
               System.out.println("this only makes sense in DB MODE !");
               continue;
            }
            int uid;
            String username;
            String password;
            long pub;
            long sub;
            String ousername;
            String opassword;
            long opub;
            long osub;
            sm.listUsers();
            System.out.print("Which user (uid) would you like to edit? ");
            try {
               uid = Integer.parseInt(br.readLine());  //obviously doesn't check for valid uid
            } catch (NumberFormatException e) {
               System.err.println("You must select a valid number");
               continue;
            }

            sm.findUserByUIDQuery.setInt(1, uid);
            ResultSet rs = sm.findUserByUIDQuery.executeQuery();
            if (rs.next()) {
               username = rs.getString(1);
               password = rs.getString(2);
               pub = rs.getLong(3);
               sub = rs.getLong(4);
               ousername = username;
               opassword = password;
               opub = pub;
               osub = sub;

               System.out.print("Would you like to change the username? ");
               if (askyn(br)) {
                  System.out.print("Enter new username (" + username + "):");
                  String tempuser = br.readLine();
                  if (tempuser != null && tempuser.length() > 0) {
                     username = tempuser;
                  }
               }
               System.out.print("Would you like to create a new password? ");
               if (askyn(br)) {
                  System.out.print("Password: ");
                  String pass1 = br.readLine();
                  System.out.print(" (again): ");
                  String pass2 = br.readLine();
                  if (!pass1.equals(pass2)) {
                     System.err.println("passwords didn't match, not changing password ");
                  }
                  else {
                     password = Utils.getMD5(pass1);
                  }
               }
               System.out.print("Would you like to change the permissions? ");
               if (askyn(br)) {
                  System.out.print("Would you like to change the permissions by specifying numeric values? ");
                  if (askyn(br)) {
                     System.out.print("Enter new publish permissions (" + Long.toHexString(pub) + "):");
                     pub = parsePerms(br.readLine(), pub);
                     System.out.print("Enter new subscribe permissions (" + Long.toHexString(sub) + "):");
                     sub = parsePerms(br.readLine(), sub);
                  }
                  else {
                     System.out.print("Would you like to change the permissions one at a time? ");
                     if (askyn(br)) {
                        String userdata = null;
                        while (!("q".equals(userdata))) {
                           System.out.println("" + sm.getPermHeaderString(12, true));
                           System.out.println("" + sm.getPermRowString(pub, 0, 12));
                           System.out.print("Press the column number for the publish permission you'd like to toggle (q to exit): ");
                           userdata = br.readLine();
                           if (Utils.isNumeric(userdata)) {
                              if (permStrings.length > Integer.parseInt(userdata)) {
                                 if (((pub >> Integer.parseInt(userdata)) & 1) == 1) {
                                    pub = pub ^ (1 << Integer.parseInt(userdata));
                                 }
                                 else {
                                    pub = pub | (1 << Integer.parseInt(userdata));
                                 }
                              }
                           }
                        }
                        userdata = null;
                        while (!("q".equals(userdata))) {
                           System.out.println("" + sm.getPermHeaderString(12, true));
                           System.out.println("" + sm.getPermRowString(sub, 0, 12));
                           System.out.print("Press the column number for the subscribe permission you'd like to toggle (q to exit): ");
                           userdata = br.readLine();
                           if (Utils.isNumeric(userdata)) {
                              if (permStrings.length > Integer.parseInt(userdata)) {
                                 if (((sub >> Integer.parseInt(userdata)) & 1) == 1) {
                                    sub = sub ^ (1 << Integer.parseInt(userdata));
                                 }
                                 else {
                                    sub = sub | (1 << Integer.parseInt(userdata));
                                 }
                              }
                           }
                        }
                     }
                  }
               }
               if (!(username.equals(ousername) && password.equals(opassword) && (pub == opub) && (sub == osub))) {
                  sm.updateUser(username, password, pub, sub, uid);
               }
               else {
                  System.out.println("No changes made!");
               }
            }
            else {
               System.err.println("Userid " + uid + " not found!");
            }
            rs.close();
         }
         else if ("5".equals(resp)) {
            sm.listConnections();
         }
         else if ("6".equals(resp)) {
            sm.dumpStats();
         }
         else if ("7".equals(resp)) {
            if (getMode() != MODE_DB) {
               System.out.println("this only makes sense in DB MODE !");
               continue;
            }
            String userdata = null;
            sm.listProjects();
            System.out.print("Which project would you like to export (enter PID)? : ");
            userdata = br.readLine();
            if (Utils.isNumeric(userdata)) {
               int lpid = Integer.parseInt(userdata);
               System.out.print("Enter the filename to export to:");
               userdata = br.readLine();
               File efile = new File(userdata);
               if (efile.exists()) {
                  System.out.println("file " + userdata + " exists, overwrite?");
                  if (!askyn(br)) {
                    System.out.println("continuing");
                    continue;
                  }
               }
               if (sm.exportProject(lpid,efile) != 0) {
                  System.err.println("export did not fully comply successfully");
               }
            }
         }
         else if ("8".equals(resp)) {
            if (getMode() != MODE_DB) {
               System.out.println("this only makes sense in DB MODE !");
               continue;
            }
            String userdata = null;
            System.out.print("Enter the filename to import from:");
            userdata = br.readLine();
            File ifile = new File(userdata);
            if (ifile.exists()) {
               sm.listUsers();
               int uid;
               System.out.print("Which user (uid) should be the new owner? ");
               try {
                  uid = Integer.parseInt(br.readLine());  //obviously doesn't check for valid uid
               } catch (NumberFormatException e) {
                  System.err.println("You must select a valid number");
                  continue;
               }
               if (sm.importProject(ifile,uid) != 0) {
                  System.err.println("import did not fully comply successfully");
               }
            }
            else {
               System.out.println("file " + userdata + " not found");
            }
         }
         else if ("9".equals(resp)) {
            if (getMode() != MODE_DB) {
               System.out.println("this only makes sense in DB MODE !");
               continue;
            }
            String userdata = null;
            sm.listProjects();
            System.out.print("Which project would you like to permenantly delete? : ");
            userdata = br.readLine();
            if (Utils.isNumeric(userdata)) {
               int lpid = Integer.parseInt(userdata);
               System.out.println("Are you sure you want to delete project " + lpid + "(and all associated updates?)");
               System.out.println("Note: this does current support projects with related snapshots or forks");
               System.out.println("yes/no");
               if (askyn(br)) {
                  sm.deleteProject(lpid);
               }
            }
         }
         else if ("10".equals(resp)) {
            sm.terminate();
            break;
         }
         else if ("11".equals(resp)) {
            System.out.println("Use of server startup/shutdown scripts (ie. /etc/init.d) is recommended.");
            System.out.print("Are you sure you want to shutdown the server? ");
            if (askyn(br)) {
               sm.shutdownServer();
            }
         }
      }
   }

}

