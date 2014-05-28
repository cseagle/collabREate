/*
   collabREate DatabaseConnectionManager
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
 * DatabaseConnectionManager
 * This class is responsible for routing incoming packets to all
 * interested clients
 * @author Tim Vidas
 * @author Chris Eagle
 * @version 0.1.0, August 2008
 */


public class DatabaseConnectionManager extends ConnectionManagerBase {

   private Connection con   = null;

   private boolean useMysql = false;
   
   private PreparedStatement postUpdateQuery;
   private PreparedStatement addProjectQuery;
   private PreparedStatement addProjectSnapQuery;
   private PreparedStatement addProjectForkQuery;
   private PreparedStatement findProjectsByHashQuery;
   private PreparedStatement findProjectByPidQuery;
   private PreparedStatement findProjectByGpidQuery;
   private PreparedStatement getUserInfoQuery;
   private PreparedStatement getLatestUpdatesQuery;
   private PreparedStatement copyUpdatesQuery;
   private PreparedStatement projectPermsUpdateQuery;
//   private PreparedStatement snapProjectQuery;

   public DatabaseConnectionManager(CollabreateServer mcs, Properties p, Connection dbconn) {
      super(mcs, p, false);
      con = dbconn;
      String driver = p.getProperty("JDBC_DRIVER", "org.postgresql.Driver");
      if (driver.indexOf("mysql") != -1) {
         useMysql = true;
      }
      initQueries();
   }

   /**
    * authenticate authenticates a user (for use in database mode)
    * bacially this is standard CHAP with HMAC (md5)
    * @param user the user to authenticate
    * @param challenge the randomly generated challenge send to the plugin
    * @param response the calculated response from the plugin to check 
    * @return the user id of an authenticated user, or INVALID_USER
    */
   protected synchronized int authenticate(Client c, String user, byte[] challenge, byte[] response) {
      int userid = Client.INVALID_USER;
      try {
         getUserInfoQuery.setString(1, user);
         ResultSet rs = getUserInfoQuery.executeQuery();
         if (rs.next()) {
            int uid = rs.getInt(1);
            String pwhash = rs.getString(2);
            byte key[] = Utils.toByteArray(pwhash);
            byte hmac[] = HmacMD5.hmac(challenge, key);
            if (response != null && Arrays.equals(response, hmac)) {
               userid = uid;
               c.setUserPub(rs.getLong(3));
               c.setUserSub(rs.getLong(4));
            }
            else {
               userid = Client.INVALID_USER;
            }
         }
         rs.close();
      } catch (Exception ex) {
         logln("Error during authenticate", LERROR);
         logex(ex);
         userid = Client.INVALID_USER;
      }
      return userid;
   }

   /**
    * migrateUpdate is very similar to 'post', migrateUpdate only 
    * archives the udpate in the database so that future clients can receive it 
    * @param newowner the new uid to attribute the update to
    * @param pid the local project id for the migrated project
    * @param cmd the 'command' that was performed (comment, rename, etc)
    * @param data the 'data' portion of the command (the comment text, etc)
    */
   protected void migrateUpdate(int newowner, int pid, int cmd, byte[] data) {
      logln("in migrateUpdate", LINFO4);
      long updateid = 0;
      synchronized (queue) {
         try {
            //db insert
            postUpdateQuery.setInt(1, newowner);
            postUpdateQuery.setInt(2, pid);
            postUpdateQuery.setInt(3, cmd);
            //note that this data array already has 8 bytes (8-15) reserved to receive the updateid
            //when updates are requested in the future
            postUpdateQuery.setBytes(4, data);
            updateid = runInsertLong(postUpdateQuery);
            logln("migrated update: " + updateid + "cmd: " + cmd + "pid: " + pid + " size: " + data.length, LINFO4);
         } catch (Exception e) {
            logex(e);
         }
         //queue.add(new Packet(src, data, updateid));   //add a new packet with the binary data to the queue
         //queue.notify();  //notify is the compliment to wait
      }
   }

   /**
    * post both queues a newly received update to be sent to other clients and (if in DB mode)
    * archives the udpate in the database so that future clients can receive it 
    * @param src the client that made the update
    * @param cmd the 'command' that was performed (comment, rename, etc)
    * @param data the 'data' portion of the command (the comment text, etc)
    */
   protected void post(Client src, int cmd, byte[] data) {
      long updateid = 0;
      synchronized (queue) {
         try {
            //db insert
            postUpdateQuery.setInt(1, src.getUid());
            postUpdateQuery.setInt(2, src.getPid());
            postUpdateQuery.setInt(3, cmd);
            //note that this data array already has 8 bytes (8-15) reserved to receive the updateid
            //when updates are requested in the future
            postUpdateQuery.setBytes(4, data);
            updateid = runInsertLong(postUpdateQuery);
            logln("Added update: " + updateid + "cmd: " + cmd + "pid: " + src.getPid() + " size: " + data.length, LINFO4);
         } catch (Exception e) {
            logex(e);
         }
         queue.add(new Packet(src, data, updateid));   //add a new packet with the binary data to the queue
         queue.notify();  //notify is the compliment to wait
      }
   }

   /**
    * initQueries sets up all the prepared statements for later use  
    */
   private void initQueries() {
      try {
         findProjectsByHashQuery = con.prepareStatement("select p.pid,p.hash,p.gpid,p.description,f.parent,p.snapupdateid,q.description,p.pub,p.sub,p.owner,p.protocol from projects p left join (forklist f left join projects q on f.parent=q.pid) on p.pid = f.child where p.hash = ? order by p.pid asc;");
         //findProjectByPidQuery = con.prepareStatement("select pid,hash,gpid,snapupdateid,description from projects where pid = ?;");
         findProjectByPidQuery = con.prepareStatement("select p.pid,p.hash,p.gpid,p.snapupdateid,p.description,f.parent,q.description,p.pub,p.sub,p.owner,p.protocol from projects p left join (forklist f left join projects q on f.parent=q.pid) on p.pid=f.child where p.pid = ? order by p.pid asc;");
         findProjectByGpidQuery = con.prepareStatement("select pid,hash,gpid,protocol from projects where gpid = ? order by pid asc;");
         getUserInfoQuery = con.prepareStatement("select userid,pwhash,pub,sub from users where username = ? order by userid asc;");
         getLatestUpdatesQuery = con.prepareStatement("select updateid,cmd,data from updates where updateid > ? and pid = ? order by updateid asc;");
         projectPermsUpdateQuery = con.prepareStatement("update projects set pub=?,sub=? where pid=?");

         if (useMysql) {
            copyUpdatesQuery = con.prepareCall("{ call copyUpdates(?,?,?) }");
            postUpdateQuery = con.prepareStatement("select insertUpdate(?,?,?,?);");
            addProjectQuery = con.prepareStatement("select addProjectQuery(?,?,?,?,?,?,?);");
            addProjectSnapQuery = con.prepareStatement("select addProjectSnapQuery(?,?,?,?,?,?);");
            addProjectForkQuery = con.prepareStatement("select addProjectForkQuery(?,?);");
         }
         else {
            copyUpdatesQuery = con.prepareStatement("begin; create temporary table tmptable (like updates) on commit drop; insert into tmptable select * from updates where pid = ? and updateid <= ?; update only tmptable set pid=?; insert into updates (select * from tmptable); commit;");
            postUpdateQuery = con.prepareStatement("insert into updates (userid,pid,cmd,data) values (?,?,?,?) returning updateid;");
            addProjectQuery = con.prepareStatement("insert into projects (hash,gpid,description,owner,pub,sub,protocol) values (?,?,?,?,?,?,?) returning pid;");
            addProjectSnapQuery = con.prepareStatement("insert into projects (hash,gpid,description,owner,snapupdateid,protocol) values (?,?,?,?,?,?) returning pid;");
            addProjectForkQuery = con.prepareStatement("insert into forklist (child,parent) values (?,?) returning fid;");
         }
   //    snapProjectQuery = con.prepareStatement("insert into snapshots (pid,updateid,description,createdby) values (?,?,?,?) returning sid;");
      } catch (Exception ex) {
         logln("Failed to initialize prepared queries", LERROR);
         logex(ex);
      }
   }

   /**
    * runInsertInt is a database insert helper function, it runs an insert and returns
    * a Int value based on the result of the query - Statements must return a value to 
    * be used with this function 
    * @param s a prepared statement that provides a return value 
    * @return integer return of the insert query
    */
   private int runInsertInt(PreparedStatement s) {
    //  logln("SQL: " + query);
      int rval = -1;
      try {
         ResultSet rs = s.executeQuery();
         if (rs.next()) {
            rval = rs.getInt(1);
            //logln("SQL Insert rval:  " + rval);
         }
         rs.close();
      } catch (SQLException e) {
         logln("SQL Exception encountered",LERROR);
         logex(e,LINFO3);
      } catch (Exception exc) {
         logln("Database Insert error (returning int) ", LERROR);
         logln("" + exc.getMessage(), LDEBUG);
      }
      return rval;
   }

   /**
    * runInsertLong is a database insert helper function, it runs an insert and returns
    * a Long value based on the result of the query - Statements must return a value to 
    * be used with this function 
    * @param s a prepared statement that provides a return value 
    * @return long return of the insert query
    */
   private long runInsertLong(PreparedStatement s) {
    //  logln("SQL: " + query);
      long rval = -1;
      try {
         ResultSet rs = s.executeQuery();
         if (rs.next()) {
            rval = rs.getLong(1);
            logln("SQL Insert rval:  " + rval, LSQL);
         }
         rs.close();
      } catch (Exception exc) {
         logln("Database Insert error (returning long) ", LERROR);
         logln("" + exc.getMessage(), LDEBUG);
         //logex(exc);
      }
      return rval;
   }

   /**
    * sendLatestUpdates sends updates from LastUpdate to current 
    * it is expected that the client has already joined a project before calling this function
    * it is expected that the client has already received updates from 0 - lastUpdate 
    * this function is typically called when a user is re-joining a project that they had previously worked on
    * @param c the client requesting updates 
    * @param lastUpdate the last update the client received 
    */
   protected synchronized void sendLatestUpdates(Client c, long lastUpdate) {
      try {
         getLatestUpdatesQuery.setLong(1, lastUpdate);
         getLatestUpdatesQuery.setInt(2, c.getPid());
         ResultSet rs = getLatestUpdatesQuery.executeQuery();
         while (rs.next()) {
            long updateid = rs.getLong(1);
            int cmd = rs.getInt(2);
            byte data[] = rs.getBytes(3);
            logln("posting " + updateid + " (cmd " + cmd + ")");
            insertUpdateid(data, 8, updateid);
            c.post(data);
         }
         rs.close();
      } catch (Exception ex) {
      }
   }

   /**
    * getProjectInfo gets informatio related to a local project
    * @param pid the local pid of a project to get info on
    * @return a  project info object for the provided pid
    */
   protected ProjectInfo getProjectInfo(int pid) {
      String projectstring;
      ProjectInfo pinfo = null;

      try {
         findProjectByPidQuery.setInt(1, pid);
         ResultSet rs = findProjectByPidQuery.executeQuery();
         while (rs.next()) {
            int proto = rs.getInt(11);
            if (proto != PROTOCOL_VERSION) {
               continue;
            }
            int lpid = rs.getInt(1);
            String desc = rs.getString(5);
            int parent = rs.getInt(6);
            long snapupdateid= rs.getLong(4);
            String pdesc = rs.getString(7);
            pinfo = new ProjectInfo(lpid, desc);
            pinfo.parent = parent;
            pinfo.pdesc = pdesc;
            pinfo.snapupdateid = snapupdateid;
            pinfo.pub = rs.getLong(8);
            pinfo.sub = rs.getLong(9);
            pinfo.owner = rs.getInt(10);
            pinfo.proto = proto;
            if (projects.containsKey(lpid)) {
               pinfo.connected = (projects.get(lpid)).size();
            }
         }
         rs.close();
      } catch (Exception ex) {
         logln("Error getting pinfo: " + ex.getMessage(),LERROR);
         logex(ex);
      }

      return pinfo;
   }

   /**
    * getProjectList generates a list of projects on this server, each list (vector) item is 
    * actually a pinfo (project info) object, the list does NOT contain all projects, but
    * only contains projects relevant to the binary that is currently loaded in IDA
    * @param phash the IDA generated hash that is unique among the analysis files
    * @return a vector of project info objects for the provided phash
    */
   protected Vector<ProjectInfo> getProjectList(String phash) {
      String projectstring;
      Vector<ProjectInfo> plist = new Vector<ProjectInfo>();

      try {
         findProjectsByHashQuery.setString(1, phash);
         ResultSet rs = findProjectsByHashQuery.executeQuery();
         while (rs.next()) {
            int proto = rs.getInt(11);
            if (proto != PROTOCOL_VERSION) {
               continue;
            }
            int lpid = rs.getInt(1);
            String desc = rs.getString(4);
            int parent = rs.getInt(5);
            long snapupdateid= rs.getLong(6);
            String pdesc = rs.getString(7);
            ProjectInfo pinfo = new ProjectInfo(lpid, desc);
            pinfo.parent = parent;
            pinfo.pdesc = pdesc;
            pinfo.snapupdateid = snapupdateid;
            pinfo.pub = rs.getLong(8);
            pinfo.sub = rs.getLong(9);
            pinfo.owner = rs.getInt(10);
            pinfo.proto = proto;
            if (projects.containsKey(lpid)) {
               pinfo.connected = (projects.get(lpid)).size();
            }

            plist.add(pinfo);
         }
         rs.close();
      } catch (Exception ex) {
         logln("Error creating plist: " + ex.getMessage(), LERROR);
         logex(ex);
      }

      return plist;
   }

   /**
    * joinProject joings a particular client to a project so that it can participate in collabREation 
    * @param c the client attempting to join 
    * @param lpid the local project id of the project on this server 
    * @return 0 on success, negative value on failure
    */
   protected int joinProject(Client c, int lpid) {
      int rval = -1;
      logln("in join");
      try {
         boolean foundPid = false;
         logln("joining in db mode");
         findProjectByPidQuery.setInt(1, lpid);
         ResultSet rs = findProjectByPidQuery.executeQuery();
         if (rs.next() && rs.getInt(11) == PROTOCOL_VERSION) {
            logln("in joinProject: " + lpid + " " + rs.getString(2) + " " + rs.getLong(4) + " " + rs.getString(5) + " " + rs.getString(7), LDEBUG);
            if (rs.getLong(4) > 0) {  //pid is a snapshot pid
               //this should now be an error condition
               //logln("Attempt to join snapshot " + lpid + " forking instead");
               //return forkProject(c, rs.getLong(4), rs.getString(7) + " + " + rs.getString(5));
               c.send_error("can't join a snapshot, you MUST fork a snapshot");
               logln("attempted to join a snapshop instead of forking", LERROR);
               return -1;
            }
            c.setPid(lpid);
            c.setHash(rs.getString(2));
            c.setGpid(rs.getString(3));
            if (rs.getInt(10) == c.getUid()) { //project owner gets full perms, regardless of user, project, or requested perms
               logln("Project Owner joined! yay!", LINFO3);
               c.setPub(FULL_PERMISSIONS);
               c.setSub(FULL_PERMISSIONS);
            }
            else { //effective permissions are user perms ANDed with project perms ANDed with the perms requested by the user
               logln("effective publish  : " + 
                     Long.toHexString(rs.getLong(8)) + " & " + 
                     Long.toHexString(c.getReqPub()) + " & " + 
                     Long.toHexString(c.getUserPub()) + " = " + 
                     Long.toHexString(rs.getLong(8) & c.getUserPub() & c.getReqPub()),LINFO1);
               logln("effective subscribe: " + 
                     Long.toHexString(rs.getLong(9)) + " & " + 
                     Long.toHexString(c.getReqSub()) + " & " + 
                     Long.toHexString(c.getUserSub()) + " = " + 
                     Long.toHexString(rs.getLong(9) & c.getUserSub() & c.getReqSub()),LINFO1);
               c.setPub(rs.getLong(8) & c.getUserPub() & c.getReqPub());
               c.setSub(rs.getLong(9) & c.getUserSub() & c.getReqSub());
            }

            foundPid = true;
         }
         rs.close();
         if (foundPid) {
            Vector<Client> vc = projects.get(lpid);
            if (vc == null) {  //not currently reflecting
               logln("JOIN: adding " + lpid + " to reflector table");
               vc = new Vector<Client>();
               projects.put(lpid, vc);
            }
            synchronized (vc) {
               vc.add(c);
            }
            rval = 0;
         }
         else {
            logln("ERROR: attempt to join a non-existant project: " + lpid, LERROR);
         }
      } catch (SQLException e) {
         logln("SQL Exception encountered",LERROR);
         logex(e, LINFO3);
      } catch (Exception ex) {
         logex(ex);
      }

      return rval;
   }
 
   /**
    * snapProject adds a snapshop for a project, this does not change the client's 
    * current project, nor copy any updates, it simply marks a point-in-time (updateid wise)
    * this point-in-time can later be used as a project fork point if desired 
    * @param c the client invoking the snapshot
    * @param lastupdateid the point-in-time the client wishes to save in the snapshot
    * @param desc a user provided description of the snapshot
    * @return the snapshotid on success, -1 on failure
    */
   protected int snapProject(Client c, long lastupdateid, String desc) {
        /*
         snapProjectQuery.setInt(1, c.getPid());
         snapProjectQuery.setLong(2, lastupdateid);
         snapProjectQuery.setString(3, desc);
         snapProjectQuery.setInt(4, c.getUid());
         int sid= runInsertInt(snapProjectQuery);
         int lpid = addProject(c, c.getHash(), desc);  //could add "forked from" to desc at this point
         if (lpid >= 0) {
         }
         else {
            //send snap error
         }
        */

      int spid = -1;
      int uid = c.getUid();
      int oldpid = c.getPid();
      String gpid;
      try {
         logln("User " + uid + " adding snapshot for " + c.getHash(), LINFO);
         synchronized (pidLock) {
            while (true) {
               //generate a new GPID; We optimistically insert, assuming
               //this gpid is unique, and catch the SQLException if the
               //gpid uniqueness constraint is violated
               byte gpid_bytes[] = Utils.getRandom(32);
               gpid = Utils.toHexString(gpid_bytes);
               logln(" ... with gpid: " + gpid, LINFO2);
               addProjectSnapQuery.setString(1, c.getHash());
               addProjectSnapQuery.setString(2, gpid);
               addProjectSnapQuery.setString(3, desc);
               addProjectSnapQuery.setInt(4, uid);
               addProjectSnapQuery.setLong(5, lastupdateid);
               addProjectSnapQuery.setInt(6, PROTOCOL_VERSION);
               try {
                  ResultSet rs = addProjectSnapQuery.executeQuery();
                  if (rs.next()) {
                     spid = rs.getInt(1);
                     //c.setPid(lpid);
                     //c.setGpid(gpid);
                     break;
                  }
                  rs.close();
               } catch (SQLException ex) {
                  //if addProjectSnapQuery fails uniqueness constraint we end up here
                 logln("snap project failed: " + ex.getMessage(), LERROR);
                 logex(ex);
               }
            }
         }
         addProjectForkQuery.setInt(1, spid);
         addProjectForkQuery.setInt(2, oldpid);
         int fid = runInsertInt(addProjectForkQuery);
         if (fid >= 0) {
            logln("Snapshot id for project " + oldpid + " at updateid " + lastupdateid + " is: " + spid, LINFO);
         }
         else {
            logln("project snap failed forklist insert", LERROR);
         }
      } catch (Exception e) {
         //logex(e);
         logln("project snap failed: " + e.getMessage(), LERROR);
      }

      return spid;
   }


   /**
    * forkProject  forks a project - creats new project and copies all updates to point to the new project,
    * publish and subscribe values are inherited
    * @param c client object invoking the fork
    * @param lastupdateid the updateid value the fork is to occur at
    * @param desc user provided description of the fork
    * @return the new projectid on success, -1 on failure
    */

   protected int forkProject(Client c, long lastupdateid, String desc) {
      int rval = -1;
      try {
         findProjectByPidQuery.setInt(1, c.getPid());
         ResultSet rs = findProjectByPidQuery.executeQuery();
         if (rs.next()) {
            long pub = rs.getLong(8);
            long sub = rs.getLong(9);
            logln("forking " + c.getPid() + " pub is " + pub + " sub is " + sub);
            rval = forkProject(c, lastupdateid, desc, pub, sub); 
         }
         rs.close();
      } catch (Exception e) {
      }

      return rval;
   }


   /**
    * forkProject  forks a project - creats new project and copies all updates to point to the new project
    * @param c client object invoking the fork
    * @param lastupdateid the updateid value the fork is to occur at
    * @param desc user provided description of the fork
    * @param pub specified publish permissions
    * @param sub specified subscribe permissions
    * @return the new projectid on success, -1 on failure
    */
   protected int forkProject(Client c, long lastupdateid, String desc, long pub, long sub) {
      logln("in forkProject ", LDEBUG);
      int rval = -1;
      try {
         int oldlpid = c.getPid();
         remove(c);
         int lpid = addProject(c, c.getHash(), desc, pub, sub);  //could add "forked from" to desc at this point
         if (lpid >= 0) {
            //gpid and lpid are set in addProject
            //add to forklist
            addProjectForkQuery.setInt(1, lpid);
            addProjectForkQuery.setInt(2, oldlpid);
            int fid = runInsertInt(addProjectForkQuery);
            logln("Forked (" + fid + "): Project " + lpid + " forked from " + oldlpid, LINFO);
            
            //dup update records
            copyUpdatesQuery.setInt(1, oldlpid);
            copyUpdatesQuery.setLong(2, lastupdateid);
            copyUpdatesQuery.setInt(3, lpid);
            //copyUpdatesQuery.setInt(4, lpid); // for select max(updatedid) where pid = ?
            long lastinserted = runInsertLong(copyUpdatesQuery);
            logln("Last inserted was " + lastinserted + ", lastupdateid was " + lastupdateid, LINFO);
            rval = lpid;
            //at this point the project has forked and the plugin that forked is on the new project
            
            //allow anyone else on the project (w/ exactly the same updates) to follow the fork
            String gpid = lpid2gpid(lpid);
            logln("sending fork follows", LINFO);
            sendForkFollows(c, oldlpid, lastupdateid, desc);
         }
         else {
            //rejoin original project
            joinProject(c, oldlpid);
            //send fork error
            c.send_error("Fork Failed, could not create forked project");
         }
      
      } catch (Exception ex) {
         logex(ex);
      }

      return rval;
   }


   /* didn't quite getting around to using this function, instead the client sends a 
    * project quit, then a rejoin with the new gpid
    */
   /*
   protected int switchProject(Client c, int newlpid) {
      int rval = -1;
      Vector<Client> vc = projects.get(newlpid);
      if (vc == null) {  //not currently reflecting
         c.send_error("attempt to switch to non-existant project");
      }
      else {
         String gpid = lpid2gpid(newlpid);
         if (mode == MODE_DB) {
            try {
               logln("switching to project " + newlpid);
               c.setPid(newlpid);
               c.setGpid(gpid);
               rval = 0;
            } catch (Exception e) {
            }
         }
         else {
            c.setPid(newlpid);
            c.setGpid(EMPTY_GPID);
            rval = 0;
         }
         synchronized (vc) {
            vc.add(c);
         }
      }
      return rval;
   }
   */
   /**
    * sendForkFollows sends a special "follow fork" message to all clients working on
    * a project that has been forked, this allows the user to decide if they would like
    * to continue to work on the existing project, or change to the newly created project
    * @param originator the client that instigated the fork
    * @param oldlpid the local pid of the original project
    * @param lastupdateid the last update processed prior to fork (if your database is different you can't change to the new project)
    * @param desc the description of the new project, so the user can make a more educated descision
    */
   protected void sendForkFollows(Client originator, int oldlpid, long lastupdateid, String desc) {
      String fuser = originator.getUser();
      String gpid = originator.getGpid();
      Vector<Client> vc = projects.get(oldlpid);  
      logln("in sendForkFollows");
      logln("pid " + oldlpid, LINFO3);
      logln("vc size " + vc.size(), LINFO3);
      if (vc != null) {
         synchronized (vc) {
            for (Client c : vc) {     //foreach Client c
               logln("processing a client", LINFO3);
               if (c != originator) {  //sanity check, originator shouldn't be in vector anymore
                  try {
                     logln("  sending follow to " + c.getUser(), LINFO3);
                     c.sendForkFollow(fuser, gpid, lastupdateid, desc);
                  } catch (Exception ex) {
                     logex(ex);
                  }
               }
            }
         }
      }
   }


   /**
    * snapforkProject -  this is a special version of forkProject that is designed to work
    * on snapshots (instead of existing projects) this works exactly like forkProject, execpt
    * updates are copied from the 'parent' of the snapshot instead of the client's currently 
    * associated project, also updates are copied until the lastupdateid from the snapshot, 
    * not from the plugin (last received update is stored in the idb)
    * @param c client invoking the snapforkProject
    * @param spid the pid of the project that is being snapshotted
    * @param desc the user provided description for the snapshot
    * @return the new project id on success, -1 on failure
    */

   protected int snapforkProject(Client c, int spid, String desc, long pub, long sub) {
      int rval = -1;
      try {
         int oldlpid = spid;
         
         //get lastupdateid from snapshot record
         long lastupdateid = -1;
         int parentlpid = -1;
         findProjectByPidQuery.setInt(1, oldlpid);
         ResultSet rs = findProjectByPidQuery.executeQuery();
         if (rs.next()) {
            lastupdateid = rs.getLong(4);
            parentlpid = rs.getInt(6);
         }
         
         if (lastupdateid >= 0 && parentlpid >= 0 ) {
            int lpid = addProject(c, c.getHash(), desc, pub, sub);  
            if (lpid >= 0) {
               //gpid and lpid are set in addProject
               //add to forklist
               addProjectForkQuery.setInt(1, lpid);
               addProjectForkQuery.setInt(2, oldlpid);
               int fid = runInsertInt(addProjectForkQuery);
               logln("Forked (" + fid + "): Project " + lpid + " forked from snapshot " + oldlpid + "(original project " + parentlpid + ")", LINFO);
               
               //dup update records from the snapshot parent projeect, upto the snapshots lastupdateid
               copyUpdatesQuery.setInt(1, parentlpid);
               copyUpdatesQuery.setLong(2, lastupdateid);
               copyUpdatesQuery.setInt(3, lpid);
               //copyUpdatesQuery.setInt(4, lpid); // for select max(updatedid) where pid = ?
               long lastinserted = runInsertLong(copyUpdatesQuery);
               logln("Last inserted was " + lastinserted + ", lastupdateid was " + lastupdateid, LINFO);
               
               rval = lpid;
            }
            else {
               c.send_error("Snapfork Failed, could not snap fork");
            }
         }
         else {
            c.send_error("attempt to snapfork a project (not a snapshot)");
         }

      } catch (Exception ex) {
         logex(ex);
      }

      return rval;
   }

   /**
    * migrateProject adds a project to the database  
    * fairly similar to addProject
    * @param owner the uid to be the owner of the new project
    * @param gpid unique global id for the incoming project
    * @param hash unique hash for the binary file originally generated by IDA
    * @param desc user provided description of the project 
    * @param pub the publish permissions for the project
    * @param sub the subscribe permissions for the project
    * @return the new project id on success, -1 on failure
    */

   protected int migrateProject(int owner, String gpid, String hash, String desc, long pub, long sub) {
      logln("in migrateProject ", LDEBUG);
      int lpid = -1;
      try {
         logln("Owner " + owner + " migrating project for " + hash, LINFO);
         logln(" P " + pub + "   S " + sub, LINFO);
         synchronized (pidLock) {
            logln(" ... with gpid: " + gpid, LINFO1);
            addProjectQuery.setString(1, hash);
            addProjectQuery.setString(2, gpid);
            addProjectQuery.setString(3, desc);
            addProjectQuery.setInt(4, owner);
            addProjectQuery.setLong(5, pub);
            addProjectQuery.setLong(6, sub);
            addProjectQuery.setInt(7, PROTOCOL_VERSION);
            try {
               ResultSet rs = addProjectQuery.executeQuery();
               if (rs.next()) {
                  lpid = rs.getInt(1);
               }
               rs.close();
            } catch (SQLException ex) {
               //if addProjectQuery fails uniqueness constraint we end up here
               logln("migrate project failed: " + ex.getMessage(), LERROR);
               logex(ex);
            }
         }
      } catch (Exception e) {
         logex(e);
         logln("project migrate failed: " + e.getMessage(), LERROR);
      }
      return lpid;
   }
   /**
    * addProject adds a project to the database and reflector (or merely a reflector in non-DB mode) 
    * @param c cliend invoking the addProject
    * @param hash unique hash for the binary file originally generated by IDA
    * @param desc user provided description of the project 
    * @param pub the publish permissions for the project
    * @param sub the subscribe permissions for the project
    * @return the new project id on success, -1 on failure
    */

   protected int addProject(Client c, String hash, String desc, long pub, long sub) {
      logln("in addProject ", LDEBUG);
      int lpid = -1;
      int uid = c.getUid();
      String gpid;
      try {
         logln("User " + uid + " adding project for " + hash, LINFO);
         logln(" P " + pub + "   S " + sub, LINFO);
         synchronized (pidLock) {
            while (true) {
               //generate a new GPID; We optimistically insert, assuming
               //this gpid is unique, and catch the SQLException if the
               //gpid uniqueness constraint is violated
               byte gpid_bytes[] = Utils.getRandom(32);
               gpid = Utils.toHexString(gpid_bytes);
               logln(" ... with gpid: " + gpid, LINFO1);
               addProjectQuery.setString(1, hash);
               addProjectQuery.setString(2, gpid);
               addProjectQuery.setString(3, desc);
               addProjectQuery.setInt(4, uid);
               addProjectQuery.setLong(5, pub);
               addProjectQuery.setLong(6, sub);
               addProjectQuery.setInt(7, PROTOCOL_VERSION);
               try {
                  ResultSet rs = addProjectQuery.executeQuery();
                  if (rs.next()) {
                     lpid = rs.getInt(1);
                     c.setPid(lpid);
                     c.setGpid(gpid);
                     //this is a newly created project, user of c must be the owner
                     c.setPub(FULL_PERMISSIONS);
                     c.setSub(FULL_PERMISSIONS);
                     break;
                  }
                  rs.close();
               } catch (SQLException ex) {
                  //if addProjectQuery fails uniqueness constraint we end up here
                  logln("add project failed: " + ex.getMessage(), LERROR);
                  logex(ex);
               }
            }
         }
      } catch (Exception e) {
         //logex(e);
         logln("project insert failed: " + e.getMessage(), LERROR);
      }
      if (lpid != -1) {
         Vector<Client> vc = projects.get(lpid);
         if (vc == null) {  //not currently reflecting
            logln("JOIN: adding " + lpid + " to reflector table (addproj)", LINFO);
            vc = new Vector<Client>();
            projects.put(lpid, vc);
         }
         synchronized (vc) {
            vc.add(c);
         }
      }
      return lpid;
   }


   /**
    * updateProjectPerms updates the publish and subscribe values in the database, it also iterates
    * across all clients connected the project and updates the effective permissions accordingly
    * @param pub the publish permissions to set
    * @param sub the subscribe permissions to set
    */
   protected void updateProjectPerms(Client c, long pub, long sub) {
      try {
         logln("Setting project " + c.getPid() + " permissions to p " + pub + " s " + sub, LINFO2);
         projectPermsUpdateQuery.setLong(1, pub);
         projectPermsUpdateQuery.setLong(2, sub);
         projectPermsUpdateQuery.setInt(3, c.getPid());
         projectPermsUpdateQuery.executeUpdate();
         
         logln("recalculating effective permissions for connected clients", LINFO3);
         Vector<Client> vc = projects.get(new Integer(c.getPid()));
         if (vc != null) {
            synchronized (vc) {
               for (Client cl : vc) {
                  if (c != cl ) {
                     long oldpperm = cl.getPub(); 
                     long newpperm = (cl.getUserPub() & cl.getReqPub() & pub);
                     long oldsperm = cl.getSub(); 
                     long newsperm = (cl.getUserSub() & cl.getReqSub() & sub);
                     if (oldpperm != newpperm) {
                        logln("updating " + cl.getUser() + 
                              " from p " + newpperm + "(was: " + oldpperm + ")" +
                              " to s "   + newsperm + "(was: " + oldsperm + ")",LINFO3);
                        cl.setPub(newpperm);
                        cl.setSub(newsperm);
                        cl.send_error("You permissions have changed as a result of the project owner changing project permissions");
                     } 
                  } 
                  else { 
                     logln("skipping owner",LINFO3);
                  }
               }
            }
         }
      } catch (Exception e) {
         logex(e);
      }
   }

   /**
    * closeDB closes all the database queries and the database connection 
    */
   private void closeDB() {
      logln("Closing database connection", LINFO);
      try {
         if (con != null) {
            postUpdateQuery.close();
            addProjectQuery.close();
            addProjectSnapQuery.close();
            findProjectsByHashQuery.close();
            findProjectByGpidQuery.close();
            findProjectByPidQuery.close();
            projectPermsUpdateQuery.close();
            con.close();
            con = null;
         }
      } catch (Exception e) {
      }
   }

   /**
    * gpid2lpid converts a gpid (which is unique across all projects on all servers)
    * to an lpid (pid local to a particular server instance) 
    * @param gpid global pid 
    * @return the local pid
    */
   protected int gpid2lpid(String gpid) {
      int rval = -1;
      try {
         logln("lookup up: " + gpid, LINFO3);
         findProjectByGpidQuery.setString(1, gpid);
         ResultSet rs = findProjectByGpidQuery.executeQuery();
         if (rs.next()) {
            rval = rs.getInt(1);
            logln("found: " + rval, LINFO3);
         }
         rs.close();
      } catch (Exception e) {
         logln("gpid2lpid failed: " + e.getMessage(), LERROR);
      }

      return rval;
   }

   /**
    * lpid2gpid converts an lpid (pid local to a particular server instance) 
    * to a gpid (which is unique across all projects on all servers)
    * @param lpid the local pid for this particular server 
    * @return the glocabl pid
    */
   protected String lpid2gpid(int lpid) {
      String rval = null;
      try {
         findProjectByPidQuery.setInt(1, lpid);
         ResultSet rs = findProjectByPidQuery.executeQuery();
         if (rs.next()) {
            rval = rs.getString(3);
         }
         rs.close();
      } catch (Exception e) {
         logln("lpid2gpid failed: " + e.getMessage(), LERROR);
      }

      return rval;
   }

}

