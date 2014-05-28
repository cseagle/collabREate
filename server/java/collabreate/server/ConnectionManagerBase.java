/*
   collabREate ConnectionManagerBase
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
 * ConnectionManagerBase
 * This class is responsible for routing incoming packets to all
 * interested clients
 * @author Tim Vidas
 * @author Chris Eagle
 * @version 0.1.0, August 2008
 */


public abstract class ConnectionManagerBase extends Thread implements CollabreateConstants {
   /**
    * For use in Basic mode when a Global project ID is not needed
    */
   public static final String EMPTY_GPID = "0000000000000000000000000000000000000000000000000000000000000000";

   protected Hashtable<Integer, Vector<Client>> projects = new Hashtable<Integer, Vector<Client>>();
   //projects is <lpid, ClientVector>

   protected Vector<Packet> queue = new Vector<Packet>();

   private boolean done = false;

   private Properties props;

   protected static Object pidLock = new Object();

   private CollabreateServer cs;
   
   private boolean basicMode = true;

   public ConnectionManagerBase(CollabreateServer mcs, Properties p, boolean mode) {
      cs = mcs;
      props = p;
      basicMode = mode;
   }

   /**
    * logs a message to the configured log file (server.conf)
    * @param msg the string to log
    */
   protected void log(String msg) {
      cs.log(msg, 0);
   }

   /**
    * logs a message to the configured log file (server.conf)
    * @param msg the string to log
    * @param verbosity apply a verbosity level to the msg
    */
   protected void log(String msg, int verbosity) {
      cs.log(msg, verbosity);
   }

   /**
    * logs a message to the configured log file (server.conf) (with newline)
    * @param msg the string to log
    */
   protected void logln(String msg) {
      cs.logln(msg, 0);
   }

   /**
    * logs a message to the configured log file (server.conf) (with newline)
    * @param msg the string to log
    * @param verbosity apply a verbosity level to the msg
    */
   protected void logln(String msg, int verbosity) {
      cs.logln(msg, verbosity);
   }

   /**
    * logs an exception to the configured log file (server.conf) (with newline)
    * @param ex the exception to log
    */
   protected void logex(Exception ex) {
      cs.logex(ex, 0);
   }

   /**
    * logs an exception to the configured log file (server.conf) (with newline)
    * @param ex the exception to log
    * @param verbosity apply a verbosity level to the exception 
    */
   protected void logex(Exception ex, int verbosity) {
      cs.logex(ex, verbosity);
   }

   /**
    * insertUpdateid is basically htonll and strategically places the result into the
    * datastream eventually to be sent out on the wire, this is done prior to sending because the 
    * lastupdateid is not known prior to the insert, but is known prior to resending to other clients
    * @param data a bytearray of the update data 
    * @param offset an offset into the data bytearray of where the empty 'placeholder' slot is for the updateid
    * @param updateid the update to byteswap and insert
    */
   protected static void insertUpdateid(byte[] data, int offset, long updateid) {
      data[offset++] = (byte)(updateid >> 56);
      data[offset++] = (byte)(updateid >> 48);
      data[offset++] = (byte)(updateid >> 40);
      data[offset++] = (byte)(updateid >> 32);
      data[offset++] = (byte)(updateid >> 24);
      data[offset++] = (byte)(updateid >> 16);
      data[offset++] = (byte)(updateid >> 8);
      data[offset] = (byte)(updateid);
   }

   /**
    * terminate terminates the connection manager
    * it terminates all clients connected to all projects 
    */
   protected void terminate() {
      logln("ConnectionManager terminating", LINFO);
      done = true;
      interrupt();
      for (Vector<Client> v : projects.values()) {
         Vector<Client> v2 = new Vector<Client>();
         v2.addAll(v);
         for (Client c : v2) {
            c.terminate();
         }
      }
   }

   /**
    * calls the terminate function of the associated CollabreateServer
    */
   protected synchronized void Shutdown() {
      cs.terminate();
   }

   /**
    * authenticate authenticates a user (for use in database mode)
    * bacially this is standard CHAP with HMAC (md5)
    * @param user the user to authenticate
    * @param challenge the randomly generated challenge send to the plugin
    * @param response the calculated response from the plugin to check 
    * @return the user id of an authenticated user, or INVALID_USER
    */
   protected abstract int authenticate(Client c, String user, byte[] challenge, byte[] response);

   /**
    * Add a new connection
    * @param s the socket to create new client for
    */
   protected void add(Socket s) {
      try {
         Client c = new Client(this, s, basicMode);
         c.start();  //this kicks off "run" in a thread
      } catch (Exception ex) {
         logln("Failed to add new client: " + ex.getMessage(), LERROR);
         try {
            s.close();
         } catch (Exception ex2) {
         }
      }
   }

   /**
    * migrateUpdate is very similar to 'post', migrateUpdate only 
    * archives the udpate in the database so that future clients can receive it 
    * @param newowner the new uid to attribute the update to
    * @param pid the local project id for the migrated project
    * @param cmd the 'command' that was performed (comment, rename, etc)
    * @param data the 'data' portion of the command (the comment text, etc)
    */
   protected abstract void migrateUpdate(int newowner, int pid, int cmd, byte[] data);

   /**
    * post both queues a newly received update to be sent to other clients and (if in DB mode)
    * archives the udpate in the database so that future clients can receive it 
    * @param src the client that made the update
    * @param cmd the 'command' that was performed (comment, rename, etc)
    * @param data the 'data' portion of the command (the comment text, etc)
    */
   protected abstract void post(Client src, int cmd, byte[] data);

   /**
    * remove removes a client from a currently reflecting project 
    * @param c the client to remove (from whatever project it is already connected to)
    */
   protected void remove(Client c) {
      Vector<Client> vc = projects.get(new Integer(c.getPid()));
      if (vc != null) {
         logln("Removing client from " + c.getGpid() + " chain", LINFO1);
         synchronized (vc) {
            vc.remove(c);
         }
      }
   }

   /**
    * dumpStats dumps send / receive stats for each connected client 
    */
   protected String dumpStats() {
      StringBuffer sb = new StringBuffer();
      int cnt = 0;
      sb.append("Stats:\n");
      for (Vector<Client> v : projects.values()) {
         synchronized (v) {
            for (Client c : v) {
               sb.append(c.dumpStats());
            }
         }
         cnt++;
      }
      if ( cnt == 0 ) {
         sb.append(" - none - \n");
      }
      return sb.toString();
   }
   /**
    * run perpetually waits to be notified that a new packet has been queued, then
    * sends this packet to other clients according to permissions and project subscription
    * this also sends the server created unique updateID back to the originator of the packet
    */ 
   public void run() {
      try {
         while (!done) {
            Packet p;
            synchronized (queue) {   //sync = mutex
               // java doesn't allow a data structure to be modified will you are iterating across it
               while (queue.size() == 0) {
                  queue.wait();   //wait for notify signal
               }
               p = queue.remove(0);
            }
            Vector<Client> vc = projects.get(new Integer(p.c.getPid()));  //what about two projects with same hash?
            if (vc != null) {
               Vector<Client> bad = new Vector<Client>();
               synchronized (vc) {
                  for (Client c : vc) {     //foreach Client c
                     if (c != p.c) {  //only send to other than originator
                        try {
                           c.post(p.d);
                        } catch (Exception ex) {
                           logex(ex);
                           bad.add(c);
                        }
                     }
                     else {
                        //send updateid back to the originator
                        CollabreateOutputStream os = new CollabreateOutputStream();
                        os.writeLong(p.uid);
                        c.send_data(MSG_ACK_UPDATEID, os.toByteArray());
                     }
                  }
               }
               for (Client c : bad) {
                  c.terminate();
               }
            }
         }
      } catch (InterruptedException iex) {
      } catch (Exception ex) {
         logex(ex);
      }
   }

   /**
    * sendLatestUpdates sends updates from LastUpdate to current 
    * it is expected that the client has already joined a project before calling this function
    * it is expected that the client has already received updates from 0 - lastUpdate 
    * this function is typically called when a user is re-joining a project that they had previously worked on
    * @param c the client requesting updates 
    * @param lastUpdate the last update the client received 
    */
   protected abstract void sendLatestUpdates(Client c, long lastUpdate);

   /**
    * getProjectInfo gets informatio related to a local project
    * @param pid the local pid of a project to get info on
    * @return a  project info object for the provided pid
    */
   protected abstract ProjectInfo getProjectInfo(int pid);

   /**
    * getProjectList generates a list of projects on this server, each list (vector) item is 
    * actually a pinfo (project info) object, the list does NOT contain all projects, but
    * only contains projects relevant to the binary that is currently loaded in IDA
    * @param phash the IDA generated hash that is unique among the analysis files
    * @return a vector of project info objects for the provided phash
    */
   protected abstract Vector<ProjectInfo> getProjectList(String phash);

   /**
    * listConnection displays the current connections to the collabREate connection manager 
    */
   protected String listConnections() {
      StringBuffer sb = new StringBuffer();
      int cnt = 0;
      try {
         sb.append("Client   Address:Port          Pub(Effective) Sub(Effective) PID     User\n");
         for (Vector<Client> v : projects.values()) {
            synchronized (v) {
               for (Client c : v) {
                  //logln(cnt + c.getAddr() + ":" + c.getPort() + "  (?|" + c.getPub() + ")    (?|" + c.getSub() + ")  ????");
                  sb.append(String.format("%6d ", ++cnt));
                  sb.append(String.format("%15s:", c.getAddr()));
                  sb.append(String.format("%5d   ", c.getPort()));
                  sb.append(String.format("0x%08x     ", c.getPub()));
                  sb.append(String.format("0x%08x     ", c.getSub()));
                  sb.append(String.format("%-5d ", c.getPid()));
                  sb.append(String.format("%3d: %s \n", c.getUid(), c.getUser()));
               }
            }
         }
         if ( cnt == 0 ) { 
            sb.append(" - none - \n");
         }
      } catch (Exception ex) {
         logln("Error Listing connections" + ex.getMessage(), LERROR);
      }
      return sb.toString();
   }

   /**
    * joinProject joings a particular client to a project so that it can participate in collabREation 
    * @param c the client attempting to join 
    * @param lpid the local project id of the project on this server 
    * @return 0 on success, negative value on failure
    */
   protected abstract int joinProject(Client c, int lpid);
 
   /**
    * snapProject adds a snapshop for a project, this does not change the client's 
    * current project, nor copy any updates, it simply marks a point-in-time (updateid wise)
    * this point-in-time can later be used as a project fork point if desired 
    * @param c the client invoking the snapshot
    * @param lastupdateid the point-in-time the client wishes to save in the snapshot
    * @param desc a user provided description of the snapshot
    * @return the snapshotid on success, -1 on failure
    */
   protected abstract int snapProject(Client c, long lastupdateid, String desc);

   /**
    * forkProject  forks a project - creats new project and copies all updates to point to the new project,
    * publish and subscribe values are inherited
    * @param c client object invoking the fork
    * @param lastupdateid the updateid value the fork is to occur at
    * @param desc user provided description of the fork
    * @return the new projectid on success, -1 on failure
    */

   protected abstract int forkProject(Client c, long lastupdateid, String desc);


   /**
    * forkProject  forks a project - creats new project and copies all updates to point to the new project
    * @param c client object invoking the fork
    * @param lastupdateid the updateid value the fork is to occur at
    * @param desc user provided description of the fork
    * @param pub specified publish permissions
    * @param sub specified subscribe permissions
    * @return the new projectid on success, -1 on failure
    */
   protected abstract int forkProject(Client c, long lastupdateid, String desc, long pub, long sub);

   /**
    * sendForkFollows sends a special "follow fork" message to all clients working on
    * a project that has been forked, this allows the user to decide if they would like
    * to continue to work on the existing project, or change to the newly created project
    * @param originator the client that instigated the fork
    * @param oldlpid the local pid of the original project
    * @param lastupdateid the last update processed prior to fork (if your database is different you can't change to the new project)
    * @param desc the description of the new project, so the user can make a more educated descision
    */
   protected abstract void sendForkFollows(Client originator, int oldlpid, long lastupdateid, String desc);

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

   protected abstract int snapforkProject(Client c, int spid, String desc, long pub, long sub);

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

   protected abstract int migrateProject(int owner, String gpid, String hash, String desc, long pub, long sub);

   /**
    * addProject adds a project to the database and reflector (or merely a reflector in non-DB mode) 
    * @param c cliend invoking the addProject
    * @param hash unique hash for the binary file originally generated by IDA
    * @param desc user provided description of the project 
    * @param pub the publish permissions for the project
    * @param sub the subscribe permissions for the project
    * @return the new project id on success, -1 on failure
    */

   protected abstract int addProject(Client c, String hash, String desc, long pub, long sub);

   /**
    * updateProjectPerms updates the publish and subscribe values in the database, it also iterates
    * across all clients connected the project and updates the effective permissions accordingly
    * @param pub the publish permissions to set
    * @param sub the subscribe permissions to set
    */
   protected abstract void updateProjectPerms(Client c, long pub, long sub);

   /**
    * gpid2lpid converts a gpid (which is unique across all projects on all servers)
    * to an lpid (pid local to a particular server instance) 
    * @param gpid global pid 
    * @return the local pid
    */
   protected abstract int gpid2lpid(String gpid);

   /**
    * lpid2gpid converts an lpid (pid local to a particular server instance) 
    * to a gpid (which is unique across all projects on all servers)
    * @param lpid the local pid for this particular server 
    * @return the glocabl pid
    */
   protected abstract String lpid2gpid(int lpid);

   /**
    * Packet is a helper class to represent a tuple pairing a client
    * with a command posted by that client
    */
   public class Packet {
      protected Client c;
      protected byte[] d;
      protected long uid;

      public Packet(Client src, byte[] data, long updateid) {
         c = src;
         d = data;
         uid = updateid;
         insertUpdateid(data, 8, uid);
      }
   }

}

