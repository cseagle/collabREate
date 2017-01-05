/*
    collabREate ProjectInfo
    Copyright (C) 2008 Tim Vidas <tvidas at gmail d0t com>
    Copyright (C) 2008 Chris Eagle <cseagle at gmail d0t com>

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

/**
 * ProjectInfo is a helper classe to represent information pertitent
 * to a single project
 * @author Tim Vidas
 * @author Chris Eagle
 * @version 0.2.0, January 2017
 */
public class ProjectInfo {
   public int lpid;
   public String desc;
   public int connected;
   public int parent;
   public String pdesc;
   public long snapupdateid;
   public long pub;
   public long sub;
   public String owner;
   public String hash;
   public String gpid;
   public int proto;

   public ProjectInfo(int localpid, String description, int currentlyconnected) {
      lpid = localpid;
      desc = description;
      connected = currentlyconnected;
   }

   public ProjectInfo(int localpid, String description) {
      this(localpid, description, 0);
   }
}
