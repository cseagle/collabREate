/*
    collabREate CollabreateOutputStream
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

/**
 * CollabreateOutputStream
 * This class wraps a DataOutputStream around a ByteArrayOutputStream for 
 * convenience in building data packets.
 * @author Tim Vidas
 * @author Chris Eagle
 * @version 0.1.0, August 2008
 */

public class CollabreateOutputStream implements DataOutput {

   private ByteArrayOutputStream baos;
   private DataOutputStream dos;

   /**
    * CollabreateOutputStream
    * This class wraps a DataOutputStream around a ByteArrayOutputStream for 
    * convenience in building data packets, for those familiar with these classes
    * the methods should be self explanitory.
    */
   public CollabreateOutputStream() {
      baos = new ByteArrayOutputStream();
      dos = new DataOutputStream(baos);
   }
   
   public void write(byte[] b) throws IOException {
      dos.write(b);
   }
   
   public void write(byte[] b, int off, int len) throws IOException {
      dos.write(b, off, len);
   }
   
   public void write(int b) throws IOException {
      dos.write(b);
   }
   
   public void writeBoolean(boolean v) throws IOException {
      dos.writeBoolean(v);
   }
   
   public void writeByte(int v) throws IOException {
      dos.writeByte(v);
   }
   
   public void writeBytes(String s) throws IOException {
      dos.writeBytes(s);
   }
   
   public void writeChar(int v) throws IOException {
      dos.writeChar(v);
   }
   
   public void writeChars(String s) throws IOException {
      dos.writeChars(s);
   }
   
   public void writeDouble(double v) throws IOException {
      dos.writeDouble(v);
   }
   
   public void writeFloat(float v) throws IOException {
      dos.writeFloat(v);
   }
   
   public void writeInt(int v) throws IOException {
      dos.writeInt(v);
   }
   
   public void writeLong(long v) throws IOException {
      dos.writeLong(v);
   }
   
   public void writeShort(int v) throws IOException {
      dos.writeShort(v);
   }
   
   public void writeTo(OutputStream out) throws IOException {
      dos.flush();
      baos.writeTo(out);
   }
   
   public void writeUTF(String s) throws IOException {
      dos.writeUTF(s);
   }
   
   public byte[] toByteArray() {
      try {
         dos.flush();
      } catch (Exception ex) {
      }
      return baos.toByteArray();
   }
   
   public int size() {
      try {
         dos.flush();
      } catch (Exception ex) {
      }
      return baos.size();
   }      
}
