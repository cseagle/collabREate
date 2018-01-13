/*
    collabREate HmacMD5
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

import java.security.*;

/**
 * HmacMD5
 * This class is responsible for computing an HmacMD5 value
 * for use in the challenge and response authentication portion
 * of a collabreate server connection, see RFC 2104
 * @author Tim Vidas
 * @author Chris Eagle
 * @version 0.1.0, August 2008
 */

public class HmacMD5 {
   /**
    * hmac calculates an HmacMD5 value
    * @param msg a byte array to hash
    * @param key a byte array to use as the hmac key
    * @return the hmacMD5
    */
   protected static byte[] hmac(byte[] msg, byte[] key) {
      MessageDigest md5 = null;
      try {
         md5 = MessageDigest.getInstance("MD5");
      } catch (Exception ex) {
      }
      if (key.length > 64) {
         md5.reset();
         key = md5.digest(key);
      }
      byte ipad[] = new byte[64];
      System.arraycopy(key, 0, ipad, 0, key.length);      
      byte opad[] = ipad.clone();
      
      /* XOR key with ipad and opad values */
      for (int i = 0; i < ipad.length; i++) {
         ipad[i] ^= (byte)0x36;
         opad[i] ^= (byte)0x5c;
      }
      
      // perform inner MD5
      md5.reset();
      md5.update(ipad);
      byte digest[] = md5.digest(msg);
      
      // perform outer MD5
      md5.reset();
      md5.update(opad);
      return md5.digest(digest);
   }
   
}
