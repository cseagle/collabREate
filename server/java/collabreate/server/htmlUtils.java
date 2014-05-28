/*
    collabREate Utils
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
 * htmlUtils
 * This class offers various utility functions used by the servlet
 * @author Tim Vidas
 * @author Chris Eagle
 * @version 0.1.0, August 2008
 */

public class htmlUtils {


   /**
    * makeLink creates a formated HTML link
    * @param url the URL (with params if needed)
    * @param text the text displayed to the user
    * @return a wrapped string
    */
   protected static String makeLink(String url, String text) {
      return String.format("<a href=\"%s\">%s</a>",url,text);
   }

   /**
    * makeTableData simply wraps a string with td tags
    * @param s the string to wrap
    * @param a alignment (optional: left, center, right. default: left)
    * @return a wrapped string
    */
   protected static String makeTableData(String s, String a) {
      return String.format("<td align='%s'>%s</td>",a,s);
   }
   protected static String makeTableData(String s) {
      return makeTableData(s,"left");
   }

   /**
    * makeTableRow simply wraps a string with tr tags
    * @param s the string to wrap
    * @return a wrapped string
    */
   protected static String makeTableRow(String s) {
      return String.format("\n<tr>%s</tr>",s);
   }


   /**
    * makeFormItem makes a http form item
    * @param name the name of the form item
    * @param type the type of the form item (text, button, radio, checkbox, password)
    * @param size the size to display (only on text/pass)
    * @param maxl the maxlen (only on text/pass)
    * @param value the value for the item
    * @param check non-zero if checked (only on checkbox / radio)
    * @param reado non-zero if the item is readonly
    * @return a string with the formatted form item
    */
   protected static String makeFormItem(String name, String type, int size, int maxl, String value, int check, int reado) {
      String rval = "";
      int canBchecked = 0;
      int canBreadonly = 0;
      if(type.equalsIgnoreCase("text")){
         rval = String.format("<input name=\"%s\" type=\"%s\" size=\"%s\" maxlength=\"%s\" value=\"%s\"",name,type,size,maxl,value);
         canBreadonly = 1;
      }
      else if(type.equalsIgnoreCase("password")){
         rval = String.format("<input name=\"%s\" type=\"%s\" size=\"%s\" maxlength=\"%s\" value=\"%s\"",name,type,size,maxl,value);
         canBreadonly = 1;
      }
      else if(type.equalsIgnoreCase("button")){
         rval = String.format("<input name=\"%s\" type=\"%s\" value=\"%s\"",name,type,value);
      }
      else if(type.equalsIgnoreCase("radio")){
         rval = String.format("<input name=\"%s\" type=\"%s\" value=\"%s\"",name,type,value);
         canBchecked = 1;
      }
      else if(type.equalsIgnoreCase("checkbox")){
         rval = String.format("<input name=\"%s\" type=\"%s\" value=\"%s\"",name,type,value);
         canBreadonly = 1;
         canBchecked = 1;
      }
      else if(type.equalsIgnoreCase("submit")){
         rval = String.format("<input name=\"%s\" type=\"%s\" value=\"%s\"",name,type,value);
      }
      else if(type.equalsIgnoreCase("hidden")){
         rval = String.format("<input name=\"%s\" type=\"%s\" value=\"%s\"",name,type,value);
      }
      if(check != 0 && canBchecked != 0) {
         rval = rval + " checked";
      }
      if(reado != 0 && canBreadonly != 0) {
         rval = rval + " readonly";
      }
      rval = rval + ">";
      return rval;
   }



}

