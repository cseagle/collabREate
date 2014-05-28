/*
    collabREate CollabreateConstants
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

/**
 * CollabreateConstants
 * This interface defines various constants used throughout
 * the collabreate server
 * @author Tim Vidas
 * @author Chris Eagle
 * @version 0.1.0, August 2008
 */

public interface CollabreateConstants {

   public static final long default_pub = 0x3fff;
   public static final long default_sub = 0x3fff;

   public static final long FULL_PERMISSIONS            = 0x7fffffff;

   public static final int PROTOCOL_VERSION             = 2;

   public static final int COMMAND_BYTE_PATCHED         = 1;
   public static final int COMMAND_CMT_CHANGED          = 2;
   public static final int COMMAND_TI_CHANGED           = 3;
   public static final int COMMAND_OP_TI_CHANGED        = 4;
   public static final int COMMAND_OP_TYPE_CHANGED      = 5;
   public static final int COMMAND_ENUM_CREATED         = 6;
   public static final int COMMAND_ENUM_DELETED         = 7;
   public static final int COMMAND_ENUM_BF_CHANGED      = 8;
   public static final int COMMAND_ENUM_RENAMED         = 9;
   public static final int COMMAND_ENUM_CMT_CHANGED     = 10;
   public static final int COMMAND_ENUM_CONST_CREATED   = 11;
   public static final int COMMAND_ENUM_CONST_DELETED   = 12;
   public static final int COMMAND_STRUC_CREATED        = 13;
   public static final int COMMAND_STRUC_DELETED        = 14;
   public static final int COMMAND_STRUC_RENAMED        = 15;
   public static final int COMMAND_STRUC_EXPANDED       = 16;
   public static final int COMMAND_STRUC_CMT_CHANGED    = 17;
   
   public static final int COMMAND_CREATE_STRUC_MEMBER_DATA = 18;
   public static final int COMMAND_CREATE_STRUC_MEMBER_STRUCT = 19;
   public static final int COMMAND_CREATE_STRUC_MEMBER_REF = 20;
   public static final int COMMAND_CREATE_STRUC_MEMBER_STROFF = 21;
   public static final int COMMAND_CREATE_STRUC_MEMBER_STR = 22;
   public static final int COMMAND_CREATE_STRUC_MEMBER_ENUM = 23;
   
   public static final int COMMAND_STRUC_MEMBER_DELETED = 24;
   
   //public static final int COMMAND_STRUC_MEMBER_RENAMED
   public static final int COMMAND_SET_STACK_VAR_NAME     = 25;
   public static final int COMMAND_SET_STRUCT_MEMBER_NAME = 26;
   
   //public static final int COMMAND_STRUC_MEMBER_CHANGED
   public static final int COMMAND_STRUC_MEMBER_CHANGED_DATA = 27;
   public static final int COMMAND_STRUC_MEMBER_CHANGED_STRUCT = 28;
   public static final int COMMAND_STRUC_MEMBER_CHANGED_STR = 29;
   
   public static final int COMMAND_THUNK_CREATED        = 30;
   public static final int COMMAND_FUNC_TAIL_APPENDED   = 31;
   public static final int COMMAND_FUNC_TAIL_REMOVED    = 32;
   public static final int COMMAND_TAIL_OWNER_CHANGED   = 33;
   public static final int COMMAND_FUNC_NORET_CHANGED   = 34;
   public static final int COMMAND_SEGM_ADDED           = 35;
   public static final int COMMAND_SEGM_DELETED         = 36;
   public static final int COMMAND_SEGM_START_CHANGED   = 37;
   public static final int COMMAND_SEGM_END_CHANGED     = 38;
   public static final int COMMAND_SEGM_MOVED           = 39;
   public static final int COMMAND_AREA_CMT_CHANGED     = 40;
   public static final int COMMAND_STRUC_MEMBER_CHANGED_OFFSET = 41;
   public static final int COMMAND_STRUC_MEMBER_CHANGED_ENUM = 42;
   public static final int COMMAND_CREATE_STRUC_MEMBER_OFFSET = 43;   
   
   public static final int COMMAND_IDP                 = 128;   //This is not a command
   public static final int COMMAND_UNDEFINE            = 129;
   public static final int COMMAND_MAKE_CODE           = 130;
   public static final int COMMAND_MAKE_DATA           = 131;
   public static final int COMMAND_MOVE_SEGM           = 132;
   public static final int COMMAND_RENAMED             = 133;
   public static final int COMMAND_ADD_FUNC            = 134;
   public static final int COMMAND_DEL_FUNC            = 135;
   public static final int COMMAND_SET_FUNC_START      = 137;
   public static final int COMMAND_SET_FUNC_END        = 138;
   public static final int COMMAND_VALIDATE_FLIRT_FUNC = 139;

   public static final int COMMAND_ADD_CREF            = 140;
   public static final int COMMAND_ADD_DREF            = 141;
   public static final int COMMAND_DEL_CREF            = 142;
   public static final int COMMAND_DEL_DREF            = 143;

   //the above commands are grouped in order to provide
   //permissions based on these masks

   public static final long  MASK_UNDEFINE               = 0x00000001;
   public static final long  MASK_MAKE_CODE              = 0x00000002;
   public static final long  MASK_MAKE_DATA              = 0x00000004;
   public static final long  MASK_SEGMENTS               = 0x00000008;
   public static final long  MASK_RENAME                 = 0x00000010;
   public static final long  MASK_FUNCTIONS              = 0x00000020;
   public static final long  MASK_BYTE_PATCH             = 0x00000040;
   public static final long  MASK_COMMENTS               = 0x00000080;
   public static final long  MASK_OPTYPES                = 0x00000100;
   public static final long  MASK_ENUMS                  = 0x00000200;
   public static final long  MASK_STRUCTS                = 0x00000400;
   public static final long  MASK_FLIRT                  = 0x00000800;
   public static final long  MASK_THUNK                  = 0x00001000;
   public static final long  MASK_XREF                   = 0x00002000;

   public static final String[] permStrings = {
                              "Undefine",
                              "Make Code",
                              "Make Data",
                              "Segments",
                              "Renames",
                              "Functions",
                              "Byte Patch",
                              "Comments",
                              "Optypes",
                              "Enums",
                              "Structs",
                              "Flirt",
                              "Thunk",
                              "Xrefs"
                       };   
   
   public static final int SERVER_THRESHOLD            = 200;
   public static final int SERVER_MAP_TID              = 200;
   public static final int SERVER_RENAME_STRUCT        = 201;
   public static final int COMMAND_USER_MESSAGE        = 202;
   
   
   public static final int MSG_CONTROL_FIRST           = 1000;
   public static final int MSG_INITIAL_CHALLENGE       = 1000;
   public static final int MSG_AUTH_REQUEST            = 1001;
   public static final int MSG_AUTH_REPLY              = 1002;
   public static final int AUTH_REPLY_SUCCESS          = 0;
   public static final int AUTH_REPLY_FAIL             = 1;
   public static final int MSG_PROJECT_LIST            = 1003;
   public static final int MSG_PROJECT_JOIN_REQUEST    = 1004;
   public static final int MSG_PROJECT_JOIN_REPLY      = 1005;
   public static final int JOIN_REPLY_SUCCESS          = 0;
   public static final int JOIN_REPLY_FAIL             = 1;
   public static final int MSG_PROJECT_NEW_REQUEST     = 1006;
   public static final int MSG_SEND_UPDATES            = 1007;
   public static final int MSG_PROJECT_REJOIN_REQUEST  = 1008;
   public static final int MSG_ACK_UPDATEID            = 1009;
   public static final int MSG_PROJECT_SNAPSHOT_REQUEST = 1010;
   public static final int MSG_PROJECT_SNAPSHOT_REPLY  = 1011;
   public static final int PROJECT_SNAPSHOT_SUCCESS    = 0;
   public static final int PROJECT_SNAPSHOT_FAIL       = 1;
   public static final int MSG_PROJECT_FORK_REQUEST    = 1012;
   public static final int MSG_PROJECT_SNAPFORK_REQUEST = 1013;
   public static final int MSG_PROJECT_FORK_FOLLOW     = 1014;
   public static final int MSG_PROJECT_LEAVE           = 1015;
   public static final int MSG_GET_REQ_PERMS           = 1016;
   public static final int MSG_GET_REQ_PERMS_REPLY     = 1017;
   public static final int MSG_SET_REQ_PERMS           = 1018;
   public static final int MSG_SET_REQ_PERMS_REPLY     = 1019;
   public static final int MSG_GET_PROJ_PERMS          = 1020;
   public static final int MSG_GET_PROJ_PERMS_REPLY    = 1021;
   public static final int MSG_SET_PROJ_PERMS          = 1022;
   public static final int MSG_SET_PROJ_PERMS_REPLY    = 1023;

   
   public static final int MSG_ERROR                    = 1100;
   public static final int MSG_FATAL                    = 1101;

   public static final int MNG_CONTROL_FIRST            = 2000;
   public static final int MNG_GET_CONNECTIONS          = 2000;
   public static final int MNG_CONNECTIONS              = 2001;
   public static final int MNG_GET_STATS                = 2002;
   public static final int MNG_STATS                    = 2003;
   public static final int MNG_SHUTDOWN                 = 2004;
   public static final int MNG_PROJECT_MIGRATE          = 2005;
   public static final int MNG_PROJECT_MIGRATE_REPLY    = 2006;
   public static final int MNG_MIGRATE_REPLY_SUCCESS    = 0;
   public static final int MNG_MIGRATE_REPLY_FAIL       = 1;
   public static final int MNG_MIGRATE_UPDATE           = 2007;

   public static final int MAX_COMMAND = 2048;

   public static final int MD5_SIZE         = 16;
   public static final int GPID_SIZE        = 32;
   public static final int CHALLENGE_SIZE   = 32;

   public static final int DEFAULT_VERBOSITY = 5;

   public static final int LERROR   = 0;
   public static final int LINFO    = 3;
   public static final int LINFO1   = 4;
   public static final int LINFO2   = 5;
   public static final int LINFO3   = 6;
   public static final int LINFO4   = 7;
   public static final int LSQL     = 10;
   public static final int LDEBUG   = 15;
 

   public static final String FILE_SIG = "collabRE";
   public static final int FILE_VER = 1;
   public static final int TAG = 0xC077ABE8;
   public static final int ENDTAG = 0xDEADBEEF;

   //could extend to CollabreateManagerInterface i guess
   public static final int MODE_DB = 1;
   public static final int MODE_BASIC = 2;

}
