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
 * @version 0.2.0, January 2017
 */

public interface CollabreateConstants {

   public static final long default_pub = 0x3fff;
   public static final long default_sub = 0x3fff;

   public static final long FULL_PERMISSIONS            = 0x7fffffff;

   public static final int PROTOCOL_VERSION             = 4;

   public static final String COMMAND_BYTE_PATCHED         = "byte_patched";
   public static final String COMMAND_CMT_CHANGED          = "cmt_changed";
   public static final String COMMAND_TI_CHANGED           = "ti_changed";
   public static final String COMMAND_OP_TI_CHANGED        = "op_ti_changed";
   public static final String COMMAND_OP_TYPE_CHANGED      = "op_type_changed";
   public static final String COMMAND_ENUM_CREATED         = "enum_created";
   public static final String COMMAND_ENUM_DELETED         = "enum_deleted";
   public static final String COMMAND_ENUM_BF_CHANGED      = "enum_bf_changed";
   public static final String COMMAND_ENUM_RENAMED         = "enum_renamed";
   public static final String COMMAND_ENUM_CMT_CHANGED     = "enum_cmt_changed";
   public static final String COMMAND_ENUM_CONST_CREATED   = "enum_const_created";
   public static final String COMMAND_ENUM_CONST_DELETED   = "enum_const_deleted";
   public static final String COMMAND_STRUC_CREATED        = "struc_created";
   public static final String COMMAND_STRUC_DELETED        = "struc_deleted";
   public static final String COMMAND_STRUC_RENAMED        = "struc_renamed";
   public static final String COMMAND_STRUC_EXPANDED       = "struc_expanded";
   public static final String COMMAND_STRUC_CMT_CHANGED    = "struc_cmt_changed";

   public static final String COMMAND_CREATE_STRUC_MEMBER_DATA   = "create_struc_mbr_data";
   public static final String COMMAND_CREATE_STRUC_MEMBER_STRUCT = "create_struc_mbr_struc";
   public static final String COMMAND_CREATE_STRUC_MEMBER_REF    = "create_struc_mbr_ref";
   public static final String COMMAND_CREATE_STRUC_MEMBER_STROFF = "create_struc_mbr_stroff";
   public static final String COMMAND_CREATE_STRUC_MEMBER_STR    = "create_struc_mbr_str";
   public static final String COMMAND_CREATE_STRUC_MEMBER_ENUM   = "create_struc_mbr_enum";

   public static final String COMMAND_STRUC_MEMBER_DELETED      = "struc_mbr_deleted";

   //public static final String COMMAND_STRUC_MEMBER_RENAMED
   public static final String COMMAND_SET_STACK_VAR_NAME        = "set_stack_var_name";
   public static final String COMMAND_SET_STRUCT_MEMBER_NAME    = "set_struc_mbr_name";

   //public static final String COMMAND_STRUC_MEMBER_CHANGED
   public static final String COMMAND_STRUC_MEMBER_CHANGED_DATA   = "struc_mbr_chg_data";
   public static final String COMMAND_STRUC_MEMBER_CHANGED_STRUCT = "struc_mbr_chg_struc";
   public static final String COMMAND_STRUC_MEMBER_CHANGED_STR    = "struc_mbr_chg_str";

   public static final String COMMAND_THUNK_CREATED        = "thunk_created";
   public static final String COMMAND_FUNC_TAIL_APPENDED   = "func_tail_appended";
   public static final String COMMAND_FUNC_TAIL_REMOVED    = "func_tail_removed";
   public static final String COMMAND_TAIL_OWNER_CHANGED   = "tail_owner_chg";
   public static final String COMMAND_FUNC_NORET_CHANGED   = "func_noret_chg";
   public static final String COMMAND_SEGM_ADDED           = "segm_added";
   public static final String COMMAND_SEGM_DELETED         = "segm_deleted";
   public static final String COMMAND_SEGM_START_CHANGED   = "segm_start_chg";
   public static final String COMMAND_SEGM_END_CHANGED     = "segm_end_chg";
   public static final String COMMAND_SEGM_MOVED           = "segm_moved";
   public static final String COMMAND_AREA_CMT_CHANGED     = "area_cmt_chg";
   public static final String COMMAND_STRUC_MEMBER_CHANGED_OFFSET = "struc_mbr_chg_offset";
   public static final String COMMAND_STRUC_MEMBER_CHANGED_ENUM   = "struc_mbr_chg_enum";
   public static final String COMMAND_CREATE_STRUC_MEMBER_OFFSET  = "create_struc_mbr_offset";

   public static final String AREACB_FUNCS                  = "funcs";
   public static final String AREACB_SEGS                   = "segs";

   public static final String COMMAND_UNDEFINE            = "undefine";
   public static final String COMMAND_MAKE_CODE           = "make_code";
   public static final String COMMAND_MAKE_DATA           = "make_data";
   public static final String COMMAND_MOVE_SEGM           = "move_segm";
   public static final String COMMAND_RENAMED             = "renamed";
   public static final String COMMAND_ADD_FUNC            = "add_func";
   public static final String COMMAND_DEL_FUNC            = "del_func";
   public static final String COMMAND_SET_FUNC_START      = "set_func_start";
   public static final String COMMAND_SET_FUNC_END        = "set_func_end";
   public static final String COMMAND_VALIDATE_FLIRT_FUNC = "validate_flirt_func";
   public static final String COMMAND_ADD_CREF            = "add_cref";
   public static final String COMMAND_ADD_DREF            = "add_dref";
   public static final String COMMAND_DEL_CREF            = "del_cref";
   public static final String COMMAND_DEL_DREF            = "del_dref";

   public static final String COMMAND_USER_MESSAGE        = "user_message";

   public static final String MSG_CONTROL_FIRST            = "control_first";
   public static final String MSG_INITIAL_CHALLENGE        = "initial_challenge";
   public static final String MSG_AUTH_REQUEST             = "auth_request";
   public static final String MSG_AUTH_REPLY               = "auth_reply";
   public static final int AUTH_REPLY_SUCCESS           = 1;
   public static final int AUTH_REPLY_FAIL              = 0;
   public static final String MSG_PROJECT_LIST             = "project_list";
   public static final String MSG_PROJECT_JOIN_REQUEST     = "project_join_request";
   public static final String MSG_PROJECT_JOIN_REPLY       = "project_join_reply";
   public static final int JOIN_REPLY_SUCCESS           = 1;
   public static final int JOIN_REPLY_FAIL              = 0;
   public static final String MSG_PROJECT_NEW_REQUEST      = "project_new_request";
   public static final String MSG_SEND_UPDATES             = "send_updates";
   public static final String MSG_PROJECT_REJOIN_REQUEST   = "project_rejoin_request";
   public static final String MSG_ACK_UPDATEID             = "ack_updateid";
   public static final String MSG_PROJECT_SNAPSHOT_REQUEST = "project_snapshot_request";
   public static final String MSG_PROJECT_SNAPSHOT_REPLY   = "project_snapshot_reply";
   public static final int PROJECT_SNAPSHOT_SUCCESS     = 1;
   public static final int PROJECT_SNAPSHOT_FAIL        = 0;
   public static final String MSG_PROJECT_FORK_REQUEST     = "project_fork_request";
   public static final String MSG_PROJECT_SNAPFORK_REQUEST = "project_snapfork_request";
   public static final String MSG_PROJECT_FORK_FOLLOW      = "project_fork_follow";
   public static final String MSG_PROJECT_LEAVE            = "project_leave";
   public static final String MSG_GET_REQ_PERMS            = "get_req_perms";
   public static final String MSG_GET_REQ_PERMS_REPLY      = "get_req_perms_reply";
   public static final String MSG_SET_REQ_PERMS            = "set_req_perms";
   public static final String MSG_SET_REQ_PERMS_REPLY      = "set_req_perms_reply";
   public static final String MSG_GET_PROJ_PERMS           = "get_proj_perms";
   public static final String MSG_GET_PROJ_PERMS_REPLY     = "get_proj_perms_reply";
   public static final String MSG_SET_PROJ_PERMS           = "set_proj_perms";
   public static final String MSG_SET_PROJ_PERMS_REPLY     = "set_proj_perms_reply";

   public static final String MSG_ERROR                    = "collab_error";
   public static final String MSG_FATAL                    = "collab_fatal";

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

   public static final int MNG_CONTROL_FIRST            = 2000;
   public static final String MNG_GET_CONNECTIONS        =  "mng_get_connections";
   public static final String MNG_CONNECTIONS            =  "mng_connections";
   public static final String MNG_GET_STATS              =  "mng_get_stats";
   public static final String MNG_STATS                  =  "mng_stats";
   public static final String MNG_SHUTDOWN               =  "mng_shutdown";
   public static final String MNG_PROJECT_MIGRATE        =  "mng_project_migrate";
   public static final String MNG_PROJECT_MIGRATE_REPLY  =  "mng_project_migrate_reply";
   public static final int MNG_MIGRATE_REPLY_SUCCESS    = 1;
   public static final int MNG_MIGRATE_REPLY_FAIL       = 0;
   public static final String MNG_MIGRATE_UPDATE         =  "mng_migrate_update";

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
