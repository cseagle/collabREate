/*
    IDA Pro Collabreation/Synchronization Plugin
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
#ifndef __COLLABREATE_H__
#define __COLLABREATE_H__

#ifdef _MSC_VER
#if _MSC_VER >= 1600
#include <stdint.h>
#else
#include "ms_stdint.h"
#endif
#else
#include <stdint.h>
#endif

#include <stdarg.h>
#include <time.h>
#include <json.h>

#define NO_OBSOLETE_FUNCS
#define USE_DANGEROUS_FUNCTIONS

#include <pro.h>

#define PLUGIN_NAME "collabREate"

#define PROTOCOL_VERSION             4

#define JSON_NEW_CONST_KEY (JSON_C_OBJECT_ADD_KEY_IS_NEW | JSON_C_OBJECT_KEY_IS_CONSTANT)

#define COMMAND_BYTE_PATCHED         "byte_patched"
#define COMMAND_CMT_CHANGED          "cmt_changed"
#define COMMAND_TI_CHANGED           "ti_changed"
#define COMMAND_OP_TI_CHANGED        "op_ti_changed"
#define COMMAND_OP_TYPE_CHANGED      "op_type_changed"
#define COMMAND_ENUM_CREATED         "enum_created"
#define COMMAND_ENUM_DELETED         "enum_deleted"
#define COMMAND_ENUM_BF_CHANGED      "enum_bf_changed"
#define COMMAND_ENUM_RENAMED         "enum_renamed"
#define COMMAND_ENUM_CMT_CHANGED     "enum_cmt_changed"
#define COMMAND_ENUM_CONST_CREATED   "enum_const_created"
#define COMMAND_ENUM_CONST_DELETED   "enum_const_deleted"
#define COMMAND_STRUC_CREATED        "struc_created"
#define COMMAND_STRUC_DELETED        "struc_deleted"
#define COMMAND_STRUC_RENAMED        "struc_renamed"
#define COMMAND_STRUC_EXPANDED       "struc_expanded"
#define COMMAND_STRUC_CMT_CHANGED    "struc_cmt_changed"

#define COMMAND_CREATE_STRUC_MEMBER_DATA   "create_struc_mbr_data"
#define COMMAND_CREATE_STRUC_MEMBER_STRUCT "create_struc_mbr_struc"
#define COMMAND_CREATE_STRUC_MEMBER_REF    "create_struc_mbr_ref"
#define COMMAND_CREATE_STRUC_MEMBER_STROFF "create_struc_mbr_stroff"
#define COMMAND_CREATE_STRUC_MEMBER_STR    "create_struc_mbr_str"
#define COMMAND_CREATE_STRUC_MEMBER_ENUM   "create_struc_mbr_enum"

#define COMMAND_STRUC_MEMBER_DELETED      "struc_mbr_deleted"

//#define COMMAND_STRUC_MEMBER_RENAMED
#define COMMAND_SET_STACK_VAR_NAME        "set_stack_var_name"
#define COMMAND_SET_STRUCT_MEMBER_NAME    "set_struc_mbr_name"

//#define COMMAND_STRUC_MEMBER_CHANGED
#define COMMAND_STRUC_MEMBER_CHANGED_DATA   "struc_mbr_chg_data"
#define COMMAND_STRUC_MEMBER_CHANGED_STRUCT "struc_mbr_chg_struc"
#define COMMAND_STRUC_MEMBER_CHANGED_STR    "struc_mbr_chg_str"

#define COMMAND_THUNK_CREATED        "thunk_created"
#define COMMAND_FUNC_TAIL_APPENDED   "func_tail_appended"
#define COMMAND_FUNC_TAIL_REMOVED    "func_tail_removed"
#define COMMAND_TAIL_OWNER_CHANGED   "tail_owner_chg"
#define COMMAND_FUNC_NORET_CHANGED   "func_noret_chg"
#define COMMAND_SEGM_ADDED           "segm_added"
#define COMMAND_SEGM_DELETED         "segm_deleted"
#define COMMAND_SEGM_START_CHANGED   "segm_start_chg"
#define COMMAND_SEGM_END_CHANGED     "segm_end_chg"
#define COMMAND_SEGM_MOVED           "segm_moved"
//#define COMMAND_AREA_CMT_CHANGED     "area_cmt_chg"
#define COMMAND_RANGE_CMT_CHANGED     "range_cmt_chg"
#define COMMAND_STRUC_MEMBER_CHANGED_OFFSET "struc_mbr_chg_offset"
#define COMMAND_STRUC_MEMBER_CHANGED_ENUM   "struc_mbr_chg_enum"
#define COMMAND_CREATE_STRUC_MEMBER_OFFSET  "create_struc_mbr_offset"

#define AREACB_FUNCS                  "funcs"
#define AREACB_SEGS                   "segs"
#define RANGE_FUNCS     AREACB_FUNCS
#define RANGE_SEGS      AREACB_SEGS

#define COMMAND_IDP                 128
#define COMMAND_UNDEFINE            "undefine"
#define COMMAND_MAKE_CODE           "make_code"
#define COMMAND_MAKE_DATA           "make_data"
#define COMMAND_MOVE_SEGM           "move_segm"
#define COMMAND_RENAMED             "renamed"
#define COMMAND_ADD_FUNC            "add_func"
#define COMMAND_DEL_FUNC            "del_func"
#define COMMAND_SET_FUNC_START      "set_func_start"
#define COMMAND_SET_FUNC_END        "set_func_end"
#define COMMAND_VALIDATE_FLIRT_FUNC "validate_flirt_func"
#define COMMAND_ADD_CREF            "add_cref"
#define COMMAND_ADD_DREF            "add_dref"
#define COMMAND_DEL_CREF            "del_cref"
#define COMMAND_DEL_DREF            "del_dref"

#define SERVER_MAP_TID              200
#define SERVER_RENAME_STRUCT        201
#define COMMAND_USER_MESSAGE        "user_message"

//all idb manipulation messages must be <= this number
#define MSG_IDA_MAX                 255

#define MSG_CONTROL_FIRST            "control_first"
#define MSG_INITIAL_CHALLENGE        "initial_challenge"
#define MSG_AUTH_REQUEST             "auth_request"
#define MSG_AUTH_REPLY               "auth_reply"
#define AUTH_REPLY_SUCCESS           1
#define AUTH_REPLY_FAIL              0
#define MSG_PROJECT_LIST             "project_list"
#define MSG_PROJECT_JOIN_REQUEST     "project_join_request"
#define MSG_PROJECT_JOIN_REPLY       "project_join_reply"
#define JOIN_REPLY_SUCCESS           1
#define JOIN_REPLY_FAIL              0
#define MSG_PROJECT_NEW_REQUEST      "project_new_request"
#define MSG_SEND_UPDATES             "send_updates"
#define MSG_PROJECT_REJOIN_REQUEST   "project_rejoin_request"
#define MSG_ACK_UPDATEID             "ack_updateid"
#define MSG_PROJECT_SNAPSHOT_REQUEST "project_snapshot_request"
#define MSG_PROJECT_SNAPSHOT_REPLY   "project_snapshot_reply"
#define PROJECT_SNAPSHOT_SUCCESS 1
#define PROJECT_SNAPSHOT_FAIL    0
#define MSG_PROJECT_FORK_REQUEST     "project_fork_request"
#define MSG_PROJECT_SNAPFORK_REQUEST "project_snapfork_request"
#define MSG_PROJECT_FORK_FOLLOW      "project_fork_follow"
#define MSG_PROJECT_LEAVE            "project_leave"
#define MSG_GET_REQ_PERMS            "get_req_perms"
#define MSG_GET_REQ_PERMS_REPLY      "get_req_perms_reply"
#define MSG_SET_REQ_PERMS            "set_req_perms"
#define MSG_SET_REQ_PERMS_REPLY      "set_req_perms_reply"
#define MSG_GET_PROJ_PERMS           "get_proj_perms"
#define MSG_GET_PROJ_PERMS_REPLY     "get_proj_perms_reply"
#define MSG_SET_PROJ_PERMS           "set_proj_perms"
#define MSG_SET_PROJ_PERMS_REPLY     "set_proj_perms_reply"

#define MSG_ERROR                    "collab_error"
#define MSG_FATAL                    "collab_fatal"

class netnode;
extern netnode cnn;
extern qvector<qstring> msgHistory;
extern qstring *changeCache;

#define COLLABREATE_NETNODE "$ COLLABREATE NETNODE"

#define COLLABREATE_ENUMS_TAG 'E'
#define COLLABREATE_STRUCTS_TAG 'T'
#define COLLABREATE_MSGHISTORY_TAG ((char)0x81)
#define COLLABREATE_CACHE_TAG ((char)0x82)

#define GPID_SUPVAL 1
#define LAST_SERVER_SUPVAL 2
#define LAST_USER_SUPVAL 3
#define LASTUPDATE_SUPVAL 4
#define OPTIONS_SUPVAL 5

#define LASTUPDATE_ALTVAL 1
#define LAST_PORT_ALTVAL 2

#define CHALLENGE_SIZE 32
#define GPID_SIZE 32

#define MD5_LEN 16

#define NEW_PROJECT_INDEX 0

//User commands available via plugin activate, once connected to a server
#define USER_FORK       0
#define USER_CHECKPOINT 1
#define USER_PERMS      2
#define PROJECT_PERMS   3
#define USER_DISCONNECT 4
#define SHOW_NETNODE    5
#define CLEAN_NETNODE   6

extern bool publish;
extern bool userPublish;
extern bool subscribe;
extern bool supress;

extern bool authenticated;
extern bool fork_pending;

extern char **optLabels;

extern char username[64];

union OptVal {
   uint64_t ll;
   uint32_t ii[2];
};

struct Options {
   OptVal pub;
   OptVal sub;
};

extern Options userOpts;
extern Options tempOpts;
extern Options *optMasks;

extern uint64_t *snapUpdateIDs;
extern char description[1024];

extern int numProjectsGlobal;
extern int isSnapShotGlobal;
extern int numOptionsGlobal;

extern int *projects;

bool setUserOpts(Options &user);
bool getUserOpts(Options &user);

bool is_connected();
void cleanup(bool warn = false);
int send_all(const qstring &s);
int send_msg(const qstring &s);

bool init_network();
bool term_network();
#define QT_NAMESPACE QT

uint64_t getLastUpdate();
void setLastUpdate(uint64_t uid);
void writeUpdateValue(uint64_t uid);
void hookAll();
void unhookAll();
int numCommands();

void hmac_md5(unsigned char *msg, int msg_len,
              unsigned char *key, int key_len,
              unsigned char *digest);
void saveAuthData(char *user, char *pass);
int chooseProject(int index, char *desc);
bool changeProject(int index);
const char *getRunCommand(int i);
int getGpid(unsigned char *gpid, int sz);
void setGpid(unsigned char *gpid, int sz);
bool getFileMd5(unsigned char *md5, int len);
void do_project_rejoin();
void sendProjectLeave();
void do_project_leave();
void sendProjectChoice(int project);
void sendProjectSnapFork(int project, const char *desc);
void sendProjectGetList();
void sendNewProjectCreate(const char *description);
void sendReqPermsChoice();
void sendProjPermsChoice();
void freeProjectFields();
void selectProject(int index);
void sendAuthData(unsigned char *challenge, int challenge_len);
void do_get_req_perms(json_object *json);
void do_get_proj_perms(json_object *json);

bool do_choose_perms(json_object *json);

void do_send_user_message(const char *msg);

int send_json(json_object *obj);
int send_json(const char *type, json_object *obj);
int send_json(ea_t ea, const char *type, json_object *obj);

const char *hex_encode(const void *bin, uint32_t len);
uint8_t *hex_decode(const char *hex, uint32_t *len);
void format_llx(uint64_t val, qstring &s);

void append_json_hex_val(json_object *obj, const char *key, const uint8_t *value, uint32_t len = 0);
void append_json_string_val(json_object *obj, const char *key, const char *value);
void append_json_string_val(json_object *obj, const char *key, const qstring &value);
void append_json_bool_val(json_object *obj, const char *key, bool value);
void append_json_uint64_val(json_object *obj, const char *key, uint64_t value);
void append_json_uint32_val(json_object *obj, const char *key, uint32_t value);
void append_json_int32_val(json_object *obj, const char *key, int32_t value);
void append_json_ea_val(json_object *obj, const char *key, ea_t value);

uint8_t *hex_from_json(json_object *json, const char *key, uint32_t *len); //qfree this result
const char *string_from_json(json_object *json, const char *key);
bool bool_from_json(json_object *json, const char *key, bool *val);
bool uint64_from_json(json_object *json, const char *key, uint64_t *val);
bool ea_from_json(json_object *json, const char *key, ea_t *val);
bool uint32_from_json(json_object *json, const char *key, uint32_t *val);
bool int32_from_json(json_object *json, const char *key, int32_t *val);

//Ida's msg function doesn't handle the ll modifier
//this one returns pointer to static buffer
char *formatOptVal(OptVal *v);
char *formatLongLong(uint64_t);

//this one formats into buf, which should be at least 17 bytes in size
char *formatOptVal(OptVal *v, char *buf);
char *formatLongLong(uint64_t, char *buf);

void postCollabMessage(const char *msg, time_t t = 0);

//IDA HOOKS
#if IDA_SDK_VERSION >= 510      //HT_IDB introduced in SDK 510
#if IDA_SDK_VERSION < 700
int idaapi idb_hook(void * /*user_data*/, int notification_code, va_list va);
#else
ssize_t idaapi idb_hook(void * /*user_data*/, int notification_code, va_list va);
#endif
#endif
#if IDA_SDK_VERSION < 700
int idaapi idp_hook(void * /*user_data*/, int notification_code, va_list va);
//int idaapi ui_hook(void *user_data, int notification_code, va_list va);
#else
ssize_t idaapi idp_hook(void * /*user_data*/, int notification_code, va_list va);
#endif

//Collabreate messaging
void build_handler_map();
int handle_idp_msg(json_object *json, const char *msg_type);
bool msg_dispatcher(const char *json_in);

//help with the transition to IDA 7.0

#if IDA_SDK_VERSION >= 700
#define get_flags_novalue(ea) get_flags(ea)
#define isEnum0(f) is_enum0(f)
#define isEnum1(f) is_enum1(f)
#define isStroff0(f) is_stroff0(f)
#define isStroff1(f) is_stroff1(f)
#define isOff0(f) is_off0(f)
#define isOff1(f) is_off1(f)
#define isOff(f, n) is_off(f, n)
#define isEnum(f, n) is_enum(f, n)
#define isStroff(f, n) is_stroff(f, n)

#define isStruct(f) is_struct(f)
#define isASCII(f) is_strlit(f)

#define get_member_name2 get_member_name
#else
#define ev_add_cref add_cref
#define ev_add_dref add_dref
#define ev_del_cref del_cref
#define ev_del_dref del_dref
#define ev_auto_queue_empty auto_queue_empty
#define set_func_start func_setstart 
#define set_func_end func_setend
#endif

#endif
