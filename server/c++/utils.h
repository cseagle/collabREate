/*
   collabREate utils.h
   Copyright (C) 2018 Chris Eagle <cseagle at gmail d0t com>
   Copyright (C) 2018 Tim Vidas <tvidas at gmail d0t com>

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

#ifndef __COLLAB_UTILS_H
#define __COLLAB_UTILS_H

#include <stdint.h>
#include <sys/select.h>
#include <string>
#include <vector>
#include <map>
#include <json-c/json.h>

using namespace std;

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
#define COMMAND_AREA_CMT_CHANGED     "area_cmt_chg"
#define COMMAND_STRUC_MEMBER_CHANGED_OFFSET "struc_mbr_chg_offset"
#define COMMAND_STRUC_MEMBER_CHANGED_ENUM   "struc_mbr_chg_enum"
#define COMMAND_CREATE_STRUC_MEMBER_OFFSET  "create_struc_mbr_offset"

#define AREACB_FUNCS                  "funcs"
#define AREACB_SEGS                   "segs"

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


#define default_pub 0x3fff
#define default_sub 0x3fff

#define FULL_PERMISSIONS            0x7fffffff

#define PROTOCOL_VERSION             4

   //the above commands are grouped in order to provide
   //permissions based on these masks

#define MASK_UNDEFINE               0x00000001
#define MASK_MAKE_CODE              0x00000002
#define MASK_MAKE_DATA              0x00000004
#define MASK_SEGMENTS               0x00000008
#define MASK_RENAME                 0x00000010
#define MASK_FUNCTIONS              0x00000020
#define MASK_BYTE_PATCH             0x00000040
#define MASK_COMMENTS               0x00000080
#define MASK_OPTYPES                0x00000100
#define MASK_ENUMS                  0x00000200
#define MASK_STRUCTS                0x00000400
#define MASK_FLIRT                  0x00000800
#define MASK_THUNK                  0x00001000
#define MASK_XREF                   0x00002000

#define SERVER_THRESHOLD            200
#define SERVER_MAP_TID              200
#define SERVER_RENAME_STRUCT        201

#define MNG_CONTROL_FIRST            2000
#define MNG_GET_CONNECTIONS          "mng_get_connections"
#define MNG_CONNECTIONS              "mng_connections"
#define MNG_GET_STATS                "mng_get_stats"
#define MNG_STATS                    "mng_stats"
#define MNG_SHUTDOWN                 "mng_shutdown"
#define MNG_PROJECT_MIGRATE          "mng_project_migrate"
#define MNG_PROJECT_MIGRATE_REPLY    "mng_project_migrate_reply"
#define MNG_MIGRATE_REPLY_SUCCESS    1
#define MNG_MIGRATE_REPLY_FAIL       0
#define MNG_MIGRATE_UPDATE           "mng_migrate_update"

#define MAX_COMMAND 2048

#define MD5_SIZE         16
#define GPID_SIZE        32
#define CHALLENGE_SIZE   32

#define DEFAULT_VERBOSITY 5

#define LERROR   0
#define LINFO    3
#define LINFO1   4
#define LINFO2   5
#define LINFO3   6
#define LINFO4   7
#define LSQL     10
#define LDEBUG   15
 
const char * const FILE_SIG = "collabRE";
#define FILE_VER 2
#define TAG      0xC077ABE8
#define ENDTAG   0xDEADBEEF

//could extend to CollabreateManagerInterface i guess
#define MODE_DB 1
#define MODE_BASIC 2

/**
 * Constant to check for an invalid uid
 */
#define INVALID_USER -1
/**
 * Constant to use for uid when in BASIC_MODE 
 */
#define BASIC_USER 0

struct sockaddr_in6;
struct sockaddr_in;
class NetworkIO;

uint64_t htonll(uint64_t val);
#define ntohll(x) htonll(x)

uint8_t *toByteArray(string hexString);
bool isNumeric(string s);
bool isHex(string s);
bool isAlphaNumeric(string s);
string toHexString(const uint8_t *buf, int len);
string getMD5(const void *tohash, int len);
string getMD5(const string &s);

void log(const string &msg, int verbosity = 0);
void logln(const string &msg, int verbosity = 0);

extern const char *permStrings[];
extern int permStringsLength;

class IOException {
public:
   IOException(const string &msg = "");
   const string &getMessage();
private:
   string msg;
};

class IOBase {
public:
   virtual ~IOBase() {};
   virtual int read() = 0;
   virtual int read(void *buf, uint32_t size) = 0;
   virtual int readAll(void *buf, uint32_t size) = 0;
   virtual bool readLine(string &s) = 0;
   virtual string readLine() = 0;
   virtual json_object *readJson();
   virtual bool writeJson(json_object *obj);
   virtual int read_until_delim(char *buf, uint32_t size, char endchar) = 0;
   virtual int sendMsg(const char *buf, bool nullflag = 0) = 0;
   virtual int sendAll(const void *buf, uint32_t len) = 0;
   virtual int sendFormat(const char *format, ...) = 0;
   virtual bool close() = 0;

   //output the string with no null terminator
   virtual IOBase &operator<<(const string &s) = 0;
   
};

class FileIO : public IOBase {
public:
   FileIO();
   virtual ~FileIO();
   int read();
   int read(void *buf, uint32_t size);
   void setFileDescriptor(int fd);
   int readAll(void *buf, uint32_t size);
   int read_until_delim(char *buf, uint32_t size, char endchar);
   bool readLine(string &s);
   string readLine();
   int sendMsg(const char *buf, bool nullflag = 0);
   int sendAll(const void *buf, uint32_t len);
   int sendFormat(const char *format, ...);
   int getFileDescriptor() {return fd;};
   bool close();

   bool write(const void *buf, uint32_t len);

   //output the string with no null terminator
   IOBase &operator<<(const string &s);

private:
   int fillbuf();
   uint32_t get_avail(void *buf, uint32_t size);

protected:
   int fd;
   int state;
   int curr;
   int max;
   unsigned char buf[4096];
};

class NetworkIO : public FileIO {
public:
   NetworkIO() {};
   NetworkIO(const char *host, int port);
   virtual ~NetworkIO() {};
//   int readAll(void *buf, uint32_t size);
//   int read_until_delim(char *buf, uint32_t size, char endchar);
//   bool readLine(string &s);
//   string readLine();
   int sendAll(const void *buf, uint32_t len);
   int getPeerPort();
   string getPeerAddr();   
};

class NetworkService {
public:
   virtual ~NetworkService();
   virtual NetworkIO *accept() = 0;
   virtual bool close();
protected:
   vector<int> fds;
   fd_set aset;
   int nfds;
};

class Tcp6Service : public NetworkService {
public:
   Tcp6Service(int port);
   Tcp6Service(const char *host, int port);
   virtual ~Tcp6Service();
    NetworkIO *accept();
private:
   sockaddr_in6 *self;
};

class Tcp6IO : public NetworkIO {
public:
   Tcp6IO(int fd, sockaddr_in6 &peer);
   virtual ~Tcp6IO();
   
private:
   sockaddr_in6 *peer;
};

class RC4 {
   unsigned char S[256];
   unsigned char i;
   unsigned char j;
public:
   RC4(unsigned char *key, uint32_t keylen);
   unsigned char generate();
   void crypt(unsigned char *blob, int len);
};

int fill_random(unsigned char *buf, uint32_t size);

json_object *parseConf(const char *conf);
short getShortOption(json_object *conf, const string &opt, short defaultValue);
int getIntOption(json_object *conf, const string &opt, int defaultValue);
string getStringOption(json_object *conf, const string &opt, const char *defaultValue);
const char *getCstringOption(json_object *conf, const string &opt, const char *defaultValue);

const char *hex_encode(const void *bin, uint32_t len);
uint8_t *hex_decode(const char *hex, uint32_t *len);

void append_json_hex_val(json_object *obj, const char *key, const uint8_t *value, uint32_t len = 0);
void append_json_string_val(json_object *obj, const char *key, const char *value);
void append_json_string_val(json_object *obj, const char *key, const string &value);
void append_json_bool_val(json_object *obj, const char *key, bool value);
void append_json_uint64_val(json_object *obj, const char *key, uint64_t value);
void append_json_uint32_val(json_object *obj, const char *key, uint32_t value);
void append_json_int32_val(json_object *obj, const char *key, int32_t value);

uint8_t *hex_from_json(json_object *json, const char *key, uint32_t *len); //qfree this result
const char *string_from_json(json_object *json, const char *key);
bool bool_from_json(json_object *json, const char *key, bool *val);
bool uint64_from_json(json_object *json, const char *key, uint64_t *val);
bool uint32_from_json(json_object *json, const char *key, uint32_t *val);
bool int32_from_json(json_object *json, const char *key, int32_t *val);

#endif

