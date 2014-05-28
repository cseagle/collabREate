/*
   collabREate utils.h
   Copyright (C) 2012 Chris Eagle <cseagle at gmail d0t com>
   Copyright (C) 2012 Tim Vidas <tvidas at gmail d0t com>

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
#include "buffer.h"

using namespace std;

#define default_pub 0x3fff
#define default_sub 0x3fff

#define FULL_PERMISSIONS            0x7fffffff

#define PROTOCOL_VERSION             2

#define COMMAND_BYTE_PATCHED         1
#define COMMAND_CMT_CHANGED          2
#define COMMAND_TI_CHANGED           3
#define COMMAND_OP_TI_CHANGED        4
#define COMMAND_OP_TYPE_CHANGED      5
#define COMMAND_ENUM_CREATED         6
#define COMMAND_ENUM_DELETED         7
#define COMMAND_ENUM_BF_CHANGED      8
#define COMMAND_ENUM_RENAMED         9
#define COMMAND_ENUM_CMT_CHANGED     10
#define COMMAND_ENUM_CONST_CREATED   11
#define COMMAND_ENUM_CONST_DELETED   12
#define COMMAND_STRUC_CREATED        13
#define COMMAND_STRUC_DELETED        14
#define COMMAND_STRUC_RENAMED        15
#define COMMAND_STRUC_EXPANDED       16
#define COMMAND_STRUC_CMT_CHANGED    17
   
#define COMMAND_CREATE_STRUC_MEMBER_DATA 18
#define COMMAND_CREATE_STRUC_MEMBER_STRUCT 19
#define COMMAND_CREATE_STRUC_MEMBER_REF 20
#define COMMAND_CREATE_STRUC_MEMBER_STROFF 21
#define COMMAND_CREATE_STRUC_MEMBER_STR 22
#define COMMAND_CREATE_STRUC_MEMBER_ENUM 23
   
#define COMMAND_STRUC_MEMBER_DELETED 24
   
   //public static final int COMMAND_STRUC_MEMBER_RENAMED
#define COMMAND_SET_STACK_VAR_NAME     25
#define COMMAND_SET_STRUCT_MEMBER_NAME 26
   
   //public static final int COMMAND_STRUC_MEMBER_CHANGED
#define COMMAND_STRUC_MEMBER_CHANGED_DATA 27
#define COMMAND_STRUC_MEMBER_CHANGED_STRUCT 28
#define COMMAND_STRUC_MEMBER_CHANGED_STR 29
   
#define COMMAND_THUNK_CREATED        30
#define COMMAND_FUNC_TAIL_APPENDED   31
#define COMMAND_FUNC_TAIL_REMOVED    32
#define COMMAND_TAIL_OWNER_CHANGED   33
#define COMMAND_FUNC_NORET_CHANGED   34
#define COMMAND_SEGM_ADDED           35
#define COMMAND_SEGM_DELETED         36
#define COMMAND_SEGM_START_CHANGED   37
#define COMMAND_SEGM_END_CHANGED     38
#define COMMAND_SEGM_MOVED           39
#define COMMAND_AREA_CMT_CHANGED     40
#define COMMAND_STRUC_MEMBER_CHANGED_OFFSET 41
#define COMMAND_STRUC_MEMBER_CHANGED_ENUM   42
#define COMMAND_CREATE_STRUC_MEMBER_OFFSET  43   
   
#define COMMAND_IDP                 128   //This is not a command
#define COMMAND_UNDEFINE            129
#define COMMAND_MAKE_CODE           130
#define COMMAND_MAKE_DATA           131
#define COMMAND_MOVE_SEGM           132
#define COMMAND_RENAMED             133
#define COMMAND_ADD_FUNC            134
#define COMMAND_DEL_FUNC            135
#define COMMAND_SET_FUNC_START      137
#define COMMAND_SET_FUNC_END        138
#define COMMAND_VALIDATE_FLIRT_FUNC 139

#define COMMAND_ADD_CREF            140
#define COMMAND_ADD_DREF            141
#define COMMAND_DEL_CREF            142
#define COMMAND_DEL_DREF            143

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
   
   
#define MSG_CONTROL_FIRST           1000
#define MSG_INITIAL_CHALLENGE       1000
#define MSG_AUTH_REQUEST            1001
#define MSG_AUTH_REPLY              1002
#define AUTH_REPLY_SUCCESS          0
#define AUTH_REPLY_FAIL             1
#define MSG_PROJECT_LIST            1003
#define MSG_PROJECT_JOIN_REQUEST    1004
#define MSG_PROJECT_JOIN_REPLY      1005
#define JOIN_REPLY_SUCCESS          0
#define JOIN_REPLY_FAIL             1
#define MSG_PROJECT_NEW_REQUEST     1006
#define MSG_SEND_UPDATES            1007
#define MSG_PROJECT_REJOIN_REQUEST  1008
#define MSG_ACK_UPDATEID            1009
#define MSG_PROJECT_SNAPSHOT_REQUEST 1010
#define MSG_PROJECT_SNAPSHOT_REPLY  1011
#define PROJECT_SNAPSHOT_SUCCESS    0
#define PROJECT_SNAPSHOT_FAIL       1
#define MSG_PROJECT_FORK_REQUEST    1012
#define MSG_PROJECT_SNAPFORK_REQUEST 1013
#define MSG_PROJECT_FORK_FOLLOW     1014
#define MSG_PROJECT_LEAVE           1015
#define MSG_GET_REQ_PERMS           1016
#define MSG_GET_REQ_PERMS_REPLY     1017
#define MSG_SET_REQ_PERMS           1018
#define MSG_SET_REQ_PERMS_REPLY     1019
#define MSG_GET_PROJ_PERMS          1020
#define MSG_GET_PROJ_PERMS_REPLY    1021
#define MSG_SET_PROJ_PERMS          1022
#define MSG_SET_PROJ_PERMS_REPLY    1023

#define MSG_ERROR                    1100
#define MSG_FATAL                    1101

#define MNG_CONTROL_FIRST            2000
#define MNG_GET_CONNECTIONS          2000
#define MNG_CONNECTIONS              2001
#define MNG_GET_STATS                2002
#define MNG_STATS                    2003
#define MNG_SHUTDOWN                 2004
#define MNG_PROJECT_MIGRATE          2005
#define MNG_PROJECT_MIGRATE_REPLY    2006
#define MNG_MIGRATE_REPLY_SUCCESS    0
#define MNG_MIGRATE_REPLY_FAIL       1
#define MNG_MIGRATE_UPDATE           2007

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
#define FILE_VER 1
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
   virtual int readAll(void *buf, uint32_t size) = 0;
   virtual bool readLine(Buffer &b) = 0;
   virtual string readLine() = 0;
   virtual int read_until_delim(char *buf, uint32_t size, char endchar) = 0;
   virtual int sendMsg(const char *buf, bool nullflag = 0) = 0;
   virtual int sendAll(const void *buf, uint32_t len) = 0;
   virtual int sendFormat(const char *format, ...) = 0;
   virtual bool close() = 0;

   //output the string with no null terminator
   virtual IOBase &operator<<(const string &s) = 0;
   //output b.size() bytes
   virtual IOBase &operator<<(const Buffer &b) = 0;
   //read at most b.sz (capacity) into b
   virtual IOBase &operator>>(Buffer &b) = 0;
   
};

class FileIO : public IOBase {
public:
   virtual ~FileIO();
   void setFileDescriptor(int fd);
   int readAll(void *buf, uint32_t size);
   int read_until_delim(char *buf, uint32_t size, char endchar);
   bool readLine(Buffer &b);
   string readLine();
   int sendMsg(const char *buf, bool nullflag = 0);
   int sendAll(const void *buf, uint32_t len);
   int sendFormat(const char *format, ...);
   int getFileDescriptor() {return fd;};
   bool close();

   uint16_t readShort();
   uint32_t readInt();
   uint64_t readLong();
   int readFully(uint8_t *buf, uint32_t len);
   string readUTF();

   bool writeShort(uint16_t s);
   bool writeInt(uint32_t i);
   bool writeLong(uint64_t l);
   bool write(const void *buf, uint32_t len);
   bool writeUTF(const string &s);

   //output the string with no null terminator
   IOBase &operator<<(const string &s);
   //output b.size() bytes
   IOBase &operator<<(const Buffer &b);
   //read at most b.sz (capacity) into b
   IOBase &operator>>(Buffer &b);

protected:
   int fd;
};

class NetworkIO : public FileIO {
public:
   NetworkIO() {};
   NetworkIO(const char *host, int port);
   virtual ~NetworkIO() {};
   int readAll(void *buf, uint32_t size);
   int read_until_delim(char *buf, uint32_t size, char endchar);
   bool readLine(Buffer &b);
   string readLine();
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

map<string,string> *parseConf(const char *conf);
short getShortOption(map<string,string> *conf, const string &opt, short defaultValue);
int getIntOption(map<string,string> *conf, const string &opt, int defaultValue);
string getStringOption(map<string,string> *conf, const string &opt, const char *defaultValue);
const char *getCharOption(map<string,string> *conf, const string &opt, const char *defaultValue);

#endif

