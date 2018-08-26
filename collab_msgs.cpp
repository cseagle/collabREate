/*
    IDA Pro Collabreation/Synchronization Plugin
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
/*
 *  This is the collabREate plugin
 *
 *  It is known to compile with
 *
 *   Microsoft Visual C++
 *   g++/make
 *
 */

#include "collabreate.h"
#include "collabreate_ui.h"

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <netnode.hpp>
#include <typeinf.hpp>
#include <struct.hpp>
#if IDA_SDK_VERSION >= 700
#include <range.hpp>
#else
#include <area.hpp>
#endif
#include <frame.hpp>
#include <segment.hpp>
#include <enum.hpp>
#include <xref.hpp>
#include <nalt.hpp>
#include <offset.hpp>
#include <auto.hpp>
#include <md5.h>

#include <json-c/json.h>

#include <map>
#include <string>
using std::map;
using std::string;

#if IDA_SDK_VERSION < 560
#define opinfo_t typeinfo_t
#endif

//bool supress = false;

typedef int (*CmdHandler)(json_object *cmd);
map<string,CmdHandler> ctrl_handlers;
map<string,CmdHandler> ida_handlers;

char username[64];
static unsigned char pwhash[16];

static qvector<qstring> updates;

#ifndef DEBUG
//#define DEBUG 1
#endif

/************* various requests we send to the server ******************/
void do_project_rejoin() { //(unsigned char * gpid) {
   unsigned char gpid[GPID_SIZE];
   if (getGpid(gpid, sizeof(gpid)) && getUserOpts(userOpts)) {
      json_object *obj = json_object_new_object();
      append_json_hex_val(obj, "gpid", gpid, GPID_SIZE);
      append_json_uint64_val(obj, "pub", userOpts.pub.ll);
      append_json_uint64_val(obj, "sub", userOpts.sub.ll);
      send_json(MSG_PROJECT_REJOIN_REQUEST, obj);
   }
}

void sendProjectLeave() {
   json_object *obj = json_object_new_object();
   send_json(MSG_PROJECT_LEAVE, obj);
}

void do_project_leave() {
   sendProjectLeave();
}

//void do_clean_netnode( void ) {
//}

void sendProjectChoice(int project) {
   json_object *obj = json_object_new_object();
   append_json_int32_val(obj, "project", project);
   append_json_uint64_val(obj, "pub", userOpts.pub.ll);
   append_json_uint64_val(obj, "sub", userOpts.sub.ll);
   send_json(MSG_PROJECT_JOIN_REQUEST, obj);
}

void sendProjectSnapFork(int project, const char *desc) {
   json_object *obj = json_object_new_object();
   append_json_int32_val(obj, "project", project);
   append_json_string_val(obj, "description", desc);
   append_json_uint64_val(obj, "pub", userOpts.pub.ll);
   append_json_uint64_val(obj, "sub", userOpts.sub.ll);
   send_json(MSG_PROJECT_SNAPFORK_REQUEST, obj);
}

void sendProjectGetList() {
   unsigned char md5[MD5_LEN];
   if (getFileMd5(md5, sizeof(md5))) {
      json_object *obj = json_object_new_object();
      append_json_hex_val(obj, "md5", md5, MD5_LEN);
      send_json(MSG_PROJECT_LIST, obj);
   }
}

void sendNewProjectCreate(const char *description) {
   unsigned char md5[MD5_LEN];
   if (getFileMd5(md5, sizeof(md5))) {
      json_object *obj = json_object_new_object();
      append_json_hex_val(obj, "md5", md5, MD5_LEN);
      append_json_string_val(obj, "description", description);
      append_json_uint64_val(obj, "pub", userOpts.pub.ll);
      append_json_uint64_val(obj, "sub", userOpts.sub.ll);
      send_json(MSG_PROJECT_NEW_REQUEST, obj);
   }
}

void sendReqPermsChoice() {
   json_object *obj = json_object_new_object();
   append_json_uint64_val(obj, "pub", tempOpts.pub.ll);
   append_json_uint64_val(obj, "sub", tempOpts.sub.ll);
   send_json(MSG_SET_REQ_PERMS, obj);
}

void sendProjPermsChoice() {
   json_object *obj = json_object_new_object();
   append_json_uint64_val(obj, "pub", tempOpts.pub.ll);
   append_json_uint64_val(obj, "sub", tempOpts.sub.ll);
   send_json(MSG_SET_PROJ_PERMS, obj);
}

void freeProjectFields() {
   qfree(snapUpdateIDs);
   snapUpdateIDs = NULL;
   qfree(projects);
   projects = NULL;
   qfree(optMasks);
   optMasks = NULL;

   for (int i = 0; i < numOptionsGlobal; i++) {
      qfree(optLabels[i]);
   }
   qfree(optLabels);
   optLabels = NULL;
}

void selectProject(int index) {
   if (index == NEW_PROJECT_INDEX) {
#ifdef DEBUG
      msg(PLUGIN_NAME": new project selected: %s\n", description);
#endif
      sendNewProjectCreate(description);
   }
   //else if (snapUpdateIDs[index + 1] != 0) {
   else if (isSnapShotGlobal == 1) {
#ifdef DEBUG
      msg(PLUGIN_NAME": snapshot %d selected\n", index);
#endif
      sendProjectSnapFork(index, description);
   }
   else {
#ifdef DEBUG
      msg(PLUGIN_NAME": project %d selected\n", index);
#endif
      sendProjectChoice(index);
   }
}

void saveAuthData(char *user, char *pass) {
   ::qstrncpy(username, user, sizeof(username));

   cnn.supset(LAST_USER_SUPVAL, user);

   size_t pwlen = strlen(pass);

   MD5Context ctx;
   MD5Init(&ctx);
   MD5Update(&ctx, (unsigned char*)pass, pwlen);
   MD5Final(pwhash, &ctx);
}

//pwhash and username must be set previously
void sendAuthData(unsigned char *challenge, int challenge_len) {
   uchar hmac[16];
#ifdef DEBUG
   msg(PLUGIN_NAME": computing hmac\n");
#endif   
   hmac_md5(challenge, challenge_len, pwhash, sizeof(pwhash), hmac);
   memset(pwhash, 0, sizeof(pwhash));
   
   //connection to server successful.
   json_object *obj = json_object_new_object();
   //send hmac
   append_json_hex_val(obj, "hmac", hmac, sizeof(hmac));
   //send plugin protocol version
   append_json_int32_val(obj, "protocol", PROTOCOL_VERSION);
#ifdef DEBUG
   msg(PLUGIN_NAME": sending auth data\n");
#endif   
   send_json(MSG_AUTH_REQUEST, obj);
}

void do_get_req_perms(json_object *json) {
   //display permission selection UI
   //tempOpts.pub = 0xAAAAAAAA;
   //tempOpts.sub = 0x55555555;
   if (do_choose_perms(json)) {
      sendReqPermsChoice();
   }
}

void do_get_proj_perms(json_object *json) {
   //display permission selection UI
   //tempOpts.pub = 0xAAAAAAAA;
   //tempOpts.sub = 0x55555555;
//   Options oldOpts = tempOpts;
   if (do_choose_perms(json)) {
      //only call this if perms actually changed
      sendProjPermsChoice();
   }
}

void do_send_user_message(const char *msg) {
   uint32_t len = 80 + (uint32_t)strlen(msg);
   char *m = new char[len];
   ::qsnprintf(m, len, "<%s> %s", username, msg);
   char *cr = m + strlen(m) - 1;
   while (*cr == '\n' || *cr == '\r') {
      *cr-- = 0;
   }

   time_t t = time(NULL);    //*** change so that server timestamps messages

   json_object *obj = json_object_new_object();
   append_json_string_val(obj, "message", m);
   append_json_uint64_val(obj, "time", (uint64_t)t);
   send_json(COMMAND_USER_MESSAGE, obj);

   delete [] m;
}

/************* handlers for update messages we receive from the server **********/

int cmd_undefine(json_object *json) {
   ea_t ea;
   ea_from_json(json, "addr", &ea);
#if 0
   do_unknown(ea, DOUNK_SIMPLE);
#else
   qstring a1;
   format_llx(ea, a1);
   const char *user = string_from_json(json, "user");
   char tmsg[128];
   ::qsnprintf(tmsg, sizeof(tmsg), "<%s> UNDEFINED at 0x%s", user, a1.c_str());
   postCollabMessage(tmsg);
#endif
   return 0;
}

int cmd_make_code(json_object *json) {
   ea_t ea;
   uint64_t tmp;
   ea_from_json(json, "addr", &ea);
   uint64_from_json(json, "length", &tmp);
   asize_t sz = (asize_t)tmp;
#if 0
   create_insn(ea);
#else
   qstring a1;
   format_llx(ea, a1);
   const char *user = string_from_json(json, "user");
   char tmsg[128];
   ::qsnprintf(tmsg, sizeof(tmsg), "<%s> MAKE CODE at 0x%s", user, a1.c_str());
   postCollabMessage(tmsg);
#endif
   return 0;
}

int cmd_make_data(json_object *json) {
   ea_t ea;
   uint64_t tmp;
   ea_from_json(json, "addr", &ea);
   uint64_from_json(json, "flags", &tmp);
   flags_t f = (flags_t)tmp;
   uint64_from_json(json, "length", &tmp);
   asize_t a = (asize_t)tmp;
   const char *name = string_from_json(json, "struc");  //name only exists if we are creating a struct
   tid_t t = (name && *name) ? get_struc_id(name) : BADNODE;
#if 0
   do_data_ex(ea, f, a, t);
#else
   qstring a1;
   format_llx(ea, a1);
   const char *user = string_from_json(json, "user");
   char tmsg[128];
   ::qsnprintf(tmsg, sizeof(tmsg), "<%s> MAKE DATA at 0x%s, length: %d%s%s", user, a1.c_str(), (uint32_t)a,
               t == BADNODE ? "" : ", struct type: ", t == BADNODE ? "" : name);
   postCollabMessage(tmsg);
#endif
   return 0;
}

int cmd_move_segm(json_object *json) {
   ea_t ea, to;
   ea_from_json(json, "from", &ea);
   segment_t *s = getseg(ea);
   ea_from_json(json, "to", &to);
   move_segm(s, to);
   return 0;
}

int cmd_renamed(json_object *json) {
   bool local;
   ea_t ea;
   ea_from_json(json, "addr", &ea);
   bool_from_json(json, "local", &local);
   int flag = local ? SN_LOCAL : 0;
   const char *name = string_from_json(json, "name");
#ifdef DEBUG
   msg(PLUGIN_NAME": renamed 0x%08x - %s\n", ea, name);
#endif
   if (name) {
      set_name(ea, name, flag | SN_NOWARN);
   }
   return 0;
}

int cmd_add_func(json_object *json) {
   ea_t endea, ea;
   ea_from_json(json, "startea", &ea);
   ea_from_json(json, "endea", &endea);
   add_func(ea, endea);
   return 0;
}

int cmd_del_func(json_object *json) {
   ea_t ea;
   ea_from_json(json, "addr", &ea);
   del_func(ea);
   return 0;
}

int cmd_set_func_start(json_object *json) {
   ea_t newstart, ea;
   ea_from_json(json, "old_start", &ea);
   ea_from_json(json, "new_start", &newstart);
   set_func_start(ea, newstart);
   return 0;
}

int cmd_set_func_end(json_object *json) {
   ea_t endea, ea;
   ea_from_json(json, "startea", &ea);
   ea_from_json(json, "endea", &endea);
   set_func_end(ea, endea);
   return 0;
}

/*
 * This function recurses through all calls made by a known library function
 * and flags them as library functions as well under the premise that library
 * functions only call other library functions.
 */
static void recursive_update(func_t *f) {
   if (f == NULL || f->flags & FUNC_LIB) return;
   f->flags |= FUNC_LIB;
   update_func(f);
   func_item_iterator_t fi(f);
   do {
      ea_t ea = fi.current();

      xrefblk_t xb;
      for (bool ok = xb.first_from(ea, XREF_FAR); ok && xb.iscode; ok = xb.next_from()) {
         if (xb.type != fl_CN && xb.type != fl_CF) continue;
         func_t *pfn = get_func(xb.to);
         recursive_update(pfn);
      }
   } while (fi.next_code());
}

int cmd_validate_flirt_func(json_object *json) {
   ea_t endea, ea;
   ea_from_json(json, "startea", &ea);
   bool has_end = ea_from_json(json, "endea", &endea);
   const char *name = string_from_json(json, "name");
   if (name) {
      set_name(ea, name, SN_NOWARN);
   }
   add_func(ea, has_end ? endea : BADADDR);
   func_t *f = get_func(ea);
   if (f) {
      //any function this calls is also a library (support) function
      recursive_update(f);
   }
   return 0;
}

int cmd_add_cref(json_object *json) {
   // args: ea_t from, ea_t to, cref_t type
   ea_t from, to;
   uint32_t reftype;
   ea_from_json(json, "from", &from);
   ea_from_json(json, "to", &to);
   uint32_from_json(json, "reftype", &reftype);
   cref_t type = (cref_t)reftype;
#if 0
   add_cref(from, to, type);
#else
   qstring a1, a2;
   format_llx(from, a1);
   format_llx(to, a2);
   const char *user = string_from_json(json, "user");
   char tmsg[128];
   ::qsnprintf(tmsg, sizeof(tmsg), "<%s> add_cref from 0x%s to 0x%s, type %d", user, a1.c_str(), a2.c_str(), (int32_t)type);
   postCollabMessage(tmsg);
#endif
   return 0;
}

int cmd_add_dref(json_object *json) {
   // args: ea_t from, ea_t to, dref_t type
   ea_t from, to;
   uint32_t reftype;
   ea_from_json(json, "from", &from);
   ea_from_json(json, "to", &to);
   uint32_from_json(json, "reftype", &reftype);
   dref_t type = (dref_t)reftype;
   add_dref(from, to, type);
   return 0;
}

int cmd_del_cref(json_object *json) {
   // args: ea_t from, ea_t to, bool expand
   ea_t from, to;
   bool expand;
   ea_from_json(json, "from", &from);
   ea_from_json(json, "to", &to);
   bool_from_json(json, "expand", &expand);
#if 0
   del_cref(from, to, expand);
#else
   qstring a1, a2;
   format_llx(from, a1);
   format_llx(to, a2);
   const char *user = string_from_json(json, "user");
   char tmsg[128];
   ::qsnprintf(tmsg, sizeof(tmsg), "<%s> del_cref from 0x%s to 0x%s", user, a1.c_str(), a2.c_str());
   postCollabMessage(tmsg);
#endif
   return 0;
}

int cmd_del_dref(json_object *json) {
   // args: ea_t from, ea_t to
   ea_t from, to;
   ea_from_json(json, "from", &from);
   ea_from_json(json, "to", &to);
   del_dref(from, to);
   return 0;
}

/*
 * Handle idb notifications received remotely
 */
int cmd_patch_byte(json_object *json) {
   ea_t ea;
   int val;
   if (ea_from_json(json, "addr", &ea) && int32_from_json(json, "value", (int32_t*)&val)) {
      patch_byte(ea, val);
   }
   return 0;
}

int cmd_cmt_changed(json_object *json) {
   ea_t ea;
   bool rep;
   if (ea_from_json(json, "addr", &ea) && bool_from_json(json, "rep", &rep)) {
      const char *cmt = string_from_json(json, "text");
      if (cmt) {
#ifdef DEBUG
         msg(PLUGIN_NAME": read comment %s\n", cmt);
#endif
         set_cmt(ea, cmt, rep);
      }
   }
   return 0;
}

int cmd_ti_changed(json_object *json) {
   ea_t ea;   //ea_t can be either 32 or 64 bits
   
   if (!ea_from_json(json, "addr", &ea)) {
      return -1;
   }
   uint32_t ti_len, fnames_len;
   const type_t *ti = (const type_t*)hex_from_json(json, "ti", &ti_len);
   if (ti == NULL) {
      return -1;
   }
   const p_list *fnames = (const p_list*)hex_from_json(json, "fnames", &fnames_len);  //NULL is a valid result here
   const type_t *ti1 = ti;  //for free because deserialize changes ti
   const p_list *fnames1 = fnames;  //for free because deserialize changes fnames
#if IDA_SDK_VERSION >= 650
   tinfo_t tinf;
   const til_t *base_til;
#if IDA_SDK_VERSION < 700
   base_til = idati;
#else
   base_til = get_idati();
#endif
   tinf.deserialize(base_til, &ti, &fnames);
#if IDA_SDK_VERSION < 700
   set_tinfo2(ea, &tinf);
#else
   set_tinfo(ea, &tinf);
#endif
#else
   set_tinfo(ea, ti, fnames);
#endif
   qfree((void*)ti1);
   qfree((void*)fnames1);
   return 0;
}

int cmd_op_ti_changed(json_object *json) {
   ea_t ea;   //ea_t can be either 32 or 64 bits
   uint32_t opnum;
   if (!ea_from_json(json, "addr", &ea) || !uint32_from_json(json, "opnum", &opnum)) {
      return -1;
   }
   uint32_t ti_len, fnames_len;
   const type_t *ti = (const type_t*)hex_from_json(json, "ti", &ti_len);
   if (ti == NULL) {
      return -1;
   }
   const p_list *fnames = (const p_list*)hex_from_json(json, "fnames", &fnames_len);  //NULL is a valid return here
   const type_t *ti1 = ti;  //for free because deserialize changes ti
   const p_list *fnames1 = fnames;  //for free because deserialize changes fnames
#if IDA_SDK_VERSION >= 650
   tinfo_t tinf;
   //*** what is appropriate value for til here? Using NULL for now
   const til_t *base_til;
#if IDA_SDK_VERSION < 700
   base_til = idati;
#else
   base_til = get_idati();
#endif
   tinf.deserialize(base_til, &ti, &fnames);
#if IDA_SDK_VERSION < 700
   set_op_tinfo2(ea, opnum, &tinf);
#else
   set_op_tinfo(ea, opnum, &tinf);
#endif
#else
   set_op_tinfo(ea, opnum, ti, fnames);
#endif
   qfree((void*)ti1);
   qfree((void*)fnames1);
   return 0;
}

int cmd_op_type_changed(json_object *json) {
   ea_t ea;   //ea_t can be either 32 or 64 bits
   uint32_t opnum, flags;
   if (!ea_from_json(json, "addr", &ea) || !uint32_from_json(json, "opnum", &opnum) || 
       !uint32_from_json(json, "flags", &flags)) {
      return -1;
   }
   if (opnum == 0xffffffff) {
      msg("COMMAND_OP_TYPE_CHANGED with n == -1\n");
      //what does this mean? op deleted?
   }
   else if (isOff(flags, opnum)) {
      uint32 rf;
      if (uint32_from_json(json, "reft_and_flags", &rf)) {
         //extra information is present for extended Offset info
         ea_t target;
         ea_from_json(json, "target", &target);
         ea_t base;
         ea_from_json(json, "base", &base);
         adiff_t delta;
         uint64_from_json(json, "delta", (uint64_t*)&delta);
         refinfo_t ri;
#if IDA_SDK_VERSION >= 570
         ri.init(rf, base, target, delta);
#else
         ri.flags = rf;
         ri.base = base;
         ri.target = target;
         ri.tdelta = delta;
#endif
         op_offset_ex(ea, opnum, &ri);
      }
      else {
         //old style plain offset
         op_offset(ea, opnum, REF_OFF32);
      }
   }
   else if (isEnum(flags, opnum)) {
      //this is a protocol addition so we need to check whether
      //the appropriate extra fields are present
      const char *ename = string_from_json(json, "ename");
      if (ename != NULL) {
         uint32_t temp;
         uint32_from_json(json, "serial", &temp);
         uchar serial = (uchar)temp;
         enum_t id = get_enum(ename);
         op_enum(ea, opnum, id, serial);
      }
   }
   else if (isStroff(flags, opnum)) {
      //this is a protocol addition so we need to check whether
      //the appropriate extra fields are present
      json_object *path = json_object_object_get(json, "path");
      if (path != NULL) {
         size_t path_len = json_object_array_length(path);
         adiff_t delta;
         uint64_from_json(json, "delta", (uint64_t*)&delta);
         tid_t *opath = (tid_t*) qalloc(path_len * sizeof(tid_t));
         for (size_t i = 0; i < path_len; i++) {
            json_object *p = json_object_array_get_idx(path, i);
            const char *sname = json_object_get_string(p);
            opath[i] = get_struc_id(sname);
         }
#if IDA_SDK_VERSION < 700
         op_stroff(ea, opnum, opath, path_len, delta);
#else
         insn_t ins;
         decode_insn(&ins, ea);
         op_stroff(ins, opnum, opath, (int)path_len, delta);
#endif
         qfree(opath);
      }
   }
   else {
      set_op_type(ea, flags, opnum);
   }
   return 0;
}

int cmd_enum_created(json_object *json) {
   const char *ename = string_from_json(json, "enum_name");
   if (ename != NULL) {
      add_enum((size_t)BADADDR, ename, (flags_t)0);
      //Perhaps should report tid to server in case it is renamed???
      //server maintains tid map
   }
   return 0;
}

int cmd_enum_deleted(json_object *json) {
   const char *ename = string_from_json(json, "enum_name");
   if (ename != NULL) {
      enum_t id = get_enum(ename);
      del_enum(id);
   }
   return 0;
}

int cmd_enum_bf_changed(json_object *json) {
   //******
   return 0;
}

int cmd_enum_renamed(json_object *json) {
   char localname[MAXNAMESIZE];
   const char *newname = string_from_json(json, "oldname");
   const char *oldname = string_from_json(json, "newname");
   if (oldname != NULL && newname != NULL) {
      for (nodeidx_t n = cnn.sup1st(COLLABREATE_ENUMS_TAG);
              n != BADNODE; n = cnn.supnxt(n, COLLABREATE_ENUMS_TAG)) {
         cnn.supstr(n, localname, sizeof(localname), COLLABREATE_ENUMS_TAG);
         if (strcmp(localname, oldname) == 0) {
            cnn.supset(n, newname, 0, COLLABREATE_ENUMS_TAG);
            set_struc_name(n, newname);
            break;
         }
      }
   }
   return 0;
}

int cmd_enum_cmt_changed(json_object *json) {
   const char *name;
   bool rep;
   const char *cmt = string_from_json(json, "comment");
   name = string_from_json(json, "enum_name");
   if (name == NULL || cmt == NULL || !bool_from_json(json, "rep", &rep)) {
      return -1;
   }
   msg("enum cmt changed for enum %s, comment: %s\n", name, cmt);
   enum_t id = get_enum(name);
   if (-1 == (int)id) {
#if IDA_SDK_VERSION >= 570
      const_t m = get_enum_member_by_name(name);
      if (-1 == (int)m) {
         set_enum_member_cmt(m, cmt, rep);
      }
#endif
   }
   else {
      set_enum_cmt(id, cmt, rep);
   }
   return 0;
}

int cmd_enum_const_created(json_object *json) {
   uval_t value;
   uint64_t tmp;
   const char *ename = string_from_json(json, "ename");
   const char *mname = string_from_json(json, "mname");
   if (ename == NULL || mname == NULL || !uint64_from_json(json, "value", &tmp)) {
      return -1;
   }
   value = (uval_t)tmp;
   enum_t id = get_enum(ename);
#if IDA_SDK_VERSION >= 570
   add_enum_member(id, mname, value);
#else
   add_const(id, mname, value);
#endif
   return 0;
}

int cmd_enum_const_deleted(json_object *json) {
   uint64_t tmp1, tmp2;
   uint32_t tmp3;
   const char *ename = string_from_json(json, "ename");
   if (ename == NULL || !uint64_from_json(json, "value", &tmp1) ||
       !uint64_from_json(json, "bmask", &tmp2) || !uint32_from_json(json, "serial", &tmp3)) {
      return -1;
   }
   uval_t value = (uval_t)tmp1;
   bmask_t bmask = (bmask_t)tmp2;
   uchar serial = (uchar)tmp3;
   
   enum_t id = get_enum(ename);
#if IDA_SDK_VERSION >= 570
   del_enum_member(id, value, serial, bmask);
#else
   del_const(id, value, serial, bmask);
#endif
   return 0;
}

int cmd_struc_created(json_object *json) {
   //Perhaps should report tid to server in case it is renamed???
   //server maintains tid map
   //ignoring uint64_t "tid" field

   bool is_union;
   const char *sname = string_from_json(json, "struc_name");
   if (sname == NULL || !bool_from_json(json, "union", &is_union)) {
      return -1;
   }
   tid_t s2 = add_struc(BADADDR, sname, is_union);

   //remember the name of the struct in case it is renamed later
   cnn.supset(s2, sname, 0, COLLABREATE_STRUCTS_TAG);
//         msg(PLUGIN_NAME": received COMMAND_STRUC_CREATED message for %s\n", sname);
   return 0;
}

int cmd_struc_deleted(json_object *json) {
   const char *name = string_from_json(json, "struc_name");
   tid_t t = get_struc_id(name);
   struc_t *s = get_struc(t);
   del_struc(s);
   return 0;
}

int cmd_struc_renamed(json_object *json) {
   char localname[MAXNAMESIZE];
   //ignoring uint64_t "tid" field, need to try to map struct id to other instances ID
   const char *newname = string_from_json(json, "newname");
   const char *oldname = string_from_json(json, "oldname");
   if (oldname != NULL && newname != NULL) {
      for (nodeidx_t n = cnn.sup1st(COLLABREATE_STRUCTS_TAG);
              n != BADNODE; n = cnn.supnxt(n, COLLABREATE_STRUCTS_TAG)) {
         cnn.supstr(n, localname, sizeof(localname), COLLABREATE_STRUCTS_TAG);
         if (strcmp(localname, oldname) == 0) {
            cnn.supset(n, newname, 0, COLLABREATE_STRUCTS_TAG);
            set_struc_name(n, newname);
            break;
         }
      }
   }
   return 0;
}

int cmd_struc_expanded(json_object *json) {
   //ignoring uint64_t "tid" field, need to try to map struct id to other instances ID
   const char *sname = string_from_json(json, "struc_name");
//         msg(PLUGIN_NAME": received COMMAND_STRUC_EXPANDED message for %s\n", sname);
   // ******
   return 0;
}

int cmd_struc_cmt_changed(json_object *json) {
   bool rep;
   const char *tname = string_from_json(json, "struc_name");
   const char *cmt = string_from_json(json, "comment");
   if (tname == NULL || cmt == NULL || !bool_from_json(json, "rep", &rep)) {
      return -1;
   }
   char *name = qstrdup(tname);
   char *dot = strchr(name, '.');
   if (dot != NULL) {
      *dot++ = '\0';
   }
   tid_t t = get_struc_id(name);
   msg("struct cmt changed for struct %s, comment: %s\n", name, cmt);
   if (dot != NULL) {
      struc_t *sptr = get_struc(t);
      member_t *mptr = get_member_by_name(sptr, dot);
      set_member_cmt(mptr, cmt, rep);
   }
   else {
      set_struc_cmt(t, cmt, rep);
   }
   qfree(name);
   return 0;
}

int cmd_create_struc_member_data(json_object *json) {
   const char *mbr = string_from_json(json, "member");
   const char *name = string_from_json(json, "struc_name");

   if (name == NULL || mbr == NULL) {
      return -1;
   }

   ea_t soff;   //not really an address
   uint64_t tmp;
   if (!ea_from_json(json, "soff", &soff) || !uint64_from_json(json, "flag", &tmp)) {
      return -1;
   }
   flags_t f = (flags_t)tmp;

   if (!uint64_from_json(json, "sz", &tmp)) {
      return -1;
   }
   
   asize_t sz = (asize_t)tmp;

   tid_t t = get_struc_id(name);
   struc_t *s = get_struc(t);
   add_struc_member(s, mbr, soff, f, NULL, sz);
//         msg(PLUGIN_NAME": received COMMAND_CREATE_STRUC_MEMBER_DATA message for %s.%s, offset %d\n", name, mbr, soff);
   return 0;
}

int cmd_create_struc_member_struct(json_object *json) {
   opinfo_t ti;
   ea_t soff;
   uint64_t tmp;
   const char *ti_name = string_from_json(json, "struc_type");
   ti.tid = get_struc_id(ti_name);
   //ignoring "properties", (uint32_t)m->props
   ea_from_json(json, "soff", &soff);
   uint64_from_json(json, "flag", &tmp);
   flags_t f = (flags_t)tmp;
   uint64_from_json(json, "sz", &tmp);
   asize_t sz = (asize_t)tmp;
   //should send opinfo_t as well
   const char *mbr = string_from_json(json, "member");
   const char *name = string_from_json(json, "struc_name");
   tid_t t = get_struc_id(name);
   struc_t *s = get_struc(t);
   add_struc_member(s, mbr, soff, f, &ti, sz);
//         msg(PLUGIN_NAME": received COMMAND_CREATE_STRUC_MEMBER_STRUCT message for %s.%s (%s)\n", name, mbr, ti_name);
   return 0;
}

int cmd_create_struc_member_str(json_object *json) {
   opinfo_t ti;
   ea_t soff;
   uint64_t tmp;
   uint64_from_json(json, "str_type", &tmp);
   ti.strtype = (int32)tmp;
   //ignoring "properties", (uint32_t)m->props
   ea_from_json(json, "soff", &soff);
   uint64_from_json(json, "flag", &tmp);
   flags_t f = (flags_t)tmp;
   uint64_from_json(json, "sz", &tmp);
   asize_t sz = (asize_t)tmp;
   //should send opinfo_t as well
   const char *mbr = string_from_json(json, "member");
   const char *name = string_from_json(json, "struc_name");
   tid_t t = get_struc_id(name);
   struc_t *s = get_struc(t);
   add_struc_member(s, mbr, soff, f, &ti, sz);
//         msg(PLUGIN_NAME": received COMMAND_CREATE_STRUC_MEMBER_STR message for %s.%s\n", name, mbr);
   return 0;
}

int cmd_create_struc_member_enum(json_object *json) {
   opinfo_t ti;
   ea_t soff;
   uint64_t tmp;
   const char *ti_name = string_from_json(json, "enum_name");
   ti.ec.tid = get_struc_id(ti_name);
   uint64_from_json(json, "serial", &tmp);
   ti.ec.serial = (uchar)tmp;
   //ignoring "properties", (uint32_t)m->props
   ea_from_json(json, "soff", &soff);
   uint64_from_json(json, "flag", &tmp);
   flags_t f = (flags_t)tmp;
   uint64_from_json(json, "sz", &tmp);
   asize_t sz = (asize_t)tmp;
   //should send opinfo_t as well
   const char *mbr = string_from_json(json, "member");
   const char *name = string_from_json(json, "struc_name");
   tid_t t = get_struc_id(name);
   struc_t *s = get_struc(t);
   add_struc_member(s, mbr, soff, f, &ti, sz);
//         msg(PLUGIN_NAME": received COMMAND_CREATE_STRUC_MEMBER_ENUM message for %s.%s (%s)\n", name, mbr, ti_name);
   return 0;
}

int cmd_create_struc_member_offset(json_object *json) {
   opinfo_t ti;
   ea_t soff;
   uint64_t tmp;
   uint32_t ri_len;
   const uint8_t *refinf = hex_from_json(json, "refinfo", &ri_len);
   memcpy(&ti.ri, refinf, sizeof(refinfo_t));
   qfree((void*)refinf);
   //ignoring "properties", (uint32_t)m->props
   ea_from_json(json, "soff", &soff);
   uint64_from_json(json, "flag", &tmp);
   flags_t f = (flags_t)tmp;
   uint64_from_json(json, "sz", &tmp);
   asize_t sz = (asize_t)tmp;
   //should send opinfo_t as well
   const char *mbr = string_from_json(json, "member");
   const char *name = string_from_json(json, "struc_name");
   tid_t t = get_struc_id(name);
   struc_t *s = get_struc(t);
   add_struc_member(s, mbr, soff, f, &ti, sz);
//         msg(PLUGIN_NAME": received COMMAND_CREATE_STRUC_MEMBER_OFFSET message for %s.%s (%s)\n", name, mbr, ti_name);
   return 0;
}

int cmd_struc_member_deleted(json_object *json) {
   ea_t off;
   ea_from_json(json, "offset", &off);
   const char *name = string_from_json(json, "struc_name");
   tid_t t = get_struc_id(name);
   struc_t *s = get_struc(t);
   del_struc_member(s, off);
   return 0;
}

int cmd_set_stack_var_name(json_object *json) {
   ea_t soff, ea;
   ea_from_json(json, "func_addr", &ea);
   ea_from_json(json, "offset", &soff);
   const char *name = string_from_json(json, "name");
   struc_t *stk_frame = get_frame(ea);
   if (name) {
      set_member_name(stk_frame, soff, name);
   }
   return 0;
}

int cmd_set_struct_member_name(json_object *json) {
   ea_t soff;
   ea_from_json(json, "offset", &soff);
   const char *sname = string_from_json(json, "struc_name");
   const char *mname = string_from_json(json, "mbr_name");
   if (sname != NULL && mname != NULL) {
      struc_t *struc = get_struc(get_struc_id(sname));
      set_member_name(struc, soff, mname);
//            msg(PLUGIN_NAME": received COMMAND_SET_STRUCT_MEMBER_NAME message for %s.%s\n", sname, mname);
   }
   return 0;
}

int cmd_struc_member_changed_data(json_object *json) {
//         tid_t s1 = b.readInt();   //send the tid to create map on the server
   ea_t soff, eoff;
   uint64_t tmp;
   ea_from_json(json, "soff", &soff);
   ea_from_json(json, "eoff", &eoff);
   uint64_from_json(json, "flag", &tmp);
   flags_t flags = (flags_t)tmp;
   const char *name = string_from_json(json, "struc_name");
   if (name) {
      struc_t *s = get_struc(get_struc_id(name));
      set_member_type(s, soff, flags, NULL, eoff - soff);
   }
//         msg(PLUGIN_NAME": received COMMAND_STRUC_MEMBER_CHANGED_DATA message for %s.%s\n", sname, mname);
   return 0;
}

int cmd_struc_member_changed_struct(json_object *json) {
   ea_t soff, eoff;
   const char *ti_name = string_from_json(json, "inner_struc");
   opinfo_t ti;
   uint64_t tmp;
   ti.tid = get_struc_id(ti_name);
   ea_from_json(json, "soff", &soff);
   ea_from_json(json, "eoff", &eoff);
   uint64_from_json(json, "flag", &tmp);
   flags_t f = (flags_t)tmp;
   //should send opinfo_t as well
   const char *sname = string_from_json(json, "struc_name");
   if (sname != NULL) {
      struc_t *s = get_struc(get_struc_id(sname));
      set_member_type(s, soff, f, &ti, eoff - soff);
   }
//         msg(PLUGIN_NAME": received COMMAND_STRUC_MEMBER_CHANGED_STRUCT message for %s.%d (%s)\n", sname, soff, ti_name);
   return 0;
}

int cmd_struc_member_changed_str(json_object *json) {
   ea_t soff, eoff;
   opinfo_t ti;
   uint64_t tmp;
   uint64_from_json(json, "str_type", &tmp);
   ti.strtype = (int32)tmp;
   ea_from_json(json, "soff", &soff);
   ea_from_json(json, "eoff", &eoff);
   uint64_from_json(json, "flag", &tmp);
   flags_t f = (flags_t)tmp;
   //should send opinfo_t as well
   const char *sname = string_from_json(json, "struc_name");
   if (sname != NULL) {
      struc_t *s = get_struc(get_struc_id(sname));
      set_member_type(s, soff, f, &ti, eoff - soff);
   }
//         msg(PLUGIN_NAME": received COMMAND_STRUC_MEMBER_CHANGED_STR message for %s.%d\n", sname, soff);
   return 0;
}

int cmd_struc_member_changed_offset(json_object *json) {
   ea_t soff, eoff;
   opinfo_t ti;
   uint64_t tmp;
   uint32_t ri_len;
   const uint8_t *refinf = hex_from_json(json, "refinfo", &ri_len);
   memcpy(&ti.ri, refinf, sizeof(refinfo_t));
   qfree((void*)refinf);
   ea_from_json(json, "soff", &soff);
   ea_from_json(json, "eoff", &eoff);
   uint64_from_json(json, "flag", &tmp);
   flags_t f = (flags_t)tmp;
   //should send opinfo_t as well
   const char *sname = string_from_json(json, "struc_name");
   if (sname != NULL) {
      struc_t *s = get_struc(get_struc_id(sname));
      set_member_type(s, soff, f, &ti, eoff - soff);
   }
//         msg(PLUGIN_NAME": received COMMAND_STRUC_MEMBER_CHANGED_OFFSET message for %s.%d\n", sname, soff);
   return 0;
}

int cmd_struc_member_changed_enum(json_object *json) {
   ea_t soff, eoff;
   opinfo_t ti;
   uint64_t tmp;
   const char *ti_name = string_from_json(json, "enum_name");
   ti.ec.tid = get_struc_id(ti_name);
   uint64_from_json(json, "serial", &tmp);
   ti.ec.serial = (uchar)tmp;
   ea_from_json(json, "soff", &soff);
   ea_from_json(json, "eoff", &eoff);
   uint64_from_json(json, "flag", &tmp);
   flags_t f = (flags_t)tmp;
   //should send opinfo_t as well
   const char *sname = string_from_json(json, "struc_name");
   if (sname != NULL) {
      struc_t *s = get_struc(get_struc_id(sname));
      set_member_type(s, soff, f, &ti, eoff - soff);
   }
//         msg(PLUGIN_NAME": received COMMAND_STRUC_MEMBER_CHANGED_ENUM message for %s.%d (%s)\n", sname, soff, ti_name);
   return 0;
}

int cmd_thunk_created(json_object *json) {
   ea_t ea;   //ea_t can be either 32 or 64 bits
   ea_from_json(json, "addr", &ea);
   func_t *f = get_func(ea);
   if (f) {
      f->flags |= FUNC_THUNK;
      update_func(f);
   }
   return 0;
}

int cmd_func_tail_appended(json_object *json) {
   ea_t start_ea, tail_start, tail_end;
   if (!ea_from_json(json, "funcea", &start_ea) || 
       !ea_from_json(json, "tail_start", &tail_start) ||
       !ea_from_json(json, "tail_end", &tail_end)) {
      return -1;
   }
   
   func_t *f = get_func(start_ea);
   if (f) {
      append_func_tail(f, tail_start, tail_end);
   }
   return 0;
}

int cmd_func_tail_removed(json_object *json) {
   ea_t start_ea, tail;
   if (!ea_from_json(json, "funcea", &start_ea) || 
       !ea_from_json(json, "tailea", &tail)) {
      return -1;
   }
   func_t *f = get_func(start_ea);
   if (f) {
      remove_func_tail(f, tail);
   }
   return 0;
}

int cmd_tail_owner_changed(json_object *json) {
   ea_t owner, tailea;
   if (!ea_from_json(json, "ownerea", &owner) || 
       !ea_from_json(json, "tailea", &tailea)) {
      return -1;
   }
   func_t *tail = get_func(tailea);
   if (tail) {
#ifndef __IDAFW__
      set_tail_owner(tail, owner);
#endif
   }
   return 0;
}

int cmd_func_noret_changed(json_object *json) {
   ea_t ea;   //ea_t can be either 32 or 64 bits
   if (!ea_from_json(json, "addr", &ea)) {
      return -1;
   }
   func_t *f = get_func(ea);
   if (f) {
      f->flags ^= FUNC_NORET;
      update_func(f);
   }
   return 0;
}

int cmd_segm_added(json_object *json) {
   int32_t tmp;
   segment_t s;
   bool valid = true;
   memset(&s, 0, sizeof(segment_t));
   valid &= ea_from_json(json, "startea", &s.start_ea);
   valid &= ea_from_json(json, "endea", &s.end_ea);
   valid &= int32_from_json(json, "orgbase", &tmp);
   s.orgbase = (uval_t)tmp;
   valid &= int32_from_json(json, "align", (int32_t*)&tmp);
   s.align = (uchar)tmp;
   valid &= int32_from_json(json, "comb", (int32_t*)&tmp);
   s.comb = (uchar)tmp;
   valid &= int32_from_json(json, "perm", (int32_t*)&tmp);
   s.perm = (uchar)tmp;
   valid &= int32_from_json(json, "bitness", (int32_t*)&tmp);
   s.bitness = (uchar)tmp;
   valid &= int32_from_json(json, "flags", (int32_t*)&tmp);
   s.flags = (ushort)tmp;
   s.color = DEFCOLOR;
   const char *name = string_from_json(json, "name");
   const char *clazz = string_from_json(json, "class");
   if (!valid || name == NULL || clazz == NULL) {
      return -1;
   }
   add_segm_ex(&s, name, clazz, ADDSEG_QUIET | ADDSEG_NOSREG);
   return 0;
}

int cmd_segm_deleted(json_object *json) {
   ea_t ea;   //ea_t can be either 32 or 64 bits
   if (!ea_from_json(json, "addr", &ea)) {
      return -1;
   }
   del_segm(ea, SEGMOD_KEEP | SEGMOD_SILENT);
   return 0;
}

int cmd_segm_start_changed(json_object *json) {
   ea_t old_end, new_start;
   if (!ea_from_json(json, "startea", &new_start) || !ea_from_json(json, "endea", &old_end)) {
      return -1;
   }
   set_segm_start(old_end, new_start, 0);
   return 0;
}

int cmd_segm_end_changed(json_object *json) {
   ea_t new_end, old_start;
   if (!ea_from_json(json, "startea", &old_start) || !ea_from_json(json, "endea", &new_end)) {
      return -1;
   }
   set_segm_start(old_start, new_end, 0);
   return 0;
}

int cmd_segm_moved(json_object *json) {
   //ignoring "size", (uint64_t)sz for now
   ea_t from, to;
   if (!ea_from_json(json, "from", &from) || !ea_from_json(json, "to", &to)) {
      return -1;
   }
   segment_t *s = getseg(from);
   move_segm(s, to, MSF_SILENT);
   return 0;
}

#if IDA_SDK_VERSION < 700
int cmd_area_cmt_changed(json_object *json) {
   ea_t ea;   //ea_t can be either 32 or 64 bits
   bool rep;
   areacb_t *cb = NULL;
   const char *area = string_from_json(json, "area");
   if (area == NULL) {
      return -1;
   }
   if (strcmp(area, AREACB_FUNCS) == 0) {
      cb = &funcs;
   }
   else if (strcmp(area, AREACB_SEGS) == 0) {
      cb = &segs;
   }
   if (cb != NULL) {
      if (!ea_from_json(json, "startea", &ea) || !bool_from_json(json, "rep", &rep)) {
         return -1;
      }
      area_t *a = cb->get_area(ea);
      if (a != NULL) {  //only change comment if we found the area
         const char *cmt = string_from_json(json, "comment");
         if (cmt != NULL) {
            cb->set_area_cmt(a, cmt, rep);
         }
      }
   }
   return 0;
}
#else
int cmd_range_cmt_changed(json_object *json) {
   ea_t ea;   //ea_t can be either 32 or 64 bits
   bool rep;
   range_kind_t rk = RANGE_KIND_UNKNOWN;
   const char *range = string_from_json(json, "range");
   if (range == NULL) {
      return -1;
   }
   if (strcmp(range, RANGE_FUNCS) == 0) {
      rk = RANGE_KIND_FUNC;
   }
   else if (strcmp(range, RANGE_SEGS) == 0) {
      rk = RANGE_KIND_SEGMENT;
   }
   if (rk != RANGE_KIND_UNKNOWN) {
      const char *cmt = string_from_json(json, "comment");
      if (cmt == NULL) {
         return 0;
      }
      if (!ea_from_json(json, "startea", &ea) || !bool_from_json(json, "rep", &rep)) {
         return -1;
      }
      if (rk == RANGE_KIND_FUNC) {
         func_t *pfn = get_func(ea);
         if (pfn) {
            set_func_cmt(pfn, cmt, rep);
         }
      }
      else {  //must be RANGE_KIND_SEGMENT
         segment_t *seg = getseg(ea);
         if (seg) {
            set_segment_cmt(seg, cmt, rep);
         }
      }
   }
   return 0;
}
#endif

int do_auth(unsigned char *challenge, int challenge_len) {
   int rval = 0;
   if (do_auth()) {
#ifdef DEBUG
      msg(PLUGIN_NAME": sending auth data\n");
#endif
      sendAuthData(challenge, challenge_len);
   }
   else {
      msg(PLUGIN_NAME": authentication cancelled.\n");
      rval = 1;
   }         
   return rval;
}

static uint8_t *challenge;

int initial_challenge(json_object *json) {
#ifdef DEBUG
   msg(PLUGIN_NAME": Received Auth Challenge\n");
#endif
   uint32_t clen;
   challenge = hex_from_json(json, "challenge", &clen);
   if (challenge == NULL || clen != CHALLENGE_SIZE) {
      return -1;
   }
   if (do_auth(challenge, CHALLENGE_SIZE) != 0) {
      cleanup();         //user canceled dialog
   }
   else {
      //challenge too short
   }
   return 0;
}

int user_message(json_object *json) {
   time_t t;
   if (sizeof(time_t) == sizeof(int64)) {
      uint64_from_json(json, "time", (uint64_t*)&t);
   }
   else {
      uint32_from_json(json, "time", (uint32_t*)&t);
   }
   const char *msg = string_from_json(json, "message");
   postCollabMessage(msg, t);
   return 0;
}

//Make sure our netnode exists
void initNetNode(void) {
   writeUpdateValue(0);
}

int auth_reply(json_object *json) {
#ifdef DEBUG
   msg(PLUGIN_NAME": in AUTH_REPLY.\n");
#endif
   int32_t reply;
   if (!int32_from_json(json, "reply", &reply)) {
      return -1;
   }
   if (reply == AUTH_REPLY_FAIL) {
      //use saved challenge from initial_challenge message
      if (do_auth(challenge, CHALLENGE_SIZE) != 0) {
         cleanup();       //user cancelled dialog
      }
      authenticated = false;
      msg(PLUGIN_NAME": authentication failed.\n");
   }
   else {
      authenticated = true;
      msg(PLUGIN_NAME": Successfully authenticated.\n");
      postCollabMessage("Successfully authenticated.");
      unsigned char gpid[GPID_SIZE];
      ssize_t sz= getGpid(gpid, sizeof(gpid));
      if (sz > 0) {
         msg(PLUGIN_NAME": Existing project found.\n");
         do_project_rejoin();  //could pass gpid
      }
      else {
         msg(PLUGIN_NAME": Virgin idb detected.\n");
         initNetNode();
         sendProjectGetList();
      }
   }
   return 0;
}

int project_list(json_object *json) {
#ifdef DEBUG
   msg(PLUGIN_NAME": in PROJECT_LIST\n");
#endif
   if (!do_project_select(json)) {
      cleanup();
   }
   return 0;
}

//Tell the server the last update that we have received so that
//it can send us all newer updates
void sendLastUpdate() {
   uint64_t last = getLastUpdate();
   msg(PLUGIN_NAME": Requesting all updates greater than %s\n", formatLongLong(last));
   json_object *obj = json_object_new_object();
   append_json_uint64_val(obj, "last_update", last);
   send_json(MSG_SEND_UPDATES, obj);
}

/**
 * empty the pending updates queue with no additional action
 * this is usually done following a successful fork
 */
void clearPendingUpdates() {
   updates.clear();
}

/**
 * Add an update packet to the pending updates queue
 */
void queueUpdate(const char *json_update) {
   updates.push_back(json_update);
}

void queueUpdate(json_object *obj) {
   size_t jlen;
   const char *json = json_object_to_json_string_length(obj, JSON_C_TO_STRING_PLAIN, &jlen);
   queueUpdate(json);
}

int project_join_reply(json_object *json) {
#ifdef DEBUG
   msg(PLUGIN_NAME": in PROJECT_JOIN_REPLY\n");
#endif
   int32_t reply;
   if (!int32_from_json(json, "reply", &reply)) {
      return -1;
   }
   if (reply == JOIN_REPLY_SUCCESS) {
      //we are joined to a project
      uint32_t len;
      uint8_t *gpid = hex_from_json(json, "gpid", &len);
      if (gpid == NULL || len != GPID_SIZE) {
         msg(PLUGIN_NAME": Project join failed, server sent bad GPID.\n");
         //is this a "HARD" error condition?  without this it's impossible to re-join later
         //gpid too short
         return -1;
      }

      msg(PLUGIN_NAME": Successfully joined project.\n");
      postCollabMessage("Successfully joined project.");
      setGpid(gpid, GPID_SIZE);
      hookAll();
      fork_pending = false;
      clearPendingUpdates();  //delete all pending updates from previous project
      //need to send a MSG_SEND_UPDATES message
      sendLastUpdate();
      if (changeCache != NULL) {
//                  msg("sending change cache of size %d\n", changeCache->size());
         send_all(*changeCache);
         changeCache->clear();
         cnn.delblob(1, COLLABREATE_CACHE_TAG);
      }
      qfree(gpid);
   }
   else if (reply == JOIN_REPLY_FAIL) {
      //if fork_pending is true, then this is a failed fork
      //what options should we offer the user?
      msg(PLUGIN_NAME": Project join explicitly failed\n");
      hookAll();
      fork_pending = false;
      clearPendingUpdates();  //delete all pending updates from previous project
      //need to send a MSG_SEND_UPDATES message
      sendLastUpdate();
   }
   else {
      msg(PLUGIN_NAME": Project join implicitly failed\n");
   }
   return 0;
}

int project_snapshot_reply(json_object *json) {
   msg(PLUGIN_NAME": project snapshot success!\n");
   postCollabMessage("Project snapshot success!");
   return 0;
}

int project_fork_follow(json_object *json) {
#ifdef DEBUG
   msg(PLUGIN_NAME": in PROJECT_FORK_FOLLOW\n");
#endif
   const char *user = string_from_json(json, "user");
   const char *desc = string_from_json(json, "description");
   
   if (user == NULL || desc == NULL) {
      return -1;
   }

   uint64_t lastupdateid;
   if (!uint64_from_json(json, "last_update", &lastupdateid)) {
      return -1;
   }

   uint32_t len;
   uint8_t *gpid = hex_from_json(json, "gpid", &len);
   if (gpid == NULL || len != GPID_SIZE) {
      return -1;
   }

   //check to make sure this idb is in the correct state to follow the fork
   if (lastupdateid == getLastUpdate()) {
#ifdef DEBUG
      msg(PLUGIN_NAME": user %s forked at 0x%s to new project: %s\n", user, formatLongLong(lastupdateid), desc);
      //msg(PLUGIN_NAME": would you like to follow the forked project? Y/N");
#endif
      if (askbuttons_c("Yes", "No", "", 0, "User %s forked to a new project: %s, would you like to follow?", user, desc) == 1) {
         msg(PLUGIN_NAME": join new project\n");
         do_project_leave();
         setGpid(gpid, GPID_SIZE);
         clearPendingUpdates();
         do_project_rejoin();
      }
      else {
         msg(PLUGIN_NAME": staying with the current project...\n");
      }
   }
   else {
      char v1[24];
      char v2[24];
      msg(PLUGIN_NAME": user %s forked at 0x%s but the current ipdateid is 0x%s\n", user, formatLongLong(lastupdateid, v1), formatLongLong(getLastUpdate(), v2));
      msg(PLUGIN_NAME": to follow you need to re-open from the original binary and join the new project:\n");
      msg(PLUGIN_NAME": \"%s\" \n",desc);
   }
   qfree(gpid);
   return 0;
}

int get_req_perms_reply(json_object *json) {
#ifdef DEBUG
   msg(PLUGIN_NAME": Got a GET_REQ_PERMS_REPLY\n");
#endif
   do_get_req_perms(json);
   return 0;
}

int set_req_perms_reply(json_object *json) {
#ifdef DEBUG
   msg(PLUGIN_NAME": Got a SET_REQ_PERMS_REPLY now what?\n"); //TMV
#endif
   return 0;
}

int get_proj_perms_reply(json_object *json) {
#ifdef DEBUG
   msg(PLUGIN_NAME": Got a GET_PROJ_PERMS_REPLY\n");
#endif
   do_get_proj_perms(json);
   return 0;
}

int set_proj_perms_reply(json_object *json) {
#ifdef DEBUG
   msg(PLUGIN_NAME": Got a SET_PROJ_PERMS_REPLY now what?\n");
#endif
   return 0;
}

int ack_updateid(json_object *json) {
   //msg(PLUGIN_NAME": in ACK_UPDATEID \n");
   uint64_t updateid;
   if (!uint64_from_json(json, "updateid", &updateid)) {
      return -1;
   }
#ifdef DEBUG
   msg(PLUGIN_NAME": got updateid: %s\n", formatLongLong(updateid));
#endif
   setLastUpdate(updateid);
   return 0;
}

int collab_error(json_object *json) {
   const char *error_msg = string_from_json(json, "error");
   if (error_msg != NULL) {
      msg(PLUGIN_NAME": error: %s\n", error_msg);
   }
   return 0;
}

int collab_fatal(json_object *json) {
   const char *error_msg = string_from_json(json, "error");
   if (error_msg != NULL) {
      msg(PLUGIN_NAME": fatal error: %s\n", error_msg);
      warning("%s", error_msg);
   }
   authenticated = false;
   cleanup();
   return 0;
}

int collab_ping(json_object *json) {
   uint64_t id;
   if (uint64_from_json(json, "id", &id)) {
      json_object *obj = json_object_new_object();
      append_json_uint64_val(obj, "id", id);
      send_json(MSG_PONG, obj);
   }
   else {
      //just ignore if id is missing??
   }
   return 0;
}

/*
 * Main dispatch routine for received remote notifications
 */
bool msg_dispatcher(json_object *json) {
   bool result = true;   
   if (json == NULL) {
      return false;
   }

   const char *msg_type = string_from_json(json, "type");      
   if (msg_type == NULL) {
      json_object_put(json);
      return false;
   }

#ifdef DEBUG
   msg(PLUGIN_NAME": msg_dispatcher called for: %s\n", json_object_to_json_string(json));
#endif

   //first see if this is an idb related message and handle accordingly
   map<string,CmdHandler>::iterator mi = ida_handlers.find(msg_type);
   if (mi == ida_handlers.end()) {
      mi = ctrl_handlers.find(msg_type);
      if (mi == ctrl_handlers.end()) {
         msg("COLLABREATE: No handler found for %s\n", msg_type);
         json_object_put(json);
         return false;
      }
      //project control message (non-idb message)
      CmdHandler handler = mi->second;
      result = (*handler)(json) == 0;
   }
   else if (subscribe) {
      //idb related message
#ifdef DEBUG
      msg(PLUGIN_NAME": msg_dispatcher subscribe is true\n");
#endif

      if (fork_pending) {
         queueUpdate(json);
      }
      else {
         uint64_t updateid;
         if (!uint64_from_json(json, "updateid", &updateid)) {
            json_object_put(json);
            return true;
         }
#ifdef DEBUG
         msg(PLUGIN_NAME": Received command %d, updateid 0x%s, b.size() %d\n", command, formatLongLong(updateid), b.size());
#endif
//         stats[0][command]++;
         //this prevents notifying ourselves of the incoming update
         unhookAll();
//         publish = false;
         //supress = true;  //don't want to regenerate this message as we apply the update
         CmdHandler handler = mi->second;
         result = (*handler)(json) == 0;
//           supress = false;
//           publish = userPublish;
//           publish = autoIsOk() == 1 ? userPublish : 0;
         if (updateid) {
#ifdef DEBUG
            msg(PLUGIN_NAME": calling setLastUpdate with uid: %s\n", formatLongLong(updateid));
#endif
            setLastUpdate(updateid);
         }
         //msg(PLUGIN_NAME": refreshing...\n");
         // force a refresh.
         refresh_idaview_anyway();
         //now that the update is complete start generating updates again
         hookAll();
      }
   }
   else {
#ifdef DEBUG
      msg(PLUGIN_NAME": msg_dispatcher subscribe is false\n");
#endif
   }
   json_object_put(json);
   return result;
}

void build_handler_map() {
   ctrl_handlers[MSG_INITIAL_CHALLENGE] = initial_challenge;
   ctrl_handlers[MSG_AUTH_REPLY] = auth_reply;
   ctrl_handlers[MSG_PROJECT_LIST] = project_list;
   ctrl_handlers[MSG_PROJECT_JOIN_REPLY] = project_join_reply;
   ctrl_handlers[MSG_PROJECT_SNAPSHOT_REPLY] = project_snapshot_reply;
   ctrl_handlers[MSG_PROJECT_FORK_FOLLOW] = project_fork_follow;
   ctrl_handlers[MSG_GET_REQ_PERMS_REPLY] = get_req_perms_reply;
   ctrl_handlers[MSG_SET_REQ_PERMS_REPLY] = set_req_perms_reply;
   ctrl_handlers[MSG_GET_PROJ_PERMS_REPLY] = get_proj_perms_reply;
   ctrl_handlers[MSG_SET_PROJ_PERMS_REPLY] = set_proj_perms_reply;
   ctrl_handlers[MSG_ACK_UPDATEID] = ack_updateid;
   ctrl_handlers[MSG_ERROR] = collab_error;
   ctrl_handlers[MSG_FATAL] = collab_fatal;
   ctrl_handlers[MSG_PING] = collab_ping;

   ida_handlers[COMMAND_UNDEFINE] = cmd_undefine;
   ida_handlers[COMMAND_MAKE_CODE] = cmd_make_code;
   ida_handlers[COMMAND_MAKE_DATA] = cmd_make_data;
   ida_handlers[COMMAND_MOVE_SEGM] = cmd_move_segm;
   ida_handlers[COMMAND_RENAMED] = cmd_renamed;
   ida_handlers[COMMAND_ADD_FUNC] = cmd_add_func;
   ida_handlers[COMMAND_DEL_FUNC] = cmd_del_func;
   ida_handlers[COMMAND_SET_FUNC_START] = cmd_set_func_start;
   ida_handlers[COMMAND_SET_FUNC_END] = cmd_set_func_end;
   ida_handlers[COMMAND_VALIDATE_FLIRT_FUNC] = cmd_validate_flirt_func;
   ida_handlers[COMMAND_ADD_CREF] = cmd_add_cref;
   ida_handlers[COMMAND_ADD_DREF] = cmd_add_dref;
   ida_handlers[COMMAND_DEL_CREF] = cmd_del_cref;
   ida_handlers[COMMAND_DEL_DREF] = cmd_del_dref;

   ida_handlers[COMMAND_BYTE_PATCHED] = cmd_patch_byte;
   ida_handlers[COMMAND_CMT_CHANGED] = cmd_cmt_changed;
   ida_handlers[COMMAND_TI_CHANGED] = cmd_ti_changed;
   ida_handlers[COMMAND_OP_TI_CHANGED] = cmd_op_ti_changed;
   ida_handlers[COMMAND_OP_TYPE_CHANGED] = cmd_op_type_changed;
   ida_handlers[COMMAND_ENUM_CREATED] = cmd_enum_created;
   ida_handlers[COMMAND_ENUM_DELETED] = cmd_enum_deleted;
   ida_handlers[COMMAND_ENUM_BF_CHANGED] = cmd_enum_bf_changed;
   ida_handlers[COMMAND_ENUM_RENAMED] = cmd_enum_renamed;
   ida_handlers[COMMAND_ENUM_CMT_CHANGED] = cmd_enum_cmt_changed;
   ida_handlers[COMMAND_ENUM_CONST_CREATED] = cmd_enum_const_created;
   ida_handlers[COMMAND_ENUM_CONST_DELETED] = cmd_enum_const_deleted;
   ida_handlers[COMMAND_STRUC_CREATED] = cmd_struc_created;
   ida_handlers[COMMAND_STRUC_DELETED] = cmd_struc_deleted;
   ida_handlers[COMMAND_STRUC_RENAMED] = cmd_struc_renamed;
   ida_handlers[COMMAND_STRUC_EXPANDED] = cmd_struc_expanded;
   ida_handlers[COMMAND_STRUC_CMT_CHANGED] = cmd_struc_cmt_changed;
   ida_handlers[COMMAND_CREATE_STRUC_MEMBER_DATA] = cmd_create_struc_member_data;
   ida_handlers[COMMAND_CREATE_STRUC_MEMBER_STRUCT] = cmd_create_struc_member_struct;
   ida_handlers[COMMAND_CREATE_STRUC_MEMBER_STR] = cmd_create_struc_member_str;
   ida_handlers[COMMAND_CREATE_STRUC_MEMBER_ENUM] = cmd_create_struc_member_enum;
   ida_handlers[COMMAND_CREATE_STRUC_MEMBER_OFFSET] = cmd_create_struc_member_offset;
   ida_handlers[COMMAND_STRUC_MEMBER_DELETED] = cmd_struc_member_deleted;
   ida_handlers[COMMAND_SET_STACK_VAR_NAME] = cmd_set_stack_var_name;
   ida_handlers[COMMAND_SET_STRUCT_MEMBER_NAME] = cmd_set_struct_member_name;
   ida_handlers[COMMAND_STRUC_MEMBER_CHANGED_DATA] = cmd_struc_member_changed_data;
   ida_handlers[COMMAND_STRUC_MEMBER_CHANGED_STRUCT] = cmd_struc_member_changed_struct;
   ida_handlers[COMMAND_STRUC_MEMBER_CHANGED_STR] = cmd_struc_member_changed_str;
   ida_handlers[COMMAND_STRUC_MEMBER_CHANGED_OFFSET] = cmd_struc_member_changed_offset;
   ida_handlers[COMMAND_STRUC_MEMBER_CHANGED_ENUM] = cmd_struc_member_changed_enum;
   ida_handlers[COMMAND_THUNK_CREATED] = cmd_thunk_created;
   ida_handlers[COMMAND_FUNC_TAIL_APPENDED] = cmd_func_tail_appended;
   ida_handlers[COMMAND_FUNC_TAIL_REMOVED] = cmd_func_tail_removed;
   ida_handlers[COMMAND_TAIL_OWNER_CHANGED] = cmd_tail_owner_changed;
   ida_handlers[COMMAND_FUNC_NORET_CHANGED] = cmd_func_noret_changed;
   ida_handlers[COMMAND_SEGM_ADDED] = cmd_segm_added;
   ida_handlers[COMMAND_SEGM_DELETED] = cmd_segm_deleted;
   ida_handlers[COMMAND_SEGM_START_CHANGED] = cmd_segm_start_changed;
   ida_handlers[COMMAND_SEGM_END_CHANGED] = cmd_segm_end_changed;
   ida_handlers[COMMAND_SEGM_MOVED] = cmd_segm_moved;
#if IDA_SDK_VERSION < 700
   ida_handlers[COMMAND_RANGE_CMT_CHANGED] = cmd_area_cmt_changed;
#else
   ida_handlers[COMMAND_RANGE_CMT_CHANGED] = cmd_range_cmt_changed;
#endif
   ida_handlers[COMMAND_USER_MESSAGE] = user_message;
}

