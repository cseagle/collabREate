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
/*
 *  This is the collabREate plugin
 *
 *  It is known to compile with
 *
 *   Microsoft Visual C++
 *   cygwin g++/make
 *
 */

#include "collabreate.h"

#ifndef __QT__
#ifdef _WIN32
#include <windows.h>
extern HWND mainWindow;
extern HMODULE hModule;
#endif
#endif

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <netnode.hpp>
#include <typeinf.hpp>
#include <struct.hpp>
#include <area.hpp>
#include <frame.hpp>
#include <segment.hpp>
#include <enum.hpp>
#include <xref.hpp>
#include <nalt.hpp>
#include <offset.hpp>
#include <auto.hpp>

#ifdef __QT__
#include "collabreate_ui_qt.hpp"
#else
#include "collabreate_ui.hpp"
#endif

#include "sdk_versions.h"

#if IDA_SDK_VERSION < 560
#define opinfo_t typeinfo_t
#endif

static bool authenticated = false;
static bool fork_pending = false;

//bool supress = false;

static bool isHooked = false;
void hookAll();
void unhookAll();
bool msg_dispatcher(Buffer &);

//where we stash collab specific infoze
netnode cnn(COLLABREATE_NETNODE, 0, true);
Buffer *msgHistory = NULL;
Buffer *changeCache = NULL;

#ifndef DEBUG
//#define DEBUG 1
#endif

const char *idp_messages[] = {
   //enum idp_notify
   "init",  //0
   "term",  //1
   "newprc",//2
   "newasm",//3
   "newfile",//4
   "oldfile",//5
   "newbinary",//6
   "endbinary",//7
   "newseg",//8
   "assemble",//9
   "obsolete_makemicro",//10
   "outlabel",//11
   "rename",//12
   "may_show_sreg",//13
   "closebase",//14
   "load_idasgn",//15
   "coagulate",//16
   "auto_empty",//17
   "auto_queue_empty",//18
   "func_bounds",//19
   "may_be_func",//20
   "is_sane_insn",//21
   "is_jump_func",//22
   "gen_regvar_def",//23
   "setsgr",//24
   "set_compiler",//25
   "is_basic_block_end",//26
   "reglink",//27
   "get_vxd_name",//28
   "custom_ana",//29
   "custom_out",//30
   "custom_emu",//31
   "custom_outop",//32
   "custom_mnem",//33
   "undefine",//34
   "make_code",//35
   "make_data",//36
   "moving_segm",//37
   "move_segm",//38
   "is_call_insn",//39
   "is_ret_insn",//40
   "get_stkvar_scale_factor",//41
   "create_flat_group",//42
   "kernel_config_loaded",//43
   "might_change_sp",//44
   "is_alloca_probe",//45
   "out_3byte",//46
   "get_reg_name",//47
   "savebase",//48
   "gen_asm_or_lst",//49
   "out_src_file_lnnum",//50
   "get_autocmt",//51
   "is_insn_table_jump",//52
   "auto_empty_finally",//53
   "loader_finished",//54
   "loader_elf_machine",//55
   "is_indirect_jump",//56
   "verify_noreturn",//57
   "verify_sp",//58
   "renamed",//59
   "add_func",//60
   "del_func",//61
   "set_func_start",//62
   "set_func_end",//63
   "treat_hindering_item",//64
   "str2reg",//65
   "create_switch_xrefs",//66
   "calc_switch_cases",//67
   "determined_main",//68
   "preprocess_chart",//69
   "get_bg_color",//70
   "validate_flirt_func",//71
   "get_operand_string",//72
   "add_cref",//73
   "add_dref",//74
   "del_cref",//75
   "del_dref",//76
   "coagulate_dref",//77
   "register_custom_fixup",//78
   "custom_refinfo",//79
   "set_proc_options",//80
   "adjust_libfunc_ea",//81
   "last_cb_before_debugger",//82
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
   #ifdef NO_OBSOLETE_FUNCS
   "obsolete_get_operand_info",//100
   #else
   "get_operand_info",//100
   #endif
   "get_reg_info",//101
   #ifdef NO_OBSOLETE_FUNCS
   "next_exec_insn",//102
   #else
   "get_jump_target",//102
   #endif
   "calc_step_over",//103
   "get_macro_insn_head",//104
   "get_dbr_opnum",//105
   "insn_reads_tbit",//106
   #ifdef NO_OBSOLETE_FUNCS
   "get_operand_info",//107
   #else
   "reserved_entry",//107
   #endif
   "calc_next_eas",//108
   "clean_tbit"//109
/*
   "decorate_name",//500
   "setup_til",//501
   "based_ptr",//502
   "max_ptr_size",//503
   "get_default_enum_size",//504
   "OBSOLETE(calc_arglocs)",//505
   "use_stkarg_type",//506
   "OBSOLETE(use_regarg_type)",//507
   "OBSOLETE(use_arg_types)",//508
   "OBSOLETE(get_fastcall_regs)",//509
   "OBSOLETE(get_thiscall_regs)",//510
   "OBSOLETE(calc_cdecl_purged_bytes)",//511
   "OBSOLETE(get_stkarg_offset)",//512
   "calc_purged_bytes",//513
   "calc_arglocs2",//514
   "calc_retloc",//515
   "calc_varglocs",//516
   "OBSOLETE(get_varcall_regs)",//517
   "use_regarg_type2",//518
   "use_arg_types2",//519
   "get_fastcall_regs2",//520
   "get_thiscall_regs2",//521
   "get_varcall_regs2",//522
   "calc_cdecl_purged_bytes2",//523
   "get_stkarg_offset2",//524
   "til_for_file",//525
   "loader=1000",//1000
*/
};

const char *idb_messages[] = {
   //enum event_code_t
   "byte_patched",   //0
   "cmt_changed",   //1
   "ti_changed",   //2
   "op_ti_changed",   //3
   "op_type_changed",   //4
   "enum_created",   //5
   "enum_deleted",   //6
   "enum_bf_changed",   //7
   "enum_renamed",   //8
   "enum_cmt_changed",   //9
   #ifndef NO_OBSOLETE_FUNCS
   "enum_const_created",   //10
   "enum_const_deleted",   //11
   #else
   "enum_member_created",   //10
   "enum_member_deleted",   //11
   #endif
   "struc_created",   //12
   "struc_deleted",   //13
   "struc_renamed",   //14
   "struc_expanded",   //15
   "struc_cmt_changed",   //16
   "struc_member_created",   //17
   "struc_member_deleted",   //18
   "struc_member_renamed",   //19
   "struc_member_changed",   //20
   "thunk_func_created",   //21
   "func_tail_appended",   //22
   "func_tail_removed",   //23
   "tail_owner_changed",   //24
   "func_noret_changed",   //25
   "segm_added",   //26
   "segm_deleted",   //27
   "segm_start_changed",   //28
   "segm_end_changed",   //29
   "segm_moved",   //30
   "area_cmt_changed",   //31
   "changing_cmt",   //32
   "changing_ti",   //33
   "changing_op_ti",   //34
   "changing_op_type",   //35
   "deleting_enum",   //36
   "changing_enum_bf",   //37
   "renaming_enum",   //38
   "changing_enum_cmt",   //39
   #ifndef NO_OBSOLETE_FUNCS
   "deleting_enum_const",   //40
   #else
   "deleting_enum_member",   //40
   #endif
   "deleting_struc",   //41
   "renaming_struc",   //42
   "expanding_struc",   //43
   "changing_struc_cmt",   //44
   "deleting_struc_member",   //45
   "renaming_struc_member",   //46
   "changing_struc_member",   //47
   "removing_func_tail",   //48
   "deleting_segm",   //49
   "changing_segm_start",   //50
   "changing_segm_end",   //51
   "changing_area_cmt",   //52
   "changing_segm_name",   //53
   "changing_segm_class",   //54
   "segm_name_changed",   //55
   "segm_class_changed",   //56
   "destroyed_items",   //57
   "changed_stkpnts",   //58
   "extra_cmt_changed"  //59
};

//Linked list of datagrams
struct PacketNode {
   Buffer *buf;
   PacketNode *next;

   PacketNode(Buffer &b);
};

PacketNode::PacketNode(Buffer &b) : next(NULL) {
   //need to duplicate the buffer because b may get destroyed
   buf = new Buffer();
   buf->append(b);
}

static PacketNode *updatesHead, *updatesTail;

/**
 * empty the pending updates queue with no additional action
 * this is usually done following a successful fork
 */
void clearPendingUpdates() {
   PacketNode *n;
   while (updatesHead) {
      n = updatesHead->next;
      delete updatesHead->buf;
      updatesHead = n;
   }
   updatesTail = NULL;
}

/**
 * Flush pending updates to database.
 * this is usually done following a failed fork when the
 * user elects to continue with the current project
 */
void flushPendingUpdates() {
   PacketNode *n;
   while (updatesHead) {
      n = updatesHead->next;
      msg_dispatcher(*(updatesHead->buf));
      delete updatesHead->buf;
      updatesHead = n;
   }
   updatesTail = NULL;
}

/**
 * Add an update packete to the pending updates queue
 */
void queueUpdate(Buffer &b) {
   if (updatesTail) {
      updatesTail->next = new PacketNode(b);
      updatesTail = updatesTail->next;
   }
   else {
      updatesHead = updatesTail = new PacketNode(b);
   }
}

//Save the user options bits into our netnode
bool setUserOpts(Options &user) {
   return cnn.supset(OPTIONS_SUPVAL, &user, sizeof(Options));
}

//Load the user options bits from our netnode
bool getUserOpts(Options &user) {
   return cnn.supval(OPTIONS_SUPVAL, &user, sizeof(Options)) != 0;
}

//Load the last update id from our netnode
uint64_t getLastUpdate() {
   uint64_t val;
   cnn.supval(LASTUPDATE_SUPVAL, &val, sizeof(val));
#ifdef DEBUG
   msg(PLUGIN_NAME": lastupdate supval is 0x%s\n", formatLongLong(val));
#endif
   return val;
}

//localize writes to LASTUPDATE_SUPVAL to a single function
void writeUpdateValue(uint64_t uid) {
   cnn.supset(LASTUPDATE_SUPVAL, &uid, sizeof(uid));
}

//Save an update id only if it is larger than the most recently saved id
void setLastUpdate(uint64_t uid) {
   if (uid > getLastUpdate()) {
#ifdef DEBUG
      msg(PLUGIN_NAME": ## setting last update to 0x%s ##\n", formatLongLong(uid));
#endif
      writeUpdateValue(uid);
   }
}

//Make sure our netnode exists
void initNetNode(void) {
   writeUpdateValue(0);
}

/*
 * This function recurses through all calls made by a known library function
 * and flags them as library functions as well under the premise that library
 * functions only call other library functions.
 */
void recursive_update(func_t *f) {
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

//array that holds counters of all the commands that have been sent and
//received in the current session
int stats[2][MSG_IDA_MAX + 1];

/*
 * Handle idp notifications received remotely
 */
bool handle_idp_msg(Buffer &b, int command) {
   char *name;
   ea_t ea = 0;
   asize_t sz;

   //
   // handle the received command appropriately.
   //
   switch(command) {
      case COMMAND_UNDEFINE: {
         ea = (ea_t)b.readLong();
#if IDA_SDK_VERSION >= 510
         do_unknown(ea, DOUNK_SIMPLE);
#else
         do_unknown(ea, false);
#endif
         break;
      }
      case COMMAND_MAKE_CODE: {
         ea = (ea_t)b.readLong();
         sz = (asize_t)b.readLong();
#if IDA_SDK_VERSION >= 540
         create_insn(ea);
#else
         ua_code(ea);
#endif
         break;
      }
      case COMMAND_MAKE_DATA: {
         ea = (ea_t)b.readLong();
         flags_t f = b.readInt();
         asize_t a = (asize_t)b.readLong();
         name = b.readUTF8();
         tid_t t = (name && *name) ? get_struc_id(name) : BADNODE;
         qfree(name);
         do_data_ex(ea, f, a, t);
         break;
      }
      case COMMAND_MOVE_SEGM: {
         ea = (ea_t)b.readLong();
         segment_t *s = getseg(ea);
         ea_t new_start = (ea_t)b.readLong();
         move_segm(s, new_start);
         break;
      }
      case COMMAND_RENAMED: {
         ea = (ea_t)b.readLong();
         int flag = b.read() ? SN_LOCAL : 0;
         name = b.readUTF8();
#ifdef DEBUG
         msg(PLUGIN_NAME": renamed 0x%08x - %s\n", ea, name);
#endif
         if (name) {
            set_name(ea, name, flag | SN_NOWARN);
         }
         qfree(name);
         break;
      }
      case COMMAND_ADD_FUNC: {
         ea = (ea_t)b.readLong();
         ea_t end = (ea_t)b.readLong();
         if (b.has_error()) {
            //old form, didn't get a start and end address
            add_func(ea, BADADDR);
         }
         else {
            //new form, got start and end addresses
            add_func(ea, end);
         }
         break;
      }
      case COMMAND_DEL_FUNC: {
         ea = (ea_t)b.readLong();
         del_func(ea);
         break;
      }
      case COMMAND_SET_FUNC_START: {
         ea = (ea_t)b.readLong();
         ea_t newstart = (ea_t)b.readLong();
         func_setstart(ea, newstart);
         break;
      }
      case COMMAND_SET_FUNC_END: {
         ea = (ea_t)b.readLong();
         ea_t newend = (ea_t)b.readLong();
         func_setend(ea, newend);
         break;
      }
      case COMMAND_VALIDATE_FLIRT_FUNC: {
         ea = (ea_t)b.readLong();
         name = b.readUTF8();
         if (name) {
            set_name(ea, name, SN_NOWARN);
         }
         ea_t end = (ea_t)b.readLong();
         if (b.has_error()) {
            //old form, didn't get a start and end address
            add_func(ea, BADADDR);
         }
         else {
            //new form, got start and end addresses
            add_func(ea, end);
         }
         func_t *f = get_func(ea);
         if (f) {
            //any function this calls is also a library (support) function
            recursive_update(f);
         }
         qfree(name);
         break;
      }
      case COMMAND_ADD_CREF: {
         // args: ea_t from, ea_t to, cref_t type
         ea_t from = (ea_t)b.readLong();
         ea_t to = (ea_t)b.readLong();
         cref_t type = (cref_t)b.readInt();
         add_cref(from, to, type);
         break;
      }
      case COMMAND_ADD_DREF: {
         // args: ea_t from, ea_t to, dref_t type
         ea_t from = (ea_t)b.readLong();
         ea_t to = (ea_t)b.readLong();
         dref_t type = (dref_t)b.readInt();
         add_dref(from, to, type);
         break;
      }
      case COMMAND_DEL_CREF: {
         // args: ea_t from, ea_t to, bool expand
         ea_t from = (ea_t)b.readLong();
         ea_t to = (ea_t)b.readLong();
         bool expand = b.read() != 0;
         del_cref(from, to, expand);
         break;
      }
      case COMMAND_DEL_DREF: {
         // args: ea_t from, ea_t to
         ea_t from = (ea_t)b.readLong();
         ea_t to = (ea_t)b.readLong();
         del_dref(from, to);
         break;
      }
      default:
         msg(PLUGIN_NAME": Received unknown command code: %d, ignoring.\n", command);
   }
   return true;
}

/*
 * Handle idb notifications received remotely
 */
bool handle_idb_msg(Buffer &b, int command) {
   ea_t ea = 0;   //ea_t can be either 32 or 64 bits
   int val;
   bool rep;
   struc_t *stk_frame;
   //
   // handle the received command appropriately.
   //
   switch(command) {
      case COMMAND_BYTE_PATCHED: {
         ea = (ea_t)b.readLong();
         val = b.readInt();
         patch_byte(ea, val);
         break;
      }
      case COMMAND_CMT_CHANGED: {
         ea = (ea_t)b.readLong();
         rep = b.read() ? 1 : 0;
         char *cmt = b.readUTF8();
#ifdef DEBUG
         msg(PLUGIN_NAME": read comment %s\n", cmt);
#endif
         if (cmt) {
            set_cmt(ea, cmt, rep);
         }
         qfree(cmt);
         break;
      }
      case COMMAND_TI_CHANGED: {
         ea_t ea = (ea_t)b.readLong();
         const type_t *ti = (const uchar*)b.readUTF8();
         const type_t *ti1 = ti;  //for free because deserialize changes ti
         const p_list *fnames = (const uchar*)b.readUTF8();
         const p_list *fnames1 = fnames;  //for free because deserialize changes fnames
#if IDA_SDK_VERSION >= 650
         tinfo_t tinf;
         //*** what is appropriate value for til here? Using NULL for now
         tinf.deserialize(idati, &ti, &fnames);
         set_tinfo2(ea, &tinf);
#elif IDA_SDK_VERSION >= 520
         set_tinfo(ea, ti, fnames);
#else
         set_ti(ea, ti, fnames);
#endif
         qfree((void*)ti1);
         qfree((void*)fnames1);
         break;
      }
      case COMMAND_OP_TI_CHANGED: {
         ea_t ea = (ea_t)b.readLong();
         int n = b.readInt();
         const type_t *ti = (const uchar*)b.readUTF8();
         const type_t *ti1 = ti;  //for free because deserialize changes ti
         const p_list *fnames = (const uchar*)b.readUTF8();
         const p_list *fnames1 = fnames;  //for free because deserialize changes fnames
#if IDA_SDK_VERSION >= 650
         tinfo_t tinf;
         //*** what is appropriate value for til here? Using NULL for now
         tinf.deserialize(idati, &ti, &fnames);
         set_op_tinfo2(ea, n, &tinf);
#elif IDA_SDK_VERSION >= 520
         set_op_tinfo(ea, n, ti, fnames);
#else
         set_op_ti(ea, n, ti, fnames);
#endif
         qfree((void*)ti1);
         qfree((void*)fnames1);
         break;
      }
      case COMMAND_OP_TYPE_CHANGED: {
         ea_t ea = (ea_t)b.readLong();
         int n = b.readInt();
         flags_t f = b.readInt();
         if (n == -1) {
            msg("COMMAND_OP_TYPE_CHANGED with n == -1\n");
            //what does this mean? op deleted?
         }
         else if (isOff(f, n)) {
            uint32 rf = b.readInt();
            if (!b.has_error()) {
               //extra information is present for extended Offset info
               ea_t target = b.readLong();
               ea_t base = b.readLong();
               adiff_t delta = b.readLong();
               refinfo_t ri;
#if IDA_SDK_VERSION >= 570
               ri.init(rf, base, target, delta);
#else
               ri.flags = rf;
               ri.base = base;
               ri.target = target;
               ri.tdelta = delta;
#endif
               op_offset_ex(ea, n, &ri);
            }
            else {
               //old style plain offset
               op_offset(ea, n, REF_OFF32);
            }
         }
         else if (isEnum(f, n)) {
            //this is a protocol addition so we need to check whether
            //the appropriate extra fields are present
            char *ename = b.readUTF8();
            if (ename != NULL) {
               uchar serial = b.read();
               enum_t id = get_enum(ename);
               op_enum(ea, n, id, serial);
               qfree(ename);
            }
         }
         else if (isStroff(f, n)) {
            //this is a protocol addition so we need to check whether
            //the appropriate extra fields are present
            int path_len = b.readInt();
            if (!b.has_error()) {
               adiff_t delta = b.readLong();
               tid_t *path = (tid_t*) qalloc(path_len * sizeof(tid_t));
               for (int i = 0; i < path_len; i++) {
                  char *sname = b.readUTF8();
                  path[i] = get_struc_id(sname);
                  qfree(sname);
               }
               op_stroff(ea, n, path, path_len, delta);
               qfree(path);
            }
         }
         else {
            set_op_type(ea, f, n);
         }
         break;
      }
      case COMMAND_ENUM_CREATED: {
         char *ename = b.readUTF8();
         add_enum((size_t)BADADDR, ename, (flags_t)0);
         //Perhaps should report tid to server in case it is renamed???
         //server maintains tid map
         qfree(ename);
         break;
      }
      case COMMAND_ENUM_DELETED: {
         char *ename = b.readUTF8();
         enum_t id = get_enum(ename);
         del_enum(id);
         qfree(ename);
         break;
      }
      case COMMAND_ENUM_BF_CHANGED: {
         //******
         break;
      }
      case COMMAND_ENUM_RENAMED: {
         char localname[MAXNAMESIZE];
         char *newname = b.readUTF8();
         char *oldname = b.readUTF8();
         if (oldname) {
            for (nodeidx_t n = cnn.sup1st(COLLABREATE_ENUMS_TAG);
                    n != BADNODE; n = cnn.supnxt(n, COLLABREATE_ENUMS_TAG)) {
               cnn.supstr(n, localname, sizeof(localname), COLLABREATE_ENUMS_TAG);
               if (strcmp(localname, oldname) == 0) {
                  cnn.supset(n, newname, 0, COLLABREATE_ENUMS_TAG);
                  set_struc_name(n, newname);
                  break;
               }
            }
            qfree(oldname);
         }
         qfree(newname);
         break;
      }
      case COMMAND_ENUM_CMT_CHANGED: {
         char *name = b.readUTF8();
         char *cmt = b.readUTF8();
         rep = b.read() ? 1 : 0;
         if (b.has_error()) {
            //old protocol did not send repeatable flag to server
            //which would result in short read above
            rep = false;
         }
         msg("enum cmt changed for enum %s, comment: %s\n", name, cmt);
         enum_t id = get_enum(name);
         if (id == -1) {
#if IDA_SDK_VERSION >= 570
            const_t m = get_enum_member_by_name(name);
            if (m != -1) {
               set_enum_member_cmt(m, cmt, rep);
            }
#endif
         }
         else {
            set_enum_cmt(id, cmt, rep);
         }
         qfree(name);
         qfree(cmt);
         break;
      }
      case COMMAND_ENUM_CONST_CREATED: {
         uval_t value = b.readInt();
         char *ename = b.readUTF8();
         char *mname = b.readUTF8();
         enum_t id = get_enum(ename);
#if IDA_SDK_VERSION >= 570
         add_enum_member(id, mname, value);
#else
         add_const(id, mname, value);
#endif
         qfree(ename);
         qfree(mname);
         break;
      }
      case COMMAND_ENUM_CONST_DELETED: {
         uval_t value = b.readInt();
         bmask_t bmask = b.readInt();
         uchar serial = b.read();
         char *ename = b.readUTF8();
         enum_t id = get_enum(ename);
#if IDA_SDK_VERSION >= 570
         del_enum_member(id, value, serial, bmask);
#else
         del_const(id, value, serial, bmask);
#endif
         qfree(ename);
         break;
      }
      case COMMAND_STRUC_CREATED: {
         //Perhaps should report tid to server in case it is renamed???
         //server maintains tid map
         /*tid_t s1 =*/ b.readInt();   //read the tid (this is actually not used)
         bool is_union = b.read() != 0;
         char *sname = b.readUTF8();
         tid_t s2 = add_struc(BADADDR, sname, is_union);

         //remember the name of the struct in case it is renamed later
         cnn.supset(s2, sname, 0, COLLABREATE_STRUCTS_TAG);
//         msg(PLUGIN_NAME": received COMMAND_STRUC_CREATED message for %s\n", sname);
         qfree(sname);
         break;
      }
      case COMMAND_STRUC_DELETED: {
         char *name = b.readUTF8();
         tid_t t = get_struc_id(name);
         struc_t *s = get_struc(t);
         del_struc(s);
         qfree(name);
         break;
      }
      case COMMAND_STRUC_RENAMED: {
         char localname[MAXNAMESIZE];
         /*tid_t t =*/ b.readInt();   //need to try to map struct id to other instances ID
         char *newname = b.readUTF8();
         char *oldname = b.readUTF8();
         if (oldname) {
            for (nodeidx_t n = cnn.sup1st(COLLABREATE_STRUCTS_TAG);
                    n != BADNODE; n = cnn.supnxt(n, COLLABREATE_STRUCTS_TAG)) {
               cnn.supstr(n, localname, sizeof(localname), COLLABREATE_STRUCTS_TAG);
               if (strcmp(localname, oldname) == 0) {
                  cnn.supset(n, newname, 0, COLLABREATE_STRUCTS_TAG);
                  set_struc_name(n, newname);
                  break;
               }
            }
            qfree(oldname);
         }
         qfree(newname);
         break;
      }
      case COMMAND_STRUC_EXPANDED: {
         /*tid_t s1 =*/ b.readInt();   //send the tid to create map on the server
         char *sname = b.readUTF8();
//         msg(PLUGIN_NAME": received COMMAND_STRUC_EXPANDED message for %s\n", sname);
         //******
         qfree(sname);
         break;
      }
      case COMMAND_STRUC_CMT_CHANGED: {
         char *name = b.readUTF8();
         char *dot = strchr(name, '.');
         if (dot != NULL) {
            *dot++ = '\0';
         }
         tid_t t = get_struc_id(name);
         char *cmt = b.readUTF8();
         rep = b.read() ? 1 : 0;
         if (b.has_error()) {
            //old protocol did not send repeatable flag to server
            //which would result in short read above
            rep = false;
         }
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
         qfree(cmt);
         break;
      }
      case COMMAND_CREATE_STRUC_MEMBER_DATA: {
         ea_t soff = b.readInt();   //not really an address
         flags_t f = b.readInt();
         asize_t sz = b.readInt();
         char *name = b.readUTF8();
         char *mbr = b.readUTF8();
         tid_t t = get_struc_id(name);
         struc_t *s = get_struc(t);
         add_struc_member(s, mbr, soff, f, NULL, sz);
//         msg(PLUGIN_NAME": received COMMAND_CREATE_STRUC_MEMBER_DATA message for %s.%s, offset %d\n", name, mbr, soff);
         qfree(name);
         qfree(mbr);
         break;
      }
      case COMMAND_CREATE_STRUC_MEMBER_STRUCT: {
         char *ti_name = b.readUTF8();
         opinfo_t ti;
         ti.tid = get_struc_id(ti_name);
         /*unsigned long p =*/ b.readInt();    //props
         ea_t soff = b.readInt();   //not really an address
         flags_t f = b.readInt();
         asize_t sz = b.readInt();
         //should send opinfo_t as well
         char *name = b.readUTF8();
         char *mbr = b.readUTF8();
         tid_t t = get_struc_id(name);
         struc_t *s = get_struc(t);
         add_struc_member(s, mbr, soff, f, &ti, sz);
//         msg(PLUGIN_NAME": received COMMAND_CREATE_STRUC_MEMBER_STRUCT message for %s.%s (%s)\n", name, mbr, ti_name);
         qfree(ti_name);
         qfree(name);
         qfree(mbr);
         break;
      }
      case COMMAND_CREATE_STRUC_MEMBER_STR: {
         opinfo_t ti;
         ti.strtype = b.readInt();
         /*unsigned long p =*/ b.readInt();    //props
         ea_t soff = b.readInt();
         flags_t f = b.readInt();
         asize_t sz = b.readInt();
         //should send opinfo_t as well
         char *name = b.readUTF8();
         char *mbr = b.readUTF8();
         tid_t t = get_struc_id(name);
         struc_t *s = get_struc(t);
         add_struc_member(s, mbr, soff, f, &ti, sz);
//         msg(PLUGIN_NAME": received COMMAND_CREATE_STRUC_MEMBER_STR message for %s.%s\n", name, mbr);
         qfree(name);
         qfree(mbr);
         break;
      }
      case COMMAND_CREATE_STRUC_MEMBER_ENUM: {
         char *ti_name = b.readUTF8();
         opinfo_t ti;
         ti.ec.tid = get_struc_id(ti_name);
         ti.ec.serial = b.read();
         /*unsigned long p =*/ b.readInt();    //props
         ea_t soff = b.readInt();
         flags_t f = b.readInt();
         asize_t sz = b.readInt();
         //should send opinfo_t as well
         char *name = b.readUTF8();
         char *mbr = b.readUTF8();
         tid_t t = get_struc_id(name);
         struc_t *s = get_struc(t);
         add_struc_member(s, mbr, soff, f, &ti, sz);
//         msg(PLUGIN_NAME": received COMMAND_CREATE_STRUC_MEMBER_STRUCT message for %s.%s (%s)\n", name, mbr, ti_name);
         qfree(ti_name);
         qfree(name);
         qfree(mbr);
         break;
      }
      case COMMAND_CREATE_STRUC_MEMBER_OFFSET: {
         opinfo_t ti;
         b.read(&ti.ri, sizeof(refinfo_t));
         /*unsigned long p =*/ b.readInt();    //props
         ea_t soff = b.readInt();
         flags_t f = b.readInt();
         asize_t sz = b.readInt();
         //should send opinfo_t as well
         char *name = b.readUTF8();
         char *mbr = b.readUTF8();
         tid_t t = get_struc_id(name);
         struc_t *s = get_struc(t);
         add_struc_member(s, mbr, soff, f, &ti, sz);
//         msg(PLUGIN_NAME": received COMMAND_CREATE_STRUC_MEMBER_OFFSET message for %s.%s (%s)\n", name, mbr, ti_name);
         qfree(name);
         qfree(mbr);
         break;
      }
      case COMMAND_STRUC_MEMBER_DELETED: {
         ea_t off = b.readInt();
         char *name = b.readUTF8();
         tid_t t = get_struc_id(name);
         struc_t *s = get_struc(t);
         del_struc_member(s, off);
         qfree(name);
         break;
      }
      case COMMAND_SET_STACK_VAR_NAME: {
         ea = (ea_t)b.readLong();  //lookup function on remote side
         stk_frame = get_frame(ea);
         ea_t soff = b.readInt();
         char *name = b.readUTF8();
         if (name) {
            set_member_name(stk_frame, soff, name);
         }
         qfree(name);
         break;
      }
      case COMMAND_SET_STRUCT_MEMBER_NAME: {
         ea_t soff = b.readInt();
         char *sname = b.readUTF8();
         char *mname = b.readUTF8();
         if (sname && mname) {
            struc_t *struc = get_struc(get_struc_id(sname));
            set_member_name(struc, soff, mname);
//            msg(PLUGIN_NAME": received COMMAND_SET_STRUCT_MEMBER_NAME message for %s.%s\n", sname, mname);
         }
         qfree(sname);
         qfree(mname);
         break;
      }
      case COMMAND_STRUC_MEMBER_CHANGED_DATA: {
//         tid_t s1 = b.readInt();   //send the tid to create map on the server
         ea_t soff = b.readInt();
         ea_t eoff = b.readInt();
         flags_t flags = b.readInt();
         char *sname = b.readUTF8();
         if (sname) {
            struc_t *s = get_struc(get_struc_id(sname));
            set_member_type(s, soff, flags, NULL, eoff - soff);
         }
//         msg(PLUGIN_NAME": received COMMAND_STRUC_MEMBER_CHANGED_DATA message for %s.%s\n", sname, mname);
         qfree(sname);
         break;
      }
      case COMMAND_STRUC_MEMBER_CHANGED_STRUCT: {
         char *ti_name = b.readUTF8();
         opinfo_t ti;
         ti.tid = get_struc_id(ti_name);
         ea_t soff = b.readInt();
         ea_t eoff = b.readInt();
         flags_t f = b.readInt();
         //should send opinfo_t as well
         char *sname = b.readUTF8();
         if (sname) {
            struc_t *s = get_struc(get_struc_id(sname));
            set_member_type(s, soff, f, &ti, eoff - soff);
         }
//         msg(PLUGIN_NAME": received COMMAND_STRUC_MEMBER_CHANGED_STRUCT message for %s.%d (%s)\n", sname, soff, ti_name);
         qfree(ti_name);
         qfree(sname);
         break;
      }
      case COMMAND_STRUC_MEMBER_CHANGED_STR: {
         opinfo_t ti;
         ti.strtype = b.readInt();
         ea_t soff = b.readInt();
         ea_t eoff = b.readInt();
         flags_t f = b.readInt();
         //should send opinfo_t as well
         char *sname = b.readUTF8();
         if (sname) {
            struc_t *s = get_struc(get_struc_id(sname));
            set_member_type(s, soff, f, &ti, eoff - soff);
         }
//         msg(PLUGIN_NAME": received COMMAND_STRUC_MEMBER_CHANGED_STR message for %s.%d\n", sname, soff);
         qfree(sname);
         break;
      }
      case COMMAND_STRUC_MEMBER_CHANGED_OFFSET: {
         opinfo_t ti;
         b.read(&ti, sizeof(refinfo_t));
         ea_t soff = b.readInt();
         ea_t eoff = b.readInt();
         flags_t f = b.readInt();
         //should send opinfo_t as well
         char *sname = b.readUTF8();
         if (sname) {
            struc_t *s = get_struc(get_struc_id(sname));
            set_member_type(s, soff, f, &ti, eoff - soff);
         }
//         msg(PLUGIN_NAME": received COMMAND_STRUC_MEMBER_CHANGED_STR message for %s.%d\n", sname, soff);
         qfree(sname);
         break;
      }
      case COMMAND_STRUC_MEMBER_CHANGED_ENUM: {
         char *ti_name = b.readUTF8();
         opinfo_t ti;
         ti.ec.tid = get_struc_id(ti_name);
         ti.ec.serial = b.read();
         ea_t soff = b.readInt();
         ea_t eoff = b.readInt();
         flags_t f = b.readInt();
         //should send opinfo_t as well
         char *sname = b.readUTF8();
         if (sname) {
            struc_t *s = get_struc(get_struc_id(sname));
            set_member_type(s, soff, f, &ti, eoff - soff);
         }
//         msg(PLUGIN_NAME": received COMMAND_STRUC_MEMBER_CHANGED_STRUCT message for %s.%d (%s)\n", sname, soff, ti_name);
         qfree(ti_name);
         qfree(sname);
         break;
      }
      case COMMAND_THUNK_CREATED: {
         ea_t startEA = (ea_t)b.readLong();
         func_t *f = get_func(startEA);
         if (f) {
            f->flags |= FUNC_THUNK;
            update_func(f);
         }
         break;
      }
      case COMMAND_FUNC_TAIL_APPENDED: {
         ea_t startEA = (ea_t)b.readLong();
         func_t *f = get_func(startEA);
         ea_t tail_start = (ea_t)b.readLong();
         ea_t tail_end = (ea_t)b.readLong();
         if (f) {
            append_func_tail(f, tail_start, tail_end);
         }
         break;
      }
      case COMMAND_FUNC_TAIL_REMOVED: {
         ea_t startEA = (ea_t)b.readLong();
         func_t *f = get_func(startEA);
         ea_t tail = (ea_t)b.readLong();
         if (f) {
            remove_func_tail(f, tail);
         }
         break;
      }
      case COMMAND_TAIL_OWNER_CHANGED: {
         ea_t startEA = (ea_t)b.readLong();
         func_t *tail = get_func(startEA);
         ea_t owner = (ea_t)b.readLong();
         if (tail) {
            set_tail_owner(tail, owner);
         }
         break;
      }
      case COMMAND_FUNC_NORET_CHANGED: {
         ea_t startEA = (ea_t)b.readLong();
         func_t *f = get_func(startEA);
         if (f) {
            f->flags ^= FUNC_NORET;
            update_func(f);
         }
         break;
      }
      case COMMAND_SEGM_ADDED: {
         segment_t s;
         memset(&s, 0, sizeof(segment_t));
         s.startEA = (ea_t)b.readLong();
         s.endEA = (ea_t)b.readLong();
         s.orgbase = b.readInt();
         s.align= b.read();
         s.comb = b.read();
         s.perm = b.read();
         s.bitness = b.read();
         s.flags = b.readShort();
         s.color = DEFCOLOR;
         char *name = b.readUTF8();
         char *clazz = b.readUTF8();
         add_segm_ex(&s, name, clazz, ADDSEG_QUIET | ADDSEG_NOSREG);
         qfree(name);
         qfree(clazz);
         break;
      }
      case COMMAND_SEGM_DELETED: {
         ea_t ea = (ea_t)b.readLong();
#if IDA_SDK_VERSION < 500
         del_segm(ea, 0);
#elif IDA_SDK_VERSION < 530
         del_segm(ea, SEGDEL_KEEP | SEGDEL_SILENT);
#else
         del_segm(ea, SEGMOD_KEEP | SEGMOD_SILENT);
#endif
         break;
      }
      case COMMAND_SEGM_START_CHANGED: {
         ea_t old_end = (ea_t)b.readLong();
         ea_t new_start = (ea_t)b.readLong();
         set_segm_start(old_end, new_start, 0);
         break;
      }
      case COMMAND_SEGM_END_CHANGED: {
         ea_t old_start = (ea_t)b.readLong();
         ea_t new_end = (ea_t)b.readLong();
         set_segm_start(old_start, new_end, 0);
         break;
      }
      case COMMAND_SEGM_MOVED: {
         ea_t from = (ea_t)b.readLong();
         ea_t to = (ea_t)b.readLong();
         /*asize_t sz =*/ b.readLong();
         segment_t *s = getseg(from);
         move_segm(s, to, MSF_SILENT);
         break;
      }
      case COMMAND_AREA_CMT_CHANGED: {
         unsigned char cbType = b.read();
         areacb_t *cb = NULL;
         if (cbType == AREACB_FUNCS) {
            cb = &funcs;
         }
         else if (cbType == AREACB_SEGS) {
            cb = &segs;
         }
         else {
            break;
         }
         ea = (ea_t)b.readLong();
         area_t *a = cb->get_area(ea);
         if (a) {  //only change comment if we found the area
            bool rep = b.read() != 0;
            char *cmt = b.readUTF8();
            cb->set_area_cmt(a, cmt, rep);
            qfree(cmt);
         }
         break;
      }
      default:
         msg(PLUGIN_NAME": Received unknown command code: %d, ignoring.\n", command);
   }
   return true;
}

//Tell the server the last update that we have received so that
//it can send us all newer updates
void sendLastUpdate() {
   Buffer b;
   b.writeInt(MSG_SEND_UPDATES);
   uint64_t last = getLastUpdate();
   msg(PLUGIN_NAME": Requesting all updates greater than %s\n", formatLongLong(last));
   b.writeLong(last);
   send_data(b);
}

//Process collabREate control messages
void handle_control_msg(Buffer &b, int command) {
   static unsigned char challenge[CHALLENGE_SIZE];
   switch (command) {
      case MSG_INITIAL_CHALLENGE: {
#ifdef DEBUG
         msg(PLUGIN_NAME": Received Auth Challenge\n");
#endif
         if (b.read(challenge, sizeof(challenge))) {
            if (do_auth(challenge, sizeof(challenge)) != 0) {
               cleanup();         //user canceled dialog
            }
         }
         else {
            //challenge too short
         }
         break;
      }
      case MSG_AUTH_REPLY: {
#ifdef DEBUG
         msg(PLUGIN_NAME": in AUTH_REPLY.\n");
#endif
         int reply = b.readInt();
         if (reply == AUTH_REPLY_FAIL) {
            //use saved challenge from initial_challenge message
            if (do_auth(challenge, sizeof(challenge)) != 0) {
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
         break;
      }
      case MSG_PROJECT_LIST: {
#ifdef DEBUG
         msg(PLUGIN_NAME": in PROJECT_LIST\n");
#endif
         if (!do_project_select(b)) {
            cleanup();
         }
         break;
      }
      case MSG_PROJECT_JOIN_REPLY: {
#ifdef DEBUG
         msg(PLUGIN_NAME": in PROJECT_JOIN_REPLY\n");
#endif
         int reply = b.readInt();
         if (reply == JOIN_REPLY_SUCCESS) {
            //we are joined to a project
            unsigned char gpid[GPID_SIZE];
            if (b.read(gpid, sizeof(gpid))) {
               msg(PLUGIN_NAME": Successfully joined project.\n");
               postCollabMessage("Successfully joined project.");
               setGpid(gpid, sizeof(gpid));
               hookAll();
               fork_pending = false;
               clearPendingUpdates();  //delete all pending updates from previous project
               //need to send a MSG_SEND_UPDATES message
               sendLastUpdate();
               if (changeCache != NULL) {
//                  msg("sending change cache of size %d\n", changeCache->size());
                  send_all(*changeCache);
                  delete changeCache;
                  changeCache = NULL;
                  cnn.delblob(1, COLLABREATE_CACHE_TAG);
               }
            }
            else {
               msg(PLUGIN_NAME": Project join failed, server sent bad GPID.\n");
               //is this a "HARD" error condition?  without this it's impossible to re-join later
               //gpid too short
            }
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
         break;
      }
      case MSG_PROJECT_SNAPSHOT_REPLY: {
#ifdef DEBUG
         msg(PLUGIN_NAME": in PROJECT_SNAPSHOT_REPLY\n");
#endif
         int reply = b.readInt();
         if (reply == MSG_PROJECT_SNAPSHOT_SUCCESS) {
            msg(PLUGIN_NAME": project snapshot success!\n");
            postCollabMessage("Project snapshot success!");
         }
         else {
            msg(PLUGIN_NAME": project snapshot failed.\n");
         }
         break;
      }
      case MSG_PROJECT_FORK_FOLLOW: {
#ifdef DEBUG
         msg(PLUGIN_NAME": in PROJECT_FORK_FOLLOW\n");
#endif
         unsigned char gpid[GPID_SIZE];
         char *user = b.readUTF8();
         b.read(gpid, sizeof(gpid));
         uint64_t lastupdateid = b.readLong();
         char *desc = b.readUTF8();

         //check to make sure this idb is in the correct state to follow the fork
         if (lastupdateid == getLastUpdate()) {
#ifdef DEBUG
            msg(PLUGIN_NAME": user %s forked at 0x%s to new project: %s\n", user, formatLongLong(lastupdateid), desc);
            //msg(PLUGIN_NAME": would you like to follow the forked project? Y/N");
#endif
            if (askbuttons_c("Yes","No","",0,"User %s forked to a new project: %s, would you like to follow?",user,desc) == 1) {
               msg(PLUGIN_NAME": join new project\n");
               do_project_leave();
               setGpid(gpid, sizeof(gpid));
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
         qfree(desc);
         qfree(user);
         break;
      }
      case MSG_GET_REQ_PERMS_REPLY: {
#ifdef DEBUG
         msg(PLUGIN_NAME": Got a GET_REQ_PERMS_REPLY\n");
#endif
         do_get_req_perms(b);
         break;
      }
      case MSG_SET_REQ_PERMS_REPLY: {
#ifdef DEBUG
         msg(PLUGIN_NAME": Got a SET_REQ_PERMS_REPLY now what?\n"); //TMV
#endif
         break;
      }
      case MSG_GET_PROJ_PERMS_REPLY: {
#ifdef DEBUG
         msg(PLUGIN_NAME": Got a GET_PROJ_PERMS_REPLY\n");
#endif
         do_get_proj_perms(b);
         break;
      }
      case MSG_SET_PROJ_PERMS_REPLY: {
#ifdef DEBUG
         msg(PLUGIN_NAME": Got a SET_PROJ_PERMS_REPLY now what?\n");
#endif
         break;
      }

      case MSG_ACK_UPDATEID: {
         //msg(PLUGIN_NAME": in ACK_UPDATEID \n");
         uint64_t updateid = b.readLong();
#ifdef DEBUG
         msg(PLUGIN_NAME": got updateid: %s\n", formatLongLong(updateid));
#endif
         setLastUpdate(updateid);
         break;
      }
      case MSG_AUTH_REQUEST:  //client should never receive this
      case MSG_PROJECT_JOIN_REQUEST:  //client should never receive this
      case MSG_PROJECT_NEW_REQUEST:  //client should never receive this
      case MSG_SEND_UPDATES:  //client should never receive this
      case MSG_GET_REQ_PERMS:
      case MSG_SET_REQ_PERMS:
      case MSG_GET_PROJ_PERMS:
      case MSG_SET_PROJ_PERMS:
         msg(PLUGIN_NAME": Error! Plugin recieved a server message: %d\n", command);
         break;
      case MSG_ERROR: {
         char *error_msg = b.readUTF8();
         msg(PLUGIN_NAME": error: %s\n", error_msg);
         qfree(error_msg);
         break;
      }
      case MSG_FATAL: {
         char *error_msg = b.readUTF8();
         msg(PLUGIN_NAME": fatal error: %s\n", error_msg);
         warning("%s", error_msg);
         qfree(error_msg);
         authenticated = false;
         cleanup();
         break;
      }
      default: {
         msg(PLUGIN_NAME": unkown message type: 0x%x\n", command);
      }
   }
}

/*
 * Main dispatch routine for received remote notifications
 */
bool msg_dispatcher(Buffer &b) {
   int command = b.readInt();
#ifdef DEBUG
   msg(PLUGIN_NAME": msg_dispatcher called for command: %d\n", command);
#endif
   if (command >= MSG_CONTROL_FIRST) {
#ifdef DEBUG
   msg(PLUGIN_NAME": msg_dispatcher dispatching a control command\n");
#endif
      handle_control_msg(b, command);
   }
   else if (subscribe) {
#ifdef DEBUG
      msg(PLUGIN_NAME": msg_dispatcher subscribe is true\n");
#endif
      if (fork_pending) {
         queueUpdate(b);
      }
      else {
         uint64_t updateid = b.readLong();
#ifdef DEBUG
         msg(PLUGIN_NAME": Received command %d, updateid 0x%s, b.size() %d\n", command, formatLongLong(updateid), b.size());
#endif
         stats[0][command]++;
         //this prevents notifying ourselves of the incoming update
         unhookAll();
//         publish = false;
         if (command == COMMAND_USER_MESSAGE) {
            time_t t = b.readInt();
            char *msg = b.readUTF8();
            postCollabMessage(msg, t);
            qfree(msg);
         }
         else {
            //supress = true;  //don't want to regenerate this message as we apply the update
            if (command < COMMAND_IDP) {
               handle_idb_msg(b, command);
            }
            else {
               handle_idp_msg(b, command);
            }
//           supress = false;
//           publish = userPublish;
//           publish = autoIsOk() == 1 ? userPublish : 0;
         }
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
   return true;
}

//Given a frame pointer, determine which if any function owns it.
//This is a reverse lookup on stack frame structures
func_t *func_from_frame(struc_t *frame) {
   size_t qty = get_func_qty();
   for (size_t i = 0; i < qty; i++) {
      func_t *f = getn_func(i);
      if (f->frame == frame->id) return f;
   }
   return NULL;
}

void comment_changed(ea_t ea, bool rep) {
   ssize_t ssz = get_cmt(ea, rep, NULL, 0) + 1;
   if (ssz != -1) {
      size_t sz = (size_t)ssz;
      char *cmt = (char*) qalloc(sz);
      if (cmt || sz == 0) {
         if (sz) {
            get_cmt(ea, rep, cmt, sz);
         }
         //send comment to server
         Buffer b;
         b.writeInt(COMMAND_CMT_CHANGED);
         b.writeLong(ea);
         b.write(&rep, 1);
         if (sz) {
            b.writeUTF8(cmt);
         }
         else {
            b.writeShort(0);   //send zero length string
         }
         if (send_data(b) == -1) {
            msg(PLUGIN_NAME": send error on comment_changed %x, %s\n", (uint32_t)ea, cmt);
         }
         qfree(cmt);
      }
   }
}

void byte_patched(ea_t ea) {
   Buffer b;
   int val = get_byte(ea);
   //send value to server
   b.writeInt(COMMAND_BYTE_PATCHED);
   b.writeLong(ea);
   b.writeInt(val);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on byte_patched %x, %x\n", (uint32_t)ea, val);
   }
}

void change_ti(ea_t ea, const type_t *type, const p_list *fnames) {
   Buffer b;
   b.writeInt(COMMAND_TI_CHANGED);
   b.writeLong(ea);
   b.writeUTF8((const char*)type);
   b.writeUTF8((const char*)fnames);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on change_ti %x\n", (uint32_t)ea);
   }
}

void change_op_ti(ea_t ea, int n, const type_t *type, const p_list *fnames) {
   Buffer b;
   b.writeInt(COMMAND_OP_TI_CHANGED);
   b.writeLong(ea);
   b.writeInt(n);
   b.writeUTF8((const char*)type);
   b.writeUTF8((const char*)fnames);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on change_op_ti %x\n", (uint32_t)ea);
   }
}

//lookup structure offset info about operand n at address ea and
//add the information into the provided buffer
void gatherStructOffsetInfo(Buffer &b, ea_t ea, int n) {
   qstring name;
   tid_t path[MAXSTRUCPATH];
   adiff_t delta;
   int path_len = get_stroff_path(ea, n, path, &delta);
   b.writeInt(path_len);
   b.writeLong(delta);
   //iterate over the structure path, adding the name of each struct
   //the the provided buffer.  We pass names here rather than tid
   //because different versions of IDA may assign different tid values
   //the the same struct type
   for (int i = 0; i < path_len; i++) {
	  name = get_struc_name(path[i]);
      b.writeUTF8(name.c_str());
   }
}

//lookup enum type info about operand n at address ea and
//add the information into the provided buffer
void gatherEnumInfo(Buffer &b, ea_t ea, int n) {
   qstring name;
   uchar serial;
   enum_t id = get_enum_id(ea, n, &serial);
   ssize_t len = get_enum_name(&name, id);
   if (len > 0) {
      //We pass a name here rather than enum_t because different
      //versions of IDA may assign different enum_t values
      //the the same enum type
      b.writeUTF8(name.c_str());
      b.write(serial);
   }
}

void gatherRefInfo(Buffer &b, refinfo_t &ri) {
   b.writeInt(ri.flags);
   b.writeLong(ri.target);
   b.writeLong(ri.base);
   b.writeLong(ri.tdelta);
}

void change_op_type(ea_t ea, int n) {
   Buffer b, extra;
   //send value to server
   flags_t f = get_flags_novalue(ea);
   if (n) {
      if (n != 1) {
         msg("change_op_type n == %d unexpected\n", n);
         return;
      }
      f = get_optype_flags1(f);
      if (isEnum1(f)) {
         //need to figure out what enum it is
         gatherEnumInfo(extra, ea, n);
      }
      else if (isStroff1(f)) {
         //need to figure out what struct it is
         gatherStructOffsetInfo(extra, ea, n);
      }
      else if (isOff1(f)) {
         refinfo_t ri;
         if (!get_refinfo(ea, n, &ri)) {
            msg(PLUGIN_NAME": missing refinfo on offset in change_op_type %x, %x", (uint32_t)ea, n);
            return;
         }
         if (ri.type() != REF_OFF32 || ri.target != BADADDR ||
                ri.base != 0 || ri.tdelta != 0) {
            gatherRefInfo(extra, ri);
         }
      }
   }
   else {
      f = get_optype_flags0(f);
      if (isEnum0(f)) {
         //need to figure out what enum it is
         gatherEnumInfo(extra, ea, n);
      }
      else if (isStroff0(f)) {
         //need to figure out what struct it is
         gatherStructOffsetInfo(extra, ea, n);
      }
      else if (isOff0(f)) {
         refinfo_t ri;
         if (!get_refinfo(ea, n, &ri)) {
            msg(PLUGIN_NAME": missing refinfo on offset in change_op_type %x, %x", (uint32_t)ea, n);
            return;
         }
         if (ri.type() != REF_OFF32 || ri.target != BADADDR ||
                ri.base != 0 || ri.tdelta != 0) {
            gatherRefInfo(extra, ri);
         }
      }
   }
   b.writeInt(COMMAND_OP_TYPE_CHANGED);
   b.writeLong(ea);
   b.writeInt(n);
   b.writeInt(f);
   b << extra;           //append any additional type specific info
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on change_op_type %x, %x, %x\n", (uint32_t)ea, n, f);
   }
}

void create_enum(enum_t id) {
   //get enum name (and fields?) and send to server
   Buffer b;
   qstring name;
   ssize_t sz = get_enum_name(&name, id);
   if (sz > 0) {
      b.writeInt(COMMAND_ENUM_CREATED);
      b.writeUTF8(name.c_str());
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on create_enum %s\n", name);
      }
      cnn.supset(id, name.c_str(), 0, COLLABREATE_ENUMS_TAG);
   }
}

void delete_enum(enum_t id) {
   //get enum name and send to server
   Buffer b;
   qstring name;
   ssize_t sz = get_enum_name(&name, id);
   if (sz > 0) {
      b.writeInt(COMMAND_ENUM_DELETED);
      b.writeUTF8(name.c_str());
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on delete_enum %s\n", name);
      }
      cnn.supdel(id, COLLABREATE_ENUMS_TAG);
   }
}

/***
 * NOT HANDLING THIS YET
 ***/
void change_enum_bf(enum_t id) {
   Buffer b;
   qstring name;
   ssize_t sz = get_enum_name(&name, id);
   if (sz > 0) {
      b.writeInt(COMMAND_ENUM_BF_CHANGED);
      b.writeUTF8(name.c_str());
/*
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on change_enum %s\n", name);
      }
*/
   }
}

void rename_enum(tid_t t) {
   Buffer b;
   qstring newname;
   char oldname[MAXNAMESIZE];
   ssize_t sz = get_enum_name(&newname, t);
   ssize_t len = cnn.supstr(t, oldname, sizeof(oldname), COLLABREATE_ENUMS_TAG);
   if (sz > 0 && len > 0) {
      b.writeInt(COMMAND_ENUM_RENAMED);
      b.writeUTF8(newname.c_str());
      b.writeUTF8(oldname);
      cnn.supset(t, newname.c_str(), 0, COLLABREATE_ENUMS_TAG);
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on rename_enum %s\n", newname);
      }
   }
}

void change_enum_cmt(tid_t t, bool rep) {
   Buffer b;
   qstring name;
   char cmt[MAXNAMESIZE];
   ssize_t sz = get_enum_name(&name, t);
   /*ssize_t csz =*/ get_enum_cmt(t, rep, cmt, sizeof(cmt));
   if (sz > 0) {
      b.writeInt(COMMAND_ENUM_CMT_CHANGED);
      b.writeUTF8(name.c_str());
      b.writeUTF8(cmt);
      b.write(&rep, 1);
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on change_enum_cmt %s\n", name);
      }
   }
}

void create_enum_member(enum_t id, const_t cid) {
   //get enum name and member name/val and send to server
   Buffer b;
#if IDA_SDK_VERSION >= 570
   uval_t value = get_enum_member_value(cid);
#else
   uval_t value = get_const_value(cid);
#endif
   qstring ename = get_enum_name(id);
   qstring mname;
#if IDA_SDK_VERSION >= 570
   get_enum_member_name(&mname, cid);
#else
   get_const_name(cid, mname, MAXNAMESIZE);
#endif
   b.writeInt(COMMAND_ENUM_CONST_CREATED);
   b.writeInt((int)value);
   b.writeUTF8(ename.c_str());
   b.writeUTF8(mname.c_str());
   send_data(b);
}

void delete_enum_member(enum_t id, const_t cid) {
   //get enum name and member name/val and send to server
   Buffer b;
#if IDA_SDK_VERSION >= 570
   uval_t value = get_enum_member_value(cid);
   bmask_t bmask = get_enum_member_bmask(cid);
   uchar serial = get_enum_member_serial(cid);
#else
   uval_t value = get_const_value(cid);
   bmask_t bmask = get_const_bmask(cid);
   uchar serial = get_const_serial(cid);
#endif
   qstring ename = get_enum_name(id);
   b.writeInt(COMMAND_ENUM_CONST_DELETED);
   b.writeInt((int)value);
   b.writeInt((int)bmask);
   b.write(serial);
   b.writeUTF8(ename.c_str());
   send_data(b);
}

void create_struct(tid_t t) {
   //get struct name (and fields?) and send to server
   Buffer b;
   qstring name;
   ssize_t sz = get_struc_name(&name, t);
   if (sz > 0) {
      struc_t *s = get_struc(t);
      b.writeInt(COMMAND_STRUC_CREATED);
      b.writeInt((int)t);   //send the tid to create map on the server
      b.write(s->is_union());
      b.writeUTF8(name.c_str());
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on create_struct %s\n", name);
      }
      //remember the name of the struct in case it is renamed later
      cnn.supset(t, name.c_str(), 0, COLLABREATE_STRUCTS_TAG);
   }
}

void delete_struct(tid_t s) {
   //get struct name and send to server
   Buffer b;
   qstring name;
   ssize_t sz = get_struc_name(&name, s);
   if (sz > 0) {
      b.writeInt(COMMAND_STRUC_DELETED);
      b.writeUTF8(name.c_str());
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on delete_struct %s\n", name);
      }
   }
}

void rename_struct(struc_t *s) {
   //get struct name (and fields?) and send to server
   //how do we know old struct name
   Buffer b;
   qstring newname;
   char oldname[MAXNAMESIZE];
   ssize_t sz = get_struc_name(&newname, s->id);
   ssize_t len = cnn.supstr(s->id, oldname, sizeof(oldname), COLLABREATE_STRUCTS_TAG);
   if (sz > 0 && len > 0) {
      b.writeInt(COMMAND_STRUC_RENAMED);
      //tids are never guaranteed to map beween any two IDBs
      b.writeInt((int)s->id);   //need to try to map struct id to other instances ID
      b.writeUTF8(newname.c_str());
      b.writeUTF8(oldname);
      cnn.supset(s->id, newname.c_str(), 0, COLLABREATE_STRUCTS_TAG);
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on rename_struct %s\n", newname);
      }
   }
}

void expand_struct(struc_t *s) {
   //what info to send to indicate expansion?
   Buffer b;
   qstring name;
   ssize_t sz = get_struc_name(&name, s->id);
   if (sz > 0) {
#ifdef DEBUG
      msg(PLUGIN_NAME": struct %s has been expanded\n", name);
#endif
      b.writeInt(COMMAND_STRUC_EXPANDED);
      b.writeInt((int)s->id);   //need to try to map struct id to other instances ID
      b.writeUTF8(name.c_str());
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on rename_struct %s\n", name);
      }
   }
}

void change_struc_cmt(tid_t t, bool rep) {
   Buffer b;
   char cmt[MAXNAMESIZE];
   qstring name = get_struc_name(t);
   
   /*ssize_t csz =*/ get_struc_cmt(t, rep, cmt, sizeof(cmt));
   b.writeInt(COMMAND_STRUC_CMT_CHANGED);
   b.writeUTF8(name.c_str());
   b.writeUTF8(cmt);
   b.write(&rep, 1);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on change_struc_cmt %s\n", name);
   }
}

void create_struct_member(struc_t *s, member_t *m) {
   //get struct name and member name/offs and send to server
   Buffer b;
   opinfo_t ti, *pti;
   qstring mbr;
   qstring name;

   pti = retrieve_member_info(m, &ti);
/*
   msg(PLUGIN_NAME": create_struct_member, tid %x\n", m->id);
   netnode mn(m->id);
   for (nodeidx_t i = mn.alt1st(); i != BADNODE; i = mn.altnxt(i)) {
      msg(PLUGIN_NAME": create_struct_member %x.altval[%d] == %d\n", m, i, mn.altval(i));
   }
*/
   if (pti) {
      //in this case, we need to send the ti info in some manner
      if (isStruct(m->flag)) {
         b.writeInt(COMMAND_CREATE_STRUC_MEMBER_STRUCT);
         /*ssize_t tsz =*/ name = get_struc_name(ti.tid);
         b.writeUTF8(name.c_str());
      }
      else if (isASCII(m->flag)) {
         b.writeInt(COMMAND_CREATE_STRUC_MEMBER_STR);
         b.writeInt(ti.strtype);
      }

      else if (isOff0(m->flag) || isOff1(m->flag)) {
         b.writeInt(COMMAND_CREATE_STRUC_MEMBER_OFFSET);
         b.write(&ti.ri, sizeof(refinfo_t));
      }
      else if (isEnum0(m->flag) || isEnum1(m->flag)) {
         b.writeInt(COMMAND_CREATE_STRUC_MEMBER_ENUM);
         /*ssize_t tsz =*/ name = get_struc_name(ti.ec.tid);
         b.writeUTF8(name.c_str());
         b.write(ti.ec.serial);
      }
      else {
         //need a command to write in this case??
         //is it even possible to have refinfo_t, strpath_t, or enum_const_t here?
         msg(PLUGIN_NAME": create_struct_member at unknown typeinfo\n");
         msg(PLUGIN_NAME": create_struct_member flags = %x, props = %x\n", m->flag, m->props);
         return;  //don't know how to handle this type yet
      }
      b.writeInt(m->props);
   }
   else {
      b.writeInt(COMMAND_CREATE_STRUC_MEMBER_DATA);
   }

   b.writeInt((int)(m->unimem() ? 0 : m->soff));
   b.writeInt(m->flag);
   b.writeInt((int)(m->unimem() ? m->eoff : (m->eoff - m->soff)));

   //should send opinfo_t as well
   /*ssize_t ssz =*/ name = get_struc_name(s->id);
   /*ssize_t msz =*/ mbr = get_member_name2(m->id);
   b.writeUTF8(name.c_str());
   b.writeUTF8(mbr.c_str());
//   msg(PLUGIN_NAME": create_struct_member %s.%s off: %d, sz: %d\n", name, mbr, m->soff, m->eoff - m->soff);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on create_struct_member %s\n", name);
   }
}

void delete_struct_member(struc_t *s, tid_t /*m*/, ea_t offset) {
   //get struct name and member name/offs and send to server
   Buffer b;
   qstring name = get_struc_name(s->id);
//   msg(PLUGIN_NAME": delete_struct_member %s, tid %x, offset %x\n", name, m, offset);
   b.writeInt(COMMAND_STRUC_MEMBER_DELETED);
   b.writeInt((int)offset);
   b.writeUTF8(name.c_str());
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on delete_struct_member %s\n", name);
   }
}

void rename_struct_member(struc_t *s, member_t *m) {
   //get struct name and member name/offs and send to server
   Buffer b;
   func_t *pfn = func_from_frame(s);
   if (pfn) {
//   if (s->props & SF_FRAME) {   //SF_FRAME is only available in SDK520 and later
//      func_t *pfn = func_from_frame(s);
      //send func ea, member offset, name
      qstring name = get_member_name2(m->id);
      b.writeInt(COMMAND_SET_STACK_VAR_NAME);
      b.writeLong(pfn->startEA);  //lookup function on remote side
      b.writeInt((int)m->soff);
      b.writeUTF8(name.c_str());
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on rename_stack_member %x, %x, %s\n", (uint32_t)pfn->startEA, (uint32_t)m->soff, name);
      }
   }
   else {
      //send struct name and member name and offset
	  qstring sname = get_struc_name(s->id);
	  qstring mname = get_member_name2(m->id);
      b.writeInt(COMMAND_SET_STRUCT_MEMBER_NAME);
      b.writeInt((int)m->soff);
      b.writeUTF8(sname.c_str());
      b.writeUTF8(mname.c_str());
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on rename_struct_member %x, %s, %s\n", (uint32_t)m->soff, sname, mname);
      }
   }
}

void change_struct_member(struc_t *s, member_t *m) {
   //what exactly constitutes a change? what info to send?
   //get struct name and member name/offs and send to server
   Buffer b;
   opinfo_t ti, *pti;
   qstring name;

   pti = retrieve_member_info(m, &ti);

   if (pti) {
      //in this case, we need to send the ti info in some manner
      if (isStruct(m->flag)) {
         b.writeInt(COMMAND_STRUC_MEMBER_CHANGED_STRUCT);
         /*ssize_t tsz =*/ name = get_struc_name(ti.tid);
         b.writeUTF8(name.c_str());
      }
      else if (isASCII(m->flag)) {
         b.writeInt(COMMAND_STRUC_MEMBER_CHANGED_STR);
         b.writeInt(ti.strtype);
      }
      else if (isOff0(m->flag) || isOff1(m->flag)) {
         b.writeInt(COMMAND_STRUC_MEMBER_CHANGED_OFFSET);
         b.write(&ti.ri, sizeof(refinfo_t));
      }
      else if (isEnum0(m->flag) || isEnum1(m->flag)) {
         b.writeInt(COMMAND_STRUC_MEMBER_CHANGED_ENUM);
         /*ssize_t tsz =*/ name = get_struc_name(ti.ec.tid);
         b.writeUTF8(name.c_str());
         b.write(ti.ec.serial);
      }
      else {
         //need a command to write in this case??
         //is it even possible to have refinfo_t, strpath_t, or enum_const_t here?
         msg(PLUGIN_NAME": change_struct_member at unknown typeinfo\n");
         msg(PLUGIN_NAME": change_struct_member flags = %x, props = %x\n", m->flag, m->props);

         //simply return since we don't know what to write yet.  FIX THIS
         return;
      }
   }
   else {
      b.writeInt(COMMAND_STRUC_MEMBER_CHANGED_DATA);
   }

   b.writeInt((int)(m->unimem() ? 0 : m->soff));
   b.writeInt((int)m->eoff);
   b.writeInt(m->flag);

   //should send opinfo_t as well
   /*ssize_t ssz =*/ name = get_struc_name(s->id);
   b.writeUTF8(name.c_str());
//   msg(PLUGIN_NAME": create_struct_member %s.%s off: %d, sz: %d\n", name, mbr, m->soff, m->eoff - m->soff);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on create_struct_member %s\n", name);
   }
}

void create_thunk(func_t *pfn) {
   Buffer b;
   b.writeInt(COMMAND_THUNK_CREATED);
   b.writeLong(pfn->startEA);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on create_thunk %x\n", (uint32_t)pfn->startEA);
   }
}

void append_func_tail(func_t *pfn, func_t *tail) {
   Buffer b;
   b.writeInt(COMMAND_FUNC_TAIL_APPENDED);
   b.writeLong(pfn->startEA);
   b.writeLong(tail->startEA);
   b.writeLong(tail->endEA);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on append_func_tail %x, %x\n", (uint32_t)pfn->startEA, (uint32_t)tail->startEA);
   }
}

void remove_function_tail(func_t *pfn, ea_t ea) {
   Buffer b;
   b.writeInt(COMMAND_FUNC_TAIL_REMOVED);
   b.writeLong(pfn->startEA);
   b.writeLong(ea);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on remove_function_tail %x, %x\n", (uint32_t)pfn->startEA, (uint32_t)ea);
   }
}

void change_tail_owner(func_t *tail, ea_t ea) {
   Buffer b;
   b.writeInt(COMMAND_TAIL_OWNER_CHANGED);
   b.writeLong(tail->startEA);
   b.writeLong(ea);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on change_tail_owner %x, %x\n", (uint32_t)tail->startEA, (uint32_t)ea);
   }
}

void change_func_noret(func_t *pfn) {
   Buffer b;
   b.writeInt(COMMAND_FUNC_NORET_CHANGED);
   b.writeLong(pfn->startEA);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on change_func_noret %d\n", (uint32_t)pfn->startEA);
   }
}

void add_segment(segment_t *seg) {
   Buffer b;
   char name[MAXNAMESIZE];
   char clazz[MAXNAMESIZE];
   b.writeInt(COMMAND_SEGM_ADDED);
   b.writeLong(seg->startEA);
   b.writeLong(seg->endEA);
   b.writeInt((int)seg->orgbase);
   b.write(seg->align);
   b.write(seg->comb);
   b.write(seg->perm);
   b.write(seg->bitness);
   b.writeShort(seg->flags);
   get_segm_name(seg, name, sizeof(name));
   b.writeUTF8(name);
   get_segm_class(seg, clazz, sizeof(clazz));
   b.writeUTF8(clazz);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on add_segment %d\n", (uint32_t)seg->startEA);
   }
}

void del_segment(ea_t ea) {
   Buffer b;
   b.writeInt(COMMAND_SEGM_DELETED);
   b.writeLong(ea);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on del_segment %d\n", (uint32_t)ea);
   }
}

void change_seg_start(segment_t *seg) {
   Buffer b;
   b.writeInt(COMMAND_SEGM_START_CHANGED);
   b.writeLong(seg->endEA);     //old end
   b.writeLong(seg->startEA);   //new start
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on change_seg_start\n");
   }
}

void change_seg_end(segment_t *seg) {
   Buffer b;
   b.writeInt(COMMAND_SEGM_END_CHANGED);
   b.writeLong(seg->startEA);     //old start
   b.writeLong(seg->endEA);   //new end
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on change_seg_end\n");
   }
}

void move_segment(ea_t from, ea_t to, asize_t sz) {
   Buffer b;
   b.writeInt(COMMAND_SEGM_MOVED);
   b.writeLong(from);
   b.writeLong(to);
   b.writeLong(sz);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on move_segment\n");
   }
}

void change_area_comment(areacb_t *cb, const area_t *a, const char *cmt, bool rep) {
   Buffer b;
   int cbType = 0;
   if (cb == &funcs) {
      cbType = AREACB_FUNCS;
   }
   else if (cb == &segs) {
      cbType = AREACB_SEGS;
   }
   else {
      msg(PLUGIN_NAME": unknown areacb_t in change_area_comment\n");
      return;
   }
   b.writeInt(COMMAND_AREA_CMT_CHANGED);
   b.write(cbType);
   b.writeLong(a->startEA);
   b.write(&rep, 1);
   b.writeUTF8(cmt);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on change_area_comment %x, %s\n", (uint32_t)a->startEA, cmt);
   }
}

//notification hook function for idb notifications
#if IDA_SDK_VERSION >= 510      //HT_IDB introduced in SDK 510
int idaapi idb_hook(void * /*user_data*/, int notification_code, va_list va) {
   if (!userPublish) {
      //should only be called if we are publishing
      return 0;
   }
   //some efforts to stop generating extra messages in response to updates
   //so far all have failed
/*
   if (auto_display.state != st_Ready) {
      return 0;
   }
   if (!publish) {
      //should only be called if we are publishing
      return 0;
   }
*/
/*
   if (supress) {
      //don't generate a database message
      return 0;
   }
*/
//   msg("entering idb::%d (%s)\n", notification_code, notification_code < 60 ? idb_messages[notification_code] : "?");
//   publish = false;
   switch (notification_code) {
      case idb_event::byte_patched: {          // A byte has been patched
                                               // in: ea_t ea
         ea_t ea = va_arg(va, ea_t);
         byte_patched(ea);
         break;
      }
      case idb_event::cmt_changed: {           // An item comment has been changed
                                               // in: ea_t ea, bool repeatable_cmt
         ea_t ea = va_arg(va, ea_t);
         bool rep = va_arg(va, int) != 0;
         comment_changed(ea, rep);
         break;
      }
      case idb_event::ti_changed: {            // An item typestring (c/c++ prototype) has been changed
                                               // in: ea_t ea, const type_t *type, const p_list *fnames
         ea_t ea = va_arg(va, ea_t);
         const type_t *type = va_arg(va, const type_t*);
         const p_list *fnames = va_arg(va, const p_list*);
         change_ti(ea, type, fnames);
         break;
      }
      case idb_event::op_ti_changed: {          // An operand typestring (c/c++ prototype) has been changed
                                                // in: ea_t ea, int n, const type_t *type, const p_list *fnames
         ea_t ea = va_arg(va, ea_t);
         int n = va_arg(va, int);
         const type_t *type = va_arg(va, const type_t*);
         const p_list *fnames = va_arg(va, const p_list*);
         change_op_ti(ea, n, type, fnames);
         break;
      }
      case idb_event::op_type_changed: {       // An operand type (offset, hex, etc...) has been changed
                                               // in: ea_t ea, int n
         ea_t ea = va_arg(va, ea_t);
         int n = va_arg(va, int);
         change_op_type(ea, n);
         break;
      }
      case idb_event::enum_created: {          // A enum type has been created
                                               // in: enum_t id
         enum_t id = va_arg(va, enum_t);
         create_enum(id);
         break;
      }
      case idb_event::enum_deleted: {          // A enum type has been deleted
                                               // in: enum_t id
         enum_t id = va_arg(va, enum_t);
         delete_enum(id);
         break;
      }
      case idb_event::enum_bf_changed: {       // A enum type 'bitfield' attribute has been cha
                                               // in: enum_t id
         enum_t id = va_arg(va, enum_t);
         change_enum_bf(id);
         break;
      }
      case idb_event::enum_renamed: {          // A enum or member has been renamed
                                               // in: tid_t id
         tid_t t = va_arg(va, tid_t);
         rename_enum(t);
         break;
      }
      case idb_event::enum_cmt_changed: {      // A enum or member type comment has been change
                                               // in: tid_t id, bool repeatable
         tid_t t = va_arg(va, tid_t);
#if IDA_SDK_VERSION < 540
         bool rep = false;
#else
         bool rep = va_arg(va, int) != 0;
#endif
         change_enum_cmt(t, rep);
         break;
      }
#if IDA_SDK_VERSION >= 570
      case idb_event::enum_member_created: {
#else
      case idb_event::enum_const_created: {    // A enum member has been created
                                               // in: enum_t id: const_t cid
#endif
         enum_t id = va_arg(va, enum_t);
         const_t cid = va_arg(va, const_t);
         create_enum_member(id, cid);
         break;
      }
#if IDA_SDK_VERSION >= 570
      case idb_event::enum_member_deleted: {
#else
      case idb_event::enum_const_deleted: {    // A enum member has been deleted
                                               // in: enum_t id: const_t cid
#endif
         enum_t id = va_arg(va, enum_t);
         const_t cid = va_arg(va, const_t);
         delete_enum_member(id, cid);
         break;
      }
      case idb_event::struc_created: {         // A new structure type has been created
                                               // in: tid_t struc_id
         tid_t t = va_arg(va, tid_t);
         create_struct(t);
         break;
      }
      case idb_event::struc_deleted: {         // A structure type has been deleted
                                               // in: tid_t struc_id
         tid_t t = va_arg(va, tid_t);
         delete_struct(t);
         break;
      }
      case idb_event::struc_renamed: {         // A structure type has been renamed
                                               // in: struc_t *sptr
         struc_t *struc = va_arg(va, struc_t*);
         rename_struct(struc);
         break;
      }
      case idb_event::struc_expanded: {        // A structure type has been expanded/shrank
                                               // in: struc_t *sptr
         struc_t *struc = va_arg(va, struc_t*);
         expand_struct(struc);
         break;
      }
      case idb_event::struc_cmt_changed: {     // A structure type comment has been changed
                                               // in: tid_t struc_id, bool repeatable
         tid_t t = va_arg(va, tid_t);
#if IDA_SDK_VERSION < 540
         bool rep = false;
#else
         bool rep = va_arg(va, int) != 0;
#endif
         change_struc_cmt(t, rep);
         break;
      }
      case idb_event::struc_member_created: {  // A structure member has been created
                                               // in: struc_t *sptr, member_t *mptr
         struc_t *struc = va_arg(va, struc_t*);
         member_t *m = va_arg(va, member_t*);
         create_struct_member(struc, m);
         break;
      }
      case idb_event::struc_member_deleted: {  // A structure member has been deleted
                                               // in: struc_t *sptr, tid_t member_id
         struc_t *struc = va_arg(va, struc_t*);
         tid_t t = va_arg(va, tid_t);
         ea_t offs = va_arg(va, ea_t);
         delete_struct_member(struc, t, offs);
         break;
      }
      case idb_event::struc_member_renamed: {  // A structure member has been renamed
                                               // in: struc_t *sptr, member_t *mptr
         //this receives notifications for stack frames, structure names for
         //stack frames look like  "$ frN"  where N varies by function
         struc_t *struc = va_arg(va, struc_t*);
         member_t *m = va_arg(va, member_t*);
         rename_struct_member(struc, m);
         break;
      }
      case idb_event::struc_member_changed: {  // A structure member has been changed
                                               // in: struc_t *sptr, member_t *mptr
         struc_t *struc = va_arg(va, struc_t*);
         member_t *m = va_arg(va, member_t*);
         change_struct_member(struc, m);
         break;
      }
      case idb_event::thunk_func_created: {    // A thunk bit has been set for a function
                                               // in: func_t *pfn
         func_t *pfn = va_arg(va, func_t*);
         create_thunk(pfn);
         break;
      }
      case idb_event::func_tail_appended: {    // A function tail chunk has been appended
                                               // in: func_t *pfn, func_t *tail
         func_t *pfn = va_arg(va, func_t*);
         func_t *tail = va_arg(va, func_t*);
         append_func_tail(pfn, tail);
         break;
      }
      case idb_event::func_tail_removed: {     // A function tail chunk has been removed
                                               // in: func_t *pfn, ea_t tail_ea
         func_t *pfn = va_arg(va, func_t*);
         ea_t ea = va_arg(va, ea_t);
         remove_function_tail(pfn, ea);
         break;
      }
      case idb_event::tail_owner_changed: {    // A tail chunk owner has been changed
                                               // in: func_t *tail, ea_t owner_func
         func_t *tail = va_arg(va, func_t*);
         ea_t ea = va_arg(va, ea_t);
         change_tail_owner(tail, ea);
         break;
      }
      case idb_event::func_noret_changed: {    // FUNC_NORET bit has been changed
                                               // in: func_t *pfn
         func_t *pfn = va_arg(va, func_t*);
         change_func_noret(pfn);
         break;
      }
      case idb_event::segm_added: {            // A new segment has been created
                                               // in: segment_t *s
         segment_t *seg = va_arg(va, segment_t*);
         add_segment(seg);
         break;
      }
      case idb_event::segm_deleted: {          // A segment has been deleted
                                               // in: ea_t startEA
         ea_t ea = va_arg(va, ea_t);
         del_segment(ea);
         break;
      }
      case idb_event::segm_start_changed: {    // Segment start address has been changed
                                               // in: segment_t *s
         segment_t *seg = va_arg(va, segment_t*);
         change_seg_start(seg);
         break;
      }
      case idb_event::segm_end_changed: {      // Segment end address has been changed
                                               // in: segment_t *s
         segment_t *seg = va_arg(va, segment_t*);
         change_seg_end(seg);
         break;
      }
      case idb_event::segm_moved: {            // Segment has been moved
                                               // in: ea_t from, ea_t to, asize_t size
         ea_t ea = va_arg(va, ea_t);
         ea_t to = va_arg(va, ea_t);
         asize_t sz = va_arg(va, asize_t);
         move_segment(ea, to, sz);
         break;
      }
#if 0
#if IDA_SDK_VERSION >= 530
      case idb_event::area_cmt_changed: {
         // in: areacb_t *cb, const area_t *a, const char *cmt, bool repeatable
         areacb_t *cb = va_arg(va, areacb_t*);
         const area_t *a = va_arg(va, const area_t*);
         const char *cmt = va_arg(va, const char*);
         bool rep = va_arg(va, int) != 0;
         change_area_comment(cb, a, cmt, rep);
         break;
      }
#endif
#if IDA_SDK_VERSION >= 540
      case idb_event::changing_cmt: {         // An item comment is to be changed
                                    // in: ea_t ea, bool repeatable_cmt, const char *newcmt
//         ea_t ea = va_arg(va, ea_t);
//         bool rep = (bool)va_arg(va, int);
//         const char *cmt = va_arg(va, const char*);
         break;
      }
      case idb_event::changing_ti: {          // An item typestring (c/c++ prototype) is to be changed
                                    // in: ea_t ea, const type_t *new_type, const p_list *new_fnames
//         ea_t ea = va_arg(va, ea_t);
//         const type_t *newType = va_arg(va, const type_t *);
//         const p_list *newFnames = va_arg(va, const p_list *);
         break;
      }
      case idb_event::changing_op_ti: {       // An operand typestring (c/c++ prototype) is to be changed
                                    // in: ea_t ea, int n, const type_t *new_type, const p_list *new_fnames
//         ea_t ea = va_arg(va, ea_t);
//         const type_t *newType = va_arg(va, const type_t *);
//         const p_list *newFnames = va_arg(va, const p_list *);
         break;
      }
      case idb_event::changing_op_type: {     // An operand type (offset, hex, etc...) is to be changed
                                    // in: ea_t ea, int n
//         ea_t ea = va_arg(va, ea_t);
//         int n = va_arg(va, int);
         break;
      }
      case idb_event::deleting_enum: {        // A enum type is to be deleted
                                    // in: enum_t id
//         enum_t id = va_arg(va, enum_t);
         break;
      }
      case idb_event::changing_enum_bf: {     // A enum type 'bitfield' attribute is to be changed
                                    // in: enum_t id, bool new_bf
//         enum_t id = va_arg(va, enum_t);
//         bool new_bf = (bool)va_arg(va, int);
         break;
      }
      case idb_event::renaming_enum: {        // A enum or enum member is to be renamed
                                    // in: tid_t id, bool is_enum, const char *newname
//         tid_t id = va_arg(va, tid_t);
//         bool is_enum = (bool)va_arg(va, int);
//         const char *newname = va_arg(va, const char*);
         break;
      }
      case idb_event::changing_enum_cmt: {    // A enum or member type comment is to be changed
                                    // in: tid_t id, bool repeatable, const char *newcmt
//         tid_t id = va_arg(va, tid_t);
//         bool rep = (bool)va_arg(va, int);
//         const char *cmt = va_arg(va, const char*);
         break;
      }
#if IDA_SDK_VERSION >= 570
      case idb_event::deleting_enum_member: {
#else
      case idb_event::deleting_enum_const: {  // A enum member is to be deleted
                                    // in: enum_t id, const_t cid
#endif
//         enum_t id = va_arg(va, enum_t);
//         const_t cid = va_arg(va, const_t);
         break;
      }
      case idb_event::deleting_struc: {       // A structure type is to be deleted
                                    // in: struc_t *sptr
//         struc_t *sptr = va_arg(va, struc_t *);
         break;
      }
      case idb_event::renaming_struc: {       // A structure type is to be renamed
                                    // in: tid_t id, const char *oldname, const char *newname
//         tid_t id = va_arg(va, tid_t);
//         const char *oldname = va_arg(va, const char*);
//         const char *newname = va_arg(va, const char*);
         break;
      }
      case idb_event::expanding_struc: {      // A structure type is to be expanded/shrunk
                                    // in: struc_t *sptr, ea_t offset, adiff_t delta
//         struc_t *sptr = va_arg(va, struc_t *);
//         ea_t offset = va_arg(va, ea_t);
//         adiff_t delta = va_arg(va, adiff_t);
         break;
      }
      case idb_event::changing_struc_cmt: {   // A structure type comment is to be changed
                                    // in: tid_t struc_id, bool repeatable, const char *newcmt
//         tid_t id = va_arg(va, tid_t);
//         bool rep = (bool)va_arg(va, int);
//         const char *cmt = va_arg(va, const char*);
         break;
      }
      case idb_event::deleting_struc_member: {// A structure member is to be deleted
                                    // in: struc_t *sptr, member_t *mptr
//         struc_t *sptr = va_arg(va, struc_t *);
//         member_t *mptr = va_arg(va, member_t *);
         break;
      }
      case idb_event::renaming_struc_member: {// A structure member is to be renamed
                                    // in: struc_t *sptr, member_t *mptr, const char *newname
//         struc_t *sptr = va_arg(va, struc_t *);
//         member_t *mptr = va_arg(va, member_t *);
//         const char *newname = va_arg(va, const char*);
         break;
      }
      case idb_event::changing_struc_member: {// A structure member is to be changed
                                    // in: struc_t *sptr, member_t *mptr, flags_t flag, const opinfo_t *ti, asize_t nbytes
//         struc_t *sptr = va_arg(va, struc_t *);
//         member_t *mptr = va_arg(va, member_t *);
//         flags_t flag = va_arg(va, flags_t);
//         const opinfo_t *ti = va_arg(va, const opinfo_t *);
//         asize_t nbytes = va_arg(va, asize_t);
         break;
      }
      case idb_event::removing_func_tail: {   // A function tail chunk is to be removed
                                    // in: func_t *pfn, constr area_t *tail
//         func_t *pfn = va_arg(va, func_t *);
//         const area_t *tail = va_arg(va, const area_t *);
         break;
      }
      case idb_event::deleting_segm: {        // A segment is to be deleted
                                    // in: ea_t startEA
//         ea_t startEA = va_arg(va, ea_t);
         break;
      }
      case idb_event::changing_segm_start: {  // Segment start address is to be changed
                                    // in: segment_t *s, ea_t new_start, int segmod_flags
//         segment_t *s = va_arg(va, segment_t *);
//         ea_t new_start = va_arg(va, ea_t);
//         int segmod_flags = va_arg(va, int);
         break;
      }
      case idb_event::changing_segm_end: {    // Segment end address is to be changed
                                    // in: segment_t *s, ea_t new_end, int segmod_flags
//         segment_t *s = va_arg(va, segment_t *);
//         ea_t new_start = va_arg(va, ea_t);
//         int segmod_flags = va_arg(va, int);
         break;
      }
      case idb_event::changing_area_cmt: {    // Area comment is to be changed
                                    // in: areacb_t *cb, const area_t *a, const char *cmt, bool repeatable
//         areacb_t *cb = va_arg(va, areacb_t *);
//         const area_t *a = va_arg(va, const area_t *);
//         const char *cmt = va_arg(va, const char *);
//         bool rep = (bool)va_arg(va, int);
         break;
      }
#endif
#if IDA_SDK_VERSION >= 600
      case idb_event::changing_segm_name: {   // Segment name is beging changed
                                    // in: segment_t *s, const char *oldname
//         segment_t *s = va_arg(va, segment_t *);
//         const char *oldname = va_arg(va, const char *);
         break;
      }
      case idb_event::changing_segm_class: {  // Segment class is being changed
                                   // in: segment_t *s
//         segment_t *s = va_arg(va, segment_t *);
         break;
      }
      case idb_event::segm_name_changed: {    // Segment name has been changed
                                    // in: segment_t *s, const char *name
//         segment_t *s = va_arg(va, segment_t *);
//         const char *name = va_arg(va, const char *);
         break;
      }
      case idb_event::segm_class_changed: {   // Segment class has been changed
                                    // in: segment_t *s, const char *sclass
//         segment_t *s = va_arg(va, segment_t *);
//         const char *sclass = va_arg(va, const char *);
         break;
      }
#endif
#endif    //0
      default:
//         autoWait();
//         publish = true;
         return 0;
   }
   //NEED TO FIND A WAY TO SUPRESS MESSAGES THAT IDA GENERATES AUTOMATICALLY
//   bool oldSupress = supress;
//   supress = supress && (auto_display.state != st_Ready);
//   autoWait();
//   supress = auto_display.state != st_Ready;
//   publish = auto_display.state != st_Work;
//   publish = true;

//   msg("trying to leave idb::%d (%s), publish: %d\n", notification_code, notification_code < 60 ? idb_messages[notification_code] : "?", publish);
//   publish = autoIsOk() == 1 ? userPublish : 0;   //may need to move this into auto_empty related notification area
                    //to let ida decide when a command is done being processed
//   msg("leaving idb::%d (%s), oldSupress: %d, supress: %d, state: %d, &notification_code: 0x%x\n", notification_code, notification_code < 60 ? idb_messages[notification_code] : "?", oldSupress, supress, auto_display.state, &notification_code);
//   supress = supress && (auto_display.state != st_Ready);
   return 0;
}
#endif  //IDA_SDK_VERSION >= 510

void idp_undefine(ea_t ea) {
   //send address to server
   Buffer b;
   b.writeInt(COMMAND_UNDEFINE);
   b.writeLong(ea);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on undefine %x\n", (uint32_t)ea);
   }
}

void idp_make_code(ea_t ea, asize_t len) {
   //send address and length to server
   Buffer b;
   b.writeInt(COMMAND_MAKE_CODE);
   b.writeLong(ea);
   b.writeLong(len);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on make_code %x, %d\n", (uint32_t)ea, (int)len);
   }
}

void idp_make_data(ea_t ea, flags_t f, tid_t t, asize_t len) {
   //send all to server
   Buffer b;
   qstring name;
   b.writeInt(COMMAND_MAKE_DATA);
   b.writeLong(ea);
   b.writeInt(f);
   b.writeLong(len);
   if (t != BADNODE) {
      name = get_struc_name(t);
      b.writeUTF8(name.c_str());
   }
   else {
      b.writeUTF8("");
   }
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on make_data %x, %x, %x, %d\n", (uint32_t)ea, f, (uint32_t)t, (int)len);
   }
}

void idp_move_segm(ea_t ea, segment_t *seg) {
   Buffer b;
   b.writeInt(COMMAND_MOVE_SEGM);
   b.writeLong(ea);
   b.writeLong(seg->startEA);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on move_segm %x, %x\n", (uint32_t)ea, (uint32_t)seg->startEA);
   }
}

void idp_renamed(ea_t ea, const char *new_name, bool is_local) {
   //send all to server
   Buffer b;
   b.writeInt(COMMAND_RENAMED);
   b.writeLong(ea);
   b.write(&is_local, 1);
   b.writeUTF8(new_name);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on rename %x, %s, %d\n", (uint32_t)ea, new_name, is_local);
   }
}

void idp_add_func(func_t *pfn) {
   //send start, end address, name, flags (bp etc), purged, locals, delta, args
   Buffer b;
   b.writeInt(COMMAND_ADD_FUNC);
   b.writeLong(pfn->startEA);
   b.writeLong(pfn->endEA);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on add_func %x\n", (uint32_t)pfn->startEA);
   }
}

void idp_del_func(func_t *pfn) {
   //send start, end address, name, flags (bp etc), purged, locals, delta, args
   Buffer b;
   b.writeInt(COMMAND_DEL_FUNC);
   b.writeLong(pfn->startEA);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on del_func %x\n", (uint32_t)pfn->startEA);
   }
}

void idp_set_func_start(func_t *pfn, ea_t ea) {
   //send pfn->startEA and ea to server
   Buffer b;
   b.writeInt(COMMAND_SET_FUNC_START);
   b.writeLong(pfn->startEA);
   b.writeLong(ea);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on set_func_start %x, %x\n", (uint32_t)pfn->startEA, (uint32_t)ea);
   }
}

void idp_set_func_end(func_t *pfn, ea_t ea) {
   //send pfn->startEA and ea to server
   Buffer b;
   b.writeInt(COMMAND_SET_FUNC_END);
   b.writeLong(pfn->startEA);
   b.writeLong(ea);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on set_func_end %x, %x\n", (uint32_t)pfn->startEA, (uint32_t)ea);
   }
}

void idp_validate_flirt(ea_t ea, const char *name) {
   //send ea and name to server, apply name and set library func flag on remote side
   Buffer b;
   b.writeInt(COMMAND_VALIDATE_FLIRT_FUNC);
   b.writeLong(ea);
   b.writeUTF8(name);
   func_t *f = get_func(ea);
   if (f) {
      b.writeInt((int)f->endEA);
   }
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on validate_flirt %x, %s\n", (uint32_t)ea, name);
   }
}

void idp_add_cref(ea_t from, ea_t to, cref_t type) {
   Buffer b;
   b.writeInt(COMMAND_ADD_CREF);
   b.writeLong(from);
   b.writeLong(to);
   b.writeInt(type);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on add_cref %x, %x, %x\n", (uint32_t)from, (uint32_t)to, type);
   }
}

void idp_add_dref(ea_t from, ea_t to, dref_t type) {
   Buffer b;
   b.writeInt(COMMAND_ADD_DREF);
   b.writeLong(from);
   b.writeLong(to);
   b.writeInt(type);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on add_dref %x, %x, %x\n", (uint32_t)from, (uint32_t)to, type);
   }
}

void idp_del_cref(ea_t from, ea_t to, bool expand) {
   Buffer b;
   b.writeInt(COMMAND_DEL_CREF);
   b.writeLong(from);
   b.writeLong(to);
   b.write(expand);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on del_cref %x, %x, %x\n", (uint32_t)from, (uint32_t)to, expand);
   }
}

void idp_del_dref(ea_t from, ea_t to) {
   Buffer b;
   b.writeInt(COMMAND_DEL_DREF);
   b.writeLong(from);
   b.writeLong(to);
   if (send_data(b) == -1) {
      msg(PLUGIN_NAME": send error on del_dref 0x%08x, 0x%08x\n", (uint32_t)from, (uint32_t)to);
   }
}

//notification hook function for idp notifications
int idaapi idp_hook(void * /*user_data*/, int notification_code, va_list va) {
   if (!userPublish) {
      //should only be called if we are publishing
      return 0;
   }
   //some efforts to stop generating extra messages in response to updates
   //so far all have failed
/*
   if (auto_display.state != st_Ready) {
      return 0;
   }
*/
/*
   if (notification_code == processor_t::auto_queue_empty) {
      publish = userPublish;
   }
*/
/*
   if (supress) {
      //don't generate a databse message
      return 0;
   }
*/
//   msg("entering idp::%d (%s)\n", notification_code, notification_code < 110 ? (idp_messages[notification_code] ? idp_messages[notification_code] : "wtf") : "?");
//   publish = false;
   switch (notification_code) {
      case processor_t::undefine: {
         ea_t ea = va_arg(va, ea_t);
         msg(PLUGIN_NAME": %x undefined\n", (uint32_t)ea);
         idp_undefine(ea);
         break;
      }
      case processor_t::make_code: {
         ea_t ea = va_arg(va, ea_t);
         asize_t len = va_arg(va, asize_t);
         idp_make_code(ea, len);
         break;
      }
      case processor_t::make_data: {
         ea_t ea = va_arg(va, ea_t);
         flags_t f = va_arg(va, flags_t);
         tid_t t = va_arg(va, tid_t);
         asize_t len = va_arg(va, asize_t);
         idp_make_data(ea, f, t, len);
         break;
      }
      case processor_t::move_segm: {
         ea_t ea = va_arg(va, ea_t);
         segment_t *seg = va_arg(va, segment_t*);
         idp_move_segm(ea, seg);
         break;
      }
#if IDA_SDK_VERSION >= 510
      case processor_t::renamed: {
         //this receives notifications for stack variables as well
         ea_t ea = va_arg(va, ea_t);
         const char *name = va_arg(va, const char *);
         bool local = va_arg(va, int) != 0;
         idp_renamed(ea, name, local);
         break;
      }
      case processor_t::add_func: {
         func_t *pfn = va_arg(va, func_t*);
         idp_add_func(pfn);
         break;
      }
      case processor_t::del_func: {
         func_t *pfn = va_arg(va, func_t*);
         idp_del_func(pfn);
         break;
      }
      case processor_t::set_func_start: {
         func_t *pfn = va_arg(va, func_t*);
         ea_t ea = va_arg(va, ea_t);
         idp_set_func_start(pfn, ea);
         break;
      }
      case processor_t::set_func_end: {
         func_t *pfn = va_arg(va, func_t*);
         ea_t ea = va_arg(va, ea_t);
         idp_set_func_end(pfn, ea);
         break;
      }
#endif
#if IDA_SDK_VERSION >= 520
#if 0
      case processor_t::validate_flirt_func: {
         ea_t ea = va_arg(va, ea_t);
         const char *name = va_arg(va, const char *);
         idp_validate_flirt(ea, name);
//         publish = autoIsOk() == 1 ? userPublish : 0;
//         supress = supress && (auto_display.state != st_Ready);
         return 1;  //trust IDA's validation
      }
#endif
#endif
#if IDA_SDK_VERSION >= 530
      case processor_t::add_cref: {
         // args: ea_t from, ea_t to, cref_t type
         ea_t from = va_arg(va, ea_t);
         ea_t to = va_arg(va, ea_t);
         cref_t type = (cref_t)va_arg(va, int);
         idp_add_cref(from, to, type);
         break;
      }
      case processor_t::add_dref: {
         // args: ea_t from, ea_t to, dref_t type
         ea_t from = va_arg(va, ea_t);
         ea_t to = va_arg(va, ea_t);
         dref_t type = (dref_t)va_arg(va, int);
         idp_add_dref(from, to, type);
         break;
      }
      case processor_t::del_cref: {
         // args: ea_t from, ea_t to, bool expand
         ea_t from = va_arg(va, ea_t);
         ea_t to = va_arg(va, ea_t);
         bool expand = va_arg(va, int) != 0;
         idp_del_cref(from, to, expand);
         break;
      }
      case processor_t::del_dref: {
         // args: ea_t from, ea_t to
         ea_t from = va_arg(va, ea_t);
         ea_t to = va_arg(va, ea_t);
         idp_del_dref(from, to);
         break;
      }
#endif
      case processor_t::auto_empty : {
//         msg("auto_empty\n");
         break;
//         return 0;
      }
      case processor_t::auto_queue_empty : {
//         msg("auto_queue_empty\n");
         break;
//         return 0;
      }
#if IDA_SDK_VERSION >= 500
      case processor_t::auto_empty_finally : {
//         msg("auto_empty_finally\n");
//         return 0;
         break;
      }
#endif
      default:
//         autoWait();
//         publish = true;
         return 0;
   }
//   autoWait();
//   bool oldSupress = supress;
//   supress = supress && (auto_display.state != st_Ready);
//   supress = auto_display.state != st_Ready;
//   publish = auto_display.state != st_Work;
//   publish = true;
//   msg("trying to leave idp::%d (%s), publish: %d\n", notification_code, notification_code < 110 ? idp_messages[notification_code] : "?", publish);
//   publish = autoIsOk() == 1 ? userPublish : 0;
//   msg("leaving idp::%d (%s), oldSupress: %d, supress: %d, state: %d, &notification_code: 0x%x\n", notification_code, notification_code < 110 ? idp_messages[notification_code] : "?", oldSupress, supress, auto_display.state, &notification_code);
   return 0;
}

/*
int idaapi ui_hook(void *user_data, int notification_code, va_list va) {
   return 0;
}
*/

//hook to all ida notification types
void hookAll() {
   if (isHooked) return;
   if (userPublish) { //the only reason to hook is if we are publishing
      hook_to_notification_point(HT_IDP, idp_hook, NULL);
//      hook_to_notification_point(HT_UI, ui_hook, NULL);
#if IDA_SDK_VERSION >= 510      //HT_IDB introduced in SDK 510
      hook_to_notification_point(HT_IDB, idb_hook, NULL);
#endif
   }
   isHooked = true;
}

//unhook from all ida notification types
void unhookAll() {
//   msg("unhookAll called\n");
   if (!isHooked) return;
   if (userPublish) { //the only reason to unhook is if we are publishing
      unhook_from_notification_point(HT_IDP, idp_hook, NULL);
//      unhook_from_notification_point(HT_UI, ui_hook, NULL);
#if IDA_SDK_VERSION >= 510      //HT_IDB introduced in SDK 510
      unhook_from_notification_point(HT_IDB, idb_hook, NULL);
#endif
   }
   isHooked = false;
}

//--------------------------------------------------------------------------
//
//      Initialize.
//
//      IDA will call this function only once.
//      If this function returns PLGUIN_SKIP, IDA will never load it again.
//      If this function returns PLUGIN_OK, IDA will unload the plugin but
//      remember that the plugin agreed to work with the database.
//      The plugin will be loaded again if the user invokes it by
//      pressing the hotkey or selecting it from the menu.
//      After the second load the plugin will stay on memory.
//      If this function returns PLUGIN_KEEP, IDA will keep the plugin
//      in the memory. In this case the initialization function can hook
//      into the processor module and user interface notification points.
//      See the hook_to_notification_point() function.
//
//      In this example we check the input file format and make the decision.
//      You may or may not check any other conditions to decide what you do:
//      whether you agree to work with the database or not.
//
int idaapi init(void) {
   unsigned char md5[MD5_LEN];
   msg(PLUGIN_NAME": collabREate has been loaded\n");
   //while the md5 is not used here, it has the side effect of ensuring
   //that the md5 is taken at the earliest opportunity for storage in
   //the database in the event that the original binary is deleted
   getFileMd5(md5, sizeof(md5));
   unsigned char gpid[GPID_SIZE];
   ssize_t sz= getGpid(gpid, sizeof(gpid));
   if (sz > 0) {
      msg(PLUGIN_NAME": Operating in caching mode until connected.\n");
      if (changeCache == NULL) {
         uint32_t sz = cnn.blobsize(1, COLLABREATE_CACHE_TAG);
         if (sz > 0) {
            changeCache = new Buffer(cnn.getblob(NULL, (size_t*)&sz, 1, COLLABREATE_CACHE_TAG), sz, false);
         }
         else {
            changeCache = new Buffer();
         }
         hookAll();
      }
   }
   if (init_network()) {
//#if IDA_SDK_VERSION < 600
      mainWindow = (HWND)callui(ui_get_hwnd).vptr;
      hModule = GetModuleHandle("collabreate.plw");
//#endif
      return PLUGIN_KEEP;
   }
   else {
      return PLUGIN_SKIP;
   }
}

//--------------------------------------------------------------------------
//      Terminate.
//      Usually this callback is empty.
//      The plugin should unhook from the notification lists if
//      hook_to_notification_point() was used.
//
//      IDA will call this function when the user asks to exit.
//      This function won't be called in the case of emergency exits.

void idaapi term(void) {
   msg(PLUGIN_NAME": collabREate is being unloaded\n");
   authenticated = false;
   if (is_connected()) {
      cleanup();
   }
   if (msgHistory != NULL) {
      cnn.setblob(msgHistory->get_buf(), msgHistory->size(), 1, COLLABREATE_MSGHISTORY_TAG);
      delete msgHistory;
      msgHistory = NULL;
   }
   if (changeCache != NULL && changeCache->size() > 0) {
      cnn.setblob(changeCache->get_buf(), changeCache->size(), 1, COLLABREATE_CACHE_TAG);
      delete changeCache;
      changeCache = NULL;
   }
   unhookAll();
   term_network();
}

//--------------------------------------------------------------------------
//
//      The plugin method
//
//      This is the main function of plugin.
//
//      It will be called when the user activates the plugin.
//
//              arg - the input argument, it can be specified in
//                    plugins.cfg file. The default is zero.

void idaapi run(int /*arg*/) {
   if (is_connected()) {
      char *desc;
      Buffer req;
      switch (do_choose_command()) {
         case USER_FORK:
            desc = askstr(HIST_CMT, "", "Please enter a forked project description");
            if (desc) {
               req.writeInt(MSG_PROJECT_FORK_REQUEST);
               req.writeLong(getLastUpdate());
               req.writeUTF8(desc);
               send_data(req);
               fork_pending = true;  //flag to temporarily disable updates
               unhookAll();  //will rehook when new project is joined
            }
            msg(PLUGIN_NAME": Fork request sent.\n");
            break;
         case USER_CHECKPOINT:
            desc = askstr(HIST_CMT, "", "Please enter a checkpoint description");
            if (desc) {
               req.writeInt(MSG_PROJECT_SNAPSHOT_REQUEST);
               req.writeLong(getLastUpdate());
               req.writeUTF8(desc);
               send_data(req);
            }
            msg(PLUGIN_NAME": Checkpoint request sent.\n");
            break;
         case USER_PERMS: {
            req.writeInt(MSG_GET_REQ_PERMS);
            send_data(req);
            //allow user to edit their requested permissions for the project
            break;
         }
         case PROJECT_PERMS: {
            req.writeInt(MSG_GET_PROJ_PERMS);
            send_data(req);
            //allow an owner to edit the default permissions for the project
            break;
         }
#ifdef DEBUG
         case SHOW_NETNODE: {
            unsigned char sgpid[GPID_SIZE];
            memset( sgpid, 0, sizeof(sgpid));
            ssize_t sz= getGpid(sgpid, sizeof(sgpid));
            if (sz > 0) {
               msg(PLUGIN_NAME": Netnode gpid: ");
               unsigned char * gpidptr = sgpid;
               for(uint32_t i = 0; i < sizeof(sgpid); i++) {
                  msg("%x", *gpidptr++);
               }
               msg("\n");
               uint64_t last = getLastUpdate();
               msg(PLUGIN_NAME": Netnode lastUpdate: %s\n", formatLongLong(last));
            }
            else {
               msg(PLUGIN_NAME": GPID not found in netnode. hrm...\n");
            }
            break;
         }
         case CLEAN_NETNODE: {
            unsigned char egpid[GPID_SIZE];
            memset( egpid, 0, sizeof(egpid));
            setGpid(egpid, sizeof(egpid));
            writeUpdateValue(0);
            //do_clean_netnode();  //maybe put in _ui.cpp
            break;
         }
#endif
         case USER_DISCONNECT: {
            authenticated = false;
            msg(PLUGIN_NAME": De-activating collabREate\n");
            cleanup();
#if IDA_SDK_VERSION < 550
            killWindow();
#endif
            unhookAll();
            msg(PLUGIN_NAME": command   rx   tx\n");
            for (int i = 0; i <= MSG_IDA_MAX; i++) {
               if (stats[0][i] || stats[1][i]) {
                  msg(PLUGIN_NAME": %5d   %4d %4d\n", i, stats[0][i], stats[1][i]);
               }
            }
            break;
         }
      }
   }
   else {
      authenticated = false;
#if IDA_SDK_VERSION < 550
      killWindow();  //just to be safe
#endif
      memset(stats, 0, sizeof(stats));
      if (do_connect(msg_dispatcher)) {
         msg(PLUGIN_NAME": collabREate activated\n");
#if IDA_SDK_VERSION >= 600
         createCollabStatus();
#endif
      }
      else {
         warning("collabREate failed to connect to server\n");
      }
   }
}

//--------------------------------------------------------------------------
//char comment[] = "This is a skeleton plugin. It doesn't do a thing.";
char *comment = NULL;
char *help = NULL;

//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

char wanted_name[] = "collabREate";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overriden in plugins.cfg file
// Note: IDA won't tell you if the hotkey is not correct
//       It will just disable the hotkey.

char wanted_hotkey[] = "Alt-F6";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN = {
  IDP_INTERFACE_VERSION,
  0,                    // plugin flags
  init,                 // initialize
  term,                 // terminate. this pointer may be NULL.
  run,                  // invoke plugin
  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint
  help,                 // multiline help about the plugin
  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
