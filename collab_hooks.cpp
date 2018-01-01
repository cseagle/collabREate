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

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <netnode.hpp>
#include <typeinf.hpp>
#include <struct.hpp>
#include <range.hpp>
#include <frame.hpp>
#include <segment.hpp>
#include <enum.hpp>
#include <xref.hpp>
#include <nalt.hpp>
#include <offset.hpp>
#include <auto.hpp>

#include <json-c/json.h>

#include <map>
#include <string>
using std::map;
using std::string;

#if IDA_SDK_VERSION < 560
#define opinfo_t typeinfo_t
#endif

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
   "extlang_changed",//82
   "delay_slot_insn",//83
   "adjust_refinfo",//84

   "last_cb_before_debugger",//85
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
   "clean_tbit",//109
   "get_reg_info2"//110
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
   "equal_reglocs",//526
   "decorate_name3",//527
   "calc_retloc3",//528
   "calc_varglocs3",//529
   "calc_arglocs3",//530
   "use_stkarg_type3",//531
   "use_regarg_type3",//532
   "use_arg_types3",//533
   "calc_purged_bytes3",//534
   "shadow_args_size",//535
   "get_varcall_regs3",//536
   "get_fastcall_regs3",//537
   "get_thiscall_regs3",//538
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
   "extra_cmt_changed",  //59
   "changing_struc",    //60
   "changed_struc",     //61
   "local_types_changed", //62
   "segm_attrs_changed"   //63
};

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

void idp_undefine(ea_t ea) {
   //send address to server
   json_object *obj = json_object_new_object();
   if (send_json(ea, COMMAND_UNDEFINE, obj) == 0) {
      qstring s;
      format_llx(ea, s);
      msg(PLUGIN_NAME": send error on undefine 0x%s\n", s.c_str());
   }
}

void idp_make_code(ea_t ea, asize_t len) {
   //send address and length to server
   json_object *obj = json_object_new_object();
   append_json_uint64_val(obj, "length", (uint64_t)len);
   if (send_json(ea, COMMAND_MAKE_CODE, obj) == 0) {
      qstring s;
      format_llx(ea, s);
      msg(PLUGIN_NAME": send error on make_code 0x%s, %d\n", s.c_str(), (int)len);
   }
}

void idp_make_data(ea_t ea, flags_t f, tid_t t, asize_t len) {
   //send all to server
   json_object *obj = json_object_new_object();
   append_json_uint64_val(obj, "length", (uint64_t)len);
   append_json_uint64_val(obj, "flags", (uint64_t)f);

   if (t != BADNODE) {
#if IDA_SDK_VERSION < 680
      char name[MAXNAMESIZE];
      get_struc_name(t, name, sizeof(name));
#else
      qstring name;
      get_struc_name(&name, t);
#endif
      append_json_string_val(obj, "struc", name);
   }

   if (send_json(ea, COMMAND_MAKE_DATA, obj) == 0) {
      qstring s;
      format_llx(ea, s);
      msg(PLUGIN_NAME": send error on make_data 0x%s, %x, %x, %d\n", s.c_str(), f, (uint32_t)t, (int)len);
   }
}

void idp_move_segm(ea_t ea, segment_t *seg) {
   json_object *obj = json_object_new_object();
   append_json_ea_val(obj, "from", ea);
   append_json_ea_val(obj, "to", seg->start_ea);
   if (send_json(COMMAND_MOVE_SEGM, obj) == 0) {
      qstring a1, a2;
      format_llx(ea, a1);
      format_llx(seg->start_ea, a2);
      msg(PLUGIN_NAME": send error on move_segm 0x%s, 0x%s\n", a1.c_str(), a2.c_str());
   }
}

void idp_renamed(ea_t ea, const char *new_name, bool is_local) {
   //send all to server
   json_object *obj = json_object_new_object();
   append_json_bool_val(obj, "local", (json_bool)is_local);
   append_json_string_val(obj, "name", new_name);
   if (send_json(ea, COMMAND_RENAMED, obj) == 0) {
      qstring a1;
      format_llx(ea, a1);
      msg(PLUGIN_NAME": send error on rename 0x%s, %s, %d\n", a1.c_str(), new_name, is_local);
   }
}

void idp_add_func(func_t *pfn) {
   //send start, end address, name, flags (bp etc), purged, locals, delta, args
   json_object *obj = json_object_new_object();
   append_json_ea_val(obj, "startea", pfn->start_ea);
   append_json_ea_val(obj, "endea", pfn->end_ea);
   send_json(COMMAND_ADD_FUNC, obj);
/*
   if (send_data(b) == -1) {
      qstring a1;
      format_llx(pfn->start_ea, a1);
      msg(PLUGIN_NAME": send error on add_func 0x%s\n", a1.c_str());
   }
*/
}

void idp_del_func(func_t *pfn) {
   //send start, end address, name, flags (bp etc), purged, locals, delta, args
   json_object *obj = json_object_new_object();
   send_json(pfn->start_ea, COMMAND_DEL_FUNC, obj);
/*
   if (send_data(b) == -1) {
      qstring a1;
      format_llx(pfn->start_ea, a1);
      msg(PLUGIN_NAME": send error on del_func 0x%s\n", a1.c_str());
   }
*/
}

void idp_set_func_start(func_t *pfn, ea_t ea) {
   //send pfn->start_ea and ea to server
   json_object *obj = json_object_new_object();
   append_json_ea_val(obj, "old_start", pfn->start_ea);
   append_json_ea_val(obj, "new_start", ea);
   send_json(COMMAND_SET_FUNC_START, obj);
/*
   if (send_data(b) == -1) {
      qstring a1, a2;
      format_llx(pfn->start_ea, a1);
      format_llx(ea, a2);
      msg(PLUGIN_NAME": send error on set_func_start 0x%s, 0x%s\n", a1.c_str(), a2.c_str());
   }
*/
}

void idp_set_func_end(func_t *pfn, ea_t ea) {
   //send pfn->start_ea and ea to server
   json_object *obj = json_object_new_object();
   append_json_ea_val(obj, "startea", pfn->start_ea);
   append_json_ea_val(obj, "endea", ea);
   send_json(COMMAND_SET_FUNC_END, obj);
/*
   if (send_data(b) == -1) {
      qstring a1, a2;
      format_llx(pfn->start_ea, a1);
      format_llx(ea, a2);
      msg(PLUGIN_NAME": send error on set_func_end 0x%s, 0x%s\n", a1.c_str(), a2.c_str());
   }
*/
}

void idp_validate_flirt(ea_t ea, const char *name) {
   //send ea and name to server, apply name and set library func flag on remote side
   json_object *obj = json_object_new_object();
   append_json_string_val(obj, "name", name);
   append_json_ea_val(obj, "startea", ea);

   func_t *f = get_func(ea);
   if (f) {
      append_json_ea_val(obj, "endea", f->end_ea);
   }

   send_json(COMMAND_VALIDATE_FLIRT_FUNC, obj);
/*
   if (send_data(b) == -1) {
      qstring a1;
      format_llx(ea, a1);
      msg(PLUGIN_NAME": send error on validate_flirt 0x%s, %s\n", a1.c_str(), name);
   }
*/
}

void idp_add_cref(ea_t from, ea_t to, cref_t type) {
   json_object *obj = json_object_new_object();
   append_json_ea_val(obj, "from", from);
   append_json_ea_val(obj, "to", to);
   append_json_uint64_val(obj, "reftype", (uint64_t)type);
   send_json(COMMAND_ADD_CREF, obj);
/*
   if (send_data(b) == -1) {
      qstring a1, a2;
      format_llx(from, a1);
      format_llx(to, a2);
      msg(PLUGIN_NAME": send error on add_cref 0x%s, 0x%s, %x\n", a1.c_str(), a2.c_str(), type);
   }
*/
}

void idp_add_dref(ea_t from, ea_t to, dref_t type) {
   json_object *obj = json_object_new_object();
   append_json_ea_val(obj, "from", from);
   append_json_ea_val(obj, "to", to);
   append_json_uint64_val(obj, "reftype", (uint64_t)type);
   send_json(COMMAND_ADD_DREF, obj);
/*
   if (send_data(b) == -1) {
      qstring a1, a2;
      format_llx(from, a1);
      format_llx(to, a2);
      msg(PLUGIN_NAME": send error on add_dref 0x%s, 0x%s, %x\n", a1.c_str(), a2.c_str(), type);
   }
*/
}

void idp_del_cref(ea_t from, ea_t to, bool expand) {
   json_object *obj = json_object_new_object();
   append_json_ea_val(obj, "from", from);
   append_json_ea_val(obj, "to", to);
   append_json_bool_val(obj, "expand", (json_bool)expand);
   send_json(COMMAND_DEL_CREF, obj);
/*
   if (send_data(b) == -1) {
      qstring a1, a2;
      format_llx(from, a1);
      format_llx(to, a2);
      msg(PLUGIN_NAME": send error on del_cref 0x%s, 0x%s, %x\n", a1.c_str(), a2.c_str(), expand);
   }
*/
}

void idp_del_dref(ea_t from, ea_t to) {
   json_object *obj = json_object_new_object();
   append_json_ea_val(obj, "from", from);
   append_json_ea_val(obj, "to", to);
   send_json(COMMAND_DEL_DREF, obj);
/*
   if (send_data(b) == -1) {
      qstring a1, a2;
      format_llx(from, a1);
      format_llx(to, a2);
      msg(PLUGIN_NAME": send error on del_dref 0x%s, 0x%s\n", a1.c_str(), a2.c_str());
   }
*/
}

void byte_patched(ea_t ea) {
   json_object *obj = json_object_new_object();
   uint32_t val = (uint32_t)get_byte(ea);
   //send value to server
   append_json_uint32_val(obj, "value", val);
   send_json(ea, COMMAND_BYTE_PATCHED, obj);
/*
   if (send_data(b) == -1) {
      qstring a1;
      format_llx(ea, a1);
      msg(PLUGIN_NAME": send error on byte_patched 0x%s, %x\n", a1.c_str(), val);
   }
*/
}

void comment_changed(ea_t ea, bool rep) {
#if IDA_SDK_VERSION < 700
   ssize_t ssz = get_cmt(ea, rep, NULL, 0) + 1;
   if (ssz != -1) {
      size_t sz = (size_t)ssz;
      char *cmt = (char*) qalloc(sz + 1);
      if (cmt || sz == 0) {
         if (sz) {
            get_cmt(ea, rep, cmt, sz);
         }
         else {
            cmt[0] = 0;
         }
         //send comment to server
         json_object *obj = json_object_new_object();
         append_json_string_val(obj, "text", cmt);
         append_json_bool_val(obj, "rep", (json_bool)rep);
         send_json(ea, COMMAND_CMT_CHANGED, obj);
/*
         if (send_data(b) == -1) {
            qstring a1;
            format_llx(ea, a1);
            msg(PLUGIN_NAME": send error on comment_changed 0x%s, %s\n", a1.c_str(), cmt);
         }
*/
         qfree(cmt);
      }
   }
#else
   qstring cmt;
   ssize_t ssz = get_cmt(&cmt, ea, rep);
   if (ssz != -1) {
      //send comment to server
      json_object *obj = json_object_new_object();
      append_json_string_val(obj, "text", cmt);
      append_json_bool_val(obj, "rep", (json_bool)rep);
      send_json(ea, COMMAND_CMT_CHANGED, obj);
   }
#endif
}

void change_ti(ea_t ea, const type_t *type, const p_list *fnames) {
   json_object *obj = json_object_new_object();
   append_json_hex_val(obj, "ti", (const uint8_t*)type);
   append_json_hex_val(obj, "fnames", (const uint8_t*)fnames);
   send_json(ea, COMMAND_TI_CHANGED, obj);
/*
   if (send_data(b) == -1) {
      qstring a1;
      format_llx(ea, a1);
      msg(PLUGIN_NAME": send error on change_ti 0x%s\n", a1.c_str());
   }
*/
}

void change_op_ti(ea_t ea, int n, const type_t *type, const p_list *fnames) {
   json_object *obj = json_object_new_object();
   append_json_hex_val(obj, "ti", (const uint8_t*)type);
   append_json_hex_val(obj, "fnames", (const uint8_t*)fnames);
   append_json_int32_val(obj, "opnum", n);
   send_json(ea, COMMAND_OP_TI_CHANGED, obj);
/*
   if (send_data(b) == -1) {
      qstring a1;
      format_llx(ea, a1);
      msg(PLUGIN_NAME": send error on change_op_ti 0x%s\n", a1.c_str());
   }
*/
}

//lookup structure offset info about operand n at address ea and
//add the information into the provided buffer
void gatherStructOffsetInfo(json_object *obj, ea_t ea, int n) {
   json_object *jpath = json_object_new_array();
   tid_t path[MAXSTRUCPATH];
   adiff_t delta;
#if IDA_SDK_VERSION >= 700
   int path_len = get_stroff_path(path, &delta, ea, n);
#else
   int path_len = get_stroff_path(ea, n, path, &delta);
#endif
   append_json_uint64_val(obj, "delta", (uint64_t)delta);
   //iterate over the structure path, adding the name of each struct
   //the the provided path.  We pass names here rather than tid
   //because different versions of IDA may assign different tid values
   //the the same struct type
   for (int i = 0; i < path_len; i++) {
#if IDA_SDK_VERSION < 680
      char name[MAXNAMESIZE];
      /*ssize_t sz =*/ get_struc_name(path[i], name, sizeof(name));
      json_object *jname = json_object_new_string(name);
#else
      qstring name;
      /*ssize_t sz =*/ get_struc_name(&name, path[i]);
      json_object *jname = json_object_new_string(name.c_str());
#endif
      json_object_array_add(jpath, jname);
   }

   json_object_object_add_ex(obj, "path", jpath, JSON_NEW_CONST_KEY);
}

//lookup enum type info about operand n at address ea and
//add the information into the provided buffer
void gatherEnumInfo(json_object *obj, ea_t ea, int n) {
   uchar serial;
#if IDA_SDK_VERSION >= 700
   enum_t id = get_enum_id(&serial, ea, n);
#else
   enum_t id = get_enum_id(ea, n, &serial);
#endif

#if IDA_SDK_VERSION < 680
   char name[MAXNAMESIZE];
   ssize_t len = get_enum_name(id, name, sizeof(name));
#else
   qstring name;
   ssize_t len = get_enum_name(&name, id);
#endif

   if (len > 0) {
      //We pass a name here rather than enum_t because different
      //versions of IDA may assign different enum_t values
      //the the same enum type
      append_json_string_val(obj, "ename", name);
      append_json_uint32_val(obj, "serial", serial);
   }
}

void gatherRefInfo(json_object *obj, refinfo_t &ri) {
   append_json_uint32_val(obj, "reft_and_flags", (uint32_t)ri.flags);
   append_json_ea_val(obj, "target", (ea_t)ri.target);
   append_json_ea_val(obj, "base", (ea_t)ri.base);
   append_json_uint64_val(obj, "delta", (uint64_t)ri.tdelta);
}

/* FINISH ME */
void change_op_type(ea_t ea, int opnum) {
   json_object *obj = json_object_new_object();

   //send value to server
   flags_t f = get_flags_novalue(ea);
   if (opnum) {
      if (opnum != 1) {
         msg("change_op_type opnum == %d unexpected\n", opnum);
         return;
      }
      f = get_optype_flags1(f);
      if (isEnum1(f)) {
         //need to figure out what enum it is
         gatherEnumInfo(obj, ea, opnum);
      }
      else if (isStroff1(f)) {
         //need to figure out what struct it is
         gatherStructOffsetInfo(obj, ea, opnum);
      }
      else if (isOff1(f)) {
         refinfo_t ri;
#if IDA_SDK_VERSION >= 700
         if (!get_refinfo(&ri, ea, opnum)) {
#else
         if (!get_refinfo(ea, opnum, &ri)) {
#endif
            msg(PLUGIN_NAME": missing refinfo on offset in change_op_type %x, %x", (uint32_t)ea, opnum);
            return;
         }
         if (ri.type() != REF_OFF32 || ri.target != BADADDR ||
                ri.base != 0 || ri.tdelta != 0) {
            gatherRefInfo(obj, ri);
         }
      }
   }
   else {
      f = get_optype_flags0(f);
      if (isEnum0(f)) {
         //need to figure out what enum it is
         gatherEnumInfo(obj, ea, opnum);
      }
      else if (isStroff0(f)) {
         //need to figure out what struct it is
         gatherStructOffsetInfo(obj, ea, opnum);
      }
      else if (isOff0(f)) {
         refinfo_t ri;
#if IDA_SDK_VERSION >= 700
         if (!get_refinfo(&ri, ea, opnum)) {
#else
         if (!get_refinfo(ea, opnum, &ri)) {
#endif
            msg(PLUGIN_NAME": missing refinfo on offset in change_op_type %x, %x", (uint32_t)ea, opnum);
            return;
         }
         if (ri.type() != REF_OFF32 || ri.target != BADADDR ||
                ri.base != 0 || ri.tdelta != 0) {
            gatherRefInfo(obj, ri);
         }
      }
   }

   append_json_uint32_val(obj, "opnum", opnum);
   append_json_uint32_val(obj, "flags", f);

   send_json(ea, COMMAND_OP_TYPE_CHANGED, obj);
/*
   if (send_data(b) == -1) {
      qstring a1;
      format_llx(ea, a1);
      msg(PLUGIN_NAME": send error on change_op_type 0x%s, %x, %x\n", a1.c_str(), opnum, f);
   }
*/
}

void create_enum(enum_t id) {
   //get enum name (and fields?) and send to server
#if IDA_SDK_VERSION < 680
   char name[MAXNAMESIZE];
   ssize_t sz = get_enum_name(id, name, sizeof(name));
#else
   qstring name;
   ssize_t sz = get_enum_name(&name, id);
#endif

   if (sz > 0) {
      json_object *obj = json_object_new_object();
      append_json_string_val(obj, "enum_name", name);
      send_json(COMMAND_ENUM_CREATED, obj);
#if IDA_SDK_VERSION < 680
/*
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on create_enum %s\n", name);
      }
*/
      cnn.supset(id, name, 0, COLLABREATE_ENUMS_TAG);
#else
/*
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on create_enum %s\n", name.c_str());
      }
*/
      cnn.supset(id, name.c_str(), 0, COLLABREATE_ENUMS_TAG);
#endif
   }
}

void delete_enum(enum_t id) {
   //get enum name and send to server
#if IDA_SDK_VERSION < 680
   char name[MAXNAMESIZE];
   ssize_t sz = get_enum_name(id, name, sizeof(name));
#else
   qstring name;
   ssize_t sz = get_enum_name(&name, id);
#endif

   if (sz > 0) {
      json_object *obj = json_object_new_object();
      append_json_string_val(obj, "enum_name", name);
      send_json(COMMAND_ENUM_DELETED, obj);
#if IDA_SDK_VERSION < 680
/*
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on delete_enum %s\n", name);
      }
*/
#else
/*
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on delete_enum %s\n", name.c_str());
      }
*/
#endif
      cnn.supdel(id, COLLABREATE_ENUMS_TAG);
   }
}

/***
 * NOT HANDLING THIS YET
 ***/
void change_enum_bf(enum_t id) {
   json_object *obj = json_object_new_object();

#if IDA_SDK_VERSION < 680
   char name[MAXNAMESIZE];
   ssize_t sz = get_enum_name(id, name, sizeof(name));
#else
   qstring name;
   ssize_t sz = get_enum_name(&name, id);
#endif

   if (sz > 0) {
      append_json_string_val(obj, "enum_name", name);
      send_json(COMMAND_ENUM_BF_CHANGED, obj);
/*
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on change_enum %s\n", name);
      }
*/
   }
}

void rename_enum(tid_t t) {
   char oldname[MAXNAMESIZE];

#if IDA_SDK_VERSION < 680
   char newname[MAXNAMESIZE];
   ssize_t sz = get_enum_name(t, newname, sizeof(newname));
#else
   qstring newname;
   ssize_t sz = get_enum_name(&newname, t);
#endif

   ssize_t len = cnn.supstr(t, oldname, sizeof(oldname), COLLABREATE_ENUMS_TAG);
   if (sz > 0 && len > 0) {
      json_object *obj = json_object_new_object();
      append_json_string_val(obj, "oldname", oldname);
      append_json_string_val(obj, "newname", newname);
      send_json(COMMAND_ENUM_RENAMED, obj);
#if IDA_SDK_VERSION < 680
      cnn.supset(t, newname, 0, COLLABREATE_ENUMS_TAG);
/*
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on rename_enum %s\n", newname);
      }
*/
#else
      cnn.supset(t, newname.c_str(), 0, COLLABREATE_ENUMS_TAG);
/*
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on rename_enum %s\n", newname.c_str());
      }
*/
#endif
   }
}

void change_enum_cmt(tid_t t, bool rep) {
#if IDA_SDK_VERSION < 680
   char name[MAXNAMESIZE];
   ssize_t sz = get_enum_name(t, name, sizeof(name));
#else
   qstring name;
   ssize_t sz = get_enum_name(&name, t);
#endif
#if IDA_SDK_VERSION >= 700
   qstring cmt;
   /*ssize_t csz =*/ get_enum_cmt(&cmt, t, rep);
   if (sz > 0) {
      json_object *obj = json_object_new_object();
      append_json_string_val(obj, "enum_name", name);
      append_json_string_val(obj, "comment", cmt);
      append_json_bool_val(obj, "rep", (json_bool)rep);
      send_json(COMMAND_ENUM_CMT_CHANGED, obj);
   }
#else
   char cmt[MAXNAMESIZE];
   /*ssize_t csz =*/ get_enum_cmt(t, rep, cmt, sizeof(cmt));
   if (sz > 0) {
      json_object *obj = json_object_new_object();
      append_json_string_val(obj, "enum_name", name);
      append_json_string_val(obj, "comment", cmt);
      append_json_bool_val(obj, "rep", (json_bool)rep);
      send_json(COMMAND_ENUM_CMT_CHANGED, obj);
/*
      if (send_data(b) == -1) {
#if IDA_SDK_VERSION < 680
         msg(PLUGIN_NAME": send error on change_enum_cmt %s\n", name);
#else
         msg(PLUGIN_NAME": send error on change_enum_cmt %s\n", name.c_str());
#endif
      }
*/
   }
#endif
}

void create_enum_member(enum_t id, const_t cid) {
   //get enum name and member name/val and send to server
   json_object *obj = json_object_new_object();

#if IDA_SDK_VERSION >= 570
   uval_t value = get_enum_member_value(cid);
#else
   uval_t value = get_const_value(cid);
#endif

#if IDA_SDK_VERSION < 680
   char ename[MAXNAMESIZE];
   get_enum_name(id, ename, MAXNAMESIZE);
#else
   qstring ename;
   get_enum_name(&ename, id);
#endif
   append_json_string_val(obj, "ename", ename);

#if IDA_SDK_VERSION >= 680
   qstring mname;
   get_enum_member_name(&mname, cid);
#elif IDA_SDK_VERSION >= 570
   char mname[MAXNAMESIZE];
   get_enum_member_name(cid, mname, MAXNAMESIZE);
#else
   char mname[MAXNAMESIZE];
   get_const_name(cid, mname, MAXNAMESIZE);
#endif

   append_json_string_val(obj, "mname", mname);
   append_json_uint64_val(obj, "value", (uint64_t)value);
   send_json(COMMAND_ENUM_CONST_CREATED, obj);
}

void delete_enum_member(enum_t id, const_t cid) {
   //get enum name and member name/val and send to server
   json_object *obj = json_object_new_object();
#if IDA_SDK_VERSION >= 570
   uval_t value = get_enum_member_value(cid);
   bmask_t bmask = get_enum_member_bmask(cid);
   uchar serial = get_enum_member_serial(cid);
#else
   uval_t value = get_const_value(cid);
   bmask_t bmask = get_const_bmask(cid);
   uchar serial = get_const_serial(cid);
#endif

   append_json_int32_val(obj, "value", (int)value);
   append_json_int32_val(obj, "bmask", (int)bmask);
   append_json_int32_val(obj, "serial", (int)serial);

#if IDA_SDK_VERSION < 680
   char ename[MAXNAMESIZE];
   get_enum_name(id, ename, MAXNAMESIZE);
#else
   qstring ename;
   get_enum_name(&ename, id);
#endif

   append_json_string_val(obj, "ename", ename);
   send_json(COMMAND_ENUM_CONST_DELETED, obj);
}

void create_struct(tid_t t) {
   //get struct name (and fields?) and send to server
#if IDA_SDK_VERSION < 680
   char name[MAXNAMESIZE];
   ssize_t sz = get_struc_name(t, name, sizeof(name));
#else
   qstring name;
   ssize_t sz = get_struc_name(&name, t);
#endif
   if (sz > 0) {
      struc_t *s = get_struc(t);

      json_object *obj = json_object_new_object();
      append_json_string_val(obj, "struc_name", name);
      append_json_uint64_val(obj, "tid", (uint64_t)t);
      append_json_bool_val(obj, "union", (json_bool)s->is_union());
      send_json(COMMAND_STRUC_CREATED, obj);

#if IDA_SDK_VERSION < 680
/*
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on create_struct %s\n", name);
      }
*/
      //remember the name of the struct in case it is renamed later
      cnn.supset(t, name, 0, COLLABREATE_STRUCTS_TAG);
#else
/*
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on create_struct %s\n", name.c_str());
      }
*/
      //remember the name of the struct in case it is renamed later
      cnn.supset(t, name.c_str(), 0, COLLABREATE_STRUCTS_TAG);
#endif
   }
}

void delete_struct(tid_t s) {
   //get struct name and send to server
#if IDA_SDK_VERSION < 680
   char name[MAXNAMESIZE];
   ssize_t sz = get_struc_name(s, name, sizeof(name));
#else
   qstring name;
   ssize_t sz = get_struc_name(&name, s);
#endif
   if (sz > 0) {
      json_object *obj = json_object_new_object();
      append_json_string_val(obj, "struc_name", name);
      send_json(COMMAND_STRUC_DELETED, obj);
/*
#if IDA_SDK_VERSION < 680
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on delete_struct %s\n", name);
      }
#else
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on delete_struct %s\n", name.c_str());
      }
#endif
*/
   }
}

void rename_struct(struc_t *s) {
   //get struct name (and fields?) and send to server
   //how do we know old struct name
   char oldname[MAXNAMESIZE];
#if IDA_SDK_VERSION < 680
   char newname[MAXNAMESIZE];
   ssize_t sz = get_struc_name(s->id, newname, sizeof(newname));
#else
   qstring newname;
   ssize_t sz = get_struc_name(&newname, s->id);
#endif
   ssize_t len = cnn.supstr(s->id, oldname, sizeof(oldname), COLLABREATE_STRUCTS_TAG);
   if (sz > 0 && len > 0) {
      json_object *obj = json_object_new_object();
      append_json_string_val(obj, "oldname", oldname);
      append_json_string_val(obj, "newname", newname);
      //tids are never guaranteed to map beween any two IDBs
      //need to try to map struct id to other instances ID
      append_json_uint64_val(obj, "tid", (uint64_t)s->id);
      send_json(COMMAND_STRUC_RENAMED, obj);

#if IDA_SDK_VERSION < 680
      cnn.supset(s->id, newname, 0, COLLABREATE_STRUCTS_TAG);
/*
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on rename_struct %s\n", newname);
      }
*/
#else
      cnn.supset(s->id, newname.c_str(), 0, COLLABREATE_STRUCTS_TAG);
/*
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on rename_struct %s\n", newname.c_str());
      }
*/
#endif
   }
}

void expand_struct(struc_t *s) {
   //what info to send to indicate expansion? at what offset and by how much?
#if IDA_SDK_VERSION < 680
   char name[MAXNAMESIZE];
   ssize_t sz = get_struc_name(s->id, name, sizeof(name));
#else
   qstring name;
   ssize_t sz = get_struc_name(&name, s->id);
#endif
   if (sz > 0) {
      json_object *obj = json_object_new_object();
#ifdef DEBUG
      msg(PLUGIN_NAME": struct %s has been expanded\n", name);
#endif
      append_json_string_val(obj, "struc_name", name);
      //tids are never guaranteed to map beween any two IDBs
      //need to try to map struct id to other instances ID
      append_json_uint64_val(obj, "tid", (uint64_t)s->id);
      send_json(COMMAND_STRUC_EXPANDED, obj);
/*
#if IDA_SDK_VERSION < 680
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on rename_struct %s\n", name);
      }
#else
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on rename_struct %s\n", name.c_str());
      }
#endif
*/
   }
}

void change_struc_cmt(tid_t t, bool rep) {
#if IDA_SDK_VERSION < 680
   char name[MAXNAMESIZE];
   /*ssize_t sz =*/ get_struc_name(t, name, sizeof(name));
#else
   qstring name;
   /*ssize_t ssz =*/ get_struc_name(&name, t);
#endif

#if IDA_SDK_VERSION >= 700
   qstring cmt;
   /*ssize_t csz =*/ get_struc_cmt(&cmt, t, rep);

   json_object *obj = json_object_new_object();
   append_json_string_val(obj, "struc_name", name);
   append_json_string_val(obj, "comment", cmt);
   append_json_bool_val(obj, "rep", (json_bool)rep);
   send_json(COMMAND_STRUC_CMT_CHANGED, obj);
#else
   char cmt[MAXNAMESIZE];
   /*ssize_t csz =*/ get_struc_cmt(t, rep, cmt, sizeof(cmt));

   json_object *obj = json_object_new_object();
   append_json_string_val(obj, "struc_name", name);
   append_json_string_val(obj, "comment", cmt);
   append_json_bool_val(obj, "rep", (json_bool)rep);
   send_json(COMMAND_STRUC_CMT_CHANGED, obj);

/*
   if (send_data(b) == -1) {
#if IDA_SDK_VERSION < 680
      msg(PLUGIN_NAME": send error on change_struc_cmt %s\n", name);
#else
      msg(PLUGIN_NAME": send error on change_struc_cmt %s\n", name.c_str());
#endif
   }
*/
#endif
}

void create_struct_member(struc_t *s, member_t *m) {
   //get struct name and member name/offs and send to server
   json_object *obj = json_object_new_object();

   opinfo_t ti, *pti;

#if IDA_SDK_VERSION < 680
   char name[MAXNAMESIZE];
#else
   qstring name;
#endif

#if IDA_SDK_VERSION >= 700
   pti = retrieve_member_info(&ti, m);
#else
   pti = retrieve_member_info(m, &ti);
#endif

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
         append_json_string_val(obj, "type", COMMAND_CREATE_STRUC_MEMBER_STRUCT);
#if IDA_SDK_VERSION < 680
         /*ssize_t tsz =*/ get_struc_name(ti.tid, name, sizeof(name));
#else
         /*ssize_t ssz =*/ get_struc_name(&name, ti.tid);
#endif
         append_json_string_val(obj, "struc_type", name);
      }
      else if (isASCII(m->flag)) {
         append_json_string_val(obj, "type", COMMAND_CREATE_STRUC_MEMBER_STR);
         append_json_uint32_val(obj, "str_type", (uint32_t)ti.strtype);
      }

      else if (isOff0(m->flag) || isOff1(m->flag)) {
         append_json_string_val(obj, "type", COMMAND_CREATE_STRUC_MEMBER_OFFSET);
         append_json_hex_val(obj, "refinfo", (uint8_t*)&ti.ri, sizeof(refinfo_t));
      }
      else if (isEnum0(m->flag) || isEnum1(m->flag)) {
         append_json_string_val(obj, "type", COMMAND_CREATE_STRUC_MEMBER_ENUM);
#if IDA_SDK_VERSION < 680
         /*ssize_t tsz =*/ get_struc_name(ti.ec.tid, name, sizeof(name));
#else
         /*ssize_t ssz =*/ get_struc_name(&name, ti.ec.tid);
#endif
         append_json_string_val(obj, "enum_name", name);
         append_json_uint32_val(obj, "serial", (uint32_t)ti.ec.serial);
      }
      else {
         //need a command to write in this case??
         //is it even possible to have refinfo_t, strpath_t, or enum_const_t here?
         msg(PLUGIN_NAME": create_struct_member at unknown typeinfo\n");
         msg(PLUGIN_NAME": create_struct_member flags = %x, props = %x\n", m->flag, m->props);
         return;  //don't know how to handle this type yet
      }
      append_json_uint32_val(obj, "properties", (uint32_t)m->props);
   }
   else {
      append_json_string_val(obj, "type", COMMAND_CREATE_STRUC_MEMBER_DATA);
   }

   append_json_ea_val(obj, "soff", m->unimem() ? 0 : m->soff);
   append_json_uint32_val(obj, "flag", (uint32_t)(m->flag));
   append_json_uint64_val(obj, "sz", (uint64_t)(m->unimem() ? m->eoff : (m->eoff - m->soff)));

   //should send opinfo_t as well
#if IDA_SDK_VERSION < 680
   char mbr[MAXNAMESIZE];
   /*ssize_t ssz =*/ get_struc_name(s->id, name, sizeof(name));
   /*ssize_t msz =*/ get_member_name(m->id, mbr, sizeof(mbr));
#else
   qstring mbr;
   /*ssize_t ssz =*/ get_struc_name(&name, s->id);
   /*ssize_t msz =*/ get_member_name2(&mbr, m->id);
#endif

   append_json_string_val(obj, "struc_name", name);
   append_json_string_val(obj, "member", mbr);

   send_json(obj);

/*
//   msg(PLUGIN_NAME": create_struct_member %s.%s off: %d, sz: %d\n", name, mbr, m->soff, m->eoff - m->soff);
   if (send_data(b) == -1) {
#if IDA_SDK_VERSION < 680
      msg(PLUGIN_NAME": send error on create_struct_member %s\n", name);
#else
      msg(PLUGIN_NAME": send error on create_struct_member %s\n", name.c_str());
#endif
   }
*/
}

void delete_struct_member(struc_t *s, tid_t /*m*/, ea_t offset) {
   //get struct name and member name/offs and send to server
   json_object *obj = json_object_new_object();

#if IDA_SDK_VERSION < 680
   char name[MAXNAMESIZE];
   /*ssize_t ssz =*/ get_struc_name(s->id, name, sizeof(name));
#else
   qstring name;
   /*ssize_t ssz =*/ get_struc_name(&name, s->id);
#endif

   append_json_string_val(obj, "struc_name", name);
   append_json_ea_val(obj, "offset", offset);

   send_json(COMMAND_STRUC_MEMBER_DELETED, obj);

/*
//   msg(PLUGIN_NAME": delete_struct_member %s, tid %x, offset %x\n", name, m, offset);
   if (send_data(b) == -1) {
#if IDA_SDK_VERSION < 680
      msg(PLUGIN_NAME": send error on delete_struct_member %s\n", name);
#else
      msg(PLUGIN_NAME": send error on delete_struct_member %s\n", name.c_str());
#endif
   }
*/
}

void rename_struct_member(struc_t *s, member_t *m) {
   //get struct name and member name/offs and send to server
   json_object *obj = json_object_new_object();
   func_t *pfn = func_from_frame(s);
   if (pfn) {
//   if (s->props & SF_FRAME) {   //SF_FRAME is only available in SDK520 and later
//      func_t *pfn = func_from_frame(s);
      //send func ea, member offset, name
      append_json_ea_val(obj, "func_addr", pfn->start_ea); //lookup function on remote side
      append_json_int32_val(obj, "offset", (int32_t)m->soff);
#if IDA_SDK_VERSION < 680
      char name[MAXNAMESIZE];
      get_member_name(m->id, name, MAXNAMESIZE);
/*
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on rename_stack_member %x, %x, %s\n", (uint32_t)pfn->start_ea, (uint32_t)m->soff, name);
      }
*/
#else
      qstring name;
      get_member_name2(&name, m->id);
/*
      if (send_data(b) == -1) {
         msg(PLUGIN_NAME": send error on rename_stack_member %x, %x, %s\n", (uint32_t)pfn->start_ea, (uint32_t)m->soff, name.c_str());
      }
*/
#endif
      append_json_string_val(obj, "name", name);
      send_json(COMMAND_SET_STACK_VAR_NAME, obj);
   }
   else {
      //send struct name and member name and offset
      append_json_ea_val(obj, "offset", m->soff);

#if IDA_SDK_VERSION < 680
      char sname[MAXNAMESIZE];
      get_struc_name(s->id, sname, MAXNAMESIZE);

      char mname[MAXNAMESIZE];
      get_member_name(m->id, mname, MAXNAMESIZE);
#else
      qstring sname;
      /*ssize_t ssz =*/ get_struc_name(&sname, s->id);

      qstring mname;
      get_member_name2(&mname, m->id);
#endif
      append_json_string_val(obj, "struc_name", sname);
      append_json_string_val(obj, "mbr_name", mname);
      send_json(COMMAND_SET_STRUCT_MEMBER_NAME, obj);
/*
      if (send_data(b) == -1) {
#if IDA_SDK_VERSION < 680
         msg(PLUGIN_NAME": send error on rename_struct_member %x, %s, %s\n", (uint32_t)m->soff, sname, mname);
#else
         msg(PLUGIN_NAME": send error on rename_struct_member %x, %s, %s\n", (uint32_t)m->soff, sname.c_str(), mname.c_str());
#endif
      }
*/
   }
}

void change_struct_member(struc_t *s, member_t *m) {
   //what exactly constitutes a change? what info to send?
   //get struct name and member name/offs and send to server
   json_object *obj = json_object_new_object();

   opinfo_t ti, *pti;
#if IDA_SDK_VERSION < 680
   char name[MAXNAMESIZE];
#else
   qstring name;
#endif

#if IDA_SDK_VERSION >= 700
   pti = retrieve_member_info(&ti, m);
#else
   pti = retrieve_member_info(m, &ti);
#endif

   if (pti) {
      //in this case, we need to send the ti info in some manner
      if (isStruct(m->flag)) {
         append_json_string_val(obj, "type", COMMAND_STRUC_MEMBER_CHANGED_STRUCT);
#if IDA_SDK_VERSION < 680
         /*ssize_t tsz =*/ get_struc_name(ti.tid, name, sizeof(name));
#else
         /*ssize_t ssz =*/ get_struc_name(&name, ti.tid);
#endif
         append_json_string_val(obj, "inner_struc", name);
      }
      else if (isASCII(m->flag)) {
         append_json_string_val(obj, "type", COMMAND_STRUC_MEMBER_CHANGED_STR);
         append_json_uint32_val(obj, "str_type", (uint32_t)ti.strtype);
      }
      else if (isOff0(m->flag) || isOff1(m->flag)) {
         qstring jref;
         append_json_string_val(obj, "type", COMMAND_STRUC_MEMBER_CHANGED_OFFSET);
         append_json_hex_val(obj, "refinfo", (uint8_t*)&ti.ri, sizeof(refinfo_t));
      }
      else if (isEnum0(m->flag) || isEnum1(m->flag)) {
         append_json_string_val(obj, "type", COMMAND_STRUC_MEMBER_CHANGED_ENUM);
#if IDA_SDK_VERSION < 680
         /*ssize_t tsz =*/ get_struc_name(ti.ec.tid, name, sizeof(name));
#else
         /*ssize_t ssz =*/ get_struc_name(&name, ti.ec.tid);
#endif
         append_json_string_val(obj, "enum_name", name);
         append_json_int32_val(obj, "enum_serial", (int32)ti.ec.serial);
      }
      else {
         //need a command to write in this case??
         //is it even possible to have refinfo_t, strpath_t, or enum_const_t here?
         msg(PLUGIN_NAME": change_struct_member at unknown typeinfo\n");
         msg(PLUGIN_NAME": change_struct_member flags = %x, props = %x\n", m->flag, m->props);

         //simply return since we don't know what to write yet.  FIX THIS
         json_object_put(obj);
         return;
      }
   }
   else {
      append_json_string_val(obj, "type", COMMAND_STRUC_MEMBER_CHANGED_DATA);
   }

   append_json_ea_val(obj, "soff", m->unimem() ? 0 : m->soff);
   append_json_ea_val(obj, "eoff", m->eoff);
   append_json_uint32_val(obj, "flag", (uint32_t)m->flag);

   //should send opinfo_t as well
#if IDA_SDK_VERSION < 680
   /*ssize_t ssz =*/ get_struc_name(s->id, name, sizeof(name));
#else
   /*ssize_t ssz =*/ get_struc_name(&name, s->id);
#endif
   append_json_string_val(obj, "struc_name", name);

   send_json(obj);

/*
//   msg(PLUGIN_NAME": create_struct_member %s.%s off: %d, sz: %d\n", name, mbr, m->soff, m->eoff - m->soff);
   if (send_data(b) == -1) {
#if IDA_SDK_VERSION < 680
      msg(PLUGIN_NAME": send error on create_struct_member %s\n", name);
#else
      msg(PLUGIN_NAME": send error on create_struct_member %s\n", name.c_str());
#endif
   }
*/
}

void create_thunk(func_t *pfn) {
   json_object *obj = json_object_new_object();
   send_json(pfn->start_ea, COMMAND_THUNK_CREATED, obj);
/*
   if (send_data(b) == -1) {
      qstring a1;
      format_llx(pfn->start_ea, a1);
      msg(PLUGIN_NAME": send error on create_thunk 0x%s\n", a1.c_str());
   }
*/
}

void append_func_tail(func_t *pfn, func_t *tail) {
   json_object *obj = json_object_new_object();
   append_json_ea_val(obj, "funcea", pfn->start_ea);
   append_json_ea_val(obj, "tail_start", tail->start_ea);
   append_json_ea_val(obj, "tail_end", tail->end_ea);

   send_json(COMMAND_FUNC_TAIL_APPENDED, obj);
/*
   if (send_data(b) == -1) {
      qstring a1, a2;
      format_llx(pfn->start_ea, a1);
      format_llx(tail->start_ea, a2);
      msg(PLUGIN_NAME": send error on append_func_tail 0x%s, 0x%s\n", a1.c_str(), a2.c_str());
   }
*/
}

void remove_function_tail(func_t *pfn, ea_t ea) {
   json_object *obj = json_object_new_object();
   append_json_ea_val(obj, "funcea", pfn->start_ea);
   append_json_ea_val(obj, "tailea", ea);

   send_json(COMMAND_FUNC_TAIL_REMOVED, obj);
/*
   if (send_data(b) == -1) {
      qstring a1, a2;
      format_llx(pfn->start_ea, a1);
      format_llx(ea, a2);
      msg(PLUGIN_NAME": send error on remove_function_tail 0x%s, 0x%s\n", a1.c_str(), a2.c_str());
   }
*/
}

void change_tail_owner(func_t *tail, ea_t ea) {
   json_object *obj = json_object_new_object();
   append_json_ea_val(obj, "ownerea", ea);
   append_json_ea_val(obj, "tailea", tail->start_ea);

   send_json(COMMAND_TAIL_OWNER_CHANGED, obj);
/*
   if (send_data(b) == -1) {
      qstring a1, a2;
      format_llx(tail->start_ea, a1);
      format_llx(ea, a2);
      msg(PLUGIN_NAME": send error on change_tail_owner 0x%s, 0x%s\n", a1.c_str(), a2.c_str());
   }
*/
}

void change_func_noret(func_t *pfn) {
   json_object *obj = json_object_new_object();
   send_json(pfn->start_ea, COMMAND_FUNC_NORET_CHANGED, obj);
/*
   if (send_data(b) == -1) {
      qstring a1;
      format_llx(pfn->start_ea, a1);
      msg(PLUGIN_NAME": send error on change_func_noret 0x%s\n", a1.c_str());
   }
*/
}

void add_segment(segment_t *seg) {
   json_object *obj = json_object_new_object();
   append_json_ea_val(obj, "startea", seg->start_ea);
   append_json_ea_val(obj, "endea", seg->end_ea);
   append_json_int32_val(obj, "orgbase", (int32_t)seg->orgbase);

   append_json_int32_val(obj, "align", (int32_t)seg->align);
   append_json_int32_val(obj, "comb", (int32_t)seg->comb);
   append_json_int32_val(obj, "perm", (int32_t)seg->perm);
   append_json_int32_val(obj, "bitness", (int32_t)seg->bitness);
   append_json_int32_val(obj, "flags", (int32_t)seg->flags);

#if IDA_SDK_VERSION < 700
   char name[MAXNAMESIZE];
   char clazz[MAXNAMESIZE];
   get_segm_name(seg, name, sizeof(name));
   get_segm_class(seg, clazz, sizeof(clazz));
#else
   qstring name;
   qstring clazz;
   get_segm_name(&name, seg);
   get_segm_class(&clazz, seg);
#endif
   append_json_string_val(obj, "name", name);
   append_json_string_val(obj, "class", clazz);

   send_json(COMMAND_SEGM_ADDED, obj);
/*
   if (send_data(b) == -1) {
      qstring a1;
      format_llx(seg->start_ea, a1);
      msg(PLUGIN_NAME": send error on add_segment 0x%s\n", a1.c_str());
   }
*/
}

void del_segment(ea_t ea) {
   json_object *obj = json_object_new_object();
   send_json(ea, COMMAND_SEGM_DELETED, obj);
/*
   if (send_data(b) == -1) {
      qstring a1;
      format_llx(ea, a1);
      msg(PLUGIN_NAME": send error on del_segment 0x%s\n", a1.c_str());
   }
*/
}

void change_seg_start(segment_t *seg) {
   json_object *obj = json_object_new_object();
   append_json_ea_val(obj, "startea", seg->start_ea);
   append_json_ea_val(obj, "endea", seg->end_ea);
   send_json(COMMAND_SEGM_START_CHANGED, obj);
/*
   if (send_data(b) == -1) {
      qstring a1;
      format_llx(seg->start_ea, a1);
      msg(PLUGIN_NAME": send error on change_seg_start: 0x%s\n", a1.c_str());
   }
*/
}

void change_seg_end(segment_t *seg) {
   json_object *obj = json_object_new_object();
   append_json_ea_val(obj, "startea", seg->start_ea);
   append_json_ea_val(obj, "endea", seg->end_ea);
   send_json(COMMAND_SEGM_END_CHANGED, obj);
/*
   if (send_data(b) == -1) {
      qstring a1;
      format_llx(seg->start_ea, a1);
      msg(PLUGIN_NAME": send error on change_seg_end: 0x%s\n", a1.c_str());
   }
*/
}

void move_segment(ea_t from, ea_t to, asize_t sz) {
   json_object *obj = json_object_new_object();
   append_json_ea_val(obj, "from", from);
   append_json_ea_val(obj, "to", to);
   append_json_uint64_val(obj, "size", (uint64_t)sz);
   send_json(COMMAND_SEGM_MOVED, obj);
/*
   if (send_data(b) == -1) {
      qstring a1, a2;
      format_llx(from, a1);
      format_llx(to, a2);
      msg(PLUGIN_NAME": send error on move_segment: 0x%s -> 0x%s\n", a1.c_str(), a2.c_str());
   }
*/
}

#if IDA_SDK_VERSION < 700
void change_area_comment(areacb_t *cb, const area_t *a, const char *cmt, bool rep) {
   json_object *obj = json_object_new_object();
   int cbType = 0;
   if (cb == &funcs) {
      append_json_string_val(obj, "range", "funcs");
   }
   else if (cb == &segs) {
      append_json_string_val(obj, "range", "segs");
   }
   else {
      msg(PLUGIN_NAME": unknown areacb_t in change_area_comment\n");
      return;
   }

   append_json_ea_val(obj, "startea", a->start_ea);
   append_json_bool_val(obj, "rep", rep);
   append_json_string_val(obj, "comment", cmt);

   send_json(COMMAND_RANGE_CMT_CHANGED, obj);
/*
   if (send_data(b) == -1) {
      qstring a1;
      format_llx(a->start_ea, a1);
      msg(PLUGIN_NAME": send error on change_area_comment 0x%s, %s\n", a1.c_str(), cmt);
   }
*/
}
#endif

#if IDA_SDK_VERSION >= 700
void change_range_comment(range_kind_t rk, const range_t *r, const char *cmt, bool rep) {
   json_object *obj = json_object_new_object();
   int cbType = 0;
   if (rk == RANGE_KIND_FUNC) {
      append_json_string_val(obj, "range", "funcs");
}
   else if (rk == RANGE_KIND_SEGMENT) {
      append_json_string_val(obj, "range", "segs");
   }
   else {
      msg(PLUGIN_NAME": unknown range_kind_t in change_range_comment\n");
      return;
   }

   append_json_ea_val(obj, "startea", r->start_ea);
   append_json_bool_val(obj, "rep", rep);
   append_json_string_val(obj, "comment", cmt);

   send_json(COMMAND_RANGE_CMT_CHANGED, obj);
}
#endif

//notification hook function for idb notifications
#if IDA_SDK_VERSION < 700
int idaapi idb_hook(void * /*user_data*/, int notification_code, va_list va) {
#else
ssize_t idaapi idb_hook(void * /*user_data*/, int notification_code, va_list va) {
#endif
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
   msg("entering idb::%d (%s)\n", notification_code, notification_code < 60 ? idb_messages[notification_code] : "?");
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
         bool rep = va_arg(va, int) != 0;
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
         bool rep = va_arg(va, int) != 0;
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
#if IDA_SDK_VERSION >= 700
      case idb_event::func_tail_deleted: {     // A function tail chunk has been removed
#else
      case idb_event::func_tail_removed: {     // A function tail chunk has been removed
#endif
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
                                               // in: ea_t start_ea
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

#if IDA_SDK_VERSION >= 700
      case idb_event::make_code: {
         insn_t *ins = va_arg(va, insn_t*);
         /*
         qstring a1;
         format_llx(ea, a1);
         msg(PLUGIN_NAME": 0x%s make_code\n", a1.c_str());
         */
         idp_make_code(ins->ea, ins->size);
         break;
      }
      case idb_event::make_data: {
         ea_t ea = va_arg(va, ea_t);
         flags_t f = va_arg(va, flags_t);
         tid_t t = va_arg(va, tid_t);
         asize_t len = va_arg(va, asize_t);
         /*
         qstring a1;re
         format_llx(ea, a1);
         msg(PLUGIN_NAME": 0x%s make_data\n", a1.c_str());
         */
         idp_make_data(ea, f, t, len);
         break;
      }
      case idb_event::renamed: {
         //this receives notifications for stack variables as well
         ea_t ea = va_arg(va, ea_t);
         const char *name = va_arg(va, const char *);
         bool local = va_arg(va, int) != 0;
         idp_renamed(ea, name, local);
         break;
      }
      case idb_event::func_added: {
         func_t *pfn = va_arg(va, func_t*);
         idp_add_func(pfn);
         break;
      }
      case idb_event::set_func_start: {
         func_t *pfn = va_arg(va, func_t*);
         ea_t ea = va_arg(va, ea_t);
         idp_set_func_start(pfn, ea);
         break;
      }
      case idb_event::set_func_end: {
         func_t *pfn = va_arg(va, func_t*);
         ea_t ea = va_arg(va, ea_t);
         idp_set_func_end(pfn, ea);
         break;
      }
      case idb_event::deleting_func: {
         func_t *pfn = va_arg(va, func_t*);
         idp_del_func(pfn);
         break;
      }
      case idb_event::auto_empty: {
         //         msg("auto_empty\n");
         break;
         //         return 0;
      }
      case idb_event::auto_empty_finally: {
         //         msg("auto_empty_finally\n");
         //         return 0;
         break;
      }
#endif

#if 0
      case idb_event::area_cmt_changed: {
         // in: areacb_t *cb, const area_t *a, const char *cmt, bool repeatable
         areacb_t *cb = va_arg(va, areacb_t*);
         const area_t *a = va_arg(va, const area_t*);
         const char *cmt = va_arg(va, const char*);
         bool rep = va_arg(va, int) != 0;
         change_area_comment(cb, a, cmt, rep);
         break;
      }
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
                                    // in: ea_t start_ea
//         ea_t start_ea = va_arg(va, ea_t);
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

//notification hook function for idp notifications
#if IDA_SDK_VERSION < 700
int idaapi idp_hook(void * /*user_data*/, int notification_code, va_list va) {
//int idaapi ui_hook(void *user_data, int notification_code, va_list va);
#else
ssize_t idaapi idp_hook(void * /*user_data*/, int notification_code, va_list va) {
#endif
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
   msg("entering idp::%d (%s)\n", notification_code, notification_code < 110 ? (idp_messages[notification_code] ? idp_messages[notification_code] : "wtf") : "?");
//   publish = false;
   switch (notification_code) {
      case processor_t::ev_undefine: {
         ea_t ea = va_arg(va, ea_t);
/*
         qstring a1;
         format_llx(ea, a1);
         msg(PLUGIN_NAME": 0x%s undefined\n", a1.c_str());
*/
         idp_undefine(ea);
         break;
      }
#if IDA_SDK_VERSION < 700
      case processor_t::make_code: {
         ea_t ea = va_arg(va, ea_t);
         asize_t len = va_arg(va, asize_t);
/*
         qstring a1;
         format_llx(ea, a1);
         msg(PLUGIN_NAME": 0x%s make_code\n", a1.c_str());
*/
         idp_make_code(ea, len);
         break;
      }
      case processor_t::make_data: {
         ea_t ea = va_arg(va, ea_t);
         flags_t f = va_arg(va, flags_t);
         tid_t t = va_arg(va, tid_t);
         asize_t len = va_arg(va, asize_t);
/*
         qstring a1;
         format_llx(ea, a1);
         msg(PLUGIN_NAME": 0x%s make_data\n", a1.c_str());
*/
         idp_make_data(ea, f, t, len);
         break;
      }
#endif
#if IDA_SDK_VERSION < 700
      case processor_t::move_segm: {
         ea_t ea = va_arg(va, ea_t);
         segment_t *seg = va_arg(va, segment_t*);
         idp_move_segm(ea, seg);
         break;
      }
#endif
#if IDA_SDK_VERSION < 700
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
      case processor_t::ev_add_cref: {
         // args: ea_t from, ea_t to, cref_t type
         ea_t from = va_arg(va, ea_t);
         ea_t to = va_arg(va, ea_t);
         cref_t type = (cref_t)va_arg(va, int);
         idp_add_cref(from, to, type);
         break;
      }
      case processor_t::ev_add_dref: {
         // args: ea_t from, ea_t to, dref_t type
         ea_t from = va_arg(va, ea_t);
         ea_t to = va_arg(va, ea_t);
         dref_t type = (dref_t)va_arg(va, int);
         idp_add_dref(from, to, type);
         break;
      }
      case processor_t::ev_del_cref: {
         // args: ea_t from, ea_t to, bool expand
         ea_t from = va_arg(va, ea_t);
         ea_t to = va_arg(va, ea_t);
         bool expand = va_arg(va, int) != 0;
         idp_del_cref(from, to, expand);
         break;
      }
      case processor_t::ev_del_dref: {
         // args: ea_t from, ea_t to
         ea_t from = va_arg(va, ea_t);
         ea_t to = va_arg(va, ea_t);
         idp_del_dref(from, to);
         break;
      }
      case processor_t::ev_auto_queue_empty : {
//         msg("auto_queue_empty\n");
         break;
//         return 0;
      }
#if IDA_SDK_VERSION < 700
      case processor_t::auto_empty: {
         //         msg("auto_empty\n");
         break;
         //         return 0;
      }
      case processor_t::auto_empty_finally: {
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

