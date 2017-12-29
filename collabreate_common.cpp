/*
    Collabreate common user interface functions
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

#include "collabreate.h"

#include <pro.h>
#include <kernwin.hpp>

#include <stdio.h>
#include <string.h>
#include <netnode.hpp>
#include <nalt.hpp>
#include <md5.h>

#include <json-c/json.h>

#include "sdk_versions.h"

#if IDA_SDK_VERSION < 500
#include <fpro.h>
#endif

bool publish  = true;
bool userPublish  = true;
bool subscribe = true;

//global pointer to the incoming project list buffer.  Used to fill
//the project list dialog
//static Buffer *projectBuffer;

//global buffer that receives the description of the project selected
//by the user.
char description[1024];
//global array of integer project ids that map to the project 
//descriptions sent by the server.
int *projects;
uint64_t *snapUpdateIDs;
Options *optMasks;
int numProjectsGlobal = 0;
int isSnapShotGlobal = 0;
int numOptionsGlobal = 0;

char **optLabels = NULL;

//global used to hold user's selected project permissions
Options userOpts = { {0xffffffffffffffffll}, {0xffffffffffffffffll}};
Options tempOpts; //temporary

//Caution: returns a pointer to a static string
char *formatOptVal(OptVal *val) {
   static char buf[24];
   ::qsnprintf(buf, sizeof(buf), "%08x%08x", val->ii[1], val->ii[0]);
   return buf;
}

char *formatLongLong(uint64_t val) {
   OptVal v;
   v.ll = val;
   return formatOptVal(&v);
}

//Caution: returns a pointer to a static string
char *formatOptVal(OptVal *val, char *buf) {
   ::qsnprintf(buf, sizeof(buf), "%08x%08x", val->ii[1], val->ii[0]);
   return buf;
}

char *formatLongLong(uint64_t val, char *buf) {
   OptVal v;
   v.ll = val;
   return formatOptVal(&v, buf);
}

/*
 * Function: hmac_md5
 */

void hmac_md5(unsigned char *msg, int msg_len, 
              unsigned char *key, int key_len,
              unsigned char *digest) {
   MD5Context ctx;
   unsigned char ipad[64];
   unsigned char opad[64];
   unsigned char tk[MD5_LEN];
   int i;
   if (key_len > 64) {
      MD5Init(&ctx);
      MD5Update(&ctx, key, key_len);
      MD5Final(tk, &ctx);
      key = tk;
      key_len = MD5_LEN;
   }
   
   /* start out by storing key in pads */
   memset(ipad, 0, sizeof(ipad));
   memcpy(ipad, key, key_len);
   memcpy(opad, ipad, sizeof(opad));
   
   /* XOR key with ipad and opad values */
   for (i = 0; i < 64; i++) {
      ipad[i] ^= 0x36;
      opad[i] ^= 0x5c;
   }
   /*
   * perform inner MD5
   */
   MD5Init(&ctx);
   MD5Update(&ctx, ipad, 64);
   MD5Update(&ctx, msg, msg_len);
   MD5Final(digest, &ctx);
   /*
   * perform outer MD5
   */
   MD5Init(&ctx);
   MD5Update(&ctx, opad, 64);
   MD5Update(&ctx, digest, MD5_LEN);
   MD5Final(digest, &ctx);
   memset(ipad, 0, sizeof(ipad));
   memset(opad, 0, sizeof(opad));
}

int chooseProject(int index, char *desc) {
   if (index == 0) { // new project
      ::qstrncpy(description, desc, sizeof(description));
   }
   if (index > 0) {
      if (numProjectsGlobal > 1) {
         if (snapUpdateIDs[index - 1] > 0) {
            ::qstrncpy(description, desc, sizeof(description));               
            isSnapShotGlobal = 1;
         }
      }
      index = projects[index - 1];
   }

   //there is still some value in keeping these as they limit the
   //amount of traffic the client will generate to some extent
#ifdef DEBUG
   msg("   publish bits are 0x%s\n", formatOptVal(&userOpts.pub));
   msg("   subscribe bits are 0x%s\n", formatOptVal(&userOpts.sub));
#endif
   publish = userPublish = userOpts.pub.ll != 0;
   subscribe = userOpts.sub.ll != 0;
   //remember these as the current options
   setUserOpts(userOpts);
   return index;
}

bool changeProject(int index) {
   bool result = true;    //whether to enable description or not
   if (index == 0) {   //New project
      //enable all persmissions for new projects
      memset(&userOpts, 0xFF, sizeof(userOpts));
   }
   else if (numProjectsGlobal > 0) {
      if (snapUpdateIDs[index - 1] != 0) {
         //enable all persmissions for new projects
         memset(&userOpts, 0xFF, sizeof(userOpts));
      }
      else {
         userOpts = optMasks[index - 1];
         result = false;
      }
   }
   else {
      //unreachable?
      msg(PLUGIN_NAME": unknown desc window state entered, please tell developers\n");
      result = false;
   }
   return result;
}

//the order of these is important, the callback returns the ordinal of the selected string
char *const runCommands[] = {
   "Fork project",
   "Set checkpoint",
   "Manage requested permissions",
   "Manage project permissions (owner only)",
#ifdef DEBUG
   "Disconnect from server",
   "Show collab netnode",
   "Clean collab netnode"
#else
   "Disconnect from server"
#endif
};

int numCommands() {
   return sizeof(runCommands) / sizeof(runCommands[0]);
}

const char *getRunCommand(int i) {
   int max = sizeof(runCommands) / sizeof(runCommands[0]);
   if (i < 0 || i >= max) {
      return NULL;
   }
   return runCommands[i];
}

//sz should be 32 and gpid should be large enough
//returns -1 if no value exists
int getGpid(unsigned char *gpid, int sz) {
   return (int)cnn.supval(GPID_SUPVAL, gpid, sz);
}

//sz should be 32 and gpid should be large enough
void setGpid(unsigned char *gpid, int sz) {
   cnn.supset(GPID_SUPVAL, gpid, sz);
}

bool getFileMd5(unsigned char *md5, int len) {
   if (len < MD5_LEN) {
      return false;
   }
   
#if IDA_SDK_VERSION >= 500
   retrieve_input_file_md5(md5);
#else
#define RIDX_MD5                  1302  //MD5 of the input file
   if (RootNode.supval(RIDX_MD5, md5, MD5_LEN) != MD5_LEN) {
      char buf[512];
      get_input_file_path(buf, sizeof(buf));
      FILE *f = qfopen(buf, "rb");
      if (f) {
         MD5Context ctx;
         MD5Init(&ctx);
         int len;
         while ((len = qfread(f, buf, sizeof(buf))) > 0) {
            MD5Update(&ctx, (unsigned char*)buf, len);
         }
         MD5Final(md5, &ctx);
         RootNode.supset(RIDX_MD5, md5, MD5_LEN);
         qfclose(f);
      }
      else {
         //failed to open input file
         return false;
      }
   }
#endif
   return true;
}

const char *hex_encode(const void *bin, uint32_t len) {
   char *res = (char*)qalloc(len * 2 + 1);
   const uint8_t *_bin = (const uint8_t *)bin;
   for (uint32_t i = 0; i < len; i++) {
      qsnprintf(res + i * 2, 3, "%02x", _bin[i]);
   }
   return res;
}

uint8_t *hex_decode(const char *hex, uint32_t *len) {
   *len = (uint32_t)strlen(hex);
   if (*len & 1) {
      return NULL;
   }
   *len /= 2;
   uint8_t *res = (uint8_t*)qalloc(*len);
   for (uint32_t i = 0; i < *len; i++) {
      uint32_t bval;
      if (sscanf(hex + i * 2, "%02x", &bval) != 1) {
         qfree(res);
         return NULL;
      }
      res[i] = (uint8_t)bval;
   }
   return res;
}

#ifdef _WIN32
#define snprintf _snprintf
#endif

void format_llx(uint64_t val, qstring &s) {
   char buf[32];
   snprintf(buf, sizeof(buf), "%llx", (uint64_t)val);
   s = buf;
}

#ifdef _WIN32
#undef snprintf
#endif


void append_json_hex_val(json_object *obj, const char *key, const uint8_t *value, uint32_t len) {
   if (len == 0) {
      len = (uint32_t)strlen((const char*)value);
   }
   const char *hex = hex_encode(value, len);
   json_object_object_add_ex(obj, key, json_object_new_string(hex), JSON_NEW_CONST_KEY);
   qfree((void*)hex);
}

void append_json_string_val(json_object *obj, const char *key, const char *value) {
   json_object_object_add_ex(obj, key, json_object_new_string(value), JSON_NEW_CONST_KEY);
}

void append_json_string_val(json_object *obj, const char *key, const qstring &value) {
   append_json_string_val(obj, key, value.c_str());
}

void append_json_bool_val(json_object *obj, const char *key, bool value) {
   json_object_object_add_ex(obj, key, json_object_new_boolean((json_bool)value), JSON_NEW_CONST_KEY);
}

void append_json_uint64_val(json_object *obj, const char *key, uint64_t value) {
   json_object_object_add_ex(obj, key, json_object_new_int64(value), JSON_NEW_CONST_KEY);
}

void append_json_uint32_val(json_object *obj, const char *key, uint32_t value) {
   append_json_uint64_val(obj, key, value);
}

void append_json_int32_val(json_object *obj, const char *key, int32_t value) {
   json_object_object_add_ex(obj, key, json_object_new_int(value), JSON_NEW_CONST_KEY);
}

void append_json_ea_val(json_object *obj, const char *key, ea_t value) {
   append_json_uint64_val(obj, key, (uint64_t)value);
}

/* This is the final use of the provided json object so
   this function does the json_object_put to release
   any associated resources */
int send_json(json_object *obj) {
   json_object_object_add_ex(obj, "user", json_object_new_string(username), JSON_NEW_CONST_KEY);
   size_t jlen;
   qstring json = json_object_to_json_string_length(obj, JSON_C_TO_STRING_PLAIN, &jlen);
   json += '\n';
   int res = send_msg(json);
   json_object_put(obj);   //release the object
   return res;
}

int send_json(const char *type, json_object *obj) {
   json_object_object_add_ex(obj, "type", json_object_new_string(type), JSON_NEW_CONST_KEY);
   return send_json(obj);      
}

int send_json(ea_t ea, const char *type, json_object *obj) {
   json_object_object_add_ex(obj, "addr", json_object_new_int64(ea), JSON_NEW_CONST_KEY);
   return send_json(type, obj);
}

uint8_t *hex_from_json(json_object *json, const char *key, uint32_t *len) {
   const char *hexstr = string_from_json(json, key);
   uint8_t *res = NULL;
   if (hexstr != NULL) {
      res = hex_decode(hexstr, len);
   }
   return res;
}

const char *string_from_json(json_object *json, const char *key) {
   json_object *value;

   if (!json_object_object_get_ex (json, key, &value)) {
      return NULL;
   }

   return json_object_get_string(value);
}

bool bool_from_json(json_object *json, const char *key, bool *val) {
   json_object *value;

   if (!json_object_object_get_ex (json, key, &value)) {
      return false;
   }

   *val = json_object_get_boolean(value) != 0;
   return true;
}

bool uint64_from_json(json_object *json, const char *key, uint64_t *val) {
   json_object *value;

   if (!json_object_object_get_ex (json, key, &value)) {
      return false;
   }

   *val = (uint64_t)json_object_get_int64(value);
   return true;
}

bool ea_from_json(json_object *json, const char *key, ea_t *val) {
   uint64_t tmp;
   if (uint64_from_json(json, key, &tmp)) {
      *val = (ea_t)tmp;
      return true;
   }
   return false;
}

bool uint32_from_json(json_object *json, const char *key, uint32_t *val) {
   uint64_t tmp;
   if (uint64_from_json(json, key, &tmp)) {
      *val = (uint32_t)tmp;
      return true;
   }
   return false;
}

bool int32_from_json(json_object *json, const char *key, int32_t *val) {
   json_object *value;

   if (!json_object_object_get_ex (json, key, &value)) {
      return false;
   }

   *val = (int32_t)json_object_get_int(value);
   return true;
}
