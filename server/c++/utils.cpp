/*
   collabREate utils.cpp
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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <err.h>
#include <stdint.h>
#include <string>
#include <openssl/md5.h>
#include <json-c/json.h>

#include "utils.h"

using std::string;

const char *permStrings[] = {
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
      "Xrefs",
      NULL
};

size_t permStringsLength = sizeof(permStrings) / sizeof(char*) - 1;

union uLongLong {
   uint64_t ll;
   uint32_t ii[2];
};

static FILE *logger = stderr;
static int log_level = 0;
time_t ping_timeout = 300;

uint64_t htonll(uint64_t val) {
   uLongLong ull;
   ull.ll = val;
   uint32_t t = ull.ii[0];
   ull.ii[0] = htonl(ull.ii[1]);
   ull.ii[1] = htonl(t);
   return ull.ll;
}

/**
 * toByteArray - generate a byte array representation of the specified
 *               string
 * @param hexString The string to convert
 * @return The byte array representation of the given string
 */
uint8_t *toByteArray(string hexString, uint32_t *rlen) {
   char buf[4];
   if ((hexString.length() % 2) == 1) {
      //invalid hex string
      return NULL;
   }
   int idx = 0;
   uint8_t *result = new uint8_t[hexString.length() / 2];
   buf[2] = 0;
   for (size_t i = 0; i < hexString.length(); i += 2) {
      buf[0] = hexString[i];
      buf[1] = hexString[i + 1];
      sscanf(buf, "%hhx", &result[idx++]);
   }
   return result;
}

/**
 * tests if the provided string contains digits only
 * @param s string to test
 */
bool isNumeric(string s) {
   if (s.length() == 0) {
      return false;
   }
   for (size_t i = 0; i < s.length(); i++) {
      if (!isdigit(s.at(i))) {
         return false;
      }
   }
   return true;
}

/**
 * tests if the provided string contains hex characters only
 * @param s string to test
 */
bool isHex(string s) {
   if (s.length() == 0) {
      return false;
   }
   for (size_t i = 0; i < s.length(); i++) {
      if (!isxdigit(s.at(i))) {
         return false;
      }
   }
   return true;
}

/**
 * tests if the provided string contains letters and digits only
 * @param s string to test
 */
bool isAlphaNumeric(string s) {
   if (s.length() == 0) {
      return false;
   }
   for (size_t i = 0; i < s.length(); i++) {
      if (!isalnum(s.at(i))) {
         return false;
      }
   }
   return true;
}

string toHexString(const uint8_t *buf, int len) {
   char hex[16];
   string res = "";
   for (int i = 0; i < len; i++) {
      snprintf(hex, sizeof(hex), "%02x", buf[i]);
      res += hex;
   }
   return res;
}

/**
 * getMD5 - calculate the md5sum of a string
 * @param tohash The string to hash
 * @return The md5sum of the input string
 */
string getMD5(const void *tohash, int len) {
   string hashString = "";
   uint8_t digest[MD5_DIGEST_LENGTH];
   MD5((const unsigned char *)tohash, len, digest);
   hashString = toHexString(digest, MD5_DIGEST_LENGTH);
   return hashString;
}

string getMD5(const string &s) {
   return getMD5(s.c_str(), s.length());
}

void vlog(const char *format, va_list va) {
   vfprintf(logger, format, va);
}

void vlog(int verbosity, const char *format, va_list va) {
   if (verbosity <= log_level) {
      vlog(format, va);
   }
}

void log(const char *format, ...) {
   va_list va;
   va_start(va, format);
   vlog(format, va);
   va_end(va);
}

void log(int verbosity, const char *format, ...) {
   va_list va;
   va_start(va, format);
   vlog(verbosity, format, va);
   va_end(va);
}

//returns true: a read was performed, check *obj
//       false: a timeout occurred
bool readJson(int sock, string &json_buffer, json_object **obj, time_t timeout) {
   char buf[2048];
   json_tokener *tok = json_tokener_new();
   enum json_tokener_error jerr;
   bool result = true;
   *obj = NULL;
   while (1) {
      //start by seeing if we have a complete json object already buffered
      json_tokener_reset(tok);
      *obj = json_tokener_parse_ex(tok, json_buffer.c_str(), json_buffer.length());
      jerr = json_tokener_get_error(tok);
      if (jerr == json_tokener_continue) {
         //json object is syntactically correct, but incomplete
         log(LDEBUG, "json_tokener_continue for %s\n", json_buffer.c_str());
      }
      else if (jerr != json_tokener_success) {
         //need to reconnect socket and in the meantime start caching event locally
         log(LERROR, "jerr != json_tokener_success for %s\n", json_buffer.c_str());
         break;
      }
      else if (*obj != NULL) {
         //we extracted a json object from the front of the string
         //queue it and trim the string
         log(LDEBUG, "jerr == json_tokener_success for %s\n", json_buffer.c_str());
         json_buffer.erase(0, tok->char_offset);
         break;
      }
      else {
         //can we ever get here?
      }

      //couldn't buid a json object so we need to read more data
      fd_set rset;
      timeval timeo = {timeout, 0};
      FD_ZERO(&rset);
      FD_SET(sock, &rset);
      int nfds = select(sock + 1, &rset, NULL, NULL, timeout ? &timeo : NULL);
      if (nfds == 0) {
         result = false;
         break;
      }
      ssize_t len = recv(sock, buf, sizeof(buf), 0);
      if (len <= 0) {
         //recv error or EOF, in any case we quit
         break;
      }
      json_buffer.append(buf, len);   //append new data into json buffer
   }
   json_tokener_free(tok);
   log(LDEBUG, "current json_buffer: %s\n", json_buffer.c_str());
   return result;
}

ssize_t sendAll(int fd, const void *buf, ssize_t size) {
   ssize_t total = 0;
   const unsigned char *b = (const unsigned char *)buf;
   while (total < size) {
      ssize_t nbytes = write(fd, b + total, size - total);
      if (nbytes == 0) return -1;
      total += nbytes;
   }
   return total;
}

/*
 * This reads up to size bytes into a user supplied buffer
 * Returns the number of bytes read or -1 if size bytes
 * could not be read.
 * This function is really only useful for reading fixed
 * size fields.
 */
ssize_t readAll(int fd, void *ubuf, ssize_t size) {
   ssize_t total = 0;
   ssize_t nbytes;
   while (total < size) {
      nbytes = read(fd, total +(char*)ubuf, size - total);
      if (nbytes <= 0) {
         return -1;
      }
      total += nbytes;
   }
   return total;
}

bool writeJson(int fd, json_object *obj) {
   size_t jlen;
   ssize_t res;
   const char *json = json_object_to_json_string_length(obj, JSON_C_TO_STRING_PLAIN, &jlen);
   res = sendAll(fd, json, jlen);
   json_object_put(obj);   //release the object
   return jlen == (size_t)res;
}

RC4::RC4(unsigned char *key, unsigned int keylen) {
   unsigned int k;
   unsigned char t;
   unsigned char jj = 0;
/*
   for (i = 0; i < keylen; i++) {
      fprintf(stderr, "%02.2x", key[i]);
   }
   fprintf(stderr, "\n");
*/
   memset(S, 0, 256);
   if (keylen == 0) return;
   for (k = 0; k <= 255; k++) {
      S[k] = (unsigned char)k;
   }
   for (k = 0; k <= 255; k++) {
      jj += S[k] + key[k % keylen];
      t = S[jj];
      S[jj] = S[k];
      S[k] = t;
   }
   j = 0;
   i = 0;
}

unsigned char RC4::generate() {
   unsigned char t;
   i++;
   j += S[i];
   t = S[j];
   S[j] = S[i];
   S[i] = t;
   t += S[j];
   return S[t];
}

void RC4::crypt(unsigned char *blob, int len) {
   for (int i = 0; i < len; i++) {
      *blob++ ^= generate();
   }
}

int fill_random(unsigned char *buf, size_t size) {
   int urand = open("/dev/urandom", O_RDONLY);
   if (urand < 0) {
      urand = 0;
      while (size--) {
         buf[urand++] = (unsigned char)rand();
      }
      return 0;
   }
   else {
      readAll(urand, buf, size);
      close(urand);
      return 1;
   }
}

short getShortOption(json_object *conf, const string &opt, short defaultValue) {
   return (short)getIntOption(conf, opt, defaultValue);
}

int getIntOption(json_object *conf, const string &opt, int defaultValue) {
   const char *var = getenv(opt.c_str());
   if (var) {
      return strtol(var, NULL, 0);
   }

   json_object *val = json_object_object_get(conf, opt.c_str());
   if (val == NULL) {
      return defaultValue;
   }
   else {
      return (int)json_object_get_int(val);
   }
}

string getStringOption(json_object *conf, const string &opt, const char *defaultValue) {
   const char *res = getenv(opt.c_str());
   if (res) {
      return res;
   }

   json_object *val = json_object_object_get(conf, opt.c_str());
   if (val == NULL) {
      return defaultValue;
   }
   else {
      return json_object_get_string(val);
   }
}

const char *getCstringOption(json_object *conf, const string &opt, const char *defaultValue) {
   const char *res = getenv(opt.c_str());
   if (res) {
      return res;
   }

   json_object *val = json_object_object_get(conf, opt.c_str());
   if (val == NULL) {
      return defaultValue;
   }
   else {
      return json_object_get_string(val);
   }
}

json_object *parseConf(const char *fname) {
   json_object *conf = json_object_from_file(fname);

   if (conf) {
      const char *logfile = getCstringOption(conf, "LOG_FILE", NULL);
      if (logfile) {
         FILE *f = fopen(logfile, "a");
         if (f) {
            setvbuf(f, NULL, _IONBF, 0);
            logger = f;
         }
      }
      log_level = getIntOption(conf, "LOG_VERBOSITY", 0);
      ping_timeout = getIntOption(conf, "PING_TIMEOUT", 300);
   }

   return conf;
}

const char *hex_encode(const void *bin, uint32_t len) {
   char *res = new char[len * 2 + 1];
   const uint8_t *_bin = (const uint8_t *)bin;
   for (uint32_t i = 0; i < len; i++) {
      snprintf(res + i * 2, 3, "%02x", _bin[i]);
   }
   return res;
}

uint8_t *hex_decode(const char *hex, uint32_t *len) {
   *len = strlen(hex);
   if (*len & 1) {
      return NULL;
   }
   *len /= 2;
   uint8_t *res = new uint8_t[*len];
   for (uint32_t i = 0; i < *len; i++) {
      uint32_t bval;
      if (sscanf(hex + i * 2, "%02x", &bval) != 1) {
         delete [] res;
         return NULL;
      }
      res[i] = (uint8_t)bval;
   }
   return res;
}

void append_json_hex_val(json_object *obj, const char *key, const uint8_t *value, uint32_t len) {
   if (len == 0) {
      len = strlen((const char*)value);
   }
   const char *hex = hex_encode(value, len);
   json_object_object_add_ex(obj, key, json_object_new_string(hex), JSON_NEW_CONST_KEY);
   delete [] hex;
}

void append_json_string_val(json_object *obj, const char *key, const char *value) {
   json_object_object_add_ex(obj, key, json_object_new_string(value), JSON_NEW_CONST_KEY);
}

void append_json_string_val(json_object *obj, const char *key, const string &value) {
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

   if (!json_object_object_get_ex(json, key, &value)) {
      return NULL;
   }

   return json_object_get_string(value);
}

bool bool_from_json(json_object *json, const char *key, bool *val) {
   json_object *value;

   if (!json_object_object_get_ex(json, key, &value)) {
      return false;
   }

   *val = (bool)json_object_get_boolean(value);
   return true;
}

bool uint64_from_json(json_object *json, const char *key, uint64_t *val) {
   json_object *value;

   if (!json_object_object_get_ex(json, key, &value)) {
      return false;
   }

   *val = (uint64_t)json_object_get_int64(value);
   return true;
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

   if (!json_object_object_get_ex(json, key, &value)) {
      return false;
   }

   *val = (int32_t)json_object_get_int(value);
   return true;
}
